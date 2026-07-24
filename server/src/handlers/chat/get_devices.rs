//! `blue.catbird.chat.getDevices` — ordinary-unsigned addressable-device query.
//!
//! Reuses the certified `inventory::get_devices` VERBATIM for the bounded audience
//! set (it owns the DID/per-DID/total bounds and canonical ordering), then
//! enriches each returned device via `read_device_view` to project the wire
//! `addressableDevice` (key id + decoded pinned capability + live available count).
//! The per-row enrichment is a deliberate bounded N+1 — the audience is hard-capped
//! at `MAX_GET_DEVICES_TOTAL` by the reused read.

use std::sync::Arc;

use axum::{
    extract::{RawQuery, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};

use catbird_atproto::generated::blue_catbird::chat as chat_dto;
use jacquard_common::DefaultStr;

use crate::chat_protocol::error::ChatEndpoint;
use crate::chat_protocol::repository::device_directory::read_device_view;
use crate::chat_protocol::repository::inventory;
use crate::chat_protocol::validation::CanonicalHttpMethod;
use crate::storage::DbPool;

use super::context;
use super::device_views::{
    addressable_device_from_directory, directory_failure, inventory_failure, InventoryFailure,
};
use super::errors::ChatFailure;
use super::runtime::ChatRuntime;

const ENDPOINT: ChatEndpoint = ChatEndpoint::GetDevices;

pub(super) async fn handle(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    match get_devices(&pool, &runtime, &headers, query.as_deref()).await {
        Ok(response) => response,
        Err(failure) => failure.into_response(),
    }
}

async fn get_devices(
    pool: &DbPool,
    runtime: &ChatRuntime,
    headers: &HeaderMap,
    query: Option<&str>,
) -> Result<Response, ChatFailure> {
    let method = CanonicalHttpMethod::parse("GET").map_err(|_| ChatFailure::invariant(ENDPOINT))?;
    let _authority = context::admit_unsigned(pool, runtime, ENDPOINT, method, headers).await?;

    let dids = parse_user_dids(query);
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| ChatFailure::storage(ENDPOINT))?;

    let rows = match inventory::get_devices(&mut transaction, &dids).await {
        Ok(rows) => rows,
        Err(error) => {
            return match inventory_failure(ENDPOINT, error) {
                // getDevices declares no retryable code and `get_devices` has no
                // SnapshotConflict path, so a retryable classification here is an
                // internal invariant break.
                InventoryFailure::Retryable => Err(ChatFailure::invariant(ENDPOINT)),
                InventoryFailure::Terminal(failure) => Err(failure),
            };
        }
    };

    let mut devices = Vec::with_capacity(rows.len());
    for row in &rows {
        // The audience read returns only active devices; a row that vanishes
        // between the two reads is skipped rather than surfaced as a phantom.
        if let Some(view) = read_device_view(&mut transaction, &row.user_did, row.device_id)
            .await
            .map_err(|error| directory_failure(ENDPOINT, error))?
        {
            devices.push(addressable_device_from_directory(
                &view,
                &row.user_did,
                ENDPOINT,
            )?);
        }
    }

    let output = chat_dto::get_devices::GetDevicesOutput::<DefaultStr> {
        devices,
        extra_data: None,
    };
    let response_bytes =
        serde_json::to_vec(&output).map_err(|_| ChatFailure::invariant(ENDPOINT))?;

    // Read-only; releasing the transaction discards nothing durable.
    let _ = transaction.rollback().await;
    Ok(context::json_ok(response_bytes))
}

/// Collect the repeated `userDids` query parameter values in wire order. Bounds
/// enforcement (too many / zero) is delegated to the certified
/// `inventory::get_devices`, so this only decodes.
fn parse_user_dids(query: Option<&str>) -> Vec<String> {
    let Some(query) = query else {
        return Vec::new();
    };
    let mut dids = Vec::new();
    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        let key = parts.next().unwrap_or("");
        if key != "userDids" {
            continue;
        }
        if let Some(raw) = parts.next() {
            dids.push(percent_decode(raw));
        }
    }
    dids
}

/// Minimal `application/x-www-form-urlencoded` value decode (`+` → space, `%XX`
/// → byte). Invalid escapes are passed through literally.
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let hi = (bytes[index + 1] as char).to_digit(16);
                let lo = (bytes[index + 2] as char).to_digit(16);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    out.push((hi * 16 + lo) as u8);
                    index += 3;
                } else {
                    out.push(bytes[index]);
                    index += 1;
                }
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}
