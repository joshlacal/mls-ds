//! `blue.catbird.chat.getOwnDevices` — ordinary-unsigned own-device snapshot.
//!
//! Materializes every device the requester owns (active AND revoked) into one
//! retained device-inventory session fence in a single transaction, and returns
//! the same `ownDeviceView` payloads inline. The whole own-device set materializes
//! in ONE `create_device_inventory_session` call — there is no event fence to
//! re-validate, so there is no `SnapshotConflict` path in practice. The OQ-8
//! whole-call retry (READ COMMITTED, N=3) is present as the program-wide pattern;
//! it is a defensive no-op here, and at the ceiling — getOwnDevices declares no
//! retryable wire code — the surface is HTTP 503 + `Retry-After`, never an
//! undeclared protocol code.

use std::sync::Arc;

use axum::{
    extract::State,
    http::{header::RETRY_AFTER, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::Duration;

use catbird_atproto::generated::blue_catbird::chat as chat_dto;
use jacquard_common::DefaultStr;

use crate::chat_protocol::error::ChatEndpoint;
use crate::chat_protocol::repository::device_directory::{
    list_own_device_views, DeviceDirectoryView,
};
use crate::chat_protocol::repository::inventory::{
    self, CreateDeviceInventorySessionRequest, DeviceInventorySubject,
};
use crate::chat_protocol::validation::CanonicalHttpMethod;
use crate::sqlx_jacquard::chrono_to_datetime;
use crate::storage::DbPool;

use super::context;
use super::device_views::{
    device_view_from_directory, directory_failure, inventory_failure, own_device_view,
    InventoryFailure,
};
use super::errors::ChatFailure;
use super::runtime::ChatRuntime;

const ENDPOINT: ChatEndpoint = ChatEndpoint::GetOwnDevices;
/// OQ-8 whole-call retry ceiling.
const MAX_ATTEMPTS: u32 = 3;
/// Retained device-inventory session lifetime.
const SESSION_TTL_MINUTES: i64 = 10;
/// `Retry-After` seconds advertised at the retry ceiling.
const RETRY_AFTER_SECONDS: &str = "1";

pub(super) async fn handle(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
) -> Response {
    match get_own_devices(&pool, &runtime, &headers).await {
        Ok(response) => response,
        Err(failure) => failure.into_response(),
    }
}

async fn get_own_devices(
    pool: &DbPool,
    runtime: &ChatRuntime,
    headers: &HeaderMap,
) -> Result<Response, ChatFailure> {
    let method = CanonicalHttpMethod::parse("GET").map_err(|_| ChatFailure::invariant(ENDPOINT))?;
    let authority = context::admit_unsigned(pool, runtime, ENDPOINT, method, headers).await?;

    let subject = authority.subject().as_str().to_owned();
    let requester_device = uuid::Uuid::parse_str(authority.device_id().as_str())
        .map_err(|_| ChatFailure::invariant(ENDPOINT))?;
    let jkt = authority.dpop_jkt().as_str().to_owned();
    // The device-inventory session timestamps must be whole seconds (the durable
    // row rejects sub-second precision); the trusted instant carries millis.
    let created_at = whole_second(authority.trusted_instant().datetime())?;
    let expires_at = created_at + Duration::minutes(SESSION_TTL_MINUTES);

    for _attempt in 0..MAX_ATTEMPTS {
        match materialize_snapshot(
            pool,
            &subject,
            requester_device,
            &jkt,
            created_at,
            expires_at,
        )
        .await?
        {
            SnapshotOutcome::Retry => continue,
            SnapshotOutcome::Completed(response_bytes) => {
                return Ok(context::json_ok(response_bytes));
            }
        }
    }

    Ok(retry_ceiling_response())
}

enum SnapshotOutcome {
    Retry,
    Completed(Vec<u8>),
}

async fn materialize_snapshot(
    pool: &DbPool,
    subject: &str,
    requester_device: uuid::Uuid,
    jkt: &str,
    created_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> Result<SnapshotOutcome, ChatFailure> {
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| ChatFailure::storage(ENDPOINT))?;
    // OQ-8: the whole call re-runs under READ COMMITTED (the pool default; set
    // explicitly for the record).
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *transaction)
        .await
        .map_err(|_| ChatFailure::storage(ENDPOINT))?;

    let views = list_own_device_views(&mut transaction, subject)
        .await
        .map_err(|error| directory_failure(ENDPOINT, error))?;

    let requester_generation = requester_auth_generation(&views, requester_device)?;

    let mut items = Vec::with_capacity(views.len());
    let mut subjects = Vec::with_capacity(views.len());
    for view in &views {
        let own = own_device_view(device_view_from_directory(view));
        let payload_bytes =
            serde_json::to_vec(&own).map_err(|_| ChatFailure::invariant(ENDPOINT))?;
        subjects.push(DeviceInventorySubject {
            subject_device_id: view.device_id,
            payload_bytes,
        });
        items.push(own);
    }

    let request = CreateDeviceInventorySessionRequest {
        device_inventory_session_id: uuid::Uuid::new_v4(),
        user_did: subject,
        device_id: requester_device,
        jkt,
        auth_generation: requester_generation,
        fence_revision: 0,
        created_at,
        expires_at,
        subjects,
    };
    match inventory::create_device_inventory_session(&mut transaction, request).await {
        Ok(_) => {}
        Err(error) => {
            return match inventory_failure(ENDPOINT, error) {
                InventoryFailure::Retryable => Ok(SnapshotOutcome::Retry),
                InventoryFailure::Terminal(failure) => Err(failure),
            };
        }
    }

    transaction
        .commit()
        .await
        .map_err(|_| ChatFailure::storage(ENDPOINT))?;

    // Single page: the whole own-device set materializes at once, so there is no
    // further page and no continuation cursor.
    let output = chat_dto::get_own_devices::GetOwnDevicesOutput::<DefaultStr> {
        has_more: false,
        items,
        next_page_cursor: None,
        snapshot_expires_at: chrono_to_datetime(expires_at),
        extra_data: None,
    };
    let response_bytes =
        serde_json::to_vec(&output).map_err(|_| ChatFailure::invariant(ENDPOINT))?;
    Ok(SnapshotOutcome::Completed(response_bytes))
}

/// Truncate an instant to a whole second (the durable device-inventory session
/// row rejects sub-second timestamps).
fn whole_second(
    value: chrono::DateTime<chrono::Utc>,
) -> Result<chrono::DateTime<chrono::Utc>, ChatFailure> {
    chrono::DateTime::from_timestamp(value.timestamp(), 0)
        .ok_or_else(|| ChatFailure::invariant(ENDPOINT))
}

/// The requester's own device must appear in its own-device set; its stored auth
/// generation drives the fence authority re-check.
fn requester_auth_generation(
    views: &[DeviceDirectoryView],
    requester_device: uuid::Uuid,
) -> Result<u64, ChatFailure> {
    let view = views
        .iter()
        .find(|view| view.device_id == requester_device)
        .ok_or_else(|| ChatFailure::invariant(ENDPOINT))?;
    u64::try_from(view.auth_generation).map_err(|_| ChatFailure::invariant(ENDPOINT))
}

/// The OQ-8 ceiling surface: HTTP 503 + `Retry-After`. getOwnDevices declares no
/// retryable protocol code, so no wire vocabulary is emitted — only a
/// transport-generic name matching the 503 status (Inf-1).
fn retry_ceiling_response() -> Response {
    let mut response = (
        StatusCode::SERVICE_UNAVAILABLE,
        axum::Json(serde_json::json!({ "error": "ServiceUnavailable" })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from_static(RETRY_AFTER_SECONDS));
    response
}
