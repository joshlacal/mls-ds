//! `blue.catbird.chat.registerPushGateway` handler (`D2`, `M-F06`).
//!
//! Validates:
//! 1. Cutover gate (`context::require_cutover` first so empty pre-cutover requests return `400 CutoverRequired`).
//! 2. Account/device service authentication (`context::verify_service_principal`).
//! 3. Canonical `RegisterPushGateway` body + DNS-pinned SSRF check on `gatewayUrl` (`400 InvalidGatewayUrl`).
//! 4. Enrolled active device & Ed25519 key in `chat.devices` + `chat.device_keys`.
//! 5. `CATBIRD-CHAT-PUSH-GATEWAY\0` canonical DAG-CBOR Ed25519 signature (`401 InvalidSignature`).
//! 6. Upserts (or deletes when `enabled == false`) `chat.push_gateway_bindings`.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use catbird_atproto::generated::blue_catbird::chat::register_push_gateway::RegisterPushGateway;
use chrono::{DateTime, SecondsFormat, Utc};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde_json::json;
use uuid::Uuid;

use super::{context, errors::ChatFailure, runtime::ChatRuntime};
use crate::{
    chat_protocol::error::{ChatEndpoint, ChatProtocolErrorCode},
    push_gateway::{build_push_gateway_transcript, ssrf::validate_push_gateway_url},
    storage::DbPool,
};

const ENDPOINT: ChatEndpoint = ChatEndpoint::RegisterPushGateway;

pub(super) async fn handle(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    register(&pool, &runtime, &headers, &body)
        .await
        .unwrap_or_else(IntoResponse::into_response)
}

async fn register(
    pool: &DbPool,
    runtime: &ChatRuntime,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Response, ChatFailure> {
    context::require_cutover(runtime, ENDPOINT)?;
    let principal = context::verify_service_principal(pool, ENDPOINT, headers).await?;
    let user_did = principal.did().to_string();

    let input: RegisterPushGateway = serde_json::from_slice(body)
        .map_err(|_| ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest))?;

    let device_uuid = Uuid::parse_str(input.device_id.as_ref())
        .map_err(|_| ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest))?;

    let enabled = input.enabled.unwrap_or(true);
    let gateway_url: &str = input.gateway_url.as_ref();
    let app_id: &str = input.app_id.as_ref();
    let push_key: &str = input.push_key.as_ref();
    let key_id: &str = input.key_id.as_ref();
    let signed_at_str = input.signed_at.as_str();

    if app_id.is_empty() || app_id.len() > 128 || input.auth_generation < 1 {
        return Err(ChatFailure::protocol(
            ENDPOINT,
            ChatProtocolErrorCode::InvalidRequest,
        ));
    }
    if enabled && (push_key.len() < 16 || push_key.len() > 256) {
        return Err(ChatFailure::protocol(
            ENDPOINT,
            ChatProtocolErrorCode::InvalidRequest,
        ));
    }
    let signed_at: DateTime<Utc> = DateTime::parse_from_rfc3339(signed_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_| ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidRequest))?;

    // DNS-pinned SSRF guard BEFORE touching DB bindings (`M-F06`)
    validate_push_gateway_url(gateway_url)
        .map_err(|_| ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidGatewayUrl))?;

    let device_row: Option<(String, i64)> = sqlx::query_as(
        "SELECT status, auth_generation FROM chat.devices WHERE user_did = $1 AND device_id = $2",
    )
    .bind(&user_did)
    .bind(device_uuid)
    .fetch_optional(pool)
    .await
    .map_err(|_| ChatFailure::storage(ENDPOINT))?;

    let Some((device_status, current_auth_gen)) = device_row else {
        return Err(ChatFailure::protocol(
            ENDPOINT,
            ChatProtocolErrorCode::DeviceNotRegistered,
        ));
    };
    if device_status == "revoked" {
        return Err(ChatFailure::protocol(
            ENDPOINT,
            ChatProtocolErrorCode::DeviceRevoked,
        ));
    }
    if device_status != "active" || current_auth_gen != input.auth_generation {
        return Err(ChatFailure::protocol(
            ENDPOINT,
            ChatProtocolErrorCode::NotAuthorized,
        ));
    }

    let key_row: Option<(Vec<u8>, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT signing_public_key, revoked_at \
           FROM chat.device_keys \
          WHERE user_did = $1 AND device_id = $2 AND key_id = $3",
    )
    .bind(&user_did)
    .bind(device_uuid)
    .bind(key_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| ChatFailure::storage(ENDPOINT))?;

    let Some((pubkey_bytes, key_revoked_at)) = key_row else {
        return Err(ChatFailure::protocol(
            ENDPOINT,
            ChatProtocolErrorCode::InvalidSignature,
        ));
    };
    if key_revoked_at.is_some() {
        return Err(ChatFailure::protocol(
            ENDPOINT,
            ChatProtocolErrorCode::DeviceRevoked,
        ));
    }

    let pubkey_arr: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| ChatFailure::invariant(ENDPOINT))?;
    let verifying_key =
        VerifyingKey::from_bytes(&pubkey_arr).map_err(|_| ChatFailure::invariant(ENDPOINT))?;
    let sig_arr: [u8; 64] =
        input.signature.as_ref().try_into().map_err(|_| {
            ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidSignature)
        })?;
    let signature = Signature::from_bytes(&sig_arr);

    let transcript = build_push_gateway_transcript(
        &device_uuid,
        key_id,
        input.auth_generation,
        gateway_url,
        app_id,
        push_key,
        enabled,
        signed_at_str,
    )
    .map_err(|_| ChatFailure::invariant(ENDPOINT))?;

    verifying_key
        .verify(&transcript, &signature)
        .map_err(|_| ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::InvalidSignature))?;

    let now: DateTime<Utc> =
        sqlx::query_scalar("SELECT date_trunc('milliseconds', clock_timestamp())")
            .fetch_one(pool)
            .await
            .map_err(|_| ChatFailure::storage(ENDPOINT))?;

    if enabled {
        sqlx::query(
            "INSERT INTO chat.push_gateway_bindings ( \
                 user_did, device_id, gateway_url, app_id, push_key, \
                 key_id, auth_generation, signed_at, updated_at \
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (user_did, device_id) DO UPDATE SET \
                 gateway_url = EXCLUDED.gateway_url, \
                 app_id = EXCLUDED.app_id, \
                 push_key = EXCLUDED.push_key, \
                 key_id = EXCLUDED.key_id, \
                 auth_generation = EXCLUDED.auth_generation, \
                 signed_at = EXCLUDED.signed_at, \
                 updated_at = EXCLUDED.updated_at",
        )
        .bind(&user_did)
        .bind(device_uuid)
        .bind(gateway_url)
        .bind(app_id)
        .bind(push_key)
        .bind(key_id)
        .bind(input.auth_generation)
        .bind(signed_at)
        .bind(now)
        .execute(pool)
        .await
        .map_err(|_| ChatFailure::storage(ENDPOINT))?;
    } else {
        sqlx::query(
            "DELETE FROM chat.push_gateway_bindings WHERE user_did = $1 AND device_id = $2",
        )
        .bind(&user_did)
        .bind(device_uuid)
        .execute(pool)
        .await
        .map_err(|_| ChatFailure::storage(ENDPOINT))?;
    }

    let response_bytes = serde_json::to_vec(&json!({
        "registeredAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
    }))
    .map_err(|_| ChatFailure::invariant(ENDPOINT))?;
    context::canonical_json_response(ENDPOINT, 200, response_bytes)
}
