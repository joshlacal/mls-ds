//! Ed25519 device-signed read authentication (`M-F07`).
//!
//! Every `blue.catbird.chat.*` GET read carries:
//! - `catbird-chat-read`: URL-safe unpadded base64 of UTF-8 JSON [`ReadClaim`]
//! - `catbird-chat-read-signature`: URL-safe unpadded base64 of the 64-byte
//!   Ed25519 signature over `b"CATBIRD-CHAT-READ\0" || claim_bytes` produced by
//!   the active `chat.device_keys` signing key of `(did, device_id)`.

use axum::http::HeaderMap;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    chat_protocol::{
        error::{ChatEndpoint, ChatProtocolErrorCode},
        transcript::verify_ed25519_strict,
    },
    handlers::chat::ChatFailure,
    storage::DbPool,
};

pub const CHAT_READ_HEADER: &str = "catbird-chat-read";
pub const CHAT_READ_SIG_HEADER: &str = "catbird-chat-read-signature";
pub const CHAT_READ_DOMAIN: &[u8] = b"CATBIRD-CHAT-READ\0";
pub(crate) const INTERNAL_CANONICAL_QUERY_HEADER: &str = "x-catbird-internal-canonical-query";

const MAX_READ_CLAIM_SKEW_MS: i64 = 300_000;
const MAX_READ_CLAIM_BYTES: usize = 4_096;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReadClaim {
    pub v: u8,
    pub nsid: String,
    pub query: String,
    pub did: String,
    #[serde(rename = "deviceId")]
    pub device_id: String,
    #[serde(rename = "issuedAt")]
    pub issued_at: i64,
}

/// Canonicalize a raw URL query string by decoding `(key, value)` pairs, sorting
/// lexicographically by `(key, value)`, and re-encoding via `application/x-www-form-urlencoded`.
#[must_use]
pub fn canonical_query(raw: Option<&str>) -> String {
    let Some(raw) = raw.filter(|s| !s.is_empty()) else {
        return String::new();
    };
    let mut pairs: Vec<(String, String)> = url::form_urlencoded::parse(raw.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    pairs.sort();
    let mut ser = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        ser.append_pair(&k, &v);
    }
    ser.finish()
}

pub(crate) fn has_any_read_auth_header(headers: &HeaderMap) -> bool {
    headers.contains_key(CHAT_READ_HEADER) || headers.contains_key(CHAT_READ_SIG_HEADER)
}

pub(crate) async fn verify_chat_read_headers(
    pool: &DbPool,
    endpoint: ChatEndpoint,
    principal_did: &str,
    actor_device_id: &str,
    headers: &HeaderMap,
) -> Result<(), ChatFailure> {
    let raw_claim = headers
        .get(CHAT_READ_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::NotAuthorized))?;
    let raw_sig = headers
        .get(CHAT_READ_SIG_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::NotAuthorized))?;

    let claim_bytes = URL_SAFE_NO_PAD
        .decode(raw_claim.trim())
        .map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::NotAuthorized))?;
    if claim_bytes.is_empty() || claim_bytes.len() > MAX_READ_CLAIM_BYTES {
        return Err(ChatFailure::protocol(
            endpoint,
            ChatProtocolErrorCode::InvalidRequest,
        ));
    }
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(raw_sig.trim())
        .map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::NotAuthorized))?;
    if sig_bytes.len() != 64 {
        return Err(ChatFailure::protocol(
            endpoint,
            ChatProtocolErrorCode::NotAuthorized,
        ));
    }

    let claim: ReadClaim = serde_json::from_slice(&claim_bytes)
        .map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;
    if claim.v != 1
        || claim.nsid != endpoint.nsid()
        || claim.did != principal_did
        || claim.device_id != actor_device_id
    {
        return Err(ChatFailure::protocol(
            endpoint,
            ChatProtocolErrorCode::NotAuthorized,
        ));
    }

    if let Some(expected_query) = headers
        .get(INTERNAL_CANONICAL_QUERY_HEADER)
        .and_then(|v| v.to_str().ok())
    {
        if claim.query != expected_query {
            return Err(ChatFailure::protocol(
                endpoint,
                ChatProtocolErrorCode::InvalidRequest,
            ));
        }
    }

    let now_ms = Utc::now().timestamp_millis();
    if (now_ms - claim.issued_at).abs() > MAX_READ_CLAIM_SKEW_MS {
        return Err(ChatFailure::protocol(
            endpoint,
            ChatProtocolErrorCode::NotAuthorized,
        ));
    }

    let device_uuid = Uuid::parse_str(actor_device_id)
        .map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::InvalidRequest))?;

    let key_row: Option<(String, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT d.status, dk.signing_public_key \
         FROM chat.devices d \
         LEFT JOIN chat.device_keys dk \
           ON dk.user_did = d.user_did \
          AND dk.device_id = d.device_id \
          AND dk.enrollment_auth_generation = d.auth_generation \
         WHERE d.user_did = $1 AND d.device_id = $2",
    )
    .bind(principal_did)
    .bind(device_uuid)
    .fetch_optional(pool)
    .await
    .map_err(|_| ChatFailure::storage(endpoint))?;

    let Some((status, pubkey_opt)) = key_row else {
        return Err(ChatFailure::protocol(
            endpoint,
            ChatProtocolErrorCode::DeviceNotRegistered,
        ));
    };
    if status != "active" {
        return Err(ChatFailure::protocol(
            endpoint,
            ChatProtocolErrorCode::DeviceRevoked,
        ));
    }
    let Some(pubkey) = pubkey_opt.filter(|k| k.len() == 32) else {
        return Err(ChatFailure::protocol(
            endpoint,
            ChatProtocolErrorCode::NotAuthorized,
        ));
    };

    let mut transcript = Vec::with_capacity(CHAT_READ_DOMAIN.len() + claim_bytes.len());
    transcript.extend_from_slice(CHAT_READ_DOMAIN);
    transcript.extend_from_slice(&claim_bytes);
    verify_ed25519_strict(&pubkey, &transcript, &sig_bytes)
        .map_err(|_| ChatFailure::protocol(endpoint, ChatProtocolErrorCode::NotAuthorized))?;

    let _ = sqlx::query(
        "UPDATE chat.devices \
         SET last_active_at = clock_timestamp(), dormant_at = NULL \
         WHERE user_did = $1 AND device_id = $2 AND status = 'active'",
    )
    .bind(principal_did)
    .bind(device_uuid)
    .execute(pool)
    .await;

    Ok(())
}
