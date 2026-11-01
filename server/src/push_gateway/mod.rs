//! Push Gateway (`D2`, `I12`, `M-F06`) client, SSRF validator, and transcript builder.
//!
//! `mls-ds` stores zero APNs/FCM credentials and zero raw device push tokens.
//! Instead, each enrolled device registers an opaque `pushKey` + `gatewayUrl`
//! (`https://<host>/xrpc/blue.catbird.push.deliver`) signed under
//! `CATBIRD-CHAT-PUSH-GATEWAY\0`. Only the recipient's home `mls-ds` dispatches
//! wakes to that device's Push Gateway (`nest` for Catbird first-party clients).

pub mod client;
pub mod ssrf;

use serde::Serialize;
use uuid::Uuid;

pub const PUSH_GATEWAY_SIGNATURE_DOMAIN: &[u8] = b"CATBIRD-CHAT-PUSH-GATEWAY\0";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PushGatewayTranscriptPayload<'a> {
    app_id: &'a str,
    auth_generation: i64,
    device_id: String,
    enabled: bool,
    gateway_url: &'a str,
    key_id: &'a str,
    push_key: &'a str,
    signed_at: &'a str,
}

/// Build the canonical `CATBIRD-CHAT-PUSH-GATEWAY\0 || DAG-CBOR(...)` byte transcript
/// signed by the enrolled device's Ed25519 key when calling `blue.catbird.chat.registerPushGateway`.
pub fn build_push_gateway_transcript(
    device_id: &Uuid,
    key_id: &str,
    auth_generation: i64,
    gateway_url: &str,
    app_id: &str,
    push_key: &str,
    enabled: bool,
    signed_at: &str,
) -> Result<Vec<u8>, String> {
    let payload = PushGatewayTranscriptPayload {
        app_id,
        auth_generation,
        device_id: device_id.to_string(),
        enabled,
        gateway_url,
        key_id,
        push_key,
        signed_at,
    };
    let cbor = serde_ipld_dagcbor::to_vec(&payload)
        .map_err(|e| format!("encode push gateway transcript DAG-CBOR: {e}"))?;
    let mut out = Vec::with_capacity(PUSH_GATEWAY_SIGNATURE_DOMAIN.len() + cbor.len());
    out.extend_from_slice(PUSH_GATEWAY_SIGNATURE_DOMAIN);
    out.extend_from_slice(&cbor);
    Ok(out)
}
