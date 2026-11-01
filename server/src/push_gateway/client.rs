//! Outbound `blue.catbird.push.deliver` Push Gateway client (`D2`, `I12`).
//!
//! Enforces:
//! - `INLINE_CIPHERTEXT_MAX_BYTES = 2200` (`I12`): `ciphertext` is embedded iff `len <= 2200` bytes;
//!   larger frames omit `ciphertext` so iOS NSE / Android FCM wakes fetch via `getEntries`.
//! - Zero display strings (`senderHandle`, `title`, `body`, `conversationTitle`) ever leave `mls-ds`.
//! - Home-`mls-ds`-only privacy (`D2`): `mls-ds` ONLY wakes devices whose `user_did` is homed on
//!   this `mls-ds` (never remote federated participants).
//! - DNS-pinned HTTPS client per target host (zero redirects) and `#atproto` ES256 DID-JWT auth
//!   (`lxm = "blue.catbird.push.deliver"`).
//! - Immediate `chat.push_gateway_bindings` pruning when the Push Gateway returns `410 Gone` (`PushTokenGone`).

use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use catbird_atproto::generated::blue_catbird::push::deliver::{
    Deliver, WakePayload, WakePayloadWakeKind,
};
use chrono::Utc;
use jacquard_common::deps::bytes::Bytes;
use p256::ecdsa::{signature::Signer, Signature, SigningKey as P256SigningKey};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use sqlx::FromRow;
use uuid::Uuid;

use super::ssrf::validate_push_gateway_url;
use crate::storage::DbPool;

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

/// Maximum MLS `PrivateMessage` ciphertext size (`2,200` bytes) eligible for inline embedding (`I12`).
pub const INLINE_CIPHERTEXT_MAX_BYTES: usize = 2_200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushWakeKind {
    ApplicationMessage,
    ControlTransition,
    DirectRequest,
    Welcome,
}

impl PushWakeKind {
    fn to_generated(self) -> WakePayloadWakeKind {
        match self {
            Self::ApplicationMessage => WakePayloadWakeKind::ApplicationMessage,
            Self::ControlTransition => WakePayloadWakeKind::ControlTransition,
            Self::DirectRequest => WakePayloadWakeKind::DirectRequest,
            Self::Welcome => WakePayloadWakeKind::Welcome,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PushWakeDispatch {
    pub wake_kind: PushWakeKind,
    pub conversation_id: Uuid,
    pub generation: i64,
    pub seq: i64,
    pub epoch: i64,
    pub ciphertext: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct PushGatewayClient {
    service_did: String,
    signing_key: P256SigningKey,
}

#[derive(Debug, FromRow)]
struct LocalGatewayBindingRow {
    user_did: String,
    device_id: Uuid,
    gateway_url: String,
    app_id: String,
    push_key: String,
}

impl PushGatewayClient {
    pub fn new_es256(service_did: String, signing_key: P256SigningKey) -> Self {
        Self {
            service_did: crate::identity::canonical_did(&service_did).to_string(),
            signing_key,
        }
    }

    pub fn from_pem(service_did: String, signing_key_pem: &str) -> Result<Self, String> {
        use p256::pkcs8::DecodePrivateKey as _;
        let key = P256SigningKey::from_pkcs8_pem(signing_key_pem)
            .map_err(|e| format!("invalid ES256 PKCS#8 key for PushGatewayClient: {e}"))?;
        Ok(Self::new_es256(service_did, key))
    }

    fn mint_deliver_jwt(
        &self,
        gateway_origin_or_aud: &str,
        canonical_gateway_url: &str,
        body_sha256: &str,
    ) -> Result<String, String> {
        let now = Utc::now().timestamp();
        let header = URL_SAFE_NO_PAD
            .encode(br##"{"alg":"ES256","typ":"atproto-push-wake+jwt","kid":"#atproto"}"##);
        let claims = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "iss": self.service_did,
                "aud": gateway_origin_or_aud,
                "lxm": "blue.catbird.push.deliver",
                "htm": "POST",
                "htu": canonical_gateway_url,
                "body_sha256": body_sha256,
                "iat": now,
                "exp": now + 60,
                "jti": Uuid::new_v4().to_string(),
            }))
            .map_err(|e| e.to_string())?,
        );
        let signing_input = format!("{header}.{claims}");
        let sig: Signature = self.signing_key.sign(signing_input.as_bytes());
        let norm = sig.normalize_s().unwrap_or(sig);
        Ok(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(norm.to_bytes())
        ))
    }

    /// Dispatch push wakes strictly for recipient `(user_did, device_id)` pairs homed on THIS `mls-ds` (`D2`).
    /// Prunes any binding that returns `410 Gone` (`PushTokenGone`).
    pub async fn dispatch_for_local_recipients(
        &self,
        pool: &DbPool,
        candidates: &[(String, Uuid)],
        wake: PushWakeDispatch,
    ) -> Result<usize, String> {
        if candidates.is_empty() {
            return Ok(0);
        }

        let inline_ct = wake
            .ciphertext
            .filter(|bytes| bytes.len() <= INLINE_CIPHERTEXT_MAX_BYTES)
            .map(Bytes::from);

        let payload = WakePayload {
            wake_kind: wake.wake_kind.to_generated(),
            conversation_id: wake.conversation_id.to_string().into(),
            generation: wake.generation,
            seq: wake.seq,
            epoch: wake.epoch,
            ciphertext: inline_ct,
            extra_data: None,
        };

        let mut delivered = 0_usize;
        for (user_did, device_id) in candidates {
            // D2 home-DS-only check: if `public.did_ds_mappings` explicitly maps `user_did` to a
            // different DS DID, this DS is NOT the user's home DS and MUST NOT send push wakes!
            let mapped_ds: Option<String> = sqlx::query_scalar(
                "SELECT ds_did FROM public.did_ds_mappings WHERE actor_did = $1 AND expires_at > NOW()",
            )
            .bind(user_did)
            .fetch_optional(pool)
            .await
            .map_err(|e| format!("query did_ds_mappings: {e}"))?;

            if let Some(ds_did) = mapped_ds {
                if crate::identity::canonical_did(&ds_did) != self.service_did {
                    continue;
                }
            }

            let binding: Option<LocalGatewayBindingRow> = sqlx::query_as(
                "SELECT b.user_did, b.device_id, b.gateway_url, b.app_id, b.push_key \
                   FROM chat.push_gateway_bindings b \
                   JOIN chat.devices d ON d.user_did = b.user_did AND d.device_id = b.device_id \
                  WHERE b.user_did = $1 AND b.device_id = $2 AND d.status = 'active'",
            )
            .bind(user_did)
            .bind(device_id)
            .fetch_optional(pool)
            .await
            .map_err(|e| format!("query push_gateway_bindings: {e}"))?;

            let Some(binding) = binding else {
                continue;
            };

            let validated = validate_push_gateway_url(&binding.gateway_url)
                .map_err(|e| format!("push gateway SSRF check failed: {e}"))?;

            let mut client_builder = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(10));
            if !validated.is_test_override && !validated.pinned_addrs.is_empty() {
                client_builder =
                    client_builder.resolve_to_addrs(&validated.host, &validated.pinned_addrs);
            }
            let http_client = client_builder.build().map_err(|e| e.to_string())?;

            let req_body = Deliver {
                app_id: binding.app_id.clone().into(),
                push_key: binding.push_key.clone().into(),
                payload: payload.clone(),
                extra_data: None,
            };
            let body_bytes = serde_json::to_vec(&req_body).map_err(|e| e.to_string())?;
            let body_sha256 = hex_lower(&Sha256::digest(&body_bytes));

            let aud_did = format!("did:web:{}", validated.host);
            let jwt = self.mint_deliver_jwt(&aud_did, &binding.gateway_url, &body_sha256)?;

            let resp = http_client
                .post(&validated.effective_url)
                .header(reqwest::header::AUTHORIZATION, format!("Bearer {jwt}"))
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body_bytes)
                .send()
                .await
                .map_err(|e| format!("push gateway POST failed: {e}"))?;

            let status = resp.status();
            if status == reqwest::StatusCode::GONE {
                sqlx::query(
                    "DELETE FROM chat.push_gateway_bindings WHERE user_did = $1 AND device_id = $2 AND push_key = $3",
                )
                .bind(&binding.user_did)
                .bind(binding.device_id)
                .bind(&binding.push_key)
                .execute(pool)
                .await
                .map_err(|e| format!("prune 410 push_gateway_bindings: {e}"))?;
            } else if status.is_success() {
                delivered += 1;
            } else {
                return Err(format!(
                    "push gateway returned unexpected status {}",
                    status.as_u16()
                ));
            }
        }

        Ok(delivered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_deliver_jwt_binds_htm_htu_and_exact_http_body_sha256() {
        let mut key_bytes = [0u8; 32];
        key_bytes[31] = 7;
        let signing_key = P256SigningKey::from_bytes((&key_bytes).into()).expect("valid P-256 key");
        let client = PushGatewayClient::new_es256(
            "did:web:chat.catbird.blue#atproto_mls".to_string(),
            signing_key,
        );

        let gateway_url = "https://api.catbird.blue/xrpc/blue.catbird.push.deliver";
        let req_body: Deliver = Deliver {
            app_id: "blue.catbird.ios".into(),
            push_key: "pk_test_1234567890abcdef".into(),
            payload: WakePayload {
                wake_kind: WakePayloadWakeKind::ApplicationMessage,
                conversation_id: Uuid::nil().to_string().into(),
                generation: 1,
                seq: 42,
                epoch: 3,
                ciphertext: Some(Bytes::from_static(b"mls-private-message")),
                extra_data: None,
            },
            extra_data: None,
        };
        let body_bytes = serde_json::to_vec(&req_body).expect("serialize Deliver");
        let expected_sha = hex_lower(&Sha256::digest(&body_bytes));

        let jwt = client
            .mint_deliver_jwt("did:web:api.catbird.blue", gateway_url, &expected_sha)
            .expect("mint_deliver_jwt");
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);

        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).expect("b64url header"))
                .expect("json header");
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["typ"], "atproto-push-wake+jwt");
        assert_eq!(header["kid"], "#atproto");

        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).expect("b64url claims"))
                .expect("json claims");
        assert_eq!(claims["iss"], "did:web:chat.catbird.blue");
        assert_eq!(claims["aud"], "did:web:api.catbird.blue");
        assert_eq!(claims["lxm"], "blue.catbird.push.deliver");
        assert_eq!(claims["htm"], "POST");
        assert_eq!(claims["htu"], gateway_url);
        assert_eq!(claims["body_sha256"], expected_sha);
    }
}
