//! Pure ES256 service-auth signing helpers shared by federation test fixtures.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use p256::ecdsa::{signature::Signer, Signature as P256Signature, SigningKey};
use serde_json::json;
use uuid::Uuid;

/// Mint an ES256 service JWT with an explicit audience, endpoint, jti, and lifetime.
pub fn mint_jwt_with_lifetime(
    issuer: &str,
    key: &SigningKey,
    audience: &str,
    endpoint_nsid: &str,
    custom_jti: Option<&str>,
    lifetime_secs: i64,
) -> String {
    let now = Utc::now().timestamp();
    let jti = custom_jti
        .map(|s| s.to_string())
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let header = json!({
        "alg": "ES256",
        "typ": "JWT",
        "kid": format!("{issuer}#atproto")
    });
    let claims = json!({
        "iss": issuer,
        "sub": issuer,
        "aud": audience,
        "lxm": endpoint_nsid,
        "iat": now,
        "exp": now + lifetime_secs,
        "jti": jti
    });

    let h_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let c_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{h_b64}.{c_b64}");
    let signature: P256Signature = key.sign(signing_input.as_bytes());
    let sig_bytes = signature.to_bytes();
    let s_b64 = URL_SAFE_NO_PAD.encode(sig_bytes);
    format!("{signing_input}.{s_b64}")
}

/// Mint a 50-second ES256 JWT for the destination node's MLS AppView service.
pub fn mint_chat_jwt(
    issuer: &str,
    key: &SigningKey,
    destination_service_did: &str,
    endpoint_nsid: &str,
) -> String {
    let audience = format!("{destination_service_did}#atproto_mls");
    mint_jwt_with_lifetime(issuer, key, &audience, endpoint_nsid, None, 50)
}
