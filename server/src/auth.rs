use axum::{
    extract::FromRef,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use moka::future::Cache;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{num::NonZeroU32, sync::Arc};
use thiserror::Error;
use tracing::debug;

use crate::identity::{canonical_did, did_web_document_url};

// ADR-016 remains endpoint-opt-in during observe/enroll rollout. Keeping the
// foundation under auth prevents it from becoming implicit transition policy.
#[path = "auth_device.rs"]
pub mod device_auth;

/// Authentication errors
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Missing authorization header")]
    MissingAuthHeader,

    #[error("Invalid authorization header format")]
    InvalidAuthFormat,

    #[error("Invalid JWT token: {0}")]
    InvalidToken(String),

    #[error("Token has expired")]
    TokenExpired,

    #[error("Invalid DID format: {0}")]
    InvalidDid(String),

    #[error("Failed to resolve DID document: {0}")]
    DidResolutionFailed(String),

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Rate limit exceeded (retry after {retry_after_secs}s)")]
    RateLimitExceeded { retry_after_secs: u64 },

    #[error("DID document missing verification method")]
    MissingVerificationMethod,

    #[error("Unsupported key type: {0}")]
    UnsupportedKeyType(String),

    #[error("Missing jti claim")]
    MissingJti,

    #[error("Replay detected")]
    ReplayDetected,

    #[error("Missing lxm claim")]
    MissingLxm,

    #[error("lxm does not match endpoint")]
    LxmMismatch,

    #[error("Internal error: {0}")]
    Internal(String),
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        // ATProto-compatible error format: { "error": "ErrorName", "message": "Human-readable" }
        let (status, error_name, error_message) = match &self {
            AuthError::MissingAuthHeader => {
                (StatusCode::UNAUTHORIZED, "AuthMissing", self.to_string())
            }
            AuthError::InvalidAuthFormat => {
                (StatusCode::UNAUTHORIZED, "InvalidAuth", self.to_string())
            }
            AuthError::InvalidToken(_) => {
                (StatusCode::UNAUTHORIZED, "InvalidToken", self.to_string())
            }
            AuthError::TokenExpired => (StatusCode::UNAUTHORIZED, "ExpiredToken", self.to_string()),
            AuthError::InvalidDid(_) => (StatusCode::BAD_REQUEST, "InvalidDid", self.to_string()),
            AuthError::DidResolutionFailed(_) => (
                StatusCode::BAD_REQUEST,
                "DidResolutionFailed",
                self.to_string(),
            ),
            AuthError::InvalidSignature => (
                StatusCode::UNAUTHORIZED,
                "InvalidSignature",
                self.to_string(),
            ),
            AuthError::RateLimitExceeded { .. } => (
                StatusCode::TOO_MANY_REQUESTS,
                "RateLimitExceeded",
                self.to_string(),
            ),
            AuthError::MissingVerificationMethod => (
                StatusCode::BAD_REQUEST,
                "MissingVerificationMethod",
                self.to_string(),
            ),
            AuthError::UnsupportedKeyType(_) => (
                StatusCode::BAD_REQUEST,
                "UnsupportedKeyType",
                self.to_string(),
            ),
            AuthError::MissingJti => (StatusCode::UNAUTHORIZED, "MissingJti", self.to_string()),
            AuthError::ReplayDetected => {
                (StatusCode::UNAUTHORIZED, "ReplayDetected", self.to_string())
            }
            AuthError::MissingLxm => (StatusCode::UNAUTHORIZED, "MissingLxm", self.to_string()),
            AuthError::LxmMismatch => (StatusCode::UNAUTHORIZED, "LxmMismatch", self.to_string()),
            AuthError::Internal(e) => {
                tracing::error!("Internal auth error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    format!("Internal error: {}", e),
                )
            }
        };

        if status.is_server_error() {
            tracing::error!(
                status = %status,
                error = %error_message,
                "Returning server error for auth failure"
            );
        } else if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            tracing::warn!(
                status = %status,
                error = %error_message,
                "Auth failure"
            );
        }

        let body = Json(json!({
            "error": error_name,
            "message": error_message,
        }));

        let mut resp = (status, body).into_response();

        // Attach Retry-After header for rate limit responses
        if let AuthError::RateLimitExceeded { retry_after_secs } = &self {
            if let Ok(val) = axum::http::HeaderValue::from_str(&retry_after_secs.to_string()) {
                resp.headers_mut()
                    .insert(axum::http::header::RETRY_AFTER, val);
            }
        }

        resp
    }
}

/// AT Protocol JWT claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtProtoClaims {
    pub iss: String,         // Issuer (DID)
    pub aud: String,         // Audience (service DID or URL)
    pub exp: i64,            // Expiration time
    pub iat: Option<i64>,    // Issued at
    pub sub: Option<String>, // Subject (can be same as iss)
    pub lxm: Option<String>, // Optional: authorized endpoint NSID
    pub jti: Option<String>, // Optional: nonce for replay-prevention
}

#[derive(Debug, Clone, Deserialize)]
struct JwtHeader {
    alg: String,
    #[allow(dead_code)]
    typ: Option<String>,
    #[allow(dead_code)]
    kid: Option<String>,
}

/// DID Document (simplified for AT Protocol)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDocument {
    pub id: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,
    pub service: Option<Vec<Service>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub key_type: String,
    pub controller: String,
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: Option<String>,
    #[serde(rename = "publicKeyJwk")]
    pub public_key_jwk: Option<PublicKeyJwk>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    pub id: String,
    #[serde(rename = "type")]
    pub service_type: String,
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
}

/// Cached DID document with expiration
#[derive(Debug, Clone)]
pub struct CachedDidDoc {
    doc: DidDocument,
    /// Insertion timestamp. Currently only consumed via Debug; kept as a future
    /// hook for staleness assertions and cache-introspection logging.
    /// TODO(phase-2.5-cleanup): wire into `/health/auth-cache` diagnostics or remove.
    #[allow(dead_code)]
    cached_at: DateTime<Utc>,
}

/// Authenticated user extracted from request
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub did: String,
    pub claims: AtProtoClaims,
}

/// Opaque exact bearer artifact produced only after `AuthMiddleware` accepts
/// the token signature and standard claims. Debug output never exposes it.
#[derive(Clone)]
pub struct VerifiedGatewayBearer {
    claims: AtProtoClaims,
    token: String,
    effective_user_did: String,
    delegated_gateway: bool,
}

impl std::fmt::Debug for VerifiedGatewayBearer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedGatewayBearer")
            .field("issuer", &crate::crypto::redact_for_log(&self.claims.iss))
            .field("token", &"<redacted>")
            .finish()
    }
}

/// Authentication middleware state
#[derive(Clone)]
pub struct AuthMiddleware {
    did_cache: Cache<String, CachedDidDoc>,
    rate_limiters:
        Arc<moka::sync::Cache<String, Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>>>,
    http_client: reqwest::Client,
    /// Stored TTL value used to construct `did_cache` (moka's `time_to_live`).
    /// Not read after construction today, but useful for diagnostics endpoints
    /// and future on-demand TTL reconfiguration without rebuilding the cache.
    /// TODO(phase-2.5-cleanup): expose via diagnostics or drop the field.
    #[allow(dead_code)]
    cache_ttl_seconds: u64,
    rate_limit_quota: Quota,
    did_host_allowlist: Option<Vec<String>>,
    #[cfg(test)]
    test_service_did: Option<String>,
}

impl AuthMiddleware {
    pub fn new() -> Self {
        let rate_limit = std::env::var("AUTH_RATE_LIMIT_PER_SECOND")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(100);
        Self::with_config(300, rate_limit, 60)
    }

    pub fn with_config(
        cache_ttl_seconds: u64,
        rate_limit_requests: u32,
        _rate_limit_period_seconds: u64,
    ) -> Self {
        let did_resolution_timeout_seconds = std::env::var("DID_RESOLUTION_TIMEOUT_SECONDS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(10);
        let did_host_allowlist = parse_host_allowlist("DID_RESOLUTION_HOST_ALLOWLIST");

        let did_cache = Cache::builder()
            .max_capacity(10_000)
            .time_to_live(std::time::Duration::from_secs(cache_ttl_seconds))
            .build();

        // SAFETY: rate_limit_requests.max(1) is always >= 1, so NonZeroU32::new() cannot fail
        let quota = Quota::per_second(
            NonZeroU32::new(rate_limit_requests.max(1))
                .expect("BUG: rate_limit_requests.max(1) should always be >= 1"),
        )
        .allow_burst(
            NonZeroU32::new((rate_limit_requests.max(1) / 10).max(1))
                .expect("BUG: burst calculation should always be >= 1"),
        );

        Self {
            did_cache,
            rate_limiters: Arc::new(
                moka::sync::Cache::builder()
                    .max_capacity(50_000)
                    .time_to_live(std::time::Duration::from_secs(300))
                    .build(),
            ),
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(
                    did_resolution_timeout_seconds,
                ))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            cache_ttl_seconds,
            rate_limit_quota: quota,
            did_host_allowlist,
            #[cfg(test)]
            test_service_did: None,
        }
    }

    #[cfg(test)]
    fn with_test_service_did(mut self, service_did: &str) -> Self {
        self.test_service_did = Some(service_did.to_string());
        self
    }

    /// Verify JWT token and extract claims.
    pub async fn verify_jwt(&self, token: &str) -> Result<AtProtoClaims, AuthError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(AuthError::InvalidToken("Invalid JWT format".into()));
        }

        let header_json = URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|e| AuthError::InvalidToken(format!("Invalid base64 header: {}", e)))?;
        let payload_json = URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|e| AuthError::InvalidToken(format!("Invalid base64 payload: {}", e)))?;

        let header: JwtHeader = serde_json::from_slice(&header_json)
            .map_err(|e| AuthError::InvalidToken(format!("Invalid header JSON: {}", e)))?;
        let claims: AtProtoClaims = serde_json::from_slice(&payload_json)
            .map_err(|e| AuthError::InvalidToken(format!("Invalid claims JSON: {}", e)))?;
        let issuer_did = canonical_did(&claims.iss);

        // Do not log full identities or tokens at info level
        tracing::debug!(
            iss = %crate::crypto::redact_for_log(issuer_did),
            aud = %crate::crypto::redact_for_log(&claims.aud),
            exp = claims.exp,
            has_lxm = claims.lxm.is_some(),
            has_jti = claims.jti.is_some(),
            "Parsed JWT claims"
        );

        // Expiration
        let now = Utc::now().timestamp();
        if claims.exp < now {
            return Err(AuthError::TokenExpired);
        }

        // Audience enforcement when configured
        #[cfg(test)]
        let service_did = self
            .test_service_did
            .clone()
            .or_else(|| std::env::var("SERVICE_DID").ok());
        #[cfg(not(test))]
        let service_did = std::env::var("SERVICE_DID").ok();
        if let Some(service_did) = service_did {
            tracing::debug!("Validating JWT audience against configured SERVICE_DID");
            if claims.aud != service_did {
                tracing::warn!("JWT audience mismatch with SERVICE_DID");
                return Err(AuthError::InvalidToken(
                    "aud does not match SERVICE_DID".into(),
                ));
            }
        }

        let signing_input = format!("{}.{}", parts[0], parts[1]);

        match header.alg.as_str() {
            // ES256: P-256 ECDSA (JOSE signature R||S)
            "ES256" => {
                use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
                use p256::EncodedPoint;
                let did_doc = self.resolve_did(issuer_did).await?;
                let vm = select_verification_method(&did_doc, header.kid.as_deref())?;
                let jwk = vm
                    .public_key_jwk
                    .as_ref()
                    .ok_or(AuthError::MissingVerificationMethod)?;
                if jwk.kty != "EC" || !jwk.crv.eq_ignore_ascii_case("P-256") {
                    return Err(AuthError::UnsupportedKeyType(format!(
                        "Expected EC P-256, got {} {}",
                        jwk.kty, jwk.crv
                    )));
                }
                let x = URL_SAFE_NO_PAD
                    .decode(&jwk.x)
                    .map_err(|e| AuthError::InvalidToken(format!("bad jwk.x: {}", e)))?;
                let y = URL_SAFE_NO_PAD
                    .decode(jwk.y.as_ref().ok_or(AuthError::MissingVerificationMethod)?)
                    .map_err(|e| AuthError::InvalidToken(format!("bad jwk.y: {}", e)))?;
                let ep = EncodedPoint::from_affine_coordinates(
                    p256::FieldBytes::from_slice(&x),
                    p256::FieldBytes::from_slice(&y),
                    false,
                );
                let vk = VerifyingKey::from_encoded_point(&ep)
                    .map_err(|_| AuthError::InvalidToken("invalid P-256 point".into()))?;
                let sig_bytes = URL_SAFE_NO_PAD
                    .decode(parts[2])
                    .map_err(|e| AuthError::InvalidToken(format!("Invalid b64 sig: {}", e)))?;
                let sig = Signature::from_slice(&sig_bytes)
                    .map_err(|_| AuthError::InvalidToken("invalid ES256 signature".into()))?;
                vk.verify(signing_input.as_bytes(), &sig)
                    .map_err(|_| AuthError::InvalidSignature)?;
                Ok(claims)
            }
            // ES256K: secp256k1 ECDSA (R||S)
            "ES256K" => {
                use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
                let did_doc = self.resolve_did(issuer_did).await?;
                let vm = select_verification_method(&did_doc, header.kid.as_deref())?;

                // Extract public key from either Multikey or JWK format
                let key_bytes = Self::extract_secp256k1_key(vm)?;

                // Create verifying key from the public key bytes
                let vk = VerifyingKey::from_sec1_bytes(&key_bytes).map_err(|e| {
                    AuthError::InvalidToken(format!("invalid secp256k1 key: {}", e))
                })?;

                // Decode and verify signature
                let sig_bytes = URL_SAFE_NO_PAD
                    .decode(parts[2])
                    .map_err(|e| AuthError::InvalidToken(format!("Invalid b64 sig: {}", e)))?;
                let sig = Signature::from_slice(&sig_bytes)
                    .map_err(|_| AuthError::InvalidToken("invalid ES256K signature".into()))?;

                vk.verify(signing_input.as_bytes(), &sig)
                    .map_err(|_| AuthError::InvalidSignature)?;

                Ok(claims)
            }
            other => Err(AuthError::UnsupportedKeyType(format!(
                "Unsupported alg: {}",
                other
            ))),
        }
    }

    /// Extract secp256k1 public key bytes from DID verification method
    /// Supports both JWK and Multikey formats
    fn extract_secp256k1_key(vm: &VerificationMethod) -> Result<Vec<u8>, AuthError> {
        // Try Multikey format first (newer AT Protocol standard)
        if let Some(multibase) = &vm.public_key_multibase {
            return Self::decode_multikey_secp256k1(multibase);
        }

        // Fall back to JWK format (older)
        if let Some(jwk) = &vm.public_key_jwk {
            if jwk.kty != "EC" {
                return Err(AuthError::UnsupportedKeyType(format!(
                    "Expected EC, got {}",
                    jwk.kty
                )));
            }
            let crv = jwk.crv.to_ascii_lowercase();
            if crv != "secp256k1" && crv != "k-256" && crv != "p-256k" {
                return Err(AuthError::UnsupportedKeyType(format!(
                    "Expected secp256k1, got {}",
                    jwk.crv
                )));
            }

            let x = URL_SAFE_NO_PAD
                .decode(&jwk.x)
                .map_err(|e| AuthError::InvalidToken(format!("bad jwk.x: {}", e)))?;
            let y = URL_SAFE_NO_PAD
                .decode(jwk.y.as_ref().ok_or(AuthError::MissingVerificationMethod)?)
                .map_err(|e| AuthError::InvalidToken(format!("bad jwk.y: {}", e)))?;

            // Uncompressed point: 0x04 || x || y
            let mut key_bytes = Vec::with_capacity(65);
            key_bytes.push(0x04);
            key_bytes.extend_from_slice(&x);
            key_bytes.extend_from_slice(&y);
            return Ok(key_bytes);
        }

        Err(AuthError::MissingVerificationMethod)
    }

    /// Decode a Multikey format public key for secp256k1
    /// Format: multibase(multicodec || public_key_bytes)
    /// For secp256k1: multicodec = 0xe7 0x01 (varint encoded 0xe7 = secp256k1-pub)
    fn decode_multikey_secp256k1(multibase_str: &str) -> Result<Vec<u8>, AuthError> {
        // Decode multibase (z prefix = base58btc)
        let (_base, bytes) = multibase::decode(multibase_str)
            .map_err(|e| AuthError::InvalidToken(format!("multibase decode failed: {}", e)))?;

        // Check multicodec prefix for secp256k1-pub (0xe7, varint encoded as 0xe7 0x01)
        if bytes.len() < 2 {
            return Err(AuthError::InvalidToken("multikey too short".into()));
        }

        // secp256k1-pub multicodec: 0xe7 0x01
        if bytes[0] == 0xe7 && bytes[1] == 0x01 {
            // Compressed or uncompressed public key follows
            Ok(bytes[2..].to_vec())
        } else {
            Err(AuthError::UnsupportedKeyType(format!(
                "Expected secp256k1-pub multicodec (0xe7 0x01), got {:02x} {:02x}",
                bytes[0],
                bytes.get(1).unwrap_or(&0)
            )))
        }
    }

    /// Resolve DID document with caching
    pub async fn resolve_did(&self, did: &str) -> Result<DidDocument, AuthError> {
        // Validate DID format
        if !did.starts_with("did:") {
            return Err(AuthError::InvalidDid(format!(
                "DID must start with 'did:': {}",
                did
            )));
        }

        // Check cache first
        if let Some(cached) = self.did_cache.get(did).await {
            debug!(
                did = %crate::crypto::redact_for_log(did),
                "DID document cache hit"
            );
            return Ok(cached.doc);
        }

        debug!(
            did = %crate::crypto::redact_for_log(did),
            "Resolving DID document"
        );

        // Resolve based on DID method
        let doc = if did.starts_with("did:plc:") {
            self.resolve_plc_did(did).await?
        } else if did.starts_with("did:web:") {
            self.resolve_web_did(did).await?
        } else {
            return Err(AuthError::InvalidDid(format!(
                "Unsupported DID method: {}",
                did
            )));
        };

        // Cache the result
        let cached = CachedDidDoc {
            doc: doc.clone(),
            cached_at: Utc::now(),
        };
        self.did_cache.insert(did.to_string(), cached).await;

        Ok(doc)
    }

    /// Resolve did:plc DID via PLC directory
    async fn resolve_plc_did(&self, did: &str) -> Result<DidDocument, AuthError> {
        let _plc_id = did
            .strip_prefix("did:plc:")
            .ok_or_else(|| AuthError::InvalidDid(format!("Invalid PLC DID: {}", did)))?;
        let plc_host = "plc.directory";
        if let Some(allowlist) = &self.did_host_allowlist {
            if !host_is_allowlisted(plc_host, allowlist) {
                return Err(AuthError::DidResolutionFailed(
                    "plc.directory is not allowlisted".to_string(),
                ));
            }
        }
        validate_resolved_host_is_public(plc_host, 443).await?;
        let url = format!("https://plc.directory/{}", did);

        tracing::debug!(
            did = %crate::crypto::redact_for_log(did),
            "Resolving DID document via PLC directory"
        );

        let response = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| AuthError::DidResolutionFailed(format!("HTTP error: {}", e)))?;

        if !response.status().is_success() {
            tracing::error!(
                status = response.status().as_u16(),
                "Failed to resolve DID from PLC directory"
            );
            return Err(AuthError::DidResolutionFailed(format!(
                "PLC directory returned status {}",
                response.status()
            )));
        }

        let doc = response.json::<DidDocument>().await.map_err(|e| {
            AuthError::DidResolutionFailed(format!("Failed to parse DID document: {}", e))
        })?;

        Ok(doc)
    }

    /// Resolve did:web DID via HTTPS
    async fn resolve_web_did(&self, did: &str) -> Result<DidDocument, AuthError> {
        let url = did_web_document_url(did)
            .ok_or_else(|| AuthError::InvalidDid(format!("Invalid WEB DID: {}", did)))?;
        let parsed = url::Url::parse(&url).map_err(|e| {
            AuthError::DidResolutionFailed(format!("Invalid did:web URL for {}: {}", did, e))
        })?;
        let host = parsed.host_str().unwrap_or("");
        if is_disallowed_host(host) {
            return Err(AuthError::DidResolutionFailed(
                "disallowed did:web host".into(),
            ));
        }
        if let Some(allowlist) = &self.did_host_allowlist {
            if !host_is_allowlisted(host, allowlist) {
                return Err(AuthError::DidResolutionFailed(
                    "did:web host is not allowlisted".to_string(),
                ));
            }
        }
        let port = parsed.port_or_known_default().unwrap_or(443);
        validate_resolved_host_is_public(host, port).await?;

        let response = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| AuthError::DidResolutionFailed(format!("HTTP error: {}", e)))?;

        if !response.status().is_success() {
            return Err(AuthError::DidResolutionFailed(format!(
                "Web server returned status {}",
                response.status()
            )));
        }

        let doc = response.json::<DidDocument>().await.map_err(|e| {
            AuthError::DidResolutionFailed(format!("Failed to parse DID document: {}", e))
        })?;

        Ok(doc)
    }
    /// Check rate limit for a DID
    fn check_rate_limit(&self, did: &str) -> Result<(), AuthError> {
        let quota = self.rate_limit_quota;
        let limiter = self
            .rate_limiters
            .get_with(did.to_string(), || Arc::new(RateLimiter::direct(quota)));

        limiter.check().map_err(|_| AuthError::RateLimitExceeded {
            retry_after_secs: 1,
        })?;

        Ok(())
    }
}

impl Default for AuthMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

// -----------------------------------------------------------------------------
// P-256 key extraction helper
// -----------------------------------------------------------------------------

/// Extract the first P-256 [`p256::ecdsa::VerifyingKey`] from a DID document's
/// verification methods.  Works with both JWK (`publicKeyJwk`) and multikey
/// (`publicKeyMultibase`) representations.
pub fn extract_p256_key(did_doc: &DidDocument) -> Option<p256::ecdsa::VerifyingKey> {
    use p256::ecdsa::VerifyingKey;
    use p256::EncodedPoint;

    for vm in &did_doc.verification_method {
        // Try JWK first
        if let Some(ref jwk) = vm.public_key_jwk {
            if jwk.kty == "EC" && jwk.crv.eq_ignore_ascii_case("P-256") {
                let x = URL_SAFE_NO_PAD.decode(&jwk.x).ok()?;
                let y = URL_SAFE_NO_PAD.decode(jwk.y.as_ref()?).ok()?;
                let ep = EncodedPoint::from_affine_coordinates(
                    p256::FieldBytes::from_slice(&x),
                    p256::FieldBytes::from_slice(&y),
                    false,
                );
                if let Ok(vk) = VerifyingKey::from_encoded_point(&ep) {
                    return Some(vk);
                }
            }
        }

        // Try multibase (multicodec P-256 key: 0x80 0x24 prefix + 33-byte compressed key)
        if let Some(ref mb) = vm.public_key_multibase {
            if let Ok((_base, bytes)) = multibase::decode(mb) {
                if bytes.len() == 35 && bytes[0] == 0x80 && bytes[1] == 0x24 {
                    if let Ok(vk) = VerifyingKey::from_sec1_bytes(&bytes[2..]) {
                        return Some(vk);
                    }
                }
            }
        }
    }
    None
}

// -----------------------------------------------------------------------------
// lxm/jti enforcement helpers
// -----------------------------------------------------------------------------

static JTI_CACHE: Lazy<moka::sync::Cache<String, ()>> = Lazy::new(|| {
    use std::time::Duration;
    moka::sync::Cache::builder()
        .time_to_live(Duration::from_secs(
            std::env::var("JTI_TTL_SECONDS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(120),
        ))
        .max_capacity(100_000)
        .build()
});

static AUTH_MIDDLEWARE: Lazy<AuthMiddleware> = Lazy::new(AuthMiddleware::new);

fn truthy(var: &str) -> bool {
    matches!(var, "1" | "true" | "TRUE" | "yes" | "YES")
}

fn parse_host_allowlist(var_name: &str) -> Option<Vec<String>> {
    let raw = std::env::var(var_name).ok()?;
    let hosts: Vec<String> = raw
        .split(',')
        .map(|v| v.trim().to_ascii_lowercase())
        .filter(|v| !v.is_empty())
        .collect();
    if hosts.is_empty() {
        None
    } else {
        Some(hosts)
    }
}

fn host_is_allowlisted(host: &str, allowlist: &[String]) -> bool {
    let host_lc = host.to_ascii_lowercase();
    allowlist
        .iter()
        .any(|allowed| host_lc == *allowed || host_lc.ends_with(&format!(".{allowed}")))
}

fn ip_is_disallowed(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_unspecified()
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_unique_local()
                || v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unicast_link_local()
        }
    }
}

fn kid_matches(vm_id: &str, kid: &str) -> bool {
    if vm_id == kid {
        return true;
    }
    let kid_fragment = kid.trim_start_matches('#');
    vm_id
        .rsplit('#')
        .next()
        .map(|frag| frag == kid_fragment)
        .unwrap_or(false)
}

fn select_verification_method<'a>(
    did_doc: &'a DidDocument,
    kid: Option<&str>,
) -> Result<&'a VerificationMethod, AuthError> {
    if did_doc.verification_method.is_empty() {
        return Err(AuthError::MissingVerificationMethod);
    }

    if let Some(kid_value) = kid {
        return did_doc
            .verification_method
            .iter()
            .find(|vm| kid_matches(&vm.id, kid_value))
            .ok_or_else(|| {
                AuthError::InvalidToken(format!(
                    "No verification method matches JWT kid '{}'",
                    kid_value
                ))
            });
    }

    if let Some(vm) = did_doc
        .verification_method
        .iter()
        .find(|vm| vm.id.rsplit('#').next() == Some("atproto"))
    {
        return Ok(vm);
    }

    did_doc
        .verification_method
        .first()
        .ok_or(AuthError::MissingVerificationMethod)
}

fn is_disallowed_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") || host.ends_with(".localhost") {
        return true;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        ip_is_disallowed(&ip)
    } else {
        false
    }
}

async fn validate_resolved_host_is_public(host: &str, port: u16) -> Result<(), AuthError> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if ip_is_disallowed(&ip) {
            return Err(AuthError::DidResolutionFailed(format!(
                "host resolved to blocked IP: {ip}"
            )));
        }
        return Ok(());
    }

    let addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| AuthError::DidResolutionFailed(format!("DNS resolution failed: {e}")))?;

    let mut saw_any = false;
    for addr in addrs {
        saw_any = true;
        if ip_is_disallowed(&addr.ip()) {
            return Err(AuthError::DidResolutionFailed(format!(
                "host resolved to blocked IP: {}",
                addr.ip()
            )));
        }
    }

    if !saw_any {
        return Err(AuthError::DidResolutionFailed(
            "host resolved to zero addresses".to_string(),
        ));
    }
    Ok(())
}

/// Enforce optional lxm and jti-claim presence.
/// Replay uniqueness must be enforced with `enforce_standard_with_replay_store`.
pub fn enforce_standard(claims: &AtProtoClaims, endpoint_nsid: &str) -> Result<(), AuthError> {
    tracing::debug!(
        iss = %crate::crypto::redact_for_log(&claims.iss),
        endpoint = endpoint_nsid,
        lxm = claims.lxm.as_deref().unwrap_or("none"),
        jti = claims.jti.as_deref().unwrap_or("none"),
        "Enforcing authorization constraints"
    );

    // Enforce lxm if requested
    // Default to enforcing LXM unless explicitly disabled
    let enforce_lxm = std::env::var("ENFORCE_LXM")
        .map(|v| truthy(&v))
        .unwrap_or(true);
    if enforce_lxm {
        if let Some(lxm) = &claims.lxm {
            if lxm != endpoint_nsid {
                tracing::warn!("LXM mismatch: JWT lxm does not match endpoint NSID");
                return Err(AuthError::LxmMismatch);
            }
        } else {
            return Err(AuthError::MissingLxm);
        }
    }

    // Enforce jti presence unless disabled
    let enforce_jti = std::env::var("ENFORCE_JTI")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes"))
        .unwrap_or(true);

    if enforce_jti && claims.jti.is_none() {
        tracing::warn!(
            iss = %crate::crypto::redact_for_log(&claims.iss),
            endpoint = endpoint_nsid,
            "Missing jti claim when ENFORCE_JTI is enabled"
        );
        return Err(AuthError::MissingJti);
    }
    Ok(())
}

pub async fn enforce_standard_with_replay_store(
    claims: &AtProtoClaims,
    endpoint_nsid: &str,
    pool: &crate::storage::DbPool,
) -> Result<(), AuthError> {
    enforce_standard_with_store(claims, endpoint_nsid, &PostgresJtiReplayStore(pool)).await
}

#[async_trait::async_trait]
trait JtiReplayStore: Sync {
    async fn insert_if_absent(
        &self,
        issuer_did: &str,
        jti: &str,
        endpoint_nsid: &str,
        ttl_seconds: u64,
    ) -> Result<bool, AuthError>;
}

struct PostgresJtiReplayStore<'a>(&'a crate::storage::DbPool);

#[async_trait::async_trait]
impl JtiReplayStore for PostgresJtiReplayStore<'_> {
    async fn insert_if_absent(
        &self,
        issuer_did: &str,
        jti: &str,
        endpoint_nsid: &str,
        ttl_seconds: u64,
    ) -> Result<bool, AuthError> {
        let inserted: Option<String> = sqlx::query_scalar(
            "INSERT INTO auth_jti_nonce (issuer_did, jti, endpoint_nsid, expires_at, created_at) \
             VALUES ($1, $2, $3, NOW() + make_interval(secs => $4), NOW()) \
             ON CONFLICT (issuer_did, jti) DO NOTHING \
             RETURNING issuer_did",
        )
        .bind(issuer_did)
        .bind(jti)
        .bind(endpoint_nsid)
        .bind(ttl_seconds as f64)
        .fetch_optional(self.0)
        .await
        .map_err(|e| AuthError::Internal(format!("shared jti store failed: {e}")))?;

        Ok(inserted.is_some())
    }
}

async fn enforce_standard_with_store(
    claims: &AtProtoClaims,
    endpoint_nsid: &str,
    store: &impl JtiReplayStore,
) -> Result<(), AuthError> {
    tracing::debug!(
        iss = %crate::crypto::redact_for_log(&claims.iss),
        endpoint = endpoint_nsid,
        lxm = claims.lxm.as_deref().unwrap_or("none"),
        jti = claims.jti.as_deref().unwrap_or("none"),
        "Enforcing authorization constraints with shared replay store"
    );

    let enforce_lxm = std::env::var("ENFORCE_LXM")
        .map(|v| truthy(&v))
        .unwrap_or(true);
    if enforce_lxm {
        match &claims.lxm {
            Some(lxm) if lxm == endpoint_nsid => {}
            Some(_) => return Err(AuthError::LxmMismatch),
            None => return Err(AuthError::MissingLxm),
        }
    }

    let enforce_jti = std::env::var("ENFORCE_JTI")
        .map(|v| truthy(&v))
        .unwrap_or(true);
    if !enforce_jti {
        return Ok(());
    }

    let ttl_seconds = std::env::var("JTI_TTL_SECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(120);

    let jti = claims.jti.as_ref().ok_or(AuthError::MissingJti)?;
    let canonical_issuer = canonical_did(&claims.iss);
    let local_key = format!("{}|{}", canonical_issuer, jti);
    if JTI_CACHE.get(&local_key).is_some() {
        return Err(AuthError::ReplayDetected);
    }

    if !store
        .insert_if_absent(canonical_issuer, jti, endpoint_nsid, ttl_seconds)
        .await?
    {
        return Err(AuthError::ReplayDetected);
    }

    JTI_CACHE.insert(local_key, ());
    Ok(())
}

pub async fn cleanup_expired_jti_nonces(pool: &crate::storage::DbPool) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("DELETE FROM auth_jti_nonce WHERE expires_at < NOW()")
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

fn endpoint_nsid_from_path(path: &str) -> Option<&str> {
    path.strip_prefix("/xrpc/")
}

fn canonical_valid_did(value: &str) -> Option<&str> {
    if value.trim() != value || value.chars().any(char::is_whitespace) {
        return None;
    }

    let did = canonical_did(value);
    let mut parts = did.splitn(3, ':');
    match (parts.next(), parts.next(), parts.next()) {
        (Some("did"), Some(method), Some(identifier))
            if !method.is_empty() && !identifier.is_empty() =>
        {
            Some(did)
        }
        _ => None,
    }
}

/// Bind the authenticated principal to the verified JWT issuer unless that
/// issuer is explicitly configured as a trusted delegating gateway.
pub(crate) fn resolve_authenticated_principal(
    claims: &AtProtoClaims,
    trusted_gateway_dids: Option<&str>,
) -> Result<String, AuthError> {
    let issuer = canonical_valid_did(&claims.iss)
        .ok_or_else(|| AuthError::InvalidToken("iss is not a valid DID".into()))?;
    let Some(subject_claim) = claims.sub.as_deref() else {
        return Ok(issuer.to_string());
    };
    let subject = canonical_valid_did(subject_claim)
        .ok_or_else(|| AuthError::InvalidToken("sub is not a valid DID".into()))?;

    if subject == issuer {
        return Ok(issuer.to_string());
    }

    let raw_allowlist = trusted_gateway_dids
        .filter(|raw| !raw.trim().is_empty())
        .ok_or_else(|| {
            AuthError::InvalidToken("JWT subject differs from untrusted issuer".into())
        })?;
    let configured_gateways: Option<Vec<&str>> = raw_allowlist
        .split(',')
        .map(str::trim)
        .map(canonical_valid_did)
        .collect();
    let configured_gateways = configured_gateways
        .filter(|gateways| !gateways.is_empty())
        .ok_or_else(|| AuthError::InvalidToken("TRUSTED_GATEWAY_DIDS is malformed".into()))?;

    if configured_gateways.contains(&issuer) {
        Ok(subject.to_string())
    } else {
        Err(AuthError::InvalidToken(
            "JWT subject differs from untrusted issuer".into(),
        ))
    }
}

fn resolve_and_check_endpoint_rate_limit(
    limiter: &crate::middleware::rate_limit::DidRateLimiter,
    claims: &AtProtoClaims,
    trusted_gateway_dids: Option<&str>,
    endpoint: &str,
) -> Result<String, AuthError> {
    let user_did = resolve_authenticated_principal(claims, trusted_gateway_dids)?;
    if let Err(retry_after) = limiter.check_did_limit(&user_did, endpoint) {
        tracing::warn!(
            did = %crate::crypto::redact_for_log(&user_did),
            endpoint = endpoint,
            retry_after = retry_after,
            "DID rate limit exceeded for endpoint"
        );
        return Err(AuthError::RateLimitExceeded {
            retry_after_secs: retry_after,
        });
    }
    Ok(user_did)
}

/// Axum extractor for authenticated requests
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
    crate::storage::DbPool: FromRef<S>,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let has_authorization = parts.headers.contains_key("authorization");
        let has_atproto_proxy = parts.headers.contains_key("atproto-proxy");
        tracing::debug!(
            method = %parts.method,
            uri = %parts.uri,
            has_authorization = has_authorization,
            has_atproto_proxy = has_atproto_proxy,
            "Processing authentication for request"
        );

        // Extract authorization header (do not log token)
        let auth_header = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                tracing::error!("Missing authorization header");
                AuthError::MissingAuthHeader
            })?;

        // Parse bearer token (redacted in logs)
        let token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
            tracing::error!("Invalid auth format - expected 'Bearer <token>'");
            AuthError::InvalidAuthFormat
        })?;

        // Use shared auth middleware (cached DID docs, rate limiting)
        let middleware: &AuthMiddleware = &AUTH_MIDDLEWARE;

        // Verify JWT and extract claims
        let claims = middleware.verify_jwt(token).await?;
        parts
            .extensions
            .insert(device_auth::VerifiedRequestTarget::from_request_parts(
                &parts.method,
                &parts.uri,
            ));

        // Enforce lxm/jti + shared replay store across all authenticated XRPC endpoints.
        let endpoint = parts.uri.path();
        let mut issuer_for_limits = claims.iss.clone();
        if let Some(endpoint_nsid) = endpoint_nsid_from_path(endpoint) {
            let pool = crate::storage::DbPool::from_ref(state);
            if let Err(err) =
                enforce_standard_with_replay_store(&claims, endpoint_nsid, &pool).await
            {
                if endpoint_nsid.starts_with("blue.catbird.mlsDS.") {
                    crate::federation::peer_policy::record_invalid_token(
                        &pool,
                        canonical_did(&claims.iss),
                    )
                    .await;
                }
                return Err(err);
            }
            issuer_for_limits = canonical_did(&claims.iss).to_string();
        }

        // Check rate limit
        middleware.check_rate_limit(&issuer_for_limits)?;

        // Resolve trusted delegation before the endpoint-specific limiter so
        // gateway users receive independent buckets. The issuer-scoped
        // limiter above remains as the aggregate gateway abuse boundary.
        let endpoint = parts.uri.path();
        let trusted_gateway_dids = std::env::var("TRUSTED_GATEWAY_DIDS").ok();
        let user_did = resolve_and_check_endpoint_rate_limit(
            &crate::middleware::rate_limit::DID_RATE_LIMITER,
            &claims,
            trusted_gateway_dids.as_deref(),
            endpoint,
        )?;
        let delegated_gateway = canonical_did(&claims.iss) != user_did;
        parts.extensions.insert(VerifiedGatewayBearer {
            claims: claims.clone(),
            token: token.to_string(),
            effective_user_did: user_did.clone(),
            delegated_gateway,
        });

        debug!(
            "Authenticated request from DID: {} (issuer: {})",
            crate::crypto::redact_for_log(&user_did),
            crate::crypto::redact_for_log(&claims.iss)
        );

        Ok(AuthUser {
            did: user_did,
            claims,
        })
    }
}

// =============================================================================
// Admin Authorization Helpers
// =============================================================================

/// Check if a user is an admin of a conversation
///
/// # Errors
/// Returns an error if:
/// - Database query fails
/// - User is not a member of the conversation
/// - User is not an admin
pub async fn verify_is_admin(
    pool: &crate::storage::DbPool,
    convo_id: &str,
    user_did: &str,
) -> Result<(), StatusCode> {
    // In multi-device mode, user_did from JWT is base DID but members.member_did is device DID
    // Check both member_did and user_did columns to support both modes
    let is_admin: Option<bool> = sqlx::query_scalar(
        "SELECT is_admin FROM members
         WHERE convo_id = $1 AND (member_did = $2 OR user_did = $2) AND left_at IS NULL
         LIMIT 1",
    )
    .bind(convo_id)
    .bind(user_did)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        tracing::error!("Failed to check admin status: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    match is_admin {
        Some(true) => Ok(()),
        Some(false) => {
            tracing::warn!("User is not an admin of conversation");
            Err(StatusCode::FORBIDDEN)
        }
        None => {
            // Return FORBIDDEN (not NOT_FOUND) for non-members to avoid information disclosure
            // and for proper handling through ATProto PDS proxy
            tracing::warn!("User is not a member of conversation");
            Err(StatusCode::FORBIDDEN)
        }
    }
}

/// Check if a user is a member of a conversation
///
/// Handles both single-device (legacy) and multi-device modes:
/// - In multi-device mode, user_did from JWT is base DID but members.member_did is device DID
/// - Checks both member_did and user_did columns to support both modes
///
/// # Errors
/// Returns an error if:
/// - Database query fails
/// - User is not a member of the conversation
pub async fn verify_is_member(
    pool: &crate::storage::DbPool,
    convo_id: &str,
    user_did: &str,
) -> Result<(), StatusCode> {
    let is_member: bool = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM members
            WHERE convo_id = $1 AND (member_did = $2 OR user_did = $2) AND left_at IS NULL
        )",
    )
    .bind(convo_id)
    .bind(user_did)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        tracing::error!("Failed to check membership: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if is_member {
        Ok(())
    } else {
        // Return FORBIDDEN (not NOT_FOUND) for non-members to avoid information disclosure
        // and for proper handling through ATProto PDS proxy
        tracing::warn!("User is not a member of conversation");
        Err(StatusCode::FORBIDDEN)
    }
}

/// Count admins in a conversation
///
/// # Errors
/// Returns an error if database query fails
pub async fn count_admins(
    pool: &crate::storage::DbPool,
    convo_id: &str,
) -> Result<i64, StatusCode> {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM members
         WHERE convo_id = $1 AND is_admin = true AND left_at IS NULL",
    )
    .bind(convo_id)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        tracing::error!("Failed to count admins: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })
}

/// Check if a user is a moderator (or admin) of a conversation
///
/// Admins have moderator privileges, so this returns true for both admins and moderators.
///
/// # Errors
/// Returns an error if:
/// - Database query fails
/// - User is not a member or doesn't have moderator/admin privileges
pub async fn verify_is_moderator_or_admin(
    pool: &crate::storage::DbPool,
    convo_id: &str,
    user_did: &str,
) -> Result<(), StatusCode> {
    let result: Option<(bool, bool)> = sqlx::query_as(
        "SELECT is_admin, COALESCE(is_moderator, false)
         FROM members
         WHERE convo_id = $1 AND (member_did = $2 OR user_did = $2) AND left_at IS NULL
         LIMIT 1",
    )
    .bind(convo_id)
    .bind(user_did)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        tracing::error!("Failed to check moderator status: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    match result {
        Some((is_admin, is_moderator)) if is_admin || is_moderator => Ok(()),
        Some(_) => {
            tracing::warn!("User is not a moderator or admin of conversation");
            Err(StatusCode::FORBIDDEN)
        }
        None => {
            // Return FORBIDDEN (not NOT_FOUND) for non-members to avoid information disclosure
            // and for proper handling through ATProto PDS proxy
            tracing::warn!("User is not a member of conversation");
            Err(StatusCode::FORBIDDEN)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(iss: &str, sub: Option<&str>) -> AtProtoClaims {
        AtProtoClaims {
            iss: iss.to_string(),
            aud: "did:web:mls.example.com".to_string(),
            exp: i64::MAX,
            iat: None,
            sub: sub.map(str::to_string),
            lxm: Some("blue.catbird.mlsChat.getConvos".to_string()),
            jti: Some("test-jti".to_string()),
        }
    }

    #[test]
    fn direct_token_without_subject_uses_canonical_issuer() {
        let claims = claims("did:plc:alice#atproto", None);

        assert_eq!(
            resolve_authenticated_principal(&claims, None).unwrap(),
            "did:plc:alice"
        );
    }

    #[test]
    fn direct_token_accepts_canonically_equal_subject() {
        let claims = claims("did:plc:alice#atproto", Some("did:plc:alice#device"));

        assert_eq!(
            resolve_authenticated_principal(&claims, None).unwrap(),
            "did:plc:alice"
        );
    }

    #[test]
    fn untrusted_issuer_cannot_impersonate_victim_or_admin() {
        for subject in ["did:plc:victim", "did:web:admin.catbird.blue"] {
            let claims = claims("did:plc:attacker", Some(subject));

            assert!(matches!(
                resolve_authenticated_principal(&claims, None),
                Err(AuthError::InvalidToken(_))
            ));
        }
    }

    #[test]
    fn configured_nest_gateway_can_delegate_subject() {
        let claims = claims(
            "did:web:api.catbird.blue#atproto",
            Some("did:plc:alice#device"),
        );

        assert_eq!(
            resolve_authenticated_principal(
                &claims,
                Some("did:web:other.example, did:web:api.catbird.blue"),
            )
            .unwrap(),
            "did:plc:alice"
        );
    }

    #[test]
    fn delegated_subjects_have_independent_endpoint_rate_limits() {
        let limiter = crate::middleware::rate_limit::DidRateLimiter::new();
        let endpoint = "/xrpc/blue.catbird.mlsChat.beginDeviceAuthBinding";
        let trusted_gateway = Some("did:web:api.catbird.blue");
        let alice = claims("did:web:api.catbird.blue", Some("did:plc:alice"));
        let bob = claims("did:web:api.catbird.blue", Some("did:plc:bob"));

        let mut alice_exhausted = false;
        for _ in 0..1_000 {
            match resolve_and_check_endpoint_rate_limit(&limiter, &alice, trusted_gateway, endpoint)
            {
                Ok(principal) => assert_eq!(principal, "did:plc:alice"),
                Err(AuthError::RateLimitExceeded { .. }) => {
                    alice_exhausted = true;
                    break;
                }
                Err(error) => panic!("unexpected Alice error: {error}"),
            }
        }
        assert!(
            alice_exhausted,
            "Alice must exhaust her own endpoint bucket"
        );

        assert_eq!(
            resolve_and_check_endpoint_rate_limit(&limiter, &bob, trusted_gateway, endpoint,)
                .expect("Bob has an independent endpoint bucket"),
            "did:plc:bob"
        );
    }

    #[test]
    fn missing_empty_or_malformed_allowlist_fails_closed_for_delegation() {
        let claims = claims("did:web:api.catbird.blue", Some("did:plc:alice"));

        for allowlist in [None, Some(""), Some(" , "), Some("api.catbird.blue")] {
            assert!(matches!(
                resolve_authenticated_principal(&claims, allowlist),
                Err(AuthError::InvalidToken(_))
            ));
        }
    }

    #[test]
    fn malformed_entries_do_not_make_an_issuer_trusted() {
        let claims = claims("did:web:api.catbird.blue", Some("did:plc:alice"));

        for allowlist in [
            "not-a-did, did:web:api.catbird.blue.example",
            "not-a-did, did:web:api.catbird.blue",
        ] {
            assert!(matches!(
                resolve_authenticated_principal(&claims, Some(allowlist)),
                Err(AuthError::InvalidToken(_))
            ));
        }
    }
}

#[cfg(test)]
#[path = "auth/staging_identity_fixture_tests.rs"]
mod staging_identity_fixture_tests;
