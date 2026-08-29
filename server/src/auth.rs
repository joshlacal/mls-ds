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
use std::{num::NonZeroU32, sync::Arc, time::Duration};
use thiserror::Error;
use tracing::debug;

pub const MLS_APPVIEW_SERVICE_REF: &str = "did:web:chat.catbird.blue#atproto_mls";
const SERVICE_AUTH_MAX_LIFETIME_SECONDS: i64 = 60;
const SERVICE_AUTH_FUTURE_IAT_LEEWAY_SECONDS: i64 = 60;

use crate::identity::{canonical_did, did_web_document_url};
use crate::util::outbound_body::{decode_json_bounded, ResponseBodyBudget, DID_DOCUMENT_MAX_BYTES};

fn audience_matches_expected(claimed: &str, expected: &str) -> bool {
    claimed == expected || (expected.contains('#') && claimed == canonical_did(expected))
}

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

    #[error("Authentication or device authorization denied")]
    DeviceAuthorizationDenied,

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
            AuthError::DeviceAuthorizationDenied => (
                StatusCode::UNAUTHORIZED,
                "Unauthorized",
                "Authentication or device authorization denied".to_string(),
            ),
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
    #[serde(rename = "verificationMethod", default)]
    pub verification_method: Vec<VerificationMethod>,
    #[serde(default)]
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

/// Opaque account principal admitted for a standard ATProto AppView request.
///
/// The raw bearer is retained only so the chat admission layer can bind its
/// audit digest. It is never exposed through Debug or to endpoint handlers.
#[derive(Clone)]
pub struct VerifiedServicePrincipal {
    did: String,
    endpoint_nsid: String,
    jti: String,
    iat: i64,
    exp: i64,
    token: String,
}

impl std::fmt::Debug for VerifiedServicePrincipal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedServicePrincipal")
            .field("did", &crate::crypto::redact_for_log(&self.did))
            .field("endpoint_nsid", &self.endpoint_nsid)
            .field("token", &"<redacted>")
            .finish()
    }
}

impl VerifiedServicePrincipal {
    pub fn did(&self) -> &str {
        &self.did
    }

    pub fn endpoint_nsid(&self) -> &str {
        &self.endpoint_nsid
    }

    pub fn jti(&self) -> &str {
        &self.jti
    }

    pub fn iat(&self) -> i64 {
        self.iat
    }

    pub fn exp(&self) -> i64 {
        self.exp
    }

    pub fn token_bytes(&self) -> &[u8] {
        self.token.as_bytes()
    }
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
    did_resolution_timeout: Duration,
    rate_limit_quota: Quota,
    did_host_allowlist: Option<Vec<String>>,
    #[cfg(test)]
    service_did_override: Option<String>,
    #[cfg(test)]
    test_service_did_source: Option<Arc<dyn Fn() -> Option<String> + Send + Sync>>,
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
                .timeout(Duration::from_secs(did_resolution_timeout_seconds))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            did_resolution_timeout: Duration::from_secs(did_resolution_timeout_seconds),
            rate_limit_quota: quota,
            did_host_allowlist,
            #[cfg(test)]
            service_did_override: None,
            #[cfg(test)]
            test_service_did_source: None,
        }
    }

    #[cfg(test)]
    fn with_test_service_did(mut self, service_did: &str) -> Self {
        self.service_did_override = Some(service_did.to_string());
        self.test_service_did_source = None;
        self
    }

    #[cfg(test)]
    fn with_test_service_did_source(
        mut self,
        source: Arc<dyn Fn() -> Option<String> + Send + Sync>,
    ) -> Self {
        self.service_did_override = None;
        self.test_service_did_source = Some(source);
        self
    }

    fn configured_service_did(&self) -> Option<String> {
        #[cfg(test)]
        {
            if let Some(source) = &self.test_service_did_source {
                return source();
            }
            if let Some(service_did) = &self.service_did_override {
                return Some(service_did.clone());
            }
        }

        std::env::var("SERVICE_DID").ok()
    }

    /// Verify JWT token and extract claims.
    pub async fn verify_jwt(&self, token: &str) -> Result<AtProtoClaims, AuthError> {
        self.verify_jwt_for_audience(token, None).await
    }

    /// Verify JWT token with an explicit expected audience (or fall back to configured SERVICE_DID).
    pub async fn verify_jwt_for_audience(
        &self,
        token: &str,
        expected_aud: Option<&str>,
    ) -> Result<AtProtoClaims, AuthError> {
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

        // Audience enforcement
        if let Some(expected) = expected_aud {
            if !audience_matches_expected(&claims.aud, expected) {
                tracing::warn!("JWT audience mismatch with expected audience {expected}");
                return Err(AuthError::InvalidToken(
                    format!("aud does not match {expected}").into(),
                ));
            }
        } else if let Some(service_did) = self.configured_service_did() {
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
                use p256::ecdsa::{signature::Verifier, Signature};
                let did_doc = self.resolve_did(issuer_did).await?;
                let vm = select_verification_method(&did_doc, header.kid.as_deref())?;
                let vk = extract_p256_key_from_vm(vm)?;
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
        let resolution = if did.starts_with("did:plc:") {
            self.resolve_plc_did(did).await
        } else if did.starts_with("did:web:") {
            self.resolve_web_did(did).await
        } else {
            return Err(AuthError::InvalidDid(format!(
                "Unsupported DID method: {}",
                did
            )));
        };

        self.cache_successful_did_resolution(did, resolution).await
    }

    async fn cache_successful_did_resolution(
        &self,
        did: &str,
        resolution: Result<DidDocument, AuthError>,
    ) -> Result<DidDocument, AuthError> {
        let doc = resolution?;
        let cached = CachedDidDoc {
            doc: doc.clone(),
            cached_at: Utc::now(),
        };
        self.did_cache.insert(did.to_string(), cached).await;

        Ok(doc)
    }

    pub async fn cache_did_document(&self, doc: DidDocument) {
        let cached = CachedDidDoc {
            doc: doc.clone(),
            cached_at: Utc::now(),
        };
        self.did_cache.insert(doc.id.clone(), cached).await;
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

        self.send_and_decode_did_document(self.http_client.get(&url), |status| {
            tracing::error!(
                status = status.as_u16(),
                "Failed to resolve DID from PLC directory"
            );
            format!("PLC directory returned status {status}")
        })
        .await
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

        self.send_and_decode_did_document(self.http_client.get(&url), |status| {
            format!("Web server returned status {status}")
        })
        .await
    }

    async fn send_and_decode_did_document<F>(
        &self,
        request: reqwest::RequestBuilder,
        status_error: F,
    ) -> Result<DidDocument, AuthError>
    where
        F: FnOnce(StatusCode) -> String,
    {
        let deadline = tokio::time::Instant::now()
            .checked_add(self.did_resolution_timeout)
            .ok_or_else(|| {
                AuthError::DidResolutionFailed(
                    "DID resolution deadline could not be represented".to_string(),
                )
            })?;
        let response = tokio::time::timeout_at(deadline, request.send())
            .await
            .map_err(|_| {
                AuthError::DidResolutionFailed("DID resolution deadline exceeded".to_string())
            })?
            .map_err(map_did_request_error)?;

        if !response.status().is_success() {
            return Err(AuthError::DidResolutionFailed(status_error(
                response.status(),
            )));
        }

        decode_json_bounded(
            response,
            ResponseBodyBudget::new(DID_DOCUMENT_MAX_BYTES, deadline),
        )
        .await
        .map_err(|error| {
            AuthError::DidResolutionFailed(format!("Failed to parse DID document: {error}"))
        })
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

fn map_did_request_error(error: reqwest::Error) -> AuthError {
    tracing::warn!(
        did_resolution_error_is_timeout = error.is_timeout(),
        did_resolution_error_is_connect = error.is_connect(),
        did_resolution_error_is_request = error.is_request(),
        did_resolution_error_is_builder = error.is_builder(),
        "DID resolution HTTP request failed"
    );
    AuthError::DidResolutionFailed("DID resolution HTTP request failed".into())
}

impl Default for AuthMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

// -----------------------------------------------------------------------------
// P-256 key extraction helper
// -----------------------------------------------------------------------------

/// Extract a P-256 [`p256::ecdsa::VerifyingKey`] from a [`VerificationMethod`].
/// Works with both JWK (`publicKeyJwk`) and Multikey (`publicKeyMultibase`) representations.
pub fn extract_p256_key_from_vm(
    vm: &VerificationMethod,
) -> Result<p256::ecdsa::VerifyingKey, AuthError> {
    use p256::ecdsa::VerifyingKey;
    use p256::EncodedPoint;

    // Try JWK first
    if let Some(ref jwk) = vm.public_key_jwk {
        if jwk.kty == "EC" && jwk.crv.eq_ignore_ascii_case("P-256") {
            let x = URL_SAFE_NO_PAD
                .decode(&jwk.x)
                .map_err(|e| AuthError::InvalidToken(format!("bad jwk.x: {}", e)))?;
            let y = URL_SAFE_NO_PAD
                .decode(jwk.y.as_ref().ok_or(AuthError::MissingVerificationMethod)?)
                .map_err(|e| AuthError::InvalidToken(format!("bad jwk.y: {}", e)))?;
            if x.len() != 32 || y.len() != 32 {
                return Err(AuthError::InvalidToken(
                    "invalid P-256 JWK coordinate length".into(),
                ));
            }
            let ep = EncodedPoint::from_affine_coordinates(
                p256::FieldBytes::from_slice(&x),
                p256::FieldBytes::from_slice(&y),
                false,
            );
            return VerifyingKey::from_encoded_point(&ep)
                .map_err(|_| AuthError::InvalidToken("invalid P-256 point".into()));
        }
    }

    // Try multibase (multicodec P-256 key: 0x80 0x24 prefix + 33-byte compressed key)
    if let Some(ref mb) = vm.public_key_multibase {
        let (_base, bytes) = multibase::decode(mb)
            .map_err(|e| AuthError::InvalidToken(format!("bad multibase key: {}", e)))?;
        if bytes.len() == 35 && bytes[0] == 0x80 && bytes[1] == 0x24 {
            return VerifyingKey::from_sec1_bytes(&bytes[2..])
                .map_err(|e| AuthError::InvalidToken(format!("invalid P-256 SEC1 key: {}", e)));
        } else {
            return Err(AuthError::UnsupportedKeyType(format!(
                "Expected p256-pub multicodec (0x80 0x24) with 33-byte key, got {} bytes",
                bytes.len(),
            )));
        }
    }

    Err(AuthError::MissingVerificationMethod)
}

/// Extract the first P-256 [`p256::ecdsa::VerifyingKey`] from a DID document's
/// verification methods.  Works with both JWK (`publicKeyJwk`) and multikey
/// (`publicKeyMultibase`) representations.
pub fn extract_p256_key(did_doc: &DidDocument) -> Option<p256::ecdsa::VerifyingKey> {
    for vm in &did_doc.verification_method {
        if let Ok(vk) = extract_p256_key_from_vm(vm) {
            return Some(vk);
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
#[doc(hidden)]
pub fn shared_auth_middleware() -> AuthMiddleware {
    AUTH_MIDDLEWARE.clone()
}

#[cfg(any(test, feature = "test-support"))]
pub async fn cache_test_did_document(doc: DidDocument) {
    AUTH_MIDDLEWARE.cache_did_document(doc).await;
}

/// Loads test DID document fixtures from environment variables (`TEST_DID_DOCUMENT_PATHS` or `TEST_DID_DOCUMENTS_DIR`).
///
/// # Security
/// This is strictly forbidden outside `APP_ENV=test`. If any fixture configuration is present
/// while `APP_ENV` is not `"test"`, this function aborts startup immediately.
#[cfg(any(test, feature = "test-support"))]
pub async fn load_test_did_fixtures_from_env() -> Result<usize, AuthError> {
    let paths_var = std::env::var("TEST_DID_DOCUMENT_PATHS")
        .or_else(|_| std::env::var("TEST_DID_DOC_PATHS"))
        .ok();
    let dir_var = std::env::var("TEST_DID_DOCUMENTS_DIR")
        .or_else(|_| std::env::var("TEST_DID_DOC_DIR"))
        .ok();

    if paths_var.is_none() && dir_var.is_none() {
        return Ok(0);
    }

    let is_test = std::env::var("APP_ENV")
        .map(|v| v.eq_ignore_ascii_case("test"))
        .unwrap_or(false);

    if !is_test {
        panic!(
            "Refusing to start: test DID document fixtures are configured via environment, \
             but APP_ENV is not 'test'. Offline DID fixtures are forbidden outside test mode."
        );
    }

    let mut paths = Vec::new();

    if let Some(raw_paths) = paths_var {
        for path_str in raw_paths
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            paths.push(std::path::PathBuf::from(path_str));
        }
    }

    if let Some(dir_str) = dir_var {
        let dir = std::path::Path::new(&dir_str);
        if !dir.is_dir() {
            return Err(AuthError::InvalidDid(format!(
                "Configured TEST_DID_DOCUMENTS_DIR '{}' is not a directory",
                dir_str
            )));
        }
        let entries = std::fs::read_dir(dir).map_err(|e| {
            AuthError::InvalidDid(format!(
                "Failed to read TEST_DID_DOCUMENTS_DIR '{}': {e}",
                dir_str
            ))
        })?;
        for entry in entries {
            let entry = entry.map_err(|e| {
                AuthError::InvalidDid(format!("Error reading directory entry: {e}"))
            })?;
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
                paths.push(path);
            }
        }
    }

    let mut count = 0;
    for path in &paths {
        let content = std::fs::read_to_string(path).map_err(|e| {
            AuthError::InvalidDid(format!(
                "Failed to read test DID doc fixture at '{}': {e}",
                path.display()
            ))
        })?;
        let doc: DidDocument = serde_json::from_str(&content).map_err(|e| {
            AuthError::InvalidDid(format!(
                "Failed to parse test DID doc fixture at '{}': {e}",
                path.display()
            ))
        })?;
        tracing::info!(
            did = %doc.id,
            path = %path.display(),
            "Cached offline test DID document fixture"
        );
        cache_test_did_document(doc).await;
        count += 1;
    }

    Ok(count)
}

/// Keep the binary startup gate and library request gate on identical flag semantics.
#[doc(hidden)]
pub fn auth_enforcement_flag_enabled(value: &str) -> bool {
    value == "1" || value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("yes")
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

pub(crate) fn select_verification_method<'a>(
    did_doc: &'a DidDocument,
    kid: Option<&str>,
) -> Result<&'a VerificationMethod, AuthError> {
    if did_doc.verification_method.is_empty() {
        return Err(AuthError::MissingVerificationMethod);
    }

    if let Some(kid_value) = kid {
        let absolute_atproto = format!("{}#atproto", did_doc.id);
        if kid_value != "#atproto" && kid_value != "atproto" && kid_value != absolute_atproto {
            return Err(AuthError::InvalidToken(
                "service auth must use the DID #atproto verification method".into(),
            ));
        }
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

    Err(AuthError::MissingVerificationMethod)
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
    enforce_standard_with_policy(claims, endpoint_nsid, AuthEnforcementPolicy::from_env())
}

#[derive(Clone, Copy)]
struct AuthEnforcementPolicy {
    enforce_lxm: bool,
    enforce_jti: bool,
    jti_ttl_seconds: u64,
}

impl AuthEnforcementPolicy {
    fn from_env() -> Self {
        Self {
            enforce_lxm: std::env::var("ENFORCE_LXM")
                .map(|value| auth_enforcement_flag_enabled(&value))
                .unwrap_or(true),
            enforce_jti: std::env::var("ENFORCE_JTI")
                .map(|value| auth_enforcement_flag_enabled(&value))
                .unwrap_or(true),
            jti_ttl_seconds: std::env::var("JTI_TTL_SECONDS")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(120),
        }
    }

    #[cfg(test)]
    const fn strict_for_test() -> Self {
        Self {
            enforce_lxm: true,
            enforce_jti: true,
            jti_ttl_seconds: 120,
        }
    }
}

fn enforce_standard_with_policy(
    claims: &AtProtoClaims,
    endpoint_nsid: &str,
    policy: AuthEnforcementPolicy,
) -> Result<(), AuthError> {
    tracing::debug!(
        iss = %crate::crypto::redact_for_log(&claims.iss),
        endpoint = endpoint_nsid,
        lxm = claims.lxm.as_deref().unwrap_or("none"),
        jti = claims.jti.as_deref().unwrap_or("none"),
        "Enforcing authorization constraints"
    );

    // Enforce lxm if requested
    // Default to enforcing LXM unless explicitly disabled
    if policy.enforce_lxm {
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
    if policy.enforce_jti && claims.jti.is_none() {
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
    enforce_standard_with_store(
        claims,
        endpoint_nsid,
        &PostgresJtiReplayStore(pool),
        AuthEnforcementPolicy::from_env(),
    )
    .await
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
    policy: AuthEnforcementPolicy,
) -> Result<(), AuthError> {
    tracing::debug!(
        iss = %crate::crypto::redact_for_log(&claims.iss),
        endpoint = endpoint_nsid,
        lxm = claims.lxm.as_deref().unwrap_or("none"),
        jti = claims.jti.as_deref().unwrap_or("none"),
        "Enforcing authorization constraints with shared replay store"
    );

    if policy.enforce_lxm {
        match &claims.lxm {
            Some(lxm) if lxm == endpoint_nsid => {}
            Some(_) => return Err(AuthError::LxmMismatch),
            None => return Err(AuthError::MissingLxm),
        }
    }

    if !policy.enforce_jti {
        return Ok(());
    }

    let ttl_seconds = policy.jti_ttl_seconds;

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

/// Verify the standard account-to-AppView service-auth contract used by every
/// `blue.catbird.chat.*` HTTP route.
pub(crate) async fn verify_mls_service_principal(
    headers: &axum::http::HeaderMap,
    pool: &crate::storage::DbPool,
    endpoint_nsid: &str,
) -> Result<VerifiedServicePrincipal, AuthError> {
    let authorization = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or(AuthError::MissingAuthHeader)?;
    let token = authorization
        .strip_prefix("Bearer ")
        .ok_or(AuthError::InvalidAuthFormat)?;
    let claims = AUTH_MIDDLEWARE
        .verify_jwt_for_audience(token, Some(MLS_APPVIEW_SERVICE_REF))
        .await?;
    let now = Utc::now().timestamp();
    let (issuer, iat) = validate_mls_service_claims(&claims, endpoint_nsid, now)?;
    enforce_standard_with_replay_store(&claims, endpoint_nsid, pool).await?;
    AUTH_MIDDLEWARE.check_rate_limit(issuer)?;
    if let Err(retry_after) =
        crate::middleware::rate_limit::DID_RATE_LIMITER.check_did_limit(issuer, endpoint_nsid)
    {
        return Err(AuthError::RateLimitExceeded {
            retry_after_secs: retry_after,
        });
    }

    Ok(VerifiedServicePrincipal {
        did: issuer.to_owned(),
        endpoint_nsid: endpoint_nsid.to_owned(),
        jti: claims.jti.ok_or(AuthError::MissingJti)?,
        iat,
        exp: claims.exp,
        token: token.to_owned(),
    })
}

fn validate_mls_service_claims<'a>(
    claims: &'a AtProtoClaims,
    endpoint_nsid: &str,
    now: i64,
) -> Result<(&'a str, i64), AuthError> {
    if !audience_matches_expected(&claims.aud, MLS_APPVIEW_SERVICE_REF) {
        return Err(AuthError::InvalidToken(
            "aud does not match the MLS AppView service reference".into(),
        ));
    }
    let issuer = canonical_valid_did(&claims.iss)
        .ok_or_else(|| AuthError::InvalidToken("iss is not a valid account DID".into()))?;
    if issuer != claims.iss
        || claims
            .iss
            .chars()
            .any(|character| matches!(character, '#' | '?'))
    {
        return Err(AuthError::InvalidToken(
            "iss must be the exact bare account DID".into(),
        ));
    }
    if claims
        .sub
        .as_deref()
        .is_some_and(|subject| subject != issuer)
    {
        return Err(AuthError::InvalidToken(
            "delegated service-auth tokens are not accepted by MLS v2".into(),
        ));
    }

    let iat = claims
        .iat
        .ok_or_else(|| AuthError::InvalidToken("missing iat claim".into()))?;
    if claims.exp < now {
        return Err(AuthError::TokenExpired);
    }
    if claims.exp <= iat
        || claims.exp - iat > SERVICE_AUTH_MAX_LIFETIME_SECONDS
        || iat > now + SERVICE_AUTH_FUTURE_IAT_LEEWAY_SECONDS
    {
        return Err(AuthError::InvalidToken(
            "service-auth token is outside the short-lived time profile".into(),
        ));
    }
    match claims.lxm.as_deref() {
        Some(lxm) if lxm == endpoint_nsid => {}
        Some(_) => return Err(AuthError::LxmMismatch),
        None => return Err(AuthError::MissingLxm),
    }
    if claims.jti.as_deref().is_none_or(str::is_empty) {
        return Err(AuthError::MissingJti);
    }
    Ok((issuer, iat))
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
        let request_target =
            device_auth::VerifiedRequestTarget::from_request_parts(&parts.method, &parts.uri);
        parts.extensions.insert(request_target.clone());

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
        let verified_bearer = VerifiedGatewayBearer {
            claims: claims.clone(),
            token: token.to_string(),
            effective_user_did: user_did.clone(),
            delegated_gateway,
        };
        parts.extensions.insert(verified_bearer.clone());

        // Startup installs the validated rollout mode exactly once. Keeping
        // this writer commit inert until that coordinator-owned integration
        // lands prevents tests and intermediate builds from reading mutable
        // process environment on every request.
        if let (Some(endpoint_nsid), Some(mode)) = (
            endpoint_nsid_from_path(endpoint),
            crate::middleware::device_auth::installed_device_auth_mode(),
        ) {
            if endpoint_nsid.starts_with("blue.catbird.chat.") {
                let pool = crate::storage::DbPool::from_ref(state);
                crate::middleware::device_auth::enforce_device_auth_policy(
                    mode,
                    endpoint_nsid,
                    &parts.headers,
                    &mut parts.extensions,
                    &pool,
                    &verified_bearer,
                    &request_target,
                    Utc::now(),
                )
                .await
                .map_err(|_| AuthError::DeviceAuthorizationDenied)?;
            }
        }

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
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    #[test]
    fn did_document_resolution_has_no_unbounded_success_collector() {
        let source = include_str!("auth.rs");
        let response_json = [".json::<", "DidDocument>()"].concat();
        let response_bytes = [".by", "tes()"].concat();
        let response_text = [".te", "xt()"].concat();

        assert!(!source.contains(&response_json));
        assert!(!source.contains(&response_bytes));
        assert!(!source.contains(&response_text));
    }

    #[test]
    fn did_resolution_client_rejects_redirects() {
        let source = include_str!("auth.rs");
        let builder = source
            .split("http_client: reqwest::Client::builder()")
            .nth(1)
            .expect("auth DID client builder")
            .split(".build()")
            .next()
            .expect("auth DID client builder boundary");

        assert!(
            builder.contains("redirect(reqwest::redirect::Policy::none())"),
            "DID resolution must not follow an unvalidated redirect hop"
        );
    }

    #[test]
    fn malformed_p256_jwk_coordinates_are_rejected_without_panicking() {
        let issuer = "did:plc:malformed-p256";
        let document = DidDocument {
            id: issuer.to_string(),
            verification_method: vec![VerificationMethod {
                id: format!("{issuer}#atproto"),
                key_type: "JsonWebKey2020".to_string(),
                controller: issuer.to_string(),
                public_key_multibase: None,
                public_key_jwk: Some(PublicKeyJwk {
                    kty: "EC".to_string(),
                    crv: "P-256".to_string(),
                    x: URL_SAFE_NO_PAD.encode([1_u8; 31]),
                    y: Some(URL_SAFE_NO_PAD.encode([2_u8; 33])),
                }),
            }],
            service: None,
        };

        let result = std::panic::catch_unwind(|| extract_p256_key(&document));
        assert!(result.is_ok(), "malformed public input must not panic");
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn did_request_error_telemetry_is_classified_without_formatting_the_error() {
        let source = include_str!("auth.rs");
        let mapper = source
            .split("fn map_did_request_error")
            .nth(1)
            .expect("dedicated request error mapper")
            .split("impl Default for AuthMiddleware")
            .next()
            .expect("mapper source boundary");

        for classifier in ["is_timeout", "is_connect", "is_request", "is_builder"] {
            assert!(
                mapper.contains(&format!("error.{classifier}()")),
                "missing sanitized {classifier} classifier"
            );
        }
        for prohibited in [
            "format!(",
            "format_args!(",
            ".to_string()",
            "%error",
            "?error",
            "error =",
            "source =",
            "url",
        ] {
            assert!(
                !mapper.contains(prohibited),
                "request error mapper must not contain {prohibited:?}"
            );
        }
    }

    fn did_test_middleware(timeout: Duration) -> AuthMiddleware {
        let mut middleware = AuthMiddleware::with_config(300, 100, 60);
        middleware.http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("test HTTP client");
        middleware.did_resolution_timeout = timeout;
        middleware
    }

    async fn spawn_raw_http_response(parts: Vec<(Duration, Vec<u8>)>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind raw HTTP fixture");
        let address = listener.local_addr().expect("fixture address");
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept fixture request");
            let mut request = [0_u8; 4096];
            let _ = stream.readable().await;
            let _ = stream.try_read(&mut request);
            for (delay, bytes) in parts {
                tokio::time::sleep(delay).await;
                if stream.write_all(&bytes).await.is_err() {
                    break;
                }
            }
        });
        format!("http://{address}/did.json")
    }

    fn exact_size_did_document(size: usize) -> Vec<u8> {
        let mut document = serde_json::json!({
            "id": "did:plc:bounded",
            "verificationMethod": [],
            "service": null,
            "padding": ""
        });
        let base = serde_json::to_vec(&document).expect("serialize base DID document");
        let padding = size.checked_sub(base.len()).expect("target fits base JSON");
        document["padding"] = serde_json::Value::String("x".repeat(padding));
        let encoded = serde_json::to_vec(&document).expect("serialize padded DID document");
        assert_eq!(encoded.len(), size);
        encoded
    }

    #[tokio::test]
    async fn declared_oversize_did_document_is_rejected_before_body_and_not_cached() {
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            DID_DOCUMENT_MAX_BYTES + 1
        )
        .into_bytes();
        let url = spawn_raw_http_response(vec![
            (Duration::ZERO, header),
            (Duration::from_secs(2), vec![b'x']),
        ])
        .await;
        let middleware = did_test_middleware(Duration::from_secs(5));
        let started = tokio::time::Instant::now();

        let resolution = middleware
            .send_and_decode_did_document(middleware.http_client.get(url), |_| {
                unreachable!("success response")
            })
            .await;
        let error = middleware
            .cache_successful_did_resolution("did:plc:bounded", resolution)
            .await
            .expect_err("declared oversize response must fail");

        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(matches!(error, AuthError::DidResolutionFailed(_)));
        assert!(middleware.did_cache.get("did:plc:bounded").await.is_none());
    }

    #[tokio::test]
    async fn chunked_did_document_is_rejected_at_crossing_chunk() {
        let first = vec![b' '; DID_DOCUMENT_MAX_BYTES];
        let response = [
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec(),
            format!("{:X}\r\n", first.len()).into_bytes(),
            first,
            b"\r\n1\r\nx\r\n0\r\n\r\n".to_vec(),
        ]
        .concat();
        let url = spawn_raw_http_response(vec![(Duration::ZERO, response)]).await;
        let middleware = did_test_middleware(Duration::from_secs(1));

        let error = middleware
            .send_and_decode_did_document(middleware.http_client.get(url), |_| {
                unreachable!("success response")
            })
            .await
            .expect_err("streamed oversize response must fail");

        let message = error.to_string();
        assert!(message.contains("exceeding limit 262144"), "{message}");
    }

    #[tokio::test]
    async fn exactly_maximum_sized_did_document_succeeds() {
        let body = exact_size_did_document(DID_DOCUMENT_MAX_BYTES);
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        let url = spawn_raw_http_response(vec![(Duration::ZERO, [header, body].concat())]).await;
        let middleware = did_test_middleware(Duration::from_secs(1));

        let document = middleware
            .send_and_decode_did_document(middleware.http_client.get(url), |_| {
                unreachable!("success response")
            })
            .await
            .expect("exactly bounded response succeeds");

        assert_eq!(document.id, "did:plc:bounded");
    }

    #[tokio::test]
    async fn bounded_malformed_did_document_fails_closed_and_is_not_cached() {
        let body = b"{not-json}".to_vec();
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        let url = spawn_raw_http_response(vec![(Duration::ZERO, [header, body].concat())]).await;
        let middleware = did_test_middleware(Duration::from_secs(1));

        let resolution = middleware
            .send_and_decode_did_document(middleware.http_client.get(url), |_| {
                unreachable!("success response")
            })
            .await;
        let error = middleware
            .cache_successful_did_resolution("did:plc:bounded", resolution)
            .await
            .expect_err("malformed JSON must fail");

        assert!(matches!(error, AuthError::DidResolutionFailed(_)));
        assert!(middleware.did_cache.get("did:plc:bounded").await.is_none());
    }

    #[tokio::test]
    async fn send_and_body_decode_share_one_pre_send_deadline() {
        let body = br#"{"id":"did:plc:bounded","verificationMethod":[],"service":null}"#.to_vec();
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        let url = spawn_raw_http_response(vec![
            (Duration::from_millis(120), header),
            (Duration::from_millis(120), body),
        ])
        .await;
        let middleware = did_test_middleware(Duration::from_millis(200));

        let error = middleware
            .send_and_decode_did_document(middleware.http_client.get(&url), |_| {
                unreachable!("success response")
            })
            .await
            .expect_err("body phase must receive only the pre-send time remaining");

        let diagnostic = format!("{error:?} {error}");
        assert!(diagnostic.contains("deadline exceeded"));
        assert!(!diagnostic.contains(&url), "{diagnostic}");
    }

    #[test]
    fn plc_and_web_success_paths_use_the_common_bounded_decoder() {
        let source = include_str!("auth.rs");
        let production = source
            .split("#[cfg(test)]\nmod tests")
            .next()
            .expect("production auth source");

        assert_eq!(
            production.matches(".send_and_decode_did_document(").count(),
            2
        );
        assert_eq!(production.matches("decode_json_bounded(").count(), 1);
        assert!(production.contains("ResponseBodyBudget::new(DID_DOCUMENT_MAX_BYTES, deadline)"));
    }

    #[tokio::test]
    async fn non_success_statuses_keep_messages_and_do_not_collect_bodies() {
        for expected in [
            "PLC directory returned status 404 Not Found",
            "Web server returned status 404 Not Found",
        ] {
            let header =
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 1\r\nConnection: close\r\n\r\n"
                    .to_vec();
            let url = spawn_raw_http_response(vec![
                (Duration::ZERO, header),
                (Duration::from_secs(2), vec![b'x']),
            ])
            .await;
            let middleware = did_test_middleware(Duration::from_secs(5));
            let started = tokio::time::Instant::now();
            let expected_owned = expected.to_string();

            let error = middleware
                .send_and_decode_did_document(middleware.http_client.get(url), |_| expected_owned)
                .await
                .expect_err("non-success status must fail before reading body");

            assert_eq!(
                error.to_string(),
                format!("Failed to resolve DID document: {expected}")
            );
            assert!(started.elapsed() < Duration::from_secs(1));
        }
    }

    #[tokio::test]
    async fn body_limit_diagnostics_omit_content_credentials_and_urls() {
        let sentinel = "Bearer SECRET Cookie=SESSION https://sensitive.example/path";
        let body = sentinel.repeat((DID_DOCUMENT_MAX_BYTES / sentinel.len()) + 2);
        let response = [
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec(),
            format!("{:X}\r\n", body.len()).into_bytes(),
            body.into_bytes(),
            b"\r\n0\r\n\r\n".to_vec(),
        ]
        .concat();
        let url = spawn_raw_http_response(vec![(Duration::ZERO, response)]).await;
        let middleware = did_test_middleware(Duration::from_secs(1));

        let error = middleware
            .send_and_decode_did_document(middleware.http_client.get(&url), |_| {
                unreachable!("success response")
            })
            .await
            .expect_err("oversize body must fail");
        let diagnostic = format!("{error:?} {error}");

        assert!(!diagnostic.contains("SECRET"), "{diagnostic}");
        assert!(!diagnostic.contains("SESSION"), "{diagnostic}");
        assert!(!diagnostic.contains("sensitive.example"), "{diagnostic}");
        assert!(!diagnostic.contains(&url), "{diagnostic}");
    }

    #[test]
    fn auth_enforcement_flags_use_case_insensitive_boolean_semantics() {
        for enabled in [
            "1", "true", "TRUE", "True", "tRuE", "yes", "YES", "Yes", "yEs",
        ] {
            assert!(
                auth_enforcement_flag_enabled(enabled),
                "expected {enabled:?} to enable enforcement"
            );
        }

        for disabled in ["0", "false", "False", "no", "No", "", " true "] {
            assert!(
                !auth_enforcement_flag_enabled(disabled),
                "expected {disabled:?} to disable enforcement"
            );
        }
    }

    #[test]
    fn mixed_case_flags_enable_both_lxm_and_jti_policy_gates() {
        let policy = AuthEnforcementPolicy {
            enforce_lxm: auth_enforcement_flag_enabled("True"),
            enforce_jti: auth_enforcement_flag_enabled("Yes"),
            jti_ttl_seconds: 120,
        };
        let mut claims = claims("did:plc:alice", None);
        claims.lxm = Some("blue.catbird.chat.sendMessage".to_string());
        assert!(matches!(
            enforce_standard_with_policy(&claims, "blue.catbird.chat.getConversations", policy,),
            Err(AuthError::LxmMismatch)
        ));

        claims.lxm = Some("blue.catbird.chat.getConversations".to_string());
        claims.jti = None;
        assert!(matches!(
            enforce_standard_with_policy(&claims, "blue.catbird.chat.getConversations", policy,),
            Err(AuthError::MissingJti)
        ));
    }

    fn claims(iss: &str, sub: Option<&str>) -> AtProtoClaims {
        AtProtoClaims {
            iss: iss.to_string(),
            aud: "did:web:mls.example.com".to_string(),
            exp: i64::MAX,
            iat: None,
            sub: sub.map(str::to_string),
            lxm: Some("blue.catbird.chat.getConversations".to_string()),
            jti: Some("test-jti".to_string()),
        }
    }

    #[tokio::test]
    async fn cached_es256k_did_document_verifies_production_jwt_branch() {
        use k256::ecdsa::{signature::Signer, Signature, SigningKey};

        let issuer = "did:plc:es256k-compatibility";
        let key_id = format!("{issuer}#atproto");
        let mut scalar = [0_u8; 32];
        scalar[31] = 7;
        let signing_key =
            SigningKey::from_slice(&scalar).expect("fixture scalar is valid secp256k1");
        let point = signing_key.verifying_key().to_encoded_point(false);
        let document = DidDocument {
            id: issuer.to_string(),
            verification_method: vec![VerificationMethod {
                id: key_id.clone(),
                key_type: "JsonWebKey2020".to_string(),
                controller: issuer.to_string(),
                public_key_multibase: None,
                public_key_jwk: Some(PublicKeyJwk {
                    kty: "EC".to_string(),
                    crv: "secp256k1".to_string(),
                    x: URL_SAFE_NO_PAD.encode(point.x().expect("uncompressed point has x")),
                    y: Some(URL_SAFE_NO_PAD.encode(point.y().expect("uncompressed point has y"))),
                }),
            }],
            service: None,
        };
        let middleware = AuthMiddleware::with_config(300, 100, 60)
            .with_test_service_did("did:web:mls.example.com");
        middleware
            .did_cache
            .insert(
                issuer.to_string(),
                CachedDidDoc {
                    doc: document,
                    cached_at: Utc::now(),
                },
            )
            .await;
        let claims = claims(issuer, None);
        let header = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({"alg": "ES256K", "typ": "JWT", "kid": key_id}))
                .expect("serialize ES256K header"),
        );
        let payload =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("serialize ES256K claims"));
        let signing_input = format!("{header}.{payload}");
        let signature: Signature = signing_key.sign(signing_input.as_bytes());
        let token = format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        );

        let verified = middleware
            .verify_jwt(&token)
            .await
            .expect("production ES256K branch verifies cached DID key");

        assert_eq!(verified.iss, issuer);
        assert!(middleware.did_cache.get(issuer).await.is_some());
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
        let endpoint = "/xrpc/blue.catbird.chat.replenishKeyPackages";
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

    fn atproto_method_doc() -> DidDocument {
        DidDocument {
            id: "did:plc:alice".into(),
            verification_method: vec![VerificationMethod {
                id: "did:plc:alice#atproto".into(),
                key_type: "Multikey".into(),
                controller: "did:plc:alice".into(),
                public_key_multibase: Some("zInvalidButSelectionDoesNotDecode".into()),
                public_key_jwk: None,
            }],
            service: None,
        }
    }

    #[test]
    fn service_auth_kid_is_exactly_the_issuer_atproto_method() {
        let doc = atproto_method_doc();
        assert!(select_verification_method(&doc, Some("#atproto")).is_ok());
        assert!(select_verification_method(&doc, Some("did:plc:alice#atproto")).is_ok());

        for wrong in [
            "did:plc:mallory#atproto",
            "attacker#atproto",
            "did:plc:alice#other",
        ] {
            assert!(matches!(
                select_verification_method(&doc, Some(wrong)),
                Err(AuthError::InvalidToken(_))
            ));
        }
    }

    #[test]
    fn service_auth_without_kid_never_falls_back_to_another_method() {
        let mut doc = atproto_method_doc();
        doc.verification_method[0].id = "did:plc:alice#recovery".into();
        assert!(matches!(
            select_verification_method(&doc, None),
            Err(AuthError::MissingVerificationMethod)
        ));
    }

    fn standard_claims(now: i64) -> AtProtoClaims {
        AtProtoClaims {
            iss: "did:plc:alice".into(),
            aud: MLS_APPVIEW_SERVICE_REF.into(),
            exp: now + 60,
            iat: Some(now),
            sub: None,
            lxm: Some("blue.catbird.chat.getOwnDevices".into()),
            jti: Some("one-use-jti".into()),
        }
    }

    #[test]
    fn standard_service_claim_profile_is_exact() {
        let now = 2_000_000_000;
        let endpoint = "blue.catbird.chat.getOwnDevices";
        let valid = standard_claims(now);
        assert_eq!(
            validate_mls_service_claims(&valid, endpoint, now).unwrap(),
            ("did:plc:alice", now)
        );

        let mut legacy_bare_aud = valid.clone();
        legacy_bare_aud.aud = "did:web:chat.catbird.blue".into();
        assert_eq!(
            validate_mls_service_claims(&legacy_bare_aud, endpoint, now).unwrap(),
            ("did:plc:alice", now)
        );

        let mut wrong_aud = valid.clone();
        wrong_aud.aud = "did:web:other.example#atproto_mls".into();
        assert!(matches!(
            validate_mls_service_claims(&wrong_aud, endpoint, now),
            Err(AuthError::InvalidToken(_))
        ));

        let mut wrong_lxm = valid.clone();
        wrong_lxm.lxm = Some("blue.catbird.chat.getDevices".into());
        assert!(matches!(
            validate_mls_service_claims(&wrong_lxm, endpoint, now),
            Err(AuthError::LxmMismatch)
        ));

        let mut delegated = valid.clone();
        delegated.sub = Some("did:plc:bob".into());
        assert!(matches!(
            validate_mls_service_claims(&delegated, endpoint, now),
            Err(AuthError::InvalidToken(_))
        ));

        let mut bare_violation = valid.clone();
        bare_violation.iss = "did:plc:alice#device".into();
        assert!(matches!(
            validate_mls_service_claims(&bare_violation, endpoint, now),
            Err(AuthError::InvalidToken(_))
        ));

        let mut expired = valid.clone();
        expired.iat = Some(now - 61);
        expired.exp = now - 1;
        assert!(matches!(
            validate_mls_service_claims(&expired, endpoint, now),
            Err(AuthError::TokenExpired)
        ));

        let mut future = valid.clone();
        future.iat = Some(now + 61);
        future.exp = now + 120;
        assert!(matches!(
            validate_mls_service_claims(&future, endpoint, now),
            Err(AuthError::InvalidToken(_))
        ));

        let mut too_long = valid;
        too_long.exp = now + SERVICE_AUTH_MAX_LIFETIME_SECONDS + 1;
        assert!(matches!(
            validate_mls_service_claims(&too_long, endpoint, now),
            Err(AuthError::InvalidToken(_))
        ));
    }
}

#[cfg(test)]
mod federation_fixture_tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
    use tokio::sync::Mutex;

    static TEST_ENV_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    #[tokio::test]
    async fn test_offline_did_fixtures_loaded_and_verified() {
        let _guard = TEST_ENV_LOCK.lock().await;

        let fixture_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("e2e-tests/fixtures");
        let ds1_did_path = fixture_dir.join("ds1-did.json");
        let ds2_did_path = fixture_dir.join("ds2-did.json");
        let ds1_key_path = fixture_dir.join("ds1-key.pem");
        let ds2_key_path = fixture_dir.join("ds2-key.pem");

        assert!(ds1_did_path.exists(), "ds1-did.json fixture exists");
        assert!(ds2_did_path.exists(), "ds2-did.json fixture exists");
        assert!(ds1_key_path.exists(), "ds1-key.pem fixture exists");
        assert!(ds2_key_path.exists(), "ds2-key.pem fixture exists");

        // Set environment for test fixture loading
        std::env::set_var("APP_ENV", "test");
        std::env::set_var(
            "TEST_DID_DOCUMENT_PATHS",
            format!("{},{}", ds1_did_path.display(), ds2_did_path.display()),
        );

        let loaded_count = load_test_did_fixtures_from_env()
            .await
            .expect("load test DID fixtures in test env");
        assert_eq!(loaded_count, 2, "must load exactly 2 DID documents");

        // Verify resolution from cache
        let doc1 = AUTH_MIDDLEWARE
            .resolve_did("did:web:ds1.catbird.blue")
            .await
            .expect("resolve ds1 did from cache");
        assert_eq!(doc1.id, "did:web:ds1.catbird.blue");
        let key1 = extract_p256_key(&doc1).expect("extract p256 key for ds1");

        let shared_middleware = shared_auth_middleware();
        let doc2 = shared_middleware
            .resolve_did("did:web:ds2.catbird.blue")
            .await
            .expect("resolve ds2 did from cache");
        assert_eq!(doc2.id, "did:web:ds2.catbird.blue");
        let key2 = extract_p256_key(&doc2).expect("extract p256 key for ds2");

        // Verify matching private keys
        let pem1 = std::fs::read_to_string(&ds1_key_path).expect("read ds1-key.pem");
        let sk1 = SigningKey::from_pkcs8_pem(&pem1).expect("parse ds1 pkcs8 pem");
        assert_eq!(*sk1.verifying_key(), key1);

        let pem2 = std::fs::read_to_string(&ds2_key_path).expect("read ds2-key.pem");
        let sk2 = SigningKey::from_pkcs8_pem(&pem2).expect("parse ds2 pkcs8 pem");
        assert_eq!(*sk2.verifying_key(), key2);

        // Test signing a request with DS1 key and verifying with AUTH_MIDDLEWARE
        let auth_client = crate::federation::ServiceAuthClient::from_es256_pem(
            "did:web:ds1.catbird.blue".to_string(),
            pem1.as_bytes(),
            Some("#atproto".to_string()),
        )
        .expect("create service auth client for ds1");

        let token = auth_client
            .sign_request("did:web:ds2.catbird.blue", "blue.catbird.mlsDS.healthCheck")
            .expect("sign request");

        // Verify the token using auth middleware
        let claims = AUTH_MIDDLEWARE
            .verify_jwt_for_audience(&token, Some("did:web:ds2.catbird.blue"))
            .await
            .expect("verify DS1 service JWT using cached DID doc");
        assert_eq!(claims.iss, "did:web:ds1.catbird.blue");
        assert_eq!(claims.aud, "did:web:ds2.catbird.blue");
        assert_eq!(
            claims.lxm.as_deref(),
            Some("blue.catbird.mlsDS.healthCheck")
        );
        assert!(claims.jti.is_some(), "service auth claims must include JTI");
        // Clean up env vars
        std::env::remove_var("TEST_DID_DOCUMENT_PATHS");
    }

    #[tokio::test]
    #[should_panic(expected = "Offline DID fixtures are forbidden outside test mode")]
    async fn test_offline_did_fixtures_aborts_outside_test_mode() {
        let _guard = TEST_ENV_LOCK.lock().await;
        std::env::set_var("APP_ENV", "production");
        std::env::set_var("TEST_DID_DOCUMENT_PATHS", "/nonexistent/path.json");

        let res = load_test_did_fixtures_from_env().await;
        std::env::remove_var("TEST_DID_DOCUMENT_PATHS");
        let _ = res;
    }

    #[tokio::test]
    async fn test_federation_config_loads_key_from_file_and_health_check_payload() {
        let _guard = TEST_ENV_LOCK.lock().await;

        let fixture_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("e2e-tests/fixtures");
        let ds1_key_path = fixture_dir.join("ds1-key.pem");

        std::env::set_var("APP_ENV", "test");
        std::env::set_var("SERVICE_DID", "did:web:ds1.catbird.blue");
        std::env::set_var("FEDERATION_ENABLED", "true");
        std::env::set_var("FEDERATION_MODE", "allowlist");
        std::env::set_var("SIGNING_KEY_FILE", ds1_key_path.to_str().unwrap());
        std::env::set_var("FEDERATION_CAPABILITIES", "baseline,reconciliation-v1");

        let fed_config = crate::federation::FederationConfig::from_env();
        assert!(fed_config.enabled);
        assert_eq!(fed_config.self_did, "did:web:ds1.catbird.blue");
        assert!(fed_config.signing_key_pem.is_some());

        let caps = crate::federation::local_federation_capabilities();
        assert!(caps.contains(&"baseline".to_string()));
        assert!(caps.contains(&"reconciliation-v1".to_string()));

        // Verify health check handler
        let res = crate::handlers::ds::health_check()
            .await
            .expect("health check ok");
        let value = res.0;
        assert_eq!(value["did"], "did:web:ds1.catbird.blue");
        assert_eq!(value["version"], "1.0.0");
        let res_caps: Vec<String> = serde_json::from_value(value["federationCapabilities"].clone())
            .expect("parse caps array");
        assert_eq!(
            res_caps,
            vec!["baseline".to_string(), "reconciliation-v1".to_string()]
        );

        std::env::remove_var("SIGNING_KEY_FILE");
        std::env::remove_var("FEDERATION_CAPABILITIES");
    }

    #[tokio::test]
    #[should_panic(expected = "could not be read")]
    async fn test_unreadable_signing_key_file_panics_in_every_environment() {
        let _guard = TEST_ENV_LOCK.lock().await;
        std::env::set_var("SERVICE_DID", "did:web:ds1.catbird.blue");
        std::env::set_var("SIGNING_KEY_FILE", "/nonexistent/path/to/signing_key.pem");
        let res = crate::federation::FederationConfig::from_env();
        std::env::remove_var("SIGNING_KEY_FILE");
        let _ = res;
    }
}

#[cfg(test)]
#[path = "auth/staging_identity_fixture_tests.rs"]
mod staging_identity_fixture_tests;
