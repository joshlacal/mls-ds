use axum::{
    async_trait,
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
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use once_cell::sync::Lazy;
use moka::future::Cache;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{collections::HashMap, num::NonZeroU32, sync::Arc};
use thiserror::Error;
use tracing::debug;

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

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

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
        let (status, error_message) = match self {
            AuthError::MissingAuthHeader => (StatusCode::UNAUTHORIZED, self.to_string()),
            AuthError::InvalidAuthFormat => (StatusCode::UNAUTHORIZED, self.to_string()),
            AuthError::InvalidToken(_) => (StatusCode::UNAUTHORIZED, self.to_string()),
            AuthError::TokenExpired => (StatusCode::UNAUTHORIZED, self.to_string()),
            AuthError::InvalidDid(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AuthError::DidResolutionFailed(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AuthError::InvalidSignature => (StatusCode::UNAUTHORIZED, self.to_string()),
            AuthError::RateLimitExceeded => (StatusCode::TOO_MANY_REQUESTS, self.to_string()),
            AuthError::MissingVerificationMethod => (StatusCode::BAD_REQUEST, self.to_string()),
            AuthError::UnsupportedKeyType(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AuthError::MissingJti => (StatusCode::UNAUTHORIZED, self.to_string()),
            AuthError::ReplayDetected => (StatusCode::UNAUTHORIZED, self.to_string()),
            AuthError::MissingLxm => (StatusCode::UNAUTHORIZED, self.to_string()),
            AuthError::LxmMismatch => (StatusCode::UNAUTHORIZED, self.to_string()),
            AuthError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };

        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
}

/// AT Protocol JWT claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtProtoClaims {
    pub iss: String,    // Issuer (DID)
    pub aud: String,    // Audience (service DID or URL)
    pub exp: i64,       // Expiration time
    pub iat: Option<i64>, // Issued at
    pub sub: Option<String>, // Subject (can be same as iss)
    pub lxm: Option<String>, // Optional: authorized endpoint NSID
    pub jti: Option<String>, // Optional: nonce for replay-prevention
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
struct CachedDidDoc {
    doc: DidDocument,
    cached_at: DateTime<Utc>,
}

/// Authenticated user extracted from request
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub did: String,
    pub claims: AtProtoClaims,
}

/// Authentication middleware state
#[derive(Clone)]
pub struct AuthMiddleware {
    did_cache: Cache<String, CachedDidDoc>,
    rate_limiters: Arc<RwLock<HashMap<String, Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>>>>,
    http_client: reqwest::Client,
    cache_ttl_seconds: u64,
    rate_limit_quota: Quota,
}

impl AuthMiddleware {
    pub fn new() -> Self {
        Self::with_config(300, 100, 60) // 5 min cache, 100 requests per 60 seconds
    }

    pub fn with_config(
        cache_ttl_seconds: u64,
        rate_limit_requests: u32,
        _rate_limit_period_seconds: u64,
    ) -> Self {
        let did_cache = Cache::builder()
            .max_capacity(10_000)
            .time_to_live(std::time::Duration::from_secs(cache_ttl_seconds))
            .build();

        let quota = Quota::per_second(NonZeroU32::new(rate_limit_requests.max(1)).unwrap())
            .allow_burst(NonZeroU32::new((rate_limit_requests.max(1) / 10).max(1)).unwrap());

        Self {
            did_cache,
            rate_limiters: Arc::new(RwLock::new(HashMap::new())),
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build().unwrap_or_else(|_| reqwest::Client::new()),
            cache_ttl_seconds,
            rate_limit_quota: quota,
        }
    }

/// Verify JWT token and extract claims (HS256 for dev, ES256/ES256K for inter-service)
async fn verify_jwt(&self, token: &str) -> Result<AtProtoClaims, AuthError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 { return Err(AuthError::InvalidToken("Invalid JWT format".into())); }

    let header_json = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| AuthError::InvalidToken(format!("Invalid base64 header: {}", e)))?;
    let payload_json = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| AuthError::InvalidToken(format!("Invalid base64 payload: {}", e)))?;

    #[derive(Deserialize)]
    struct JwtHeader { alg: String, #[allow(dead_code)] typ: Option<String> }
    let header: JwtHeader = serde_json::from_slice(&header_json)
        .map_err(|e| AuthError::InvalidToken(format!("Invalid header JSON: {}", e)))?;
    let claims: AtProtoClaims = serde_json::from_slice(&payload_json)
        .map_err(|e| AuthError::InvalidToken(format!("Invalid claims JSON: {}", e)))?;

    // Expiration
    let now = Utc::now().timestamp();
    if claims.exp < now { return Err(AuthError::TokenExpired); }

    // Audience enforcement when configured
    if let Ok(service_did) = std::env::var("SERVICE_DID") {
        if claims.aud != service_did {
            return Err(AuthError::InvalidToken("aud does not match SERVICE_DID".into()));
        }
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);

    match header.alg.as_str() {
        // Dev/staging shared-secret auth
        "HS256" => {
            let secret = std::env::var("JWT_SECRET")
                .map_err(|_| AuthError::InvalidToken("HS256 requires JWT_SECRET".into()))?;
            let mut val = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
            val.set_audience(&[&claims.aud]);
            val.set_issuer(&[&claims.iss]);
            jsonwebtoken::decode::<AtProtoClaims>(token, &jsonwebtoken::DecodingKey::from_secret(secret.as_bytes()), &val)
                .map_err(|e| AuthError::InvalidToken(format!("HS256 verify failed: {}", e)))
                .map(|d| d.claims)
        }
        // ES256: P-256 ECDSA (JOSE signature R||S)
        "ES256" => {
            use p256::ecdsa::{signature::Verifier, VerifyingKey, Signature};
            use p256::EncodedPoint;
            let did_doc = self.resolve_did(&claims.iss).await?;
            let vm = did_doc.verification_method.first().ok_or(AuthError::MissingVerificationMethod)?;
            let jwk = vm.public_key_jwk.as_ref().ok_or(AuthError::MissingVerificationMethod)?;
            if jwk.kty != "EC" || jwk.crv.to_ascii_uppercase() != "P-256" { return Err(AuthError::UnsupportedKeyType(format!("Expected EC P-256, got {} {}", jwk.kty, jwk.crv))); }
            let x = URL_SAFE_NO_PAD.decode(&jwk.x).map_err(|e| AuthError::InvalidToken(format!("bad jwk.x: {}", e)))?;
            let y = URL_SAFE_NO_PAD.decode(jwk.y.as_ref().ok_or_else(|| AuthError::MissingVerificationMethod)?)
                .map_err(|e| AuthError::InvalidToken(format!("bad jwk.y: {}", e)))?;
            let ep = EncodedPoint::from_affine_coordinates(p256::FieldBytes::from_slice(&x), p256::FieldBytes::from_slice(&y), false);
            let vk = VerifyingKey::from_encoded_point(&ep).map_err(|_| AuthError::InvalidToken("invalid P-256 point".into()))?;
            let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).map_err(|e| AuthError::InvalidToken(format!("Invalid b64 sig: {}", e)))?;
            let sig = Signature::from_slice(&sig_bytes).map_err(|_| AuthError::InvalidToken("invalid ES256 signature".into()))?;
            vk.verify(signing_input.as_bytes(), &sig).map_err(|_| AuthError::InvalidSignature)?;
            Ok(claims)
        }
        // ES256K: secp256k1 ECDSA (R||S)
        "ES256K" => {
            use k256::ecdsa::{signature::Verifier, VerifyingKey, Signature};
            use k256::EncodedPoint;
            let did_doc = self.resolve_did(&claims.iss).await?;
            let vm = did_doc.verification_method.first().ok_or(AuthError::MissingVerificationMethod)?;
            let jwk = vm.public_key_jwk.as_ref().ok_or(AuthError::MissingVerificationMethod)?;
            if jwk.kty != "EC" { return Err(AuthError::UnsupportedKeyType(format!("Expected EC, got {}", jwk.kty))); }
            let crv = jwk.crv.to_ascii_lowercase();
            if crv != "secp256k1" && crv != "k-256" && crv != "p-256k" { return Err(AuthError::UnsupportedKeyType(format!("Expected secp256k1, got {}", jwk.crv))); }
            let x = URL_SAFE_NO_PAD.decode(&jwk.x).map_err(|e| AuthError::InvalidToken(format!("bad jwk.x: {}", e)))?;
            let y = URL_SAFE_NO_PAD.decode(jwk.y.as_ref().ok_or_else(|| AuthError::MissingVerificationMethod)?)
                .map_err(|e| AuthError::InvalidToken(format!("bad jwk.y: {}", e)))?;
            let ep = EncodedPoint::from_affine_coordinates(p256::FieldBytes::from_slice(&x), p256::FieldBytes::from_slice(&y), false);
            let vk = VerifyingKey::from_encoded_point(&ep).map_err(|_| AuthError::InvalidToken("invalid secp256k1 point".into()))?;
            let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).map_err(|e| AuthError::InvalidToken(format!("Invalid b64 sig: {}", e)))?;
            let sig = Signature::from_slice(&sig_bytes).map_err(|_| AuthError::InvalidToken("invalid ES256K signature".into()))?;
            vk.verify(signing_input.as_bytes(), &sig).map_err(|_| AuthError::InvalidSignature)?;
            Ok(claims)
        }
        other => Err(AuthError::UnsupportedKeyType(format!("Unsupported alg: {}", other))),
    }
}

/// Resolve DID document with caching
    async fn resolve_did(&self, did: &str) -> Result<DidDocument, AuthError> {
        // Validate DID format
        if !did.starts_with("did:") {
            return Err(AuthError::InvalidDid(format!("DID must start with 'did:': {}", did)));
        }

        // Check cache first
        if let Some(cached) = self.did_cache.get(did).await {
            debug!("DID document cache hit for {}", did);
            return Ok(cached.doc);
        }

        debug!("Resolving DID document for {}", did);

        // Resolve based on DID method
        let doc = if did.starts_with("did:plc:") {
            self.resolve_plc_did(did).await?
        } else if did.starts_with("did:web:") {
            self.resolve_web_did(did).await?
        } else {
            return Err(AuthError::InvalidDid(format!("Unsupported DID method: {}", did)));
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
        let _plc_id = did.strip_prefix("did:plc:").ok_or_else(|| AuthError::InvalidDid(format!("Invalid PLC DID: {}", did)))?;
        let url = format!("https://plc.directory/{}", did);

        let response = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| AuthError::DidResolutionFailed(format!("HTTP error: {}", e)))?;

        if !response.status().is_success() {
            return Err(AuthError::DidResolutionFailed(format!(
                "PLC directory returned status {}",
                response.status()
            )));
        }

        let doc = response
            .json::<DidDocument>()
            .await
            .map_err(|e| AuthError::DidResolutionFailed(format!("Failed to parse DID document: {}", e)))?;

        Ok(doc)
    }

    /// Resolve did:web DID via HTTPS
    async fn resolve_web_did(&self, did: &str) -> Result<DidDocument, AuthError> {
        let web_path = did.strip_prefix("did:web:").ok_or_else(|| AuthError::InvalidDid(format!("Invalid WEB DID: {}", did)))?;
        let domain = web_path.replace(':', "/");
        let url = format!("https://{}/.well-known/did.json", domain);

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

        let doc = response
            .json::<DidDocument>()
            .await
            .map_err(|e| AuthError::DidResolutionFailed(format!("Failed to parse DID document: {}", e)))?;

        Ok(doc)
    }
    /// Check rate limit for a DID
    fn check_rate_limit(&self, did: &str) -> Result<(), AuthError> {
        let mut limiters = self.rate_limiters.write();
        
        let limiter = limiters
            .entry(did.to_string())
            .or_insert_with(|| {
                Arc::new(RateLimiter::direct(self.rate_limit_quota))
            })
            .clone();

        drop(limiters);

        limiter
            .check()
            .map_err(|_| AuthError::RateLimitExceeded)?;

        Ok(())
    }
}

impl Default for AuthMiddleware {
    fn default() -> Self {
        Self::new()
    }
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

fn truthy(var: &str) -> bool {
    matches!(var, "1" | "true" | "TRUE" | "yes" | "YES")
}

/// Enforce optional lxm (endpoint) and jti (replay) constraints.
pub fn enforce_standard(claims: &AtProtoClaims, endpoint_nsid: &str) -> Result<(), AuthError> {
    // Enforce lxm if requested
    if truthy(&std::env::var("ENFORCE_LXM").unwrap_or_default()) {
        let lxm = claims.lxm.as_deref().ok_or(AuthError::MissingLxm)?;
        if lxm != endpoint_nsid {
            return Err(AuthError::LxmMismatch);
        }
    }

    // Enforce jti replay-prevention unless disabled
    let enforce_jti = std::env::var("ENFORCE_JTI").map(|s| truthy(&s)).unwrap_or(true);
    if enforce_jti {
        let jti = claims.jti.as_deref().ok_or(AuthError::MissingJti)?;
        let key = format!("{}|{}", claims.iss, jti);
        if JTI_CACHE.get(&key).is_some() {
            return Err(AuthError::ReplayDetected);
        }
        JTI_CACHE.insert(key, ());
    }
    Ok(())
}

/// Axum extractor for authenticated requests
#[async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Extract authorization header
        let auth_header = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or(AuthError::MissingAuthHeader)?;

        // Parse bearer token
        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or(AuthError::InvalidAuthFormat)?;

        // Get or create auth middleware (in production, this should be passed via state)
        let middleware = AuthMiddleware::new();

        // Verify JWT and extract claims
        let claims = middleware.verify_jwt(token).await?;

        // Check rate limit
        middleware.check_rate_limit(&claims.iss)?;

        debug!("Authenticated request from DID: {}", claims.iss);

        Ok(AuthUser {
            did: claims.iss.clone(),
            claims,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}
