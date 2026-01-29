use axum::{
    extract::Request,
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use base64::Engine;
use dashmap::DashMap;
use once_cell::sync::Lazy;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

/// Header name for recovery mode bypass requests
/// When set to "true", the middleware allows the request through but
/// the handler MUST verify the client actually needs recovery (0 key packages)
pub const RECOVERY_MODE_HEADER: &str = "x-mls-recovery-mode";

/// Token bucket rate limiter
#[derive(Clone)]
pub struct TokenBucket {
    /// Maximum tokens (burst capacity)
    capacity: u32,
    /// Current token count
    tokens: f64,
    /// Refill rate (tokens per second)
    refill_rate: f64,
    /// Last refill timestamp
    last_refill: Instant,
}

impl TokenBucket {
    pub fn new(capacity: u32, refill_rate: f64) -> Self {
        Self {
            capacity,
            tokens: capacity as f64,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    /// Try to consume a token, returns true if successful
    pub fn try_consume(&mut self) -> bool {
        self.refill();

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Refill tokens based on elapsed time
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();

        let new_tokens = elapsed * self.refill_rate;
        self.tokens = (self.tokens + new_tokens).min(self.capacity as f64);
        self.last_refill = now;
    }

    /// Time until next token available (for retryAfter header)
    pub fn retry_after_secs(&self) -> u64 {
        if self.tokens >= 1.0 {
            0
        } else {
            let needed_tokens = 1.0 - self.tokens;
            (needed_tokens / self.refill_rate).ceil() as u64
        }
    }
}

/// Rate limiter state shared across middleware
#[derive(Clone)]
pub struct RateLimiter {
    /// Buckets per key (format: "did:room_id" or just "did" for global)
    buckets: Arc<DashMap<String, TokenBucket>>,
    /// Default capacity (burst)
    capacity: u32,
    /// Default refill rate (tokens/sec)
    refill_rate: f64,
}

impl RateLimiter {
    pub fn new(capacity: u32, refill_rate: f64) -> Self {
        Self {
            buckets: Arc::new(DashMap::new()),
            capacity,
            refill_rate,
        }
    }

    /// Check if request is allowed for given key
    pub fn check(&self, key: &str) -> Result<(), u64> {
        let mut bucket = self
            .buckets
            .entry(key.to_string())
            .or_insert_with(|| TokenBucket::new(self.capacity, self.refill_rate));

        if bucket.try_consume() {
            Ok(())
        } else {
            Err(bucket.retry_after_secs())
        }
    }

    /// Cleanup old buckets (call periodically to prevent memory leak)
    pub async fn cleanup_old_buckets(&self, max_age: Duration) {
        let now = Instant::now();
        self.buckets
            .retain(|_, bucket| now.duration_since(bucket.last_refill) < max_age);
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        // Defaults: 60 requests per minute for unauthenticated (per-IP)
        let per_minute = std::env::var("RATE_LIMIT_IP_PER_MINUTE")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(60);

        // Allow short bursts (10% of per-minute limit)
        let burst = std::env::var("IP_RATE_BURST")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(per_minute.max(10) / 10);

        // Refill rate: per_minute / 60 = tokens per second
        let refill = per_minute as f64 / 60.0;

        Self::new(burst, refill)
    }
}

/// Per-DID rate limiter with endpoint-specific quotas
#[derive(Clone)]
pub struct DidRateLimiter {
    /// Buckets per DID:endpoint key
    buckets: Arc<DashMap<String, TokenBucket>>,
}

impl DidRateLimiter {
    pub fn new() -> Self {
        Self {
            buckets: Arc::new(DashMap::new()),
        }
    }

    /// Check if request is allowed for given DID and endpoint
    pub fn check_did_limit(&self, did: &str, endpoint: &str) -> Result<(), u64> {
        let (limit, window) = get_endpoint_quota(endpoint);
        let refill_rate = limit as f64 / window.as_secs_f64();

        let key = format!("{}:{}", did, endpoint);

        let mut bucket = self
            .buckets
            .entry(key)
            .or_insert_with(|| TokenBucket::new(limit, refill_rate));

        if bucket.try_consume() {
            Ok(())
        } else {
            Err(bucket.retry_after_secs())
        }
    }

    /// Cleanup old buckets (call periodically to prevent memory leak)
    pub async fn cleanup_old_buckets(&self, max_age: Duration) {
        let now = Instant::now();
        self.buckets
            .retain(|_, bucket| now.duration_since(bucket.last_refill) < max_age);
    }
}

impl Default for DidRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Get endpoint-specific quota (limit, window duration)
fn get_endpoint_quota(endpoint: &str) -> (u32, Duration) {
    let window = Duration::from_secs(60); // 1 minute window

    // Extract base endpoint name from path
    let endpoint_name = endpoint
        .trim_start_matches("/xrpc/")
        .trim_start_matches("blue.catbird.mls.");

    let limit = if endpoint_name.contains("sendMessage") {
        std::env::var("RATE_LIMIT_SEND_MESSAGE")
        .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(100) // High frequency messaging
    } else if endpoint_name.contains("getMessages") || endpoint_name.contains("getConvos") {
        std::env::var("RATE_LIMIT_GET_MESSAGES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(500) // High frequency polling/sync operations
    } else if endpoint_name.contains("updateReadState") || endpoint_name.contains("markRead") {
        std::env::var("RATE_LIMIT_READ_STATE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(300) // Read receipts called frequently
    } else if endpoint_name.contains("publishKeyPackage") {
        std::env::var("RATE_LIMIT_PUBLISH_KEY_PACKAGE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(50) // Increased from 20 for recovery scenarios (per-device)
    } else if endpoint_name.contains("registerDevice") {
        std::env::var("RATE_LIMIT_REGISTER_DEVICE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10) // Device registration (per-device, allows fresh installs)
    } else if endpoint_name.contains("syncKeyPackages") {
        std::env::var("RATE_LIMIT_SYNC_KEY_PACKAGES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30) // Key package sync for recovery (per-device)
    } else if endpoint_name.contains("addMembers") || endpoint_name.contains("removeMember") {
        std::env::var("RATE_LIMIT_ADD_MEMBERS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10) // Admin operations
    } else if endpoint_name.contains("createConvo") {
        std::env::var("RATE_LIMIT_CREATE_CONVO")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5) // Expensive operations
    } else if endpoint_name.contains("reportMember") {
        std::env::var("RATE_LIMIT_REPORT_MEMBER")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5) // Prevent report spam
    } else {
        std::env::var("RATE_LIMIT_DID_DEFAULT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(200) // Default for other operations
    };

    (limit, window)
}

/// Global DID rate limiter instance
pub static DID_RATE_LIMITER: Lazy<DidRateLimiter> = Lazy::new(DidRateLimiter::new);

/// Per-IP rate limiter instance
pub static IP_LIMITER: Lazy<RateLimiter> = Lazy::new(RateLimiter::default);

/// Check if an endpoint should use device-based rate limiting
/// Device-based limits give fresh devices (app reinstall) their own quota
fn should_use_device_rate_limit(endpoint: &str) -> bool {
    let endpoint_name = endpoint
        .trim_start_matches("/xrpc/")
        .trim_start_matches("blue.catbird.mls.");
    
    // Device-specific operations get per-device limits
    // This allows a fresh device (app reinstall) to upload key packages
    // even if the user's other devices have exhausted the quota
    endpoint_name.contains("publishKeyPackage")
        || endpoint_name.contains("registerDevice")
        || endpoint_name.contains("syncKeyPackages")
}

/// Check if request is in recovery mode
/// Recovery mode bypasses rate limits for key package operations
/// The HANDLER must verify the client genuinely has 0 key packages
fn is_recovery_mode_request(headers: &HeaderMap, endpoint: &str) -> bool {
    // Only allow recovery mode for key package endpoints
    if !should_use_device_rate_limit(endpoint) {
        return false;
    }
    
    // Check for recovery mode header
    headers
        .get(RECOVERY_MODE_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Middleware for rate limiting based on user DID or device DID
pub async fn rate_limit_middleware(request: Request, next: Next) -> Result<Response, StatusCode> {

    let headers = request.headers();
    let uri = request.uri().to_string();

    // Check for recovery mode bypass (handler MUST verify 0 key packages)
    if is_recovery_mode_request(headers, &uri) {
        let did = extract_did_from_auth_header(headers).unwrap_or_else(|| "unknown".to_string());
        tracing::info!(
            "🚨 Recovery mode bypass requested for {}: {} (handler must verify)",
            did,
            uri
        );
        return Ok(next.run(request).await);
    }

    // Try to extract DID from Authorization header for authenticated requests
    let did_opt = extract_did_from_auth_header(headers);

    // Use DID-based rate limiting for authenticated requests
    if let Some(did) = did_opt {
        // For device-specific operations, use the full DID (includes #device-uuid)
        // For other operations, extract just the user DID to share quota across devices
        let use_device_limit = should_use_device_rate_limit(&uri);
        let rate_limit_key = if use_device_limit {
            // Use full DID including device fragment for device-specific operations
            // Format: did:plc:user#device-uuid
            did.clone()
        } else {
            // Extract base user DID (strip #device-uuid if present)
            did.split('#').next().unwrap_or(&did).to_string()
        };
        
        match DID_RATE_LIMITER.check_did_limit(&rate_limit_key, &uri) {
            Ok(()) => {
                tracing::debug!(
                    "Rate limit passed for {} (mode: {}): {}",
                    rate_limit_key,
                    if use_device_limit { "device" } else { "user" },
                    uri
                );
                Ok(next.run(request).await)
            }
            Err(retry_after) => {
                tracing::warn!(
                    "Rate limit exceeded for {} (mode: {}): {} (retry after {} seconds)",
                    rate_limit_key,
                    if use_device_limit { "device" } else { "user" },
                    uri,
                    retry_after
                );
                let mut resp = Response::new(axum::body::Body::empty());
                let headers = resp.headers_mut();
                headers.insert(
                    axum::http::header::RETRY_AFTER,
                    axum::http::HeaderValue::from_str(&retry_after.to_string())
                        .unwrap_or(axum::http::HeaderValue::from_static("1")),
                );
                *resp.status_mut() = StatusCode::TOO_MANY_REQUESTS;
                Ok(resp)
            }
        }
    } else {
        // Fall back to IP-based rate limiting for unauthenticated requests
        let client_ip = extract_client_ip(headers);
        match IP_LIMITER.check(&client_ip) {
            Ok(()) => {
                tracing::debug!("IP rate limit passed for {}: {}", client_ip, uri);
                Ok(next.run(request).await)
            }
            Err(retry_after) => {
                tracing::warn!(
                    "IP rate limit exceeded for {}: {} (retry after {} seconds)",
                    client_ip,
                    uri,
                    retry_after
                );
                let mut resp = Response::new(axum::body::Body::empty());
                let headers = resp.headers_mut();
                headers.insert(
                    axum::http::header::RETRY_AFTER,
                    axum::http::HeaderValue::from_str(&retry_after.to_string())
                        .unwrap_or(axum::http::HeaderValue::from_static("1")),
                );
                *resp.status_mut() = StatusCode::TOO_MANY_REQUESTS;
                Ok(resp)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_bucket() {
        let mut bucket = TokenBucket::new(10, 5.0); // 10 capacity, 5/s refill

        // Should be able to consume up to capacity
        for _ in 0..10 {
            assert!(bucket.try_consume());
        }

        // Should fail after exhausting tokens
        assert!(!bucket.try_consume());
    }

    #[tokio::test]
    async fn test_token_bucket_refill() {
        let mut bucket = TokenBucket::new(10, 10.0); // 10/s refill

        // Exhaust tokens
        for _ in 0..10 {
            bucket.try_consume();
        }

        // Wait 1 second for refill
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Should have ~10 tokens refilled
        assert!(bucket.try_consume());
    }

    #[tokio::test]
    async fn test_rate_limiter() {
        let limiter = RateLimiter::new(5, 1.0);

        // Should allow first 5 requests
        for _ in 0..5 {
            assert!(limiter.check("user1").is_ok());
        }

        // Should deny 6th request
        assert!(limiter.check("user1").is_err());

        // Different user should have own bucket
        assert!(limiter.check("user2").is_ok());
    }
}

fn extract_client_ip(headers: &HeaderMap) -> String {
    // Prefer X-Forwarded-For first value
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|h| h.to_str().ok()) {
        if let Some(ip) = xff.split(',').next().map(|s| s.trim().to_string()) {
            if !ip.is_empty() {
                return ip;
            }
        }
    }
    // Then Cloudflare / Nginx style headers
    if let Some(ip) = headers
        .get("cf-connecting-ip")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|h| h.to_str().ok())
    {
        return ip.to_string();
    }
    // Fall back to opaque key
    "unknown".to_string()
}

/// Extract DID from Authorization header (lightweight parsing, no validation)
fn extract_did_from_auth_header(headers: &HeaderMap) -> Option<String> {
    let auth_header = headers.get(axum::http::header::AUTHORIZATION)?;
    let auth_str = auth_header.to_str().ok()?;

    // Extract Bearer token
    let token = auth_str.strip_prefix("Bearer ")?.trim();

    // Parse JWT without validation (we only need the DID for rate limiting)
    // JWT format: header.payload.signature
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }

    // Decode payload (base64url)
    let payload = parts[1];
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;

    // Parse JSON to extract issuer (DID)
    let json: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    let iss = json.get("iss")?.as_str()?;

    Some(iss.to_string())
}
