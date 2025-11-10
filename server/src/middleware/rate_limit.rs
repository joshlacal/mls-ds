use axum::{
    extract::Request,
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;
use once_cell::sync::Lazy;

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
    buckets: Arc<RwLock<HashMap<String, TokenBucket>>>,
    /// Default capacity (burst)
    capacity: u32,
    /// Default refill rate (tokens/sec)
    refill_rate: f64,
}

impl RateLimiter {
    pub fn new(capacity: u32, refill_rate: f64) -> Self {
        Self {
            buckets: Arc::new(RwLock::new(HashMap::new())),
            capacity,
            refill_rate,
        }
    }

    /// Check if request is allowed for given key
    pub async fn check(&self, key: &str) -> Result<(), u64> {
        let mut buckets = self.buckets.write().await;

        let bucket = buckets
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
        let mut buckets = self.buckets.write().await;
        let now = Instant::now();

        buckets.retain(|_, bucket| now.duration_since(bucket.last_refill) < max_age);
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
    buckets: Arc<RwLock<HashMap<String, TokenBucket>>>,
}

impl DidRateLimiter {
    pub fn new() -> Self {
        Self {
            buckets: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Check if request is allowed for given DID and endpoint
    pub async fn check_did_limit(&self, did: &str, endpoint: &str) -> Result<(), u64> {
        let (limit, window) = get_endpoint_quota(endpoint);
        let refill_rate = limit as f64 / window.as_secs_f64();

        let mut buckets = self.buckets.write().await;
        let key = format!("{}:{}", did, endpoint);

        let bucket = buckets
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
        let mut buckets = self.buckets.write().await;
        let now = Instant::now();

        buckets.retain(|_, bucket| now.duration_since(bucket.last_refill) < max_age);
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
    } else if endpoint_name.contains("publishKeyPackage") {
        std::env::var("RATE_LIMIT_PUBLISH_KEY_PACKAGE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(20) // Batch key package uploads
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

/// Middleware for rate limiting based on user DID
pub async fn rate_limit_middleware(request: Request, next: Next) -> Result<Response, StatusCode> {
    // Per-IP global limiter to protect unauthenticated paths and act as backstop
    static IP_LIMITER: Lazy<RateLimiter> = Lazy::new(RateLimiter::default);

    let client_ip = extract_client_ip(request.headers());
    match IP_LIMITER.check(&client_ip).await {
        Ok(()) => Ok(next.run(request).await),
        Err(retry_after) => {
            // Return 429 Too Many Requests (no body to avoid leaks)
            let mut resp = Response::new(axum::body::Body::empty());
            let headers = resp.headers_mut();
            headers.insert(
                axum::http::header::RETRY_AFTER,
                axum::http::HeaderValue::from_str(&retry_after.to_string()).unwrap_or(axum::http::HeaderValue::from_static("1")),
            );
            *resp.status_mut() = StatusCode::TOO_MANY_REQUESTS;
            Ok(resp)
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
            assert!(limiter.check("user1").await.is_ok());
        }

        // Should deny 6th request
        assert!(limiter.check("user1").await.is_err());

        // Different user should have own bucket
        assert!(limiter.check("user2").await.is_ok());
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
