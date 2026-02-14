use axum::{
    extract::{connect_info::ConnectInfo, Request},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use ipnet::IpNet;
use moka::sync::Cache;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::{
    net::{IpAddr, SocketAddr},
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
    /// Buckets per key (bounded + expiring cache)
    buckets: Arc<Cache<String, Arc<Mutex<TokenBucket>>>>,
    /// Default capacity (burst)
    capacity: u32,
    /// Default refill rate (tokens/sec)
    refill_rate: f64,
}

fn parse_u64_env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
}

fn build_bucket_cache(
    capacity: u64,
    ttl_seconds: u64,
) -> Arc<Cache<String, Arc<Mutex<TokenBucket>>>> {
    Arc::new(
        Cache::builder()
            .max_capacity(capacity)
            .time_to_idle(Duration::from_secs(ttl_seconds))
            .build(),
    )
}

impl RateLimiter {
    pub fn new(capacity: u32, refill_rate: f64) -> Self {
        let max_keys = parse_u64_env("RATE_LIMIT_IP_MAX_KEYS", 100_000);
        let ttl_seconds = parse_u64_env("RATE_LIMIT_BUCKET_TTL_SECONDS", 600);
        Self {
            buckets: build_bucket_cache(max_keys, ttl_seconds),
            capacity,
            refill_rate,
        }
    }

    /// Check if request is allowed for given key
    pub fn check(&self, key: &str) -> Result<(), u64> {
        let bucket = self.buckets.get_with(key.to_string(), || {
            Arc::new(Mutex::new(TokenBucket::new(
                self.capacity,
                self.refill_rate,
            )))
        });
        let mut bucket = bucket.lock();

        if bucket.try_consume() {
            Ok(())
        } else {
            Err(bucket.retry_after_secs())
        }
    }

    /// Cleanup old buckets (call periodically to prevent memory leak)
    pub async fn cleanup_old_buckets(&self, _max_age: Duration) {
        self.buckets.run_pending_tasks();
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
            .unwrap_or(per_minute.max(20));

        // Refill rate: per_minute / 60 = tokens per second
        let refill = per_minute as f64 / 60.0;

        Self::new(burst, refill)
    }
}

/// Per-DID rate limiter with endpoint-specific quotas
#[derive(Clone)]
pub struct DidRateLimiter {
    /// Buckets per DID:endpoint key (bounded + expiring cache)
    buckets: Arc<Cache<String, Arc<Mutex<TokenBucket>>>>,
}

impl DidRateLimiter {
    pub fn new() -> Self {
        let max_keys = parse_u64_env("RATE_LIMIT_DID_MAX_KEYS", 300_000);
        let ttl_seconds = parse_u64_env("RATE_LIMIT_DID_BUCKET_TTL_SECONDS", 900);
        Self {
            buckets: build_bucket_cache(max_keys, ttl_seconds),
        }
    }

    /// Check if request is allowed for given DID and endpoint
    pub fn check_did_limit(&self, did: &str, endpoint: &str) -> Result<(), u64> {
        let (limit, window) = get_endpoint_quota(endpoint);
        let refill_rate = limit as f64 / window.as_secs_f64();

        // Include effective limit in key so dynamic quota changes do not reuse stale capacity.
        let key = format!("{}:{}:{}", did, endpoint, limit);

        let bucket = self.buckets.get_with(key, || {
            Arc::new(Mutex::new(TokenBucket::new(limit, refill_rate)))
        });
        let mut bucket = bucket.lock();

        if bucket.try_consume() {
            Ok(())
        } else {
            Err(bucket.retry_after_secs())
        }
    }

    /// Cleanup old buckets (call periodically to prevent memory leak)
    pub async fn cleanup_old_buckets(&self, _max_age: Duration) {
        self.buckets.run_pending_tasks();
    }
}

impl Default for DidRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-DS federation rate limiter (separate from user DID quotas).
#[derive(Clone)]
pub struct FederationPeerRateLimiter {
    buckets: Arc<Cache<String, Arc<Mutex<TokenBucket>>>>,
}

impl FederationPeerRateLimiter {
    pub fn new() -> Self {
        let max_keys = parse_u64_env("RATE_LIMIT_FEDERATION_MAX_KEYS", 100_000);
        let ttl_seconds = parse_u64_env("RATE_LIMIT_FEDERATION_BUCKET_TTL_SECONDS", 900);
        Self {
            buckets: build_bucket_cache(max_keys, ttl_seconds),
        }
    }

    /// Check if request is allowed for given peer DS and federation NSID.
    ///
    /// `per_minute_override` comes from peer policy and, when set, overrides endpoint defaults.
    pub fn check_peer_limit(
        &self,
        peer_ds_did: &str,
        endpoint_nsid: &str,
        per_minute_override: Option<u32>,
    ) -> Result<(), u64> {
        let (limit, window) = get_federation_endpoint_quota(endpoint_nsid, per_minute_override);
        let refill_rate = limit as f64 / window.as_secs_f64();

        // Include effective limit in the key so quota changes don't reuse stale bucket capacity.
        let key = format!("{}:{}:{}", peer_ds_did, endpoint_nsid, limit);

        let bucket = self.buckets.get_with(key, || {
            Arc::new(Mutex::new(TokenBucket::new(limit, refill_rate)))
        });
        let mut bucket = bucket.lock();

        if bucket.try_consume() {
            Ok(())
        } else {
            Err(bucket.retry_after_secs())
        }
    }

    pub async fn cleanup_old_buckets(&self, _max_age: Duration) {
        self.buckets.run_pending_tasks();
    }
}

impl Default for FederationPeerRateLimiter {
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

fn get_federation_endpoint_quota(
    endpoint_nsid: &str,
    per_minute_override: Option<u32>,
) -> (u32, Duration) {
    let window = Duration::from_secs(60);

    if let Some(limit) = per_minute_override {
        return (limit.max(1), window);
    }

    let limit = if endpoint_nsid.ends_with(".deliverMessage") {
        std::env::var("FEDERATION_RATE_LIMIT_DELIVER_MESSAGE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(240)
    } else if endpoint_nsid.ends_with(".deliverWelcome") {
        std::env::var("FEDERATION_RATE_LIMIT_DELIVER_WELCOME")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(120)
    } else if endpoint_nsid.ends_with(".submitCommit") {
        std::env::var("FEDERATION_RATE_LIMIT_SUBMIT_COMMIT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(120)
    } else if endpoint_nsid.ends_with(".fetchKeyPackage") {
        std::env::var("FEDERATION_RATE_LIMIT_FETCH_KEY_PACKAGE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(120)
    } else if endpoint_nsid.ends_with(".transferSequencer") {
        std::env::var("FEDERATION_RATE_LIMIT_TRANSFER_SEQUENCER")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30)
    } else {
        std::env::var("FEDERATION_RATE_LIMIT_DEFAULT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(180)
    };

    (limit.max(1), window)
}

/// Global DID rate limiter instance
pub static DID_RATE_LIMITER: Lazy<DidRateLimiter> = Lazy::new(DidRateLimiter::new);
/// Global per-source-DS limiter for federation endpoints.
pub static FEDERATION_DS_RATE_LIMITER: Lazy<FederationPeerRateLimiter> =
    Lazy::new(FederationPeerRateLimiter::new);

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

static TRUSTED_PROXY_CIDRS: Lazy<Vec<IpNet>> = Lazy::new(|| {
    std::env::var("TRUSTED_PROXY_CIDRS")
        .ok()
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .filter_map(|entry| match entry.parse::<IpNet>() {
                    Ok(net) => Some(net),
                    Err(err) => {
                        tracing::warn!(
                            cidr = entry,
                            error = %err,
                            "Ignoring invalid TRUSTED_PROXY_CIDRS entry"
                        );
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default()
});

/// Middleware for pre-auth throttling.
/// Uses only source IP identity (optionally from trusted proxy headers).
pub async fn rate_limit_middleware(request: Request, next: Next) -> Result<Response, StatusCode> {
    let headers = request.headers();
    let uri = request.uri().to_string();
    let client_ip = extract_client_ip(&request);

    // Check for recovery mode bypass (handler MUST verify 0 key packages)
    if is_recovery_mode_request(headers, &uri) {
        tracing::info!(
            client_ip = %client_ip,
            endpoint = %uri,
            "Recovery mode bypass requested (handler must verify true recovery state)"
        );
        return Ok(next.run(request).await);
    }

    match IP_LIMITER.check(&client_ip) {
        Ok(()) => {
            tracing::debug!("IP pre-auth rate limit passed for {}: {}", client_ip, uri);
            Ok(next.run(request).await)
        }
        Err(retry_after) => {
            tracing::warn!(
                "IP pre-auth rate limit exceeded for {}: {} (retry after {} seconds)",
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use std::net::{IpAddr, Ipv4Addr};

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

    #[test]
    fn test_trusted_proxy_uses_forwarded_ip() {
        let request = HttpRequest::builder()
            .uri("/xrpc/blue.catbird.mls.getMessages")
            .header("cf-connecting-ip", "203.0.113.10")
            .body(Body::empty())
            .expect("request");
        let mut request = request;
        request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            443,
        )));

        let trusted = vec!["10.0.0.0/8".parse::<IpNet>().expect("cidr parse")];
        assert_eq!(
            extract_client_ip_with_trusted(&request, &trusted),
            "203.0.113.10"
        );
    }

    #[test]
    fn test_untrusted_proxy_ignores_forwarded_ip() {
        let request = HttpRequest::builder()
            .uri("/xrpc/blue.catbird.mls.getMessages")
            .header("cf-connecting-ip", "203.0.113.10")
            .body(Body::empty())
            .expect("request");
        let mut request = request;
        request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
            443,
        )));

        let trusted = vec!["10.0.0.0/8".parse::<IpNet>().expect("cidr parse")];
        assert_eq!(
            extract_client_ip_with_trusted(&request, &trusted),
            "198.51.100.20"
        );
    }
}

fn parse_ip_from_header(headers: &HeaderMap, name: &str) -> Option<IpAddr> {
    headers
        .get(name)
        .and_then(|h| h.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .and_then(|value| value.parse::<IpAddr>().ok())
}

fn is_trusted_proxy(ip: IpAddr, trusted_cidrs: &[IpNet]) -> bool {
    !trusted_cidrs.is_empty() && trusted_cidrs.iter().any(|cidr| cidr.contains(&ip))
}

fn extract_client_ip_with_trusted(request: &Request, trusted_cidrs: &[IpNet]) -> String {
    let peer_ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());

    if let Some(source_ip) = peer_ip {
        if is_trusted_proxy(source_ip, trusted_cidrs) {
            if let Some(ip) = parse_ip_from_header(request.headers(), "cf-connecting-ip")
                .or_else(|| parse_ip_from_header(request.headers(), "x-forwarded-for"))
                .or_else(|| parse_ip_from_header(request.headers(), "x-real-ip"))
            {
                return ip.to_string();
            }
        }
        return source_ip.to_string();
    }

    "unknown".to_string()
}

fn extract_client_ip(request: &Request) -> String {
    extract_client_ip_with_trusted(request, &TRUSTED_PROXY_CIDRS)
}
