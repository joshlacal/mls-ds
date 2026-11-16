use axum::{
    extract::{connect_info::ConnectInfo, Request},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use ipnet::IpNet;
use moka::sync::Cache;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use serde_json::json;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

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
        if crate::sim_hooks::is_deterministic_clock_active() {
            return Ok(());
        }
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

    /// Inspect an existing failure bucket without charging a valid request.
    /// An unseen key has the full burst available.
    pub fn retry_after_if_exhausted(&self, key: &str) -> Option<u64> {
        if crate::sim_hooks::is_deterministic_clock_active() {
            return None;
        }
        let bucket = self.buckets.get(key)?;
        let mut bucket = bucket.lock();
        bucket.refill();
        (bucket.tokens < 1.0).then(|| bucket.retry_after_secs())
    }

    /// Cleanup old buckets (call periodically to prevent memory leak)
    pub async fn cleanup_old_buckets(&self, _max_age: Duration) {
        self.buckets.run_pending_tasks();
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        // Defaults: 300 requests per minute for unauthenticated (per-IP).
        // This is intentionally generous – real abuse is caught by the
        // per-DID post-auth limiter.  The pre-auth IP limiter should only
        // fire under genuine flood/DoS conditions.
        let per_minute = std::env::var("RATE_LIMIT_IP_PER_MINUTE")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(300);

        // Allow short bursts – clients legitimately send many requests
        // during startup (sync, device registration, key packages, etc.).
        let burst = std::env::var("IP_RATE_BURST")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(per_minute.max(60));

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
        if crate::sim_hooks::is_deterministic_clock_active() {
            return Ok(());
        }
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
        if crate::sim_hooks::is_deterministic_clock_active() {
            return Ok(());
        }
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
        .trim_start_matches("blue.catbird.chat.")
        .trim_start_matches("blue.catbird.mlsDS.");

    let limit = if endpoint_name == "enrollDevice" {
        std::env::var("RATE_LIMIT_DEVICE_AUTH_BINDING")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10)
    } else if endpoint_name.contains("sendMessage") {
        std::env::var("RATE_LIMIT_SEND_MESSAGE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(100) // High frequency messaging
    } else if endpoint_name.contains("getEntries")
        || endpoint_name.contains("getConversations")
        || endpoint_name.contains("getConversationState")
    {
        std::env::var("RATE_LIMIT_GET_MESSAGES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(500) // High frequency polling/sync operations
    } else if endpoint_name.contains("publishTyping") {
        std::env::var("RATE_LIMIT_UPDATE_CURSOR")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(300) // Ephemeral typing events
    } else if endpoint_name.contains("replenishKeyPackages") {
        std::env::var("RATE_LIMIT_PUBLISH_KEY_PACKAGE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(50) // Key packages replenished (per-device)
    } else if endpoint_name.contains("createConversation") {
        std::env::var("RATE_LIMIT_CREATE_CONVO")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5) // Expensive operations
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
/// `getRecoveryShare` charges only malformed/unauthorized ingress here. A
/// signed wrong-token miss has its own device and IP buckets in the handler,
/// and a valid fetch must not be blocked by another device's misses.
static RECOVERY_SHARE_INGRESS_FAILURE_LIMITER: Lazy<RateLimiter> =
    Lazy::new(|| RateLimiter::new(300, 300.0 / 60.0));

fn default_trusted_proxy_cidrs() -> Vec<IpNet> {
    [
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "::1/128",
        "fc00::/7",
    ]
    .into_iter()
    .map(|cidr| cidr.parse::<IpNet>().expect("static trusted proxy CIDR"))
    .collect()
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
        .unwrap_or_else(default_trusted_proxy_cidrs)
});

/// Middleware for pre-auth throttling.
/// Uses only source IP identity (optionally from trusted proxy headers).
pub async fn rate_limit_middleware(request: Request, next: Next) -> Result<Response, StatusCode> {
    // Log the path only. The query string of chat reads carries device ids, conversation
    // ids and DIDs, and an address next to it would tie those identifiers to a network
    // location in the log.
    let path = request.uri().path().to_owned();
    // A valid fetch is exempt from the shared pre-auth bucket: another
    // device's wrong fetch tokens must not block this one. Malformed or
    // unauthorized ingress still needs a per-IP cap before expensive auth.
    if path == "/xrpc/blue.catbird.labyrinth.getRecoveryShare"
        && request.method() == axum::http::Method::POST
    {
        let client_ip = extract_client_ip(&request);
        if let Some(retry_after) =
            RECOVERY_SHARE_INGRESS_FAILURE_LIMITER.retry_after_if_exhausted(&client_ip)
        {
            return Ok(rate_limited_response(retry_after));
        }
        let response = next.run(request).await;
        if recovery_ingress_failure(response.status()) {
            let _ = RECOVERY_SHARE_INGRESS_FAILURE_LIMITER.check(&client_ip);
        }
        return Ok(response);
    }
    let client_ip = extract_client_ip(&request);

    match IP_LIMITER.check(&client_ip) {
        Ok(()) => {
            tracing::debug!(path = %path, "IP pre-auth rate limit passed");
            Ok(next.run(request).await)
        }
        Err(retry_after) => {
            tracing::warn!(
                "IP pre-auth rate limit exceeded for {}: {} (retry after {} seconds)",
                client_ip,
                path,
                retry_after
            );
            Ok(rate_limited_response(retry_after))
        }
    }
}

fn recovery_ingress_failure(status: StatusCode) -> bool {
    status.is_client_error()
        && !matches!(
            status,
            StatusCode::NOT_FOUND | StatusCode::TOO_MANY_REQUESTS
        )
}

fn rate_limited_response(retry_after: u64) -> Response {
    let body = Json(json!({
        "error": "RateLimitExceeded",
        "message": format!(
            "Too many requests from this IP. Retry after {} second(s).",
            retry_after
        ),
    }));
    let mut response = (StatusCode::TOO_MANY_REQUESTS, body).into_response();
    response.headers_mut().insert(
        axum::http::header::RETRY_AFTER,
        axum::http::HeaderValue::from_str(&retry_after.to_string())
            .unwrap_or(axum::http::HeaderValue::from_static("1")),
    );
    response
}

fn parse_ip_from_header(headers: &HeaderMap, name: &str) -> Option<IpAddr> {
    headers
        .get(name)
        .and_then(|h| h.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .and_then(|value| value.parse::<IpAddr>().ok())
}

fn parse_xff_rightmost_untrusted(headers: &HeaderMap, trusted_cidrs: &[IpNet]) -> Option<IpAddr> {
    let values: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    for raw in values.into_iter().rev() {
        for hop in raw.rsplit(',').map(str::trim).filter(|s| !s.is_empty()) {
            let ip = hop.parse::<IpAddr>().ok()?;
            if !is_trusted_proxy(ip, trusted_cidrs) {
                return Some(ip);
            }
        }
    }
    None
}

fn is_trusted_proxy(ip: IpAddr, trusted_cidrs: &[IpNet]) -> bool {
    !trusted_cidrs.is_empty() && trusted_cidrs.iter().any(|cidr| cidr.contains(&ip))
}

fn client_ip_with_trusted(
    headers: &HeaderMap,
    peer_ip: Option<IpAddr>,
    trusted_cidrs: &[IpNet],
) -> String {
    if let Some(source_ip) = peer_ip {
        if is_trusted_proxy(source_ip, trusted_cidrs) {
            if let Some(ip) = parse_ip_from_header(headers, "cf-connecting-ip")
                .or_else(|| parse_xff_rightmost_untrusted(headers, trusted_cidrs))
                .or_else(|| parse_ip_from_header(headers, "x-real-ip"))
            {
                return ip.to_string();
            }
        }
        return source_ip.to_string();
    }

    "unknown".to_string()
}

/// The same trusted-proxy origin selection used by the global IP middleware,
/// available to recovery-share miss throttling after authentication.
pub fn recovery_client_ip(headers: &HeaderMap, peer: Option<SocketAddr>) -> String {
    client_ip_with_trusted(headers, peer.map(|addr| addr.ip()), &TRUSTED_PROXY_CIDRS)
}

fn extract_client_ip_with_trusted(request: &Request, trusted_cidrs: &[IpNet]) -> String {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());
    client_ip_with_trusted(request.headers(), peer, trusted_cidrs)
}

fn extract_client_ip(request: &Request) -> String {
    extract_client_ip_with_trusted(request, &TRUSTED_PROXY_CIDRS)
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

    #[test]
    fn recovery_ingress_bucket_charges_failures_only() {
        let limiter = RateLimiter::new(2, 0.001);
        assert!(limiter.retry_after_if_exhausted("shared-ip").is_none());
        assert!(limiter.check("shared-ip").is_ok());
        assert!(limiter.retry_after_if_exhausted("shared-ip").is_none());
        assert!(limiter.check("shared-ip").is_ok());
        assert!(limiter.retry_after_if_exhausted("shared-ip").is_some());
        assert!(limiter.retry_after_if_exhausted("other-ip").is_none());

        for status in [
            StatusCode::BAD_REQUEST,
            StatusCode::UNAUTHORIZED,
            StatusCode::FORBIDDEN,
            StatusCode::METHOD_NOT_ALLOWED,
            StatusCode::PAYLOAD_TOO_LARGE,
        ] {
            assert!(recovery_ingress_failure(status));
        }
        for status in [
            StatusCode::OK,
            StatusCode::NOT_FOUND,
            StatusCode::TOO_MANY_REQUESTS,
        ] {
            assert!(!recovery_ingress_failure(status));
        }
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
    fn deterministic_admission_does_not_read_or_spend_shared_buckets() {
        use crate::sim_hooks::{with_ds_clock, ManualDsClock};

        let now = chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        let clock = Arc::new(ManualDsClock::new(now));
        let ip = RateLimiter::new(1, 0.0);
        let did = DidRateLimiter::new();
        let federation = FederationPeerRateLimiter::new();
        with_ds_clock(clock, || {
            for _ in 0..8 {
                assert!(ip.check("127.0.0.1").is_ok());
                assert!(did
                    .check_did_limit("did:plc:alice", "createConversation")
                    .is_ok());
                assert!(federation
                    .check_peer_limit("did:web:peer.example.com", "deliverMessage", Some(1))
                    .is_ok());
            }
        });
        for buckets in [&ip.buckets, &did.buckets, &federation.buckets] {
            assert!(buckets.iter().next().is_none());
        }
        assert!(ip.check("127.0.0.1").is_ok());
        assert!(ip.check("127.0.0.1").is_err());
    }

    #[test]
    fn device_auth_binding_has_dedicated_tight_quota() {
        let (limit, window) = get_endpoint_quota("/xrpc/blue.catbird.chat.enrollDevice");

        assert_eq!(limit, 10);
        assert_eq!(window, Duration::from_secs(60));
    }

    #[test]
    fn test_trusted_proxy_uses_forwarded_ip() {
        let request = HttpRequest::builder()
            .uri("/xrpc/blue.catbird.chat.getEntries")
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
            .uri("/xrpc/blue.catbird.chat.getEntries")
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

    #[test]
    fn mf10_xff_extracts_rightmost_untrusted_ip_and_defaults_trust_local_proxies() {
        let mut request = HttpRequest::builder()
            .uri("/xrpc/blue.catbird.chat.getEntries")
            .header("x-forwarded-for", "1.2.3.4, 198.51.100.7, 10.0.0.2")
            .body(Body::empty())
            .expect("request");
        request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            443,
        )));

        let trusted = vec![
            "127.0.0.0/8".parse::<IpNet>().unwrap(),
            "10.0.0.0/8".parse::<IpNet>().unwrap(),
        ];
        assert_eq!(
            extract_client_ip_with_trusted(&request, &trusted),
            "198.51.100.7",
            "must select rightmost non-trusted XFF hop, ignoring spoofed leftmost entry"
        );

        // Default TRUSTED_PROXY_CIDRS (when env var is unset) trusts loopback/private proxies
        // while still ignoring headers from public untrusted peers.
        if std::env::var("TRUSTED_PROXY_CIDRS").is_err() {
            assert_eq!(extract_client_ip(&request), "198.51.100.7");

            let mut direct_public = HttpRequest::builder()
                .uri("/xrpc/blue.catbird.chat.getEntries")
                .header("x-forwarded-for", "1.2.3.4")
                .body(Body::empty())
                .expect("request");
            direct_public
                .extensions_mut()
                .insert(ConnectInfo(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
                    443,
                )));
            assert_eq!(extract_client_ip(&direct_public), "198.51.100.20");
        }
    }
}
