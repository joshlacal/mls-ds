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

/// Per-minute quotas of the Space authority policy endpoints
/// (`getSpaceMembership`, `deleteSpaceGeneration`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpaceAuthorityQuota {
    /// Calls for one user by one authority. Applies when the call names a user.
    pub per_user: u32,
    /// Calls to one endpoint by one authority, across all users.
    pub per_authority: u32,
}

impl Default for SpaceAuthorityQuota {
    fn default() -> Self {
        Self {
            per_user: 300,
            per_authority: 6000,
        }
    }
}

impl SpaceAuthorityQuota {
    pub fn from_env() -> Self {
        let read = |name: &str, default: u32| {
            std::env::var(name)
                .ok()
                .and_then(|v| v.parse::<u32>().ok())
                .filter(|v| *v > 0)
                .unwrap_or(default)
        };
        let default = Self::default();
        Self {
            per_user: read("RATE_LIMIT_SPACE_AUTHORITY_PER_USER", default.per_user),
            per_authority: read(
                "RATE_LIMIT_SPACE_AUTHORITY_PER_MINUTE",
                default.per_authority,
            ),
        }
    }

    /// Pre-auth calls to one policy endpoint from one client IP per minute.
    /// It defaults to the per-authority ceiling: an authority sends every
    /// user's calls from its one egress address, so a smaller bound would
    /// make the ceiling unreachable and let one user throttle every other.
    pub fn per_client_ip_from_env() -> u32 {
        std::env::var("RATE_LIMIT_SPACE_AUTHORITY_IP_PER_MINUTE")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .filter(|v| *v > 0)
            .unwrap_or_else(|| Self::from_env().per_authority)
    }
}

/// Request paths of the Space authority policy endpoints.
const SPACE_AUTHORITY_POLICY_PATHS: [&str; 2] = [
    "/xrpc/blue.catbird.labyrinth.getSpaceMembership",
    "/xrpc/blue.catbird.labyrinth.deleteSpaceGeneration",
];

fn space_authority_policy_path(path: &str) -> Option<&'static str> {
    SPACE_AUTHORITY_POLICY_PATHS
        .iter()
        .copied()
        .find(|policy_path| *policy_path == path)
}

/// Quota of the Space authority policy endpoints. One authority DID calls
/// them for every user of a deployment, so the per-issuer [`DidRateLimiter`]
/// bucket would make all of those users share one bucket. Here each user has
/// a bucket per authority, under a larger per-authority ceiling.
#[derive(Clone)]
pub struct SpaceAuthorityRateLimiter {
    buckets: Arc<Cache<String, Arc<Mutex<TokenBucket>>>>,
}

impl SpaceAuthorityRateLimiter {
    pub fn new() -> Self {
        let max_keys = parse_u64_env("RATE_LIMIT_SPACE_AUTHORITY_MAX_KEYS", 300_000);
        let ttl_seconds = parse_u64_env("RATE_LIMIT_SPACE_AUTHORITY_BUCKET_TTL_SECONDS", 900);
        Self {
            buckets: build_bucket_cache(max_keys, ttl_seconds),
        }
    }

    /// Take one call to `endpoint` by `authority`, on behalf of `user` when
    /// the call names one. `Err` carries the Retry-After seconds. The user's
    /// bucket is checked first, so a throttled user does not spend the
    /// authority's shared ceiling.
    pub fn check(
        &self,
        authority: &str,
        endpoint: &str,
        user: Option<&str>,
        quota: SpaceAuthorityQuota,
    ) -> Result<(), u64> {
        if let Some(user) = user {
            self.take(format!("{authority}|{endpoint}|{user}"), quota.per_user)?;
        }
        self.take(format!("{authority}|{endpoint}|*"), quota.per_authority)
    }

    /// Take one pre-auth call to the policy endpoint at `path` from
    /// `client_ip`. `Err` carries the Retry-After seconds.
    pub fn check_client(&self, client_ip: &str, path: &str, per_minute: u32) -> Result<(), u64> {
        self.take(format!("{client_ip}|{path}"), per_minute)
    }

    fn take(&self, key: String, per_minute: u32) -> Result<(), u64> {
        let limit = per_minute.max(1);
        // Include the limit in the key so a quota change does not reuse stale capacity.
        let bucket = self.buckets.get_with(format!("{key}|{limit}"), || {
            Arc::new(Mutex::new(TokenBucket::new(limit, limit as f64 / 60.0)))
        });
        let mut bucket = bucket.lock();
        if bucket.try_consume() {
            Ok(())
        } else {
            Err(bucket.retry_after_secs())
        }
    }
}

impl Default for SpaceAuthorityRateLimiter {
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
/// Global limiter of the Space authority policy endpoints.
pub static SPACE_AUTHORITY_RATE_LIMITER: Lazy<SpaceAuthorityRateLimiter> =
    Lazy::new(SpaceAuthorityRateLimiter::new);
/// Per-IP pre-auth limiter of the Space authority policy endpoints, which
/// skip [`IP_LIMITER`]. A separate cache from the post-auth buckets.
pub static SPACE_AUTHORITY_IP_LIMITER: Lazy<SpaceAuthorityRateLimiter> =
    Lazy::new(SpaceAuthorityRateLimiter::new);

/// Per-IP rate limiter instance
pub static IP_LIMITER: Lazy<RateLimiter> = Lazy::new(RateLimiter::default);

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
    let uri = request.uri().to_string();
    let client_ip = extract_client_ip(&request);

    // A Space authority sends every user's policy calls from its one egress
    // address, so these routes skip the general per-IP bucket, which one
    // user's calls could otherwise spend for every other user. Their own
    // per-IP bucket is sized to the per-authority ceiling and still bounds
    // unauthenticated calls, which resolve the issuer DID; the
    // per-(authority, user) quota applies after auth.
    let (limited, check) = match space_authority_policy_path(request.uri().path()) {
        Some(path) => (
            "Space authority policy",
            SPACE_AUTHORITY_IP_LIMITER.check_client(
                &client_ip,
                path,
                SpaceAuthorityQuota::per_client_ip_from_env(),
            ),
        ),
        None => ("IP", IP_LIMITER.check(&client_ip)),
    };

    match check {
        Ok(()) => {
            tracing::debug!(
                "{} pre-auth rate limit passed for {}: {}",
                limited,
                client_ip,
                uri
            );
            Ok(next.run(request).await)
        }
        Err(retry_after) => {
            tracing::warn!(
                "{} pre-auth rate limit exceeded for {}: {} (retry after {} seconds)",
                limited,
                client_ip,
                uri,
                retry_after
            );
            // Return ATProto-compatible JSON error body with Retry-After header
            let body = Json(json!({
                "error": "RateLimitExceeded",
                "message": format!(
                    "Too many requests from this IP. Retry after {} second(s).",
                    retry_after
                ),
            }));
            let mut resp = (StatusCode::TOO_MANY_REQUESTS, body).into_response();
            resp.headers_mut().insert(
                axum::http::header::RETRY_AFTER,
                axum::http::HeaderValue::from_str(&retry_after.to_string())
                    .unwrap_or(axum::http::HeaderValue::from_static("1")),
            );
            Ok(resp)
        }
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

    const MEMBERSHIP: &str = "blue.catbird.labyrinth.getSpaceMembership";
    const DELETION: &str = "blue.catbird.labyrinth.deleteSpaceGeneration";
    const AUTHORITY: &str = "did:web:authority.example.com";

    // MLSDS-01: two users of one authority each cost 150 policy calls in a
    // minute. The shared 200/min issuer bucket throttled both (and every
    // other user); per-user buckets admit both.
    #[test]
    fn space_authority_default_quota_admits_two_users_past_the_did_default() {
        let limiter = SpaceAuthorityRateLimiter::new();
        let quota = SpaceAuthorityQuota::default();
        for user in ["did:plc:alice", "did:plc:bob"] {
            for call in 0..150 {
                assert!(
                    limiter
                        .check(AUTHORITY, MEMBERSHIP, Some(user), quota)
                        .is_ok(),
                    "{user} throttled at call {call}"
                );
            }
        }
    }

    #[test]
    fn space_authority_quota_is_keyed_by_authority_and_user() {
        let limiter = SpaceAuthorityRateLimiter::new();
        let quota = SpaceAuthorityQuota {
            per_user: 3,
            per_authority: 5,
        };
        let alice = Some("did:plc:alice");
        for _ in 0..3 {
            assert!(limiter.check(AUTHORITY, MEMBERSHIP, alice, quota).is_ok());
        }
        let retry_after = limiter
            .check(AUTHORITY, MEMBERSHIP, alice, quota)
            .unwrap_err();
        assert!(retry_after >= 1);
        // Bob has his own bucket under the same authority.
        assert!(limiter
            .check(AUTHORITY, MEMBERSHIP, Some("did:plc:bob"), quota)
            .is_ok());
        assert!(limiter
            .check(AUTHORITY, MEMBERSHIP, Some("did:plc:bob"), quota)
            .is_ok());
        // Alice's throttled call did not spend the ceiling, which is now
        // spent (3 + 2), so it holds for a fresh user too.
        assert!(limiter
            .check(AUTHORITY, MEMBERSHIP, Some("did:plc:carol"), quota)
            .is_err());
        // Other authorities, and the authority's other endpoint, are separate.
        assert!(limiter
            .check("did:web:other.example.com", MEMBERSHIP, alice, quota)
            .is_ok());
        assert!(limiter.check(AUTHORITY, DELETION, None, quota).is_ok());
    }

    #[test]
    fn space_authority_call_without_user_uses_only_the_ceiling() {
        let limiter = SpaceAuthorityRateLimiter::new();
        let quota = SpaceAuthorityQuota {
            per_user: 1,
            per_authority: 2,
        };
        assert!(limiter.check(AUTHORITY, DELETION, None, quota).is_ok());
        assert!(limiter.check(AUTHORITY, DELETION, None, quota).is_ok());
        assert!(limiter.check(AUTHORITY, DELETION, None, quota).unwrap_err() >= 1);
    }

    #[test]
    fn space_authority_pre_auth_bound_is_keyed_by_client_ip_and_path() {
        let limiter = SpaceAuthorityRateLimiter::new();
        let [membership, deletion] = SPACE_AUTHORITY_POLICY_PATHS;
        assert!(limiter.check_client("192.0.2.1", membership, 2).is_ok());
        assert!(limiter.check_client("192.0.2.1", membership, 2).is_ok());
        assert!(
            limiter
                .check_client("192.0.2.1", membership, 2)
                .unwrap_err()
                >= 1
        );
        assert!(limiter.check_client("192.0.2.2", membership, 2).is_ok());
        assert!(limiter.check_client("192.0.2.1", deletion, 2).is_ok());
    }

    #[test]
    fn space_authority_pre_auth_bound_defaults_to_the_ceiling() {
        assert_eq!(
            SpaceAuthorityQuota::per_client_ip_from_env(),
            SpaceAuthorityQuota::from_env().per_authority
        );
        assert_eq!(
            space_authority_policy_path("/xrpc/blue.catbird.labyrinth.getSpaceMembership"),
            Some("/xrpc/blue.catbird.labyrinth.getSpaceMembership")
        );
        assert_eq!(
            space_authority_policy_path("/xrpc/blue.catbird.labyrinth.listSpaceBatches"),
            None
        );
    }

    /// A router behind [`rate_limit_middleware`] that answers 200 on both
    /// Space authority policy paths and on one ordinary path.
    fn limited_router() -> axum::Router {
        use axum::routing::{get, post};
        let [membership, deletion] = SPACE_AUTHORITY_POLICY_PATHS;
        axum::Router::new()
            .route(membership, get(|| async { StatusCode::OK }))
            .route(deletion, post(|| async { StatusCode::OK }))
            .route(
                "/xrpc/blue.catbird.chat.getEntries",
                get(|| async { StatusCode::OK }),
            )
            .layer(axum::middleware::from_fn(rate_limit_middleware))
    }

    async fn call_from(router: &axum::Router, ip: [u8; 4], method: &str, path: &str) -> Response {
        use tower_util::ServiceExt;
        let mut request = HttpRequest::builder()
            .method(method)
            .uri(path)
            .body(Body::empty())
            .expect("request");
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from((ip, 443))));
        router.clone().oneshot(request).await.expect("router")
    }

    // Review of MLSDS-01: an authority sends every user's policy calls from
    // one address. Through the general per-IP bucket, one user's calls ran
    // it dry for every other user.
    #[tokio::test]
    async fn space_authority_policy_paths_skip_the_general_ip_bucket() {
        let router = limited_router();
        let egress = [192, 0, 2, 10];
        let general = IP_LIMITER.capacity;
        assert!(SpaceAuthorityQuota::per_client_ip_from_env() > general);
        let [membership, _] = SPACE_AUTHORITY_POLICY_PATHS;
        for call in 0..=general {
            let response = call_from(&router, egress, "GET", membership).await;
            assert_eq!(response.status(), StatusCode::OK, "call {call}");
        }
        // The general bucket of that address is untouched.
        let response =
            call_from(&router, egress, "GET", "/xrpc/blue.catbird.chat.getEntries").await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    // The policy paths keep a pre-auth bound per client IP, because an
    // unauthenticated call still resolves the issuer DID.
    #[tokio::test]
    async fn space_authority_policy_paths_keep_a_pre_auth_ip_bound() {
        let router = limited_router();
        let client = [192, 0, 2, 20];
        let [_, deletion] = SPACE_AUTHORITY_POLICY_PATHS;
        let bound = SpaceAuthorityQuota::per_client_ip_from_env();
        for call in 0..bound {
            let response = call_from(&router, client, "POST", deletion).await;
            assert_eq!(response.status(), StatusCode::OK, "call {call}");
        }
        // The bucket refilled at bound/60 per second during those calls, far
        // slower than they ran, so it runs dry within a bounded number more.
        let mut throttled = None;
        for _ in 0..bound {
            let response = call_from(&router, client, "POST", deletion).await;
            if response.status() != StatusCode::OK {
                throttled = Some(response);
                break;
            }
        }
        let throttled = throttled.expect("the pre-auth bound never ran dry");
        assert_eq!(throttled.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry_after: u64 = throttled.headers()[axum::http::header::RETRY_AFTER]
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!(retry_after >= 1);
        let bytes = axum::body::to_bytes(throttled.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"], "RateLimitExceeded");
        // Another address is not throttled.
        let response = call_from(&router, [192, 0, 2, 21], "POST", deletion).await;
        assert_eq!(response.status(), StatusCode::OK);
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
}
