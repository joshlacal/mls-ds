use axum::{extract::Request, http::StatusCode, middleware::Next, response::Response};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

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
        // Default: 20 req/s with burst of 40
        Self::new(40, 20.0)
    }
}

/// Middleware for rate limiting based on user DID
pub async fn rate_limit_middleware(request: Request, next: Next) -> Result<Response, StatusCode> {
    // Extract user DID from auth extension (set by auth middleware)
    let user_did = request
        .extensions()
        .get::<crate::auth::AuthUser>()
        .map(|u| u.did.clone());

    if let Some(did) = user_did {
        // TODO: Extract room_id from request path/body for per-room limiting
        // For now, use global per-DID limiting
        let key = did;

        // Get rate limiter from app state
        // Note: This requires RateLimiter to be added to app state in main.rs
        // For now, create a default one (in production, should come from state)
        let limiter = RateLimiter::default();

        match limiter.check(&key).await {
            Ok(()) => Ok(next.run(request).await),
            Err(retry_after) => {
                // Return 429 Too Many Requests with retryAfter
                Err(StatusCode::TOO_MANY_REQUESTS)
                // TODO: Add Retry-After header
            }
        }
    } else {
        // No auth, let auth middleware handle it
        Ok(next.run(request).await)
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
