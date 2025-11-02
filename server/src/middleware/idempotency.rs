//! Idempotency Middleware
//!
//! Provides idempotency guarantees for write operations by:
//! 1. Extracting idempotencyKey from request body (JSON)
//! 2. Checking PostgreSQL idempotency_cache table for cached responses
//! 3. Caching successful responses with configurable TTL (default: 1 hour)
//! 4. Handling both success and error responses appropriately
//!
//! ## Usage
//!
//! Add to router with state containing DbPool:
//! ```rust
//! use axum::Router;
//! use crate::middleware::idempotency::IdempotencyLayer;
//!
//! let app = Router::new()
//!     .route("/xrpc/blue.catbird.mls.sendMessage", post(handler))
//!     .layer(IdempotencyLayer::new(pool.clone()));
//! ```

use axum::{
    body::{Body, Bytes},
    extract::{FromRequest, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Default TTL for cached responses (1 hour)
const DEFAULT_TTL_SECONDS: i64 = 3600;

/// Idempotency layer configuration
#[derive(Clone)]
pub struct IdempotencyLayer {
    pool: PgPool,
    ttl_seconds: i64,
}

impl IdempotencyLayer {
    /// Create new idempotency layer with default TTL (1 hour)
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            ttl_seconds: DEFAULT_TTL_SECONDS,
        }
    }

    /// Create new idempotency layer with custom TTL
    pub fn with_ttl(pool: PgPool, ttl: Duration) -> Self {
        Self {
            pool,
            ttl_seconds: ttl.as_secs() as i64,
        }
    }
}

/// Cached response from idempotency_cache table
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
struct CachedResponse {
    response_body: serde_json::Value,
    status_code: i32,
}

/// Extract idempotency key from request body (if present)
fn extract_idempotency_key(body: &[u8]) -> Option<String> {
    // Parse JSON body
    if let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) {
        // Try to extract idempotencyKey field
        if let Some(key) = json.get("idempotencyKey") {
            if let Some(key_str) = key.as_str() {
                return Some(key_str.to_string());
            }
        }
    }
    None
}

/// Check idempotency cache for existing response
async fn check_cache(
    pool: &PgPool,
    idempotency_key: &str,
    endpoint: &str,
) -> Result<Option<CachedResponse>, sqlx::Error> {
    let result = sqlx::query_as::<_, CachedResponse>(
        r#"
        SELECT response_body, status_code
        FROM idempotency_cache
        WHERE key = $1
          AND endpoint = $2
          AND expires_at > NOW()
        "#,
    )
    .bind(idempotency_key)
    .bind(endpoint)
    .fetch_optional(pool)
    .await?;

    Ok(result)
}

/// Store response in idempotency cache
async fn store_cache(
    pool: &PgPool,
    idempotency_key: &str,
    endpoint: &str,
    status_code: i32,
    response_body: &serde_json::Value,
    ttl_seconds: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO idempotency_cache (key, endpoint, response_body, status_code, expires_at)
        VALUES ($1, $2, $3, $4, NOW() + $5 * INTERVAL '1 second')
        ON CONFLICT (key) DO UPDATE SET
            response_body = EXCLUDED.response_body,
            status_code = EXCLUDED.status_code,
            expires_at = EXCLUDED.expires_at
        "#,
    )
    .bind(idempotency_key)
    .bind(endpoint)
    .bind(response_body)
    .bind(status_code)
    .bind(ttl_seconds)
    .execute(pool)
    .await?;

    Ok(())
}

/// Idempotency middleware handler
pub async fn idempotency_middleware(
    State(layer): State<IdempotencyLayer>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract endpoint path
    let endpoint = request.uri().path().to_string();

    // Only apply to write operations (POST/PUT/PATCH)
    let method = request.method().clone();
    if !matches!(
        method.as_str(),
        "POST" | "PUT" | "PATCH"
    ) {
        debug!("Skipping idempotency check for {} {}", method, endpoint);
        return Ok(next.run(request).await);
    }

    // Read the request body using Axum's Bytes extractor
    let (parts, body) = request.into_parts();

    // Reconstruct request temporarily to use Bytes extractor
    let temp_request = Request::from_parts(parts, body);
    let body_bytes = match Bytes::from_request(temp_request, &()).await {
        Ok(bytes) => bytes,
        Err(_) => {
            error!("Failed to extract request body bytes");
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    // Split request again for later use
    let (parts, _) = Request::new(Body::empty()).into_parts();

    // Extract idempotency key from body
    let idempotency_key = match extract_idempotency_key(&body_bytes) {
        Some(key) => {
            debug!("Extracted idempotency key: {}", key);
            key
        }
        None => {
            // No idempotency key provided - skip caching
            debug!("No idempotency key in request body, skipping cache");
            let request = Request::from_parts(parts, Body::from(body_bytes));
            return Ok(next.run(request).await);
        }
    };

    // Check cache for existing response
    match check_cache(&layer.pool, &idempotency_key, &endpoint).await {
        Ok(Some(cached)) => {
            info!(
                "Idempotency cache HIT for key={} endpoint={} status={}",
                idempotency_key, endpoint, cached.status_code
            );

            // Return cached response
            let status = StatusCode::from_u16(cached.status_code as u16)
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

            let body_string = serde_json::to_string(&cached.response_body)
                .unwrap_or_else(|_| "{}".to_string());

            return Ok((
                status,
                [("content-type", "application/json")],
                body_string,
            )
                .into_response());
        }
        Ok(None) => {
            debug!(
                "Idempotency cache MISS for key={} endpoint={}",
                idempotency_key, endpoint
            );
        }
        Err(e) => {
            error!(
                "Failed to check idempotency cache: {} (continuing anyway)",
                e
            );
            // Continue processing even if cache check fails
        }
    }

    // Reconstruct request and process it
    let request = Request::from_parts(parts, Body::from(body_bytes.clone()));
    let response = next.run(request).await;

    // Extract response status
    let status_code = response.status().as_u16() as i32;

    // Convert response to extract body
    let (response_parts, response_body) = response.into_parts();

    // Extract response body bytes using Bytes extractor
    let temp_response = Response::from_parts(response_parts, response_body);
    let (response_parts, response_body) = temp_response.into_parts();

    // Manually read the body stream
    let response_bytes = match axum::body::to_bytes(response_body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Failed to collect response body: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // Only cache successful responses (2xx) and client errors (4xx)
    // Don't cache server errors (5xx) as they may be transient
    if (200..500).contains(&status_code) {
        // Parse response body as JSON
        match serde_json::from_slice::<serde_json::Value>(&response_bytes) {
            Ok(json_body) => {
                // Store in cache
                if let Err(e) = store_cache(
                    &layer.pool,
                    &idempotency_key,
                    &endpoint,
                    status_code,
                    &json_body,
                    layer.ttl_seconds,
                )
                .await
                {
                    error!(
                        "Failed to store idempotency cache for key={}: {}",
                        idempotency_key, e
                    );
                    // Continue anyway - caching is best-effort
                } else {
                    info!(
                        "Stored idempotency cache for key={} endpoint={} status={} ttl={}s",
                        idempotency_key, endpoint, status_code, layer.ttl_seconds
                    );
                }
            }
            Err(e) => {
                warn!(
                    "Response body is not valid JSON, skipping cache: {}",
                    e
                );
            }
        }
    } else {
        debug!(
            "Not caching response with status {} (server error)",
            status_code
        );
    }

    // Reconstruct and return response
    let response = Response::from_parts(response_parts, Body::from(response_bytes));
    Ok(response)
}

/// Cleanup expired entries from idempotency_cache
///
/// This should be called periodically (e.g., via a background task)
/// to prevent unbounded growth of the cache table.
///
/// ## Example
///
/// ```rust
/// use tokio::time::{interval, Duration};
/// use crate::middleware::idempotency::cleanup_expired_entries;
///
/// tokio::spawn(async move {
///     let mut interval = interval(Duration::from_secs(3600)); // Every hour
///     loop {
///         interval.tick().await;
///         if let Err(e) = cleanup_expired_entries(&pool).await {
///             tracing::error!("Failed to cleanup idempotency cache: {}", e);
///         }
///     }
/// });
/// ```
pub async fn cleanup_expired_entries(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        r#"
        DELETE FROM idempotency_cache
        WHERE expires_at < NOW()
        "#,
    )
    .execute(pool)
    .await?;

    let deleted = result.rows_affected();
    if deleted > 0 {
        info!("Cleaned up {} expired idempotency cache entries", deleted);
    }

    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_idempotency_key() {
        let body = r#"{"idempotencyKey": "test-key-123", "other": "data"}"#;
        let key = extract_idempotency_key(body.as_bytes());
        assert_eq!(key, Some("test-key-123".to_string()));
    }

    #[test]
    fn test_extract_idempotency_key_missing() {
        let body = r#"{"other": "data"}"#;
        let key = extract_idempotency_key(body.as_bytes());
        assert_eq!(key, None);
    }

    #[test]
    fn test_extract_idempotency_key_invalid_json() {
        let body = b"invalid json";
        let key = extract_idempotency_key(body);
        assert_eq!(key, None);
    }
}
