//! Idempotency middleware for chat write endpoints.
//!
//! Security and behavior:
//! - Applies replay caching when an optional `Idempotency-Key` is present on
//!   write requests to `/xrpc/blue.catbird.chat.*`
//! - Verifies bearer JWT before cache lookup
//! - Caches only successful JSON responses scoped by effective caller DID + endpoint + key
//! - Caps cacheable response bodies to 256 KiB

use axum::{
    body::{Body, HttpBody as _},
    extract::{FromRequestParts, Request, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use sqlx::PgPool;
use std::time::Duration;
use tracing::{debug, error, info, warn};

use crate::{
    auth::{
        enforce_standard, resolve_authenticated_principal, AtProtoClaims, AuthMiddleware, AuthUser,
    },
    identity::canonical_did,
};

const DEFAULT_TTL_SECONDS: i64 = 86400;
const IDEMPOTENCY_KEY_HEADER: &str = "Idempotency-Key";
const IDEMPOTENCY_REPLAYED_HEADER: &str = "Idempotency-Replayed";
const CHAT_XRPC_PREFIX: &str = "/xrpc/blue.catbird.chat.";
const ENROLL_DEVICE_ENDPOINT: &str =
    "/xrpc/blue.catbird.chat.enrollDevice";
const REBIND_DEVICE_AUTH_ENDPOINT: &str =
    "/xrpc/blue.catbird.chat.rebindDeviceAuthentication";
const MAX_IDEMPOTENCY_KEY_LEN: usize = 128;
const MAX_CACHEABLE_RESPONSE_BYTES: usize = 256 * 1024;

#[derive(Clone)]
pub struct IdempotencyLayer {
    pool: PgPool,
    ttl_seconds: i64,
    auth_middleware: AuthMiddleware,
}

impl IdempotencyLayer {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            ttl_seconds: DEFAULT_TTL_SECONDS,
            auth_middleware: AuthMiddleware::new(),
        }
    }

    pub fn with_ttl(pool: PgPool, ttl: Duration) -> Self {
        Self {
            pool,
            ttl_seconds: ttl.as_secs() as i64,
            auth_middleware: AuthMiddleware::new(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
struct CachedResponse {
    response_body: serde_json::Value,
    status_code: i32,
}

fn should_apply(endpoint: &str, method: &Method) -> bool {
    endpoint.starts_with(CHAT_XRPC_PREFIX)
        && matches!(method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE")
        // Enrollment has stronger, request-bound replay semantics: every
        // attempt needs a fresh DPoP proof and complete consumes a one-time
        // challenge. Returning a cached response here would bypass both the
        // DPoP verifier and the handler's database rechecks.
        && endpoint != ENROLL_DEVICE_ENDPOINT
        && endpoint != REBIND_DEVICE_AUTH_ENDPOINT
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    let auth_header = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    auth_header.strip_prefix("Bearer ")
}

fn extract_optional_idempotency_key(headers: &HeaderMap) -> Result<Option<String>, StatusCode> {
    let Some(raw) = headers.get(IDEMPOTENCY_KEY_HEADER) else {
        return Ok(None);
    };
    let key = raw.to_str().map_err(|_| StatusCode::BAD_REQUEST)?.trim();

    if key.is_empty() || key.len() > MAX_IDEMPOTENCY_KEY_LEN {
        return Err(StatusCode::BAD_REQUEST);
    }

    Ok(Some(key.to_string()))
}

fn resolve_cache_principal(
    claims: &AtProtoClaims,
    endpoint_nsid: &str,
    trusted_gateway_dids: Option<&str>,
) -> Result<String, crate::auth::AuthError> {
    enforce_standard(claims, endpoint_nsid)?;
    resolve_authenticated_principal(claims, trusted_gateway_dids)
}

async fn check_cache(
    pool: &PgPool,
    caller_did: &str,
    idempotency_key: &str,
    endpoint: &str,
) -> Result<Option<CachedResponse>, sqlx::Error> {
    sqlx::query_as::<_, CachedResponse>(
        r#"
        SELECT response_body, status_code
        FROM idempotency_cache
        WHERE caller_did = $1
          AND endpoint = $2
          AND key = $3
          AND expires_at > NOW()
        "#,
    )
    .bind(caller_did)
    .bind(endpoint)
    .bind(idempotency_key)
    .fetch_optional(pool)
    .await
}

async fn store_cache(
    pool: &PgPool,
    caller_did: &str,
    idempotency_key: &str,
    endpoint: &str,
    status_code: i32,
    response_body: &serde_json::Value,
    ttl_seconds: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO idempotency_cache (caller_did, endpoint, key, response_body, status_code, expires_at)
        VALUES ($1, $2, $3, $4, $5, NOW() + $6 * INTERVAL '1 second')
        ON CONFLICT (caller_did, endpoint, key) DO UPDATE
            SET response_body = EXCLUDED.response_body,
                status_code = EXCLUDED.status_code,
                expires_at = EXCLUDED.expires_at
        "#,
    )
    .bind(caller_did)
    .bind(endpoint)
    .bind(idempotency_key)
    .bind(response_body)
    .bind(status_code)
    .bind(ttl_seconds)
    .execute(pool)
    .await?;

    Ok(())
}

fn set_replayed_header(response: &mut Response, replayed: bool) {
    let value = if replayed { "true" } else { "false" };
    response
        .headers_mut()
        .insert(IDEMPOTENCY_REPLAYED_HEADER, HeaderValue::from_static(value));
}

fn bounded_response_length(response: &Response) -> Option<usize> {
    // Axum's ordinary Json response bodies carry an exact body size hint even
    // though Content-Length is normally synthesized later by Hyper. Requiring
    // a finite upper body hint lets us cache those responses without
    // consuming an unbounded or genuinely streaming body.
    let hinted_length = usize::try_from(response.body().size_hint().upper()?).ok()?;
    let declared_length = response
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(hinted_length);
    Some(hinted_length.max(declared_length))
}

pub async fn idempotency_middleware(
    State(layer): State<IdempotencyLayer>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let endpoint = request.uri().path().to_string();
    let method = request.method().clone();

    if !should_apply(&endpoint, &method) {
        return Ok(next.run(request).await);
    }

    let idempotency_key = match extract_optional_idempotency_key(request.headers()) {
        Ok(Some(key)) => key,
        Ok(None) => {
            metrics::counter!(
                "idempotency_requests_without_key_total",
                1,
                "method" => method.as_str().to_string(),
                "endpoint" => endpoint.clone()
            );
            return Ok(next.run(request).await);
        }
        Err(status) => {
            metrics::counter!(
                "idempotency_requests_with_invalid_key_total",
                1,
                "method" => method.as_str().to_string(),
                "endpoint" => endpoint.clone()
            );
            return Err(status);
        }
    };

    let token = extract_bearer_token(request.headers()).ok_or(StatusCode::UNAUTHORIZED)?;
    let claims = layer
        .auth_middleware
        .verify_jwt(token)
        .await
        .map_err(|error| error.into_response().status())?;
    let endpoint_nsid = endpoint
        .strip_prefix("/xrpc/")
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let trusted_gateway_dids = std::env::var("TRUSTED_GATEWAY_DIDS").ok();
    let caller_did =
        resolve_cache_principal(&claims, endpoint_nsid, trusted_gateway_dids.as_deref())
            .map_err(|error| error.into_response().status())?;

    let cache_check_start = std::time::Instant::now();
    match check_cache(&layer.pool, &caller_did, &idempotency_key, &endpoint).await {
        Ok(Some(cached)) => {
            // A replayed response still represents a fresh authenticated
            // request. Run the exact handler extractor so shared JTI replay
            // protection and both authentication rate-limit layers cannot be
            // bypassed by a cache hit. Cache misses deliberately leave the
            // request untouched so the handler authenticates it exactly once.
            let (mut parts, _body) = request.into_parts();
            let authenticated = AuthUser::from_request_parts(&mut parts, &layer.pool)
                .await
                .map_err(|error| error.into_response().status())?;
            if canonical_did(&authenticated.did) != canonical_did(&caller_did) {
                return Err(StatusCode::UNAUTHORIZED);
            }

            metrics::histogram!(
                "idempotency_cache_check_duration_seconds",
                cache_check_start.elapsed().as_secs_f64(),
                "endpoint" => endpoint.clone()
            );
            metrics::counter!(
                "idempotency_cache_hits_total",
                1,
                "method" => method.as_str().to_string(),
                "endpoint" => endpoint.clone()
            );

            let status = StatusCode::from_u16(cached.status_code as u16)
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            let body = serde_json::to_string(&cached.response_body).unwrap_or_else(|_| "{}".into());

            let mut response = (
                status,
                [(header::CONTENT_TYPE.as_str(), "application/json")],
                body,
            )
                .into_response();
            set_replayed_header(&mut response, true);
            return Ok(response);
        }
        Ok(None) => {
            metrics::histogram!(
                "idempotency_cache_check_duration_seconds",
                cache_check_start.elapsed().as_secs_f64(),
                "endpoint" => endpoint.clone()
            );
            metrics::counter!(
                "idempotency_cache_misses_total",
                1,
                "method" => method.as_str().to_string(),
                "endpoint" => endpoint.clone()
            );
        }
        Err(e) => {
            metrics::counter!(
                "idempotency_cache_check_errors_total",
                1,
                "method" => method.as_str().to_string(),
                "endpoint" => endpoint.clone()
            );
            error!(error = %e, "Failed to check idempotency cache (continuing)");
        }
    }

    let response = next.run(request).await;
    let status_code = response.status().as_u16() as i32;

    // Only cache successful JSON responses.
    if !(200..300).contains(&status_code) {
        let mut response = response;
        set_replayed_header(&mut response, false);
        metrics::counter!(
            "idempotency_cache_skipped_total",
            1,
            "method" => method.as_str().to_string(),
            "endpoint" => endpoint.clone(),
            "reason" => "non_2xx".to_string()
        );
        return Ok(response);
    }

    let is_json = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.starts_with("application/json"))
        .unwrap_or(false);

    if !is_json {
        let mut response = response;
        set_replayed_header(&mut response, false);
        metrics::counter!(
            "idempotency_cache_skipped_total",
            1,
            "method" => method.as_str().to_string(),
            "endpoint" => endpoint.clone(),
            "reason" => "non_json".to_string()
        );
        return Ok(response);
    }

    let Some(content_len) = bounded_response_length(&response) else {
        let mut response = response;
        set_replayed_header(&mut response, false);
        metrics::counter!(
            "idempotency_cache_skipped_total",
            1,
            "method" => method.as_str().to_string(),
            "endpoint" => endpoint.clone(),
            "reason" => "unbounded_body".to_string()
        );
        return Ok(response);
    };

    if content_len > MAX_CACHEABLE_RESPONSE_BYTES {
        let mut response = response;
        set_replayed_header(&mut response, false);
        metrics::counter!(
            "idempotency_cache_skipped_total",
            1,
            "method" => method.as_str().to_string(),
            "endpoint" => endpoint.clone(),
            "reason" => "body_too_large".to_string()
        );
        return Ok(response);
    }

    let (response_parts, response_body) = response.into_parts();
    let response_bytes =
        match axum::body::to_bytes(response_body, MAX_CACHEABLE_RESPONSE_BYTES).await {
            Ok(bytes) => bytes,
            Err(e) => {
                error!(error = %e, "Failed to collect response body for idempotency cache");
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };

    match serde_json::from_slice::<serde_json::Value>(&response_bytes) {
        Ok(json_body) => {
            let store_start = std::time::Instant::now();
            if let Err(e) = store_cache(
                &layer.pool,
                &caller_did,
                &idempotency_key,
                &endpoint,
                status_code,
                &json_body,
                layer.ttl_seconds,
            )
            .await
            {
                metrics::counter!(
                    "idempotency_cache_store_errors_total",
                    1,
                    "method" => method.as_str().to_string(),
                    "endpoint" => endpoint.clone()
                );
                warn!(error = %e, "Failed to store idempotency cache entry");
            } else {
                metrics::histogram!(
                    "idempotency_cache_store_duration_seconds",
                    store_start.elapsed().as_secs_f64(),
                    "endpoint" => endpoint.clone()
                );
                metrics::counter!(
                    "idempotency_cache_stores_total",
                    1,
                    "method" => method.as_str().to_string(),
                    "endpoint" => endpoint.clone()
                );
                info!(
                    caller_did = %crate::crypto::redact_for_log(&caller_did),
                    endpoint = %endpoint,
                    "Stored idempotency cache entry"
                );
            }
        }
        Err(e) => {
            warn!(error = %e, "Response body is not valid JSON, skipping cache");
            metrics::counter!(
                "idempotency_cache_skipped_total",
                1,
                "method" => method.as_str().to_string(),
                "endpoint" => endpoint.clone(),
                "reason" => "json_parse_failed".to_string()
            );
        }
    }

    let mut response = Response::from_parts(response_parts, Body::from(response_bytes));
    set_replayed_header(&mut response, false);
    Ok(response)
}

/// Cleanup expired entries from idempotency_cache.
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
        metrics::counter!("idempotency_cache_cleanup_deleted_total", deleted);
        info!(deleted, "Cleaned up expired idempotency cache entries");
    } else {
        debug!("No expired idempotency cache entries to clean");
    }

    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(issuer: &str, subject: Option<&str>, lxm: &str) -> crate::auth::AtProtoClaims {
        crate::auth::AtProtoClaims {
            iss: issuer.to_string(),
            aud: "did:web:mls.example".to_string(),
            exp: chrono::Utc::now().timestamp() + 60,
            iat: None,
            sub: subject.map(str::to_string),
            lxm: Some(lxm.to_string()),
            jti: Some("fresh-jti".to_string()),
        }
    }

    #[test]
    fn apply_only_to_chat_write_endpoints() {
        assert!(should_apply(
            "/xrpc/blue.catbird.chat.sendMessage",
            &Method::POST
        ));
        assert!(!should_apply(
            "/xrpc/blue.catbird.mlsDS.deliverMessage",
            &Method::POST
        ));
        assert!(!should_apply(
            "/xrpc/blue.catbird.chat.getConversations",
            &Method::GET
        ));
    }

    #[test]
    fn excludes_device_auth_enrollment_from_pre_verification_cache() {
        for endpoint in [
            "/xrpc/blue.catbird.chat.enrollDevice",
            "/xrpc/blue.catbird.chat.rebindDeviceAuthentication",
        ] {
            assert!(!should_apply(endpoint, &Method::POST));
            assert!(!should_apply(endpoint, &Method::PUT));
        }

        assert!(should_apply(
            "/xrpc/blue.catbird.chat.enrollDeviceExtra",
            &Method::POST
        ));
        assert!(should_apply(
            "/xrpc/blue.catbird.chat.rebindDeviceAuthentication/extra",
            &Method::POST
        ));
    }

    #[test]
    fn reject_invalid_idempotency_key() {
        let mut headers = HeaderMap::new();
        headers.insert(IDEMPOTENCY_KEY_HEADER, HeaderValue::from_static("   "));
        assert!(extract_optional_idempotency_key(&headers).is_err());

        let long_key = "a".repeat(MAX_IDEMPOTENCY_KEY_LEN + 1);
        headers.insert(
            IDEMPOTENCY_KEY_HEADER,
            HeaderValue::from_str(&long_key).unwrap(),
        );
        assert!(extract_optional_idempotency_key(&headers).is_err());
    }

    #[test]
    fn missing_idempotency_key_preserves_optional_contract() {
        assert_eq!(
            extract_optional_idempotency_key(&HeaderMap::new()).expect("missing is valid"),
            None
        );
    }

    #[test]
    fn present_valid_idempotency_key_still_enables_cache_path() {
        let mut headers = HeaderMap::new();
        headers.insert(
            IDEMPOTENCY_KEY_HEADER,
            HeaderValue::from_static(" stable-retry-key "),
        );
        assert_eq!(
            extract_optional_idempotency_key(&headers).expect("valid key"),
            Some("stable-retry-key".to_string())
        );
    }

    #[test]
    fn ordinary_json_without_content_length_has_a_bounded_cacheable_body() {
        let response = axum::Json(serde_json::json!({"ok": true})).into_response();
        assert!(response.headers().get(header::CONTENT_LENGTH).is_none());
        let length = bounded_response_length(&response).expect("Json body has a finite upper hint");
        assert!(length > 0);
        assert!(length <= MAX_CACHEABLE_RESPONSE_BYTES);
    }

    #[test]
    fn cache_scope_uses_effective_delegated_subject_and_exact_lxm() {
        let endpoint = "blue.catbird.chat.sendMessage";
        let direct = claims("did:plc:alice", None, endpoint);
        assert_eq!(
            resolve_cache_principal(&direct, endpoint, None).expect("direct principal"),
            "did:plc:alice"
        );

        let delegated = claims("did:web:nest.example", Some("did:plc:alice"), endpoint);
        assert_eq!(
            resolve_cache_principal(&delegated, endpoint, Some("did:web:nest.example"))
                .expect("trusted delegation"),
            "did:plc:alice"
        );

        let wrong_lxm = claims(
            "did:web:nest.example",
            Some("did:plc:alice"),
            "blue.catbird.chat.createConversation",
        );
        assert!(
            resolve_cache_principal(&wrong_lxm, endpoint, Some("did:web:nest.example")).is_err()
        );

        let mut missing_jti = direct;
        missing_jti.jti = None;
        assert!(resolve_cache_principal(&missing_jti, endpoint, None).is_err());
        assert!(resolve_cache_principal(&delegated, endpoint, None).is_err());
    }
}
