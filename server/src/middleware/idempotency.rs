//! Idempotency pass-through middleware.
//!
//! Revised clean-chat routes under `blue.catbird.chat.*` use request-bound
//! database arbitration (`chat.operation_claims`) and exact signed-body
//! idempotency rather than generic HTTP header caching (`idempotency_cache` was
//! retired in the clean-slate migration).

use axum::{
    body::HttpBody as _,
    extract::{Request, State},
    http::{header, HeaderMap, Method, StatusCode},
    middleware::Next,
    response::Response,
};
use sqlx::PgPool;
use std::time::Duration;

use crate::auth::{enforce_standard, resolve_authenticated_principal, AtProtoClaims};

const IDEMPOTENCY_KEY_HEADER: &str = "Idempotency-Key";
const MAX_IDEMPOTENCY_KEY_LEN: usize = 128;
const MAX_CACHEABLE_RESPONSE_BYTES: usize = 256 * 1024;

#[derive(Clone)]
pub struct IdempotencyLayer {
    _pool: PgPool,
    _ttl_seconds: i64,
}

impl IdempotencyLayer {
    pub fn new(pool: PgPool) -> Self {
        Self {
            _pool: pool,
            _ttl_seconds: 86400,
        }
    }

    pub fn with_ttl(pool: PgPool, ttl: Duration) -> Self {
        Self {
            _pool: pool,
            _ttl_seconds: ttl.as_secs() as i64,
        }
    }
}

fn should_apply(endpoint: &str, method: &Method) -> bool {
    let _ = (endpoint, method);
    false
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

fn bounded_response_length(response: &Response) -> Option<usize> {
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
    State(_layer): State<IdempotencyLayer>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let endpoint = request.uri().path().to_string();
    let method = request.method().clone();
    let _ = should_apply(&endpoint, &method);
    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{http::HeaderValue, response::IntoResponse};

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
    fn excludes_revised_clean_chat_endpoints_from_generic_cache() {
        for endpoint in [
            "/xrpc/blue.catbird.chat.sendMessage",
            "/xrpc/blue.catbird.chat.enrollDevice",
            "/xrpc/blue.catbird.chat.createConversation",
        ] {
            assert!(!should_apply(endpoint, &Method::POST));
            assert!(!should_apply(endpoint, &Method::PUT));
        }
        assert!(!should_apply(
            "/xrpc/blue.catbird.chat.getConversations",
            &Method::GET
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
