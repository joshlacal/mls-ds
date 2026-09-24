//! Authenticated internal request-push eligibility route and its fixed runtime.

use std::{sync::Arc, time::Duration};

use axum::{
    body::Bytes,
    extract::State,
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration as ChronoDuration, Utc};
use p256::elliptic_curve::subtle::ConstantTimeEq;
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, Semaphore};
use url::Url;

use crate::{
    chat_protocol::{
        repository::direct_request_push::{evaluate_eligibility, RequestPushEligibilityError},
        request_push::{
            canonical_time, RequestPushEligibilityBody, RequestPushEligibilityRequest,
            MAX_INTERNAL_BODY_BYTES, REQUEST_PUSH_AUTHORITY,
        },
    },
    db::DbPool,
};

use super::ChatRuntime;

const EVENT_PATH: &str = "/internal/chat/request-events";
const MAX_CONCURRENCY: usize = 16;
const MAX_REQUESTS_PER_SECOND: u32 = 64;
pub(crate) const REQUEST_PUSH_HTTP_TIMEOUT_SECONDS: u64 = 5;

#[derive(Debug)]
struct RateWindow {
    started: tokio::time::Instant,
    requests: u32,
}

/// Immutable startup configuration shared by the route and delivery worker.
pub(crate) struct RequestPushConfig {
    event_endpoint: Url,
    eligibility_credential_digest: [u8; 32],
    client: reqwest::Client,
    concurrency: Arc<Semaphore>,
    rate: Mutex<RateWindow>,
}

impl std::fmt::Debug for RequestPushConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RequestPushConfig")
            .field("event_endpoint", &self.event_endpoint)
            .field("credential", &"sha256-only")
            .finish_non_exhaustive()
    }
}

impl RequestPushConfig {
    pub(crate) fn from_env(enabled: bool) -> Result<Option<Arc<Self>>, String> {
        if !enabled {
            return Ok(None);
        }
        let endpoint = std::env::var("CHAT_REQUEST_PUSH_NEST_EVENTS_URL")
            .map_err(|_| "CHAT_REQUEST_PUSH_NEST_EVENTS_URL must be configured")?;
        let event_endpoint = parse_production_event_endpoint(&endpoint)?;
        let credential = std::env::var("CHAT_REQUEST_PUSH_ELIGIBILITY_BEARER")
            .map_err(|_| "CHAT_REQUEST_PUSH_ELIGIBILITY_BEARER must be configured")?;
        let credential = credential.trim();
        let decoded = URL_SAFE_NO_PAD
            .decode(credential)
            .map_err(|_| "CHAT_REQUEST_PUSH_ELIGIBILITY_BEARER must be canonical base64url")?;
        if decoded.len() < 32
            || decoded.len() > 128
            || URL_SAFE_NO_PAD.encode(&decoded) != credential
        {
            return Err(
                "CHAT_REQUEST_PUSH_ELIGIBILITY_BEARER must be canonical unpadded base64url for 32..128 bytes"
                    .into(),
            );
        }
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(REQUEST_PUSH_HTTP_TIMEOUT_SECONDS))
            .build()
            .map_err(|_| "request push HTTP client configuration failed")?;
        Ok(Some(Arc::new(Self {
            event_endpoint,
            eligibility_credential_digest: Sha256::digest(credential.as_bytes()).into(),
            client,
            concurrency: Arc::new(Semaphore::new(MAX_CONCURRENCY)),
            rate: Mutex::new(RateWindow {
                started: tokio::time::Instant::now(),
                requests: 0,
            }),
        })))
    }

    pub(crate) fn event_endpoint(&self) -> &Url {
        &self.event_endpoint
    }

    pub(crate) fn client(&self) -> &reqwest::Client {
        &self.client
    }

    fn credential_matches(&self, headers: &HeaderMap) -> bool {
        let values = headers.get_all(AUTHORIZATION).iter().collect::<Vec<_>>();
        let Some(value) = values
            .as_slice()
            .first()
            .filter(|_| values.len() == 1)
            .and_then(|value| value.to_str().ok())
        else {
            return false;
        };
        let Some(credential) = value.strip_prefix("Bearer ") else {
            return false;
        };
        let digest: [u8; 32] = Sha256::digest(credential.as_bytes()).into();
        bool::from(digest.ct_eq(&self.eligibility_credential_digest))
    }

    async fn admit_rate(&self) -> bool {
        let mut rate = self.rate.lock().await;
        let now = tokio::time::Instant::now();
        if now.duration_since(rate.started) >= Duration::from_secs(1) {
            rate.started = now;
            rate.requests = 0;
        }
        if rate.requests >= MAX_REQUESTS_PER_SECOND {
            return false;
        }
        rate.requests += 1;
        true
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn loopback_for_test(
        event_endpoint: Url,
        canonical_credential: &str,
    ) -> Result<Arc<Self>, String> {
        if event_endpoint.scheme() != "http"
            || !matches!(
                event_endpoint.host_str(),
                Some("127.0.0.1" | "localhost" | "::1")
            )
            || event_endpoint.path() != EVENT_PATH
            || event_endpoint.query().is_some()
            || event_endpoint.fragment().is_some()
        {
            return Err("test request-push endpoint must be exact loopback HTTP".into());
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(canonical_credential)
            .map_err(|_| "test bearer must be base64url")?;
        if decoded.len() < 32 || URL_SAFE_NO_PAD.encode(decoded) != canonical_credential {
            return Err("test bearer must be canonical and at least 32 bytes".into());
        }
        Ok(Arc::new(Self {
            event_endpoint,
            eligibility_credential_digest: Sha256::digest(canonical_credential.as_bytes()).into(),
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(REQUEST_PUSH_HTTP_TIMEOUT_SECONDS))
                .build()
                .map_err(|_| "test request push client")?,
            concurrency: Arc::new(Semaphore::new(MAX_CONCURRENCY)),
            rate: Mutex::new(RateWindow {
                started: tokio::time::Instant::now(),
                requests: 0,
            }),
        }))
    }
}

fn parse_production_event_endpoint(raw: &str) -> Result<Url, String> {
    let url = Url::parse(raw).map_err(|_| "CHAT_REQUEST_PUSH_NEST_EVENTS_URL is invalid")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != EVENT_PATH
        || url.as_str() != raw
    {
        return Err(
            "CHAT_REQUEST_PUSH_NEST_EVENTS_URL must be an exact HTTPS /internal/chat/request-events URL without credentials, query, or fragment"
                .into(),
        );
    }
    Ok(url)
}

/// Nest's fresh, signed pre-send authority check.
pub(crate) async fn eligibility(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(config) = runtime.request_push_config() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !config.credential_matches(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if body.is_empty() || body.len() > MAX_INTERNAL_BODY_BYTES {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    let Ok(_permit) = config.concurrency.clone().try_acquire_owned() else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    if !config.admit_rate().await {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    let request: RequestPushEligibilityRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    if request.validate().is_err() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let Some(signer) = runtime.request_receipt_signer() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let now: chrono::DateTime<Utc> = match sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *tx)
        .await
    {
        Ok(now) => now,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let decision = match evaluate_eligibility(
        &mut tx,
        &request,
        config.eligibility_credential_digest,
        runtime.relationship_authority(),
        now,
    )
    .await
    {
        Ok(decision) => decision,
        Err(RequestPushEligibilityError::Invalid) => {
            return StatusCode::BAD_REQUEST.into_response()
        }
        Err(RequestPushEligibilityError::NotFound) => return StatusCode::NOT_FOUND.into_response(),
        Err(
            RequestPushEligibilityError::PolicyUnavailable
            | RequestPushEligibilityError::Database(_),
        ) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        Err(RequestPushEligibilityError::Invariant) => {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    };
    if tx.commit().await.is_err() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let checked_at = decision.checked_at;
    let response = RequestPushEligibilityBody {
        protocol_version: 1,
        authority_did: REQUEST_PUSH_AUTHORITY.into(),
        key_id: signer.key_id().into(),
        event_id: request.event_id,
        request_id: request.request_id,
        recipient_did: request.recipient_did,
        device_id: request.device_id,
        provider: request.provider,
        registration_id: request.registration_id,
        token_generation: request.token_generation,
        binding_digest: request.binding_digest,
        target_key_id: request.target_key_id,
        device_auth_generation: request.device_auth_generation,
        conversation_id: decision.conversation_id.to_string(),
        first_message_id: decision.first_message_id.to_string(),
        sender_did: decision.sender_did,
        eligible: decision.eligible,
        checked_at: canonical_time(checked_at),
        expires_at: canonical_time(checked_at + ChronoDuration::seconds(5)),
    };
    match signer.seal_request_push_eligibility(response, checked_at) {
        Ok(envelope) => (StatusCode::OK, Json(envelope)).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_endpoint_is_exact_https_only() {
        assert!(parse_production_event_endpoint(
            "https://nest.example.test/internal/chat/request-events"
        )
        .is_ok());
        for value in [
            "http://nest.example.test/internal/chat/request-events",
            "https://user@nest.example.test/internal/chat/request-events",
            "https://nest.example.test/internal/chat/request-events?x=1",
            "https://nest.example.test/internal/chat/request-events/",
            "https://nest.example.test/internal/chat/request-push-eligibility",
        ] {
            assert!(parse_production_event_endpoint(value).is_err(), "{value}");
        }
    }

    #[tokio::test]
    async fn eligibility_bearer_is_exact_and_digest_only() {
        let credential = URL_SAFE_NO_PAD.encode([7; 32]);
        let config = RequestPushConfig::loopback_for_test(
            Url::parse("http://127.0.0.1:3000/internal/chat/request-events").unwrap(),
            &credential,
        )
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            format!("Bearer {credential}").parse().unwrap(),
        );
        assert!(config.credential_matches(&headers));
        headers.insert(
            AUTHORIZATION,
            format!("Bearer {}", URL_SAFE_NO_PAD.encode([8; 32]))
                .parse()
                .unwrap(),
        );
        assert!(!config.credential_matches(&headers));
        headers.append(
            AUTHORIZATION,
            format!("Bearer {credential}").parse().unwrap(),
        );
        assert!(!config.credential_matches(&headers));
        assert_eq!(config.eligibility_credential_digest.len(), 32);
    }
}
