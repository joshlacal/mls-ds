use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::Instant;
use tracing::{debug, warn};

use super::ack::DeliveryAck;
use super::receipt::SequencerReceipt;
use crate::util::outbound_body::{
    collect_bounded, decode_json_bounded, summarize_error_body, OutboundBodyError,
    ResponseBodyBudget, SanitizedErrorSummary, ERROR_RESPONSE_MAX_BYTES,
    ORDINARY_DS_CONTROL_MAX_BYTES,
};

const REMOTE_DS: &str = "remote DS";

/// HTTP client for outbound DS-to-DS calls.
pub struct OutboundClient {
    http: Client,
    connect_timeout: Duration,
    request_timeout: Duration,
}

/// Response from a remote DS.
#[derive(Debug, Deserialize)]
pub struct DsResponse {
    #[serde(default)]
    pub accepted: bool,
    pub seq: Option<i64>,
    pub assigned_epoch: Option<i32>,
    pub conflict_reason: Option<String>,
    pub key_package: Option<String>,
    pub key_package_hash: Option<String>,
    #[serde(rename = "reasonCode")]
    pub reason_code: Option<String>,
    pub error: Option<String>,
    pub message: Option<String>,
    pub ack: Option<DeliveryAck>,
    /// Sequencer receipt proving commit ordering (only present for commit responses).
    pub receipt: Option<SequencerReceipt>,
}

impl OutboundClient {
    pub fn new(connect_timeout_secs: u64, request_timeout_secs: u64) -> Self {
        #[cfg(feature = "test-support")]
        if let Some(transport) = crate::chat_protocol::relationship_policy::installed_test_https_relationship_transport() {
            return Self {
                http: transport.client,
                connect_timeout: Duration::from_secs(connect_timeout_secs),
                request_timeout: Duration::from_secs(request_timeout_secs),
            };
        }
        #[cfg(feature = "test-support")]
        if let Some(client) = crate::auth::test_fixture_http_client() {
            return Self {
                http: client,
                connect_timeout: Duration::from_secs(connect_timeout_secs),
                request_timeout: Duration::from_secs(request_timeout_secs),
            };
        }
        let mut builder = Client::builder()
            .connect_timeout(Duration::from_secs(connect_timeout_secs))
            .timeout(Duration::from_secs(request_timeout_secs))
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(10)
            .user_agent("catbird-mls-ds/1.0");

        if let (Ok(hosts), Ok(port_str), Ok(ca_path)) = (
            std::env::var("REQUEST_FIXTURE_DID_HOSTS"),
            std::env::var("REQUEST_FIXTURE_DID_PORT"),
            std::env::var("REQUEST_FIXTURE_DID_CA_PEM"),
        ) {
            if let (Ok(port), Ok(ca_pem)) = (port_str.parse::<u16>(), std::fs::read(&ca_path)) {
                if let Ok(cert) = reqwest::Certificate::from_pem(&ca_pem) {
                    let loopback = std::net::SocketAddr::from(([127, 0, 0, 1], port));
                    builder = builder
                        .tls_built_in_root_certs(false)
                        .add_root_certificate(cert);
                    for host in hosts.split(',').map(str::trim).filter(|h| !h.is_empty()) {
                        builder = builder.resolve(host, loopback);
                    }
                }
            }
        }

        let http = builder.build().expect("failed to build HTTP client");

        Self {
            http,
            connect_timeout: Duration::from_secs(connect_timeout_secs),
            request_timeout: Duration::from_secs(request_timeout_secs),
        }
    }

    async fn http_for_endpoint(&self, endpoint: &str) -> Result<Client, OutboundError> {
        #[cfg(test)]
        if endpoint.starts_with("http://127.0.0.1:") {
            return Ok(self.http.clone());
        }
        let parsed = super::resolver::validate_endpoint_url(endpoint).map_err(|error| {
            OutboundError::ResolutionFailed {
                endpoint: REMOTE_DS.into(),
                reason: error.to_string(),
                retryable: false,
            }
        })?;
        let (host, addrs) = super::resolver::resolve_and_pin_destination(&parsed)
            .await
            .map_err(|error| OutboundError::ResolutionFailed {
                endpoint: REMOTE_DS.into(),
                reason: error.to_string(),
                retryable: false,
            })?;
        if addrs.is_empty() {
            return Ok(self.http.clone());
        }
        Client::builder()
            .no_proxy()
            .connect_timeout(self.connect_timeout)
            .timeout(self.request_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(&host, &addrs)
            .build()
            .map_err(|error| OutboundError::RequestFailed {
                endpoint: REMOTE_DS.into(),
                reason: format!("Cannot connect to validated DS address: {error}"),
            })
    }

    /// Make an authenticated XRPC procedure call to a remote DS.
    pub async fn call_procedure(
        &self,
        endpoint: &str,
        method: &str,
        auth_token: &str,
        body: &impl Serialize,
    ) -> Result<DsResponse, OutboundError> {
        let url = format!("{}/xrpc/{}", endpoint.trim_end_matches('/'), method);
        debug!(method, "Outbound DS call");
        let deadline = self.deadline(method)?;

        let send = self
            .http_for_endpoint(endpoint).await?
            .post(&url)
            .header("Authorization", format!("Bearer {auth_token}"))
            .header("Content-Type", "application/json")
            .json(body)
            .send();
        let resp = tokio::time::timeout_at(deadline, send)
            .await
            .map_err(|_| timeout_error(method))?
            .map_err(|error| classify_ordinary_reqwest_error(error, method))?;

        parse_response(resp, method, deadline).await
    }

    /// Make an authenticated XRPC query call to a remote DS.
    pub async fn call_query(
        &self,
        endpoint: &str,
        method: &str,
        auth_token: &str,
        params: &[(&str, &str)],
    ) -> Result<DsResponse, OutboundError> {
        let url = format!("{}/xrpc/{}", endpoint.trim_end_matches('/'), method);
        debug!(method, "Outbound DS query");
        let deadline = self.deadline(method)?;

        let send = self
            .http_for_endpoint(endpoint).await?
            .get(&url)
            .header("Authorization", format!("Bearer {auth_token}"))
            .query(params)
            .send();
        let resp = tokio::time::timeout_at(deadline, send)
            .await
            .map_err(|_| timeout_error(method))?
            .map_err(|error| classify_ordinary_reqwest_error(error, method))?;

        parse_response(resp, method, deadline).await
    }

    /// Make an authenticated XRPC query call returning raw JSON.
    pub async fn call_query_json(
        &self,
        endpoint: &str,
        method: &str,
        auth_token: &str,
        params: &[(&str, &str)],
    ) -> Result<serde_json::Value, OutboundError> {
        let url = format!("{}/xrpc/{}", endpoint.trim_end_matches('/'), method);
        debug!(method, "Outbound DS query (raw json)");
        let deadline = self.deadline(method)?;

        let send = self
            .http_for_endpoint(endpoint).await?
            .get(&url)
            .header("Authorization", format!("Bearer {auth_token}"))
            .query(params)
            .send();
        let resp = tokio::time::timeout_at(deadline, send)
            .await
            .map_err(|_| timeout_error(method))?
            .map_err(|error| classify_ordinary_reqwest_error(error, method))?;

        let status = resp.status();
        if status.is_success() {
            decode_json_bounded(
                resp,
                ResponseBodyBudget::new(ORDINARY_DS_CONTROL_MAX_BYTES, deadline),
            )
            .await
            .map_err(|error| map_ordinary_body_error(error, method))
        } else {
            let (body, predecessor_reason) = parse_error_response(resp, deadline).await;
            Err(OutboundError::RemoteError {
                status: status.as_u16(),
                body,
                endpoint: REMOTE_DS.to_string(),
                method: method.to_string(),
                predecessor_reason,
            })
        }
    }
    /// Make an authenticated XRPC procedure call returning raw JSON.
    pub async fn call_procedure_json(
        &self,
        endpoint: &str,
        method: &str,
        auth_token: &str,
        body: &impl Serialize,
    ) -> Result<serde_json::Value, OutboundError> {
        let url = format!("{}/xrpc/{}", endpoint.trim_end_matches('/'), method);
        debug!(method, "Outbound DS procedure (raw json)");
        let deadline = self.deadline(method)?;

        let send = self
            .http_for_endpoint(endpoint).await?
            .post(&url)
            .header("Authorization", format!("Bearer {auth_token}"))
            .header("Content-Type", "application/json")
            .json(body)
            .send();
        let resp = tokio::time::timeout_at(deadline, send)
            .await
            .map_err(|_| timeout_error(method))?
            .map_err(|error| classify_ordinary_reqwest_error(error, method))?;

        let status = resp.status();
        if status.is_success() {
            decode_json_bounded(
                resp,
                ResponseBodyBudget::new(ORDINARY_DS_CONTROL_MAX_BYTES, deadline),
            )
            .await
            .map_err(|error| map_ordinary_body_error(error, method))
        } else {
            let (error_body, predecessor_reason) = parse_error_response(resp, deadline).await;
            Err(OutboundError::RemoteError {
                status: status.as_u16(),
                body: error_body,
                endpoint: endpoint.to_string(),
                method: method.to_string(),
                predecessor_reason,
            })
        }
    }
    /// Check if a remote DS is reachable.
    pub async fn health_check(
        &self,
        endpoint: &str,
        auth_token: &str,
    ) -> Result<bool, OutboundError> {
        match self
            .call_query(endpoint, "blue.catbird.mlsDS.healthCheck", auth_token, &[])
            .await
        {
            Ok(_) => Ok(true),
            Err(OutboundError::Timeout { .. } | OutboundError::ConnectionFailed { .. }) => {
                warn!("Remote DS health check failed (unreachable)");
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    fn deadline(&self, method: &str) -> Result<Instant, OutboundError> {
        Instant::now()
            .checked_add(self.request_timeout)
            .ok_or_else(|| timeout_error(method))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn timeout_error(method: &str) -> OutboundError {
    OutboundError::Timeout {
        endpoint: REMOTE_DS.to_string(),
        method: method.to_string(),
    }
}

fn classify_ordinary_reqwest_error(error: reqwest::Error, method: &str) -> OutboundError {
    if error.is_timeout() {
        timeout_error(method)
    } else if error.is_connect() {
        OutboundError::ConnectionFailed {
            endpoint: REMOTE_DS.to_string(),
            reason: "connection failed".to_string(),
        }
    } else {
        OutboundError::RequestFailed {
            endpoint: REMOTE_DS.to_string(),
            reason: "request failed".to_string(),
        }
    }
}

async fn parse_response(
    resp: reqwest::Response,
    method: &str,
    deadline: Instant,
) -> Result<DsResponse, OutboundError> {
    let status = resp.status();
    if status.is_success() {
        decode_json_bounded(
            resp,
            ResponseBodyBudget::new(ORDINARY_DS_CONTROL_MAX_BYTES, deadline),
        )
        .await
        .map_err(|error| map_ordinary_body_error(error, method))
    } else {
        let (body, predecessor_reason) = parse_error_response(resp, deadline).await;
        Err(OutboundError::RemoteError {
            status: status.as_u16(),
            body,
            endpoint: REMOTE_DS.to_string(),
            method: method.to_string(),
            predecessor_reason,
        })
    }
}

fn map_ordinary_body_error(error: OutboundBodyError, method: &str) -> OutboundError {
    match error {
        OutboundBodyError::DeadlineExceeded => timeout_error(method),
        OutboundBodyError::ReadFailed(source) => {
            if source.is_timeout() {
                timeout_error(method)
            } else {
                OutboundError::RequestFailed {
                    endpoint: REMOTE_DS.to_string(),
                    reason: "response body read failed".to_string(),
                }
            }
        }
        OutboundBodyError::InvalidJson(_) => OutboundError::InvalidResponse {
            reason: "outbound response JSON was invalid".to_string(),
        },
        other => OutboundError::InvalidResponse {
            reason: format!("Response body rejected: {other}"),
        },
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Outbound-specific errors.
#[derive(Debug, thiserror::Error)]
pub enum OutboundError {
    #[error("Connection to {endpoint} failed: {reason}")]
    ConnectionFailed { endpoint: String, reason: String },

    #[error("Request to {endpoint} {method} timed out")]
    Timeout { endpoint: String, method: String },

    #[error("Request to {endpoint} failed: {reason}")]
    RequestFailed { endpoint: String, reason: String },

    #[error("Resolution failed for {endpoint}: {reason}")]
    ResolutionFailed {
        endpoint: String,
        reason: String,
        retryable: bool,
    },

    #[error("Remote DS {endpoint} returned {status}: {body}")]
    RemoteError {
        status: u16,
        body: String,
        endpoint: String,
        method: String,
        predecessor_reason: Option<String>,
    },

    #[error("Invalid response from remote DS: {reason}")]
    InvalidResponse { reason: String },
}

impl OutboundError {
    /// Whether this error is transient and the request should be retried.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::ConnectionFailed { .. } | Self::Timeout { .. } | Self::RequestFailed { .. } => {
                true
            }
            Self::ResolutionFailed { retryable, .. } => *retryable,
            Self::RemoteError { status, .. } => *status >= 500 || *status == 429,
            Self::InvalidResponse { .. } => false,
        }
    }

    pub fn predecessor_reason(&self) -> Option<&str> {
        match self {
            Self::RemoteError { predecessor_reason, .. } => predecessor_reason.as_deref(),
            _ => None,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ErrorResponseBody {
    error: Option<String>,
    message: Option<String>,
    #[serde(rename = "reasonCode")]
    reason_code: Option<String>,
}

async fn parse_error_response(
    resp: reqwest::Response,
    deadline: Instant,
) -> (String, Option<String>) {
    let declared_bytes = resp.content_length();
    let budget = ResponseBodyBudget::new(ERROR_RESPONSE_MAX_BYTES, deadline);
    match collect_bounded(resp, budget).await {
        Ok(bytes) => {
            let summary = SanitizedErrorSummary {
                declared_bytes,
                observed_at_least_bytes: bytes.len(),
                truncated: false,
            };
            let predecessor_reason = parse_predecessor_reason(&bytes);
            (summary.to_string(), predecessor_reason)
        }
        Err(err) => {
            let summary = match err {
                OutboundBodyError::DeclaredTooLarge { declared_bytes, .. } => SanitizedErrorSummary {
                    declared_bytes: Some(declared_bytes),
                    observed_at_least_bytes: usize::try_from(declared_bytes).unwrap_or(usize::MAX),
                    truncated: true,
                },
                OutboundBodyError::StreamedTooLarge {
                    observed_at_least_bytes,
                    ..
                } => SanitizedErrorSummary {
                    declared_bytes,
                    observed_at_least_bytes,
                    truncated: true,
                },
                _ => SanitizedErrorSummary {
                    declared_bytes,
                    observed_at_least_bytes: 0,
                    truncated: false,
                },
            };
            (summary.to_string(), None)
        }
    }
}

fn parse_predecessor_reason(bytes: &[u8]) -> Option<String> {
    if let Ok(parsed) = serde_json::from_slice::<ErrorResponseBody>(bytes) {
        if let Some(msg) = parsed.message.filter(|s| is_predecessor_error_text(s)) {
            return Some(msg);
        }
        if let Some(code) = parsed.reason_code.filter(|s| is_predecessor_error_text(s)) {
            return Some(code);
        }
        if let Some(err) = parsed.error.filter(|s| is_predecessor_error_text(s)) {
            return Some(err);
        }
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        if is_predecessor_error_text(text) {
            let snippet = text.chars().take(128).collect::<String>();
            return Some(snippet);
        }
    }
    None
}

fn is_predecessor_error_text(s: &str) -> bool {
    s.to_ascii_lowercase().contains("predecessor")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Response, StatusCode},
        routing::{get, post},
        Json, Router,
    };
    use bytes::Bytes;
    use futures::stream;
    use serde_json::json;
    use std::convert::Infallible;
    use tokio::net::TcpListener;

    const TEST_METHOD: &str = "blue.catbird.mlsDS.test";

    async fn spawn_ds(router: Router) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        format!("http://{address}")
    }

    #[tokio::test]
    async fn bounded_procedure_and_typed_query_responses_succeed() {
        let route = format!("/xrpc/{TEST_METHOD}");
        let router = Router::new().route(
            &route,
            post(|| async { Json(json!({ "accepted": true, "seq": 41 })) })
                .get(|| async { Json(json!({ "accepted": true, "seq": 42 })) }),
        );
        let endpoint = spawn_ds(router).await;
        let client = OutboundClient::new(1, 1);

        let procedure = client
            .call_procedure(&endpoint, TEST_METHOD, "token", &json!({}))
            .await
            .unwrap();
        let query = client
            .call_query(&endpoint, TEST_METHOD, "token", &[])
            .await
            .unwrap();

        assert_eq!(procedure.seq, Some(41));
        assert_eq!(query.seq, Some(42));
    }

    #[tokio::test]
    async fn declared_procedure_body_over_one_mib_is_rejected() {
        let route = format!("/xrpc/{TEST_METHOD}");
        let router = Router::new().route(
            &route,
            post(|| async {
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from(vec![
                        b' ';
                        crate::util::outbound_body::ORDINARY_DS_CONTROL_MAX_BYTES
                            + 1
                    ]))
                    .unwrap()
            }),
        );
        let endpoint = spawn_ds(router).await;

        let error = OutboundClient::new(1, 1)
            .call_procedure(&endpoint, TEST_METHOD, "token", &json!({}))
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            OutboundError::InvalidResponse { ref reason }
                if reason.contains("exceeding limit 1048576")
        ));
    }

    #[tokio::test]
    async fn chunked_typed_query_body_over_one_mib_is_rejected() {
        let route = format!("/xrpc/{TEST_METHOD}");
        let router = Router::new().route(
            &route,
            get(|| async {
                let chunks = [
                    Ok::<_, Infallible>(Bytes::from(vec![b' '; 700 * 1024])),
                    Ok::<_, Infallible>(Bytes::from(vec![b' '; 400 * 1024])),
                ];
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from_stream(stream::iter(chunks)))
                    .unwrap()
            }),
        );
        let endpoint = spawn_ds(router).await;

        let error = OutboundClient::new(1, 1)
            .call_query(&endpoint, TEST_METHOD, "token", &[])
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            OutboundError::InvalidResponse { ref reason }
                if reason.contains("exceeding limit 1048576")
        ));
    }

    #[tokio::test]
    async fn declared_raw_json_query_body_over_one_mib_is_rejected() {
        let route = format!("/xrpc/{TEST_METHOD}");
        let router = Router::new().route(
            &route,
            get(|| async {
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from(vec![
                        b' ';
                        crate::util::outbound_body::ORDINARY_DS_CONTROL_MAX_BYTES
                            + 1
                    ]))
                    .unwrap()
            }),
        );
        let endpoint = spawn_ds(router).await;

        let error = OutboundClient::new(1, 1)
            .call_query_json(&endpoint, TEST_METHOD, "token", &[])
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            OutboundError::InvalidResponse { ref reason }
                if reason.contains("exceeding limit 1048576")
        ));
    }

    #[tokio::test]
    async fn raw_json_query_headers_and_body_share_one_deadline() {
        let route = format!("/xrpc/{TEST_METHOD}");
        let router = Router::new().route(
            &route,
            get(|| async {
                tokio::time::sleep(Duration::from_millis(550)).await;
                let chunks = stream::once(async {
                    tokio::time::sleep(Duration::from_millis(550)).await;
                    Ok::<_, Infallible>(Bytes::from_static(br#"{}"#))
                });
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from_stream(chunks))
                    .unwrap()
            }),
        );
        let endpoint = spawn_ds(router).await;

        let error = OutboundClient::new(1, 1)
            .call_query_json(&endpoint, TEST_METHOD, "token", &[])
            .await
            .unwrap_err();

        assert!(matches!(error, OutboundError::Timeout { .. }));
    }

    #[tokio::test]
    async fn procedure_headers_and_body_share_one_deadline() {
        let route = format!("/xrpc/{TEST_METHOD}");
        let router = Router::new().route(
            &route,
            post(|| async {
                tokio::time::sleep(Duration::from_millis(550)).await;
                let chunks = stream::once(async {
                    tokio::time::sleep(Duration::from_millis(550)).await;
                    Ok::<_, Infallible>(Bytes::from_static(br#"{"accepted":true}"#))
                });
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from_stream(chunks))
                    .unwrap()
            }),
        );
        let endpoint = spawn_ds(router).await;

        let error = OutboundClient::new(1, 1)
            .call_procedure(&endpoint, TEST_METHOD, "token", &json!({}))
            .await
            .unwrap_err();

        assert!(matches!(error, OutboundError::Timeout { .. }));
    }

    #[tokio::test]
    async fn non_success_preserves_status_and_retryability_without_body_content() {
        const CANARY: &str = "bearer=canary-token cookie=canary-cookie";
        let route = format!("/xrpc/{TEST_METHOD}");
        let router = Router::new().route(
            &route,
            get(|| async {
                Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(Body::from(CANARY))
                    .unwrap()
            }),
        );
        let endpoint = spawn_ds(router).await;

        let error = OutboundClient::new(1, 1)
            .call_query(&endpoint, TEST_METHOD, "token", &[])
            .await
            .unwrap_err();
        let display = error.to_string();
        let debug = format!("{error:?}");

        assert!(matches!(
            error,
            OutboundError::RemoteError { status: 503, .. }
        ));
        assert!(error.is_retryable());
        assert!(!display.contains(CANARY));
        assert!(!debug.contains(CANARY));
        assert!(!display.contains("canary"));
        assert!(!debug.contains("canary"));
    }

    #[tokio::test]
    async fn malformed_bounded_json_has_sanitized_invalid_response() {
        const CANARY: &str = "malformed-canary-secret";
        let route = format!("/xrpc/{TEST_METHOD}");
        let router = Router::new().route(
            &route,
            post(|| async {
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from(CANARY))
                    .unwrap()
            }),
        );
        let endpoint = spawn_ds(router).await;

        let error = OutboundClient::new(1, 1)
            .call_procedure(&endpoint, TEST_METHOD, "token", &json!({}))
            .await
            .unwrap_err();
        let display = error.to_string();
        let debug = format!("{error:?}");

        assert!(matches!(error, OutboundError::InvalidResponse { .. }));
        assert!(!display.contains(CANARY));
        assert!(!debug.contains(CANARY));
        assert!(!display.contains("canary"));
        assert!(!debug.contains("canary"));
    }

    #[test]
    fn health_check_warning_does_not_attach_endpoint_url() {
        let source = include_str!("outbound.rs");
        let health_check = source
            .split("    pub async fn health_check(")
            .nth(1)
            .unwrap()
            .split("    fn deadline(")
            .next()
            .unwrap();

        assert!(!health_check.contains("warn!(endpoint"));
    }

    #[test]
    fn test_connection_failed_is_retryable() {
        assert!(OutboundError::ConnectionFailed {
            endpoint: "https://ds.example.com".into(),
            reason: "connection refused".into(),
        }
        .is_retryable());
    }

    #[test]
    fn test_timeout_is_retryable() {
        assert!(OutboundError::Timeout {
            endpoint: "https://ds.example.com".into(),
            method: "blue.catbird.mlsDS.deliverMessage".into(),
        }
        .is_retryable());
    }

    #[test]
    fn test_request_failed_is_retryable() {
        assert!(OutboundError::RequestFailed {
            endpoint: "https://ds.example.com".into(),
            reason: "DNS resolution failed".into(),
        }
        .is_retryable());
    }

    #[test]
    fn test_invalid_response_not_retryable() {
        assert!(!OutboundError::InvalidResponse {
            reason: "bad json".into(),
        }
        .is_retryable());
    }

    #[test]
    fn test_remote_error_5xx_retryable() {
        for status in [500, 502, 503, 504] {
            assert!(
                OutboundError::RemoteError {
                    status,
                    body: "".into(),
                    endpoint: "x".into(),
                    method: "y".into(),
                    predecessor_reason: None,
                }
                .is_retryable(),
                "status {status} should be retryable"
            );
        }
    }

    #[test]
    fn test_remote_error_429_retryable() {
        assert!(OutboundError::RemoteError {
            status: 429,
            body: "rate limited".into(),
            endpoint: "x".into(),
            method: "y".into(),
            predecessor_reason: None,
        }
        .is_retryable());
    }

    #[test]
    fn test_remote_error_4xx_not_retryable() {
        for status in [400, 401, 403, 404, 422] {
            assert!(
                !OutboundError::RemoteError {
                    status,
                    body: "".into(),
                    endpoint: "x".into(),
                    method: "y".into(),
                    predecessor_reason: None,
                }
                .is_retryable(),
                "status {status} should NOT be retryable"
            );
        }
    }

    #[test]
    fn test_resolution_failed_retryability() {
        assert!(OutboundError::ResolutionFailed {
            endpoint: "did:web:example.com".into(),
            reason: "timeout".into(),
            retryable: true,
        }
        .is_retryable());

        assert!(!OutboundError::ResolutionFailed {
            endpoint: "did:web:example.com".into(),
            reason: "invalid did document json".into(),
            retryable: false,
        }
        .is_retryable());
    }

    #[tokio::test]
    async fn non_success_400_with_predecessor_preserves_typed_reason_and_sanitizes_body() {
        let route = format!("/xrpc/{TEST_METHOD}");
        let router = Router::new().route(
            &route,
            post(|| async {
                Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        r#"{"error":"InvalidRequest","message":"missing signed predecessor entry","reasonCode":"invalid_request"}"#,
                    ))
                    .unwrap()
            }),
        );
        let endpoint = spawn_ds(router).await;

        let error = OutboundClient::new(1, 1)
            .call_procedure(&endpoint, TEST_METHOD, "token", &json!({}))
            .await
            .unwrap_err();

        assert_eq!(
            error.predecessor_reason(),
            Some("missing signed predecessor entry")
        );
        assert!(!error.is_retryable());
        assert!(!error.to_string().contains("missing signed predecessor entry"));
    }

    #[tokio::test]
    async fn outbound_post_does_not_follow_redirect_to_private_sink() {
        use std::sync::{atomic::{AtomicUsize, Ordering}, Arc};

        let sink_hits = Arc::new(AtomicUsize::new(0));
        let hits = sink_hits.clone();
        let sink = spawn_ds(Router::new().route(
            "/private",
            post(move || {
                let hits = hits.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    Json(json!({"accepted": true}))
                }
            }),
        )).await;
        let redirect = spawn_ds(Router::new().route(
            &format!("/xrpc/{TEST_METHOD}"),
            post(move || {
                let target = format!("{sink}/private");
                async move {
                    Response::builder()
                        .status(StatusCode::TEMPORARY_REDIRECT)
                        .header("location", target)
                        .body(Body::empty())
                        .unwrap()
                }
            }),
        )).await;
        let failure = OutboundClient::new(1, 2)
            .call_procedure_json(&redirect, TEST_METHOD, "secret", &json!({}))
            .await
            .unwrap_err();
        assert!(matches!(failure, OutboundError::RemoteError { status: 307, .. }));
        assert_eq!(sink_hits.load(Ordering::SeqCst), 0, "redirected request reached private sink");
    }
}
