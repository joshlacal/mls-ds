use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::Instant;
use tracing::{debug, warn};

use super::ack::DeliveryAck;
use super::receipt::SequencerReceipt;
use crate::util::outbound_body::{
    decode_json_bounded, summarize_error_body, OutboundBodyError, ResponseBodyBudget,
    ORDINARY_DS_CONTROL_MAX_BYTES,
};

const REMOTE_DS: &str = "remote DS";

use super::resolver::ValidatedRemoteDestination;

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
        let http = Client::builder()
            .connect_timeout(Duration::from_secs(connect_timeout_secs))
            .timeout(Duration::from_secs(request_timeout_secs))
            .pool_max_idle_per_host(10)
            .user_agent("catbird-mls-ds/1.0")
            .build()
            .expect("failed to build HTTP client");

        Self {
            http,
            connect_timeout: Duration::from_secs(connect_timeout_secs),
            request_timeout: Duration::from_secs(request_timeout_secs),
        }
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
            .http
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

    /// Make an authenticated XRPC procedure call to a remote DS with pinned SSRF-validated socket addresses.
    pub async fn call_procedure_pinned(
        &self,
        destination: &ValidatedRemoteDestination,
        method: &str,
        auth_token: &str,
        body: &impl Serialize,
    ) -> Result<DsResponse, OutboundError> {
        let endpoint = destination.url.as_str().trim_end_matches('/');
        let url = format!("{}/xrpc/{}", endpoint, method);
        debug!(method, host = %destination.host, "Outbound pinned DS call");
        let deadline = self.deadline(method)?;

        let client = Client::builder()
            .connect_timeout(self.connect_timeout)
            .timeout(self.request_timeout)
            .user_agent("catbird-mls-ds/1.0")
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(&destination.host, &destination.addrs)
            .build()
            .map_err(|e| OutboundError::RequestFailed {
                endpoint: destination.host.clone(),
                reason: format!("Failed to build pinned HTTP client: {e}"),
            })?;
        let send = client
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
            .http
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
            .http
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
            let body = summarize_error_body(resp, deadline)
                .await
                .map(|summary| summary.to_string())
                .unwrap_or_else(|error| format!("error response metadata unavailable: {error}"));
            Err(OutboundError::RemoteError {
                status: status.as_u16(),
                body,
                endpoint: REMOTE_DS.to_string(),
                method: method.to_string(),
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
        let body = summarize_error_body(resp, deadline)
            .await
            .map(|summary| summary.to_string())
            .unwrap_or_else(|error| format!("error response metadata unavailable: {error}"));
        Err(OutboundError::RemoteError {
            status: status.as_u16(),
            body,
            endpoint: REMOTE_DS.to_string(),
            method: method.to_string(),
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

    #[error("Remote DS {endpoint} returned {status}: {body}")]
    RemoteError {
        status: u16,
        body: String,
        endpoint: String,
        method: String,
    },

    #[error("Invalid response from remote DS: {reason}")]
    InvalidResponse { reason: String },

    #[error("Resolution failed for {did}: {kind}")]
    ResolutionFailed {
        did: String,
        kind: super::errors::ResolutionFailureKind,
    },
}

impl OutboundError {
    /// Whether this error is transient and the request should be retried.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::ConnectionFailed { .. } | Self::Timeout { .. } | Self::RequestFailed { .. } => {
                true
            }
            Self::RemoteError { status, .. } => *status >= 500 || *status == 429,
            Self::InvalidResponse { .. } => false,
            Self::ResolutionFailed { kind, .. } => kind.is_retryable(),
        }
    }
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

        assert!(OutboundError::ResolutionFailed {
            did: "did:web:ds.example.com".into(),
            kind: super::super::errors::ResolutionFailureKind::DnsTemporary("EAI_AGAIN".into()),
        }
        .is_retryable());

        assert!(OutboundError::ResolutionFailed {
            did: "did:web:ds.example.com".into(),
            kind: super::super::errors::ResolutionFailureKind::DnsTimeout("lookup timeout".into()),
        }
        .is_retryable());

        assert!(!OutboundError::ResolutionFailed {
            did: "did:web:ds.example.com".into(),
            kind: super::super::errors::ResolutionFailureKind::DnsNxdomain("NXDOMAIN".into()),
        }
        .is_retryable());

        assert!(!OutboundError::ResolutionFailed {
            did: "did:web:ds.example.com".into(),
            kind: super::super::errors::ResolutionFailureKind::SsrfBlocked(
                "Blocked private address".into()
            ),
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
                }
                .is_retryable(),
                "status {status} should NOT be retryable"
            );
        }
    }

    #[test]
    fn test_outbound_client_creation() {
        let client = OutboundClient::new(5, 30);
        // Just verify it doesn't panic — the HTTP client is opaque
        let _ = client;
    }

    #[test]
    fn test_ds_response_defaults() {
        let json = r#"{"accepted": true}"#;
        let resp: DsResponse = serde_json::from_str(json).unwrap();
        assert!(resp.accepted);
        assert!(resp.seq.is_none());
        assert!(resp.assigned_epoch.is_none());
        assert!(resp.error.is_none());
    }

    #[test]
    fn test_ds_response_full() {
        let json = r#"{"accepted": true, "seq": 42, "assigned_epoch": 7}"#;
        let resp: DsResponse = serde_json::from_str(json).unwrap();
        assert!(resp.accepted);
        assert_eq!(resp.seq, Some(42));
        assert_eq!(resp.assigned_epoch, Some(7));
    }

    #[test]
    fn test_ds_response_error() {
        let json =
            r#"{"accepted": false, "error": "ConflictDetected", "message": "epoch mismatch"}"#;
        let resp: DsResponse = serde_json::from_str(json).unwrap();
        assert!(!resp.accepted);
        assert_eq!(resp.error.as_deref(), Some("ConflictDetected"));
        assert_eq!(resp.message.as_deref(), Some("epoch mismatch"));
    }
}
