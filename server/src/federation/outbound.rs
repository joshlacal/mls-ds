use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, warn};

use super::ack::DeliveryAck;
use super::receipt::SequencerReceipt;

/// HTTP client for outbound DS-to-DS calls.
pub struct OutboundClient {
    http: Client,
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

        Self { http }
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
        debug!(url = %url, method, "Outbound DS call");

        let resp = self
            .http
            .post(&url)
            .header("Authorization", format!("Bearer {auth_token}"))
            .header("Content-Type", "application/json")
            .json(body)
            .send()
            .await
            .map_err(|e| classify_reqwest_error(e, endpoint, method))?;

        parse_response(resp, endpoint, method).await
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
        debug!(url = %url, method, "Outbound DS query");

        let resp = self
            .http
            .get(&url)
            .header("Authorization", format!("Bearer {auth_token}"))
            .query(params)
            .send()
            .await
            .map_err(|e| classify_reqwest_error(e, endpoint, method))?;

        parse_response(resp, endpoint, method).await
    }

    /// Check if a remote DS is reachable.
    pub async fn health_check(
        &self,
        endpoint: &str,
        auth_token: &str,
    ) -> Result<bool, OutboundError> {
        match self
            .call_query(endpoint, "blue.catbird.mls.ds.healthCheck", auth_token, &[])
            .await
        {
            Ok(_) => Ok(true),
            Err(OutboundError::Timeout { .. } | OutboundError::ConnectionFailed { .. }) => {
                warn!(endpoint, "Remote DS health check failed (unreachable)");
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn classify_reqwest_error(e: reqwest::Error, endpoint: &str, method: &str) -> OutboundError {
    if e.is_timeout() {
        OutboundError::Timeout {
            endpoint: endpoint.to_string(),
            method: method.to_string(),
        }
    } else if e.is_connect() {
        OutboundError::ConnectionFailed {
            endpoint: endpoint.to_string(),
            reason: e.to_string(),
        }
    } else {
        OutboundError::RequestFailed {
            endpoint: endpoint.to_string(),
            reason: e.to_string(),
        }
    }
}

async fn parse_response(
    resp: reqwest::Response,
    endpoint: &str,
    method: &str,
) -> Result<DsResponse, OutboundError> {
    let status = resp.status();
    if status.is_success() {
        resp.json::<DsResponse>()
            .await
            .map_err(|e| OutboundError::InvalidResponse {
                reason: e.to_string(),
            })
    } else {
        let body_text = resp
            .text()
            .await
            .unwrap_or_else(|_| String::from("<unreadable>"));
        Err(OutboundError::RemoteError {
            status: status.as_u16(),
            body: body_text,
            endpoint: endpoint.to_string(),
            method: method.to_string(),
        })
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            method: "blue.catbird.mls.ds.deliverMessage".into(),
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
