use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum FederationError {
    #[error("DS endpoint not found for DID {did}")]
    EndpointNotFound { did: String },

    #[error("DS at {endpoint} is unreachable: {reason}")]
    DsUnreachable { endpoint: String, reason: String },

    #[error("Commit conflict on conversation {convo_id}: current epoch is {current_epoch}")]
    CommitConflict {
        convo_id: String,
        current_epoch: i32,
    },

    #[error("Not the sequencer for conversation {convo_id}")]
    NotSequencer { convo_id: String },

    #[error(
        "Stale sequencer term for conversation {convo_id}: provided {provided_term}, current {current_term}"
    )]
    TermStale {
        convo_id: String,
        provided_term: i64,
        current_term: i64,
    },

    #[error("Service auth failed: {reason}")]
    AuthFailed { reason: String },

    #[error("Sequencer transfer failed: {reason}")]
    TransferFailed { reason: String },

    #[error("Remote DS returned error: {status} {body}")]
    RemoteError { status: u16, body: String },

    #[error("Resolution failed for {did}: {kind}")]
    ResolutionFailed {
        did: String,
        kind: ResolutionFailureKind,
    },

    #[error("Conversation not found: {convo_id}")]
    ConversationNotFound { convo_id: String },

    #[error("Recipient not found: {did}")]
    RecipientNotFound { did: String },

    #[error("No key packages available for {did}")]
    NoKeyPackagesAvailable { did: String },

    #[error("Invalid proof for sequencer transfer")]
    InvalidProof,

    #[error("Invalid commit framing: {reason}")]
    InvalidCommitFraming { reason: String },

    #[error("Configuration error: {reason}")]
    ConfigError { reason: String },

    #[error(
        "Outbound queue per-peer pending cap exceeded for {target_ds_did}: {pending} pending (limit {limit})"
    )]
    OutboundQueuePeerCapExceeded {
        target_ds_did: String,
        pending: i64,
        limit: i64,
    },

    #[error(
        "Outbound queue per-conversation pending cap exceeded for peer {target_ds_did} in conversation {convo_id}: {pending} pending (limit {limit})"
    )]
    OutboundQueueConvoPeerCapExceeded {
        target_ds_did: String,
        convo_id: String,
        pending: i64,
        limit: i64,
    },

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

impl FederationError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::EndpointNotFound { .. }
            | Self::ConversationNotFound { .. }
            | Self::RecipientNotFound { .. }
            | Self::NoKeyPackagesAvailable { .. } => StatusCode::NOT_FOUND,
            Self::CommitConflict { .. } | Self::TermStale { .. } => StatusCode::CONFLICT,
            Self::NotSequencer { .. } => StatusCode::FORBIDDEN,
            Self::AuthFailed { .. } => StatusCode::UNAUTHORIZED,
            Self::InvalidProof | Self::InvalidCommitFraming { .. } => StatusCode::BAD_REQUEST,
            Self::DsUnreachable { .. } | Self::ResolutionFailed { .. } | Self::Http(_) => {
                StatusCode::BAD_GATEWAY
            }
            Self::OutboundQueuePeerCapExceeded { .. }
            | Self::OutboundQueueConvoPeerCapExceeded { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::RemoteError { status, .. } => {
                StatusCode::from_u16(*status).unwrap_or(StatusCode::BAD_GATEWAY)
            }
            Self::TransferFailed { .. } | Self::ConfigError { .. } | Self::Database(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::Json(_) => StatusCode::BAD_REQUEST,
        }
    }

    fn error_name(&self) -> &'static str {
        match self {
            Self::EndpointNotFound { .. } => "EndpointNotFound",
            Self::DsUnreachable { .. } => "DsUnreachable",
            Self::CommitConflict { .. } => "ConflictDetected",
            Self::NotSequencer { .. } => "NotSequencer",
            Self::TermStale { .. } => "TermStale",
            Self::AuthFailed { .. } => "Unauthorized",
            Self::TransferFailed { .. } => "TransferFailed",
            Self::RemoteError { .. } => "RemoteError",
            Self::ResolutionFailed { .. } => "ResolutionFailed",
            Self::ConversationNotFound { .. } => "ConversationNotFound",
            Self::RecipientNotFound { .. } => "RecipientNotFound",
            Self::NoKeyPackagesAvailable { .. } => "NoKeyPackagesAvailable",
            Self::InvalidProof => "InvalidProof",
            Self::InvalidCommitFraming { .. } => "InvalidCommitFraming",
            Self::ConfigError { .. } => "ConfigError",
            Self::OutboundQueuePeerCapExceeded { .. }
            | Self::OutboundQueueConvoPeerCapExceeded { .. } => "QueueCapacityExceeded",
            Self::Database(_) => "InternalError",
            Self::Http(_) => "NetworkError",
            Self::Json(_) => "InvalidRequest",
        }
    }

    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::AuthFailed { .. } => "auth_failed",
            Self::NotSequencer { .. } => "not_sequencer",
            Self::TermStale { .. } => "term_stale",
            Self::CommitConflict { .. } | Self::ConversationNotFound { .. } => "conflict",
            Self::RemoteError { status, .. } if *status == 429 => "rate_limited",
            Self::OutboundQueuePeerCapExceeded { .. }
            | Self::OutboundQueueConvoPeerCapExceeded { .. } => "queue_capacity_exceeded",
            Self::Json(_) | Self::InvalidProof | Self::InvalidCommitFraming { .. } => {
                "invalid_payload"
            }
            _ => "conflict",
        }
    }

    pub fn is_retryable(&self) -> bool {
        match self {
            Self::DsUnreachable { .. } => true,
            Self::Http(err) => {
                err.is_timeout()
                    || err.is_connect()
                    || err
                        .status()
                        .map(|s| s.as_u16() >= 500 || s.as_u16() == 429)
                        .unwrap_or(false)
            }
            Self::RemoteError { status, .. } => *status >= 500 || *status == 429,
            Self::ResolutionFailed { kind, .. } => kind.is_retryable(),
            Self::Database(_) => true,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResolutionFailureKind {
    #[error("DNS temporary failure: {0}")]
    DnsTemporary(String),

    #[error("DNS NXDOMAIN/not found: {0}")]
    DnsNxdomain(String),

    #[error("DNS lookup timed out: {0}")]
    DnsTimeout(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("HTTP status {status}: {message}")]
    HttpStatus { status: u16, message: String },

    #[error("Blocked by SSRF policy: {0}")]
    SsrfBlocked(String),

    #[error("Blocked by allowlist policy: {0}")]
    AllowlistBlocked(String),

    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    #[error("Invalid DID: {0}")]
    InvalidDid(String),

    #[error("Invalid declaration record: {0}")]
    InvalidDeclaration(String),

    #[error("Invalid payload: {0}")]
    InvalidPayload(String),

    #[error("Service missing: {0}")]
    ServiceMissing(String),

    #[error("Redirect rejected: {0}")]
    RedirectRejected(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),

    #[error("Permanent error: {0}")]
    Permanent(String),

    #[error("Transient error: {0}")]
    Transient(String),
}

impl ResolutionFailureKind {
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::DnsTemporary(_)
            | Self::DnsTimeout(_)
            | Self::Timeout(_)
            | Self::ConnectionFailed(_)
            | Self::Transient(_) => true,
            Self::HttpStatus { status, .. } => *status >= 500 || *status == 429,
            Self::DnsNxdomain(_)
            | Self::SsrfBlocked(_)
            | Self::AllowlistBlocked(_)
            | Self::InvalidUrl(_)
            | Self::InvalidDid(_)
            | Self::InvalidDeclaration(_)
            | Self::InvalidPayload(_)
            | Self::ServiceMissing(_)
            | Self::RedirectRejected(_)
            | Self::InvalidConfiguration(_)
            | Self::Permanent(_) => false,
        }
    }
}

impl IntoResponse for FederationError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let error_name = self.error_name();
        crate::metrics::record_federation_rejection_reason(self.reason_code());
        tracing::error!(error = %self, error_name, "Federation error");
        (
            status,
            Json(json!({
                "error": error_name,
                "message": self.to_string(),
                "reasonCode": self.reason_code()
            })),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn test_error_status_codes() {
        assert_eq!(
            FederationError::EndpointNotFound { did: "x".into() }.status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            FederationError::ConversationNotFound {
                convo_id: "x".into()
            }
            .status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            FederationError::RecipientNotFound { did: "x".into() }.status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            FederationError::NoKeyPackagesAvailable { did: "x".into() }.status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            FederationError::CommitConflict {
                convo_id: "x".into(),
                current_epoch: 1
            }
            .status_code(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            FederationError::NotSequencer {
                convo_id: "x".into()
            }
            .status_code(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            FederationError::TermStale {
                convo_id: "x".into(),
                provided_term: 1,
                current_term: 2
            }
            .status_code(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            FederationError::AuthFailed { reason: "x".into() }.status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            FederationError::InvalidProof.status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            FederationError::DsUnreachable {
                endpoint: "x".into(),
                reason: "y".into()
            }
            .status_code(),
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            FederationError::ResolutionFailed {
                did: "x".into(),
                kind: ResolutionFailureKind::Permanent("y".into()),
            }
            .status_code(),
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            FederationError::TransferFailed { reason: "x".into() }.status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            FederationError::OutboundQueuePeerCapExceeded {
                target_ds_did: "x".into(),
                pending: 5,
                limit: 5
            }
            .status_code(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            FederationError::ConfigError { reason: "x".into() }.status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            FederationError::RemoteError {
                status: 503,
                body: "x".into()
            }
            .status_code(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn test_remote_error_preserves_status() {
        assert_eq!(
            FederationError::RemoteError {
                status: 404,
                body: "".into()
            }
            .status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            FederationError::RemoteError {
                status: 429,
                body: "".into()
            }
            .status_code(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[test]
    fn test_error_display() {
        let err = FederationError::CommitConflict {
            convo_id: "abc".to_string(),
            current_epoch: 5,
        };
        let msg = format!("{err}");
        assert!(msg.contains("abc"));
        assert!(msg.contains("5"));
    }

    #[test]
    fn test_error_display_endpoint_not_found() {
        let err = FederationError::EndpointNotFound {
            did: "did:web:test.example.com".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("did:web:test.example.com"));
    }

    #[test]
    fn test_error_name_mapping() {
        assert_eq!(
            FederationError::EndpointNotFound { did: "x".into() }.error_name(),
            "EndpointNotFound"
        );
        assert_eq!(
            FederationError::CommitConflict {
                convo_id: "x".into(),
                current_epoch: 0
            }
            .error_name(),
            "ConflictDetected"
        );
        assert_eq!(
            FederationError::NotSequencer {
                convo_id: "x".into()
            }
            .error_name(),
            "NotSequencer"
        );
        assert_eq!(
            FederationError::TermStale {
                convo_id: "x".into(),
                provided_term: 1,
                current_term: 2
            }
            .error_name(),
            "TermStale"
        );
        assert_eq!(
            FederationError::AuthFailed { reason: "x".into() }.error_name(),
            "Unauthorized"
        );
        assert_eq!(FederationError::InvalidProof.error_name(), "InvalidProof");
    }

    #[test]
    fn test_reason_code_mapping() {
        assert_eq!(
            FederationError::AuthFailed { reason: "x".into() }.reason_code(),
            "auth_failed"
        );
        assert_eq!(
            FederationError::NotSequencer {
                convo_id: "x".into()
            }
            .reason_code(),
            "not_sequencer"
        );
        assert_eq!(
            FederationError::TermStale {
                convo_id: "x".into(),
                provided_term: 1,
                current_term: 2
            }
            .reason_code(),
            "term_stale"
        );
        assert_eq!(
            FederationError::RemoteError {
                status: 429,
                body: "x".into()
            }
            .reason_code(),
            "rate_limited"
        );
        assert_eq!(
            FederationError::Json(serde_json::Error::io(std::io::Error::other("bad payload")))
                .reason_code(),
            "invalid_payload"
        );
        assert_eq!(
            FederationError::OutboundQueueConvoPeerCapExceeded {
                target_ds_did: "x".into(),
                convo_id: "c".into(),
                pending: 10,
                limit: 10
            }
            .reason_code(),
            "queue_capacity_exceeded"
        );
    }

    #[test]
    fn test_federation_error_retryability() {
        assert!(FederationError::DsUnreachable {
            endpoint: "https://ds.example.com".into(),
            reason: "connection failed".into()
        }
        .is_retryable());

        assert!(FederationError::RemoteError {
            status: 503,
            body: "service unavailable".into()
        }
        .is_retryable());

        assert!(FederationError::RemoteError {
            status: 429,
            body: "rate limited".into()
        }
        .is_retryable());

        assert!(!FederationError::RemoteError {
            status: 404,
            body: "not found".into()
        }
        .is_retryable());

        // Transient resolution errors are retryable
        assert!(FederationError::ResolutionFailed {
            did: "did:web:ds.example.com".into(),
            kind: ResolutionFailureKind::DnsTimeout(
                "DNS lookup timed out for host ds.example.com".into()
            ),
        }
        .is_retryable());

        assert!(FederationError::ResolutionFailed {
            did: "did:web:ds.example.com".into(),
            kind: ResolutionFailureKind::DnsTemporary(
                "Failed to resolve host ds.example.com: Temporary failure in name resolution"
                    .into()
            ),
        }
        .is_retryable());

        assert!(FederationError::ResolutionFailed {
            did: "did:web:ds.example.com".into(),
            kind: ResolutionFailureKind::Timeout("outbound resolution: deadline exceeded".into()),
        }
        .is_retryable());

        assert!(FederationError::ResolutionFailed {
            did: "did:web:ds.example.com".into(),
            kind: ResolutionFailureKind::ConnectionFailed("Connection refused".into()),
        }
        .is_retryable());

        assert!(FederationError::ResolutionFailed {
            did: "did:web:ds.example.com".into(),
            kind: ResolutionFailureKind::HttpStatus {
                status: 503,
                message: "DID document server returned status 503".into()
            },
        }
        .is_retryable());

        assert!(FederationError::ResolutionFailed {
            did: "did:web:ds.example.com".into(),
            kind: ResolutionFailureKind::HttpStatus {
                status: 429,
                message: "Rate limit exceeded".into()
            },
        }
        .is_retryable());

        // Non-retryable resolution errors are NOT retryable
        assert!(!FederationError::ResolutionFailed {
            did: "did:web:ds.example.com".into(),
            kind: ResolutionFailureKind::DnsNxdomain("Host ds.example.com not found".into()),
        }
        .is_retryable());

        assert!(!FederationError::ResolutionFailed {
            did: "did:web:ds.example.com".into(),
            kind: ResolutionFailureKind::SsrfBlocked("Blocked non-global IP: 127.0.0.1".into()),
        }
        .is_retryable());

        assert!(!FederationError::ResolutionFailed {
            did: "did:web:ds.example.com".into(),
            kind: ResolutionFailureKind::SsrfBlocked("Blocked private address: 10.0.0.1".into()),
        }
        .is_retryable());

        assert!(!FederationError::ResolutionFailed {
            did: "did:web:ds.example.com".into(),
            kind: ResolutionFailureKind::AllowlistBlocked(
                "Host ds.example.com is not in FEDERATION_OUTBOUND_HOST_ALLOWLIST".into()
            ),
        }
        .is_retryable());

        assert!(!FederationError::ResolutionFailed {
            did: "did:web:ds.example.com".into(),
            kind: ResolutionFailureKind::InvalidUrl(
                "Invalid URL: relative URL without a base".into()
            ),
        }
        .is_retryable());

        assert!(!FederationError::ResolutionFailed {
            did: "invalid".into(),
            kind: ResolutionFailureKind::InvalidDid("Invalid ATProto DID syntax: invalid".into()),
        }
        .is_retryable());

        assert!(!FederationError::ResolutionFailed {
            did: "did:web:ds.example.com".into(),
            kind: ResolutionFailureKind::HttpStatus {
                status: 404,
                message: "DID document server returned status 404".into()
            },
        }
        .is_retryable());

        assert!(!FederationError::ResolutionFailed {
            did: "did:web:ds.example.com".into(),
            kind: ResolutionFailureKind::ServiceMissing(
                "No #atproto_mls service in DID document".into()
            ),
        }
        .is_retryable());

        assert!(!FederationError::ResolutionFailed {
            did: "did:web:ds.example.com".into(),
            kind: ResolutionFailureKind::InvalidDeclaration(
                "Declaration record missing $type".into()
            ),
        }
        .is_retryable());

        assert!(!FederationError::ResolutionFailed {
            did: "did:web:ds.example.com".into(),
            kind: ResolutionFailureKind::RedirectRejected("Redirect rejected".into()),
        }
        .is_retryable());
        assert!(!FederationError::AuthFailed {
            reason: "unauthorized".into()
        }
        .is_retryable());
    }
}
