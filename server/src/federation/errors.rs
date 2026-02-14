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

    #[error("Service auth failed: {reason}")]
    AuthFailed { reason: String },

    #[error("Sequencer transfer failed: {reason}")]
    TransferFailed { reason: String },

    #[error("Remote DS returned error: {status} {body}")]
    RemoteError { status: u16, body: String },

    #[error("Resolution failed for {did}: {reason}")]
    ResolutionFailed { did: String, reason: String },

    #[error("Conversation not found: {convo_id}")]
    ConversationNotFound { convo_id: String },

    #[error("Recipient not found: {did}")]
    RecipientNotFound { did: String },

    #[error("No key packages available for {did}")]
    NoKeyPackagesAvailable { did: String },

    #[error("Invalid proof for sequencer transfer")]
    InvalidProof,

    #[error("Configuration error: {reason}")]
    ConfigError { reason: String },

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
            Self::CommitConflict { .. } => StatusCode::CONFLICT,
            Self::NotSequencer { .. } => StatusCode::FORBIDDEN,
            Self::AuthFailed { .. } => StatusCode::UNAUTHORIZED,
            Self::InvalidProof => StatusCode::BAD_REQUEST,
            Self::DsUnreachable { .. } | Self::ResolutionFailed { .. } | Self::Http(_) => {
                StatusCode::BAD_GATEWAY
            }
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
            Self::AuthFailed { .. } => "Unauthorized",
            Self::TransferFailed { .. } => "TransferFailed",
            Self::RemoteError { .. } => "RemoteError",
            Self::ResolutionFailed { .. } => "ResolutionFailed",
            Self::ConversationNotFound { .. } => "ConversationNotFound",
            Self::RecipientNotFound { .. } => "RecipientNotFound",
            Self::NoKeyPackagesAvailable { .. } => "NoKeyPackagesAvailable",
            Self::InvalidProof => "InvalidProof",
            Self::ConfigError { .. } => "ConfigError",
            Self::Database(_) => "InternalError",
            Self::Http(_) => "NetworkError",
            Self::Json(_) => "InvalidRequest",
        }
    }
}

impl IntoResponse for FederationError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let error_name = self.error_name();
        tracing::error!(error = %self, error_name, "Federation error");
        (
            status,
            Json(json!({ "error": error_name, "message": self.to_string() })),
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
                reason: "y".into()
            }
            .status_code(),
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            FederationError::TransferFailed { reason: "x".into() }.status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
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
            FederationError::AuthFailed { reason: "x".into() }.error_name(),
            "Unauthorized"
        );
        assert_eq!(FederationError::InvalidProof.error_name(), "InvalidProof");
    }
}
