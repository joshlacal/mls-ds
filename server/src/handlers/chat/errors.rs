//! The single failure→wire mapper for every clean-chat (`blue.catbird.chat.*`)
//! handler.
//!
//! Every handler failure is funneled through [`ChatFailure`], which owns the
//! only path a protocol error code can reach the wire. A code is admitted only
//! after [`EndpointProtocolError::new`] proves the exact `(endpoint, code)` pair
//! is declared by the frozen Lexicon; any undeclared pair is downgraded to an
//! internal `InvariantViolation` (HTTP 500 with no protocol code and no internal
//! string) and logged as a contract defect (ruling OQ-11). Internal
//! storage/invariant failures never carry a protocol code or a free-form
//! message across the boundary.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use crate::chat_protocol::error::{
    ChatEndpoint, ChatProtocolErrorCode, EndpointProtocolError, ErrorExposure,
};

/// A handler failure bound to the endpoint that produced it. Construct it only
/// through the associated functions so that no code can manufacture an
/// undeclared `(endpoint, code)` pair.
#[derive(Debug, Clone, Copy)]
pub struct ChatFailure {
    endpoint: ChatEndpoint,
    exposure: ErrorExposure,
    retry_after_secs: Option<u64>,
}

impl ChatFailure {
    /// Attempt to expose `code` as `endpoint`'s declared protocol failure. If
    /// the Lexicon does not declare the pair, the failure is downgraded to an
    /// internal invariant violation (never a vocabulary leak) and the defect is
    /// logged for the coordinator (ruling OQ-11).
    pub(crate) fn protocol(endpoint: ChatEndpoint, code: ChatProtocolErrorCode) -> Self {
        Self::protocol_with_retry(endpoint, code, None)
    }

    /// Attempt to expose `code` with an optional retry-after interval in seconds.
    pub(crate) fn protocol_with_retry(
        endpoint: ChatEndpoint,
        code: ChatProtocolErrorCode,
        retry_after_secs: Option<u64>,
    ) -> Self {
        match EndpointProtocolError::new(endpoint, code) {
            Ok(error) => Self {
                endpoint,
                exposure: ErrorExposure::Protocol(error),
                retry_after_secs,
            },
            Err(undeclared) => {
                tracing::error!(
                    endpoint = undeclared.endpoint().nsid(),
                    code = undeclared.code().as_str(),
                    "clean-chat handler produced an undeclared (endpoint, code) pair; \
                     downgrading to InvariantViolation (contract defect, OQ-11)"
                );
                Self {
                    endpoint,
                    exposure: ErrorExposure::InvariantViolation,
                    retry_after_secs: None,
                }
            }
        }
    }

    /// An internal invariant violation: HTTP 500, no protocol code, no internal
    /// detail on the wire.
    pub(crate) fn invariant(endpoint: ChatEndpoint) -> Self {
        Self {
            endpoint,
            exposure: ErrorExposure::InvariantViolation,
            retry_after_secs: None,
        }
    }

    /// An internal storage failure: HTTP 500, no protocol code, no internal
    /// detail on the wire.
    pub(crate) fn storage(endpoint: ChatEndpoint) -> Self {
        Self {
            endpoint,
            exposure: ErrorExposure::StorageFailure,
            retry_after_secs: None,
        }
    }

    pub(crate) fn code(&self) -> Option<ChatProtocolErrorCode> {
        self.exposure.public_code()
    }

    #[cfg(test)]
    pub(crate) fn exposure(self) -> ErrorExposure {
        self.exposure
    }

    #[cfg(test)]
    pub(crate) fn endpoint(self) -> ChatEndpoint {
        self.endpoint
    }
}

impl IntoResponse for ChatFailure {
    fn into_response(self) -> Response {
        match self.exposure {
            ErrorExposure::Protocol(error) => {
                let code = error.code();
                let status = protocol_http_status(code);
                let mut response = (
                    status,
                    Json(json!({
                        "error": code.as_str(),
                        "message": code.as_str(),
                    })),
                )
                    .into_response();
                if let Some(retry_after) = self.retry_after_secs {
                    if let Ok(value) = axum::http::HeaderValue::from_str(&retry_after.to_string()) {
                        response
                            .headers_mut()
                            .insert(axum::http::header::RETRY_AFTER, value);
                    }
                }
                response
            }
            ErrorExposure::StorageFailure | ErrorExposure::InvariantViolation => {
                tracing::error!(
                    endpoint = self.endpoint.nsid(),
                    "clean-chat handler internal failure (no protocol code exposed)"
                );
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "InternalServerError" })),
                )
                    .into_response()
            }
        }
    }
}

/// HTTP status for a declared protocol failure. The wire contract is the error
/// *name* (XRPC clients dispatch on it); the status is a best-effort transport
/// hint. Auth failures surface 401, capacity/relationship-unavailable 429/503,
/// everything else the XRPC default 400.
fn protocol_http_status(code: ChatProtocolErrorCode) -> StatusCode {
    use ChatProtocolErrorCode::{
        AccountSessionExpired, AcknowledgementConflict, AuthenticationGenerationConflict,
        CancellationConflict, ConversationAlreadyExists, DeviceBindingMismatch,
        DeviceNotRegistered, DeviceRevoked, IdempotencyConflict, InvalidSignature,
        LeaveAlreadyPending, NotAuthorized, RateLimited, RelationshipPolicyUnavailable,
        ResetAlreadyPending, StaleCoordinates,
    };
    match code {
        AccountSessionExpired
        | DeviceBindingMismatch
        | InvalidSignature
        | NotAuthorized
        | DeviceRevoked
        | DeviceNotRegistered => StatusCode::UNAUTHORIZED,
        RateLimited => StatusCode::TOO_MANY_REQUESTS,
        RelationshipPolicyUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        AcknowledgementConflict
        | AuthenticationGenerationConflict
        | CancellationConflict
        | ConversationAlreadyExists
        | IdempotencyConflict
        | LeaveAlreadyPending
        | ResetAlreadyPending
        | StaleCoordinates => StatusCode::CONFLICT,
        _ => StatusCode::BAD_REQUEST,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::RETRY_AFTER;

    #[test]
    fn rate_limited_failure_sets_retry_after_header() {
        let failure = ChatFailure::protocol_with_retry(
            ChatEndpoint::SendMessage,
            ChatProtocolErrorCode::RateLimited,
            Some(42),
        );
        let response = failure.into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response
                .headers()
                .get(RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
            Some("42")
        );
    }
}
