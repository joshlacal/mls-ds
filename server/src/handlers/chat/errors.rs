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
pub(crate) struct ChatFailure {
    endpoint: ChatEndpoint,
    exposure: ErrorExposure,
}

impl ChatFailure {
    /// Attempt to expose `code` as `endpoint`'s declared protocol failure. If
    /// the Lexicon does not declare the pair, the failure is downgraded to an
    /// internal invariant violation (never a vocabulary leak) and the defect is
    /// logged for the coordinator (ruling OQ-11).
    pub(crate) fn protocol(endpoint: ChatEndpoint, code: ChatProtocolErrorCode) -> Self {
        match EndpointProtocolError::new(endpoint, code) {
            Ok(error) => Self {
                endpoint,
                exposure: ErrorExposure::Protocol(error),
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
        }
    }

    /// An internal storage failure: HTTP 500, no protocol code, no internal
    /// detail on the wire.
    pub(crate) fn storage(endpoint: ChatEndpoint) -> Self {
        Self {
            endpoint,
            exposure: ErrorExposure::StorageFailure,
        }
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
        match self.exposure.public_error() {
            Some(error) => {
                let code = error.code();
                let status = protocol_http_status(code);
                (
                    status,
                    Json(json!({ "error": code.as_str(), "message": code.as_str() })),
                )
                    .into_response()
            }
            // Internal exposure: never a protocol code, never an internal
            // string. A bare generic transport error name only. The endpoint is
            // logged (never returned) for operability.
            None => {
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
        DeviceNotRegistered, DeviceRevoked, InvalidDPoP, InvalidSignature, NotAuthorized,
        RateLimited, RelationshipPolicyUnavailable,
    };
    match code {
        InvalidDPoP | InvalidSignature | NotAuthorized | DeviceRevoked | DeviceNotRegistered => {
            StatusCode::UNAUTHORIZED
        }
        RateLimited => StatusCode::TOO_MANY_REQUESTS,
        RelationshipPolicyUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::BAD_REQUEST,
    }
}
