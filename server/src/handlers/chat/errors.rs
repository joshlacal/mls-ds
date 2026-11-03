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
    status: Option<StatusCode>,
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
                status: None,
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
                    status: None,
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
            status: None,
        }
    }

    /// Carry an upstream authority's HTTP status as the transport hint of a
    /// declared protocol failure; the declared error name is unchanged.
    pub(crate) fn with_status(mut self, status: StatusCode) -> Self {
        self.status = Some(status);
        self
    }

    /// An internal storage failure: HTTP 500, no protocol code, no internal
    /// detail on the wire.
    pub(crate) fn storage(endpoint: ChatEndpoint) -> Self {
        Self {
            endpoint,
            exposure: ErrorExposure::StorageFailure,
            retry_after_secs: None,
            status: None,
        }
    }

    /// A source the endpoint depends on could not answer now: a closed
    /// federation gate, or a peer or resolver that was unreachable or answered
    /// 5xx/429. That decided nothing, so it is the endpoint's declared
    /// retryable code (`RelationshipPolicyUnavailable`, else
    /// `CapacityUnavailable`) with a 5 s retry; an endpoint declaring neither
    /// answers 503 with the same retry and no protocol code.
    pub(crate) fn unavailable(endpoint: ChatEndpoint) -> Self {
        use ChatProtocolErrorCode::{CapacityUnavailable, RelationshipPolicyUnavailable};
        match [RelationshipPolicyUnavailable, CapacityUnavailable]
            .into_iter()
            .find(|code| endpoint.declares(*code))
        {
            Some(code) => Self::protocol_with_retry(endpoint, code, Some(5)),
            None => Self {
                retry_after_secs: Some(5),
                status: Some(StatusCode::SERVICE_UNAVAILABLE),
                ..Self::storage(endpoint)
            },
        }
    }

    pub(crate) fn code(&self) -> Option<ChatProtocolErrorCode> {
        self.exposure.public_code()
    }

    /// Decided nothing: a retry-hinted protocol failure or a storage failure.
    /// The caller may keep retry-safe state for the identical retry.
    pub(crate) fn is_transient(&self) -> bool {
        self.retry_after_secs.is_some() || matches!(self.exposure, ErrorExposure::StorageFailure)
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
        let mut response = match self.exposure {
            ErrorExposure::Protocol(error) => {
                let code = error.code();
                let status = self.status.unwrap_or_else(|| protocol_http_status(code));
                (
                    status,
                    Json(json!({
                        "error": code.as_str(),
                        "message": code.as_str(),
                    })),
                )
                    .into_response()
            }
            ErrorExposure::StorageFailure | ErrorExposure::InvariantViolation => {
                tracing::error!(
                    endpoint = self.endpoint.nsid(),
                    "clean-chat handler internal failure (no protocol code exposed)"
                );
                (
                    self.status.unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                    Json(json!({ "error": "InternalServerError" })),
                )
                    .into_response()
            }
        };
        if let Some(retry_after) = self.retry_after_secs {
            if let Ok(value) = axum::http::HeaderValue::from_str(&retry_after.to_string()) {
                response
                    .headers_mut()
                    .insert(axum::http::header::RETRY_AFTER, value);
            }
        }
        response
    }
}

/// HTTP status for a declared protocol failure. The wire contract is the error
/// *name* (XRPC clients dispatch on it); the status is a best-effort transport
/// hint. Auth failures surface 401, rate limits 429, a capacity or relationship
/// source that is unavailable now 503, everything else the XRPC default 400.
fn protocol_http_status(code: ChatProtocolErrorCode) -> StatusCode {
    use ChatProtocolErrorCode::{
        AccountSessionExpired, CapacityUnavailable, DeviceBindingMismatch, DeviceNotRegistered,
        DeviceRevoked, InvalidSignature, NotAuthorized, RateLimited, RelationshipPolicyUnavailable,
    };
    match code {
        AccountSessionExpired
        | DeviceBindingMismatch
        | InvalidSignature
        | NotAuthorized
        | DeviceRevoked
        | DeviceNotRegistered => StatusCode::UNAUTHORIZED,
        RateLimited => StatusCode::TOO_MANY_REQUESTS,
        RelationshipPolicyUnavailable | CapacityUnavailable => StatusCode::SERVICE_UNAVAILABLE,
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

    /// Every endpoint answers a source that could not answer now with 503 and
    /// `Retry-After: 5`: its declared retryable code, else no protocol code.
    #[tokio::test]
    async fn unavailable_is_503_with_retry_after_on_every_endpoint() {
        for (endpoint, error) in [
            (
                ChatEndpoint::SubmitTransition,
                "RelationshipPolicyUnavailable",
            ),
            (ChatEndpoint::PublishDirectRequest, "CapacityUnavailable"),
            (ChatEndpoint::GetConversationState, "InternalServerError"),
        ] {
            let failure = ChatFailure::unavailable(endpoint);
            assert!(failure.is_transient(), "{endpoint:?}");
            let response = failure.into_response();
            assert_eq!(
                response.status(),
                StatusCode::SERVICE_UNAVAILABLE,
                "{endpoint:?}"
            );
            assert_eq!(
                response
                    .headers()
                    .get(RETRY_AFTER)
                    .and_then(|v| v.to_str().ok()),
                Some("5"),
                "{endpoint:?}"
            );
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body["error"], error, "{endpoint:?}");
        }
        // This DS's own store failing is not a retry hint.
        let response = ChatFailure::storage(ChatEndpoint::GetConversationState).into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(response.headers().get(RETRY_AFTER).is_none());
    }
}
