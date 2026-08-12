//! Clean-cutover chat HTTP handler layer (`blue.catbird.chat.*`).
//!
//! This is the v2 handler tree, isolated from the superseded
//! `handlers/mls_chat/` namespace. It exposes the certified
//! `chat_protocol` repository/executor spine over XRPC. All 32 chat routes are
//! registered up front by [`chat_router`]. Device lifecycle plus the sealed
//! Reset, G6, Welcome, and Recovery mutation compositors have real routes;
//! every remaining endpoint stays on the shared cutover-gated stub.

use std::sync::Arc;

use axum::{
    extract::{FromRef, State},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};

use crate::chat_protocol::error::ChatEndpoint;
use crate::chat_protocol::validation::ValidatedChatNsid;
use crate::storage::DbPool;

mod context;
mod device_views;
mod enroll_device;
mod errors;
#[cfg(not(test))]
mod expiry_worker;
mod get_devices;
mod get_own_devices;
mod rebind_device_authentication;
#[cfg(not(test))]
mod recovery;
#[cfg(not(test))]
mod recovery_scheduler;
mod replenish_key_packages;
#[cfg(not(test))]
mod reset;
#[cfg(not(test))]
mod revoke_device;
mod runtime;
#[cfg(not(test))]
mod submit_transition;
#[cfg(not(test))]
mod welcome;

use errors::ChatFailure;
#[cfg(not(test))]
pub use expiry_worker::{run_chat_expiry_sweeper, ChatExpirySweepConfig};
pub use runtime::ChatRuntime;

/// Build the isolated `blue.catbird.chat.*` router. Generic over the
/// application state so it can be assembled in the binary crate where
/// `AppState` lives, as long as that state can hand out a [`DbPool`] and the
/// shared [`ChatRuntime`]. Every one of the 32 chat NSIDs is registered so
/// routing and per-route body limits are exercised from the first slice; slices
/// fill in real handler bodies over time.
pub fn chat_router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    DbPool: FromRef<S>,
    Arc<ChatRuntime>: FromRef<S>,
{
    let mut router = Router::new();
    for &endpoint in ChatEndpoint::ALL {
        if is_implemented(endpoint) {
            continue;
        }
        let path = xrpc_path(endpoint);
        let handler = move |State(runtime): State<Arc<ChatRuntime>>| async move {
            not_implemented(endpoint, &runtime)
        };
        router = if uses_http_get(endpoint) {
            router.route(&path, get(handler))
        } else {
            router.route(&path, post(handler))
        };
    }
    router.merge(implemented_routes::<S>())
}

/// Whether `endpoint` has a real handler in this slice.
fn is_implemented(endpoint: ChatEndpoint) -> bool {
    if matches!(
        endpoint,
        ChatEndpoint::EnrollDevice
            | ChatEndpoint::ReplenishKeyPackages
            | ChatEndpoint::RebindDeviceAuthentication
            | ChatEndpoint::GetDevices
            | ChatEndpoint::GetOwnDevices
    ) {
        return true;
    }
    #[cfg(not(test))]
    {
        matches!(
            endpoint,
            ChatEndpoint::RequestReset
                | ChatEndpoint::ActivateReset
                | ChatEndpoint::RevokeDevice
                | ChatEndpoint::AcknowledgeWelcome
                | ChatEndpoint::RejectWelcome
                | ChatEndpoint::RequestLeafRecovery
                | ChatEndpoint::CancelLeafRecovery
                | ChatEndpoint::SubmitTransition
        )
    }
    #[cfg(test)]
    {
        false
    }
}

/// Register every real clean-chat handler in this slice.
fn implemented_routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    DbPool: FromRef<S>,
    Arc<ChatRuntime>: FromRef<S>,
{
    let router = Router::new()
        .route(
            &xrpc_path(ChatEndpoint::EnrollDevice),
            post(enroll_device::handle),
        )
        .route(
            &xrpc_path(ChatEndpoint::ReplenishKeyPackages),
            post(replenish_key_packages::handle),
        )
        .route(
            &xrpc_path(ChatEndpoint::RebindDeviceAuthentication),
            post(rebind_device_authentication::handle),
        )
        .route(
            &xrpc_path(ChatEndpoint::GetDevices),
            get(get_devices::handle),
        )
        .route(
            &xrpc_path(ChatEndpoint::GetOwnDevices),
            get(get_own_devices::handle),
        );
    #[cfg(not(test))]
    let router = router
        .route(
            &xrpc_path(ChatEndpoint::RequestReset),
            post(reset::handle_request),
        )
        .route(
            &xrpc_path(ChatEndpoint::ActivateReset),
            post(reset::handle_activation),
        )
        .route(
            &xrpc_path(ChatEndpoint::RevokeDevice),
            post(revoke_device::handle),
        )
        .route(
            &xrpc_path(ChatEndpoint::AcknowledgeWelcome),
            post(welcome::handle_acknowledgement),
        )
        .route(
            &xrpc_path(ChatEndpoint::RejectWelcome),
            post(welcome::handle_rejection),
        )
        .route(
            &xrpc_path(ChatEndpoint::RequestLeafRecovery),
            post(recovery::handle_request),
        )
        .route(
            &xrpc_path(ChatEndpoint::CancelLeafRecovery),
            post(recovery::handle_cancellation),
        )
        .route(
            &xrpc_path(ChatEndpoint::SubmitTransition),
            post(submit_transition::handle),
        );
    router
}

fn xrpc_path(endpoint: ChatEndpoint) -> String {
    format!("/xrpc/{}", endpoint.nsid())
}

/// Whether the endpoint is served over HTTP GET. Sourced from the authoritative
/// `ValidatedChatNsid::dpop_method` classification; `subscribeEvents` (which has
/// no DPoP method because it is a ticket-only WebSocket upgrade) is served over
/// GET.
fn uses_http_get(endpoint: ChatEndpoint) -> bool {
    match ValidatedChatNsid::parse(endpoint.nsid()) {
        Ok(nsid) => match nsid.dpop_method() {
            Ok(method) => method.as_str() == "GET",
            Err(_) => true,
        },
        Err(_) => false,
    }
}

/// The shared not-implemented stub for every route without a real handler yet.
///
/// It is cutover-gated: while the clean protocol is not active (the default,
/// operative state) it returns the declared `CutoverRequired` code — a valid
/// wire outcome for every one of the 32 endpoints. Once cutover is enabled, a
/// still-unimplemented route is an internal invariant violation (HTTP 500, no
/// protocol code, no invented vocabulary). This is how `revokeDevice` and the
/// H2–H7 routes stub without ever inventing a "not implemented" code.
fn not_implemented(endpoint: ChatEndpoint, runtime: &ChatRuntime) -> Response {
    match context::require_cutover(runtime, endpoint) {
        Err(failure) => failure.into_response(),
        Ok(()) => ChatFailure::invariant(endpoint).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat_protocol::error::{
        ChatProtocolErrorCode, EndpointProtocolError, ErrorExposure,
    };

    /// Exhaustiveness property (build-time gate, ruling OQ-11 + risk R1): for
    /// every `(endpoint, code)` pair the failure mapper admits the code only
    /// when the Lexicon declares it, and downgrades every undeclared pair to an
    /// internal invariant violation — never a vocabulary leak.
    #[test]
    fn failure_mapper_never_emits_undeclared_code() {
        for &endpoint in ChatEndpoint::ALL {
            for &code in ChatProtocolErrorCode::ALL {
                let declared = endpoint.declares(code);
                // The guarded constructor must agree with the Lexicon.
                assert_eq!(
                    EndpointProtocolError::new(endpoint, code).is_ok(),
                    declared,
                    "declaration disagreement for {}::{}",
                    endpoint.nsid(),
                    code.as_str()
                );
                let failure = ChatFailure::protocol(endpoint, code);
                assert_eq!(failure.endpoint(), endpoint);
                match failure.exposure() {
                    ErrorExposure::Protocol(error) => {
                        assert!(
                            declared,
                            "undeclared {}::{} escaped as a protocol code",
                            endpoint.nsid(),
                            code.as_str()
                        );
                        assert_eq!(error.code(), code);
                        assert_eq!(error.endpoint(), endpoint);
                    }
                    ErrorExposure::InvariantViolation => {
                        assert!(
                            !declared,
                            "declared {}::{} was wrongly downgraded",
                            endpoint.nsid(),
                            code.as_str()
                        );
                    }
                    ErrorExposure::StorageFailure => {
                        panic!("protocol() must never produce a storage exposure");
                    }
                }
            }
        }
    }

    /// Every chat endpoint must map to a registrable route method.
    #[test]
    fn every_endpoint_has_a_route_method() {
        for &endpoint in ChatEndpoint::ALL {
            let path = xrpc_path(endpoint);
            assert!(path.starts_with("/xrpc/blue.catbird.chat."));
            // Exercises the GET/POST classification without panicking.
            let _ = uses_http_get(endpoint);
        }
    }
}
