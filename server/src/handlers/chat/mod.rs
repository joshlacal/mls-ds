//! Clean-cutover chat HTTP handler layer (`blue.catbird.chat.*`).

use std::sync::Arc;

use axum::{
    extract::{DefaultBodyLimit, FromRef, State},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};

use crate::chat_protocol::error::ChatEndpoint;
use crate::chat_protocol::validation::ValidatedChatNsid;
use crate::storage::DbPool;

mod accept_conversation;
mod acknowledge_entries;
mod context;
mod conversation_state;
mod create_conversation;
mod device_views;
mod direct_requests;
mod enroll_device;
mod errors;
mod expiry_worker;
mod get_device_key;
mod get_devices;
mod get_entries;
mod get_own_devices;
mod inventory;
mod leave;
mod publish_direct_request;
mod publish_typing;
mod recovery;
mod recovery_scheduler;
mod replenish_key_packages;
pub(crate) mod request_push;
mod reset;
mod revoke_device;
mod runtime;
mod send_message;
mod submit_transition;
mod subscribe_events;
mod subscription;
mod welcome;

pub use errors::ChatFailure;
pub use expiry_worker::{run_chat_expiry_sweeper, ChatExpirySweepConfig};
#[cfg(feature = "test-support")]
pub use runtime::install_test_https_relationship_resolver;
pub use runtime::ChatRuntime;
pub use subscribe_events::{parse_query as parse_subscribe_events_query, SubscribeEventsQuery};

#[cfg(any(test, feature = "test-support"))]
pub(crate) async fn admit_signed_operation_for_test(
    pool: &DbPool,
    runtime: &ChatRuntime,
    endpoint: ChatEndpoint,
    headers: &axum::http::HeaderMap,
    body: &[u8],
) -> Result<crate::chat_protocol::repository::auth::SignedOperationAdmission, ChatFailure> {
    context::admit_signed_operation_only(pool, runtime, endpoint, headers, body).await
}

/// Build the isolated `blue.catbird.chat.*` router.
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
    router
        .merge(implemented_routes::<S>())
        .layer(axum::middleware::from_fn(attach_canonical_query_header))
}

async fn attach_canonical_query_header(
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    req.headers_mut()
        .remove(crate::chat_protocol::read_auth::INTERNAL_CANONICAL_QUERY_HEADER);
    let canonical = crate::chat_protocol::read_auth::canonical_query(req.uri().query());
    if let Ok(value) = axum::http::HeaderValue::from_str(&canonical) {
        req.headers_mut().insert(
            crate::chat_protocol::read_auth::INTERNAL_CANONICAL_QUERY_HEADER,
            value,
        );
    }
    next.run(req).await
}

/// Whether `endpoint` has a real handler in this slice.
fn is_implemented(endpoint: ChatEndpoint) -> bool {
    matches!(
        endpoint,
        ChatEndpoint::PublishDirectRequestKeys
            | ChatEndpoint::PublishDirectRequest
            | ChatEndpoint::PrepareDirectRequest
            | ChatEndpoint::GetDirectRequestOutcome
            | ChatEndpoint::CancelDirectRequestPreparation
            | ChatEndpoint::EnrollDevice
            | ChatEndpoint::ReplenishKeyPackages
            | ChatEndpoint::GetDeviceKey
            | ChatEndpoint::GetDevices
            | ChatEndpoint::GetOwnDevices
            | ChatEndpoint::RequestLeave
            | ChatEndpoint::CancelLeave
            | ChatEndpoint::CloseConversation
            | ChatEndpoint::SendMessage
            | ChatEndpoint::PublishTyping
            | ChatEndpoint::CreateConversation
            | ChatEndpoint::AcceptConversation
            | ChatEndpoint::AcknowledgeEntries
            | ChatEndpoint::GetConversations
            | ChatEndpoint::GetPendingWelcomes
            | ChatEndpoint::GetLeafRecoveryInbox
            | ChatEndpoint::GetSubscriptionTicket
            | ChatEndpoint::SubscribeEvents
            | ChatEndpoint::GetConversationState
            | ChatEndpoint::RequestReset
            | ChatEndpoint::ActivateReset
            | ChatEndpoint::RevokeDevice
            | ChatEndpoint::AcknowledgeWelcome
            | ChatEndpoint::RejectWelcome
            | ChatEndpoint::RequestLeafRecovery
            | ChatEndpoint::CancelLeafRecovery
            | ChatEndpoint::SubmitTransition
            | ChatEndpoint::GetEntries
    )
}

/// Register every real clean-chat handler in this slice.
fn implemented_routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    DbPool: FromRef<S>,
    Arc<ChatRuntime>: FromRef<S>,
{
    Router::new()
        .route(
            &xrpc_path(ChatEndpoint::PublishDirectRequestKeys),
            post(direct_requests::publish_keys).layer(DefaultBodyLimit::max(16_777_216)),
        )
        .route(
            &xrpc_path(ChatEndpoint::PublishDirectRequest),
            post(publish_direct_request::handle).layer(DefaultBodyLimit::max(16_777_216)),
        )
        .route(
            &xrpc_path(ChatEndpoint::PrepareDirectRequest),
            post(direct_requests::prepare).layer(DefaultBodyLimit::max(65_536)),
        )
        .route(
            &xrpc_path(ChatEndpoint::CancelDirectRequestPreparation),
            post(direct_requests::cancel).layer(DefaultBodyLimit::max(65_536)),
        )
        .route(
            &xrpc_path(ChatEndpoint::GetDirectRequestOutcome),
            get(direct_requests::outcome),
        )
        .route(
            &xrpc_path(ChatEndpoint::EnrollDevice),
            post(enroll_device::handle),
        )
        .route(
            &xrpc_path(ChatEndpoint::ReplenishKeyPackages),
            post(replenish_key_packages::handle),
        )
        .route(
            &xrpc_path(ChatEndpoint::GetDeviceKey),
            get(get_device_key::handle),
        )
        .route(
            &xrpc_path(ChatEndpoint::GetDevices),
            get(get_devices::handle),
        )
        .route(
            &xrpc_path(ChatEndpoint::GetOwnDevices),
            get(get_own_devices::handle),
        )
        .route(
            &xrpc_path(ChatEndpoint::CreateConversation),
            post(create_conversation::handle).layer(DefaultBodyLimit::max(15_728_640)),
        )
        .route(
            &xrpc_path(ChatEndpoint::GetConversationState),
            get(conversation_state::handle),
        )
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
            post(submit_transition::handle).layer(DefaultBodyLimit::max(15_728_640)),
        )
        .route(
            &xrpc_path(ChatEndpoint::GetEntries),
            get(get_entries::handle),
        )
        .route(
            &xrpc_path(ChatEndpoint::AcknowledgeEntries),
            post(acknowledge_entries::handle).layer(DefaultBodyLimit::max(65_536)),
        )
        .route(
            &xrpc_path(ChatEndpoint::RequestLeave),
            post(leave::handle_request),
        )
        .route(
            &xrpc_path(ChatEndpoint::CancelLeave),
            post(leave::handle_cancellation),
        )
        .route(
            &xrpc_path(ChatEndpoint::CloseConversation),
            post(leave::handle_close),
        )
        .route(
            &xrpc_path(ChatEndpoint::SendMessage),
            post(send_message::handle).layer(DefaultBodyLimit::max(15_728_640)),
        )
        .route(
            &xrpc_path(ChatEndpoint::PublishTyping),
            post(publish_typing::handle),
        )
        .route(
            &xrpc_path(ChatEndpoint::AcceptConversation),
            post(accept_conversation::handle),
        )
        .route(
            &xrpc_path(ChatEndpoint::GetConversations),
            get(inventory::conversations),
        )
        .route(
            &xrpc_path(ChatEndpoint::GetPendingWelcomes),
            get(inventory::welcomes),
        )
        .route(
            &xrpc_path(ChatEndpoint::GetLeafRecoveryInbox),
            get(inventory::recovery),
        )
        .route(
            &xrpc_path(ChatEndpoint::GetSubscriptionTicket),
            post(subscription::handle),
        )
        .route(
            &xrpc_path(ChatEndpoint::SubscribeEvents),
            get(subscribe_events::handle),
        )
        .route(
            "/internal/chat/request-push-eligibility",
            post(request_push::eligibility).layer(DefaultBodyLimit::max(
                crate::chat_protocol::request_push::MAX_INTERNAL_BODY_BYTES,
            )),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.reserveRecipientBootstrap",
            post(crate::handlers::ds::direct_requests::reserve_recipient_bootstrap)
                .layer(DefaultBodyLimit::max(65_536)),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.releaseRecipientBootstrap",
            post(crate::handlers::ds::direct_requests::release_recipient_bootstrap)
                .layer(DefaultBodyLimit::max(65_536)),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.prepareDirectRequest",
            post(crate::handlers::ds::direct_requests::prepare_direct_request)
                .layer(DefaultBodyLimit::max(65_536)),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.publishDirectRequest",
            post(crate::handlers::ds::direct_requests::publish_direct_request)
                .layer(DefaultBodyLimit::max(16_777_216)),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.deliverDirectRequest",
            post(crate::handlers::ds::direct_requests::deliver_direct_request)
                .layer(DefaultBodyLimit::max(16_777_216)),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.deliverAcceptance",
            post(crate::handlers::ds::direct_requests::deliver_acceptance)
                .layer(DefaultBodyLimit::max(65_536)),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.deliverAcceptanceEntry",
            post(crate::handlers::ds::direct_requests::deliver_acceptance_entry)
                .layer(DefaultBodyLimit::max(65_536)),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.relaySendMessage",
            post(crate::handlers::ds::direct_requests::relay_send_message)
                .layer(DefaultBodyLimit::max(15_728_640)),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.deliverMessageEntry",
            post(crate::handlers::ds::direct_requests::deliver_message_entry)
                .layer(DefaultBodyLimit::max(15_728_640)),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.getDirectRequestOutcome",
            get(crate::handlers::ds::direct_requests::get_direct_request_outcome),
        )
}

fn xrpc_path(endpoint: ChatEndpoint) -> String {
    format!("/xrpc/{}", endpoint.nsid())
}

fn uses_http_get(endpoint: ChatEndpoint) -> bool {
    match ValidatedChatNsid::parse(endpoint.nsid()) {
        Ok(nsid) => match nsid.dpop_method() {
            Ok(method) => method.as_str() == "GET",
            Err(_) => true,
        },
        Err(_) => false,
    }
}

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

    #[test]
    fn failure_mapper_never_emits_undeclared_code() {
        for &endpoint in ChatEndpoint::ALL {
            for &code in ChatProtocolErrorCode::ALL {
                let declared = endpoint.declares(code);
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

    #[test]
    fn every_endpoint_has_a_route_method() {
        for &endpoint in ChatEndpoint::ALL {
            let path = xrpc_path(endpoint);
            assert!(path.starts_with("/xrpc/blue.catbird.chat."));
            let _ = uses_http_get(endpoint);
        }
    }
}

#[cfg(all(
    feature = "chat-protocol-production-proof",
    not(feature = "server-bin")
))]
pub(crate) fn production_proof_signed_operation_failure(
    error: crate::chat_protocol::repository::prelude::PreludeError,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    context::operation_prelude_failure(
        crate::chat_protocol::error::ChatEndpoint::SubmitTransition,
        error,
    )
    .into_response()
}
