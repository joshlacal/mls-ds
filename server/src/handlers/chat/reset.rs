//! Shared one-transaction compositor for `requestReset` and `activateReset`.
//!
//! The repository facade owns Reset discovery, canonical entries/events,
//! executor artifacts, apply, and exact response bytes. This layer owns only
//! admission, the caller-owned outer transaction, completion, and commit.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};

use crate::{
    chat_protocol::{
        error::{ChatEndpoint, ChatProtocolErrorCode},
        repository::{
            prelude::{self, PreludeError},
            reset::{self, ResetFacadeError, ResetRepositoryError, ResetTransactionOutcome},
        },
        state_machine::StateMachineError,
    },
    storage::DbPool,
};

use super::{context, errors::ChatFailure, runtime::ChatRuntime};

pub(super) async fn handle_request(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    handle(&pool, &runtime, ChatEndpoint::RequestReset, &headers, &body)
        .await
        .unwrap_or_else(IntoResponse::into_response)
}

pub(super) async fn handle_activation(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    handle(
        &pool,
        &runtime,
        ChatEndpoint::ActivateReset,
        &headers,
        &body,
    )
    .await
    .unwrap_or_else(IntoResponse::into_response)
}

async fn handle(
    pool: &DbPool,
    runtime: &ChatRuntime,
    endpoint: ChatEndpoint,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Response, ChatFailure> {
    let admission =
        context::admit_signed_operation_only(pool, runtime, endpoint, headers, body).await?;
    if let Some(response) =
        context::try_relay_remote_lifecycle(pool, runtime, endpoint, &admission, body).await?
    {
        return Ok(response);
    }
    context::refuse_remote_sequencing(pool, endpoint, &admission).await?;
    execute_admitted(pool, runtime, endpoint, admission, body, None).await
}

pub(super) async fn execute_admitted(
    pool: &DbPool,
    runtime: &ChatRuntime,
    endpoint: ChatEndpoint,
    admission: crate::chat_protocol::repository::auth::SignedOperationAdmission,
    body: &[u8],
    relay_home: Option<&str>,
) -> Result<Response, ChatFailure> {
    let actor = admission.subject().to_owned();
    let completed_preflight =
        crate::chat_protocol::repository::auth::preflight_completed_response(pool, &admission)
            .await
            .map_err(|error| context::auth_repository_failure(endpoint, error))?
            .is_some();

    let conversation_id = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .pointer("/signedRequest/body/prior/conversationId")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| uuid::Uuid::parse_str(value).ok())
        });
    let c33_control_home = match (completed_preflight, conversation_id, relay_home) {
        (false, _, Some(home)) => Some(home.to_owned()),
        (false, Some(conversation_id), None) => {
            crate::federation::group_relay::C33PeerHomes::transition_peer_home(
                pool,
                conversation_id,
                &actor,
            )
            .await
            .map_err(|error| {
                tracing::warn!(?error, "Reset C33 peer resolution failed");
                ChatFailure::storage(endpoint)
            })?
        }
        _ => None,
    };
    if c33_control_home.is_some() && runtime.i13_receipt_signer().is_none() {
        tracing::error!("C33 Reset refused without an I13 receipt signer");
        return Err(ChatFailure::storage(endpoint));
    }
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
    let prepared = prelude::prepare_signed_operation(&mut transaction, admission)
        .await
        .map_err(|error| context::operation_prelude_failure(endpoint, error))?;
    let outcome =
        reset::execute_prepared_reset(&mut transaction, prepared, runtime.i13_receipt_signer())
            .await
            .map_err(|error| reset_failure(endpoint, error))?;

    let (response, response_bytes) = match outcome {
        ResetTransactionOutcome::Replay(completed) => {
            let bytes = completed.response_bytes().to_vec();
            (context::replay_response(endpoint, &completed)?, bytes)
        }
        ResetTransactionOutcome::First(applied) => {
            let event_position = applied.event_position();
            let (_, completion, response) = applied.into_parts();
            let status = response.status();
            let response_bytes = response.as_bytes().to_vec();
            let (authority, scope, completion) = completion.into_parts();
            prelude::complete_operation(
                &mut transaction,
                &authority,
                scope,
                completion,
                status,
                &response_bytes,
                event_position,
            )
            .await
            .map_err(|error| context::operation_prelude_failure(endpoint, error))?;
            if endpoint == ChatEndpoint::ActivateReset {
                if let Some(cid) = conversation_id {
                    crate::chat_protocol::repository::delivery::prune_unblocked_for_conversation_and_notify(
                        &mut transaction,
                        cid,
                        crate::sim_hooks::current_utc(),
                    )
                    .await
                    .map_err(|_| ChatFailure::storage(endpoint))?;
                }
            }
            (
                context::canonical_json_response(endpoint, status, response_bytes.clone())?,
                response_bytes,
            )
        }
    };
    if let Some(home) = c33_control_home.as_deref() {
        crate::federation::group_relay::enqueue_transport_control_response(
            &mut transaction,
            home,
            &response_bytes,
            crate::sim_hooks::current_utc(),
        )
        .await
        .map_err(|error| {
            tracing::error!(?error, "C33 Reset control queueing failed");
            ChatFailure::storage(endpoint)
        })?;
    }
    let response_value =
        serde_json::from_slice(&response_bytes).map_err(|_| ChatFailure::invariant(endpoint))?;
    let group_fanout = crate::federation::group_fanout::prepare_group_entry_fanout(
        &mut transaction,
        &response_value,
    )
    .await
    .map_err(|_| ChatFailure::storage(endpoint))?;

    transaction
        .commit()
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
    if let Some(fanout) = group_fanout {
        runtime.spawn_post_commit_group_entry_fanout(pool, fanout);
    }
    runtime.notify_events();
    Ok(response)
}

fn reset_failure(endpoint: ChatEndpoint, error: ResetFacadeError) -> ChatFailure {
    use ChatProtocolErrorCode as C;
    use ResetFacadeError as E;
    use ResetRepositoryError as R;
    use StateMachineError as S;

    match error {
        E::Database(_) | E::Delivery(_) => ChatFailure::storage(endpoint),
        E::Prelude(error) => prelude_failure(endpoint, error),
        E::Primitive(_) => ChatFailure::protocol(endpoint, C::InvalidSignature),
        E::Repository(R::Database(_)) => ChatFailure::storage(endpoint),
        E::Repository(R::ConversationMissing) => {
            ChatFailure::protocol(endpoint, C::ConversationNotFound)
        }
        E::Repository(R::PendingResetAlreadyExists) if endpoint == ChatEndpoint::RequestReset => {
            ChatFailure::protocol(endpoint, C::ResetAlreadyPending)
        }
        E::Repository(R::PendingResetNotFound) if endpoint == ChatEndpoint::ActivateReset => {
            ChatFailure::protocol(endpoint, C::ResetRequestNotFound)
        }
        E::Repository(
            R::PendingResetTerminal | R::PendingResetExpired | R::PendingResetNotExpired,
        ) if endpoint == ChatEndpoint::ActivateReset => {
            ChatFailure::protocol(endpoint, C::ResetRequestStale)
        }
        E::Repository(R::AdminRequired) => ChatFailure::protocol(endpoint, C::AdminRequired),
        E::Repository(R::PendingResetCoordinateMismatch | R::CompareAndSetConflict) => {
            ChatFailure::protocol(endpoint, C::StaleCoordinates)
        }
        E::StateMachine(S::StaleCoordinates) => {
            ChatFailure::protocol(endpoint, C::StaleCoordinates)
        }
        E::StateMachine(S::CoordinateOverflow) => {
            ChatFailure::protocol(endpoint, C::CoordinateOverflow)
        }
        E::StateMachine(S::NotMember) => ChatFailure::protocol(endpoint, C::NotMember),
        E::StateMachine(S::AdminRequired) if endpoint == ChatEndpoint::RequestReset => {
            ChatFailure::protocol(endpoint, C::NotAuthorized)
        }
        E::StateMachine(S::AdminRequired) => ChatFailure::protocol(endpoint, C::AdminRequired),
        E::StateMachine(S::ResetAlreadyPending) if endpoint == ChatEndpoint::RequestReset => {
            ChatFailure::protocol(endpoint, C::ResetAlreadyPending)
        }
        E::StateMachine(S::ResetRequestNotFound) if endpoint == ChatEndpoint::ActivateReset => {
            ChatFailure::protocol(endpoint, C::ResetRequestNotFound)
        }
        E::StateMachine(S::ResetRequestStale | S::WorkExpired)
            if endpoint == ChatEndpoint::ActivateReset =>
        {
            ChatFailure::protocol(endpoint, C::ResetRequestStale)
        }
        error @ (E::MissingMutation
        | E::UnsupportedMutation
        | E::InvalidCanonicalMaterial
        | E::Repository(_)
        | E::StateMachine(_)
        | E::ExecutionContext(_)
        | E::Executor(_)) => {
            // Never exposed to the caller; the concrete variant is the only
            // evidence an operator has for an unmapped (endpoint, cause) pair.
            tracing::error!(endpoint = endpoint.nsid(), variant = ?error, "reset handler invariant failure");
            ChatFailure::invariant(endpoint)
        }
    }
}

fn prelude_failure(endpoint: ChatEndpoint, error: PreludeError) -> ChatFailure {
    context::operation_prelude_failure(endpoint, error)
}
