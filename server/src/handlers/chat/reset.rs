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
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
    let prepared = prelude::prepare_signed_operation(&mut transaction, admission)
        .await
        .map_err(|error| context::operation_prelude_failure(endpoint, error))?;
    let outcome = reset::execute_prepared_reset(&mut transaction, prepared)
        .await
        .map_err(|error| reset_failure(endpoint, error))?;

    let response = match outcome {
        ResetTransactionOutcome::Replay(completed) => context::replay_response(&completed),
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
            context::canonical_json_response(endpoint, status, response_bytes)?
        }
    };

    transaction
        .commit()
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
    Ok(response)
}

fn reset_failure(endpoint: ChatEndpoint, error: ResetFacadeError) -> ChatFailure {
    use ChatProtocolErrorCode as C;
    use ResetFacadeError as E;
    use ResetRepositoryError as R;
    use StateMachineError as S;

    match error {
        E::Database(_) => ChatFailure::storage(endpoint),
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
        E::MissingMutation
        | E::UnsupportedMutation
        | E::InvalidCanonicalMaterial
        | E::Repository(_)
        | E::StateMachine(_)
        | E::ExecutionContext(_)
        | E::Executor(_) => ChatFailure::invariant(endpoint),
    }
}

fn prelude_failure(endpoint: ChatEndpoint, error: PreludeError) -> ChatFailure {
    context::operation_prelude_failure(endpoint, error)
}
