//! HTTP compositors for requestLeave, cancelLeave, and closeConversation.
//! Authentication and DPoP admission remain in `context`; this module owns
//! only the caller transaction and endpoint-specific error mapping.

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
            leave::{self, LeaveFacadeError},
            prelude,
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
    execute(&pool, &runtime, ChatEndpoint::RequestLeave, &headers, &body)
        .await
        .unwrap_or_else(IntoResponse::into_response)
}

pub(super) async fn handle_cancellation(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    execute(&pool, &runtime, ChatEndpoint::CancelLeave, &headers, &body)
        .await
        .unwrap_or_else(IntoResponse::into_response)
}

pub(super) async fn handle_close(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    execute(
        &pool,
        &runtime,
        ChatEndpoint::CloseConversation,
        &headers,
        &body,
    )
    .await
    .unwrap_or_else(IntoResponse::into_response)
}

async fn execute(
    pool: &DbPool,
    runtime: &ChatRuntime,
    endpoint: ChatEndpoint,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Response, ChatFailure> {
    let admission =
        context::admit_signed_operation_only(pool, runtime, endpoint, headers, body).await?;
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
    let prepared = prelude::prepare_signed_operation(&mut tx, admission)
        .await
        .map_err(|error| context::operation_prelude_failure(endpoint, error))?;
    let outcome = leave::execute_prepared_leave(&mut tx, prepared)
        .await
        .map_err(|error| map_failure(endpoint, error))?;
    let response =
        context::canonical_json_response(endpoint, outcome.status, outcome.response_bytes.clone())?;
    if let Some(completion) = outcome.completion {
        let (authority, scope, guard) = completion.into_parts();
        prelude::complete_operation(
            &mut tx,
            &authority,
            scope,
            guard,
            outcome.status,
            &outcome.response_bytes,
            outcome.event_position,
        )
        .await
        .map_err(|error| context::operation_prelude_failure(endpoint, error))?;
    }
    tx.commit()
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
    Ok(response)
}

fn map_failure(endpoint: ChatEndpoint, error: LeaveFacadeError) -> ChatFailure {
    use ChatProtocolErrorCode as C;
    use LeaveFacadeError as E;
    use StateMachineError as S;
    match error {
        E::Database(_) | E::Authorization(_) => ChatFailure::storage(endpoint),
        E::Prelude(error) => context::operation_prelude_failure(endpoint, error),
        E::Conversation(error) => match error {
            crate::chat_protocol::repository::core::ConversationStateHydrationError::Database(_) => {
                ChatFailure::storage(endpoint)
            }
            crate::chat_protocol::repository::core::ConversationStateHydrationError::ReadSetMismatch => {
                ChatFailure::protocol(endpoint, C::StaleCoordinates)
            }
            _ => ChatFailure::protocol(endpoint, C::ConversationNotFound),
        },
        E::Transition(crate::chat_protocol::repository::transition::TransitionRepositoryError::Database(_))
        | E::ExecutionContext(crate::chat_protocol::repository::execution_context::ExecutionContextHydrationError::Database(_))
        | E::Executor(crate::chat_protocol::state_machine::ExecutorError::Transition(crate::chat_protocol::repository::transition::TransitionRepositoryError::Database(_))) => ChatFailure::storage(endpoint),
        E::Transition(crate::chat_protocol::repository::transition::TransitionRepositoryError::CompareAndSetConflict)
        | E::Executor(crate::chat_protocol::state_machine::ExecutorError::Transition(crate::chat_protocol::repository::transition::TransitionRepositoryError::CompareAndSetConflict))
        | E::StateMachine(S::StaleCoordinates) => ChatFailure::protocol(endpoint, C::StaleCoordinates),
        E::StateMachine(S::CoordinateOverflow) => ChatFailure::protocol(endpoint, C::CoordinateOverflow),
        E::StateMachine(S::DirectParticipantMutationForbidden) => ChatFailure::protocol(endpoint, C::DirectParticipantMutationForbidden),
        E::StateMachine(S::LastAdminRequired) => ChatFailure::protocol(endpoint, C::LastAdminRequired),
        E::StateMachine(S::NotMember) => {
            if endpoint == ChatEndpoint::RequestLeave { ChatFailure::protocol(endpoint, C::NotMember) }
            else { ChatFailure::protocol(endpoint, C::NotAuthorized) }
        }
        E::StateMachine(S::NotParticipant) => {
            if endpoint == ChatEndpoint::CloseConversation { ChatFailure::protocol(endpoint, C::NotParticipant) }
            else { ChatFailure::protocol(endpoint, C::NotAuthorized) }
        }
        E::StateMachine(S::ConversationCloseNotAllowed) => ChatFailure::protocol(endpoint, C::ConversationCloseNotAllowed),
        E::StateMachine(S::LeaveAlreadyPending) => ChatFailure::protocol(endpoint, C::LeaveAlreadyPending),
        E::StateMachine(S::LeaveRequestNotFound) => ChatFailure::protocol(endpoint, C::LeaveRequestNotFound),
        E::StateMachine(S::WorkExpired) => {
            if endpoint == ChatEndpoint::CancelLeave { ChatFailure::protocol(endpoint, C::CancellationConflict) }
            else { ChatFailure::protocol(endpoint, C::LeaveRequestExpired) }
        }
        E::MissingMutation | E::UnsupportedMutation | E::InvalidCanonicalMaterial
        | E::ExecutionContext(_) | E::Transition(_) | E::Executor(_) | E::StateMachine(_) => ChatFailure::invariant(endpoint),
    }
}
