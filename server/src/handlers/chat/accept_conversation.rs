//! XRPC compositor for acceptConversation.

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
            acceptance::{self, AcceptanceFacadeError},
            prelude::PreludeError,
        },
        state_machine::StateMachineError,
    },
    storage::DbPool,
};

use super::{context, errors::ChatFailure, runtime::ChatRuntime};

pub(super) async fn handle(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let endpoint = ChatEndpoint::AcceptConversation;
    handle_inner(&pool, &runtime, endpoint, &headers, &body)
        .await
        .unwrap_or_else(IntoResponse::into_response)
}

async fn handle_inner(
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
    let prepared = crate::chat_protocol::repository::prelude::prepare_signed_operation(
        &mut transaction,
        admission,
    )
    .await
    .map_err(|error| context::operation_prelude_failure(endpoint, error))?;
    let outcome = acceptance::execute_prepared_acceptance(
        &mut transaction,
        prepared,
        runtime.relationship_authority().as_ref(),
    )
    .await
    .map_err(|error| acceptance_failure(endpoint, error))?;
    let response = context::canonical_json_response(
        endpoint,
        outcome.status(),
        outcome.response_bytes().to_vec(),
    )?;
    transaction
        .commit()
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
    Ok(response)
}

fn acceptance_failure(endpoint: ChatEndpoint, error: AcceptanceFacadeError) -> ChatFailure {
    tracing::error!("acceptance_failure: {:?}", error);
    use AcceptanceFacadeError as E;
    use ChatProtocolErrorCode as C;
    use StateMachineError as S;
    match error {
        E::Database(_) => ChatFailure::storage(endpoint),
        E::Prelude(PreludeError::Authorization(error)) => {
            context::auth_repository_failure(endpoint, error)
        }
        E::Prelude(error) => context::operation_prelude_failure(endpoint, error),
        E::Primitive(_) => ChatFailure::protocol(endpoint, C::InvalidSignature),
        E::Conversation(error) => match error {
            crate::chat_protocol::repository::core::ConversationStateHydrationError::Database(_) => {
                ChatFailure::storage(endpoint)
            }
            crate::chat_protocol::repository::core::ConversationStateHydrationError::ReadSetMismatch => {
                ChatFailure::protocol(endpoint, C::StaleCoordinates)
            }
            _ => ChatFailure::protocol(endpoint, C::ConversationNotFound),
        },
        E::RecoveryPackage(error) => match error {
            crate::chat_protocol::repository::core::RecoveryPackageHydrationError::Database(_) => {
                ChatFailure::storage(endpoint)
            }
            crate::chat_protocol::repository::core::RecoveryPackageHydrationError::PackageMissing => {
                ChatFailure::protocol(endpoint, C::KeyPackageUnavailable)
            }
            _ => ChatFailure::invariant(endpoint),
        },
        E::Relationship(_) => ChatFailure::invariant(endpoint),
        E::StateMachine(S::StaleCoordinates) => {
            ChatFailure::protocol(endpoint, C::StaleCoordinates)
        }
        E::StateMachine(S::InvitationNotPending) => {
            ChatFailure::protocol(endpoint, C::InvitationNotPending)
        }
        E::StateMachine(S::NotParticipant) => ChatFailure::protocol(endpoint, C::NotParticipant),
        E::StateMachine(S::InvalidPolicyAuthority) => {
            ChatFailure::protocol(endpoint, C::BlockedRelationship)
        }
        E::StateMachine(S::WorkExpired) => ChatFailure::protocol(endpoint, C::InvitationNotPending),
        E::MissingMutation
        | E::InvalidCanonicalMaterial
        | E::StateMachine(_)
        | E::ExecutionContext(_)
        | E::Executor(_) => ChatFailure::invariant(endpoint),
    }
}
