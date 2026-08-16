//! XRPC compositor for createConversation.

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
            creation::{self, CreationFacadeError},
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
    let endpoint = ChatEndpoint::CreateConversation;
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
    let outcome = creation::execute_prepared_creation(
        &mut transaction,
        prepared,
        runtime.relationship_authority().as_ref(),
    )
    .await
    .map_err(|error| creation_failure(endpoint, error))?;
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

fn creation_failure(endpoint: ChatEndpoint, error: CreationFacadeError) -> ChatFailure {
    use ChatProtocolErrorCode as C;
    use CreationFacadeError as E;
    use StateMachineError as S;

    match error {
        E::Database(_) => ChatFailure::storage(endpoint),
        E::Prelude(PreludeError::Authorization(error)) => {
            context::auth_repository_failure(endpoint, error)
        }
        E::Prelude(error) => context::operation_prelude_failure(endpoint, error),
        E::Primitive(_) => ChatFailure::protocol(endpoint, C::InvalidSignature),
        E::CreationHead(error) => match error {
            crate::chat_protocol::repository::core::CreationHeadHydrationError::ConversationExists => {
                ChatFailure::protocol(endpoint, C::ConversationAlreadyExists)
            }
            crate::chat_protocol::repository::core::CreationHeadHydrationError::Database(_) => {
                ChatFailure::storage(endpoint)
            }
            _ => ChatFailure::invariant(endpoint),
        },
        E::StateMachine(S::ExistingConversationConflict) => {
            ChatFailure::protocol(endpoint, C::ConversationAlreadyExists)
        }
        E::InvitationQuota(error) => match error {
            crate::chat_protocol::repository::core::InvitationQuotaHydrationError::Database(_) => {
                ChatFailure::storage(endpoint)
            }
            _ => ChatFailure::protocol(endpoint, C::InvitationLimitReached),
        },
        E::Relationship(error) => match error {
            crate::chat_protocol::repository::relationship::RelationshipRepositoryError::Database(_) => {
                ChatFailure::storage(endpoint)
            }
            _ => ChatFailure::invariant(endpoint),
        },
        E::StateMachine(S::InvalidPolicyAuthority) => {
            ChatFailure::protocol(endpoint, C::BlockedRelationship)
        }
        E::StateMachine(S::InvalidMetadataAuthority) => {
            ChatFailure::protocol(endpoint, C::InvalidMetadataSnapshot)
        }
        E::StateMachine(S::CoordinateOverflow) => {
            ChatFailure::protocol(endpoint, C::UnsupportedMlsProfile)
        }
        E::StateMachine(S::InvalidPublicState) => {
            ChatFailure::protocol(endpoint, C::InvalidGenesisGroupInfo)
        }
        E::StateMachine(S::DirectParticipantMutationForbidden) => {
            ChatFailure::protocol(endpoint, C::InvalidRequest)
        }
        E::DirectLookup(error) => match error {
            crate::chat_protocol::repository::core::DirectConversationLookupError::Database(_) => {
                ChatFailure::storage(endpoint)
            }
            _ => ChatFailure::invariant(endpoint),
        },
        E::StateMachine(_) => {
            ChatFailure::invariant(endpoint)
        }
        E::MissingMutation
        | E::InvalidCanonicalMaterial
        | E::ExecutionContext(_)
        | E::Executor(_) => ChatFailure::invariant(endpoint),
    }
}
