//! `blue.catbird.chat.submitTransition` closed-union HTTP compositor.
//!
//! The handler inspects only the verified mutation discriminator. Recovery
//! fulfillment is routed to the stronger Recovery facade; the other four
//! variants use the non-Recovery transition facade. Both return exact canonical
//! bytes and leave the outer commit here.

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
            core::{InvitationQuotaHydrationError, RecoveryPackageHydrationError},
            execution_context::ExecutionContextHydrationError,
            prelude,
            relationship::RelationshipRepositoryError,
            submit_transition::{self, SubmitTransitionFacadeError},
        },
        state_machine::StateMachineError,
        transcript::SignedMutationKind,
    },
    storage::DbPool,
};

use super::{context, errors::ChatFailure, recovery, runtime::ChatRuntime};

const ENDPOINT: ChatEndpoint = ChatEndpoint::SubmitTransition;

pub(super) async fn handle(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    submit(&pool, &runtime, &headers, &body)
        .await
        .unwrap_or_else(IntoResponse::into_response)
}

async fn submit(
    pool: &DbPool,
    runtime: &ChatRuntime,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Response, ChatFailure> {
    let admission =
        context::admit_signed_operation_only(pool, runtime, ENDPOINT, headers, body).await?;
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| ChatFailure::storage(ENDPOINT))?;
    let prepared = prelude::prepare_signed_operation(&mut transaction, admission)
        .await
        .map_err(|error| context::operation_prelude_failure(ENDPOINT, error))?;
    let mutation_kind = prepared
        .mutation_kind()
        .ok_or_else(|| ChatFailure::invariant(ENDPOINT))?;

    let response = match mutation_kind {
        SignedMutationKind::LeafRecoveryFulfillment => {
            recovery::execute_prepared(&mut transaction, runtime, ENDPOINT, prepared).await?
        }
        SignedMutationKind::CommitTransition
        | SignedMutationKind::PolicyTransition
        | SignedMutationKind::MetadataTransition
        | SignedMutationKind::LeaveCommitFulfillment => {
            let outcome = submit_transition::execute_prepared_submit_transition(
                &mut transaction,
                prepared,
                runtime.relationship_authority().as_ref(),
            )
            .await
            .map_err(|error| submit_failure(mutation_kind, error))?;
            context::canonical_json_response(
                ENDPOINT,
                outcome.status(),
                outcome.response_bytes().to_vec(),
            )?
        }
        _ => return Err(ChatFailure::invariant(ENDPOINT)),
    };

    transaction
        .commit()
        .await
        .map_err(|_| ChatFailure::storage(ENDPOINT))?;
    Ok(response)
}

fn submit_failure(
    mutation_kind: SignedMutationKind,
    error: SubmitTransitionFacadeError,
) -> ChatFailure {
    use ChatProtocolErrorCode as C;
    use ExecutionContextHydrationError as X;
    use InvitationQuotaHydrationError as Q;
    use RecoveryPackageHydrationError as P;
    use RelationshipRepositoryError as R;
    use StateMachineError as S;
    use SubmitTransitionFacadeError as E;

    match error {
        E::Database(_)
        | E::RecoveryPackage(P::Database(_))
        | E::InvitationQuota(Q::Database(_))
        | E::Relationship(R::Database(_))
        | E::ExecutionContext(X::Database(_)) => ChatFailure::storage(ENDPOINT),
        E::Prelude(error) => context::operation_prelude_failure(ENDPOINT, error),
        E::Primitive(_) => ChatFailure::protocol(ENDPOINT, C::InvalidSignature),
        E::StateMachine(S::StaleCoordinates) => {
            ChatFailure::protocol(ENDPOINT, C::StaleCoordinates)
        }
        E::StateMachine(S::CoordinateOverflow) => {
            ChatFailure::protocol(ENDPOINT, C::CoordinateOverflow)
        }
        E::StateMachine(S::DirectParticipantMutationForbidden) => {
            ChatFailure::protocol(ENDPOINT, C::DirectParticipantMutationForbidden)
        }
        E::StateMachine(S::NotMember | S::NotParticipant) => {
            ChatFailure::protocol(ENDPOINT, C::NotMember)
        }
        E::StateMachine(S::AdminRequired) => ChatFailure::protocol(ENDPOINT, C::AdminRequired),
        E::StateMachine(S::LastAdminRequired) => {
            ChatFailure::protocol(ENDPOINT, C::LastAdminRequired)
        }
        E::StateMachine(S::InvalidWelcomeMapping) => {
            ChatFailure::protocol(ENDPOINT, C::InvalidWelcomeMapping)
        }
        E::StateMachine(S::MetadataVersionOverflow) => {
            ChatFailure::protocol(ENDPOINT, C::MetadataVersionOverflow)
        }
        E::StateMachine(S::InvalidMetadataAuthority)
            if mutation_kind == SignedMutationKind::MetadataTransition =>
        {
            ChatFailure::protocol(ENDPOINT, C::InvalidMetadataSnapshot)
        }
        E::StateMachine(S::InvalidTransition | S::InvalidCommitEffects | S::InvalidPublicState)
            if mutation_kind == SignedMutationKind::MetadataTransition =>
        {
            ChatFailure::protocol(ENDPOINT, C::InvalidMetadataSnapshot)
        }
        E::StateMachine(S::InvalidTransition | S::InvalidCommitEffects | S::InvalidPublicState) => {
            ChatFailure::protocol(ENDPOINT, C::InvalidCommit)
        }
        E::StateMachine(S::LeaveRequestNotFound) => {
            ChatFailure::protocol(ENDPOINT, C::LeaveRequestNotFound)
        }
        E::StateMachine(S::WorkExpired)
            if mutation_kind == SignedMutationKind::LeaveCommitFulfillment =>
        {
            ChatFailure::protocol(ENDPOINT, C::LeaveRequestExpired)
        }
        E::MissingMutation
        | E::UnsupportedMutation
        | E::InvalidCanonicalMaterial
        | E::CandidateScopeDrift
        | E::StateMachine(_)
        | E::Conversation(_)
        | E::RecoveryPackage(_)
        | E::InvitationQuota(_)
        | E::Relationship(_)
        | E::ExecutionContext(_)
        | E::Executor(_) => ChatFailure::invariant(ENDPOINT),
    }
}
