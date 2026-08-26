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
            core::{
                ConversationHeadHydrationError, ConversationStateHydrationError,
                InvitationQuotaHydrationError, RecoveryPackageHydrationError,
            },
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
    match submit(&pool, &runtime, &headers, &body).await {
        Ok(response) => response,
        Err(failure) => failure.into_response(),
    }
}

async fn submit(
    pool: &DbPool,
    runtime: &ChatRuntime,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Response, ChatFailure> {
    let admission =
        context::admit_signed_operation_only(pool, runtime, ENDPOINT, headers, body).await?;
    let completed_preflight =
        crate::chat_protocol::repository::auth::preflight_completed_response(pool, &admission)
            .await
            .map_err(|e| context::auth_repository_failure(ENDPOINT, e))?
            .is_some();
    // The preflight is advisory only. A hit suppresses the expensive routing
    // lookup, but the canonical operation prelude still owns replay locking,
    // post-state proof, and response release inside the normal transaction.
    let routing_intent = if completed_preflight {
        None
    } else if let Ok(add_principals) = admission.policy_addition_dids() {
        if !add_principals.is_empty() {
            let routes = crate::chat_protocol::federation_routing::resolve_participant_routing(
                pool,
                runtime.resolver().map(|resolver| resolver.as_ref()),
                &add_principals,
            )
            .await
            .map_err(|err| {
                tracing::warn!(
                    ?err,
                    "submitTransition participant routing resolution failed"
                );
                ChatFailure::protocol(ENDPOINT, ChatProtocolErrorCode::NotAuthorized)
            })?;
            Some(crate::chat_protocol::federation_routing::ParticipantRoutingIntent::new(routes))
        } else {
            None
        }
    } else {
        None
    };

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
                routing_intent,
                runtime.commit_submitter().map(|s| s.as_ref()),
            )
            .await
            .map_err(|error| submit_failure(mutation_kind, error))?;
            context::canonical_json_response(
                ENDPOINT,
                outcome.status(),
                outcome.response_bytes().to_vec(),
            )
            .map_err(|error| {
                tracing::error!(
                    ?error,
                    "submitTransition canonical response construction failed"
                );
                error
            })?
        }
        _ => return Err(ChatFailure::invariant(ENDPOINT)),
    };

    transaction.commit().await.map_err(|error| {
        tracing::error!(?error, "submitTransition outer transaction commit failed");
        ChatFailure::storage(ENDPOINT)
    })?;
    Ok(response)
}

fn submit_failure(
    mutation_kind: SignedMutationKind,
    error: SubmitTransitionFacadeError,
) -> ChatFailure {
    tracing::error!(
        "submit_failure: mutation_kind={:?}, error={:?}",
        mutation_kind,
        error
    );
    use ChatProtocolErrorCode as C;
    use ConversationHeadHydrationError as H;
    use ConversationStateHydrationError as CS;
    use ExecutionContextHydrationError as X;
    use InvitationQuotaHydrationError as Q;
    use RecoveryPackageHydrationError as P;
    use RelationshipRepositoryError as R;
    use SubmitTransitionFacadeError as E;
    match error {
        E::Database(_)
        | E::RecoveryPackage(P::Database(_))
        | E::InvitationQuota(Q::Database(_))
        | E::Relationship(R::Database(_))
        | E::ExecutionContext(X::Database(_))
        | E::Conversation(CS::Head(H::Database(_))) => ChatFailure::storage(ENDPOINT),
        E::Prelude(error) => context::operation_prelude_failure(ENDPOINT, error),
        E::Primitive(_) => ChatFailure::protocol(ENDPOINT, C::InvalidSignature),
        E::CandidateScopeDrift => ChatFailure::protocol(ENDPOINT, C::StaleCoordinates),
        E::Conversation(CS::Head(H::ConversationMissing)) => {
            ChatFailure::protocol(ENDPOINT, C::ConversationNotFound)
        }
        E::Conversation(CS::ReadSetMismatch) => {
            ChatFailure::protocol(ENDPOINT, C::StaleCoordinates)
        }
        E::Conversation(CS::TerminalLifecycleUnsupported | CS::ConversationDomain) => {
            ChatFailure::protocol(ENDPOINT, C::InvalidRequest)
        }
        E::Conversation(CS::Metadata(_)) => {
            ChatFailure::protocol(ENDPOINT, C::InvalidMetadataSnapshot)
        }
        E::Conversation(CS::Snapshot(_)) => ChatFailure::protocol(ENDPOINT, C::InvalidCommit),
        E::Conversation(CS::State(s) | CS::Authority(s)) => {
            map_state_machine_error(mutation_kind, s)
        }
        E::Relationship(R::InvalidAuthorityConfiguration(_)) => {
            ChatFailure::protocol(ENDPOINT, C::RelationshipPolicyUnavailable)
        }
        E::Relationship(R::InvalidProjection) => {
            ChatFailure::protocol(ENDPOINT, C::BlockedRelationship)
        }
        E::InvitationQuota(_) => ChatFailure::protocol(ENDPOINT, C::InvitationLimitReached),
        E::RecoveryPackage(_) => ChatFailure::protocol(ENDPOINT, C::LeafRecoveryNotFound),
        E::StateMachine(s) => map_state_machine_error(mutation_kind, s),
        E::MissingMutation | E::UnsupportedMutation | E::InvalidCanonicalMaterial => {
            ChatFailure::protocol(ENDPOINT, C::InvalidRequest)
        }
        E::Federation(fed_error) => {
            tracing::warn!(?fed_error, "submitTransition remote federation error");
            match fed_error {
                crate::federation::FederationError::CommitConflict { .. }
                | crate::federation::FederationError::DeliveryConflict { .. }
                | crate::federation::FederationError::SequenceConflict { .. }
                | crate::federation::FederationError::RemoteError { status: 409, .. } => {
                    ChatFailure::protocol(ENDPOINT, C::StaleCoordinates)
                }
                crate::federation::FederationError::UnauthorizedParticipantDs { .. }
                | crate::federation::FederationError::UnauthorizedRecipient { .. }
                | crate::federation::FederationError::AuthFailed { .. }
                | crate::federation::FederationError::RemoteError {
                    status: 401 | 403, ..
                } => ChatFailure::protocol(ENDPOINT, C::NotAuthorized),
                crate::federation::FederationError::TermStale { .. }
                | crate::federation::FederationError::InvalidCommitFraming { .. }
                | crate::federation::FederationError::InvalidEnvelope { .. }
                | crate::federation::FederationError::RemoteError { status: 400, .. } => {
                    ChatFailure::protocol(ENDPOINT, C::InvalidRequest)
                }
                crate::federation::FederationError::ConversationNotFound { .. }
                | crate::federation::FederationError::RecipientNotFound { .. }
                | crate::federation::FederationError::RemoteError { status: 404, .. } => {
                    ChatFailure::protocol(ENDPOINT, C::ConversationNotFound)
                }
                crate::federation::FederationError::DsUnreachable { .. }
                | crate::federation::FederationError::ResolutionFailed { .. }
                | crate::federation::FederationError::SignerUnavailable
                | crate::federation::FederationError::RemoteError { status: 503, .. } => {
                    ChatFailure::protocol(ENDPOINT, C::RelationshipPolicyUnavailable)
                }
                crate::federation::FederationError::Database(_) => ChatFailure::storage(ENDPOINT),
                _ => ChatFailure::invariant(ENDPOINT),
            }
        }
        E::Conversation(_) | E::ExecutionContext(_) | E::Executor(_) => {
            ChatFailure::invariant(ENDPOINT)
        }
    }
}

fn map_state_machine_error(
    mutation_kind: SignedMutationKind,
    error: StateMachineError,
) -> ChatFailure {
    use ChatProtocolErrorCode as C;
    use StateMachineError as S;

    match error {
        S::StaleCoordinates => ChatFailure::protocol(ENDPOINT, C::StaleCoordinates),
        S::CoordinateOverflow => ChatFailure::protocol(ENDPOINT, C::CoordinateOverflow),
        S::DirectParticipantMutationForbidden => {
            ChatFailure::protocol(ENDPOINT, C::DirectParticipantMutationForbidden)
        }
        S::NotMember | S::NotParticipant => ChatFailure::protocol(ENDPOINT, C::NotMember),
        S::AdminRequired => ChatFailure::protocol(ENDPOINT, C::AdminRequired),
        S::LastAdminRequired => ChatFailure::protocol(ENDPOINT, C::LastAdminRequired),
        S::InvalidWelcomeMapping => ChatFailure::protocol(ENDPOINT, C::InvalidWelcomeMapping),
        S::MetadataVersionOverflow => ChatFailure::protocol(ENDPOINT, C::MetadataVersionOverflow),
        S::InvalidPolicyAuthority => ChatFailure::protocol(ENDPOINT, C::BlockedRelationship),
        S::LeaveRequestNotFound => ChatFailure::protocol(ENDPOINT, C::LeaveRequestNotFound),
        S::LeafRecoveryNotFound => ChatFailure::protocol(ENDPOINT, C::LeafRecoveryNotFound),
        S::LeafRecoveryAlreadyOpen => ChatFailure::protocol(ENDPOINT, C::LeafRecoveryAlreadyOpen),
        S::LeafRecoverySuperseded => ChatFailure::protocol(ENDPOINT, C::LeafRecoverySuperseded),
        S::WorkExpired if mutation_kind == SignedMutationKind::LeaveCommitFulfillment => {
            ChatFailure::protocol(ENDPOINT, C::LeaveRequestExpired)
        }
        S::WorkExpired => ChatFailure::protocol(ENDPOINT, C::LeafRecoveryExpired),
        S::InvalidMetadataAuthority => ChatFailure::protocol(ENDPOINT, C::InvalidMetadataSnapshot),
        S::InvalidTransition | S::InvalidCommitEffects | S::InvalidPublicState
            if mutation_kind == SignedMutationKind::MetadataTransition =>
        {
            ChatFailure::protocol(ENDPOINT, C::InvalidMetadataSnapshot)
        }
        S::InvalidTransition | S::InvalidCommitEffects | S::InvalidPublicState => {
            ChatFailure::protocol(ENDPOINT, C::InvalidCommit)
        }
        S::InvalidIntervalBoundary => ChatFailure::protocol(ENDPOINT, C::InvalidCommit),
        S::ConversationCloseNotAllowed => ChatFailure::protocol(ENDPOINT, C::AdminRequired),
        S::InvalidPrincipal
        | S::InvalidDeviceId
        | S::InvalidCreation
        | S::ExistingConversationConflict
        | S::InvitationNotPending
        | S::RecoveryKindMismatch
        | S::RecoveryDeviceMismatch
        | S::ResetAlreadyPending
        | S::ResetRequestNotFound
        | S::ResetRequestStale
        | S::ResetSuccessorMismatch
        | S::ConversationClosed
        | S::LeaveAlreadyPending
        | S::InvalidServerTime => ChatFailure::protocol(ENDPOINT, C::InvalidRequest),
        S::InvariantViolation | S::InvalidHydrationAuthority => ChatFailure::invariant(ENDPOINT),
    }
}
