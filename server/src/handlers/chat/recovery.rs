//! Client-facing Recovery compositors.
//!
//! Request, cancellation, and the Recovery arm of `submitTransition` all use
//! the same sealed repository facade. This module never plans Recovery,
//! constructs artifacts, or commits from repository code.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use sqlx::{Postgres, Transaction};

use crate::{
    chat_protocol::{
        error::{ChatEndpoint, ChatProtocolErrorCode},
        repository::{
            core::{
                ConversationHeadHydrationError, ConversationStateHydrationError,
                RecoveryPackageHydrationError,
            },
            prelude::{self, PreparedSignedOperation},
            recovery::{self, RecoveryRepositoryError},
            relationship::RelationshipRepositoryError,
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
    handle(
        &pool,
        &runtime,
        ChatEndpoint::RequestLeafRecovery,
        &headers,
        &body,
    )
    .await
    .unwrap_or_else(IntoResponse::into_response)
}

pub(super) async fn handle_cancellation(
    State(pool): State<DbPool>,
    State(runtime): State<Arc<ChatRuntime>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    handle(
        &pool,
        &runtime,
        ChatEndpoint::CancelLeafRecovery,
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
    let response = execute_prepared(&mut transaction, runtime, endpoint, prepared).await?;
    transaction
        .commit()
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
    Ok(response)
}

/// Execute one already-arbitrated Recovery operation inside the caller's outer
/// transaction. The `submitTransition` compositor uses this only for the
/// `LeafRecoveryFulfillment` discriminator.
pub(super) async fn execute_prepared(
    transaction: &mut Transaction<'_, Postgres>,
    runtime: &ChatRuntime,
    endpoint: ChatEndpoint,
    prepared: PreparedSignedOperation,
) -> Result<Response, ChatFailure> {
    let outcome = recovery::execute_prepared_recovery(
        transaction,
        prepared,
        runtime.relationship_authority().as_ref(),
    )
    .await
    .map_err(|error| recovery_failure(endpoint, error))?;
    context::canonical_json_response(
        endpoint,
        outcome.status(),
        outcome.response_bytes().to_vec(),
    )
}

fn recovery_failure(endpoint: ChatEndpoint, error: RecoveryRepositoryError) -> ChatFailure {
    tracing::error!(
        "recovery_failure: endpoint={:?}, error={:?}",
        endpoint,
        error
    );
    use ChatProtocolErrorCode as C;
    use ConversationHeadHydrationError as H;
    use ConversationStateHydrationError as CS;
    use RecoveryPackageHydrationError as P;
    use RecoveryRepositoryError as E;
    use RelationshipRepositoryError as R;

    match error {
        E::Database(_)
        | E::AggregateHydration(CS::Head(H::Database(_)))
        | E::PackageHydration(P::Database(_))
        | E::Relationship(R::Database(_)) => ChatFailure::storage(endpoint),
        E::Prelude(error) => context::operation_prelude_failure(endpoint, error),
        E::ConversationMissing | E::AggregateHydration(CS::Head(H::ConversationMissing)) => {
            ChatFailure::protocol(endpoint, C::ConversationNotFound)
        }
        E::ConversationDrift | E::ReadSetMismatch | E::CompareAndSetConflict => {
            ChatFailure::protocol(endpoint, C::StaleCoordinates)
        }
        E::RecoveryMissing => ChatFailure::protocol(endpoint, C::LeafRecoveryNotFound),
        E::PackageUnavailable => ChatFailure::protocol(endpoint, C::KeyPackageUnavailable),
        E::RelationshipUnavailable | E::Relationship(R::InvalidAuthorityConfiguration(_)) => {
            ChatFailure::protocol(endpoint, C::RelationshipPolicyUnavailable)
        }
        E::Relationship(R::InvalidProjection) => {
            ChatFailure::protocol(endpoint, C::BlockedRelationship)
        }
        E::AggregateHydration(CS::ReadSetMismatch) => {
            ChatFailure::protocol(endpoint, C::StaleCoordinates)
        }
        E::AggregateHydration(CS::TerminalLifecycleUnsupported | CS::ConversationDomain) => {
            ChatFailure::protocol(endpoint, C::InvalidRequest)
        }
        E::AggregateHydration(CS::Metadata(_)) => {
            ChatFailure::protocol(endpoint, C::InvalidMetadataSnapshot)
        }
        E::AggregateHydration(CS::Snapshot(_)) => ChatFailure::protocol(endpoint, C::InvalidCommit),
        E::AggregateHydration(CS::State(s) | CS::Authority(s)) => {
            map_recovery_state_machine_error(endpoint, s)
        }
        E::StateMachine(s) => map_recovery_state_machine_error(endpoint, s),
        E::ForeignTransaction
        | E::UnsupportedAuthority
        | E::AuthorityBindingMismatch
        | E::NonCanonicalOperation
        | E::TrustedInstantMismatch
        | E::InvalidDurableRow
        | E::ActionNotLive
        | E::ExpiryNotDue
        | E::AggregateHydration(_)
        | E::PackageHydration(_)
        | E::ExecutionHydration(_)
        | E::Execution(_) => ChatFailure::invariant(endpoint),
    }
}

fn map_recovery_state_machine_error(
    endpoint: ChatEndpoint,
    error: StateMachineError,
) -> ChatFailure {
    use ChatProtocolErrorCode as C;
    use StateMachineError as S;

    match error {
        S::StaleCoordinates => ChatFailure::protocol(endpoint, C::StaleCoordinates),
        S::CoordinateOverflow => ChatFailure::protocol(endpoint, C::CoordinateOverflow),
        S::DirectParticipantMutationForbidden => {
            ChatFailure::protocol(endpoint, C::DirectParticipantMutationForbidden)
        }
        S::NotParticipant => ChatFailure::protocol(endpoint, C::NotParticipant),
        S::NotMember => ChatFailure::protocol(endpoint, C::NotMember),
        S::AdminRequired => ChatFailure::protocol(endpoint, C::AdminRequired),
        S::LastAdminRequired => ChatFailure::protocol(endpoint, C::LastAdminRequired),
        S::LeafRecoveryAlreadyOpen => ChatFailure::protocol(endpoint, C::LeafRecoveryAlreadyOpen),
        S::LeafRecoveryNotFound => ChatFailure::protocol(endpoint, C::LeafRecoveryNotFound),
        S::LeafRecoverySuperseded => ChatFailure::protocol(endpoint, C::LeafRecoverySuperseded),
        S::WorkExpired => ChatFailure::protocol(endpoint, C::LeafRecoveryExpired),
        S::InvalidWelcomeMapping => ChatFailure::protocol(endpoint, C::InvalidWelcomeMapping),
        S::InvalidPolicyAuthority => ChatFailure::protocol(endpoint, C::BlockedRelationship),
        S::InvalidMetadataAuthority => ChatFailure::protocol(endpoint, C::InvalidMetadataSnapshot),
        S::InvalidTransition | S::InvalidCommitEffects | S::InvalidPublicState => {
            ChatFailure::protocol(endpoint, C::InvalidCommit)
        }
        S::InvalidIntervalBoundary => ChatFailure::protocol(endpoint, C::InvalidCommit),
        S::MetadataVersionOverflow => ChatFailure::protocol(endpoint, C::MetadataVersionOverflow),
        S::LeaveRequestNotFound => ChatFailure::protocol(endpoint, C::LeaveRequestNotFound),
        S::ConversationCloseNotAllowed => ChatFailure::protocol(endpoint, C::AdminRequired),
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
        | S::InvalidServerTime => ChatFailure::protocol(endpoint, C::InvalidRequest),
        S::InvariantViolation | S::InvalidHydrationAuthority => ChatFailure::invariant(endpoint),
    }
}
