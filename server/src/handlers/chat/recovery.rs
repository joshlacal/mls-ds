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
    if let Some(response) =
        context::try_relay_remote_lifecycle(pool, runtime, endpoint, &admission, body).await?
    {
        return Ok(response);
    }
    context::refuse_remote_sequencing(pool, endpoint, &admission).await?;
    execute_admitted(pool, runtime, endpoint, admission, None).await
}

pub(super) async fn execute_admitted(
    pool: &DbPool,
    runtime: &ChatRuntime,
    endpoint: ChatEndpoint,
    admission: crate::chat_protocol::repository::auth::SignedOperationAdmission,
    _relay_home: Option<&str>,
) -> Result<Response, ChatFailure> {
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
    let prepared = prelude::prepare_signed_operation(&mut transaction, admission)
        .await
        .map_err(|error| context::operation_prelude_failure(endpoint, error))?;
    let (response, _) = execute_prepared(&mut transaction, runtime, endpoint, prepared).await?;
    transaction
        .commit()
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
    runtime.notify_events();
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
) -> Result<(Response, Vec<u8>), ChatFailure> {
    let outcome = recovery::execute_prepared_recovery(
        transaction,
        prepared,
        runtime.relationship_authority().as_ref(),
        runtime.i13_receipt_signer(),
    )
    .await
    .map_err(|error| recovery_failure(endpoint, error))?;
    let bytes = outcome.response_bytes().to_vec();
    let resp = context::canonical_json_response(endpoint, outcome.status(), bytes.clone())?;
    Ok((resp, bytes))
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
        E::PackageUnavailable | E::PackageHydration(P::PackageMissing) => {
            ChatFailure::protocol(endpoint, C::KeyPackageUnavailable)
        }
        // A relationship source that could not answer now decided nothing.
        E::RelationshipUnavailable | E::Relationship(R::Unavailable) => {
            ChatFailure::unavailable(endpoint)
        }
        E::Relationship(R::InvalidAuthorityConfiguration(_)) => {
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
        S::InvalidTransition
        | S::InvalidCommitEffects
        | S::InvalidPublicState
        | S::InvalidIntervalBoundary => ChatFailure::protocol(
            endpoint,
            if endpoint == ChatEndpoint::SubmitTransition {
                C::InvalidCommit
            } else {
                C::InvalidRequest
            },
        ),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat_protocol::relationship_policy::RelationshipPolicyConfigError;
    use axum::http::header::RETRY_AFTER;

    /// Status, `Retry-After` presence and declared code of one failure.
    fn wire(
        endpoint: ChatEndpoint,
        error: RecoveryRepositoryError,
    ) -> (u16, bool, Option<&'static str>) {
        let failure = recovery_failure(endpoint, error);
        let response = failure.into_response();
        (
            response.status().as_u16(),
            response.headers().contains_key(RETRY_AFTER),
            failure.code().map(ChatProtocolErrorCode::as_str),
        )
    }

    /// Requesting and fulfilling recovery: a relationship source that could
    /// not answer now decided nothing (503 with a retry hint); this server's
    /// store failing is a 500; a fixed configuration fault keeps its unhinted
    /// code; unusable evidence stays the declared refusal.
    #[test]
    fn relationship_failures_keep_outage_store_and_refusal_distinct() {
        use RecoveryRepositoryError as E;
        use RelationshipRepositoryError as R;
        for endpoint in [
            ChatEndpoint::RequestLeafRecovery,
            ChatEndpoint::SubmitTransition,
        ] {
            let outage = (503, true, Some("RelationshipPolicyUnavailable"));
            assert_eq!(wire(endpoint, E::Relationship(R::Unavailable)), outage);
            assert_eq!(wire(endpoint, E::RelationshipUnavailable), outage);
            let store = E::Relationship(R::Database(sqlx::Error::PoolTimedOut));
            assert_eq!(wire(endpoint, store), (500, false, None));
            let configuration = E::Relationship(R::InvalidAuthorityConfiguration(
                RelationshipPolicyConfigError::InvalidLimit,
            ));
            assert_eq!(
                wire(endpoint, configuration),
                (503, false, Some("RelationshipPolicyUnavailable"))
            );
            assert_eq!(
                wire(endpoint, E::Relationship(R::InvalidProjection)),
                (400, false, Some("BlockedRelationship"))
            );
        }
    }

    #[test]
    fn recovery_state_machine_and_package_missing_errors_use_endpoint_declared_codes() {
        use RecoveryPackageHydrationError as P;
        use RecoveryRepositoryError as E;
        use StateMachineError as S;

        assert_eq!(
            wire(
                ChatEndpoint::RequestLeafRecovery,
                E::StateMachine(S::InvalidTransition),
            ),
            (400, false, Some("InvalidRequest"))
        );
        assert_eq!(
            wire(
                ChatEndpoint::CancelLeafRecovery,
                E::StateMachine(S::InvalidTransition),
            ),
            (400, false, Some("InvalidRequest"))
        );
        assert_eq!(
            wire(
                ChatEndpoint::SubmitTransition,
                E::StateMachine(S::InvalidTransition),
            ),
            (400, false, Some("InvalidCommit"))
        );
        let unavailable = wire(ChatEndpoint::RequestLeafRecovery, E::PackageUnavailable);
        assert_eq!(unavailable.2, Some("KeyPackageUnavailable"));
        assert_eq!(
            wire(
                ChatEndpoint::RequestLeafRecovery,
                E::PackageHydration(P::PackageMissing),
            ),
            unavailable
        );
    }
}
