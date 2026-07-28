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
            prelude::{self, PreparedSignedOperation},
            recovery::{self, RecoveryRepositoryError},
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
    use ChatProtocolErrorCode as C;
    use RecoveryRepositoryError as E;
    use StateMachineError as S;

    match error {
        E::Database(_) => ChatFailure::storage(endpoint),
        E::Prelude(error) => context::operation_prelude_failure(endpoint, error),
        E::ConversationMissing => ChatFailure::protocol(endpoint, C::ConversationNotFound),
        E::RecoveryMissing => ChatFailure::protocol(endpoint, C::LeafRecoveryNotFound),
        E::PackageUnavailable => ChatFailure::protocol(endpoint, C::KeyPackageUnavailable),
        E::RelationshipUnavailable => {
            ChatFailure::protocol(endpoint, C::RelationshipPolicyUnavailable)
        }
        E::StateMachine(S::StaleCoordinates) => {
            ChatFailure::protocol(endpoint, C::StaleCoordinates)
        }
        E::StateMachine(S::NotParticipant) => ChatFailure::protocol(endpoint, C::NotParticipant),
        E::StateMachine(S::LeafRecoveryAlreadyOpen) => {
            ChatFailure::protocol(endpoint, C::LeafRecoveryAlreadyOpen)
        }
        E::StateMachine(S::LeafRecoveryNotFound) => {
            ChatFailure::protocol(endpoint, C::LeafRecoveryNotFound)
        }
        E::StateMachine(S::LeafRecoverySuperseded) => {
            ChatFailure::protocol(endpoint, C::LeafRecoverySuperseded)
        }
        E::StateMachine(S::WorkExpired) => ChatFailure::protocol(endpoint, C::LeafRecoveryExpired),
        E::StateMachine(S::InvalidWelcomeMapping) => {
            ChatFailure::protocol(endpoint, C::InvalidWelcomeMapping)
        }
        E::ForeignTransaction
        | E::UnsupportedAuthority
        | E::AuthorityBindingMismatch
        | E::NonCanonicalOperation
        | E::TrustedInstantMismatch
        | E::ConversationDrift
        | E::ReadSetMismatch
        | E::InvalidDurableRow
        | E::ActionNotLive
        | E::ExpiryNotDue
        | E::CompareAndSetConflict
        | E::AggregateHydration(_)
        | E::PackageHydration(_)
        | E::Relationship(_)
        | E::StateMachine(_)
        | E::ExecutionHydration(_)
        | E::Execution(_) => ChatFailure::invariant(endpoint),
    }
}
