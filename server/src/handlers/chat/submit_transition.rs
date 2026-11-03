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
    if let Some(relayed) =
        try_relay_remote_group_submit_transition(pool, runtime, &admission, body).await?
    {
        return Ok(relayed);
    }
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
                context::routing_failure(ENDPOINT, &err)
            })?;
            crate::federation::group_relay::stage_remote_group_participants(pool, &routes)
                .await
                .map_err(|err| {
                    tracing::warn!(?err, "submitTransition remote participant staging failed");
                    context::remote_member_failure(ENDPOINT, &err)
                })?;
            Some(crate::chat_protocol::federation_routing::ParticipantRoutingIntent::new(routes))
        } else {
            None
        }
    } else {
        None
    };

    let remote_commit = if completed_preflight {
        submit_transition::RemoteCommitPreflightOutcome::NotRemoteOrDeferred
    } else {
        let preflight_kind = admission.mutation_kind();
        submit_transition::preflight_remote_commit(
            pool,
            &admission,
            routing_intent.as_ref(),
            runtime.commit_submitter().map(|s| s.as_ref()),
        )
        .await
        .map_err(|error| submit_failure(preflight_kind, error))?
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

    let (response, post_commit_bytes, group_fanout, local_push) = match mutation_kind {
        SignedMutationKind::LeafRecoveryFulfillment => {
            let (resp, bytes) =
                recovery::execute_prepared(&mut transaction, runtime, ENDPOINT, prepared).await?;
            let (fanout, local_push) =
                prepare_post_commit_work(&mut transaction, runtime, &bytes).await?;
            (resp, None, fanout, local_push)
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
                remote_commit,
            )
            .await
            .map_err(|error| submit_failure(mutation_kind, error))?;
            let bytes = outcome.response_bytes().to_vec();
            let (fanout, local_push) =
                prepare_post_commit_work(&mut transaction, runtime, &bytes).await?;
            let post_commit = matches!(
                mutation_kind,
                SignedMutationKind::CommitTransition
                    | SignedMutationKind::PolicyTransition
                    | SignedMutationKind::LeaveCommitFulfillment
            )
            .then(|| bytes.clone());
            let resp = context::canonical_json_response(ENDPOINT, outcome.status(), bytes)
                .inspect_err(|error| {
                    tracing::error!(
                        ?error,
                        "submitTransition canonical response construction failed"
                    );
                })?;
            (resp, post_commit, fanout, local_push)
        }
        _ => return Err(ChatFailure::invariant(ENDPOINT)),
    };

    transaction.commit().await.map_err(|error| {
        tracing::error!(?error, "submitTransition outer transaction commit failed");
        ChatFailure::storage(ENDPOINT)
    })?;
    if let Some(fanout) = group_fanout {
        runtime.spawn_post_commit_group_entry_fanout(pool, fanout);
    }
    if let Some(wake) = local_push {
        runtime.spawn_post_commit_local_push(pool, wake);
    }
    if let Some(bytes) = post_commit_bytes {
        runtime.spawn_post_commit_membership_transition(pool, &bytes);
    }
    runtime.notify_events();
    Ok(response)
}

/// Capture remote group fan-out and local push audiences before commit.
async fn prepare_post_commit_work(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    runtime: &ChatRuntime,
    bytes: &[u8],
) -> Result<
    (
        Option<crate::federation::group_fanout::PreparedGroupEntryFanout>,
        Option<crate::push_gateway::client::PreparedLocalWake>,
    ),
    ChatFailure,
> {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return Ok((None, None));
    };
    let fanout = crate::federation::group_fanout::prepare_group_entry_fanout(transaction, &value)
        .await
        .map_err(|_| ChatFailure::storage(ENDPOINT))?;
    let local_push = match runtime.push_gateway_client() {
        Some(_) => crate::push_gateway::client::prepare_local_entry_wake(transaction, &value)
            .await
            .map_err(|_| ChatFailure::storage(ENDPOINT))?,
        None => None,
    };
    Ok((fanout, local_push))
}

async fn try_relay_remote_group_submit_transition(
    pool: &DbPool,
    runtime: &ChatRuntime,
    admission: &crate::chat_protocol::repository::auth::SignedOperationAdmission,
    body: &[u8],
) -> Result<Option<Response>, ChatFailure> {
    let kind = admission.mutation_kind();
    if !matches!(
        kind,
        SignedMutationKind::CommitTransition
            | SignedMutationKind::PolicyTransition
            | SignedMutationKind::MetadataTransition
            | SignedMutationKind::LeaveCommitFulfillment
    ) {
        return Ok(None);
    }
    let Some(resolver) = runtime.resolver() else {
        return Ok(None);
    };
    let mailbox_commit =
        kind == SignedMutationKind::CommitTransition && runtime.commit_submitter().is_some();
    crate::federation::group_relay::relay_remote_group_submit_transition(
        pool,
        resolver,
        admission.subject(),
        admission.device_id(),
        mailbox_commit,
        body,
    )
    .await
    .map_err(|error| {
        tracing::warn!(?error, "relayed group submitTransition failed");
        error.into_failure(ENDPOINT)
    })?
    .map(|bytes| context::canonical_json_response(ENDPOINT, 200, bytes))
    .transpose()
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
        // A relationship source that could not answer now decided nothing.
        E::Relationship(R::Unavailable) => ChatFailure::unavailable(ENDPOINT),
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
                crate::federation::FederationError::Database(_) => ChatFailure::storage(ENDPOINT),
                // A closed federation gate, an unreachable sequencer, or its
                // 5xx/429 decided nothing: the same request may be retried.
                error if error.is_retryable() => ChatFailure::unavailable(ENDPOINT),
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
                // This DS's own signer or resolver configuration.
                crate::federation::FederationError::ResolutionFailed {
                    kind: crate::federation::ResolutionFailureKind::InvalidConfiguration(_),
                    ..
                }
                | crate::federation::FederationError::SignerUnavailable
                | crate::federation::FederationError::ConfigError { .. } => {
                    ChatFailure::storage(ENDPOINT)
                }
                // The sequencer cannot be routed (a permanent resolution
                // failure), as a participant home that cannot be routed.
                crate::federation::FederationError::ResolutionFailed { .. }
                | crate::federation::FederationError::EndpointNotFound { .. }
                | crate::federation::FederationError::Unsupported(_) => {
                    ChatFailure::protocol(ENDPOINT, C::NotAuthorized)
                }
                crate::federation::FederationError::RemoteError {
                    status: 400..=499, ..
                } => ChatFailure::protocol(ENDPOINT, C::InvalidRequest),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat_protocol::relationship_policy::RelationshipPolicyConfigError;
    use axum::http::header::RETRY_AFTER;

    /// Status, `Retry-After` presence and declared code of one failure.
    fn wire(error: RelationshipRepositoryError) -> (u16, bool, Option<&'static str>) {
        let failure = submit_failure(
            SignedMutationKind::PolicyTransition,
            SubmitTransitionFacadeError::Relationship(error),
        );
        let response = failure.into_response();
        (
            response.status().as_u16(),
            response.headers().contains_key(RETRY_AFTER),
            failure.code().map(ChatProtocolErrorCode::as_str),
        )
    }

    /// A relationship source that could not answer now decided nothing: 503
    /// with a retry hint. This server's store failing is a 500, a fixed
    /// configuration fault keeps its unhinted code, and unusable evidence
    /// stays the declared refusal.
    #[test]
    fn relationship_failures_keep_outage_store_and_refusal_distinct() {
        use RelationshipRepositoryError as R;
        assert_eq!(
            wire(R::Unavailable),
            (503, true, Some("RelationshipPolicyUnavailable"))
        );
        assert_eq!(
            wire(R::Database(sqlx::Error::PoolTimedOut)),
            (500, false, None)
        );
        assert_eq!(
            wire(R::InvalidAuthorityConfiguration(
                RelationshipPolicyConfigError::InvalidLimit,
            )),
            (503, false, Some("RelationshipPolicyUnavailable"))
        );
        assert_eq!(
            wire(R::InvalidProjection),
            (400, false, Some("BlockedRelationship"))
        );
    }

    /// A transition forwarded to a remote sequencer: an outage is retryable,
    /// this DS's own configuration is a 500, and a sequencer that cannot be
    /// routed or refuses with any 4xx is a declared refusal, never a 503
    /// without a retry hint or an internal error.
    #[test]
    fn forwarded_failures_keep_outage_local_fault_and_refusal_distinct() {
        use crate::federation::{FederationError as F, ResolutionFailureKind as K};
        let wire = |error: F| {
            let failure = submit_failure(
                SignedMutationKind::PolicyTransition,
                SubmitTransitionFacadeError::Federation(error),
            );
            let response = failure.into_response();
            (
                response.status().as_u16(),
                response.headers().contains_key(RETRY_AFTER),
                failure.code().map(ChatProtocolErrorCode::as_str),
            )
        };
        let resolution = |kind| F::ResolutionFailed {
            did: "did:web:seq.example".into(),
            kind,
        };
        assert_eq!(
            wire(resolution(K::DnsTemporary("SERVFAIL".into()))),
            (503, true, Some("RelationshipPolicyUnavailable"))
        );
        assert_eq!(
            wire(resolution(K::ServiceMissing("no #atproto_mls".into()))),
            (401, false, Some("NotAuthorized"))
        );
        assert_eq!(
            wire(F::EndpointNotFound {
                did: "did:web:seq.example".into()
            }),
            (401, false, Some("NotAuthorized"))
        );
        assert_eq!(
            wire(resolution(K::InvalidConfiguration("client".into()))),
            (500, false, None)
        );
        assert_eq!(wire(F::SignerUnavailable), (500, false, None));
        assert_eq!(
            wire(F::RemoteError {
                status: 422,
                body: String::new()
            }),
            (400, false, Some("InvalidRequest"))
        );
        assert_eq!(
            wire(F::RemoteError {
                status: 429,
                body: String::new()
            }),
            (503, true, Some("RelationshipPolicyUnavailable"))
        );
    }
}
