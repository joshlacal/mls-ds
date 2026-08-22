// Transaction-bound facade for Welcome acknowledgement/rejection.
//
// Lock order is inherited from the shared business prelude: operation,
// identity scope, conversation aggregate, exact Welcome delivery. No handler
// bytes or post-head identity lookup crosses this boundary.

use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use thiserror::Error;
use uuid::Uuid;

use super::prelude::release_signed_operation_replay;
use super::{
    auth::CompletedIdempotentResponse,
    core::{
        hydrate_locked_conversation_state, lock_welcome_terminal, ConversationStateHydrationError,
        LockedConversationStateGuard, LockedWelcomeTerminal, WelcomeLockError,
    },
    execution_context::{
        apply_prepared_welcome_terminal_execution, prepare_welcome_terminal_execution,
        ExecutionContextHydrationError,
    },
    prelude::{
        complete_operation, lock_signed_operation_replay_authority, prepare_actor_prelude,
        LockedSignedOperationReplayAuthority, OperationCompletionGuard, PreludeError,
        PreparedSignedOperation, PreparedSignedOperationState, ScopeBoundBusinessAuthority,
        WelcomeOperationEndpoint,
    },
};
use crate::chat_protocol::{
    dpop::VerifiedChatDeviceRequest,
    snapshot::PublicGroupSnapshotCoordinate,
    state_machine::{
        AppliedTransition, ConversationPersistencePlan, DurableSignedRequestEnvelope,
        ExecutorError, HydrationAuthority, StateMachineError, WelcomeTerminalPlan,
    },
    transcript::{
        decode_and_verify_signed_mutation, CanonicalValueRef, SignedMutationKind,
        VerifiedMutationProjection, VerifiedSignedMutation,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WelcomeEndpoint {
    Acknowledge,
    Reject,
}

impl WelcomeEndpoint {
    fn endpoint_nsid(self) -> &'static str {
        match self {
            Self::Acknowledge => "blue.catbird.chat.acknowledgeWelcome",
            Self::Reject => "blue.catbird.chat.rejectWelcome",
        }
    }

    fn mutation_kind(self) -> SignedMutationKind {
        match self {
            Self::Acknowledge => SignedMutationKind::WelcomeAcknowledgement,
            Self::Reject => SignedMutationKind::WelcomeRejection,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WelcomeTerminalClass {
    PendingNotDue,
    PendingDue,
    Acknowledged,
    Rejected,
    Expired,
    SupersededByTransition,
    SupersededByRevocation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WelcomeTerminalDecision {
    PrepareAcknowledgement,
    PrepareRejection,
    PrepareExpiry,
    ExactAcknowledgementReplay,
    ExactRejectionReplay,
    AcknowledgementConflict,
    RejectionConflict,
    WelcomeExpired,
    SupersededByTransition,
    SupersededByRevocation,
}

pub(crate) fn classify_welcome_terminal(
    endpoint: WelcomeEndpoint,
    classification: WelcomeTerminalClass,
    exact_replay: bool,
) -> WelcomeTerminalDecision {
    match classification {
        WelcomeTerminalClass::PendingNotDue => match endpoint {
            WelcomeEndpoint::Acknowledge => WelcomeTerminalDecision::PrepareAcknowledgement,
            WelcomeEndpoint::Reject => WelcomeTerminalDecision::PrepareRejection,
        },
        WelcomeTerminalClass::PendingDue => WelcomeTerminalDecision::PrepareExpiry,
        WelcomeTerminalClass::Acknowledged
            if endpoint == WelcomeEndpoint::Acknowledge && exact_replay =>
        {
            WelcomeTerminalDecision::ExactAcknowledgementReplay
        }
        WelcomeTerminalClass::Rejected if endpoint == WelcomeEndpoint::Reject && exact_replay => {
            WelcomeTerminalDecision::ExactRejectionReplay
        }
        WelcomeTerminalClass::Acknowledged => WelcomeTerminalDecision::AcknowledgementConflict,
        WelcomeTerminalClass::Rejected => WelcomeTerminalDecision::RejectionConflict,
        WelcomeTerminalClass::Expired => WelcomeTerminalDecision::WelcomeExpired,
        WelcomeTerminalClass::SupersededByTransition => {
            WelcomeTerminalDecision::SupersededByTransition
        }
        WelcomeTerminalClass::SupersededByRevocation => {
            WelcomeTerminalDecision::SupersededByRevocation
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum WelcomeCanonicalMaterial {
    Acknowledged {
        welcome_id: Uuid,
        terminal_at: DateTime<Utc>,
    },
    Rejected {
        welcome_id: Uuid,
        terminal_at: DateTime<Utc>,
    },
    ExactReplay {
        welcome_id: Uuid,
        terminal: WelcomeTerminalClass,
        terminal_at: DateTime<Utc>,
    },
    Conflict {
        welcome_id: Uuid,
        terminal: WelcomeTerminalClass,
    },
    WelcomeExpired {
        welcome_id: Uuid,
        expired_at: DateTime<Utc>,
    },
    WelcomeSuperseded {
        welcome_id: Uuid,
        cause: WelcomeSupersessionCause,
    },
    WelcomeNotFound {
        welcome_id: Uuid,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum WelcomeSupersessionCause {
    Transition(Uuid),
    DeviceRevocation(Uuid),
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct WelcomeCanonicalResponse {
    status: i32,
    bytes: Box<[u8]>,
    sha256: [u8; 32],
}

impl WelcomeCanonicalResponse {
    pub(crate) fn status(&self) -> i32 {
        self.status
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
}

/// Private-constructor proof that a completed Welcome replay was checked
/// against one exact locked aggregate + Welcome terminal row before stored
/// response bytes became observable.
pub(in crate::chat_protocol::repository) struct WelcomeReplayPostStateProof {
    transaction_id: String,
    operation_id: Uuid,
    principal_did: String,
    endpoint_nsid: &'static str,
    mutation_kind: SignedMutationKind,
    request_digest: [u8; 32],
    accepted_request_sha256: [u8; 32],
    signature: [u8; 64],
    conversation_id: Uuid,
    welcome_id: Uuid,
    terminal_classification: Option<WelcomeTerminalClass>,
    terminal_at: Option<DateTime<Utc>>,
    locked_terminal_digest: [u8; 32],
    expected_status: i32,
    expected_response_sha256: [u8; 32],
    seal: [u8; 32],
}

impl WelcomeReplayPostStateProof {
    #[allow(clippy::too_many_arguments)]
    fn from_locked_facts(
        transaction_id: String,
        operation_id: Uuid,
        principal_did: String,
        endpoint_nsid: &'static str,
        mutation_kind: SignedMutationKind,
        request_digest: [u8; 32],
        accepted_request_sha256: [u8; 32],
        signature: [u8; 64],
        conversation_id: Uuid,
        welcome_id: Uuid,
        terminal_classification: Option<WelcomeTerminalClass>,
        terminal_at: Option<DateTime<Utc>>,
        locked_terminal_digest: [u8; 32],
        expected_status: i32,
        expected_response_sha256: [u8; 32],
    ) -> Result<Self, WelcomeTerminalFacadeError> {
        if transaction_id.is_empty()
            || principal_did.is_empty()
            || !matches!(
                (
                    endpoint_nsid,
                    mutation_kind,
                    terminal_classification,
                    terminal_at
                ),
                (
                    "blue.catbird.chat.acknowledgeWelcome",
                    SignedMutationKind::WelcomeAcknowledgement,
                    None,
                    None
                ) | (
                    "blue.catbird.chat.rejectWelcome",
                    SignedMutationKind::WelcomeRejection,
                    None,
                    None
                ) | (
                    "blue.catbird.chat.acknowledgeWelcome",
                    SignedMutationKind::WelcomeAcknowledgement,
                    Some(
                        WelcomeTerminalClass::Acknowledged
                            | WelcomeTerminalClass::Rejected
                            | WelcomeTerminalClass::Expired
                            | WelcomeTerminalClass::SupersededByTransition
                            | WelcomeTerminalClass::SupersededByRevocation
                    ),
                    Some(_)
                ) | (
                    "blue.catbird.chat.rejectWelcome",
                    SignedMutationKind::WelcomeRejection,
                    Some(
                        WelcomeTerminalClass::Acknowledged
                            | WelcomeTerminalClass::Rejected
                            | WelcomeTerminalClass::Expired
                            | WelcomeTerminalClass::SupersededByTransition
                            | WelcomeTerminalClass::SupersededByRevocation
                    ),
                    Some(_)
                )
            )
            || request_digest == [0; 32]
            || accepted_request_sha256 == [0; 32]
            || signature == [0; 64]
            || locked_terminal_digest == [0; 32]
            || !(200..=599).contains(&expected_status)
            || expected_response_sha256 == [0; 32]
        {
            return Err(WelcomeTerminalFacadeError::ReplayPostState);
        }
        let mut proof = Self {
            transaction_id,
            operation_id,
            principal_did,
            endpoint_nsid,
            mutation_kind,
            request_digest,
            accepted_request_sha256,
            signature,
            conversation_id,
            welcome_id,
            terminal_classification,
            terminal_at,
            locked_terminal_digest,
            expected_status,
            expected_response_sha256,
            seal: [0; 32],
        };
        proof.seal = welcome_replay_post_state_seal(&proof);
        Ok(proof)
    }

    pub(in crate::chat_protocol::repository) fn transaction_id(&self) -> &str {
        &self.transaction_id
    }

    pub(in crate::chat_protocol::repository) fn operation_id(&self) -> Uuid {
        self.operation_id
    }

    pub(in crate::chat_protocol::repository) fn principal_did(&self) -> &str {
        &self.principal_did
    }

    pub(in crate::chat_protocol::repository) fn endpoint_nsid(&self) -> &str {
        self.endpoint_nsid
    }

    pub(in crate::chat_protocol::repository) fn mutation_kind(&self) -> SignedMutationKind {
        self.mutation_kind
    }

    pub(in crate::chat_protocol::repository) fn request_digest(&self) -> &[u8; 32] {
        &self.request_digest
    }

    pub(in crate::chat_protocol::repository) fn accepted_request_sha256(&self) -> &[u8; 32] {
        &self.accepted_request_sha256
    }

    pub(in crate::chat_protocol::repository) fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    pub(in crate::chat_protocol::repository) fn conversation_id(&self) -> Uuid {
        self.conversation_id
    }

    pub(in crate::chat_protocol::repository) fn welcome_id(&self) -> Uuid {
        self.welcome_id
    }

    pub(in crate::chat_protocol::repository) fn terminal_classification(
        &self,
    ) -> Option<WelcomeTerminalClass> {
        self.terminal_classification
    }

    pub(in crate::chat_protocol::repository) fn terminal_at(&self) -> Option<DateTime<Utc>> {
        self.terminal_at
    }

    pub(in crate::chat_protocol::repository) fn locked_terminal_digest(&self) -> &[u8; 32] {
        &self.locked_terminal_digest
    }

    pub(in crate::chat_protocol::repository) fn post_state_digest(&self) -> &[u8; 32] {
        &self.locked_terminal_digest
    }

    pub(in crate::chat_protocol::repository) fn expected_status(&self) -> i32 {
        self.expected_status
    }

    pub(in crate::chat_protocol::repository) fn expected_response_sha256(&self) -> &[u8; 32] {
        &self.expected_response_sha256
    }

    pub(in crate::chat_protocol::repository) fn validates_seal(&self) -> bool {
        self.seal == welcome_replay_post_state_seal(self)
    }
}

fn welcome_replay_post_state_seal(proof: &WelcomeReplayPostStateProof) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-WELCOME-REPLAY-POST-STATE\0");
    digest_len(&mut digest, proof.transaction_id.as_bytes());
    digest.update(proof.operation_id.as_bytes());
    digest_len(&mut digest, proof.principal_did.as_bytes());
    digest_len(&mut digest, proof.endpoint_nsid.as_bytes());
    digest_len(&mut digest, proof.mutation_kind.type_id().as_bytes());
    digest.update(proof.request_digest);
    digest.update(proof.accepted_request_sha256);
    digest.update(proof.signature);
    digest.update(proof.conversation_id.as_bytes());
    digest.update(proof.welcome_id.as_bytes());
    digest.update([match proof.terminal_classification {
        None => 0,
        Some(WelcomeTerminalClass::PendingNotDue) => 1,
        Some(WelcomeTerminalClass::PendingDue) => 2,
        Some(WelcomeTerminalClass::Acknowledged) => 3,
        Some(WelcomeTerminalClass::Rejected) => 4,
        Some(WelcomeTerminalClass::Expired) => 5,
        Some(WelcomeTerminalClass::SupersededByTransition) => 6,
        Some(WelcomeTerminalClass::SupersededByRevocation) => 7,
    }]);
    digest.update(
        proof
            .terminal_at
            .map_or(i64::MIN, |value| value.timestamp_millis())
            .to_be_bytes(),
    );
    digest.update(proof.locked_terminal_digest);
    digest.update(proof.expected_status.to_be_bytes());
    digest.update(proof.expected_response_sha256);
    digest.finalize().into()
}

fn digest_len(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

pub(crate) struct WelcomeCompletion {
    authority: VerifiedChatDeviceRequest,
    scope_authority: ScopeBoundBusinessAuthority,
    completion: OperationCompletionGuard,
    expected_status: i32,
    expected_response_sha256: [u8; 32],
}

impl WelcomeCompletion {
    fn new(
        authority: VerifiedChatDeviceRequest,
        scope_authority: ScopeBoundBusinessAuthority,
        completion: OperationCompletionGuard,
        response: &WelcomeCanonicalResponse,
    ) -> Self {
        Self {
            authority,
            scope_authority,
            completion,
            expected_status: response.status(),
            expected_response_sha256: *response.sha256(),
        }
    }

    pub(crate) async fn complete(
        self,
        transaction: &mut Transaction<'_, Postgres>,
        response: &WelcomeCanonicalResponse,
        event_position: Option<i64>,
    ) -> Result<(), WelcomeTerminalFacadeError> {
        if response.status() != self.expected_status
            || response.sha256() != &self.expected_response_sha256
            || &<[u8; 32]>::from(Sha256::digest(response.as_bytes())) != response.sha256()
        {
            return Err(WelcomeTerminalFacadeError::ReplayPostState);
        }
        complete_operation(
            transaction,
            &self.authority,
            self.scope_authority,
            self.completion,
            response.status(),
            response.as_bytes(),
            event_position,
        )
        .await?;
        Ok(())
    }
}

pub(crate) struct PreparedWelcomeMutation {
    plan: ConversationPersistencePlan,
    completion: WelcomeCompletion,
    material: WelcomeCanonicalMaterial,
    response: WelcomeCanonicalResponse,
}

impl PreparedWelcomeMutation {
    pub(crate) fn material(&self) -> &WelcomeCanonicalMaterial {
        &self.material
    }

    pub(crate) fn response(&self) -> &WelcomeCanonicalResponse {
        &self.response
    }

    pub(crate) async fn apply(
        self,
        transaction: &mut Transaction<'_, Postgres>,
    ) -> Result<AppliedWelcomeMutation, WelcomeTerminalFacadeError> {
        let Self {
            plan,
            completion,
            material,
            response,
        } = self;
        let prepared = prepare_welcome_terminal_execution(transaction, &plan).await?;
        let applied = apply_prepared_welcome_terminal_execution(prepared).await?;
        Ok(AppliedWelcomeMutation {
            applied,
            completion,
            material,
            response,
        })
    }
}

pub(crate) struct AppliedWelcomeMutation {
    pub(crate) applied: AppliedTransition,
    pub(crate) completion: WelcomeCompletion,
    pub(crate) material: WelcomeCanonicalMaterial,
    pub(crate) response: WelcomeCanonicalResponse,
}

pub(crate) enum WelcomeTerminalTransactionOutcome {
    Prepared(PreparedWelcomeMutation),
    Classified {
        completion: WelcomeCompletion,
        material: WelcomeCanonicalMaterial,
        response: WelcomeCanonicalResponse,
    },
    Replay {
        response: CompletedIdempotentResponse,
        material: WelcomeCanonicalMaterial,
    },
}

#[derive(Debug, Error)]
pub(crate) enum WelcomeTerminalFacadeError {
    #[error("Welcome request body is out of domain")]
    InvalidRequest,
    #[error("completed Welcome operation disagrees with the locked terminal state")]
    ReplayPostState,
    #[error("Welcome operation claim is invalid: {0}")]
    Prelude(#[from] PreludeError),
    #[error("Welcome aggregate hydration failed: {0}")]
    Aggregate(#[from] ConversationStateHydrationError),
    #[error("Welcome lock failed: {0}")]
    WelcomeLock(#[from] WelcomeLockError),
    #[error("Welcome planning failed: {0}")]
    StateMachine(#[from] StateMachineError),
    #[error("Welcome execution hydration failed: {0}")]
    ExecutionHydration(#[from] ExecutionContextHydrationError),
    #[error("Welcome execution failed: {0:?}")]
    Execution(ExecutorError),
}

impl From<ExecutorError> for WelcomeTerminalFacadeError {
    fn from(value: ExecutorError) -> Self {
        Self::Execution(value)
    }
}


pub(crate) async fn prepare_welcome_terminal(
    transaction: &mut Transaction<'_, Postgres>,
    operation: PreparedSignedOperation,
) -> Result<WelcomeTerminalTransactionOutcome, WelcomeTerminalFacadeError> {
    match operation.into_state() {
        PreparedSignedOperationState::First {
            authority,
            reservation,
        } => prepare_first_welcome_terminal(transaction, authority, reservation).await,
        PreparedSignedOperationState::Replay { authority, replay } => {
            let replay =
                lock_signed_operation_replay_authority(transaction, authority, replay).await?;
            prepare_completed_welcome_replay(transaction, replay).await
        }
    }
}

async fn prepare_first_welcome_terminal(
    transaction: &mut Transaction<'_, Postgres>,
    authority: VerifiedChatDeviceRequest,
    reservation: super::prelude::OperationReservationGuard,
) -> Result<WelcomeTerminalTransactionOutcome, WelcomeTerminalFacadeError> {
    let trusted_instant = authority.trusted_instant();
    let admitted = authority
        .mutation()
        .ok_or(WelcomeTerminalFacadeError::InvalidRequest)?;
    let parsed = parse_welcome_request(admitted)?;
    if authority.endpoint().as_str() != parsed.endpoint.endpoint_nsid() {
        return Err(WelcomeTerminalFacadeError::InvalidRequest);
    }
    let prelude = prepare_actor_prelude(transaction, &authority, reservation).await?;
    let mutation = reverify_scope_mutation(prelude.scope_authority(), admitted)?;
    let prelude = prelude.verify_welcome_operation(
        parsed.operation_endpoint,
        parsed.operation_id,
        &mutation,
    )?;
    if prelude.scope_authority().trusted_instant() != trusted_instant.datetime() {
        return Err(WelcomeTerminalFacadeError::InvalidRequest);
    }

    let aggregate = hydrate_locked_conversation_state(
        transaction,
        parsed.conversation_id,
        trusted_instant.datetime(),
    )
    .await?;
    let classification =
        match lock_welcome_terminal(transaction, &aggregate, parsed.welcome_id).await {
            Ok(classification) => classification,
            Err(WelcomeLockError::Missing) => {
                let (scope_authority, completion) = prelude.into_execution_parts();
                let material = WelcomeCanonicalMaterial::WelcomeNotFound {
                    welcome_id: parsed.welcome_id,
                };
                let response = canonical_welcome_response(parsed.endpoint, &material)?;
                return Ok(WelcomeTerminalTransactionOutcome::Classified {
                    completion: WelcomeCompletion::new(
                        authority,
                        scope_authority,
                        completion,
                        &response,
                    ),
                    material,
                    response,
                });
            }
            Err(error) => return Err(error.into()),
        };

    let snapshot = welcome_terminal_snapshot(&classification);
    let hydration = HydrationAuthority::from_locked_conversation(&aggregate)?;
    let registration =
        hydration.locked_registration_from_scope_authority(prelude.scope_authority())?;
    let envelope =
        DurableSignedRequestEnvelope::new(*parsed.conversation_id.as_bytes(), trusted_instant)?;
    let composed = hydration.compose_welcome_terminal(
        &aggregate,
        envelope,
        mutation,
        registration,
        classification,
    )?;
    let (scope_authority, completion) = prelude.into_execution_parts();

    match composed {
        WelcomeTerminalPlan::Planned(plan) => {
            let material = first_execution_material(
                parsed.endpoint,
                parsed.welcome_id,
                trusted_instant.datetime(),
            );
            let response = canonical_welcome_response(parsed.endpoint, &material)?;
            let completion =
                WelcomeCompletion::new(authority, scope_authority, completion, &response);
            Ok(WelcomeTerminalTransactionOutcome::Prepared(
                PreparedWelcomeMutation {
                    plan: plan.into_persistence_plan()?,
                    completion,
                    response,
                    material,
                },
            ))
        }
        WelcomeTerminalPlan::DueExpiry(plan) => {
            let expired_at = snapshot
                .terminal_at
                .ok_or(WelcomeTerminalFacadeError::InvalidRequest)?;
            let material = WelcomeCanonicalMaterial::WelcomeExpired {
                welcome_id: parsed.welcome_id,
                expired_at,
            };
            let response = canonical_welcome_response(parsed.endpoint, &material)?;
            let completion =
                WelcomeCompletion::new(authority, scope_authority, completion, &response);
            Ok(WelcomeTerminalTransactionOutcome::Prepared(
                PreparedWelcomeMutation {
                    plan: plan.into_persistence_plan()?,
                    completion,
                    response,
                    material,
                },
            ))
        }
        WelcomeTerminalPlan::Terminal { exact_replay, .. } => {
            let decision =
                classify_welcome_terminal(parsed.endpoint, snapshot.classification, exact_replay);
            let material = terminal_material(parsed.welcome_id, snapshot, decision)?;
            let response = canonical_welcome_response(parsed.endpoint, &material)?;
            let completion =
                WelcomeCompletion::new(authority, scope_authority, completion, &response);
            Ok(WelcomeTerminalTransactionOutcome::Classified {
                completion,
                response,
                material,
            })
        }
    }
}


async fn prepare_completed_welcome_replay(
    transaction: &mut Transaction<'_, Postgres>,
    replay: LockedSignedOperationReplayAuthority,
) -> Result<WelcomeTerminalTransactionOutcome, WelcomeTerminalFacadeError> {
    let authority = replay.authority();
    let trusted_instant = authority.trusted_instant();
    let parsed = parse_welcome_request(authority.mutation())?;
    if authority.endpoint().as_str() != parsed.endpoint.endpoint_nsid()
        || authority.subject() != authority.mutation().actor_did()
        || authority.device_id() != authority.mutation().actor_device_id()
    {
        return Err(WelcomeTerminalFacadeError::InvalidRequest);
    }
    let aggregate =
        hydrate_locked_conversation_state(transaction, parsed.conversation_id, trusted_instant)
            .await?;
    let (material, terminal_classification, terminal_at, locked_terminal_digest) =
        match lock_welcome_terminal(transaction, &aggregate, parsed.welcome_id).await {
            Ok(terminal) => {
                let exact_replay =
                    validate_locked_welcome_replay(&parsed, authority.mutation(), &terminal)?;
                let snapshot = welcome_terminal_snapshot(&terminal);
                let terminal_classification = snapshot.classification;
                let terminal_at = snapshot.terminal_at;
                let material = completed_replay_material(
                    parsed.welcome_id,
                    parsed.endpoint,
                    snapshot,
                    exact_replay,
                )?;
                let digest =
                    locked_welcome_replay_digest(&aggregate, parsed.welcome_id, Some(&terminal))?;
                (material, Some(terminal_classification), terminal_at, digest)
            }
            Err(WelcomeLockError::Missing) => (
                WelcomeCanonicalMaterial::WelcomeNotFound {
                    welcome_id: parsed.welcome_id,
                },
                None,
                None,
                locked_welcome_replay_digest(&aggregate, parsed.welcome_id, None)?,
            ),
            Err(error) => return Err(error.into()),
        };
    let expected_response = canonical_welcome_response(parsed.endpoint, &material)?;
    if completed_replay_status(&material) != Some(expected_response.status()) {
        return Err(WelcomeTerminalFacadeError::ReplayPostState);
    }
    let proof = build_welcome_replay_proof(
        authority,
        &aggregate,
        &parsed,
        terminal_classification,
        terminal_at,
        locked_terminal_digest,
        &expected_response,
    )?;
    let proof = match parsed.endpoint {
        WelcomeEndpoint::Acknowledge => {
            super::prelude::SignedOperationReplayPostStateProof::WelcomeAcknowledgement(proof)
        }
        WelcomeEndpoint::Reject => {
            super::prelude::SignedOperationReplayPostStateProof::WelcomeRejection(proof)
        }
    };
    let response = release_signed_operation_replay(transaction, replay, proof).await?;
    if response.status() != expected_response.status()
        || response.response_sha256() != expected_response.sha256()
    {
        return Err(WelcomeTerminalFacadeError::ReplayPostState);
    }
    Ok(WelcomeTerminalTransactionOutcome::Replay { response, material })
}

fn validate_locked_welcome_replay(
    parsed: &ParsedWelcomeRequest,
    mutation: &VerifiedSignedMutation,
    terminal: &LockedWelcomeTerminal,
) -> Result<bool, WelcomeTerminalFacadeError> {
    let (row, authorization, stored_reason, terminal_transaction_id, locked_at) = match terminal {
        LockedWelcomeTerminal::Acknowledged {
            transaction_id,
            locked_at,
            row,
            authorization,
            ..
        } => (row, Some(authorization), None, transaction_id, *locked_at),
        LockedWelcomeTerminal::Rejected {
            transaction_id,
            locked_at,
            row,
            authorization,
            reason,
            ..
        } => (
            row,
            Some(authorization),
            Some(reason.as_str()),
            transaction_id,
            *locked_at,
        ),
        LockedWelcomeTerminal::Expired {
            transaction_id,
            locked_at,
            row,
            ..
        }
        | LockedWelcomeTerminal::SupersededByTransition {
            transaction_id,
            locked_at,
            row,
            ..
        }
        | LockedWelcomeTerminal::SupersededByRevocation {
            transaction_id,
            locked_at,
            row,
            ..
        } => (row, None, None, transaction_id, *locked_at),
        LockedWelcomeTerminal::PendingNotDue(_) | LockedWelcomeTerminal::PendingDue(_) => {
            return Err(WelcomeTerminalFacadeError::ReplayPostState)
        }
    };
    if terminal_transaction_id.is_empty()
        || locked_at.timestamp_millis() < 0
        || parsed.welcome_id.as_bytes() != &row.welcome_id
        || mutation.actor_did().as_str().as_bytes() != row.recipient.principal().as_bytes()
        || mutation.actor_device_id().as_bytes() != row.recipient.device_id()
        || parsed.transition_seq != row.transition_seq
        || !parsed_coordinate_matches(parsed, &row.coordinate)
    {
        return Err(WelcomeTerminalFacadeError::ReplayPostState);
    }
    if matches!(terminal, LockedWelcomeTerminal::Rejected { .. })
        && parsed.endpoint == WelcomeEndpoint::Reject
        && parsed.rejection_reason.as_deref() != stored_reason
    {
        return Err(WelcomeTerminalFacadeError::InvalidRequest);
    }
    let accepted_wrapper = mutation
        .accepted_wrapper_bytes()
        .ok_or(WelcomeTerminalFacadeError::InvalidRequest)?;
    Ok(authorization.is_some_and(|stored| {
        stored.signed_request_bytes() == accepted_wrapper
            && stored.signing_transcript_bytes() == mutation.transcript_bytes()
            && stored.request_digest() == mutation.request_digest()
            && stored.signature() == mutation.signature()
    }))
}

#[allow(clippy::too_many_arguments)]
fn build_welcome_replay_proof(
    authority: &super::auth::SignedOperationReplayAuthority,
    aggregate: &LockedConversationStateGuard,
    parsed: &ParsedWelcomeRequest,
    terminal_classification: Option<WelcomeTerminalClass>,
    terminal_at: Option<DateTime<Utc>>,
    locked_terminal_digest: [u8; 32],
    expected_response: &WelcomeCanonicalResponse,
) -> Result<WelcomeReplayPostStateProof, WelcomeTerminalFacadeError> {
    let mutation = authority.mutation();
    let accepted = mutation
        .accepted_wrapper_bytes()
        .ok_or(WelcomeTerminalFacadeError::InvalidRequest)?;
    WelcomeReplayPostStateProof::from_locked_facts(
        aggregate.head().transaction_id().to_owned(),
        parsed.operation_id,
        authority.subject().as_str().to_owned(),
        parsed.endpoint.endpoint_nsid(),
        parsed.endpoint.mutation_kind(),
        *mutation.request_digest(),
        Sha256::digest(accepted).into(),
        *mutation.signature(),
        parsed.conversation_id,
        parsed.welcome_id,
        terminal_classification,
        terminal_at,
        locked_terminal_digest,
        expected_response.status(),
        *expected_response.sha256(),
    )
}

fn locked_welcome_replay_digest(
    aggregate: &LockedConversationStateGuard,
    welcome_id: Uuid,
    terminal: Option<&LockedWelcomeTerminal>,
) -> Result<[u8; 32], WelcomeTerminalFacadeError> {
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-LOCKED-WELCOME-REPLAY\0");
    digest_len(&mut digest, aggregate.head().transaction_id().as_bytes());
    digest.update(aggregate.head().conversation_id().as_bytes());
    digest.update(aggregate.head().durable_row_digest());
    digest.update(aggregate.locked_graph_digest());
    match aggregate.locked_snapshot_digest() {
        Some(snapshot) => {
            digest.update([1]);
            digest.update(snapshot);
        }
        None => digest.update([0]),
    }
    digest.update(welcome_id.as_bytes());
    let Some(terminal) = terminal else {
        digest.update([0]);
        return Ok(digest.finalize().into());
    };
    let snapshot = welcome_terminal_snapshot(terminal);
    let (transaction_id, locked_at, row) = match terminal {
        LockedWelcomeTerminal::Acknowledged {
            transaction_id,
            locked_at,
            row,
            ..
        }
        | LockedWelcomeTerminal::Rejected {
            transaction_id,
            locked_at,
            row,
            ..
        }
        | LockedWelcomeTerminal::Expired {
            transaction_id,
            locked_at,
            row,
            ..
        }
        | LockedWelcomeTerminal::SupersededByTransition {
            transaction_id,
            locked_at,
            row,
            ..
        }
        | LockedWelcomeTerminal::SupersededByRevocation {
            transaction_id,
            locked_at,
            row,
            ..
        } => (transaction_id, locked_at, row),
        LockedWelcomeTerminal::PendingNotDue(_) | LockedWelcomeTerminal::PendingDue(_) => {
            return Err(WelcomeTerminalFacadeError::ReplayPostState)
        }
    };
    if transaction_id != aggregate.head().transaction_id()
        || row.welcome_id != *welcome_id.as_bytes()
        || row.coordinate.conversation_id() != aggregate.head().conversation_id().as_bytes()
    {
        return Err(WelcomeTerminalFacadeError::ReplayPostState);
    }
    digest.update([1]);
    digest_len(&mut digest, transaction_id.as_bytes());
    digest.update(locked_at.timestamp_millis().to_be_bytes());
    digest.update(row.welcome_id);
    digest_len(&mut digest, row.recipient.principal().as_bytes());
    digest.update(row.recipient.device_id());
    digest.update(row.transition_seq.to_be_bytes());
    digest_coordinate(&mut digest, &row.coordinate);
    digest.update(row.recovery_request_id);
    digest.update(row.key_package_ref);
    digest.update(row.sha256);
    digest.update(Sha256::digest(&row.opaque_welcome));
    digest.update(row.expires_at.unix_millis().to_be_bytes());
    digest.update([match snapshot.classification {
        WelcomeTerminalClass::PendingNotDue => 1,
        WelcomeTerminalClass::PendingDue => 2,
        WelcomeTerminalClass::Acknowledged => 3,
        WelcomeTerminalClass::Rejected => 4,
        WelcomeTerminalClass::Expired => 5,
        WelcomeTerminalClass::SupersededByTransition => 6,
        WelcomeTerminalClass::SupersededByRevocation => 7,
    }]);
    digest.update(
        snapshot
            .terminal_at
            .ok_or(WelcomeTerminalFacadeError::ReplayPostState)?
            .timestamp_millis()
            .to_be_bytes(),
    );
    match terminal {
        LockedWelcomeTerminal::Acknowledged { authorization, .. } => {
            digest.update([1]);
            digest_authorization(&mut digest, authorization);
        }
        LockedWelcomeTerminal::Rejected {
            authorization,
            reason,
            ..
        } => {
            digest.update([2]);
            digest_authorization(&mut digest, authorization);
            digest_len(&mut digest, reason.as_bytes());
        }
        LockedWelcomeTerminal::Expired { .. } => digest.update([3]),
        LockedWelcomeTerminal::SupersededByTransition { transition_id, .. } => {
            digest.update([4]);
            digest.update(transition_id.as_bytes());
        }
        LockedWelcomeTerminal::SupersededByRevocation { revocation_id, .. } => {
            digest.update([5]);
            digest.update(revocation_id.as_bytes());
        }
        LockedWelcomeTerminal::PendingNotDue(_) | LockedWelcomeTerminal::PendingDue(_) => {
            unreachable!("pending terminal rejected above")
        }
    }
    Ok(digest.finalize().into())
}

fn digest_authorization(
    digest: &mut Sha256,
    authorization: &super::core::LockedWelcomeClientAuthorization,
) {
    digest.update(Sha256::digest(authorization.signed_request_bytes()));
    digest.update(Sha256::digest(authorization.signing_transcript_bytes()));
    digest.update(authorization.request_digest());
    digest.update(authorization.signature());
}

fn digest_coordinate(digest: &mut Sha256, coordinate: &PublicGroupSnapshotCoordinate) {
    digest.update(coordinate.conversation_id());
    digest.update(coordinate.generation().to_be_bytes());
    digest.update(coordinate.state_version().to_be_bytes());
    digest.update(coordinate.group_id());
    digest.update(coordinate.epoch().to_be_bytes());
    digest.update(coordinate.group_context_hash());
    digest.update(coordinate.confirmation_tag());
    digest.update([match coordinate.lifecycle() {
        crate::chat_protocol::snapshot::PublicGroupSnapshotLifecycle::Active => 1,
        crate::chat_protocol::snapshot::PublicGroupSnapshotLifecycle::Superseded => 2,
    }]);
}

fn first_execution_material(
    endpoint: WelcomeEndpoint,
    welcome_id: Uuid,
    terminal_at: DateTime<Utc>,
) -> WelcomeCanonicalMaterial {
    match endpoint {
        WelcomeEndpoint::Acknowledge => WelcomeCanonicalMaterial::Acknowledged {
            welcome_id,
            terminal_at,
        },
        WelcomeEndpoint::Reject => WelcomeCanonicalMaterial::Rejected {
            welcome_id,
            terminal_at,
        },
    }
}

fn reverify_scope_mutation(
    scope: &ScopeBoundBusinessAuthority,
    admitted: &VerifiedSignedMutation,
) -> Result<VerifiedSignedMutation, WelcomeTerminalFacadeError> {
    let raw = admitted
        .accepted_wrapper_bytes()
        .ok_or(WelcomeTerminalFacadeError::InvalidRequest)?;
    let signing_public_key = scope
        .actor_signing_public_key()
        .ok_or(WelcomeTerminalFacadeError::InvalidRequest)?;
    let verified = decode_and_verify_signed_mutation(raw, signing_public_key)
        .map_err(|_| WelcomeTerminalFacadeError::InvalidRequest)?;
    if verified.kind() != admitted.kind()
        || verified.type_id() != admitted.type_id()
        || verified.domain() != admitted.domain()
        || verified.canonical_projection() != admitted.canonical_projection()
        || verified.transcript_bytes() != admitted.transcript_bytes()
        || verified.request_digest() != admitted.request_digest()
        || verified.signature() != admitted.signature()
        || verified.accepted_wrapper_bytes() != admitted.accepted_wrapper_bytes()
        || verified.actor_did() != admitted.actor_did()
        || verified.actor_device_id() != admitted.actor_device_id()
        || verified.key_id() != admitted.key_id()
        || verified.auth_generation() != admitted.auth_generation()
        || verified.signed_at() != admitted.signed_at()
    {
        return Err(WelcomeTerminalFacadeError::InvalidRequest);
    }
    Ok(verified)
}

struct ParsedWelcomeRequest {
    endpoint: WelcomeEndpoint,
    operation_endpoint: WelcomeOperationEndpoint,
    operation_id: Uuid,
    welcome_id: Uuid,
    conversation_id: Uuid,
    transition_seq: u64,
    coordinate: ParsedWelcomeCoordinate,
    rejection_reason: Option<String>,
}

struct ParsedWelcomeCoordinate {
    generation: u64,
    state_version: u64,
    group_id: [u8; 32],
    epoch: u64,
    group_context_hash: [u8; 32],
    confirmation_tag: [u8; 32],
}

fn parse_welcome_request(
    mutation: &VerifiedSignedMutation,
) -> Result<ParsedWelcomeRequest, WelcomeTerminalFacadeError> {
    let (endpoint, operation_endpoint, body) = match mutation.projection() {
        VerifiedMutationProjection::WelcomeAcknowledgement(value) => (
            WelcomeEndpoint::Acknowledge,
            WelcomeOperationEndpoint::AcknowledgeWelcome,
            value.body(),
        ),
        VerifiedMutationProjection::WelcomeRejection(value) => (
            WelcomeEndpoint::Reject,
            WelcomeOperationEndpoint::RejectWelcome,
            value.body(),
        ),
        _ => return Err(WelcomeTerminalFacadeError::InvalidRequest),
    };
    let operation_id = body_uuid(&body, "idempotencyKey")?;
    let welcome_id = body_uuid(&body, "welcomeId")?;
    let transition_seq = body_integer(&body, "transitionSeq")?;
    let coordinates = match body.get("coordinates") {
        Some(CanonicalValueRef::Object(value)) => value,
        _ => return Err(WelcomeTerminalFacadeError::InvalidRequest),
    };
    let conversation_id = body_uuid(&coordinates, "conversationId")?;
    let coordinate = ParsedWelcomeCoordinate {
        generation: body_integer(&coordinates, "generation")?,
        state_version: body_integer(&coordinates, "stateVersion")?,
        group_id: body_bytes32(&coordinates, "groupId")?,
        epoch: body_integer(&coordinates, "epoch")?,
        group_context_hash: body_bytes32(&coordinates, "groupContextHash")?,
        confirmation_tag: body_bytes32(&coordinates, "confirmationTag")?,
    };
    if !matches!(
        coordinates.get("lifecycle"),
        Some(CanonicalValueRef::Text("active"))
    ) {
        return Err(WelcomeTerminalFacadeError::InvalidRequest);
    }
    let rejection_reason = match endpoint {
        WelcomeEndpoint::Acknowledge if body.get("reason").is_none() => None,
        WelcomeEndpoint::Reject => match body.get("reason") {
            Some(CanonicalValueRef::Text(value))
                if matches!(
                    value,
                    "noMatchingKeyPackage"
                        | "invalidWelcome"
                        | "unsupportedCipherSuite"
                        | "coordinateMismatch"
                        | "localStateConflict"
                ) =>
            {
                Some(value.to_owned())
            }
            _ => return Err(WelcomeTerminalFacadeError::InvalidRequest),
        },
        WelcomeEndpoint::Acknowledge => return Err(WelcomeTerminalFacadeError::InvalidRequest),
    };
    Ok(ParsedWelcomeRequest {
        endpoint,
        operation_endpoint,
        operation_id,
        welcome_id,
        conversation_id,
        transition_seq,
        coordinate,
        rejection_reason,
    })
}

fn body_uuid(
    body: &crate::chat_protocol::transcript::ClosedObjectRef<'_>,
    field: &str,
) -> Result<Uuid, WelcomeTerminalFacadeError> {
    match body.get(field) {
        Some(CanonicalValueRef::Uuid(value)) => Ok(Uuid::from_bytes(*value.as_bytes())),
        _ => Err(WelcomeTerminalFacadeError::InvalidRequest),
    }
}

fn body_integer(
    body: &crate::chat_protocol::transcript::ClosedObjectRef<'_>,
    field: &str,
) -> Result<u64, WelcomeTerminalFacadeError> {
    match body.get(field) {
        Some(CanonicalValueRef::Integer(value)) => Ok(value),
        _ => Err(WelcomeTerminalFacadeError::InvalidRequest),
    }
}

fn body_bytes32(
    body: &crate::chat_protocol::transcript::ClosedObjectRef<'_>,
    field: &str,
) -> Result<[u8; 32], WelcomeTerminalFacadeError> {
    match body.get(field) {
        Some(CanonicalValueRef::Bytes(value)) => value
            .try_into()
            .map_err(|_| WelcomeTerminalFacadeError::InvalidRequest),
        _ => Err(WelcomeTerminalFacadeError::InvalidRequest),
    }
}

fn parsed_coordinate_matches(
    parsed: &ParsedWelcomeRequest,
    expected: &PublicGroupSnapshotCoordinate,
) -> bool {
    parsed.conversation_id.as_bytes() == expected.conversation_id()
        && parsed.coordinate.generation == expected.generation()
        && parsed.coordinate.state_version == expected.state_version()
        && parsed.coordinate.group_id == *expected.group_id()
        && parsed.coordinate.epoch == expected.epoch()
        && parsed.coordinate.group_context_hash == *expected.group_context_hash()
        && parsed.coordinate.confirmation_tag == *expected.confirmation_tag()
        && matches!(
            expected.lifecycle(),
            crate::chat_protocol::snapshot::PublicGroupSnapshotLifecycle::Active
        )
}

struct WelcomeTerminalSnapshot {
    classification: WelcomeTerminalClass,
    terminal_at: Option<DateTime<Utc>>,
    cause: Option<WelcomeSupersessionCause>,
}

fn welcome_terminal_snapshot(value: &LockedWelcomeTerminal) -> WelcomeTerminalSnapshot {
    match value {
        LockedWelcomeTerminal::PendingNotDue(_) => WelcomeTerminalSnapshot {
            classification: WelcomeTerminalClass::PendingNotDue,
            terminal_at: None,
            cause: None,
        },
        LockedWelcomeTerminal::PendingDue(guard) => WelcomeTerminalSnapshot {
            classification: WelcomeTerminalClass::PendingDue,
            terminal_at: Some(guard.expires_at()),
            cause: None,
        },
        LockedWelcomeTerminal::Acknowledged { terminal_at, .. } => WelcomeTerminalSnapshot {
            classification: WelcomeTerminalClass::Acknowledged,
            terminal_at: Some(*terminal_at),
            cause: None,
        },
        LockedWelcomeTerminal::Rejected { terminal_at, .. } => WelcomeTerminalSnapshot {
            classification: WelcomeTerminalClass::Rejected,
            terminal_at: Some(*terminal_at),
            cause: None,
        },
        LockedWelcomeTerminal::Expired { terminal_at, .. } => WelcomeTerminalSnapshot {
            classification: WelcomeTerminalClass::Expired,
            terminal_at: Some(*terminal_at),
            cause: None,
        },
        LockedWelcomeTerminal::SupersededByTransition {
            transition_id,
            terminal_at,
            ..
        } => WelcomeTerminalSnapshot {
            classification: WelcomeTerminalClass::SupersededByTransition,
            terminal_at: Some(*terminal_at),
            cause: Some(WelcomeSupersessionCause::Transition(*transition_id)),
        },
        LockedWelcomeTerminal::SupersededByRevocation {
            revocation_id,
            terminal_at,
            ..
        } => WelcomeTerminalSnapshot {
            classification: WelcomeTerminalClass::SupersededByRevocation,
            terminal_at: Some(*terminal_at),
            cause: Some(WelcomeSupersessionCause::DeviceRevocation(*revocation_id)),
        },
    }
}

fn terminal_material(
    welcome_id: Uuid,
    snapshot: WelcomeTerminalSnapshot,
    decision: WelcomeTerminalDecision,
) -> Result<WelcomeCanonicalMaterial, WelcomeTerminalFacadeError> {
    Ok(match decision {
        WelcomeTerminalDecision::ExactAcknowledgementReplay
        | WelcomeTerminalDecision::ExactRejectionReplay => WelcomeCanonicalMaterial::ExactReplay {
            welcome_id,
            terminal: snapshot.classification,
            terminal_at: snapshot
                .terminal_at
                .ok_or(WelcomeTerminalFacadeError::InvalidRequest)?,
        },
        WelcomeTerminalDecision::AcknowledgementConflict
        | WelcomeTerminalDecision::RejectionConflict => WelcomeCanonicalMaterial::Conflict {
            welcome_id,
            terminal: snapshot.classification,
        },
        WelcomeTerminalDecision::WelcomeExpired => WelcomeCanonicalMaterial::WelcomeExpired {
            welcome_id,
            expired_at: snapshot
                .terminal_at
                .ok_or(WelcomeTerminalFacadeError::InvalidRequest)?,
        },
        WelcomeTerminalDecision::SupersededByTransition
        | WelcomeTerminalDecision::SupersededByRevocation => {
            WelcomeCanonicalMaterial::WelcomeSuperseded {
                welcome_id,
                cause: snapshot
                    .cause
                    .ok_or(WelcomeTerminalFacadeError::InvalidRequest)?,
            }
        }
        WelcomeTerminalDecision::PrepareAcknowledgement
        | WelcomeTerminalDecision::PrepareRejection
        | WelcomeTerminalDecision::PrepareExpiry => {
            return Err(WelcomeTerminalFacadeError::InvalidRequest)
        }
    })
}

fn completed_replay_material(
    welcome_id: Uuid,
    endpoint: WelcomeEndpoint,
    snapshot: WelcomeTerminalSnapshot,
    exact_replay: bool,
) -> Result<WelcomeCanonicalMaterial, WelcomeTerminalFacadeError> {
    let decision = classify_welcome_terminal(endpoint, snapshot.classification, exact_replay);
    if matches!(
        decision,
        WelcomeTerminalDecision::PrepareAcknowledgement
            | WelcomeTerminalDecision::PrepareRejection
            | WelcomeTerminalDecision::PrepareExpiry
    ) || (exact_replay
        && !matches!(
            decision,
            WelcomeTerminalDecision::ExactAcknowledgementReplay
                | WelcomeTerminalDecision::ExactRejectionReplay
        ))
    {
        return Err(WelcomeTerminalFacadeError::ReplayPostState);
    }
    terminal_material(welcome_id, snapshot, decision)
}

fn completed_replay_status(material: &WelcomeCanonicalMaterial) -> Option<i32> {
    match material {
        WelcomeCanonicalMaterial::Acknowledged { .. }
        | WelcomeCanonicalMaterial::Rejected { .. } => Some(200),
        WelcomeCanonicalMaterial::ExactReplay {
            terminal: WelcomeTerminalClass::Acknowledged | WelcomeTerminalClass::Rejected,
            ..
        } => Some(200),
        WelcomeCanonicalMaterial::ExactReplay { .. } => None,
        WelcomeCanonicalMaterial::Conflict { .. }
        | WelcomeCanonicalMaterial::WelcomeExpired { .. }
        | WelcomeCanonicalMaterial::WelcomeSuperseded { .. }
        | WelcomeCanonicalMaterial::WelcomeNotFound { .. } => Some(400),
    }
}

fn canonical_welcome_response(
    endpoint: WelcomeEndpoint,
    material: &WelcomeCanonicalMaterial,
) -> Result<WelcomeCanonicalResponse, WelcomeTerminalFacadeError> {
    let (status, value) = match (endpoint, material) {
        (
            WelcomeEndpoint::Acknowledge,
            WelcomeCanonicalMaterial::Acknowledged { terminal_at, .. }
            | WelcomeCanonicalMaterial::ExactReplay {
                terminal: WelcomeTerminalClass::Acknowledged,
                terminal_at,
                ..
            },
        ) => (
            200,
            json!({
                "status": "acknowledged",
                "acknowledgedAt": canonical_datetime(*terminal_at),
            }),
        ),
        (
            WelcomeEndpoint::Reject,
            WelcomeCanonicalMaterial::Rejected { terminal_at, .. }
            | WelcomeCanonicalMaterial::ExactReplay {
                terminal: WelcomeTerminalClass::Rejected,
                terminal_at,
                ..
            },
        ) => (
            200,
            json!({
                "status": "rejected",
                "rejectedAt": canonical_datetime(*terminal_at),
            }),
        ),
        (WelcomeEndpoint::Acknowledge, WelcomeCanonicalMaterial::Conflict { .. }) => {
            protocol_error_response("AcknowledgementConflict")
        }
        (WelcomeEndpoint::Reject, WelcomeCanonicalMaterial::Conflict { .. }) => {
            protocol_error_response("RejectionConflict")
        }
        (_, WelcomeCanonicalMaterial::WelcomeExpired { .. }) => {
            protocol_error_response("WelcomeExpired")
        }
        (_, WelcomeCanonicalMaterial::WelcomeSuperseded { .. }) => {
            protocol_error_response("WelcomeSuperseded")
        }
        (_, WelcomeCanonicalMaterial::WelcomeNotFound { .. }) => {
            protocol_error_response("WelcomeNotFound")
        }
        _ => return Err(WelcomeTerminalFacadeError::ReplayPostState),
    };
    let bytes =
        serde_json::to_vec(&value).map_err(|_| WelcomeTerminalFacadeError::ReplayPostState)?;
    let sha256 = Sha256::digest(&bytes).into();
    Ok(WelcomeCanonicalResponse {
        status,
        bytes: bytes.into_boxed_slice(),
        sha256,
    })
}

fn protocol_error_response(code: &'static str) -> (i32, serde_json::Value) {
    (400, json!({ "error": code, "message": code }))
}

fn canonical_datetime(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn welcome_id() -> Uuid {
        Uuid::parse_str("9ceacb0c-610d-4df3-b538-5e8d6bd96278").unwrap()
    }

    fn terminal_at() -> DateTime<Utc> {
        DateTime::from_timestamp_millis(1_700_000_000_123).unwrap()
    }

    #[test]
    fn first_execution_material_retains_the_terminal_instant() {
        let terminal_at = terminal_at();

        assert_eq!(
            first_execution_material(WelcomeEndpoint::Acknowledge, welcome_id(), terminal_at),
            WelcomeCanonicalMaterial::Acknowledged {
                welcome_id: welcome_id(),
                terminal_at,
            }
        );
        assert_eq!(
            first_execution_material(WelcomeEndpoint::Reject, welcome_id(), terminal_at),
            WelcomeCanonicalMaterial::Rejected {
                welcome_id: welcome_id(),
                terminal_at,
            }
        );
    }

    #[test]
    fn exact_terminal_replay_retains_the_historic_terminal_instant() {
        let terminal_at = terminal_at();
        let material = terminal_material(
            welcome_id(),
            WelcomeTerminalSnapshot {
                classification: WelcomeTerminalClass::Acknowledged,
                terminal_at: Some(terminal_at),
                cause: None,
            },
            WelcomeTerminalDecision::ExactAcknowledgementReplay,
        )
        .unwrap();

        assert_eq!(
            material,
            WelcomeCanonicalMaterial::ExactReplay {
                welcome_id: welcome_id(),
                terminal: WelcomeTerminalClass::Acknowledged,
                terminal_at,
            }
        );
    }

    #[test]
    fn completed_replay_requires_a_closed_terminal_and_exact_status_family() {
        let terminal_at = terminal_at();
        let exact = completed_replay_material(
            welcome_id(),
            WelcomeEndpoint::Acknowledge,
            WelcomeTerminalSnapshot {
                classification: WelcomeTerminalClass::Acknowledged,
                terminal_at: Some(terminal_at),
                cause: None,
            },
            true,
        )
        .unwrap();
        assert_eq!(completed_replay_status(&exact), Some(200));

        let conflict = completed_replay_material(
            welcome_id(),
            WelcomeEndpoint::Reject,
            WelcomeTerminalSnapshot {
                classification: WelcomeTerminalClass::Acknowledged,
                terminal_at: Some(terminal_at),
                cause: None,
            },
            false,
        )
        .unwrap();
        assert_eq!(completed_replay_status(&conflict), Some(400));

        let pending = completed_replay_material(
            welcome_id(),
            WelcomeEndpoint::Acknowledge,
            WelcomeTerminalSnapshot {
                classification: WelcomeTerminalClass::PendingNotDue,
                terminal_at: None,
                cause: None,
            },
            false,
        );
        assert!(matches!(
            pending,
            Err(WelcomeTerminalFacadeError::ReplayPostState)
        ));
    }

    #[test]
    fn canonical_replay_response_is_endpoint_and_terminal_bound() {
        let terminal_at = terminal_at();
        let acknowledgement = canonical_welcome_response(
            WelcomeEndpoint::Acknowledge,
            &WelcomeCanonicalMaterial::ExactReplay {
                welcome_id: welcome_id(),
                terminal: WelcomeTerminalClass::Acknowledged,
                terminal_at,
            },
        )
        .unwrap();
        assert_eq!(acknowledgement.status(), 200);
        assert_eq!(
            acknowledgement.as_bytes(),
            br#"{"acknowledgedAt":"2023-11-14T22:13:20.123Z","status":"acknowledged"}"#
        );
        assert_eq!(
            acknowledgement.sha256(),
            &<[u8; 32]>::from(Sha256::digest(acknowledgement.as_bytes()))
        );

        assert!(matches!(
            canonical_welcome_response(
                WelcomeEndpoint::Reject,
                &WelcomeCanonicalMaterial::ExactReplay {
                    welcome_id: welcome_id(),
                    terminal: WelcomeTerminalClass::Acknowledged,
                    terminal_at,
                },
            ),
            Err(WelcomeTerminalFacadeError::ReplayPostState)
        ));
    }

    #[test]
    fn replay_post_state_seal_covers_expected_response_and_terminal_facts() {
        let mut proof = WelcomeReplayPostStateProof::from_locked_facts(
            "41".to_owned(),
            Uuid::parse_str("6b4f6314-7e4d-4478-bcd0-80dfa8f9b640").unwrap(),
            "did:plc:welcome-proof".to_owned(),
            "blue.catbird.chat.acknowledgeWelcome",
            SignedMutationKind::WelcomeAcknowledgement,
            [1; 32],
            [2; 32],
            [3; 64],
            Uuid::parse_str("2b123e2e-d0aa-4c6b-9c8a-9c2896024482").unwrap(),
            welcome_id(),
            Some(WelcomeTerminalClass::Acknowledged),
            Some(terminal_at()),
            [4; 32],
            200,
            [5; 32],
        )
        .unwrap();
        assert!(proof.validates_seal());

        proof.expected_status = 400;
        assert!(!proof.validates_seal());
    }
}
