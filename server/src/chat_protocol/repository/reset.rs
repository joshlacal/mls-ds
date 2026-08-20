// Transaction-bound repository authority for clean-chat Reset.
//
// This is deliberately separate from `repository::transition`: transition
// contains exact row writers, while this module owns the prewrite read-set,
// canonical lock order, immutable pending-request witness, expiry replacement
// authority, and full-row terminal CAS.

#[cfg(test)]
use std::sync::Arc;

#[cfg(not(test))]
use catbird_atproto::generated::blue_catbird::chat as chat_dto;
#[cfg(not(test))]
use chrono::SecondsFormat;
use chrono::{DateTime, Duration, Utc};
#[cfg(not(test))]
use jacquard_common::DefaultStr;
#[cfg(not(test))]
use serde_json::{json, Value as JsonValue};
use sha2::{Digest, Sha256};
use sqlx::{Acquire, FromRow, Postgres, Transaction};
use uuid::Uuid;

#[cfg(not(test))]
use super::{
    auth::CompletedIdempotentResponse,
    execution_context::{
        hydrate_execution_context, ExecutionContextArtifacts, ExecutionContextHydrationError,
    },
    prelude::{
        lock_signed_operation_replay_authority, prepare_identity_scope_prelude,
        release_signed_operation_replay, LockedSignedOperationReplayAuthority,
        OperationCompletionGuard, OperationReservationGuard, PreludeError, PreparedSignedOperation,
        PreparedSignedOperationState, SignedOperationReplayPostStateProof,
    },
};
use super::{
    auth::RepositoryAuthorityClass,
    core::{
        hydrate_locked_conversation_state, hydrate_locked_reserved_recovery_package,
        ConversationHeadHydrationError, ConversationStateHydrationError,
        LockedConversationStateGuard, LockedRecoveryPackageGuard,
    },
    prelude::{
        CanonicalDeviceIdentity, CanonicalLockScope, PreparedBusinessPrelude,
        ResetOperationEndpoint, ScopeBoundBusinessAuthority,
    },
};
use crate::chat_protocol::{
    dpop::VerifiedChatDeviceRequest,
    snapshot::{PublicGroupSnapshotCoordinate, PublicGroupSnapshotLifecycle, MAX_PROTOCOL_INTEGER},
    state_machine::{
        HydrationAuthority, ParticipantRole, PlannedTransition, PrincipalId, StateMachineError,
    },
    transcript::{
        decode_and_verify_signed_mutation, CanonicalValueRef, SignedMutationKind,
        VerifiedControlEntry, VerifiedMutationProjection, VerifiedSignedMutation,
    },
    validation::{BareDid, KeyThumbprint},
};
#[cfg(not(test))]
use crate::chat_protocol::{
    model::AuthPrimitiveError,
    state_machine::{
        executor::AppliedTransition, ConversationPersistencePlan, ExecutorError, PlanKind,
    },
    transcript::{
        build_verified_control_entry, CanonicalControlEntryProducts, CanonicalControlServerFields,
        ControlEntryKind,
    },
    validation::CanonicalUuidV4,
};

const MAX_PREPARE_ATTEMPTS: usize = 3;
const RESET_REQUEST_IMMUTABLE_DOMAIN: &[u8] = b"CATBIRD-CHAT-RESET-REQUEST-IMMUTABLE-ROW\0";
const LOCKED_PENDING_RESET_DOMAIN: &[u8] = b"CATBIRD-CHAT-LOCKED-PENDING-RESET-REQUEST\0";
const RESET_ADMISSION_DOMAIN: &[u8] = b"CATBIRD-CHAT-RESET-ADMISSION\0";
const RESET_ADMITTED_MUTATION_DOMAIN: &[u8] = b"CATBIRD-CHAT-RESET-ADMITTED-MUTATION\0";

#[cfg(test)]
pub(crate) struct ResetPrepareProbeForTest {
    inject_candidate_scope_drift_once: bool,
    attempts: usize,
    after_scope_locks_reached: Option<Arc<tokio::sync::Notify>>,
    release_before_head: Option<Arc<tokio::sync::Notify>>,
}

#[cfg(test)]
impl ResetPrepareProbeForTest {
    pub(crate) fn candidate_scope_drift_once() -> Self {
        Self {
            inject_candidate_scope_drift_once: true,
            attempts: 0,
            after_scope_locks_reached: None,
            release_before_head: None,
        }
    }

    pub(crate) fn pause_before_head(
        reached: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    ) -> Self {
        Self {
            inject_candidate_scope_drift_once: false,
            attempts: 0,
            after_scope_locks_reached: Some(reached),
            release_before_head: Some(release),
        }
    }

    pub(crate) fn attempts(&self) -> usize {
        self.attempts
    }
}

#[derive(Debug)]
pub(crate) enum ResetRepositoryError {
    Database(sqlx::Error),
    ForeignTransaction,
    UnsupportedAuthority,
    AuthorityBindingMismatch,
    TrustedInstantMismatch,
    NonCanonicalOperation,
    NonCanonicalScope,
    MissingPrincipal,
    MissingDevice,
    MissingDeviceKey,
    DeviceOrKeyDrift,
    HeadBusy,
    CandidateScopeDrift,
    RetryExhausted,
    ConversationMissing,
    ConversationNotActive,
    OperationIdAlreadyUsed,
    PendingResetAlreadyExists,
    PendingResetNotFound,
    PendingResetTerminal,
    PendingResetExpired,
    PendingResetNotExpired,
    PendingResetCoordinateMismatch,
    InvalidResetRow,
    GuardInvariant,
    CompareAndSetConflict,
}

#[derive(Debug)]
pub(crate) enum ResetCompositionError {
    Repository(ResetRepositoryError),
    StateMachine(StateMachineError),
}

impl From<ResetRepositoryError> for ResetCompositionError {
    fn from(value: ResetRepositoryError) -> Self {
        Self::Repository(value)
    }
}

impl From<StateMachineError> for ResetCompositionError {
    fn from(value: StateMachineError) -> Self {
        Self::StateMachine(value)
    }
}

impl From<sqlx::Error> for ResetRepositoryError {
    fn from(value: sqlx::Error) -> Self {
        Self::Database(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PendingResetTimeState {
    Live,
    Expired,
}

pub(crate) fn classify_pending_reset_at(
    trusted_instant: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> PendingResetTimeState {
    if trusted_instant < expires_at {
        PendingResetTimeState::Live
    } else {
        PendingResetTimeState::Expired
    }
}

/// Canonical repository-owned payload for a newly persisted Reset request.
///
/// Field order and whitespace are protocol constants so the first response
/// and every exact replay retain byte-identical event material. UUID's
/// hyphenated lowercase display contains no JSON metacharacters.
pub(crate) fn canonical_reset_requested_event_payload(
    reset_request_id: Uuid,
    conversation_id: Uuid,
) -> Vec<u8> {
    format!(
        r#"{{"$type":"blue.catbird.chat.defs#resetRequestedEvent","resetRequestId":"{}","conversationId":"{}"}}"#,
        reset_request_id.hyphenated(),
        conversation_id.hyphenated(),
    )
    .into_bytes()
}

/// Canonical repository-owned primary event for a successful Reset activation.
pub(crate) fn canonical_reset_activation_event_payload(conversation_id: Uuid) -> Vec<u8> {
    format!(
        r#"{{"$type":"blue.catbird.chat.defs#conversationChangedEvent","conversationId":"{}"}}"#,
        conversation_id.hyphenated(),
    )
    .into_bytes()
}

/// High-level Reset composition failure. Every arm is pre-commit: the caller
/// retains sole ownership of the outer transaction and must roll it back on an
/// error.
#[cfg(not(test))]
#[derive(Debug)]
pub(crate) enum ResetFacadeError {
    MissingMutation,
    UnsupportedMutation,
    InvalidCanonicalMaterial,
    Repository(ResetRepositoryError),
    Prelude(PreludeError),
    Primitive(AuthPrimitiveError),
    StateMachine(StateMachineError),
    ExecutionContext(ExecutionContextHydrationError),
    Executor(ExecutorError),
    Database(sqlx::Error),
}

#[cfg(not(test))]
impl From<ResetRepositoryError> for ResetFacadeError {
    fn from(value: ResetRepositoryError) -> Self {
        Self::Repository(value)
    }
}

#[cfg(not(test))]
impl From<ResetCompositionError> for ResetFacadeError {
    fn from(value: ResetCompositionError) -> Self {
        match value {
            ResetCompositionError::Repository(error) => Self::Repository(error),
            ResetCompositionError::StateMachine(error) => Self::StateMachine(error),
        }
    }
}

#[cfg(not(test))]
impl From<PreludeError> for ResetFacadeError {
    fn from(value: PreludeError) -> Self {
        Self::Prelude(value)
    }
}

#[cfg(not(test))]
impl From<AuthPrimitiveError> for ResetFacadeError {
    fn from(value: AuthPrimitiveError) -> Self {
        Self::Primitive(value)
    }
}

#[cfg(not(test))]
impl From<StateMachineError> for ResetFacadeError {
    fn from(value: StateMachineError) -> Self {
        Self::StateMachine(value)
    }
}

#[cfg(not(test))]
impl From<ExecutionContextHydrationError> for ResetFacadeError {
    fn from(value: ExecutionContextHydrationError) -> Self {
        Self::ExecutionContext(value)
    }
}

#[cfg(not(test))]
impl From<ExecutorError> for ResetFacadeError {
    fn from(value: ExecutorError) -> Self {
        Self::Executor(value)
    }
}

#[cfg(not(test))]
impl From<sqlx::Error> for ResetFacadeError {
    fn from(value: sqlx::Error) -> Self {
        Self::Database(value)
    }
}

/// Generated-DTO-validated response bytes retained by the sealed Reset graph.
///
/// The handler may pass these exact bytes to operation completion but cannot
/// assemble or alter Reset response fields.
#[cfg(not(test))]
#[derive(Debug)]
pub(crate) struct ResetCanonicalResponse {
    endpoint: ResetOperationEndpoint,
    bytes: Box<[u8]>,
    binding_digest: [u8; 32],
}

#[cfg(not(test))]
impl ResetCanonicalResponse {
    pub(crate) fn endpoint(&self) -> ResetOperationEndpoint {
        self.endpoint
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn status(&self) -> i32 {
        200
    }

    pub(crate) fn sha256(&self) -> [u8; 32] {
        Sha256::digest(&self.bytes).into()
    }

    fn request(
        entry_json: &[u8],
        reset_request_id: Uuid,
        conversation_id: Uuid,
        requester_did: &str,
        requester_device_id: Uuid,
        prior: &PublicGroupSnapshotCoordinate,
        reason: &str,
        requested_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, ResetFacadeError> {
        let output: chat_dto::request_reset::RequestResetOutput<DefaultStr> =
            serde_json::from_value(json!({
                "entry": parse_json(entry_json)?,
                "resetRequest": {
                    "resetRequestId": reset_request_id.hyphenated().to_string(),
                    "conversationId": conversation_id.hyphenated().to_string(),
                    "requesterDid": requester_did,
                    "requesterDeviceId": requester_device_id.hyphenated().to_string(),
                    "prior": coordinate_json(prior)?,
                    "reason": reason,
                    "status": "pending",
                    "requestedAt": canonical_datetime(requested_at),
                    "expiresAt": canonical_datetime(expires_at),
                },
            }))
            .map_err(|_| ResetFacadeError::InvalidCanonicalMaterial)?;
        let bytes =
            serde_json::to_vec(&output).map_err(|_| ResetFacadeError::InvalidCanonicalMaterial)?;
        Self::new(ResetOperationEndpoint::RequestReset, bytes)
    }

    fn activation(
        entry_json: &[u8],
        retired: &PublicGroupSnapshotCoordinate,
        successor: &PublicGroupSnapshotCoordinate,
    ) -> Result<Self, ResetFacadeError> {
        let output: chat_dto::activate_reset::ActivateResetOutput<DefaultStr> =
            serde_json::from_value(json!({
                "entry": parse_json(entry_json)?,
                "retiredCoordinates": coordinate_json(retired)?,
                "successorCoordinates": coordinate_json(successor)?,
            }))
            .map_err(|_| ResetFacadeError::InvalidCanonicalMaterial)?;
        let bytes =
            serde_json::to_vec(&output).map_err(|_| ResetFacadeError::InvalidCanonicalMaterial)?;
        Self::new(ResetOperationEndpoint::ActivateReset, bytes)
    }

    fn new(endpoint: ResetOperationEndpoint, bytes: Vec<u8>) -> Result<Self, ResetFacadeError> {
        if bytes.is_empty() {
            return Err(ResetFacadeError::InvalidCanonicalMaterial);
        }
        let mut digest = Sha256::new();
        digest.update(b"CATBIRD-CHAT-RESET-CANONICAL-RESPONSE\0");
        digest.update(match endpoint {
            ResetOperationEndpoint::RequestReset => b"request".as_slice(),
            ResetOperationEndpoint::ActivateReset => b"activation".as_slice(),
        });
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(&bytes);
        Ok(Self {
            endpoint,
            bytes: bytes.into_boxed_slice(),
            binding_digest: digest.finalize().into(),
        })
    }

    fn matches(&self, endpoint: ResetOperationEndpoint, bytes: &[u8]) -> bool {
        if self.endpoint != endpoint || self.bytes.as_ref() != bytes {
            return false;
        }
        let mut digest = Sha256::new();
        digest.update(b"CATBIRD-CHAT-RESET-CANONICAL-RESPONSE\0");
        digest.update(match endpoint {
            ResetOperationEndpoint::RequestReset => b"request".as_slice(),
            ResetOperationEndpoint::ActivateReset => b"activation".as_slice(),
        });
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(bytes);
        self.binding_digest == <[u8; 32]>::from(digest.finalize())
    }
}

/// Linear first-execution completion authority returned only after the Reset
/// executor has applied inside the caller-owned transaction.
#[cfg(not(test))]
pub(crate) struct ResetCompletion {
    authority: VerifiedChatDeviceRequest,
    scope_authority: ScopeBoundBusinessAuthority,
    completion: OperationCompletionGuard,
}

#[cfg(not(test))]
impl ResetCompletion {
    pub(crate) fn into_parts(
        self,
    ) -> (
        VerifiedChatDeviceRequest,
        ScopeBoundBusinessAuthority,
        OperationCompletionGuard,
    ) {
        (self.authority, self.scope_authority, self.completion)
    }
}

#[cfg(not(test))]
pub(crate) struct AppliedResetOperation {
    applied: AppliedTransition,
    completion: ResetCompletion,
    response: ResetCanonicalResponse,
}

#[cfg(not(test))]
impl AppliedResetOperation {
    pub(crate) fn response(&self) -> &ResetCanonicalResponse {
        &self.response
    }

    pub(crate) fn event_position(&self) -> Option<i64> {
        self.applied.event_positions.first().copied()
    }

    pub(crate) fn into_parts(self) -> (AppliedTransition, ResetCompletion, ResetCanonicalResponse) {
        (self.applied, self.completion, self.response)
    }
}

#[cfg(not(test))]
pub(crate) enum ResetTransactionOutcome {
    First(AppliedResetOperation),
    Replay(CompletedIdempotentResponse),
}

#[cfg(not(test))]
struct PreparedResetExecutionGraph {
    plan: ConversationPersistencePlan,
    artifacts: ExecutionContextArtifacts,
    response: ResetCanonicalResponse,
}

#[cfg(not(test))]
impl PreparedResetExecutionGraph {
    fn new(
        plan: ConversationPersistencePlan,
        artifacts: ExecutionContextArtifacts,
        response: ResetCanonicalResponse,
    ) -> Result<Self, ResetFacadeError> {
        let expected = match plan.effects().kind() {
            PlanKind::ResetRequest => ResetOperationEndpoint::RequestReset,
            PlanKind::ResetActivation => ResetOperationEndpoint::ActivateReset,
            _ => return Err(ResetFacadeError::InvalidCanonicalMaterial),
        };
        if response.endpoint() != expected
            || !response.matches(expected, response.as_bytes())
            || artifacts.accepted_control_entry_bytes.is_none()
            || artifacts.primary_event_payload.is_none()
            || !artifacts.welcome_disposition_event_payloads.is_empty()
            || (expected == ResetOperationEndpoint::RequestReset
                && artifacts.genesis_group_info_bytes.is_some())
            || (expected == ResetOperationEndpoint::ActivateReset
                && artifacts.genesis_group_info_bytes.is_none())
        {
            return Err(ResetFacadeError::InvalidCanonicalMaterial);
        }
        Ok(Self {
            plan,
            artifacts,
            response,
        })
    }

    async fn apply(
        self,
        transaction: &mut Transaction<'_, Postgres>,
    ) -> Result<(AppliedTransition, ResetCanonicalResponse), ResetFacadeError> {
        let Self {
            plan,
            artifacts,
            response,
        } = self;
        let prepared = hydrate_execution_context(transaction, &plan, artifacts).await?;
        let applied =
            crate::chat_protocol::state_machine::executor::apply_conversation_persistence_plan(
                prepared,
            )
            .await?;
        Ok((applied, response))
    }
}

#[cfg(not(test))]
fn parse_json(bytes: &[u8]) -> Result<JsonValue, ResetFacadeError> {
    serde_json::from_slice(bytes).map_err(|_| ResetFacadeError::InvalidCanonicalMaterial)
}

#[cfg(not(test))]
fn canonical_datetime(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}

#[cfg(not(test))]
fn coordinate_json(
    coordinate: &PublicGroupSnapshotCoordinate,
) -> Result<JsonValue, ResetFacadeError> {
    use base64::{engine::general_purpose::STANDARD, Engine};

    let generation = i64::try_from(coordinate.generation())
        .map_err(|_| ResetFacadeError::InvalidCanonicalMaterial)?;
    let state_version = i64::try_from(coordinate.state_version())
        .map_err(|_| ResetFacadeError::InvalidCanonicalMaterial)?;
    let epoch = i64::try_from(coordinate.epoch())
        .map_err(|_| ResetFacadeError::InvalidCanonicalMaterial)?;
    let lifecycle = match coordinate.lifecycle() {
        PublicGroupSnapshotLifecycle::Active => "active",
        PublicGroupSnapshotLifecycle::Superseded => "superseded",
    };
    Ok(json!({
        "conversationId": Uuid::from_bytes(*coordinate.conversation_id()).hyphenated().to_string(),
        "generation": generation,
        "stateVersion": state_version,
        "groupId": STANDARD.encode(coordinate.group_id()),
        "epoch": epoch,
        "groupContextHash": STANDARD.encode(coordinate.group_context_hash()),
        "confirmationTag": STANDARD.encode(coordinate.confirmation_tag()),
        "lifecycle": lifecycle,
    }))
}

#[derive(Debug, FromRow)]
struct PendingResetRow {
    reset_request_id: Uuid,
    conversation_id: Uuid,
    requester_did: String,
    requester_device_id: Uuid,
    requester_key_id: String,
    requester_auth_generation: i64,
    prior_generation: i64,
    prior_state_version: i64,
    prior_group_id: Vec<u8>,
    prior_epoch: i64,
    prior_group_context_hash: Vec<u8>,
    prior_confirmation_tag: Vec<u8>,
    reason: String,
    status: String,
    signed_request_bytes: Vec<u8>,
    signing_transcript_bytes: Vec<u8>,
    request_digest: Vec<u8>,
    signature: Vec<u8>,
    received_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    terminal_transition_id: Option<Uuid>,
    terminal_at: Option<DateTime<Utc>>,
}

#[cfg(not(test))]
#[derive(Debug, FromRow)]
struct ResetReplayHeadRow {
    kind: String,
    lifecycle: String,
    current_generation: i64,
    current_state_version: i64,
    next_entry_seq: i64,
}

#[cfg(not(test))]
#[derive(Debug, FromRow)]
struct ResetReplayEntryRow {
    seq: i64,
    entry_id: Uuid,
    accepted_payload_bytes: Vec<u8>,
    accepted_payload_sha256: Vec<u8>,
    signed_request_bytes: Vec<u8>,
    request_digest: Vec<u8>,
    signature: Vec<u8>,
    server_fields_bytes: Vec<u8>,
    outer_entry_fingerprint: Vec<u8>,
    actor_did: String,
    actor_device_id: Uuid,
    actor_key_id: String,
    actor_auth_generation: i64,
    generation: Option<i64>,
    state_version: Option<i64>,
    transition_id: Option<Uuid>,
    received_at: DateTime<Utc>,
}

#[cfg(not(test))]
#[derive(Debug, FromRow)]
struct ResetReplayTransitionRow {
    transition_id: Uuid,
    conversation_id: Uuid,
    kind: String,
    actor_did: String,
    actor_device_id: Uuid,
    actor_key_id: String,
    actor_auth_generation: i64,
    actor_role: String,
    actor_device_status: String,
    signed_request_bytes: Vec<u8>,
    unsigned_projection_bytes: Vec<u8>,
    signing_transcript_bytes: Vec<u8>,
    request_digest: Vec<u8>,
    signature: Vec<u8>,
    prior_generation: Option<i64>,
    prior_state_version: Option<i64>,
    next_generation: Option<i64>,
    next_state_version: Option<i64>,
    retired_generation: Option<i64>,
    retired_state_version: Option<i64>,
    successor_generation: Option<i64>,
    successor_state_version: Option<i64>,
    reset_request_id: Option<Uuid>,
    entry_seq: i64,
    accepted_at: DateTime<Utc>,
}

#[cfg(not(test))]
#[derive(Debug, FromRow)]
struct ResetReplayGenerationRow {
    group_id: Vec<u8>,
    genesis_group_info_bytes: Vec<u8>,
    genesis_group_info_sha256: Vec<u8>,
    activated_seq: i64,
    activated_at: DateTime<Utc>,
}

#[cfg(not(test))]
#[derive(Debug, FromRow)]
struct ResetReplaySuccessorRow {
    group_id: Vec<u8>,
    epoch: i64,
    group_context_hash: Vec<u8>,
    confirmation_tag: Vec<u8>,
    lifecycle: String,
    state_kind: String,
    producing_transition_id: Uuid,
    created_at: DateTime<Utc>,
}

/// Reset-owned, private-constructor replay proof. Prelude can inspect the
/// complete binding but cannot mint one or substitute loose endpoint facts.
#[cfg(not(test))]
pub(in crate::chat_protocol::repository) struct ResetReplayPostStateProof {
    transaction_id: Box<str>,
    operation_id: Uuid,
    principal_did: Box<str>,
    endpoint_nsid: Box<str>,
    mutation_kind: SignedMutationKind,
    request_digest: [u8; 32],
    accepted_request_sha256: [u8; 32],
    signature: [u8; 64],
    post_state_digest: [u8; 32],
    expected_response_status: i32,
    expected_response_sha256: [u8; 32],
    seal_digest: [u8; 32],
}

#[cfg(not(test))]
impl ResetReplayPostStateProof {
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
        &self.endpoint_nsid
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

    pub(in crate::chat_protocol::repository) fn post_state_digest(&self) -> &[u8; 32] {
        &self.post_state_digest
    }

    pub(in crate::chat_protocol::repository) fn expected_response_status(&self) -> i32 {
        self.expected_response_status
    }

    pub(in crate::chat_protocol::repository) fn expected_response_sha256(&self) -> &[u8; 32] {
        &self.expected_response_sha256
    }

    pub(in crate::chat_protocol::repository) fn validates_seal(&self) -> bool {
        self.post_state_digest != [0; 32]
            && self.expected_response_sha256 != [0; 32]
            && self.seal_digest
                == reset_replay_seal(
                    &self.transaction_id,
                    self.operation_id,
                    &self.principal_did,
                    &self.endpoint_nsid,
                    self.mutation_kind,
                    &self.request_digest,
                    &self.accepted_request_sha256,
                    &self.signature,
                    &self.post_state_digest,
                    self.expected_response_status,
                    &self.expected_response_sha256,
                )
    }
}

/// Exact immutable pending Reset row plus its requester device/key bindings.
/// There is no public or test reseal constructor.
#[must_use]
#[derive(Debug)]
pub(crate) struct LockedPendingResetRequestGuard {
    transaction_id: Box<str>,
    trusted_instant: DateTime<Utc>,
    scope_digest: [u8; 32],
    head_digest: [u8; 32],
    reset_request_id: Uuid,
    conversation_id: Uuid,
    requester_did: Box<str>,
    requester_device_id: Uuid,
    requester_key_id: Box<str>,
    requester_auth_generation: i64,
    prior: PublicGroupSnapshotCoordinate,
    reason: Box<str>,
    signed_request_bytes: Box<[u8]>,
    signing_transcript_bytes: Box<[u8]>,
    request_digest: [u8; 32],
    signature: [u8; 64],
    received_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    requester_device_digest: [u8; 32],
    requester_key_digest: [u8; 32],
    immutable_row_digest: [u8; 32],
    authorized_terminal: SealedResetTerminal,
    guard_digest: [u8; 32],
}

impl LockedPendingResetRequestGuard {
    pub(crate) fn reset_request_id(&self) -> Uuid {
        self.reset_request_id
    }

    pub(crate) fn conversation_id(&self) -> Uuid {
        self.conversation_id
    }

    pub(crate) fn prior(&self) -> &PublicGroupSnapshotCoordinate {
        &self.prior
    }

    pub(crate) fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub(crate) fn trusted_instant(&self) -> DateTime<Utc> {
        self.trusted_instant
    }

    pub(crate) fn guard_digest(&self) -> &[u8; 32] {
        &self.guard_digest
    }
}

#[derive(Debug)]
pub(crate) enum LockedResetRequestDisposition {
    Vacant,
    Pending(LockedPendingResetRequestGuard),
    ExpiredReplacement(LockedPendingResetRequestGuard),
}

#[must_use]
#[derive(Debug)]
pub(crate) struct LockedResetRequestAuthority {
    prelude: PreparedBusinessPrelude,
    aggregate: LockedConversationStateGuard,
    transaction_id: Box<str>,
    trusted_instant: DateTime<Utc>,
    operation_id: Uuid,
    incoming_request_digest: [u8; 32],
    admitted_mutation_digest: [u8; 32],
    actor_did: Box<str>,
    actor_device_id: Uuid,
    actor_key_id: Box<str>,
    actor_auth_generation: i64,
    actor_signing_public_key: Box<[u8]>,
    actor_dpop_jkt: Option<Box<str>>,
    scope_digest: [u8; 32],
    head_digest: [u8; 32],
    admission_digest: [u8; 32],
    disposition: LockedResetRequestDisposition,
}

impl LockedResetRequestAuthority {
    pub(crate) fn disposition(&self) -> &LockedResetRequestDisposition {
        &self.disposition
    }

    pub(crate) fn plan_vacant_reset_request_entry(
        self,
        mutation: &VerifiedSignedMutation,
        entry: VerifiedControlEntry,
    ) -> Result<(PlannedTransition, PreparedBusinessPrelude), ResetCompositionError> {
        if !matches!(self.disposition, LockedResetRequestDisposition::Vacant) {
            return Err(ResetRepositoryError::PendingResetAlreadyExists.into());
        }
        validate_sealed_admission(
            self.prelude.scope_authority(),
            mutation,
            SignedMutationKind::ResetRequest,
            self.operation_id,
            &self.incoming_request_digest,
            &self.admitted_mutation_digest,
            &self.actor_did,
            self.actor_device_id,
            &self.actor_key_id,
            self.actor_auth_generation,
            &self.actor_signing_public_key,
            self.actor_dpop_jkt.as_deref(),
            &self.transaction_id,
            self.trusted_instant,
            &self.scope_digest,
            &self.head_digest,
            &self.admission_digest,
        )?;
        validate_control_entry_mutation(&entry, mutation)?;
        let plan =
            plan_reset_request_entry(&self.aggregate, self.prelude.scope_authority(), entry)?;
        Ok((plan, self.prelude))
    }
}

#[must_use]
#[derive(Debug)]
pub(crate) struct LockedResetActivationAuthority {
    prelude: PreparedBusinessPrelude,
    aggregate: LockedConversationStateGuard,
    transaction_id: Box<str>,
    trusted_instant: DateTime<Utc>,
    operation_id: Uuid,
    incoming_request_digest: [u8; 32],
    admitted_mutation_digest: [u8; 32],
    actor_did: Box<str>,
    actor_device_id: Uuid,
    actor_key_id: Box<str>,
    actor_auth_generation: i64,
    actor_signing_public_key: Box<[u8]>,
    actor_dpop_jkt: Option<Box<str>>,
    scope_digest: [u8; 32],
    head_digest: [u8; 32],
    admission_digest: [u8; 32],
    request: LockedPendingResetRequestGuard,
    terminal_packages: Vec<LockedRecoveryPackageGuard>,
}

impl LockedResetActivationAuthority {
    pub(crate) fn request(&self) -> &LockedPendingResetRequestGuard {
        &self.request
    }

    pub(crate) fn plan_reset_activation_entry(
        self,
        mutation: &VerifiedSignedMutation,
        entry: VerifiedControlEntry,
    ) -> Result<
        (
            PlannedTransition,
            LockedPendingResetRequestGuard,
            PreparedBusinessPrelude,
        ),
        ResetCompositionError,
    > {
        validate_sealed_admission(
            self.prelude.scope_authority(),
            mutation,
            SignedMutationKind::ResetActivation,
            self.operation_id,
            &self.incoming_request_digest,
            &self.admitted_mutation_digest,
            &self.actor_did,
            self.actor_device_id,
            &self.actor_key_id,
            self.actor_auth_generation,
            &self.actor_signing_public_key,
            self.actor_dpop_jkt.as_deref(),
            &self.transaction_id,
            self.trusted_instant,
            &self.scope_digest,
            &self.head_digest,
            &self.admission_digest,
        )?;
        validate_control_entry_mutation(&entry, mutation)?;
        let plan = plan_reset_activation_entry(
            &self.aggregate,
            self.prelude.scope_authority(),
            entry,
            self.terminal_packages,
        )?;
        Ok((plan, self.request, self.prelude))
    }
}

#[must_use]
#[derive(Debug)]
pub(crate) struct ExpiredResetReplacementProof {
    prelude: PreparedBusinessPrelude,
    aggregate: LockedConversationStateGuard,
    transaction_id: Box<str>,
    trusted_instant: DateTime<Utc>,
    expired_request_id: Uuid,
    incoming_operation_id: Uuid,
    incoming_request_digest: [u8; 32],
    admitted_mutation_digest: [u8; 32],
    actor_did: Box<str>,
    actor_device_id: Uuid,
    actor_key_id: Box<str>,
    actor_auth_generation: i64,
    actor_signing_public_key: Box<[u8]>,
    actor_dpop_jkt: Option<Box<str>>,
    scope_digest: [u8; 32],
    head_digest: [u8; 32],
    admission_digest: [u8; 32],
}

impl ExpiredResetReplacementProof {
    pub(crate) fn expired_request_id(&self) -> Uuid {
        self.expired_request_id
    }

    pub(crate) fn transaction_id(&self) -> &str {
        &self.transaction_id
    }

    pub(crate) fn trusted_instant(&self) -> DateTime<Utc> {
        self.trusted_instant
    }

    pub(crate) fn incoming_operation_id(&self) -> Uuid {
        self.incoming_operation_id
    }

    pub(crate) fn admission_digest(&self) -> &[u8; 32] {
        &self.admission_digest
    }

    pub(crate) fn authorizes_replacement(&self, mutation: &VerifiedSignedMutation) -> bool {
        validate_sealed_admission(
            self.prelude.scope_authority(),
            mutation,
            SignedMutationKind::ResetRequest,
            self.incoming_operation_id,
            &self.incoming_request_digest,
            &self.admitted_mutation_digest,
            &self.actor_did,
            self.actor_device_id,
            &self.actor_key_id,
            self.actor_auth_generation,
            &self.actor_signing_public_key,
            self.actor_dpop_jkt.as_deref(),
            &self.transaction_id,
            self.trusted_instant,
            &self.scope_digest,
            &self.head_digest,
            &self.admission_digest,
        )
        .is_ok()
    }

    pub(crate) fn plan_replacement_reset_request_entry(
        self,
        mutation: &VerifiedSignedMutation,
        entry: VerifiedControlEntry,
    ) -> Result<(PlannedTransition, PreparedBusinessPrelude), ResetCompositionError> {
        validate_sealed_admission(
            self.prelude.scope_authority(),
            mutation,
            SignedMutationKind::ResetRequest,
            self.incoming_operation_id,
            &self.incoming_request_digest,
            &self.admitted_mutation_digest,
            &self.actor_did,
            self.actor_device_id,
            &self.actor_key_id,
            self.actor_auth_generation,
            &self.actor_signing_public_key,
            self.actor_dpop_jkt.as_deref(),
            &self.transaction_id,
            self.trusted_instant,
            &self.scope_digest,
            &self.head_digest,
            &self.admission_digest,
        )?;
        validate_control_entry_mutation(&entry, mutation)?;
        let plan =
            plan_reset_request_entry(&self.aggregate, self.prelude.scope_authority(), entry)?;
        Ok((plan, self.prelude))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SealedResetTerminal {
    Unavailable,
    Consumed { transition_id: Uuid },
    Stale { transition_id: Uuid },
    Expired,
}

#[derive(Clone, Copy)]
enum ResetPreparationKind {
    Request,
    Activation,
}

struct ParsedResetAuthority {
    kind: ResetPreparationKind,
    operation_id: Uuid,
    reset_request_id: Uuid,
    prior: PublicGroupSnapshotCoordinate,
}

struct PreparedResetReadSet {
    prelude: PreparedBusinessPrelude,
    aggregate: LockedConversationStateGuard,
    transaction_id: String,
    trusted_instant: DateTime<Utc>,
    operation_id: Uuid,
    incoming_request_digest: [u8; 32],
    admitted_mutation_digest: [u8; 32],
    actor_did: String,
    actor_device_id: Uuid,
    actor_key_id: String,
    actor_auth_generation: i64,
    actor_signing_public_key: Vec<u8>,
    actor_dpop_jkt: Option<String>,
    scope_digest: [u8; 32],
    head_digest: [u8; 32],
    pending: Option<LockedPendingResetRequestGuard>,
}

struct PreparedResetAttempt {
    aggregate: LockedConversationStateGuard,
    transaction_id: String,
    trusted_instant: DateTime<Utc>,
    operation_id: Uuid,
    incoming_request_digest: [u8; 32],
    admitted_mutation_digest: [u8; 32],
    actor_did: String,
    actor_device_id: Uuid,
    actor_key_id: String,
    actor_auth_generation: i64,
    actor_signing_public_key: Vec<u8>,
    actor_dpop_jkt: Option<String>,
    scope_digest: [u8; 32],
    head_digest: [u8; 32],
    pending: Option<LockedPendingResetRequestGuard>,
}

pub(crate) async fn prepare_reset_request_authority(
    transaction: &mut Transaction<'_, Postgres>,
    prelude: PreparedBusinessPrelude,
    authority: &VerifiedSignedMutation,
) -> Result<LockedResetRequestAuthority, ResetRepositoryError> {
    let parsed = parse_reset_authority(authority, ResetPreparationKind::Request)?;
    let prelude = prelude
        .verify_reset_operation(
            ResetOperationEndpoint::RequestReset,
            parsed.operation_id,
            authority,
        )
        .map_err(|_| ResetRepositoryError::NonCanonicalOperation)?;
    let prepared = prepare_reset_read_set(transaction, prelude, authority, &parsed).await?;
    finish_reset_request_authority(prepared)
}

fn finish_reset_request_authority(
    prepared: PreparedResetReadSet,
) -> Result<LockedResetRequestAuthority, ResetRepositoryError> {
    let disposition = match prepared.pending {
        None => LockedResetRequestDisposition::Vacant,
        Some(guard)
            if classify_pending_reset_at(prepared.trusted_instant, guard.expires_at())
                == PendingResetTimeState::Live =>
        {
            return Err(ResetRepositoryError::PendingResetAlreadyExists);
        }
        Some(guard) => LockedResetRequestDisposition::ExpiredReplacement(guard),
    };
    let admission_digest = reset_admission_digest(
        prepared.operation_id,
        &prepared.incoming_request_digest,
        &prepared.actor_did,
        prepared.actor_device_id,
        &prepared.actor_key_id,
        prepared.actor_auth_generation,
        prepared.trusted_instant,
        &prepared.scope_digest,
        &prepared.head_digest,
    );
    Ok(LockedResetRequestAuthority {
        prelude: prepared.prelude,
        aggregate: prepared.aggregate,
        transaction_id: prepared.transaction_id.into_boxed_str(),
        trusted_instant: prepared.trusted_instant,
        operation_id: prepared.operation_id,
        incoming_request_digest: prepared.incoming_request_digest,
        admitted_mutation_digest: prepared.admitted_mutation_digest,
        actor_did: prepared.actor_did.into_boxed_str(),
        actor_device_id: prepared.actor_device_id,
        actor_key_id: prepared.actor_key_id.into_boxed_str(),
        actor_auth_generation: prepared.actor_auth_generation,
        actor_signing_public_key: prepared.actor_signing_public_key.into_boxed_slice(),
        actor_dpop_jkt: prepared.actor_dpop_jkt.map(String::into_boxed_str),
        scope_digest: prepared.scope_digest,
        head_digest: prepared.head_digest,
        admission_digest,
        disposition,
    })
}

#[cfg(test)]
pub(crate) async fn prepare_reset_request_authority_with_probe_for_test(
    transaction: &mut Transaction<'_, Postgres>,
    prelude: PreparedBusinessPrelude,
    authority: &VerifiedSignedMutation,
    probe: &mut ResetPrepareProbeForTest,
) -> Result<LockedResetRequestAuthority, ResetRepositoryError> {
    let parsed = parse_reset_authority(authority, ResetPreparationKind::Request)?;
    let prelude = prelude
        .verify_reset_operation(
            ResetOperationEndpoint::RequestReset,
            parsed.operation_id,
            authority,
        )
        .map_err(|_| ResetRepositoryError::NonCanonicalOperation)?;
    let prepared =
        prepare_reset_read_set_with_probe(transaction, prelude, authority, &parsed, probe).await?;
    finish_reset_request_authority(prepared)
}

pub(crate) async fn prepare_reset_activation_authority(
    transaction: &mut Transaction<'_, Postgres>,
    prelude: PreparedBusinessPrelude,
    authority: &VerifiedSignedMutation,
) -> Result<LockedResetActivationAuthority, ResetRepositoryError> {
    let parsed = parse_reset_authority(authority, ResetPreparationKind::Activation)?;
    let prelude = prelude
        .verify_reset_operation(
            ResetOperationEndpoint::ActivateReset,
            parsed.operation_id,
            authority,
        )
        .map_err(|_| ResetRepositoryError::NonCanonicalOperation)?;
    let prepared = prepare_reset_read_set(transaction, prelude, authority, &parsed).await?;
    let request = prepared
        .pending
        .ok_or(ResetRepositoryError::PendingResetNotFound)?;
    if request.reset_request_id() != parsed.reset_request_id {
        return Err(ResetRepositoryError::PendingResetNotFound);
    }
    if request.prior() != &parsed.prior {
        return Err(ResetRepositoryError::PendingResetCoordinateMismatch);
    }
    if classify_pending_reset_at(prepared.trusted_instant, request.expires_at())
        == PendingResetTimeState::Expired
    {
        return Err(ResetRepositoryError::PendingResetExpired);
    }
    let mut terminal_packages = Vec::new();
    for recovery in prepared.aggregate.state().recovery_requests() {
        if recovery.status() == crate::chat_protocol::state_machine::RecoveryRequestStatus::Open {
            terminal_packages.push(
                hydrate_locked_reserved_recovery_package(
                    transaction,
                    prepared.aggregate.head(),
                    Uuid::from_bytes(*recovery.request_id()),
                )
                .await
                .map_err(|_| ResetRepositoryError::GuardInvariant)?,
            );
        }
    }
    let admission_digest = reset_admission_digest(
        prepared.operation_id,
        &prepared.incoming_request_digest,
        &prepared.actor_did,
        prepared.actor_device_id,
        &prepared.actor_key_id,
        prepared.actor_auth_generation,
        prepared.trusted_instant,
        &prepared.scope_digest,
        &prepared.head_digest,
    );
    Ok(LockedResetActivationAuthority {
        prelude: prepared.prelude,
        aggregate: prepared.aggregate,
        transaction_id: prepared.transaction_id.into_boxed_str(),
        trusted_instant: prepared.trusted_instant,
        operation_id: prepared.operation_id,
        incoming_request_digest: prepared.incoming_request_digest,
        admitted_mutation_digest: prepared.admitted_mutation_digest,
        actor_did: prepared.actor_did.into_boxed_str(),
        actor_device_id: prepared.actor_device_id,
        actor_key_id: prepared.actor_key_id.into_boxed_str(),
        actor_auth_generation: prepared.actor_auth_generation,
        actor_signing_public_key: prepared.actor_signing_public_key.into_boxed_slice(),
        actor_dpop_jkt: prepared.actor_dpop_jkt.map(String::into_boxed_str),
        scope_digest: prepared.scope_digest,
        head_digest: prepared.head_digest,
        admission_digest,
        request,
        terminal_packages,
    })
}

pub(crate) async fn expire_pending_reset_for_replacement(
    transaction: &mut Transaction<'_, Postgres>,
    authority: LockedResetRequestAuthority,
) -> Result<ExpiredResetReplacementProof, ResetRepositoryError> {
    let LockedResetRequestAuthority {
        prelude,
        transaction_id,
        trusted_instant,
        operation_id,
        incoming_request_digest,
        admitted_mutation_digest,
        actor_did,
        actor_device_id,
        actor_key_id,
        actor_auth_generation,
        actor_signing_public_key,
        actor_dpop_jkt,
        scope_digest,
        head_digest,
        admission_digest,
        disposition,
        aggregate: _,
    } = authority;
    let guard = match disposition {
        LockedResetRequestDisposition::ExpiredReplacement(guard) => guard,
        LockedResetRequestDisposition::Pending(_) | LockedResetRequestDisposition::Vacant => {
            return Err(ResetRepositoryError::PendingResetNotExpired);
        }
    };
    ensure_live_transaction(transaction, &transaction_id).await?;
    if trusted_instant < guard.expires_at() {
        return Err(ResetRepositoryError::PendingResetNotExpired);
    }
    let expired_request_id = guard.reset_request_id();
    let conversation_id = guard.conversation_id();
    terminalize_locked_reset_request(transaction, guard).await?;
    let aggregate =
        hydrate_locked_conversation_state(transaction, conversation_id, trusted_instant)
            .await
            .map_err(map_aggregate_error)?;
    if aggregate.head().transaction_id() != &*transaction_id
        || aggregate.head().durable_row_digest() != &head_digest
    {
        return Err(ResetRepositoryError::GuardInvariant);
    }
    Ok(ExpiredResetReplacementProof {
        prelude,
        aggregate,
        transaction_id,
        trusted_instant,
        expired_request_id,
        incoming_operation_id: operation_id,
        incoming_request_digest,
        admitted_mutation_digest,
        actor_did,
        actor_device_id,
        actor_key_id,
        actor_auth_generation,
        actor_signing_public_key,
        actor_dpop_jkt,
        scope_digest,
        head_digest,
        admission_digest,
    })
}

pub(crate) async fn terminalize_locked_reset_request(
    transaction: &mut Transaction<'_, Postgres>,
    guard: LockedPendingResetRequestGuard,
) -> Result<(), ResetRepositoryError> {
    ensure_live_transaction(transaction, &guard.transaction_id).await?;
    validate_locked_pending_reset_digest(
        &guard.guard_digest,
        &guard.transaction_id,
        guard.trusted_instant,
        &guard.scope_digest,
        &guard.head_digest,
        &guard.immutable_row_digest,
        &guard.requester_device_digest,
        &guard.requester_key_digest,
        guard.authorized_terminal,
    )?;
    match guard.authorized_terminal {
        SealedResetTerminal::Unavailable => {
            return Err(ResetRepositoryError::AuthorityBindingMismatch);
        }
        SealedResetTerminal::Expired if guard.trusted_instant < guard.expires_at => {
            return Err(ResetRepositoryError::PendingResetNotExpired);
        }
        SealedResetTerminal::Consumed { transition_id }
        | SealedResetTerminal::Stale { transition_id }
            if !uuid_v4(transition_id) =>
        {
            return Err(ResetRepositoryError::NonCanonicalOperation);
        }
        SealedResetTerminal::Consumed { .. } | SealedResetTerminal::Stale { .. }
            if guard.trusted_instant >= guard.expires_at =>
        {
            return Err(ResetRepositoryError::PendingResetExpired);
        }
        _ => {}
    }
    cas_terminalize(transaction, &guard, guard.authorized_terminal).await
}

#[cfg(not(test))]
async fn lock_reset_replay_post_state(
    transaction: &mut Transaction<'_, Postgres>,
    locked: &LockedSignedOperationReplayAuthority,
) -> Result<ResetReplayPostStateProof, ResetFacadeError> {
    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await?;
    let replay = locked.authority();
    let mutation = replay.mutation();
    let expected = match mutation.kind() {
        SignedMutationKind::ResetRequest => ResetPreparationKind::Request,
        SignedMutationKind::ResetActivation => ResetPreparationKind::Activation,
        _ => return Err(ResetFacadeError::UnsupportedMutation),
    };
    let parsed = parse_reset_authority(mutation, expected)?;
    let conversation_id = Uuid::from_bytes(*parsed.prior.conversation_id());
    let head: ResetReplayHeadRow = sqlx::query_as(
        r#"
        SELECT kind,lifecycle,current_generation,current_state_version,next_entry_seq
          FROM chat.conversations
         WHERE conversation_id=$1
         FOR UPDATE
        "#,
    )
    .bind(conversation_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(ResetRepositoryError::ConversationMissing)?;
    if !matches!(head.kind.as_str(), "direct" | "group")
        || !matches!(head.lifecycle.as_str(), "active" | "superseded")
        || head.current_generation < 0
        || head.current_state_version < 0
        || head.next_entry_seq < 2
    {
        return Err(ResetFacadeError::InvalidCanonicalMaterial);
    }

    let (post_state_digest, response) = match expected {
        ResetPreparationKind::Request => {
            lock_reset_request_replay_rows(transaction, mutation, &parsed, &head).await?
        }
        ResetPreparationKind::Activation => {
            lock_reset_activation_replay_rows(transaction, mutation, &parsed, &head).await?
        }
    };
    let raw = mutation
        .accepted_wrapper_bytes()
        .ok_or(ResetFacadeError::InvalidCanonicalMaterial)?;
    let expected_response_status = response.status();
    let expected_response_sha256 = response.sha256();
    let endpoint_nsid = match expected {
        ResetPreparationKind::Request => "blue.catbird.chat.requestReset",
        ResetPreparationKind::Activation => "blue.catbird.chat.activateReset",
    };
    if replay.endpoint().as_str() != endpoint_nsid
        || response.endpoint()
            != match expected {
                ResetPreparationKind::Request => ResetOperationEndpoint::RequestReset,
                ResetPreparationKind::Activation => ResetOperationEndpoint::ActivateReset,
            }
    {
        return Err(ResetFacadeError::InvalidCanonicalMaterial);
    }
    let accepted_request_sha256: [u8; 32] = Sha256::digest(raw).into();
    let seal_digest = reset_replay_seal(
        &transaction_id,
        parsed.operation_id,
        replay.subject().as_str(),
        endpoint_nsid,
        mutation.kind(),
        mutation.request_digest(),
        &accepted_request_sha256,
        mutation.signature(),
        &post_state_digest,
        expected_response_status,
        &expected_response_sha256,
    );
    let proof = ResetReplayPostStateProof {
        transaction_id: transaction_id.into_boxed_str(),
        operation_id: parsed.operation_id,
        principal_did: replay.subject().as_str().to_owned().into_boxed_str(),
        endpoint_nsid: endpoint_nsid.into(),
        mutation_kind: mutation.kind(),
        request_digest: *mutation.request_digest(),
        accepted_request_sha256,
        signature: *mutation.signature(),
        post_state_digest,
        expected_response_status,
        expected_response_sha256,
        seal_digest,
    };
    if !proof.validates_seal() {
        return Err(ResetFacadeError::InvalidCanonicalMaterial);
    }
    Ok(proof)
}

#[cfg(not(test))]
async fn lock_reset_request_replay_rows(
    transaction: &mut Transaction<'_, Postgres>,
    mutation: &VerifiedSignedMutation,
    parsed: &ParsedResetAuthority,
    head: &ResetReplayHeadRow,
) -> Result<([u8; 32], ResetCanonicalResponse), ResetFacadeError> {
    let row: PendingResetRow = sqlx::query_as(
        r#"
        SELECT reset_request_id,conversation_id,requester_did,requester_device_id,
               requester_key_id,requester_auth_generation,prior_generation,
               prior_state_version,prior_group_id,prior_epoch,
               prior_group_context_hash,prior_confirmation_tag,reason,status,
               signed_request_bytes,signing_transcript_bytes,request_digest,
               signature,received_at,expires_at,terminal_transition_id,terminal_at
          FROM chat.reset_requests
         WHERE reset_request_id=$1
         FOR UPDATE
        "#,
    )
    .bind(parsed.reset_request_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(ResetRepositoryError::PendingResetNotFound)?;
    let accepted = mutation
        .accepted_wrapper_bytes()
        .ok_or(ResetFacadeError::InvalidCanonicalMaterial)?;
    let prior = coordinate_from_row(&row)?;
    let actor_generation = i64::try_from(mutation.auth_generation())
        .map_err(|_| ResetFacadeError::InvalidCanonicalMaterial)?;
    if row.reset_request_id != parsed.reset_request_id
        || row.conversation_id != Uuid::from_bytes(*parsed.prior.conversation_id())
        || row.requester_did != mutation.actor_did().as_str()
        || row.requester_device_id != Uuid::from_bytes(*mutation.actor_device_id().as_bytes())
        || row.requester_key_id != mutation.key_id().as_str()
        || row.requester_auth_generation != actor_generation
        || prior != parsed.prior
        || !matches!(
            row.status.as_str(),
            "pending" | "stale" | "consumed" | "expired"
        )
        || row.signed_request_bytes != accepted
        || row.signing_transcript_bytes != mutation.transcript_bytes()
        || row.request_digest.as_slice() != mutation.request_digest()
        || row.signature.as_slice() != mutation.signature()
        || row.expires_at != row.received_at + Duration::hours(24)
        || !whole_millis(row.received_at)
        || !whole_millis(row.expires_at)
    {
        return Err(ResetFacadeError::InvalidCanonicalMaterial);
    }
    let expected_reason = match mutation.projection() {
        VerifiedMutationProjection::ResetRequest(value) => value.reason(),
        _ => return Err(ResetFacadeError::UnsupportedMutation),
    };
    if row.reason != expected_reason {
        return Err(ResetFacadeError::InvalidCanonicalMaterial);
    }
    let entry = lock_reset_replay_entry(
        transaction,
        mutation,
        row.conversation_id,
        "blue.catbird.chat.defs#resetRequestEntry",
        None,
    )
    .await?;
    if entry.generation.is_some()
        || entry.state_version.is_some()
        || entry.transition_id.is_some()
        || entry.received_at != row.received_at
        || entry.seq >= head.next_entry_seq
    {
        return Err(ResetFacadeError::InvalidCanonicalMaterial);
    }
    let response = ResetCanonicalResponse::request(
        &entry.accepted_payload_bytes,
        row.reset_request_id,
        row.conversation_id,
        &row.requester_did,
        row.requester_device_id,
        &prior,
        &row.reason,
        row.received_at,
        row.expires_at,
    )?;
    let mut digest = reset_replay_post_state_digest("request", head, &entry);
    digest_uuid(&mut digest, row.reset_request_id);
    digest_uuid(&mut digest, row.conversation_id);
    digest_len(&mut digest, row.requester_did.as_bytes());
    digest_uuid(&mut digest, row.requester_device_id);
    digest_len(&mut digest, row.requester_key_id.as_bytes());
    digest.update(row.requester_auth_generation.to_be_bytes());
    digest_coordinate(&mut digest, &prior);
    digest_len(&mut digest, row.reason.as_bytes());
    digest_len(&mut digest, row.status.as_bytes());
    digest_len(&mut digest, &row.signed_request_bytes);
    digest_len(&mut digest, &row.signing_transcript_bytes);
    digest_len(&mut digest, &row.request_digest);
    digest_len(&mut digest, &row.signature);
    digest.update(row.received_at.timestamp_millis().to_be_bytes());
    digest.update(row.expires_at.timestamp_millis().to_be_bytes());
    digest_optional_uuid(&mut digest, row.terminal_transition_id);
    digest_optional_time(&mut digest, row.terminal_at);
    Ok((digest.finalize().into(), response))
}

#[cfg(not(test))]
async fn lock_reset_activation_replay_rows(
    transaction: &mut Transaction<'_, Postgres>,
    mutation: &VerifiedSignedMutation,
    parsed: &ParsedResetAuthority,
    head: &ResetReplayHeadRow,
) -> Result<([u8; 32], ResetCanonicalResponse), ResetFacadeError> {
    let activation = match mutation.projection() {
        VerifiedMutationProjection::ResetActivation(value) => value,
        _ => return Err(ResetFacadeError::UnsupportedMutation),
    };
    let retired = parse_coordinate(&activation.retired())?;
    let successor = parse_coordinate(&activation.successor())?;
    let transition: ResetReplayTransitionRow = sqlx::query_as(
        r#"
        SELECT transition_id,conversation_id,kind,actor_did,actor_device_id,
               actor_key_id,actor_auth_generation,actor_role,actor_device_status,
               signed_request_bytes,unsigned_projection_bytes,signing_transcript_bytes,
               request_digest,signature,prior_generation,prior_state_version,
               next_generation,next_state_version,retired_generation,
               retired_state_version,successor_generation,successor_state_version,
               reset_request_id,entry_seq,accepted_at
          FROM chat.transitions
         WHERE transition_id=$1
         FOR UPDATE
        "#,
    )
    .bind(parsed.operation_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(ResetRepositoryError::OperationIdAlreadyUsed)?;
    let conversation_id = Uuid::from_bytes(*parsed.prior.conversation_id());
    let actor_generation = i64::try_from(mutation.auth_generation())
        .map_err(|_| ResetFacadeError::InvalidCanonicalMaterial)?;
    let prior_pair = coordinate_pair(&parsed.prior)?;
    let retired_pair = coordinate_pair(&retired)?;
    let successor_pair = coordinate_pair(&successor)?;
    let accepted = mutation
        .accepted_wrapper_bytes()
        .ok_or(ResetFacadeError::InvalidCanonicalMaterial)?;
    if transition.transition_id != parsed.operation_id
        || transition.conversation_id != conversation_id
        || transition.kind != "resetActivation"
        || transition.actor_did != mutation.actor_did().as_str()
        || transition.actor_device_id != Uuid::from_bytes(*mutation.actor_device_id().as_bytes())
        || transition.actor_key_id != mutation.key_id().as_str()
        || transition.actor_auth_generation != actor_generation
        || transition.actor_role != "admin"
        || transition.actor_device_status != "active"
        || transition.signed_request_bytes != accepted
        || transition.unsigned_projection_bytes != mutation.canonical_projection()
        || transition.signing_transcript_bytes != mutation.transcript_bytes()
        || transition.request_digest.as_slice() != mutation.request_digest()
        || transition.signature.as_slice() != mutation.signature()
        || (transition.prior_generation, transition.prior_state_version)
            != (Some(prior_pair.0), Some(prior_pair.1))
        || (
            transition.retired_generation,
            transition.retired_state_version,
        ) != (Some(retired_pair.0), Some(retired_pair.1))
        || (
            transition.successor_generation,
            transition.successor_state_version,
        ) != (Some(successor_pair.0), Some(successor_pair.1))
        || (transition.next_generation, transition.next_state_version)
            != (Some(successor_pair.0), Some(successor_pair.1))
        || transition.reset_request_id != Some(parsed.reset_request_id)
        || !whole_millis(transition.accepted_at)
        || transition.entry_seq < 1
        || transition.entry_seq >= head.next_entry_seq
    {
        return Err(ResetFacadeError::InvalidCanonicalMaterial);
    }
    let request: PendingResetRow = sqlx::query_as(
        r#"
        SELECT reset_request_id,conversation_id,requester_did,requester_device_id,
               requester_key_id,requester_auth_generation,prior_generation,
               prior_state_version,prior_group_id,prior_epoch,
               prior_group_context_hash,prior_confirmation_tag,reason,status,
               signed_request_bytes,signing_transcript_bytes,request_digest,
               signature,received_at,expires_at,terminal_transition_id,terminal_at
          FROM chat.reset_requests
         WHERE reset_request_id=$1
         FOR UPDATE
        "#,
    )
    .bind(parsed.reset_request_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(ResetRepositoryError::PendingResetNotFound)?;
    if request.conversation_id != conversation_id
        || coordinate_from_row(&request)? != parsed.prior
        || request.status != "consumed"
        || request.terminal_transition_id != Some(parsed.operation_id)
        || request.terminal_at != Some(transition.accepted_at)
    {
        return Err(ResetFacadeError::InvalidCanonicalMaterial);
    }
    let entry = lock_reset_replay_entry(
        transaction,
        mutation,
        conversation_id,
        "blue.catbird.chat.defs#resetActivationEntry",
        Some(parsed.operation_id),
    )
    .await?;
    if entry.seq != transition.entry_seq
        || entry.generation != Some(successor_pair.0)
        || entry.state_version != Some(successor_pair.1)
        || entry.received_at != transition.accepted_at
    {
        return Err(ResetFacadeError::InvalidCanonicalMaterial);
    }
    let generation: ResetReplayGenerationRow = sqlx::query_as(
        r#"
        SELECT group_id,genesis_group_info_bytes,genesis_group_info_sha256,
               activated_seq,activated_at
          FROM chat.generations
         WHERE conversation_id=$1 AND generation=$2
         FOR UPDATE
        "#,
    )
    .bind(conversation_id)
    .bind(successor_pair.0)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(ResetFacadeError::InvalidCanonicalMaterial)?;
    let expected_group_info = reset_group_info_bytes(mutation)?;
    if generation.group_id.as_slice() != successor.group_id()
        || generation.genesis_group_info_bytes != expected_group_info
        || generation.genesis_group_info_sha256.as_slice()
            != Sha256::digest(&generation.genesis_group_info_bytes).as_slice()
        || generation.activated_seq != transition.entry_seq
        || generation.activated_at != transition.accepted_at
    {
        return Err(ResetFacadeError::InvalidCanonicalMaterial);
    }
    let retired_row =
        lock_reset_generation_state(transaction, &retired, parsed.operation_id).await?;
    let successor_row =
        lock_reset_generation_state(transaction, &successor, parsed.operation_id).await?;
    if retired_row.state_kind != "resetRetirement"
        || retired_row.lifecycle != "superseded"
        || successor_row.state_kind != "resetSuccessor"
        || !matches!(successor_row.lifecycle.as_str(), "active" | "superseded")
        || retired_row.created_at != transition.accepted_at
        || successor_row.created_at != transition.accepted_at
    {
        return Err(ResetFacadeError::InvalidCanonicalMaterial);
    }
    let response =
        ResetCanonicalResponse::activation(&entry.accepted_payload_bytes, &retired, &successor)?;
    let mut digest = reset_replay_post_state_digest("activation", head, &entry);
    digest_transition(&mut digest, &transition);
    digest_uuid(&mut digest, request.reset_request_id);
    digest_len(&mut digest, request.status.as_bytes());
    digest_optional_uuid(&mut digest, request.terminal_transition_id);
    digest_optional_time(&mut digest, request.terminal_at);
    digest_coordinate(&mut digest, &retired);
    digest_coordinate(&mut digest, &successor);
    digest_len(&mut digest, &generation.group_id);
    digest_len(&mut digest, &generation.genesis_group_info_bytes);
    digest_len(&mut digest, &generation.genesis_group_info_sha256);
    digest.update(generation.activated_seq.to_be_bytes());
    digest.update(generation.activated_at.timestamp_millis().to_be_bytes());
    digest_generation_state(&mut digest, &retired_row);
    digest_generation_state(&mut digest, &successor_row);
    Ok((digest.finalize().into(), response))
}

#[cfg(not(test))]
async fn lock_reset_replay_entry(
    transaction: &mut Transaction<'_, Postgres>,
    mutation: &VerifiedSignedMutation,
    conversation_id: Uuid,
    entry_kind: &str,
    transition_id: Option<Uuid>,
) -> Result<ResetReplayEntryRow, ResetFacadeError> {
    let accepted = mutation
        .accepted_wrapper_bytes()
        .ok_or(ResetFacadeError::InvalidCanonicalMaterial)?;
    let rows: Vec<ResetReplayEntryRow> = sqlx::query_as(
        r#"
        SELECT seq,entry_id,accepted_payload_bytes,accepted_payload_sha256,
               signed_request_bytes,request_digest,signature,server_fields_bytes,
               outer_entry_fingerprint,actor_did,actor_device_id,actor_key_id,
               actor_auth_generation,generation,state_version,transition_id,received_at
          FROM chat.entries
         WHERE conversation_id=$1 AND entry_kind=$2
           AND signed_request_bytes=$3 AND request_digest=$4 AND signature=$5
           AND transition_id IS NOT DISTINCT FROM $6
         ORDER BY seq
         FOR UPDATE
        "#,
    )
    .bind(conversation_id)
    .bind(entry_kind)
    .bind(accepted)
    .bind(mutation.request_digest().as_slice())
    .bind(mutation.signature().as_slice())
    .bind(transition_id)
    .fetch_all(&mut **transaction)
    .await?;
    let [row] = rows.as_slice() else {
        return Err(ResetFacadeError::InvalidCanonicalMaterial);
    };
    let actor_generation = i64::try_from(mutation.auth_generation())
        .map_err(|_| ResetFacadeError::InvalidCanonicalMaterial)?;
    if row.entry_id.get_version_num() != 4
        || row.seq < 1
        || row.accepted_payload_bytes.is_empty()
        || row.accepted_payload_sha256.as_slice()
            != Sha256::digest(&row.accepted_payload_bytes).as_slice()
        || row.signed_request_bytes != accepted
        || row.request_digest.as_slice() != mutation.request_digest()
        || row.signature.as_slice() != mutation.signature()
        || row.server_fields_bytes.is_empty()
        || row.outer_entry_fingerprint.len() != 32
        || row.actor_did != mutation.actor_did().as_str()
        || row.actor_device_id != Uuid::from_bytes(*mutation.actor_device_id().as_bytes())
        || row.actor_key_id != mutation.key_id().as_str()
        || row.actor_auth_generation != actor_generation
        || row.transition_id != transition_id
        || !whole_millis(row.received_at)
    {
        return Err(ResetFacadeError::InvalidCanonicalMaterial);
    }
    Ok(rows.into_iter().next().expect("single exact Reset entry"))
}

#[cfg(not(test))]
async fn lock_reset_generation_state(
    transaction: &mut Transaction<'_, Postgres>,
    coordinate: &PublicGroupSnapshotCoordinate,
    transition_id: Uuid,
) -> Result<ResetReplaySuccessorRow, ResetFacadeError> {
    let (generation, state_version) = coordinate_pair(coordinate)?;
    let row: ResetReplaySuccessorRow = sqlx::query_as(
        r#"
        SELECT group_id,epoch,group_context_hash,confirmation_tag,lifecycle,
               state_kind,producing_transition_id,created_at
          FROM chat.generation_states
         WHERE conversation_id=$1 AND generation=$2 AND state_version=$3
         FOR UPDATE
        "#,
    )
    .bind(Uuid::from_bytes(*coordinate.conversation_id()))
    .bind(generation)
    .bind(state_version)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(ResetFacadeError::InvalidCanonicalMaterial)?;
    if row.group_id.as_slice() != coordinate.group_id()
        || row.epoch
            != i64::try_from(coordinate.epoch())
                .map_err(|_| ResetFacadeError::InvalidCanonicalMaterial)?
        || row.group_context_hash.as_slice() != coordinate.group_context_hash()
        || row.confirmation_tag.as_slice() != coordinate.confirmation_tag()
        || row.producing_transition_id != transition_id
    {
        return Err(ResetFacadeError::InvalidCanonicalMaterial);
    }
    Ok(row)
}

#[cfg(not(test))]
fn coordinate_pair(
    coordinate: &PublicGroupSnapshotCoordinate,
) -> Result<(i64, i64), ResetFacadeError> {
    Ok((
        i64::try_from(coordinate.generation())
            .map_err(|_| ResetFacadeError::InvalidCanonicalMaterial)?,
        i64::try_from(coordinate.state_version())
            .map_err(|_| ResetFacadeError::InvalidCanonicalMaterial)?,
    ))
}

/// Consume one globally arbitrated signed Reset operation. First execution
/// owns discovery, full scope locking, entry minting, planning, canonical
/// artifacts/response, and apply. Replay remains byte-opaque until the exact
/// Reset durable post-state has been locked and validated.
#[cfg(not(test))]
pub(crate) async fn execute_prepared_reset(
    transaction: &mut Transaction<'_, Postgres>,
    prepared: PreparedSignedOperation,
) -> Result<ResetTransactionOutcome, ResetFacadeError> {
    match prepared.into_state() {
        PreparedSignedOperationState::First {
            authority,
            reservation,
        } => execute_first_reset(transaction, authority, reservation)
            .await
            .map(ResetTransactionOutcome::First),
        PreparedSignedOperationState::Replay { authority, replay } => {
            let locked =
                lock_signed_operation_replay_authority(transaction, authority, replay).await?;
            let post_state = lock_reset_replay_post_state(transaction, &locked).await?;
            let expected_response_sha256 = post_state.expected_response_sha256;
            let closed_post_state = match post_state.mutation_kind() {
                SignedMutationKind::ResetRequest => {
                    SignedOperationReplayPostStateProof::ResetRequest(post_state)
                }
                SignedMutationKind::ResetActivation => {
                    SignedOperationReplayPostStateProof::ResetActivation(post_state)
                }
                _ => return Err(ResetFacadeError::UnsupportedMutation),
            };
            let response =
                release_signed_operation_replay(transaction, locked, closed_post_state).await?;
            if response.response_sha256() != &expected_response_sha256
                || Sha256::digest(response.response_bytes()).as_slice()
                    != response.response_sha256()
            {
                return Err(ResetFacadeError::InvalidCanonicalMaterial);
            }
            Ok(ResetTransactionOutcome::Replay(response))
        }
    }
}

#[cfg(not(test))]
async fn execute_first_reset(
    transaction: &mut Transaction<'_, Postgres>,
    authority: VerifiedChatDeviceRequest,
    reservation: OperationReservationGuard,
) -> Result<AppliedResetOperation, ResetFacadeError> {
    let mutation = authority
        .mutation()
        .ok_or(ResetFacadeError::MissingMutation)?;
    let expected = match mutation.kind() {
        SignedMutationKind::ResetRequest => ResetPreparationKind::Request,
        SignedMutationKind::ResetActivation => ResetPreparationKind::Activation,
        _ => return Err(ResetFacadeError::UnsupportedMutation),
    };
    let parsed = parse_reset_authority(mutation, expected)?;
    let conversation_id = Uuid::from_bytes(*parsed.prior.conversation_id());
    let scope =
        discover_reset_identity_scope(transaction, &authority, mutation, conversation_id).await?;
    let prelude =
        prepare_identity_scope_prelude(transaction, &authority, reservation, scope).await?;
    let graph = match expected {
        ResetPreparationKind::Request => {
            prepare_reset_request_graph(transaction, &authority, prelude, mutation).await?
        }
        ResetPreparationKind::Activation => {
            prepare_reset_activation_graph(transaction, &authority, prelude, mutation).await?
        }
    };
    let (scope_authority, completion) = graph.1.into_execution_parts();
    let (applied, response) = graph.0.apply(transaction).await?;
    Ok(AppliedResetOperation {
        applied,
        completion: ResetCompletion {
            authority,
            scope_authority,
            completion,
        },
        response,
    })
}

#[cfg(not(test))]
async fn prepare_reset_request_graph(
    transaction: &mut Transaction<'_, Postgres>,
    request: &VerifiedChatDeviceRequest,
    prelude: PreparedBusinessPrelude,
    mutation: &VerifiedSignedMutation,
) -> Result<(PreparedResetExecutionGraph, PreparedBusinessPrelude), ResetFacadeError> {
    let authority = prepare_reset_request_authority(transaction, prelude, mutation).await?;
    let parsed = parse_reset_authority(mutation, ResetPreparationKind::Request)?;
    let scope = authority.prelude.scope_authority();
    let verified_mutation = reverify_scope_mutation(scope, mutation)?;
    let entry_id = canonical_uuid_v4(Uuid::new_v4())?;
    let conversation_id = Uuid::from_bytes(*parsed.prior.conversation_id());
    let seq = authority.aggregate.head().next_entry_seq();
    let entry = build_verified_control_entry(
        verified_mutation,
        request.endpoint(),
        entry_id,
        canonical_uuid_v4(conversation_id)?,
        seq,
        request.trusted_instant(),
        CanonicalControlServerFields::empty(ControlEntryKind::ResetRequest)?,
    )?;
    let products = CanonicalControlEntryProducts::mint(&entry)?;
    let trusted_instant = authority.trusted_instant;
    let expires_at = trusted_instant
        .checked_add_signed(Duration::hours(24))
        .ok_or(ResetFacadeError::InvalidCanonicalMaterial)?;
    let reason = match entry.mutation().projection() {
        VerifiedMutationProjection::ResetRequest(value) => value.reason(),
        _ => return Err(ResetFacadeError::UnsupportedMutation),
    };
    let response = ResetCanonicalResponse::request(
        products.canonical_response_json(),
        parsed.reset_request_id,
        conversation_id,
        entry.mutation().actor_did().as_str(),
        Uuid::from_bytes(*entry.mutation().actor_device_id().as_bytes()),
        &parsed.prior,
        reason,
        trusted_instant,
        expires_at,
    )?;
    let artifacts = ExecutionContextArtifacts {
        accepted_control_entry_bytes: Some(products.durable_json().to_vec()),
        genesis_group_info_bytes: None,
        primary_event_payload: Some(canonical_reset_requested_event_payload(
            parsed.reset_request_id,
            conversation_id,
        )),
        welcome_disposition_event_payloads: Vec::new(),
    };
    let (planned, prelude) = match authority.disposition() {
        LockedResetRequestDisposition::Vacant => {
            authority.plan_vacant_reset_request_entry(mutation, entry)?
        }
        LockedResetRequestDisposition::ExpiredReplacement(_) => {
            // Entry, response, and every executor artifact are sealed before
            // expiry terminalization performs the replacement's first write.
            let replacement = expire_pending_reset_for_replacement(transaction, authority).await?;
            replacement.plan_replacement_reset_request_entry(mutation, entry)?
        }
        LockedResetRequestDisposition::Pending(_) => {
            return Err(ResetRepositoryError::PendingResetAlreadyExists.into());
        }
    };
    let plan = planned.into_persistence_plan()?;
    Ok((
        PreparedResetExecutionGraph::new(plan, artifacts, response)?,
        prelude,
    ))
}

#[cfg(not(test))]
async fn prepare_reset_activation_graph(
    transaction: &mut Transaction<'_, Postgres>,
    request: &VerifiedChatDeviceRequest,
    prelude: PreparedBusinessPrelude,
    mutation: &VerifiedSignedMutation,
) -> Result<(PreparedResetExecutionGraph, PreparedBusinessPrelude), ResetFacadeError> {
    let authority = prepare_reset_activation_authority(transaction, prelude, mutation).await?;
    let parsed = parse_reset_authority(mutation, ResetPreparationKind::Activation)?;
    let scope = authority.prelude.scope_authority();
    let verified_mutation = reverify_scope_mutation(scope, mutation)?;
    let group_info = reset_group_info_bytes(mutation)?;
    let entry_id = canonical_uuid_v4(Uuid::new_v4())?;
    let conversation_id = Uuid::from_bytes(*parsed.prior.conversation_id());
    let seq = authority.aggregate.head().next_entry_seq();
    let entry = build_verified_control_entry(
        verified_mutation,
        request.endpoint(),
        entry_id,
        canonical_uuid_v4(conversation_id)?,
        seq,
        request.trusted_instant(),
        CanonicalControlServerFields::empty(ControlEntryKind::ResetActivation)?,
    )?;
    let products = CanonicalControlEntryProducts::mint(&entry)?;
    let (planned, _pending, prelude) = authority.plan_reset_activation_entry(mutation, entry)?;
    let plan = planned.into_persistence_plan()?;
    let retired = plan
        .retired_coordinate()
        .ok_or(ResetFacadeError::InvalidCanonicalMaterial)?;
    let successor = plan
        .successor_coordinate()
        .ok_or(ResetFacadeError::InvalidCanonicalMaterial)?;
    let response =
        ResetCanonicalResponse::activation(products.canonical_response_json(), retired, successor)?;
    let artifacts = ExecutionContextArtifacts {
        accepted_control_entry_bytes: Some(products.durable_json().to_vec()),
        genesis_group_info_bytes: Some(group_info),
        primary_event_payload: Some(canonical_reset_activation_event_payload(conversation_id)),
        welcome_disposition_event_payloads: Vec::new(),
    };
    Ok((
        PreparedResetExecutionGraph::new(plan, artifacts, response)?,
        prelude,
    ))
}

#[cfg(not(test))]
fn canonical_uuid_v4(value: Uuid) -> Result<CanonicalUuidV4, ResetFacadeError> {
    CanonicalUuidV4::parse(&value.hyphenated().to_string()).map_err(ResetFacadeError::from)
}

#[cfg(not(test))]
fn reset_group_info_bytes(mutation: &VerifiedSignedMutation) -> Result<Vec<u8>, ResetFacadeError> {
    let object = match mutation.projection() {
        VerifiedMutationProjection::ResetActivation(value) => value.genesis_group_info(),
        _ => return Err(ResetFacadeError::UnsupportedMutation),
    };
    let bytes = match object.get("bytes") {
        Some(CanonicalValueRef::Bytes(value)) => value,
        _ => return Err(ResetFacadeError::InvalidCanonicalMaterial),
    };
    let declared: [u8; 32] = match object.get("sha256") {
        Some(CanonicalValueRef::Bytes(value)) => value
            .try_into()
            .map_err(|_| ResetFacadeError::InvalidCanonicalMaterial)?,
        _ => return Err(ResetFacadeError::InvalidCanonicalMaterial),
    };
    if <[u8; 32]>::from(Sha256::digest(bytes)) != declared {
        return Err(ResetFacadeError::InvalidCanonicalMaterial);
    }
    Ok(bytes.to_vec())
}

#[cfg(not(test))]
fn reverify_scope_mutation(
    scope: &ScopeBoundBusinessAuthority,
    mutation: &VerifiedSignedMutation,
) -> Result<VerifiedSignedMutation, ResetFacadeError> {
    let raw = mutation
        .accepted_wrapper_bytes()
        .ok_or(ResetFacadeError::InvalidCanonicalMaterial)?;
    let signing_public_key = scope
        .actor_signing_public_key()
        .ok_or(ResetFacadeError::InvalidCanonicalMaterial)?;
    let verified = decode_and_verify_signed_mutation(raw, signing_public_key)?;
    if verified.kind() != mutation.kind()
        || verified.type_id() != mutation.type_id()
        || verified.domain() != mutation.domain()
        || verified.canonical_projection() != mutation.canonical_projection()
        || verified.transcript_bytes() != mutation.transcript_bytes()
        || verified.request_digest() != mutation.request_digest()
        || verified.signature() != mutation.signature()
        || verified.accepted_wrapper_bytes() != mutation.accepted_wrapper_bytes()
        || verified.actor_did() != mutation.actor_did()
        || verified.actor_device_id() != mutation.actor_device_id()
        || verified.key_id() != mutation.key_id()
        || verified.auth_generation() != mutation.auth_generation()
        || verified.signed_at() != mutation.signed_at()
    {
        return Err(ResetFacadeError::InvalidCanonicalMaterial);
    }
    Ok(verified)
}

async fn prepare_reset_read_set(
    transaction: &mut Transaction<'_, Postgres>,
    prelude: PreparedBusinessPrelude,
    authority: &VerifiedSignedMutation,
    parsed: &ParsedResetAuthority,
) -> Result<PreparedResetReadSet, ResetRepositoryError> {
    #[cfg(test)]
    {
        return prepare_reset_read_set_inner(transaction, prelude, authority, parsed, None).await;
    }
    #[cfg(not(test))]
    {
        prepare_reset_read_set_inner(transaction, prelude, authority, parsed).await
    }
}

#[cfg(test)]
async fn prepare_reset_read_set_with_probe(
    transaction: &mut Transaction<'_, Postgres>,
    prelude: PreparedBusinessPrelude,
    authority: &VerifiedSignedMutation,
    parsed: &ParsedResetAuthority,
    probe: &mut ResetPrepareProbeForTest,
) -> Result<PreparedResetReadSet, ResetRepositoryError> {
    prepare_reset_read_set_inner(transaction, prelude, authority, parsed, Some(probe)).await
}

async fn prepare_reset_read_set_inner(
    transaction: &mut Transaction<'_, Postgres>,
    prelude: PreparedBusinessPrelude,
    authority: &VerifiedSignedMutation,
    parsed: &ParsedResetAuthority,
    #[cfg(test)] mut probe: Option<&mut ResetPrepareProbeForTest>,
) -> Result<PreparedResetReadSet, ResetRepositoryError> {
    let conversation_id = Uuid::from_bytes(*parsed.prior.conversation_id());
    let scope = prelude.scope_authority();
    validate_scope_and_mutation(transaction, scope, authority).await?;
    let discovered = discover_reset_identity_scope_for_actor(
        transaction,
        conversation_id,
        authority.actor_did().as_str(),
        Uuid::from_bytes(*authority.actor_device_id().as_bytes()),
    )
    .await?;
    if !scope_matches_discovery(scope, &discovered) {
        return Err(ResetRepositoryError::CandidateScopeDrift);
    }

    for attempt in 0..MAX_PREPARE_ATTEMPTS {
        #[cfg(test)]
        if let Some(probe) = probe.as_deref_mut() {
            probe.attempts += 1;
        }
        let mut savepoint = (&mut **transaction).begin().await?;
        match prepare_reset_attempt(
            &mut savepoint,
            scope,
            authority,
            parsed,
            conversation_id,
            #[cfg(test)]
            probe.as_deref_mut(),
        )
        .await
        {
            Ok(value) => {
                savepoint.commit().await?;
                return Ok(PreparedResetReadSet {
                    prelude,
                    aggregate: value.aggregate,
                    transaction_id: value.transaction_id,
                    trusted_instant: value.trusted_instant,
                    operation_id: value.operation_id,
                    incoming_request_digest: value.incoming_request_digest,
                    admitted_mutation_digest: value.admitted_mutation_digest,
                    actor_did: value.actor_did,
                    actor_device_id: value.actor_device_id,
                    actor_key_id: value.actor_key_id,
                    actor_auth_generation: value.actor_auth_generation,
                    actor_signing_public_key: value.actor_signing_public_key,
                    actor_dpop_jkt: value.actor_dpop_jkt,
                    scope_digest: value.scope_digest,
                    head_digest: value.head_digest,
                    pending: value.pending,
                });
            }
            Err(error)
                if attempt + 1 < MAX_PREPARE_ATTEMPTS
                    && matches!(error, ResetRepositoryError::HeadBusy) =>
            {
                savepoint.rollback().await?;
            }
            Err(error) => {
                savepoint.rollback().await?;
                return if matches!(error, ResetRepositoryError::HeadBusy) {
                    Err(ResetRepositoryError::RetryExhausted)
                } else {
                    Err(error)
                };
            }
        }
    }
    Err(ResetRepositoryError::RetryExhausted)
}

async fn prepare_reset_attempt(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &ScopeBoundBusinessAuthority,
    authority: &VerifiedSignedMutation,
    parsed: &ParsedResetAuthority,
    conversation_id: Uuid,
    #[cfg(test)] probe: Option<&mut ResetPrepareProbeForTest>,
) -> Result<PreparedResetAttempt, ResetRepositoryError> {
    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await?;
    if transaction_id != scope.transaction_id() {
        return Err(ResetRepositoryError::ForeignTransaction);
    }
    let trusted_instant = scope.trusted_instant();
    if !whole_millis(trusted_instant) {
        return Err(ResetRepositoryError::TrustedInstantMismatch);
    }

    #[cfg(test)]
    if let Some(probe) = probe {
        if probe.inject_candidate_scope_drift_once {
            probe.inject_candidate_scope_drift_once = false;
            return Err(ResetRepositoryError::CandidateScopeDrift);
        }
        if let (Some(reached), Some(release)) = (
            probe.after_scope_locks_reached.take(),
            probe.release_before_head.take(),
        ) {
            reached.notify_one();
            release.notified().await;
        }
    }
    lock_head_nowait(transaction, conversation_id).await?;
    let discovered = discover_reset_identity_scope_for_actor(
        transaction,
        conversation_id,
        authority.actor_did().as_str(),
        Uuid::from_bytes(*authority.actor_device_id().as_bytes()),
    )
    .await?;
    if !scope_matches_discovery(scope, &discovered) {
        return Err(ResetRepositoryError::CandidateScopeDrift);
    }

    lock_operation_and_pending_rows(
        transaction,
        conversation_id,
        parsed.operation_id,
        parsed.reset_request_id,
        parsed.kind,
    )
    .await?;

    let aggregate =
        hydrate_locked_conversation_state(transaction, conversation_id, trusted_instant)
            .await
            .map_err(map_aggregate_error)?;
    let head = aggregate.head();
    if head.transaction_id() != transaction_id || head.locked_at() != trusted_instant {
        return Err(ResetRepositoryError::GuardInvariant);
    }
    let head_coordinate = head
        .prior_coordinate()
        .ok_or(ResetRepositoryError::ConversationMissing)?;
    if head_coordinate.lifecycle() != PublicGroupSnapshotLifecycle::Active {
        return Err(ResetRepositoryError::ConversationNotActive);
    }
    if head_coordinate != &parsed.prior {
        return Err(ResetRepositoryError::PendingResetCoordinateMismatch);
    }
    let head_digest = *head.durable_row_digest();
    let actor_principal = PrincipalId::new(authority.actor_did().as_str().as_bytes().to_vec())
        .map_err(|_| ResetRepositoryError::AuthorityBindingMismatch)?;
    let actor = aggregate
        .state()
        .participant(&actor_principal)
        .ok_or(ResetRepositoryError::AuthorityBindingMismatch)?;
    let actor_authorized = match parsed.kind {
        ResetPreparationKind::Request => actor.is_active(),
        ResetPreparationKind::Activation => {
            actor.is_active() && actor.role() == ParticipantRole::Admin
        }
    };
    if !actor_authorized {
        return Err(ResetRepositoryError::AuthorityBindingMismatch);
    }
    let pending_row = load_locked_pending_row(transaction, conversation_id).await?;
    let pending = match pending_row {
        None => None,
        Some(row) => {
            // Finding 3. `load_locked_pending_row` selects by conversation_id
            // ALONE, and this seal used to re-verify the ORIGINAL requester's
            // LIVE device unconditionally. So once that requester was revoked or
            // rebound, the row became unsealable for EVERY principal — including
            // through the `requestReset` arm that exists to classify a lapsed row
            // `ExpiredReplacement` and clear it. The documented rescue was
            // unreachable and the conversation lost reset capability outright.
            //
            // A LAPSED row is therefore disposed of against the authority the row
            // RECORDED, re-verified below over its own immutable signed bytes.
            // `Activation` is deliberately absent from this condition:
            // `activateReset` keeps full strict live-authority verification.
            let binding = if matches!(parsed.kind, ResetPreparationKind::Request)
                && trusted_instant >= row.expires_at
            {
                ResetAuthorityBinding::RecordedForDisposal
            } else {
                ResetAuthorityBinding::Live
            };
            Some(seal_pending_reset(
                row,
                &transaction_id,
                trusted_instant,
                scope,
                head_coordinate,
                head_digest,
                parsed.kind,
                parsed.operation_id,
                binding,
            )?)
        }
    };

    Ok(PreparedResetAttempt {
        aggregate,
        transaction_id,
        trusted_instant,
        operation_id: parsed.operation_id,
        incoming_request_digest: *authority.request_digest(),
        admitted_mutation_digest: admitted_mutation_digest(authority)?,
        actor_did: authority.actor_did().as_str().to_owned(),
        actor_device_id: Uuid::from_bytes(*authority.actor_device_id().as_bytes()),
        actor_key_id: authority.key_id().as_str().to_owned(),
        actor_auth_generation: i64::try_from(authority.auth_generation())
            .map_err(|_| ResetRepositoryError::AuthorityBindingMismatch)?,
        actor_signing_public_key: scope
            .actor_signing_public_key()
            .ok_or(ResetRepositoryError::AuthorityBindingMismatch)?
            .to_vec(),
        actor_dpop_jkt: scope.actor_dpop_jkt().map(|s| s.to_owned()),
        scope_digest: *scope.scope_digest(),
        head_digest,
        pending,
    })
}

async fn validate_scope_and_mutation(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &ScopeBoundBusinessAuthority,
    authority: &VerifiedSignedMutation,
) -> Result<(), ResetRepositoryError> {
    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await?;
    if transaction_id != scope.transaction_id()
        || scope.actor_class() != RepositoryAuthorityClass::ExistingDevice
    {
        return Err(ResetRepositoryError::UnsupportedAuthority);
    }
    let actor_device_id = Uuid::from_bytes(*authority.actor_device_id().as_bytes());
    let auth_generation = i64::try_from(authority.auth_generation())
        .map_err(|_| ResetRepositoryError::AuthorityBindingMismatch)?;
    if scope.actor_did() != authority.actor_did().as_str()
        || scope.actor_device_id() != actor_device_id
        || scope.actor_auth_generation() != Some(auth_generation)
        || scope.actor_key_id() != Some(authority.key_id().as_str())
        || scope.actor_signing_public_key().is_none()
        || authority.accepted_wrapper_bytes().is_none()
        || !whole_millis(scope.trusted_instant())
    {
        return Err(ResetRepositoryError::AuthorityBindingMismatch);
    }
    Ok(())
}

fn scope_matches_discovery(
    scope: &ScopeBoundBusinessAuthority,
    discovered: &CanonicalLockScope,
) -> bool {
    scope.principals() == discovered.principals()
        && scope.devices().len() == discovered.devices().len()
        && scope
            .devices()
            .iter()
            .zip(discovered.devices())
            .all(|(locked, expected)| {
                locked.user_did() == expected.did() && locked.device_id() == expected.device_id()
            })
}

#[allow(clippy::too_many_arguments)]
fn validate_sealed_admission(
    scope: &ScopeBoundBusinessAuthority,
    mutation: &VerifiedSignedMutation,
    expected_kind: SignedMutationKind,
    operation_id: Uuid,
    request_digest: &[u8; 32],
    expected_mutation_digest: &[u8; 32],
    actor_did: &str,
    actor_device_id: Uuid,
    actor_key_id: &str,
    actor_auth_generation: i64,
    actor_signing_public_key: &[u8],
    actor_dpop_jkt: Option<&str>,
    transaction_id: &str,
    trusted_instant: DateTime<Utc>,
    scope_digest: &[u8; 32],
    head_digest: &[u8; 32],
    admission_digest: &[u8; 32],
) -> Result<(), ResetRepositoryError> {
    let expected_preparation = match expected_kind {
        SignedMutationKind::ResetRequest => ResetPreparationKind::Request,
        SignedMutationKind::ResetActivation => ResetPreparationKind::Activation,
        _ => return Err(ResetRepositoryError::UnsupportedAuthority),
    };
    let parsed = parse_reset_authority(mutation, expected_preparation)?;
    if parsed.operation_id != operation_id
        || mutation.kind() != expected_kind
        || mutation.request_digest() != request_digest
        || admitted_mutation_digest(mutation).as_ref().ok() != Some(expected_mutation_digest)
        || mutation.actor_did().as_str() != actor_did
        || Uuid::from_bytes(*mutation.actor_device_id().as_bytes()) != actor_device_id
        || mutation.key_id().as_str() != actor_key_id
        || i64::try_from(mutation.auth_generation()).ok() != Some(actor_auth_generation)
        || scope.actor_class() != RepositoryAuthorityClass::ExistingDevice
        || scope.transaction_id() != transaction_id
        || scope.trusted_instant() != trusted_instant
        || scope.actor_did() != actor_did
        || scope.actor_device_id() != actor_device_id
        || scope.actor_key_id() != Some(actor_key_id)
        || scope.actor_auth_generation() != Some(actor_auth_generation)
        || scope.actor_signing_public_key() != Some(actor_signing_public_key)
        || scope.actor_dpop_jkt() != actor_dpop_jkt
        || scope.scope_digest() != scope_digest
        || admission_digest
            != &reset_admission_digest(
                operation_id,
                request_digest,
                actor_did,
                actor_device_id,
                actor_key_id,
                actor_auth_generation,
                trusted_instant,
                scope_digest,
                head_digest,
            )
    {
        return Err(ResetRepositoryError::AuthorityBindingMismatch);
    }
    Ok(())
}

fn validate_control_entry_mutation(
    entry: &VerifiedControlEntry,
    mutation: &VerifiedSignedMutation,
) -> Result<(), ResetRepositoryError> {
    let actual = entry.mutation();
    if actual.kind() != mutation.kind()
        || actual.type_id() != mutation.type_id()
        || actual.domain() != mutation.domain()
        || actual.canonical_projection() != mutation.canonical_projection()
        || actual.transcript_bytes() != mutation.transcript_bytes()
        || actual.request_digest() != mutation.request_digest()
        || actual.signature() != mutation.signature()
        || actual.accepted_wrapper_bytes() != mutation.accepted_wrapper_bytes()
        || actual.actor_did() != mutation.actor_did()
        || actual.actor_device_id() != mutation.actor_device_id()
        || actual.key_id() != mutation.key_id()
        || actual.auth_generation() != mutation.auth_generation()
        || actual.signed_at() != mutation.signed_at()
    {
        return Err(ResetRepositoryError::AuthorityBindingMismatch);
    }
    Ok(())
}

fn plan_reset_request_entry(
    aggregate: &LockedConversationStateGuard,
    scope: &ScopeBoundBusinessAuthority,
    entry: VerifiedControlEntry,
) -> Result<PlannedTransition, ResetCompositionError> {
    let hydration = HydrationAuthority::from_locked_conversation(aggregate)?;
    let registration = hydration.locked_registration_from_scope_authority(scope)?;
    Ok(hydration.plan_reset_request_entry(aggregate, entry, registration)?)
}

fn plan_reset_activation_entry(
    aggregate: &LockedConversationStateGuard,
    scope: &ScopeBoundBusinessAuthority,
    entry: VerifiedControlEntry,
    terminal_packages: Vec<LockedRecoveryPackageGuard>,
) -> Result<PlannedTransition, ResetCompositionError> {
    let hydration = HydrationAuthority::from_locked_conversation(aggregate)?;
    let registration = hydration.locked_registration_from_scope_authority(scope)?;
    Ok(
        hydration.plan_reset_activation_entry(
            aggregate,
            entry,
            &registration,
            terminal_packages,
        )?,
    )
}

fn map_aggregate_error(error: ConversationStateHydrationError) -> ResetRepositoryError {
    match error {
        ConversationStateHydrationError::Head(
            ConversationHeadHydrationError::ConversationMissing,
        ) => ResetRepositoryError::ConversationMissing,
        ConversationStateHydrationError::TerminalLifecycleUnsupported => {
            ResetRepositoryError::ConversationNotActive
        }
        ConversationStateHydrationError::ResetWork(_) => ResetRepositoryError::InvalidResetRow,
        ConversationStateHydrationError::Database(error)
        | ConversationStateHydrationError::Head(ConversationHeadHydrationError::Database(error)) => {
            ResetRepositoryError::Database(error)
        }
        _ => ResetRepositoryError::GuardInvariant,
    }
}

fn parse_reset_authority(
    authority: &VerifiedSignedMutation,
    expected: ResetPreparationKind,
) -> Result<ParsedResetAuthority, ResetRepositoryError> {
    let (body, reset_request_id, operation_id, prior) = match (expected, authority.projection()) {
        (ResetPreparationKind::Request, VerifiedMutationProjection::ResetRequest(value)) => {
            let body = value.body();
            (
                body,
                Uuid::from_bytes(*value.reset_request_id().as_bytes()),
                Uuid::from_bytes(*value.reset_request_id().as_bytes()),
                value.prior(),
            )
        }
        (ResetPreparationKind::Activation, VerifiedMutationProjection::ResetActivation(value)) => {
            let body = value.body();
            (
                body,
                Uuid::from_bytes(*value.reset_request_id().as_bytes()),
                Uuid::from_bytes(*value.transition_id().as_bytes()),
                value.prior(),
            )
        }
        _ => return Err(ResetRepositoryError::UnsupportedAuthority),
    };
    let idempotency_key = match body.get("idempotencyKey") {
        Some(CanonicalValueRef::Uuid(value)) => Uuid::from_bytes(*value.as_bytes()),
        _ => return Err(ResetRepositoryError::NonCanonicalOperation),
    };
    if !uuid_v4(operation_id)
        || !uuid_v4(reset_request_id)
        || idempotency_key != operation_id
        || authority.accepted_wrapper_bytes().is_none()
    {
        return Err(ResetRepositoryError::NonCanonicalOperation);
    }
    Ok(ParsedResetAuthority {
        kind: expected,
        operation_id,
        reset_request_id,
        prior: parse_coordinate(&prior)?,
    })
}

fn parse_coordinate(
    value: &crate::chat_protocol::transcript::ClosedObjectRef<'_>,
) -> Result<PublicGroupSnapshotCoordinate, ResetRepositoryError> {
    let uuid = match value.get("conversationId") {
        Some(CanonicalValueRef::Uuid(value)) => *value.as_bytes(),
        _ => return Err(ResetRepositoryError::NonCanonicalScope),
    };
    let integer = |name| match value.get(name) {
        Some(CanonicalValueRef::Integer(value)) if value <= MAX_PROTOCOL_INTEGER => Ok(value),
        _ => Err(ResetRepositoryError::NonCanonicalScope),
    };
    let bytes32 = |name| match value.get(name) {
        Some(CanonicalValueRef::Bytes(value)) => value
            .try_into()
            .map_err(|_| ResetRepositoryError::NonCanonicalScope),
        _ => Err(ResetRepositoryError::NonCanonicalScope),
    };
    let lifecycle = match value.get("lifecycle") {
        Some(CanonicalValueRef::Text("active")) => PublicGroupSnapshotLifecycle::Active,
        Some(CanonicalValueRef::Text("superseded")) => PublicGroupSnapshotLifecycle::Superseded,
        _ => return Err(ResetRepositoryError::NonCanonicalScope),
    };
    Ok(PublicGroupSnapshotCoordinate::new(
        uuid,
        integer("generation")?,
        integer("stateVersion")?,
        bytes32("groupId")?,
        integer("epoch")?,
        bytes32("groupContextHash")?,
        bytes32("confirmationTag")?,
        lifecycle,
    ))
}

/// Discover the complete Reset principal/device identity scope without taking
/// locks. The caller passes this exact scope to the global business prelude;
/// locked Reset preparation later compares the live identity set with the
/// prelude's sealed projection and returns `CandidateScopeDrift` on mismatch.
pub(crate) async fn discover_reset_identity_scope(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &VerifiedChatDeviceRequest,
    mutation: &VerifiedSignedMutation,
    conversation_id: Uuid,
) -> Result<CanonicalLockScope, ResetRepositoryError> {
    let preparation_kind = match mutation.kind() {
        SignedMutationKind::ResetRequest => ResetPreparationKind::Request,
        SignedMutationKind::ResetActivation => ResetPreparationKind::Activation,
        _ => return Err(ResetRepositoryError::UnsupportedAuthority),
    };
    let parsed = parse_reset_authority(mutation, preparation_kind)?;
    if parsed.prior.conversation_id() != conversation_id.as_bytes()
        || !request_contains_exact_mutation(authority, mutation)
    {
        return Err(ResetRepositoryError::AuthorityBindingMismatch);
    }
    discover_reset_identity_scope_for_actor(
        transaction,
        conversation_id,
        mutation.actor_did().as_str(),
        Uuid::from_bytes(*mutation.actor_device_id().as_bytes()),
    )
    .await
}

async fn discover_reset_identity_scope_for_actor(
    transaction: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    actor_did: &str,
    actor_device_id: Uuid,
) -> Result<CanonicalLockScope, ResetRepositoryError> {
    let principals: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT user_did
          FROM (
            SELECT p.user_did
              FROM chat.participants p
             WHERE p.conversation_id=$1 AND p.current_membership
            UNION
            SELECT $2::text
            UNION
            SELECT wd.recipient_did
              FROM chat.welcome_bundles wb
              JOIN chat.welcome_deliveries wd ON wd.welcome_id=wb.welcome_id
             WHERE wb.conversation_id=$1 AND wd.status='pending'
          ) candidate_principals
        "#,
    )
    .bind(conversation_id)
    .bind(actor_did)
    .fetch_all(&mut **transaction)
    .await?;
    let devices: Vec<(String, Uuid)> = sqlx::query_as(
        r#"
        SELECT user_did,device_id
          FROM (
            SELECT DISTINCT p.user_did,d.device_id
              FROM chat.participants p
              JOIN chat.devices d ON d.user_did=p.user_did
             WHERE p.conversation_id=$1 AND p.current_membership
            UNION
            SELECT $2::text,$3::uuid
            UNION
            SELECT wd.recipient_did,wd.recipient_device_id
              FROM chat.welcome_bundles wb
              JOIN chat.welcome_deliveries wd ON wd.welcome_id=wb.welcome_id
             WHERE wb.conversation_id=$1 AND wd.status='pending'
          ) candidate_devices
        "#,
    )
    .bind(conversation_id)
    .bind(actor_did)
    .bind(actor_device_id)
    .fetch_all(&mut **transaction)
    .await?;
    CanonicalLockScope::new(
        principals,
        devices
            .into_iter()
            .map(|(did, device_id)| CanonicalDeviceIdentity::new(did, device_id))
            .collect(),
    )
    .map_err(|_| ResetRepositoryError::NonCanonicalScope)
}

fn request_contains_exact_mutation(
    authority: &VerifiedChatDeviceRequest,
    mutation: &VerifiedSignedMutation,
) -> bool {
    authority.mutation().is_some_and(|admitted| {
        admitted.kind() == mutation.kind()
            && admitted.type_id() == mutation.type_id()
            && admitted.domain() == mutation.domain()
            && admitted.canonical_projection() == mutation.canonical_projection()
            && admitted.transcript_bytes() == mutation.transcript_bytes()
            && admitted.request_digest() == mutation.request_digest()
            && admitted.signature() == mutation.signature()
            && admitted.accepted_wrapper_bytes() == mutation.accepted_wrapper_bytes()
            && admitted.actor_did() == mutation.actor_did()
            && admitted.actor_device_id() == mutation.actor_device_id()
            && admitted.key_id() == mutation.key_id()
            && admitted.auth_generation() == mutation.auth_generation()
            && admitted.signed_at() == mutation.signed_at()
    })
}

async fn lock_head_nowait(
    transaction: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
) -> Result<(), ResetRepositoryError> {
    let result: Result<Option<Uuid>, sqlx::Error> = sqlx::query_scalar(
        "SELECT conversation_id FROM chat.conversations \
         WHERE conversation_id=$1 FOR UPDATE NOWAIT",
    )
    .bind(conversation_id)
    .fetch_optional(&mut **transaction)
    .await;
    match result {
        Ok(Some(id)) if id == conversation_id => Ok(()),
        Ok(None) => Err(ResetRepositoryError::ConversationMissing),
        Ok(Some(_)) => Err(ResetRepositoryError::GuardInvariant),
        Err(error)
            if error
                .as_database_error()
                .and_then(|error| error.code())
                .as_deref()
                == Some("55P03") =>
        {
            Err(ResetRepositoryError::HeadBusy)
        }
        Err(error) => Err(ResetRepositoryError::Database(error)),
    }
}

async fn lock_operation_and_pending_rows(
    transaction: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    operation_id: Uuid,
    request_id: Uuid,
    kind: ResetPreparationKind,
) -> Result<(), ResetRepositoryError> {
    let rows: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT reset_request_id,status FROM chat.reset_requests \
         WHERE (conversation_id=$1 AND status='pending') \
            OR reset_request_id=$2 OR reset_request_id=$3 \
         ORDER BY uuid_send(reset_request_id) FOR UPDATE",
    )
    .bind(conversation_id)
    .bind(operation_id)
    .bind(request_id)
    .fetch_all(&mut **transaction)
    .await?;
    for (id, status) in &rows {
        if *id == operation_id {
            return Err(ResetRepositoryError::OperationIdAlreadyUsed);
        }
        if *id == request_id && status != "pending" {
            return match kind {
                ResetPreparationKind::Request => Err(ResetRepositoryError::OperationIdAlreadyUsed),
                ResetPreparationKind::Activation => Err(ResetRepositoryError::PendingResetTerminal),
            };
        }
    }
    let transition_reused: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM chat.transitions WHERE transition_id=$1)")
            .bind(operation_id)
            .fetch_one(&mut **transaction)
            .await?;
    if transition_reused {
        return Err(ResetRepositoryError::OperationIdAlreadyUsed);
    }
    Ok(())
}

async fn load_locked_pending_row(
    transaction: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
) -> Result<Option<PendingResetRow>, ResetRepositoryError> {
    Ok(sqlx::query_as(
        r#"
        SELECT reset_request_id,conversation_id,requester_did,requester_device_id,
               requester_key_id,requester_auth_generation,prior_generation,
               prior_state_version,prior_group_id,prior_epoch,
               prior_group_context_hash,prior_confirmation_tag,reason,status,
               signed_request_bytes,signing_transcript_bytes,request_digest,
               signature,received_at,expires_at,terminal_transition_id,terminal_at
          FROM chat.reset_requests
         WHERE conversation_id=$1 AND status='pending'
         FOR UPDATE
        "#,
    )
    .bind(conversation_id)
    .fetch_optional(&mut **transaction)
    .await?)
}

/// Which authority a pending row is sealed AGAINST.
///
/// `Live` is the strict rule both endpoints have always used: the ORIGINAL
/// requester's device and key must still be active, unrevoked, and at the exact
/// generation the row recorded.
///
/// `RecordedForDisposal` exists only so a LAPSED row can be disposed of. It
/// binds to the authority the row itself RECORDED and to its immutable signed
/// bytes — every structural check, the coordinate match, the transcript digest,
/// the recorded public-key hash and a full re-verification of the signature
/// still run — and skips ONLY the live-device comparison. It authorizes exactly
/// one terminal, `Expired`. `activateReset` never uses it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ResetAuthorityBinding {
    Live,
    RecordedForDisposal,
}

fn seal_pending_reset(
    row: PendingResetRow,
    transaction_id: &str,
    trusted_instant: DateTime<Utc>,
    scope: &ScopeBoundBusinessAuthority,
    head_coordinate: &PublicGroupSnapshotCoordinate,
    head_digest: [u8; 32],
    preparation_kind: ResetPreparationKind,
    operation_id: Uuid,
    binding: ResetAuthorityBinding,
) -> Result<LockedPendingResetRequestGuard, ResetRepositoryError> {
    if row.status != "pending"
        || row.terminal_transition_id.is_some()
        || row.terminal_at.is_some()
        || !uuid_v4(row.reset_request_id)
        || row.conversation_id != Uuid::from_bytes(*head_coordinate.conversation_id())
        || BareDid::parse(&row.requester_did).is_err()
        || KeyThumbprint::parse(&row.requester_key_id).is_err()
        || !whole_millis(row.received_at)
        || !whole_millis(row.expires_at)
        || row.expires_at != row.received_at + Duration::hours(24)
        || row.signed_request_bytes.is_empty()
        || row.signing_transcript_bytes.is_empty()
        || row.request_digest.len() != 32
        || row.signature.len() != 64
        || Sha256::digest(&row.signing_transcript_bytes).as_slice() != row.request_digest
        || !matches!(
            row.reason.as_str(),
            "localStateLost" | "poisonedState" | "epochDivergence" | "manualRecovery"
        )
    {
        return Err(ResetRepositoryError::InvalidResetRow);
    }
    let prior = coordinate_from_row(&row)?;
    if &prior != head_coordinate {
        return Err(ResetRepositoryError::PendingResetCoordinateMismatch);
    }
    let device = scope
        .devices()
        .iter()
        .find(|candidate| {
            candidate.user_did() == row.requester_did
                && candidate.device_id() == row.requester_device_id
        })
        .ok_or(ResetRepositoryError::MissingDevice)?;
    let key = scope
        .keys()
        .iter()
        .find(|candidate| {
            candidate.user_did() == row.requester_did
                && candidate.device_id() == row.requester_device_id
                && candidate.key_id() == row.requester_key_id
                && candidate.enrollment_auth_generation() == row.requester_auth_generation
        })
        .ok_or(ResetRepositoryError::MissingDeviceKey)?;
    // Finding 3: this comparison is what made a pending row unsealable — and so
    // the whole conversation unresettable — once its requester was revoked or
    // rebound. It stays exactly as strict for every live use, including all of
    // `activateReset`; only lapsed-row disposal is exempt, and that path binds
    // to the recorded authority re-verified below instead.
    if binding == ResetAuthorityBinding::Live
        && (device.auth_generation() != row.requester_auth_generation
            || key.enrollment_auth_generation() != row.requester_auth_generation
            || device.status() != "active"
            || device.revoked_at().is_some()
            || key.revoked_at().is_some())
    {
        return Err(ResetRepositoryError::DeviceOrKeyDrift);
    }
    let requester_public_key = scope
        .signing_public_key_for(
            &row.requester_did,
            row.requester_device_id,
            &row.requester_key_id,
            row.requester_auth_generation,
        )
        .ok_or(ResetRepositoryError::MissingDeviceKey)?;
    validate_requester_public_key_hash(requester_public_key, &key.signing_public_key_sha256())?;
    let verified =
        decode_and_verify_signed_mutation(&row.signed_request_bytes, requester_public_key)
            .map_err(|_| ResetRepositoryError::InvalidResetRow)?;
    let VerifiedMutationProjection::ResetRequest(projection) = verified.projection() else {
        return Err(ResetRepositoryError::InvalidResetRow);
    };
    let parsed = parse_reset_authority(&verified, ResetPreparationKind::Request)
        .map_err(|_| ResetRepositoryError::InvalidResetRow)?;
    if parsed.reset_request_id != row.reset_request_id
        || parsed.prior != prior
        || projection.reason() != row.reason
        || verified.actor_did().as_str() != row.requester_did
        || Uuid::from_bytes(*verified.actor_device_id().as_bytes()) != row.requester_device_id
        || verified.key_id().as_str() != row.requester_key_id
        || i64::try_from(verified.auth_generation()).ok() != Some(row.requester_auth_generation)
        || verified.transcript_bytes() != row.signing_transcript_bytes
        || verified.request_digest().as_slice() != row.request_digest
        || verified.signature().as_slice() != row.signature
        || verified.accepted_wrapper_bytes() != Some(row.signed_request_bytes.as_slice())
    {
        return Err(ResetRepositoryError::InvalidResetRow);
    }
    let request_digest: [u8; 32] = row
        .request_digest
        .as_slice()
        .try_into()
        .map_err(|_| ResetRepositoryError::InvalidResetRow)?;
    let signature: [u8; 64] = row
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| ResetRepositoryError::InvalidResetRow)?;
    let device_digest = candidate_device_digest(
        device.user_did(),
        device.device_id(),
        device.status(),
        device.auth_generation(),
        device.revoked_at(),
    );
    let key_digest = candidate_key_digest(
        key.user_did(),
        key.device_id(),
        key.key_id(),
        requester_public_key,
        key.enrollment_auth_generation(),
        key.revoked_at(),
    );
    let immutable_row_digest = reset_immutable_row_digest(&row, &prior);
    let authorized_terminal = match (binding, preparation_kind) {
        // Defence in depth: a disposal binding can mint EXACTLY the expiry
        // terminal, and only for a row that has genuinely lapsed. It can never
        // reach `Consumed` (an activation) or `Stale`, so relaxing the live
        // check cannot widen what the guard is able to authorize.
        (ResetAuthorityBinding::RecordedForDisposal, ResetPreparationKind::Request)
            if trusted_instant >= row.expires_at =>
        {
            SealedResetTerminal::Expired
        }
        (ResetAuthorityBinding::RecordedForDisposal, _) => {
            return Err(ResetRepositoryError::GuardInvariant);
        }
        (ResetAuthorityBinding::Live, ResetPreparationKind::Request)
            if trusted_instant >= row.expires_at =>
        {
            SealedResetTerminal::Expired
        }
        (ResetAuthorityBinding::Live, ResetPreparationKind::Request) => {
            SealedResetTerminal::Unavailable
        }
        (ResetAuthorityBinding::Live, ResetPreparationKind::Activation) => {
            SealedResetTerminal::Consumed {
                transition_id: operation_id,
            }
        }
    };
    let guard_digest = locked_pending_reset_digest(
        transaction_id,
        trusted_instant,
        scope.scope_digest(),
        &head_digest,
        &immutable_row_digest,
        &device_digest,
        &key_digest,
        authorized_terminal,
    );
    Ok(LockedPendingResetRequestGuard {
        transaction_id: transaction_id.to_owned().into_boxed_str(),
        trusted_instant,
        scope_digest: *scope.scope_digest(),
        head_digest,
        reset_request_id: row.reset_request_id,
        conversation_id: row.conversation_id,
        requester_did: row.requester_did.into_boxed_str(),
        requester_device_id: row.requester_device_id,
        requester_key_id: row.requester_key_id.into_boxed_str(),
        requester_auth_generation: row.requester_auth_generation,
        prior,
        reason: row.reason.into_boxed_str(),
        signed_request_bytes: row.signed_request_bytes.into_boxed_slice(),
        signing_transcript_bytes: row.signing_transcript_bytes.into_boxed_slice(),
        request_digest,
        signature,
        received_at: row.received_at,
        expires_at: row.expires_at,
        requester_device_digest: device_digest,
        requester_key_digest: key_digest,
        immutable_row_digest,
        authorized_terminal,
        guard_digest,
    })
}

async fn cas_terminalize(
    transaction: &mut Transaction<'_, Postgres>,
    guard: &LockedPendingResetRequestGuard,
    terminal: SealedResetTerminal,
) -> Result<(), ResetRepositoryError> {
    let (status, transition_id, terminal_at) = match terminal {
        SealedResetTerminal::Unavailable => {
            return Err(ResetRepositoryError::AuthorityBindingMismatch);
        }
        SealedResetTerminal::Consumed { transition_id } => {
            ("consumed", Some(transition_id), guard.trusted_instant)
        }
        SealedResetTerminal::Stale { transition_id } => {
            ("stale", Some(transition_id), guard.trusted_instant)
        }
        SealedResetTerminal::Expired => ("expired", None, guard.expires_at),
    };
    let result = sqlx::query(
        r#"
        UPDATE chat.reset_requests
           SET status=$20,terminal_transition_id=$21,terminal_at=$22
         WHERE reset_request_id=$1 AND conversation_id=$2
           AND requester_did=$3 AND requester_device_id=$4
           AND requester_key_id=$5 AND requester_auth_generation=$6
           AND prior_generation=$7 AND prior_state_version=$8
           AND prior_group_id=$9 AND prior_epoch=$10
           AND prior_group_context_hash=$11 AND prior_confirmation_tag=$12
           AND reason=$13 AND status='pending'
           AND signed_request_bytes=$14 AND signing_transcript_bytes=$15
           AND request_digest=$16 AND signature=$17
           AND received_at=$18 AND expires_at=$19
           AND terminal_transition_id IS NULL AND terminal_at IS NULL
        "#,
    )
    .bind(guard.reset_request_id)
    .bind(guard.conversation_id)
    .bind(&*guard.requester_did)
    .bind(guard.requester_device_id)
    .bind(&*guard.requester_key_id)
    .bind(guard.requester_auth_generation)
    .bind(
        i64::try_from(guard.prior.generation())
            .map_err(|_| ResetRepositoryError::GuardInvariant)?,
    )
    .bind(
        i64::try_from(guard.prior.state_version())
            .map_err(|_| ResetRepositoryError::GuardInvariant)?,
    )
    .bind(guard.prior.group_id().as_slice())
    .bind(i64::try_from(guard.prior.epoch()).map_err(|_| ResetRepositoryError::GuardInvariant)?)
    .bind(guard.prior.group_context_hash().as_slice())
    .bind(guard.prior.confirmation_tag().as_slice())
    .bind(&*guard.reason)
    .bind(&*guard.signed_request_bytes)
    .bind(&*guard.signing_transcript_bytes)
    .bind(guard.request_digest.as_slice())
    .bind(guard.signature.as_slice())
    .bind(guard.received_at)
    .bind(guard.expires_at)
    .bind(status)
    .bind(transition_id)
    .bind(terminal_at)
    .execute(&mut **transaction)
    .await?;
    if result.rows_affected() != 1 {
        return Err(ResetRepositoryError::CompareAndSetConflict);
    }
    Ok(())
}

async fn ensure_live_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    expected: &str,
) -> Result<(), ResetRepositoryError> {
    let actual: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await?;
    if actual != expected {
        return Err(ResetRepositoryError::ForeignTransaction);
    }
    Ok(())
}

fn coordinate_from_row(
    row: &PendingResetRow,
) -> Result<PublicGroupSnapshotCoordinate, ResetRepositoryError> {
    let generation = protocol_u64(row.prior_generation)?;
    let state_version = protocol_u64(row.prior_state_version)?;
    let epoch = protocol_u64(row.prior_epoch)?;
    Ok(PublicGroupSnapshotCoordinate::new(
        *row.conversation_id.as_bytes(),
        generation,
        state_version,
        row.prior_group_id
            .as_slice()
            .try_into()
            .map_err(|_| ResetRepositoryError::InvalidResetRow)?,
        epoch,
        row.prior_group_context_hash
            .as_slice()
            .try_into()
            .map_err(|_| ResetRepositoryError::InvalidResetRow)?,
        row.prior_confirmation_tag
            .as_slice()
            .try_into()
            .map_err(|_| ResetRepositoryError::InvalidResetRow)?,
        PublicGroupSnapshotLifecycle::Active,
    ))
}

fn protocol_u64(value: i64) -> Result<u64, ResetRepositoryError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value <= MAX_PROTOCOL_INTEGER)
        .ok_or(ResetRepositoryError::InvalidResetRow)
}

fn uuid_v4(value: Uuid) -> bool {
    value.get_version_num() == 4 && value.get_variant() == uuid::Variant::RFC4122
}

fn whole_millis(value: DateTime<Utc>) -> bool {
    value.timestamp_millis() >= 0 && value.timestamp_subsec_nanos() % 1_000_000 == 0
}

fn candidate_device_digest(
    user_did: &str,
    device_id: Uuid,
    status: &str,
    auth_generation: i64,
    revoked_at: Option<DateTime<Utc>>,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-RESET-CANDIDATE-DEVICE\0");
    digest_len(&mut digest, user_did.as_bytes());
    digest.update(device_id.as_bytes());
    digest_len(&mut digest, status.as_bytes());
    digest.update(auth_generation.to_be_bytes());
    digest_optional_time(&mut digest, revoked_at);
    digest.finalize().into()
}

fn candidate_key_digest(
    user_did: &str,
    device_id: Uuid,
    key_id: &str,
    signing_public_key: &[u8],
    enrollment_auth_generation: i64,
    revoked_at: Option<DateTime<Utc>>,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-RESET-CANDIDATE-KEY\0");
    digest_len(&mut digest, user_did.as_bytes());
    digest.update(device_id.as_bytes());
    digest_len(&mut digest, key_id.as_bytes());
    digest_len(&mut digest, signing_public_key);
    digest.update(enrollment_auth_generation.to_be_bytes());
    digest_optional_time(&mut digest, revoked_at);
    digest.finalize().into()
}

fn validate_requester_public_key_hash(
    requester_public_key: &[u8],
    stored_public_key_sha256: &[u8; 32],
) -> Result<(), ResetRepositoryError> {
    if <[u8; 32]>::from(Sha256::digest(requester_public_key)) != *stored_public_key_sha256 {
        return Err(ResetRepositoryError::DeviceOrKeyDrift);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_locked_pending_reset_digest(
    expected_guard_digest: &[u8; 32],
    transaction_id: &str,
    trusted_instant: DateTime<Utc>,
    scope_digest: &[u8; 32],
    head_digest: &[u8; 32],
    immutable_row_digest: &[u8; 32],
    requester_device_digest: &[u8; 32],
    requester_key_digest: &[u8; 32],
    terminal: SealedResetTerminal,
) -> Result<(), ResetRepositoryError> {
    if expected_guard_digest
        != &locked_pending_reset_digest(
            transaction_id,
            trusted_instant,
            scope_digest,
            head_digest,
            immutable_row_digest,
            requester_device_digest,
            requester_key_digest,
            terminal,
        )
    {
        return Err(ResetRepositoryError::GuardInvariant);
    }
    Ok(())
}

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(crate) enum PendingResetCryptographicBindingMutationForTest {
    ScopeDigest,
    RequesterDeviceDigest,
    RequesterKeyDigest,
    RawPublicKey,
    StoredRawPublicKeyHash,
}

#[cfg(test)]
pub(crate) fn pending_reset_cryptographic_binding_mutation_rejected_for_test(
    mutation: PendingResetCryptographicBindingMutationForTest,
) -> bool {
    let transaction_id = "reset-pure-fixture-transaction";
    let trusted_instant = DateTime::from_timestamp_millis(1_784_942_400_000).unwrap();
    let mut scope_digest = [1; 32];
    let head_digest = [2; 32];
    let immutable_row_digest = [3; 32];
    let mut requester_device_digest = [4; 32];
    let mut requester_key_digest = [5; 32];
    let terminal = SealedResetTerminal::Expired;
    let expected_guard_digest = locked_pending_reset_digest(
        transaction_id,
        trusted_instant,
        &scope_digest,
        &head_digest,
        &immutable_row_digest,
        &requester_device_digest,
        &requester_key_digest,
        terminal,
    );
    match mutation {
        PendingResetCryptographicBindingMutationForTest::ScopeDigest => scope_digest[0] ^= 1,
        PendingResetCryptographicBindingMutationForTest::RequesterDeviceDigest => {
            requester_device_digest[0] ^= 1
        }
        PendingResetCryptographicBindingMutationForTest::RequesterKeyDigest => {
            requester_key_digest[0] ^= 1
        }
        PendingResetCryptographicBindingMutationForTest::RawPublicKey
        | PendingResetCryptographicBindingMutationForTest::StoredRawPublicKeyHash => {
            let mut raw_public_key = [6; 32];
            let mut stored_hash: [u8; 32] = Sha256::digest(raw_public_key).into();
            match mutation {
                PendingResetCryptographicBindingMutationForTest::RawPublicKey => {
                    raw_public_key[0] ^= 1
                }
                PendingResetCryptographicBindingMutationForTest::StoredRawPublicKeyHash => {
                    stored_hash[0] ^= 1
                }
                _ => unreachable!(),
            }
            return validate_requester_public_key_hash(&raw_public_key, &stored_hash).is_err();
        }
    }
    validate_locked_pending_reset_digest(
        &expected_guard_digest,
        transaction_id,
        trusted_instant,
        &scope_digest,
        &head_digest,
        &immutable_row_digest,
        &requester_device_digest,
        &requester_key_digest,
        terminal,
    )
    .is_err()
}

fn reset_immutable_row_digest(
    row: &PendingResetRow,
    prior: &PublicGroupSnapshotCoordinate,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(RESET_REQUEST_IMMUTABLE_DOMAIN);
    digest.update(row.reset_request_id.as_bytes());
    digest.update(row.conversation_id.as_bytes());
    digest_len(&mut digest, row.requester_did.as_bytes());
    digest.update(row.requester_device_id.as_bytes());
    digest_len(&mut digest, row.requester_key_id.as_bytes());
    digest.update(row.requester_auth_generation.to_be_bytes());
    digest_coordinate(&mut digest, prior);
    digest_len(&mut digest, row.reason.as_bytes());
    digest_len(&mut digest, &row.signed_request_bytes);
    digest_len(&mut digest, &row.signing_transcript_bytes);
    digest_len(&mut digest, &row.request_digest);
    digest_len(&mut digest, &row.signature);
    digest.update(row.received_at.timestamp_millis().to_be_bytes());
    digest.update(row.expires_at.timestamp_millis().to_be_bytes());
    digest.finalize().into()
}

fn locked_pending_reset_digest(
    transaction_id: &str,
    trusted_instant: DateTime<Utc>,
    scope_digest: &[u8; 32],
    head_digest: &[u8; 32],
    immutable_row_digest: &[u8; 32],
    requester_device_digest: &[u8; 32],
    requester_key_digest: &[u8; 32],
    authorized_terminal: SealedResetTerminal,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(LOCKED_PENDING_RESET_DOMAIN);
    digest_len(&mut digest, transaction_id.as_bytes());
    digest.update(trusted_instant.timestamp_millis().to_be_bytes());
    digest.update(scope_digest);
    digest.update(head_digest);
    digest.update(immutable_row_digest);
    digest.update(requester_device_digest);
    digest.update(requester_key_digest);
    match authorized_terminal {
        SealedResetTerminal::Unavailable => digest.update([0]),
        SealedResetTerminal::Consumed { transition_id } => {
            digest.update([1]);
            digest.update(transition_id.as_bytes());
        }
        SealedResetTerminal::Stale { transition_id } => {
            digest.update([2]);
            digest.update(transition_id.as_bytes());
        }
        SealedResetTerminal::Expired => digest.update([3]),
    }
    digest.finalize().into()
}

#[allow(clippy::too_many_arguments)]
fn reset_admission_digest(
    operation_id: Uuid,
    request_digest: &[u8; 32],
    actor_did: &str,
    actor_device_id: Uuid,
    actor_key_id: &str,
    actor_auth_generation: i64,
    trusted_instant: DateTime<Utc>,
    scope_digest: &[u8; 32],
    head_digest: &[u8; 32],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(RESET_ADMISSION_DOMAIN);
    digest.update(operation_id.as_bytes());
    digest.update(request_digest);
    digest_len(&mut digest, actor_did.as_bytes());
    digest.update(actor_device_id.as_bytes());
    digest_len(&mut digest, actor_key_id.as_bytes());
    digest.update(actor_auth_generation.to_be_bytes());
    digest.update(trusted_instant.timestamp_millis().to_be_bytes());
    digest.update(scope_digest);
    digest.update(head_digest);
    digest.finalize().into()
}

fn admitted_mutation_digest(
    mutation: &VerifiedSignedMutation,
) -> Result<[u8; 32], ResetRepositoryError> {
    let accepted_wrapper = mutation
        .accepted_wrapper_bytes()
        .ok_or(ResetRepositoryError::NonCanonicalOperation)?;
    let mut digest = Sha256::new();
    digest.update(RESET_ADMITTED_MUTATION_DOMAIN);
    digest_len(&mut digest, mutation.type_id().as_bytes());
    digest_len(&mut digest, mutation.domain());
    digest_len(&mut digest, mutation.canonical_projection());
    digest_len(&mut digest, mutation.transcript_bytes());
    digest.update(mutation.request_digest());
    digest.update(mutation.signature());
    digest_len(&mut digest, accepted_wrapper);
    digest_len(&mut digest, mutation.actor_did().as_str().as_bytes());
    digest.update(mutation.actor_device_id().as_bytes());
    digest_len(&mut digest, mutation.key_id().as_str().as_bytes());
    digest.update(mutation.auth_generation().to_be_bytes());
    digest_len(&mut digest, mutation.signed_at().as_str().as_bytes());
    Ok(digest.finalize().into())
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
        PublicGroupSnapshotLifecycle::Active => 1,
        PublicGroupSnapshotLifecycle::Superseded => 2,
    }]);
}

#[cfg(not(test))]
fn reset_replay_post_state_digest(
    family: &str,
    head: &ResetReplayHeadRow,
    entry: &ResetReplayEntryRow,
) -> Sha256 {
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-RESET-REPLAY-POST-STATE\0");
    digest_len(&mut digest, family.as_bytes());
    digest_len(&mut digest, head.kind.as_bytes());
    digest_len(&mut digest, head.lifecycle.as_bytes());
    digest.update(head.current_generation.to_be_bytes());
    digest.update(head.current_state_version.to_be_bytes());
    digest.update(head.next_entry_seq.to_be_bytes());
    digest.update(entry.seq.to_be_bytes());
    digest_uuid(&mut digest, entry.entry_id);
    digest_len(&mut digest, &entry.accepted_payload_bytes);
    digest_len(&mut digest, &entry.accepted_payload_sha256);
    digest_len(&mut digest, &entry.signed_request_bytes);
    digest_len(&mut digest, &entry.request_digest);
    digest_len(&mut digest, &entry.signature);
    digest_len(&mut digest, &entry.server_fields_bytes);
    digest_len(&mut digest, &entry.outer_entry_fingerprint);
    digest_len(&mut digest, entry.actor_did.as_bytes());
    digest_uuid(&mut digest, entry.actor_device_id);
    digest_len(&mut digest, entry.actor_key_id.as_bytes());
    digest.update(entry.actor_auth_generation.to_be_bytes());
    digest_optional_i64(&mut digest, entry.generation);
    digest_optional_i64(&mut digest, entry.state_version);
    digest_optional_uuid(&mut digest, entry.transition_id);
    digest.update(entry.received_at.timestamp_millis().to_be_bytes());
    digest
}

#[cfg(not(test))]
fn digest_transition(digest: &mut Sha256, row: &ResetReplayTransitionRow) {
    digest_uuid(digest, row.transition_id);
    digest_uuid(digest, row.conversation_id);
    digest_len(digest, row.kind.as_bytes());
    digest_len(digest, row.actor_did.as_bytes());
    digest_uuid(digest, row.actor_device_id);
    digest_len(digest, row.actor_key_id.as_bytes());
    digest.update(row.actor_auth_generation.to_be_bytes());
    digest_len(digest, row.actor_role.as_bytes());
    digest_len(digest, row.actor_device_status.as_bytes());
    digest_len(digest, &row.signed_request_bytes);
    digest_len(digest, &row.unsigned_projection_bytes);
    digest_len(digest, &row.signing_transcript_bytes);
    digest_len(digest, &row.request_digest);
    digest_len(digest, &row.signature);
    digest_optional_i64(digest, row.prior_generation);
    digest_optional_i64(digest, row.prior_state_version);
    digest_optional_i64(digest, row.next_generation);
    digest_optional_i64(digest, row.next_state_version);
    digest_optional_i64(digest, row.retired_generation);
    digest_optional_i64(digest, row.retired_state_version);
    digest_optional_i64(digest, row.successor_generation);
    digest_optional_i64(digest, row.successor_state_version);
    digest_optional_uuid(digest, row.reset_request_id);
    digest.update(row.entry_seq.to_be_bytes());
    digest.update(row.accepted_at.timestamp_millis().to_be_bytes());
}

#[cfg(not(test))]
fn digest_generation_state(digest: &mut Sha256, row: &ResetReplaySuccessorRow) {
    digest_len(digest, &row.group_id);
    digest.update(row.epoch.to_be_bytes());
    digest_len(digest, &row.group_context_hash);
    digest_len(digest, &row.confirmation_tag);
    digest_len(digest, row.lifecycle.as_bytes());
    digest_len(digest, row.state_kind.as_bytes());
    digest_uuid(digest, row.producing_transition_id);
    digest.update(row.created_at.timestamp_millis().to_be_bytes());
}

#[cfg(not(test))]
#[allow(clippy::too_many_arguments)]
fn reset_replay_seal(
    transaction_id: &str,
    operation_id: Uuid,
    principal_did: &str,
    endpoint_nsid: &str,
    mutation_kind: SignedMutationKind,
    request_digest: &[u8; 32],
    accepted_request_sha256: &[u8; 32],
    signature: &[u8; 64],
    post_state_digest: &[u8; 32],
    expected_response_status: i32,
    expected_response_sha256: &[u8; 32],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-RESET-REPLAY-PROOF\0");
    digest_len(&mut digest, transaction_id.as_bytes());
    digest_uuid(&mut digest, operation_id);
    digest_len(&mut digest, principal_did.as_bytes());
    digest_len(&mut digest, endpoint_nsid.as_bytes());
    digest_len(&mut digest, mutation_kind.type_id().as_bytes());
    digest.update(request_digest);
    digest.update(accepted_request_sha256);
    digest.update(signature);
    digest.update(post_state_digest);
    digest.update(expected_response_status.to_be_bytes());
    digest.update(expected_response_sha256);
    digest.finalize().into()
}

#[cfg(not(test))]
fn digest_uuid(digest: &mut Sha256, value: Uuid) {
    digest.update(value.as_bytes());
}

#[cfg(not(test))]
fn digest_optional_uuid(digest: &mut Sha256, value: Option<Uuid>) {
    match value {
        Some(value) => {
            digest.update([1]);
            digest_uuid(digest, value);
        }
        None => digest.update([0]),
    }
}

#[cfg(not(test))]
fn digest_optional_i64(digest: &mut Sha256, value: Option<i64>) {
    match value {
        Some(value) => {
            digest.update([1]);
            digest.update(value.to_be_bytes());
        }
        None => digest.update([0]),
    }
}

fn digest_len(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

fn digest_optional_time(digest: &mut Sha256, value: Option<DateTime<Utc>>) {
    match value {
        None => digest.update([0]),
        Some(value) => {
            digest.update([1]);
            digest.update(value.timestamp_millis().to_be_bytes());
        }
    }
}
