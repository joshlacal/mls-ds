// Transaction-bound repository authority for clean-chat Reset.
//
// This is deliberately separate from `repository::transition`: transition
// contains exact row writers, while this module owns the prewrite read-set,
// canonical lock order, immutable pending-request witness, expiry replacement
// authority, and full-row terminal CAS.

#[cfg(test)]
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use sqlx::{Acquire, FromRow, Postgres, Transaction};
use uuid::Uuid;

use super::{
    auth::{BusinessAuthorityGuard, RepositoryAuthorityClass},
    core::{
        hydrate_locked_conversation_state, ConversationHeadHydrationError,
        ConversationStateHydrationError, LockedConversationStateGuard, LockedRecoveryPackageGuard,
    },
};
use crate::chat_protocol::{
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

const MAX_PREPARE_ATTEMPTS: usize = 3;
const RESET_REQUEST_IMMUTABLE_DOMAIN: &[u8] = b"CATBIRD-CHAT-RESET-REQUEST-IMMUTABLE-ROW\0";
const LOCKED_PENDING_RESET_DOMAIN: &[u8] = b"CATBIRD-CHAT-LOCKED-PENDING-RESET-REQUEST\0";
const RESET_CANDIDATE_SCOPE_DOMAIN: &[u8] = b"CATBIRD-CHAT-RESET-CANDIDATE-SCOPE\0";
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

#[derive(Clone, Debug, Eq, PartialEq, FromRow)]
struct ResetCandidateRow {
    user_did: String,
    device_id: Uuid,
    status: String,
    auth_generation: i64,
    key_id: Option<String>,
    signing_public_key: Option<Vec<u8>>,
    enrollment_auth_generation: Option<i64>,
    device_revoked_at: Option<DateTime<Utc>>,
    key_revoked_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResetCandidateSnapshot {
    principals: Vec<String>,
    rows: Vec<ResetCandidateRow>,
}

#[derive(Debug)]
struct LockedResetScope {
    principals: Box<[String]>,
    rows: Box<[ResetCandidateRow]>,
    digest: [u8; 32],
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
    actor_dpop_jkt: Box<str>,
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
        business: BusinessAuthorityGuard,
        mutation: &VerifiedSignedMutation,
        entry: VerifiedControlEntry,
    ) -> Result<PlannedTransition, ResetCompositionError> {
        if !matches!(self.disposition, LockedResetRequestDisposition::Vacant) {
            return Err(ResetRepositoryError::PendingResetAlreadyExists.into());
        }
        validate_sealed_admission(
            &business,
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
            &self.actor_dpop_jkt,
            &self.transaction_id,
            self.trusted_instant,
            &self.scope_digest,
            &self.head_digest,
            &self.admission_digest,
        )?;
        validate_control_entry_mutation(&entry, mutation)?;
        plan_reset_request_entry(self.aggregate, business, entry)
    }
}

#[must_use]
#[derive(Debug)]
pub(crate) struct LockedResetActivationAuthority {
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
    actor_dpop_jkt: Box<str>,
    scope_digest: [u8; 32],
    head_digest: [u8; 32],
    admission_digest: [u8; 32],
    request: LockedPendingResetRequestGuard,
}

impl LockedResetActivationAuthority {
    pub(crate) fn request(&self) -> &LockedPendingResetRequestGuard {
        &self.request
    }

    pub(crate) fn plan_reset_activation_entry(
        self,
        business: BusinessAuthorityGuard,
        mutation: &VerifiedSignedMutation,
        entry: VerifiedControlEntry,
        terminal_packages: Vec<LockedRecoveryPackageGuard>,
    ) -> Result<(PlannedTransition, LockedPendingResetRequestGuard), ResetCompositionError> {
        validate_sealed_admission(
            &business,
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
            &self.actor_dpop_jkt,
            &self.transaction_id,
            self.trusted_instant,
            &self.scope_digest,
            &self.head_digest,
            &self.admission_digest,
        )?;
        validate_control_entry_mutation(&entry, mutation)?;
        let plan = plan_reset_activation_entry(self.aggregate, business, entry, terminal_packages)?;
        Ok((plan, self.request))
    }
}

#[must_use]
#[derive(Debug)]
pub(crate) struct ExpiredResetReplacementProof {
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
    actor_dpop_jkt: Box<str>,
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

    pub(crate) fn authorizes_replacement(
        &self,
        business: &BusinessAuthorityGuard,
        mutation: &VerifiedSignedMutation,
    ) -> bool {
        validate_sealed_admission(
            business,
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
            &self.actor_dpop_jkt,
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
        business: BusinessAuthorityGuard,
        mutation: &VerifiedSignedMutation,
        entry: VerifiedControlEntry,
    ) -> Result<PlannedTransition, ResetCompositionError> {
        validate_sealed_admission(
            &business,
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
            &self.actor_dpop_jkt,
            &self.transaction_id,
            self.trusted_instant,
            &self.scope_digest,
            &self.head_digest,
            &self.admission_digest,
        )?;
        validate_control_entry_mutation(&entry, mutation)?;
        plan_reset_request_entry(self.aggregate, business, entry)
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
    actor_dpop_jkt: String,
    scope: LockedResetScope,
    head_digest: [u8; 32],
    pending: Option<LockedPendingResetRequestGuard>,
}

pub(crate) async fn prepare_reset_request_authority(
    transaction: &mut Transaction<'_, Postgres>,
    business: &BusinessAuthorityGuard,
    authority: &VerifiedSignedMutation,
) -> Result<LockedResetRequestAuthority, ResetRepositoryError> {
    let parsed = parse_reset_authority(authority, ResetPreparationKind::Request)?;
    let prepared = prepare_reset_read_set(transaction, business, authority, &parsed).await?;
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
        &prepared.scope.digest,
        &prepared.head_digest,
    );
    Ok(LockedResetRequestAuthority {
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
        actor_dpop_jkt: prepared.actor_dpop_jkt.into_boxed_str(),
        scope_digest: prepared.scope.digest,
        head_digest: prepared.head_digest,
        admission_digest,
        disposition,
    })
}

#[cfg(test)]
pub(crate) async fn prepare_reset_request_authority_with_probe_for_test(
    transaction: &mut Transaction<'_, Postgres>,
    business: &BusinessAuthorityGuard,
    authority: &VerifiedSignedMutation,
    probe: &mut ResetPrepareProbeForTest,
) -> Result<LockedResetRequestAuthority, ResetRepositoryError> {
    let parsed = parse_reset_authority(authority, ResetPreparationKind::Request)?;
    let prepared =
        prepare_reset_read_set_with_probe(transaction, business, authority, &parsed, probe).await?;
    finish_reset_request_authority(prepared)
}

pub(crate) async fn prepare_reset_activation_authority(
    transaction: &mut Transaction<'_, Postgres>,
    business: &BusinessAuthorityGuard,
    authority: &VerifiedSignedMutation,
) -> Result<LockedResetActivationAuthority, ResetRepositoryError> {
    let parsed = parse_reset_authority(authority, ResetPreparationKind::Activation)?;
    let prepared = prepare_reset_read_set(transaction, business, authority, &parsed).await?;
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
    let admission_digest = reset_admission_digest(
        prepared.operation_id,
        &prepared.incoming_request_digest,
        &prepared.actor_did,
        prepared.actor_device_id,
        &prepared.actor_key_id,
        prepared.actor_auth_generation,
        prepared.trusted_instant,
        &prepared.scope.digest,
        &prepared.head_digest,
    );
    Ok(LockedResetActivationAuthority {
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
        actor_dpop_jkt: prepared.actor_dpop_jkt.into_boxed_str(),
        scope_digest: prepared.scope.digest,
        head_digest: prepared.head_digest,
        admission_digest,
        request,
    })
}

pub(crate) async fn expire_pending_reset_for_replacement(
    transaction: &mut Transaction<'_, Postgres>,
    authority: LockedResetRequestAuthority,
) -> Result<ExpiredResetReplacementProof, ResetRepositoryError> {
    let LockedResetRequestAuthority {
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
    if guard.guard_digest
        != locked_pending_reset_digest(
            &guard.transaction_id,
            guard.trusted_instant,
            &guard.scope_digest,
            &guard.head_digest,
            &guard.immutable_row_digest,
            &guard.requester_device_digest,
            &guard.requester_key_digest,
            guard.authorized_terminal,
        )
    {
        return Err(ResetRepositoryError::GuardInvariant);
    }
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

async fn prepare_reset_read_set(
    transaction: &mut Transaction<'_, Postgres>,
    business: &BusinessAuthorityGuard,
    authority: &VerifiedSignedMutation,
    parsed: &ParsedResetAuthority,
) -> Result<PreparedResetReadSet, ResetRepositoryError> {
    #[cfg(test)]
    {
        return prepare_reset_read_set_inner(transaction, business, authority, parsed, None).await;
    }
    #[cfg(not(test))]
    {
        prepare_reset_read_set_inner(transaction, business, authority, parsed).await
    }
}

#[cfg(test)]
async fn prepare_reset_read_set_with_probe(
    transaction: &mut Transaction<'_, Postgres>,
    business: &BusinessAuthorityGuard,
    authority: &VerifiedSignedMutation,
    parsed: &ParsedResetAuthority,
    probe: &mut ResetPrepareProbeForTest,
) -> Result<PreparedResetReadSet, ResetRepositoryError> {
    prepare_reset_read_set_inner(transaction, business, authority, parsed, Some(probe)).await
}

async fn prepare_reset_read_set_inner(
    transaction: &mut Transaction<'_, Postgres>,
    business: &BusinessAuthorityGuard,
    authority: &VerifiedSignedMutation,
    parsed: &ParsedResetAuthority,
    #[cfg(test)] mut probe: Option<&mut ResetPrepareProbeForTest>,
) -> Result<PreparedResetReadSet, ResetRepositoryError> {
    validate_business_binding(business, authority)?;
    let conversation_id = Uuid::from_bytes(*parsed.prior.conversation_id());

    for attempt in 0..MAX_PREPARE_ATTEMPTS {
        #[cfg(test)]
        if let Some(probe) = probe.as_deref_mut() {
            probe.attempts += 1;
        }
        let mut savepoint = (&mut **transaction).begin().await?;
        match prepare_reset_attempt(
            &mut savepoint,
            business,
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
                return Ok(value);
            }
            Err(error)
                if attempt + 1 < MAX_PREPARE_ATTEMPTS
                    && matches!(
                        error,
                        ResetRepositoryError::HeadBusy | ResetRepositoryError::CandidateScopeDrift
                    ) =>
            {
                savepoint.rollback().await?;
            }
            Err(error) => {
                savepoint.rollback().await?;
                return if matches!(
                    error,
                    ResetRepositoryError::HeadBusy | ResetRepositoryError::CandidateScopeDrift
                ) {
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
    business: &BusinessAuthorityGuard,
    authority: &VerifiedSignedMutation,
    parsed: &ParsedResetAuthority,
    conversation_id: Uuid,
    #[cfg(test)] probe: Option<&mut ResetPrepareProbeForTest>,
) -> Result<PreparedResetReadSet, ResetRepositoryError> {
    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await?;
    if transaction_id != business.transaction_id() {
        return Err(ResetRepositoryError::ForeignTransaction);
    }
    let trusted_instant = business.trusted_instant();
    if !whole_millis(trusted_instant) {
        return Err(ResetRepositoryError::TrustedInstantMismatch);
    }

    let s0 = load_candidate_scope(transaction, conversation_id, business).await?;
    lock_principals(transaction, &s0.principals).await?;
    let s1 = load_candidate_scope(transaction, conversation_id, business).await?;
    if s1 != s0 {
        return Err(ResetRepositoryError::CandidateScopeDrift);
    }
    lock_candidate_devices_and_keys(transaction, &s1.rows).await?;
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
    let s2 = load_candidate_scope(transaction, conversation_id, business).await?;
    if s2 != s1 {
        return Err(ResetRepositoryError::CandidateScopeDrift);
    }
    let scope = LockedResetScope {
        digest: candidate_scope_digest(&s2),
        principals: s2.principals.into_boxed_slice(),
        rows: s2.rows.into_boxed_slice(),
    };
    validate_actor_scope_binding(&scope, business)?;

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
        Some(row) => Some(seal_pending_reset(
            row,
            &transaction_id,
            trusted_instant,
            &scope,
            head_coordinate,
            head_digest,
            parsed.kind,
            parsed.operation_id,
        )?),
    };

    Ok(PreparedResetReadSet {
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
        actor_signing_public_key: business
            .stored_signing_public_key()
            .ok_or(ResetRepositoryError::AuthorityBindingMismatch)?
            .to_vec(),
        actor_dpop_jkt: business
            .stored_dpop_jkt()
            .ok_or(ResetRepositoryError::AuthorityBindingMismatch)?
            .to_owned(),
        scope,
        head_digest,
        pending,
    })
}

fn validate_business_binding(
    business: &BusinessAuthorityGuard,
    authority: &VerifiedSignedMutation,
) -> Result<(), ResetRepositoryError> {
    if business.class() != RepositoryAuthorityClass::ExistingDevice {
        return Err(ResetRepositoryError::UnsupportedAuthority);
    }
    let actor_device_id = Uuid::from_bytes(*authority.actor_device_id().as_bytes());
    let auth_generation = i64::try_from(authority.auth_generation())
        .map_err(|_| ResetRepositoryError::AuthorityBindingMismatch)?;
    if business.subject() != authority.actor_did().as_str()
        || business.device_id() != actor_device_id
        || business.stored_auth_generation() != Some(auth_generation)
        || business.stored_key_id() != Some(authority.key_id().as_str())
        || business.stored_signing_public_key().is_none()
    {
        return Err(ResetRepositoryError::AuthorityBindingMismatch);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_sealed_admission(
    business: &BusinessAuthorityGuard,
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
    actor_dpop_jkt: &str,
    transaction_id: &str,
    trusted_instant: DateTime<Utc>,
    scope_digest: &[u8; 32],
    head_digest: &[u8; 32],
    admission_digest: &[u8; 32],
) -> Result<(), ResetRepositoryError> {
    validate_business_binding(business, mutation)?;
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
        || business.class() != RepositoryAuthorityClass::ExistingDevice
        || business.transaction_id() != transaction_id
        || business.trusted_instant() != trusted_instant
        || business.subject() != actor_did
        || business.device_id() != actor_device_id
        || business.stored_key_id() != Some(actor_key_id)
        || business.stored_auth_generation() != Some(actor_auth_generation)
        || business.stored_signing_public_key() != Some(actor_signing_public_key)
        || business.stored_dpop_jkt() != Some(actor_dpop_jkt)
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
    aggregate: LockedConversationStateGuard,
    business: BusinessAuthorityGuard,
    entry: VerifiedControlEntry,
) -> Result<PlannedTransition, ResetCompositionError> {
    let hydration = HydrationAuthority::from_locked_conversation(&aggregate)?;
    let registration = hydration.locked_registration_from_guard(business)?;
    Ok(hydration.plan_reset_request_entry(&aggregate, entry, registration)?)
}

fn plan_reset_activation_entry(
    aggregate: LockedConversationStateGuard,
    business: BusinessAuthorityGuard,
    entry: VerifiedControlEntry,
    terminal_packages: Vec<LockedRecoveryPackageGuard>,
) -> Result<PlannedTransition, ResetCompositionError> {
    let hydration = HydrationAuthority::from_locked_conversation(&aggregate)?;
    let registration = hydration.locked_registration_from_guard(business)?;
    Ok(hydration.plan_reset_activation_entry(
        &aggregate,
        entry,
        &registration,
        terminal_packages,
    )?)
}

fn validate_actor_scope_binding(
    scope: &LockedResetScope,
    business: &BusinessAuthorityGuard,
) -> Result<(), ResetRepositoryError> {
    let row = scope
        .rows
        .iter()
        .find(|row| {
            row.user_did == business.subject()
                && row.device_id == business.device_id()
                && row.key_id.as_deref() == business.stored_key_id()
        })
        .ok_or(ResetRepositoryError::MissingDeviceKey)?;
    if row.status != "active"
        || row.device_revoked_at.is_some()
        || row.key_revoked_at.is_some()
        || Some(row.auth_generation) != business.stored_auth_generation()
        || row.enrollment_auth_generation != Some(row.auth_generation)
        || row.signing_public_key.as_deref() != business.stored_signing_public_key()
    {
        return Err(ResetRepositoryError::AuthorityBindingMismatch);
    }
    Ok(())
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

async fn load_candidate_scope(
    transaction: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    business: &BusinessAuthorityGuard,
) -> Result<ResetCandidateSnapshot, ResetRepositoryError> {
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
         ORDER BY convert_to(user_did,'UTF8')
        "#,
    )
    .bind(conversation_id)
    .bind(business.subject())
    .fetch_all(&mut **transaction)
    .await?;
    let rows = sqlx::query_as(
        r#"
        WITH candidate_identities(user_did,device_id) AS (
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
        )
        SELECT c.user_did,c.device_id,d.status,d.auth_generation,
               k.key_id,k.signing_public_key,k.enrollment_auth_generation,
               d.revoked_at AS device_revoked_at,k.revoked_at AS key_revoked_at
          FROM candidate_identities c
          JOIN chat.devices d
            ON d.user_did=c.user_did AND d.device_id=c.device_id
          LEFT JOIN chat.device_keys k
            ON k.user_did=d.user_did AND k.device_id=d.device_id
         ORDER BY convert_to(c.user_did,'UTF8'),uuid_send(c.device_id),
                  k.key_id IS NULL,convert_to(k.key_id,'UTF8')
        "#,
    )
    .bind(conversation_id)
    .bind(business.subject())
    .bind(business.device_id())
    .fetch_all(&mut **transaction)
    .await?;
    if principals.is_empty() || rows.is_empty() {
        return Err(ResetRepositoryError::NonCanonicalScope);
    }
    Ok(ResetCandidateSnapshot { principals, rows })
}

async fn lock_principals(
    transaction: &mut Transaction<'_, Postgres>,
    principals: &[String],
) -> Result<(), ResetRepositoryError> {
    if !principals
        .windows(2)
        .all(|pair| pair[0].as_bytes() < pair[1].as_bytes())
    {
        return Err(ResetRepositoryError::NonCanonicalScope);
    }
    for did in principals {
        let locked: Option<String> =
            sqlx::query_scalar("SELECT user_did FROM chat.principals WHERE user_did=$1 FOR UPDATE")
                .bind(did)
                .fetch_optional(&mut **transaction)
                .await?;
        if locked.as_deref() != Some(did.as_str()) {
            return Err(ResetRepositoryError::MissingPrincipal);
        }
    }
    Ok(())
}

async fn lock_candidate_devices_and_keys(
    transaction: &mut Transaction<'_, Postgres>,
    rows: &[ResetCandidateRow],
) -> Result<(), ResetRepositoryError> {
    let mut last_device: Option<(&str, Uuid)> = None;
    for row in rows {
        let identity = (row.user_did.as_str(), row.device_id);
        if last_device == Some(identity) {
            continue;
        }
        let locked: Option<(String, i64, Option<DateTime<Utc>>)> = sqlx::query_as(
            "SELECT status,auth_generation,revoked_at FROM chat.devices \
             WHERE user_did=$1 AND device_id=$2 FOR UPDATE",
        )
        .bind(&row.user_did)
        .bind(row.device_id)
        .fetch_optional(&mut **transaction)
        .await?;
        if locked.as_ref()
            != Some(&(
                row.status.clone(),
                row.auth_generation,
                row.device_revoked_at,
            ))
        {
            return Err(ResetRepositoryError::DeviceOrKeyDrift);
        }
        last_device = Some(identity);
    }

    for row in rows {
        let Some(key_id) = row.key_id.as_deref() else {
            if row.signing_public_key.is_some()
                || row.enrollment_auth_generation.is_some()
                || row.key_revoked_at.is_some()
            {
                return Err(ResetRepositoryError::DeviceOrKeyDrift);
            }
            continue;
        };
        let locked: Option<(Vec<u8>, i64, Option<DateTime<Utc>>)> = sqlx::query_as(
            "SELECT signing_public_key,enrollment_auth_generation,revoked_at FROM chat.device_keys \
             WHERE user_did=$1 AND device_id=$2 AND key_id=$3 FOR UPDATE",
        )
        .bind(&row.user_did)
        .bind(row.device_id)
        .bind(key_id)
        .fetch_optional(&mut **transaction)
        .await?;
        if locked.as_ref().map(|(public_key, generation, revoked_at)| {
            (public_key.as_slice(), *generation, *revoked_at)
        }) != Some((
            row.signing_public_key
                .as_deref()
                .ok_or(ResetRepositoryError::DeviceOrKeyDrift)?,
            row.enrollment_auth_generation
                .ok_or(ResetRepositoryError::DeviceOrKeyDrift)?,
            row.key_revoked_at,
        )) {
            return Err(ResetRepositoryError::DeviceOrKeyDrift);
        }
    }
    Ok(())
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

fn seal_pending_reset(
    row: PendingResetRow,
    transaction_id: &str,
    trusted_instant: DateTime<Utc>,
    scope: &LockedResetScope,
    head_coordinate: &PublicGroupSnapshotCoordinate,
    head_digest: [u8; 32],
    preparation_kind: ResetPreparationKind,
    operation_id: Uuid,
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
    let candidate = scope
        .rows
        .iter()
        .find(|candidate| {
            candidate.user_did == row.requester_did
                && candidate.device_id == row.requester_device_id
                && candidate.key_id.as_deref() == Some(row.requester_key_id.as_str())
        })
        .ok_or(ResetRepositoryError::MissingDeviceKey)?;
    if candidate.auth_generation != row.requester_auth_generation
        || candidate.enrollment_auth_generation != Some(row.requester_auth_generation)
        || candidate.status != "active"
        || candidate.device_revoked_at.is_some()
        || candidate.key_revoked_at.is_some()
    {
        return Err(ResetRepositoryError::DeviceOrKeyDrift);
    }
    let requester_public_key = candidate
        .signing_public_key
        .as_deref()
        .ok_or(ResetRepositoryError::MissingDeviceKey)?;
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
    let device_digest = candidate_device_digest(candidate);
    let key_digest = candidate_key_digest(candidate)?;
    let immutable_row_digest = reset_immutable_row_digest(&row, &prior);
    let authorized_terminal = match preparation_kind {
        ResetPreparationKind::Request if trusted_instant >= row.expires_at => {
            SealedResetTerminal::Expired
        }
        ResetPreparationKind::Request => SealedResetTerminal::Unavailable,
        ResetPreparationKind::Activation => SealedResetTerminal::Consumed {
            transition_id: operation_id,
        },
    };
    let guard_digest = locked_pending_reset_digest(
        transaction_id,
        trusted_instant,
        &scope.digest,
        &head_digest,
        &immutable_row_digest,
        &device_digest,
        &key_digest,
        authorized_terminal,
    );
    Ok(LockedPendingResetRequestGuard {
        transaction_id: transaction_id.to_owned().into_boxed_str(),
        trusted_instant,
        scope_digest: scope.digest,
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

fn candidate_scope_digest(snapshot: &ResetCandidateSnapshot) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(RESET_CANDIDATE_SCOPE_DOMAIN);
    digest.update((snapshot.principals.len() as u64).to_be_bytes());
    for principal in &snapshot.principals {
        digest_len(&mut digest, principal.as_bytes());
    }
    digest.update((snapshot.rows.len() as u64).to_be_bytes());
    for row in &snapshot.rows {
        digest_len(&mut digest, row.user_did.as_bytes());
        digest.update(row.device_id.as_bytes());
        digest_len(&mut digest, row.status.as_bytes());
        digest.update(row.auth_generation.to_be_bytes());
        match (
            row.key_id.as_deref(),
            row.signing_public_key.as_deref(),
            row.enrollment_auth_generation,
        ) {
            (None, None, None) => digest.update([0]),
            (Some(key_id), Some(signing_public_key), Some(enrollment_auth_generation)) => {
                digest.update([1]);
                digest_len(&mut digest, key_id.as_bytes());
                digest_len(&mut digest, signing_public_key);
                digest.update(enrollment_auth_generation.to_be_bytes());
            }
            _ => digest.update([2]),
        }
        digest_optional_time(&mut digest, row.device_revoked_at);
        digest_optional_time(&mut digest, row.key_revoked_at);
    }
    digest.finalize().into()
}

fn candidate_device_digest(row: &ResetCandidateRow) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-RESET-CANDIDATE-DEVICE\0");
    digest_len(&mut digest, row.user_did.as_bytes());
    digest.update(row.device_id.as_bytes());
    digest_len(&mut digest, row.status.as_bytes());
    digest.update(row.auth_generation.to_be_bytes());
    digest_optional_time(&mut digest, row.device_revoked_at);
    digest.finalize().into()
}

fn candidate_key_digest(row: &ResetCandidateRow) -> Result<[u8; 32], ResetRepositoryError> {
    let key_id = row
        .key_id
        .as_deref()
        .ok_or(ResetRepositoryError::MissingDeviceKey)?;
    let signing_public_key = row
        .signing_public_key
        .as_deref()
        .ok_or(ResetRepositoryError::MissingDeviceKey)?;
    let enrollment_auth_generation = row
        .enrollment_auth_generation
        .ok_or(ResetRepositoryError::MissingDeviceKey)?;
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-RESET-CANDIDATE-KEY\0");
    digest_len(&mut digest, row.user_did.as_bytes());
    digest.update(row.device_id.as_bytes());
    digest_len(&mut digest, key_id.as_bytes());
    digest_len(&mut digest, signing_public_key);
    digest.update(enrollment_auth_generation.to_be_bytes());
    digest_optional_time(&mut digest, row.key_revoked_at);
    Ok(digest.finalize().into())
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
