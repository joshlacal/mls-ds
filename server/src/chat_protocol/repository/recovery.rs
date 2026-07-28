// Transaction-bound repository authority for clean-chat leaf Recovery.
//
// `transition` owns exact writes. This module owns the ordered read-set and
// linear authority that may feed those writes. Client-authored acquisition
// starts only after `PreparedBusinessPrelude` has locked the global operation
// identity and canonical principal/device/key prefix. The remaining order is
// conversation head+graph, recovery request, reservation, KeyPackage.
//
// This file is intentionally not wired from `repository/mod.rs` yet. Until the
// integration slice adds that module edge, the dedicated compile target
// includes it directly.

use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, Postgres, Transaction};
use uuid::Uuid;

#[cfg(not(test))]
use super::super::state_machine::{
    PlannedRecoveryMutation, PlannedSchedulerRecoveryExpiry, RecoveryPlannedKind,
};
use super::super::{
    dpop::VerifiedChatDeviceRequest,
    relationship_policy::{
        ProjectionOperationScope, PublicTransport, RelationshipAuthority, RelationshipProjection,
    },
    snapshot::MAX_PROTOCOL_INTEGER,
    state_machine::{
        recovery_plan_fingerprint, AppliedTransition, ConversationPersistencePlan, ExecutorError,
        HydrationAuthority, PlanAuthority, RecoveryPlanClass, ServerTimestamp, StateMachineError,
    },
    transcript::{
        decode_and_verify_signed_mutation, CanonicalValueRef, VerifiedMutationProjection,
        VerifiedSignedMutation,
    },
    validation::TrustedRequestInstant,
};
use super::{
    auth::RepositoryAuthorityClass,
    core::{
        hydrate_locked_available_recovery_package, hydrate_locked_conversation_state,
        hydrate_locked_reserved_recovery_package, ConversationStateHydrationError,
        LockedConversationStateGuard, LockedRecoveryPackageGuard, RecoveryPackageHydrationError,
    },
    execution_context::{
        apply_prepared_recovery_execution, prepare_recovery_execution,
        ExecutionContextHydrationError,
    },
    prelude::{
        canonical_operation_lock_key, CanonicalDeviceIdentity, CanonicalLockScope,
        OperationCompletionGuard, PreparedBusinessPrelude, RecoveryOperationEndpoint,
        RecoveryPreludeAggregatePlanBinding, RecoveryPreludeClientExpiryError,
        RecoveryPreludePersistenceMode, RecoveryPreludePlanBinding, RecoveryPreludePlanKind,
        RecoveryPreludePrewriteWitness, ScopeBoundBusinessAuthority,
    },
    relationship::{
        load_fallback_relationship_projection, seal_recovery_fallback_scope,
        LockedRelationshipDecisionGuard, RelationshipRepositoryError,
    },
    transition::{
        self, LeafRecoveryKind, LeafRecoverySource, NewLeafRecoveryRequest, NewReservation,
    },
};

const RECOVERY_AUTHORITY_DOMAIN: &[u8] = b"CATBIRD-CHAT-RECOVERY-REPOSITORY-AUTHORITY\0";
const RECOVERY_HEAD_DOMAIN: &[u8] = b"CATBIRD-CHAT-RECOVERY-HEAD\0";
const RECOVERY_GRAPH_DOMAIN: &[u8] = b"CATBIRD-CHAT-RECOVERY-GRAPH\0";
const RECOVERY_AGGREGATE_CROSS_BINDING_DOMAIN: &[u8] =
    b"CATBIRD-CHAT-RECOVERY-AGGREGATE-CROSS-BINDING\0";

/// Linear capability proving that Recovery repository code completed its
/// ordered locked read-set before constructing a Recovery SQL binding.
///
/// The field and mint are private to this module. `transition` may name and
/// require the type, but no other crate module can manufacture a value.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct RecoverySqlAuthoritySeal {
    _private: (),
}

impl RecoverySqlAuthoritySeal {
    fn mint() -> Self {
        Self { _private: () }
    }
}

/// Seals the generic aggregate read and Recovery's custom ordered head/graph
/// read into one transaction-local authority. The two digest families use
/// different domains and are therefore bound side-by-side after exact
/// coordinate equality; they are never incorrectly compared as equal.
#[derive(Debug, Eq, PartialEq)]
pub(in crate::chat_protocol) struct RecoveryAggregateCrossBinding {
    transaction_id: Box<str>,
    trusted_instant: DateTime<Utc>,
    conversation_id: Uuid,
    generation: i64,
    state_version: i64,
    group_id: [u8; 32],
    epoch: i64,
    group_context_hash: [u8; 32],
    confirmation_tag: [u8; 32],
    aggregate_head_digest: [u8; 32],
    aggregate_graph_digest: [u8; 32],
    aggregate_snapshot_digest: Option<[u8; 32]>,
    recovery_head_digest: [u8; 32],
    recovery_graph_digest: [u8; 32],
    seal_digest: [u8; 32],
}

impl RecoveryAggregateCrossBinding {
    fn seal(
        transaction_id: &str,
        trusted_instant: DateTime<Utc>,
        aggregate: &LockedConversationStateGuard,
        recovery: &LockedRecoveryHeadGraph,
    ) -> Result<Self, RecoveryRepositoryError> {
        let coordinate = aggregate
            .head()
            .prior_coordinate()
            .ok_or(RecoveryRepositoryError::ReadSetMismatch)?;
        let generation = i64::try_from(coordinate.generation())
            .map_err(|_| RecoveryRepositoryError::ReadSetMismatch)?;
        let state_version = i64::try_from(coordinate.state_version())
            .map_err(|_| RecoveryRepositoryError::ReadSetMismatch)?;
        let epoch = i64::try_from(coordinate.epoch())
            .map_err(|_| RecoveryRepositoryError::ReadSetMismatch)?;
        let conversation_id = Uuid::from_bytes(*coordinate.conversation_id());
        if aggregate.head().transaction_id() != transaction_id
            || aggregate.head().locked_at() != trusted_instant
            || conversation_id != recovery.conversation_id
            || generation != recovery.generation
            || state_version != recovery.state_version
            || coordinate.group_id() != &recovery.group_id
            || epoch != recovery.epoch
            || coordinate.group_context_hash() != &recovery.group_context_hash
            || coordinate.confirmation_tag() != &recovery.confirmation_tag
        {
            return Err(RecoveryRepositoryError::ReadSetMismatch);
        }
        let mut binding = Self {
            transaction_id: transaction_id.to_owned().into_boxed_str(),
            trusted_instant,
            conversation_id,
            generation,
            state_version,
            group_id: *coordinate.group_id(),
            epoch,
            group_context_hash: *coordinate.group_context_hash(),
            confirmation_tag: *coordinate.confirmation_tag(),
            aggregate_head_digest: *aggregate.head().durable_row_digest(),
            aggregate_graph_digest: *aggregate.locked_graph_digest(),
            aggregate_snapshot_digest: aggregate.locked_snapshot_digest().copied(),
            recovery_head_digest: recovery.head_digest,
            recovery_graph_digest: recovery.graph_digest,
            seal_digest: [0; 32],
        };
        binding.seal_digest = binding.rederive_digest();
        Ok(binding)
    }

    fn rederive_digest(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(RECOVERY_AGGREGATE_CROSS_BINDING_DOMAIN);
        digest_len(&mut digest, self.transaction_id.as_bytes());
        digest.update(self.trusted_instant.timestamp_millis().to_be_bytes());
        digest.update(self.conversation_id.as_bytes());
        digest.update(self.generation.to_be_bytes());
        digest.update(self.state_version.to_be_bytes());
        digest.update(self.group_id);
        digest.update(self.epoch.to_be_bytes());
        digest.update(self.group_context_hash);
        digest.update(self.confirmation_tag);
        digest.update(self.aggregate_head_digest);
        digest.update(self.aggregate_graph_digest);
        match self.aggregate_snapshot_digest {
            Some(value) => {
                digest.update([1]);
                digest.update(value);
            }
            None => digest.update([0]),
        }
        digest.update(self.recovery_head_digest);
        digest.update(self.recovery_graph_digest);
        digest.finalize().into()
    }

    fn validates(
        &self,
        aggregate: &LockedConversationStateGuard,
        recovery: &LockedRecoveryHeadGraph,
    ) -> bool {
        self.validates_live_aggregate_digests(
            aggregate.head().durable_row_digest(),
            aggregate.locked_graph_digest(),
            aggregate.locked_snapshot_digest(),
        ) && Self::seal(
            &self.transaction_id,
            self.trusted_instant,
            aggregate,
            recovery,
        )
        .is_ok_and(|expected| expected == *self && self.seal_digest == self.rederive_digest())
    }

    fn validates_live_aggregate_digests(
        &self,
        head: &[u8; 32],
        graph: &[u8; 32],
        snapshot: Option<&[u8; 32]>,
    ) -> bool {
        self.seal_digest == self.rederive_digest()
            && &self.aggregate_head_digest == head
            && &self.aggregate_graph_digest == graph
            && self.aggregate_snapshot_digest.as_ref() == snapshot
    }

    fn validates_reloaded_recovery_head(&self, recovery: &LockedRecoveryHeadGraph) -> bool {
        self.seal_digest == self.rederive_digest()
            && self.conversation_id == recovery.conversation_id
            && self.generation == recovery.generation
            && self.state_version == recovery.state_version
            && self.group_id == recovery.group_id
            && self.epoch == recovery.epoch
            && self.group_context_hash == recovery.group_context_hash
            && self.confirmation_tag == recovery.confirmation_tag
            && self.recovery_head_digest == recovery.head_digest
            && self.recovery_graph_digest == recovery.graph_digest
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum RecoveryLockStage {
    GlobalOperation,
    Principals,
    Devices,
    ActorKey,
    ConversationHead,
    ConversationGraph,
    RecoveryRequest,
    Reservation,
    KeyPackage,
    RelationshipSnapshot,
    RelationshipEvidence,
    RelationshipDecision,
}

pub(crate) const CANONICAL_RECOVERY_LOCK_ORDER: [RecoveryLockStage; 12] = [
    RecoveryLockStage::GlobalOperation,
    RecoveryLockStage::Principals,
    RecoveryLockStage::Devices,
    RecoveryLockStage::ActorKey,
    RecoveryLockStage::ConversationHead,
    RecoveryLockStage::ConversationGraph,
    RecoveryLockStage::RecoveryRequest,
    RecoveryLockStage::Reservation,
    RecoveryLockStage::KeyPackage,
    RecoveryLockStage::RelationshipSnapshot,
    RecoveryLockStage::RelationshipEvidence,
    RecoveryLockStage::RelationshipDecision,
];

pub(crate) const LOCK_RECOVERY_EXPIRY_PRINCIPAL_SQL: &str =
    "SELECT user_did FROM chat.principals WHERE user_did=$1 FOR UPDATE";

pub(crate) const LOCK_RECOVERY_EXPIRY_DEVICE_SQL: &str = r#"
    SELECT status,auth_generation,revoked_at
      FROM chat.devices
     WHERE user_did=$1 AND device_id=$2
     FOR UPDATE
"#;

pub(crate) const LOCK_RECOVERY_EXPIRY_KEY_SQL: &str = r#"
    SELECT signing_public_key,enrollment_auth_generation,revoked_at
      FROM chat.device_keys
     WHERE user_did=$1 AND device_id=$2 AND key_id=$3
     FOR UPDATE
"#;

pub(crate) const RECOVERY_TERMINAL_LOCATOR_SQL: &str = r#"
    SELECT recovery_request_id,conversation_id,requester_did,requester_device_id,
           requester_key_id,requester_auth_generation
      FROM chat.leaf_recovery_requests
     WHERE recovery_request_id=$1
"#;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryRowStatus {
    Open,
    Fulfilled,
    Cancelled,
    Expired,
    Superseded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryTerminalClassification {
    OpenLive,
    OpenDue,
    RetainedFulfilled,
    RetainedCancelled,
    RetainedExpired,
    RetainedSuperseded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryClientTerminalAction {
    Cancel,
    Fulfill,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryClientTerminalError {
    CancellationConflict,
    RecoveryNotFound,
    RecoveryExpired,
    RecoverySuperseded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryClientTerminalDisposition {
    Execute,
    ExpireFirst(RecoveryClientTerminalError),
    Retained(RecoveryClientTerminalError),
}

pub(crate) fn classify_client_terminal_disposition(
    action: RecoveryClientTerminalAction,
    classification: RecoveryTerminalClassification,
) -> RecoveryClientTerminalDisposition {
    use RecoveryClientTerminalAction::{Cancel, Fulfill};
    use RecoveryClientTerminalDisposition::{Execute, ExpireFirst, Retained};
    use RecoveryClientTerminalError::{
        CancellationConflict, RecoveryExpired, RecoveryNotFound, RecoverySuperseded,
    };
    use RecoveryTerminalClassification::{
        OpenDue, OpenLive, RetainedCancelled, RetainedExpired, RetainedFulfilled,
        RetainedSuperseded,
    };

    match (action, classification) {
        (_, OpenLive) => Execute,
        (Cancel, OpenDue) => ExpireFirst(RecoveryNotFound),
        (Fulfill, OpenDue) => ExpireFirst(RecoveryExpired),
        (Cancel, RetainedCancelled) => Retained(CancellationConflict),
        (Cancel, RetainedFulfilled | RetainedExpired | RetainedSuperseded) => {
            Retained(RecoveryNotFound)
        }
        (Fulfill, RetainedExpired) => Retained(RecoveryExpired),
        (Fulfill, RetainedSuperseded) => Retained(RecoverySuperseded),
        (Fulfill, RetainedCancelled | RetainedFulfilled) => Retained(RecoveryNotFound),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryPersistedOrigin {
    LeafRecoveryRequest,
    ParticipantAcceptance,
}

pub(crate) fn persisted_recovery_origin(
    source: &str,
) -> Result<RecoveryPersistedOrigin, RecoveryRepositoryError> {
    match source {
        "requestLeafRecovery" => Ok(RecoveryPersistedOrigin::LeafRecoveryRequest),
        "acceptConversation" => Ok(RecoveryPersistedOrigin::ParticipantAcceptance),
        _ => Err(RecoveryRepositoryError::InvalidDurableRow),
    }
}

pub(crate) fn classify_locked_recovery(
    status: RecoveryRowStatus,
    trusted_instant: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> RecoveryTerminalClassification {
    match status {
        RecoveryRowStatus::Open if trusted_instant < expires_at => {
            RecoveryTerminalClassification::OpenLive
        }
        RecoveryRowStatus::Open => RecoveryTerminalClassification::OpenDue,
        RecoveryRowStatus::Fulfilled => RecoveryTerminalClassification::RetainedFulfilled,
        RecoveryRowStatus::Cancelled => RecoveryTerminalClassification::RetainedCancelled,
        RecoveryRowStatus::Expired => RecoveryTerminalClassification::RetainedExpired,
        RecoveryRowStatus::Superseded => RecoveryTerminalClassification::RetainedSuperseded,
    }
}

pub(crate) fn cancellation_actor_matches_requester(
    actor_did: &str,
    actor_device_id: Uuid,
    actor_key_id: &str,
    actor_auth_generation: i64,
    requester_did: &str,
    requester_device_id: Uuid,
    requester_key_id: &str,
    requester_auth_generation: i64,
) -> bool {
    actor_did == requester_did
        && actor_device_id == requester_device_id
        && actor_key_id == requester_key_id
        && actor_auth_generation == requester_auth_generation
}

#[derive(Debug)]
pub(crate) enum RecoveryRepositoryError {
    Database(sqlx::Error),
    ForeignTransaction,
    UnsupportedAuthority,
    AuthorityBindingMismatch,
    NonCanonicalOperation,
    TrustedInstantMismatch,
    ConversationMissing,
    ConversationDrift,
    RecoveryMissing,
    PackageUnavailable,
    ReadSetMismatch,
    InvalidDurableRow,
    ActionNotLive,
    ExpiryNotDue,
    CompareAndSetConflict,
    AggregateHydration(ConversationStateHydrationError),
    PackageHydration(RecoveryPackageHydrationError),
    Relationship(RelationshipRepositoryError),
    RelationshipUnavailable,
    StateMachine(StateMachineError),
    ExecutionHydration(ExecutionContextHydrationError),
    Execution(ExecutorError),
}

impl From<sqlx::Error> for RecoveryRepositoryError {
    fn from(value: sqlx::Error) -> Self {
        Self::Database(value)
    }
}

impl From<ConversationStateHydrationError> for RecoveryRepositoryError {
    fn from(value: ConversationStateHydrationError) -> Self {
        Self::AggregateHydration(value)
    }
}

impl From<RecoveryPackageHydrationError> for RecoveryRepositoryError {
    fn from(value: RecoveryPackageHydrationError) -> Self {
        Self::PackageHydration(value)
    }
}

impl From<RelationshipRepositoryError> for RecoveryRepositoryError {
    fn from(value: RelationshipRepositoryError) -> Self {
        Self::Relationship(value)
    }
}

impl From<StateMachineError> for RecoveryRepositoryError {
    fn from(value: StateMachineError) -> Self {
        Self::StateMachine(value)
    }
}

impl From<ExecutionContextHydrationError> for RecoveryRepositoryError {
    fn from(value: ExecutionContextHydrationError) -> Self {
        Self::ExecutionHydration(value)
    }
}

impl From<ExecutorError> for RecoveryRepositoryError {
    fn from(value: ExecutorError) -> Self {
        Self::Execution(value)
    }
}

impl From<transition::TransitionRepositoryError> for RecoveryRepositoryError {
    fn from(value: transition::TransitionRepositoryError) -> Self {
        match value {
            transition::TransitionRepositoryError::CompareAndSetConflict => {
                Self::CompareAndSetConflict
            }
            transition::TransitionRepositoryError::Database(error) => Self::Database(error),
            transition::TransitionRepositoryError::MetadataNonceReuse => {
                Self::CompareAndSetConflict
            }
        }
    }
}

pub(crate) const LOCK_RECOVERY_CONVERSATION_SQL: &str = r#"
    SELECT
        c.conversation_id,
        c.kind,
        c.lifecycle,
        c.current_generation,
        c.current_state_version,
        c.next_entry_seq,
        c.direct_did_low,
        c.direct_did_high,
        c.created_at,
        c.close_transition_id,
        c.close_generation,
        c.close_state_version,
        c.close_seq,
        c.closed_at
    FROM chat.conversations c
    WHERE c.conversation_id = $1
    FOR UPDATE OF c
"#;

pub(crate) const LOCK_RECOVERY_GENERATION_SQL: &str = r#"
    SELECT
        g.conversation_id,
        g.generation,
        g.group_id,
        g.lifecycle AS generation_lifecycle,
        g.genesis_group_info_sha256,
        g.current_state_version AS generation_state_version,
        g.activated_seq,
        g.activated_at,
        g.superseded_seq,
        g.superseded_at
    FROM chat.generations g
    WHERE g.conversation_id = $1 AND g.generation = $2
    FOR UPDATE OF g
"#;

pub(crate) const LOCK_RECOVERY_GENERATION_STATE_SQL: &str = r#"
    SELECT
        s.conversation_id,
        s.generation,
        s.state_version,
        s.epoch,
        s.group_context_hash,
        s.confirmation_tag,
        s.lifecycle AS state_lifecycle,
        s.state_kind,
        s.producing_transition_id,
        s.snapshot_sha256,
        s.tree_summary_sha256,
        s.leaf_count,
        s.created_at AS state_created_at
    FROM chat.generation_states s
    WHERE s.conversation_id = $1 AND s.generation = $2 AND s.state_version = $3
    FOR UPDATE OF s
"#;

pub(crate) const LOCK_RECOVERY_MEMBER_DEVICE_SQL: &str = r#"
    SELECT md.leaf_period_id
    FROM chat.member_devices md
    WHERE md.conversation_id = $1
      AND md.generation = $2
      AND md.user_did = $3
      AND md.device_id = $4
      AND md.active
    FOR UPDATE OF md
"#;

pub(crate) const LOCK_AVAILABLE_RECOVERY_PACKAGE_SQL: &str = r#"
    SELECT
        kp.key_package_ref,
        kp.wrapper_bytes,
        kp.wrapper_sha256,
        kp.init_key,
        kp.owner_did,
        kp.owner_device_id,
        kp.owner_key_id,
        kp.owner_auth_generation,
        kp.not_before,
        kp.not_after,
        kp.status,
        kp.terminal_transition_id,
        kp.terminal_revocation_id,
        kp.terminal_at,
        kp.created_at
    FROM chat.key_packages kp
    WHERE kp.owner_did = $1
      AND kp.owner_device_id = $2
      AND kp.owner_key_id = $3
      AND kp.owner_auth_generation = $4
      AND kp.status = 'available'
      AND kp.terminal_transition_id IS NULL
      AND kp.terminal_revocation_id IS NULL
      AND kp.terminal_at IS NULL
      AND kp.not_before < $5
      AND kp.created_at <= $5
      AND $5 < kp.not_after
    ORDER BY kp.created_at, kp.key_package_ref
    LIMIT 1
    FOR UPDATE OF kp
"#;

pub(crate) const LOCK_RECOVERY_REQUEST_SQL: &str = r#"
    SELECT
        rr.recovery_request_id,
        rr.conversation_id,
        rr.generation,
        rr.requester_did,
        rr.requester_device_id,
        rr.requester_key_id,
        rr.requester_auth_generation,
        rr.recovery_kind,
        rr.source,
        rr.bound_state_version,
        rr.bound_group_id,
        rr.bound_epoch,
        rr.bound_group_context_hash,
        rr.bound_confirmation_tag,
        rr.reservation_request_id,
        rr.replaced_leaf_period_id,
        rr.status,
        rr.signed_request_bytes,
        rr.signing_transcript_bytes,
        rr.request_digest,
        rr.signature,
        rr.requested_at,
        rr.expires_at,
        rr.fulfilling_transition_id,
        rr.terminal_transition_id,
        rr.terminal_revocation_id,
        rr.terminal_signed_request_bytes,
        rr.terminal_signing_transcript_bytes,
        rr.terminal_request_digest,
        rr.terminal_signature,
        rr.terminal_at
    FROM chat.leaf_recovery_requests rr
    WHERE rr.recovery_request_id = $1
    FOR UPDATE OF rr
"#;

pub(crate) const LOCK_RECOVERY_RESERVATION_SQL: &str = r#"
    SELECT
        kr.recovery_request_id,
        kr.key_package_ref,
        kr.conversation_id,
        kr.generation,
        kr.requester_did,
        kr.requester_device_id,
        kr.requester_key_id,
        kr.requester_auth_generation,
        kr.recipient_did,
        kr.recipient_device_id,
        kr.bound_state_version,
        kr.bound_group_id,
        kr.bound_epoch,
        kr.bound_group_context_hash,
        kr.bound_confirmation_tag,
        kr.purpose,
        kr.expires_at,
        kr.status,
        kr.consumed_transition_id,
        kr.terminal_transition_id,
        kr.terminal_revocation_id,
        kr.terminal_request_digest,
        kr.terminal_at,
        kr.created_at
    FROM chat.key_package_reservations kr
    WHERE kr.recovery_request_id = $1
    FOR UPDATE OF kr
"#;

pub(crate) const LOCK_RECOVERY_PACKAGE_SQL: &str = r#"
    SELECT
        kp.key_package_ref,
        kp.wrapper_bytes,
        kp.wrapper_sha256,
        kp.init_key,
        kp.owner_did,
        kp.owner_device_id,
        kp.owner_key_id,
        kp.owner_auth_generation,
        kp.not_before,
        kp.not_after,
        kp.status,
        kp.terminal_transition_id,
        kp.terminal_revocation_id,
        kp.terminal_at,
        kp.created_at
    FROM chat.key_packages kp
    WHERE kp.key_package_ref = $1
    FOR UPDATE OF kp
"#;

#[derive(FromRow)]
struct RecoveryConversationRow {
    conversation_id: Uuid,
    kind: String,
    lifecycle: String,
    current_generation: i64,
    current_state_version: i64,
    next_entry_seq: i64,
    direct_did_low: Option<String>,
    direct_did_high: Option<String>,
    created_at: DateTime<Utc>,
    close_transition_id: Option<Uuid>,
    close_generation: Option<i64>,
    close_state_version: Option<i64>,
    close_seq: Option<i64>,
    closed_at: Option<DateTime<Utc>>,
}

#[derive(FromRow)]
struct RecoveryGenerationRow {
    conversation_id: Uuid,
    generation: i64,
    group_id: Vec<u8>,
    generation_lifecycle: String,
    genesis_group_info_sha256: Vec<u8>,
    generation_state_version: i64,
    activated_seq: i64,
    activated_at: DateTime<Utc>,
    superseded_seq: Option<i64>,
    superseded_at: Option<DateTime<Utc>>,
}

#[derive(FromRow)]
struct RecoveryGenerationStateRow {
    conversation_id: Uuid,
    generation: i64,
    state_version: i64,
    epoch: i64,
    group_context_hash: Vec<u8>,
    confirmation_tag: Vec<u8>,
    state_lifecycle: String,
    state_kind: String,
    producing_transition_id: Uuid,
    snapshot_sha256: Vec<u8>,
    tree_summary_sha256: Vec<u8>,
    leaf_count: i64,
    state_created_at: DateTime<Utc>,
}

struct RecoveryHeadGraphRow {
    conversation_id: Uuid,
    kind: String,
    lifecycle: String,
    current_generation: i64,
    current_state_version: i64,
    next_entry_seq: i64,
    direct_did_low: Option<String>,
    direct_did_high: Option<String>,
    created_at: DateTime<Utc>,
    close_transition_id: Option<Uuid>,
    close_generation: Option<i64>,
    close_state_version: Option<i64>,
    close_seq: Option<i64>,
    closed_at: Option<DateTime<Utc>>,
    group_id: Vec<u8>,
    generation_lifecycle: String,
    genesis_group_info_sha256: Vec<u8>,
    generation_state_version: i64,
    activated_seq: i64,
    activated_at: DateTime<Utc>,
    superseded_seq: Option<i64>,
    superseded_at: Option<DateTime<Utc>>,
    epoch: i64,
    group_context_hash: Vec<u8>,
    confirmation_tag: Vec<u8>,
    state_lifecycle: String,
    state_kind: String,
    producing_transition_id: Uuid,
    snapshot_sha256: Vec<u8>,
    tree_summary_sha256: Vec<u8>,
    leaf_count: i64,
    state_created_at: DateTime<Utc>,
    actor_leaf_period_id: Option<Uuid>,
}

struct LockedRecoveryHeadGraph {
    conversation_id: Uuid,
    generation: i64,
    state_version: i64,
    group_id: [u8; 32],
    epoch: i64,
    group_context_hash: [u8; 32],
    confirmation_tag: [u8; 32],
    actor_leaf_period_id: Option<Uuid>,
    head_digest: [u8; 32],
    graph_digest: [u8; 32],
}

#[derive(FromRow)]
struct RecoveryRequestRow {
    recovery_request_id: Uuid,
    conversation_id: Uuid,
    generation: i64,
    requester_did: String,
    requester_device_id: Uuid,
    requester_key_id: String,
    requester_auth_generation: i64,
    recovery_kind: String,
    source: String,
    bound_state_version: i64,
    bound_group_id: Vec<u8>,
    bound_epoch: i64,
    bound_group_context_hash: Vec<u8>,
    bound_confirmation_tag: Vec<u8>,
    reservation_request_id: Uuid,
    replaced_leaf_period_id: Option<Uuid>,
    status: String,
    signed_request_bytes: Vec<u8>,
    signing_transcript_bytes: Vec<u8>,
    request_digest: Vec<u8>,
    signature: Vec<u8>,
    requested_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    fulfilling_transition_id: Option<Uuid>,
    terminal_transition_id: Option<Uuid>,
    terminal_revocation_id: Option<Uuid>,
    terminal_signed_request_bytes: Option<Vec<u8>>,
    terminal_signing_transcript_bytes: Option<Vec<u8>>,
    terminal_request_digest: Option<Vec<u8>>,
    terminal_signature: Option<Vec<u8>>,
    terminal_at: Option<DateTime<Utc>>,
}

#[derive(FromRow)]
struct RecoveryReservationRow {
    recovery_request_id: Uuid,
    key_package_ref: Vec<u8>,
    conversation_id: Uuid,
    generation: i64,
    requester_did: String,
    requester_device_id: Uuid,
    requester_key_id: String,
    requester_auth_generation: i64,
    recipient_did: String,
    recipient_device_id: Uuid,
    bound_state_version: i64,
    bound_group_id: Vec<u8>,
    bound_epoch: i64,
    bound_group_context_hash: Vec<u8>,
    bound_confirmation_tag: Vec<u8>,
    purpose: String,
    expires_at: DateTime<Utc>,
    status: String,
    consumed_transition_id: Option<Uuid>,
    terminal_transition_id: Option<Uuid>,
    terminal_revocation_id: Option<Uuid>,
    terminal_request_digest: Option<Vec<u8>>,
    terminal_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct RecoveryTerminalLocatorRow {
    recovery_request_id: Uuid,
    conversation_id: Uuid,
    requester_did: String,
    requester_device_id: Uuid,
    requester_key_id: String,
    requester_auth_generation: i64,
}

#[derive(Debug, Eq, FromRow, PartialEq)]
struct RecoveryPackageRow {
    key_package_ref: Vec<u8>,
    wrapper_bytes: Vec<u8>,
    wrapper_sha256: Vec<u8>,
    init_key: Vec<u8>,
    owner_did: String,
    owner_device_id: Uuid,
    owner_key_id: String,
    owner_auth_generation: i64,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    status: String,
    terminal_transition_id: Option<Uuid>,
    terminal_revocation_id: Option<Uuid>,
    terminal_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Eq, PartialEq)]
enum RecoveryPersistenceMode {
    Open,
    Cancelled {
        terminal_signed_request_bytes: Box<[u8]>,
        terminal_signing_transcript_bytes: Box<[u8]>,
        terminal_request_digest: [u8; 32],
        terminal_signature: [u8; 64],
        terminal_at: DateTime<Utc>,
    },
    Fulfilled {
        transition_id: Uuid,
        terminal_at: DateTime<Utc>,
    },
    Expired {
        terminal_at: DateTime<Utc>,
    },
}

/// Exact, owned Task-4 row witness consumed only by the prepared Recovery
/// executor. It retains the complete insertion-shaped request and reservation,
/// the complete locked package row, and the aggregate/custom-head cross seal.
#[derive(Debug, Eq, PartialEq)]
pub(in crate::chat_protocol) struct RecoveryPersistenceWitness {
    sql_authority: RecoverySqlAuthoritySeal,
    transaction_id: Box<str>,
    trusted_instant: DateTime<Utc>,
    graph_actor_did: Box<str>,
    graph_actor_device_id: Uuid,
    aggregate_cross_binding: RecoveryAggregateCrossBinding,
    request: NewLeafRecoveryRequest,
    reservation: NewReservation,
    package: RecoveryPackageRow,
    mode: RecoveryPersistenceMode,
}

/// Opaque executor-only capability minted only after the complete Recovery
/// graph has passed its same-transaction prewrite validation.
///
/// The persistence witness remains planner data until this capability exists;
/// no sibling module can construct one or invoke the Recovery SQL writers from
/// a separable planned result.
pub(in crate::chat_protocol) struct RecoveryExecutorWriteAuthority<'witness> {
    witness: &'witness RecoveryPersistenceWitness,
}

impl RecoveryExecutorWriteAuthority<'_> {
    pub(in crate::chat_protocol) async fn apply_open(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
    ) -> Result<(), ExecutorError> {
        self.witness.apply_open(transaction).await
    }

    pub(in crate::chat_protocol) async fn apply_terminal(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
    ) -> Result<(), ExecutorError> {
        self.witness.apply_terminal(transaction).await
    }
}

impl RecoveryPersistenceWitness {
    fn new(
        context: RecoveryAuthorityContext,
        request: NewLeafRecoveryRequest,
        reservation: NewReservation,
        package: RecoveryPackageRow,
        mode: RecoveryPersistenceMode,
    ) -> (
        Self,
        LockedConversationStateGuard,
        VerifiedSignedMutation,
        PreparedBusinessPrelude,
        Vec<LockedRecoveryPackageGuard>,
    ) {
        let RecoveryAuthorityContext {
            sql_authority,
            prelude,
            transaction_id,
            trusted_instant,
            actor_did,
            actor_device_id,
            aggregate,
            aggregate_cross_binding,
            verified_mutation,
            head: _,
            evidence: _,
            authority_digest: _,
            terminal_packages,
            actor_key_id: _,
            actor_auth_generation: _,
        } = context;
        (
            Self {
                sql_authority,
                transaction_id,
                trusted_instant,
                graph_actor_did: actor_did,
                graph_actor_device_id: actor_device_id,
                aggregate_cross_binding,
                request,
                reservation,
                package,
                mode,
            },
            aggregate,
            verified_mutation,
            prelude,
            terminal_packages,
        )
    }

    fn package_cas(&self) -> transition::RecoveryKeyPackageRowCas<'_> {
        transition::RecoveryKeyPackageRowCas::new(
            &self.sql_authority,
            &self.package.key_package_ref,
            &self.package.wrapper_bytes,
            &self.package.wrapper_sha256,
            &self.package.init_key,
            &self.package.owner_did,
            self.package.owner_device_id,
            &self.package.owner_key_id,
            self.package.owner_auth_generation,
            self.package.not_before,
            self.package.not_after,
            self.package.created_at,
        )
    }

    fn matches_plan(&self, plan: &ConversationPersistencePlan) -> bool {
        let Some(head) = plan.effects().head_cas() else {
            return false;
        };
        let binding = &self.aggregate_cross_binding;
        let coordinate_matches = head.transaction_id() == self.transaction_id.as_ref()
            && head.locked_at().unix_millis() == self.trusted_instant.timestamp_millis()
            && head.locked_head_digest() == &binding.aggregate_head_digest
            && head.expected_prior().is_some_and(|coordinate| {
                coordinate.conversation_id() == binding.conversation_id.as_bytes()
                    && i64::try_from(coordinate.generation()).ok() == Some(binding.generation)
                    && i64::try_from(coordinate.state_version()).ok() == Some(binding.state_version)
                    && coordinate.group_id() == &binding.group_id
                    && i64::try_from(coordinate.epoch()).ok() == Some(binding.epoch)
                    && coordinate.group_context_hash() == &binding.group_context_hash
                    && coordinate.confirmation_tag() == &binding.confirmation_tag
            })
            && binding.seal_digest == binding.rederive_digest();
        let request_id = self.request.recovery_request_id;
        let package_ref = self.package.key_package_ref.as_slice();
        let semantic_edge = plan.effects().package_transitions().iter().any(|edge| {
            edge.request_id() == request_id.as_bytes()
                && edge.key_package_ref().as_slice() == package_ref
        });
        let mode_matches = match (&self.mode, plan.effects().kind()) {
            (
                RecoveryPersistenceMode::Open,
                super::super::state_machine::PlanKind::RecoveryRequest,
            )
            | (
                RecoveryPersistenceMode::Cancelled { .. },
                super::super::state_machine::PlanKind::RecoveryCancellation,
            )
            | (
                RecoveryPersistenceMode::Expired { .. },
                super::super::state_machine::PlanKind::RecoveryExpiry,
            ) => true,
            (
                RecoveryPersistenceMode::Fulfilled { transition_id, .. },
                super::super::state_machine::PlanKind::Commit,
            ) => {
                matches!(
                    plan.effects().authority(),
                    Some(super::super::state_machine::PlanAuthority::Transition(evidence))
                        if evidence.transition_id() == transition_id.as_bytes()
                            && evidence
                                .signed_authority()
                                .is_some_and(|authority| {
                                    authority.kind()
                                        == super::super::transcript::SignedMutationKind::LeafRecoveryFulfillment
                                })
                )
            }
            _ => false,
        };
        coordinate_matches && semantic_edge && mode_matches
    }

    fn aggregate_prelude_plan_binding(&self) -> RecoveryPreludeAggregatePlanBinding {
        let binding = &self.aggregate_cross_binding;
        RecoveryPreludeAggregatePlanBinding::new(
            binding.conversation_id,
            binding.generation,
            binding.state_version,
            binding.group_id,
            binding.epoch,
            binding.group_context_hash,
            binding.confirmation_tag,
            binding.aggregate_head_digest,
            binding.aggregate_graph_digest,
            binding.aggregate_snapshot_digest,
            binding.recovery_head_digest,
            binding.recovery_graph_digest,
            binding.seal_digest,
        )
    }

    fn material_matches_plan(
        &self,
        plan: &ConversationPersistencePlan,
        material: RecoveryCanonicalMaterial,
    ) -> bool {
        let request_id = self.request.recovery_request_id;
        let effects = plan.effects();
        match (material, &self.mode, effects.kind(), effects.authority()) {
            (
                RecoveryCanonicalMaterial::Requested {
                    recovery_request_id,
                },
                RecoveryPersistenceMode::Open,
                super::super::state_machine::PlanKind::RecoveryRequest,
                Some(PlanAuthority::Request(authority)),
            ) => {
                recovery_request_id == request_id
                    && authority.request_id() == request_id.as_bytes()
                    && authority.signed_authority().is_some_and(|signed| {
                        signed.kind()
                            == super::super::transcript::SignedMutationKind::LeafRecoveryRequest
                    })
            }
            (
                RecoveryCanonicalMaterial::Cancelled {
                    recovery_request_id,
                },
                RecoveryPersistenceMode::Cancelled { .. },
                super::super::state_machine::PlanKind::RecoveryCancellation,
                Some(PlanAuthority::Request(authority)),
            ) => {
                recovery_request_id == request_id
                    && authority.request_id() == request_id.as_bytes()
                    && authority.signed_authority().is_some_and(|signed| {
                        signed.kind()
                        == super::super::transcript::SignedMutationKind::LeafRecoveryCancellation
                    })
            }
            (
                RecoveryCanonicalMaterial::Fulfilled {
                    recovery_request_id,
                    transition_id,
                },
                RecoveryPersistenceMode::Fulfilled {
                    transition_id: sealed_transition_id,
                    ..
                },
                super::super::state_machine::PlanKind::Commit,
                Some(PlanAuthority::Transition(authority)),
            ) => {
                recovery_request_id == request_id
                    && transition_id == *sealed_transition_id
                    && authority.transition_id() == transition_id.as_bytes()
                    && authority.signed_authority().is_some_and(|signed| {
                        signed.kind()
                            == super::super::transcript::SignedMutationKind::LeafRecoveryFulfillment
                    })
            }
            (
                RecoveryCanonicalMaterial::ClientExpired {
                    recovery_request_id,
                    terminal_at,
                    post_apply_error,
                },
                RecoveryPersistenceMode::Expired {
                    terminal_at: sealed_terminal_at,
                },
                super::super::state_machine::PlanKind::RecoveryExpiry,
                Some(PlanAuthority::RecoveryExpiry(authority)),
            ) => {
                recovery_request_id == request_id
                    && terminal_at == *sealed_terminal_at
                    && authority.request_id() == request_id.as_bytes()
                    && authority.terminal_at().unix_millis()
                        == sealed_terminal_at.timestamp_millis()
                    && matches!(
                        post_apply_error,
                        RecoveryClientTerminalError::RecoveryNotFound
                            | RecoveryClientTerminalError::RecoveryExpired
                    )
            }
            (
                RecoveryCanonicalMaterial::SchedulerExpired {
                    recovery_request_id,
                    terminal_at,
                },
                RecoveryPersistenceMode::Expired {
                    terminal_at: sealed_terminal_at,
                },
                super::super::state_machine::PlanKind::RecoveryExpiry,
                Some(PlanAuthority::RecoveryExpiry(authority)),
            ) => {
                recovery_request_id == request_id
                    && terminal_at == *sealed_terminal_at
                    && authority.request_id() == request_id.as_bytes()
                    && authority.terminal_at().unix_millis()
                        == sealed_terminal_at.timestamp_millis()
            }
            _ => false,
        }
    }

    fn client_prelude_plan_binding(
        &self,
        plan: &ConversationPersistencePlan,
        accepted_control_entry_bytes: Option<&[u8]>,
        material: RecoveryCanonicalMaterial,
    ) -> Result<RecoveryPreludePlanBinding, RecoveryRepositoryError> {
        if !self.matches_plan(plan) || !self.material_matches_plan(plan, material) {
            return Err(RecoveryRepositoryError::AuthorityBindingMismatch);
        }
        let fingerprint = recovery_plan_fingerprint(plan, accepted_control_entry_bytes)?;
        let (endpoint, mutation_kind, mode, plan_kind, expected_class) = match material {
            RecoveryCanonicalMaterial::Requested { .. } => (
                RecoveryOperationEndpoint::RequestLeafRecovery,
                super::super::transcript::SignedMutationKind::LeafRecoveryRequest,
                RecoveryPreludePersistenceMode::Open,
                RecoveryPreludePlanKind::RecoveryRequest,
                RecoveryPlanClass::Request,
            ),
            RecoveryCanonicalMaterial::Cancelled { .. } => (
                RecoveryOperationEndpoint::CancelLeafRecovery,
                super::super::transcript::SignedMutationKind::LeafRecoveryCancellation,
                RecoveryPreludePersistenceMode::Cancelled,
                RecoveryPreludePlanKind::RecoveryCancellation,
                RecoveryPlanClass::Cancellation,
            ),
            RecoveryCanonicalMaterial::Fulfilled { .. } => (
                RecoveryOperationEndpoint::SubmitRecoveryFulfillment,
                super::super::transcript::SignedMutationKind::LeafRecoveryFulfillment,
                RecoveryPreludePersistenceMode::Fulfilled,
                RecoveryPreludePlanKind::Commit,
                RecoveryPlanClass::Fulfillment,
            ),
            RecoveryCanonicalMaterial::ClientExpired {
                terminal_at,
                post_apply_error,
                ..
            } => {
                let post_apply_error = match post_apply_error {
                    RecoveryClientTerminalError::RecoveryNotFound => {
                        RecoveryPreludeClientExpiryError::RecoveryNotFound
                    }
                    RecoveryClientTerminalError::RecoveryExpired => {
                        RecoveryPreludeClientExpiryError::RecoveryExpired
                    }
                    _ => return Err(RecoveryRepositoryError::AuthorityBindingMismatch),
                };
                let (endpoint, mutation_kind) = match post_apply_error {
                    RecoveryPreludeClientExpiryError::RecoveryNotFound => (
                        RecoveryOperationEndpoint::CancelLeafRecovery,
                        super::super::transcript::SignedMutationKind::LeafRecoveryCancellation,
                    ),
                    RecoveryPreludeClientExpiryError::RecoveryExpired => (
                        RecoveryOperationEndpoint::SubmitRecoveryFulfillment,
                        super::super::transcript::SignedMutationKind::LeafRecoveryFulfillment,
                    ),
                    _ => return Err(RecoveryRepositoryError::AuthorityBindingMismatch),
                };
                (
                    endpoint,
                    mutation_kind,
                    RecoveryPreludePersistenceMode::ClientExpired {
                        terminal_at,
                        post_apply_error,
                    },
                    RecoveryPreludePlanKind::RecoveryExpiry,
                    RecoveryPlanClass::Expiry,
                )
            }
            RecoveryCanonicalMaterial::SchedulerExpired { .. } => {
                return Err(RecoveryRepositoryError::AuthorityBindingMismatch)
            }
        };
        if fingerprint.class() != expected_class {
            return Err(RecoveryRepositoryError::AuthorityBindingMismatch);
        }
        let accepted_control_sha256 =
            accepted_control_entry_bytes.map(|bytes| Sha256::digest(bytes).into());
        Ok(RecoveryPreludePlanBinding::new(
            endpoint,
            mutation_kind,
            mode,
            plan_kind,
            self.request.recovery_request_id,
            &self.transaction_id,
            &self.graph_actor_did,
            self.graph_actor_device_id,
            self.aggregate_prelude_plan_binding(),
            *fingerprint.digest(),
            accepted_control_sha256,
        ))
    }

    fn scheduler_graph_seal(
        &self,
        plan_fingerprint: [u8; 32],
        material: RecoveryCanonicalMaterial,
    ) -> [u8; 32] {
        let RecoveryCanonicalMaterial::SchedulerExpired {
            recovery_request_id,
            terminal_at,
        } = material
        else {
            return [0; 32];
        };
        let mut digest = Sha256::new();
        digest.update(b"CATBIRD-CHAT-RECOVERY-SCHEDULER-GRAPH-SEAL\0");
        digest_len(&mut digest, self.transaction_id.as_bytes());
        digest.update(self.trusted_instant.timestamp_micros().to_be_bytes());
        digest_len(&mut digest, self.graph_actor_did.as_bytes());
        digest.update(self.graph_actor_device_id.as_bytes());
        digest.update(recovery_request_id.as_bytes());
        digest.update(terminal_at.timestamp_micros().to_be_bytes());
        digest.update(self.aggregate_cross_binding.seal_digest);
        digest.update(plan_fingerprint);
        digest.finalize().into()
    }

    pub(in crate::chat_protocol) async fn validate_prewrite(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        plan: &ConversationPersistencePlan,
    ) -> Result<(), ExecutionContextHydrationError> {
        let live_transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
            .fetch_one(&mut **transaction)
            .await?;
        if live_transaction_id != self.transaction_id.as_ref() || !self.matches_plan(plan) {
            return Err(ExecutionContextHydrationError::AuthorityMismatch);
        }
        // Rehydrate and reseal the complete durable aggregate before touching
        // any Recovery row. This makes the aggregate graph and active public
        // snapshot digests load-bearing at executor prewrite rather than merely
        // self-authenticated fields copied from planning.
        let reloaded_aggregate = hydrate_locked_conversation_state(
            transaction,
            self.request.conversation_id,
            self.trusted_instant,
        )
        .await
        .map_err(|_| ExecutionContextHydrationError::AuthorityMismatch)?;
        let reloaded_head = lock_head_graph(
            transaction,
            self.request.conversation_id,
            &self.graph_actor_did,
            self.graph_actor_device_id,
        )
        .await
        .map_err(|_| ExecutionContextHydrationError::AuthorityMismatch)?;
        if !self
            .aggregate_cross_binding
            .validates(&reloaded_aggregate, &reloaded_head)
        {
            return Err(ExecutionContextHydrationError::AuthorityMismatch);
        }
        let package: RecoveryPackageRow = sqlx::query_as(LOCK_RECOVERY_PACKAGE_SQL)
            .bind(&self.package.key_package_ref)
            .fetch_optional(&mut **transaction)
            .await?
            .ok_or(ExecutionContextHydrationError::AuthorityMismatch)?;
        if package != self.package {
            return Err(ExecutionContextHydrationError::AuthorityMismatch);
        }
        match self.mode {
            RecoveryPersistenceMode::Open => {
                let occupied: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM chat.leaf_recovery_requests WHERE recovery_request_id=$1) \
                     OR EXISTS(SELECT 1 FROM chat.key_package_reservations WHERE recovery_request_id=$1)",
                )
                .bind(self.request.recovery_request_id)
                .fetch_one(&mut **transaction)
                .await?;
                if occupied
                    || self.package.status != "available"
                    || self.package.terminal_transition_id.is_some()
                    || self.package.terminal_revocation_id.is_some()
                    || self.package.terminal_at.is_some()
                {
                    return Err(ExecutionContextHydrationError::AuthorityMismatch);
                }
            }
            _ => {
                let request: RecoveryRequestRow = sqlx::query_as(LOCK_RECOVERY_REQUEST_SQL)
                    .bind(self.request.recovery_request_id)
                    .fetch_optional(&mut **transaction)
                    .await?
                    .ok_or(ExecutionContextHydrationError::AuthorityMismatch)?;
                let reservation: RecoveryReservationRow =
                    sqlx::query_as(LOCK_RECOVERY_RESERVATION_SQL)
                        .bind(self.request.recovery_request_id)
                        .fetch_optional(&mut **transaction)
                        .await?
                        .ok_or(ExecutionContextHydrationError::AuthorityMismatch)?;
                if new_request_from_row(&request).ok().as_ref() != Some(&self.request)
                    || new_reservation_from_row(&reservation).ok().as_ref()
                        != Some(&self.reservation)
                    || request.status != "open"
                    || reservation.status != "active"
                    || self.package.status != "reserved"
                    || request.fulfilling_transition_id.is_some()
                    || request.terminal_transition_id.is_some()
                    || request.terminal_revocation_id.is_some()
                    || request.terminal_at.is_some()
                    || reservation.consumed_transition_id.is_some()
                    || reservation.terminal_transition_id.is_some()
                    || reservation.terminal_revocation_id.is_some()
                    || reservation.terminal_at.is_some()
                    || self.package.terminal_transition_id.is_some()
                    || self.package.terminal_revocation_id.is_some()
                    || self.package.terminal_at.is_some()
                {
                    return Err(ExecutionContextHydrationError::AuthorityMismatch);
                }
            }
        }
        Ok(())
    }

    async fn apply_open(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
    ) -> Result<(), ExecutorError> {
        if !matches!(self.mode, RecoveryPersistenceMode::Open) {
            return Err(ExecutorError::InconsistentPlan(
                "Recovery open executor received a terminal witness",
            ));
        }
        let package = transition::AvailableRecoveryPackageReservationCas::new(
            &self.sql_authority,
            &self.transaction_id,
            self.package_cas(),
        );
        transition::reserve_available_recovery_package(transaction, &package).await?;
        transition::insert_leaf_recovery_request(transaction, &self.request).await?;
        transition::insert_reservation(transaction, &self.reservation).await?;
        Ok(())
    }

    async fn apply_terminal(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
    ) -> Result<(), ExecutorError> {
        let termination = match &self.mode {
            RecoveryPersistenceMode::Cancelled {
                terminal_signed_request_bytes,
                terminal_signing_transcript_bytes,
                terminal_request_digest,
                terminal_signature,
                terminal_at,
            } => transition::RecoveryTerminalTripleTermination::Cancelled {
                authority: &self.sql_authority,
                terminal_signed_request_bytes,
                terminal_signing_transcript_bytes,
                terminal_request_digest,
                terminal_signature,
                terminal_at: *terminal_at,
            },
            RecoveryPersistenceMode::Fulfilled {
                transition_id,
                terminal_at,
            } => transition::RecoveryTerminalTripleTermination::Fulfilled {
                authority: &self.sql_authority,
                transition_id: *transition_id,
                terminal_at: *terminal_at,
            },
            RecoveryPersistenceMode::Expired { terminal_at } => {
                transition::RecoveryTerminalTripleTermination::Expired {
                    authority: &self.sql_authority,
                    terminal_at: *terminal_at,
                }
            }
            RecoveryPersistenceMode::Open => {
                return Err(ExecutorError::InconsistentPlan(
                    "Recovery terminal executor received an open witness",
                ))
            }
        };
        let binding = transition::RecoveryTerminalTripleCas::new(
            &self.sql_authority,
            &self.transaction_id,
            &self.request,
            &self.reservation,
            self.package_cas(),
            termination,
        );
        transition::terminalize_recovery_triple(transaction, &binding).await?;
        Ok(())
    }
}

struct RecoveryEvidence {
    signed_request_bytes: Box<[u8]>,
    signing_transcript_bytes: Box<[u8]>,
    request_digest: [u8; 32],
    signature: [u8; 64],
}

struct RecoveryAuthorityContext {
    sql_authority: RecoverySqlAuthoritySeal,
    prelude: PreparedBusinessPrelude,
    transaction_id: Box<str>,
    trusted_instant: DateTime<Utc>,
    actor_did: Box<str>,
    actor_device_id: Uuid,
    actor_key_id: Box<str>,
    actor_auth_generation: i64,
    aggregate: LockedConversationStateGuard,
    aggregate_cross_binding: RecoveryAggregateCrossBinding,
    verified_mutation: VerifiedSignedMutation,
    head: LockedRecoveryHeadGraph,
    evidence: RecoveryEvidence,
    authority_digest: [u8; 32],
    terminal_packages: Vec<LockedRecoveryPackageGuard>,
}

/// Sealed available-package authority. Its single exit is
/// [`into_plan_input`](RecoveryRequestAuthority::into_plan_input). No package
/// reservation occurs before the state-machine executor.
#[must_use]
pub(crate) struct RecoveryRequestAuthority {
    context: RecoveryAuthorityContext,
    request: NewLeafRecoveryRequest,
    reservation: NewReservation,
    package: RecoveryPackageRow,
    execution_package: LockedRecoveryPackageGuard,
}

#[must_use]
pub(crate) struct RecoveryCancellationAuthority {
    context: RecoveryAuthorityContext,
    request: NewLeafRecoveryRequest,
    reservation: NewReservation,
    package: RecoveryPackageRow,
    execution_package: LockedRecoveryPackageGuard,
}

#[must_use]
pub(crate) struct RecoveryFulfillmentAuthority {
    context: RecoveryAuthorityContext,
    request: NewLeafRecoveryRequest,
    reservation: NewReservation,
    package: RecoveryPackageRow,
    execution_package: LockedRecoveryPackageGuard,
    transition_id: Uuid,
}

#[must_use]
pub(crate) struct RecoveryClientExpiryAuthority {
    sql_authority: RecoverySqlAuthoritySeal,
    prelude: PreparedBusinessPrelude,
    transaction_id: Box<str>,
    trusted_instant: DateTime<Utc>,
    graph_actor_did: Box<str>,
    graph_actor_device_id: Uuid,
    aggregate: LockedConversationStateGuard,
    aggregate_cross_binding: RecoveryAggregateCrossBinding,
    execution_package: LockedRecoveryPackageGuard,
    head: LockedRecoveryHeadGraph,
    request: NewLeafRecoveryRequest,
    reservation: NewReservation,
    package: RecoveryPackageRow,
    authority_digest: [u8; 32],
}

#[must_use]
pub(crate) struct RecoverySchedulerExpiryAuthority {
    sql_authority: RecoverySqlAuthoritySeal,
    transaction_id: Box<str>,
    trusted_instant: DateTime<Utc>,
    graph_actor_did: Box<str>,
    graph_actor_device_id: Uuid,
    aggregate: LockedConversationStateGuard,
    aggregate_cross_binding: RecoveryAggregateCrossBinding,
    execution_package: LockedRecoveryPackageGuard,
    head: LockedRecoveryHeadGraph,
    request: NewLeafRecoveryRequest,
    reservation: NewReservation,
    package: RecoveryPackageRow,
    authority_digest: [u8; 32],
}

#[must_use]
pub(crate) struct RecoveryClientExpiryPlanInput {
    authority: RecoveryClientExpiryAuthority,
    trusted_request_instant: TrustedRequestInstant,
    post_apply_error: RecoveryClientTerminalError,
}

#[must_use]
pub(crate) struct RecoverySchedulerExpiryPlanInput {
    authority: RecoverySchedulerExpiryAuthority,
}

pub(in crate::chat_protocol) struct RecoveryClientExpiryPlannerParts {
    pub(in crate::chat_protocol) aggregate: LockedConversationStateGuard,
    pub(in crate::chat_protocol) execution_package: LockedRecoveryPackageGuard,
    pub(in crate::chat_protocol) prelude: PreparedBusinessPrelude,
    pub(in crate::chat_protocol) observed_at: DateTime<Utc>,
    pub(in crate::chat_protocol) terminal_at: DateTime<Utc>,
    pub(in crate::chat_protocol) request_id: Uuid,
    pub(in crate::chat_protocol) locked_read_set_digest: [u8; 32],
    pub(in crate::chat_protocol) trusted_request_instant: TrustedRequestInstant,
    pub(in crate::chat_protocol) post_apply_error: RecoveryClientTerminalError,
    pub(in crate::chat_protocol) persistence_witness: RecoveryPersistenceWitness,
}

pub(in crate::chat_protocol) struct RecoverySchedulerExpiryPlannerParts {
    pub(in crate::chat_protocol) aggregate: LockedConversationStateGuard,
    pub(in crate::chat_protocol) execution_package: LockedRecoveryPackageGuard,
    pub(in crate::chat_protocol) observed_at: DateTime<Utc>,
    pub(in crate::chat_protocol) terminal_at: DateTime<Utc>,
    pub(in crate::chat_protocol) request_id: Uuid,
    pub(in crate::chat_protocol) locked_read_set_digest: [u8; 32],
    pub(in crate::chat_protocol) persistence_witness: RecoveryPersistenceWitness,
}

#[must_use]
pub(crate) struct RecoveryCancellationDueForExpiry {
    authority: RecoveryClientExpiryAuthority,
}

#[must_use]
pub(crate) struct RecoveryFulfillmentDueForExpiry {
    authority: RecoveryClientExpiryAuthority,
}

#[must_use]
pub(crate) struct RecoveryCancellationRetained {
    prelude: PreparedBusinessPrelude,
    error: RecoveryClientTerminalError,
}

#[must_use]
pub(crate) struct RecoveryFulfillmentRetained {
    prelude: PreparedBusinessPrelude,
    error: RecoveryClientTerminalError,
}

#[must_use]
pub(crate) struct RecoveryClassifiedTerminalOutcome {
    prelude: PreparedBusinessPrelude,
    error: RecoveryClientTerminalError,
}

pub(crate) enum RecoveryCancellationRead {
    Execute(RecoveryCancellationAuthority),
    DueForExpiry(RecoveryCancellationDueForExpiry),
    Classified(RecoveryCancellationRetained),
}

pub(crate) enum RecoveryFulfillmentRead {
    Execute(RecoveryFulfillmentAuthority),
    DueForExpiry(RecoveryFulfillmentDueForExpiry),
    Classified(RecoveryFulfillmentRetained),
}

#[must_use]
pub(crate) struct RecoverySchedulerRetainedTerminal {
    _classification: RecoveryTerminalClassification,
}

pub(crate) enum RecoverySchedulerExpiryRead {
    Authority(RecoverySchedulerExpiryAuthority),
    Retained(RecoverySchedulerRetainedTerminal),
}

impl RecoveryCancellationDueForExpiry {
    pub(crate) fn into_plan_input(
        self,
        trusted_request_instant: &TrustedRequestInstant,
    ) -> Result<RecoveryClientExpiryPlanInput, RecoveryRepositoryError> {
        self.authority.into_plan_input_with_error(
            trusted_request_instant,
            RecoveryClientTerminalError::RecoveryNotFound,
        )
    }
}

impl RecoveryFulfillmentDueForExpiry {
    pub(crate) fn into_plan_input(
        self,
        trusted_request_instant: &TrustedRequestInstant,
    ) -> Result<RecoveryClientExpiryPlanInput, RecoveryRepositoryError> {
        self.authority.into_plan_input_with_error(
            trusted_request_instant,
            RecoveryClientTerminalError::RecoveryExpired,
        )
    }
}

impl RecoveryCancellationRetained {
    pub(crate) fn into_classified_outcome(self) -> RecoveryClassifiedTerminalOutcome {
        RecoveryClassifiedTerminalOutcome {
            prelude: self.prelude,
            error: self.error,
        }
    }
}

impl RecoveryFulfillmentRetained {
    pub(crate) fn into_classified_outcome(self) -> RecoveryClassifiedTerminalOutcome {
        RecoveryClassifiedTerminalOutcome {
            prelude: self.prelude,
            error: self.error,
        }
    }
}

impl RecoveryClassifiedTerminalOutcome {
    pub(crate) fn into_parts(self) -> (PreparedBusinessPrelude, RecoveryClientTerminalError) {
        (self.prelude, self.error)
    }
}

/// Opaque state-machine plan input sealing the exact recovery-request
/// read-set. No DB write has occurred; the executor bridge is the sole writer.
#[must_use]
pub(crate) struct RecoveryRequestPlanInput {
    context: RecoveryAuthorityContext,
    request: NewLeafRecoveryRequest,
    reservation: NewReservation,
    package: RecoveryPackageRow,
    execution_package: LockedRecoveryPackageGuard,
    relationship: RelationshipProjection,
    relationship_decision: LockedRelationshipDecisionGuard,
    trusted_request_instant: TrustedRequestInstant,
}

/// Opaque cancellation plan input.
#[must_use]
pub(crate) struct RecoveryCancellationPlanInput {
    context: RecoveryAuthorityContext,
    request: NewLeafRecoveryRequest,
    reservation: NewReservation,
    package: RecoveryPackageRow,
    execution_package: LockedRecoveryPackageGuard,
    trusted_request_instant: TrustedRequestInstant,
}

/// Opaque fulfillment plan input.
#[must_use]
pub(crate) struct RecoveryFulfillmentPlanInput {
    context: RecoveryAuthorityContext,
    request: NewLeafRecoveryRequest,
    reservation: NewReservation,
    package: RecoveryPackageRow,
    execution_package: LockedRecoveryPackageGuard,
    relationship: RelationshipProjection,
    relationship_decision: LockedRelationshipDecisionGuard,
    transition_id: Uuid,
    trusted_request_instant: TrustedRequestInstant,
}

pub(in crate::chat_protocol) struct RecoveryRequestPlannerParts {
    pub(in crate::chat_protocol) aggregate: LockedConversationStateGuard,
    pub(in crate::chat_protocol) mutation: VerifiedSignedMutation,
    pub(in crate::chat_protocol) prelude: PreparedBusinessPrelude,
    pub(in crate::chat_protocol) execution_package: LockedRecoveryPackageGuard,
    pub(in crate::chat_protocol) relationship: RelationshipProjection,
    pub(in crate::chat_protocol) relationship_decision: LockedRelationshipDecisionGuard,
    pub(in crate::chat_protocol) trusted_request_instant: TrustedRequestInstant,
    pub(in crate::chat_protocol) persistence_witness: RecoveryPersistenceWitness,
}

pub(in crate::chat_protocol) struct RecoveryCancellationPlannerParts {
    pub(in crate::chat_protocol) aggregate: LockedConversationStateGuard,
    pub(in crate::chat_protocol) mutation: VerifiedSignedMutation,
    pub(in crate::chat_protocol) prelude: PreparedBusinessPrelude,
    pub(in crate::chat_protocol) execution_package: LockedRecoveryPackageGuard,
    pub(in crate::chat_protocol) trusted_request_instant: TrustedRequestInstant,
    pub(in crate::chat_protocol) persistence_witness: RecoveryPersistenceWitness,
}

pub(in crate::chat_protocol) struct RecoveryFulfillmentPlannerParts {
    pub(in crate::chat_protocol) aggregate: LockedConversationStateGuard,
    pub(in crate::chat_protocol) mutation: VerifiedSignedMutation,
    pub(in crate::chat_protocol) prelude: PreparedBusinessPrelude,
    pub(in crate::chat_protocol) execution_package: LockedRecoveryPackageGuard,
    pub(in crate::chat_protocol) terminal_packages: Vec<LockedRecoveryPackageGuard>,
    pub(in crate::chat_protocol) relationship: RelationshipProjection,
    pub(in crate::chat_protocol) relationship_decision: LockedRelationshipDecisionGuard,
    pub(in crate::chat_protocol) transition_id: Uuid,
    pub(in crate::chat_protocol) trusted_request_instant: TrustedRequestInstant,
    pub(in crate::chat_protocol) persistence_witness: RecoveryPersistenceWitness,
}

#[cfg(not(test))]
pub(crate) struct RecoveryCompletion {
    scope_authority: ScopeBoundBusinessAuthority,
    completion: OperationCompletionGuard,
}

#[cfg(not(test))]
impl RecoveryCompletion {
    pub(crate) fn into_parts(self) -> (ScopeBoundBusinessAuthority, OperationCompletionGuard) {
        (self.scope_authority, self.completion)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryCanonicalMaterial {
    Requested {
        recovery_request_id: Uuid,
    },
    Cancelled {
        recovery_request_id: Uuid,
    },
    Fulfilled {
        recovery_request_id: Uuid,
        transition_id: Uuid,
    },
    ClientExpired {
        recovery_request_id: Uuid,
        terminal_at: DateTime<Utc>,
        post_apply_error: RecoveryClientTerminalError,
    },
    SchedulerExpired {
        recovery_request_id: Uuid,
        terminal_at: DateTime<Utc>,
    },
}

#[cfg(not(test))]
pub(crate) struct PreparedRecoveryMutation {
    graph: PreparedRecoveryExecutionGraph,
    completion: RecoveryCompletion,
}

enum RecoveryGraphPrewriteOrigin {
    Client {
        witness: RecoveryPreludePrewriteWitness,
    },
    Scheduler {
        plan_fingerprint: [u8; 32],
        seal_digest: [u8; 32],
    },
}

/// Private, single-owner graph carrying every serialized product retained by a
/// planned Recovery mutation. The execution facade borrows this graph as one
/// value; no caller can pair a plan with another mutation's accepted control
/// entry.
pub(in crate::chat_protocol) struct PreparedRecoveryExecutionGraph {
    plan: ConversationPersistencePlan,
    accepted_control_entry_bytes: Option<Vec<u8>>,
    persistence_witness: RecoveryPersistenceWitness,
    origin: RecoveryGraphPrewriteOrigin,
    material: RecoveryCanonicalMaterial,
}

impl PreparedRecoveryExecutionGraph {
    fn new_client(
        plan: ConversationPersistencePlan,
        accepted_control_entry_bytes: Option<Vec<u8>>,
        persistence_witness: RecoveryPersistenceWitness,
        prewrite: RecoveryPreludePrewriteWitness,
        material: RecoveryCanonicalMaterial,
    ) -> Result<Self, RecoveryRepositoryError> {
        let binding = persistence_witness.client_prelude_plan_binding(
            &plan,
            accepted_control_entry_bytes.as_deref(),
            material,
        )?;
        let witness = prewrite
            .seal_recovery_plan(binding)
            .map_err(|_| RecoveryRepositoryError::AuthorityBindingMismatch)?;
        Ok(Self {
            plan,
            accepted_control_entry_bytes,
            persistence_witness,
            origin: RecoveryGraphPrewriteOrigin::Client { witness },
            material,
        })
    }

    fn new_scheduler(
        plan: ConversationPersistencePlan,
        persistence_witness: RecoveryPersistenceWitness,
        material: RecoveryCanonicalMaterial,
    ) -> Result<Self, RecoveryRepositoryError> {
        if !matches!(material, RecoveryCanonicalMaterial::SchedulerExpired { .. })
            || !matches!(
                persistence_witness.mode,
                RecoveryPersistenceMode::Expired { .. }
            )
        {
            return Err(RecoveryRepositoryError::AuthorityBindingMismatch);
        }
        let fingerprint = recovery_plan_fingerprint(&plan, None)?;
        if fingerprint.class() != RecoveryPlanClass::Expiry
            || !persistence_witness.material_matches_plan(&plan, material)
        {
            return Err(RecoveryRepositoryError::AuthorityBindingMismatch);
        }
        let plan_fingerprint = *fingerprint.digest();
        let seal_digest = persistence_witness.scheduler_graph_seal(plan_fingerprint, material);
        Ok(Self {
            plan,
            accepted_control_entry_bytes: None,
            persistence_witness,
            origin: RecoveryGraphPrewriteOrigin::Scheduler {
                plan_fingerprint,
                seal_digest,
            },
            material,
        })
    }

    pub(in crate::chat_protocol::repository) fn plan(&self) -> &ConversationPersistencePlan {
        &self.plan
    }

    pub(in crate::chat_protocol::repository) fn accepted_control_entry_bytes(
        &self,
    ) -> Option<Vec<u8>> {
        self.accepted_control_entry_bytes.clone()
    }

    pub(in crate::chat_protocol::repository) async fn validate_prewrite(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
    ) -> Result<RecoveryExecutorWriteAuthority<'_>, ExecutionContextHydrationError> {
        if !self
            .persistence_witness
            .material_matches_plan(&self.plan, self.material)
        {
            return Err(ExecutionContextHydrationError::AuthorityMismatch);
        }
        match &self.origin {
            RecoveryGraphPrewriteOrigin::Client { witness } => {
                let live_binding = self
                    .persistence_witness
                    .client_prelude_plan_binding(
                        &self.plan,
                        self.accepted_control_entry_bytes.as_deref(),
                        self.material,
                    )
                    .map_err(|_| ExecutionContextHydrationError::AuthorityMismatch)?;
                witness
                    .validate_recovery_prewrite(transaction, &live_binding)
                    .await
                    .map_err(|_| ExecutionContextHydrationError::AuthorityMismatch)?;
            }
            RecoveryGraphPrewriteOrigin::Scheduler {
                plan_fingerprint,
                seal_digest,
            } => {
                let live = recovery_plan_fingerprint(&self.plan, None)
                    .map_err(|_| ExecutionContextHydrationError::AuthorityMismatch)?;
                if live.class() != RecoveryPlanClass::Expiry
                    || live.digest() != plan_fingerprint
                    || *seal_digest
                        != self
                            .persistence_witness
                            .scheduler_graph_seal(*plan_fingerprint, self.material)
                {
                    return Err(ExecutionContextHydrationError::AuthorityMismatch);
                }
            }
        }
        self.persistence_witness
            .validate_prewrite(transaction, &self.plan)
            .await?;
        Ok(RecoveryExecutorWriteAuthority {
            witness: &self.persistence_witness,
        })
    }

    fn material(&self) -> RecoveryCanonicalMaterial {
        self.material
    }
}

#[cfg(not(test))]
impl PreparedRecoveryMutation {
    pub(crate) fn material(&self) -> RecoveryCanonicalMaterial {
        self.graph.material()
    }

    pub(crate) async fn apply(
        self,
        transaction: &mut Transaction<'_, Postgres>,
    ) -> Result<AppliedRecoveryMutation, RecoveryRepositoryError> {
        let Self { graph, completion } = self;
        let material = graph.material();
        let prepared = prepare_recovery_execution(transaction, &graph).await?;
        let applied = apply_prepared_recovery_execution(prepared).await?;
        Ok(AppliedRecoveryMutation {
            applied,
            completion,
            material,
        })
    }
}

#[cfg(not(test))]
pub(crate) struct AppliedRecoveryMutation {
    pub(crate) applied: AppliedTransition,
    pub(crate) completion: RecoveryCompletion,
    pub(crate) material: RecoveryCanonicalMaterial,
}

#[cfg(not(test))]
fn seal_planned_recovery(
    planned: PlannedRecoveryMutation,
) -> Result<PreparedRecoveryMutation, RecoveryRepositoryError> {
    let (
        transition,
        scope_authority,
        completion,
        prewrite,
        accepted_control_entry_bytes,
        persistence_witness,
        kind,
    ) = planned.into_parts();
    let material = match kind {
        RecoveryPlannedKind::Request {
            recovery_request_id,
        } => RecoveryCanonicalMaterial::Requested {
            recovery_request_id,
        },
        RecoveryPlannedKind::Cancellation {
            recovery_request_id,
        } => RecoveryCanonicalMaterial::Cancelled {
            recovery_request_id,
        },
        RecoveryPlannedKind::Fulfillment {
            recovery_request_id,
            transition_id,
        } => RecoveryCanonicalMaterial::Fulfilled {
            recovery_request_id,
            transition_id,
        },
    };
    Ok(PreparedRecoveryMutation {
        graph: PreparedRecoveryExecutionGraph::new_client(
            transition.into_persistence_plan()?,
            accepted_control_entry_bytes,
            persistence_witness,
            prewrite,
            material,
        )?,
        completion: RecoveryCompletion {
            scope_authority,
            completion,
        },
    })
}

#[cfg(not(test))]
fn client_expiry_material(
    recovery_request_id: Uuid,
    terminal_at: ServerTimestamp,
    post_apply_error: RecoveryClientTerminalError,
) -> Result<RecoveryCanonicalMaterial, RecoveryRepositoryError> {
    let terminal_at = DateTime::<Utc>::from_timestamp_millis(terminal_at.unix_millis())
        .ok_or(RecoveryRepositoryError::InvalidDurableRow)?;
    Ok(RecoveryCanonicalMaterial::ClientExpired {
        recovery_request_id,
        terminal_at,
        post_apply_error,
    })
}

#[cfg(not(test))]
fn scheduler_expiry_material(
    recovery_request_id: Uuid,
    terminal_at: ServerTimestamp,
) -> Result<RecoveryCanonicalMaterial, RecoveryRepositoryError> {
    let terminal_at = DateTime::<Utc>::from_timestamp_millis(terminal_at.unix_millis())
        .ok_or(RecoveryRepositoryError::InvalidDurableRow)?;
    Ok(RecoveryCanonicalMaterial::SchedulerExpired {
        recovery_request_id,
        terminal_at,
    })
}

#[cfg(not(test))]
pub(crate) fn plan_recovery_request<T: PublicTransport>(
    input: RecoveryRequestPlanInput,
    relationship_authority: &RelationshipAuthority<T>,
) -> Result<PreparedRecoveryMutation, RecoveryRepositoryError> {
    seal_planned_recovery(HydrationAuthority::plan_recovery_request_input(
        input,
        relationship_authority,
    )?)
}

#[cfg(not(test))]
pub(crate) fn plan_recovery_cancellation(
    input: RecoveryCancellationPlanInput,
) -> Result<PreparedRecoveryMutation, RecoveryRepositoryError> {
    seal_planned_recovery(HydrationAuthority::plan_recovery_cancellation_input(input)?)
}

#[cfg(not(test))]
pub(crate) fn plan_recovery_fulfillment<T: PublicTransport>(
    input: RecoveryFulfillmentPlanInput,
    relationship_authority: &RelationshipAuthority<T>,
) -> Result<PreparedRecoveryMutation, RecoveryRepositoryError> {
    seal_planned_recovery(HydrationAuthority::plan_recovery_fulfillment_input(
        input,
        relationship_authority,
    )?)
}

#[cfg(not(test))]
pub(crate) fn plan_client_recovery_expiry(
    input: RecoveryClientExpiryPlanInput,
) -> Result<PreparedRecoveryMutation, RecoveryRepositoryError> {
    let planned = HydrationAuthority::plan_client_recovery_expiry_input(input)?;
    let (
        transition,
        scope_authority,
        completion,
        prewrite,
        request_id,
        terminal_at,
        persistence_witness,
        post_apply_error,
    ) = planned.into_parts();
    let material = client_expiry_material(request_id, terminal_at, post_apply_error)?;
    Ok(PreparedRecoveryMutation {
        graph: PreparedRecoveryExecutionGraph::new_client(
            transition.into_persistence_plan()?,
            None,
            persistence_witness,
            prewrite,
            material,
        )?,
        completion: RecoveryCompletion {
            scope_authority,
            completion,
        },
    })
}

#[cfg(not(test))]
pub(crate) struct PreparedSchedulerRecoveryExpiry {
    graph: PreparedRecoveryExecutionGraph,
}

#[cfg(not(test))]
impl PreparedSchedulerRecoveryExpiry {
    pub(crate) fn material(&self) -> RecoveryCanonicalMaterial {
        self.graph.material()
    }

    pub(crate) async fn apply(
        self,
        transaction: &mut Transaction<'_, Postgres>,
    ) -> Result<AppliedSchedulerRecoveryExpiry, RecoveryRepositoryError> {
        let material = self.graph.material();
        let prepared = prepare_recovery_execution(transaction, &self.graph).await?;
        let applied = apply_prepared_recovery_execution(prepared).await?;
        Ok(AppliedSchedulerRecoveryExpiry { applied, material })
    }
}

#[cfg(not(test))]
pub(crate) struct AppliedSchedulerRecoveryExpiry {
    pub(crate) applied: AppliedTransition,
    pub(crate) material: RecoveryCanonicalMaterial,
}

#[cfg(not(test))]
pub(crate) fn plan_scheduler_recovery_expiry(
    input: RecoverySchedulerExpiryPlanInput,
) -> Result<PreparedSchedulerRecoveryExpiry, RecoveryRepositoryError> {
    let planned: PlannedSchedulerRecoveryExpiry =
        HydrationAuthority::plan_scheduler_recovery_expiry_input(input)?;
    let (transition, request_id, terminal_at, persistence_witness) = planned.into_parts();
    let material = scheduler_expiry_material(request_id, terminal_at)?;
    Ok(PreparedSchedulerRecoveryExpiry {
        graph: PreparedRecoveryExecutionGraph::new_scheduler(
            transition.into_persistence_plan()?,
            persistence_witness,
            material,
        )?,
    })
}

/// Non-shipping compiler proof for the exact production Recovery composition.
///
/// This module is deliberately compiled in the normal library configuration,
/// not through a path-included `cfg(test)` shadow. Each function consumes a real
/// opaque repository authority/input, crosses the real planner and private
/// `PreparedRecoveryExecutionGraph`, then invokes the facade whose prewrite
/// witness and prepared executor are the only write path. The returned client
/// result still owns the exact completion guards; scheduler expiry has no
/// completion authority by construction.
#[cfg(all(
    feature = "chat-protocol-production-proof",
    not(feature = "server-bin")
))]
#[allow(dead_code)]
pub mod production_composition_proof {
    use super::*;
    use crate::chat_protocol::state_machine::executor::{DropSafetyProbe, DropSafetyProbeMode};
    use futures::FutureExt as _;
    use serde_json::Value;
    use sqlx::PgPool;
    use std::panic::AssertUnwindSafe;

    mod production_proof_fixture {
        include!("recovery/production_proof_fixture.rs");
    }

    mod production_client_proof {
        include!("recovery/production_client_proof.rs");
    }

    mod production_fulfillment_proof {
        include!("recovery/production_fulfillment_proof.rs");
    }

    #[doc(hidden)]
    pub async fn run_request_leaf_recovery_happy_path(pool: &PgPool) -> Result<(), String> {
        production_client_proof::run_request_leaf_recovery_happy_path(pool).await
    }

    #[doc(hidden)]
    pub async fn run_request_leaf_recovery_operation_claim_drift_negative(
        pool: &PgPool,
    ) -> Result<(), String> {
        production_client_proof::run_request_leaf_recovery_operation_claim_drift_negative(pool)
            .await
    }

    #[doc(hidden)]
    pub async fn run_request_leaf_recovery_scope_drift_negative(
        pool: &PgPool,
    ) -> Result<(), String> {
        production_client_proof::run_request_leaf_recovery_scope_drift_negative(pool).await
    }

    #[doc(hidden)]
    pub async fn run_request_leaf_recovery_completion_rollback_negative(
        pool: &PgPool,
    ) -> Result<(), String> {
        production_client_proof::run_request_leaf_recovery_completion_rollback_negative(pool).await
    }

    #[doc(hidden)]
    pub async fn run_leaf_recovery_cancellation_happy_path(pool: &PgPool) -> Result<(), String> {
        production_client_proof::run_leaf_recovery_cancellation_happy_path(pool).await
    }

    #[doc(hidden)]
    pub async fn run_leaf_recovery_cancellation_due_for_expiry_ordering(
        pool: &PgPool,
    ) -> Result<(), String> {
        production_client_proof::run_leaf_recovery_cancellation_due_for_expiry_ordering(pool).await
    }

    #[doc(hidden)]
    pub async fn run_leaf_recovery_fulfillment_happy_path(pool: &PgPool) -> Result<(), String> {
        production_fulfillment_proof::run_leaf_recovery_fulfillment_happy_path(pool).await
    }

    #[doc(hidden)]
    pub async fn run_leaf_recovery_fulfillment_due_for_expiry_ordering(
        pool: &PgPool,
    ) -> Result<(), String> {
        production_fulfillment_proof::run_leaf_recovery_fulfillment_due_for_expiry_ordering(pool)
            .await
    }

    const PROOF_DATABASE: &str = "catbird_chat_protocol_test_20260722";

    async fn require_local_owned_gate(pool: &PgPool) -> Result<(), String> {
        let (database, user, owner, address): (String, String, String, Option<String>) =
            sqlx::query_as(
                "SELECT current_database(),current_user,pg_get_userbyid(d.datdba),\
                 inet_server_addr()::text FROM pg_database d \
                 WHERE d.datname=current_database()",
            )
            .fetch_one(pool)
            .await
            .map_err(|error| format!("inspect production-proof database: {error}"))?;
        if database != PROOF_DATABASE
            || user != owner
            || !address.as_deref().is_none_or(|value| {
                matches!(value, "127.0.0.1" | "127.0.0.1/32" | "::1" | "::1/128")
            })
        {
            return Err(format!(
                "refusing Recovery production proof on database={database:?} \
                 user={user:?} owner={owner:?} address={address:?}"
            ));
        }
        Ok(())
    }

    async fn due_request_id(transaction: &mut Transaction<'_, Postgres>) -> Result<Uuid, String> {
        sqlx::query_scalar(
            "SELECT recovery_request_id FROM chat.leaf_recovery_requests \
             WHERE status='open' \
               AND expires_at <= date_trunc('milliseconds',transaction_timestamp()) \
             ORDER BY requested_at DESC,recovery_request_id DESC LIMIT 1",
        )
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| format!("locate due Recovery proof fixture: {error}"))?
        .ok_or_else(|| {
            "production proof requires one production-valid due open Recovery fixture".to_owned()
        })
    }

    async fn prepare_scheduler(
        transaction: &mut Transaction<'_, Postgres>,
    ) -> Result<(Uuid, PreparedSchedulerRecoveryExpiry), String> {
        let request_id = due_request_id(transaction).await?;
        let authority = match prepare_recovery_expiry_authority(transaction, request_id)
            .await
            .map_err(|error| format!("prepare scheduler authority: {error:?}"))?
        {
            RecoverySchedulerExpiryRead::Authority(authority) => authority,
            RecoverySchedulerExpiryRead::Retained(_) => {
                return Err("due Recovery proof fixture became retained".to_owned())
            }
        };
        let prepared = plan_scheduler_recovery_expiry(authority.into_plan_input())
            .map_err(|error| format!("plan scheduler Recovery expiry: {error:?}"))?;
        Ok((request_id, prepared))
    }

    #[derive(Debug, Eq, FromRow, PartialEq)]
    struct RecoveryResidue {
        request_row: Value,
        reservation_row: Value,
        package_row: Value,
        conversation_row: Value,
        protocol_instance_id: Uuid,
        generations: Value,
        generation_states: Value,
        metadata_snapshots: Value,
        transitions: Value,
        entries: Value,
        events: Value,
        event_recipients: Value,
        outbox: Value,
        request_completions: Value,
    }

    impl RecoveryResidue {
        fn row_count(value: &Value, family: &str) -> Result<usize, String> {
            value
                .as_array()
                .map(Vec::len)
                .ok_or_else(|| format!("Recovery residue {family} is not a JSON array"))
        }

        fn event_count(&self) -> Result<usize, String> {
            Self::row_count(&self.events, "events")
        }

        fn outbox_count(&self) -> Result<usize, String> {
            Self::row_count(&self.outbox, "outbox")
        }
    }

    async fn residue_counts(
        transaction: &mut Transaction<'_, Postgres>,
        request_id: Uuid,
    ) -> Result<RecoveryResidue, String> {
        sqlx::query_as(
            "SELECT to_jsonb(request) AS request_row,\
                    to_jsonb(reservation) AS reservation_row,\
                    to_jsonb(package) AS package_row,\
                    to_jsonb(conversation) AS conversation_row,\
                    conversation.protocol_instance_id,\
                    COALESCE((SELECT jsonb_agg(to_jsonb(generation)\
                                             ORDER BY generation.generation)\
                      FROM chat.generations generation\
                     WHERE generation.conversation_id=request.conversation_id),\
                             '[]'::jsonb) AS generations,\
                    COALESCE((SELECT jsonb_agg(to_jsonb(state)\
                                             ORDER BY state.generation,state.state_version)\
                      FROM chat.generation_states state\
                     WHERE state.conversation_id=request.conversation_id),\
                             '[]'::jsonb) AS generation_states,\
                    COALESCE((SELECT jsonb_agg(to_jsonb(metadata)\
                                             ORDER BY metadata.metadata_snapshot_id)\
                      FROM chat.metadata_snapshots metadata\
                     WHERE metadata.conversation_id=request.conversation_id),\
                             '[]'::jsonb) AS metadata_snapshots,\
                    COALESCE((SELECT jsonb_agg(to_jsonb(transition)\
                                             ORDER BY transition.entry_seq,transition.transition_id)\
                      FROM chat.transitions transition\
                     WHERE transition.conversation_id=request.conversation_id),\
                             '[]'::jsonb) AS transitions,\
                    COALESCE((SELECT jsonb_agg(to_jsonb(entry)\
                                             ORDER BY entry.seq,entry.entry_id)\
                      FROM chat.entries entry\
                     WHERE entry.conversation_id=request.conversation_id),\
                             '[]'::jsonb) AS entries,\
                    COALESCE((SELECT jsonb_agg(to_jsonb(event)\
                                             ORDER BY event.event_position)\
                      FROM chat.events event\
                     WHERE event.protocol_instance_id=conversation.protocol_instance_id),\
                             '[]'::jsonb) AS events,\
                    COALESCE((SELECT jsonb_agg(to_jsonb(recipient)\
                                             ORDER BY recipient.event_position,\
                                                      recipient.user_did,\
                                                      recipient.device_id)\
                      FROM chat.event_recipients recipient\
                      JOIN chat.events event USING(event_position)\
                     WHERE event.protocol_instance_id=conversation.protocol_instance_id),\
                             '[]'::jsonb) AS event_recipients,\
                    COALESCE((SELECT jsonb_agg(to_jsonb(work)\
                                             ORDER BY work.event_position,work.outbox_id)\
                      FROM chat.outbox work\
                      JOIN chat.events event USING(event_position)\
                     WHERE event.protocol_instance_id=conversation.protocol_instance_id),\
                             '[]'::jsonb) AS outbox,\
                    COALESCE((SELECT jsonb_agg(to_jsonb(completion)\
                                             ORDER BY completion.principal_did,\
                                                      completion.endpoint_nsid,\
                                                      completion.operation_id)\
                      FROM chat.idempotency_records completion\
                      WHERE completion.principal_did=request.requester_did\
                        AND completion.endpoint_nsid='blue.catbird.chat.requestLeafRecovery'\
                        AND completion.operation_id=request.recovery_request_id),\
                             '[]'::jsonb) AS request_completions\
             FROM chat.leaf_recovery_requests request\
             JOIN chat.key_package_reservations reservation\
               ON reservation.recovery_request_id=request.recovery_request_id\
             JOIN chat.key_packages package\
               ON package.key_package_ref=request.key_package_ref\
             JOIN chat.conversations conversation\
               ON conversation.conversation_id=request.conversation_id\
             WHERE request.recovery_request_id=$1",
        )
        .bind(request_id)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|error| format!("read complete Recovery proof residue: {error}"))
    }

    fn require_prewrite_authority_mismatch(error: RecoveryRepositoryError) -> Result<(), String> {
        if matches!(
            error,
            RecoveryRepositoryError::ExecutionHydration(
                ExecutionContextHydrationError::AuthorityMismatch
            )
        ) {
            Ok(())
        } else {
            Err(format!(
                "expected executor-prewrite AuthorityMismatch, got {error:?}"
            ))
        }
    }

    async fn corrupt_aggregate_graph(
        transaction: &mut Transaction<'_, Postgres>,
        request_id: Uuid,
    ) -> Result<(), String> {
        sqlx::query("SET LOCAL session_replication_role='replica'")
            .execute(&mut **transaction)
            .await
            .map_err(|error| format!("enter privileged aggregate-drift simulation: {error}"))?;
        let changed = sqlx::query(
            "WITH target AS (\
               SELECT metadata.metadata_snapshot_id\
                 FROM chat.leaf_recovery_requests request\
                 JOIN chat.conversations conversation\
                   ON conversation.conversation_id=request.conversation_id\
                 JOIN chat.metadata_snapshots metadata\
                   ON metadata.conversation_id=request.conversation_id\
                  AND metadata.generation=request.generation\
                 JOIN chat.transitions producer\
                   ON producer.conversation_id=metadata.conversation_id\
                  AND producer.transition_id=metadata.producing_transition_id\
                WHERE request.recovery_request_id=$1\
                  AND producer.entry_seq < conversation.next_entry_seq\
                ORDER BY producer.entry_seq DESC,metadata.metadata_snapshot_id DESC\
                LIMIT 1\
             )\
             UPDATE chat.metadata_snapshots metadata SET \
                 ciphertext=set_byte(metadata.ciphertext,0,get_byte(metadata.ciphertext,0) # 1),\
                 ciphertext_sha256=digest(\
                   set_byte(metadata.ciphertext,0,get_byte(metadata.ciphertext,0) # 1),'sha256')\
             FROM target\
             WHERE metadata.metadata_snapshot_id=target.metadata_snapshot_id",
        )
        .bind(request_id)
        .execute(&mut **transaction)
        .await
        .map_err(|error| format!("inject aggregate graph drift: {error}"))?
        .rows_affected();
        sqlx::query("SET LOCAL session_replication_role='origin'")
            .execute(&mut **transaction)
            .await
            .map_err(|error| format!("leave aggregate-drift simulation: {error}"))?;
        if changed != 1 {
            return Err(format!(
                "aggregate-drift fixture expected one metadata row, changed {changed}"
            ));
        }
        Ok(())
    }

    async fn corrupt_public_snapshot(
        transaction: &mut Transaction<'_, Postgres>,
        request_id: Uuid,
    ) -> Result<(), String> {
        sqlx::query("SET LOCAL session_replication_role='replica'")
            .execute(&mut **transaction)
            .await
            .map_err(|error| format!("enter privileged snapshot-drift simulation: {error}"))?;
        let changed = sqlx::query(
            "UPDATE chat.generation_states state SET \
                 public_snapshot_bytes=set_byte(\
                   state.public_snapshot_bytes,0,get_byte(state.public_snapshot_bytes,0) # 1),\
                 snapshot_sha256=digest(set_byte(\
                   state.public_snapshot_bytes,0,get_byte(state.public_snapshot_bytes,0) # 1),\
                   'sha256')\
             FROM chat.leaf_recovery_requests request\
             WHERE request.recovery_request_id=$1\
               AND state.conversation_id=request.conversation_id\
               AND state.generation=request.generation\
               AND state.state_version=request.bound_state_version",
        )
        .bind(request_id)
        .execute(&mut **transaction)
        .await
        .map_err(|error| format!("inject public-snapshot drift: {error}"))?
        .rows_affected();
        sqlx::query("SET LOCAL session_replication_role='origin'")
            .execute(&mut **transaction)
            .await
            .map_err(|error| format!("leave snapshot-drift simulation: {error}"))?;
        if changed != 1 {
            return Err(format!(
                "snapshot-drift fixture expected one generation-state row, changed {changed}"
            ));
        }
        Ok(())
    }

    #[derive(Clone, Copy)]
    enum ExactRecoveryDrift {
        Request,
        Reservation,
        Package,
    }

    async fn corrupt_exact_recovery_row(
        transaction: &mut Transaction<'_, Postgres>,
        request_id: Uuid,
        drift: ExactRecoveryDrift,
    ) -> Result<(), String> {
        sqlx::query("SET LOCAL session_replication_role='replica'")
            .execute(&mut **transaction)
            .await
            .map_err(|error| format!("enter exact-row drift simulation: {error}"))?;
        let changed = match drift {
            ExactRecoveryDrift::Request => {
                sqlx::query(
                    "UPDATE chat.leaf_recovery_requests\
                    SET requester_auth_generation=requester_auth_generation+1\
                  WHERE recovery_request_id=$1",
                )
                .bind(request_id)
                .execute(&mut **transaction)
                .await
            }
            ExactRecoveryDrift::Reservation => {
                sqlx::query(
                    "UPDATE chat.key_package_reservations\
                    SET requester_auth_generation=requester_auth_generation+1\
                  WHERE recovery_request_id=$1",
                )
                .bind(request_id)
                .execute(&mut **transaction)
                .await
            }
            ExactRecoveryDrift::Package => {
                sqlx::query(
                    "UPDATE chat.key_packages package SET\
                    wrapper_bytes=set_byte(package.wrapper_bytes,0,\
                        get_byte(package.wrapper_bytes,0) # 1),\
                    wrapper_sha256=digest(set_byte(package.wrapper_bytes,0,\
                        get_byte(package.wrapper_bytes,0) # 1),'sha256')\
                  FROM chat.leaf_recovery_requests request\
                 WHERE request.recovery_request_id=$1\
                   AND package.key_package_ref=request.key_package_ref",
                )
                .bind(request_id)
                .execute(&mut **transaction)
                .await
            }
        }
        .map_err(|error| format!("inject exact Recovery row drift: {error}"))?
        .rows_affected();
        sqlx::query("SET LOCAL session_replication_role='origin'")
            .execute(&mut **transaction)
            .await
            .map_err(|error| format!("leave exact-row drift simulation: {error}"))?;
        if changed != 1 {
            return Err(format!(
                "exact-row drift expected one durable row, changed {changed}"
            ));
        }
        Ok(())
    }

    async fn run_exact_row_drift(pool: &PgPool, drift: ExactRecoveryDrift) -> Result<(), String> {
        require_local_owned_gate(pool).await?;
        let mut transaction = pool
            .begin()
            .await
            .map_err(|error| format!("begin exact-row drift proof: {error}"))?;
        let (request_id, prepared) = prepare_scheduler(&mut transaction).await?;
        corrupt_exact_recovery_row(&mut transaction, request_id, drift).await?;
        // The corruption is the test precondition. Snapshot it after
        // injection so equality proves the executor added no further write.
        let before = residue_counts(&mut transaction, request_id).await?;
        let error = match prepared.apply(&mut transaction).await {
            Ok(_) => return Err("exact Recovery row drift reached executor writes".to_owned()),
            Err(error) => error,
        };
        require_prewrite_authority_mismatch(error)?;
        let after = residue_counts(&mut transaction, request_id).await?;
        if after != before {
            return Err(format!(
                "exact-row prewrite drift left residue: before={before:?} after={after:?}"
            ));
        }
        transaction
            .rollback()
            .await
            .map_err(|error| format!("rollback exact-row drift proof: {error}"))
    }

    /// Moves a genuine prepared scheduler graph across transaction identity and
    /// requires executor prewrite rejection with no durable residue.
    #[doc(hidden)]
    pub async fn run_foreign_transaction_negative(pool: &PgPool) -> Result<(), String> {
        require_local_owned_gate(pool).await?;
        let mut planning = pool
            .begin()
            .await
            .map_err(|error| format!("begin foreign planning transaction: {error}"))?;
        let (request_id, prepared) = prepare_scheduler(&mut planning).await?;
        planning
            .rollback()
            .await
            .map_err(|error| format!("release foreign planning transaction: {error}"))?;
        let mut execution = pool
            .begin()
            .await
            .map_err(|error| format!("begin foreign execution transaction: {error}"))?;
        let before = residue_counts(&mut execution, request_id).await?;
        let error = match prepared.apply(&mut execution).await {
            Ok(_) => return Err("foreign transaction applied a Recovery graph".to_owned()),
            Err(error) => error,
        };
        require_prewrite_authority_mismatch(error)?;
        let after = residue_counts(&mut execution, request_id).await?;
        if after != before {
            return Err(format!(
                "foreign transaction left residue: before={before:?} after={after:?}"
            ));
        }
        execution
            .rollback()
            .await
            .map_err(|error| format!("rollback foreign execution transaction: {error}"))
    }

    /// Preparing and then abandoning a real private graph performs no write.
    #[doc(hidden)]
    pub async fn run_prepare_abandon_negative(pool: &PgPool) -> Result<(), String> {
        require_local_owned_gate(pool).await?;
        let mut transaction = pool
            .begin()
            .await
            .map_err(|error| format!("begin prepare-abandon proof: {error}"))?;
        let (request_id, prepared) = prepare_scheduler(&mut transaction).await?;
        let before = residue_counts(&mut transaction, request_id).await?;
        drop(prepared);
        sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
            .execute(&mut *transaction)
            .await
            .map_err(|error| format!("validate abandoned graph constraints: {error}"))?;
        let after = residue_counts(&mut transaction, request_id).await?;
        if after != before {
            return Err(format!(
                "abandoned prepared graph left residue: before={before:?} after={after:?}"
            ));
        }
        transaction
            .rollback()
            .await
            .map_err(|error| format!("rollback prepare-abandon proof: {error}"))
    }

    async fn install_exact_head_cas_blocker(
        transaction: &mut Transaction<'_, Postgres>,
        request_id: Uuid,
    ) -> Result<(), String> {
        let conversation_id: Uuid = sqlx::query_scalar(
            "SELECT conversation_id FROM chat.leaf_recovery_requests \
             WHERE recovery_request_id=$1",
        )
        .bind(request_id)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|error| format!("locate exact Recovery conversation: {error}"))?;
        sqlx::query("SELECT set_config('catbird.recovery_proof_conversation',$1,true)")
            .bind(conversation_id.hyphenated().to_string())
            .execute(&mut **transaction)
            .await
            .map_err(|error| format!("bind exact Recovery CAS blocker: {error}"))?;
        sqlx::query(
            "CREATE OR REPLACE FUNCTION pg_temp.catbird_recovery_proof_block_head() \
             RETURNS trigger LANGUAGE plpgsql AS $$ \
             BEGIN \
               IF OLD.conversation_id::text = \
                    current_setting('catbird.recovery_proof_conversation',true) \
               THEN RETURN NULL; \
               END IF; \
               RETURN NEW; \
             END $$",
        )
        .execute(&mut **transaction)
        .await
        .map_err(|error| format!("create Recovery CAS blocker function: {error}"))?;
        sqlx::query(
            "CREATE TRIGGER catbird_recovery_proof_block_head \
             BEFORE UPDATE ON chat.conversations \
             FOR EACH ROW EXECUTE FUNCTION pg_temp.catbird_recovery_proof_block_head()",
        )
        .execute(&mut **transaction)
        .await
        .map_err(|error| format!("install Recovery CAS blocker trigger: {error}"))?;
        Ok(())
    }

    /// Forces the exact conversation-head CAS to fail after the Recovery
    /// terminal triple has been written inside the executor savepoint. The
    /// executor must synchronously roll that savepoint back before returning.
    #[doc(hidden)]
    pub async fn run_terminal_head_cas_rollback_negative(pool: &PgPool) -> Result<(), String> {
        require_local_owned_gate(pool).await?;
        let mut transaction = pool
            .begin()
            .await
            .map_err(|error| format!("begin late-CAS rollback proof: {error}"))?;
        let (request_id, prepared) = prepare_scheduler(&mut transaction).await?;
        let before = residue_counts(&mut transaction, request_id).await?;
        install_exact_head_cas_blocker(&mut transaction, request_id).await?;
        let error = match prepared.apply(&mut transaction).await {
            Ok(_) => return Err("blocked Recovery head CAS unexpectedly applied".to_owned()),
            Err(error) => error,
        };
        if !matches!(
            error,
            RecoveryRepositoryError::Execution(ExecutorError::Transition(
                transition::TransitionRepositoryError::CompareAndSetConflict
            ))
        ) {
            return Err(format!(
                "expected late exact head CompareAndSetConflict, got {error:?}"
            ));
        }
        sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
            .execute(&mut *transaction)
            .await
            .map_err(|error| format!("validate late-CAS rollback constraints: {error}"))?;
        let after = residue_counts(&mut transaction, request_id).await?;
        if after != before {
            return Err(format!(
                "late head-CAS failure left savepoint residue: before={before:?} after={after:?}"
            ));
        }
        transaction
            .rollback()
            .await
            .map_err(|error| format!("rollback late-CAS proof: {error}"))
    }

    #[derive(Clone, Copy)]
    enum PostWriteAbort {
        Cancellation,
        Panic,
    }

    async fn run_postwrite_abort(pool: &PgPool, abort: PostWriteAbort) -> Result<(), String> {
        require_local_owned_gate(pool).await?;
        let mut transaction = pool
            .begin()
            .await
            .map_err(|error| format!("begin post-write abort proof: {error}"))?;
        let (request_id, prepared) = prepare_scheduler(&mut transaction).await?;
        let before = residue_counts(&mut transaction, request_id).await?;
        let PreparedSchedulerRecoveryExpiry { graph } = prepared;
        {
            let prepared_execution = prepare_recovery_execution(&mut transaction, &graph)
                .await
                .map_err(|error| format!("prepare post-write abort execution: {error:?}"))?;
            let mode = match abort {
                PostWriteAbort::Cancellation => DropSafetyProbeMode::Pending,
                PostWriteAbort::Panic => DropSafetyProbeMode::Panic,
            };
            let (probe, reached) = DropSafetyProbe::new(mode);
            let execution = apply_prepared_recovery_execution(
                prepared_execution.with_drop_safety_probe_for_proof(probe),
            );
            match abort {
                PostWriteAbort::Cancellation => {
                    tokio::pin!(execution);
                    tokio::select! {
                        signal = reached => {
                            signal.map_err(|_| {
                                "post-write cancellation probe closed before executor writes"
                                    .to_owned()
                            })?;
                        }
                        result = &mut execution => {
                            return Err(format!(
                                "post-write cancellation executor completed before cancellation: \
                                 {result:?}"
                            ));
                        }
                    }
                }
                PostWriteAbort::Panic => {
                    let result = AssertUnwindSafe(execution).catch_unwind().await;
                    if result.is_ok() {
                        return Err("post-write panic probe returned without unwinding".to_owned());
                    }
                    reached.await.map_err(|_| {
                        "post-write panic probe closed before executor writes".to_owned()
                    })?;
                }
            }
        }
        // Dropping/unwinding the SQLx savepoint queues ROLLBACK TO SAVEPOINT.
        // The first same-connection round trip drains that rollback before the
        // caller is allowed to inspect or reuse the outer transaction.
        sqlx::query("SELECT 1")
            .execute(&mut *transaction)
            .await
            .map_err(|error| format!("drain queued post-write rollback: {error}"))?;
        sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
            .execute(&mut *transaction)
            .await
            .map_err(|error| format!("validate post-write rollback constraints: {error}"))?;
        let after = residue_counts(&mut transaction, request_id).await?;
        if after != before {
            return Err(format!(
                "post-write abort left savepoint residue: before={before:?} after={after:?}"
            ));
        }
        transaction
            .rollback()
            .await
            .map_err(|error| format!("rollback post-write abort proof: {error}"))
    }

    /// Cancels a real Recovery executor future after all writes and before
    /// savepoint release, then proves the queued SQLx rollback erases them.
    #[doc(hidden)]
    pub async fn run_postwrite_cancellation_rollback_negative(pool: &PgPool) -> Result<(), String> {
        run_postwrite_abort(pool, PostWriteAbort::Cancellation).await
    }

    /// Unwinds a real Recovery executor future after all writes and before
    /// savepoint release, then proves the queued SQLx rollback erases them.
    #[doc(hidden)]
    pub async fn run_postwrite_panic_rollback_negative(pool: &PgPool) -> Result<(), String> {
        run_postwrite_abort(pool, PostWriteAbort::Panic).await
    }

    #[doc(hidden)]
    pub async fn run_request_row_drift_negative(pool: &PgPool) -> Result<(), String> {
        run_exact_row_drift(pool, ExactRecoveryDrift::Request).await
    }

    #[doc(hidden)]
    pub async fn run_reservation_row_drift_negative(pool: &PgPool) -> Result<(), String> {
        run_exact_row_drift(pool, ExactRecoveryDrift::Reservation).await
    }

    #[doc(hidden)]
    pub async fn run_package_row_drift_negative(pool: &PgPool) -> Result<(), String> {
        run_exact_row_drift(pool, ExactRecoveryDrift::Package).await
    }

    #[derive(Debug)]
    struct SchedulerTerminalExpectation {
        terminal_at: DateTime<Utc>,
        package_not_after: DateTime<Utc>,
        package_status: &'static str,
    }

    async fn scheduler_terminal_expectation(
        transaction: &mut Transaction<'_, Postgres>,
        request_id: Uuid,
        prepared: &PreparedSchedulerRecoveryExpiry,
    ) -> Result<SchedulerTerminalExpectation, String> {
        let terminal_at = match prepared.material() {
            RecoveryCanonicalMaterial::SchedulerExpired {
                recovery_request_id,
                terminal_at,
            } if recovery_request_id == request_id => terminal_at,
            material => {
                return Err(format!(
                    "scheduler preparation returned wrong canonical material: {material:?}"
                ))
            }
        };
        let (request_expires_at, package_not_after): (DateTime<Utc>, DateTime<Utc>) =
            sqlx::query_as(
                "SELECT request.expires_at,package.not_after\
                   FROM chat.leaf_recovery_requests request\
                   JOIN chat.key_packages package\
                     ON package.key_package_ref=request.key_package_ref\
                  WHERE request.recovery_request_id=$1",
            )
            .bind(request_id)
            .fetch_one(&mut **transaction)
            .await
            .map_err(|error| format!("read scheduler terminal expectation: {error}"))?;
        if request_expires_at != terminal_at || package_not_after < terminal_at {
            return Err(format!(
                "scheduler plan terminal binding disagrees with durable lifetime: \
                 material={terminal_at} request={request_expires_at} package={package_not_after}"
            ));
        }
        Ok(SchedulerTerminalExpectation {
            terminal_at,
            package_not_after,
            package_status: if package_not_after == terminal_at {
                "expired"
            } else {
                "available"
            },
        })
    }

    async fn require_exact_scheduler_terminal(
        transaction: &mut Transaction<'_, Postgres>,
        request_id: Uuid,
        expected: &SchedulerTerminalExpectation,
    ) -> Result<(), String> {
        let (request, reservation, package) = lock_terminal_rows(transaction, request_id)
            .await
            .map_err(|error| format!("reload exact scheduler terminal rows: {error:?}"))?;
        let request_exact = request.status == "expired"
            && request.expires_at == expected.terminal_at
            && request.fulfilling_transition_id.is_none()
            && request.terminal_transition_id.is_none()
            && request.terminal_revocation_id.is_none()
            && request.terminal_signed_request_bytes.is_none()
            && request.terminal_signing_transcript_bytes.is_none()
            && request.terminal_request_digest.is_none()
            && request.terminal_signature.is_none()
            && request.terminal_at == Some(expected.terminal_at);
        let reservation_exact = reservation.status == "expired"
            && reservation.expires_at == expected.terminal_at
            && reservation.consumed_transition_id.is_none()
            && reservation.terminal_transition_id.is_none()
            && reservation.terminal_revocation_id.is_none()
            && reservation.terminal_request_digest.is_none()
            && reservation.terminal_at == Some(expected.terminal_at);
        let package_exact = package.not_after == expected.package_not_after
            && package.status == expected.package_status
            && package.terminal_transition_id.is_none()
            && package.terminal_revocation_id.is_none()
            && match expected.package_status {
                "expired" => package.terminal_at == Some(expected.package_not_after),
                "available" => package.terminal_at.is_none(),
                _ => false,
            };
        if request_exact && reservation_exact && package_exact {
            Ok(())
        } else {
            Err(format!(
                "scheduler terminal rows violate exact expected branch \
                 expected={expected:?} request_status={} request_terminal_at={:?} \
                 reservation_status={} reservation_terminal_at={:?} \
                 package_status={} package_not_after={} package_terminal_at={:?} \
                 request_transition={:?}/{:?} reservation_transition={:?}/{:?}/{:?} \
                 package_transition={:?}/{:?}",
                request.status,
                request.terminal_at,
                reservation.status,
                reservation.terminal_at,
                package.status,
                package.not_after,
                package.terminal_at,
                request.terminal_transition_id,
                request.terminal_revocation_id,
                reservation.consumed_transition_id,
                reservation.terminal_transition_id,
                reservation.terminal_revocation_id,
                package.terminal_transition_id,
                package.terminal_revocation_id,
            ))
        }
    }

    /// Executes the real scheduler lifecycle through its opaque authority,
    /// planner, private graph, witness prewrite, prepared executor, exact
    /// terminal triple, event/outbox, and scheduler-only material. The outer
    /// transaction is rolled back so the gate fixture remains reusable.
    #[doc(hidden)]
    pub async fn run_scheduler_expiry_lifecycle(pool: &PgPool) -> Result<(), String> {
        require_local_owned_gate(pool).await?;
        let mut transaction = pool
            .begin()
            .await
            .map_err(|error| format!("begin scheduler production proof: {error}"))?;
        let (request_id, prepared) = prepare_scheduler(&mut transaction).await?;
        let expected =
            scheduler_terminal_expectation(&mut transaction, request_id, &prepared).await?;
        let before = residue_counts(&mut transaction, request_id).await?;
        let before_event_count = before.event_count()?;
        let before_outbox_count = before.outbox_count()?;
        let applied = prepared
            .apply(&mut transaction)
            .await
            .map_err(|error| format!("apply scheduler production proof: {error:?}"))?;
        if !matches!(
            applied.material,
            RecoveryCanonicalMaterial::SchedulerExpired {
                recovery_request_id,
                terminal_at,
            } if recovery_request_id == request_id && terminal_at == expected.terminal_at
        ) {
            return Err("scheduler proof returned client/completion material".to_owned());
        }
        let after = residue_counts(&mut transaction, request_id).await?;
        require_exact_scheduler_terminal(&mut transaction, request_id, &expected).await?;
        if applied.applied.event_positions.len() != 1 {
            return Err(format!(
                "scheduler proof emitted {} event positions, expected exactly one",
                applied.applied.event_positions.len()
            ));
        }
        let event_position = applied.applied.event_positions[0];
        let (event_kind, protocol_instance_id, outbox_rows): (String, Uuid, i64) = sqlx::query_as(
            "SELECT event.event_kind,event.protocol_instance_id,\
                        (SELECT count(*) FROM chat.outbox outbox\
                          WHERE outbox.event_position=event.event_position)\
                   FROM chat.events event WHERE event.event_position=$1",
        )
        .bind(event_position)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|error| format!("read scheduler proof event/outbox: {error}"))?;
        if event_kind != "leafRecovery"
            || protocol_instance_id != before.protocol_instance_id
            || outbox_rows != 1
            || after.event_count()? != before_event_count + 1
            || after.outbox_count()? != before_outbox_count + 1
            || after.request_completions != before.request_completions
        {
            return Err(format!(
                "scheduler proof event/outbox/completion delta mismatch: \
                 before={before:?} after={after:?} event_kind={event_kind:?} \
                 protocol_instance_id={protocol_instance_id} outbox_rows={outbox_rows}"
            ));
        }
        transaction
            .rollback()
            .await
            .map_err(|error| format!("rollback scheduler production proof: {error}"))
    }

    async fn run_prewrite_drift(pool: &PgPool, snapshot: bool) -> Result<(), String> {
        require_local_owned_gate(pool).await?;
        let mut transaction = pool
            .begin()
            .await
            .map_err(|error| format!("begin Recovery drift proof: {error}"))?;
        let (request_id, prepared) = prepare_scheduler(&mut transaction).await?;
        if snapshot {
            corrupt_public_snapshot(&mut transaction, request_id).await?;
        } else {
            corrupt_aggregate_graph(&mut transaction, request_id).await?;
        }
        // The privileged corruption is the test precondition. Snapshot it
        // after injection so equality proves the executor added no write.
        let before = residue_counts(&mut transaction, request_id).await?;
        let error = match prepared.apply(&mut transaction).await {
            Ok(_) => return Err("durable aggregate drift reached executor writes".to_owned()),
            Err(error) => error,
        };
        require_prewrite_authority_mismatch(error)?;
        let after = residue_counts(&mut transaction, request_id).await?;
        if after != before {
            return Err(format!(
                "prewrite drift left business/event/outbox/completion residue: \
                 before={before:?} after={after:?}"
            ));
        }
        transaction
            .rollback()
            .await
            .map_err(|error| format!("rollback Recovery drift proof: {error}"))
    }

    /// Privileged gate-only corruption simulation for a durable aggregate graph
    /// fact. It bypasses the immutable-row trigger, then requires the real
    /// executor prewrite to reject with zero residue.
    #[doc(hidden)]
    pub async fn run_aggregate_graph_drift_negative(pool: &PgPool) -> Result<(), String> {
        run_prewrite_drift(pool, false).await
    }

    /// Privileged gate-only corruption simulation for the active public
    /// snapshot. It bypasses the immutable-row trigger, then requires the real
    /// executor prewrite to reject with zero residue.
    #[doc(hidden)]
    pub async fn run_public_snapshot_drift_negative(pool: &PgPool) -> Result<(), String> {
        run_prewrite_drift(pool, true).await
    }

    async fn request<T: PublicTransport>(
        authority: RecoveryRequestAuthority,
        transaction: &mut Transaction<'_, Postgres>,
        relationship_authority: &RelationshipAuthority<T>,
        trusted_request_instant: &TrustedRequestInstant,
    ) -> Result<AppliedRecoveryMutation, RecoveryRepositoryError> {
        let input = authority
            .into_plan_input(transaction, relationship_authority, trusted_request_instant)
            .await?;
        plan_recovery_request(input, relationship_authority)?
            .apply(transaction)
            .await
    }

    async fn cancellation(
        authority: RecoveryCancellationAuthority,
        transaction: &mut Transaction<'_, Postgres>,
        trusted_request_instant: &TrustedRequestInstant,
    ) -> Result<AppliedRecoveryMutation, RecoveryRepositoryError> {
        let input = authority.into_plan_input(trusted_request_instant)?;
        plan_recovery_cancellation(input)?.apply(transaction).await
    }

    async fn fulfillment<T: PublicTransport>(
        authority: RecoveryFulfillmentAuthority,
        transaction: &mut Transaction<'_, Postgres>,
        relationship_authority: &RelationshipAuthority<T>,
        trusted_request_instant: &TrustedRequestInstant,
    ) -> Result<AppliedRecoveryMutation, RecoveryRepositoryError> {
        let input = authority
            .into_plan_input(transaction, relationship_authority, trusted_request_instant)
            .await?;
        plan_recovery_fulfillment(input, relationship_authority)?
            .apply(transaction)
            .await
    }

    async fn client_expiry(
        input: RecoveryClientExpiryPlanInput,
        transaction: &mut Transaction<'_, Postgres>,
    ) -> Result<AppliedRecoveryMutation, RecoveryRepositoryError> {
        plan_client_recovery_expiry(input)?.apply(transaction).await
    }

    async fn scheduler_expiry(
        input: RecoverySchedulerExpiryPlanInput,
        transaction: &mut Transaction<'_, Postgres>,
    ) -> Result<AppliedSchedulerRecoveryExpiry, RecoveryRepositoryError> {
        plan_scheduler_recovery_expiry(input)?
            .apply(transaction)
            .await
    }

    fn client_completion(
        applied: AppliedRecoveryMutation,
    ) -> (
        AppliedTransition,
        ScopeBoundBusinessAuthority,
        OperationCompletionGuard,
        RecoveryCanonicalMaterial,
    ) {
        let AppliedRecoveryMutation {
            applied,
            completion,
            material,
        } = applied;
        let (scope, completion) = completion.into_parts();
        (applied, scope, completion, material)
    }

    fn exact_executor_surface_typechecks() {
        let _ = PreparedRecoveryExecutionGraph::validate_prewrite;
        let _ = RecoveryPersistenceWitness::validate_prewrite;
        let _ = RecoveryExecutorWriteAuthority::apply_open;
        let _ = RecoveryExecutorWriteAuthority::apply_terminal;
        let _ = prepare_recovery_execution;
        let _ = apply_prepared_recovery_execution;
    }
}

impl RecoveryRequestAuthority {
    #[cfg(not(test))]
    pub(crate) async fn into_plan_input<T: PublicTransport>(
        self,
        transaction: &mut Transaction<'_, Postgres>,
        relationship_authority: &RelationshipAuthority<T>,
        trusted_request_instant: &TrustedRequestInstant,
    ) -> Result<RecoveryRequestPlanInput, RecoveryRepositoryError> {
        if trusted_request_instant.datetime() != self.context.trusted_instant {
            return Err(RecoveryRepositoryError::TrustedInstantMismatch);
        }
        validate_client_context(transaction, &self.context).await?;
        let hydration = HydrationAuthority::from_locked_conversation(&self.context.aggregate)?;
        let registration = hydration
            .locked_registration_from_scope_authority(self.context.prelude.scope_authority())?;
        let decision_scope = seal_recovery_fallback_scope(
            &self.context.aggregate,
            &registration,
            ProjectionOperationScope::RecoveryReservation,
        )?;
        let (relationship, relationship_decision) = load_fallback_relationship_projection(
            transaction,
            decision_scope,
            relationship_authority,
        )
        .await?
        .ok_or(RecoveryRepositoryError::RelationshipUnavailable)?;
        Ok(RecoveryRequestPlanInput {
            context: self.context,
            request: self.request,
            reservation: self.reservation,
            package: self.package,
            execution_package: self.execution_package,
            relationship,
            relationship_decision,
            trusted_request_instant: trusted_request_instant.clone(),
        })
    }
}

fn recovery_roster(
    locked: &LockedConversationStateGuard,
) -> Result<Vec<String>, RecoveryRepositoryError> {
    let mut roster = locked
        .state()
        .participants()
        .iter()
        .map(|participant| {
            String::from_utf8(participant.principal().as_bytes().to_vec())
                .map_err(|_| RecoveryRepositoryError::InvalidDurableRow)
        })
        .collect::<Result<Vec<_>, _>>()?;
    roster.sort();
    if roster.is_empty() || roster.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(RecoveryRepositoryError::InvalidDurableRow);
    }
    Ok(roster)
}

impl RecoveryRequestPlanInput {
    pub(crate) fn transaction_id(&self) -> &str {
        &self.context.transaction_id
    }

    pub(crate) fn trusted_instant(&self) -> DateTime<Utc> {
        self.context.trusted_instant
    }

    pub(crate) fn request(&self) -> &NewLeafRecoveryRequest {
        &self.request
    }

    pub(crate) fn reservation(&self) -> &NewReservation {
        &self.reservation
    }

    pub(crate) async fn validate_same_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
    ) -> Result<(), RecoveryRepositoryError> {
        validate_client_context(transaction, &self.context).await
    }

    pub(in crate::chat_protocol) fn into_planner_parts(self) -> RecoveryRequestPlannerParts {
        let Self {
            context,
            request,
            reservation,
            package,
            execution_package,
            relationship,
            relationship_decision,
            trusted_request_instant,
        } = self;
        let (persistence_witness, aggregate, mutation, prelude, _terminal_packages) =
            RecoveryPersistenceWitness::new(
                context,
                request,
                reservation,
                package,
                RecoveryPersistenceMode::Open,
            );
        RecoveryRequestPlannerParts {
            aggregate,
            mutation,
            prelude,
            execution_package,
            relationship,
            relationship_decision,
            trusted_request_instant,
            persistence_witness,
        }
    }
}

impl RecoveryCancellationAuthority {
    pub(crate) fn into_plan_input(
        self,
        trusted_request_instant: &TrustedRequestInstant,
    ) -> Result<RecoveryCancellationPlanInput, RecoveryRepositoryError> {
        if trusted_request_instant.datetime() != self.context.trusted_instant {
            return Err(RecoveryRepositoryError::TrustedInstantMismatch);
        }
        Ok(RecoveryCancellationPlanInput {
            context: self.context,
            request: self.request,
            reservation: self.reservation,
            package: self.package,
            execution_package: self.execution_package,
            trusted_request_instant: trusted_request_instant.clone(),
        })
    }

    pub(crate) fn into_prelude(self) -> PreparedBusinessPrelude {
        self.context.prelude
    }
}

impl RecoveryFulfillmentAuthority {
    #[cfg(not(test))]
    pub(crate) async fn into_plan_input<T: PublicTransport>(
        self,
        transaction: &mut Transaction<'_, Postgres>,
        relationship_authority: &RelationshipAuthority<T>,
        trusted_request_instant: &TrustedRequestInstant,
    ) -> Result<RecoveryFulfillmentPlanInput, RecoveryRepositoryError> {
        if trusted_request_instant.datetime() != self.context.trusted_instant {
            return Err(RecoveryRepositoryError::TrustedInstantMismatch);
        }
        validate_client_context(transaction, &self.context).await?;
        let hydration = HydrationAuthority::from_locked_conversation(&self.context.aggregate)?;
        let registration = hydration
            .locked_registration_from_scope_authority(self.context.prelude.scope_authority())?;
        let decision_scope = seal_recovery_fallback_scope(
            &self.context.aggregate,
            &registration,
            ProjectionOperationScope::RecoveryFulfillment,
        )?;
        let (relationship, relationship_decision) = load_fallback_relationship_projection(
            transaction,
            decision_scope,
            relationship_authority,
        )
        .await?
        .ok_or(RecoveryRepositoryError::RelationshipUnavailable)?;
        Ok(RecoveryFulfillmentPlanInput {
            context: self.context,
            request: self.request,
            reservation: self.reservation,
            package: self.package,
            execution_package: self.execution_package,
            relationship,
            relationship_decision,
            transition_id: self.transition_id,
            trusted_request_instant: trusted_request_instant.clone(),
        })
    }

    pub(crate) fn into_prelude(self) -> PreparedBusinessPrelude {
        self.context.prelude
    }
}

impl RecoveryCancellationPlanInput {
    pub(crate) fn transaction_id(&self) -> &str {
        &self.context.transaction_id
    }

    pub(crate) fn trusted_instant(&self) -> DateTime<Utc> {
        self.context.trusted_instant
    }

    pub(crate) fn request(&self) -> &NewLeafRecoveryRequest {
        &self.request
    }

    pub(crate) fn reservation(&self) -> &NewReservation {
        &self.reservation
    }

    pub(crate) async fn validate_same_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
    ) -> Result<(), RecoveryRepositoryError> {
        validate_client_context(transaction, &self.context).await
    }

    pub(in crate::chat_protocol) fn into_planner_parts(self) -> RecoveryCancellationPlannerParts {
        let Self {
            context,
            request,
            reservation,
            package,
            execution_package,
            trusted_request_instant,
        } = self;
        let mode = RecoveryPersistenceMode::Cancelled {
            terminal_signed_request_bytes: context.evidence.signed_request_bytes.clone(),
            terminal_signing_transcript_bytes: context.evidence.signing_transcript_bytes.clone(),
            terminal_request_digest: context.evidence.request_digest,
            terminal_signature: context.evidence.signature,
            terminal_at: context.trusted_instant,
        };
        let (persistence_witness, aggregate, mutation, prelude, _terminal_packages) =
            RecoveryPersistenceWitness::new(context, request, reservation, package, mode);
        RecoveryCancellationPlannerParts {
            aggregate,
            mutation,
            prelude,
            execution_package,
            trusted_request_instant,
            persistence_witness,
        }
    }
}

impl RecoveryFulfillmentPlanInput {
    pub(crate) fn transaction_id(&self) -> &str {
        &self.context.transaction_id
    }

    pub(crate) fn trusted_instant(&self) -> DateTime<Utc> {
        self.context.trusted_instant
    }

    pub(crate) fn transition_id(&self) -> Uuid {
        self.transition_id
    }

    pub(crate) fn request(&self) -> &NewLeafRecoveryRequest {
        &self.request
    }

    pub(crate) fn reservation(&self) -> &NewReservation {
        &self.reservation
    }

    pub(crate) async fn validate_same_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
    ) -> Result<(), RecoveryRepositoryError> {
        validate_client_context(transaction, &self.context).await
    }

    pub(in crate::chat_protocol) fn into_planner_parts(self) -> RecoveryFulfillmentPlannerParts {
        let Self {
            context,
            request,
            reservation,
            package,
            execution_package,
            relationship,
            relationship_decision,
            transition_id,
            trusted_request_instant,
        } = self;
        let mode = RecoveryPersistenceMode::Fulfilled {
            transition_id,
            terminal_at: context.trusted_instant,
        };
        let (persistence_witness, aggregate, mutation, prelude, terminal_packages) =
            RecoveryPersistenceWitness::new(context, request, reservation, package, mode);
        RecoveryFulfillmentPlannerParts {
            aggregate,
            mutation,
            prelude,
            execution_package,
            terminal_packages,
            relationship,
            relationship_decision,
            transition_id,
            trusted_request_instant,
            persistence_witness,
        }
    }
}

impl RecoverySchedulerExpiryAuthority {
    pub(crate) fn into_plan_input(self) -> RecoverySchedulerExpiryPlanInput {
        RecoverySchedulerExpiryPlanInput { authority: self }
    }
}

impl RecoveryClientExpiryAuthority {
    fn into_plan_input_with_error(
        self,
        trusted_request_instant: &TrustedRequestInstant,
        post_apply_error: RecoveryClientTerminalError,
    ) -> Result<RecoveryClientExpiryPlanInput, RecoveryRepositoryError> {
        if trusted_request_instant.datetime() != self.trusted_instant {
            return Err(RecoveryRepositoryError::TrustedInstantMismatch);
        }
        Ok(RecoveryClientExpiryPlanInput {
            authority: self,
            trusted_request_instant: trusted_request_instant.clone(),
            post_apply_error,
        })
    }
}

impl RecoveryClientExpiryPlanInput {
    pub(in crate::chat_protocol) fn into_planner_parts(
        self,
    ) -> Result<RecoveryClientExpiryPlannerParts, RecoveryRepositoryError> {
        let authority = self.authority;
        if authority.trusted_instant < authority.request.expires_at
            || !authority
                .aggregate_cross_binding
                .validates(&authority.aggregate, &authority.head)
            || authority.authority_digest
                != expiry_authority_digest(
                    &authority.transaction_id,
                    authority.trusted_instant,
                    &authority.head,
                    &authority.request,
                    &authority.reservation,
                    &authority.package,
                )
        {
            return Err(RecoveryRepositoryError::ReadSetMismatch);
        }
        let RecoveryClientExpiryAuthority {
            sql_authority,
            prelude,
            transaction_id,
            trusted_instant,
            graph_actor_did,
            graph_actor_device_id,
            aggregate,
            aggregate_cross_binding,
            execution_package,
            head: _,
            request,
            reservation,
            package,
            authority_digest,
        } = authority;
        let terminal_at = request.expires_at;
        let request_id = request.recovery_request_id;
        let persistence_witness = RecoveryPersistenceWitness {
            sql_authority,
            transaction_id,
            trusted_instant,
            graph_actor_did,
            graph_actor_device_id,
            aggregate_cross_binding,
            request,
            reservation,
            package,
            mode: RecoveryPersistenceMode::Expired { terminal_at },
        };
        Ok(RecoveryClientExpiryPlannerParts {
            aggregate,
            execution_package,
            prelude,
            observed_at: trusted_instant,
            terminal_at,
            request_id,
            locked_read_set_digest: authority_digest,
            trusted_request_instant: self.trusted_request_instant,
            post_apply_error: self.post_apply_error,
            persistence_witness,
        })
    }
}

impl RecoverySchedulerExpiryPlanInput {
    pub(in crate::chat_protocol) fn into_planner_parts(
        self,
    ) -> Result<RecoverySchedulerExpiryPlannerParts, RecoveryRepositoryError> {
        let authority = self.authority;
        if authority.trusted_instant < authority.request.expires_at
            || !authority
                .aggregate_cross_binding
                .validates(&authority.aggregate, &authority.head)
            || authority.authority_digest
                != expiry_authority_digest(
                    &authority.transaction_id,
                    authority.trusted_instant,
                    &authority.head,
                    &authority.request,
                    &authority.reservation,
                    &authority.package,
                )
        {
            return Err(RecoveryRepositoryError::ReadSetMismatch);
        }
        let RecoverySchedulerExpiryAuthority {
            sql_authority,
            transaction_id,
            trusted_instant,
            graph_actor_did,
            graph_actor_device_id,
            aggregate,
            aggregate_cross_binding,
            execution_package,
            head: _,
            request,
            reservation,
            package,
            authority_digest,
        } = authority;
        let terminal_at = request.expires_at;
        let request_id = request.recovery_request_id;
        let persistence_witness = RecoveryPersistenceWitness {
            sql_authority,
            transaction_id,
            trusted_instant,
            graph_actor_did,
            graph_actor_device_id,
            aggregate_cross_binding,
            request,
            reservation,
            package,
            mode: RecoveryPersistenceMode::Expired { terminal_at },
        };
        Ok(RecoverySchedulerExpiryPlannerParts {
            aggregate,
            execution_package,
            observed_at: trusted_instant,
            terminal_at,
            request_id,
            locked_read_set_digest: authority_digest,
            persistence_witness,
        })
    }
}

pub(crate) async fn prepare_recovery_request_authority(
    transaction: &mut Transaction<'_, Postgres>,
    prelude: PreparedBusinessPrelude,
    mutation: &VerifiedSignedMutation,
) -> Result<RecoveryRequestAuthority, RecoveryRepositoryError> {
    let request = match mutation.projection() {
        VerifiedMutationProjection::LeafRecoveryRequest(value) => value,
        _ => return Err(RecoveryRepositoryError::UnsupportedAuthority),
    };
    let request_id = Uuid::from_bytes(*request.recovery_request_id().as_bytes());
    require_idempotency_key(request.body(), request_id)?;
    let prelude = prelude
        .verify_recovery_operation(
            RecoveryOperationEndpoint::RequestLeafRecovery,
            request_id,
            mutation,
        )
        .map_err(|_| RecoveryRepositoryError::NonCanonicalOperation)?;
    let coordinate = signed_coordinate(request.prior())?;
    let scope = prelude.scope_authority();
    let transaction_id = validate_scope_and_mutation(transaction, scope, mutation).await?;
    let trusted_instant = scope.trusted_instant();
    let actor_did = scope.actor_did().to_owned();
    let actor_device_id = scope.actor_device_id();
    let actor_key_id = scope
        .actor_key_id()
        .ok_or(RecoveryRepositoryError::AuthorityBindingMismatch)?
        .to_owned();
    let actor_auth_generation = scope
        .actor_auth_generation()
        .ok_or(RecoveryRepositoryError::AuthorityBindingMismatch)?;
    let verified_mutation = reverify_scope_mutation(scope, mutation)?;
    let aggregate =
        hydrate_locked_conversation_state(transaction, coordinate.conversation_id, trusted_instant)
            .await?;
    let head = lock_head_graph(
        transaction,
        coordinate.conversation_id,
        &actor_did,
        actor_device_id,
    )
    .await?;
    require_coordinate(&head, &coordinate)?;
    let recovery_kind = match request.recovery_kind() {
        "add" if head.actor_leaf_period_id.is_none() => LeafRecoveryKind::Add,
        "replace" => LeafRecoveryKind::Replace {
            replaced_leaf_period_id: head
                .actor_leaf_period_id
                .ok_or(RecoveryRepositoryError::ReadSetMismatch)?,
        },
        _ => return Err(RecoveryRepositoryError::ReadSetMismatch),
    };
    let package: RecoveryPackageRow = sqlx::query_as(LOCK_AVAILABLE_RECOVERY_PACKAGE_SQL)
        .bind(&actor_did)
        .bind(actor_device_id)
        .bind(&actor_key_id)
        .bind(actor_auth_generation)
        .bind(trusted_instant)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or(RecoveryRepositoryError::PackageUnavailable)?;
    validate_package(&package, "available")?;
    let expires_at = std::cmp::min(trusted_instant + Duration::minutes(5), package.not_after);
    if expires_at <= trusted_instant {
        return Err(RecoveryRepositoryError::PackageUnavailable);
    }
    let evidence = recovery_evidence(mutation)?;
    let execution_package = hydrate_locked_available_recovery_package(
        transaction,
        aggregate.head(),
        request_id,
        &actor_did,
        actor_device_id,
        &actor_key_id,
        actor_auth_generation,
        *aggregate.state().coordinate(),
    )
    .await?;
    if execution_package.key_package_ref().as_slice() != package.key_package_ref.as_slice() {
        return Err(RecoveryRepositoryError::ReadSetMismatch);
    }
    let request_row = NewLeafRecoveryRequest {
        recovery_request_id: request_id,
        conversation_id: head.conversation_id,
        generation: head.generation,
        requester_did: actor_did.clone(),
        requester_device_id: actor_device_id,
        requester_key_id: actor_key_id.clone(),
        requester_auth_generation: actor_auth_generation,
        recovery_kind,
        source: LeafRecoverySource::RequestLeafRecovery,
        bound_state_version: head.state_version,
        bound_group_id: head.group_id.to_vec(),
        bound_epoch: head.epoch,
        bound_group_context_hash: head.group_context_hash.to_vec(),
        bound_confirmation_tag: head.confirmation_tag.to_vec(),
        reservation_request_id: request_id,
        signed_request_bytes: evidence.signed_request_bytes.to_vec(),
        signing_transcript_bytes: evidence.signing_transcript_bytes.to_vec(),
        request_digest: evidence.request_digest.to_vec(),
        signature: evidence.signature.to_vec(),
        requested_at: trusted_instant,
        expires_at,
    };
    let reservation = NewReservation {
        recovery_request_id: request_id,
        key_package_ref: package.key_package_ref.clone(),
        conversation_id: head.conversation_id,
        generation: head.generation,
        requester_did: actor_did.clone(),
        requester_device_id: actor_device_id,
        requester_key_id: actor_key_id.clone(),
        requester_auth_generation: actor_auth_generation,
        recipient_did: actor_did.clone(),
        recipient_device_id: actor_device_id,
        bound_state_version: head.state_version,
        bound_group_id: head.group_id.to_vec(),
        bound_epoch: head.epoch,
        bound_group_context_hash: head.group_context_hash.to_vec(),
        bound_confirmation_tag: head.confirmation_tag.to_vec(),
        expires_at,
        created_at: trusted_instant,
    };
    let authority_digest = client_authority_digest(
        &transaction_id,
        trusted_instant,
        &actor_did,
        actor_device_id,
        &actor_key_id,
        actor_auth_generation,
        &head,
        &evidence,
    );
    let aggregate_cross_binding =
        RecoveryAggregateCrossBinding::seal(&transaction_id, trusted_instant, &aggregate, &head)?;
    Ok(RecoveryRequestAuthority {
        context: RecoveryAuthorityContext {
            sql_authority: RecoverySqlAuthoritySeal::mint(),
            prelude,
            transaction_id: transaction_id.into_boxed_str(),
            trusted_instant,
            actor_did: actor_did.into_boxed_str(),
            actor_device_id,
            actor_key_id: actor_key_id.into_boxed_str(),
            actor_auth_generation,
            aggregate,
            aggregate_cross_binding,
            verified_mutation,
            head,
            evidence,
            authority_digest,
            terminal_packages: Vec::new(),
        },
        request: request_row,
        reservation,
        package,
        execution_package,
    })
}

pub(crate) async fn prepare_recovery_cancellation_authority(
    transaction: &mut Transaction<'_, Postgres>,
    prelude: PreparedBusinessPrelude,
    mutation: &VerifiedSignedMutation,
) -> Result<RecoveryCancellationRead, RecoveryRepositoryError> {
    let (request_id, operation_id) = match mutation.projection() {
        VerifiedMutationProjection::LeafRecoveryCancellation(value) => {
            let operation_id = body_uuid(&value.body(), "idempotencyKey")?;
            if !uuid_v4(operation_id) {
                return Err(RecoveryRepositoryError::NonCanonicalOperation);
            }
            (
                Uuid::from_bytes(*value.recovery_request_id().as_bytes()),
                operation_id,
            )
        }
        _ => return Err(RecoveryRepositoryError::UnsupportedAuthority),
    };
    let prelude = prelude
        .verify_recovery_operation(
            RecoveryOperationEndpoint::CancelLeafRecovery,
            operation_id,
            mutation,
        )
        .map_err(|_| RecoveryRepositoryError::NonCanonicalOperation)?;
    let context =
        prepare_client_terminal_context(transaction, prelude, mutation, request_id).await?;
    if !cancellation_actor_matches_requester(
        &context.context.actor_did,
        context.context.actor_device_id,
        &context.context.actor_key_id,
        context.context.actor_auth_generation,
        &context.request.requester_did,
        context.request.requester_device_id,
        &context.request.requester_key_id,
        context.request.requester_auth_generation,
    ) {
        return Err(RecoveryRepositoryError::AuthorityBindingMismatch);
    }
    match context.classification {
        RecoveryTerminalClassification::OpenLive => Ok(RecoveryCancellationRead::Execute(
            context.into_cancellation_authority()?,
        )),
        RecoveryTerminalClassification::OpenDue => Ok(RecoveryCancellationRead::DueForExpiry(
            RecoveryCancellationDueForExpiry {
                authority: context.into_expiry_authority()?,
            },
        )),
        retained => {
            let RecoveryClientTerminalDisposition::Retained(error) =
                classify_client_terminal_disposition(
                    RecoveryClientTerminalAction::Cancel,
                    retained,
                )
            else {
                return Err(RecoveryRepositoryError::InvalidDurableRow);
            };
            Ok(RecoveryCancellationRead::Classified(
                RecoveryCancellationRetained {
                    prelude: context.into_retained_prelude(),
                    error,
                },
            ))
        }
    }
}

pub(crate) async fn prepare_recovery_fulfillment_authority(
    transaction: &mut Transaction<'_, Postgres>,
    prelude: PreparedBusinessPrelude,
    mutation: &VerifiedSignedMutation,
) -> Result<RecoveryFulfillmentRead, RecoveryRepositoryError> {
    let (request_id, transition_id, coordinate) = match mutation.projection() {
        VerifiedMutationProjection::LeafRecoveryFulfillment(value) => (
            Uuid::from_bytes(*value.recovery_request_id().as_bytes()),
            Uuid::from_bytes(*value.transition_id().as_bytes()),
            signed_coordinate(value.prior())?,
        ),
        _ => return Err(RecoveryRepositoryError::UnsupportedAuthority),
    };
    require_idempotency_key_from_mutation(mutation, transition_id)?;
    let prelude = prelude
        .verify_recovery_operation(
            RecoveryOperationEndpoint::SubmitRecoveryFulfillment,
            transition_id,
            mutation,
        )
        .map_err(|_| RecoveryRepositoryError::NonCanonicalOperation)?;
    let context =
        prepare_client_terminal_context(transaction, prelude, mutation, request_id).await?;
    require_request_coordinate(&context.request, &coordinate)?;
    if context.context.actor_did.as_ref() == context.request.requester_did
        && context.context.actor_device_id == context.request.requester_device_id
    {
        return Err(RecoveryRepositoryError::AuthorityBindingMismatch);
    }
    match context.classification {
        RecoveryTerminalClassification::OpenLive => {
            require_coordinate(&context.context.head, &coordinate)?;
            Ok(RecoveryFulfillmentRead::Execute(
                context.into_fulfillment_authority(transition_id)?,
            ))
        }
        RecoveryTerminalClassification::OpenDue => Ok(RecoveryFulfillmentRead::DueForExpiry(
            RecoveryFulfillmentDueForExpiry {
                authority: context.into_expiry_authority()?,
            },
        )),
        RecoveryTerminalClassification::RetainedFulfilled
            if context.fulfilling_transition_id == Some(transition_id) =>
        {
            // Fulfilled by this exact transition. The same-token operation
            // replay must have returned completed response bytes before
            // repository preparation. Reaching the terminal classifier
            // without a completed receipt is an invariant failure.
            Err(RecoveryRepositoryError::InvalidDurableRow)
        }
        retained => {
            let RecoveryClientTerminalDisposition::Retained(error) =
                classify_client_terminal_disposition(
                    RecoveryClientTerminalAction::Fulfill,
                    retained,
                )
            else {
                return Err(RecoveryRepositoryError::InvalidDurableRow);
            };
            Ok(RecoveryFulfillmentRead::Classified(
                RecoveryFulfillmentRetained {
                    prelude: context.into_retained_prelude(),
                    error,
                },
            ))
        }
    }
}

/// Read-only fulfillment terminal-scope discovery, executed before the shared
/// operation prelude. The returned canonical scope contains both the exact
/// admitted acting fulfiller and the original requester identity. The locator
/// read acquires no row lock; every authoritative fact is re-read under the
/// canonical locks during authority preparation.
pub(crate) async fn discover_recovery_fulfillment_terminal_scope(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &VerifiedChatDeviceRequest,
    mutation: &VerifiedSignedMutation,
) -> Result<CanonicalLockScope, RecoveryRepositoryError> {
    let request_id = match mutation.projection() {
        VerifiedMutationProjection::LeafRecoveryFulfillment(value) => {
            Uuid::from_bytes(*value.recovery_request_id().as_bytes())
        }
        _ => return Err(RecoveryRepositoryError::UnsupportedAuthority),
    };
    if !mutation_contains_exact_admission(authority, mutation) {
        return Err(RecoveryRepositoryError::AuthorityBindingMismatch);
    }
    let locator: RecoveryTerminalLocatorRow = sqlx::query_as(RECOVERY_TERMINAL_LOCATOR_SQL)
        .bind(request_id)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or(RecoveryRepositoryError::RecoveryMissing)?;
    if locator.recovery_request_id != request_id {
        return Err(RecoveryRepositoryError::AuthorityBindingMismatch);
    }
    let actor_did = authority.subject().as_str().to_owned();
    let actor_device_id = Uuid::from_bytes(*authority.device_id().as_bytes());
    CanonicalLockScope::new(
        vec![actor_did.clone(), locator.requester_did.clone()],
        vec![
            CanonicalDeviceIdentity::new(actor_did, actor_device_id),
            CanonicalDeviceIdentity::new(locator.requester_did, locator.requester_device_id),
        ],
    )
    .map_err(|_| RecoveryRepositoryError::NonCanonicalOperation)
}

fn mutation_contains_exact_admission(
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

fn reverify_scope_mutation(
    scope: &ScopeBoundBusinessAuthority,
    mutation: &VerifiedSignedMutation,
) -> Result<VerifiedSignedMutation, RecoveryRepositoryError> {
    let raw = mutation
        .accepted_wrapper_bytes()
        .ok_or(RecoveryRepositoryError::AuthorityBindingMismatch)?;
    let signing_public_key = scope
        .actor_signing_public_key()
        .ok_or(RecoveryRepositoryError::AuthorityBindingMismatch)?;
    let verified = decode_and_verify_signed_mutation(raw, signing_public_key)
        .map_err(|_| RecoveryRepositoryError::AuthorityBindingMismatch)?;
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
        return Err(RecoveryRepositoryError::AuthorityBindingMismatch);
    }
    Ok(verified)
}

/// Mint scheduler expiry authority in a fresh transaction.
///
/// The recovery request id is the global advisory identity. The initial
/// locator read acquires no row lock; it only identifies the canonical
/// principal/device/key prefix. Every authoritative fact is re-read under the
/// subsequent locks, and authority exists only at the exact whole-millisecond
/// boundary `transaction_timestamp() == expires_at`.
pub(crate) async fn prepare_recovery_expiry_authority(
    transaction: &mut Transaction<'_, Postgres>,
    request_id: Uuid,
) -> Result<RecoverySchedulerExpiryRead, RecoveryRepositoryError> {
    if !uuid_v4(request_id) {
        return Err(RecoveryRepositoryError::NonCanonicalOperation);
    }
    let operation_key = canonical_operation_lock_key(request_id);
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(operation_key)
        .execute(&mut **transaction)
        .await?;

    let locator: RecoveryTerminalLocatorRow = sqlx::query_as(RECOVERY_TERMINAL_LOCATOR_SQL)
        .bind(request_id)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or(RecoveryRepositoryError::RecoveryMissing)?;
    if locator.recovery_request_id != request_id {
        return Err(RecoveryRepositoryError::AuthorityBindingMismatch);
    }
    let principal: Option<String> = sqlx::query_scalar(LOCK_RECOVERY_EXPIRY_PRINCIPAL_SQL)
        .bind(&locator.requester_did)
        .fetch_optional(&mut **transaction)
        .await?;
    if principal.as_deref() != Some(locator.requester_did.as_str()) {
        return Err(RecoveryRepositoryError::AuthorityBindingMismatch);
    }

    let device: Option<(String, i64, Option<DateTime<Utc>>)> =
        sqlx::query_as(LOCK_RECOVERY_EXPIRY_DEVICE_SQL)
            .bind(&locator.requester_did)
            .bind(locator.requester_device_id)
            .fetch_optional(&mut **transaction)
            .await?;
    let (requester_device_status, requester_device_auth_generation, requester_device_revoked_at) =
        device.ok_or(RecoveryRepositoryError::AuthorityBindingMismatch)?;
    if requester_device_auth_generation != locator.requester_auth_generation
        || !matches!(requester_device_status.as_str(), "active" | "revoked")
        || (requester_device_status == "active") != requester_device_revoked_at.is_none()
    {
        return Err(RecoveryRepositoryError::AuthorityBindingMismatch);
    }

    let key: Option<(Vec<u8>, i64, Option<DateTime<Utc>>)> =
        sqlx::query_as(LOCK_RECOVERY_EXPIRY_KEY_SQL)
            .bind(&locator.requester_did)
            .bind(locator.requester_device_id)
            .bind(&locator.requester_key_id)
            .fetch_optional(&mut **transaction)
            .await?;
    let (signing_public_key, enrollment_auth_generation, key_revoked_at) =
        key.ok_or(RecoveryRepositoryError::AuthorityBindingMismatch)?;
    if enrollment_auth_generation != locator.requester_auth_generation
        || signing_public_key.len() != 32
    {
        return Err(RecoveryRepositoryError::AuthorityBindingMismatch);
    }

    let transaction_id = live_transaction_id(transaction).await?;
    let trusted_instant: DateTime<Utc> =
        sqlx::query_scalar("SELECT date_trunc('milliseconds', transaction_timestamp())")
            .fetch_one(&mut **transaction)
            .await?;
    if !whole_millis(trusted_instant) {
        return Err(RecoveryRepositoryError::TrustedInstantMismatch);
    }
    let aggregate =
        hydrate_locked_conversation_state(transaction, locator.conversation_id, trusted_instant)
            .await?;

    let head = lock_head_graph(
        transaction,
        locator.conversation_id,
        &locator.requester_did,
        locator.requester_device_id,
    )
    .await?;
    let (request_row, reservation_row, package) =
        lock_terminal_rows(transaction, request_id).await?;
    if request_row.conversation_id != locator.conversation_id
        || request_row.requester_did != locator.requester_did
        || request_row.requester_device_id != locator.requester_device_id
        || request_row.requester_key_id != locator.requester_key_id
        || request_row.requester_auth_generation != locator.requester_auth_generation
    {
        return Err(RecoveryRepositoryError::ReadSetMismatch);
    }
    reverify_persisted_request(&request_row, &signing_public_key)?;
    let classification = validate_locked_triple(
        &head,
        &request_row,
        &reservation_row,
        &package,
        trusted_instant,
        &signing_public_key,
    )?;
    validate_requester_liveness_at_rehydration(
        classification,
        request_row.requested_at,
        &requester_device_status,
        requester_device_revoked_at,
        key_revoked_at,
    )?;
    validate_terminal_linkage(transaction, &request_row, &reservation_row).await?;
    match classification {
        RecoveryTerminalClassification::OpenDue => {
            let execution_package =
                hydrate_locked_reserved_recovery_package(transaction, aggregate.head(), request_id)
                    .await?;
            let request = new_request_from_row(&request_row)?;
            let reservation = new_reservation_from_row(&reservation_row)?;
            let authority_digest = expiry_authority_digest(
                &transaction_id,
                trusted_instant,
                &head,
                &request,
                &reservation,
                &package,
            );
            let aggregate_cross_binding = RecoveryAggregateCrossBinding::seal(
                &transaction_id,
                trusted_instant,
                &aggregate,
                &head,
            )?;
            Ok(RecoverySchedulerExpiryRead::Authority(
                RecoverySchedulerExpiryAuthority {
                    sql_authority: RecoverySqlAuthoritySeal::mint(),
                    transaction_id: transaction_id.into_boxed_str(),
                    trusted_instant,
                    graph_actor_did: locator.requester_did.into_boxed_str(),
                    graph_actor_device_id: locator.requester_device_id,
                    aggregate,
                    aggregate_cross_binding,
                    execution_package,
                    head,
                    request,
                    reservation,
                    package,
                    authority_digest,
                },
            ))
        }
        RecoveryTerminalClassification::OpenLive => Err(RecoveryRepositoryError::ExpiryNotDue),
        retained => Ok(RecoverySchedulerExpiryRead::Retained(
            RecoverySchedulerRetainedTerminal {
                _classification: retained,
            },
        )),
    }
}

struct PreparedTerminalContext {
    context: RecoveryAuthorityContext,
    request: NewLeafRecoveryRequest,
    reservation: NewReservation,
    package: RecoveryPackageRow,
    execution_package: Option<LockedRecoveryPackageGuard>,
    classification: RecoveryTerminalClassification,
    fulfilling_transition_id: Option<Uuid>,
}

impl PreparedTerminalContext {
    fn into_cancellation_authority(
        self,
    ) -> Result<RecoveryCancellationAuthority, RecoveryRepositoryError> {
        Ok(RecoveryCancellationAuthority {
            context: self.context,
            request: self.request,
            reservation: self.reservation,
            package: self.package,
            execution_package: self
                .execution_package
                .ok_or(RecoveryRepositoryError::ReadSetMismatch)?,
        })
    }

    fn into_fulfillment_authority(
        self,
        transition_id: Uuid,
    ) -> Result<RecoveryFulfillmentAuthority, RecoveryRepositoryError> {
        Ok(RecoveryFulfillmentAuthority {
            context: self.context,
            request: self.request,
            reservation: self.reservation,
            package: self.package,
            execution_package: self
                .execution_package
                .ok_or(RecoveryRepositoryError::ReadSetMismatch)?,
            transition_id,
        })
    }

    fn into_expiry_authority(
        self,
    ) -> Result<RecoveryClientExpiryAuthority, RecoveryRepositoryError> {
        if self.context.trusted_instant < self.request.expires_at {
            return Err(RecoveryRepositoryError::ExpiryNotDue);
        }
        let authority_digest = expiry_authority_digest(
            &self.context.transaction_id,
            self.context.trusted_instant,
            &self.context.head,
            &self.request,
            &self.reservation,
            &self.package,
        );
        Ok(RecoveryClientExpiryAuthority {
            sql_authority: self.context.sql_authority,
            prelude: self.context.prelude,
            transaction_id: self.context.transaction_id,
            trusted_instant: self.context.trusted_instant,
            graph_actor_did: self.context.actor_did,
            graph_actor_device_id: self.context.actor_device_id,
            aggregate: self.context.aggregate,
            aggregate_cross_binding: self.context.aggregate_cross_binding,
            execution_package: self
                .execution_package
                .ok_or(RecoveryRepositoryError::ReadSetMismatch)?,
            head: self.context.head,
            request: self.request,
            reservation: self.reservation,
            package: self.package,
            authority_digest,
        })
    }

    fn into_retained_prelude(self) -> PreparedBusinessPrelude {
        self.context.prelude
    }
}

async fn prepare_client_terminal_context(
    transaction: &mut Transaction<'_, Postgres>,
    prelude: PreparedBusinessPrelude,
    mutation: &VerifiedSignedMutation,
    request_id: Uuid,
) -> Result<PreparedTerminalContext, RecoveryRepositoryError> {
    let scope = prelude.scope_authority();
    let transaction_id = validate_scope_and_mutation(transaction, scope, mutation).await?;
    let trusted_instant = scope.trusted_instant();
    let actor_did = scope.actor_did().to_owned();
    let actor_device_id = scope.actor_device_id();
    let actor_key_id = scope
        .actor_key_id()
        .ok_or(RecoveryRepositoryError::AuthorityBindingMismatch)?
        .to_owned();
    let actor_auth_generation = scope
        .actor_auth_generation()
        .ok_or(RecoveryRepositoryError::AuthorityBindingMismatch)?;
    let verified_mutation = reverify_scope_mutation(scope, mutation)?;
    let conversation_id: Uuid = sqlx::query_scalar(
        "SELECT conversation_id FROM chat.leaf_recovery_requests WHERE recovery_request_id=$1",
    )
    .bind(request_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(RecoveryRepositoryError::RecoveryMissing)?;
    let aggregate =
        hydrate_locked_conversation_state(transaction, conversation_id, trusted_instant).await?;
    let mut terminal_packages = Vec::new();
    for request in aggregate.state().recovery_requests() {
        if request.status() == super::super::state_machine::RecoveryRequestStatus::Open
            && Uuid::from_bytes(*request.request_id()) != request_id
        {
            terminal_packages.push(
                hydrate_locked_reserved_recovery_package(
                    transaction,
                    aggregate.head(),
                    Uuid::from_bytes(*request.request_id()),
                )
                .await?,
            );
        }
    }
    let head = lock_head_graph(transaction, conversation_id, &actor_did, actor_device_id).await?;
    let (request_row, reservation_row, package) =
        lock_terminal_rows(transaction, request_id).await?;
    let requester_signing_public_key =
        reverify_scoped_request(transaction, scope, &request_row).await?;
    let classification = validate_locked_triple(
        &head,
        &request_row,
        &reservation_row,
        &package,
        trusted_instant,
        &requester_signing_public_key,
    )?;
    validate_scope_contains_requester(scope, &request_row, classification)?;
    validate_terminal_linkage(transaction, &request_row, &reservation_row).await?;
    let execution_package = if matches!(
        classification,
        RecoveryTerminalClassification::OpenLive | RecoveryTerminalClassification::OpenDue
    ) {
        Some(
            hydrate_locked_reserved_recovery_package(transaction, aggregate.head(), request_id)
                .await?,
        )
    } else {
        None
    };
    let evidence = recovery_evidence(mutation)?;
    let authority_digest = client_authority_digest(
        &transaction_id,
        trusted_instant,
        &actor_did,
        actor_device_id,
        &actor_key_id,
        actor_auth_generation,
        &head,
        &evidence,
    );
    let aggregate_cross_binding =
        RecoveryAggregateCrossBinding::seal(&transaction_id, trusted_instant, &aggregate, &head)?;
    Ok(PreparedTerminalContext {
        context: RecoveryAuthorityContext {
            sql_authority: RecoverySqlAuthoritySeal::mint(),
            prelude,
            transaction_id: transaction_id.into_boxed_str(),
            trusted_instant,
            actor_did: actor_did.into_boxed_str(),
            actor_device_id,
            actor_key_id: actor_key_id.into_boxed_str(),
            actor_auth_generation,
            aggregate,
            aggregate_cross_binding,
            verified_mutation,
            head,
            evidence,
            authority_digest,
            terminal_packages,
        },
        request: new_request_from_row(&request_row)?,
        reservation: new_reservation_from_row(&reservation_row)?,
        package,
        execution_package,
        classification,
        fulfilling_transition_id: request_row.fulfilling_transition_id,
    })
}

async fn reverify_scoped_request(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &ScopeBoundBusinessAuthority,
    request: &RecoveryRequestRow,
) -> Result<Vec<u8>, RecoveryRepositoryError> {
    let locked_key = scope
        .keys()
        .iter()
        .find(|row| {
            row.user_did() == request.requester_did
                && row.device_id() == request.requester_device_id
                && row.key_id() == request.requester_key_id
                && row.enrollment_auth_generation() == request.requester_auth_generation
                && row
                    .revoked_at()
                    .is_none_or(|revoked_at| revoked_at >= request.requested_at)
        })
        .ok_or(RecoveryRepositoryError::AuthorityBindingMismatch)?;
    // The prelude already owns this row lock. This projection acquires no new
    // lock; it retrieves the bytes needed to reverify the retained signed row.
    let signing_public_key: Vec<u8> = sqlx::query_scalar(
        "SELECT signing_public_key FROM chat.device_keys \
         WHERE user_did=$1 AND device_id=$2 AND key_id=$3",
    )
    .bind(&request.requester_did)
    .bind(request.requester_device_id)
    .bind(&request.requester_key_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(RecoveryRepositoryError::AuthorityBindingMismatch)?;
    if <[u8; 32]>::from(Sha256::digest(&signing_public_key))
        != locked_key.signing_public_key_sha256()
    {
        return Err(RecoveryRepositoryError::AuthorityBindingMismatch);
    }
    reverify_persisted_request(request, &signing_public_key)?;
    Ok(signing_public_key)
}

#[cfg(test)]
mod aggregate_cross_binding_tests {
    use super::*;

    fn fixture() -> RecoveryAggregateCrossBinding {
        let mut binding = RecoveryAggregateCrossBinding {
            transaction_id: "101".into(),
            trusted_instant: DateTime::<Utc>::from_timestamp_millis(1_900_000_000_000).unwrap(),
            conversation_id: Uuid::parse_str("11111111-2222-4333-8444-555555555555").unwrap(),
            generation: 7,
            state_version: 11,
            group_id: [0x10; 32],
            epoch: 13,
            group_context_hash: [0x20; 32],
            confirmation_tag: [0x30; 32],
            aggregate_head_digest: [0x40; 32],
            aggregate_graph_digest: [0x50; 32],
            aggregate_snapshot_digest: Some([0x60; 32]),
            recovery_head_digest: [0x70; 32],
            recovery_graph_digest: [0x80; 32],
            seal_digest: [0; 32],
        };
        binding.seal_digest = binding.rederive_digest();
        binding
    }

    #[test]
    fn cross_binding_digest_changes_for_every_sealed_authority_dimension() {
        let baseline = fixture();
        let expected = baseline.rederive_digest();
        assert_eq!(baseline.seal_digest, expected);

        macro_rules! rejects_drift {
            ($field:ident, $value:expr) => {{
                let mut drifted = fixture();
                drifted.$field = $value;
                assert_ne!(
                    drifted.rederive_digest(),
                    expected,
                    "digest did not bind {}",
                    stringify!($field)
                );
            }};
        }

        rejects_drift!(transaction_id, "102".into());
        rejects_drift!(
            trusted_instant,
            DateTime::<Utc>::from_timestamp_millis(1_900_000_000_001).unwrap()
        );
        rejects_drift!(conversation_id, Uuid::new_v4());
        rejects_drift!(generation, 8);
        rejects_drift!(state_version, 12);
        rejects_drift!(group_id, [0x11; 32]);
        rejects_drift!(epoch, 14);
        rejects_drift!(group_context_hash, [0x21; 32]);
        rejects_drift!(confirmation_tag, [0x31; 32]);
        rejects_drift!(aggregate_head_digest, [0x41; 32]);
        rejects_drift!(aggregate_graph_digest, [0x51; 32]);
        rejects_drift!(aggregate_snapshot_digest, None);
        rejects_drift!(recovery_head_digest, [0x71; 32]);
        rejects_drift!(recovery_graph_digest, [0x81; 32]);
    }

    #[test]
    fn live_aggregate_graph_and_public_snapshot_drift_reject_independently() {
        let binding = fixture();
        assert!(binding.validates_live_aggregate_digests(
            &[0x40; 32],
            &[0x50; 32],
            Some(&[0x60; 32]),
        ));
        assert!(!binding.validates_live_aggregate_digests(
            &[0x40; 32],
            &[0x51; 32],
            Some(&[0x60; 32]),
        ));
        assert!(!binding.validates_live_aggregate_digests(
            &[0x40; 32],
            &[0x50; 32],
            Some(&[0x61; 32]),
        ));
        assert!(!binding.validates_live_aggregate_digests(&[0x40; 32], &[0x50; 32], None,));
    }
}

async fn lock_head_graph(
    transaction: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    actor_did: &str,
    actor_device_id: Uuid,
) -> Result<LockedRecoveryHeadGraph, RecoveryRepositoryError> {
    let conversation: RecoveryConversationRow = sqlx::query_as(LOCK_RECOVERY_CONVERSATION_SQL)
        .bind(conversation_id)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or(RecoveryRepositoryError::ConversationMissing)?;
    let generation: RecoveryGenerationRow = sqlx::query_as(LOCK_RECOVERY_GENERATION_SQL)
        .bind(conversation_id)
        .bind(conversation.current_generation)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or(RecoveryRepositoryError::ConversationDrift)?;
    let state: RecoveryGenerationStateRow = sqlx::query_as(LOCK_RECOVERY_GENERATION_STATE_SQL)
        .bind(conversation_id)
        .bind(conversation.current_generation)
        .bind(conversation.current_state_version)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or(RecoveryRepositoryError::ConversationDrift)?;
    let actor_leaf_period_id: Option<Uuid> = sqlx::query_scalar(LOCK_RECOVERY_MEMBER_DEVICE_SQL)
        .bind(conversation_id)
        .bind(conversation.current_generation)
        .bind(actor_did)
        .bind(actor_device_id)
        .fetch_optional(&mut **transaction)
        .await?;
    let graph_identity_valid = generation.conversation_id == conversation_id
        && generation.generation == conversation.current_generation
        && state.conversation_id == conversation_id
        && state.generation == conversation.current_generation
        && state.state_version == conversation.current_state_version;
    let row = RecoveryHeadGraphRow {
        conversation_id: conversation.conversation_id,
        kind: conversation.kind,
        lifecycle: conversation.lifecycle,
        current_generation: conversation.current_generation,
        current_state_version: conversation.current_state_version,
        next_entry_seq: conversation.next_entry_seq,
        direct_did_low: conversation.direct_did_low,
        direct_did_high: conversation.direct_did_high,
        created_at: conversation.created_at,
        close_transition_id: conversation.close_transition_id,
        close_generation: conversation.close_generation,
        close_state_version: conversation.close_state_version,
        close_seq: conversation.close_seq,
        closed_at: conversation.closed_at,
        group_id: generation.group_id,
        generation_lifecycle: generation.generation_lifecycle,
        genesis_group_info_sha256: generation.genesis_group_info_sha256,
        generation_state_version: generation.generation_state_version,
        activated_seq: generation.activated_seq,
        activated_at: generation.activated_at,
        superseded_seq: generation.superseded_seq,
        superseded_at: generation.superseded_at,
        epoch: state.epoch,
        group_context_hash: state.group_context_hash,
        confirmation_tag: state.confirmation_tag,
        state_lifecycle: state.state_lifecycle,
        state_kind: state.state_kind,
        producing_transition_id: state.producing_transition_id,
        snapshot_sha256: state.snapshot_sha256,
        tree_summary_sha256: state.tree_summary_sha256,
        leaf_count: state.leaf_count,
        state_created_at: state.state_created_at,
        actor_leaf_period_id,
    };
    if row.conversation_id != conversation_id
        || !graph_identity_valid
        || row.lifecycle != "active"
        || row.generation_lifecycle != "active"
        || row.state_lifecycle != "active"
        || row.current_state_version != row.generation_state_version
        || !safe_nonnegative(row.current_generation)
        || !safe_nonnegative(row.current_state_version)
        || !safe_nonnegative(row.epoch)
        || row.next_entry_seq <= 0
        || !whole_millis(row.created_at)
        || !whole_millis(row.activated_at)
        || !whole_millis(row.state_created_at)
    {
        return Err(RecoveryRepositoryError::ConversationDrift);
    }
    let group_id = bytes32(&row.group_id)?;
    let group_context_hash = bytes32(&row.group_context_hash)?;
    let confirmation_tag = bytes32(&row.confirmation_tag)?;
    let head_digest = digest_head(&row);
    let graph_digest = digest_graph(&row);
    Ok(LockedRecoveryHeadGraph {
        conversation_id,
        generation: row.current_generation,
        state_version: row.current_state_version,
        group_id,
        epoch: row.epoch,
        group_context_hash,
        confirmation_tag,
        actor_leaf_period_id: row.actor_leaf_period_id,
        head_digest,
        graph_digest,
    })
}

async fn lock_terminal_rows(
    transaction: &mut Transaction<'_, Postgres>,
    request_id: Uuid,
) -> Result<
    (
        RecoveryRequestRow,
        RecoveryReservationRow,
        RecoveryPackageRow,
    ),
    RecoveryRepositoryError,
> {
    let request: RecoveryRequestRow = sqlx::query_as(LOCK_RECOVERY_REQUEST_SQL)
        .bind(request_id)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or(RecoveryRepositoryError::RecoveryMissing)?;
    let reservation: RecoveryReservationRow = sqlx::query_as(LOCK_RECOVERY_RESERVATION_SQL)
        .bind(request_id)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or(RecoveryRepositoryError::ReadSetMismatch)?;
    let package: RecoveryPackageRow = sqlx::query_as(LOCK_RECOVERY_PACKAGE_SQL)
        .bind(&reservation.key_package_ref)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or(RecoveryRepositoryError::ReadSetMismatch)?;
    Ok((request, reservation, package))
}

fn validate_locked_triple(
    head: &LockedRecoveryHeadGraph,
    request: &RecoveryRequestRow,
    reservation: &RecoveryReservationRow,
    package: &RecoveryPackageRow,
    trusted_instant: DateTime<Utc>,
    requester_signing_public_key: &[u8],
) -> Result<RecoveryTerminalClassification, RecoveryRepositoryError> {
    let status = parse_request_status(&request.status)?;
    let classification = classify_locked_recovery(status, trusted_instant, request.expires_at);
    if request.recovery_request_id != reservation.recovery_request_id
        || request.reservation_request_id != request.recovery_request_id
        || reservation.conversation_id != request.conversation_id
        || reservation.generation != request.generation
        || request.requester_did != reservation.requester_did
        || request.requester_device_id != reservation.requester_device_id
        || request.requester_key_id != reservation.requester_key_id
        || request.requester_auth_generation != reservation.requester_auth_generation
        || reservation.recipient_did != request.requester_did
        || reservation.recipient_device_id != request.requester_device_id
        || reservation.purpose != "leafRecovery"
        || reservation.bound_state_version != request.bound_state_version
        || reservation.bound_group_id != request.bound_group_id
        || reservation.bound_epoch != request.bound_epoch
        || reservation.bound_group_context_hash != request.bound_group_context_hash
        || reservation.bound_confirmation_tag != request.bound_confirmation_tag
        || request.expires_at != reservation.expires_at
        || reservation.key_package_ref != package.key_package_ref
        || package.owner_did != request.requester_did
        || package.owner_device_id != request.requester_device_id
        || package.owner_key_id != request.requester_key_id
        || package.owner_auth_generation != request.requester_auth_generation
        || reservation.expires_at > package.not_after
        || !whole_millis(request.requested_at)
        || !whole_millis(request.expires_at)
        || !whole_millis(reservation.created_at)
        || !whole_millis(package.not_before)
        || !whole_millis(package.not_after)
        || !whole_millis(package.created_at)
        || !safe_nonnegative(request.generation)
        || !safe_nonnegative(request.bound_state_version)
        || !safe_nonnegative(request.bound_epoch)
        || request.bound_group_id.len() != 32
        || request.bound_group_context_hash.len() != 32
        || request.bound_confirmation_tag.len() != 32
        || request.request_digest.as_slice()
            != Sha256::digest(&request.signing_transcript_bytes).as_slice()
        || request.signature.len() != 64
        || request.signed_request_bytes.is_empty()
        || request.signing_transcript_bytes.is_empty()
    {
        return Err(RecoveryRepositoryError::ReadSetMismatch);
    }
    if matches!(
        classification,
        RecoveryTerminalClassification::OpenLive | RecoveryTerminalClassification::OpenDue
    ) && (request.conversation_id != head.conversation_id
        || request.generation != head.generation
        || request.bound_state_version != head.state_version
        || request.bound_group_id != head.group_id
        || request.bound_epoch != head.epoch
        || request.bound_group_context_hash != head.group_context_hash
        || request.bound_confirmation_tag != head.confirmation_tag)
    {
        return Err(RecoveryRepositoryError::ConversationDrift);
    }
    validate_terminal_shapes(classification, request, reservation, package)?;
    if classification == RecoveryTerminalClassification::RetainedCancelled {
        reverify_retained_cancellation(request, requester_signing_public_key)?;
    }
    Ok(classification)
}

fn reverify_persisted_request(
    row: &RecoveryRequestRow,
    signing_public_key: &[u8],
) -> Result<(), RecoveryRepositoryError> {
    let verified = decode_and_verify_signed_mutation(&row.signed_request_bytes, signing_public_key)
        .map_err(|_| RecoveryRepositoryError::InvalidDurableRow)?;
    let (request_id, coordinate, expected_idempotency_key) = match (
        persisted_recovery_origin(&row.source)?,
        verified.projection(),
    ) {
        (
            RecoveryPersistedOrigin::LeafRecoveryRequest,
            VerifiedMutationProjection::LeafRecoveryRequest(value),
        ) => {
            if value.recovery_kind() != row.recovery_kind {
                return Err(RecoveryRepositoryError::InvalidDurableRow);
            }
            (
                Uuid::from_bytes(*value.recovery_request_id().as_bytes()),
                signed_coordinate(value.prior())?,
                Uuid::from_bytes(*value.recovery_request_id().as_bytes()),
            )
        }
        (
            RecoveryPersistedOrigin::ParticipantAcceptance,
            VerifiedMutationProjection::ParticipantAcceptance(value),
        ) => {
            if row.recovery_kind != "add" {
                return Err(RecoveryRepositoryError::InvalidDurableRow);
            }
            (
                Uuid::from_bytes(*value.recovery_request_id().as_bytes()),
                signed_coordinate(value.next())?,
                Uuid::from_bytes(*value.transition_id().as_bytes()),
            )
        }
        _ => return Err(RecoveryRepositoryError::InvalidDurableRow),
    };
    require_persisted_idempotency_key(&verified, expected_idempotency_key)?;
    if request_id != row.recovery_request_id
        || verified.actor_did().as_str() != row.requester_did
        || Uuid::from_bytes(*verified.actor_device_id().as_bytes()) != row.requester_device_id
        || verified.key_id().as_str() != row.requester_key_id
        || i64::try_from(verified.auth_generation()).ok() != Some(row.requester_auth_generation)
        || verified.transcript_bytes() != row.signing_transcript_bytes
        || verified.request_digest().as_slice() != row.request_digest
        || verified.signature().as_slice() != row.signature
        || verified.accepted_wrapper_bytes() != Some(row.signed_request_bytes.as_slice())
        || coordinate.conversation_id != row.conversation_id
        || coordinate.generation != row.generation
        || coordinate.state_version != row.bound_state_version
        || coordinate.group_id.as_slice() != row.bound_group_id
        || coordinate.epoch != row.bound_epoch
        || coordinate.group_context_hash.as_slice() != row.bound_group_context_hash
        || coordinate.confirmation_tag.as_slice() != row.bound_confirmation_tag
    {
        return Err(RecoveryRepositoryError::InvalidDurableRow);
    };
    Ok(())
}

fn require_persisted_idempotency_key(
    mutation: &VerifiedSignedMutation,
    expected: Uuid,
) -> Result<(), RecoveryRepositoryError> {
    let body = match mutation.projection() {
        VerifiedMutationProjection::LeafRecoveryRequest(value) => value.body(),
        VerifiedMutationProjection::ParticipantAcceptance(value) => value.body(),
        VerifiedMutationProjection::LeafRecoveryCancellation(value) => value.body(),
        _ => return Err(RecoveryRepositoryError::InvalidDurableRow),
    };
    if body_uuid(&body, "idempotencyKey").map_err(|_| RecoveryRepositoryError::InvalidDurableRow)?
        == expected
    {
        Ok(())
    } else {
        Err(RecoveryRepositoryError::InvalidDurableRow)
    }
}

pub(crate) fn expired_recovery_package_shape_valid(
    status: &str,
    not_after: DateTime<Utc>,
    terminal_at: Option<DateTime<Utc>>,
    terminal_transition_id: Option<Uuid>,
    terminal_revocation_id: Option<Uuid>,
) -> bool {
    status == "expired"
        && terminal_transition_id.is_none()
        && terminal_revocation_id.is_none()
        && terminal_at == Some(not_after)
}

fn validate_terminal_shapes(
    classification: RecoveryTerminalClassification,
    request: &RecoveryRequestRow,
    reservation: &RecoveryReservationRow,
    package: &RecoveryPackageRow,
) -> Result<(), RecoveryRepositoryError> {
    let request_terminal_null = request.fulfilling_transition_id.is_none()
        && request.terminal_transition_id.is_none()
        && request.terminal_revocation_id.is_none()
        && request.terminal_signed_request_bytes.is_none()
        && request.terminal_signing_transcript_bytes.is_none()
        && request.terminal_request_digest.is_none()
        && request.terminal_signature.is_none()
        && request.terminal_at.is_none();
    let reservation_terminal_null = reservation.consumed_transition_id.is_none()
        && reservation.terminal_transition_id.is_none()
        && reservation.terminal_revocation_id.is_none()
        && reservation.terminal_request_digest.is_none()
        && reservation.terminal_at.is_none();
    let package_terminal_null = package.terminal_transition_id.is_none()
        && package.terminal_revocation_id.is_none()
        && package.terminal_at.is_none();
    let valid = match classification {
        RecoveryTerminalClassification::OpenLive | RecoveryTerminalClassification::OpenDue => {
            request.status == "open"
                && reservation.status == "active"
                && package.status == "reserved"
                && request_terminal_null
                && reservation_terminal_null
                && package_terminal_null
        }
        RecoveryTerminalClassification::RetainedFulfilled => {
            reservation.status == "consumed"
                && package.status == "consumed"
                && request.fulfilling_transition_id.is_some()
                && request.fulfilling_transition_id == reservation.consumed_transition_id
                && request.fulfilling_transition_id == package.terminal_transition_id
                && request.terminal_transition_id.is_none()
                && request.terminal_revocation_id.is_none()
                && request.terminal_signed_request_bytes.is_none()
                && request.terminal_signing_transcript_bytes.is_none()
                && request.terminal_request_digest.is_none()
                && request.terminal_signature.is_none()
                && reservation.terminal_transition_id.is_none()
                && reservation.terminal_revocation_id.is_none()
                && reservation.terminal_request_digest.is_none()
                && package.terminal_revocation_id.is_none()
                && request.terminal_at == reservation.terminal_at
                && request.terminal_at == package.terminal_at
                && request
                    .terminal_at
                    .is_some_and(|at| at >= request.requested_at && at < request.expires_at)
        }
        RecoveryTerminalClassification::RetainedCancelled => {
            reservation.status == "released"
                && package.status == "available"
                && request.fulfilling_transition_id.is_none()
                && request.terminal_transition_id.is_none()
                && request.terminal_revocation_id.is_none()
                && request.terminal_signed_request_bytes.is_some()
                && request.terminal_signing_transcript_bytes.is_some()
                && request.terminal_request_digest.is_some()
                && request.terminal_signature.is_some()
                && reservation.consumed_transition_id.is_none()
                && reservation.terminal_transition_id.is_none()
                && reservation.terminal_revocation_id.is_none()
                && request.terminal_request_digest == reservation.terminal_request_digest
                && request.terminal_at == reservation.terminal_at
                && request
                    .terminal_at
                    .is_some_and(|at| at >= request.requested_at && at < request.expires_at)
                && package_terminal_null
        }
        RecoveryTerminalClassification::RetainedExpired => {
            reservation.status == "expired"
                && request.fulfilling_transition_id.is_none()
                && request.terminal_transition_id.is_none()
                && request.terminal_revocation_id.is_none()
                && request.terminal_signed_request_bytes.is_none()
                && request.terminal_signing_transcript_bytes.is_none()
                && request.terminal_request_digest.is_none()
                && request.terminal_signature.is_none()
                && reservation.consumed_transition_id.is_none()
                && reservation.terminal_transition_id.is_none()
                && reservation.terminal_revocation_id.is_none()
                && reservation.terminal_request_digest.is_none()
                && request.terminal_at == Some(request.expires_at)
                && reservation.terminal_at == Some(request.expires_at)
                && ((package.status == "available" && package_terminal_null)
                    || (package.not_after == request.expires_at
                        && expired_recovery_package_shape_valid(
                            &package.status,
                            package.not_after,
                            package.terminal_at,
                            package.terminal_transition_id,
                            package.terminal_revocation_id,
                        )))
        }
        RecoveryTerminalClassification::RetainedSuperseded => {
            validate_superseded_terminal_shapes(request, reservation, package)
        }
    };
    if valid {
        Ok(())
    } else {
        Err(RecoveryRepositoryError::InvalidDurableRow)
    }
}

fn validate_superseded_terminal_shapes(
    request: &RecoveryRequestRow,
    reservation: &RecoveryReservationRow,
    package: &RecoveryPackageRow,
) -> bool {
    let transition = request.terminal_transition_id;
    let revocation = request.terminal_revocation_id;
    let common = request.fulfilling_transition_id.is_none()
        && request.terminal_signed_request_bytes.is_none()
        && request.terminal_signing_transcript_bytes.is_none()
        && request.terminal_request_digest.is_none()
        && request.terminal_signature.is_none()
        && request
            .terminal_at
            .is_some_and(|at| at >= request.requested_at && at < request.expires_at)
        && transition.is_some() != revocation.is_some()
        && reservation.status == "released"
        && reservation.consumed_transition_id.is_none()
        && reservation.terminal_transition_id == transition
        && reservation.terminal_revocation_id == revocation
        && reservation.terminal_request_digest.is_none()
        && reservation.terminal_at == request.terminal_at;
    common
        && match (transition, revocation) {
            (Some(_), None) => {
                package.status == "available"
                    && package.terminal_transition_id.is_none()
                    && package.terminal_revocation_id.is_none()
                    && package.terminal_at.is_none()
            }
            (None, Some(revocation_id)) => {
                package.status == "revoked"
                    && package.terminal_transition_id.is_none()
                    && package.terminal_revocation_id == Some(revocation_id)
                    && package.terminal_at == request.terminal_at
            }
            _ => false,
        }
}

fn reverify_retained_cancellation(
    request: &RecoveryRequestRow,
    signing_public_key: &[u8],
) -> Result<(), RecoveryRepositoryError> {
    let signed = request
        .terminal_signed_request_bytes
        .as_deref()
        .ok_or(RecoveryRepositoryError::InvalidDurableRow)?;
    let transcript = request
        .terminal_signing_transcript_bytes
        .as_deref()
        .ok_or(RecoveryRepositoryError::InvalidDurableRow)?;
    let digest = request
        .terminal_request_digest
        .as_deref()
        .ok_or(RecoveryRepositoryError::InvalidDurableRow)?;
    let signature = request
        .terminal_signature
        .as_deref()
        .ok_or(RecoveryRepositoryError::InvalidDurableRow)?;
    let verified = decode_and_verify_signed_mutation(signed, signing_public_key)
        .map_err(|_| RecoveryRepositoryError::InvalidDurableRow)?;
    let cancellation = match verified.projection() {
        VerifiedMutationProjection::LeafRecoveryCancellation(value) => value,
        _ => return Err(RecoveryRepositoryError::InvalidDurableRow),
    };
    // A cancellation operation id is independently chosen, but remains a
    // canonical UUIDv4 and is cryptographically covered by the wrapper.
    body_uuid(&cancellation.body(), "idempotencyKey")
        .map_err(|_| RecoveryRepositoryError::InvalidDurableRow)?;
    if Uuid::from_bytes(*cancellation.recovery_request_id().as_bytes())
        != request.recovery_request_id
        || verified.actor_did().as_str() != request.requester_did
        || Uuid::from_bytes(*verified.actor_device_id().as_bytes()) != request.requester_device_id
        || verified.key_id().as_str() != request.requester_key_id
        || i64::try_from(verified.auth_generation()).ok() != Some(request.requester_auth_generation)
        || verified.transcript_bytes() != transcript
        || verified.request_digest().as_slice() != digest
        || verified.signature().as_slice() != signature
        || verified.accepted_wrapper_bytes() != Some(signed)
        || digest != Sha256::digest(transcript).as_slice()
    {
        return Err(RecoveryRepositoryError::InvalidDurableRow);
    }
    Ok(())
}

async fn validate_terminal_linkage(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RecoveryRequestRow,
    reservation: &RecoveryReservationRow,
) -> Result<(), RecoveryRepositoryError> {
    let linked = match request.status.as_str() {
        "fulfilled" => {
            let Some(transition_id) = request.fulfilling_transition_id else {
                return Err(RecoveryRepositoryError::InvalidDurableRow);
            };
            sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM chat.transitions \
                 WHERE transition_id=$1 AND kind='leafRecovery' AND conversation_id=$2 \
                   AND prior_generation=$3 AND prior_state_version=$4 AND accepted_at=$5)",
            )
            .bind(transition_id)
            .bind(request.conversation_id)
            .bind(request.generation)
            .bind(request.bound_state_version)
            .bind(request.terminal_at)
            .fetch_one(&mut **transaction)
            .await?
        }
        "superseded" => match (
            request.terminal_transition_id,
            request.terminal_revocation_id,
        ) {
            (Some(transition_id), None) => {
                sqlx::query_scalar::<_, bool>(
                    "SELECT EXISTS(SELECT 1 FROM chat.transitions \
                 WHERE transition_id=$1 AND conversation_id=$2 \
                   AND prior_generation=$3 AND prior_state_version=$4 AND accepted_at=$5)",
                )
                .bind(transition_id)
                .bind(request.conversation_id)
                .bind(request.generation)
                .bind(request.bound_state_version)
                .bind(request.terminal_at)
                .fetch_one(&mut **transaction)
                .await?
            }
            (None, Some(revocation_id)) => {
                sqlx::query_scalar::<_, bool>(
                    "SELECT EXISTS(SELECT 1 FROM chat.device_revocations \
                 WHERE revocation_id=$1 AND target_did=$2 AND target_device_id=$3 \
                   AND target_auth_generation=$4 AND accepted_at=$5)",
                )
                .bind(revocation_id)
                .bind(&request.requester_did)
                .bind(request.requester_device_id)
                .bind(request.requester_auth_generation)
                .bind(request.terminal_at)
                .fetch_one(&mut **transaction)
                .await?
            }
            _ => false,
        },
        _ => return Ok(()),
    };
    if !linked
        || reservation.terminal_transition_id != request.terminal_transition_id
        || reservation.terminal_revocation_id != request.terminal_revocation_id
    {
        return Err(RecoveryRepositoryError::InvalidDurableRow);
    }
    Ok(())
}

fn validate_package(
    package: &RecoveryPackageRow,
    expected_status: &str,
) -> Result<(), RecoveryRepositoryError> {
    if package.status != expected_status
        || package.terminal_transition_id.is_some()
        || package.terminal_revocation_id.is_some()
        || package.terminal_at.is_some()
        || package.key_package_ref.len() != 32
        || package.wrapper_bytes.is_empty()
        || package.wrapper_sha256.as_slice() != Sha256::digest(&package.wrapper_bytes).as_slice()
        || package.init_key.is_empty()
        || !whole_millis(package.not_before)
        || !whole_millis(package.not_after)
        || !whole_millis(package.created_at)
        || package.not_before >= package.created_at
        || package.created_at >= package.not_after
    {
        return Err(RecoveryRepositoryError::InvalidDurableRow);
    }
    Ok(())
}

async fn validate_scope_and_mutation(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &ScopeBoundBusinessAuthority,
    mutation: &VerifiedSignedMutation,
) -> Result<String, RecoveryRepositoryError> {
    let transaction_id = live_transaction_id(transaction).await?;
    let auth_generation = i64::try_from(mutation.auth_generation())
        .map_err(|_| RecoveryRepositoryError::AuthorityBindingMismatch)?;
    if transaction_id != scope.transaction_id()
        || scope.actor_class() != RepositoryAuthorityClass::ExistingDevice
        || scope.actor_did() != mutation.actor_did().as_str()
        || scope.actor_device_id() != Uuid::from_bytes(*mutation.actor_device_id().as_bytes())
        || scope.actor_key_id() != Some(mutation.key_id().as_str())
        || scope.actor_auth_generation() != Some(auth_generation)
        || scope.actor_signing_public_key().is_none()
        || mutation.accepted_wrapper_bytes().is_none()
        || !whole_millis(scope.trusted_instant())
    {
        return Err(RecoveryRepositoryError::AuthorityBindingMismatch);
    }
    Ok(transaction_id)
}

async fn validate_client_context(
    transaction: &mut Transaction<'_, Postgres>,
    context: &RecoveryAuthorityContext,
) -> Result<(), RecoveryRepositoryError> {
    let transaction_id = live_transaction_id(transaction).await?;
    if transaction_id != &*context.transaction_id
        || !context
            .aggregate_cross_binding
            .validates(&context.aggregate, &context.head)
        || context.authority_digest
            != client_authority_digest(
                &context.transaction_id,
                context.trusted_instant,
                &context.actor_did,
                context.actor_device_id,
                &context.actor_key_id,
                context.actor_auth_generation,
                &context.head,
                &context.evidence,
            )
    {
        return Err(RecoveryRepositoryError::ForeignTransaction);
    }
    Ok(())
}

fn validate_scope_contains_requester(
    scope: &ScopeBoundBusinessAuthority,
    request: &RecoveryRequestRow,
    classification: RecoveryTerminalClassification,
) -> Result<(), RecoveryRepositoryError> {
    let principal = scope
        .principals()
        .binary_search_by(|did| did.as_bytes().cmp(request.requester_did.as_bytes()))
        .is_ok();
    let device = scope.devices().iter().any(|row| {
        row.user_did() == request.requester_did
            && row.device_id() == request.requester_device_id
            && row.auth_generation() == request.requester_auth_generation
            && requester_row_liveness_matches(
                classification,
                request.requested_at,
                row.status(),
                row.revoked_at(),
            )
    });
    let key = scope.keys().iter().any(|row| {
        row.user_did() == request.requester_did
            && row.device_id() == request.requester_device_id
            && row.key_id() == request.requester_key_id
            && row.enrollment_auth_generation() == request.requester_auth_generation
            && requester_key_liveness_matches(
                classification,
                request.requested_at,
                row.revoked_at(),
            )
    });
    if principal && device && key {
        Ok(())
    } else {
        Err(RecoveryRepositoryError::AuthorityBindingMismatch)
    }
}

fn validate_requester_liveness_at_rehydration(
    classification: RecoveryTerminalClassification,
    requested_at: DateTime<Utc>,
    device_status: &str,
    device_revoked_at: Option<DateTime<Utc>>,
    key_revoked_at: Option<DateTime<Utc>>,
) -> Result<(), RecoveryRepositoryError> {
    if requester_row_liveness_matches(
        classification,
        requested_at,
        device_status,
        device_revoked_at,
    ) && requester_key_liveness_matches(classification, requested_at, key_revoked_at)
    {
        Ok(())
    } else {
        Err(RecoveryRepositoryError::AuthorityBindingMismatch)
    }
}

pub(crate) fn requester_row_liveness_matches(
    classification: RecoveryTerminalClassification,
    requested_at: DateTime<Utc>,
    status: &str,
    revoked_at: Option<DateTime<Utc>>,
) -> bool {
    match classification {
        RecoveryTerminalClassification::OpenLive | RecoveryTerminalClassification::OpenDue => {
            status == "active" && revoked_at.is_none()
        }
        _ => {
            (status == "active" && revoked_at.is_none())
                || (status == "revoked"
                    && revoked_at.is_some_and(|revoked_at| revoked_at >= requested_at))
        }
    }
}

pub(crate) fn requester_key_liveness_matches(
    classification: RecoveryTerminalClassification,
    requested_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
) -> bool {
    match classification {
        RecoveryTerminalClassification::OpenLive | RecoveryTerminalClassification::OpenDue => {
            revoked_at.is_none()
        }
        _ => revoked_at.is_none_or(|revoked_at| revoked_at >= requested_at),
    }
}

fn new_request_from_row(
    row: &RecoveryRequestRow,
) -> Result<NewLeafRecoveryRequest, RecoveryRepositoryError> {
    let recovery_kind = match (row.recovery_kind.as_str(), row.replaced_leaf_period_id) {
        ("add", None) => LeafRecoveryKind::Add,
        ("replace", Some(replaced_leaf_period_id)) => LeafRecoveryKind::Replace {
            replaced_leaf_period_id,
        },
        _ => return Err(RecoveryRepositoryError::InvalidDurableRow),
    };
    let source = match row.source.as_str() {
        "requestLeafRecovery" => LeafRecoverySource::RequestLeafRecovery,
        "acceptConversation" => LeafRecoverySource::AcceptConversation,
        _ => return Err(RecoveryRepositoryError::InvalidDurableRow),
    };
    Ok(NewLeafRecoveryRequest {
        recovery_request_id: row.recovery_request_id,
        conversation_id: row.conversation_id,
        generation: row.generation,
        requester_did: row.requester_did.clone(),
        requester_device_id: row.requester_device_id,
        requester_key_id: row.requester_key_id.clone(),
        requester_auth_generation: row.requester_auth_generation,
        recovery_kind,
        source,
        bound_state_version: row.bound_state_version,
        bound_group_id: row.bound_group_id.clone(),
        bound_epoch: row.bound_epoch,
        bound_group_context_hash: row.bound_group_context_hash.clone(),
        bound_confirmation_tag: row.bound_confirmation_tag.clone(),
        reservation_request_id: row.reservation_request_id,
        signed_request_bytes: row.signed_request_bytes.clone(),
        signing_transcript_bytes: row.signing_transcript_bytes.clone(),
        request_digest: row.request_digest.clone(),
        signature: row.signature.clone(),
        requested_at: row.requested_at,
        expires_at: row.expires_at,
    })
}

fn new_reservation_from_row(
    row: &RecoveryReservationRow,
) -> Result<NewReservation, RecoveryRepositoryError> {
    if row.purpose != "leafRecovery" {
        return Err(RecoveryRepositoryError::InvalidDurableRow);
    }
    Ok(NewReservation {
        recovery_request_id: row.recovery_request_id,
        key_package_ref: row.key_package_ref.clone(),
        conversation_id: row.conversation_id,
        generation: row.generation,
        requester_did: row.requester_did.clone(),
        requester_device_id: row.requester_device_id,
        requester_key_id: row.requester_key_id.clone(),
        requester_auth_generation: row.requester_auth_generation,
        recipient_did: row.recipient_did.clone(),
        recipient_device_id: row.recipient_device_id,
        bound_state_version: row.bound_state_version,
        bound_group_id: row.bound_group_id.clone(),
        bound_epoch: row.bound_epoch,
        bound_group_context_hash: row.bound_group_context_hash.clone(),
        bound_confirmation_tag: row.bound_confirmation_tag.clone(),
        expires_at: row.expires_at,
        created_at: row.created_at,
    })
}

struct SignedCoordinate {
    conversation_id: Uuid,
    generation: i64,
    state_version: i64,
    group_id: [u8; 32],
    epoch: i64,
    group_context_hash: [u8; 32],
    confirmation_tag: [u8; 32],
}

fn signed_coordinate(
    value: super::super::transcript::ClosedObjectRef<'_>,
) -> Result<SignedCoordinate, RecoveryRepositoryError> {
    let conversation_id = body_uuid(&value, "conversationId")?;
    let integer = |name| match value.get(name) {
        Some(CanonicalValueRef::Integer(value))
            if value <= MAX_PROTOCOL_INTEGER && value <= i64::MAX as u64 =>
        {
            Ok(value as i64)
        }
        _ => Err(RecoveryRepositoryError::NonCanonicalOperation),
    };
    let bytes = |name| match value.get(name) {
        Some(CanonicalValueRef::Bytes(value)) => bytes32(value),
        _ => Err(RecoveryRepositoryError::NonCanonicalOperation),
    };
    if !matches!(
        value.get("lifecycle"),
        Some(CanonicalValueRef::Text("active"))
    ) {
        return Err(RecoveryRepositoryError::NonCanonicalOperation);
    }
    Ok(SignedCoordinate {
        conversation_id,
        generation: integer("generation")?,
        state_version: integer("stateVersion")?,
        group_id: bytes("groupId")?,
        epoch: integer("epoch")?,
        group_context_hash: bytes("groupContextHash")?,
        confirmation_tag: bytes("confirmationTag")?,
    })
}

fn require_coordinate(
    head: &LockedRecoveryHeadGraph,
    coordinate: &SignedCoordinate,
) -> Result<(), RecoveryRepositoryError> {
    if head.conversation_id == coordinate.conversation_id
        && head.generation == coordinate.generation
        && head.state_version == coordinate.state_version
        && head.group_id == coordinate.group_id
        && head.epoch == coordinate.epoch
        && head.group_context_hash == coordinate.group_context_hash
        && head.confirmation_tag == coordinate.confirmation_tag
    {
        Ok(())
    } else {
        Err(RecoveryRepositoryError::ConversationDrift)
    }
}

fn require_request_coordinate(
    request: &NewLeafRecoveryRequest,
    coordinate: &SignedCoordinate,
) -> Result<(), RecoveryRepositoryError> {
    if request.conversation_id == coordinate.conversation_id
        && request.generation == coordinate.generation
        && request.bound_state_version == coordinate.state_version
        && request.bound_group_id == coordinate.group_id
        && request.bound_epoch == coordinate.epoch
        && request.bound_group_context_hash == coordinate.group_context_hash
        && request.bound_confirmation_tag == coordinate.confirmation_tag
    {
        Ok(())
    } else {
        Err(RecoveryRepositoryError::ConversationDrift)
    }
}

fn require_idempotency_key(
    body: super::super::transcript::ClosedObjectRef<'_>,
    expected: Uuid,
) -> Result<(), RecoveryRepositoryError> {
    if body_uuid(&body, "idempotencyKey")? == expected {
        Ok(())
    } else {
        Err(RecoveryRepositoryError::NonCanonicalOperation)
    }
}

fn require_idempotency_key_from_mutation(
    mutation: &VerifiedSignedMutation,
    expected: Uuid,
) -> Result<(), RecoveryRepositoryError> {
    let body = match mutation.projection() {
        VerifiedMutationProjection::LeafRecoveryFulfillment(value) => value.body(),
        _ => return Err(RecoveryRepositoryError::UnsupportedAuthority),
    };
    require_idempotency_key(body, expected)
}

fn body_uuid(
    body: &super::super::transcript::ClosedObjectRef<'_>,
    name: &str,
) -> Result<Uuid, RecoveryRepositoryError> {
    match body.get(name) {
        Some(CanonicalValueRef::Uuid(value)) => {
            let uuid = Uuid::from_bytes(*value.as_bytes());
            if uuid_v4(uuid) {
                Ok(uuid)
            } else {
                Err(RecoveryRepositoryError::NonCanonicalOperation)
            }
        }
        _ => Err(RecoveryRepositoryError::NonCanonicalOperation),
    }
}

fn recovery_evidence(
    mutation: &VerifiedSignedMutation,
) -> Result<RecoveryEvidence, RecoveryRepositoryError> {
    let signed_request_bytes = mutation
        .accepted_wrapper_bytes()
        .ok_or(RecoveryRepositoryError::NonCanonicalOperation)?;
    if signed_request_bytes.is_empty()
        || mutation.transcript_bytes().is_empty()
        || mutation.request_digest().as_slice()
            != Sha256::digest(mutation.transcript_bytes()).as_slice()
    {
        return Err(RecoveryRepositoryError::NonCanonicalOperation);
    }
    Ok(RecoveryEvidence {
        signed_request_bytes: signed_request_bytes.to_vec().into_boxed_slice(),
        signing_transcript_bytes: mutation.transcript_bytes().to_vec().into_boxed_slice(),
        request_digest: *mutation.request_digest(),
        signature: *mutation.signature(),
    })
}

fn parse_request_status(value: &str) -> Result<RecoveryRowStatus, RecoveryRepositoryError> {
    match value {
        "open" => Ok(RecoveryRowStatus::Open),
        "fulfilled" => Ok(RecoveryRowStatus::Fulfilled),
        "cancelled" => Ok(RecoveryRowStatus::Cancelled),
        "expired" => Ok(RecoveryRowStatus::Expired),
        "superseded" => Ok(RecoveryRowStatus::Superseded),
        _ => Err(RecoveryRepositoryError::InvalidDurableRow),
    }
}

async fn live_transaction_id(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<String, RecoveryRepositoryError> {
    Ok(sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await?)
}

fn digest_head(row: &RecoveryHeadGraphRow) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(RECOVERY_HEAD_DOMAIN);
    digest.update(row.conversation_id.as_bytes());
    digest_len(&mut digest, row.kind.as_bytes());
    digest_len(&mut digest, row.lifecycle.as_bytes());
    digest.update(row.current_generation.to_be_bytes());
    digest.update(row.current_state_version.to_be_bytes());
    digest.update(row.next_entry_seq.to_be_bytes());
    digest_optional_text(&mut digest, row.direct_did_low.as_deref());
    digest_optional_text(&mut digest, row.direct_did_high.as_deref());
    digest.update(row.created_at.timestamp_millis().to_be_bytes());
    digest_optional_uuid(&mut digest, row.close_transition_id);
    digest_optional_i64(&mut digest, row.close_generation);
    digest_optional_i64(&mut digest, row.close_state_version);
    digest_optional_i64(&mut digest, row.close_seq);
    digest_optional_time(&mut digest, row.closed_at);
    digest.finalize().into()
}

fn digest_graph(row: &RecoveryHeadGraphRow) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(RECOVERY_GRAPH_DOMAIN);
    digest.update(row.conversation_id.as_bytes());
    digest.update(row.current_generation.to_be_bytes());
    digest_len(&mut digest, &row.group_id);
    digest_len(&mut digest, row.generation_lifecycle.as_bytes());
    digest_len(&mut digest, &row.genesis_group_info_sha256);
    digest.update(row.generation_state_version.to_be_bytes());
    digest.update(row.activated_seq.to_be_bytes());
    digest.update(row.activated_at.timestamp_millis().to_be_bytes());
    digest_optional_i64(&mut digest, row.superseded_seq);
    digest_optional_time(&mut digest, row.superseded_at);
    digest.update(row.epoch.to_be_bytes());
    digest_len(&mut digest, &row.group_context_hash);
    digest_len(&mut digest, &row.confirmation_tag);
    digest_len(&mut digest, row.state_lifecycle.as_bytes());
    digest_len(&mut digest, row.state_kind.as_bytes());
    digest.update(row.producing_transition_id.as_bytes());
    digest_len(&mut digest, &row.snapshot_sha256);
    digest_len(&mut digest, &row.tree_summary_sha256);
    digest.update(row.leaf_count.to_be_bytes());
    digest.update(row.state_created_at.timestamp_millis().to_be_bytes());
    digest_optional_uuid(&mut digest, row.actor_leaf_period_id);
    digest.finalize().into()
}

#[allow(clippy::too_many_arguments)]
fn client_authority_digest(
    transaction_id: &str,
    trusted_instant: DateTime<Utc>,
    actor_did: &str,
    actor_device_id: Uuid,
    actor_key_id: &str,
    actor_auth_generation: i64,
    head: &LockedRecoveryHeadGraph,
    evidence: &RecoveryEvidence,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(RECOVERY_AUTHORITY_DOMAIN);
    digest_len(&mut digest, transaction_id.as_bytes());
    digest.update(trusted_instant.timestamp_millis().to_be_bytes());
    digest_len(&mut digest, actor_did.as_bytes());
    digest.update(actor_device_id.as_bytes());
    digest_len(&mut digest, actor_key_id.as_bytes());
    digest.update(actor_auth_generation.to_be_bytes());
    digest.update(head.head_digest);
    digest.update(head.graph_digest);
    digest_len(&mut digest, &evidence.signed_request_bytes);
    digest_len(&mut digest, &evidence.signing_transcript_bytes);
    digest.update(evidence.request_digest);
    digest.update(evidence.signature);
    digest.finalize().into()
}

fn expiry_authority_digest(
    transaction_id: &str,
    trusted_instant: DateTime<Utc>,
    head: &LockedRecoveryHeadGraph,
    request: &NewLeafRecoveryRequest,
    reservation: &NewReservation,
    package: &RecoveryPackageRow,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-RECOVERY-EXPIRY-AUTHORITY\0");
    digest_len(&mut digest, transaction_id.as_bytes());
    digest.update(trusted_instant.timestamp_millis().to_be_bytes());
    digest.update(head.head_digest);
    digest.update(head.graph_digest);
    digest.update(request.recovery_request_id.as_bytes());
    digest.update(request.conversation_id.as_bytes());
    digest.update(request.expires_at.timestamp_millis().to_be_bytes());
    digest_len(&mut digest, &request.request_digest);
    digest.update(reservation.recovery_request_id.as_bytes());
    digest_len(&mut digest, &reservation.key_package_ref);
    digest_len(&mut digest, &package.key_package_ref);
    digest_len(&mut digest, &package.wrapper_sha256);
    digest.finalize().into()
}

fn bytes32(value: &[u8]) -> Result<[u8; 32], RecoveryRepositoryError> {
    value
        .try_into()
        .map_err(|_| RecoveryRepositoryError::InvalidDurableRow)
}

fn whole_millis(value: DateTime<Utc>) -> bool {
    value.timestamp_millis() >= 0 && value.timestamp_subsec_nanos() % 1_000_000 == 0
}

fn safe_nonnegative(value: i64) -> bool {
    value >= 0 && value as u64 <= MAX_PROTOCOL_INTEGER
}

fn uuid_v4(value: Uuid) -> bool {
    value.get_version_num() == 4 && value.get_variant() == uuid::Variant::RFC4122
}

fn digest_len(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

fn digest_optional_text(digest: &mut Sha256, value: Option<&str>) {
    match value {
        None => digest.update([0]),
        Some(value) => {
            digest.update([1]);
            digest_len(digest, value.as_bytes());
        }
    }
}

fn digest_optional_uuid(digest: &mut Sha256, value: Option<Uuid>) {
    match value {
        None => digest.update([0]),
        Some(value) => {
            digest.update([1]);
            digest.update(value.as_bytes());
        }
    }
}

fn digest_optional_i64(digest: &mut Sha256, value: Option<i64>) {
    match value {
        None => digest.update([0]),
        Some(value) => {
            digest.update([1]);
            digest.update(value.to_be_bytes());
        }
    }
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
