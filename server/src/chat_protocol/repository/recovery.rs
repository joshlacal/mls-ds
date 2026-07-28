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

use super::super::{
    dpop::VerifiedChatDeviceRequest,
    snapshot::MAX_PROTOCOL_INTEGER,
    transcript::{
        decode_and_verify_signed_mutation, CanonicalValueRef, VerifiedMutationProjection,
        VerifiedSignedMutation,
    },
};
use super::{
    auth::RepositoryAuthorityClass,
    prelude::{
        canonical_operation_lock_key, CanonicalDeviceIdentity, CanonicalLockScope,
        PreparedBusinessPrelude, RecoveryOperationEndpoint, ScopeBoundBusinessAuthority,
    },
    transition::{
        self, LeafRecoveryKind, LeafRecoverySource, NewLeafRecoveryRequest, NewReservation,
        RecoveryKeyPackageRowCas, RecoveryTerminalTripleCas, RecoveryTerminalTripleTermination,
    },
};

const RECOVERY_AUTHORITY_DOMAIN: &[u8] = b"CATBIRD-CHAT-RECOVERY-REPOSITORY-AUTHORITY\0";
const RECOVERY_HEAD_DOMAIN: &[u8] = b"CATBIRD-CHAT-RECOVERY-HEAD\0";
const RECOVERY_GRAPH_DOMAIN: &[u8] = b"CATBIRD-CHAT-RECOVERY-GRAPH\0";

/// Linear capability proving that Recovery repository code completed its
/// ordered locked read-set before constructing a Recovery SQL binding.
///
/// The field and mint are private to this module. `transition` may name and
/// require the type, but no other crate module can manufacture a value.
#[derive(Debug)]
pub(crate) struct RecoverySqlAuthoritySeal {
    _private: (),
}

impl RecoverySqlAuthoritySeal {
    fn mint() -> Self {
        Self { _private: () }
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
}

pub(crate) const CANONICAL_RECOVERY_LOCK_ORDER: [RecoveryLockStage; 9] = [
    RecoveryLockStage::GlobalOperation,
    RecoveryLockStage::Principals,
    RecoveryLockStage::Devices,
    RecoveryLockStage::ActorKey,
    RecoveryLockStage::ConversationHead,
    RecoveryLockStage::ConversationGraph,
    RecoveryLockStage::RecoveryRequest,
    RecoveryLockStage::Reservation,
    RecoveryLockStage::KeyPackage,
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
}

impl From<sqlx::Error> for RecoveryRepositoryError {
    fn from(value: sqlx::Error) -> Self {
        Self::Database(value)
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

#[derive(FromRow)]
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
    head: LockedRecoveryHeadGraph,
    evidence: RecoveryEvidence,
    authority_digest: [u8; 32],
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
}

#[must_use]
pub(crate) struct RecoveryCancellationAuthority {
    context: RecoveryAuthorityContext,
    request: NewLeafRecoveryRequest,
    reservation: NewReservation,
    package: RecoveryPackageRow,
}

#[must_use]
pub(crate) struct RecoveryFulfillmentAuthority {
    context: RecoveryAuthorityContext,
    request: NewLeafRecoveryRequest,
    reservation: NewReservation,
    package: RecoveryPackageRow,
    transition_id: Uuid,
}

#[must_use]
pub(crate) struct RecoveryExpiryAuthority {
    sql_authority: RecoverySqlAuthoritySeal,
    prelude: Option<PreparedBusinessPrelude>,
    transaction_id: Box<str>,
    trusted_instant: DateTime<Utc>,
    head: LockedRecoveryHeadGraph,
    request: NewLeafRecoveryRequest,
    reservation: NewReservation,
    package: RecoveryPackageRow,
    authority_digest: [u8; 32],
}

#[must_use]
pub(crate) struct RecoveryRetainedTerminal {
    classification: RecoveryTerminalClassification,
    prelude: Option<PreparedBusinessPrelude>,
}

pub(crate) enum RecoveryTerminalRead<T> {
    Authority(T),
    DueForExpiry(RecoveryExpiryAuthority),
    Retained(RecoveryRetainedTerminal),
}

impl RecoveryRetainedTerminal {
    pub(crate) fn classification(&self) -> RecoveryTerminalClassification {
        self.classification
    }

    pub(crate) fn into_prelude(self) -> Option<PreparedBusinessPrelude> {
        self.prelude
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
}

/// Opaque cancellation plan input.
#[must_use]
pub(crate) struct RecoveryCancellationPlanInput {
    context: RecoveryAuthorityContext,
    request: NewLeafRecoveryRequest,
    reservation: NewReservation,
    package: RecoveryPackageRow,
}

/// Opaque fulfillment plan input.
#[must_use]
pub(crate) struct RecoveryFulfillmentPlanInput {
    context: RecoveryAuthorityContext,
    request: NewLeafRecoveryRequest,
    reservation: NewReservation,
    package: RecoveryPackageRow,
    transition_id: Uuid,
}

/// The only values a Recovery state-machine bridge may hand to the SQL
/// executor.  Construction consumes the linear plan input, so callers cannot
/// retain a second copy of the authority or substitute an unsealed row.
#[must_use]
pub(crate) struct RecoveryExecutorCapsule {
    operation: RecoveryExecutorOperation,
    transaction_id: Box<str>,
    prelude: PreparedBusinessPrelude,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryExecutorOperation {
    Request,
    Cancellation,
    Fulfillment { transition_id: Uuid },
}

impl RecoveryExecutorCapsule {
    pub(crate) fn operation(&self) -> RecoveryExecutorOperation {
        self.operation
    }

    pub(crate) fn transaction_id(&self) -> &str {
        &self.transaction_id
    }

    pub(crate) fn into_prelude(self) -> PreparedBusinessPrelude {
        self.prelude
    }
}

/// Scheduler expiry is deliberately a separate capsule: it carries no client
/// prelude, operation claim, or idempotency completion capability.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct RecoverySchedulerExpiryCapsule {
    transaction_id: Box<str>,
    request_id: Uuid,
}

impl RecoverySchedulerExpiryCapsule {
    pub(crate) fn transaction_id(&self) -> &str {
        &self.transaction_id
    }

    pub(crate) fn request_id(&self) -> Uuid {
        self.request_id
    }
}

impl<T> RecoveryTerminalRead<T> {
    pub(crate) fn map_authority<U>(self, adapt: impl FnOnce(T) -> U) -> RecoveryTerminalRead<U> {
        match self {
            RecoveryTerminalRead::Authority(authority) => {
                RecoveryTerminalRead::Authority(adapt(authority))
            }
            RecoveryTerminalRead::DueForExpiry(authority) => {
                RecoveryTerminalRead::DueForExpiry(authority)
            }
            RecoveryTerminalRead::Retained(terminal) => RecoveryTerminalRead::Retained(terminal),
        }
    }
}

impl RecoveryTerminalRead<RecoveryRequestAuthority> {
    pub(crate) fn map_authority_into_plan_input(
        self,
    ) -> RecoveryTerminalRead<RecoveryRequestPlanInput> {
        self.map_authority(RecoveryRequestAuthority::into_plan_input)
    }
}

impl RecoveryRequestAuthority {
    pub(crate) fn into_plan_input(self) -> RecoveryRequestPlanInput {
        RecoveryRequestPlanInput {
            context: self.context,
            request: self.request,
            reservation: self.reservation,
            package: self.package,
        }
    }
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

    pub(crate) fn into_prelude(self) -> PreparedBusinessPrelude {
        self.context.prelude
    }

    pub(crate) fn into_executor_capsule(self) -> RecoveryExecutorCapsule {
        RecoveryExecutorCapsule {
            operation: RecoveryExecutorOperation::Request,
            transaction_id: self.context.transaction_id,
            prelude: self.context.prelude,
        }
    }
}

impl RecoveryCancellationAuthority {
    pub(crate) fn into_plan_input(self) -> RecoveryCancellationPlanInput {
        RecoveryCancellationPlanInput {
            context: self.context,
            request: self.request,
            reservation: self.reservation,
            package: self.package,
        }
    }

    pub(crate) fn into_prelude(self) -> PreparedBusinessPrelude {
        self.context.prelude
    }
}

impl RecoveryFulfillmentAuthority {
    pub(crate) fn into_plan_input(self) -> RecoveryFulfillmentPlanInput {
        RecoveryFulfillmentPlanInput {
            context: self.context,
            request: self.request,
            reservation: self.reservation,
            package: self.package,
            transition_id: self.transition_id,
        }
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

    pub(crate) fn into_prelude(self) -> PreparedBusinessPrelude {
        self.context.prelude
    }

    pub(crate) fn into_executor_capsule(self) -> RecoveryExecutorCapsule {
        RecoveryExecutorCapsule {
            operation: RecoveryExecutorOperation::Cancellation,
            transaction_id: self.context.transaction_id,
            prelude: self.context.prelude,
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

    pub(crate) fn into_prelude(self) -> PreparedBusinessPrelude {
        self.context.prelude
    }

    pub(crate) fn into_executor_capsule(self) -> RecoveryExecutorCapsule {
        RecoveryExecutorCapsule {
            operation: RecoveryExecutorOperation::Fulfillment {
                transition_id: self.transition_id,
            },
            transaction_id: self.context.transaction_id,
            prelude: self.context.prelude,
        }
    }
}

impl RecoveryExpiryAuthority {
    pub(crate) fn into_scheduler_capsule(self) -> RecoverySchedulerExpiryCapsule {
        RecoverySchedulerExpiryCapsule {
            transaction_id: self.transaction_id,
            request_id: self.request.recovery_request_id,
        }
    }

    pub(crate) fn terminal_cas(&self) -> RecoveryTerminalTripleCas<'_> {
        RecoveryTerminalTripleCas::new(
            &self.sql_authority,
            &self.transaction_id,
            &self.request,
            &self.reservation,
            package_cas(&self.sql_authority, &self.package),
            RecoveryTerminalTripleTermination::Expired {
                authority: &self.sql_authority,
                terminal_at: self.request.expires_at,
            },
        )
    }

    pub(crate) async fn terminalize(
        self,
        transaction: &mut Transaction<'_, Postgres>,
    ) -> Result<Option<PreparedBusinessPrelude>, RecoveryRepositoryError> {
        let actual = live_transaction_id(transaction).await?;
        if actual != &*self.transaction_id
            || self.trusted_instant < self.request.expires_at
            || self.authority_digest
                != expiry_authority_digest(
                    &self.transaction_id,
                    self.trusted_instant,
                    &self.head,
                    &self.request,
                    &self.reservation,
                    &self.package,
                )
        {
            return Err(RecoveryRepositoryError::ForeignTransaction);
        }
        let binding = self.terminal_cas();
        transition::terminalize_recovery_triple(transaction, &binding).await?;
        Ok(self.prelude)
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
            head,
            evidence,
            authority_digest,
        },
        request: request_row,
        reservation,
        package,
    })
}

pub(crate) async fn prepare_recovery_cancellation_authority(
    transaction: &mut Transaction<'_, Postgres>,
    prelude: PreparedBusinessPrelude,
    mutation: &VerifiedSignedMutation,
) -> Result<RecoveryTerminalRead<RecoveryCancellationAuthority>, RecoveryRepositoryError> {
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
        RecoveryTerminalClassification::OpenLive => Ok(RecoveryTerminalRead::Authority(
            RecoveryCancellationAuthority {
                context: context.context,
                request: context.request,
                reservation: context.reservation,
                package: context.package,
            },
        )),
        RecoveryTerminalClassification::OpenDue => Ok(RecoveryTerminalRead::DueForExpiry(
            context.into_expiry_authority()?,
        )),
        retained => Ok(RecoveryTerminalRead::Retained(
            context.into_retained_terminal(retained),
        )),
    }
}

pub(crate) async fn prepare_recovery_fulfillment_authority(
    transaction: &mut Transaction<'_, Postgres>,
    prelude: PreparedBusinessPrelude,
    mutation: &VerifiedSignedMutation,
) -> Result<RecoveryTerminalRead<RecoveryFulfillmentAuthority>, RecoveryRepositoryError> {
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
            Ok(RecoveryTerminalRead::Authority(
                RecoveryFulfillmentAuthority {
                    context: context.context,
                    request: context.request,
                    reservation: context.reservation,
                    package: context.package,
                    transition_id,
                },
            ))
        }
        RecoveryTerminalClassification::OpenDue => Ok(RecoveryTerminalRead::DueForExpiry(
            context.into_expiry_authority()?,
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
        retained => Ok(RecoveryTerminalRead::Retained(
            context.into_retained_terminal(retained),
        )),
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
) -> Result<RecoveryTerminalRead<RecoveryExpiryAuthority>, RecoveryRepositoryError> {
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
            Ok(RecoveryTerminalRead::Authority(RecoveryExpiryAuthority {
                sql_authority: RecoverySqlAuthoritySeal::mint(),
                prelude: None,
                transaction_id: transaction_id.into_boxed_str(),
                trusted_instant,
                head,
                request,
                reservation,
                package,
                authority_digest,
            }))
        }
        RecoveryTerminalClassification::OpenLive => Err(RecoveryRepositoryError::ExpiryNotDue),
        retained => Ok(RecoveryTerminalRead::Retained(RecoveryRetainedTerminal {
            classification: retained,
            prelude: None,
        })),
    }
}

struct PreparedTerminalContext {
    context: RecoveryAuthorityContext,
    request: NewLeafRecoveryRequest,
    reservation: NewReservation,
    package: RecoveryPackageRow,
    classification: RecoveryTerminalClassification,
    fulfilling_transition_id: Option<Uuid>,
}

impl PreparedTerminalContext {
    fn into_expiry_authority(self) -> Result<RecoveryExpiryAuthority, RecoveryRepositoryError> {
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
        Ok(RecoveryExpiryAuthority {
            sql_authority: self.context.sql_authority,
            prelude: Some(self.context.prelude),
            transaction_id: self.context.transaction_id,
            trusted_instant: self.context.trusted_instant,
            head: self.context.head,
            request: self.request,
            reservation: self.reservation,
            package: self.package,
            authority_digest,
        })
    }

    fn into_retained_terminal(
        self,
        classification: RecoveryTerminalClassification,
    ) -> RecoveryRetainedTerminal {
        RecoveryRetainedTerminal {
            classification,
            prelude: Some(self.context.prelude),
        }
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
    let conversation_id: Uuid = sqlx::query_scalar(
        "SELECT conversation_id FROM chat.leaf_recovery_requests WHERE recovery_request_id=$1",
    )
    .bind(request_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(RecoveryRepositoryError::RecoveryMissing)?;
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
            head,
            evidence,
            authority_digest,
        },
        request: new_request_from_row(&request_row)?,
        reservation: new_reservation_from_row(&reservation_row)?,
        package,
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
                    || (package.status == "expired"
                        && package.not_after == request.expires_at
                        && package.terminal_at == Some(package.not_after)))
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

fn package_cas<'a>(
    authority: &'a RecoverySqlAuthoritySeal,
    package: &'a RecoveryPackageRow,
) -> RecoveryKeyPackageRowCas<'a> {
    RecoveryKeyPackageRowCas::new(
        authority,
        &package.key_package_ref,
        &package.wrapper_bytes,
        &package.wrapper_sha256,
        &package.init_key,
        &package.owner_did,
        package.owner_device_id,
        &package.owner_key_id,
        package.owner_auth_generation,
        package.not_before,
        package.not_after,
        package.created_at,
    )
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
