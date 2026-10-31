#![allow(unused_imports)]
use chrono::{DateTime, Utc};
use sha2::Digest;
use uuid::Uuid;

use sqlx::Acquire;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use super::super::public_state::encode_public_tree_summary;
use super::super::repository::delivery::{
    self as delivery, AppendEntry, ApplicationIntervalClose, DeliveryRepositoryError,
    EntryEntitlementKind, EntryRecipient, EventEntitlementKind, EventKind, EventRecipient,
    IntervalCloseKind, IntervalOpeningKind, NewApplicationInterval, NewEvent,
    NewScheduleTerminalProof, NewWelcomeBundle, NewWelcomeDelivery, OutboxWorkKind,
    WelcomeClientAuthorization, WelcomeDisposition, WelcomeRejectionReason,
};
use super::super::repository::transition::{
    self as transition, cas_registration_revoke, insert_device_revocation, ActiveLeafPeriodBinding,
    ConversationHeadClose, ConversationHeadKind, GenerationStateKind, GenerationStateLifecycle,
    GenerationSupersede, LeafClose, LeafOrigin, LeafRecoveryKind as RepoLeafRecoveryKind,
    LeafRecoverySource, LeafRecoveryTermination, LeaveRequestTermination, MetadataAvatarBinding,
    NewDeviceRevocation, NewGeneration, NewGenerationState, NewLeafPeriod, NewLeafRecoveryRequest,
    NewLeaveRequest, NewMetadataSnapshot, NewParticipantPeriod, NewReservation, NewTransition,
    PackageStatus as RepoPackageStatus, PackageSuccessor, ParticipantAcceptance,
    ParticipantAcceptanceCas, ParticipantInvitation, ParticipantRole as RepoParticipantRole,
    ParticipantRoleCas, ParticipantStatus as RepoParticipantStatus, RegistrationRevoke,
    ReservationTermination, ResetRequestTermination, TransitionActorRole, TransitionCoordinates,
    TransitionKind, TransitionRepositoryError,
};
use super::{
    classify_role_producer, coordinate_is_in_lineage, coordinate_only_successor,
    initial_participant_role, invitation_matches_participant, metadata_author_matches_evidence,
    metadata_coordinate_matches, recovery_package_cas_authority_digest,
    revocation_package_cas_bijection_valid, validate_transition_evidence, CloseKind,
    ConversationKind, DeviceIdentity, DeviceRevocationBatchPersistencePlan, LeafHydrationRow,
    LeafRecord, LeafRecoveryKind, LeaveRequestStatus, ManifestParticipantChange,
    MetadataSnapshotBinding, PackageStatus, ParticipantHydrationRow, ParticipantRecord,
    ParticipantRole, ParticipantStatus, PlanAuthority, PlanKind, PrincipalId,
    PublicGroupSnapshotCoordinate, RecoveryOriginEvidence, RecoveryRequest, RecoveryRequestStatus,
    RecoveryReservation, RecoverySource, ReservationStatus, ResetRequest, ResetRequestStatus,
    ServerTimestamp, SignedMutationKind, StateChange, TransitionBodyBinding, TransitionEffects,
    WelcomeStatus, WelcomeWork, WorkTerminalEvidence,
};
use super::{ConversationPersistencePlan, ConversationStateHydration};
use super::{Engine, URL_SAFE_NO_PAD};

/// Failures the executor surfaces. Repository errors propagate typed; the
/// executor's own contract violations (an effect family the current
/// composition does not persist, a missing context input, a coordinate that
/// overflows `i64`) are distinct so a caller can tell a CAS conflict from a
/// programming/plan-shape error.
#[derive(Debug)]
pub(crate) enum ExecutorError {
    /// A `repository::transition` writer failed (including its typed
    /// `CompareAndSetConflict` — the head/spine CAS lost a race or drifted).
    Transition(TransitionRepositoryError),
    /// A `repository::delivery` writer failed (append/audience/event, or its
    /// typed `CompareAndSetConflict`).
    Delivery(DeliveryRepositoryError),
    /// The plan carried a non-empty effect family this executor does not yet
    /// persist. Emitted as a HARD error rather than silently dropped, so a
    /// future planner change cannot lose writes. Carries the family name.
    UnsupportedEffect(&'static str),
    /// The plan was internally inconsistent for the executor's contract
    /// (e.g. a creation plan without a head CAS binding or without the
    /// required metadata snapshot). Never a silent skip.
    InconsistentPlan(&'static str),
    /// An `ExecutionContext` input required for a row was absent (e.g. no
    /// leaf-auth-generation for an opened leaf).
    MissingContext(&'static str),
    /// A protocol integer or timestamp fell outside the safe `i64` range.
    /// The repository plan omitted the routing authority for a participant.
    MissingParticipantRoutingAuthority,
    ValueOutOfRange,
    /// The prepared execution no longer belongs to the live SQL
    /// transaction, or one of its transaction-bound effects disagrees.
    TransactionBindingMismatch,
    /// SQLx could not read the live database transaction identity.
    TransactionIdentity(sqlx::Error),
    /// SQLx could not create the executor's nested savepoint.
    SavepointBegin(sqlx::Error),
    /// The operation succeeded but SQLx could not release its savepoint.
    SavepointRelease(sqlx::Error),
    /// The operation failed and its savepoint rollback also failed. The
    /// caller must treat the outer transaction as fatal.
    SavepointRollback {
        operation: Box<ExecutorError>,
        rollback: sqlx::Error,
    },
    /// Symbolic revocation event schedule or predecessor-chain drift.
    EventChain(EventChainCursorError),
    /// Execution context hydration encountered a database error.
    HydrationDatabase(sqlx::Error),
}

impl From<TransitionRepositoryError> for ExecutorError {
    fn from(error: TransitionRepositoryError) -> Self {
        Self::Transition(error)
    }
}

impl From<DeliveryRepositoryError> for ExecutorError {
    fn from(error: DeliveryRepositoryError) -> Self {
        Self::Delivery(error)
    }
}

impl ExecutorError {
    /// Infrastructure failures at the savepoint boundary do not promise
    /// that the caller-owned outer transaction remains reusable.
    pub(crate) fn requires_outer_abort(&self) -> bool {
        matches!(
            self,
            Self::TransactionIdentity(_)
                | Self::SavepointBegin(_)
                | Self::SavepointRelease(_)
                | Self::SavepointRollback { .. }
        )
    }
}

/// The actor's identity + auth-sourced columns the plan does NOT carry. The
/// facade sources these from the locked registration / participant / device
/// context; the integration tests supply them explicitly from their fixtures.
#[derive(Clone, Debug)]
pub(crate) struct ExecutionActor {
    pub(crate) user_did: String,
    pub(crate) device_id: Uuid,
    pub(crate) key_id: String,
    pub(crate) auth_generation: i64,
    /// `transitions.actor_role` — the actor's locked participant role.
    pub(crate) role: TransitionActorRole,
    /// `transitions.actor_device_status` — the actor's locked device status.
    pub(crate) device_status: String,
}

/// The exact control-entry row content + the transition's signed material.
/// Every field is the verified signed artifact or its digest; none is
/// re-derived by the executor.
#[derive(Clone, Debug)]
pub(crate) struct ControlEntryContent {
    pub(crate) entry_id: Uuid,
    pub(crate) entry_kind: String,
    pub(crate) accepted_payload_bytes: Vec<u8>,
    pub(crate) accepted_payload_sha256: Vec<u8>,
    pub(crate) signed_request_bytes: Vec<u8>,
    pub(crate) unsigned_projection_bytes: Vec<u8>,
    pub(crate) signing_transcript_bytes: Vec<u8>,
    pub(crate) request_digest: Vec<u8>,
    pub(crate) signature: Vec<u8>,
    pub(crate) server_fields_bytes: Vec<u8>,
    pub(crate) outer_entry_fingerprint: Vec<u8>,
}

/// Closed execution authority consumed by the persistence executor.
///
/// `WelcomeExpiry` and `DeviceRevocation` are the only entryless plan
/// families. Their exact durable operation identifier is retained directly,
/// so neither the hydration facade nor a caller can invent control-entry
/// bytes, digests, fingerprints, or signatures for them.
// Keep the authority shape explicit and allocation-free at this executor
// boundary; the larger control-entry arm is the common case.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
pub(crate) enum ExecutionAuthority {
    ControlEntry(ControlEntryContent),
    Entryless { operation_id: Uuid },
}

impl ExecutionAuthority {
    pub(crate) fn control_entry(&self) -> Option<&ControlEntryContent> {
        match self {
            Self::ControlEntry(entry) => Some(entry),
            Self::Entryless { .. } => None,
        }
    }

    pub(crate) fn operation_id(&self) -> Uuid {
        match self {
            Self::ControlEntry(entry) => entry.entry_id,
            Self::Entryless { operation_id } => *operation_id,
        }
    }
}

pub(crate) use crate::chat_protocol::repository::remote_prefix::HistoricalWriteWitness;

/// Sealed authority for historical remote prefix execution.
///
/// An execution capsule carrying this authority suppresses event emission,
/// event recipients, and outbox/queue work for deterministic replay.
#[derive(Debug)]
pub(crate) struct HistoricalExecutionWriteAuthority {
    pub(in crate::chat_protocol::state_machine::executor) admission_digest: [u8; 32],
    pub(in crate::chat_protocol::state_machine::executor) source_entry_id: Uuid,
    pub(in crate::chat_protocol::state_machine::executor) source_entry_kind: &'static str,
    pub(in crate::chat_protocol::state_machine::executor) source_entry_sha256: [u8; 32],
    pub(in crate::chat_protocol::state_machine::executor) outer_fingerprint: [u8; 32],
}

impl HistoricalExecutionWriteAuthority {
    pub(crate) fn new(
        _witness: HistoricalWriteWitness,
        admission_digest: [u8; 32],
        source_entry_id: Uuid,
        source_entry_kind: &'static str,
        source_entry_sha256: [u8; 32],
        outer_fingerprint: [u8; 32],
    ) -> Self {
        Self {
            admission_digest,
            source_entry_id,
            source_entry_kind,
            source_entry_sha256,
            outer_fingerprint,
        }
    }

    pub(crate) fn source_entry_id(&self) -> Uuid {
        self.source_entry_id
    }

    /// Fail closed unless the executing entry is exactly the admitted source entry.
    pub(crate) fn matches_context(
        &self,
        entry_id: Uuid,
        entry_kind: &str,
        accepted_payload_sha256: &[u8],
        outer_fingerprint: &[u8],
    ) -> bool {
        self.admission_digest != [0; 32]
            && self.source_entry_id == entry_id
            && self.source_entry_kind == entry_kind
            && self.source_entry_sha256.as_slice() == accepted_payload_sha256
            && self.outer_fingerprint.as_slice() == outer_fingerprint
    }
}

/// The public-state serialization artifacts the coordinate spine stores. The
/// facade produces these from the validated merged public state; they are
/// input, never re-serialized by the executor.
#[derive(Clone, Debug)]
pub(crate) struct SpineArtifacts {
    pub(crate) public_snapshot_bytes: Vec<u8>,
    pub(crate) public_snapshot_sha256: Vec<u8>,
    pub(crate) tree_summary_bytes: Vec<u8>,
    pub(crate) tree_summary_sha256: Vec<u8>,
    pub(crate) leaf_count: i64,
    /// Genesis GroupInfo for the activated generation (creation / reset).
    pub(crate) genesis_group_info_bytes: Vec<u8>,
    pub(crate) genesis_group_info_sha256: Vec<u8>,
}

/// Per-opened-leaf columns absent from `LeafHydrationRow`: the leaf's key id
/// and `member_devices.leaf_auth_generation` (sourced from
/// `chat.device_keys.enrollment_auth_generation`).
#[derive(Clone, Debug)]
pub(crate) struct LeafPersistenceColumns {
    pub(crate) device: DeviceIdentity,
    pub(crate) leaf_key_id: String,
    pub(crate) leaf_auth_generation: i64,
}

/// Metadata author columns the `MetadataSnapshotBinding` does not carry as DB
/// strings: `author_role` / `author_device_status` (DDL-forced `admin` /
/// `active`) and the 32-byte Ed25519 signature public key stored verbatim.
#[derive(Clone, Debug)]
pub(crate) struct MetadataAuthorColumns {
    pub(crate) author_role: String,
    pub(crate) author_device_status: String,
    pub(crate) author_public_key: Vec<u8>,
    /// The author's `chat.device_keys.key_id` (base64url) — the DB string the
    /// `MetadataSnapshotBinding` author-proof carries only as a raw 32-byte id.
    /// For a creation/reset self-origin snapshot this equals the actor's key id;
    /// for a commit/leafRecovery re-encryption it is the ORIGINAL author's key
    /// id (carried forward, may differ from the fulfiller).
    pub(crate) author_key_id: String,
    /// Fresh `chat.metadata_snapshots` primary key for this snapshot.
    pub(crate) metadata_snapshot_id: Uuid,
}

/// Repository-sealed persistence authority for a signed metadata avatar (`1A`).
/// A reused avatar carries the immutable historical binding columns read
/// under lock; a fresh Space-backed avatar binds the signed origin/version/owner
/// without storing media bytes in `mls-ds`.
#[derive(Clone, Debug)]
pub(crate) enum MetadataAvatarPersistence {
    Reuse {
        snapshot: MetadataAvatarBinding,
    },
    Fresh {
        snapshot: MetadataAvatarBinding,
    },
}

impl MetadataAvatarPersistence {
    pub(crate) fn snapshot(&self) -> &MetadataAvatarBinding {
        match self {
            Self::Reuse { snapshot } | Self::Fresh { snapshot } => snapshot,
        }
    }
}

/// One event to append with its frozen audience and outbox work.
#[derive(Clone, Debug)]
pub(crate) struct EventFanout {
    pub(crate) event_id: Uuid,
    pub(crate) event_kind: EventKind,
    pub(crate) payload_bytes: Vec<u8>,
    /// `(device, entitlement, predecessor_position)` in canonical order.
    pub(crate) recipients: Vec<(DeviceIdentity, EventEntitlementKind, Option<i64>)>,
    /// `(outbox_id, work_kind)` rows to enqueue for this event.
    pub(crate) outbox: Vec<(Uuid, OutboxWorkKind)>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct EventChainSlot(pub(crate) u32);

#[cfg_attr(test, derive(Clone))]
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct PreparedRevocationRecipient {
    pub(crate) slot: EventChainSlot,
    pub(crate) entitlement: EventEntitlementKind,
}

/// One fully frozen revocation event shape. Its digest binds every value
/// except the predecessor positions, which the transaction-local cursor
/// resolves from the retained prelude tails.
#[cfg_attr(test, derive(Clone))]
#[derive(Debug)]
pub(crate) struct PreparedRevocationEvent {
    pub(crate) event_id: Uuid,
    pub(crate) event_kind: EventKind,
    pub(crate) payload_bytes: Vec<u8>,
    pub(crate) recipients: Vec<PreparedRevocationRecipient>,
    pub(crate) outbox: Vec<(Uuid, OutboxWorkKind)>,
    pub(in crate::chat_protocol::state_machine::executor) schedule_digest: [u8; 32],
}

impl PreparedRevocationEvent {
    pub(crate) fn new(
        event_id: Uuid,
        event_kind: EventKind,
        payload_bytes: Vec<u8>,
        recipients: Vec<PreparedRevocationRecipient>,
        outbox: Vec<(Uuid, OutboxWorkKind)>,
    ) -> Result<Self, EventChainCursorError> {
        if payload_bytes.is_empty() || recipients.is_empty() {
            return Err(EventChainCursorError::EventShapeMismatch);
        }
        if recipients
            .windows(2)
            .any(|pair| pair[0].slot >= pair[1].slot)
        {
            return Err(EventChainCursorError::DuplicateRecipient);
        }
        let schedule_digest = prepared_revocation_event_digest(
            event_id,
            event_kind,
            &payload_bytes,
            &recipients,
            &outbox,
        );
        Ok(Self {
            event_id,
            event_kind,
            payload_bytes,
            recipients,
            outbox,
            schedule_digest,
        })
    }
}

pub(in crate::chat_protocol::state_machine::executor) fn prepared_revocation_event_digest(
    event_id: Uuid,
    event_kind: EventKind,
    payload_bytes: &[u8],
    recipients: &[PreparedRevocationRecipient],
    outbox: &[(Uuid, OutboxWorkKind)],
) -> [u8; 32] {
    let mut digest = sha2::Sha256::new();
    digest.update(b"CATBIRD-CHAT-PREPARED-REVOCATION-EVENT\0");
    digest.update(event_id.as_bytes());
    digest.update([match event_kind {
        EventKind::ConversationChanged => 1,
        EventKind::ConversationClosed => 2,
        EventKind::MessageAvailable => 3,
        EventKind::WelcomeAvailable => 4,
        EventKind::WelcomeDisposition => 5,
        EventKind::ResetRequested => 6,
        EventKind::LeafRecovery => 7,
        EventKind::LeaveRequest => 8,
        EventKind::AccessEnded => 9,
        EventKind::Watermark => 10,
    }]);
    digest.update((payload_bytes.len() as u64).to_be_bytes());
    digest.update(payload_bytes);
    digest.update((recipients.len() as u64).to_be_bytes());
    for recipient in recipients {
        digest.update(recipient.slot.0.to_be_bytes());
        digest.update([match recipient.entitlement {
            EventEntitlementKind::Participant => 1,
            EventEntitlementKind::Leaf => 2,
            EventEntitlementKind::Welcome => 3,
            EventEntitlementKind::Recovery => 4,
            EventEntitlementKind::HistoricalSchedule => 5,
        }]);
    }
    digest.update((outbox.len() as u64).to_be_bytes());
    for (outbox_id, work_kind) in outbox {
        digest.update(outbox_id.as_bytes());
        digest.update([match work_kind {
            OutboxWorkKind::Stream => 1,
            OutboxWorkKind::Notification => 2,
            OutboxWorkKind::Recovery => 3,
        }]);
    }
    digest.finalize().into()
}

#[path = "executor/event_chain.rs"]
mod event_chain;
pub(crate) use self::event_chain::EventChainCursorError;
pub(crate) use self::event_chain::EventChainCursor;
pub(crate) use self::event_chain::WelcomeExpiryContext;
pub(crate) use self::event_chain::WelcomeResponseContext;
pub(crate) use self::event_chain::WelcomeRejectionWork;
pub(crate) use self::event_chain::ExecutionContext;
pub(crate) use self::event_chain::PreparedConversationExecution;
#[cfg(any(
    test,
    all(
        feature = "chat-protocol-production-proof",
        not(feature = "server-bin")
    )
))]
pub(crate) use self::event_chain::{DropSafetyProbe, DropSafetyProbeMode};
pub(crate) use self::event_chain::plan_transaction_bindings_match;
pub(crate) use self::event_chain::batch_transaction_bindings_match;
pub(crate) use self::event_chain::WelcomeDispositionInput;
pub(crate) use self::event_chain::RecoveryOpenContext;
pub(crate) use self::event_chain::ResetRequestRow;
pub(crate) use self::event_chain::AppliedTransition;
use self::event_chain::PendingPreparedEvent;
use self::event_chain::event_chain_cursor_binding_digest;
#[path = "executor/read_ops.rs"]
mod read_ops;
use self::read_ops::principal_did;
use self::read_ops::device_did;
use self::read_ops::device_uuid;
use self::read_ops::checked_i64;
use self::read_ops::require_execution_authority;
use self::read_ops::server_instant;
use self::read_ops::repo_participant_status;
use self::read_ops::repo_participant_role;
use self::read_ops::old_role_provenance_matches;
use self::read_ops::validate_policy_participant_writes;
use self::read_ops::terminalize_policy_participants;
use self::read_ops::reject_if_present;
use self::read_ops::verify_recovery_package_bijection;
use self::read_ops::verify_recovery_package_consistency;
use self::read_ops::terminal_is_exact_transition;
use self::read_ops::terminal_is_exact_due_expiry;
use self::read_ops::OwnStalingKind;
use self::read_ops::classify_prior_bound_staling;
#[path = "executor/prior_bound_ops.rs"]
mod prior_bound_ops;
use self::prior_bound_ops::prior_bound;
use self::prior_bound_ops::prior_bound::*;
use self::prior_bound_ops::recovery_request_identity_is_unchanged;
use self::prior_bound_ops::recovery_reservation_identity_is_unchanged;
use self::prior_bound_ops::reset_request_identity_is_unchanged;
use self::prior_bound_ops::leave_request_identity_is_unchanged;
use self::prior_bound_ops::welcome_identity_is_unchanged;
use self::prior_bound_ops::interval_identity_is_unchanged;
use self::prior_bound_ops::leaf_matches_hydration;
#[path = "executor/preflight.rs"]
mod preflight;
use self::preflight::preflight_reset_activation;
use self::preflight::preflight_leaf_recovery_fulfillment;
#[path = "executor/dispatch.rs"]
mod dispatch;
pub(crate) use self::dispatch::apply_conversation_persistence_plan;
#[cfg(test)]
pub(crate) use self::dispatch::apply_conversation_persistence_plan_unscoped_for_test;
use self::dispatch::MetadataExecutionBinding;
use self::dispatch::preflight_metadata_transition;
use self::dispatch::apply_conversation_persistence_plan_inner;
#[path = "executor/welcome_ops.rs"]
mod welcome_ops;
use self::welcome_ops::apply_leaf_recovery_request;
use self::welcome_ops::terminal_welcome_context_is_closed;
use self::welcome_ops::exact_welcome_actor_role;
use self::welcome_ops::repository_welcome_rejection_reason;
use self::welcome_ops::preflight_welcome_terminal_event;
use self::welcome_ops::preflight_welcome_response_execution_context;
use self::welcome_ops::preflight_welcome_expiry_execution_context;
use self::welcome_ops::apply_welcome_expiry;
#[path = "executor/federation_ops.rs"]
mod federation_ops;
pub(crate) use self::federation_ops::PreparedDeviceRevocationBatchMembers;
pub(crate) use self::federation_ops::PrefixedDeviceRevocationBatchMembers;
pub(crate) use self::federation_ops::prepare_device_revocation_batch_members;
pub(crate) use self::federation_ops::apply_prepared_device_revocation_prefix;
pub(crate) use self::federation_ops::apply_prepared_device_revocation_members;
#[cfg(test)]
pub(crate) use self::federation_ops::apply_device_revocation_batch_unscoped_for_test;
use self::federation_ops::apply_device_revocation;
use self::federation_ops::PreparedRevocationMember;
use self::federation_ops::preflight_device_revocation_plan_and_context;
use self::federation_ops::prepared_device_revocation_members_binding_digest;
use self::federation_ops::prepared_revocation_event_from_fanout;
use self::federation_ops::apply_prepared_device_revocation_member;
use self::federation_ops::write_revocation_bound_supersessions;
use self::federation_ops::preflight_device_revocation_batch;
use self::federation_ops::apply_device_revocation_batch_prefix;
#[path = "executor/recovery_ops.rs"]
mod recovery_ops;
use self::recovery_ops::apply_welcome_response;
use self::recovery_ops::apply_leaf_recovery_cancellation;
use self::recovery_ops::apply_leaf_recovery_expiry;
#[path = "executor/fulfillment_ops.rs"]
mod fulfillment_ops;
use self::fulfillment_ops::apply_leaf_recovery_fulfillment;
#[path = "executor/commit_leave_ops.rs"]
mod commit_leave_ops;
use self::commit_leave_ops::apply_generic_commit;
use self::commit_leave_ops::preflight_leave_fulfillment;
use self::commit_leave_ops::partition_leave_fulfillment_requests;
use self::commit_leave_ops::apply_leave_fulfillment;
#[path = "executor/creation_ops.rs"]
mod creation_ops;
use self::creation_ops::apply_creation;
use self::creation_ops::apply_policy;
use self::creation_ops::apply_metadata_transition;
#[path = "executor/lifecycle_ops.rs"]
mod lifecycle_ops;
use self::lifecycle_ops::apply_zero_leaf_leave;
use self::lifecycle_ops::apply_close;
use self::lifecycle_ops::apply_reset_request;
use self::lifecycle_ops::apply_leave_request;
#[path = "executor/reset_accept_ops.rs"]
mod reset_accept_ops;
use self::reset_accept_ops::apply_leave_cancellation;
use self::reset_accept_ops::apply_reset_activation;
use self::reset_accept_ops::apply_acceptance;
#[path = "executor/write_ops.rs"]
mod write_ops;
use self::write_ops::write_recovery_open;
use self::write_ops::write_successor_leaf;
use self::write_ops::closing_leaf_period;
use self::write_ops::repo_interval_close_kind;
use self::write_ops::direct_pair;
use self::write_ops::build_append_entry;
use self::write_ops::write_creation_metadata_snapshot;
use self::write_ops::write_metadata_update_snapshot;
use self::write_ops::write_commit_metadata_snapshot;
use self::write_ops::write_participants;
use self::write_ops::write_creation_leaves;
use self::write_ops::participant_period_for;
use self::write_ops::write_creation_intervals;
use self::write_ops::build_entry_recipients;
#[path = "executor/pruning.rs"]
mod pruning;
use self::pruning::write_prior_bound_supersessions;
use self::pruning::write_prior_bound_staling;
use self::pruning::write_observed_leave_expiries;
use self::pruning::FamilyCounts;
use self::pruning::reconcile_coordinate_change_families;
use self::pruning::WelcomeSupersessionCause;
use self::pruning::write_welcome_supersessions;
use self::pruning::write_welcome_supersessions_with_cursor;
use self::pruning::append_one_event;
use self::pruning::append_one_event_with_cursor;
use self::pruning::append_one_event_at_with_cursor;
use self::pruning::write_events;
use self::pruning::write_events_with_cursor;
#[path = "executor/inline_tests.rs"]
mod inline_tests;
#[cfg(any(test, all(feature = "chat-protocol-production-proof", not(feature = "server-bin"))))]
use self::inline_tests::metadata_executor_tests;


#[cfg(all(
    feature = "chat-protocol-production-proof",
    not(feature = "server-bin")
))]
pub(in crate::chat_protocol) fn run_metadata_semantic_proof() -> Result<(), String> {
    metadata_executor_tests::run_production_semantic_proof()
}
