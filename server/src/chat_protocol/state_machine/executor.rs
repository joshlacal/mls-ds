use chrono::{DateTime, Utc};
use sha2::Digest;
use uuid::Uuid;

use sqlx::Acquire;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use super::super::public_state::encode_public_tree_summary;
use super::super::repository::blobs::{
    self as blobs, BindingKind, BlobPurpose, BlobRepositoryError, NewBlobBinding,
};
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
use super::super::transcript::canonical_metadata_avatar_blob_aad;
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
    /// A metadata-avatar bind CAS or immutable binding insert failed.
    Blob(BlobRepositoryError),
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

impl From<BlobRepositoryError> for ExecutorError {
    fn from(error: BlobRepositoryError) -> Self {
        Self::Blob(error)
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
    admission_digest: [u8; 32],
    source_entry_id: Uuid,
    source_entry_kind: &'static str,
    source_entry_sha256: [u8; 32],
    outer_fingerprint: [u8; 32],
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

/// Repository-sealed persistence authority for a signed metadata avatar.
/// A reused avatar carries the immutable historical binding columns read
/// under lock. A fresh avatar additionally carries the exact locked
/// completed-unbound blob row projected as the single-use binding CAS.
#[derive(Clone, Debug)]
pub(crate) enum MetadataAvatarPersistence {
    Reuse {
        snapshot: MetadataAvatarBinding,
    },
    Fresh {
        snapshot: MetadataAvatarBinding,
        binding: NewBlobBinding,
    },
}

impl MetadataAvatarPersistence {
    pub(crate) fn snapshot(&self) -> &MetadataAvatarBinding {
        match self {
            Self::Reuse { snapshot } | Self::Fresh { snapshot, .. } => snapshot,
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
    schedule_digest: [u8; 32],
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

fn prepared_revocation_event_digest(
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum EventChainCursorError {
    #[error("event-chain prelude digest or device vector is invalid")]
    PreludeDigestMismatch,
    #[error("event-chain schedule received an unexpected event")]
    UnexpectedEvent,
    #[error("event-chain event shape changed after preparation")]
    EventShapeMismatch,
    #[error("event-chain event repeats or reorders a recipient")]
    DuplicateRecipient,
    #[error("event-chain event names a device outside the locked prelude")]
    UnknownSlot,
    #[error("event-chain cursor already has an event pending completion")]
    EventAlreadyPending,
    #[error("event-chain cursor has no event pending completion")]
    NoPendingEvent,
    #[error("event-chain event position is not monotonic")]
    PositionNotMonotonic,
    #[error("event-chain schedule was not fully consumed")]
    IncompleteSchedule,
}

struct PendingPreparedEvent {
    event_id: Uuid,
    slots: Vec<EventChainSlot>,
}

/// Pure, SQL-free resolver for the device-global event predecessor chain.
/// It is deliberately single-use and remains owned by the opaque prepared
/// revocation batch.
pub(crate) struct EventChainCursor {
    prelude_digest: [u8; 32],
    devices: Vec<DeviceIdentity>,
    current_tails: Vec<Option<i64>>,
    remaining: VecDeque<PreparedRevocationEvent>,
    pending_event: Option<PendingPreparedEvent>,
    initial_binding_digest: [u8; 32],
}

impl EventChainCursor {
    pub(crate) fn new(
        prelude_digest: [u8; 32],
        devices: Vec<DeviceIdentity>,
        current_tails: Vec<Option<i64>>,
        schedule: Vec<PreparedRevocationEvent>,
    ) -> Result<Self, EventChainCursorError> {
        if prelude_digest == [0; 32] {
            return Err(EventChainCursorError::PreludeDigestMismatch);
        }
        if devices.len() != current_tails.len() || devices.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(EventChainCursorError::PreludeDigestMismatch);
        }
        let mut event_ids = BTreeSet::new();
        for event in &schedule {
            if !event_ids.insert(event.event_id) {
                return Err(EventChainCursorError::EventShapeMismatch);
            }
            let mut previous = None;
            for recipient in &event.recipients {
                let slot = usize::try_from(recipient.slot.0)
                    .map_err(|_| EventChainCursorError::UnknownSlot)?;
                if slot >= devices.len() {
                    return Err(EventChainCursorError::UnknownSlot);
                }
                if previous.is_some_and(|prior| prior >= recipient.slot) {
                    return Err(EventChainCursorError::DuplicateRecipient);
                }
                previous = Some(recipient.slot);
            }
        }
        let initial_binding_digest = event_chain_cursor_binding_digest(
            &prelude_digest,
            &devices,
            &current_tails,
            schedule.len(),
            schedule.iter(),
        );
        Ok(Self {
            prelude_digest,
            devices,
            current_tails,
            remaining: schedule.into(),
            pending_event: None,
            initial_binding_digest,
        })
    }

    fn recompute_initial_binding_digest(&self) -> [u8; 32] {
        event_chain_cursor_binding_digest(
            &self.prelude_digest,
            &self.devices,
            &self.current_tails,
            self.remaining.len(),
            self.remaining.iter(),
        )
    }

    fn initial_binding_is_intact(&self) -> bool {
        self.pending_event.is_none()
            && self.initial_binding_digest == self.recompute_initial_binding_digest()
    }

    fn initial_binding_digest(&self) -> &[u8; 32] {
        &self.initial_binding_digest
    }

    pub(crate) fn begin_event(
        &mut self,
        event: &PreparedRevocationEvent,
    ) -> Result<Vec<EventRecipient>, EventChainCursorError> {
        if self.pending_event.is_some() {
            return Err(EventChainCursorError::EventAlreadyPending);
        }
        let expected = self
            .remaining
            .front()
            .ok_or(EventChainCursorError::UnexpectedEvent)?;
        if event.event_id != expected.event_id {
            return Err(EventChainCursorError::UnexpectedEvent);
        }
        let actual_digest = prepared_revocation_event_digest(
            event.event_id,
            event.event_kind,
            &event.payload_bytes,
            &event.recipients,
            &event.outbox,
        );
        if actual_digest != expected.schedule_digest
            || actual_digest != event.schedule_digest
            || event.event_kind != expected.event_kind
            || event.payload_bytes != expected.payload_bytes
            || event.recipients != expected.recipients
            || event.outbox != expected.outbox
        {
            return Err(EventChainCursorError::EventShapeMismatch);
        }
        let mut rows = Vec::with_capacity(event.recipients.len());
        let mut slots = Vec::with_capacity(event.recipients.len());
        for recipient in &event.recipients {
            let slot = usize::try_from(recipient.slot.0)
                .map_err(|_| EventChainCursorError::UnknownSlot)?;
            let device = self
                .devices
                .get(slot)
                .ok_or(EventChainCursorError::UnknownSlot)?;
            rows.push(EventRecipient {
                user_did: String::from_utf8(device.principal().as_bytes().to_vec())
                    .map_err(|_| EventChainCursorError::UnknownSlot)?,
                device_id: Uuid::from_bytes(*device.device_id()),
                entitlement_kind: recipient.entitlement,
                audience_predecessor_position: self.current_tails[slot],
            });
            slots.push(recipient.slot);
        }
        self.pending_event = Some(PendingPreparedEvent {
            event_id: event.event_id,
            slots,
        });
        Ok(rows)
    }

    fn begin_fanout(
        &mut self,
        event: &EventFanout,
    ) -> Result<Vec<EventRecipient>, EventChainCursorError> {
        if self.pending_event.is_some() {
            return Err(EventChainCursorError::EventAlreadyPending);
        }
        let expected = self
            .remaining
            .front()
            .ok_or(EventChainCursorError::UnexpectedEvent)?;
        if event.event_id != expected.event_id {
            return Err(EventChainCursorError::UnexpectedEvent);
        }
        if event.event_kind != expected.event_kind
            || event.payload_bytes != expected.payload_bytes
            || event.outbox != expected.outbox
            || event.recipients.len() != expected.recipients.len()
        {
            return Err(EventChainCursorError::EventShapeMismatch);
        }
        let mut rows = Vec::with_capacity(expected.recipients.len());
        let mut slots = Vec::with_capacity(expected.recipients.len());
        for (actual, expected_recipient) in event.recipients.iter().zip(&expected.recipients) {
            let slot = expected_recipient.slot.0 as usize;
            let expected_device = self
                .devices
                .get(slot)
                .ok_or(EventChainCursorError::UnknownSlot)?;
            if &actual.0 != expected_device || actual.1 != expected_recipient.entitlement {
                return Err(EventChainCursorError::EventShapeMismatch);
            }
            rows.push(EventRecipient {
                user_did: device_did(expected_device)
                    .map_err(|_| EventChainCursorError::UnknownSlot)?,
                device_id: device_uuid(expected_device),
                entitlement_kind: expected_recipient.entitlement,
                audience_predecessor_position: self.current_tails[slot],
            });
            slots.push(expected_recipient.slot);
        }
        self.pending_event = Some(PendingPreparedEvent {
            event_id: event.event_id,
            slots,
        });
        Ok(rows)
    }

    pub(crate) fn complete_event(
        &mut self,
        event_id: Uuid,
        event_position: i64,
    ) -> Result<(), EventChainCursorError> {
        let pending = self
            .pending_event
            .as_ref()
            .ok_or(EventChainCursorError::NoPendingEvent)?;
        if pending.event_id != event_id {
            return Err(EventChainCursorError::UnexpectedEvent);
        }
        if event_position <= 0
            || pending.slots.iter().any(|slot| {
                self.current_tails[slot.0 as usize].is_some_and(|tail| event_position <= tail)
            })
        {
            return Err(EventChainCursorError::PositionNotMonotonic);
        }
        let pending = self.pending_event.take().expect("checked pending event");
        for slot in pending.slots {
            self.current_tails[slot.0 as usize] = Some(event_position);
        }
        self.remaining.pop_front();
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<(), EventChainCursorError> {
        if self.pending_event.is_some() || !self.remaining.is_empty() {
            return Err(EventChainCursorError::IncompleteSchedule);
        }
        let _ = self.prelude_digest;
        Ok(())
    }

    #[cfg(test)]
    fn finish_for_test(&self) -> Result<(), EventChainCursorError> {
        if self.pending_event.is_some() || !self.remaining.is_empty() {
            Err(EventChainCursorError::IncompleteSchedule)
        } else {
            Ok(())
        }
    }
}

fn event_chain_cursor_binding_digest<'event>(
    prelude_digest: &[u8; 32],
    devices: &[DeviceIdentity],
    initial_tails: &[Option<i64>],
    schedule_len: usize,
    schedule: impl IntoIterator<Item = &'event PreparedRevocationEvent>,
) -> [u8; 32] {
    let mut digest = sha2::Sha256::new();
    digest.update(b"CATBIRD-CHAT-G6-EVENT-CHAIN-CURSOR\0");
    digest.update(prelude_digest);
    digest.update((devices.len() as u64).to_be_bytes());
    for (device, tail) in devices.iter().zip(initial_tails) {
        digest.update((device.principal().as_bytes().len() as u64).to_be_bytes());
        digest.update(device.principal().as_bytes());
        digest.update(device.device_id());
        match tail {
            Some(value) => {
                digest.update([1]);
                digest.update(value.to_be_bytes());
            }
            None => digest.update([0]),
        }
    }
    digest.update((schedule_len as u64).to_be_bytes());
    for event in schedule {
        digest.update(event.schedule_digest);
    }
    digest.finalize().into()
}

/// For a `welcomeExpiry` edge: the DB-side facts the plan does not carry — the
/// fresh `recovery_work_items` primary key and the `welcomeDisposition` event
/// whose position binds the disposition row. The welcome id / recipient /
/// bound coordinate / `expires_at` come from the plan's `welcome_changes`.
/// `None` for every other edge.
#[derive(Clone, Debug)]
pub(crate) struct WelcomeExpiryContext {
    pub(crate) recovery_work_id: Uuid,
    pub(crate) event: EventFanout,
}

/// For a `welcomeAcknowledgement` / `welcomeRejection` edge: the
/// `welcomeDisposition` event (its position binds the disposition row) plus, for
/// a REJECTION only, the `welcomeRejected` recovery work. The client-authored
/// signed authorization the disposition row binds comes from `ctx.entry` (the
/// signed request's bytes/digest/signature); the welcome id / recipient / bound
/// coordinate come from the plan's `welcome_changes`. `None` otherwise.
#[derive(Clone, Debug)]
pub(crate) struct WelcomeResponseContext {
    pub(crate) event: EventFanout,
    /// `Some` for a rejection (adds a `welcomeRejected` recovery work item with
    /// the closed reason); `None` for an acknowledgement (no recovery work).
    pub(crate) rejection: Option<WelcomeRejectionWork>,
}

/// The `welcomeRejected` recovery work a rejection creates.
#[derive(Clone, Debug)]
pub(crate) struct WelcomeRejectionWork {
    pub(crate) recovery_work_id: Uuid,
    pub(crate) reason: WelcomeRejectionReason,
}

/// Everything the plan does NOT carry. AUDIENCE IS INPUT, NOT DERIVED: the
/// executor never queries `chat.devices` to invent an audience.
#[cfg_attr(test, derive(Clone))]
#[derive(Debug)]
pub(crate) struct ExecutionContext {
    pub(crate) protocol_instance_id: Uuid,
    /// The trusted request instant `T` — every `*_at` the executor writes.
    pub(crate) applied_at: DateTime<Utc>,
    pub(crate) actor: ExecutionActor,
    pub(crate) authority: ExecutionAuthority,
    pub(crate) spine: SpineArtifacts,
    pub(crate) opened_leaves: Vec<LeafPersistenceColumns>,
    pub(crate) metadata_author: Option<MetadataAuthorColumns>,
    pub(crate) metadata_avatar: Option<MetadataAvatarPersistence>,
    /// Fresh participant-period ids in the plan's canonical participant order.
    pub(crate) participant_period_ids: Vec<Uuid>,
    /// Fresh leaf-period ids in the plan's opened-leaf order.
    pub(crate) leaf_period_ids: Vec<Uuid>,
    /// The exact control-entry audience, canonical `(DID, device)` order.
    pub(crate) entry_recipients: Vec<(DeviceIdentity, EntryEntitlementKind)>,
    pub(crate) events: Vec<EventFanout>,
    /// For a `close`/`reset` edge that closes existing intervals: the exact
    /// active leaf-period id to record as each interval's
    /// `closing_leaf_period_id`. The facade queries `chat.member_devices` for
    /// the recipient's active leaf under lock; the plan's `interval_changes`
    /// supply everything else (terminal seq, closing transition + fingerprint).
    /// Empty for edges that close no interval (creation / policy / reset req).
    pub(crate) closing_leaf_periods: Vec<(DeviceIdentity, Uuid)>,
    /// For an edge that TERMINALIZES an existing participant period (a
    /// Policy/leave removal): the
    /// exact active `chat.participants.participant_period_id` to close. The
    /// removed participant is NOT in the successor hydration, so its period id
    /// cannot come from `participant_period_ids`; the facade queries
    /// `chat.participants` for it under lock. Empty for every other edge.
    pub(crate) closing_participant_periods: Vec<(PrincipalId, Uuid)>,
    /// For a `reset request` edge: the exact `chat.reset_requests` row content
    /// the signed request carries (reason + signed material + expiry). `None`
    /// for every other edge.
    pub(crate) reset_request_row: Option<ResetRequestRow>,
    /// For an edge that OPENS a leaf-recovery request + reservation and
    /// reserves a key package (acceptance / leaf-recovery request): the DB-side
    /// facts the plan does not carry. `None` for every other edge. The
    /// requester/recipient identity is the transition/request actor
    /// (`ctx.actor`); the request id, kind, bound coordinate, and key-package
    /// ref come from the plan's `recovery_request_changes`.
    pub(crate) recovery_open: Option<RecoveryOpenContext>,
    /// For a `welcomeExpiry` edge (see `WelcomeExpiryContext`). `None` otherwise.
    pub(crate) welcome_expiry: Option<WelcomeExpiryContext>,
    /// For a `welcomeAcknowledgement`/`welcomeRejection` edge (see
    /// `WelcomeResponseContext`). `None` otherwise.
    pub(crate) welcome_response: Option<WelcomeResponseContext>,
    /// For a coordinate-changing commit that SUPERSEDES a prior-coordinate
    /// pending Welcome: the `welcomeDisposition` event the executor appends and
    /// binds the disposition row to (one per superseded welcome). Empty for
    pub(crate) welcome_dispositions: Vec<WelcomeDispositionInput>,
    pub(crate) is_remote: bool,
    pub(crate) sequencer_ds: Option<String>,
    pub(crate) sequencer_term: i64,
    pub(crate) participant_ds_dids: std::collections::HashMap<String, Option<String>>,
}

impl ExecutionContext {
    fn entry(&self) -> &ControlEntryContent {
        self.authority
            .control_entry()
            .expect("execution authority validated before executor dispatch")
    }

    fn operation_id(&self) -> Uuid {
        self.authority.operation_id()
    }
}

/// A single-use execution capsule minted only after repository hydration
/// has bound one exact plan and context to the live SQL transaction.
///
/// The constructor requires an unforgeable token owned by
/// `repository::execution_context`. No production API accepts a separable
/// plan or raw `ExecutionContext`.
#[must_use = "a prepared execution must be consumed by the atomic executor"]
pub(crate) struct PreparedConversationExecution<'borrow, 'connection, 'plan> {
    transaction: &'borrow mut sqlx::Transaction<'connection, sqlx::Postgres>,
    plan: &'plan ConversationPersistencePlan,
    context: ExecutionContext,
    expected_transaction_id: Box<str>,
    recovery_write_authority:
        Option<super::super::repository::recovery::RecoveryExecutorWriteAuthority<'plan>>,
    historical_write_authority: Option<HistoricalExecutionWriteAuthority>,
    _proof: super::super::repository::execution_context::ExecutionContextHydrationProof,
    #[cfg(any(
        test,
        all(
            feature = "chat-protocol-production-proof",
            not(feature = "server-bin")
        )
    ))]
    drop_safety_probe: Option<DropSafetyProbe>,
}

impl<'borrow, 'connection, 'plan> PreparedConversationExecution<'borrow, 'connection, 'plan> {
    pub(crate) fn from_hydrated_parts(
        transaction: &'borrow mut sqlx::Transaction<'connection, sqlx::Postgres>,
        plan: &'plan ConversationPersistencePlan,
        context: ExecutionContext,
        expected_transaction_id: Box<str>,
        proof: super::super::repository::execution_context::ExecutionContextHydrationProof,
    ) -> Self {
        Self {
            transaction,
            plan,
            context,
            expected_transaction_id,
            recovery_write_authority: None,
            historical_write_authority: None,
            _proof: proof,
            #[cfg(any(
                test,
                all(
                    feature = "chat-protocol-production-proof",
                    not(feature = "server-bin")
                )
            ))]
            drop_safety_probe: None,
        }
    }

    /// Attach a deterministic test-only suspension/unwind point without
    /// changing any plan, authority, context, or transaction binding.
    #[cfg(test)]
    pub(crate) fn with_drop_safety_probe_for_test(mut self, probe: DropSafetyProbe) -> Self {
        self.drop_safety_probe = Some(probe);
        self
    }

    /// Attach the same per-capsule post-write probe to the non-shipping
    /// production-proof build. The proof feature is compile-incompatible
    /// with `server-bin`, so this seam cannot enter the shipping executor.
    #[cfg(all(
        feature = "chat-protocol-production-proof",
        not(feature = "server-bin")
    ))]
    pub(in crate::chat_protocol) fn with_drop_safety_probe_for_proof(
        mut self,
        probe: DropSafetyProbe,
    ) -> Self {
        self.drop_safety_probe = Some(probe);
        self
    }

    pub(in crate::chat_protocol) fn with_recovery_write_authority(
        mut self,
        authority: super::super::repository::recovery::RecoveryExecutorWriteAuthority<'plan>,
    ) -> Self {
        self.recovery_write_authority = Some(authority);
        self
    }

    pub(in crate::chat_protocol) fn with_historical_write_authority(
        mut self,
        authority: HistoricalExecutionWriteAuthority,
    ) -> Self {
        self.historical_write_authority = Some(authority);
        self
    }
}

/// Test-only behavior at the prepared executor's post-write,
/// pre-savepoint-release boundary.
#[cfg(any(
    test,
    all(
        feature = "chat-protocol-production-proof",
        not(feature = "server-bin")
    )
))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DropSafetyProbeMode {
    Pending,
    Panic,
}

/// Per-capsule drop-safety probe. It is neither global nor cloneable and is
/// attachable only after repository hydration has minted the production
/// capsule, so it cannot weaken any authority or artifact check.
#[cfg(any(
    test,
    all(
        feature = "chat-protocol-production-proof",
        not(feature = "server-bin")
    )
))]
pub(crate) struct DropSafetyProbe {
    mode: DropSafetyProbeMode,
    reached: tokio::sync::oneshot::Sender<()>,
}

#[cfg(any(
    test,
    all(
        feature = "chat-protocol-production-proof",
        not(feature = "server-bin")
    )
))]
impl DropSafetyProbe {
    pub(crate) fn new(mode: DropSafetyProbeMode) -> (Self, tokio::sync::oneshot::Receiver<()>) {
        let (reached, receiver) = tokio::sync::oneshot::channel();
        (Self { mode, reached }, receiver)
    }

    async fn reach(self) {
        let _ = self.reached.send(());
        match self.mode {
            DropSafetyProbeMode::Pending => std::future::pending::<()>().await,
            DropSafetyProbeMode::Panic => {
                panic!("prepared-executor drop-safety probe")
            }
        }
    }
}

pub(crate) fn plan_transaction_bindings_match(
    plan: &ConversationPersistencePlan,
    expected_transaction_id: &str,
) -> bool {
    let effects = plan.effects();
    effects
        .head_cas()
        .is_some_and(|binding| binding.transaction_id() == expected_transaction_id)
        && effects
            .recovery_package_cas()
            .iter()
            .all(|binding| binding.transaction_id() == expected_transaction_id)
        && effects
            .revocation_package_cas()
            .iter()
            .all(|binding| binding.transaction_id() == expected_transaction_id)
        && effects
            .revocation_target_cas()
            .is_none_or(|binding| binding.transaction_id() == expected_transaction_id)
        && effects
            .welcome_cas()
            .is_none_or(|binding| binding.transaction_id() == expected_transaction_id)
        && effects
            .invitation_quota_cas()
            .is_none_or(|binding| binding.transaction_id() == expected_transaction_id)
}

pub(crate) fn batch_transaction_bindings_match(
    plan: &DeviceRevocationBatchPersistencePlan,
    expected_transaction_id: &str,
) -> bool {
    plan.target_cas().transaction_id() == expected_transaction_id
        && plan
            .revoked_packages()
            .iter()
            .all(|binding| binding.transaction_id() == expected_transaction_id)
        && plan.conversations().iter().all(|conversation| {
            plan_transaction_bindings_match(conversation, expected_transaction_id)
        })
}

/// The `welcomeDisposition` event + outbox the executor appends when a
/// coordinate change retires a prior-coordinate pending Welcome. The
/// disposition row (`terminalize_welcome_delivery`) is bound to this event's
/// position.
///
/// A prior-bound welcome retires one of two ways, and the DB treats them very
/// differently. `Pending->Superseded` is caused BY the transition and creates no
/// recovery work. `Pending->Expired` is a due expiry the transition merely
/// OBSERVES — `assert_recovery_work_integrity` requires exactly one
/// `welcomeExpired` `recovery_work_items` row for it, exactly as the dedicated
/// `apply_welcome_expiry` arm writes. So the expiry case needs the same fresh
/// primary key `WelcomeExpiryContext` carries, minted by the same repository
/// hydration; `None` for the supersession case, which must have no work item.
#[derive(Clone, Debug)]
pub(crate) struct WelcomeDispositionInput {
    pub(crate) welcome_id: Uuid,
    /// `Some` iff this welcome's delta is `Pending->Expired`.
    pub(crate) recovery_work_id: Option<Uuid>,
    pub(crate) event: EventFanout,
}

/// DB-side facts a recovery-opening edge needs that the plan does not carry.
/// The `expires_at` the mapping trigger checks is
/// `LEAST(created_at + 5 min, package.not_after)`, so the executor writes
/// DB-clock timestamps (`created_at = requested_at = applied_at`) and needs the
/// reserved package's `not_after` to compute that bound exactly.
#[derive(Clone, Debug)]
pub(crate) struct RecoveryOpenContext {
    /// The acceptor's current participant period — the acceptance CAS target.
    /// `Some` only for the acceptance edge (a leaf-recovery request touches no
    /// participant row).
    pub(crate) participant_period_id: Option<Uuid>,
    /// `chat.key_packages.not_after` of the reserved package.
    pub(crate) package_not_after: DateTime<Utc>,
    /// For a `replace` leaf-recovery request: the leaf period being replaced.
    /// `None` for an `add`.
    pub(crate) replaced_leaf_period_id: Option<Uuid>,
}

/// The exact `chat.reset_requests` row a reset-request edge persists. Sourced
/// from the verified signed `requestReset` body; the executor writes it
/// verbatim (the DB re-verifies `request_digest`/`expires_at`).
#[derive(Clone, Debug)]
pub(crate) struct ResetRequestRow {
    pub(crate) reset_request_id: Uuid,
    pub(crate) reason: transition::ResetReason,
    pub(crate) signed_request_bytes: Vec<u8>,
    pub(crate) signing_transcript_bytes: Vec<u8>,
    pub(crate) request_digest: Vec<u8>,
    pub(crate) signature: Vec<u8>,
    pub(crate) expires_at: DateTime<Utc>,
}

/// What the executor allocated/produced, echoed for the caller's response.
#[derive(Clone, Debug)]
pub(crate) struct AppliedTransition {
    pub(crate) allocated_seq: u64,
    pub(crate) entry_id: Uuid,
    pub(crate) event_positions: Vec<i64>,
    pub(crate) successor_coordinate: Option<PublicGroupSnapshotCoordinate>,
}

fn principal_did(principal: &PrincipalId) -> Result<String, ExecutorError> {
    String::from_utf8(principal.as_bytes().to_vec()).map_err(|_| ExecutorError::ValueOutOfRange)
}

fn device_did(device: &DeviceIdentity) -> Result<String, ExecutorError> {
    principal_did(device.principal())
}

fn device_uuid(device: &DeviceIdentity) -> Uuid {
    Uuid::from_bytes(*device.device_id())
}

fn checked_i64(value: u64) -> Result<i64, ExecutorError> {
    i64::try_from(value).map_err(|_| ExecutorError::ValueOutOfRange)
}

fn require_execution_authority(
    kind: PlanKind,
    authority: &ExecutionAuthority,
) -> Result<Uuid, ExecutorError> {
    match (kind, authority) {
        (
            PlanKind::WelcomeExpiry | PlanKind::RecoveryExpiry | PlanKind::DeviceRevocation,
            ExecutionAuthority::Entryless { operation_id },
        ) => Ok(*operation_id),
        (
            PlanKind::WelcomeExpiry | PlanKind::RecoveryExpiry | PlanKind::DeviceRevocation,
            ExecutionAuthority::ControlEntry(_),
        ) => Err(ExecutorError::MissingContext(
            "entryless operation authority",
        )),
        (_, ExecutionAuthority::ControlEntry(entry)) => Ok(entry.entry_id),
        (_, ExecutionAuthority::Entryless { .. }) => {
            Err(ExecutorError::MissingContext("control-entry authority"))
        }
    }
}

fn server_instant(value: ServerTimestamp) -> Result<DateTime<Utc>, ExecutorError> {
    DateTime::<Utc>::from_timestamp_millis(value.unix_millis())
        .ok_or(ExecutorError::ValueOutOfRange)
}

fn repo_participant_status(status: ParticipantStatus) -> RepoParticipantStatus {
    match status {
        ParticipantStatus::Pending => RepoParticipantStatus::Pending,
        ParticipantStatus::Active => RepoParticipantStatus::Active,
    }
}

fn repo_participant_role(role: ParticipantRole) -> RepoParticipantRole {
    match role {
        ParticipantRole::Member => RepoParticipantRole::Member,
        ParticipantRole::Admin => RepoParticipantRole::Admin,
    }
}

fn old_role_provenance_matches(
    participant: &ParticipantRecord,
    conversation_kind: ConversationKind,
    expected_prior: &PublicGroupSnapshotCoordinate,
    current: &super::TransitionEvidence,
) -> bool {
    let Some(old) = participant.role_producer.as_ref() else {
        return initial_participant_role(conversation_kind, participant) == Some(participant.role)
            && participant.invitation.as_ref().is_none_or(|invitation| {
                invitation_matches_participant(conversation_kind, participant, invitation)
            });
    };
    if !validate_transition_evidence(old)
        || old.seq >= current.seq
        || old.received_at > current.received_at
        || old.authority.as_ref().is_none_or(|authority| {
            authority.kind != SignedMutationKind::PolicyTransition
                || authority.control_conversation_id != Some(*expected_prior.conversation_id())
        })
        || !matches!(
            classify_role_producer(old.clone(), participant.principal(), participant.role),
            Ok(Some(classified)) if classified == *old
        )
    {
        return false;
    }
    matches!(old.body_binding.as_ref(),
            Some(TransitionBodyBinding::Policy { prior, next, .. })
                if coordinate_only_successor(prior).is_ok_and(|expected| &expected == next)
                    && coordinate_is_in_lineage(next, expected_prior))
}

/// Exhaustively classify the policy's complete participant delta before the
/// executor performs its first write. This is the write-side counterpart to
/// the unchanged aggregate role-provenance validator.
fn validate_policy_participant_writes(
    effects: &TransitionEffects,
    hydration: &ConversationStateHydration,
    ctx: &ExecutionContext,
    expected_prior: &PublicGroupSnapshotCoordinate,
    transition_id: Uuid,
) -> Result<(), ExecutorError> {
    let current = &hydration.producer;
    if !validate_transition_evidence(current)
        || current.transition_id() != transition_id.as_bytes()
        || current.outer_entry_fingerprint() != ctx.entry().outer_entry_fingerprint.as_slice()
    {
        return Err(ExecutorError::InconsistentPlan(
            "policy producer does not bind the current transition",
        ));
    }
    let body_changes = match current.body_binding.as_ref() {
        Some(TransitionBodyBinding::Policy {
            prior,
            next,
            participant_changes,
        }) if prior == expected_prior && next == &hydration.coordinate => participant_changes,
        _ => {
            return Err(ExecutorError::InconsistentPlan(
                "policy producer body does not bind the plan coordinates",
            ))
        }
    };
    if body_changes.len() != effects.participant_changes().len() {
        return Err(ExecutorError::InconsistentPlan(
            "policy body and participant delta counts differ",
        ));
    }

    let signed_authority = current.authority.as_ref();
    if let Some(authority) = signed_authority {
        if authority.kind != SignedMutationKind::PolicyTransition
            || authority.control_entry_id != Some(*ctx.entry().entry_id.as_bytes())
            || authority.control_conversation_id != Some(*hydration.coordinate.conversation_id())
            || authority.actor.principal().as_bytes() != ctx.actor.user_did.as_bytes()
            || Uuid::from_bytes(*authority.actor.device_id()) != ctx.actor.device_id
            || authority.signed_request_bytes != ctx.entry().signed_request_bytes
            || authority.request_digest.as_slice() != ctx.entry().request_digest
            || authority.signature.as_slice() != ctx.entry().signature
        {
            return Err(ExecutorError::InconsistentPlan(
                "policy signed authority does not bind execution context",
            ));
        }
    }

    let mut add_count = 0usize;
    let mut removed_principals = BTreeSet::new();
    for change in effects.participant_changes() {
        match (change.before(), change.after()) {
            (None, Some(after)) => {
                let matching_adds = body_changes
                    .iter()
                    .filter(|body| {
                        matches!(body, ManifestParticipantChange::Add(principal)
                                if principal == after.principal())
                    })
                    .count();
                let invitation = after.invitation.as_ref();
                if matching_adds != 1
                    || after.status != ParticipantStatus::Pending
                    || after.role != ParticipantRole::Member
                    || after.role_producer.is_some()
                    || after.acceptance.is_some()
                    || !invitation.is_some_and(|invitation| {
                        invitation.transition == *current
                            && invitation.inviter.principal().as_bytes()
                                == ctx.actor.user_did.as_bytes()
                            && Uuid::from_bytes(*invitation.inviter.device_id())
                                == ctx.actor.device_id
                    })
                {
                    return Err(ExecutorError::InconsistentPlan(
                        "policy Add participant delta is not exact",
                    ));
                }
                add_count += 1;
            }
            (Some(before), Some(after)) => {
                // A role change requires genuine signed current authority;
                // authority-less test evidence is never sufficient to update
                // an existing durable participant row.
                if signed_authority.is_none() {
                    return Err(ExecutorError::InconsistentPlan(
                        "policy ChangeRole lacks signed authority",
                    ));
                }
                let matching_role_changes = body_changes
                    .iter()
                    .filter(|body| {
                        matches!(body,
                                ManifestParticipantChange::ChangeRole(principal, role)
                                    if principal == after.principal() && *role == after.role)
                    })
                    .count();
                if matching_role_changes != 1
                    || before.principal != after.principal
                    || before.status != ParticipantStatus::Active
                    || after.status != ParticipantStatus::Active
                    || before.role == after.role
                    || before.invitation != after.invitation
                    || before.acceptance != after.acceptance
                    || !old_role_provenance_matches(before, hydration.kind, expected_prior, current)
                    || after.role_producer.as_ref() != Some(current)
                {
                    return Err(ExecutorError::InconsistentPlan(
                        "policy ChangeRole participant delta is not exact",
                    ));
                }
            }
            (Some(before), None) => {
                if signed_authority.is_none() {
                    return Err(ExecutorError::InconsistentPlan(
                        "policy Remove lacks signed authority",
                    ));
                }
                let matching_removes = body_changes
                    .iter()
                    .filter(|body| {
                        matches!(body, ManifestParticipantChange::Remove(principal)
                                if principal == before.principal())
                    })
                    .count();
                if matching_removes != 1 || !removed_principals.insert(before.principal().clone()) {
                    return Err(ExecutorError::InconsistentPlan(
                        "policy Remove participant delta is not exact",
                    ));
                }
            }
            (None, None) => {
                return Err(ExecutorError::InconsistentPlan(
                    "policy participant delta is empty",
                ))
            }
        }
    }
    if ctx.participant_period_ids.len() != add_count {
        return Err(ExecutorError::InconsistentPlan(
            "policy participant period ids do not match Add deltas",
        ));
    }
    if ctx.closing_participant_periods.len() != removed_principals.len()
        || ctx
            .closing_participant_periods
            .iter()
            .any(|(principal, _)| {
                !removed_principals.contains(principal)
                    || ctx
                        .closing_participant_periods
                        .iter()
                        .filter(|(candidate, _)| candidate == principal)
                        .count()
                        != 1
            })
    {
        return Err(ExecutorError::InconsistentPlan(
            "policy closing participant periods do not match Remove deltas",
        ));
    }
    Ok(())
}

async fn terminalize_policy_participants(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    effects: &TransitionEffects,
    ctx: &ExecutionContext,
    transition_id: Uuid,
    seq_i64: i64,
    applied_at: DateTime<Utc>,
) -> Result<(), ExecutorError> {
    for removed in effects.participant_changes().iter().filter_map(|change| {
        match (change.before(), change.after()) {
            (Some(before), None) => Some(before),
            _ => None,
        }
    }) {
        let participant_period_id = ctx
            .closing_participant_periods
            .iter()
            .find(|(principal, _)| principal == removed.principal())
            .map(|(_, period_id)| *period_id)
            .ok_or(ExecutorError::MissingContext(
                "closing participant period id for policy Remove",
            ))?;
        transition::terminalize_participant_period(
            transaction,
            &transition::ParticipantTerminalization {
                participant_period_id,
                removing_transition_id: transition_id,
                removing_seq: seq_i64,
                removed_at: applied_at,
            },
        )
        .await?;
    }
    Ok(())
}

/// Reject any non-empty effect family the executor does not (yet) persist,
/// so nothing is ever silently dropped. Called for every family this
/// composition path does not translate.
fn reject_if_present<T>(family: &'static str, changes: &[T]) -> Result<(), ExecutorError> {
    if changes.is_empty() {
        Ok(())
    } else {
        Err(ExecutorError::UnsupportedEffect(family))
    }
}

/// Make the `recovery_package_cas` binding load-bearing (E2b-6b review MINOR-1),
/// mirroring the invitation-quota discipline: production requires it to be
/// BIJECTIVE with `package_transitions` (`package_cas_bijection_valid`), and
/// `persistence_plan_for_test` now synthesizes it, so this asserts the
/// bijection rather than silently reading the witness. Additionally
/// cross-validates (MINOR-4) that the exact key-package ref the executor drives
/// through `cas_key_package_status` equals every semantic package edge's own
/// ref — a planner that disagreed would be a hard error, never a silent skip.
/// The `recovery_package_cas` <-> `package_transitions` bijection production
/// requires (`package_cas_bijection_valid`), made load-bearing (E2b-6b MINOR-1).
fn verify_recovery_package_bijection(effects: &TransitionEffects) -> Result<(), ExecutorError> {
    let edges = effects.package_transitions();
    let cas = effects.recovery_package_cas();
    if edges.len() != cas.len() {
        return Err(ExecutorError::InconsistentPlan(
            "recovery package CAS is not bijective with package_transitions",
        ));
    }
    for edge in edges {
        let unique = cas
            .iter()
            .filter(|binding| {
                binding.request_id == edge.request_id
                    && binding.key_package_ref == edge.key_package_ref
                    && binding.expected_status == edge.from
                    && binding.successor_status == edge.to
            })
            .count();
        if unique != 1 {
            return Err(ExecutorError::InconsistentPlan(
                "recovery package CAS binding missing/duplicated for a package edge",
            ));
        }
    }
    if cas.iter().any(|binding| {
        binding.authority_digest != recovery_package_cas_authority_digest(binding)
            || binding.locked_row_digest == [0; 32]
    }) {
        return Err(ExecutorError::InconsistentPlan(
            "recovery package CAS authority seal or locked-row digest drift",
        ));
    }
    Ok(())
}

/// Bijection + the OWN package edge's driven-ref (MINOR-4) and direction
/// (MINOR-2) — for an arm that drives exactly ONE own package edge. Any OTHER
/// edges (prior-bound `Reserved->Available` supersessions) are validated by
/// `write_prior_bound_supersessions`; here only the own edge is direction-checked.
fn verify_recovery_package_consistency(
    effects: &TransitionEffects,
    driven_key_package_ref: &[u8; 32],
    expected_from: PackageStatus,
    expected_to: PackageStatus,
) -> Result<(), ExecutorError> {
    verify_recovery_package_bijection(effects)?;
    let own = effects
        .package_transitions()
        .iter()
        .filter(|edge| edge.key_package_ref == *driven_key_package_ref)
        .count();
    if own != 1 {
        return Err(ExecutorError::InconsistentPlan(
            "exactly one package edge must match the executor's driven ref",
        ));
    }
    let own_edge = effects
        .package_transitions()
        .iter()
        .find(|edge| edge.key_package_ref == *driven_key_package_ref)
        .expect("own edge exists");
    if own_edge.from != expected_from || own_edge.to != expected_to {
        return Err(ExecutorError::InconsistentPlan(
            "the driven package edge's direction disagrees with the executor's CAS",
        ));
    }
    Ok(())
}

fn terminal_is_exact_transition(
    terminal: &Option<WorkTerminalEvidence>,
    producer: &super::TransitionEvidence,
) -> bool {
    matches!(terminal, Some(WorkTerminalEvidence::Transition(value)) if value == producer)
}

fn terminal_is_exact_due_expiry(
    terminal: &Option<WorkTerminalEvidence>,
    expires_at: ServerTimestamp,
    applied_at: DateTime<Utc>,
) -> bool {
    matches!(terminal, Some(WorkTerminalEvidence::Expiry(value)) if *value == expires_at)
        && server_instant(expires_at).is_ok_and(|expiry| applied_at >= expiry)
}

/// Which reset / leave / Welcome edge, if any, the calling arm terminalizes
/// itself. Everything else in those three families is prior-bound work the
/// arm's coordinate change retires.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum OwnStalingKind {
    /// The arm terminalizes none of these families itself.
    None,
    /// `apply_leave_fulfillment` fulfills its requester's leave
    /// (`Pending -> Fulfilled`); per ADR-019 Erratum 01 the same `leaveCommit`
    /// MAY additionally stale other members' prior-bound pending leaves.
    LeaveFulfillment,
    /// `apply_reset_activation` consumes the exact signed reset request it
    /// activates (`Pending -> Consumed`). Every other prior-bound reset / leave /
    /// Welcome in the plan is work its generation retirement retires. The own
    /// edge's cardinality and its binding to the signed request id stay
    /// `preflight_reset_activation`'s own pre-CAS check.
    ResetActivation,
}

/// The single prior-bound reset / leave / Welcome classifier, shared by the
/// coordinate-changing executor arms and called by each strictly BEFORE its own
/// first head compare-and-set. Returns the terminalized Welcome ids so a caller
/// can prove its disposition bijection against them.
///
/// Extracted from `preflight_metadata_transition`, the only arm that proved
/// these shapes. The others relied on `reconcile_coordinate_change_families`,
/// but that fence runs AFTER the writers and only counts what they consumed —
/// and both `write_welcome_supersessions` and `write_prior_bound_staling`
/// accept a `Pending->Expired` delta. An incoherent expiry (transition evidence
/// carried on an `Expired` status, or an expiry not yet due at `applied_at`)
/// therefore reconciled cleanly and COMMITTED, terminalizing a live Welcome
/// delivery / reset / leave request that was never actually due.
///
/// Derives every comparand from `plan` and `ctx` — the prior coordinate from
/// the head CAS, the producer from the hydrated successor state. `own_kind`
/// selects the arm's own edge by exact typed shape, never by a caller-supplied
/// id or predicate; that edge's cardinality stays the arm's own pre-CAS check.
fn classify_prior_bound_staling(
    plan: &ConversationPersistencePlan,
    ctx: &ExecutionContext,
    own_kind: OwnStalingKind,
) -> Result<BTreeSet<[u8; 16]>, ExecutorError> {
    let effects = plan.effects();
    let head = effects.head_cas().ok_or(ExecutorError::InconsistentPlan(
        "prior-bound staling needs a head CAS binding",
    ))?;
    let prior = head
        .expected_prior()
        .ok_or(ExecutorError::InconsistentPlan(
            "prior-bound staling needs an expected prior",
        ))?;
    let producer = &plan.state().producer;

    for change in effects.reset_request_changes() {
        let (Some(before), Some(after)) = (change.before(), change.after()) else {
            return Err(ExecutorError::InconsistentPlan(
                "prior-bound reset request delta is not terminal",
            ));
        };
        // The arm's own consumption edge binds the exact signed request id, so it
        // is not a staling. Select it out here exactly as the leave loop below
        // selects out a fulfillment; its cardinality and signed-id binding stay
        // `preflight_reset_activation`'s own pre-CAS check.
        if own_kind == OwnStalingKind::ResetActivation
            && after.status == ResetRequestStatus::Consumed
        {
            continue;
        }
        let exact_terminal = match after.status {
            ResetRequestStatus::Stale => terminal_is_exact_transition(&after.terminal, producer),
            ResetRequestStatus::Expired => {
                terminal_is_exact_due_expiry(&after.terminal, after.expires_at, ctx.applied_at)
            }
            _ => false,
        };
        if !reset_request_identity_is_unchanged(before, after)
            || before.status != ResetRequestStatus::Pending
            || before.bound_coordinate != *prior
            || !exact_terminal
        {
            return Err(ExecutorError::InconsistentPlan(
                "prior-bound reset request staling drifted",
            ));
        }
    }

    for change in effects.leave_request_changes() {
        let (Some(before), Some(after)) = (change.before(), change.after()) else {
            return Err(ExecutorError::InconsistentPlan(
                "prior-bound leave request delta is not terminal",
            ));
        };
        // The arm's own fulfillment edge binds a fulfilled participant, so it is
        // neither identity-unchanged nor a staling. Select it out here; its
        // cardinality and exact shape stay `apply_leave_fulfillment`'s own
        // pre-CAS partition (exactly one Fulfilled, never also staled).
        if own_kind == OwnStalingKind::LeaveFulfillment
            && after.status == LeaveRequestStatus::Fulfilled
        {
            continue;
        }
        let exact_terminal = match after.status {
            LeaveRequestStatus::Stale => terminal_is_exact_transition(&after.terminal, producer),
            LeaveRequestStatus::Expired => {
                terminal_is_exact_due_expiry(&after.terminal, after.expires_at, ctx.applied_at)
            }
            _ => false,
        };
        if !leave_request_identity_is_unchanged(before, after)
            || before.status != LeaveRequestStatus::Pending
            || before.bound_coordinate != *prior
            || !exact_terminal
        {
            return Err(ExecutorError::InconsistentPlan(
                "prior-bound leave request staling drifted",
            ));
        }
    }
    let mut welcome_ids = BTreeSet::new();
    for change in effects.welcome_changes() {
        let (Some(before), Some(after)) = (change.before(), change.after()) else {
            return Err(ExecutorError::InconsistentPlan(
                "prior-bound Welcome delta is not terminal",
            ));
        };
        let exact_terminal = match after.status {
            WelcomeStatus::Superseded => terminal_is_exact_transition(&after.terminal, producer),
            WelcomeStatus::Expired => {
                terminal_is_exact_due_expiry(&after.terminal, after.expires_at, ctx.applied_at)
            }
            _ => false,
        };
        if !welcome_identity_is_unchanged(before, after)
            || before.status != WelcomeStatus::Pending
            || before.coordinate != *prior
            || !exact_terminal
            || !welcome_ids.insert(after.welcome_id)
        {
            return Err(ExecutorError::InconsistentPlan(
                "prior-bound Welcome supersession drifted",
            ));
        }
    }
    Ok(welcome_ids)
}

/// Everything the nine executor arms may know about prior-bound recovery work.
///
/// `PriorBoundPartition`'s fields are private to this module and it has no public
/// constructor, so `classify_prior_bound_recovery` is the ONLY way an arm can obtain
/// one. Deleting the classifier call from an arm is therefore a compile error, not a
/// silent skip. An independent review demonstrated the need: with the partition a
/// plain struct, an arm could hand-derive an equivalent value and the type-enforced
/// write-receipt fence still reconciled cleanly — proving only that the writer agreed
/// with SOME partition, never that the classifier had run.
mod prior_bound {
    use super::*;

    /// Which coordinate-changing recovery family, if any, the calling arm drives
    /// itself. Everything the arm does NOT drive is prior-bound work it must
    /// supersede, and is classified by `classify_prior_bound_recovery`.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub(super) enum OwnFamilyKind {
        /// Seven of the nine arms drive no recovery family of their own.
        None,
        /// `apply_acceptance` opens exactly one family:
        /// `(None -> Open, None -> Active, Available -> Reserved)`.
        Acceptance,
        /// `preflight_leaf_recovery_fulfillment` closes exactly one family:
        /// `(Open -> Fulfilled, Active -> Consumed, Reserved -> Consumed)`.
        LeafRecoveryFulfillment,
    }

    /// Typed partition of a plan's recovery families, produced by
    /// `classify_prior_bound_recovery`.
    ///
    /// Every prior-bound family contributes **exactly one** request, one
    /// reservation and one package edge — the classifier rejects the plan
    /// otherwise — so the per-family counts are the key count, and
    /// `requests()`/`reservations()`/`packages()` are exact rather than
    /// approximate. Callers rebuild their `FamilyCounts` recovery fields from
    /// these accessors so the pre-writer fence stays load-bearing instead of
    /// becoming tautological.
    #[derive(Debug)]
    pub(super) struct PriorBoundPartition {
        /// One entry per prior-bound family, `(request_id, key_package_ref)`.
        keys: BTreeSet<([u8; 16], [u8; 32])>,
        /// The arm's own family key, when `OwnFamilyKind` is not `None`.
        own: Option<([u8; 16], [u8; 32])>,
    }

    impl PriorBoundPartition {
        pub(super) fn requests(&self) -> usize {
            self.keys.len()
        }

        pub(super) fn reservations(&self) -> usize {
            self.keys.len()
        }

        pub(super) fn packages(&self) -> usize {
            self.keys.len()
        }

        /// The arm's own family key, when `OwnFamilyKind` is not `None`.
        pub(super) fn own(&self) -> Option<([u8; 16], [u8; 32])> {
            self.own
        }

        /// Build a partition directly, for tests that exercise the write-receipt
        /// fence itself. Gated exactly like the regression module, so it exists in
        /// neither shipping binary and cannot be used to bypass the classifier in
        /// production code.
        #[cfg(any(
            test,
            all(
                feature = "chat-protocol-production-proof",
                not(feature = "server-bin")
            )
        ))]
        pub(super) fn for_receipt_test(
            keys: BTreeSet<([u8; 16], [u8; 32])>,
            own: Option<([u8; 16], [u8; 32])>,
        ) -> Self {
            Self { keys, own }
        }

        pub(super) fn keys(&self) -> &BTreeSet<([u8; 16], [u8; 32])> {
            &self.keys
        }
    }

    pub(super) use prior_bound_receipt::PriorBoundWriteReceipt;

    /// The write receipt lives in its own module so its fields are UNREACHABLE from the
    /// nine executor arms. An arm cannot obtain the counts it needs without calling
    /// `reconcile_into_counts`, so deleting the design 5 step 6 fence is a COMPILE
    /// ERROR rather than a silent skip. An independent review demonstrated the need:
    /// with the fence expressed as a discardable `verify(&receipt)?` call, removing all
    /// nine left the entire suite green.
    mod prior_bound_receipt {
        use super::{BTreeSet, ExecutorError, FamilyCounts, PriorBoundPartition};

        /// What `write_prior_bound_supersessions` actually wrote: the per-family counts
        /// each arm folds into its `FamilyCounts`, plus the exact keys — kept DISTINCT
        /// so the key set never leaks into the welcome / reset / leave counts the tail
        /// fence consumes.
        pub(in crate::chat_protocol::state_machine::executor) struct PriorBoundWriteReceipt {
            counts: FamilyCounts,
            keys: BTreeSet<([u8; 16], [u8; 32])>,
        }

        impl PriorBoundWriteReceipt {
            pub(in crate::chat_protocol::state_machine::executor) fn new(
                counts: FamilyCounts,
                keys: BTreeSet<([u8; 16], [u8; 32])>,
            ) -> Self {
                Self { counts, keys }
            }

            /// Design 5 step 6. The ONLY way to reach the counts. Compares what the
            /// writer actually wrote against what the classifier approved, by KEY and
            /// not merely by count: `write_prior_bound_supersessions` SKIPS any delta
            /// that is not its exact supersession shape, so a silent drop is the real
            /// failure mode, and a count-only comparison cannot tell a dropped family
            /// from a substituted one.
            pub(in crate::chat_protocol::state_machine::executor) fn reconcile_into_counts(
                self,
                expected: &PriorBoundPartition,
            ) -> Result<FamilyCounts, ExecutorError> {
                if self.keys != *expected.keys() {
                    return Err(ExecutorError::InconsistentPlan(
                        "prior-bound writer key set disagrees with the classified families",
                    ));
                }
                if self.counts.requests != expected.requests()
                    || self.counts.reservations != expected.reservations()
                    || self.counts.packages != expected.packages()
                {
                    return Err(ExecutorError::InconsistentPlan(
                        "prior-bound writer counts disagree with the classified families",
                    ));
                }
                Ok(self.counts)
            }
        }
    }

    /// The single prior-bound recovery classifier, shared by all nine
    /// coordinate-changing executor arms and called by each strictly BEFORE its
    /// own first head compare-and-set.
    ///
    /// Extracted from `preflight_metadata_transition`, which was the only arm
    /// that proved these properties. The other eight either rejected every plan
    /// carrying package work outright or accepted it unproven, which is what
    /// wedged device recovery: a fulfillment whose peer's request is overdue is
    /// planner-legal and was executor-fatal, and retry re-planned the identical
    /// shape.
    ///
    /// Derives every comparand internally from `plan` and `ctx` — design 4.5
    /// forbids trusting caller-supplied loose effects, prior coordinates,
    /// producer IDs, due times, CAS lists, status filters, or exemption
    /// predicates. `own_kind` selects the arm's own family by exact typed shape
    /// and cardinality; it is not an exemption set.
    ///
    /// Only the properties common to all nine arms are validated here. Each
    /// arm's successor generation / state-version / epoch / close shape remains
    /// that arm's own pre-CAS check.
    pub(super) fn classify_prior_bound_recovery(
        plan: &ConversationPersistencePlan,
        ctx: &ExecutionContext,
        own_kind: OwnFamilyKind,
    ) -> Result<PriorBoundPartition, ExecutorError> {
        let effects = plan.effects();
        let head = effects.head_cas().ok_or(ExecutorError::InconsistentPlan(
            "prior-bound classification needs a head CAS binding",
        ))?;
        let prior = head
            .expected_prior()
            .ok_or(ExecutorError::InconsistentPlan(
                "prior-bound classification needs an expected prior",
            ))?;
        let producer = &plan.state().producer;

        // Properties common to all nine arms. Arm-specific successor shape
        // (reset advances generation+1 / stateVersion 0; close retires the
        // coordinate; commit and fulfillment bump state-version and epoch) stays
        // in each arm's existing check.
        if head.conversation_id() != prior.conversation_id()
            || plan.expected_prior.as_ref() != Some(prior)
            || plan
                .successor_coordinate
                .as_ref()
                .is_some_and(|successor| successor.conversation_id() != prior.conversation_id())
        {
            return Err(ExecutorError::InconsistentPlan(
                "prior-bound classification: plan/head coordinate binding drifted",
            ));
        }

        // The arm's own family, derived by exact typed shape and cardinality.
        let own = match own_kind {
            OwnFamilyKind::None => None,
            OwnFamilyKind::Acceptance => Some(classify_own_acceptance_family(effects, prior)?),
            OwnFamilyKind::LeafRecoveryFulfillment => {
                Some(classify_own_fulfillment_family(effects, prior, producer)?)
            }
        };

        let mut request_keys: BTreeMap<([u8; 16], [u8; 32]), bool> = BTreeMap::new();
        for change in effects.recovery_request_changes() {
            let (Some(before_request), Some(after_request)) = (change.before(), change.after())
            else {
                // A creation or deletion is only legal as the arm's own family;
                // `classify_own_acceptance_family` has already proved that shape.
                if own_kind == OwnFamilyKind::Acceptance && change.before().is_none() {
                    continue;
                }
                return Err(ExecutorError::InconsistentPlan(
                    "metadata recovery request delta is not terminal",
                ));
            };
            let key = (after_request.request_id, after_request.key_package_ref);
            if own == Some(key) {
                continue;
            }
            let expired = match after_request.status {
                RecoveryRequestStatus::Superseded
                    if terminal_is_exact_transition(&after_request.terminal, producer) =>
                {
                    false
                }
                RecoveryRequestStatus::Expired
                    if terminal_is_exact_due_expiry(
                        &after_request.terminal,
                        after_request.expires_at,
                        ctx.applied_at,
                    ) =>
                {
                    true
                }
                _ => {
                    return Err(ExecutorError::InconsistentPlan(
                        "metadata recovery request has an illegal terminal shape",
                    ))
                }
            };
            if !recovery_request_identity_is_unchanged(before_request, after_request)
                || before_request.status != RecoveryRequestStatus::Open
                || before_request.bound_coordinate != *prior
                || request_keys.insert(key, expired).is_some()
            {
                return Err(ExecutorError::InconsistentPlan(
                    "metadata recovery request terminalization drifted",
                ));
            }
        }

        let mut reservation_keys: BTreeMap<([u8; 16], [u8; 32]), bool> = BTreeMap::new();
        for change in effects.reservation_changes() {
            let (Some(before_reservation), Some(after_reservation)) =
                (change.before(), change.after())
            else {
                if own_kind == OwnFamilyKind::Acceptance && change.before().is_none() {
                    continue;
                }
                return Err(ExecutorError::InconsistentPlan(
                    "metadata reservation delta is not terminal",
                ));
            };
            let key = (
                after_reservation.request_id,
                after_reservation.key_package_ref,
            );
            if own == Some(key) {
                continue;
            }
            let expired = match after_reservation.status {
                ReservationStatus::Released
                    if terminal_is_exact_transition(&after_reservation.terminal, producer) =>
                {
                    false
                }
                ReservationStatus::Expired
                    if terminal_is_exact_due_expiry(
                        &after_reservation.terminal,
                        after_reservation.expires_at,
                        ctx.applied_at,
                    ) =>
                {
                    true
                }
                _ => {
                    return Err(ExecutorError::InconsistentPlan(
                        "metadata reservation has an illegal terminal shape",
                    ))
                }
            };
            if !recovery_reservation_identity_is_unchanged(before_reservation, after_reservation)
                || before_reservation.status != ReservationStatus::Active
                || before_reservation.bound_coordinate != *prior
                || reservation_keys.insert(key, expired).is_some()
            {
                return Err(ExecutorError::InconsistentPlan(
                    "metadata reservation terminalization drifted",
                ));
            }
        }

        // Own/prior key collision is a hard rejection, never a silent skip
        // (design 4.5). The `continue` arms above skip the own key by exact
        // match; a planner that also emitted it as prior-bound work would be
        // caught here.
        if let Some(own_key) = own {
            if request_keys.contains_key(&own_key) || reservation_keys.contains_key(&own_key) {
                return Err(ExecutorError::InconsistentPlan(
                    "own recovery family also appears as prior-bound work",
                ));
            }
        }

        let package_keys = effects
            .package_transitions()
            .iter()
            .filter(|edge| own != Some((edge.request_id, edge.key_package_ref)))
            .map(|edge| {
                (
                    (edge.request_id, edge.key_package_ref),
                    (edge.from, edge.to),
                )
            })
            .collect::<BTreeMap<_, _>>();
        verify_recovery_package_bijection(effects)?;
        let own_edges = usize::from(own.is_some());
        if request_keys != reservation_keys
                || request_keys.len() != package_keys.len()
                || package_keys.len() + own_edges != effects.package_transitions().len()
                // Design 4.3: `Reserved -> Expired` is rejected for prior-bound
                // families. It is production-unproducible — MIN_KEY_PACKAGE_REMAINING
                // (600s) strictly exceeds RECOVERY_RESERVATION_TTL (300s), so
                // `recovery_expiry`'s `.min()` never clamps — but readers still
                // accepted it. Both Row A and Row B terminalize the package to
                // `Available`; only the request/reservation terminal shape differs.
                || request_keys.keys().any(|key| {
                    !matches!(
                        package_keys.get(key),
                        Some((PackageStatus::Reserved, PackageStatus::Available))
                    )
                })
        {
            return Err(ExecutorError::InconsistentPlan(
                "metadata recovery request/reservation/package families are not bijective",
            ));
        }

        for binding in effects.recovery_package_cas() {
            let key = (binding.request_id, binding.key_package_ref);
            if own == Some(key) {
                continue;
            }
            let request = effects
                .recovery_request_changes()
                .iter()
                .filter_map(StateChange::after)
                .find(|request| {
                    request.request_id == binding.request_id
                        && request.key_package_ref == binding.key_package_ref
                })
                .ok_or(ExecutorError::InconsistentPlan(
                    "metadata package authority has no exact recovery request",
                ))?;
            let reservation = effects
                .reservation_changes()
                .iter()
                .filter_map(StateChange::after)
                .find(|reservation| {
                    reservation.request_id == binding.request_id
                        && reservation.key_package_ref == binding.key_package_ref
                })
                .ok_or(ExecutorError::InconsistentPlan(
                    "metadata package authority has no exact reservation",
                ))?;
            let (origin_key_id, origin_auth_generation) = match &request.origin {
                RecoveryOriginEvidence::Acceptance(value) => {
                    let authority =
                        value
                            .authority
                            .as_ref()
                            .ok_or(ExecutorError::InconsistentPlan(
                                "metadata recovery acceptance has no signing authority",
                            ))?;
                    (authority.key_id, authority.auth_generation)
                }
                RecoveryOriginEvidence::Request(value) => (value.key_id, value.auth_generation),
            };
            // Amended design 4.4 check 8. The wrapper SHA has a comparand on the
            // `Acceptance` branch only; on the `Request` branch check 8 reads
            // neither the body binding nor the signed authority, and their
            // absence is NOT a rejection ground — `RequestEvidence.key_id` and
            // `.auth_generation` are non-Optional and are taken directly above.
            // A universal fail-closed rule would be a different truth table than
            // the sealed base and would strand design 6.4 positive rows 2/3/4.
            if let RecoveryOriginEvidence::Acceptance(value) = &request.origin {
                let recovery = match value.body_binding.as_ref() {
                    Some(TransitionBodyBinding::Acceptance { recovery, .. }) => recovery,
                    _ => {
                        return Err(ExecutorError::InconsistentPlan(
                            "prior-bound recovery acceptance has no acceptance body binding",
                        ))
                    }
                };
                if binding.key_package_wrapper_sha256 != recovery.key_package_wrapper_sha256
                    || <[u8; 32]>::from(sha2::Sha256::digest(&recovery.key_package_wrapper))
                        != recovery.key_package_wrapper_sha256
                {
                    return Err(ExecutorError::InconsistentPlan(
                        "prior-bound recovery package wrapper digest drift",
                    ));
                }
            }
            if binding.transaction_id != head.transaction_id
                    || binding.conversation_id != *prior.conversation_id()
                    || binding.target != request.target
                    || binding.target != reservation.target
                    || binding.target_key_id != origin_key_id
                    || binding.target_auth_generation != origin_auth_generation
                    || binding.bound_coordinate != *prior
                    || binding.bound_coordinate != request.bound_coordinate
                    || binding.bound_coordinate != reservation.bound_coordinate
                    || binding.package_not_after != reservation.package_not_after
                    || binding.claimed_at != request.received_at
                    || binding.claimed_at != reservation.received_at
                    // Sealed proved this pair directly; the binding pins every other
                    // cross-field equality but not `expires_at`, which is what
                    // `terminal_is_exact_due_expiry` tests the terminal against. A
                    // request and reservation disagreeing here could have one due and
                    // the other not.
                    || request.expires_at != reservation.expires_at
                    || binding.expected_status != PackageStatus::Reserved
                    || binding.successor_status
                        != package_keys
                            .get(&key)
                            .map(|(_, successor)| *successor)
                            .ok_or(ExecutorError::InconsistentPlan(
                                "metadata package authority has no semantic edge",
                            ))?
            {
                return Err(ExecutorError::InconsistentPlan(
                    "metadata recovery package CAS authority drift",
                ));
            }
        }

        // Amended design 4.4 check 8-DiD (defence in depth; mandatory here, not a
        // 6.4 matrix row). `recovery_package_guard_digest` hashes
        // `key_package_ref` with every variable-length input length-prefixed, so
        // distinct refs imply distinct digests absent a SHA-256 collision. This
        // fires on planner digest-reuse across two references.
        let mut seen_row_digests: BTreeMap<[u8; 32], [u8; 32]> = BTreeMap::new();
        for binding in effects.recovery_package_cas() {
            if let Some(previous_ref) =
                seen_row_digests.insert(binding.locked_row_digest, binding.key_package_ref)
            {
                if previous_ref != binding.key_package_ref {
                    return Err(ExecutorError::InconsistentPlan(
                        "distinct key package refs share one locked row digest",
                    ));
                }
            }
        }

        Ok(PriorBoundPartition {
            keys: request_keys.into_keys().collect(),
            own,
        })
    }

    /// `apply_acceptance`'s own family: exactly one
    /// `(None -> Open, None -> Active, Available -> Reserved)` triple, keyed
    /// `(request_id, key_package_ref)`. Derived by exact typed shape and
    /// cardinality — never by a caller-supplied exemption set.
    fn classify_own_acceptance_family(
        effects: &TransitionEffects,
        prior: &PublicGroupSnapshotCoordinate,
    ) -> Result<([u8; 16], [u8; 32]), ExecutorError> {
        // CRITICAL: the acceptance own family is opened as PART of the coordinate
        // change, so `plan_accept_conversation_inner` binds both the request and the
        // reservation to `coordinate_only_successor(prior)`, never to `prior` itself.
        // Comparing against `prior` here rejects every acceptConversation before its
        // head CAS, and retry re-plans the identical shape — a permanent
        // device-can-never-join wedge. Only the PRIOR-BOUND families are prior-bound.
        let own_bound = coordinate_only_successor(prior).map_err(|_| {
            ExecutorError::InconsistentPlan("acceptance successor is not coordinate-only")
        })?;
        let mut own: Option<([u8; 16], [u8; 32])> = None;
        for change in effects.recovery_request_changes() {
            let (None, Some(after)) = (change.before(), change.after()) else {
                continue;
            };
            if after.status != RecoveryRequestStatus::Open
                || after.bound_coordinate != own_bound
                || after.terminal.is_some()
            {
                return Err(ExecutorError::InconsistentPlan(
                    "acceptance own recovery request has an illegal shape",
                ));
            }
            if own
                .replace((after.request_id, after.key_package_ref))
                .is_some()
            {
                return Err(ExecutorError::InconsistentPlan(
                    "acceptance carries multiple own recovery requests",
                ));
            }
        }
        let own = own.ok_or(ExecutorError::InconsistentPlan(
            "acceptance carries no own opened recovery request",
        ))?;

        let mut reservations = 0usize;
        for change in effects.reservation_changes() {
            let (None, Some(after)) = (change.before(), change.after()) else {
                continue;
            };
            if (after.request_id, after.key_package_ref) != own
                || after.status != ReservationStatus::Active
                || after.bound_coordinate != own_bound
                || after.terminal.is_some()
            {
                return Err(ExecutorError::InconsistentPlan(
                    "acceptance own reservation has an illegal shape",
                ));
            }
            reservations += 1;
        }
        if reservations != 1 {
            return Err(ExecutorError::InconsistentPlan(
                "acceptance must open exactly one reservation",
            ));
        }

        let own_edges = effects
            .package_transitions()
            .iter()
            .filter(|edge| (edge.request_id, edge.key_package_ref) == own)
            .collect::<Vec<_>>();
        if own_edges.len() != 1
            || own_edges[0].from != PackageStatus::Available
            || own_edges[0].to != PackageStatus::Reserved
        {
            return Err(ExecutorError::InconsistentPlan(
                "acceptance must drive exactly one Available -> Reserved package edge",
            ));
        }
        Ok(own)
    }

    /// `preflight_leaf_recovery_fulfillment`'s own family: exactly one
    /// `(Open -> Fulfilled, Active -> Consumed, Reserved -> Consumed)` triple.
    /// Its terminal must be the exact producer transition — an `Expiry` terminal
    /// is never the fulfilling device's own work.
    fn classify_own_fulfillment_family(
        effects: &TransitionEffects,
        prior: &PublicGroupSnapshotCoordinate,
        producer: &super::super::TransitionEvidence,
    ) -> Result<([u8; 16], [u8; 32]), ExecutorError> {
        let mut own: Option<&RecoveryRequest> = None;
        for change in effects.recovery_request_changes() {
            let (Some(before), Some(after)) = (change.before(), change.after()) else {
                continue;
            };
            if before.status != RecoveryRequestStatus::Open
                || after.status != RecoveryRequestStatus::Fulfilled
            {
                continue;
            }
            if !recovery_request_identity_is_unchanged(before, after)
                    || before.bound_coordinate != *prior
                    // The own family closes by THIS producer's transition. An `Expiry`
                    // terminal is never the fulfilling device's own work; it belongs to
                    // a prior-bound peer family and is classified as such.
                    || !terminal_is_exact_transition(&after.terminal, producer)
            {
                return Err(ExecutorError::InconsistentPlan(
                    "fulfillment own recovery request identity/terminal drift",
                ));
            }
            if own.replace(after).is_some() {
                return Err(ExecutorError::InconsistentPlan(
                    "fulfillment carries multiple own recovery requests",
                ));
            }
        }
        let own_request = own.ok_or(ExecutorError::InconsistentPlan(
            "fulfillment carries no own fulfilled recovery request",
        ))?;
        let own = (own_request.request_id, own_request.key_package_ref);

        let mut reservations = 0usize;
        for change in effects.reservation_changes() {
            let (Some(before), Some(after)) = (change.before(), change.after()) else {
                continue;
            };
            if (after.request_id, after.key_package_ref) != own {
                continue;
            }
            if before.status != ReservationStatus::Active
                    || after.status != ReservationStatus::Consumed
                    || !recovery_reservation_identity_is_unchanged(before, after)
                    || before.bound_coordinate != *prior
                    || !terminal_is_exact_transition(&after.terminal, producer)
                    // Sealed proved the own request and reservation agree field-for-field
                    // ("fulfillment own request/reservation are not bijective"). The
                    // key and request id are implied by the `own` match above; target,
                    // received_at and expires_at are not.
                    || after.target != own_request.target
                    || after.received_at != own_request.received_at
                    || after.expires_at != own_request.expires_at
            {
                return Err(ExecutorError::InconsistentPlan(
                    "fulfillment own reservation has an illegal shape",
                ));
            }
            reservations += 1;
        }
        if reservations != 1 {
            return Err(ExecutorError::InconsistentPlan(
                "fulfillment must consume exactly one own reservation",
            ));
        }

        let own_edges = effects
            .package_transitions()
            .iter()
            .filter(|edge| (edge.request_id, edge.key_package_ref) == own)
            .collect::<Vec<_>>();
        if own_edges.len() != 1
            || own_edges[0].from != PackageStatus::Reserved
            || own_edges[0].to != PackageStatus::Consumed
        {
            return Err(ExecutorError::InconsistentPlan(
                "fulfillment must drive exactly one Reserved -> Consumed package edge",
            ));
        }
        Ok(own)
    }
}

use prior_bound::{
    classify_prior_bound_recovery, OwnFamilyKind, PriorBoundPartition, PriorBoundWriteReceipt,
};

fn recovery_request_identity_is_unchanged(
    before: &RecoveryRequest,
    after: &RecoveryRequest,
) -> bool {
    before.request_id == after.request_id
        && before.target == after.target
        && before.kind == after.kind
        && before.source == after.source
        && before.bound_coordinate == after.bound_coordinate
        && before.key_package_ref == after.key_package_ref
        && before.received_at == after.received_at
        && before.expires_at == after.expires_at
        && before.terminal.is_none()
}

fn recovery_reservation_identity_is_unchanged(
    before: &RecoveryReservation,
    after: &RecoveryReservation,
) -> bool {
    before.request_id == after.request_id
        && before.target == after.target
        && before.bound_coordinate == after.bound_coordinate
        && before.key_package_ref == after.key_package_ref
        && before.received_at == after.received_at
        && before.expires_at == after.expires_at
        && before.package_not_after == after.package_not_after
        && before.terminal.is_none()
}

fn reset_request_identity_is_unchanged(before: &ResetRequest, after: &ResetRequest) -> bool {
    before.request_id == after.request_id
        && before.requester == after.requester
        && before.bound_coordinate == after.bound_coordinate
        && before.received_at == after.received_at
        && before.expires_at == after.expires_at
        && before.origin == after.origin
        && before.terminal.is_none()
}

fn leave_request_identity_is_unchanged(
    before: &super::LeaveRequest,
    after: &super::LeaveRequest,
) -> bool {
    before.request_id == after.request_id
        && before.requester == after.requester
        && before.bound_coordinate == after.bound_coordinate
        && before.received_at == after.received_at
        && before.expires_at == after.expires_at
        && before.origin == after.origin
        && before.fulfilled_participant == after.fulfilled_participant
        && before.terminal.is_none()
}

fn welcome_identity_is_unchanged(before: &WelcomeWork, after: &WelcomeWork) -> bool {
    before.welcome_id == after.welcome_id
        && before.recipient == after.recipient
        && before.transition_seq == after.transition_seq
        && before.coordinate == after.coordinate
        && before.recovery_request_id == after.recovery_request_id
        && before.key_package_ref == after.key_package_ref
        && before.opaque_welcome == after.opaque_welcome
        && before.sha256 == after.sha256
        && before.expires_at == after.expires_at
        && before.terminal.is_none()
}

fn interval_identity_is_unchanged(
    before: &super::AccessInterval,
    after: &super::AccessInterval,
) -> bool {
    before.recipient == after.recipient
        && before.generation == after.generation
        && before.opening == after.opening
        && before.opening_kind == after.opening_kind
        && before.opening_context == after.opening_context
        && before.end.is_none()
}

fn leaf_matches_hydration(leaf: &LeafRecord, row: &LeafHydrationRow) -> bool {
    leaf.device == row.device
        && leaf.leaf_index == row.leaf_index
        && leaf.basic_credential == row.basic_credential
        && leaf.signature_key == row.signature_key
        && leaf.encryption_key == row.encryption_key
        && leaf.key_package_ref == row.key_package_ref
}

/// Complete logical-shape fence for ResetActivation. This runs before the
/// head CAS; applied-row reconciliation remains a second fence.
fn preflight_reset_activation(
    plan: &ConversationPersistencePlan,
    ctx: &ExecutionContext,
    prior: &PublicGroupSnapshotCoordinate,
    retired: &PublicGroupSnapshotCoordinate,
    transition_id: Uuid,
    seq_i64: i64,
) -> Result<Uuid, ExecutorError> {
    let effects = plan.effects();
    let hydration = plan.state();
    let producer = &hydration.producer;
    if producer.transition_id != *transition_id.as_bytes()
        || i64::try_from(producer.seq).ok() != Some(seq_i64)
    {
        return Err(ExecutorError::InconsistentPlan(
            "reset producer disagrees with allocated transition/sequence",
        ));
    }
    let (signed_request_id, signed_metadata) = match producer.body_binding.as_ref() {
        Some(super::TransitionBodyBinding::ResetActivation {
            reset_request_id,
            prior: bound_prior,
            retired: bound_retired,
            successor,
            metadata,
            ..
        }) if bound_prior == prior
            && bound_retired == retired
            && successor == &hydration.coordinate =>
        {
            (*reset_request_id, metadata)
        }
        _ => {
            return Err(ExecutorError::InconsistentPlan(
                "reset producer coordinates/request binding drift",
            ))
        }
    };

    // Prior-bound reset / leave / Welcome work this generation retirement
    // retires, proved by the SHARED classifier — the same one every other
    // coordinate-changing arm calls, and the only place these three families are
    // shape-checked.
    //
    // The four hand-rolled loops this replaces accepted only Row A
    // (`Pending->Stale` / `Pending->Superseded`, terminal evidence = this
    // transition) and duplicated, more narrowly, checks the arm already performs.
    // But `resolve_prior_bound_work` emits Row B — status `Expired` with
    // `Expiry(expires_at)` — for ANY prior-bound reset / leave / Welcome whose
    // `expires_at` had already passed at `evidence.received_at`, and
    // `write_prior_bound_staling` / `write_welcome_supersessions` already write
    // that row. So an `activateReset` over a coordinate carrying a peer's overdue
    // pending leave (24h TTL, never swept) or an overdue pending Welcome was
    // planner-legal and executor-fatal, and a retry replanned the identical
    // shape: a permanent wedge. The classifier proves BOTH rows exactly —
    // identity unchanged, `before` Pending, `before` bound to this exact prior,
    // Row A's terminal the exact producer, Row B's terminal an exact DUE expiry
    // (`applied_at >= expires_at`) — so accepting it here is the executor
    // accepting its own planner's output, not a relaxation.
    //
    // The recovery request / reservation / package / `recovery_package_cas`
    // loops are gone for the same reason: `apply_reset_activation` already calls
    // `classify_prior_bound_recovery` (strictly before this preflight), which
    // proves those four families as a strict superset — both rows, the
    // request/reservation/package bijection, the `Reserved->Available` package
    // edge, and every CAS field equality. The `PriorBoundPartition` it returns has
    // no public constructor, so that call cannot be dropped without a compile
    // error.
    let welcome_ids = classify_prior_bound_staling(plan, ctx, OwnStalingKind::ResetActivation)?;

    // The arm's OWN edge, which the classifier deliberately leaves to it: exactly
    // one `Pending->Consumed` reset request, and it must be the exact request the
    // signed producer body names. It can never be Row B —
    // `plan_reset_activation_inner` rejects an overdue target with `WorkExpired`
    // before planning.
    let mut own_reset = None;
    for change in effects.reset_request_changes() {
        let (Some(before), Some(after)) = (change.before(), change.after()) else {
            return Err(ExecutorError::InconsistentPlan(
                "reset request delta is not terminal",
            ));
        };
        if after.status != ResetRequestStatus::Consumed {
            continue;
        }
        if after.request_id != signed_request_id
            || !reset_request_identity_is_unchanged(before, after)
            || before.status != ResetRequestStatus::Pending
            || before.bound_coordinate != *prior
            || !terminal_is_exact_transition(&after.terminal, producer)
            || own_reset.replace(after).is_some()
        {
            return Err(ExecutorError::InconsistentPlan(
                "reset own request identity/binding/terminal drift",
            ));
        }
    }
    let _own_reset = own_reset.ok_or(ExecutorError::InconsistentPlan(
        "reset consumes no exact signed pending request",
    ))?;

    let disposition_ids = ctx
        .welcome_dispositions
        .iter()
        .map(|input| *input.welcome_id.as_bytes())
        .collect::<BTreeSet<_>>();
    if welcome_ids != disposition_ids || disposition_ids.len() != ctx.welcome_dispositions.len() {
        return Err(ExecutorError::InconsistentPlan(
            "reset Welcome dispositions are not complete/bijective",
        ));
    }

    if hydration.leaves.len() != 1
        || ctx.opened_leaves.len() != 1
        || ctx.leaf_period_ids.len() != 1
        || ctx.participant_period_ids.len() != hydration.participants.len()
        || effects.opened_intervals().len() != 1
        || ctx.closing_leaf_periods.len() != effects.closed_intervals().len()
        || usize::try_from(ctx.spine.leaf_count).ok() != Some(ctx.closing_leaf_periods.len())
        || hydration
            .public_state
            .as_ref()
            .map(|state| state.binding().tree_summary().leaves().len())
            != Some(1)
        || ctx.events.len() != 1
        || ctx.metadata_author.is_none()
        || ctx.spine.leaf_count < 1
        || sha2::Sha256::digest(&ctx.spine.public_snapshot_bytes).as_slice()
            != ctx.spine.public_snapshot_sha256
        || sha2::Sha256::digest(&ctx.spine.tree_summary_bytes).as_slice()
            != ctx.spine.tree_summary_sha256
        || ctx.spine.genesis_group_info_bytes.is_empty()
        || sha2::Sha256::digest(&ctx.spine.genesis_group_info_bytes).as_slice()
            != ctx.spine.genesis_group_info_sha256
    {
        return Err(ExecutorError::InconsistentPlan(
            "reset execution context/spine cardinality or digest mismatch",
        ));
    }
    if hydration.leaves[0].device != ctx.opened_leaves[0].device
        || device_did(&hydration.leaves[0].device)? != ctx.actor.user_did
        || device_uuid(&hydration.leaves[0].device) != ctx.actor.device_id
        || effects.opened_intervals()[0] != hydration.leaves[0].device
    {
        return Err(ExecutorError::InconsistentPlan(
            "reset successor is not the singleton activator leaf/interval",
        ));
    }
    let closed_devices = effects
        .closed_intervals()
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let closing_context_devices = ctx
        .closing_leaf_periods
        .iter()
        .map(|(device, _)| device.clone())
        .collect::<BTreeSet<_>>();
    if closed_devices != closing_context_devices
        || closing_context_devices.len() != ctx.closing_leaf_periods.len()
    {
        return Err(ExecutorError::InconsistentPlan(
            "reset old leaf/interval closure context is incomplete",
        ));
    }

    // Validate every actual leaf delta. Reset closes the complete prior
    // generation and installs one successor leaf. `diff_by_key` may omit
    // the activator when its leaf bytes are identical across generations,
    // so completeness is the closed-device set minus at most that one
    // unchanged activator; every delta that is present remains fully
    // load-bearing.
    let successor_device = &hydration.leaves[0].device;
    let mut changed_before_devices = BTreeSet::new();
    let mut changed_after_devices = BTreeSet::new();
    for change in effects.leaf_changes() {
        match (change.before(), change.after()) {
            (Some(before), None)
                if before.device != *successor_device
                    && closed_devices.contains(&before.device) =>
            {
                if !changed_before_devices.insert(before.device.clone()) {
                    return Err(ExecutorError::InconsistentPlan(
                        "reset repeats an old leaf delta",
                    ));
                }
            }
            (Some(before), Some(after))
                if before.device == *successor_device
                    && after.device == *successor_device
                    && before != after
                    && leaf_matches_hydration(after, &hydration.leaves[0])
                    && closed_devices.contains(&before.device) =>
            {
                if !changed_before_devices.insert(before.device.clone())
                    || !changed_after_devices.insert(after.device.clone())
                {
                    return Err(ExecutorError::InconsistentPlan(
                        "reset repeats the successor leaf delta",
                    ));
                }
            }
            _ => {
                return Err(ExecutorError::InconsistentPlan(
                    "reset leaf change has an illegal shape/content",
                ))
            }
        }
    }
    let mut accounted_old_leaves = changed_before_devices;
    accounted_old_leaves.insert(successor_device.clone());
    if accounted_old_leaves != closed_devices || changed_after_devices.len() > 1 {
        return Err(ExecutorError::InconsistentPlan(
            "reset leaf deltas do not account for the prior/successor leaves",
        ));
    }

    // Validate every actual interval delta, including the complete
    // TransitionEvidence value. This is deliberately before the head CAS:
    // writers must never persist a caller-mutated closing fingerprint.
    let mut closed_interval_devices = BTreeSet::new();
    let mut opened_interval_devices = BTreeSet::new();
    for change in effects.interval_changes() {
        match (change.before(), change.after()) {
            (Some(before), Some(after))
                if interval_identity_is_unchanged(before, after)
                    && before.generation == prior.generation()
                    && after.end.as_ref().is_some_and(|end| {
                        end.kind == CloseKind::Reset && end.evidence == *producer
                    }) =>
            {
                if !closed_interval_devices.insert(after.recipient.clone()) {
                    return Err(ExecutorError::InconsistentPlan(
                        "reset repeats a closed interval",
                    ));
                }
            }
            (None, Some(after))
                if after.recipient == *successor_device
                    && after.generation == hydration.coordinate.generation()
                    && after.opening == *producer
                    && after.opening_kind == super::OpeningKind::Reset
                    && after.opening_context == hydration.coordinate
                    && after.end.is_none() =>
            {
                if !opened_interval_devices.insert(after.recipient.clone()) {
                    return Err(ExecutorError::InconsistentPlan(
                        "reset repeats the successor interval",
                    ));
                }
            }
            _ => {
                return Err(ExecutorError::InconsistentPlan(
                    "reset interval change has an illegal shape/evidence",
                ))
            }
        }
    }
    if closed_interval_devices != closed_devices
        || opened_interval_devices != BTreeSet::from([successor_device.clone()])
        || effects.interval_changes().len()
            != closed_devices
                .len()
                .checked_add(1)
                .ok_or(ExecutorError::ValueOutOfRange)?
    {
        return Err(ExecutorError::InconsistentPlan(
            "reset interval changes are not complete/bijective",
        ));
    }

    // The actual metadata delta must be the exact signed ResetActivation
    // binding and the context columns must be the same authenticated author.
    let metadata_change = effects
        .metadata_change()
        .ok_or(ExecutorError::InconsistentPlan(
            "reset metadata change is missing",
        ))?;
    let (Some(before_metadata), Some(after_metadata)) =
        (metadata_change.before(), metadata_change.after())
    else {
        return Err(ExecutorError::InconsistentPlan(
            "reset metadata change is not a complete replacement",
        ));
    };
    let metadata_author = ctx
        .metadata_author
        .as_ref()
        .ok_or(ExecutorError::MissingContext(
            "reset metadata author columns",
        ))?;
    if after_metadata != signed_metadata
        || before_metadata == after_metadata
        || after_metadata.coordinate_conversation_id() != hydration.coordinate.conversation_id()
        || after_metadata.coordinate_generation() != hydration.coordinate.generation()
        || after_metadata.coordinate_group_id() != hydration.coordinate.group_id()
        || after_metadata.coordinate_epoch() != hydration.coordinate.epoch()
        || after_metadata.coordinate_group_context_hash()
            != hydration.coordinate.group_context_hash()
        || after_metadata.coordinate_confirmation_tag() != hydration.coordinate.confirmation_tag()
        || after_metadata.author() != successor_device
        || metadata_author.author_role != "admin"
        || metadata_author.author_device_status != "active"
        || metadata_author.author_key_id != URL_SAFE_NO_PAD.encode(after_metadata.author_key_id())
        || metadata_author.author_public_key != after_metadata.signature_public_key()
        || u64::try_from(ctx.actor.auth_generation).ok()
            != Some(after_metadata.author_auth_generation_at_origin())
    {
        return Err(ExecutorError::InconsistentPlan(
            "reset metadata delta/context does not bind the signed successor",
        ));
    }

    // Validate entry/event shapes exhaustively. UUIDs and predecessors are
    // server-minted, but every security-relevant recipient, entitlement,
    // event kind, and outbox direction is fixed here before any write.
    let entry_devices = ctx
        .entry_recipients
        .iter()
        .map(|(device, entitlement)| {
            if *entitlement != EntryEntitlementKind::IntervalClose {
                return Err(ExecutorError::InconsistentPlan(
                    "reset entry recipient has the wrong entitlement",
                ));
            }
            Ok(device.clone())
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if entry_devices != closed_devices || entry_devices.len() != ctx.entry_recipients.len() {
        return Err(ExecutorError::InconsistentPlan(
            "reset entry audience is not complete/bijective",
        ));
    }
    let disposition_devices = ctx
        .welcome_dispositions
        .iter()
        .map(|input| {
            let welcome = effects
                .welcome_changes()
                .iter()
                .find_map(|change| {
                    change.after().filter(|after| {
                        // BOTH terminal rows carry a `welcomeDisposition` event.
                        // Which row this is was already proved exactly by
                        // `classify_prior_bound_staling` above; here we only need
                        // the delta the disposition event belongs to, so pinning
                        // `Superseded` alone rejected the legal due-expiry row.
                        after.welcome_id == *input.welcome_id.as_bytes()
                            && matches!(
                                after.status,
                                WelcomeStatus::Superseded | WelcomeStatus::Expired
                            )
                    })
                })
                .ok_or(ExecutorError::InconsistentPlan(
                    "reset Welcome disposition has no exact delta",
                ))?;
            let event = &input.event;
            if !super::is_uuid_v4(event.event_id.as_bytes())
                || event.event_kind != EventKind::WelcomeDisposition
                || event.payload_bytes.is_empty()
                || event.recipients.len() != 1
                || event.recipients[0].0 != welcome.recipient
                || event.recipients[0].1 != EventEntitlementKind::Welcome
                || event.outbox.len() != 1
                || !super::is_uuid_v4(event.outbox[0].0.as_bytes())
                || event.outbox[0].1 != OutboxWorkKind::Stream
            {
                return Err(ExecutorError::InconsistentPlan(
                    "reset Welcome disposition event has an illegal shape",
                ));
            }
            Ok(welcome.recipient.clone())
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let primary = &ctx.events[0];
    let primary_devices = primary
        .recipients
        .iter()
        .map(|(device, entitlement, _)| {
            if *entitlement != EventEntitlementKind::Participant {
                return Err(ExecutorError::InconsistentPlan(
                    "reset primary event has the wrong entitlement",
                ));
            }
            Ok(device.clone())
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected_primary = entry_devices
        .difference(&disposition_devices)
        .cloned()
        .collect::<BTreeSet<_>>();
    if !super::is_uuid_v4(primary.event_id.as_bytes())
        || primary.event_kind != EventKind::ConversationChanged
        || primary.payload_bytes.is_empty()
        || primary_devices != expected_primary
        || primary_devices.len() != primary.recipients.len()
        || primary.outbox.len() != 1
        || !super::is_uuid_v4(primary.outbox[0].0.as_bytes())
        || primary.outbox[0].1 != OutboxWorkKind::Stream
    {
        return Err(ExecutorError::InconsistentPlan(
            "reset primary event has an illegal shape/audience",
        ));
    }
    Ok(Uuid::from_bytes(signed_request_id))
}

/// Pure, complete effect-family validation for a leaf-recovery fulfillment.
/// This runs before the first repository writer. It classifies the arm's four
/// own edges and every legal prior-bound supersession/staling edge, proves the
/// cross-family request/package bijections, and validates the target leaf /
/// interval shape. The write phase retains applied-count reconciliation as a
/// second fence.
fn preflight_leaf_recovery_fulfillment(
    plan: &ConversationPersistencePlan,
    effects: &TransitionEffects,
    hydration: &ConversationStateHydration,
    ctx: &ExecutionContext,
    transition_id: Uuid,
    seq_i64: i64,
) -> Result<(FamilyCounts, PriorBoundPartition), ExecutorError> {
    reject_if_present("participant_changes", effects.participant_changes())?;
    reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
    reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
    if effects.revocation_target_cas().is_some()
        || effects.welcome_cas().is_some()
        || effects.invitation_quota_cas().is_some()
    {
        return Err(ExecutorError::UnsupportedEffect(
            "fulfillment revocation/welcome/quota CAS",
        ));
    }
    if effects
        .metadata_change()
        .and_then(StateChange::after)
        .is_none()
        || ctx.metadata_author.is_none()
    {
        return Err(ExecutorError::InconsistentPlan(
            "fulfillment carries no complete metadata re-encryption",
        ));
    }

    let producer = &hydration.producer;
    if producer.transition_id != *transition_id.as_bytes()
        || i64::try_from(producer.seq).ok() != Some(seq_i64)
    {
        return Err(ExecutorError::InconsistentPlan(
            "fulfillment producer disagrees with allocated transition/sequence",
        ));
    }

    // DEFECT 2 FIX. The two blocks this replaces demanded
    // `terminal_is_exact_transition` of EVERY recovery request and reservation
    // on the coordinate, so a peer's overdue `Expiry` terminal fell through to
    // the `_ => illegal direction` arm. Open recovery requests are unique per
    // TARGET and coordinate-preserving, so peers stack requests on one
    // coordinate with staggered `expires_at`; fulfilling one device while a
    // peer's request was overdue produced a planner-valid, executor-fatal plan,
    // and the recovering device wedged PERMANENTLY because retry re-planned the
    // identical shape. Prior-bound families are now classified, not rejected.
    let partition =
        classify_prior_bound_recovery(plan, ctx, OwnFamilyKind::LeafRecoveryFulfillment)?;
    let own_key = partition.own().ok_or(ExecutorError::InconsistentPlan(
        "fulfillment carries no own recovery family",
    ))?;
    let own_request = effects
        .recovery_request_changes()
        .iter()
        .filter_map(StateChange::after)
        .find(|request| (request.request_id, request.key_package_ref) == own_key)
        .ok_or(ExecutorError::InconsistentPlan(
            "fulfillment carries no own fulfilled recovery request",
        ))?;
    let own_reservation = effects
        .reservation_changes()
        .iter()
        .filter_map(StateChange::after)
        .find(|reservation| (reservation.request_id, reservation.key_package_ref) == own_key)
        .ok_or(ExecutorError::InconsistentPlan(
            "fulfillment carries no own consumed reservation",
        ))?;

    // Retained: the own package edge's driven-ref and direction check.
    verify_recovery_package_consistency(
        effects,
        &own_request.key_package_ref,
        PackageStatus::Reserved,
        PackageStatus::Consumed,
    )?;

    let own_cas = effects
        .recovery_package_cas()
        .iter()
        .filter(|binding| {
            binding.request_id == own_request.request_id
                && binding.key_package_ref == own_request.key_package_ref
                && binding.expected_status == PackageStatus::Reserved
                && binding.successor_status == PackageStatus::Consumed
        })
        .collect::<Vec<_>>();
    if own_cas.len() != 1
        || own_cas[0].target != own_request.target
        || own_cas[0].bound_coordinate != own_request.bound_coordinate
        || own_cas[0].package_not_after != own_reservation.package_not_after
    {
        return Err(ExecutorError::InconsistentPlan(
            "fulfillment package CAS disagrees with own open work",
        ));
    }

    let mut own_welcome: Option<&WelcomeWork> = None;
    let mut superseded_welcomes = BTreeSet::new();
    for change in effects.welcome_changes() {
        match (change.before(), change.after()) {
            (None, Some(after))
                if after.status == WelcomeStatus::Pending && after.terminal.is_none() =>
            {
                if own_welcome.replace(after).is_some() {
                    return Err(ExecutorError::InconsistentPlan(
                        "fulfillment carries multiple own pending welcomes",
                    ));
                }
            }
            (Some(before), Some(after))
                if welcome_identity_is_unchanged(before, after)
                    && before.status == WelcomeStatus::Pending
                    && after.status == WelcomeStatus::Superseded
                    && terminal_is_exact_transition(&after.terminal, producer) =>
            {
                if !superseded_welcomes.insert(after.welcome_id) {
                    return Err(ExecutorError::InconsistentPlan(
                        "fulfillment repeats a superseded Welcome",
                    ));
                }
            }
            _ => {
                return Err(ExecutorError::InconsistentPlan(
                    "fulfillment welcome change has an illegal shape",
                ))
            }
        }
    }
    let own_welcome = own_welcome.ok_or(ExecutorError::InconsistentPlan(
        "fulfillment carries no own pending welcome",
    ))?;
    if own_welcome.recipient != own_request.target
        || own_welcome.recovery_request_id != own_request.request_id
        || own_welcome.key_package_ref != own_request.key_package_ref
        || own_welcome.coordinate != hydration.coordinate
        || i64::try_from(own_welcome.transition_seq).ok() != Some(seq_i64)
        || own_welcome.expires_at != own_reservation.package_not_after
        || own_welcome.sha256 != <[u8; 32]>::from(sha2::Sha256::digest(&own_welcome.opaque_welcome))
    {
        return Err(ExecutorError::InconsistentPlan(
            "fulfillment pending Welcome is not bijective with own work/successor",
        ));
    }
    let disposition_welcomes = ctx
        .welcome_dispositions
        .iter()
        .map(|input| *input.welcome_id.as_bytes())
        .collect::<BTreeSet<_>>();
    if disposition_welcomes.len() != ctx.welcome_dispositions.len()
        || disposition_welcomes != superseded_welcomes
    {
        return Err(ExecutorError::InconsistentPlan(
            "fulfillment Welcome dispositions are not bijective",
        ));
    }

    let mut staled_resets = BTreeSet::new();
    for change in effects.reset_request_changes() {
        let (Some(before), Some(after)) = (change.before(), change.after()) else {
            return Err(ExecutorError::InconsistentPlan(
                "fulfillment reset request change is not terminal",
            ));
        };
        if !reset_request_identity_is_unchanged(before, after)
            || before.status != ResetRequestStatus::Pending
            || after.status != ResetRequestStatus::Stale
            || !terminal_is_exact_transition(&after.terminal, producer)
        {
            return Err(ExecutorError::InconsistentPlan(
                "fulfillment reset request change is not exact prior-bound staling",
            ));
        }
        if !staled_resets.insert(after.request_id) {
            return Err(ExecutorError::InconsistentPlan(
                "fulfillment repeats a staled reset request",
            ));
        }
    }
    let mut staled_leaves = BTreeSet::new();
    for change in effects.leave_request_changes() {
        let (Some(before), Some(after)) = (change.before(), change.after()) else {
            return Err(ExecutorError::InconsistentPlan(
                "fulfillment leave request change is not terminal",
            ));
        };
        if !leave_request_identity_is_unchanged(before, after)
            || before.status != LeaveRequestStatus::Pending
            || after.status != LeaveRequestStatus::Stale
            || !terminal_is_exact_transition(&after.terminal, producer)
        {
            return Err(ExecutorError::InconsistentPlan(
                "fulfillment leave request change is not exact prior-bound staling",
            ));
        }
        if !staled_leaves.insert(after.request_id) {
            return Err(ExecutorError::InconsistentPlan(
                "fulfillment repeats a staled leave request",
            ));
        }
    }

    let target = &own_request.target;
    let mut target_leaf_is_replace = None;
    let mut changed_leaf_devices = BTreeSet::new();
    for change in effects.leaf_changes() {
        match (change.before(), change.after()) {
            (None, Some(after))
                if after.device() == target
                    && hydration
                        .leaves
                        .iter()
                        .any(|row| leaf_matches_hydration(after, row)) =>
            {
                if target_leaf_is_replace.replace(false).is_some() {
                    return Err(ExecutorError::InconsistentPlan(
                        "fulfillment repeats the target leaf change",
                    ));
                }
            }
            (Some(before), Some(after))
                if before.device() == target
                    && after.device() == target
                    && before != after
                    && hydration
                        .leaves
                        .iter()
                        .any(|row| leaf_matches_hydration(after, row)) =>
            {
                if target_leaf_is_replace.replace(true).is_some() {
                    return Err(ExecutorError::InconsistentPlan(
                        "fulfillment repeats the target leaf change",
                    ));
                }
            }
            (Some(before), Some(after))
                if before.device() == after.device()
                    && hydration
                        .leaves
                        .iter()
                        .any(|row| leaf_matches_hydration(after, row)) => {}
            _ => {
                return Err(ExecutorError::InconsistentPlan(
                    "fulfillment carries an unexpected leaf change",
                ))
            }
        }
        let device = change
            .after()
            .expect("every accepted fulfillment leaf change has an after")
            .device()
            .clone();
        if !changed_leaf_devices.insert(device) {
            return Err(ExecutorError::InconsistentPlan(
                "fulfillment repeats a changed leaf device",
            ));
        }
    }
    let is_replace = target_leaf_is_replace.ok_or(ExecutorError::InconsistentPlan(
        "fulfillment carries no target leaf change",
    ))?;
    if is_replace != (own_request.kind == LeafRecoveryKind::Replace)
        || (!is_replace && own_request.kind != LeafRecoveryKind::Add)
        || hydration
            .leaves
            .iter()
            .filter(|leaf| &leaf.device == target)
            .count()
            != 1
        || ctx.opened_leaves.len() != 1
        || ctx
            .opened_leaves
            .iter()
            .filter(|leaf| &leaf.device == target)
            .count()
            != 1
        || ctx.leaf_period_ids.len() != 1
        || ctx.closing_leaf_periods.len() != usize::from(is_replace)
    {
        return Err(ExecutorError::InconsistentPlan(
            "fulfillment target leaf/context shape disagrees with request kind",
        ));
    }

    let mut opened_intervals = 0usize;
    let mut closed_intervals = 0usize;
    for change in effects.interval_changes() {
        match (change.before(), change.after()) {
            (None, Some(after))
                if after.recipient() == target
                    && after.opening_kind() == super::OpeningKind::Add
                    && after.opening == *producer
                    && after.generation == hydration.coordinate.generation()
                    && after.end().is_none()
                    && after.opening_context() == &hydration.coordinate =>
            {
                opened_intervals += 1;
            }
            (Some(before), Some(after))
                if interval_identity_is_unchanged(before, after)
                    && before.recipient() == target
                    && after.recipient() == target
                    && after.end().is_some_and(|end| {
                        end.kind() == CloseKind::Replace && end.evidence == *producer
                    }) =>
            {
                closed_intervals += 1;
            }
            _ => {
                return Err(ExecutorError::InconsistentPlan(
                    "fulfillment interval change has an illegal shape/binding",
                ))
            }
        }
    }
    if opened_intervals != 1 || closed_intervals != usize::from(is_replace) {
        return Err(ExecutorError::InconsistentPlan(
            "fulfillment interval changes do not match the request kind",
        ));
    }

    let prior_bound = FamilyCounts {
        // Rebuilt from the classifier's typed partition, over ALL classified
        // prior-bound keys (Row A and Row B). welcomes/reset_requests/
        // leave_requests keep their own locals — those families are outside
        // the classifier's scope, and zeroing them would fail the fence.
        requests: partition.requests(),
        reservations: partition.reservations(),
        packages: partition.packages(),
        welcomes: superseded_welcomes.len(),
        reset_requests: staled_resets.len(),
        leave_requests: staled_leaves.len(),
    };
    reconcile_coordinate_change_families(
        effects,
        &FamilyCounts {
            requests: 1,
            reservations: 1,
            packages: 1,
            welcomes: 1,
            reset_requests: 0,
            leave_requests: 0,
        },
        &prior_bound,
    )?;
    Ok((prior_bound, partition))
}

#[derive(Debug)]
struct MetadataExecutionBinding<'a> {
    metadata: &'a MetadataSnapshotBinding,
    author: &'a MetadataAuthorColumns,
    avatar: Option<&'a MetadataAvatarPersistence>,
    /// The classified prior-bound families, carried to `apply_metadata_transition`
    /// so it reconciles the writer's receipt against them before any other writer
    /// runs (design 5 step 6).
    prior_bound: PriorBoundPartition,
}

/// Re-derive the complete metadata-transition contract from the sealed plan
/// and repository-hydrated context before the first writer runs.
///
/// A metadata transition is a coordinate-only successor: same generation
/// and MLS crypto coordinate, `state_version + 1`, one signed self-origin
/// metadata snapshot, and no membership/leaf/interval mutation. It may
/// terminalize work bound to the retired coordinate; every such family is
/// classified here and reconciled again after its writer runs.
fn preflight_metadata_transition<'a>(
    plan: &'a ConversationPersistencePlan,
    ctx: &'a ExecutionContext,
    transition_id: Uuid,
    seq_i64: i64,
) -> Result<MetadataExecutionBinding<'a>, ExecutorError> {
    let effects = plan.effects();
    let hydration = plan.state();
    let head = effects
        .head_cas()
        .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
    let prior = head
        .expected_prior()
        .ok_or(ExecutorError::InconsistentPlan(
            "metadata transition needs an expected prior",
        ))?;
    let expected_next = coordinate_only_successor(prior).map_err(|_| {
        ExecutorError::InconsistentPlan("metadata successor is not coordinate-only")
    })?;
    if effects.kind() != PlanKind::Metadata
        || plan.expected_prior.as_ref() != Some(prior)
        || plan.retired_coordinate.is_some()
        || plan.successor_coordinate.as_ref() != Some(&expected_next)
        || hydration.coordinate != expected_next
        || head.conversation_id() != prior.conversation_id()
        || head.allocated_entry_id() != Some(transition_id.as_bytes())
        || head
            .allocated_seq()
            .and_then(|value| i64::try_from(value).ok())
            != Some(seq_i64)
        || head
            .expected_next_entry_seq()
            .checked_add(1)
            .filter(|value| *value == head.successor_next_entry_seq())
            .is_none()
    {
        return Err(ExecutorError::InconsistentPlan(
            "metadata plan/head/coordinate binding drifted",
        ));
    }

    let producer = &hydration.producer;
    let authority = match effects.authority() {
        Some(PlanAuthority::Transition(authority)) if authority == producer => authority,
        _ => {
            return Err(ExecutorError::InconsistentPlan(
                "metadata plan lacks its exact transition authority",
            ))
        }
    };
    let signed = authority
        .authority
        .as_ref()
        .ok_or(ExecutorError::InconsistentPlan(
            "metadata transition lacks signed authority",
        ))?;
    let actor_did = device_did(&signed.actor)?;
    let actor_key_id = URL_SAFE_NO_PAD.encode(signed.key_id);
    if signed.kind != SignedMutationKind::MetadataTransition
        || signed.control_entry_id != Some(*transition_id.as_bytes())
        || signed.control_conversation_id != Some(*prior.conversation_id())
        || authority.transition_id != *transition_id.as_bytes()
        || i64::try_from(authority.seq).ok() != Some(seq_i64)
        || authority.received_at != head.locked_at()
        || ctx.applied_at != server_instant(authority.received_at)?
        || ctx.entry().entry_id != transition_id
        || ctx.entry().signed_request_bytes != signed.signed_request_bytes
        || ctx.entry().unsigned_projection_bytes != signed.canonical_projection
        || ctx.entry().signing_transcript_bytes != signed.transcript_bytes
        || ctx.entry().request_digest.as_slice() != signed.request_digest
        || ctx.entry().signature.as_slice() != signed.signature
        || ctx.entry().outer_entry_fingerprint.as_slice() != authority.outer_entry_fingerprint
        || ctx.entry().server_fields_bytes != authority.server_fields_dag_cbor
        || ctx.actor.user_did != actor_did
        || ctx.actor.device_id != device_uuid(&signed.actor)
        || ctx.actor.key_id != actor_key_id
        || u64::try_from(ctx.actor.auth_generation).ok() != Some(signed.auth_generation)
        || ctx.actor.role != TransitionActorRole::Admin
        || ctx.actor.device_status != "active"
    {
        return Err(ExecutorError::InconsistentPlan(
            "metadata signed/control/actor authority drifted",
        ));
    }

    let metadata_change = effects
        .metadata_change()
        .ok_or(ExecutorError::InconsistentPlan(
            "metadata transition has no metadata delta",
        ))?;
    let (Some(before), Some(after)) = (metadata_change.before(), metadata_change.after()) else {
        return Err(ExecutorError::InconsistentPlan(
            "metadata transition delta is not a replacement",
        ));
    };
    let signed_metadata = match authority.body_binding.as_ref() {
        Some(TransitionBodyBinding::Metadata {
            prior: signed_prior,
            next: signed_next,
            metadata,
        }) if signed_prior == prior && signed_next == &expected_next => metadata,
        _ => {
            return Err(ExecutorError::InconsistentPlan(
                "metadata transition body binding drifted",
            ))
        }
    };
    let expected_version = before.metadata_version().checked_add(1);
    if after != signed_metadata
        || hydration.metadata.as_ref() != Some(after)
        || hydration.metadata_producer.as_ref() != Some(authority)
        || !metadata_coordinate_matches(before, prior)
        || !metadata_coordinate_matches(after, &expected_next)
        || expected_version != Some(after.metadata_version())
        || after.origin_transition_id() != transition_id.as_bytes()
        || after.author_origin_transition_id() != transition_id.as_bytes()
        || i64::try_from(after.author_origin_seq()).ok() != Some(seq_i64)
        || after.nonce() == before.nonce()
        || after.author() != &signed.actor
        || !metadata_author_matches_evidence(after, authority)
    {
        return Err(ExecutorError::InconsistentPlan(
            "metadata snapshot provenance/version/nonce drifted",
        ));
    }
    let author = ctx
        .metadata_author
        .as_ref()
        .ok_or(ExecutorError::MissingContext(
            "metadata transition author columns",
        ))?;
    if author.author_role != "admin"
        || author.author_device_status != "active"
        || author.author_key_id != actor_key_id
        || author.author_public_key != after.signature_public_key()
        || u64::try_from(ctx.actor.auth_generation).ok()
            != Some(after.author_auth_generation_at_origin())
    {
        return Err(ExecutorError::InconsistentPlan(
            "metadata author columns disagree with signed provenance",
        ));
    }
    let avatar = match (after.avatar_binding(), ctx.metadata_avatar.as_ref()) {
        (None, None) => None,
        (Some(signed_avatar), Some(persistence)) => {
            let durable = persistence.snapshot();
            if durable.avatar_blob_id.as_bytes() != signed_avatar.blob_id()
                || durable.avatar_ciphertext_sha256.as_slice() != signed_avatar.ciphertext_sha256()
                || u64::try_from(durable.avatar_ciphertext_size).ok()
                    != Some(signed_avatar.ciphertext_size())
            {
                return Err(ExecutorError::InconsistentPlan(
                    "metadata avatar durable columns disagree with signed descriptor",
                ));
            }
            match persistence {
                MetadataAvatarPersistence::Reuse { .. } => {
                    if !before
                        .avatar_binding()
                        .is_some_and(|prior| prior == signed_avatar)
                    {
                        return Err(ExecutorError::InconsistentPlan(
                            "metadata avatar reuse lacks an exact signed predecessor",
                        ));
                    }
                }
                MetadataAvatarPersistence::Fresh { binding, .. } => {
                    if before
                        .avatar_binding()
                        .is_some_and(|prior| prior.blob_id() == signed_avatar.blob_id())
                        || durable.avatar_binding_origin_transition_id != transition_id
                        || u64::try_from(durable.avatar_binding_metadata_version).ok()
                            != Some(after.metadata_version())
                        || durable.avatar_binding_owner_did != actor_did
                        || durable.avatar_binding_owner_device_id != device_uuid(after.author())
                        || binding.blob_id.as_bytes() != signed_avatar.blob_id()
                        || binding.ciphertext_sha256.as_slice() != signed_avatar.ciphertext_sha256()
                        || u64::try_from(binding.ciphertext_size).ok()
                            != Some(signed_avatar.ciphertext_size())
                        || binding.descriptor_bytes != signed_avatar.canonical_descriptor()
                        || binding.descriptor_sha256.as_slice() != signed_avatar.digest()
                        || binding.binding_kind != BindingKind::MetadataAvatar
                        || binding.conversation_id
                            != Uuid::from_bytes(*after.coordinate_conversation_id())
                        || binding.entry_seq.is_some()
                        || binding.message_id.is_some()
                        || binding.metadata_origin_transition_id != Some(transition_id)
                        || binding.metadata_version != i64::try_from(after.metadata_version()).ok()
                        || binding.owner_did != actor_did
                        || binding.owner_device_id != device_uuid(after.author())
                        || binding.purpose != BlobPurpose::Metadata
                        || binding.ciphertext_size
                            != binding.plaintext_size.saturating_add(blobs::AEAD_TAG_BYTES)
                        || binding.aad_bytes.is_empty()
                        || sha2::Sha256::digest(&binding.aad_bytes).as_slice() != binding.aad_sha256
                        || binding.bound_at != ctx.applied_at
                        || binding.uploaded_at > binding.bound_at
                        || binding.bound_at >= binding.unbound_expires_at
                    {
                        return Err(ExecutorError::InconsistentPlan(
                            "metadata fresh avatar lock/binding authority drifted",
                        ));
                    }
                }
            }
            Some(persistence)
        }
        _ => {
            return Err(ExecutorError::InconsistentPlan(
                "metadata avatar signed/context presence drifted",
            ))
        }
    };

    reject_if_present("participant_changes", effects.participant_changes())?;
    reject_if_present("leaf_changes", effects.leaf_changes())?;
    reject_if_present("interval_changes", effects.interval_changes())?;
    reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
    reject_if_present("opened_intervals", effects.opened_intervals())?;
    reject_if_present("closed_intervals", effects.closed_intervals())?;
    reject_if_present(
        "terminal_proof_recipients",
        effects.terminal_proof_recipients(),
    )?;
    reject_if_present(
        "superseded_recovery_requests",
        effects.superseded_recovery_requests(),
    )?;
    reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
    if effects.policy_evidence_digest().is_some()
        || effects.revocation_target_cas().is_some()
        || effects.welcome_cas().is_some()
        || effects.invitation_quota_cas().is_some()
    {
        return Err(ExecutorError::UnsupportedEffect(
            "metadata transition carries unrelated authority effects",
        ));
    }
    if !ctx.opened_leaves.is_empty()
        || !ctx.participant_period_ids.is_empty()
        || !ctx.leaf_period_ids.is_empty()
        || !ctx.closing_leaf_periods.is_empty()
        || !ctx.closing_participant_periods.is_empty()
        || ctx.reset_request_row.is_some()
        || ctx.recovery_open.is_some()
        || ctx.welcome_expiry.is_some()
        || ctx.welcome_response.is_some()
        || !ctx.spine.genesis_group_info_bytes.is_empty()
        || !ctx.spine.genesis_group_info_sha256.is_empty()
        || sha2::Sha256::digest(&ctx.spine.public_snapshot_bytes).as_slice()
            != ctx.spine.public_snapshot_sha256
        || sha2::Sha256::digest(&ctx.spine.tree_summary_bytes).as_slice()
            != ctx.spine.tree_summary_sha256
    {
        return Err(ExecutorError::InconsistentPlan(
            "metadata transition carries unrelated or invalid execution context",
        ));
    }

    // Prior-bound recovery families. This block WAS the reference
    // implementation; it is now the shared classifier every one of the nine
    // coordinate-changing arms calls, strictly before its own first head CAS.
    let prior_bound_partition = classify_prior_bound_recovery(plan, ctx, OwnFamilyKind::None)?;
    // Prior-bound reset / leave / Welcome families. This block WAS the reference
    // implementation too; it is now `classify_prior_bound_staling`, shared with
    // the five arms that previously proved none of it.
    let welcome_ids = classify_prior_bound_staling(plan, ctx, OwnStalingKind::None)?;
    let disposition_ids = ctx
        .welcome_dispositions
        .iter()
        .map(|input| *input.welcome_id.as_bytes())
        .collect::<BTreeSet<_>>();
    if welcome_ids != disposition_ids || disposition_ids.len() != ctx.welcome_dispositions.len() {
        return Err(ExecutorError::InconsistentPlan(
            "metadata Welcome dispositions are not complete/bijective",
        ));
    }

    let expected_entry_devices = hydration
        .leaves
        .iter()
        .map(|leaf| leaf.device.clone())
        .collect::<BTreeSet<_>>();
    let entry_devices = ctx
        .entry_recipients
        .iter()
        .map(|(device, entitlement)| {
            if *entitlement != EntryEntitlementKind::Control {
                return Err(ExecutorError::InconsistentPlan(
                    "metadata entry recipient has the wrong entitlement",
                ));
            }
            Ok(device.clone())
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if entry_devices != expected_entry_devices || entry_devices.len() != ctx.entry_recipients.len()
    {
        return Err(ExecutorError::InconsistentPlan(
            "metadata entry audience is not complete/bijective",
        ));
    }
    let mut disposition_devices = BTreeSet::new();
    for input in &ctx.welcome_dispositions {
        let welcome = effects
            .welcome_changes()
            .iter()
            .find_map(|change| {
                change.after().filter(|after| {
                    after.welcome_id == *input.welcome_id.as_bytes()
                        && matches!(
                            after.status,
                            WelcomeStatus::Superseded | WelcomeStatus::Expired
                        )
                })
            })
            .ok_or(ExecutorError::InconsistentPlan(
                "metadata Welcome disposition has no exact terminal delta",
            ))?;
        let status = if welcome.status == WelcomeStatus::Expired {
            "expired"
        } else {
            "superseded"
        };
        let event = &input.event;
        if !super::is_uuid_v4(event.event_id.as_bytes())
            || event.event_kind != EventKind::WelcomeDisposition
            || event.payload_bytes
                != delivery::canonical_welcome_disposition_event_payload(input.welcome_id, status)
            || event.recipients.len() != 1
            || event.recipients[0].0 != welcome.recipient
            || event.recipients[0].1 != EventEntitlementKind::Welcome
            || event.outbox.len() != 1
            || !super::is_uuid_v4(event.outbox[0].0.as_bytes())
            || event.outbox[0].1 != OutboxWorkKind::Stream
            || !disposition_devices.insert(welcome.recipient.clone())
        {
            return Err(ExecutorError::InconsistentPlan(
                "metadata Welcome disposition event has an illegal shape",
            ));
        }
    }
    let primary = ctx.events.first().ok_or(ExecutorError::MissingContext(
        "metadata conversationChanged event",
    ))?;
    let primary_devices = primary
        .recipients
        .iter()
        .map(|(device, entitlement, _)| {
            if *entitlement != EventEntitlementKind::Participant {
                return Err(ExecutorError::InconsistentPlan(
                    "metadata primary event has the wrong entitlement",
                ));
            }
            Ok(device.clone())
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected_primary = entry_devices
        .difference(&disposition_devices)
        .cloned()
        .collect::<BTreeSet<_>>();
    let canonical_primary = format!(
        r#"{{"$type":"blue.catbird.chat.defs#conversationChangedEvent","conversationId":"{}"}}"#,
        Uuid::from_bytes(*prior.conversation_id()).hyphenated(),
    )
    .into_bytes();
    if ctx.events.len() != 1
        || !super::is_uuid_v4(primary.event_id.as_bytes())
        || primary.event_kind != EventKind::ConversationChanged
        || primary.payload_bytes != canonical_primary
        || primary_devices != expected_primary
        || primary_devices.len() != primary.recipients.len()
        || primary.outbox.len() != 1
        || !super::is_uuid_v4(primary.outbox[0].0.as_bytes())
        || primary.outbox[0].1 != OutboxWorkKind::Stream
        || usize::try_from(ctx.spine.leaf_count).ok() != Some(hydration.leaves.len())
        || ctx.spine.public_snapshot_bytes.is_empty()
        || ctx.spine.tree_summary_bytes.is_empty()
    {
        return Err(ExecutorError::InconsistentPlan(
            "metadata primary event/audience/spine shape drifted",
        ));
    }

    Ok(MetadataExecutionBinding {
        prior_bound: prior_bound_partition,
        metadata: after,
        author,
        avatar,
    })
}

/// Apply one `ConversationPersistencePlan` inside the caller's transaction.
///
/// Transaction-scoped: never begins or commits. Ordered per the E2b-2 design
/// (head → generation → generation_state → entry → transition → metadata →
/// families → audience → events). Every effect family is consumed
/// exhaustively; a non-empty family this path does not handle is a hard
/// `UnsupportedEffect`, never a silent skip.
async fn apply_conversation_persistence_plan_inner(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &ConversationPersistencePlan,
    ctx: &ExecutionContext,
    recovery_write_authority: Option<
        &super::super::repository::recovery::RecoveryExecutorWriteAuthority<'_>,
    >,
    historical_write_authority: Option<&HistoricalExecutionWriteAuthority>,
) -> Result<AppliedTransition, ExecutorError> {
    let effects = plan.effects();
    require_execution_authority(effects.kind(), &ctx.authority)?;
    let head = effects
        .head_cas()
        .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
    let hydration = plan.state();
    let coordinate = &hydration.coordinate;
    let conversation_id = Uuid::from_bytes(*coordinate.conversation_id());
    let transition_id = Uuid::from_bytes(*hydration.producer.transition_id());
    let generation = checked_i64(coordinate.generation())?;
    let state_version = checked_i64(coordinate.state_version())?;
    let epoch = checked_i64(coordinate.epoch())?;

    // Dispatch split: entry-less internal ops vs entry-bearing edges.
    //
    // `leafRecoveryRequest` / `leafRecoveryCancellation` are INTERNAL — there
    // is no control-entry kind for them (`bind_non_control_request_authority`:
    // `allocated_seq == None`, `successor_next_entry_seq == expected`), so they
    // append NO entry and allocate NO seq, and their head CAS is a
    // prior-coordinate VERIFY that advances neither the coordinate nor the
    // counter. Branch on these BEFORE the entry-bearing `allocated_seq`
    // extraction (which would otherwise `InconsistentPlan` on their `None`
    // seq). Every OTHER plan kind is entry-bearing (creation / policy / accept
    // / commit / close / reset-activation / fulfillment) and allocates a seq.
    match effects.kind() {
        PlanKind::RecoveryRequest => {
            return apply_leaf_recovery_request(
                transaction,
                plan,
                ctx,
                conversation_id,
                generation,
                state_version,
                epoch,
                recovery_write_authority,
            )
            .await;
        }
        PlanKind::RecoveryCancellation => {
            return apply_leaf_recovery_cancellation(
                transaction,
                plan,
                ctx,
                conversation_id,
                generation,
                state_version,
                epoch,
                recovery_write_authority,
            )
            .await;
        }
        PlanKind::RecoveryExpiry => {
            return apply_leaf_recovery_expiry(
                transaction,
                plan,
                ctx,
                conversation_id,
                generation,
                state_version,
                epoch,
                recovery_write_authority,
            )
            .await;
        }
        // `welcomeExpiry` is ALSO entry-less (server-observed pending-only CAS,
        // `bind_welcome_expiry_authority`: `allocated_seq == None`, coordinate +
        // seq counter UNCHANGED) — dispatch it here before the `allocated_seq`
        // extraction would `InconsistentPlan` on its `None` seq.
        PlanKind::WelcomeExpiry => {
            return apply_welcome_expiry(
                transaction,
                plan,
                ctx,
                conversation_id,
                generation,
                state_version,
                epoch,
            )
            .await;
        }
        // `welcomeAcknowledgement` / `welcomeRejection` are entry-less signed
        // non-control responses (`bind_non_control_request_authority`:
        // `allocated_seq == None`, coordinate + seq UNCHANGED) — dispatch here.
        PlanKind::WelcomeAcknowledgement | PlanKind::WelcomeRejection => {
            return apply_welcome_response(
                transaction,
                plan,
                ctx,
                conversation_id,
                generation,
                state_version,
                epoch,
            )
            .await;
        }
        // `deviceRevocation` is entry-less and coordinate-UNCHANGED (a global
        // signed authority op; `bind_device_revocation_authority`:
        // `allocated_seq == None`, successor coordinate == prior). It closes
        // NO leaf / interval — it only supersedes the target's own recovery
        // requests / reservations / welcomes and revokes their packages, all
        // bound to the revocation id. Dispatch here before the entry-bearing
        // `allocated_seq` extraction would `InconsistentPlan` on its `None` seq.
        PlanKind::DeviceRevocation => {
            return apply_device_revocation(
                transaction,
                plan,
                ctx,
                conversation_id,
                generation,
                state_version,
                epoch,
                None,
            )
            .await;
        }
        _ => {}
    }

    let allocated_seq = head.allocated_seq().ok_or(ExecutorError::InconsistentPlan(
        "head CAS has no allocated seq",
    ))?;
    let seq_i64 = checked_i64(allocated_seq)?;
    let successor_next_entry_seq = checked_i64(head.successor_next_entry_seq())?;

    match effects.kind() {
        PlanKind::Creation => {
            apply_creation(
                transaction,
                plan,
                ctx,
                conversation_id,
                transition_id,
                seq_i64,
                successor_next_entry_seq,
                generation,
                state_version,
                epoch,
                historical_write_authority,
            )
            .await
        }
        PlanKind::Policy => {
            apply_policy(
                transaction,
                plan,
                ctx,
                conversation_id,
                transition_id,
                seq_i64,
                successor_next_entry_seq,
                generation,
                state_version,
                epoch,
                historical_write_authority,
            )
            .await
        }
        // Every other plan kind is a real, planned edge this executor slice
        // does not yet compose. It is a HARD error (never a silent skip), so a
        // caller cannot mistake "not implemented" for "applied". The
        // remaining kinds (acceptConversation, metadata, commit, reset
        // request/activation, leave family, welcome dispositions, device
        // revocation, close) are the E2b-3 remainder — see the report.
        PlanKind::Acceptance => {
            apply_acceptance(
                transaction,
                plan,
                ctx,
                conversation_id,
                transition_id,
                seq_i64,
                successor_next_entry_seq,
                generation,
                state_version,
                epoch,
                historical_write_authority,
            )
            .await
        }
        PlanKind::Metadata => {
            apply_metadata_transition(
                transaction,
                plan,
                ctx,
                conversation_id,
                transition_id,
                seq_i64,
                successor_next_entry_seq,
                generation,
                state_version,
                epoch,
            )
            .await
        }
        PlanKind::Commit => {
            // Three `PlanKind::Commit` shapes, partitioned by their own edges.
            //
            // PARTITION PROOF (exhaustive + mutually exclusive by construction —
            // the planners are the authority):
            //   * A LEAVE fulfillment is the ONLY `Commit` whose planner
            //     (`plan_leave_fulfillment_inner`) terminalizes a leave request as
            //     FULFILLED (`Pending->Fulfilled`); it removes members and emits NO
            //     new Welcome. The discriminator matches that exact edge — NOT any
            //     leave-request delta: EVERY coordinate-advancing commit (generic /
            //     recovery / leave) may ALSO carry a prior-bound `Pending->Stale`
            //     leave staling (a co-pending leave request the coordinate change
            //     retired), which must NOT be read as a fulfillment.
            //   * A leaf-recovery fulfillment (`plan_leaf_recovery_fulfillment_inner`)
            //     ALWAYS emits exactly one NEW Welcome (`None->Some`, how the
            //     recovered target joins) and NEVER FULFILLS a leave request (though
            //     it may stale one).
            //   * A generic commit (`plan_commit_inner`) does NEITHER — no leave
            //     FULFILLMENT and no `None->Some` welcome. It may canonically remove
            //     leaves (closing their application intervals), and its only welcome
            //     delta is a prior-bound `Pending->Superseded`.
            // The two predicates are therefore disjoint (a Pending->Fulfilled leave
            // edge vs. a None->Some welcome are never both set) and exhaustive
            // (their negation is exactly the generic commit). Each branch's own
            // exact-shape guards (leave requires exactly one leave-request +
            // participant close; recovery requires exactly one own request/
            // reservation/package/new welcome; generic rejects participant and Add
            // membership deltas while enforcing Remove/interval bijection) HARD-error
            // a mis-partitioned plan rather than mis-applying it —
            // the discriminator is backstopped, never load-bearing alone.
            let is_leave_fulfillment = effects.leave_request_changes().iter().any(|change| {
                matches!(
                    (change.before(), change.after()),
                    (Some(before), Some(after))
                        if before.status() == LeaveRequestStatus::Pending
                            && after.status() == LeaveRequestStatus::Fulfilled
                )
            });
            let is_recovery_fulfillment = effects
                .welcome_changes()
                .iter()
                .any(|change| matches!((change.before(), change.after()), (None, Some(_))));
            if is_leave_fulfillment {
                apply_leave_fulfillment(
                    transaction,
                    plan,
                    ctx,
                    conversation_id,
                    transition_id,
                    seq_i64,
                    successor_next_entry_seq,
                    generation,
                    state_version,
                    epoch,
                )
                .await
            } else if is_recovery_fulfillment {
                apply_leaf_recovery_fulfillment(
                    transaction,
                    plan,
                    ctx,
                    conversation_id,
                    transition_id,
                    seq_i64,
                    successor_next_entry_seq,
                    generation,
                    state_version,
                    epoch,
                    recovery_write_authority,
                    historical_write_authority,
                )
                .await
            } else {
                apply_generic_commit(
                    transaction,
                    plan,
                    ctx,
                    conversation_id,
                    transition_id,
                    seq_i64,
                    successor_next_entry_seq,
                    generation,
                    state_version,
                    epoch,
                )
                .await
            }
        }
        // Entry-less internal ops are dispatched (and returned) above, before
        // the entry-bearing `allocated_seq` extraction.
        PlanKind::RecoveryRequest | PlanKind::RecoveryCancellation | PlanKind::RecoveryExpiry => {
            unreachable!("entry-less recovery ops are dispatched before this match")
        }
        // Entry-less; dispatched (and returned) above.
        PlanKind::DeviceRevocation => {
            unreachable!("entry-less device revocation is dispatched before this match")
        }
        PlanKind::ResetRequest => {
            apply_reset_request(
                transaction,
                plan,
                ctx,
                conversation_id,
                seq_i64,
                successor_next_entry_seq,
                generation,
                state_version,
                epoch,
            )
            .await
        }
        PlanKind::ResetActivation => {
            apply_reset_activation(
                transaction,
                plan,
                ctx,
                conversation_id,
                transition_id,
                seq_i64,
                successor_next_entry_seq,
                generation,
                state_version,
                epoch,
            )
            .await
        }
        PlanKind::LeaveRequest => {
            apply_leave_request(
                transaction,
                plan,
                ctx,
                conversation_id,
                seq_i64,
                successor_next_entry_seq,
                generation,
                state_version,
                epoch,
            )
            .await
        }
        PlanKind::LeaveCancellation => {
            apply_leave_cancellation(
                transaction,
                plan,
                ctx,
                conversation_id,
                seq_i64,
                successor_next_entry_seq,
                generation,
                state_version,
                epoch,
            )
            .await
        }
        PlanKind::ZeroLeafLeave => {
            apply_zero_leaf_leave(
                transaction,
                plan,
                ctx,
                conversation_id,
                transition_id,
                seq_i64,
                successor_next_entry_seq,
                generation,
                state_version,
                epoch,
            )
            .await
        }
        // Entry-less; dispatched (and returned) above.
        PlanKind::WelcomeAcknowledgement | PlanKind::WelcomeRejection | PlanKind::WelcomeExpiry => {
            unreachable!("entry-less welcome disposition ops are dispatched before this match")
        }
        PlanKind::Close => {
            apply_close(
                transaction,
                plan,
                ctx,
                conversation_id,
                transition_id,
                seq_i64,
                successor_next_entry_seq,
                generation,
                state_version,
                epoch,
            )
            .await
        }
    }
}

/// Apply one repository-prepared plan inside a nested SQL savepoint.
///
/// Every returned body error explicitly rolls the savepoint back before the
/// caller regains the outer transaction. Cancellation or panic drops SQLx's
/// live nested `Transaction`, which queues `ROLLBACK TO SAVEPOINT` on this
/// same PostgreSQL connection. The caller may reuse the outer transaction
/// only after a same-connection round trip succeeds and therefore drains
/// that queued rollback. Transaction-identity or savepoint infrastructure
/// errors still require the outer transaction to be abandoned.
pub(crate) async fn apply_conversation_persistence_plan(
    prepared: PreparedConversationExecution<'_, '_, '_>,
) -> Result<AppliedTransition, ExecutorError> {
    let PreparedConversationExecution {
        transaction,
        plan,
        context,
        expected_transaction_id,
        recovery_write_authority,
        historical_write_authority,
        _proof,
        #[cfg(any(
            test,
            all(
                feature = "chat-protocol-production-proof",
                not(feature = "server-bin")
            )
        ))]
        drop_safety_probe,
    } = prepared;
    let mut savepoint = transaction
        .begin()
        .await
        .map_err(ExecutorError::SavepointBegin)?;
    let live_transaction_id: Result<String, sqlx::Error> =
        sqlx::query_scalar("SELECT txid_current()::text")
            .fetch_one(&mut *savepoint)
            .await;
    let operation = match live_transaction_id {
        Ok(live_transaction_id)
            if live_transaction_id == expected_transaction_id.as_ref()
                && plan_transaction_bindings_match(plan, expected_transaction_id.as_ref()) =>
        {
            apply_conversation_persistence_plan_inner(
                &mut savepoint,
                plan,
                &context,
                recovery_write_authority.as_ref(),
                historical_write_authority.as_ref(),
            )
            .await
        }
        Ok(_) => Err(ExecutorError::TransactionBindingMismatch),
        Err(error) => Err(ExecutorError::TransactionIdentity(error)),
    };
    match operation {
        Ok(applied) => {
            #[cfg(any(
                test,
                all(
                    feature = "chat-protocol-production-proof",
                    not(feature = "server-bin")
                )
            ))]
            if let Some(probe) = drop_safety_probe {
                probe.reach().await;
            }
            savepoint
                .commit()
                .await
                .map_err(ExecutorError::SavepointRelease)?;
            Ok(applied)
        }
        Err(operation) => match savepoint.rollback().await {
            Ok(()) => Err(operation),
            Err(rollback) => Err(ExecutorError::SavepointRollback {
                operation: Box::new(operation),
                rollback,
            }),
        },
    }
}

/// Raw executor seam retained only for cfg(test) mutation/shape harnesses.
/// Its explicit name prevents it from shadowing or being counted as the
/// production prepared-capsule path above.
#[cfg(test)]
pub(crate) async fn apply_conversation_persistence_plan_unscoped_for_test(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &ConversationPersistencePlan,
    context: &ExecutionContext,
) -> Result<AppliedTransition, ExecutorError> {
    apply_conversation_persistence_plan_inner(transaction, plan, context, None, None).await
}

/// Apply an entry-less `leafRecoveryRequest` internal op. The coordinate and
/// seq counter are UNCHANGED (the head CAS is a prior-coordinate verify); it
/// opens the `add`/`replace` recovery request + reservation and reserves the
/// requester's key package, all bound to the CURRENT coordinate. No entry, no
/// transition, no generation state, no participant change.
#[allow(clippy::too_many_arguments)]
async fn apply_leaf_recovery_request(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &ConversationPersistencePlan,
    ctx: &ExecutionContext,
    conversation_id: Uuid,
    generation: i64,
    state_version: i64,
    _epoch: i64,
    recovery_write_authority: Option<
        &super::super::repository::recovery::RecoveryExecutorWriteAuthority<'_>,
    >,
) -> Result<AppliedTransition, ExecutorError> {
    let effects = plan.effects();
    #[cfg(test)]
    let applied_at = ctx.applied_at;
    let head = effects
        .head_cas()
        .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
    let expected_prior = head
        .expected_prior()
        .ok_or(ExecutorError::InconsistentPlan(
            "leaf recovery request needs a prior",
        ))?;
    let expected_generation = checked_i64(expected_prior.generation())?;
    let expected_state_version = checked_i64(expected_prior.state_version())?;
    let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;
    let successor_next_entry_seq = checked_i64(head.successor_next_entry_seq())?;

    // Internal op: only a new open recovery request + its reservation + the
    // Available->Reserved package edge. Everything else must be empty.
    reject_if_present("participant_changes", effects.participant_changes())?;
    reject_if_present("leaf_changes", effects.leaf_changes())?;
    reject_if_present("interval_changes", effects.interval_changes())?;
    reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
    reject_if_present("reset_request_changes", effects.reset_request_changes())?;
    reject_if_present("leave_request_changes", effects.leave_request_changes())?;
    reject_if_present("welcome_changes", effects.welcome_changes())?;
    reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
    if effects.metadata_change().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "leaf recovery request metadata change",
        ));
    }
    if effects.revocation_target_cas().is_some()
        || effects.welcome_cas().is_some()
        || effects.invitation_quota_cas().is_some()
    {
        return Err(ExecutorError::UnsupportedEffect(
            "leaf recovery request revocation/welcome/quota CAS",
        ));
    }
    // Internal op MUST NOT change the coordinate or advance the seq counter
    // (E2b-6b review MINOR-2: the head CAS is a pure prior-coordinate verify).
    if successor_next_entry_seq != expected_next_entry_seq {
        return Err(ExecutorError::InconsistentPlan(
            "leaf recovery request must not advance the seq counter",
        ));
    }
    if generation != expected_generation || state_version != expected_state_version {
        return Err(ExecutorError::InconsistentPlan(
            "leaf recovery request must not change the coordinate",
        ));
    }

    let recovery = effects
        .recovery_request_changes()
        .iter()
        .find_map(|change| match (change.before(), change.after()) {
            (None, Some(after)) => Some(after),
            _ => None,
        })
        .ok_or(ExecutorError::InconsistentPlan(
            "leaf recovery request adds no open recovery request",
        ))?;
    if effects.recovery_request_changes().len() != 1
        || effects.reservation_changes().len() != 1
        || effects.package_transitions().len() != 1
    {
        return Err(ExecutorError::InconsistentPlan(
            "leaf recovery request must add exactly one request + reservation + package edge",
        ));
    }
    verify_recovery_package_consistency(
        effects,
        recovery.key_package_ref(),
        PackageStatus::Available,
        PackageStatus::Reserved,
    )?;

    // 1. The repository-owned exact package/request/reservation witness is
    //    the first durable mutation for production Recovery. The test-only
    //    raw executor seam retains its legacy reconstruction path.
    #[cfg(not(test))]
    recovery_write_authority
        .ok_or(ExecutorError::MissingContext(
            "missing validated Recovery executor write authority",
        ))?
        .apply_open(transaction)
        .await?;
    #[cfg(test)]
    if let Some(authority) = recovery_write_authority {
        authority.apply_open(transaction).await?;
    }

    // 2. Head CAS VERIFY — coordinate and seq counter both UNCHANGED
    //    (successor == expected on every column). A drifted head is a typed
    //    conflict; a matched head is a no-op update that pins the read.
    transition::cas_conversation_head(
        transaction,
        &transition::ConversationHeadCas {
            conversation_id,
            expected_generation,
            expected_state_version,
            expected_next_entry_seq,
            successor_generation: generation,
            successor_state_version: state_version,
            successor_next_entry_seq,
            close: None,
        },
    )
    .await?;

    #[cfg(test)]
    if recovery_write_authority.is_none() {
        write_recovery_open(transaction, ctx, recovery, conversation_id, applied_at).await?;
    }

    // 3. No control entry (internal op) -> no entry recipients; only events.
    let event_positions = write_events(transaction, ctx, None).await?;

    Ok(AppliedTransition {
        // No control entry / seq was allocated; echo the unchanged counter.
        allocated_seq: u64::try_from(successor_next_entry_seq).unwrap(),
        entry_id: ctx.entry().entry_id,
        event_positions,
        successor_coordinate: plan.successor_coordinate().copied(),
    })
}

fn terminal_welcome_context_is_closed(
    ctx: &ExecutionContext,
    response: bool,
) -> Result<(), ExecutorError> {
    if !ctx.opened_leaves.is_empty()
        || ctx.metadata_author.is_some()
        || !ctx.participant_period_ids.is_empty()
        || !ctx.leaf_period_ids.is_empty()
        || !ctx.entry_recipients.is_empty()
        || !ctx.events.is_empty()
        || !ctx.closing_leaf_periods.is_empty()
        || !ctx.closing_participant_periods.is_empty()
        || ctx.reset_request_row.is_some()
        || ctx.recovery_open.is_some()
        || !ctx.welcome_dispositions.is_empty()
        || (response && ctx.welcome_expiry.is_some())
        || (!response && ctx.welcome_response.is_some())
    {
        return Err(ExecutorError::InconsistentPlan(
            "Welcome terminal context carries an unrelated family",
        ));
    }
    Ok(())
}

fn exact_welcome_actor_role(
    plan: &ConversationPersistencePlan,
    actor: &DeviceIdentity,
) -> Result<TransitionActorRole, ExecutorError> {
    let participant = plan
        .state()
        .participants
        .iter()
        .find(|participant| participant.principal == *actor.principal())
        .ok_or(ExecutorError::InconsistentPlan(
            "Welcome actor has no exact participant role",
        ))?;
    Ok(match participant.role {
        ParticipantRole::Member => TransitionActorRole::Member,
        ParticipantRole::Admin => TransitionActorRole::Admin,
    })
}

fn repository_welcome_rejection_reason(value: &str) -> Option<WelcomeRejectionReason> {
    match value {
        "noMatchingKeyPackage" => Some(WelcomeRejectionReason::NoMatchingKeyPackage),
        "invalidWelcome" => Some(WelcomeRejectionReason::InvalidWelcome),
        "unsupportedCipherSuite" => Some(WelcomeRejectionReason::UnsupportedCipherSuite),
        "coordinateMismatch" => Some(WelcomeRejectionReason::CoordinateMismatch),
        "localStateConflict" => Some(WelcomeRejectionReason::LocalStateConflict),
        _ => None,
    }
}

async fn preflight_welcome_terminal_event(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ctx: &ExecutionContext,
    event: &EventFanout,
    welcome_id: Uuid,
    status: &str,
    recipient: &DeviceIdentity,
) -> Result<(), ExecutorError> {
    let protocol_instance_id: Uuid = sqlx::query_scalar(
        "SELECT protocol_instance_id FROM chat.protocol_instances \
             WHERE singleton FOR SHARE",
    )
    .fetch_one(&mut **transaction)
    .await
    .map_err(DeliveryRepositoryError::from)?;
    if ctx.protocol_instance_id != protocol_instance_id
        || !super::is_uuid_v4(event.event_id.as_bytes())
        || event.event_kind != EventKind::WelcomeDisposition
        || event.payload_bytes
            != delivery::canonical_welcome_disposition_event_payload(welcome_id, status)
        || event.recipients.len() != 1
        || event.recipients[0].0 != *recipient
        || event.recipients[0].1 != EventEntitlementKind::Welcome
        || event.outbox.len() != 1
        || !super::is_uuid_v4(event.outbox[0].0.as_bytes())
        || event.outbox[0].1 != OutboxWorkKind::Stream
    {
        return Err(ExecutorError::InconsistentPlan(
            "Welcome terminal event context is not exact",
        ));
    }
    let current_predecessor: Option<i64> = sqlx::query_scalar(
        "SELECT max(event_position) FROM chat.event_recipients \
             WHERE user_did=$1 AND device_id=$2",
    )
    .bind(device_did(recipient)?)
    .bind(device_uuid(recipient))
    .fetch_one(&mut **transaction)
    .await
    .map_err(DeliveryRepositoryError::from)?;
    if event.recipients[0].2 != current_predecessor {
        return Err(ExecutorError::InconsistentPlan(
            "Welcome terminal event predecessor is stale",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn preflight_welcome_response_execution_context(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &ConversationPersistencePlan,
    ctx: &ExecutionContext,
    head: &super::ConversationHeadCasBinding,
    welcome_cas: &super::WelcomeCasBinding,
    responded: &WelcomeWork,
    response: &WelcomeResponseContext,
    successor_status: WelcomeStatus,
) -> Result<(), ExecutorError> {
    terminal_welcome_context_is_closed(ctx, true)?;
    let expected_kind = match successor_status {
        WelcomeStatus::Acknowledged => super::RequestEntryKind::WelcomeAcknowledgement,
        WelcomeStatus::Rejected => super::RequestEntryKind::WelcomeRejection,
        _ => {
            return Err(ExecutorError::InconsistentPlan(
                "Welcome response has an invalid successor",
            ))
        }
    };
    let evidence = match plan.effects().authority() {
        Some(PlanAuthority::Request(evidence)) => evidence,
        _ => {
            return Err(ExecutorError::InconsistentPlan(
                "Welcome response lacks request authority",
            ))
        }
    };
    super::validate_request_evidence(
        evidence,
        expected_kind,
        welcome_cas.conversation_id(),
        responded.welcome_id(),
        responded.recipient(),
        evidence.received_at,
    )
    .map_err(|_| ExecutorError::InconsistentPlan("Welcome response request evidence is invalid"))?;
    let signed = evidence
        .authority
        .as_ref()
        .ok_or(ExecutorError::MissingContext(
            "authenticated Welcome request evidence",
        ))?;
    let signed_reason = match evidence.body_binding.as_ref() {
        Some(super::RequestBodyBinding::WelcomeResponse {
            coordinates,
            transition_seq,
            rejection_reason,
        }) if coordinates == responded.coordinate()
            && *transition_seq == responded.transition_seq()
            && super::welcome_response_reason_matches(
                expected_kind,
                rejection_reason.as_deref(),
            ) =>
        {
            rejection_reason.as_deref()
        }
        _ => {
            return Err(ExecutorError::InconsistentPlan(
                "Welcome response body binding is invalid",
            ))
        }
    };
    let expected_applied_at = server_instant(evidence.received_at)?;
    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await
        .map_err(DeliveryRepositoryError::from)?;
    if transaction_id != head.transaction_id()
        || transaction_id != welcome_cas.transaction_id()
        || head.conversation_id() != welcome_cas.conversation_id()
        || head.expected_prior() != Some(responded.coordinate())
        || head.allocated_entry_id().is_some()
        || head.allocated_seq().is_some()
        || head.expected_next_entry_seq() != head.successor_next_entry_seq()
        || head.locked_at() != evidence.received_at
        || head.locked_at() != welcome_cas.locked_at()
        || head.locked_head_digest() == &[0; 32]
        || welcome_cas.locked_row_digest() == &[0; 32]
        || ctx.applied_at != expected_applied_at
        || ctx.applied_at != server_instant(welcome_cas.locked_at())?
    {
        return Err(ExecutorError::InconsistentPlan(
            "Welcome response transaction/head authority is inconsistent",
        ));
    }
    let entry = match &ctx.authority {
        ExecutionAuthority::ControlEntry(entry) => entry,
        ExecutionAuthority::Entryless { .. } => {
            return Err(ExecutorError::MissingContext(
                "signed Welcome response execution authority",
            ))
        }
    };
    let expected_actor_did = device_did(evidence.actor())?;
    if entry.entry_id.as_bytes() != evidence.request_id()
        || entry.entry_kind != signed.type_id()
        || entry.accepted_payload_bytes != signed.signed_request_bytes()
        || entry.accepted_payload_bytes != evidence.signed_request_bytes
        || entry.accepted_payload_sha256.as_slice()
            != sha2::Sha256::digest(&entry.accepted_payload_bytes).as_slice()
        || entry.signed_request_bytes != signed.signed_request_bytes()
        || entry.unsigned_projection_bytes != signed.canonical_projection()
        || entry.signing_transcript_bytes != signed.transcript_bytes()
        || entry.request_digest != signed.request_digest()
        || entry.signature != signed.signature()
        || !entry.server_fields_bytes.is_empty()
        || entry.outer_entry_fingerprint != evidence.durable_row_digest()
        || ctx.actor.user_did != expected_actor_did
        || ctx.actor.device_id != device_uuid(evidence.actor())
        || ctx.actor.key_id != URL_SAFE_NO_PAD.encode(signed.key_id())
        || u64::try_from(ctx.actor.auth_generation).ok() != Some(signed.auth_generation())
        || ctx.actor.role != exact_welcome_actor_role(plan, evidence.actor())?
        || ctx.actor.device_status != "active"
    {
        return Err(ExecutorError::InconsistentPlan(
            "Welcome response execution authority/context drifted",
        ));
    }
    match successor_status {
        WelcomeStatus::Acknowledged if response.rejection.is_none() => {}
        WelcomeStatus::Rejected => {
            let rejection = response
                .rejection
                .as_ref()
                .ok_or(ExecutorError::MissingContext(
                    "welcome rejection recovery work",
                ))?;
            if !super::is_uuid_v4(rejection.recovery_work_id.as_bytes())
                || signed_reason.and_then(repository_welcome_rejection_reason)
                    != Some(rejection.reason)
            {
                return Err(ExecutorError::InconsistentPlan(
                    "Welcome rejection work is not bound to the signed reason",
                ));
            }
        }
        WelcomeStatus::Acknowledged => {
            return Err(ExecutorError::InconsistentPlan(
                "welcome acknowledgement must not carry rejection recovery work",
            ))
        }
        _ => unreachable!("successor status checked above"),
    }
    let status = match successor_status {
        WelcomeStatus::Acknowledged => "acknowledged",
        WelcomeStatus::Rejected => "rejected",
        _ => unreachable!("successor status checked above"),
    };
    preflight_welcome_terminal_event(
        transaction,
        ctx,
        &response.event,
        Uuid::from_bytes(*responded.welcome_id()),
        status,
        responded.recipient(),
    )
    .await
}

async fn preflight_welcome_expiry_execution_context(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &ConversationPersistencePlan,
    ctx: &ExecutionContext,
    head: &super::ConversationHeadCasBinding,
    welcome_cas: &super::WelcomeCasBinding,
    expired: &WelcomeWork,
    expiry: &WelcomeExpiryContext,
) -> Result<(), ExecutorError> {
    terminal_welcome_context_is_closed(ctx, false)?;
    let evidence = match plan.effects().authority() {
        Some(PlanAuthority::WelcomeExpiry(evidence)) => evidence,
        _ => {
            return Err(ExecutorError::InconsistentPlan(
                "Welcome expiry lacks expiry authority",
            ))
        }
    };
    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await
        .map_err(DeliveryRepositoryError::from)?;
    if transaction_id != head.transaction_id()
        || transaction_id != welcome_cas.transaction_id()
        || head.conversation_id() != welcome_cas.conversation_id()
        || head.expected_prior() != Some(expired.coordinate())
        || head.allocated_entry_id().is_some()
        || head.allocated_seq().is_some()
        || head.expected_next_entry_seq() != head.successor_next_entry_seq()
        || head.locked_at() != evidence.observed_at()
        || head.locked_at() != welcome_cas.locked_at()
        || head.locked_head_digest() == &[0; 32]
        || welcome_cas.locked_row_digest() == &[0; 32]
        || evidence.welcome_id() != expired.welcome_id()
        || evidence.recipient() != expired.recipient()
        || evidence.coordinate() != expired.coordinate()
        || evidence.transition_seq() != expired.transition_seq()
        || evidence.terminal_at() != expired.expires_at()
        || evidence.observed_at() < evidence.terminal_at()
        || evidence.locked_row_digest() != welcome_cas.locked_row_digest()
        || ctx.applied_at != server_instant(evidence.terminal_at())?
        || ctx.operation_id().as_bytes() != evidence.welcome_id()
        || ctx.actor.user_did != device_did(evidence.recipient())?
        || ctx.actor.device_id != device_uuid(evidence.recipient())
        || ctx.actor.role != exact_welcome_actor_role(plan, evidence.recipient())?
        || !super::is_uuid_v4(expiry.recovery_work_id.as_bytes())
    {
        return Err(ExecutorError::InconsistentPlan(
            "Welcome expiry authority/context drifted",
        ));
    }
    preflight_welcome_terminal_event(
        transaction,
        ctx,
        &expiry.event,
        Uuid::from_bytes(*expired.welcome_id()),
        "expired",
        expired.recipient(),
    )
    .await
}

/// Apply an entry-less `welcomeExpiry` op: a server-observed pending Welcome
/// past its `expires_at` is terminalized `expired` and a `welcomeExpired`
/// `recovery_work_items` row is created so the recipient can be re-added later.
/// Coordinate + seq counter UNCHANGED (a pure prior-coordinate verify). NO
/// entry, transition, or membership change. Both the disposition `terminal_at`
/// and the recovery-work `created_at` are the welcome's OWN `expires_at` (the DB
/// `welcome_deliveries.terminal_at = expires_at` and `recovery_work_items.created_at
/// = disposition_terminal_at` cross-checks), NOT `applied_at`; the recovery-work
/// coordinate is the welcome's OWN bound coordinate.
async fn apply_welcome_expiry(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &ConversationPersistencePlan,
    ctx: &ExecutionContext,
    conversation_id: Uuid,
    generation: i64,
    state_version: i64,
    _epoch: i64,
) -> Result<AppliedTransition, ExecutorError> {
    let effects = plan.effects();
    let head = effects
        .head_cas()
        .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
    let expected_prior = head
        .expected_prior()
        .ok_or(ExecutorError::InconsistentPlan(
            "welcome expiry needs an expected prior",
        ))?;
    let expected_generation = checked_i64(expected_prior.generation())?;
    let expected_state_version = checked_i64(expected_prior.state_version())?;
    let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;
    let successor_next_entry_seq = checked_i64(head.successor_next_entry_seq())?;

    // Only a welcome delivery CAS (Pending -> Expired). Reject every other family.
    reject_if_present("participant_changes", effects.participant_changes())?;
    reject_if_present("leaf_changes", effects.leaf_changes())?;
    reject_if_present("interval_changes", effects.interval_changes())?;
    reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
    reject_if_present(
        "recovery_request_changes",
        effects.recovery_request_changes(),
    )?;
    reject_if_present("reservation_changes", effects.reservation_changes())?;
    reject_if_present("reset_request_changes", effects.reset_request_changes())?;
    reject_if_present("leave_request_changes", effects.leave_request_changes())?;
    reject_if_present("package_transitions", effects.package_transitions())?;
    reject_if_present("recovery_package_cas", effects.recovery_package_cas())?;
    reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
    if effects.metadata_change().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "welcome expiry metadata change",
        ));
    }
    if effects.revocation_target_cas().is_some() || effects.invitation_quota_cas().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "welcome expiry revocation/quota CAS",
        ));
    }
    // A `welcomeExpiry` is the ONE kind that carries `welcome_cas` (the
    // authoritative pending-only CAS binding). The `welcome_changes` delta drives
    // the write; the CAS binding is a LOAD-BEARING witness validated against that
    // delta below (welcome id, recipient, bound coordinate, expiry instant, and
    // the Pending->Expired direction must all agree).
    let welcome_cas = effects
        .welcome_cas()
        .ok_or(ExecutorError::InconsistentPlan(
            "welcome expiry plan missing welcome CAS binding",
        ))?;

    // Pure prior-coordinate verify: coordinate + seq counter UNCHANGED.
    if successor_next_entry_seq != expected_next_entry_seq {
        return Err(ExecutorError::InconsistentPlan(
            "welcome expiry must not advance the seq counter",
        ));
    }
    if generation != expected_generation || state_version != expected_state_version {
        return Err(ExecutorError::InconsistentPlan(
            "welcome expiry must not change the coordinate",
        ));
    }

    // Exactly one Pending -> Expired welcome change.
    if effects.welcome_changes().len() != 1 {
        return Err(ExecutorError::InconsistentPlan(
            "welcome expiry must change exactly one welcome",
        ));
    }
    let expired = effects
        .welcome_changes()
        .iter()
        .find_map(|change| match (change.before(), change.after()) {
            (Some(before), Some(after))
                if before.status() == WelcomeStatus::Pending
                    && after.status() == WelcomeStatus::Expired =>
            {
                Some(after)
            }
            _ => None,
        })
        .ok_or(ExecutorError::InconsistentPlan(
            "welcome expiry must expire a pending welcome",
        ))?;
    let welcome_id = Uuid::from_bytes(*expired.welcome_id());
    if ctx.operation_id() != welcome_id {
        return Err(ExecutorError::MissingContext(
            "exact Welcome expiry operation id",
        ));
    }
    let terminal_at = server_instant(expired.expires_at())?;
    let recipient = expired.recipient().clone();
    let welcome_coordinate = expired.coordinate();
    // Consume the CAS binding as load-bearing: it must bind exactly the pending
    // welcome the delta expires, AND the binding's domain-separated seal must
    // reaffirm every nonsemantic authority family (opaque digest, expiry,
    // locked instant, and locked-row digest) independent of the welcome_change
    // delta. A planner that disagreed, or a drifted binding that the
    // welcome_change delta alone does not surface, is a hard `InconsistentPlan`
    // raised before the head CAS verify or event insert — never a
    // silently-stale witness that first fails at the delivery writer.
    if welcome_cas.welcome_id() != expired.welcome_id()
        || welcome_cas.recipient() != &recipient
        || welcome_cas.coordinate() != welcome_coordinate
        || welcome_cas.expires_at() != expired.expires_at()
        || welcome_cas.expected_status() != WelcomeStatus::Pending
        || welcome_cas.successor_status() != WelcomeStatus::Expired
        || !welcome_cas.verify_seal()
    {
        return Err(ExecutorError::InconsistentPlan(
            "welcome expiry CAS binding disagrees with the welcome change",
        ));
    }
    let expiry = ctx
        .welcome_expiry
        .as_ref()
        .ok_or(ExecutorError::MissingContext("welcome expiry context"))?;
    preflight_welcome_expiry_execution_context(
        transaction,
        plan,
        ctx,
        head,
        welcome_cas,
        expired,
        expiry,
    )
    .await?;
    delivery::preflight_pending_welcome_terminal_cas(
        transaction,
        welcome_cas,
        &WelcomeDisposition::Expired,
        terminal_at,
    )
    .await?;

    // 1. Head CAS VERIFY (coordinate + seq counter both UNCHANGED).
    transition::cas_conversation_head(
        transaction,
        &transition::ConversationHeadCas {
            conversation_id,
            expected_generation,
            expected_state_version,
            expected_next_entry_seq,
            successor_generation: generation,
            successor_state_version: state_version,
            successor_next_entry_seq,
            close: None,
        },
    )
    .await?;

    // 2. Append the `welcomeDisposition` event. Its `created_at` MUST equal the
    //    welcome's `expires_at` (`assert_welcome_disposition_cas`:
    //    `event.created_at = delivery.terminal_at`), NOT `applied_at` — a welcome
    //    expiry is stamped at the deterministic `expires_at`, so this arm uses
    //    `terminal_at` throughout and never `applied_at`.
    let position = delivery::append_event(
        transaction,
        &NewEvent {
            event_id: expiry.event.event_id,
            event_kind: expiry.event.event_kind,
            payload_bytes: expiry.event.payload_bytes.clone(),
            created_at: terminal_at,
            protocol_instance_id: ctx.protocol_instance_id,
        },
    )
    .await?;
    let event_recipients = expiry
        .event
        .recipients
        .iter()
        .map(|(device, kind, predecessor)| {
            Ok(EventRecipient {
                user_did: device_did(device)?,
                device_id: device_uuid(device),
                entitlement_kind: *kind,
                audience_predecessor_position: *predecessor,
            })
        })
        .collect::<Result<Vec<_>, ExecutorError>>()?;
    delivery::insert_event_recipients(transaction, position, &event_recipients).await?;
    for (outbox_id, work_kind) in &expiry.event.outbox {
        delivery::enqueue_outbox(transaction, *outbox_id, position, *work_kind, terminal_at)
            .await?;
    }

    // 3. Terminalize the pending delivery `expired` at its `expires_at`.
    delivery::terminalize_welcome_delivery(
        transaction,
        welcome_cas,
        &WelcomeDisposition::Expired,
        terminal_at,
        position,
    )
    .await?;

    // 4. The `welcomeExpired` recovery work item (created_at == the disposition
    //    terminal_at; coordinate == the welcome's own bound coordinate).
    delivery::insert_recovery_work_item(
        transaction,
        &delivery::NewRecoveryWorkItem {
            recovery_work_id: expiry.recovery_work_id,
            conversation_id,
            recipient_did: device_did(&recipient)?,
            recipient_device_id: device_uuid(&recipient),
            source_kind: delivery::RecoveryWorkSourceKind::WelcomeExpired,
            source_id: welcome_id,
            generation: checked_i64(welcome_coordinate.generation())?,
            state_version: checked_i64(welcome_coordinate.state_version())?,
            created_at: terminal_at,
        },
    )
    .await?;

    Ok(AppliedTransition {
        // No control entry / seq was allocated; echo the unchanged counter.
        allocated_seq: u64::try_from(successor_next_entry_seq).unwrap(),
        entry_id: ctx.operation_id(),
        event_positions: vec![position],
        successor_coordinate: plan.successor_coordinate().copied(),
    })
}

/// Apply an entry-less `deviceRevocation` op for ONE conversation. The
/// coordinate + seq counter are UNCHANGED (a pure prior-coordinate verify);
/// there is NO MLS Remove and NO interval close. It supersedes the TARGET's
/// own open recovery requests (Open->Superseded), releases their reservations
/// (Active->Released), revokes their reserved packages (Reserved->Revoked),
/// and supersedes their pending welcomes (Pending->Superseded) — ALL bound to
/// the revocation id at `terminal_at == accepted_at`. The immutable
/// `device_revocations` row + the registration revoke are batch-level
/// (`apply_device_revocation_batch_prefix`); this arm owns only the
/// per-conversation work terminalizations. Modeled on
/// `apply_leaf_recovery_request`.
#[allow(clippy::too_many_arguments)]
async fn apply_device_revocation(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &ConversationPersistencePlan,
    ctx: &ExecutionContext,
    conversation_id: Uuid,
    generation: i64,
    state_version: i64,
    _epoch: i64,
    mut event_cursor: Option<&mut EventChainCursor>,
) -> Result<AppliedTransition, ExecutorError> {
    let effects = plan.effects();
    let head = effects
        .head_cas()
        .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
    let expected_prior = head
        .expected_prior()
        .ok_or(ExecutorError::InconsistentPlan(
            "device revocation needs a prior",
        ))?;
    let expected_generation = checked_i64(expected_prior.generation())?;
    let expected_state_version = checked_i64(expected_prior.state_version())?;
    let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;
    let successor_next_entry_seq = checked_i64(head.successor_next_entry_seq())?;

    // The revocation identity comes from the plan authority — the revocation
    // id + accepted_at every terminalization binds (all `terminal_at`).
    let evidence = match effects.authority() {
        Some(PlanAuthority::DeviceRevocation(evidence)) => evidence,
        _ => {
            return Err(ExecutorError::InconsistentPlan(
                "device revocation plan missing revocation authority",
            ))
        }
    };
    let revocation_id = Uuid::from_bytes(*evidence.revocation_id());
    if ctx.operation_id() != revocation_id {
        return Err(ExecutorError::MissingContext(
            "exact device revocation operation id",
        ));
    }
    let accepted_at = server_instant(evidence.accepted_at())?;

    // Only the target's own work is terminalized; every other family empty.
    // recovery_request / reservation / package / welcome deltas are the
    // revocation-bound supersessions (handled below); everything else is a
    // hard error, never a silent drop.
    reject_if_present("participant_changes", effects.participant_changes())?;
    reject_if_present("leaf_changes", effects.leaf_changes())?;
    reject_if_present("interval_changes", effects.interval_changes())?;
    reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
    reject_if_present("reset_request_changes", effects.reset_request_changes())?;
    reject_if_present("leave_request_changes", effects.leave_request_changes())?;
    reject_if_present("recovery_package_cas", effects.recovery_package_cas())?;
    if effects.metadata_change().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "device revocation metadata change",
        ));
    }
    if effects.welcome_cas().is_some()
        || effects.revocation_target_cas().is_some()
        || effects.invitation_quota_cas().is_some()
    {
        return Err(ExecutorError::UnsupportedEffect(
            "device revocation welcome/target/quota CAS",
        ));
    }
    // Internal op MUST NOT change the coordinate or advance the seq counter.
    if successor_next_entry_seq != expected_next_entry_seq {
        return Err(ExecutorError::InconsistentPlan(
            "device revocation must not advance the seq counter",
        ));
    }
    if generation != expected_generation || state_version != expected_state_version {
        return Err(ExecutorError::InconsistentPlan(
            "device revocation must not change the coordinate",
        ));
    }
    // The package edges are Reserved->Revoked, load-bearing-bound to the
    // `revocation_package_cas` witnesses (bijective per the plan seam). An
    // empty package set (a target with only welcomes) is legal.
    if !effects.package_transitions().is_empty() && !revocation_package_cas_bijection_valid(effects)
    {
        return Err(ExecutorError::InconsistentPlan(
            "device revocation package CAS is not bijective with the Reserved->Revoked edges",
        ));
    }

    // 1. Head CAS VERIFY (coordinate + seq counter both UNCHANGED).
    transition::cas_conversation_head(
        transaction,
        &transition::ConversationHeadCas {
            conversation_id,
            expected_generation,
            expected_state_version,
            expected_next_entry_seq,
            successor_generation: generation,
            successor_state_version: state_version,
            successor_next_entry_seq,
            close: None,
        },
    )
    .await?;

    // 2. Revocation-bound terminalizations of the target's OWN work.
    let mut superseded =
        write_revocation_bound_supersessions(transaction, effects, revocation_id, accepted_at)
            .await?;
    // 3. The target's pending welcomes (Pending->Superseded), each bound to a
    //    `welcomeDisposition` event (stamped at ctx.applied_at == accepted_at).
    superseded.welcomes = write_welcome_supersessions_with_cursor(
        transaction,
        ctx,
        effects,
        WelcomeSupersessionCause::Revocation {
            terminal_revocation_id: revocation_id,
        },
        event_cursor.as_deref_mut(),
    )
    .await?;
    // 4. Silent-drop guard: a device revocation FULFILLS nothing (own == 0),
    //    so every delta MUST be a revocation-bound supersession.
    reconcile_coordinate_change_families(effects, &FamilyCounts::default(), &superseded)?;

    // 5. No control entry (internal op) -> no entry recipients; only events.
    let event_positions =
        write_events_with_cursor(transaction, ctx, event_cursor.as_deref_mut(), None).await?;

    Ok(AppliedTransition {
        // No control entry / seq was allocated; echo the unchanged counter.
        allocated_seq: u64::try_from(successor_next_entry_seq).unwrap(),
        entry_id: ctx.operation_id(),
        event_positions,
        successor_coordinate: plan.successor_coordinate().copied(),
    })
}

/// A single member whose complete rejectable semantics were checked before
/// the batch prefix. The fields are private and the type is held only by the
/// opaque batch, so application cannot receive a newly substituted plan or
/// context after the first write.
#[derive(Debug)]
struct PreparedRevocationMember<'plan> {
    plan: &'plan ConversationPersistencePlan,
    context: ExecutionContext,
    conversation_id: Uuid,
    generation: i64,
    state_version: i64,
    next_entry_seq: i64,
    revocation_id: Uuid,
    accepted_at: DateTime<Utc>,
}

/// Opaque state-machine half of the G6 capsule. Raw members, cursors and
/// symbolic events never cross the module boundary.
#[must_use = "prepared revocation members must be consumed atomically"]
pub(crate) struct PreparedDeviceRevocationBatchMembers<'plan> {
    plan: &'plan DeviceRevocationBatchPersistencePlan,
    members: Vec<PreparedRevocationMember<'plan>>,
    cursor: EventChainCursor,
    binding_digest: [u8; 32],
}

impl PreparedDeviceRevocationBatchMembers<'_> {
    pub(crate) fn binding_digest(&self) -> &[u8; 32] {
        &self.binding_digest
    }

    pub(crate) fn binding_is_intact(&self) -> bool {
        self.cursor.initial_binding_is_intact()
            && self.binding_digest
                == prepared_device_revocation_members_binding_digest(
                    self.plan,
                    &self.members,
                    &self.cursor,
                )
    }
}

/// Typestate returned only after the immutable/device-global prefix has
/// succeeded. It remains opaque and can be consumed exactly once.
pub(crate) struct PrefixedDeviceRevocationBatchMembers<'plan> {
    members: Vec<PreparedRevocationMember<'plan>>,
    cursor: EventChainCursor,
}

/// Complete SQL-free preflight for every semantic rejection formerly
/// reachable from `apply_device_revocation`. In particular, this validates
/// every family edge and requires an exact bijection between superseded
/// Welcome IDs and disposition artifacts.
fn preflight_device_revocation_plan_and_context<'plan>(
    plan: &'plan ConversationPersistencePlan,
    context: ExecutionContext,
    batch_revocation_id: Uuid,
) -> Result<PreparedRevocationMember<'plan>, ExecutorError> {
    let effects = plan.effects();
    if effects.kind() != PlanKind::DeviceRevocation {
        return Err(ExecutorError::InconsistentPlan(
            "prepared revocation member has non-revocation plan",
        ));
    }
    let head = effects
        .head_cas()
        .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
    let expected_prior = head
        .expected_prior()
        .ok_or(ExecutorError::InconsistentPlan(
            "device revocation needs a prior",
        ))?;
    let expected_generation = checked_i64(expected_prior.generation())?;
    let expected_state_version = checked_i64(expected_prior.state_version())?;
    let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;
    let successor_next_entry_seq = checked_i64(head.successor_next_entry_seq())?;
    let evidence = match effects.authority() {
        Some(PlanAuthority::DeviceRevocation(evidence)) => evidence,
        _ => {
            return Err(ExecutorError::InconsistentPlan(
                "device revocation plan missing revocation authority",
            ))
        }
    };
    let revocation_id = Uuid::from_bytes(*evidence.revocation_id());
    if revocation_id != batch_revocation_id || context.operation_id() != revocation_id {
        return Err(ExecutorError::MissingContext(
            "exact device revocation operation id",
        ));
    }
    let accepted_at = server_instant(evidence.accepted_at())?;
    if context.applied_at != accepted_at {
        return Err(ExecutorError::InconsistentPlan(
            "device revocation context instant disagrees with authority",
        ));
    }

    reject_if_present("participant_changes", effects.participant_changes())?;
    reject_if_present("leaf_changes", effects.leaf_changes())?;
    reject_if_present("interval_changes", effects.interval_changes())?;
    reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
    reject_if_present("reset_request_changes", effects.reset_request_changes())?;
    reject_if_present("leave_request_changes", effects.leave_request_changes())?;
    reject_if_present("recovery_package_cas", effects.recovery_package_cas())?;
    if effects.metadata_change().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "device revocation metadata change",
        ));
    }
    if effects.welcome_cas().is_some()
        || effects.revocation_target_cas().is_some()
        || effects.invitation_quota_cas().is_some()
    {
        return Err(ExecutorError::UnsupportedEffect(
            "device revocation welcome/target/quota CAS",
        ));
    }
    let coordinate = &plan.state().coordinate;
    let generation = checked_i64(coordinate.generation())?;
    let state_version = checked_i64(coordinate.state_version())?;
    let _epoch = checked_i64(coordinate.epoch())?;
    if successor_next_entry_seq != expected_next_entry_seq {
        return Err(ExecutorError::InconsistentPlan(
            "device revocation must not advance the seq counter",
        ));
    }
    if generation != expected_generation || state_version != expected_state_version {
        return Err(ExecutorError::InconsistentPlan(
            "device revocation must not change the coordinate",
        ));
    }
    if !effects.package_transitions().is_empty() && !revocation_package_cas_bijection_valid(effects)
    {
        return Err(ExecutorError::InconsistentPlan(
            "device revocation package CAS is not bijective with the Reserved->Revoked edges",
        ));
    }
    if effects.recovery_request_changes().iter().any(|change| {
        !matches!(
            (change.before(), change.after()),
            (Some(before), Some(after))
                if before.status() == RecoveryRequestStatus::Open
                    && after.status() == RecoveryRequestStatus::Superseded
        )
    }) {
        return Err(ExecutorError::InconsistentPlan(
            "device revocation recovery request family is not exact Open->Superseded",
        ));
    }
    if effects.reservation_changes().iter().any(|change| {
        !matches!(
            (change.before(), change.after()),
            (Some(before), Some(after))
                if before.status() == ReservationStatus::Active
                    && after.status() == ReservationStatus::Released
        )
    }) {
        return Err(ExecutorError::InconsistentPlan(
            "device revocation reservation family is not exact Active->Released",
        ));
    }
    if effects
        .package_transitions()
        .iter()
        .any(|edge| edge.from != PackageStatus::Reserved || edge.to != PackageStatus::Revoked)
    {
        return Err(ExecutorError::InconsistentPlan(
            "device revocation package family is not exact Reserved->Revoked",
        ));
    }

    let mut welcome_ids = BTreeSet::new();
    for change in effects.welcome_changes() {
        let (before, after) = match (change.before(), change.after()) {
            (Some(before), Some(after))
                if before.status() == WelcomeStatus::Pending
                    && after.status() == WelcomeStatus::Superseded =>
            {
                (before, after)
            }
            _ => {
                return Err(ExecutorError::InconsistentPlan(
                    "device revocation Welcome family is not exact Pending->Superseded",
                ))
            }
        };
        if before.welcome_id() != after.welcome_id()
            || !welcome_ids.insert(Uuid::from_bytes(*after.welcome_id()))
        {
            return Err(ExecutorError::InconsistentPlan(
                "device revocation Welcome family repeats or changes identity",
            ));
        }
    }
    let mut disposition_ids = BTreeSet::new();
    for disposition in &context.welcome_dispositions {
        if !disposition_ids.insert(disposition.welcome_id) {
            return Err(ExecutorError::MissingContext(
                "unique welcome disposition event per superseded welcome",
            ));
        }
    }
    if welcome_ids != disposition_ids {
        return Err(ExecutorError::MissingContext(
            "exact welcome disposition events for superseded welcomes",
        ));
    }

    Ok(PreparedRevocationMember {
        plan,
        context,
        conversation_id: Uuid::from_bytes(*coordinate.conversation_id()),
        generation,
        state_version,
        next_entry_seq: successor_next_entry_seq,
        revocation_id,
        accepted_at,
    })
}

/// Mint the opaque state-machine batch only after repository hydration has
/// produced the unforgeable proof. All member preflights and the complete
/// event schedule are frozen before this returns.
pub(crate) fn prepare_device_revocation_batch_members<'plan>(
    plan: &'plan DeviceRevocationBatchPersistencePlan,
    contexts: Vec<ExecutionContext>,
    prelude_digest: [u8; 32],
    devices: Vec<DeviceIdentity>,
    initial_tails: Vec<Option<i64>>,
    _proof: super::super::repository::execution_context::RevocationBatchHydrationProof,
) -> Result<PreparedDeviceRevocationBatchMembers<'plan>, ExecutorError> {
    if plan.conversations().len() != contexts.len() {
        return Err(ExecutorError::InconsistentPlan(
            "device revocation batch needs one execution context per conversation",
        ));
    }
    let revocation_id = preflight_device_revocation_batch(plan)?;
    let slots = devices
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, device)| {
            let slot = u32::try_from(index)
                .map(EventChainSlot)
                .map_err(|_| ExecutorError::EventChain(EventChainCursorError::UnknownSlot))?;
            Ok((device, slot))
        })
        .collect::<Result<BTreeMap<_, _>, ExecutorError>>()?;
    let mut members = Vec::with_capacity(contexts.len());
    let mut schedule = Vec::new();
    for (member_plan, context) in plan.conversations().iter().zip(contexts) {
        let member =
            preflight_device_revocation_plan_and_context(member_plan, context, revocation_id)?;
        for disposition in &member.context.welcome_dispositions {
            schedule.push(prepared_revocation_event_from_fanout(
                &disposition.event,
                &slots,
            )?);
        }
        for event in &member.context.events {
            schedule.push(prepared_revocation_event_from_fanout(event, &slots)?);
        }
        members.push(member);
    }
    let cursor = EventChainCursor::new(prelude_digest, devices, initial_tails, schedule)
        .map_err(ExecutorError::EventChain)?;
    let binding_digest = prepared_device_revocation_members_binding_digest(plan, &members, &cursor);
    Ok(PreparedDeviceRevocationBatchMembers {
        plan,
        members,
        cursor,
        binding_digest,
    })
}

fn prepared_device_revocation_members_binding_digest(
    plan: &DeviceRevocationBatchPersistencePlan,
    members: &[PreparedRevocationMember<'_>],
    cursor: &EventChainCursor,
) -> [u8; 32] {
    let mut digest = sha2::Sha256::new();
    digest.update(b"CATBIRD-CHAT-G6-PREPARED-MEMBERS\0");
    let plan_projection = format!("{plan:?}");
    digest.update((plan_projection.len() as u64).to_be_bytes());
    digest.update(plan_projection.as_bytes());
    digest.update((members.len() as u64).to_be_bytes());
    for member in members {
        let member_projection = format!("{member:?}");
        digest.update((member_projection.len() as u64).to_be_bytes());
        digest.update(member_projection.as_bytes());
    }
    digest.update(cursor.initial_binding_digest());
    digest.finalize().into()
}

fn prepared_revocation_event_from_fanout(
    event: &EventFanout,
    slots: &BTreeMap<DeviceIdentity, EventChainSlot>,
) -> Result<PreparedRevocationEvent, ExecutorError> {
    let recipients = event
        .recipients
        .iter()
        .map(|(device, entitlement, _)| {
            let slot = slots.get(device).copied().ok_or(ExecutorError::EventChain(
                EventChainCursorError::UnknownSlot,
            ))?;
            Ok(PreparedRevocationRecipient {
                slot,
                entitlement: *entitlement,
            })
        })
        .collect::<Result<Vec<_>, ExecutorError>>()?;
    PreparedRevocationEvent::new(
        event.event_id,
        event.event_kind,
        event.payload_bytes.clone(),
        recipients,
        event.outbox.clone(),
    )
    .map_err(ExecutorError::EventChain)
}

async fn apply_prepared_device_revocation_member(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    member: PreparedRevocationMember<'_>,
    event_cursor: &mut EventChainCursor,
) -> Result<AppliedTransition, ExecutorError> {
    let effects = member.plan.effects();
    transition::cas_conversation_head(
        transaction,
        &transition::ConversationHeadCas {
            conversation_id: member.conversation_id,
            expected_generation: member.generation,
            expected_state_version: member.state_version,
            expected_next_entry_seq: member.next_entry_seq,
            successor_generation: member.generation,
            successor_state_version: member.state_version,
            successor_next_entry_seq: member.next_entry_seq,
            close: None,
        },
    )
    .await?;
    write_revocation_bound_supersessions(
        transaction,
        effects,
        member.revocation_id,
        member.accepted_at,
    )
    .await?;
    for change in effects.welcome_changes() {
        let after = change
            .after()
            .expect("prepared revocation Welcome has an after image");
        let welcome_id = Uuid::from_bytes(*after.welcome_id());
        let disposition = member
            .context
            .welcome_dispositions
            .iter()
            .find(|input| input.welcome_id == welcome_id)
            .expect("prepared revocation has exact Welcome dispositions");
        let position = append_one_event_with_cursor(
            transaction,
            &member.context,
            &disposition.event,
            Some(event_cursor),
        )
        .await?;
        delivery::terminalize_welcome_delivery_for_supersession(
            transaction,
            welcome_id,
            &WelcomeDisposition::SupersededByRevocation {
                terminal_revocation_id: member.revocation_id,
            },
            member.context.applied_at,
            position,
        )
        .await?;
    }
    let event_positions =
        write_events_with_cursor(transaction, &member.context, Some(event_cursor), None).await?;
    Ok(AppliedTransition {
        allocated_seq: u64::try_from(member.next_entry_seq)
            .expect("prepared next entry sequence is nonnegative"),
        entry_id: member.revocation_id,
        event_positions,
        successor_coordinate: member.plan.successor_coordinate().copied(),
    })
}

/// Consume the state-machine half of the opaque capsule. The only errors
/// after the prefix are durable SQL/CAS failures or violations of the
/// already-frozen event-position cursor; no plan/context semantics are
/// revalidated here.
pub(crate) async fn apply_prepared_device_revocation_prefix<'plan>(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    prepared: PreparedDeviceRevocationBatchMembers<'plan>,
) -> Result<PrefixedDeviceRevocationBatchMembers<'plan>, ExecutorError> {
    if !prepared.binding_is_intact() {
        return Err(ExecutorError::InconsistentPlan(
            "prepared revocation member binding changed before the prefix",
        ));
    }
    let PreparedDeviceRevocationBatchMembers {
        plan,
        members,
        cursor,
        binding_digest: _,
    } = prepared;
    apply_device_revocation_batch_prefix(transaction, plan).await?;
    Ok(PrefixedDeviceRevocationBatchMembers { members, cursor })
}

pub(crate) async fn apply_prepared_device_revocation_members(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    prepared: PrefixedDeviceRevocationBatchMembers<'_>,
) -> Result<Vec<AppliedTransition>, ExecutorError> {
    let PrefixedDeviceRevocationBatchMembers {
        members,
        mut cursor,
    } = prepared;
    let mut applied = Vec::with_capacity(members.len());
    for member in members {
        applied
            .push(apply_prepared_device_revocation_member(transaction, member, &mut cursor).await?);
    }
    cursor.finish().map_err(ExecutorError::EventChain)?;
    Ok(applied)
}

/// Terminalize the target's OWN open recovery requests / active reservations /
/// reserved packages, all bound to `revocation_id` at `terminal_at`. Mirrors
/// `write_prior_bound_supersessions` but binds a REVOCATION (not a transition)
/// and drives packages Reserved->**Revoked** (not Reserved->Available). Returns
/// the per-family counts (welcomes left 0 — the caller adds them) so the caller
/// reconciles `own + superseded == total`. A delta that is NOT one of these
/// exact shapes is skipped here and caught by that reconciliation, never
/// silently dropped.
async fn write_revocation_bound_supersessions(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    effects: &TransitionEffects,
    revocation_id: Uuid,
    terminal_at: DateTime<Utc>,
) -> Result<FamilyCounts, ExecutorError> {
    let mut counts = FamilyCounts::default();
    for change in effects.recovery_request_changes() {
        if let (Some(before), Some(after)) = (change.before(), change.after()) {
            if before.status() == RecoveryRequestStatus::Open
                && after.status() == RecoveryRequestStatus::Superseded
            {
                transition::terminalize_leaf_recovery_request(
                    transaction,
                    Uuid::from_bytes(*after.request_id()),
                    &LeafRecoveryTermination::SupersededByRevocation {
                        terminal_revocation_id: revocation_id,
                        terminal_at,
                    },
                )
                .await?;
                counts.requests += 1;
            }
        }
    }
    for change in effects.reservation_changes() {
        if let (Some(before), Some(after)) = (change.before(), change.after()) {
            if before.status() == ReservationStatus::Active
                && after.status() == ReservationStatus::Released
            {
                transition::terminalize_reservation(
                    transaction,
                    Uuid::from_bytes(after.request_id),
                    &ReservationTermination::ReleasedByRevocation {
                        terminal_revocation_id: revocation_id,
                        terminal_at,
                    },
                )
                .await?;
                counts.reservations += 1;
            }
        }
    }
    for edge in effects.package_transitions() {
        if edge.from == PackageStatus::Reserved && edge.to == PackageStatus::Revoked {
            transition::cas_key_package_status(
                transaction,
                &edge.key_package_ref,
                RepoPackageStatus::Reserved,
                &PackageSuccessor::Revoke {
                    terminal_revocation_id: revocation_id,
                    terminal_at,
                },
            )
            .await?;
            counts.packages += 1;
        }
    }
    Ok(counts)
}

fn preflight_device_revocation_batch(
    plan: &DeviceRevocationBatchPersistencePlan,
) -> Result<Uuid, ExecutorError> {
    let revocation_id = Uuid::from_bytes(*plan.authority().revocation_id());
    let mut conversation_ids = BTreeSet::new();
    for conversation in plan.conversations() {
        if conversation.effects().kind() != PlanKind::DeviceRevocation {
            return Err(ExecutorError::InconsistentPlan(
                "device revocation batch contains a non-revocation conversation plan",
            ));
        }
        let conversation_evidence = match conversation.effects().authority() {
            Some(PlanAuthority::DeviceRevocation(evidence)) => evidence,
            _ => {
                return Err(ExecutorError::InconsistentPlan(
                    "device revocation batch conversation lacks revocation authority",
                ))
            }
        };
        if Uuid::from_bytes(*conversation_evidence.revocation_id()) != revocation_id {
            return Err(ExecutorError::InconsistentPlan(
                "device revocation batch conversation authority disagrees",
            ));
        }
        let conversation_id = Uuid::from_bytes(*conversation.state().coordinate.conversation_id());
        if !conversation_ids.insert(conversation_id) {
            return Err(ExecutorError::InconsistentPlan(
                "device revocation batch repeats a conversation",
            ));
        }
    }
    Ok(revocation_id)
}

/// Apply the immutable/device-global prefix of a planned revocation batch:
/// insert the revocation row, revoke the registration once, and revoke every
/// AVAILABLE package. The caller owns the open transaction and must next
/// hydrate + apply each conversation in the plan's canonical order.
///
/// This function never begins, commits, or rolls back a transaction. The
/// eventual handler owns the idempotency receipt required by the deferred
/// revocation mapping.
async fn apply_device_revocation_batch_prefix(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &DeviceRevocationBatchPersistencePlan,
) -> Result<(), ExecutorError> {
    let revocation_id = preflight_device_revocation_batch(plan)?;
    let evidence = plan.authority();
    let accepted_at = server_instant(evidence.accepted_at())?;
    let revocation_row = NewDeviceRevocation {
        revocation_id,
        actor_did: device_did(evidence.actor())?,
        actor_device_id: device_uuid(evidence.actor()),
        actor_key_id: URL_SAFE_NO_PAD.encode(evidence.actor_key_id()),
        actor_auth_generation: checked_i64(evidence.actor_auth_generation())?,
        target_did: device_did(evidence.target())?,
        target_device_id: device_uuid(evidence.target()),
        target_auth_generation: checked_i64(evidence.expected_target_auth_generation())?,
        accepted_request_bytes: evidence.signed_request_bytes().to_vec(),
        signing_transcript_bytes: evidence.signing_transcript_bytes().to_vec(),
        request_digest: evidence.request_digest().to_vec(),
        signature: evidence.signature().to_vec(),
        signed_at: server_instant(evidence.signed_at())?,
        accepted_at,
    };
    let target_cas = plan.target_cas();
    let registration_revoke = RegistrationRevoke {
        target_did: device_did(target_cas.target())?,
        target_device_id: device_uuid(target_cas.target()),
        expected_auth_generation: checked_i64(target_cas.expected_auth_generation())?,
        revocation_id,
        revoked_at: accepted_at,
    };

    insert_device_revocation(transaction, &revocation_row).await?;
    cas_registration_revoke(transaction, &registration_revoke).await?;
    // After the revocation row and the revoked registration both exist, so the
    // deferred composite FK into chat.device_revocations resolves at COMMIT.
    transition::terminalize_reset_requests_for_revoked_device(
        transaction,
        &registration_revoke.target_did,
        registration_revoke.target_device_id,
        revocation_id,
        accepted_at,
    )
    .await?;
    for binding in plan.revoked_packages() {
        if binding.conversation_id().is_none() {
            transition::cas_key_package_status(
                transaction,
                binding.key_package_ref(),
                RepoPackageStatus::Available,
                &PackageSuccessor::Revoke {
                    terminal_revocation_id: revocation_id,
                    terminal_at: accepted_at,
                },
            )
            .await?;
        }
    }
    Ok(())
}

/// Compatibility seam for executor harnesses that construct contexts
/// directly. Production callers cannot prehydrate a revocation batch.
#[cfg(test)]
pub(crate) async fn apply_device_revocation_batch_unscoped_for_test(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &DeviceRevocationBatchPersistencePlan,
    conversation_ctxs: &[ExecutionContext],
) -> Result<Vec<AppliedTransition>, ExecutorError> {
    if plan.conversations().len() != conversation_ctxs.len() {
        return Err(ExecutorError::InconsistentPlan(
            "device revocation batch needs one execution context per conversation",
        ));
    }
    let revocation_id = preflight_device_revocation_batch(plan)?;
    for ctx in conversation_ctxs {
        let operation_id = require_execution_authority(PlanKind::DeviceRevocation, &ctx.authority)?;
        if operation_id != revocation_id {
            return Err(ExecutorError::MissingContext(
                "exact device revocation operation id",
            ));
        }
    }
    apply_device_revocation_batch_prefix(transaction, plan).await?;
    let mut applied = Vec::with_capacity(plan.conversations().len());
    for (conversation, ctx) in plan.conversations().iter().zip(conversation_ctxs) {
        applied.push(
            apply_conversation_persistence_plan_unscoped_for_test(transaction, conversation, ctx)
                .await?,
        );
    }
    Ok(applied)
}

/// Apply an entry-less `welcomeAcknowledgement` / `welcomeRejection`: a
/// client-authored signed disposition of a pending Welcome. Coordinate + seq
/// counter UNCHANGED (a pure prior-coordinate verify); NO entry / transition /
/// membership change. Terminalizes the delivery `acknowledged` (recipient
/// joined — NO recovery work) or `rejected` (adds a `welcomeRejected`
/// recovery-work item with the closed reason). The disposition row binds the
/// client's signed authorization (from `ctx.entry`). Unlike expiry, every
/// timestamp is the request instant `applied_at` (the client's action time,
/// which the DB requires `< expires_at`), so the disposition event uses
/// `applied_at` (`= terminal_at`). `welcome_cas` is validated load-bearing.
async fn apply_welcome_response(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &ConversationPersistencePlan,
    ctx: &ExecutionContext,
    conversation_id: Uuid,
    generation: i64,
    state_version: i64,
    _epoch: i64,
) -> Result<AppliedTransition, ExecutorError> {
    let effects = plan.effects();
    let applied_at = ctx.applied_at;
    let head = effects
        .head_cas()
        .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
    let expected_prior = head
        .expected_prior()
        .ok_or(ExecutorError::InconsistentPlan(
            "welcome response needs an expected prior",
        ))?;
    let expected_generation = checked_i64(expected_prior.generation())?;
    let expected_state_version = checked_i64(expected_prior.state_version())?;
    let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;
    let successor_next_entry_seq = checked_i64(head.successor_next_entry_seq())?;

    // Only a welcome delivery CAS. Reject every other family.
    reject_if_present("participant_changes", effects.participant_changes())?;
    reject_if_present("leaf_changes", effects.leaf_changes())?;
    reject_if_present("interval_changes", effects.interval_changes())?;
    reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
    reject_if_present(
        "recovery_request_changes",
        effects.recovery_request_changes(),
    )?;
    reject_if_present("reservation_changes", effects.reservation_changes())?;
    reject_if_present("reset_request_changes", effects.reset_request_changes())?;
    reject_if_present("leave_request_changes", effects.leave_request_changes())?;
    reject_if_present("package_transitions", effects.package_transitions())?;
    reject_if_present("recovery_package_cas", effects.recovery_package_cas())?;
    reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
    if effects.metadata_change().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "welcome response metadata change",
        ));
    }
    if effects.revocation_target_cas().is_some() || effects.invitation_quota_cas().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "welcome response revocation/quota CAS",
        ));
    }
    let welcome_cas = effects
        .welcome_cas()
        .ok_or(ExecutorError::InconsistentPlan(
            "welcome response plan missing welcome CAS binding",
        ))?;

    // Pure prior-coordinate verify: coordinate + seq counter UNCHANGED.
    if successor_next_entry_seq != expected_next_entry_seq {
        return Err(ExecutorError::InconsistentPlan(
            "welcome response must not advance the seq counter",
        ));
    }
    if generation != expected_generation || state_version != expected_state_version {
        return Err(ExecutorError::InconsistentPlan(
            "welcome response must not change the coordinate",
        ));
    }

    // Exactly one Pending -> {Acknowledged,Rejected} welcome change.
    if effects.welcome_changes().len() != 1 {
        return Err(ExecutorError::InconsistentPlan(
            "welcome response must change exactly one welcome",
        ));
    }
    let responded = effects
        .welcome_changes()
        .iter()
        .find_map(|change| match (change.before(), change.after()) {
            (Some(before), Some(after))
                if before.status() == WelcomeStatus::Pending
                    && matches!(
                        after.status(),
                        WelcomeStatus::Acknowledged | WelcomeStatus::Rejected
                    ) =>
            {
                Some(after)
            }
            _ => None,
        })
        .ok_or(ExecutorError::InconsistentPlan(
            "welcome response must acknowledge or reject a pending welcome",
        ))?;
    let successor_status = responded.status();
    let welcome_id = Uuid::from_bytes(*responded.welcome_id());
    let recipient = responded.recipient().clone();
    let welcome_coordinate = responded.coordinate();
    // Load-bearing welcome CAS validation (mirrors the expiry arm). The
    // binding's domain-separated seal re-affirms every nonsemantic authority
    // family (opaque digest, expiry, locked instant, locked-row digest)
    // independent of the welcome_change delta; a drifted binding that the
    // delta alone does not surface is rejected here, BEFORE the head CAS
    // verify or event insert, rather than first failing at the delivery
    // writer after the event/outbox row is already appended.
    if welcome_cas.welcome_id() != responded.welcome_id()
        || welcome_cas.recipient() != &recipient
        || welcome_cas.coordinate() != welcome_coordinate
        || welcome_cas.expires_at() != responded.expires_at()
        || welcome_cas.expected_status() != WelcomeStatus::Pending
        || welcome_cas.successor_status() != successor_status
        || !welcome_cas.verify_seal()
    {
        return Err(ExecutorError::InconsistentPlan(
            "welcome response CAS binding disagrees with the welcome change",
        ));
    }
    let response = ctx
        .welcome_response
        .as_ref()
        .ok_or(ExecutorError::MissingContext("welcome response context"))?;
    preflight_welcome_response_execution_context(
        transaction,
        plan,
        ctx,
        head,
        welcome_cas,
        responded,
        response,
        successor_status,
    )
    .await?;
    // The client-authored signed authorization the disposition row binds — the
    // signed request's bytes/digest/signature (the signature-shape trigger
    // requires them non-NULL for acknowledged/rejected).
    let authorization = WelcomeClientAuthorization {
        signed_request_bytes: ctx.entry().signed_request_bytes.clone(),
        signing_transcript_bytes: ctx.entry().signing_transcript_bytes.clone(),
        request_digest: ctx.entry().request_digest.clone(),
        signature: ctx.entry().signature.clone(),
    };
    // The disposition shape must match the successor status; a rejection carries
    // the recovery work, an acknowledgement must not.
    let (disposition, rejection_work): (WelcomeDisposition, Option<&WelcomeRejectionWork>) =
        match successor_status {
            WelcomeStatus::Acknowledged => {
                if response.rejection.is_some() {
                    return Err(ExecutorError::InconsistentPlan(
                        "welcome acknowledgement must not carry rejection recovery work",
                    ));
                }
                (WelcomeDisposition::Acknowledged { authorization }, None)
            }
            WelcomeStatus::Rejected => {
                let rejection =
                    response
                        .rejection
                        .as_ref()
                        .ok_or(ExecutorError::MissingContext(
                            "welcome rejection recovery work",
                        ))?;
                (
                    WelcomeDisposition::Rejected {
                        authorization,
                        reason: rejection.reason,
                    },
                    Some(rejection),
                )
            }
            _ => {
                return Err(ExecutorError::InconsistentPlan(
                    "welcome response status must be acknowledged or rejected",
                ))
            }
        };
    delivery::preflight_pending_welcome_terminal_cas(
        transaction,
        welcome_cas,
        &disposition,
        applied_at,
    )
    .await?;

    // 1. Head CAS VERIFY (coordinate + seq counter both UNCHANGED).
    transition::cas_conversation_head(
        transaction,
        &transition::ConversationHeadCas {
            conversation_id,
            expected_generation,
            expected_state_version,
            expected_next_entry_seq,
            successor_generation: generation,
            successor_state_version: state_version,
            successor_next_entry_seq,
            close: None,
        },
    )
    .await?;

    // 2. Append the `welcomeDisposition` event. Its `created_at` (= applied_at)
    //    must equal the delivery terminal_at (= applied_at), so append_one_event
    //    (which stamps applied_at) is correct here.
    let position = append_one_event(transaction, ctx, &response.event).await?;

    // 3. Terminalize the pending delivery at the request instant, binding the
    //    client authorization (+ reason for a rejection).
    delivery::terminalize_welcome_delivery(
        transaction,
        welcome_cas,
        &disposition,
        applied_at,
        position,
    )
    .await?;

    // 4. A rejection additionally creates the `welcomeRejected` recovery work.
    if let Some(rejection) = rejection_work {
        delivery::insert_recovery_work_item(
            transaction,
            &delivery::NewRecoveryWorkItem {
                recovery_work_id: rejection.recovery_work_id,
                conversation_id,
                recipient_did: device_did(&recipient)?,
                recipient_device_id: device_uuid(&recipient),
                source_kind: delivery::RecoveryWorkSourceKind::WelcomeRejected,
                source_id: welcome_id,
                generation: checked_i64(welcome_coordinate.generation())?,
                state_version: checked_i64(welcome_coordinate.state_version())?,
                created_at: applied_at,
            },
        )
        .await?;
    }

    Ok(AppliedTransition {
        allocated_seq: u64::try_from(successor_next_entry_seq).unwrap(),
        entry_id: ctx.entry().entry_id,
        event_positions: vec![position],
        successor_coordinate: plan.successor_coordinate().copied(),
    })
}

/// Apply an entry-less `leafRecoveryCancellation` internal op: terminalize one
/// open recovery request as `cancelled` with its signed cancellation
/// provenance, release its reservation, and RE-ACTIVATE the reserved key
/// package back to `available` (the E2b-6b `PackageSuccessor::Reactivate`
/// writer). The coordinate and seq counter are byte-untouched (head CAS
/// verify). The `assert_recovery_fulfillment_mapping` cancelled-status arm
/// requires the released reservation and request to carry the SAME
/// `terminal_request_digest` + `terminal_at`, and the package to be
/// `available` with all terminal columns NULL — all satisfied here.
#[allow(clippy::too_many_arguments)]
async fn apply_leaf_recovery_cancellation(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &ConversationPersistencePlan,
    ctx: &ExecutionContext,
    conversation_id: Uuid,
    generation: i64,
    state_version: i64,
    _epoch: i64,
    recovery_write_authority: Option<
        &super::super::repository::recovery::RecoveryExecutorWriteAuthority<'_>,
    >,
) -> Result<AppliedTransition, ExecutorError> {
    let effects = plan.effects();
    #[cfg(test)]
    let applied_at = ctx.applied_at;
    let head = effects
        .head_cas()
        .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
    let expected_prior = head
        .expected_prior()
        .ok_or(ExecutorError::InconsistentPlan(
            "leaf recovery cancellation needs a prior",
        ))?;
    let expected_generation = checked_i64(expected_prior.generation())?;
    let expected_state_version = checked_i64(expected_prior.state_version())?;
    let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;
    let successor_next_entry_seq = checked_i64(head.successor_next_entry_seq())?;

    // Only a request terminalization + reservation release + package
    // re-activation. Everything else must be empty.
    reject_if_present("participant_changes", effects.participant_changes())?;
    reject_if_present("leaf_changes", effects.leaf_changes())?;
    reject_if_present("interval_changes", effects.interval_changes())?;
    reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
    reject_if_present("reset_request_changes", effects.reset_request_changes())?;
    reject_if_present("leave_request_changes", effects.leave_request_changes())?;
    reject_if_present("welcome_changes", effects.welcome_changes())?;
    reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
    if effects.metadata_change().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "leaf recovery cancellation metadata change",
        ));
    }
    if effects.revocation_target_cas().is_some()
        || effects.welcome_cas().is_some()
        || effects.invitation_quota_cas().is_some()
    {
        return Err(ExecutorError::UnsupportedEffect(
            "leaf recovery cancellation revocation/welcome/quota CAS",
        ));
    }
    // Internal op MUST NOT change the coordinate or advance the seq counter
    // (E2b-6b review MINOR-2).
    if successor_next_entry_seq != expected_next_entry_seq {
        return Err(ExecutorError::InconsistentPlan(
            "leaf recovery cancellation must not advance the seq counter",
        ));
    }
    if generation != expected_generation || state_version != expected_state_version {
        return Err(ExecutorError::InconsistentPlan(
            "leaf recovery cancellation must not change the coordinate",
        ));
    }

    // Exactly one Open->Cancelled recovery request + one released reservation +
    // one package edge.
    let recovery = effects
        .recovery_request_changes()
        .iter()
        .find_map(|change| match (change.before(), change.after()) {
            (Some(before), Some(after))
                if before.status() == RecoveryRequestStatus::Open
                    && after.status() == RecoveryRequestStatus::Cancelled =>
            {
                Some(after)
            }
            _ => None,
        })
        .ok_or(ExecutorError::InconsistentPlan(
            "cancellation does not cancel an open recovery request",
        ))?;
    if effects.recovery_request_changes().len() != 1
        || effects.reservation_changes().len() != 1
        || effects.package_transitions().len() != 1
    {
        return Err(ExecutorError::InconsistentPlan(
            "cancellation must terminalize exactly one request + reservation + package edge",
        ));
    }
    verify_recovery_package_consistency(
        effects,
        recovery.key_package_ref(),
        PackageStatus::Reserved,
        PackageStatus::Available,
    )?;
    #[cfg(test)]
    let recovery_request_id = Uuid::from_bytes(*recovery.request_id());
    #[cfg(test)]
    let key_package_ref = recovery.key_package_ref().to_vec();
    // The signed cancellation request's digest — the SAME value the released
    // reservation records, per the cancelled-status mapping cross-check.
    #[cfg(test)]
    let terminal_request_digest = ctx.entry().request_digest.clone();

    // 1. Production consumes the Task-4 full-row triple as the first
    //    durable mutation. The enclosing executor savepoint rolls it back
    //    if the later head/event/completion composition fails.
    #[cfg(not(test))]
    recovery_write_authority
        .ok_or(ExecutorError::MissingContext(
            "missing validated Recovery executor write authority",
        ))?
        .apply_terminal(transaction)
        .await?;
    #[cfg(test)]
    if let Some(authority) = recovery_write_authority {
        authority.apply_terminal(transaction).await?;
    }

    // 2. Head CAS VERIFY (coordinate + seq counter unchanged).
    transition::cas_conversation_head(
        transaction,
        &transition::ConversationHeadCas {
            conversation_id,
            expected_generation,
            expected_state_version,
            expected_next_entry_seq,
            successor_generation: generation,
            successor_state_version: state_version,
            successor_next_entry_seq,
            close: None,
        },
    )
    .await?;

    #[cfg(test)]
    if recovery_write_authority.is_none() {
        // Test-only raw-executor compatibility path.
        transition::terminalize_leaf_recovery_request(
            transaction,
            recovery_request_id,
            &LeafRecoveryTermination::Cancelled {
                terminal_signed_request_bytes: ctx.entry().signed_request_bytes.clone(),
                terminal_signing_transcript_bytes: ctx.entry().signing_transcript_bytes.clone(),
                terminal_request_digest: terminal_request_digest.clone(),
                terminal_signature: ctx.entry().signature.clone(),
                terminal_at: applied_at,
            },
        )
        .await?;
        transition::terminalize_reservation(
            transaction,
            recovery_request_id,
            &ReservationTermination::ReleasedByRequestDigest {
                terminal_request_digest,
                terminal_at: applied_at,
            },
        )
        .await?;
        transition::cas_key_package_status(
            transaction,
            &key_package_ref,
            RepoPackageStatus::Reserved,
            &PackageSuccessor::Reactivate,
        )
        .await?;
    }

    // 5. No control entry (internal op); only events.
    let event_positions = write_events(transaction, ctx, None).await?;

    Ok(AppliedTransition {
        allocated_seq: u64::try_from(successor_next_entry_seq).unwrap(),
        entry_id: ctx.entry().entry_id,
        event_positions,
        successor_coordinate: plan.successor_coordinate().copied(),
    })
}

/// Apply one due Recovery expiry as an entryless exact triple transition.
/// The executor is the sole business writer: request, reservation, package,
/// canonical event, and head verification share this savepoint.
#[allow(clippy::too_many_arguments)]
async fn apply_leaf_recovery_expiry(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &ConversationPersistencePlan,
    ctx: &ExecutionContext,
    conversation_id: Uuid,
    generation: i64,
    state_version: i64,
    _epoch: i64,
    recovery_write_authority: Option<
        &super::super::repository::recovery::RecoveryExecutorWriteAuthority<'_>,
    >,
) -> Result<AppliedTransition, ExecutorError> {
    let effects = plan.effects();
    let head = effects
        .head_cas()
        .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
    let expected_prior = head
        .expected_prior()
        .ok_or(ExecutorError::InconsistentPlan(
            "leaf recovery expiry needs a prior",
        ))?;
    let expected_generation = checked_i64(expected_prior.generation())?;
    let expected_state_version = checked_i64(expected_prior.state_version())?;
    let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;
    let successor_next_entry_seq = checked_i64(head.successor_next_entry_seq())?;
    let authority = match effects.authority() {
        Some(PlanAuthority::RecoveryExpiry(authority)) => authority,
        _ => {
            return Err(ExecutorError::InconsistentPlan(
                "leaf recovery expiry lacks authority",
            ))
        }
    };
    let operation_id = match &ctx.authority {
        ExecutionAuthority::Entryless { operation_id } => *operation_id,
        ExecutionAuthority::ControlEntry(_) => {
            return Err(ExecutorError::MissingContext(
                "entryless leaf recovery expiry authority",
            ))
        }
    };
    let terminal_at = server_instant(authority.terminal_at())?;
    if operation_id.as_bytes() != authority.request_id()
        || authority.observed_at() < authority.terminal_at()
        || authority.locked_read_set_digest() == &[0; 32]
        || head.allocated_entry_id().is_some()
        || head.allocated_seq().is_some()
        || head.successor_next_entry_seq() != head.expected_next_entry_seq()
        || head.locked_at() != authority.observed_at()
        || ctx.applied_at != terminal_at
        || generation != expected_generation
        || state_version != expected_state_version
        || successor_next_entry_seq != expected_next_entry_seq
    {
        return Err(ExecutorError::InconsistentPlan(
            "leaf recovery expiry authority/head drifted",
        ));
    }
    reject_if_present("participant_changes", effects.participant_changes())?;
    reject_if_present("leaf_changes", effects.leaf_changes())?;
    reject_if_present("interval_changes", effects.interval_changes())?;
    reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
    reject_if_present("reset_request_changes", effects.reset_request_changes())?;
    reject_if_present("leave_request_changes", effects.leave_request_changes())?;
    reject_if_present("welcome_changes", effects.welcome_changes())?;
    reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
    if effects.metadata_change().is_some()
        || effects.revocation_target_cas().is_some()
        || effects.welcome_cas().is_some()
        || effects.invitation_quota_cas().is_some()
        || effects.recovery_request_changes().len() != 1
        || effects.reservation_changes().len() != 1
        || effects.package_transitions().len() != 1
        || !ctx.entry_recipients.is_empty()
        || !ctx.opened_leaves.is_empty()
        || ctx.metadata_author.is_some()
        || !ctx.participant_period_ids.is_empty()
        || !ctx.leaf_period_ids.is_empty()
        || !ctx.closing_leaf_periods.is_empty()
        || !ctx.closing_participant_periods.is_empty()
        || ctx.reset_request_row.is_some()
        || ctx.recovery_open.is_some()
        || ctx.welcome_expiry.is_some()
        || ctx.welcome_response.is_some()
        || !ctx.welcome_dispositions.is_empty()
    {
        return Err(ExecutorError::InconsistentPlan(
            "leaf recovery expiry carries unrelated effects/context",
        ));
    }
    let expired = effects
        .recovery_request_changes()
        .iter()
        .find_map(|change| match (change.before(), change.after()) {
            (Some(before), Some(after))
                if before.status() == RecoveryRequestStatus::Open
                    && after.status() == RecoveryRequestStatus::Expired
                    && after.request_id() == authority.request_id()
                    && after.target() == authority.requester()
                    && *after.expires_at() == authority.terminal_at() =>
            {
                Some(after)
            }
            _ => None,
        })
        .ok_or(ExecutorError::InconsistentPlan(
            "leaf recovery expiry lacks exact request edge",
        ))?;
    let package_edge =
        effects
            .package_transitions()
            .first()
            .ok_or(ExecutorError::InconsistentPlan(
                "leaf recovery expiry lacks package edge",
            ))?;
    if package_edge.request_id() != authority.request_id()
        || package_edge.key_package_ref() != expired.key_package_ref()
        || package_edge.from() != PackageStatus::Reserved
        || !matches!(
            package_edge.to(),
            PackageStatus::Available | PackageStatus::Expired
        )
    {
        return Err(ExecutorError::InconsistentPlan(
            "leaf recovery expiry package edge is invalid",
        ));
    }
    verify_recovery_package_consistency(
        effects,
        expired.key_package_ref(),
        PackageStatus::Reserved,
        package_edge.to(),
    )?;
    if ctx.events.len() != 1
        || ctx.events[0].event_kind != EventKind::LeafRecovery
        || ctx.events[0].payload_bytes
            != delivery::canonical_leaf_recovery_event_payload(
                operation_id,
                conversation_id,
                delivery::LeafRecoveryEventStatus::Expired,
            )
        || ctx.events[0].outbox.len() != 1
        || ctx.events[0].outbox[0].1 != OutboxWorkKind::Stream
    {
        return Err(ExecutorError::InconsistentPlan(
            "leaf recovery expiry event is not canonical",
        ));
    }

    #[cfg(not(test))]
    recovery_write_authority
        .ok_or(ExecutorError::MissingContext(
            "missing validated Recovery executor write authority",
        ))?
        .apply_terminal(transaction)
        .await?;
    #[cfg(test)]
    if let Some(authority) = recovery_write_authority {
        authority.apply_terminal(transaction).await?;
    }
    transition::cas_conversation_head(
        transaction,
        &transition::ConversationHeadCas {
            conversation_id,
            expected_generation,
            expected_state_version,
            expected_next_entry_seq,
            successor_generation: generation,
            successor_state_version: state_version,
            successor_next_entry_seq,
            close: None,
        },
    )
    .await?;
    #[cfg(test)]
    if recovery_write_authority.is_none() {
        transition::terminalize_leaf_recovery_request(
            transaction,
            operation_id,
            &LeafRecoveryTermination::Expired { terminal_at },
        )
        .await?;
        transition::terminalize_reservation(
            transaction,
            operation_id,
            &ReservationTermination::Expired { terminal_at },
        )
        .await?;
        let successor = match package_edge.to() {
            PackageStatus::Available => PackageSuccessor::Reactivate,
            PackageStatus::Expired => PackageSuccessor::Expire { terminal_at },
            _ => unreachable!("expiry package successor checked above"),
        };
        transition::cas_key_package_status(
            transaction,
            expired.key_package_ref(),
            RepoPackageStatus::Reserved,
            &successor,
        )
        .await?;
    }
    let event_positions = write_events(transaction, ctx, None).await?;
    Ok(AppliedTransition {
        allocated_seq: u64::try_from(successor_next_entry_seq).unwrap(),
        entry_id: operation_id,
        event_positions,
        successor_coordinate: plan.successor_coordinate().copied(),
    })
}

/// Apply a `signedLeafRecoveryFulfillment` edge (kind `leafRecovery`): the
/// epoch-changing commit that adds the recovered target by KeyPackage and emits
/// its Welcome. sv+1, epoch+1 (new hash/tag), same generation. Composes: head
/// CAS + gen-state-version CAS + `commit`/active gen_state (epoch+1) +
/// leafRecoveryFulfillmentEntry + transition (`leafRecovery`) + metadata
/// RE-ENCRYPTION snapshot + exactly one `addLeafByRecovery` (the target's leaf
/// period, `keyPackage` origin with join provenance, + its `add`-opened interval
/// at the fulfillment seq) + request `fulfilled` / reservation `consumed` /
/// package `consumed` + Welcome bundle + delivery (`expires_at` == consumed
/// package `not_after`) + audience + `welcomeAvailable` event.
///
/// SCOPE: the single-request Add fulfillment (what the frozen corpus commit
/// exercises). Prior-coordinate open-request supersession (multiple
/// recovery/reservation/package changes) and a `replace` close are NOT composed
/// here — the exact-count guards below turn either into a hard `InconsistentPlan`
/// rather than a silent drop; they are a bounded follow-on once a corpus with a
/// second open request / a Remove-capable commit exists.
#[allow(clippy::too_many_arguments)]
async fn apply_leaf_recovery_fulfillment(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &ConversationPersistencePlan,
    ctx: &ExecutionContext,
    conversation_id: Uuid,
    transition_id: Uuid,
    seq_i64: i64,
    successor_next_entry_seq: i64,
    generation: i64,
    state_version: i64,
    epoch: i64,
    recovery_write_authority: Option<
        &super::super::repository::recovery::RecoveryExecutorWriteAuthority<'_>,
    >,
    historical_write_authority: Option<&HistoricalExecutionWriteAuthority>,
) -> Result<AppliedTransition, ExecutorError> {
    let effects = plan.effects();
    let hydration = plan.state();
    let coordinate = &hydration.coordinate; // successor (sv+1, epoch+1).
    let applied_at = ctx.applied_at;
    let head = effects
        .head_cas()
        .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
    let expected_prior = head
        .expected_prior()
        .ok_or(ExecutorError::InconsistentPlan("fulfillment needs a prior"))?;
    let expected_generation = checked_i64(expected_prior.generation())?;
    let expected_state_version = checked_i64(expected_prior.state_version())?;
    let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;

    // Guards: fulfillment carries leaf / interval / welcome / recovery-request /
    // reservation / package / metadata changes + (a legal interleaving)
    // prior-bound reset/leave STALING; reject the families it never has.
    reject_if_present("participant_changes", effects.participant_changes())?;
    reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
    reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
    if effects.revocation_target_cas().is_some()
        || effects.welcome_cas().is_some()
        || effects.invitation_quota_cas().is_some()
    {
        return Err(ExecutorError::UnsupportedEffect(
            "fulfillment revocation/welcome/quota CAS",
        ));
    }
    // Metadata re-encryption is MANDATORY (DDL requires_snapshot ∋ leafRecovery).
    let metadata = effects
        .metadata_change()
        .and_then(StateChange::after)
        .ok_or(ExecutorError::InconsistentPlan(
            "fulfillment carries no metadata re-encryption",
        ))?;
    let author_cols = ctx
        .metadata_author
        .as_ref()
        .ok_or(ExecutorError::MissingContext(
            "fulfillment commit metadata author",
        ))?;

    // Exact-SHAPE: exactly ONE own Open->Fulfilled recovery request +
    // Active->Consumed reservation + Reserved->Consumed package edge + one new
    // pending welcome. Any OTHER recovery/reservation/package delta must be a
    // prior-bound supersession (Open->Superseded / Active->Released /
    // Reserved->Available), consumed by write_prior_bound_supersessions.
    let own_fulfilled = effects
        .recovery_request_changes()
        .iter()
        .filter(|change| {
            matches!((change.before(), change.after()), (Some(b), Some(a))
                    if b.status() == RecoveryRequestStatus::Open
                        && a.status() == RecoveryRequestStatus::Fulfilled)
        })
        .count();
    let own_consumed = effects
        .reservation_changes()
        .iter()
        .filter(|change| {
            matches!((change.before(), change.after()), (Some(b), Some(a))
                    if b.status() == ReservationStatus::Active
                        && a.status() == ReservationStatus::Consumed)
        })
        .count();
    // Exactly ONE own NEW pending welcome. A `replace` fulfillment ALSO
    // supersedes the target's prior-bound pending welcome (a (Some,Some)
    // Pending->Superseded change consumed by write_welcome_supersessions +
    // reconcile), so the total welcome-change count is NOT constrained here —
    // only the own new-pending count is.
    let own_new_welcomes = effects
        .welcome_changes()
        .iter()
        .filter(|change| {
            matches!((change.before(), change.after()), (None, Some(a))
                    if a.status() == WelcomeStatus::Pending)
        })
        .count();
    if own_fulfilled != 1 || own_consumed != 1 || own_new_welcomes != 1 {
        return Err(ExecutorError::InconsistentPlan(
                "fulfillment must carry exactly one own fulfilled request + consumed reservation + welcome",
            ));
    }
    let fulfilled = effects
        .recovery_request_changes()
        .iter()
        .find_map(|change| match (change.before(), change.after()) {
            (Some(before), Some(after))
                if before.status() == RecoveryRequestStatus::Open
                    && after.status() == RecoveryRequestStatus::Fulfilled =>
            {
                Some(after)
            }
            _ => None,
        })
        .ok_or(ExecutorError::InconsistentPlan(
            "fulfillment fulfills no open recovery request",
        ))?;
    let recovery_request_id = Uuid::from_bytes(*fulfilled.request_id());
    let reserved_ref = *fulfilled.key_package_ref();
    // The OWN Reserved -> Consumed package edge (bijection + driven-ref +
    // direction); any other edges are Reserved->Available supersessions.
    verify_recovery_package_consistency(
        effects,
        &reserved_ref,
        PackageStatus::Reserved,
        PackageStatus::Consumed,
    )?;
    // Exactly one new pending welcome.
    let welcome = effects
        .welcome_changes()
        .iter()
        .find_map(|change| match (change.before(), change.after()) {
            (None, Some(after)) if after.status() == WelcomeStatus::Pending => Some(after),
            _ => None,
        })
        .ok_or(ExecutorError::InconsistentPlan(
            "fulfillment adds no pending welcome",
        ))?;
    let (preflight_prior_bound, partition) =
        preflight_leaf_recovery_fulfillment(plan, effects, hydration, ctx, transition_id, seq_i64)?;

    // 1. Head CAS sv+1.
    transition::cas_conversation_head(
        transaction,
        &transition::ConversationHeadCas {
            conversation_id,
            expected_generation,
            expected_state_version,
            expected_next_entry_seq,
            successor_generation: generation,
            successor_state_version: state_version,
            successor_next_entry_seq,
            close: None,
        },
    )
    .await?;

    // 2. Generation state-version pointer CAS (same generation).
    transition::cas_generation_state_version(
        transaction,
        &transition::GenerationStateVersionCas {
            conversation_id,
            generation,
            expected_state_version,
            successor_state_version: state_version,
        },
    )
    .await?;

    // 3. `commit`/active gen_state at the NEW epoch (fresh hash/tag).
    transition::insert_generation_state_row(
        transaction,
        &NewGenerationState {
            conversation_id,
            generation,
            state_version,
            group_id: coordinate.group_id().to_vec(),
            epoch,
            group_context_hash: coordinate.group_context_hash().to_vec(),
            confirmation_tag: coordinate.confirmation_tag().to_vec(),
            lifecycle: GenerationStateLifecycle::Active,
            state_kind: GenerationStateKind::Commit,
            producing_transition_id: transition_id,
            public_snapshot_bytes: ctx.spine.public_snapshot_bytes.clone(),
            snapshot_sha256: ctx.spine.public_snapshot_sha256.clone(),
            tree_summary_bytes: ctx.spine.tree_summary_bytes.clone(),
            tree_summary_sha256: ctx.spine.tree_summary_sha256.clone(),
            leaf_count: ctx.spine.leaf_count,
            created_at: applied_at,
        },
    )
    .await?;

    // 4. Entry (leafRecoveryFulfillmentEntry).
    let append = build_append_entry(
        ctx,
        conversation_id,
        generation,
        state_version,
        transition_id,
    );
    delivery::append_entry_at(transaction, &append, u64::try_from(seq_i64).unwrap()).await?;

    // 5. Transition (kind leafRecovery, prior -> next, carries the request).
    transition::insert_transition_row(
        transaction,
        &NewTransition {
            transition_id,
            conversation_id,
            kind: TransitionKind::LeafRecovery,
            actor_did: ctx.actor.user_did.clone(),
            actor_device_id: ctx.actor.device_id,
            actor_key_id: ctx.actor.key_id.clone(),
            actor_auth_generation: ctx.actor.auth_generation,
            actor_role: ctx.actor.role,
            actor_device_status: ctx.actor.device_status.clone(),
            signed_request_bytes: ctx.entry().signed_request_bytes.clone(),
            unsigned_projection_bytes: ctx.entry().unsigned_projection_bytes.clone(),
            signing_transcript_bytes: ctx.entry().signing_transcript_bytes.clone(),
            request_digest: ctx.entry().request_digest.clone(),
            signature: ctx.entry().signature.clone(),
            coordinates: TransitionCoordinates {
                prior: Some((expected_generation, expected_state_version)),
                next: Some((generation, state_version)),
                retired: None,
                successor: None,
            },
            reset_request_id: None,
            close_transition_id: None,
            metadata_snapshot_id: Some(author_cols.metadata_snapshot_id),
            entry_seq: seq_i64,
            accepted_at: applied_at,
        },
    )
    .await?;

    // 6. Metadata re-encryption snapshot (carry-forward author/origin/version).
    write_commit_metadata_snapshot(
        transaction,
        metadata,
        author_cols,
        conversation_id,
        generation,
        state_version,
        epoch,
        &coordinate.group_id().to_vec(),
        &coordinate.group_context_hash().to_vec(),
        &coordinate.confirmation_tag().to_vec(),
        transition_id,
        applied_at,
    )
    .await?;

    // 7. The target's recovered leaf. An `add` fulfillment opens a fresh
    //    (None,Some) leaf for a target that had none; a `replace` fulfillment
    //    ROTATES an existing target leaf — because the diff is keyed by DEVICE
    //    (not leaf index), the rotation surfaces as ONE (Some,Some) change for
    //    the target (the whole `LeafRecord` differs: new signature/encryption
    //    key + key-package origin), which must close the OLD leaf period and
    //    open a fresh one. A NON-target (Some,Some) is the committer's own
    //    tolerated key rotation — the DS `member_devices` row stores no
    //    ephemeral encryption key, so it needs no write. Any other leaf delta
    //    (a non-target add, or a full removal) is a hard error.
    let target = fulfilled.target().clone();
    let mut target_leaf: Option<(bool, &LeafRecord)> = None;
    for change in effects.leaf_changes() {
        match (change.before(), change.after()) {
            (None, Some(after)) if after.device() == &target => {
                if target_leaf.replace((false, after)).is_some() {
                    return Err(ExecutorError::InconsistentPlan(
                        "fulfillment carries more than one target leaf change",
                    ));
                }
            }
            (Some(_), Some(after)) if after.device() == &target => {
                if target_leaf.replace((true, after)).is_some() {
                    return Err(ExecutorError::InconsistentPlan(
                        "fulfillment carries more than one target leaf change",
                    ));
                }
            }
            (Some(_), Some(_)) => {}
            (None, Some(_)) | (Some(_), None) | (None, None) => {
                return Err(ExecutorError::InconsistentPlan(
                    "fulfillment carries an unexpected leaf change",
                ))
            }
        }
    }
    let (is_replace, new_leaf_change) = target_leaf.ok_or(ExecutorError::InconsistentPlan(
        "fulfillment carries no target leaf change",
    ))?;
    debug_assert_eq!(new_leaf_change.device(), &target);
    let leaf_row = hydration
        .leaves
        .iter()
        .find(|row| row.device == target)
        .ok_or(ExecutorError::InconsistentPlan(
            "recovered leaf not in hydration",
        ))?;
    let leaf_cols = ctx
        .opened_leaves
        .iter()
        .find(|cols| cols.device == target)
        .ok_or(ExecutorError::MissingContext("recovered leaf columns"))?;
    let leaf_period_id = *ctx
        .leaf_period_ids
        .first()
        .ok_or(ExecutorError::MissingContext("recovered leaf period id"))?;
    let participant_period_id = participant_period_for(ctx, hydration, target.principal())?;
    // A `replace` closes the target's OLD leaf period FIRST (a single active
    // leaf per device), sourcing the period id from ctx.closing_leaf_periods,
    // before the fresh period below reuses the vacated slot.
    if is_replace {
        let old_leaf_period = closing_leaf_period(ctx, &target)?;
        transition::close_leaf_period(
            transaction,
            &LeafClose {
                leaf_period_id: old_leaf_period,
                removed_state_version: state_version,
                removed_transition_id: transition_id,
                removed_seq: seq_i64,
                removed_at: applied_at,
            },
        )
        .await?;
    }
    transition::insert_leaf_period(
        transaction,
        &NewLeafPeriod {
            leaf_period_id,
            participant_period_id,
            conversation_id,
            generation,
            user_did: device_did(&target)?,
            device_id: device_uuid(&target),
            leaf_index: checked_i64(u64::from(leaf_row.leaf_index))?,
            basic_credential: leaf_row.basic_credential.clone(),
            leaf_signature_key: leaf_row.signature_key.clone(),
            leaf_key_id: leaf_cols.leaf_key_id.clone(),
            leaf_auth_generation: leaf_cols.leaf_auth_generation,
            origin: LeafOrigin::KeyPackage {
                key_package_ref: reserved_ref.to_vec(),
            },
            joined_state_version: state_version,
            joined_transition_id: transition_id,
            joined_seq: seq_i64,
            created_at: applied_at,
        },
    )
    .await?;

    // 8. Intervals. The target's fresh `add` interval opens at the fulfillment
    //    seq (keyed on the new opening seq). A `replace` ADDITIONALLY carries
    //    the target's PRIOR interval as a (Some,Some) close (keyed on the old
    //    opening seq), `Replace`-closed inclusively at the fulfillment seq —
    //    the removed old leaf period sources the close. Every interval change
    //    must be consumed; the counts are asserted against the request kind.
    let mut opened_intervals = 0usize;
    let mut closed_intervals = 0usize;
    for change in effects.interval_changes() {
        match (change.before(), change.after()) {
            (None, Some(after)) => {
                if after.recipient() != &target
                    || after.opening_kind() != super::OpeningKind::Add
                    || after.end().is_some()
                {
                    return Err(ExecutorError::InconsistentPlan(
                        "fulfillment opens an unexpected interval",
                    ));
                }
                let opening_context = after.opening_context();
                delivery::insert_application_interval(
                    transaction,
                    &NewApplicationInterval {
                        membership_interval_id: Uuid::from_bytes(*after.opening_transition_id()),
                        conversation_id,
                        generation: checked_i64(opening_context.generation())?,
                        recipient_did: device_did(after.recipient())?,
                        recipient_device_id: device_uuid(after.recipient()),
                        start_seq: checked_i64(after.opening_seq())?,
                        opening_kind: IntervalOpeningKind::Add,
                        opening_transition_id: Uuid::from_bytes(*after.opening_transition_id()),
                        opening_outer_entry_fingerprint: after
                            .opening_outer_entry_fingerprint()
                            .to_vec(),
                        opening_state_version: checked_i64(opening_context.state_version())?,
                        opening_group_id: opening_context.group_id().to_vec(),
                        opening_epoch: checked_i64(opening_context.epoch())?,
                        opening_group_context_hash: opening_context.group_context_hash().to_vec(),
                        opening_confirmation_tag: opening_context.confirmation_tag().to_vec(),
                        opening_leaf_period_id: leaf_period_id,
                        created_at: applied_at,
                    },
                )
                .await?;
                opened_intervals += 1;
            }
            (Some(_), Some(after)) => {
                let end = after.end().ok_or(ExecutorError::InconsistentPlan(
                    "fulfillment replace-close carries no interval end",
                ))?;
                if after.recipient() != &target || end.kind() != CloseKind::Replace {
                    return Err(ExecutorError::InconsistentPlan(
                        "fulfillment closes an unexpected interval",
                    ));
                }
                let old_leaf_period = closing_leaf_period(ctx, after.recipient())?;
                delivery::close_application_interval(
                    transaction,
                    &ApplicationIntervalClose {
                        membership_interval_id: Uuid::from_bytes(*after.opening_transition_id()),
                        terminal_seq: checked_i64(end.seq())?,
                        closing_state_version: state_version,
                        closing_transition_id: Uuid::from_bytes(*end.transition_id()),
                        closing_outer_entry_fingerprint: end.outer_entry_fingerprint().to_vec(),
                        closing_kind: repo_interval_close_kind(end.kind()),
                        closing_leaf_period_id: old_leaf_period,
                        removed_at: applied_at,
                    },
                )
                .await?;
                closed_intervals += 1;
            }
            (Some(_), None) | (None, None) => {
                return Err(ExecutorError::InconsistentPlan(
                    "fulfillment carries an unexpected interval change",
                ))
            }
        }
    }
    let expected_closed = usize::from(is_replace);
    if opened_intervals != 1 || closed_intervals != expected_closed {
        return Err(ExecutorError::InconsistentPlan(
            "fulfillment interval changes do not match the request kind",
        ));
    }

    // 9. Terminalize the exact full-row triple. This remains after the
    //    transition insert because the fulfilled rows reference it, while
    //    the prewrite reread already rejected all triple drift before the
    //    savepoint's first mutation.
    if let Some(authority) = recovery_write_authority {
        authority.apply_terminal(transaction).await?;
    } else {
        // No live Recovery write authority exists for a reconstructed historical
        // prefix, so replay terminalizes the triple directly; test builds share
        // that path, and production without either authority fails closed.
        #[cfg(not(test))]
        {
            if historical_write_authority.is_none() {
                return Err(ExecutorError::MissingContext(
                    "missing validated Recovery executor write authority",
                ));
            }
        }
        transition::terminalize_leaf_recovery_request(
            transaction,
            recovery_request_id,
            &LeafRecoveryTermination::Fulfilled {
                fulfilling_transition_id: transition_id,
                terminal_at: applied_at,
            },
        )
        .await?;
        transition::terminalize_reservation(
            transaction,
            recovery_request_id,
            &ReservationTermination::Consumed {
                consumed_transition_id: transition_id,
                terminal_at: applied_at,
            },
        )
        .await?;
        transition::cas_key_package_status(
            transaction,
            &reserved_ref,
            RepoPackageStatus::Reserved,
            &PackageSuccessor::Consume {
                terminal_transition_id: transition_id,
                terminal_at: applied_at,
            },
        )
        .await?;
    }

    // 10. Welcome bundle + delivery (expires_at == consumed package not_after).
    let welcome_id = Uuid::from_bytes(*welcome.welcome_id());
    delivery::insert_welcome_bundle(
        transaction,
        &NewWelcomeBundle {
            welcome_id,
            conversation_id,
            transition_id,
            entry_seq: seq_i64,
            generation,
            state_version,
            group_id: coordinate.group_id().to_vec(),
            epoch,
            group_context_hash: coordinate.group_context_hash().to_vec(),
            confirmation_tag: coordinate.confirmation_tag().to_vec(),
            wrapper_bytes: welcome.opaque_welcome().to_vec(),
            wrapper_sha256: welcome.sha256().to_vec(),
            created_at: applied_at,
        },
    )
    .await?;
    delivery::insert_welcome_delivery(
        transaction,
        &NewWelcomeDelivery {
            welcome_id,
            recipient_did: device_did(welcome.recipient())?,
            recipient_device_id: device_uuid(welcome.recipient()),
            recovery_request_id,
            key_package_ref: welcome.key_package_ref().to_vec(),
            expires_at: server_instant(welcome.expires_at())?,
        },
    )
    .await?;
    let recipient_did_str = device_did(welcome.recipient())?;
    let self_base = crate::identity::service_did_base();
    let participant_row: Option<Option<String>> = sqlx::query_scalar(
        "SELECT ds_did FROM chat.participants \
         WHERE conversation_id = $1 AND user_did = $2 \
           AND current_membership = TRUE AND status IN ('pending', 'active')",
    )
    .bind(conversation_id)
    .bind(&recipient_did_str)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|e| ExecutorError::Delivery(DeliveryRepositoryError::Database(e)))?;

    let ds_did_opt = match participant_row {
        None => {
            tracing::error!(
                conversation_id = %crate::crypto::redact_for_log(&conversation_id.hyphenated().to_string()),
                recipient_did = %crate::crypto::redact_for_log(&recipient_did_str),
                "welcome emission failed: recipient participant is absent from conversation"
            );
            return Err(ExecutorError::InconsistentPlan(
                "recipient participant not found in conversation for welcome emission",
            ));
        }
        Some(ds_did_opt) => ds_did_opt,
    };

    let is_local = match &ds_did_opt {
        None => true,
        Some(ds) => {
            let canonical_ds = crate::identity::canonical_did(ds);
            crate::identity::dids_equivalent(&canonical_ds, &self_base)
        }
    };

    if is_local || historical_write_authority.is_some() {
        tracing::debug!(
            conversation_id = %crate::crypto::redact_for_log(&conversation_id.hyphenated().to_string()),
            recipient_did = %crate::crypto::redact_for_log(&recipient_did_str),
            "welcome emission: recipient is local participant or historical reconstruction, skipping remote federation enqueue"
        );
    } else {
        let target_ds_did = ds_did_opt.unwrap();
        let pub_snap_sha: [u8; 32] = ctx
            .spine
            .public_snapshot_sha256
            .as_slice()
            .try_into()
            .map_err(|_| ExecutorError::InconsistentPlan("invalid public snapshot sha256"))?;
        let tree_sum_sha: [u8; 32] = ctx
            .spine
            .tree_summary_sha256
            .as_slice()
            .try_into()
            .map_err(|_| ExecutorError::InconsistentPlan("invalid tree summary sha256"))?;

        let coordinates = catbird_atproto::generated::blue_catbird::chat::ConversationCoordinates {
            conversation_id: jacquard_common::deps::smol_str::SmolStr::from(
                conversation_id.hyphenated().to_string(),
            ),
            generation,
            state_version,
            epoch,
            group_id: jacquard_common::deps::bytes::Bytes::copy_from_slice(coordinate.group_id()),
            group_context_hash: jacquard_common::deps::bytes::Bytes::copy_from_slice(
                coordinate.group_context_hash(),
            ),
            confirmation_tag: jacquard_common::deps::bytes::Bytes::copy_from_slice(
                coordinate.confirmation_tag(),
            ),
            lifecycle: jacquard_common::deps::smol_str::SmolStr::from(
                match coordinate.lifecycle() {
                    crate::chat_protocol::snapshot::PublicGroupSnapshotLifecycle::Active => {
                        "active"
                    }
                    crate::chat_protocol::snapshot::PublicGroupSnapshotLifecycle::Superseded => {
                        "superseded"
                    }
                },
            ),
            extra_data: None,
        };

        crate::chat_protocol::repository::federation::enqueue_federated_welcome_job(
            transaction,
            conversation_id,
            &target_ds_did,
            &recipient_did_str,
            device_uuid(welcome.recipient()),
            welcome_id,
            recovery_request_id,
            &reserved_ref,
            welcome.opaque_welcome(),
            welcome.sha256(),
            &append,
            u64::try_from(seq_i64).unwrap(),
            coordinates,
            &pub_snap_sha,
            &tree_sum_sha,
            ctx.sequencer_term as u64,
        )
        .await
        .map_err(|e| {
            tracing::error!(?e, "failed to enqueue federated welcome job");
            ExecutorError::InconsistentPlan("failed to enqueue federated welcome job")
        })?;
    }

    // 11. Audience + events.
    let recipients = build_entry_recipients(&ctx.entry_recipients)?;
    if !recipients.is_empty() {
        delivery::insert_entry_recipients(
            transaction,
            conversation_id,
            u64::try_from(seq_i64).unwrap(),
            &recipients,
        )
        .await?;
    }
    let event_positions = write_events(transaction, ctx, historical_write_authority).await?;
    // Prior-coordinate open-work supersession (a legal interleaving): the corpus
    // fulfillment carries none, but the path composes it for the general case.
    let receipt =
        write_prior_bound_supersessions(transaction, effects, transition_id, applied_at).await?;
    // Design 5 step 6: reconcile the recovery families against the classifier's
    // KEYED expectation immediately, before any other writer runs. No unrelated
    // write may intervene. The counts are reachable ONLY through this call, so the
    // fence cannot be dropped without breaking the build.
    let mut superseded = receipt.reconcile_into_counts(&partition)?;
    superseded.welcomes = write_welcome_supersessions(
        transaction,
        ctx,
        effects,
        WelcomeSupersessionCause::Transition {
            terminal_transition_id: transition_id,
        },
    )
    .await?;
    // Durably stale any prior-bound pending reset/leave request the coordinate
    // change retired (this arm owns none — kind is `leafRecovery`, DB-legal for
    // the leave `stale` edge).
    let staled = write_prior_bound_staling(
        transaction,
        effects,
        transition_id,
        &ctx.entry().request_digest,
        applied_at,
    )
    .await?;
    superseded.reset_requests = staled.reset_requests;
    superseded.leave_requests = staled.leave_requests;
    if superseded != preflight_prior_bound {
        return Err(ExecutorError::InconsistentPlan(
            "fulfillment applied prior-bound counts disagree with preflight",
        ));
    }
    // Silent-drop guard: this arm's OWN edges are exactly one fulfilled request +
    // consumed reservation + Reserved->Consumed package + new pending welcome; every
    // OTHER delta MUST be a supersession/staling the calls above applied. Reject any
    // delta that is neither (e.g. an Open->Expired request) rather than dropping it.
    reconcile_coordinate_change_families(
        effects,
        &FamilyCounts {
            requests: 1,
            reservations: 1,
            packages: 1,
            welcomes: 1,
            reset_requests: 0,
            leave_requests: 0,
        },
        &superseded,
    )?;

    Ok(AppliedTransition {
        allocated_seq: u64::try_from(seq_i64).unwrap(),
        entry_id: ctx.entry().entry_id,
        event_positions,
        successor_coordinate: plan.successor_coordinate().copied(),
    })
}

/// Apply a generic `signedCommitTransition` (zero Adds): an epoch-changing
/// crypto commit that may carry canonical RemoveLeaf effects. sv+1 AND epoch+1
/// with a fresh hash/tag, metadata re-encryption, exact removed leaf-period and
/// application-interval closes, and no participant terminalization or own
/// welcome/recovery work. Distinguished from a fulfillment by the ABSENCE of a
/// new Welcome (a recovery fulfillment always emits exactly one), backstopped
/// by the exact-shape and bijection guards below.
#[allow(clippy::too_many_arguments)]
async fn apply_generic_commit(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &ConversationPersistencePlan,
    ctx: &ExecutionContext,
    conversation_id: Uuid,
    transition_id: Uuid,
    seq_i64: i64,
    successor_next_entry_seq: i64,
    generation: i64,
    state_version: i64,
    epoch: i64,
) -> Result<AppliedTransition, ExecutorError> {
    let effects = plan.effects();
    let hydration = plan.state();
    let coordinate = &hydration.coordinate; // successor (sv+1, epoch+1).
    let applied_at = ctx.applied_at;
    let head = effects
        .head_cas()
        .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
    let expected_prior = head
        .expected_prior()
        .ok_or(ExecutorError::InconsistentPlan(
            "generic commit needs a prior",
        ))?;
    let expected_generation = checked_i64(expected_prior.generation())?;
    let expected_state_version = checked_i64(expected_prior.state_version())?;
    let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;

    // A generic no-Add commit changes the crypto coordinate + re-encrypted
    // metadata, MAY close signed RemoveLeaf devices and their intervals, and MAY
    // carry legal prior-coordinate open-work supersession/staling. It has no
    // participant change and no OWN recovery/reset/leave work.
    reject_if_present("participant_changes", effects.participant_changes())?;
    reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
    reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
    // recovery_request_changes / reservation_changes / package_transitions /
    // welcome_changes: NOT rejected — a coordinate-changing commit supersedes
    // prior-coordinate open work (request->Superseded, reservation->Released,
    // package Reserved->Available) and a prior pending Welcome. Handled by
    // write_prior_bound_supersessions + write_welcome_supersessions; every such
    // delta MUST be a supersession shape (exact-shape checks below).
    // Prior-bound recovery families. The three shape loops this replaces
    // accepted only Row A (Open->Superseded / Active->Released) and never
    // checked terminal evidence, family identity, or the CAS bindings — so a
    // legal Row B due-expiry family was rejected here exactly as it was in leaf
    // recovery fulfillment. The shared classifier proves both rows, strictly
    // before this arm's first head CAS.
    let partition = classify_prior_bound_recovery(plan, ctx, OwnFamilyKind::None)?; // generic commit

    // Prior-bound reset / leave / Welcome families. A generic commit owns none of
    // them, so every such delta must be an exact terminalization of prior-bound
    // work. The tail reconciliation only counts what the writers consumed, and
    // both writers accept a `Pending->Expired` shape, so an incoherent expiry
    // used to commit here.
    classify_prior_bound_staling(plan, ctx, OwnStalingKind::None)?;
    if effects.revocation_target_cas().is_some()
        || effects.welcome_cas().is_some()
        || effects.invitation_quota_cas().is_some()
    {
        return Err(ExecutorError::UnsupportedEffect(
            "generic commit revocation/welcome/quota CAS",
        ));
    }
    // Validate the leaf/interval/context three-way bijection before the first
    // write. Some->None is a real signed Remove. Some->Some is tolerated only
    // for the actor's stable leaf identity/key material (the public tree's
    // sender encryption-key update is not stored in member_devices). Adds,
    // empty deltas, foreign/duplicate context, and every unmatched close reject.
    let mut removed_devices = BTreeSet::new();
    for change in effects.leaf_changes() {
        match (change.before(), change.after()) {
            (Some(before), None) => {
                if !removed_devices.insert(before.device.clone()) {
                    return Err(ExecutorError::InconsistentPlan(
                        "generic commit duplicates a removed leaf",
                    ));
                }
            }
            (Some(before), Some(after))
                if before.device == after.device
                    && before.leaf_index == after.leaf_index
                    && before.basic_credential == after.basic_credential
                    && before.signature_key == after.signature_key
                    && before.key_package_ref == after.key_package_ref
                    && device_did(&before.device)? == ctx.actor.user_did
                    && device_uuid(&before.device) == ctx.actor.device_id => {}
            (None, Some(_)) => {
                return Err(ExecutorError::InconsistentPlan(
                    "generic commit must not add a leaf",
                ))
            }
            (None, None) => {
                return Err(ExecutorError::InconsistentPlan(
                    "generic commit carries an empty leaf delta",
                ))
            }
            (Some(_), Some(_)) => {
                return Err(ExecutorError::InconsistentPlan(
                    "generic commit carries a non-sender leaf update",
                ))
            }
        }
    }
    let declared_closed = effects
        .closed_intervals()
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if !effects.opened_intervals().is_empty() || declared_closed != removed_devices {
        return Err(ExecutorError::InconsistentPlan(
            "generic commit removed-leaf and closed-interval declarations disagree",
        ));
    }
    let mut interval_devices = BTreeSet::new();
    for change in effects.interval_changes() {
        let (before, after) = match (change.before(), change.after()) {
            (Some(before), Some(after)) => (before, after),
            _ => {
                return Err(ExecutorError::InconsistentPlan(
                    "generic commit interval delta is not an exact close",
                ))
            }
        };
        let end = after.end.as_ref().ok_or(ExecutorError::InconsistentPlan(
            "generic commit interval close has no end",
        ))?;
        if before.recipient != after.recipient
            || before.generation != after.generation
            || before.opening != after.opening
            || before.opening_kind != after.opening_kind
            || before.opening_context != after.opening_context
            || before.end.is_some()
            || end.kind != CloseKind::Remove
            || end.evidence != hydration.producer
            || !removed_devices.contains(&after.recipient)
            || !interval_devices.insert(after.recipient.clone())
        {
            return Err(ExecutorError::InconsistentPlan(
                "generic commit interval close mismatches its removed leaf",
            ));
        }
    }
    if interval_devices != removed_devices {
        return Err(ExecutorError::InconsistentPlan(
            "generic commit removal lacks exactly one matching interval close",
        ));
    }
    let mut context_devices = BTreeSet::new();
    let mut context_periods = BTreeSet::new();
    for (device, period_id) in &ctx.closing_leaf_periods {
        if !removed_devices.contains(device)
            || !context_devices.insert(device.clone())
            || !context_periods.insert(*period_id)
        {
            return Err(ExecutorError::InconsistentPlan(
                "generic commit closing leaf context is foreign or duplicated",
            ));
        }
    }
    for device in &removed_devices {
        if !context_devices.contains(device) {
            return Err(ExecutorError::MissingContext(
                "closing leaf period id for generic Remove",
            ));
        }
    }
    // Metadata re-encryption is MANDATORY (DDL requires_snapshot ∋ commit).
    let metadata = effects
        .metadata_change()
        .and_then(StateChange::after)
        .ok_or(ExecutorError::InconsistentPlan(
            "generic commit carries no metadata re-encryption",
        ))?;
    let author_cols = ctx
        .metadata_author
        .as_ref()
        .ok_or(ExecutorError::MissingContext(
            "generic commit metadata author",
        ))?;
    let leaf_period_bindings = removed_devices
        .iter()
        .map(|device| {
            Ok(ActiveLeafPeriodBinding {
                leaf_period_id: closing_leaf_period(ctx, device)?,
                conversation_id,
                generation: expected_generation,
                user_did: device_did(device)?,
                device_id: device_uuid(device),
            })
        })
        .collect::<Result<Vec<_>, ExecutorError>>()?;
    if !transition::lock_active_leaf_period_bindings(transaction, &leaf_period_bindings).await? {
        return Err(ExecutorError::InconsistentPlan(
            "generic commit closing leaf period mismatches its removed device",
        ));
    }

    // 1. Head CAS sv+1 (the epoch bump lives in the gen_state).
    transition::cas_conversation_head(
        transaction,
        &transition::ConversationHeadCas {
            conversation_id,
            expected_generation,
            expected_state_version,
            expected_next_entry_seq,
            successor_generation: generation,
            successor_state_version: state_version,
            successor_next_entry_seq,
            close: None,
        },
    )
    .await?;

    // 2. Generation state-version pointer CAS (same generation).
    transition::cas_generation_state_version(
        transaction,
        &transition::GenerationStateVersionCas {
            conversation_id,
            generation,
            expected_state_version,
            successor_state_version: state_version,
        },
    )
    .await?;

    // 3. `commit`/active gen_state at the NEW epoch (fresh hash/tag).
    transition::insert_generation_state_row(
        transaction,
        &NewGenerationState {
            conversation_id,
            generation,
            state_version,
            group_id: coordinate.group_id().to_vec(),
            epoch,
            group_context_hash: coordinate.group_context_hash().to_vec(),
            confirmation_tag: coordinate.confirmation_tag().to_vec(),
            lifecycle: GenerationStateLifecycle::Active,
            state_kind: GenerationStateKind::Commit,
            producing_transition_id: transition_id,
            public_snapshot_bytes: ctx.spine.public_snapshot_bytes.clone(),
            snapshot_sha256: ctx.spine.public_snapshot_sha256.clone(),
            tree_summary_bytes: ctx.spine.tree_summary_bytes.clone(),
            tree_summary_sha256: ctx.spine.tree_summary_sha256.clone(),
            leaf_count: ctx.spine.leaf_count,
            created_at: applied_at,
        },
    )
    .await?;

    // 4. Entry (commitEntry).
    let append = build_append_entry(
        ctx,
        conversation_id,
        generation,
        state_version,
        transition_id,
    );
    delivery::append_entry_at(transaction, &append, u64::try_from(seq_i64).unwrap()).await?;

    // 5. Transition (kind commit, prior -> next).
    transition::insert_transition_row(
        transaction,
        &NewTransition {
            transition_id,
            conversation_id,
            kind: TransitionKind::Commit,
            actor_did: ctx.actor.user_did.clone(),
            actor_device_id: ctx.actor.device_id,
            actor_key_id: ctx.actor.key_id.clone(),
            actor_auth_generation: ctx.actor.auth_generation,
            actor_role: ctx.actor.role,
            actor_device_status: ctx.actor.device_status.clone(),
            signed_request_bytes: ctx.entry().signed_request_bytes.clone(),
            unsigned_projection_bytes: ctx.entry().unsigned_projection_bytes.clone(),
            signing_transcript_bytes: ctx.entry().signing_transcript_bytes.clone(),
            request_digest: ctx.entry().request_digest.clone(),
            signature: ctx.entry().signature.clone(),
            coordinates: TransitionCoordinates {
                prior: Some((expected_generation, expected_state_version)),
                next: Some((generation, state_version)),
                retired: None,
                successor: None,
            },
            reset_request_id: None,
            close_transition_id: None,
            metadata_snapshot_id: Some(author_cols.metadata_snapshot_id),
            entry_seq: seq_i64,
            accepted_at: applied_at,
        },
    )
    .await?;

    // 6. Metadata re-encryption snapshot (carry-forward author/origin/version).
    write_commit_metadata_snapshot(
        transaction,
        metadata,
        author_cols,
        conversation_id,
        generation,
        state_version,
        epoch,
        &coordinate.group_id().to_vec(),
        &coordinate.group_context_hash().to_vec(),
        &coordinate.confirmation_tag().to_vec(),
        transition_id,
        applied_at,
    )
    .await?;

    // 7. Close every removed leaf period and its one exact Remove interval.
    for change in effects.leaf_changes() {
        if let (Some(before), None) = (change.before(), change.after()) {
            transition::close_leaf_period(
                transaction,
                &LeafClose {
                    leaf_period_id: closing_leaf_period(ctx, before.device())?,
                    removed_state_version: state_version,
                    removed_transition_id: transition_id,
                    removed_seq: seq_i64,
                    removed_at: applied_at,
                },
            )
            .await?;
        }
    }
    for change in effects.interval_changes() {
        let after = change.after().ok_or(ExecutorError::InconsistentPlan(
            "validated generic interval close disappeared",
        ))?;
        let end = after.end().ok_or(ExecutorError::InconsistentPlan(
            "validated generic interval end disappeared",
        ))?;
        delivery::close_application_interval(
            transaction,
            &ApplicationIntervalClose {
                membership_interval_id: Uuid::from_bytes(*after.opening_transition_id()),
                terminal_seq: checked_i64(end.seq())?,
                closing_state_version: state_version,
                closing_transition_id: Uuid::from_bytes(*end.transition_id()),
                closing_outer_entry_fingerprint: end.outer_entry_fingerprint().to_vec(),
                closing_kind: repo_interval_close_kind(end.kind()),
                closing_leaf_period_id: closing_leaf_period(ctx, after.recipient())?,
                removed_at: applied_at,
            },
        )
        .await?;
    }

    // 8. Audience + events.
    let recipients = build_entry_recipients(&ctx.entry_recipients)?;
    delivery::insert_entry_recipients(
        transaction,
        conversation_id,
        u64::try_from(seq_i64).unwrap(),
        &recipients,
    )
    .await?;
    let event_positions = write_events(transaction, ctx, None).await?;
    // Supersede prior-coordinate open work (requests/reservations/packages) +
    // any prior pending Welcome the epoch change retired.
    let receipt =
        write_prior_bound_supersessions(transaction, effects, transition_id, applied_at).await?;
    // Design 5 step 6: reconcile the recovery families against the classifier's
    // KEYED expectation immediately, before any other writer runs. No unrelated
    // write may intervene. The counts are reachable ONLY through this call, so the
    // fence cannot be dropped without breaking the build.
    let mut superseded = receipt.reconcile_into_counts(&partition)?;
    superseded.welcomes = write_welcome_supersessions(
        transaction,
        ctx,
        effects,
        WelcomeSupersessionCause::Transition {
            terminal_transition_id: transition_id,
        },
    )
    .await?;
    // Durably stale any prior-bound pending reset/leave request the epoch change
    // retired (kind is `commit`, DB-legal for the leave `stale` edge).
    let staled = write_prior_bound_staling(
        transaction,
        effects,
        transition_id,
        &ctx.entry().request_digest,
        applied_at,
    )
    .await?;
    superseded.reset_requests = staled.reset_requests;
    superseded.leave_requests = staled.leave_requests;
    // Silent-drop guard: a generic commit has NO own recovery/reservation/package/
    // welcome/reset/leave edge — every such delta MUST be a supersession/staling the
    // calls above applied. The per-delta shape loops above already reject a malformed
    // recovery/reservation/package delta; this additionally catches a malformed
    // welcome delta (e.g. Pending->Expired) or a non-Pending->Stale reset/leave delta
    // that the writers skip, closing the last silent-drop path.
    reconcile_coordinate_change_families(effects, &FamilyCounts::default(), &superseded)?;

    Ok(AppliedTransition {
        allocated_seq: u64::try_from(seq_i64).unwrap(),
        entry_id: ctx.entry().entry_id,
        event_positions,
        successor_coordinate: plan.successor_coordinate().copied(),
    })
}

/// Apply a `leaveCommitFulfillment` (`PlanKind::Commit`): a DIFFERENT-DID
/// current member commits a Remove of every requester leaf, fulfilling the
/// requester's retained group-leave consent. `sv+1` AND `epoch+1` (fresh
/// hash/tag), metadata re-encryption carry-forward (`leaveCommit` ∈
/// requires_snapshot), every requester leaf closed + its interval closed
/// (`Remove`, inclusive at the fulfillment seq), the requester participant
/// terminalized, and the pending leave request marked `fulfilled` (bound to
/// this `leaveCommit` transition). Coordinate-changing, so it runs the SHARED
/// prior-bound supersession path WITH the reconciliation from the start — the
/// fulfillment-scenario prior carries a pending Welcome the epoch change
/// supersedes (own welcome 0 + superseded 1). The committer's own key rotation
/// surfaces as a `(Some,Some)` leaf change with no DS row impact (tolerated).
#[allow(clippy::too_many_arguments)]
/// The synchronous family guards `apply_leave_fulfillment` runs before its first
/// writer, extracted so they are reachable without a database.
///
/// DEFECT 1 lived here: the second line used to be
/// `reject_if_present("recovery_package_cas", ..)`, which — because
/// `into_persistence_plan` enforces the CAS <-> edge bijection — meant "reject any
/// plan carrying any package edge", the exact opposite of the arm's own comment.
/// Any `leaveCommit` on a coordinate with open recovery work was planner-legal and
/// executor-fatal. `apply_leave_fulfillment` is `async` and needs a live transaction,
/// so before this extraction the shipped defect could be reinstated with the whole
/// suite still green. It is now pinned by
/// `leave_fulfillment_preflight_classifies_prior_bound_work`.
fn preflight_leave_fulfillment(
    plan: &ConversationPersistencePlan,
    ctx: &ExecutionContext,
) -> Result<PriorBoundPartition, ExecutorError> {
    let effects = plan.effects();
    reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
    // Prior-bound package work is CLASSIFIED, not rejected.
    let partition = classify_prior_bound_recovery(plan, ctx, OwnFamilyKind::None)?;
    // Prior-bound reset / leave / Welcome families. The arm's ONE own leave edge
    // (Pending->Fulfilled) is selected out by kind; every other delta must be an
    // exact terminalization of prior-bound work.
    classify_prior_bound_staling(plan, ctx, OwnStalingKind::LeaveFulfillment)?;
    reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
    if effects.revocation_target_cas().is_some()
        || effects.welcome_cas().is_some()
        || effects.invitation_quota_cas().is_some()
    {
        return Err(ExecutorError::UnsupportedEffect(
            "leave fulfillment revocation/welcome/quota CAS",
        ));
    }
    Ok(partition)
}

/// Partition `apply_leave_fulfillment`'s leave-request deltas and return the ONE
/// request the commit fulfills (ADR-019 Erratum 01).
///
/// Extracted so it is reachable WITHOUT a database, for the same reason
/// `preflight_leave_fulfillment` was: `apply_leave_fulfillment` is `async` and
/// needs a live transaction, so a shipped defect in this partition could be
/// reinstated with the whole suite still green. Pinned by
/// `leave_fulfillment_partition_accepts_an_overdue_prior_bound_leave`.
fn partition_leave_fulfillment_requests(
    effects: &TransitionEffects,
) -> Result<[u8; 16], ExecutorError> {
    // Partition the leave-request deltas (ADR-019 Erratum 01). A leaveCommit
    // fulfills EXACTLY ONE requester's leave (its own Pending->Fulfilled edge) and
    // MAY additionally retire any number of OTHER members' predecessor-bound
    // pending leaves — `Pending->Stale` when the commit supersedes them, or
    // `Pending->Expired` when their own 24h `expires_at` had already passed at
    // `evidence.received_at` (`resolve_prior_bound_work` picks the row; the
    // OVERDUE case is Row B). Both are legal prior-bound terminalizations that the
    // shared `classify_prior_bound_staling` proves exactly and
    // `write_prior_bound_staling` already writes, so both must be accepted here or
    // an overdue peer leave permanently wedges every leaveCommit on the
    // coordinate. This arm's OWN request can never be Row B:
    // `plan_leave_fulfillment_inner` rejects an overdue target with `WorkExpired`
    // before planning.
    //
    // Reject every other shape: a non-transition delta, a request that did not
    // start Pending, a re-binding (ruling point 4), a second Fulfilled, or a
    // retirement that targets the fulfilled request itself (ruling point 3 — the
    // fulfilled request is `fulfilled`, never `stale`/`expired`). The retired
    // others flow through `write_prior_bound_staling` at the tail; reconcile
    // own(1) + staled == total.
    let mut fulfilled_request_id: Option<[u8; 16]> = None;
    for change in effects.leave_request_changes() {
        let (before, after) = match (change.before(), change.after()) {
            (Some(before), Some(after)) => (before, after),
            _ => {
                return Err(ExecutorError::InconsistentPlan(
                    "leave fulfillment leave-request delta must be a status transition",
                ))
            }
        };
        if before.status() != LeaveRequestStatus::Pending {
            return Err(ExecutorError::InconsistentPlan(
                "leave fulfillment leave-request delta must start Pending",
            ));
        }
        if before.bound_coordinate != after.bound_coordinate {
            return Err(ExecutorError::InconsistentPlan(
                "leave fulfillment must not re-bind a leave request",
            ));
        }
        match after.status() {
            LeaveRequestStatus::Fulfilled => {
                if fulfilled_request_id.is_some() {
                    return Err(ExecutorError::InconsistentPlan(
                        "leave fulfillment must fulfill exactly one leave request",
                    ));
                }
                fulfilled_request_id = Some(after.request_id);
            }
            LeaveRequestStatus::Stale | LeaveRequestStatus::Expired => {}
            _ => {
                return Err(ExecutorError::InconsistentPlan(
                    "leave fulfillment leave-request delta must be Fulfilled, Stale or Expired",
                ))
            }
        }
    }
    let fulfilled_request_id = fulfilled_request_id.ok_or(ExecutorError::InconsistentPlan(
        "leave fulfillment must fulfill a pending leave request",
    ))?;
    // Ruling point 3: no prior-bound retirement may target the request being
    // fulfilled — neither a staling nor a due expiry.
    for change in effects.leave_request_changes() {
        if let Some(after) = change.after() {
            if matches!(
                after.status(),
                LeaveRequestStatus::Stale | LeaveRequestStatus::Expired
            ) && after.request_id == fulfilled_request_id
            {
                return Err(ExecutorError::InconsistentPlan(
                    "leave fulfillment must not retire the request it fulfills",
                ));
            }
        }
    }
    Ok(fulfilled_request_id)
}

async fn apply_leave_fulfillment(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &ConversationPersistencePlan,
    ctx: &ExecutionContext,
    conversation_id: Uuid,
    transition_id: Uuid,
    seq_i64: i64,
    successor_next_entry_seq: i64,
    generation: i64,
    state_version: i64,
    epoch: i64,
) -> Result<AppliedTransition, ExecutorError> {
    let effects = plan.effects();
    let hydration = plan.state();
    let coordinate = &hydration.coordinate; // successor (sv+1, epoch+1).
    let applied_at = ctx.applied_at;
    let head = effects
        .head_cas()
        .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
    let expected_prior = head
        .expected_prior()
        .ok_or(ExecutorError::InconsistentPlan(
            "leave fulfillment needs a prior",
        ))?;
    let expected_generation = checked_i64(expected_prior.generation())?;
    let expected_state_version = checked_i64(expected_prior.state_version())?;
    let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;

    // Guards. Leave fulfillment carries participant/leaf/interval/leave-request/
    // metadata changes + (a legal interleaving) prior-bound recovery/welcome
    // SUPERSESSIONS + prior-bound reset/leave STALING. It has NO own recovery/
    // reservation/package edge and no terminal-proof/revocation change; those
    // recovery families flow ONLY through the shared supersession path (own
    // counts 0, verified by the reconciliation). Its OWN leave-request edge is the
    // single Pending->Fulfilled fulfilled below; per ADR-019 Erratum 01 the same
    // leaveCommit MAY additionally stale OTHER members' predecessor-bound pending
    // leaves (the partition check below enforces exactly-one-fulfilled + others-
    // only Pending->Stale). Reject the families it never carries.
    let partition = preflight_leave_fulfillment(plan, ctx)?;

    // Metadata re-encryption is MANDATORY (DDL requires_snapshot ∋ leaveCommit).
    let metadata = effects
        .metadata_change()
        .and_then(StateChange::after)
        .ok_or(ExecutorError::InconsistentPlan(
            "leave fulfillment carries no metadata re-encryption",
        ))?;
    let author_cols = ctx
        .metadata_author
        .as_ref()
        .ok_or(ExecutorError::MissingContext(
            "leave fulfillment commit metadata author",
        ))?;

    let fulfilled_request_id = partition_leave_fulfillment_requests(effects)?;
    let leave_request_id = Uuid::from_bytes(fulfilled_request_id);

    // Exactly one participant is removed (the requester).
    if effects.participant_changes().len() != 1 {
        return Err(ExecutorError::InconsistentPlan(
            "leave fulfillment must remove exactly one participant",
        ));
    }
    let removed = effects
        .participant_changes()
        .iter()
        .find_map(|change| match (change.before(), change.after()) {
            (Some(before), None) => Some(before),
            _ => None,
        })
        .ok_or(ExecutorError::InconsistentPlan(
            "leave fulfillment must close the requester participant",
        ))?;
    let participant_period_id = ctx
        .closing_participant_periods
        .iter()
        .find(|(principal, _)| principal == removed.principal())
        .map(|(_, id)| *id)
        .ok_or(ExecutorError::MissingContext(
            "closing participant period id for the leave requester",
        ))?;

    // 1. Head CAS sv+1.
    transition::cas_conversation_head(
        transaction,
        &transition::ConversationHeadCas {
            conversation_id,
            expected_generation,
            expected_state_version,
            expected_next_entry_seq,
            successor_generation: generation,
            successor_state_version: state_version,
            successor_next_entry_seq,
            close: None,
        },
    )
    .await?;

    // 2. Generation state-version pointer CAS (same generation).
    transition::cas_generation_state_version(
        transaction,
        &transition::GenerationStateVersionCas {
            conversation_id,
            generation,
            expected_state_version,
            successor_state_version: state_version,
        },
    )
    .await?;

    // 3. `commit`/active gen_state at the NEW epoch (fresh hash/tag).
    transition::insert_generation_state_row(
        transaction,
        &NewGenerationState {
            conversation_id,
            generation,
            state_version,
            group_id: coordinate.group_id().to_vec(),
            epoch,
            group_context_hash: coordinate.group_context_hash().to_vec(),
            confirmation_tag: coordinate.confirmation_tag().to_vec(),
            lifecycle: GenerationStateLifecycle::Active,
            state_kind: GenerationStateKind::Commit,
            producing_transition_id: transition_id,
            public_snapshot_bytes: ctx.spine.public_snapshot_bytes.clone(),
            snapshot_sha256: ctx.spine.public_snapshot_sha256.clone(),
            tree_summary_bytes: ctx.spine.tree_summary_bytes.clone(),
            tree_summary_sha256: ctx.spine.tree_summary_sha256.clone(),
            leaf_count: ctx.spine.leaf_count,
            created_at: applied_at,
        },
    )
    .await?;

    // 4. Entry (leaveCommitFulfillmentEntry).
    let append = build_append_entry(
        ctx,
        conversation_id,
        generation,
        state_version,
        transition_id,
    );
    delivery::append_entry_at(transaction, &append, u64::try_from(seq_i64).unwrap()).await?;

    // 5. Transition (kind leaveCommit, prior -> next).
    transition::insert_transition_row(
        transaction,
        &NewTransition {
            transition_id,
            conversation_id,
            kind: TransitionKind::LeaveCommit,
            actor_did: ctx.actor.user_did.clone(),
            actor_device_id: ctx.actor.device_id,
            actor_key_id: ctx.actor.key_id.clone(),
            actor_auth_generation: ctx.actor.auth_generation,
            actor_role: ctx.actor.role,
            actor_device_status: ctx.actor.device_status.clone(),
            signed_request_bytes: ctx.entry().signed_request_bytes.clone(),
            unsigned_projection_bytes: ctx.entry().unsigned_projection_bytes.clone(),
            signing_transcript_bytes: ctx.entry().signing_transcript_bytes.clone(),
            request_digest: ctx.entry().request_digest.clone(),
            signature: ctx.entry().signature.clone(),
            coordinates: TransitionCoordinates {
                prior: Some((expected_generation, expected_state_version)),
                next: Some((generation, state_version)),
                retired: None,
                successor: None,
            },
            reset_request_id: None,
            close_transition_id: None,
            metadata_snapshot_id: Some(author_cols.metadata_snapshot_id),
            entry_seq: seq_i64,
            accepted_at: applied_at,
        },
    )
    .await?;

    // 6. Metadata re-encryption snapshot (carry-forward author/origin/version).
    write_commit_metadata_snapshot(
        transaction,
        metadata,
        author_cols,
        conversation_id,
        generation,
        state_version,
        epoch,
        &coordinate.group_id().to_vec(),
        &coordinate.group_context_hash().to_vec(),
        &coordinate.confirmation_tag().to_vec(),
        transition_id,
        applied_at,
    )
    .await?;

    // 7. Close every requester leaf. A `(Some,None)` is a real removal; the
    //    committer's own key rotation is a tolerated `(Some,Some)` (no DS row);
    //    an add `(None,Some)` is not a leave and is a hard error.
    let mut removed_leaves = 0usize;
    for change in effects.leaf_changes() {
        match (change.before(), change.after()) {
            (Some(before), None) => {
                let leaf = closing_leaf_period(ctx, before.device())?;
                transition::close_leaf_period(
                    transaction,
                    &LeafClose {
                        leaf_period_id: leaf,
                        removed_state_version: state_version,
                        removed_transition_id: transition_id,
                        removed_seq: seq_i64,
                        removed_at: applied_at,
                    },
                )
                .await?;
                removed_leaves += 1;
            }
            (Some(_), Some(_)) => {}
            (None, Some(_)) => {
                return Err(ExecutorError::InconsistentPlan(
                    "leave fulfillment must not add a leaf",
                ))
            }
            (None, None) => {}
        }
    }
    if removed_leaves == 0 {
        return Err(ExecutorError::InconsistentPlan(
            "leave fulfillment removed no leaf",
        ));
    }

    // 8. Close every removed device's interval inclusively at the fulfillment
    //    seq (`Remove`), sourcing the closing leaf period from ctx.
    for change in effects.interval_changes() {
        match (change.before(), change.after()) {
            (Some(_), Some(after)) => {
                let end = after.end().ok_or(ExecutorError::InconsistentPlan(
                    "leave-closed interval has no end",
                ))?;
                let leaf = closing_leaf_period(ctx, after.recipient())?;
                delivery::close_application_interval(
                    transaction,
                    &ApplicationIntervalClose {
                        membership_interval_id: Uuid::from_bytes(*after.opening_transition_id()),
                        terminal_seq: checked_i64(end.seq())?,
                        closing_state_version: state_version,
                        closing_transition_id: Uuid::from_bytes(*end.transition_id()),
                        closing_outer_entry_fingerprint: end.outer_entry_fingerprint().to_vec(),
                        closing_kind: repo_interval_close_kind(end.kind()),
                        closing_leaf_period_id: leaf,
                        removed_at: applied_at,
                    },
                )
                .await?;
            }
            _ => {
                return Err(ExecutorError::InconsistentPlan(
                    "leave fulfillment interval change must close an open interval",
                ))
            }
        }
    }

    // 9. Terminalize the requester's participant period.
    transition::terminalize_participant_period(
        transaction,
        &transition::ParticipantTerminalization {
            participant_period_id,
            removing_transition_id: transition_id,
            removing_seq: seq_i64,
            removed_at: applied_at,
        },
    )
    .await?;

    // 10. Mark the leave request `fulfilled`, bound to this leaveCommit
    //     transition (the assert_leave_request_mapping fulfilled arm cross-checks
    //     kind ∈ leaveCommit/leavePolicy + prior coordinate + digest + instant).
    transition::terminalize_leave_request(
        transaction,
        leave_request_id,
        &LeaveRequestTermination::Fulfilled {
            terminal_request_digest: ctx.entry().request_digest.clone(),
            terminal_transition_id: transition_id,
            terminal_at: applied_at,
        },
    )
    .await?;

    // 11. Audience + events.
    let recipients = build_entry_recipients(&ctx.entry_recipients)?;
    delivery::insert_entry_recipients(
        transaction,
        conversation_id,
        u64::try_from(seq_i64).unwrap(),
        &recipients,
    )
    .await?;
    let event_positions = write_events(transaction, ctx, None).await?;

    // 12. Shared prior-bound supersession + welcome supersession + reset/leave
    //     STALING + the silent-drop reconciliation (own recovery/reservation/
    //     package/welcome edges are ALL zero for a leave fulfillment; its ONE own
    //     leave edge is the Pending->Fulfilled handled above — every OTHER delta
    //     must be a supersession/staling the calls below applied). Per ADR-019
    //     Erratum 01 `write_prior_bound_staling` now also terminalizes any
    //     Pending->Stale leaves of OTHER members the leaveCommit retired (bound to
    //     this transition + the commit's request digest); reconcile own(1) +
    //     staled == total.
    let receipt =
        write_prior_bound_supersessions(transaction, effects, transition_id, applied_at).await?;
    // Design 5 step 6: reconcile the recovery families against the classifier's
    // KEYED expectation immediately, before any other writer runs. No unrelated
    // write may intervene. The counts are reachable ONLY through this call, so the
    // fence cannot be dropped without breaking the build.
    let mut superseded = receipt.reconcile_into_counts(&partition)?;
    superseded.welcomes = write_welcome_supersessions(
        transaction,
        ctx,
        effects,
        WelcomeSupersessionCause::Transition {
            terminal_transition_id: transition_id,
        },
    )
    .await?;
    let staled = write_prior_bound_staling(
        transaction,
        effects,
        transition_id,
        &ctx.entry().request_digest,
        applied_at,
    )
    .await?;
    superseded.reset_requests = staled.reset_requests;
    superseded.leave_requests = staled.leave_requests;
    reconcile_coordinate_change_families(
        effects,
        &FamilyCounts {
            leave_requests: 1,
            ..FamilyCounts::default()
        },
        &superseded,
    )?;

    Ok(AppliedTransition {
        allocated_seq: u64::try_from(seq_i64).unwrap(),
        entry_id: ctx.entry().entry_id,
        event_positions,
        successor_coordinate: plan.successor_coordinate().copied(),
    })
}

#[allow(clippy::too_many_arguments)]
async fn apply_creation(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &ConversationPersistencePlan,
    ctx: &ExecutionContext,
    conversation_id: Uuid,
    transition_id: Uuid,
    seq_i64: i64,
    successor_next_entry_seq: i64,
    generation: i64,
    state_version: i64,
    epoch: i64,
    historical_write_authority: Option<&HistoricalExecutionWriteAuthority>,
) -> Result<AppliedTransition, ExecutorError> {
    let effects = plan.effects();
    let hydration = plan.state();
    let coordinate = &hydration.coordinate;
    let applied_at = ctx.applied_at;
    let group_id = coordinate.group_id().to_vec();
    let group_context_hash = coordinate.group_context_hash().to_vec();
    let confirmation_tag = coordinate.confirmation_tag().to_vec();

    // Creation carries no prior; every side family is a pure insert. Reject
    // any family this path does not translate so nothing is silently dropped.
    reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
    reject_if_present(
        "recovery_request_changes",
        effects.recovery_request_changes(),
    )?;
    reject_if_present("reservation_changes", effects.reservation_changes())?;
    reject_if_present("reset_request_changes", effects.reset_request_changes())?;
    reject_if_present("leave_request_changes", effects.leave_request_changes())?;
    reject_if_present("welcome_changes", effects.welcome_changes())?;
    reject_if_present("package_transitions", effects.package_transitions())?;
    reject_if_present("recovery_package_cas", effects.recovery_package_cas())?;
    reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
    if effects.revocation_target_cas().is_some() {
        return Err(ExecutorError::UnsupportedEffect("revocation_target_cas"));
    }
    if effects.welcome_cas().is_some() {
        return Err(ExecutorError::UnsupportedEffect("welcome_cas"));
    }
    // invitation_quota_cas: EXPLICITLY consumed, not written. It is the
    // WITNESS of the planner's locked live-pending-invitation counts for the
    // newly pending recipients; there is no row for the executor to persist.
    // The invitation quota is enforced by the `enforce_invitation_quota`
    // DEFERRED trigger, which independently re-counts live pending
    // invitations under `FOR UPDATE` at COMMIT. Production
    // `into_persistence_plan` requires EVERY Creation/Policy plan to carry
    // this binding (else `InvalidHydrationAuthority`); a missing binding here
    // is an `InconsistentPlan`, so this family is consumed — never silently
    // dropped — exactly as the exhaustive-dispatch contract demands. A
    // reconstructed historical prefix carries no live quota binding at all.
    if historical_write_authority.is_none() {
        let _invitation_quota_witness =
            effects
                .invitation_quota_cas()
                .ok_or(ExecutorError::InconsistentPlan(
                    "creation plan missing invitation quota CAS binding",
                ))?;
    }
    // effects.authority() is likewise deliberately unread: it is the sealed
    // control/request/revocation authority that JUSTIFIED the plan
    // (provenance/witness), not a persistable row family. The signed bytes it
    // attests to reach the durable rows through `ExecutionContext` (the entry
    // + transition signed material), which is caller-supplied input.

    // 1. Head (INSERT — true absence; the seq counter starts already advanced
    //    past the genesis entry).
    let head_kind = match hydration.kind {
        ConversationKind::Group => ConversationHeadKind::Group,
        ConversationKind::Direct => {
            let (low, high) = direct_pair(&hydration.participants)?;
            ConversationHeadKind::Direct {
                direct_did_low: low,
                direct_did_high: high,
            }
        }
    };
    transition::insert_conversation_head(
        transaction,
        &transition::NewConversationHead {
            conversation_id,
            kind: head_kind,
            current_generation: generation,
            current_state_version: state_version,
            next_entry_seq: successor_next_entry_seq,
            created_at: applied_at,
            is_remote: ctx.is_remote,
            sequencer_ds: ctx.sequencer_ds.clone(),
            sequencer_term: ctx.sequencer_term,
        },
    )
    .await?;

    // 2. Generation (activated at the genesis seq/instant).
    transition::insert_generation(
        transaction,
        &NewGeneration {
            conversation_id,
            generation,
            group_id: group_id.clone(),
            genesis_group_info_bytes: ctx.spine.genesis_group_info_bytes.clone(),
            genesis_group_info_sha256: ctx.spine.genesis_group_info_sha256.clone(),
            current_state_version: state_version,
            activated_seq: seq_i64,
            activated_at: applied_at,
        },
    )
    .await?;

    // 3. Generation state (the produced `creation` public coordinate).
    transition::insert_generation_state_row(
        transaction,
        &NewGenerationState {
            conversation_id,
            generation,
            state_version,
            group_id: group_id.clone(),
            epoch,
            group_context_hash: group_context_hash.clone(),
            confirmation_tag: confirmation_tag.clone(),
            lifecycle: GenerationStateLifecycle::Active,
            state_kind: GenerationStateKind::Creation,
            producing_transition_id: transition_id,
            public_snapshot_bytes: ctx.spine.public_snapshot_bytes.clone(),
            snapshot_sha256: ctx.spine.public_snapshot_sha256.clone(),
            tree_summary_bytes: ctx.spine.tree_summary_bytes.clone(),
            tree_summary_sha256: ctx.spine.tree_summary_sha256.clone(),
            leaf_count: ctx.spine.leaf_count,
            created_at: applied_at,
        },
    )
    .await?;

    // 4. Entry at the exact allocated seq (the head already advanced the
    //    counter). Immediate FK targets for the transition's `entry_seq`.
    let append = build_append_entry(
        ctx,
        conversation_id,
        generation,
        state_version,
        transition_id,
    );
    delivery::append_entry_at(transaction, &append, u64::try_from(seq_i64).unwrap()).await?;

    // 5. Metadata snapshot — REQUIRED for creation by the deferred mapping.
    let metadata = effects
        .metadata_change()
        .and_then(StateChange::after)
        .ok_or(ExecutorError::InconsistentPlan(
            "creation plan carries no metadata snapshot",
        ))?;
    let author_cols = ctx
        .metadata_author
        .as_ref()
        .ok_or(ExecutorError::MissingContext("metadata author columns"))?;
    write_creation_metadata_snapshot(
        transaction,
        metadata,
        author_cols,
        &ctx.actor,
        conversation_id,
        generation,
        state_version,
        epoch,
        &group_id,
        &group_context_hash,
        &confirmation_tag,
        transition_id,
        seq_i64,
        applied_at,
    )
    .await?;

    // 6. Transition row (needs entry_seq; entry written above).
    transition::insert_transition_row(
        transaction,
        &NewTransition {
            transition_id,
            conversation_id,
            kind: TransitionKind::Creation,
            actor_did: ctx.actor.user_did.clone(),
            actor_device_id: ctx.actor.device_id,
            actor_key_id: ctx.actor.key_id.clone(),
            actor_auth_generation: ctx.actor.auth_generation,
            actor_role: ctx.actor.role,
            actor_device_status: ctx.actor.device_status.clone(),
            signed_request_bytes: ctx.entry().signed_request_bytes.clone(),
            unsigned_projection_bytes: ctx.entry().unsigned_projection_bytes.clone(),
            signing_transcript_bytes: ctx.entry().signing_transcript_bytes.clone(),
            request_digest: ctx.entry().request_digest.clone(),
            signature: ctx.entry().signature.clone(),
            coordinates: TransitionCoordinates {
                prior: None,
                next: Some((generation, state_version)),
                retired: None,
                successor: None,
            },
            reset_request_id: None,
            close_transition_id: None,
            metadata_snapshot_id: Some(author_cols.metadata_snapshot_id),
            entry_seq: seq_i64,
            accepted_at: applied_at,
        },
    )
    .await?;

    // 7. Participant periods, then leaves, then intervals — every change is a
    //    pure insert for creation; a non-insert shape is a hard error.
    write_participants(
        transaction,
        ctx,
        hydration,
        effects,
        transition_id,
        applied_at,
        false,
    )
    .await?;
    let leaf_ids = write_creation_leaves(
        transaction,
        ctx,
        hydration,
        effects,
        conversation_id,
        generation,
        transition_id,
        state_version,
        seq_i64,
        applied_at,
    )
    .await?;
    write_creation_intervals(transaction, effects, &leaf_ids, conversation_id, applied_at).await?;

    // 8. Frozen control-entry audience.
    let recipients = build_entry_recipients(&ctx.entry_recipients)?;
    if !recipients.is_empty() {
        delivery::insert_entry_recipients(
            transaction,
            conversation_id,
            u64::try_from(seq_i64).unwrap(),
            &recipients,
        )
        .await?;
    }

    // 9. Events + audience + outbox.
    let event_positions = write_events(transaction, ctx, historical_write_authority).await?;

    Ok(AppliedTransition {
        allocated_seq: u64::try_from(seq_i64).unwrap(),
        entry_id: ctx.entry().entry_id,
        event_positions,
        successor_coordinate: plan.successor_coordinate().copied(),
    })
}

/// Apply a group `policy` addParticipant edge: same crypto coordinate,
/// `stateVersion+1`, no metadata / leaf / interval change. Reuses the head
/// CAS (existing conversation), the generation-pointer CAS, and the
/// participant-insert path that creation uses; the only new participant is
/// the added `pending/member` (the `StateChange` diff).
#[allow(clippy::too_many_arguments)]
async fn apply_policy(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &ConversationPersistencePlan,
    ctx: &ExecutionContext,
    conversation_id: Uuid,
    transition_id: Uuid,
    seq_i64: i64,
    successor_next_entry_seq: i64,
    generation: i64,
    state_version: i64,
    epoch: i64,
    historical_write_authority: Option<&HistoricalExecutionWriteAuthority>,
) -> Result<AppliedTransition, ExecutorError> {
    let effects = plan.effects();
    let hydration = plan.state();
    let coordinate = &hydration.coordinate;
    let applied_at = ctx.applied_at;
    let head = effects
        .head_cas()
        .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
    let expected_prior = head
        .expected_prior()
        .ok_or(ExecutorError::InconsistentPlan(
            "policy needs an expected prior",
        ))?;
    let expected_generation = checked_i64(expected_prior.generation())?;
    let expected_state_version = checked_i64(expected_prior.state_version())?;
    let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;
    validate_policy_participant_writes(effects, hydration, ctx, expected_prior, transition_id)?;

    // Policy is a coordinate-only participant edge. It carries NO leaf /
    // interval / terminal-proof change, but `plan_policy_transition` calls
    // `resolve_prior_bound_work` unconditionally, so it CAN carry (a legal
    // interleaving) prior-coordinate open-work SUPERSESSIONS — a co-open
    // leaf-recovery request (Open->Superseded) + its reservation (Active->Released)
    // + reserved package (Reserved->Available), a prior pending Welcome
    // (Pending->Superseded), and prior-bound reset/leave STALING (Pending->Stale).
    // Policy owns NONE of those (own counts 0); every such delta MUST be a
    // supersession/staling the shared writers apply at the tail, exact-shape
    // checked here (mirroring the close/commit arms). `recovery_package_cas` is the
    // production-shape package witness the bijection validates, NOT a rejected
    // family. (kind is `policy`, DB-legal for the recovery/welcome/leave edges.)
    reject_if_present("leaf_changes", effects.leaf_changes())?;
    reject_if_present("interval_changes", effects.interval_changes())?;
    reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
    reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
    // Prior-bound recovery families. The three shape loops this replaces
    // accepted only Row A (Open->Superseded / Active->Released) and never
    // checked terminal evidence, family identity, or the CAS bindings — so a
    // legal Row B due-expiry family was rejected here exactly as it was in leaf
    // recovery fulfillment. The shared classifier proves both rows, strictly
    // before this arm's first head CAS.
    let partition = classify_prior_bound_recovery(plan, ctx, OwnFamilyKind::None)?; // policy

    // Prior-bound reset / leave / Welcome families. Policy owns none of them.
    classify_prior_bound_staling(plan, ctx, OwnStalingKind::None)?;
    if effects.metadata_change().is_some() {
        return Err(ExecutorError::UnsupportedEffect("policy metadata change"));
    }
    if effects.revocation_target_cas().is_some() {
        return Err(ExecutorError::UnsupportedEffect("revocation_target_cas"));
    }
    if effects.welcome_cas().is_some() {
        return Err(ExecutorError::UnsupportedEffect("welcome_cas"));
    }
    // invitation_quota_cas: consumed as witness (see apply_creation) — a
    // group policy addParticipant edge is the other kind production requires
    // to carry it. The quota itself is enforced by the deferred
    // `enforce_invitation_quota` trigger; a missing binding is InconsistentPlan.
    // A reconstructed historical prefix carries no live quota binding at all.
    if historical_write_authority.is_none() {
        let _invitation_quota_witness =
            effects
                .invitation_quota_cas()
                .ok_or(ExecutorError::InconsistentPlan(
                    "policy plan missing invitation quota CAS binding",
                ))?;
    }

    // 1. Head CAS advances the coordinate + counter (single seq authority).
    transition::cas_conversation_head(
        transaction,
        &transition::ConversationHeadCas {
            conversation_id,
            expected_generation,
            expected_state_version,
            expected_next_entry_seq,
            successor_generation: generation,
            successor_state_version: state_version,
            successor_next_entry_seq,
            close: None,
        },
    )
    .await?;

    // 2. Advance the generation's state-version pointer (same generation).
    transition::cas_generation_state_version(
        transaction,
        &transition::GenerationStateVersionCas {
            conversation_id,
            generation,
            expected_state_version,
            successor_state_version: state_version,
        },
    )
    .await?;

    // 3. Successor generation state (policy kind, identical crypto edge).
    transition::insert_generation_state_row(
        transaction,
        &NewGenerationState {
            conversation_id,
            generation,
            state_version,
            group_id: coordinate.group_id().to_vec(),
            epoch,
            group_context_hash: coordinate.group_context_hash().to_vec(),
            confirmation_tag: coordinate.confirmation_tag().to_vec(),
            lifecycle: GenerationStateLifecycle::Active,
            state_kind: GenerationStateKind::Policy,
            producing_transition_id: transition_id,
            public_snapshot_bytes: ctx.spine.public_snapshot_bytes.clone(),
            snapshot_sha256: ctx.spine.public_snapshot_sha256.clone(),
            tree_summary_bytes: ctx.spine.tree_summary_bytes.clone(),
            tree_summary_sha256: ctx.spine.tree_summary_sha256.clone(),
            leaf_count: ctx.spine.leaf_count,
            created_at: applied_at,
        },
    )
    .await?;

    // 4. Entry at the allocated seq.
    let append = build_append_entry(
        ctx,
        conversation_id,
        generation,
        state_version,
        transition_id,
    );
    delivery::append_entry_at(transaction, &append, u64::try_from(seq_i64).unwrap()).await?;

    // 5. Transition (prior -> next).
    transition::insert_transition_row(
        transaction,
        &NewTransition {
            transition_id,
            conversation_id,
            kind: TransitionKind::Policy,
            actor_did: ctx.actor.user_did.clone(),
            actor_device_id: ctx.actor.device_id,
            actor_key_id: ctx.actor.key_id.clone(),
            actor_auth_generation: ctx.actor.auth_generation,
            actor_role: ctx.actor.role,
            actor_device_status: ctx.actor.device_status.clone(),
            signed_request_bytes: ctx.entry().signed_request_bytes.clone(),
            unsigned_projection_bytes: ctx.entry().unsigned_projection_bytes.clone(),
            signing_transcript_bytes: ctx.entry().signing_transcript_bytes.clone(),
            request_digest: ctx.entry().request_digest.clone(),
            signature: ctx.entry().signature.clone(),
            coordinates: TransitionCoordinates {
                prior: Some((expected_generation, expected_state_version)),
                next: Some((generation, state_version)),
                retired: None,
                successor: None,
            },
            reset_request_id: None,
            close_transition_id: None,
            metadata_snapshot_id: None,
            entry_seq: seq_i64,
            accepted_at: applied_at,
        },
    )
    .await?;

    // 6. Apply the already-classified pending inserts and/or exact active
    //    role CAS updates. Role changes consume no participant-period IDs.
    write_participants(
        transaction,
        ctx,
        hydration,
        effects,
        transition_id,
        applied_at,
        true,
    )
    .await?;
    terminalize_policy_participants(
        transaction,
        effects,
        ctx,
        transition_id,
        seq_i64,
        applied_at,
    )
    .await?;

    // 7. Audience + events.
    let recipients = build_entry_recipients(&ctx.entry_recipients)?;
    if !recipients.is_empty() {
        delivery::insert_entry_recipients(
            transaction,
            conversation_id,
            u64::try_from(seq_i64).unwrap(),
            &recipients,
        )
        .await?;
    }
    let event_positions = write_events(transaction, ctx, historical_write_authority).await?;

    // 8. Supersede prior-coordinate open work the policy edge retired (an open
    //    recovery request / active reservation / reserved package + a prior pending
    //    Welcome) AND stale any prior-bound pending reset/leave request. Policy owns
    //    NONE of these families (own == default), so every such delta MUST be a
    //    supersession/staling the shared writers below applied — reconcile rejects
    //    any that is neither (silent-drop guard).
    let receipt =
        write_prior_bound_supersessions(transaction, effects, transition_id, applied_at).await?;
    // Design 5 step 6: reconcile the recovery families against the classifier's
    // KEYED expectation immediately, before any other writer runs. No unrelated
    // write may intervene. The counts are reachable ONLY through this call, so the
    // fence cannot be dropped without breaking the build.
    let mut superseded = receipt.reconcile_into_counts(&partition)?;
    superseded.welcomes = write_welcome_supersessions(
        transaction,
        ctx,
        effects,
        WelcomeSupersessionCause::Transition {
            terminal_transition_id: transition_id,
        },
    )
    .await?;
    let staled = write_prior_bound_staling(
        transaction,
        effects,
        transition_id,
        &ctx.entry().request_digest,
        applied_at,
    )
    .await?;
    superseded.reset_requests = staled.reset_requests;
    superseded.leave_requests = staled.leave_requests;
    reconcile_coordinate_change_families(effects, &FamilyCounts::default(), &superseded)?;

    Ok(AppliedTransition {
        allocated_seq: u64::try_from(seq_i64).unwrap(),
        entry_id: ctx.entry().entry_id,
        event_positions,
        successor_coordinate: plan.successor_coordinate().copied(),
    })
}

/// Apply a `signedMetadataTransition`: same MLS crypto coordinate,
/// `stateVersion+1`, one self-origin/version-advancing encrypted metadata
/// snapshot, and no membership/leaf/interval mutation.
#[allow(clippy::too_many_arguments)]
async fn apply_metadata_transition(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &ConversationPersistencePlan,
    ctx: &ExecutionContext,
    conversation_id: Uuid,
    transition_id: Uuid,
    seq_i64: i64,
    successor_next_entry_seq: i64,
    generation: i64,
    state_version: i64,
    epoch: i64,
) -> Result<AppliedTransition, ExecutorError> {
    let effects = plan.effects();
    let hydration = plan.state();
    let coordinate = &hydration.coordinate;
    let applied_at = ctx.applied_at;
    let head = effects
        .head_cas()
        .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
    let expected_prior = head
        .expected_prior()
        .ok_or(ExecutorError::InconsistentPlan(
            "metadata transition needs an expected prior",
        ))?;
    let expected_generation = checked_i64(expected_prior.generation())?;
    let expected_state_version = checked_i64(expected_prior.state_version())?;
    let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;
    let binding = preflight_metadata_transition(plan, ctx, transition_id, seq_i64)?;
    let partition = &binding.prior_bound;

    // 1. Serialize and advance the exact head coordinate + entry counter.
    transition::cas_conversation_head(
        transaction,
        &transition::ConversationHeadCas {
            conversation_id,
            expected_generation,
            expected_state_version,
            expected_next_entry_seq,
            successor_generation: generation,
            successor_state_version: state_version,
            successor_next_entry_seq,
            close: None,
        },
    )
    .await?;

    // 2. Advance the active generation's state-version pointer.
    transition::cas_generation_state_version(
        transaction,
        &transition::GenerationStateVersionCas {
            conversation_id,
            generation,
            expected_state_version,
            successor_state_version: state_version,
        },
    )
    .await?;

    // 3. Append the coordinate-only metadata successor state.
    transition::insert_generation_state_row(
        transaction,
        &NewGenerationState {
            conversation_id,
            generation,
            state_version,
            group_id: coordinate.group_id().to_vec(),
            epoch,
            group_context_hash: coordinate.group_context_hash().to_vec(),
            confirmation_tag: coordinate.confirmation_tag().to_vec(),
            lifecycle: GenerationStateLifecycle::Active,
            state_kind: GenerationStateKind::Metadata,
            producing_transition_id: transition_id,
            public_snapshot_bytes: ctx.spine.public_snapshot_bytes.clone(),
            snapshot_sha256: ctx.spine.public_snapshot_sha256.clone(),
            tree_summary_bytes: ctx.spine.tree_summary_bytes.clone(),
            tree_summary_sha256: ctx.spine.tree_summary_sha256.clone(),
            leaf_count: ctx.spine.leaf_count,
            created_at: applied_at,
        },
    )
    .await?;

    // 4. Persist the canonical control entry at the head-allocated sequence.
    let append = build_append_entry(
        ctx,
        conversation_id,
        generation,
        state_version,
        transition_id,
    );
    delivery::append_entry_at(transaction, &append, u64::try_from(seq_i64).unwrap()).await?;

    // 5. Bind a fresh signed avatar (reuse needs no new blob mutation), then
    // persist the exact self-origin metadata snapshot.
    if let Some(MetadataAvatarPersistence::Fresh { binding, .. }) = binding.avatar {
        blobs::bind_metadata_avatar_blob(transaction, binding).await?;
    }
    write_metadata_update_snapshot(
        transaction,
        binding.metadata,
        binding.author,
        binding.avatar.map(MetadataAvatarPersistence::snapshot),
        conversation_id,
        generation,
        state_version,
        epoch,
        coordinate.group_id(),
        coordinate.group_context_hash(),
        coordinate.confirmation_tag(),
        transition_id,
        seq_i64,
        applied_at,
    )
    .await?;

    // 6. Persist the signed transition and bind it to that snapshot.
    transition::insert_transition_row(
        transaction,
        &NewTransition {
            transition_id,
            conversation_id,
            kind: TransitionKind::Metadata,
            actor_did: ctx.actor.user_did.clone(),
            actor_device_id: ctx.actor.device_id,
            actor_key_id: ctx.actor.key_id.clone(),
            actor_auth_generation: ctx.actor.auth_generation,
            actor_role: ctx.actor.role,
            actor_device_status: ctx.actor.device_status.clone(),
            signed_request_bytes: ctx.entry().signed_request_bytes.clone(),
            unsigned_projection_bytes: ctx.entry().unsigned_projection_bytes.clone(),
            signing_transcript_bytes: ctx.entry().signing_transcript_bytes.clone(),
            request_digest: ctx.entry().request_digest.clone(),
            signature: ctx.entry().signature.clone(),
            coordinates: TransitionCoordinates {
                prior: Some((expected_generation, expected_state_version)),
                next: Some((generation, state_version)),
                retired: None,
                successor: None,
            },
            reset_request_id: None,
            close_transition_id: None,
            metadata_snapshot_id: Some(binding.author.metadata_snapshot_id),
            entry_seq: seq_i64,
            accepted_at: applied_at,
        },
    )
    .await?;

    // 7. Frozen entry audience + canonical server event schedule.
    let recipients = build_entry_recipients(&ctx.entry_recipients)?;
    delivery::insert_entry_recipients(
        transaction,
        conversation_id,
        u64::try_from(seq_i64).unwrap(),
        &recipients,
    )
    .await?;
    let event_positions = write_events(transaction, ctx, None).await?;

    // 8. Terminalize every prior-coordinate work item retired by this
    // coordinate change, then prove no family was silently skipped.
    let receipt =
        write_prior_bound_supersessions(transaction, effects, transition_id, applied_at).await?;
    // Design 5 step 6: reconcile the recovery families against the classifier's
    // KEYED expectation immediately, before any other writer runs. No unrelated
    // write may intervene. The counts are reachable ONLY through this call, so the
    // fence cannot be dropped without breaking the build.
    let mut superseded = receipt.reconcile_into_counts(&partition)?;
    superseded.welcomes = write_welcome_supersessions(
        transaction,
        ctx,
        effects,
        WelcomeSupersessionCause::Transition {
            terminal_transition_id: transition_id,
        },
    )
    .await?;
    let staled = write_prior_bound_staling(
        transaction,
        effects,
        transition_id,
        &ctx.entry().request_digest,
        applied_at,
    )
    .await?;
    superseded.reset_requests = staled.reset_requests;
    superseded.leave_requests = staled.leave_requests;
    reconcile_coordinate_change_families(effects, &FamilyCounts::default(), &superseded)?;

    Ok(AppliedTransition {
        allocated_seq: u64::try_from(seq_i64).unwrap(),
        entry_id: ctx.entry().entry_id,
        event_positions,
        successor_coordinate: plan.successor_coordinate().copied(),
    })
}

/// Apply a `zeroLeafLeave` edge: an active but LEAFLESS participant (a pending
/// invitee who never joined) self-removes immediately. `stateVersion+1`, same
/// generation/epoch (a coordinate-only rebind, NO crypto commit and NO metadata
/// snapshot — `leavePolicy` is not in the metadata-required set). It closes the
/// participant period (releasing its invitation-quota slot, which the deferred
/// `enforce_invitation_quota` trigger recomputes), with no leaf/interval change
/// (the leaver had neither). Mirrors `apply_policy`'s coordinate/gen-state CAS
/// spine, but terminalizes the participant instead of adding one.
#[allow(clippy::too_many_arguments)]
async fn apply_zero_leaf_leave(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &ConversationPersistencePlan,
    ctx: &ExecutionContext,
    conversation_id: Uuid,
    transition_id: Uuid,
    seq_i64: i64,
    successor_next_entry_seq: i64,
    generation: i64,
    state_version: i64,
    epoch: i64,
) -> Result<AppliedTransition, ExecutorError> {
    let effects = plan.effects();
    let hydration = plan.state();
    let coordinate = &hydration.coordinate;
    let applied_at = ctx.applied_at;
    let head = effects
        .head_cas()
        .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
    let expected_prior = head
        .expected_prior()
        .ok_or(ExecutorError::InconsistentPlan(
            "zero-leaf leave needs an expected prior",
        ))?;
    let expected_generation = checked_i64(expected_prior.generation())?;
    let expected_state_version = checked_i64(expected_prior.state_version())?;
    let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;

    // Coordinate-only self-removal: the leaver's OWN delta is one participant
    // close (leafless, so no leaf/interval/proof change). But
    // `plan_zero_leaf_leave_inner` calls `resolve_prior_bound_work`
    // unconditionally, so it CAN carry prior-coordinate open-work SUPERSESSIONS —
    // a co-open recovery request / reservation / reserved package + a prior
    // pending Welcome — which are consumed via the shared writers at the tail
    // (own counts 0), exact-shape checked here (mirroring close/policy).
    reject_if_present("leaf_changes", effects.leaf_changes())?;
    reject_if_present("interval_changes", effects.interval_changes())?;
    reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
    // reset_request_changes: KEPT fail-closed. A leavePolicy transition staling a
    // prior-bound reset request is DB-legal (reset `stale` accepts any kind), but
    // ADR-019 Erratum 01 rules only on LEAVE staling; reset staling on this arm is
    // out of scope and stays rejected pending its own ruling (the planner does not
    // emit it in the reachable zero-leaf-leave flows).
    reject_if_present("reset_request_changes", effects.reset_request_changes())?;
    // leave_request_changes (ADR-019 Erratum 01): a zeroLeafLeave (leavePolicy)
    // owns NO leave request of its own — it removes a leafless invitee via a
    // zeroLeafLeaveEntry, never a leave request. Every leave delta must therefore
    // be a prior-bound terminalization of a DIFFERENT member's predecessor-bound
    // pending leave (own leave count 0): `Pending->Stale` when this coordinate
    // change supersedes it, or `Pending->Expired` when its own 24h `expires_at`
    // had already passed at `evidence.received_at` — `resolve_prior_bound_work`
    // emits the second row unconditionally for an overdue request, and
    // `write_prior_bound_staling` already writes it. Accepting only the first row
    // made an overdue peer leave a permanent wedge. Validate the shape here; the
    // exact terminal evidence for BOTH rows is proved by the shared
    // `classify_prior_bound_staling` below, and the own-DID exclusion is checked
    // once the leaver is resolved. The rows flow through
    // `write_prior_bound_staling` at the tail (own 0 + staled == total).
    for change in effects.leave_request_changes() {
        let (before, after) = match (change.before(), change.after()) {
            (Some(before), Some(after)) => (before, after),
            _ => {
                return Err(ExecutorError::InconsistentPlan(
                    "zero-leaf leave leave-request delta must be a status transition",
                ))
            }
        };
        if before.status() != LeaveRequestStatus::Pending
            || !matches!(
                after.status(),
                LeaveRequestStatus::Stale | LeaveRequestStatus::Expired
            )
        {
            return Err(ExecutorError::InconsistentPlan(
                "zero-leaf leave leave-request delta must be Pending->Stale/Expired",
            ));
        }
        // No re-binding (ruling point 4): staling never moves a request's binding.
        if before.bound_coordinate != after.bound_coordinate {
            return Err(ExecutorError::InconsistentPlan(
                "zero-leaf leave must not re-bind a leave request",
            ));
        }
    }
    reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
    // Prior-bound recovery families. The three shape loops this replaces
    // accepted only Row A (Open->Superseded / Active->Released) and never
    // checked terminal evidence, family identity, or the CAS bindings — so a
    // legal Row B due-expiry family was rejected here exactly as it was in leaf
    // recovery fulfillment. The shared classifier proves both rows, strictly
    // before this arm's first head CAS.
    let partition = classify_prior_bound_recovery(plan, ctx, OwnFamilyKind::None)?; // zero-leaf leave

    // Prior-bound reset / leave / Welcome families. A zero-leaf leave owns none
    // of them (its own consent never reaches a leave-request delta here).
    classify_prior_bound_staling(plan, ctx, OwnStalingKind::None)?;
    if effects.metadata_change().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "zero-leaf leave metadata change",
        ));
    }
    if effects.revocation_target_cas().is_some() || effects.welcome_cas().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "zero-leaf leave revocation/welcome CAS",
        ));
    }
    // A zero-leaf leave releases (never consumes) an invitation slot, so the
    // plan carries NO invitation-quota CAS (only Creation/Policy do); the
    // deferred quota trigger recomputes from the closed participant row.
    if effects.invitation_quota_cas().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "zero-leaf leave invitation quota CAS",
        ));
    }
    // Exactly one participant is closed (Some -> None); records are never
    // deleted, only terminalized.
    if effects.participant_changes().len() != 1 {
        return Err(ExecutorError::InconsistentPlan(
            "zero-leaf leave must change exactly one participant",
        ));
    }
    let removed = effects
        .participant_changes()
        .iter()
        .find_map(|change| match (change.before(), change.after()) {
            (Some(before), None) => Some(before),
            _ => None,
        })
        .ok_or(ExecutorError::InconsistentPlan(
            "zero-leaf leave must close exactly one participant",
        ))?;
    // ADR-019 Erratum 01: a zeroLeafLeave stales only OTHER members' leaves. Any
    // leave delta targeting the leaver's own DID is a hard InconsistentPlan (a
    // zero-leaf leaver holds no leave request of its own).
    for change in effects.leave_request_changes() {
        if let Some(after) = change.after() {
            if after.requester().principal() == removed.principal() {
                return Err(ExecutorError::InconsistentPlan(
                    "zero-leaf leave must not stale its own leave request",
                ));
            }
        }
    }
    let participant_period_id = ctx
        .closing_participant_periods
        .iter()
        .find(|(principal, _)| principal == removed.principal())
        .map(|(_, id)| *id)
        .ok_or(ExecutorError::MissingContext(
            "closing participant period id for the zero-leaf leaver",
        ))?;

    // 1. Head CAS advances the coordinate + counter (single seq authority).
    transition::cas_conversation_head(
        transaction,
        &transition::ConversationHeadCas {
            conversation_id,
            expected_generation,
            expected_state_version,
            expected_next_entry_seq,
            successor_generation: generation,
            successor_state_version: state_version,
            successor_next_entry_seq,
            close: None,
        },
    )
    .await?;

    // 2. Advance the generation's state-version pointer (same generation).
    transition::cas_generation_state_version(
        transaction,
        &transition::GenerationStateVersionCas {
            conversation_id,
            generation,
            expected_state_version,
            successor_state_version: state_version,
        },
    )
    .await?;

    // 3. Successor generation state (leavePolicy kind, coordinate-only rebind).
    transition::insert_generation_state_row(
        transaction,
        &NewGenerationState {
            conversation_id,
            generation,
            state_version,
            group_id: coordinate.group_id().to_vec(),
            epoch,
            group_context_hash: coordinate.group_context_hash().to_vec(),
            confirmation_tag: coordinate.confirmation_tag().to_vec(),
            lifecycle: GenerationStateLifecycle::Active,
            state_kind: GenerationStateKind::LeavePolicy,
            producing_transition_id: transition_id,
            public_snapshot_bytes: ctx.spine.public_snapshot_bytes.clone(),
            snapshot_sha256: ctx.spine.public_snapshot_sha256.clone(),
            tree_summary_bytes: ctx.spine.tree_summary_bytes.clone(),
            tree_summary_sha256: ctx.spine.tree_summary_sha256.clone(),
            leaf_count: ctx.spine.leaf_count,
            created_at: applied_at,
        },
    )
    .await?;

    // 4. Entry (zeroLeafLeaveEntry) at the allocated seq.
    let append = build_append_entry(
        ctx,
        conversation_id,
        generation,
        state_version,
        transition_id,
    );
    delivery::append_entry_at(transaction, &append, u64::try_from(seq_i64).unwrap()).await?;

    // 5. Transition (leavePolicy, prior -> next, no metadata snapshot).
    transition::insert_transition_row(
        transaction,
        &NewTransition {
            transition_id,
            conversation_id,
            kind: TransitionKind::LeavePolicy,
            actor_did: ctx.actor.user_did.clone(),
            actor_device_id: ctx.actor.device_id,
            actor_key_id: ctx.actor.key_id.clone(),
            actor_auth_generation: ctx.actor.auth_generation,
            actor_role: ctx.actor.role,
            actor_device_status: ctx.actor.device_status.clone(),
            signed_request_bytes: ctx.entry().signed_request_bytes.clone(),
            unsigned_projection_bytes: ctx.entry().unsigned_projection_bytes.clone(),
            signing_transcript_bytes: ctx.entry().signing_transcript_bytes.clone(),
            request_digest: ctx.entry().request_digest.clone(),
            signature: ctx.entry().signature.clone(),
            coordinates: TransitionCoordinates {
                prior: Some((expected_generation, expected_state_version)),
                next: Some((generation, state_version)),
                retired: None,
                successor: None,
            },
            reset_request_id: None,
            close_transition_id: None,
            metadata_snapshot_id: None,
            entry_seq: seq_i64,
            accepted_at: applied_at,
        },
    )
    .await?;

    // 6. Close the leaver's participant period (invitation-slot release).
    transition::terminalize_participant_period(
        transaction,
        &transition::ParticipantTerminalization {
            participant_period_id,
            removing_transition_id: transition_id,
            removing_seq: seq_i64,
            removed_at: applied_at,
        },
    )
    .await?;

    // 7. Audience + events.
    let recipients = build_entry_recipients(&ctx.entry_recipients)?;
    delivery::insert_entry_recipients(
        transaction,
        conversation_id,
        u64::try_from(seq_i64).unwrap(),
        &recipients,
    )
    .await?;
    let event_positions = write_events(transaction, ctx, None).await?;

    // Supersede prior-coordinate open work the leave retired (an open recovery
    // request / active reservation / reserved package + a prior pending Welcome)
    // AND stale any prior-bound pending LEAVE request of OTHER members (ADR-019
    // Erratum 01). A zero-leaf leave owns NONE of these families (own == default),
    // so every such delta MUST be a supersession/staling the shared writers
    // applied — reconcile rejects any that is neither. reset was rejected above
    // (count 0), so its family trivially reconciles.
    let receipt =
        write_prior_bound_supersessions(transaction, effects, transition_id, applied_at).await?;
    // Design 5 step 6: reconcile the recovery families against the classifier's
    // KEYED expectation immediately, before any other writer runs. No unrelated
    // write may intervene. The counts are reachable ONLY through this call, so the
    // fence cannot be dropped without breaking the build.
    let mut superseded = receipt.reconcile_into_counts(&partition)?;
    superseded.welcomes = write_welcome_supersessions(
        transaction,
        ctx,
        effects,
        WelcomeSupersessionCause::Transition {
            terminal_transition_id: transition_id,
        },
    )
    .await?;
    let staled = write_prior_bound_staling(
        transaction,
        effects,
        transition_id,
        &ctx.entry().request_digest,
        applied_at,
    )
    .await?;
    superseded.leave_requests = staled.leave_requests;
    reconcile_coordinate_change_families(effects, &FamilyCounts::default(), &superseded)?;

    Ok(AppliedTransition {
        allocated_seq: u64::try_from(seq_i64).unwrap(),
        entry_id: ctx.entry().entry_id,
        event_positions,
        successor_coordinate: plan.successor_coordinate().copied(),
    })
}

/// Apply a `closeConversation` edge: `stateVersion+1`, `lifecycle=superseded`,
/// no successor. Closes every still-open interval with a `Terminal` proof,
/// inserts one schedule terminal proof per historical device schedule, closes
/// the genesis leaf, and emits the single conversation-close tombstone event.
#[allow(clippy::too_many_arguments)]
async fn apply_close(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &ConversationPersistencePlan,
    ctx: &ExecutionContext,
    conversation_id: Uuid,
    transition_id: Uuid,
    seq_i64: i64,
    successor_next_entry_seq: i64,
    generation: i64,
    state_version: i64,
    epoch: i64,
) -> Result<AppliedTransition, ExecutorError> {
    let effects = plan.effects();
    let hydration = plan.state();
    let coordinate = &hydration.coordinate; // retired coordinate (same crypto).
    let applied_at = ctx.applied_at;
    let head = effects
        .head_cas()
        .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
    let expected_prior = head
        .expected_prior()
        .ok_or(ExecutorError::InconsistentPlan(
            "close needs an expected prior",
        ))?;
    let expected_generation = checked_i64(expected_prior.generation())?;
    let expected_state_version = checked_i64(expected_prior.state_version())?;
    let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;

    // Close is coordinate-retire + interval/leaf teardown. It carries NO own
    // recovery/welcome edge, but it DOES supersede prior-coordinate open work:
    // `plan_close_inner` calls `resolve_prior_bound_work` unconditionally, and a
    // close IS reachable while the actor's own (group-of-1 admin) or the other
    // party's (direct 1:1) leaf-recovery request is open — superseding it +
    // releasing the reservation + reactivating the package. Those deltas are
    // consumed below via the shared write_prior_bound_supersessions +
    // write_welcome_supersessions + write_prior_bound_staling + reconcile (own
    // counts 0). A close is likewise reachable while a pending reset/leave request
    // is bound to the prior coordinate — staled below (kind is `closeConversation`,
    // DB-legal for the leave `stale` edge). Families the close genuinely never
    // carries stay fail-closed.
    reject_if_present("participant_changes", effects.participant_changes())?;
    reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
    // Every recovery/reservation/package delta a close carries MUST be a
    // prior-bound supersession (request Open->Superseded, reservation
    // Active->Released, package Reserved->Available) — exact-shape checked here
    // (mirroring the generic-commit arm) and consumed below. `recovery_package_cas`
    // is the production-shape package witness the bijection validates, NOT a
    // rejected family.
    // Prior-bound recovery families. The three shape loops this replaces
    // accepted only Row A (Open->Superseded / Active->Released) and never
    // checked terminal evidence, family identity, or the CAS bindings — so a
    // legal Row B due-expiry family was rejected here exactly as it was in leaf
    // recovery fulfillment. The shared classifier proves both rows, strictly
    // before this arm's first head CAS.
    let partition = classify_prior_bound_recovery(plan, ctx, OwnFamilyKind::None)?; // close

    // Prior-bound reset / leave / Welcome families. A close owns none of them.
    classify_prior_bound_staling(plan, ctx, OwnStalingKind::None)?;
    if effects.metadata_change().is_some() {
        return Err(ExecutorError::UnsupportedEffect("close metadata change"));
    }
    if effects.revocation_target_cas().is_some() || effects.welcome_cas().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "close revocation/welcome CAS",
        ));
    }
    if effects.invitation_quota_cas().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "close invitation quota CAS",
        ));
    }

    // 1. Head CAS to superseded with the exact close coordinate.
    transition::cas_conversation_head(
        transaction,
        &transition::ConversationHeadCas {
            conversation_id,
            expected_generation,
            expected_state_version,
            expected_next_entry_seq,
            successor_generation: generation,
            successor_state_version: state_version,
            successor_next_entry_seq,
            close: Some(ConversationHeadClose {
                close_transition_id: transition_id,
                close_generation: generation,
                close_state_version: state_version,
                close_seq: seq_i64,
                closed_at: applied_at,
            }),
        },
    )
    .await?;

    // 2. Supersede the generation (points at the superseded state).
    transition::supersede_generation(
        transaction,
        &GenerationSupersede {
            conversation_id,
            generation,
            expected_state_version,
            successor_state_version: state_version,
            superseded_seq: seq_i64,
            superseded_at: applied_at,
        },
    )
    .await?;

    // 3. Superseded closeConversation generation state (same crypto edge).
    transition::insert_generation_state_row(
        transaction,
        &NewGenerationState {
            conversation_id,
            generation,
            state_version,
            group_id: coordinate.group_id().to_vec(),
            epoch,
            group_context_hash: coordinate.group_context_hash().to_vec(),
            confirmation_tag: coordinate.confirmation_tag().to_vec(),
            lifecycle: GenerationStateLifecycle::Superseded,
            state_kind: GenerationStateKind::CloseConversation,
            producing_transition_id: transition_id,
            public_snapshot_bytes: ctx.spine.public_snapshot_bytes.clone(),
            snapshot_sha256: ctx.spine.public_snapshot_sha256.clone(),
            tree_summary_bytes: ctx.spine.tree_summary_bytes.clone(),
            tree_summary_sha256: ctx.spine.tree_summary_sha256.clone(),
            leaf_count: ctx.spine.leaf_count,
            created_at: applied_at,
        },
    )
    .await?;

    // 4. Entry (conversationCloseEntry) at the close seq.
    let append = build_append_entry(
        ctx,
        conversation_id,
        generation,
        state_version,
        transition_id,
    );
    delivery::append_entry_at(transaction, &append, u64::try_from(seq_i64).unwrap()).await?;

    // 5. Transition (prior -> retired; a close transition references itself).
    transition::insert_transition_row(
        transaction,
        &NewTransition {
            transition_id,
            conversation_id,
            kind: TransitionKind::CloseConversation,
            actor_did: ctx.actor.user_did.clone(),
            actor_device_id: ctx.actor.device_id,
            actor_key_id: ctx.actor.key_id.clone(),
            actor_auth_generation: ctx.actor.auth_generation,
            actor_role: ctx.actor.role,
            actor_device_status: ctx.actor.device_status.clone(),
            signed_request_bytes: ctx.entry().signed_request_bytes.clone(),
            unsigned_projection_bytes: ctx.entry().unsigned_projection_bytes.clone(),
            signing_transcript_bytes: ctx.entry().signing_transcript_bytes.clone(),
            request_digest: ctx.entry().request_digest.clone(),
            signature: ctx.entry().signature.clone(),
            coordinates: TransitionCoordinates {
                prior: Some((expected_generation, expected_state_version)),
                next: Some((generation, state_version)),
                retired: None,
                successor: None,
            },
            reset_request_id: None,
            close_transition_id: Some(transition_id),
            metadata_snapshot_id: None,
            entry_seq: seq_i64,
            accepted_at: applied_at,
        },
    )
    .await?;

    // 6. Close the genesis leaf (leaf_change = Some -> None).
    for change in effects.leaf_changes() {
        let before = match (change.before(), change.after()) {
            (Some(before), None) => before,
            _ => {
                return Err(ExecutorError::UnsupportedEffect(
                    "close leaf change is not a removal",
                ))
            }
        };
        let leaf_period_id = closing_leaf_period(ctx, before.device())?;
        transition::close_leaf_period(
            transaction,
            &LeafClose {
                leaf_period_id,
                removed_state_version: state_version,
                removed_transition_id: transition_id,
                removed_seq: seq_i64,
                removed_at: applied_at,
            },
        )
        .await?;
    }

    // 7. Close every still-open interval with the Terminal proof (from the plan).
    for change in effects.interval_changes() {
        let after = match (change.before(), change.after()) {
            (Some(_), Some(after)) => after,
            _ => {
                return Err(ExecutorError::UnsupportedEffect(
                    "close interval change is not a finite close",
                ))
            }
        };
        let end = after.end().ok_or(ExecutorError::InconsistentPlan(
            "close interval carries no end",
        ))?;
        let leaf_period_id = closing_leaf_period(ctx, after.recipient())?;
        delivery::close_application_interval(
            transaction,
            &ApplicationIntervalClose {
                membership_interval_id: Uuid::from_bytes(*after.opening_transition_id()),
                terminal_seq: checked_i64(end.seq())?,
                closing_state_version: state_version,
                closing_transition_id: Uuid::from_bytes(*end.transition_id()),
                closing_outer_entry_fingerprint: end.outer_entry_fingerprint().to_vec(),
                closing_kind: repo_interval_close_kind(end.kind()),
                closing_leaf_period_id: leaf_period_id,
                removed_at: applied_at,
            },
        )
        .await?;
    }

    // 8. One schedule terminal proof per historical device schedule.
    for change in effects.terminal_proof_changes() {
        let proof = match (change.before(), change.after()) {
            (None, Some(proof)) => proof,
            _ => {
                return Err(ExecutorError::UnsupportedEffect(
                    "schedule proof change is not an insert",
                ))
            }
        };
        delivery::insert_schedule_terminal_proof(
            transaction,
            &NewScheduleTerminalProof {
                conversation_id,
                recipient_did: device_did(proof.recipient())?,
                recipient_device_id: device_uuid(proof.recipient()),
                terminal_seq: seq_i64,
                transition_id,
                outer_entry_fingerprint: ctx.entry().outer_entry_fingerprint.clone(),
                received_at: applied_at,
            },
        )
        .await?;
    }

    // 9. Retained scheduleTerminal audience + the conversation-close event.
    let recipients = build_entry_recipients(&ctx.entry_recipients)?;
    delivery::insert_entry_recipients(
        transaction,
        conversation_id,
        u64::try_from(seq_i64).unwrap(),
        &recipients,
    )
    .await?;
    let event_positions = write_events(transaction, ctx, None).await?;

    // 10. Supersede prior-coordinate open work the close retired: an open
    //     leaf-recovery request (Open->Superseded) + its reservation
    //     (Active->Released) + reserved package (Reserved->Available), any prior
    //     pending welcome, and any prior-bound pending reset/leave request
    //     (Pending->Stale). The close has ZERO own recovery/welcome/reset/leave
    //     edges, so own == default and every such delta MUST be a supersession/
    //     staling the calls below applied — reconcile rejects any that is neither.
    let receipt =
        write_prior_bound_supersessions(transaction, effects, transition_id, applied_at).await?;
    // Design 5 step 6: reconcile the recovery families against the classifier's
    // KEYED expectation immediately, before any other writer runs. No unrelated
    // write may intervene. The counts are reachable ONLY through this call, so the
    // fence cannot be dropped without breaking the build.
    let mut superseded = receipt.reconcile_into_counts(&partition)?;
    superseded.welcomes = write_welcome_supersessions(
        transaction,
        ctx,
        effects,
        WelcomeSupersessionCause::Transition {
            terminal_transition_id: transition_id,
        },
    )
    .await?;
    let staled = write_prior_bound_staling(
        transaction,
        effects,
        transition_id,
        &ctx.entry().request_digest,
        applied_at,
    )
    .await?;
    superseded.reset_requests = staled.reset_requests;
    superseded.leave_requests = staled.leave_requests;
    reconcile_coordinate_change_families(effects, &FamilyCounts::default(), &superseded)?;

    Ok(AppliedTransition {
        allocated_seq: u64::try_from(seq_i64).unwrap(),
        entry_id: ctx.entry().entry_id,
        event_positions,
        successor_coordinate: plan.successor_coordinate().copied(),
    })
}

/// Apply a `reset request` edge: a non-mutating signed intent. It appends the
/// request entry + the `chat.reset_requests` row + the event, and advances the
/// seq counter — but the crypto coordinate is UNCHANGED (no generation state,
/// no transition row, no stateVersion bump).
#[allow(clippy::too_many_arguments)]
async fn apply_reset_request(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &ConversationPersistencePlan,
    ctx: &ExecutionContext,
    conversation_id: Uuid,
    seq_i64: i64,
    successor_next_entry_seq: i64,
    generation: i64,
    state_version: i64,
    epoch: i64,
) -> Result<AppliedTransition, ExecutorError> {
    let effects = plan.effects();
    let hydration = plan.state();
    let coordinate = &hydration.coordinate; // unchanged coordinate.
    let applied_at = ctx.applied_at;
    let head = effects
        .head_cas()
        .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
    let expected_prior = head
        .expected_prior()
        .ok_or(ExecutorError::InconsistentPlan(
            "reset request needs an expected prior",
        ))?;
    let expected_generation = checked_i64(expected_prior.generation())?;
    let expected_state_version = checked_i64(expected_prior.state_version())?;
    let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;

    // Non-mutating: only a reset-request row changes. Everything else empty.
    reject_if_present("participant_changes", effects.participant_changes())?;
    reject_if_present("leaf_changes", effects.leaf_changes())?;
    reject_if_present("interval_changes", effects.interval_changes())?;
    reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
    reject_if_present(
        "recovery_request_changes",
        effects.recovery_request_changes(),
    )?;
    reject_if_present("reservation_changes", effects.reservation_changes())?;
    reject_if_present("leave_request_changes", effects.leave_request_changes())?;
    reject_if_present("welcome_changes", effects.welcome_changes())?;
    reject_if_present("package_transitions", effects.package_transitions())?;
    reject_if_present("recovery_package_cas", effects.recovery_package_cas())?;
    reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
    if effects.metadata_change().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "reset request metadata change",
        ));
    }
    // Complete defensive dispatch (E2b-4 review): a resetRequest plan carries
    // none of these; production `into_persistence_plan` forces them empty/None.
    // Guarding them keeps this path in the same no-silent-skip class as the rest.
    if effects.revocation_target_cas().is_some() || effects.welcome_cas().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "reset request revocation/welcome CAS",
        ));
    }
    if effects.invitation_quota_cas().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "reset request invitation quota CAS",
        ));
    }
    let row = ctx
        .reset_request_row
        .as_ref()
        .ok_or(ExecutorError::MissingContext("reset request row content"))?;
    // Exactly one new pending reset request in the delta.
    if effects.reset_request_changes().len() != 1 {
        return Err(ExecutorError::InconsistentPlan(
            "reset request must add exactly one pending request",
        ));
    }

    // 1. Head CAS: advance the seq counter, coordinate UNCHANGED.
    transition::cas_conversation_head(
        transaction,
        &transition::ConversationHeadCas {
            conversation_id,
            expected_generation,
            expected_state_version,
            expected_next_entry_seq,
            successor_generation: generation,
            successor_state_version: state_version,
            successor_next_entry_seq,
            close: None,
        },
    )
    .await?;

    // 2. The request entry (resetRequestEntry carries no transition_id).
    let mut append =
        build_append_entry(ctx, conversation_id, generation, state_version, Uuid::nil());
    append.generation = None;
    append.state_version = None;
    append.transition_id = None;
    delivery::append_entry_at(transaction, &append, u64::try_from(seq_i64).unwrap()).await?;

    // 3. The pending reset_requests row (signed content from ctx; bound
    //    coordinate from the unchanged current coordinate).
    transition::insert_reset_request(
        transaction,
        &transition::NewResetRequest {
            reset_request_id: row.reset_request_id,
            conversation_id,
            requester_did: ctx.actor.user_did.clone(),
            requester_device_id: ctx.actor.device_id,
            requester_key_id: ctx.actor.key_id.clone(),
            requester_auth_generation: ctx.actor.auth_generation,
            prior_generation: generation,
            prior_state_version: state_version,
            prior_group_id: coordinate.group_id().to_vec(),
            prior_epoch: epoch,
            prior_group_context_hash: coordinate.group_context_hash().to_vec(),
            prior_confirmation_tag: coordinate.confirmation_tag().to_vec(),
            reason: row.reason.clone(),
            signed_request_bytes: row.signed_request_bytes.clone(),
            signing_transcript_bytes: row.signing_transcript_bytes.clone(),
            request_digest: row.request_digest.clone(),
            signature: row.signature.clone(),
            received_at: applied_at,
            expires_at: row.expires_at,
        },
    )
    .await?;

    // 4. Audience + event.
    let recipients = build_entry_recipients(&ctx.entry_recipients)?;
    delivery::insert_entry_recipients(
        transaction,
        conversation_id,
        u64::try_from(seq_i64).unwrap(),
        &recipients,
    )
    .await?;
    let event_positions = write_events(transaction, ctx, None).await?;

    Ok(AppliedTransition {
        allocated_seq: u64::try_from(seq_i64).unwrap(),
        entry_id: ctx.entry().entry_id,
        event_positions,
        successor_coordinate: plan.successor_coordinate().copied(),
    })
}

/// Apply an entry-bearing `leaveRequest` control op. Non-mutating: the head
/// CAS advances ONLY the seq counter (the `(generation,state_version)`
/// coordinate is untouched), it appends the `leaveRequestEntry`, and it inserts
/// a pending 24h-consent `leave_requests` row bound to the current coordinate.
/// The row's signed material is the entry's — `assert_leave_request_mapping`
/// requires the row and its `leaveRequestEntry` to carry byte-equal
/// `signed_request_bytes`/`request_digest`/`signature`/`received_at` — so no
/// side ctx row is needed; the DB `expires_at = received_at + 24h`. Mirrors
/// `apply_reset_request`.
#[allow(clippy::too_many_arguments)]
async fn apply_leave_request(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &ConversationPersistencePlan,
    ctx: &ExecutionContext,
    conversation_id: Uuid,
    seq_i64: i64,
    successor_next_entry_seq: i64,
    generation: i64,
    state_version: i64,
    epoch: i64,
) -> Result<AppliedTransition, ExecutorError> {
    let effects = plan.effects();
    let hydration = plan.state();
    let coordinate = &hydration.coordinate; // unchanged coordinate.
    let applied_at = ctx.applied_at;
    let head = effects
        .head_cas()
        .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
    let expected_prior = head
        .expected_prior()
        .ok_or(ExecutorError::InconsistentPlan(
            "leave request needs an expected prior",
        ))?;
    let expected_generation = checked_i64(expected_prior.generation())?;
    let expected_state_version = checked_i64(expected_prior.state_version())?;
    let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;

    // Non-mutating: only a leave-request row changes. Everything else empty.
    reject_if_present("participant_changes", effects.participant_changes())?;
    reject_if_present("leaf_changes", effects.leaf_changes())?;
    reject_if_present("interval_changes", effects.interval_changes())?;
    reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
    reject_if_present(
        "recovery_request_changes",
        effects.recovery_request_changes(),
    )?;
    reject_if_present("reservation_changes", effects.reservation_changes())?;
    reject_if_present("reset_request_changes", effects.reset_request_changes())?;
    reject_if_present("welcome_changes", effects.welcome_changes())?;
    reject_if_present("package_transitions", effects.package_transitions())?;
    reject_if_present("recovery_package_cas", effects.recovery_package_cas())?;
    reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
    if effects.metadata_change().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "leave request metadata change",
        ));
    }
    if effects.revocation_target_cas().is_some() || effects.welcome_cas().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "leave request revocation/welcome CAS",
        ));
    }
    if effects.invitation_quota_cas().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "leave request invitation quota CAS",
        ));
    }
    // Exactly one new pending leave request, plus the observed expiry of
    // however many past-due pending rows `expire_due_leave_requests` swept at
    // the lock. Any OTHER delta shape is a hard `InconsistentPlan` — the same
    // no-silent-drop discipline `reconcile_coordinate_change_families` enforces
    // for the coordinate-changing arms.
    let changes = effects.leave_request_changes();
    let openings = changes
        .iter()
        .filter(|change| {
            matches!(
                (change.before(), change.after()),
                (None, Some(after)) if after.status() == LeaveRequestStatus::Pending
            )
        })
        .count();
    let observed_expiries = changes
        .iter()
        .filter(|change| {
            matches!(
                (change.before(), change.after()),
                (Some(before), Some(after))
                    if before.status() == LeaveRequestStatus::Pending
                        && after.status() == LeaveRequestStatus::Expired
            )
        })
        .count();
    if openings != 1 || openings + observed_expiries != changes.len() {
        return Err(ExecutorError::InconsistentPlan(
            "leave request must open exactly one pending request and observe only expiries",
        ));
    }
    let request = changes
        .iter()
        .find_map(|change| match (change.before(), change.after()) {
            (None, Some(after)) if after.status() == LeaveRequestStatus::Pending => Some(after),
            _ => None,
        })
        .ok_or(ExecutorError::InconsistentPlan(
            "leave request must open exactly one pending request",
        ))?;
    let leave_request_id = Uuid::from_bytes(request.request_id);

    // 1. Head CAS: advance the seq counter, coordinate UNCHANGED.
    transition::cas_conversation_head(
        transaction,
        &transition::ConversationHeadCas {
            conversation_id,
            expected_generation,
            expected_state_version,
            expected_next_entry_seq,
            successor_generation: generation,
            successor_state_version: state_version,
            successor_next_entry_seq,
            close: None,
        },
    )
    .await?;

    // 2. The request entry (leaveRequestEntry carries no transition_id).
    let mut append =
        build_append_entry(ctx, conversation_id, generation, state_version, Uuid::nil());
    append.generation = None;
    append.state_version = None;
    append.transition_id = None;
    delivery::append_entry_at(transaction, &append, u64::try_from(seq_i64).unwrap()).await?;

    // 3. Observed expiry of every past-due pending row the planner swept.
    //    MUST precede the insert: `leave_requests_one_pending_uq` is a plain
    //    partial unique index, NOT a deferrable constraint, so a same-requester
    //    replacement would collide the moment the insert lands while the lapsed
    //    row is still `pending`.
    let written_expiries = write_observed_leave_expiries(transaction, effects).await?;
    if written_expiries != observed_expiries {
        return Err(ExecutorError::InconsistentPlan(
            "leave request observed expiry write count drift",
        ));
    }

    // 4. The pending leave_requests row. Signed material is the entry's (the
    //    entry<->row mapping trigger requires byte-equality); the bound
    //    coordinate is the unchanged current coordinate; `expires_at` is the
    //    DB-required `received_at + 24h`.
    transition::insert_leave_request(
        transaction,
        &NewLeaveRequest {
            leave_request_id,
            conversation_id,
            requester_did: ctx.actor.user_did.clone(),
            requester_device_id: ctx.actor.device_id,
            requester_key_id: ctx.actor.key_id.clone(),
            requester_auth_generation: ctx.actor.auth_generation,
            prior_generation: generation,
            prior_state_version: state_version,
            prior_group_id: coordinate.group_id().to_vec(),
            prior_epoch: epoch,
            prior_group_context_hash: coordinate.group_context_hash().to_vec(),
            prior_confirmation_tag: coordinate.confirmation_tag().to_vec(),
            signed_request_bytes: ctx.entry().signed_request_bytes.clone(),
            signing_transcript_bytes: ctx.entry().signing_transcript_bytes.clone(),
            request_digest: ctx.entry().request_digest.clone(),
            signature: ctx.entry().signature.clone(),
            received_at: applied_at,
            expires_at: applied_at + chrono::Duration::hours(24),
        },
    )
    .await?;

    // 5. Audience + event.
    let recipients = build_entry_recipients(&ctx.entry_recipients)?;
    delivery::insert_entry_recipients(
        transaction,
        conversation_id,
        u64::try_from(seq_i64).unwrap(),
        &recipients,
    )
    .await?;
    let event_positions = write_events(transaction, ctx, None).await?;

    Ok(AppliedTransition {
        allocated_seq: u64::try_from(seq_i64).unwrap(),
        entry_id: ctx.entry().entry_id,
        event_positions,
        successor_coordinate: plan.successor_coordinate().copied(),
    })
}

/// Apply an entry-bearing `leaveCancellation` control op. Non-mutating (the
/// requester withdraws their own pending leave consent): the head CAS advances
/// only the seq counter, it appends the `leaveCancellationEntry`, and it
/// terminalizes the pending `leave_requests` row as `cancelled`. The cancelled
/// row's `terminal_request_digest` == the cancellation entry's `request_digest`
/// and `terminal_at` == its `received_at` (`= applied_at`), exactly as the
/// cancelled-status arms of `assert_leave_request_mapping` /
/// `assert_control_request_entry` cross-check. No transition (non-mutating).
#[allow(clippy::too_many_arguments)]
async fn apply_leave_cancellation(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &ConversationPersistencePlan,
    ctx: &ExecutionContext,
    conversation_id: Uuid,
    seq_i64: i64,
    successor_next_entry_seq: i64,
    generation: i64,
    state_version: i64,
    _epoch: i64,
) -> Result<AppliedTransition, ExecutorError> {
    let effects = plan.effects();
    let applied_at = ctx.applied_at;
    let head = effects
        .head_cas()
        .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
    let expected_prior = head
        .expected_prior()
        .ok_or(ExecutorError::InconsistentPlan(
            "leave cancellation needs an expected prior",
        ))?;
    let expected_generation = checked_i64(expected_prior.generation())?;
    let expected_state_version = checked_i64(expected_prior.state_version())?;
    let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;

    // Non-mutating: only a leave-request row is terminalized. Everything else empty.
    reject_if_present("participant_changes", effects.participant_changes())?;
    reject_if_present("leaf_changes", effects.leaf_changes())?;
    reject_if_present("interval_changes", effects.interval_changes())?;
    reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
    reject_if_present(
        "recovery_request_changes",
        effects.recovery_request_changes(),
    )?;
    reject_if_present("reservation_changes", effects.reservation_changes())?;
    reject_if_present("reset_request_changes", effects.reset_request_changes())?;
    reject_if_present("welcome_changes", effects.welcome_changes())?;
    reject_if_present("package_transitions", effects.package_transitions())?;
    reject_if_present("recovery_package_cas", effects.recovery_package_cas())?;
    reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
    if effects.metadata_change().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "leave cancellation metadata change",
        ));
    }
    if effects.revocation_target_cas().is_some() || effects.welcome_cas().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "leave cancellation revocation/welcome CAS",
        ));
    }
    if effects.invitation_quota_cas().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "leave cancellation invitation quota CAS",
        ));
    }
    // Exactly one pending -> cancelled leave request in the delta.
    if effects.leave_request_changes().len() != 1 {
        return Err(ExecutorError::InconsistentPlan(
            "leave cancellation must change exactly one request",
        ));
    }
    let cancelled = effects
        .leave_request_changes()
        .iter()
        .find_map(|change| match (change.before(), change.after()) {
            (Some(before), Some(after))
                if before.status() == LeaveRequestStatus::Pending
                    && after.status() == LeaveRequestStatus::Cancelled =>
            {
                Some(after)
            }
            _ => None,
        })
        .ok_or(ExecutorError::InconsistentPlan(
            "leave cancellation must cancel exactly one pending request",
        ))?;
    let leave_request_id = Uuid::from_bytes(cancelled.request_id);

    // 1. Head CAS: advance the seq counter, coordinate UNCHANGED.
    transition::cas_conversation_head(
        transaction,
        &transition::ConversationHeadCas {
            conversation_id,
            expected_generation,
            expected_state_version,
            expected_next_entry_seq,
            successor_generation: generation,
            successor_state_version: state_version,
            successor_next_entry_seq,
            close: None,
        },
    )
    .await?;

    // 2. The cancellation entry (leaveCancellationEntry carries no transition_id).
    let mut append =
        build_append_entry(ctx, conversation_id, generation, state_version, Uuid::nil());
    append.generation = None;
    append.state_version = None;
    append.transition_id = None;
    delivery::append_entry_at(transaction, &append, u64::try_from(seq_i64).unwrap()).await?;

    // 3. Terminalize the pending request as `cancelled`, bound to the
    //    cancellation entry's digest + instant (the mapping cross-check).
    transition::terminalize_leave_request(
        transaction,
        leave_request_id,
        &LeaveRequestTermination::Cancelled {
            terminal_request_digest: ctx.entry().request_digest.clone(),
            terminal_at: applied_at,
        },
    )
    .await?;

    // 4. Audience + event.
    let recipients = build_entry_recipients(&ctx.entry_recipients)?;
    delivery::insert_entry_recipients(
        transaction,
        conversation_id,
        u64::try_from(seq_i64).unwrap(),
        &recipients,
    )
    .await?;
    let event_positions = write_events(transaction, ctx, None).await?;

    Ok(AppliedTransition {
        allocated_seq: u64::try_from(seq_i64).unwrap(),
        entry_id: ctx.entry().entry_id,
        event_positions,
        successor_coordinate: plan.successor_coordinate().copied(),
    })
}

/// Apply a `resetActivation` edge: retire the old generation and activate a
/// fresh one. Retired gen_state (`stateVersion+1`, superseded) + a new
/// generation at `generation+1` (epoch 0, fresh group/hash/tag) + successor
/// gen_state (sv 0, active) + head CAS to the successor pointer; close every
/// still-open old interval at the reset seq and open ONLY the activator's
/// successor interval at the same seq (touching `Reset -> Reset`); close every
/// old-generation leaf and install the activator's new genesis leaf;
/// terminalize the pending reset request as consumed.
#[allow(clippy::too_many_arguments)]
async fn apply_reset_activation(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &ConversationPersistencePlan,
    ctx: &ExecutionContext,
    conversation_id: Uuid,
    transition_id: Uuid,
    seq_i64: i64,
    successor_next_entry_seq: i64,
    generation: i64,
    state_version: i64,
    epoch: i64,
) -> Result<AppliedTransition, ExecutorError> {
    let effects = plan.effects();
    let hydration = plan.state();
    let coordinate = &hydration.coordinate; // successor coordinate.
    let applied_at = ctx.applied_at;
    let head = effects
        .head_cas()
        .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
    let prior = head
        .expected_prior()
        .ok_or(ExecutorError::InconsistentPlan(
            "reset activation needs a prior",
        ))?;
    let retired = plan
        .retired_coordinate()
        .ok_or(ExecutorError::InconsistentPlan(
            "reset activation needs a retired coordinate",
        ))?;
    let prior_generation = checked_i64(prior.generation())?;
    let prior_state_version = checked_i64(prior.state_version())?;
    let retired_generation = checked_i64(retired.generation())?;
    let retired_state_version = checked_i64(retired.state_version())?;
    let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;
    let successor_public_state =
        hydration
            .public_state
            .as_ref()
            .ok_or(ExecutorError::InconsistentPlan(
                "reset successor has no verified public state",
            ))?;
    let successor_tree = encode_public_tree_summary(
        successor_public_state.binding().tree_summary(),
    )
    .map_err(|_| ExecutorError::InconsistentPlan("reset successor tree is not canonical"))?;

    // Reset activation carries no participant change and no OWN recovery edge.
    // Its ONE own request edge is the named reset request it CONSUMES
    // (Pending->Consumed, step 11 below). It DOES supersede prior-coordinate open
    // work: a retired generation's pending welcome / open recovery request /
    // active reservation / reserved package are all resolved to superseded/
    // released by the plan and consumed below via write_prior_bound_supersessions
    // + write_welcome_supersessions + reconcile (own counts 0 for those). It also
    // stales a prior-bound pending LEAVE request the retirement retired
    // (Pending->Stale; kind is `resetActivation`, DB-legal for the leave `stale`
    // edge — the one-pending index means no SECOND reset request can be staled).
    // Families the reset genuinely never carries stay fail-closed.
    reject_if_present("participant_changes", effects.participant_changes())?;
    reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
    reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
    // Every recovery/reservation/package delta a reset carries MUST be a
    // prior-bound supersession (mirroring the generic-commit / close arms):
    // request Open->Superseded, reservation Active->Released, package
    // Reserved->Available. `recovery_package_cas` is the production-shape witness
    // the bijection validates, NOT a rejected family — so a reset that retires a
    // generation with an OPEN recovery request (reserved package) is composed,
    // not hard-errored.
    // Prior-bound recovery families. The three shape loops this replaces
    // accepted only Row A (Open->Superseded / Active->Released) and never
    // checked terminal evidence, family identity, or the CAS bindings — so a
    // legal Row B due-expiry family was rejected here exactly as it was in leaf
    // recovery fulfillment. The shared classifier proves both rows, strictly
    // before this arm's first head CAS.
    let partition = classify_prior_bound_recovery(plan, ctx, OwnFamilyKind::None)?; // reset activation
    if effects.revocation_target_cas().is_some() || effects.welcome_cas().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "reset revocation/welcome CAS",
        ));
    }
    if effects.metadata_change().is_none() {
        return Err(ExecutorError::InconsistentPlan(
            "reset activation carries no metadata",
        ));
    }
    if effects.invitation_quota_cas().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "reset invitation quota CAS",
        ));
    }
    let metadata = effects
        .metadata_change()
        .and_then(StateChange::after)
        .ok_or(ExecutorError::InconsistentPlan(
            "reset activation carries no metadata",
        ))?;
    let author_cols = ctx
        .metadata_author
        .as_ref()
        .ok_or(ExecutorError::MissingContext(
            "reset metadata author columns",
        ))?;
    let reset_request_id =
        preflight_reset_activation(plan, ctx, prior, retired, transition_id, seq_i64)?;

    // 1. Head CAS to the successor pointer (generation+1, stateVersion 0).
    transition::cas_conversation_head(
        transaction,
        &transition::ConversationHeadCas {
            conversation_id,
            expected_generation: prior_generation,
            expected_state_version: prior_state_version,
            expected_next_entry_seq,
            successor_generation: generation,
            successor_state_version: state_version,
            successor_next_entry_seq,
            close: None,
        },
    )
    .await?;

    // 2. Supersede the old generation (points at the retired state).
    transition::supersede_generation(
        transaction,
        &GenerationSupersede {
            conversation_id,
            generation: prior_generation,
            expected_state_version: prior_state_version,
            successor_state_version: retired_state_version,
            superseded_seq: seq_i64,
            superseded_at: applied_at,
        },
    )
    .await?;

    // 3. Retired generation state (old crypto, superseded, resetRetirement).
    transition::insert_generation_state_row(
        transaction,
        &NewGenerationState {
            conversation_id,
            generation: retired_generation,
            state_version: retired_state_version,
            group_id: prior.group_id().to_vec(),
            epoch: checked_i64(prior.epoch())?,
            group_context_hash: prior.group_context_hash().to_vec(),
            confirmation_tag: prior.confirmation_tag().to_vec(),
            lifecycle: GenerationStateLifecycle::Superseded,
            state_kind: GenerationStateKind::ResetRetirement,
            producing_transition_id: transition_id,
            public_snapshot_bytes: ctx.spine.public_snapshot_bytes.clone(),
            snapshot_sha256: ctx.spine.public_snapshot_sha256.clone(),
            tree_summary_bytes: ctx.spine.tree_summary_bytes.clone(),
            tree_summary_sha256: ctx.spine.tree_summary_sha256.clone(),
            leaf_count: ctx.spine.leaf_count,
            created_at: applied_at,
        },
    )
    .await?;

    // 4. Fresh successor generation (epoch 0, fresh group id).
    transition::insert_generation(
        transaction,
        &NewGeneration {
            conversation_id,
            generation,
            group_id: coordinate.group_id().to_vec(),
            genesis_group_info_bytes: ctx.spine.genesis_group_info_bytes.clone(),
            genesis_group_info_sha256: ctx.spine.genesis_group_info_sha256.clone(),
            current_state_version: state_version,
            activated_seq: seq_i64,
            activated_at: applied_at,
        },
    )
    .await?;

    // 5. Successor generation state (fresh crypto, active, resetSuccessor).
    transition::insert_generation_state_row(
        transaction,
        &NewGenerationState {
            conversation_id,
            generation,
            state_version,
            group_id: coordinate.group_id().to_vec(),
            epoch,
            group_context_hash: coordinate.group_context_hash().to_vec(),
            confirmation_tag: coordinate.confirmation_tag().to_vec(),
            lifecycle: GenerationStateLifecycle::Active,
            state_kind: GenerationStateKind::ResetSuccessor,
            producing_transition_id: transition_id,
            public_snapshot_bytes: successor_public_state.snapshot().to_vec(),
            snapshot_sha256: successor_public_state.snapshot_sha256().to_vec(),
            tree_summary_bytes: successor_tree.bytes().to_vec(),
            tree_summary_sha256: successor_tree.sha256().to_vec(),
            leaf_count: i64::try_from(
                successor_public_state
                    .binding()
                    .tree_summary()
                    .leaves()
                    .len(),
            )
            .map_err(|_| ExecutorError::ValueOutOfRange)?,
            created_at: applied_at,
        },
    )
    .await?;

    // 6. Entry (resetActivationEntry).
    let append = build_append_entry(
        ctx,
        conversation_id,
        generation,
        state_version,
        transition_id,
    );
    delivery::append_entry_at(transaction, &append, u64::try_from(seq_i64).unwrap()).await?;

    // 7. Transition (prior -> retired + successor; carries the reset request).
    transition::insert_transition_row(
        transaction,
        &NewTransition {
            transition_id,
            conversation_id,
            kind: TransitionKind::ResetActivation,
            actor_did: ctx.actor.user_did.clone(),
            actor_device_id: ctx.actor.device_id,
            actor_key_id: ctx.actor.key_id.clone(),
            actor_auth_generation: ctx.actor.auth_generation,
            actor_role: ctx.actor.role,
            actor_device_status: ctx.actor.device_status.clone(),
            signed_request_bytes: ctx.entry().signed_request_bytes.clone(),
            unsigned_projection_bytes: ctx.entry().unsigned_projection_bytes.clone(),
            signing_transcript_bytes: ctx.entry().signing_transcript_bytes.clone(),
            request_digest: ctx.entry().request_digest.clone(),
            signature: ctx.entry().signature.clone(),
            coordinates: TransitionCoordinates {
                // resetActivation: next == successor (both point at the fresh
                // generation), retired == (prior_gen, prior_sv + 1).
                prior: Some((prior_generation, prior_state_version)),
                next: Some((generation, state_version)),
                retired: Some((retired_generation, retired_state_version)),
                successor: Some((generation, state_version)),
            },
            reset_request_id: Some(reset_request_id),
            close_transition_id: None,
            metadata_snapshot_id: Some(author_cols.metadata_snapshot_id),
            entry_seq: seq_i64,
            accepted_at: applied_at,
        },
    )
    .await?;

    // 8. Successor metadata snapshot (self-origin, version from the binding).
    write_creation_metadata_snapshot(
        transaction,
        metadata,
        author_cols,
        &ctx.actor,
        conversation_id,
        generation,
        state_version,
        epoch,
        &coordinate.group_id().to_vec(),
        &coordinate.group_context_hash().to_vec(),
        &coordinate.confirmation_tag().to_vec(),
        transition_id,
        seq_i64,
        applied_at,
    )
    .await?;

    // 9. Close every old-generation leaf (facade-supplied) and install the
    //    successor genesis leaf(s). `leaf_changes` is a same-content diff that
    //    under-reports the generation change (the activator's new leaf has the
    //    same credential/index/keys as its old leaf), so the reset leaf ops are
    //    driven authoritatively by ctx.closing_leaf_periods + the successor
    //    hydration leaves rather than by the delta.
    for (device, old_leaf) in &ctx.closing_leaf_periods {
        let _ = device;
        transition::close_leaf_period(
            transaction,
            &LeafClose {
                leaf_period_id: *old_leaf,
                removed_state_version: retired_state_version,
                removed_transition_id: transition_id,
                removed_seq: seq_i64,
                removed_at: applied_at,
            },
        )
        .await?;
    }
    for (index, row) in hydration.leaves.iter().enumerate() {
        let leaf_period_id = *ctx
            .leaf_period_ids
            .get(index)
            .ok_or(ExecutorError::MissingContext("successor leaf period id"))?;
        write_successor_leaf(
            transaction,
            ctx,
            hydration,
            row,
            leaf_period_id,
            conversation_id,
            generation,
            transition_id,
            state_version,
            seq_i64,
            applied_at,
        )
        .await?;
    }

    // 10. Close old open intervals (Reset), open the activator's new one (Reset).
    for change in effects.interval_changes() {
        match (change.before(), change.after()) {
            (Some(_), Some(after)) => {
                let end = after.end().ok_or(ExecutorError::InconsistentPlan(
                    "reset closed interval has no end",
                ))?;
                let leaf = closing_leaf_period(ctx, after.recipient())?;
                delivery::close_application_interval(
                    transaction,
                    &ApplicationIntervalClose {
                        membership_interval_id: Uuid::from_bytes(*after.opening_transition_id()),
                        terminal_seq: checked_i64(end.seq())?,
                        closing_state_version: retired_state_version,
                        closing_transition_id: Uuid::from_bytes(*end.transition_id()),
                        closing_outer_entry_fingerprint: end.outer_entry_fingerprint().to_vec(),
                        closing_kind: repo_interval_close_kind(end.kind()),
                        closing_leaf_period_id: leaf,
                        removed_at: applied_at,
                    },
                )
                .await?;
            }
            (None, Some(after)) => {
                let opening_context = after.opening_context();
                let opening_leaf_period_id =
                    *ctx.leaf_period_ids
                        .first()
                        .ok_or(ExecutorError::MissingContext(
                            "successor interval leaf period",
                        ))?;
                delivery::insert_application_interval(
                    transaction,
                    &NewApplicationInterval {
                        membership_interval_id: Uuid::from_bytes(*after.opening_transition_id()),
                        conversation_id,
                        generation: checked_i64(opening_context.generation())?,
                        recipient_did: device_did(after.recipient())?,
                        recipient_device_id: device_uuid(after.recipient()),
                        start_seq: checked_i64(after.opening_seq())?,
                        opening_kind: IntervalOpeningKind::Reset,
                        opening_transition_id: Uuid::from_bytes(*after.opening_transition_id()),
                        opening_outer_entry_fingerprint: after
                            .opening_outer_entry_fingerprint()
                            .to_vec(),
                        opening_state_version: checked_i64(opening_context.state_version())?,
                        opening_group_id: opening_context.group_id().to_vec(),
                        opening_epoch: checked_i64(opening_context.epoch())?,
                        opening_group_context_hash: opening_context.group_context_hash().to_vec(),
                        opening_confirmation_tag: opening_context.confirmation_tag().to_vec(),
                        opening_leaf_period_id,
                        created_at: applied_at,
                    },
                )
                .await?;
            }
            _ => {
                return Err(ExecutorError::UnsupportedEffect(
                    "reset interval change shape",
                ))
            }
        }
    }

    // 11. Terminalize the pending reset request as consumed.
    transition::terminalize_reset_request(
        transaction,
        reset_request_id,
        &ResetRequestTermination::Consumed {
            terminal_transition_id: transition_id,
            terminal_at: applied_at,
        },
    )
    .await?;

    // 12. Audience + event.
    let recipients = build_entry_recipients(&ctx.entry_recipients)?;
    delivery::insert_entry_recipients(
        transaction,
        conversation_id,
        u64::try_from(seq_i64).unwrap(),
        &recipients,
    )
    .await?;
    let event_positions = write_events(transaction, ctx, None).await?;

    // 13. Supersede prior-coordinate open work the reset retired: the retired
    //     generation's pending welcome(s) + any open recovery request / active
    //     reservation / reserved package bound to the prior coordinate, and stale
    //     any prior-bound pending LEAVE request. The reset has ZERO own recovery/
    //     welcome/leave edges (its ONE own request edge is the reset request
    //     CONSUMED in step 11, counted as own below), so every recovery/welcome/
    //     leave delta MUST be a supersession/staling the calls below applied —
    //     reconcile rejects any that is neither (silent-drop guard). The reset
    //     loop in write_prior_bound_staling skips the own Pending->Consumed edge.
    let receipt =
        write_prior_bound_supersessions(transaction, effects, transition_id, applied_at).await?;
    // Design 5 step 6: reconcile the recovery families against the classifier's
    // KEYED expectation immediately, before any other writer runs. No unrelated
    // write may intervene. The counts are reachable ONLY through this call, so the
    // fence cannot be dropped without breaking the build.
    let mut superseded = receipt.reconcile_into_counts(&partition)?;
    superseded.welcomes = write_welcome_supersessions(
        transaction,
        ctx,
        effects,
        WelcomeSupersessionCause::Transition {
            terminal_transition_id: transition_id,
        },
    )
    .await?;
    let staled = write_prior_bound_staling(
        transaction,
        effects,
        transition_id,
        &ctx.entry().request_digest,
        applied_at,
    )
    .await?;
    superseded.reset_requests = staled.reset_requests;
    superseded.leave_requests = staled.leave_requests;
    reconcile_coordinate_change_families(
        effects,
        &FamilyCounts {
            reset_requests: 1,
            ..FamilyCounts::default()
        },
        &superseded,
    )?;

    Ok(AppliedTransition {
        allocated_seq: u64::try_from(seq_i64).unwrap(),
        entry_id: ctx.entry().entry_id,
        event_positions,
        successor_coordinate: plan.successor_coordinate().copied(),
    })
}

/// Apply an `acceptConversation` edge: promote a pending invitee to active and
/// atomically open the `add` leaf-recovery request + reservation bound to the
/// NEXT coordinate, reserving the acceptor's key package. `stateVersion+1`,
/// same crypto edge, no metadata / leaf / interval change.
#[allow(clippy::too_many_arguments)]
async fn apply_acceptance(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &ConversationPersistencePlan,
    ctx: &ExecutionContext,
    conversation_id: Uuid,
    transition_id: Uuid,
    seq_i64: i64,
    successor_next_entry_seq: i64,
    generation: i64,
    state_version: i64,
    epoch: i64,
    historical_write_authority: Option<&HistoricalExecutionWriteAuthority>,
) -> Result<AppliedTransition, ExecutorError> {
    let effects = plan.effects();
    let hydration = plan.state();
    let coordinate = &hydration.coordinate; // next coordinate (same crypto, sv+1).
    let applied_at = ctx.applied_at;
    let head = effects
        .head_cas()
        .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
    let expected_prior = head
        .expected_prior()
        .ok_or(ExecutorError::InconsistentPlan(
            "acceptance needs an expected prior",
        ))?;
    let expected_generation = checked_i64(expected_prior.generation())?;
    let expected_state_version = checked_i64(expected_prior.state_version())?;
    let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;

    // Acceptance OWNS: one pending->active participant, one new open recovery
    // request (None->Open), one new active reservation (None->Active), one
    // Available->Reserved package transition. It ALSO calls
    // `resolve_prior_bound_work` (via `plan_accept_conversation_inner`), so it CAN
    // carry (a legal interleaving) prior-coordinate open-work SUPERSESSIONS — a
    // DIFFERENT member's open recovery request (Open->Superseded) + reservation
    // (Active->Released) + reserved package (Reserved->Available), a prior pending
    // Welcome (Pending->Superseded), AND a prior-bound pending reset/leave request
    // (Pending->Stale). The own vs superseded partition is proven by the own-counts
    // below + the reconciliation; acceptance owns NO reset/leave edge (own 0 for
    // both). The `acceptConversation` kind is DB-LEGAL as the terminal authority
    // for both stale edges — reset staling has no kind restriction, and
    // `assert_leave_request_mapping` forbids only `leaveCommit`/`leavePolicy` (the
    // deferred Concerns 1/3 wall applies to zero-leaf-leave + leave-fulfillment
    // ONLY, not acceptance). So reset/leave staling is wired here exactly like
    // apply_policy. Every family the acceptance never carries is a hard error.
    reject_if_present("leaf_changes", effects.leaf_changes())?;
    reject_if_present("interval_changes", effects.interval_changes())?;
    reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
    reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
    if effects.metadata_change().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "acceptance metadata change",
        ));
    }
    if effects.revocation_target_cas().is_some() || effects.welcome_cas().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "acceptance revocation/welcome CAS",
        ));
    }
    if effects.invitation_quota_cas().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "acceptance invitation quota CAS",
        ));
    }
    // Exactly one pending->active participant.
    let participant_change = {
        let changes = effects.participant_changes();
        if changes.len() != 1 {
            return Err(ExecutorError::InconsistentPlan(
                "acceptance must change exactly one participant",
            ));
        }
        match (changes[0].before(), changes[0].after()) {
            (Some(before), Some(after))
                if before.status() == ParticipantStatus::Pending
                    && after.status() == ParticipantStatus::Active =>
            {
                after
            }
            _ => {
                return Err(ExecutorError::UnsupportedEffect(
                    "acceptance participant change is not pending->active",
                ))
            }
        }
    };
    // Exactly one new open recovery request + one new active reservation +
    // one package transition (Available->Reserved).
    let recovery = effects
        .recovery_request_changes()
        .iter()
        .find_map(|change| match (change.before(), change.after()) {
            (None, Some(after)) => Some(after),
            _ => None,
        })
        .ok_or(ExecutorError::InconsistentPlan(
            "acceptance adds no open recovery request",
        ))?;
    // Exactly ONE own edge per family (None->Open recovery, None->Active
    // reservation, Available->Reserved package). Any OTHER recovery/reservation/
    // package delta must be a prior-bound supersession (Open->Superseded /
    // Active->Released / Reserved->Available), consumed by
    // write_prior_bound_supersessions and proven by the tail reconciliation.
    let own_open = effects
        .recovery_request_changes()
        .iter()
        .filter(|change| matches!((change.before(), change.after()), (None, Some(_))))
        .count();
    let own_reserved = effects
        .reservation_changes()
        .iter()
        .filter(|change| {
            matches!((change.before(), change.after()), (None, Some(a))
                    if a.status() == ReservationStatus::Active)
        })
        .count();
    let own_package = effects
        .package_transitions()
        .iter()
        .filter(|edge| edge.from == PackageStatus::Available && edge.to == PackageStatus::Reserved)
        .count();
    if own_open != 1 || own_reserved != 1 || own_package != 1 {
        return Err(ExecutorError::InconsistentPlan(
            "acceptance must add exactly one own recovery request + reservation + package edge",
        ));
    }
    // Load-bearing recovery-package CAS bijection (over ALL edges) + the OWN
    // package edge's driven-ref + direction; any prior-bound Reserved->Available
    // supersession edges are validated by write_prior_bound_supersessions.
    verify_recovery_package_consistency(
        effects,
        recovery.key_package_ref(),
        PackageStatus::Available,
        PackageStatus::Reserved,
    )?;

    // Prior-bound recovery families. Acceptance previously proved only its OWN
    // family and left every prior-bound supersession to the writer, unproven
    // before the head CAS. The classifier derives the own family independently
    // by exact typed shape and proves every other family, Row A and Row B.
    let partition = classify_prior_bound_recovery(plan, ctx, OwnFamilyKind::Acceptance)?;

    // 1. Head CAS advances the coordinate + counter (sv+1, same generation).
    transition::cas_conversation_head(
        transaction,
        &transition::ConversationHeadCas {
            conversation_id,
            expected_generation,
            expected_state_version,
            expected_next_entry_seq,
            successor_generation: generation,
            successor_state_version: state_version,
            successor_next_entry_seq,
            close: None,
        },
    )
    .await?;

    // 2. Advance the generation's state-version pointer (same generation).
    transition::cas_generation_state_version(
        transaction,
        &transition::GenerationStateVersionCas {
            conversation_id,
            generation,
            expected_state_version,
            successor_state_version: state_version,
        },
    )
    .await?;

    // 3. Successor generation state (acceptConversation, identical crypto edge).
    transition::insert_generation_state_row(
        transaction,
        &NewGenerationState {
            conversation_id,
            generation,
            state_version,
            group_id: coordinate.group_id().to_vec(),
            epoch,
            group_context_hash: coordinate.group_context_hash().to_vec(),
            confirmation_tag: coordinate.confirmation_tag().to_vec(),
            lifecycle: GenerationStateLifecycle::Active,
            state_kind: GenerationStateKind::AcceptConversation,
            producing_transition_id: transition_id,
            public_snapshot_bytes: ctx.spine.public_snapshot_bytes.clone(),
            snapshot_sha256: ctx.spine.public_snapshot_sha256.clone(),
            tree_summary_bytes: ctx.spine.tree_summary_bytes.clone(),
            tree_summary_sha256: ctx.spine.tree_summary_sha256.clone(),
            leaf_count: ctx.spine.leaf_count,
            created_at: applied_at,
        },
    )
    .await?;

    // 4. Entry (participantAcceptanceEntry) at the allocated seq.
    let append = build_append_entry(
        ctx,
        conversation_id,
        generation,
        state_version,
        transition_id,
    );
    delivery::append_entry_at(transaction, &append, u64::try_from(seq_i64).unwrap()).await?;

    // 5. Transition (prior -> next).
    transition::insert_transition_row(
        transaction,
        &NewTransition {
            transition_id,
            conversation_id,
            kind: TransitionKind::AcceptConversation,
            actor_did: ctx.actor.user_did.clone(),
            actor_device_id: ctx.actor.device_id,
            actor_key_id: ctx.actor.key_id.clone(),
            actor_auth_generation: ctx.actor.auth_generation,
            actor_role: ctx.actor.role,
            actor_device_status: ctx.actor.device_status.clone(),
            signed_request_bytes: ctx.entry().signed_request_bytes.clone(),
            unsigned_projection_bytes: ctx.entry().unsigned_projection_bytes.clone(),
            signing_transcript_bytes: ctx.entry().signing_transcript_bytes.clone(),
            request_digest: ctx.entry().request_digest.clone(),
            signature: ctx.entry().signature.clone(),
            coordinates: TransitionCoordinates {
                prior: Some((expected_generation, expected_state_version)),
                next: Some((generation, state_version)),
                retired: None,
                successor: None,
            },
            reset_request_id: None,
            close_transition_id: None,
            metadata_snapshot_id: None,
            entry_seq: seq_i64,
            accepted_at: applied_at,
        },
    )
    .await?;

    // 6. Promote the pending participant to active with acceptance provenance.
    let open = ctx
        .recovery_open
        .as_ref()
        .ok_or(ExecutorError::MissingContext("recovery open context"))?;
    let participant_period_id = open
        .participant_period_id
        .ok_or(ExecutorError::MissingContext(
            "acceptance participant period id",
        ))?;
    transition::cas_participant_pending_to_active(
        transaction,
        &ParticipantAcceptanceCas {
            participant_period_id,
            conversation_id,
            user_did: principal_did(participant_change.principal())?,
            acceptance: ParticipantAcceptance {
                acceptance_transition_id: transition_id,
                acceptance_entry_id: ctx.entry().entry_id,
                accepted_at: applied_at,
            },
        },
    )
    .await?;

    // 7-9. The atomic recovery open (request + reservation + package reserve),
    //      bound to the NEXT coordinate; requester = recipient = the acceptor.
    write_recovery_open(transaction, ctx, recovery, conversation_id, applied_at).await?;

    // 10. Audience + events.
    let recipients = build_entry_recipients(&ctx.entry_recipients)?;
    if !recipients.is_empty() {
        delivery::insert_entry_recipients(
            transaction,
            conversation_id,
            u64::try_from(seq_i64).unwrap(),
            &recipients,
        )
        .await?;
    }
    let event_positions = write_events(transaction, ctx, historical_write_authority).await?;

    // 11. Supersede any prior-coordinate open work a DIFFERENT member left bound
    //     to the retired coordinate (Open->Superseded recovery / Active->Released
    //     reservation / Reserved->Available package + Pending->Superseded welcome).
    //     Acceptance's OWN edges are the None->Open recovery / None->Active
    //     reservation / Available->Reserved package applied by write_recovery_open
    //     above (own counts {1,1,1}); write_prior_bound_supersessions SKIPS those
    //     (they are not the supersession shape), so it consumes ONLY the other
    //     member's work, and reconcile proves own + superseded == total.
    let receipt =
        write_prior_bound_supersessions(transaction, effects, transition_id, applied_at).await?;
    // Design 5 step 6: reconcile the recovery families against the classifier's
    // KEYED expectation immediately, before any other writer runs. No unrelated
    // write may intervene. The counts are reachable ONLY through this call, so the
    // fence cannot be dropped without breaking the build.
    let mut superseded = receipt.reconcile_into_counts(&partition)?;
    superseded.welcomes = write_welcome_supersessions(
        transaction,
        ctx,
        effects,
        WelcomeSupersessionCause::Transition {
            terminal_transition_id: transition_id,
        },
    )
    .await?;
    // Stale any prior-bound pending reset/leave request the acceptance retired
    // (own 0 — acceptance creates/consumes neither; kind `acceptConversation` is
    // DB-legal for both stale edges), exactly like apply_policy.
    let staled = write_prior_bound_staling(
        transaction,
        effects,
        transition_id,
        &ctx.entry().request_digest,
        applied_at,
    )
    .await?;
    superseded.reset_requests = staled.reset_requests;
    superseded.leave_requests = staled.leave_requests;
    reconcile_coordinate_change_families(
        effects,
        &FamilyCounts {
            requests: 1,
            reservations: 1,
            packages: 1,
            welcomes: 0,
            reset_requests: 0,
            leave_requests: 0,
        },
        &superseded,
    )?;

    Ok(AppliedTransition {
        allocated_seq: u64::try_from(seq_i64).unwrap(),
        entry_id: ctx.entry().entry_id,
        event_positions,
        successor_coordinate: plan.successor_coordinate().copied(),
    })
}

/// Open a leaf-recovery request + its paired reservation and reserve the
/// requester's key package (Available -> Reserved), all bound to
/// `recovery.bound_coordinate()`. Shared by the acceptance edge (source
/// `acceptConversation`, kind `add`, bound to the successor) and the
/// leaf-recovery request edge (source `requestLeafRecovery`, `add`/`replace`,
/// bound to the current coordinate). The requester and recipient are the same
/// device — the transition/request actor (`ctx.actor`). Timestamps are DB-clock:
/// `created_at == requested_at == applied_at` and
/// `expires_at == LEAST(applied_at + 5 min, package.not_after)`, exactly what
/// `assert_recovery_fulfillment_mapping` cross-checks.
async fn write_recovery_open(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ctx: &ExecutionContext,
    recovery: &super::RecoveryRequest,
    conversation_id: Uuid,
    applied_at: DateTime<Utc>,
) -> Result<(), ExecutorError> {
    let open = ctx
        .recovery_open
        .as_ref()
        .ok_or(ExecutorError::MissingContext("recovery open context"))?;
    let bound = recovery.bound_coordinate();
    let generation = checked_i64(bound.generation())?;
    let bound_state_version = checked_i64(bound.state_version())?;
    let bound_epoch = checked_i64(bound.epoch())?;
    let requested_at = applied_at;
    let expires_at = (applied_at + chrono::Duration::minutes(5)).min(open.package_not_after);
    let recovery_request_id = Uuid::from_bytes(*recovery.request_id());
    let key_package_ref = recovery.key_package_ref().to_vec();
    let recovery_kind = match recovery.kind() {
        LeafRecoveryKind::Add => RepoLeafRecoveryKind::Add,
        LeafRecoveryKind::Replace => RepoLeafRecoveryKind::Replace {
            replaced_leaf_period_id: open.replaced_leaf_period_id.ok_or(
                ExecutorError::MissingContext("replace request replaced leaf period id"),
            )?,
        },
    };
    let source = match recovery.source() {
        RecoverySource::Acceptance => LeafRecoverySource::AcceptConversation,
        RecoverySource::Request => LeafRecoverySource::RequestLeafRecovery,
    };
    transition::insert_leaf_recovery_request(
        transaction,
        &NewLeafRecoveryRequest {
            recovery_request_id,
            conversation_id,
            generation,
            requester_did: ctx.actor.user_did.clone(),
            requester_device_id: ctx.actor.device_id,
            requester_key_id: ctx.actor.key_id.clone(),
            requester_auth_generation: ctx.actor.auth_generation,
            recovery_kind,
            source,
            bound_state_version,
            bound_group_id: bound.group_id().to_vec(),
            bound_epoch,
            bound_group_context_hash: bound.group_context_hash().to_vec(),
            bound_confirmation_tag: bound.confirmation_tag().to_vec(),
            reservation_request_id: recovery_request_id,
            signed_request_bytes: ctx.entry().signed_request_bytes.clone(),
            signing_transcript_bytes: ctx.entry().signing_transcript_bytes.clone(),
            request_digest: ctx.entry().request_digest.clone(),
            signature: ctx.entry().signature.clone(),
            requested_at,
            expires_at,
        },
    )
    .await?;
    transition::insert_reservation(
        transaction,
        &NewReservation {
            recovery_request_id,
            key_package_ref: key_package_ref.clone(),
            conversation_id,
            generation,
            requester_did: ctx.actor.user_did.clone(),
            requester_device_id: ctx.actor.device_id,
            requester_key_id: ctx.actor.key_id.clone(),
            requester_auth_generation: ctx.actor.auth_generation,
            recipient_did: ctx.actor.user_did.clone(),
            recipient_device_id: ctx.actor.device_id,
            bound_state_version,
            bound_group_id: bound.group_id().to_vec(),
            bound_epoch,
            bound_group_context_hash: bound.group_context_hash().to_vec(),
            bound_confirmation_tag: bound.confirmation_tag().to_vec(),
            expires_at,
            created_at: requested_at,
        },
    )
    .await?;
    transition::cas_key_package_status(
        transaction,
        &key_package_ref,
        RepoPackageStatus::Available,
        &PackageSuccessor::Reserve,
    )
    .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn write_successor_leaf(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ctx: &ExecutionContext,
    hydration: &ConversationStateHydration,
    row: &LeafHydrationRow,
    leaf_period_id: Uuid,
    conversation_id: Uuid,
    generation: i64,
    transition_id: Uuid,
    state_version: i64,
    seq_i64: i64,
    applied_at: DateTime<Utc>,
) -> Result<(), ExecutorError> {
    let cols = ctx
        .opened_leaves
        .iter()
        .find(|cols| cols.device == row.device)
        .ok_or(ExecutorError::MissingContext("successor leaf columns"))?;
    let participant_period_id = participant_period_for(ctx, hydration, row.device.principal())?;
    transition::insert_leaf_period(
        transaction,
        &NewLeafPeriod {
            leaf_period_id,
            participant_period_id,
            conversation_id,
            generation,
            user_did: device_did(&row.device)?,
            device_id: device_uuid(&row.device),
            leaf_index: checked_i64(u64::from(row.leaf_index))?,
            basic_credential: row.basic_credential.clone(),
            leaf_signature_key: row.signature_key.clone(),
            leaf_key_id: cols.leaf_key_id.clone(),
            leaf_auth_generation: cols.leaf_auth_generation,
            origin: LeafOrigin::Genesis,
            joined_state_version: state_version,
            joined_transition_id: transition_id,
            joined_seq: seq_i64,
            created_at: applied_at,
        },
    )
    .await?;
    Ok(())
}

fn closing_leaf_period(
    ctx: &ExecutionContext,
    device: &DeviceIdentity,
) -> Result<Uuid, ExecutorError> {
    ctx.closing_leaf_periods
        .iter()
        .find(|(candidate, _)| candidate == device)
        .map(|(_, id)| *id)
        .ok_or(ExecutorError::MissingContext("closing leaf period id"))
}

fn repo_interval_close_kind(kind: CloseKind) -> IntervalCloseKind {
    match kind {
        CloseKind::Remove => IntervalCloseKind::Remove,
        CloseKind::Replace => IntervalCloseKind::Replace,
        CloseKind::Reset => IntervalCloseKind::Reset,
        CloseKind::Terminal => IntervalCloseKind::Terminal,
    }
}

fn direct_pair(
    participants: &[ParticipantHydrationRow],
) -> Result<(String, String), ExecutorError> {
    if participants.len() != 2 {
        return Err(ExecutorError::InconsistentPlan(
            "direct conversation is not a pair",
        ));
    }
    let mut dids = participants
        .iter()
        .map(|row| principal_did(&row.principal))
        .collect::<Result<Vec<_>, _>>()?;
    dids.sort();
    Ok((dids[0].clone(), dids[1].clone()))
}

fn build_append_entry(
    ctx: &ExecutionContext,
    conversation_id: Uuid,
    generation: i64,
    state_version: i64,
    transition_id: Uuid,
) -> AppendEntry {
    AppendEntry {
        conversation_id,
        entry_id: ctx.entry().entry_id,
        entry_kind: ctx.entry().entry_kind.clone(),
        accepted_payload_bytes: ctx.entry().accepted_payload_bytes.clone(),
        accepted_payload_sha256: ctx.entry().accepted_payload_sha256.clone(),
        signed_request_bytes: ctx.entry().signed_request_bytes.clone(),
        request_digest: ctx.entry().request_digest.clone(),
        signature: ctx.entry().signature.clone(),
        server_fields_bytes: ctx.entry().server_fields_bytes.clone(),
        outer_entry_fingerprint: ctx.entry().outer_entry_fingerprint.clone(),
        actor_did: ctx.actor.user_did.clone(),
        actor_device_id: ctx.actor.device_id,
        actor_key_id: ctx.actor.key_id.clone(),
        actor_auth_generation: ctx.actor.auth_generation,
        generation: Some(generation),
        state_version: Some(state_version),
        transition_id: Some(transition_id),
        message_id: None,
        received_at: ctx.applied_at,
    }
}

/// Persist the creation metadata snapshot. The author identity is sourced
/// from the **actor** (not the binding): for creation the metadata author is
/// definitionally the creation actor, and the deferred author-proof trigger
/// joins the snapshot's author columns back to the creation transition's
/// actor columns, so they must byte-equal. The encrypted CONTENT (nonce,
/// ciphertext, its digest) is sourced from the plan's `MetadataSnapshotBinding`;
/// `origin_transition_id`/`metadata_version`/`author_origin_seq` are the
/// creation transition itself / 1 / the genesis seq.
#[allow(clippy::too_many_arguments)]
async fn write_creation_metadata_snapshot(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    metadata: &MetadataSnapshotBinding,
    author_cols: &MetadataAuthorColumns,
    actor: &ExecutionActor,
    conversation_id: Uuid,
    generation: i64,
    state_version: i64,
    epoch: i64,
    group_id: &[u8],
    group_context_hash: &[u8],
    confirmation_tag: &[u8],
    transition_id: Uuid,
    seq_i64: i64,
    applied_at: DateTime<Utc>,
) -> Result<(), ExecutorError> {
    let ciphertext = metadata.ciphertext().to_vec();
    let ciphertext_size = checked_i64(ciphertext.len() as u64)?;
    transition::insert_metadata_snapshot(
        transaction,
        &NewMetadataSnapshot {
            metadata_snapshot_id: author_cols.metadata_snapshot_id,
            conversation_id,
            generation,
            state_version,
            group_id: group_id.to_vec(),
            epoch,
            group_context_hash: group_context_hash.to_vec(),
            confirmation_tag: confirmation_tag.to_vec(),
            producing_transition_id: transition_id,
            // Self-origin snapshot: creation (version 1) and reset activation
            // (fresh, version prior+1) both set origin_transition_id to the
            // producing transition and author = the actor; the version comes
            // from the plan's binding so this serves both edges.
            origin_transition_id: transition_id,
            metadata_version: checked_i64(metadata.metadata_version())?,
            nonce: metadata.nonce().to_vec(),
            ciphertext_sha256: metadata.ciphertext_sha256().to_vec(),
            ciphertext,
            ciphertext_size,
            avatar: None,
            author_did: actor.user_did.clone(),
            author_device_id: actor.device_id,
            author_key_id: actor.key_id.clone(),
            author_public_key: author_cols.author_public_key.clone(),
            author_auth_generation: actor.auth_generation,
            author_origin_seq: seq_i64,
            author_role: author_cols.author_role.clone(),
            author_device_status: author_cols.author_device_status.clone(),
            created_at: applied_at,
        },
    )
    .await?;
    Ok(())
}

/// Persist a self-origin `signedMetadataTransition` snapshot. Unlike an
/// epoch re-encryption, this edge advances `metadata_version`, binds the new
/// origin to this transition, and records the current admin signer as the
/// author. The pure preflight has already proved those facts against the
/// signed body, actor, and repository-hydrated author columns.
#[allow(clippy::too_many_arguments)]
async fn write_metadata_update_snapshot(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    metadata: &MetadataSnapshotBinding,
    author_cols: &MetadataAuthorColumns,
    avatar: Option<&MetadataAvatarBinding>,
    conversation_id: Uuid,
    generation: i64,
    state_version: i64,
    epoch: i64,
    group_id: &[u8],
    group_context_hash: &[u8],
    confirmation_tag: &[u8],
    transition_id: Uuid,
    seq_i64: i64,
    applied_at: DateTime<Utc>,
) -> Result<(), ExecutorError> {
    let ciphertext = metadata.ciphertext().to_vec();
    let ciphertext_size = checked_i64(ciphertext.len() as u64)?;
    transition::insert_metadata_snapshot(
        transaction,
        &NewMetadataSnapshot {
            metadata_snapshot_id: author_cols.metadata_snapshot_id,
            conversation_id,
            generation,
            state_version,
            group_id: group_id.to_vec(),
            epoch,
            group_context_hash: group_context_hash.to_vec(),
            confirmation_tag: confirmation_tag.to_vec(),
            producing_transition_id: transition_id,
            origin_transition_id: transition_id,
            metadata_version: checked_i64(metadata.metadata_version())?,
            nonce: metadata.nonce().to_vec(),
            ciphertext_sha256: metadata.ciphertext_sha256().to_vec(),
            ciphertext,
            ciphertext_size,
            avatar: avatar.cloned(),
            author_did: device_did(metadata.author())?,
            author_device_id: device_uuid(metadata.author()),
            author_key_id: author_cols.author_key_id.clone(),
            author_public_key: metadata.signature_public_key().to_vec(),
            author_auth_generation: checked_i64(metadata.author_auth_generation_at_origin())?,
            author_origin_seq: seq_i64,
            author_role: author_cols.author_role.clone(),
            author_device_status: author_cols.author_device_status.clone(),
            created_at: applied_at,
        },
    )
    .await?;
    Ok(())
}

/// Persist a commit/leafRecovery metadata RE-ENCRYPTION snapshot. Per the DDL
/// `assert_metadata_snapshot_mapping` `commit/leafRecovery/leaveCommit` arm the
/// new snapshot's author / origin / metadata_version / ciphertext_size / avatar
/// columns must byte-equal the PRIOR snapshot's — only nonce / ciphertext /
/// ciphertext_sha256 are fresh (the metadata content re-encrypted for the new
/// epoch). So author identity is CARRIED FORWARD from the re-encryption
/// binding's author-proof (the ORIGINAL author — creation/metadata author, NOT
/// the fulfiller `ctx.actor`), with the DB `author_key_id` / `author_role` /
/// `author_device_status` / snapshot PK supplied by `MetadataAuthorColumns`;
/// `producing_transition_id` and the coordinate are this transition's successor.
#[allow(clippy::too_many_arguments)]
async fn write_commit_metadata_snapshot(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    metadata: &MetadataSnapshotBinding,
    author_cols: &MetadataAuthorColumns,
    conversation_id: Uuid,
    generation: i64,
    state_version: i64,
    epoch: i64,
    group_id: &[u8],
    group_context_hash: &[u8],
    confirmation_tag: &[u8],
    producing_transition_id: Uuid,
    applied_at: DateTime<Utc>,
) -> Result<(), ExecutorError> {
    let proof = &metadata.author_proof;
    let ciphertext = metadata.ciphertext().to_vec();
    let ciphertext_size = checked_i64(ciphertext.len() as u64)?;
    transition::insert_metadata_snapshot(
        transaction,
        &NewMetadataSnapshot {
            metadata_snapshot_id: author_cols.metadata_snapshot_id,
            conversation_id,
            generation,
            state_version,
            group_id: group_id.to_vec(),
            epoch,
            group_context_hash: group_context_hash.to_vec(),
            confirmation_tag: confirmation_tag.to_vec(),
            producing_transition_id,
            // Carry-forward origin + version from the prior snapshot.
            origin_transition_id: Uuid::from_bytes(*metadata.origin_transition_id()),
            metadata_version: checked_i64(metadata.metadata_version())?,
            // Fresh re-encryption (same ciphertext size as the prior snapshot).
            nonce: metadata.nonce().to_vec(),
            ciphertext_sha256: metadata.ciphertext_sha256().to_vec(),
            ciphertext,
            ciphertext_size,
            avatar: None,
            // Carry-forward author identity from the binding's author-proof.
            author_did: principal_did(proof.author.principal())?,
            author_device_id: device_uuid(&proof.author),
            author_key_id: author_cols.author_key_id.clone(),
            author_public_key: proof.signature_public_key.to_vec(),
            author_auth_generation: checked_i64(proof.auth_generation_at_origin)?,
            author_origin_seq: checked_i64(proof.origin_seq)?,
            author_role: author_cols.author_role.clone(),
            author_device_status: author_cols.author_device_status.clone(),
            created_at: applied_at,
        },
    )
    .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn write_participants(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ctx: &ExecutionContext,
    hydration: &ConversationStateHydration,
    effects: &TransitionEffects,
    transition_id: Uuid,
    applied_at: DateTime<Utc>,
    allow_role_changes: bool,
) -> Result<(), ExecutorError> {
    let creator = &ctx.actor;
    let mut period_ids = ctx.participant_period_ids.iter();
    for change in effects.participant_changes() {
        let after = match (change.before(), change.after()) {
            (Some(before), Some(after)) if allow_role_changes => {
                transition::cas_participant_active_role(
                    transaction,
                    &ParticipantRoleCas {
                        conversation_id: Uuid::from_bytes(*hydration.coordinate.conversation_id()),
                        user_did: principal_did(after.principal())?,
                        expected_role: repo_participant_role(before.role()),
                        successor_role: repo_participant_role(after.role()),
                        role_transition_id: transition_id,
                        role_changed_at: applied_at,
                    },
                )
                .await?;
                continue;
            }
            (None, Some(after)) => after,
            (Some(_), None) if allow_role_changes => continue,
            _ => {
                return Err(ExecutorError::UnsupportedEffect(
                    "participant change is not an insert or policy role change",
                ))
            }
        };
        let row = hydration
            .participants
            .iter()
            .find(|row| &row.principal == after.principal())
            .ok_or(ExecutorError::InconsistentPlan(
                "participant not in hydration",
            ))?;
        let period_id = *period_ids
            .next()
            .ok_or(ExecutorError::MissingContext("participant period id"))?;
        let invitation = match &row.invitation {
            Some(_) => Some(ParticipantInvitation {
                invitation_transition_id: transition_id,
                invitation_entry_id: ctx.entry().entry_id,
                invited_at: applied_at,
            }),
            None => None,
        };
        let user_did = principal_did(&row.principal)?;
        // `Some(None)` is an explicit local route. A missing map entry is
        // missing authority and must never silently become local.
        let ds_did = ctx
            .participant_ds_dids
            .get(&user_did)
            .cloned()
            .ok_or(ExecutorError::MissingParticipantRoutingAuthority)?;
        transition::insert_participant_period(
            transaction,
            &NewParticipantPeriod {
                participant_period_id: period_id,
                conversation_id: Uuid::from_bytes(*hydration.coordinate.conversation_id()),
                user_did,
                status: repo_participant_status(row.status),
                role: repo_participant_role(row.role),
                role_transition_id: transition_id,
                role_changed_at: applied_at,
                created_by_did: creator.user_did.clone(),
                created_by_device_id: creator.device_id,
                invitation,
                acceptance: None,
                created_at: applied_at,
                ds_did,
            },
        )
        .await?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn write_creation_leaves(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ctx: &ExecutionContext,
    hydration: &ConversationStateHydration,
    effects: &TransitionEffects,
    conversation_id: Uuid,
    generation: i64,
    transition_id: Uuid,
    state_version: i64,
    seq_i64: i64,
    applied_at: DateTime<Utc>,
) -> Result<HashMap<DeviceIdentity, Uuid>, ExecutorError> {
    let mut opened: HashMap<DeviceIdentity, Uuid> = HashMap::new();
    let mut leaf_ids = ctx.leaf_period_ids.iter();
    for change in effects.leaf_changes() {
        let after = match (change.before(), change.after()) {
            (None, Some(after)) => after,
            _ => {
                return Err(ExecutorError::UnsupportedEffect(
                    "leaf change is not a creation insert",
                ))
            }
        };
        let row: &LeafHydrationRow = hydration
            .leaves
            .iter()
            .find(|row| &row.device == after.device())
            .ok_or(ExecutorError::InconsistentPlan("leaf not in hydration"))?;
        let cols = ctx
            .opened_leaves
            .iter()
            .find(|cols| &cols.device == after.device())
            .ok_or(ExecutorError::MissingContext("leaf persistence columns"))?;
        // The owning participant period must already be inserted; its id is
        // matched by DID (one current period per DID at creation).
        let participant_period_id =
            participant_period_for(ctx, hydration, after.device().principal())?;
        let leaf_id = *leaf_ids
            .next()
            .ok_or(ExecutorError::MissingContext("leaf period id"))?;
        transition::insert_leaf_period(
            transaction,
            &NewLeafPeriod {
                leaf_period_id: leaf_id,
                participant_period_id,
                conversation_id,
                generation,
                user_did: device_did(after.device())?,
                device_id: device_uuid(after.device()),
                leaf_index: checked_i64(u64::from(row.leaf_index))?,
                basic_credential: row.basic_credential.clone(),
                leaf_signature_key: row.signature_key.clone(),
                leaf_key_id: cols.leaf_key_id.clone(),
                leaf_auth_generation: cols.leaf_auth_generation,
                origin: LeafOrigin::Genesis,
                joined_state_version: state_version,
                joined_transition_id: transition_id,
                joined_seq: seq_i64,
                created_at: applied_at,
            },
        )
        .await?;
        opened.insert(after.device().clone(), leaf_id);
    }
    Ok(opened)
}

/// Resolve the participant-period id the executor minted for `principal`.
/// Creation inserts periods in the plan's canonical participant order, so the
/// id is the ctx `participant_period_ids` entry at that principal's index.
fn participant_period_for(
    ctx: &ExecutionContext,
    hydration: &ConversationStateHydration,
    principal: &PrincipalId,
) -> Result<Uuid, ExecutorError> {
    let index = hydration
        .participants
        .iter()
        .position(|row| &row.principal == principal)
        .ok_or(ExecutorError::InconsistentPlan(
            "leaf owner not a participant",
        ))?;
    ctx.participant_period_ids
        .get(index)
        .copied()
        .ok_or(ExecutorError::MissingContext(
            "participant period id for leaf owner",
        ))
}

async fn write_creation_intervals(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    effects: &TransitionEffects,
    leaf_ids: &HashMap<DeviceIdentity, Uuid>,
    conversation_id: Uuid,
    applied_at: DateTime<Utc>,
) -> Result<(), ExecutorError> {
    for change in effects.interval_changes() {
        let after = match (change.before(), change.after()) {
            (None, Some(after)) => after,
            _ => {
                return Err(ExecutorError::UnsupportedEffect(
                    "interval change is not a creation open",
                ))
            }
        };
        if after.end().is_some() {
            return Err(ExecutorError::UnsupportedEffect(
                "creation interval is born closed",
            ));
        }
        if after.opening_kind() != super::OpeningKind::Creation {
            return Err(ExecutorError::UnsupportedEffect(
                "non-creation interval opening in a creation plan",
            ));
        }
        let opening_transition_id = Uuid::from_bytes(*after.opening_transition_id());
        let opening_leaf_period_id =
            *leaf_ids
                .get(after.recipient())
                .ok_or(ExecutorError::InconsistentPlan(
                    "interval recipient has no opened leaf",
                ))?;
        let opening_context = after.opening_context();
        delivery::insert_application_interval(
            transaction,
            &NewApplicationInterval {
                membership_interval_id: opening_transition_id,
                conversation_id,
                generation: checked_i64(opening_context.generation())?,
                recipient_did: device_did(after.recipient())?,
                recipient_device_id: device_uuid(after.recipient()),
                start_seq: checked_i64(after.opening_seq())?,
                opening_kind: IntervalOpeningKind::Creation,
                opening_transition_id,
                opening_outer_entry_fingerprint: after.opening_outer_entry_fingerprint().to_vec(),
                opening_state_version: checked_i64(opening_context.state_version())?,
                opening_group_id: opening_context.group_id().to_vec(),
                opening_epoch: checked_i64(opening_context.epoch())?,
                opening_group_context_hash: opening_context.group_context_hash().to_vec(),
                opening_confirmation_tag: opening_context.confirmation_tag().to_vec(),
                opening_leaf_period_id,
                created_at: applied_at,
            },
        )
        .await?;
    }
    Ok(())
}

fn build_entry_recipients(
    recipients: &[(DeviceIdentity, EntryEntitlementKind)],
) -> Result<Vec<EntryRecipient>, ExecutorError> {
    recipients
        .iter()
        .map(|(device, kind)| {
            Ok(EntryRecipient {
                user_did: device_did(device)?,
                device_id: device_uuid(device),
                entitlement_kind: *kind,
            })
        })
        .collect()
}

/// Consume the prior-coordinate open-work SUPERSESSION deltas a
/// coordinate-changing commit carries (the planner's `resolve_prior_bound_work`
/// emits them; E2b-7 arm 1). For each `(Open -> Superseded)` recovery request:
/// terminalize `SupersededByTransition`. For each `(Active -> Released)`
/// reservation: terminalize `ReleasedByTransition`. For each
/// `Reserved -> Available` package edge: re-activate. The OWN delta of an
/// edge (a fulfillment's `Fulfilled`/`Consumed`/`Consumed`) has a DIFFERENT
/// shape and is SKIPPED here (the arm handles it), so this is safely callable
/// from every coordinate-changing arm. Returns the number of each family
/// superseded so the caller can enforce exact-shape (own + supersessions ==
/// total). All three are bound to the same producing transition.
async fn write_prior_bound_supersessions(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    effects: &TransitionEffects,
    transition_id: Uuid,
    applied_at: DateTime<Utc>,
) -> Result<PriorBoundWriteReceipt, ExecutorError> {
    let mut counts = FamilyCounts::default();
    let mut keys: BTreeSet<([u8; 16], [u8; 32])> = BTreeSet::new();
    // Consume the exact locked package authority while its paired durable
    // request/reservation rows are still in the Open/Active pre-state.
    // Terminalizing those rows first would force this writer to fall back
    // to a semantic `(ref,status)` edge and discard the guard.
    for edge in effects.package_transitions() {
        if edge.from == PackageStatus::Reserved
            && matches!(edge.to, PackageStatus::Available | PackageStatus::Expired)
        {
            let mut matches = effects.recovery_package_cas().iter().filter(|binding| {
                binding.request_id == edge.request_id
                    && binding.key_package_ref == edge.key_package_ref
                    && binding.expected_status == edge.from
                    && binding.successor_status == edge.to
            });
            let binding = matches.next().ok_or(ExecutorError::InconsistentPlan(
                "prior-bound package edge has no exact locked authority",
            ))?;
            if matches.next().is_some() {
                return Err(ExecutorError::InconsistentPlan(
                    "prior-bound package edge has duplicate locked authority",
                ));
            }
            let target_did = device_did(&binding.target)?;
            let target_key_id = URL_SAFE_NO_PAD.encode(binding.target_key_id);
            transition::release_reserved_recovery_package(
                transaction,
                &transition::ReservedRecoveryPackageReleaseCas {
                    transaction_id: &binding.transaction_id,
                    conversation_id: Uuid::from_bytes(binding.conversation_id),
                    request_id: Uuid::from_bytes(binding.request_id),
                    target_did: &target_did,
                    target_device_id: device_uuid(&binding.target),
                    target_key_id: &target_key_id,
                    target_auth_generation: checked_i64(binding.target_auth_generation)?,
                    generation: checked_i64(binding.bound_coordinate.generation())?,
                    state_version: checked_i64(binding.bound_coordinate.state_version())?,
                    group_id: binding.bound_coordinate.group_id(),
                    epoch: checked_i64(binding.bound_coordinate.epoch())?,
                    group_context_hash: binding.bound_coordinate.group_context_hash(),
                    confirmation_tag: binding.bound_coordinate.confirmation_tag(),
                    key_package_ref: &binding.key_package_ref,
                    wrapper_sha256: &binding.key_package_wrapper_sha256,
                    package_not_after: server_instant(binding.package_not_after)?,
                    claimed_at: server_instant(binding.claimed_at)?,
                    locked_row_digest: &binding.locked_row_digest,
                    authority_digest: &binding.authority_digest,
                    successor_status: match binding.successor_status {
                        PackageStatus::Available => RepoPackageStatus::Available,
                        PackageStatus::Expired => RepoPackageStatus::Expired,
                        _ => {
                            return Err(ExecutorError::InconsistentPlan(
                                "prior-bound package has an illegal terminal successor",
                            ))
                        }
                    },
                    terminal_at: (binding.successor_status == PackageStatus::Expired)
                        .then_some(server_instant(binding.package_not_after)?),
                },
            )
            .await?;
            counts.packages += 1;
            keys.insert((edge.request_id, edge.key_package_ref));
        }
    }
    for change in effects.recovery_request_changes() {
        if let (Some(before), Some(after)) = (change.before(), change.after()) {
            if before.status() == RecoveryRequestStatus::Open {
                let termination = match after.status() {
                    RecoveryRequestStatus::Superseded => {
                        Some(LeafRecoveryTermination::SupersededByTransition {
                            terminal_transition_id: transition_id,
                            terminal_at: applied_at,
                        })
                    }
                    RecoveryRequestStatus::Expired => Some(LeafRecoveryTermination::Expired {
                        terminal_at: server_instant(*after.expires_at())?,
                    }),
                    _ => None,
                };
                if let Some(termination) = termination {
                    transition::terminalize_leaf_recovery_request(
                        transaction,
                        Uuid::from_bytes(*after.request_id()),
                        &termination,
                    )
                    .await?;
                    counts.requests += 1;
                }
            }
        }
    }
    for change in effects.reservation_changes() {
        if let (Some(before), Some(after)) = (change.before(), change.after()) {
            if before.status() == ReservationStatus::Active {
                let termination = match after.status() {
                    ReservationStatus::Released => {
                        Some(ReservationTermination::ReleasedByTransition {
                            terminal_transition_id: transition_id,
                            terminal_at: applied_at,
                        })
                    }
                    ReservationStatus::Expired => Some(ReservationTermination::Expired {
                        terminal_at: server_instant(after.expires_at)?,
                    }),
                    _ => None,
                };
                if let Some(termination) = termination {
                    transition::terminalize_reservation(
                        transaction,
                        Uuid::from_bytes(after.request_id),
                        &termination,
                    )
                    .await?;
                    counts.reservations += 1;
                }
            }
        }
    }
    Ok(PriorBoundWriteReceipt::new(counts, keys))
}

/// Durably stale each prior-coordinate PENDING reset/leave request the plan
/// retired. `resolve_prior_bound_work` marks a `Pending` reset request `Stale`
/// and a `Pending` leave request `Stale` when a coordinate-advancing transition
/// supersedes the coordinate they were bound to; this consumes exactly those
/// `(Pending -> Stale)` deltas. A reset/leave delta of any OTHER shape (the
/// arm's OWN `Pending -> Consumed` reset-activation edge, or `Pending ->
/// Fulfilled` leave-fulfillment edge) is SKIPPED here and handled by the arm,
/// with `reconcile_coordinate_change_families` proving `own + staled == total`
/// per family so nothing is silently dropped.
///
/// The leave-request `stale` terminal edge binds the STALING transition's own
/// request digest (`assert_leave_request_mapping` requires
/// `terminal_request_digest == transition.request_digest`). Per ADR-019
/// Erratum 01 the terminal transition may be of ANY kind, INCLUDING
/// `leaveCommit`/`leavePolicy`: the coordinate-binding invariant governs, so a
/// coordinate-advancing leave-kind transition stales OTHER members'
/// predecessor-bound pending leave requests (the `fulfilled`-not-`stale`
/// distinction for the request the transition fulfills is enforced here in the
/// executor, not the DDL). The reset-request `stale` edge needs only the
/// transition id + instant. Returns the per-family staled counts for the
/// caller's reconciliation.
async fn write_prior_bound_staling(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    effects: &TransitionEffects,
    transition_id: Uuid,
    staling_request_digest: &[u8],
    applied_at: DateTime<Utc>,
) -> Result<FamilyCounts, ExecutorError> {
    let mut counts = FamilyCounts::default();
    for change in effects.reset_request_changes() {
        if let (Some(before), Some(after)) = (change.before(), change.after()) {
            if before.status() == ResetRequestStatus::Pending {
                let termination = match after.status() {
                    ResetRequestStatus::Stale => Some(ResetRequestTermination::Stale {
                        terminal_transition_id: transition_id,
                        terminal_at: applied_at,
                    }),
                    ResetRequestStatus::Expired => Some(ResetRequestTermination::Expired {
                        terminal_at: server_instant(after.expires_at)?,
                    }),
                    _ => None,
                };
                if let Some(termination) = termination {
                    transition::terminalize_reset_request(
                        transaction,
                        Uuid::from_bytes(after.request_id),
                        &termination,
                    )
                    .await?;
                    counts.reset_requests += 1;
                }
            }
        }
    }
    for change in effects.leave_request_changes() {
        if let (Some(before), Some(after)) = (change.before(), change.after()) {
            if before.status() == LeaveRequestStatus::Pending {
                let termination = match after.status() {
                    LeaveRequestStatus::Stale => Some(LeaveRequestTermination::Stale {
                        terminal_request_digest: staling_request_digest.to_vec(),
                        terminal_transition_id: transition_id,
                        terminal_at: applied_at,
                    }),
                    LeaveRequestStatus::Expired => Some(LeaveRequestTermination::Expired {
                        terminal_at: server_instant(after.expires_at)?,
                    }),
                    _ => None,
                };
                if let Some(termination) = termination {
                    transition::terminalize_leave_request(
                        transaction,
                        Uuid::from_bytes(after.request_id),
                        &termination,
                    )
                    .await?;
                    counts.leave_requests += 1;
                }
            }
        }
    }
    Ok(counts)
}

/// Durably record the OBSERVED expiry of every past-due `pending` leave
/// request an expire-first planner swept on the coordinate-PRESERVING request
/// path (`expire_due_leave_requests`).
///
/// This writes the identical terminal shape `write_prior_bound_staling` writes
/// for the identical `Pending -> Expired` delta, and for the identical reason:
/// status `expired`, NULL `terminal_request_digest`, NULL
/// `terminal_transition_id`, and `terminal_at` = the request's OWN `expires_at`
/// — the only combination `leave_requests_terminal_shape_check` accepts for
/// `expired`. Nothing about the observing actor is bound, so the row records
/// that consent lapsed, never that anyone withdrew or superseded it.
///
/// Any delta that is not exactly `Pending -> Expired` is skipped here; the
/// caller has already proven that the ONLY shapes present are its own opening
/// plus these expiries, and cross-checks this function's return against that
/// count, so a skipped delta can never become a silent drop.
async fn write_observed_leave_expiries(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    effects: &TransitionEffects,
) -> Result<usize, ExecutorError> {
    let mut written = 0;
    for change in effects.leave_request_changes() {
        let (Some(before), Some(after)) = (change.before(), change.after()) else {
            continue;
        };
        if before.status() != LeaveRequestStatus::Pending
            || after.status() != LeaveRequestStatus::Expired
        {
            continue;
        }
        transition::terminalize_leave_request(
            transaction,
            Uuid::from_bytes(after.request_id),
            &LeaveRequestTermination::Expired {
                terminal_at: server_instant(after.expires_at)?,
            },
        )
        .await?;
        written += 1;
    }
    Ok(written)
}

/// The per-family count of deltas a coordinate-changing arm actually
/// consumed. Used for both the applied SUPERSESSIONS (what
/// `write_prior_bound_supersessions` / `write_welcome_supersessions` wrote) and
/// the arm's OWN edges, so the reconciliation `own + superseded == total` holds
/// per family (see `reconcile_coordinate_change_families`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct FamilyCounts {
    requests: usize,
    reservations: usize,
    packages: usize,
    welcomes: usize,
    reset_requests: usize,
    leave_requests: usize,
}

/// The silent-drop guard for every coordinate-changing arm (fulfillment,
/// generic commit, leave fulfillment). `write_prior_bound_supersessions` and
/// `write_welcome_supersessions` SKIP any delta that is not their exact
/// supersession shape; an arm's own-edge handling consumes exactly its own
/// deltas. So a delta that is NEITHER the arm's own shape NOR a valid
/// supersession (e.g. an `Open->Expired` request, a wrong-direction package
/// edge, a `Pending->Expired` welcome) would be neither applied nor rejected —
/// a silent drop. This reconciliation makes that impossible: for EVERY family,
/// `own + superseded` MUST equal the plan's total delta count, else the whole
/// transaction is a hard `InconsistentPlan` (rolled back by the caller). A
/// future planner that emits a shape neither path handles surfaces here, never
/// as a lost write.
fn reconcile_coordinate_change_families(
    effects: &TransitionEffects,
    own: &FamilyCounts,
    superseded: &FamilyCounts,
) -> Result<(), ExecutorError> {
    if own.requests + superseded.requests != effects.recovery_request_changes().len() {
        return Err(ExecutorError::InconsistentPlan(
            "recovery request delta neither applied as own nor superseded (silent-drop guard)",
        ));
    }
    if own.reservations + superseded.reservations != effects.reservation_changes().len() {
        return Err(ExecutorError::InconsistentPlan(
            "reservation delta neither applied as own nor released (silent-drop guard)",
        ));
    }
    if own.packages + superseded.packages != effects.package_transitions().len() {
        return Err(ExecutorError::InconsistentPlan(
            "package edge neither applied as own nor reactivated (silent-drop guard)",
        ));
    }
    if own.welcomes + superseded.welcomes != effects.welcome_changes().len() {
        return Err(ExecutorError::InconsistentPlan(
            "welcome delta neither applied as own nor superseded (silent-drop guard)",
        ));
    }
    if own.reset_requests + superseded.reset_requests != effects.reset_request_changes().len() {
        return Err(ExecutorError::InconsistentPlan(
            "reset request delta neither applied as own nor staled (silent-drop guard)",
        ));
    }
    if own.leave_requests + superseded.leave_requests != effects.leave_request_changes().len() {
        return Err(ExecutorError::InconsistentPlan(
            "leave request delta neither applied as own nor staled (silent-drop guard)",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum WelcomeSupersessionCause {
    Transition { terminal_transition_id: Uuid },
    Revocation { terminal_revocation_id: Uuid },
}

/// Supersede each prior-coordinate pending Welcome the plan retired: append its
/// `welcomeDisposition` event and terminalize the delivery as `superseded`,
/// bound to that event and to the exact transition/revocation already held by
/// the executor authority. A coordinate-changing commit whose prior carried a
/// pending Welcome (e.g. an epoch commit after a leaf-recovery fulfillment)
/// carries these `welcome_changes` `(Pending -> Superseded)`; consuming them
/// keeps the durable delivery in sync with the state machine.
///
/// Returns the COUNT of welcomes actually superseded so the caller can
/// reconcile `own + superseded == total` (`reconcile_coordinate_change_families`)
/// — a `Pending->Expired` or other non-supersession welcome delta is skipped
/// here and must be caught by that reconciliation, never silently dropped.
async fn write_welcome_supersessions(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ctx: &ExecutionContext,
    effects: &TransitionEffects,
    cause: WelcomeSupersessionCause,
) -> Result<usize, ExecutorError> {
    write_welcome_supersessions_with_cursor(transaction, ctx, effects, cause, None).await
}

async fn write_welcome_supersessions_with_cursor(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ctx: &ExecutionContext,
    effects: &TransitionEffects,
    cause: WelcomeSupersessionCause,
    mut event_cursor: Option<&mut EventChainCursor>,
) -> Result<usize, ExecutorError> {
    let mut superseded = 0usize;
    for change in effects.welcome_changes() {
        // Only prior-bound supersessions here; a fulfillment's OWN new welcome
        // (None->Some Pending) is handled by its arm and skipped.
        let after = match (change.before(), change.after()) {
            (Some(before), Some(after))
                if before.status() == WelcomeStatus::Pending
                    && matches!(
                        after.status(),
                        WelcomeStatus::Superseded | WelcomeStatus::Expired
                    ) =>
            {
                after
            }
            _ => continue,
        };
        let welcome_id = Uuid::from_bytes(*after.welcome_id());
        let disposition = ctx
            .welcome_dispositions
            .iter()
            .find(|input| input.welcome_id == welcome_id)
            .ok_or(ExecutorError::MissingContext(
                "welcome disposition event for a superseded welcome",
            ))?;
        if after.status() == WelcomeStatus::Expired {
            // A DUE EXPIRY the transition merely OBSERVES. Every instant this
            // writes is the welcome's own `expires_at`, never `applied_at`:
            // `assert_welcome_disposition_cas` pins `event.created_at =
            // delivery.terminal_at`, and `assert_recovery_work_integrity` pins
            // `recovery_work_items.created_at = disposition.terminal_at`. This is
            // exactly the shape the dedicated `apply_welcome_expiry` arm writes.
            let terminal_at = server_instant(after.expires_at())?;
            let recovery_work_id =
                disposition
                    .recovery_work_id
                    .ok_or(ExecutorError::MissingContext(
                        "recovery work id for a prior-bound Welcome expiry",
                    ))?;
            let position = append_one_event_at_with_cursor(
                transaction,
                ctx,
                &disposition.event,
                terminal_at,
                event_cursor.as_deref_mut(),
            )
            .await?;
            delivery::terminalize_prior_bound_welcome_expiry(
                transaction,
                after,
                terminal_at,
                position,
            )
            .await?;
            // The `welcomeExpired` re-add work the recipient is owed. Without it
            // the deferred `assert_recovery_work_integrity` rejects the WHOLE
            // transition (`winner_kind='expired'` requires exactly one item), and
            // the invitee is never re-invited.
            delivery::insert_recovery_work_item(
                transaction,
                &delivery::NewRecoveryWorkItem {
                    recovery_work_id,
                    conversation_id: Uuid::from_bytes(*after.coordinate().conversation_id()),
                    recipient_did: device_did(after.recipient())?,
                    recipient_device_id: device_uuid(after.recipient()),
                    source_kind: delivery::RecoveryWorkSourceKind::WelcomeExpired,
                    source_id: welcome_id,
                    generation: checked_i64(after.coordinate().generation())?,
                    state_version: checked_i64(after.coordinate().state_version())?,
                    created_at: terminal_at,
                },
            )
            .await?;
        } else {
            if disposition.recovery_work_id.is_some() {
                // Only a due expiry creates recovery work; a supersession that
                // carried one would be rejected by the same deferred trigger
                // ('non-recovery Welcome disposition has recovery work').
                return Err(ExecutorError::InconsistentPlan(
                    "prior-bound Welcome supersession must carry no recovery work id",
                ));
            }
            let position = append_one_event_with_cursor(
                transaction,
                ctx,
                &disposition.event,
                event_cursor.as_deref_mut(),
            )
            .await?;
            let terminal_disposition = match cause {
                WelcomeSupersessionCause::Transition {
                    terminal_transition_id,
                } => WelcomeDisposition::SupersededByTransition {
                    terminal_transition_id,
                },
                WelcomeSupersessionCause::Revocation {
                    terminal_revocation_id,
                } => WelcomeDisposition::SupersededByRevocation {
                    terminal_revocation_id,
                },
            };
            delivery::terminalize_welcome_delivery_for_supersession(
                transaction,
                welcome_id,
                &terminal_disposition,
                ctx.applied_at,
                position,
            )
            .await?;
        }
        superseded += 1;
    }
    Ok(superseded)
}

/// Append one event with its audience + outbox, returning its position.
async fn append_one_event(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ctx: &ExecutionContext,
    event: &EventFanout,
) -> Result<i64, ExecutorError> {
    append_one_event_with_cursor(transaction, ctx, event, None).await
}

async fn append_one_event_with_cursor(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ctx: &ExecutionContext,
    event: &EventFanout,
    event_cursor: Option<&mut EventChainCursor>,
) -> Result<i64, ExecutorError> {
    append_one_event_at_with_cursor(transaction, ctx, event, ctx.applied_at, event_cursor).await
}

/// `append_one_event_with_cursor` with an explicit `created_at` for the event
/// row and its outbox work.
///
/// Almost every event is stamped `ctx.applied_at`. The exception is a Welcome
/// terminal disposition: `assert_welcome_disposition_cas` requires
/// `event.created_at = delivery.terminal_at`, and a due EXPIRY's terminal
/// instant is the welcome's own `expires_at`, which is strictly before
/// `applied_at` whenever the expiry is observed by a later transition. The
/// dedicated `apply_welcome_expiry` arm already appends at `terminal_at`
/// directly; this is the same rule for the shared prior-bound writer.
async fn append_one_event_at_with_cursor(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ctx: &ExecutionContext,
    event: &EventFanout,
    created_at: DateTime<Utc>,
    mut event_cursor: Option<&mut EventChainCursor>,
) -> Result<i64, ExecutorError> {
    // The symbolic schedule is a prewrite contract. Resolve and validate
    // the exact audience before allocating the durable event position.
    let recipients = match event_cursor.as_deref_mut() {
        Some(cursor) => cursor
            .begin_fanout(event)
            .map_err(ExecutorError::EventChain)?,
        None => event
            .recipients
            .iter()
            .map(|(device, kind, predecessor)| {
                Ok(EventRecipient {
                    user_did: device_did(device)?,
                    device_id: device_uuid(device),
                    entitlement_kind: *kind,
                    audience_predecessor_position: *predecessor,
                })
            })
            .collect::<Result<Vec<_>, ExecutorError>>()?,
    };
    let position = delivery::append_event(
        transaction,
        &NewEvent {
            event_id: event.event_id,
            event_kind: event.event_kind,
            payload_bytes: event.payload_bytes.clone(),
            created_at,
            protocol_instance_id: ctx.protocol_instance_id,
        },
    )
    .await?;
    delivery::insert_event_recipients(transaction, position, &recipients).await?;
    for (outbox_id, work_kind) in &event.outbox {
        delivery::enqueue_outbox(transaction, *outbox_id, position, *work_kind, created_at).await?;
    }
    if let Some(cursor) = event_cursor {
        cursor
            .complete_event(event.event_id, position)
            .map_err(ExecutorError::EventChain)?;
    }
    Ok(position)
}

async fn write_events(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ctx: &ExecutionContext,
    historical_write_authority: Option<&HistoricalExecutionWriteAuthority>,
) -> Result<Vec<i64>, ExecutorError> {
    write_events_with_cursor(transaction, ctx, None, historical_write_authority).await
}

async fn write_events_with_cursor(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ctx: &ExecutionContext,
    mut event_cursor: Option<&mut EventChainCursor>,
    historical_write_authority: Option<&HistoricalExecutionWriteAuthority>,
) -> Result<Vec<i64>, ExecutorError> {
    if let Some(historical) = historical_write_authority {
        let entry = ctx.entry();
        if !historical.matches_context(
            entry.entry_id,
            entry.entry_kind.as_str(),
            &entry.accepted_payload_sha256,
            &entry.outer_entry_fingerprint,
        ) {
            return Err(ExecutorError::MissingContext(
                "historical write authority entry context mismatch",
            ));
        }
        return Ok(Vec::new());
    }

    let mut positions = Vec::with_capacity(ctx.events.len());
    for event in &ctx.events {
        let position =
            append_one_event_with_cursor(transaction, ctx, event, event_cursor.as_deref_mut())
                .await?;
        positions.push(position);
    }
    Ok(positions)
}

#[cfg(test)]
mod authority_shape_tests {
    use super::*;

    fn cursor_device(seed: u8) -> DeviceIdentity {
        let mut device_id = [seed; 16];
        device_id[6] = (device_id[6] & 0x0f) | 0x40;
        device_id[8] = (device_id[8] & 0x3f) | 0x80;
        DeviceIdentity::new(
            PrincipalId::new(format!("did:plc:cursorproof{seed:02}xxxxxxxx").into_bytes())
                .expect("valid cursor DID"),
            device_id,
        )
        .expect("valid cursor device")
    }

    fn prepared_cursor_event(event_id: Uuid, slot: u32, payload: &[u8]) -> PreparedRevocationEvent {
        PreparedRevocationEvent::new(
            event_id,
            EventKind::ConversationChanged,
            payload.to_vec(),
            vec![PreparedRevocationRecipient {
                slot: EventChainSlot(slot),
                entitlement: EventEntitlementKind::Participant,
            }],
            vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        )
        .expect("valid prepared cursor event")
    }

    #[test]
    fn revocation_event_cursor_rejects_shape_and_state_mutations() {
        let first_id = Uuid::new_v4();
        let second_id = Uuid::new_v4();
        let first = prepared_cursor_event(first_id, 0, b"first");
        let second = prepared_cursor_event(second_id, 0, b"second");
        let devices = vec![cursor_device(1)];

        let mut cursor = EventChainCursor::new(
            [7; 32],
            devices.clone(),
            vec![Some(41)],
            vec![first.clone(), second.clone()],
        )
        .expect("valid cursor");
        let recipients = cursor.begin_event(&first).expect("first event begins");
        assert_eq!(recipients.len(), 1);
        assert_eq!(recipients[0].audience_predecessor_position, Some(41));
        assert!(matches!(
            cursor.begin_event(&first),
            Err(EventChainCursorError::EventAlreadyPending)
        ));
        assert!(matches!(
            cursor.complete_event(first_id, 41),
            Err(EventChainCursorError::PositionNotMonotonic)
        ));
        cursor
            .complete_event(first_id, 42)
            .expect("first event completes");
        assert!(matches!(
            cursor.finish_for_test(),
            Err(EventChainCursorError::IncompleteSchedule)
        ));
        let recipients = cursor.begin_event(&second).expect("second event begins");
        assert_eq!(
            recipients[0].audience_predecessor_position,
            Some(42),
            "the first prepared event must advance the shared device tail"
        );
        cursor
            .complete_event(second_id, 43)
            .expect("second event completes");
        cursor.finish().expect("complete schedule finishes");

        let mut reordered = EventChainCursor::new(
            [7; 32],
            devices.clone(),
            vec![Some(41)],
            vec![first.clone(), second.clone()],
        )
        .expect("valid cursor");
        assert!(matches!(
            reordered.begin_event(&second),
            Err(EventChainCursorError::UnexpectedEvent)
        ));

        let changed = prepared_cursor_event(first_id, 0, b"changed");
        let mut changed_cursor = EventChainCursor::new(
            [7; 32],
            devices.clone(),
            vec![Some(41)],
            vec![first.clone()],
        )
        .expect("valid cursor");
        assert!(matches!(
            changed_cursor.begin_event(&changed),
            Err(EventChainCursorError::EventShapeMismatch)
        ));

        let unknown = prepared_cursor_event(first_id, 1, b"first");
        assert!(matches!(
            EventChainCursor::new([7; 32], devices, vec![Some(41)], vec![unknown]),
            Err(EventChainCursorError::UnknownSlot)
        ));

        let duplicate = PreparedRevocationEvent::new(
            first_id,
            EventKind::ConversationChanged,
            b"first".to_vec(),
            vec![
                PreparedRevocationRecipient {
                    slot: EventChainSlot(0),
                    entitlement: EventEntitlementKind::Participant,
                },
                PreparedRevocationRecipient {
                    slot: EventChainSlot(0),
                    entitlement: EventEntitlementKind::Participant,
                },
            ],
            vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        );
        assert!(matches!(
            duplicate,
            Err(EventChainCursorError::DuplicateRecipient)
        ));

        let mut no_pending =
            EventChainCursor::new([7; 32], vec![cursor_device(1)], vec![None], vec![])
                .expect("empty schedule cursor");
        assert!(matches!(
            no_pending.complete_event(first_id, 1),
            Err(EventChainCursorError::NoPendingEvent)
        ));
    }

    #[test]
    fn revocation_event_cursor_preserves_exact_historical_welcome_recipient() {
        let current_participant = cursor_device(1);
        // This slot models an inactive/historical target device retained
        // solely because a pending Welcome names it exactly.
        let historical_welcome_recipient = cursor_device(2);
        let event_id = Uuid::new_v4();
        let outbox = vec![(Uuid::new_v4(), OutboxWorkKind::Stream)];
        let prepared = PreparedRevocationEvent::new(
            event_id,
            EventKind::WelcomeDisposition,
            b"exact historical Welcome".to_vec(),
            vec![PreparedRevocationRecipient {
                slot: EventChainSlot(1),
                entitlement: EventEntitlementKind::Welcome,
            }],
            outbox.clone(),
        )
        .expect("exact historical Welcome schedule");
        let live = EventFanout {
            event_id,
            event_kind: EventKind::WelcomeDisposition,
            payload_bytes: b"exact historical Welcome".to_vec(),
            recipients: vec![(
                historical_welcome_recipient.clone(),
                EventEntitlementKind::Welcome,
                Some(999), // Ignored: the locked prelude owns the true tail.
            )],
            outbox,
        };
        let mut cursor = EventChainCursor::new(
            [9; 32],
            vec![current_participant, historical_welcome_recipient.clone()],
            vec![Some(40), Some(73)],
            vec![prepared],
        )
        .expect("cursor retains historical Welcome recipient slot");
        let recipients = cursor
            .begin_fanout(&live)
            .expect("exact historical Welcome event matches");
        assert_eq!(recipients.len(), 1);
        assert_eq!(
            recipients[0].device_id,
            Uuid::from_bytes(*historical_welcome_recipient.device_id())
        );
        assert_eq!(
            recipients[0].entitlement_kind,
            EventEntitlementKind::Welcome
        );
        assert_eq!(recipients[0].audience_predecessor_position, Some(73));
        cursor.complete_event(event_id, 74).expect("event advances");
        cursor.finish().expect("exact Welcome schedule consumed");
    }

    #[test]
    fn transaction_identity_failure_requires_outer_abort() {
        assert!(ExecutorError::TransactionIdentity(sqlx::Error::RowNotFound).requires_outer_abort());
        assert!(!ExecutorError::TransactionBindingMismatch.requires_outer_abort());
    }

    #[test]
    fn welcome_expiry_authority_is_entryless_and_retains_exact_welcome_id() {
        let welcome_id =
            Uuid::parse_str("6d5b4f71-5ff3-4ac2-89a9-8bcfd1675e61").expect("fixed Welcome UUID");
        let authority = ExecutionAuthority::Entryless {
            operation_id: welcome_id,
        };

        let operation_id = require_execution_authority(PlanKind::WelcomeExpiry, &authority)
            .expect("Welcome expiry accepts exact entryless authority");

        assert_eq!(operation_id, welcome_id);
        assert!(
            authority.control_entry().is_none(),
            "server-authored expiry must carry no control content"
        );
    }

    #[test]
    fn entry_bearing_plan_rejects_entryless_authority() {
        let authority = ExecutionAuthority::Entryless {
            operation_id: Uuid::parse_str("78b7734f-7423-46a5-85f8-ac86a2527ee0")
                .expect("fixed operation UUID"),
        };

        assert!(matches!(
            require_execution_authority(PlanKind::Policy, &authority),
            Err(ExecutorError::MissingContext("control-entry authority"))
        ));
    }

    #[test]
    fn entryless_plan_rejects_control_entry_authority() {
        let authority = ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id: Uuid::parse_str("3afcbca2-89c9-4454-ae41-2450dac4f845")
                .expect("fixed entry UUID"),
            entry_kind: "blue.catbird.chat.defs#policyEntry".to_owned(),
            accepted_payload_bytes: vec![1],
            accepted_payload_sha256: vec![2; 32],
            signed_request_bytes: vec![3],
            unsigned_projection_bytes: vec![4],
            signing_transcript_bytes: vec![5],
            request_digest: vec![6; 32],
            signature: vec![7; 64],
            server_fields_bytes: vec![8],
            outer_entry_fingerprint: vec![9; 32],
        });

        assert!(matches!(
            require_execution_authority(PlanKind::DeviceRevocation, &authority),
            Err(ExecutorError::MissingContext(
                "entryless operation authority"
            ))
        ));
    }
}

#[cfg(any(
    test,
    all(
        feature = "chat-protocol-production-proof",
        not(feature = "server-bin")
    )
))]
mod metadata_executor_tests {
    use super::super::{
        AuthenticatedEntryEvidence, ConversationPersistencePlan, ConversationStateHydration,
        LeaveRequest, LeaveRequestHydrationRow, MetadataAvatarDescriptorBinding,
        MetadataCryptoCoordinate, MetadataSnapshotBinding, PackageTransition, PlanAuthority,
        PublicGroupSnapshotLifecycle, RecoveryOriginHydrationRow, RecoveryPackageCasBinding,
        RecoveryRequestHydrationRow, RecoveryReservationHydrationRow, RequestEntryKind,
        RequestEvidence, ResetRequestHydrationRow, StateChange, StateCounts, TransitionBodyBinding,
        TransitionEffects, WelcomeHydrationRow, WorkTerminalHydrationRow,
    };
    use super::*;

    fn uuid(marker: u8) -> [u8; 16] {
        let mut value = [marker; 16];
        value[6] = 0x40 | (marker & 0x0f);
        value[8] = 0x80 | (marker & 0x3f);
        value
    }

    fn device(marker: u8) -> DeviceIdentity {
        DeviceIdentity::new(
            PrincipalId::new(format!("did:plc:metadataexecutor{marker:02x}aaaaaa").into_bytes())
                .expect("valid test DID"),
            uuid(marker),
        )
        .expect("valid test device")
    }

    fn coordinate(conversation_id: [u8; 16], state_version: u64) -> PublicGroupSnapshotCoordinate {
        PublicGroupSnapshotCoordinate::new(
            conversation_id,
            1,
            state_version,
            [0x31; 32],
            4,
            [0x32; 32],
            [0x33; 32],
            PublicGroupSnapshotLifecycle::Active,
        )
    }

    fn snapshot(
        coordinate: PublicGroupSnapshotCoordinate,
        transition_id: [u8; 16],
        seq: u64,
        actor: DeviceIdentity,
        key_id: [u8; 32],
        public_key: [u8; 32],
        version: u64,
        nonce: [u8; 12],
        avatar_binding: Option<MetadataAvatarDescriptorBinding>,
    ) -> MetadataSnapshotBinding {
        let ciphertext = vec![version as u8, 0x51, 0x52];
        let ciphertext_sha256 = sha2::Sha256::digest(&ciphertext).into();
        let canonical_snapshot = ciphertext.clone();
        MetadataSnapshotBinding {
            coordinate: MetadataCryptoCoordinate {
                conversation_id: *coordinate.conversation_id(),
                generation: coordinate.generation(),
                group_id: *coordinate.group_id(),
                epoch: coordinate.epoch(),
                group_context_hash: *coordinate.group_context_hash(),
                confirmation_tag: *coordinate.confirmation_tag(),
            },
            origin_transition_id: transition_id,
            metadata_version: version,
            nonce,
            ciphertext,
            ciphertext_sha256,
            avatar_binding,
            author_proof: super::super::MetadataAuthorProofBinding {
                author: actor,
                author_key_id: key_id,
                signature_public_key: public_key,
                auth_generation_at_origin: 3,
                origin_transition_id: transition_id,
                origin_seq: seq,
            },
            digest: sha2::Sha256::digest(&canonical_snapshot).into(),
            canonical_snapshot,
        }
    }

    #[derive(Clone, Copy)]
    enum AvatarFixture {
        None,
        Fresh,
        Reuse,
    }

    #[derive(Clone, Copy)]
    enum DueExpiryFamily {
        Recovery,
        Reset,
        Leave,
        Welcome,
    }

    fn request_evidence(
        kind: RequestEntryKind,
        request_id: [u8; 16],
        actor: DeviceIdentity,
        conversation_id: [u8; 16],
        received_at: ServerTimestamp,
        key_id: [u8; 32],
    ) -> RequestEvidence {
        RequestEvidence {
            kind,
            control_entry_id: Some(uuid(0x70)),
            conversation_id,
            control_seq: Some(4),
            control_outer_entry_fingerprint: Some([0x71; 32]),
            control_outer_projection: Some(vec![0x72]),
            control_server_fields_dag_cbor: Some(vec![0x73]),
            request_id,
            actor,
            key_id,
            auth_generation: 3,
            request_digest: [0x74; 32],
            signature: [0x75; 64],
            signed_request_bytes: vec![0x76],
            durable_row_digest: [0x77; 32],
            received_at,
            authority: None,
            body_binding: None,
        }
    }

    fn avatar_descriptor() -> MetadataAvatarDescriptorBinding {
        let canonical_descriptor = vec![0xa4, 0x01, 0x02, 0x03];
        MetadataAvatarDescriptorBinding {
            blob_id: uuid(0x45),
            ciphertext_sha256: [0x46; 32],
            ciphertext_size: 64,
            digest: sha2::Sha256::digest(&canonical_descriptor).into(),
            canonical_descriptor,
        }
    }

    fn exact_fixture() -> (ConversationPersistencePlan, ExecutionContext) {
        exact_fixture_with_avatar(AvatarFixture::None)
    }

    fn exact_fixture_with_avatar(
        avatar_fixture: AvatarFixture,
    ) -> (ConversationPersistencePlan, ExecutionContext) {
        let conversation_id = uuid(0x21);
        let prior = coordinate(conversation_id, 7);
        let next = coordinate(conversation_id, 8);
        let actor = device(0x22);
        let prior_transition_id = uuid(0x23);
        let transition_id = uuid(0x24);
        let key_id = [0x25; 32];
        let public_key = [0x26; 32];
        let avatar = (!matches!(avatar_fixture, AvatarFixture::None)).then(avatar_descriptor);
        let prior_metadata = snapshot(
            prior,
            prior_transition_id,
            5,
            actor.clone(),
            key_id,
            public_key,
            1,
            [0x27; 12],
            matches!(avatar_fixture, AvatarFixture::Reuse)
                .then(|| avatar.clone().expect("reuse avatar")),
        );
        let next_metadata = snapshot(
            next,
            transition_id,
            6,
            actor.clone(),
            key_id,
            public_key,
            2,
            [0x28; 12],
            avatar.clone(),
        );
        let received_at = ServerTimestamp::from_unix_millis(6_000).unwrap();
        let mut producer = super::super::TransitionEvidence::for_test_at(
            6,
            transition_id,
            [0x29; 32],
            received_at,
        )
        .unwrap();
        producer.authority = Some(AuthenticatedEntryEvidence {
            kind: SignedMutationKind::MetadataTransition,
            type_id: SignedMutationKind::MetadataTransition.type_id(),
            domain: SignedMutationKind::MetadataTransition.domain().to_vec(),
            control_entry_id: Some(transition_id),
            control_conversation_id: Some(conversation_id),
            actor: actor.clone(),
            key_id,
            auth_generation: 3,
            signed_at: received_at,
            request_digest: [0x2a; 32],
            signature: [0x2b; 64],
            signed_request_bytes: vec![0x2c],
            canonical_projection: vec![0x2d],
            transcript_bytes: vec![0x2e],
        });
        producer.body_binding = Some(TransitionBodyBinding::Metadata {
            prior,
            next,
            metadata: next_metadata.clone(),
        });
        producer.outer_control_projection = vec![0x2f];
        producer.server_fields_dag_cbor = vec![0x30];

        let mut effects = TransitionEffects::new(PlanKind::Metadata);
        effects.complete = true;
        effects.before_counts = StateCounts::default();
        effects.after_counts = StateCounts::default();
        effects.metadata_change = Some(StateChange {
            before: Some(prior_metadata),
            after: Some(next_metadata.clone()),
        });
        effects.authority = Some(PlanAuthority::Transition(producer.clone()));
        effects.head_cas = Some(super::super::ConversationHeadCasBinding {
            transaction_id: "metadata-executor-test-tx".to_owned(),
            conversation_id,
            expected_prior: Some(prior),
            expected_next_entry_seq: 6,
            allocated_entry_id: Some(transition_id),
            allocated_seq: Some(6),
            successor_next_entry_seq: 7,
            locked_at: received_at,
            locked_head_digest: [0x34; 32],
        });
        let plan = ConversationPersistencePlan {
            expected_prior: Some(prior),
            retired_coordinate: None,
            successor_coordinate: Some(next),
            state: ConversationStateHydration {
                kind: ConversationKind::Group,
                coordinate: next,
                producer: producer.clone(),
                public_state: None,
                metadata: Some(next_metadata),
                metadata_producer: Some(producer),
                participants: Vec::new(),
                leaves: Vec::new(),
                intervals: Vec::new(),
                terminal_proofs: Vec::new(),
                recovery_requests: Vec::new(),
                recovery_reservations: Vec::new(),
                reset_requests: Vec::new(),
                leave_requests: Vec::new(),
                welcomes: Vec::new(),
            },
            effects,
        };
        let key_id_text = URL_SAFE_NO_PAD.encode(key_id);
        let actor_did = String::from_utf8(actor.principal().as_bytes().to_vec()).unwrap();
        let applied_at = DateTime::<Utc>::from_timestamp_millis(received_at.unix_millis()).unwrap();
        let metadata_avatar = avatar.as_ref().map(|signed_avatar| {
            let snapshot = MetadataAvatarBinding {
                avatar_blob_id: Uuid::from_bytes(*signed_avatar.blob_id()),
                avatar_ciphertext_sha256: signed_avatar.ciphertext_sha256().to_vec(),
                avatar_ciphertext_size: i64::try_from(signed_avatar.ciphertext_size())
                    .expect("fixture avatar size"),
                avatar_binding_origin_transition_id: Uuid::from_bytes(
                    if matches!(avatar_fixture, AvatarFixture::Reuse) {
                        prior_transition_id
                    } else {
                        transition_id
                    },
                ),
                avatar_binding_metadata_version: if matches!(avatar_fixture, AvatarFixture::Reuse) {
                    1
                } else {
                    2
                },
                avatar_binding_owner_did: actor_did.clone(),
                avatar_binding_owner_device_id: Uuid::from_bytes(*actor.device_id()),
            };
            if matches!(avatar_fixture, AvatarFixture::Reuse) {
                MetadataAvatarPersistence::Reuse { snapshot }
            } else {
                let plaintext_size = 48;
                let aad_bytes = canonical_metadata_avatar_blob_aad(
                    conversation_id,
                    transition_id,
                    2,
                    *signed_avatar.blob_id(),
                    "image/png",
                    plaintext_size,
                );
                MetadataAvatarPersistence::Fresh {
                    snapshot,
                    binding: NewBlobBinding {
                        blob_id: Uuid::from_bytes(*signed_avatar.blob_id()),
                        binding_kind: BindingKind::MetadataAvatar,
                        conversation_id: Uuid::from_bytes(conversation_id),
                        entry_seq: None,
                        message_id: None,
                        metadata_origin_transition_id: Some(Uuid::from_bytes(transition_id)),
                        metadata_version: Some(2),
                        owner_did: actor_did.clone(),
                        owner_device_id: Uuid::from_bytes(*actor.device_id()),
                        descriptor_bytes: signed_avatar.canonical_descriptor().to_vec(),
                        descriptor_sha256: signed_avatar.digest().to_vec(),
                        aad_sha256: sha2::Sha256::digest(&aad_bytes).to_vec(),
                        aad_bytes,
                        ciphertext_sha256: signed_avatar.ciphertext_sha256().to_vec(),
                        plaintext_size: i64::try_from(plaintext_size)
                            .expect("fixture plaintext size"),
                        ciphertext_size: i64::try_from(signed_avatar.ciphertext_size())
                            .expect("fixture ciphertext size"),
                        purpose: BlobPurpose::Metadata,
                        bound_at: applied_at,
                        uploaded_at: DateTime::<Utc>::from_timestamp_millis(5_000).unwrap(),
                        unbound_expires_at: DateTime::<Utc>::from_timestamp_millis(7_000).unwrap(),
                    },
                }
            }
        });
        let context = ExecutionContext {
                protocol_instance_id: Uuid::from_bytes(uuid(0x35)),
                applied_at,
                actor: ExecutionActor {
                    user_did: actor_did,
                    device_id: Uuid::from_bytes(*actor.device_id()),
                    key_id: key_id_text.clone(),
                    auth_generation: 3,
                    role: TransitionActorRole::Admin,
                    device_status: "active".to_owned(),
                },
                authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
                    entry_id: Uuid::from_bytes(transition_id),
                    entry_kind: "blue.catbird.chat.defs#transitionEntry".to_owned(),
                    accepted_payload_bytes: vec![0x36],
                    accepted_payload_sha256: vec![0x37; 32],
                    signed_request_bytes: vec![0x2c],
                    unsigned_projection_bytes: vec![0x2d],
                    signing_transcript_bytes: vec![0x2e],
                    request_digest: vec![0x2a; 32],
                    signature: vec![0x2b; 64],
                    server_fields_bytes: vec![0x30],
                    outer_entry_fingerprint: vec![0x29; 32],
                }),
                spine: SpineArtifacts {
                    public_snapshot_bytes: vec![0x38],
                    public_snapshot_sha256: sha2::Sha256::digest([0x38]).to_vec(),
                    tree_summary_bytes: vec![0x39],
                    tree_summary_sha256: sha2::Sha256::digest([0x39]).to_vec(),
                    leaf_count: 0,
                    genesis_group_info_bytes: Vec::new(),
                    genesis_group_info_sha256: Vec::new(),
                },
                opened_leaves: Vec::new(),
                metadata_author: Some(MetadataAuthorColumns {
                    author_role: "admin".to_owned(),
                    author_device_status: "active".to_owned(),
                    author_public_key: public_key.to_vec(),
                    author_key_id: key_id_text,
                    metadata_snapshot_id: Uuid::from_bytes(uuid(0x3a)),
                }),
                metadata_avatar,
                participant_period_ids: Vec::new(),
                leaf_period_ids: Vec::new(),
                is_remote: false,
                sequencer_ds: None,
                sequencer_term: 0,
                participant_ds_dids: std::collections::HashMap::new(),
                entry_recipients: Vec::new(),
                events: vec![EventFanout {
                    event_id: Uuid::from_bytes(uuid(0x3b)),
                    event_kind: EventKind::ConversationChanged,
                    payload_bytes: format!(
                        r#"{{"$type":"blue.catbird.chat.defs#conversationChangedEvent","conversationId":"{}"}}"#,
                        Uuid::from_bytes(conversation_id).hyphenated(),
                    )
                    .into_bytes(),
                    recipients: Vec::new(),
                    outbox: vec![(Uuid::from_bytes(uuid(0x3c)), OutboxWorkKind::Stream)],
                }],
                closing_leaf_periods: Vec::new(),
                closing_participant_periods: Vec::new(),
                reset_request_row: None,
                recovery_open: None,
                welcome_expiry: None,
                welcome_response: None,
                welcome_dispositions: Vec::new(),
            };
        (plan, context)
    }

    fn mutate_all_inner_metadata_coordinates(
        plan: &mut ConversationPersistencePlan,
        group_id: Option<[u8; 32]>,
        confirmation_tag: Option<[u8; 32]>,
    ) -> usize {
        fn mutate(
            metadata: &mut MetadataSnapshotBinding,
            group_id: Option<[u8; 32]>,
            confirmation_tag: Option<[u8; 32]>,
        ) {
            if let Some(group_id) = group_id {
                metadata.coordinate.group_id = group_id;
            }
            if let Some(confirmation_tag) = confirmation_tag {
                metadata.coordinate.confirmation_tag = confirmation_tag;
            }
        }

        let mut copies = 0;
        mutate(
            plan.effects
                .metadata_change
                .as_mut()
                .and_then(|change| change.after.as_mut())
                .expect("metadata delta after binding"),
            group_id,
            confirmation_tag,
        );
        copies += 1;
        let PlanAuthority::Transition(evidence) = plan
            .effects
            .authority
            .as_mut()
            .expect("metadata plan authority")
        else {
            panic!("metadata plan authority is a transition");
        };
        let Some(TransitionBodyBinding::Metadata { metadata, .. }) = evidence.body_binding.as_mut()
        else {
            panic!("metadata plan authority has a metadata body");
        };
        mutate(metadata, group_id, confirmation_tag);
        copies += 1;
        mutate(
            plan.state
                .metadata
                .as_mut()
                .expect("hydrated metadata binding"),
            group_id,
            confirmation_tag,
        );
        copies += 1;
        for evidence in [
            &mut plan.state.producer,
            plan.state
                .metadata_producer
                .as_mut()
                .expect("metadata producer"),
        ] {
            let Some(TransitionBodyBinding::Metadata { metadata, .. }) =
                evidence.body_binding.as_mut()
            else {
                panic!("metadata producer has a metadata body");
            };
            mutate(metadata, group_id, confirmation_tag);
            copies += 1;
        }
        copies
    }

    fn exact_due_expiry_fixture(
        family: DueExpiryFamily,
    ) -> (ConversationPersistencePlan, ExecutionContext, FamilyCounts) {
        let (mut plan, mut context) = exact_fixture();
        let prior = plan.expected_prior.expect("metadata prior");
        let actor = plan
            .effects
            .authority
            .as_ref()
            .and_then(|authority| match authority {
                PlanAuthority::Transition(transition) => transition.authority.as_ref(),
                _ => None,
            })
            .expect("metadata actor authority")
            .actor
            .clone();
        let received_at = ServerTimestamp::from_unix_millis(4_000).unwrap();
        let expires_at = ServerTimestamp::from_unix_millis(5_000).unwrap();
        // Production relation, not the boundary. MIN_KEY_PACKAGE_REMAINING_SECONDS
        // (600) strictly exceeds RECOVERY_RESERVATION_TTL_MILLIS (300_000) and the
        // floor is re-enforced at CLAIM time against claimed_at
        // (repository/core.rs:2994, :3397), so a claimed package always outlives its
        // reservation. A fixture with package_not_after == expires_at sits exactly on
        // `terminal_time >= after.package_not_after` (:9984) and makes the planner
        // emit Reserved -> Expired — a shape production cannot produce.
        let package_not_after = ServerTimestamp::from_unix_millis(305_000).unwrap();
        let terminal = Some(WorkTerminalEvidence::Expiry(expires_at));
        let mut expected = FamilyCounts {
            requests: 0,
            reservations: 0,
            packages: 0,
            welcomes: 0,
            reset_requests: 0,
            leave_requests: 0,
        };

        match family {
            DueExpiryFamily::Recovery => {
                let request_id = uuid(0x60);
                let key_package_ref = [0x61; 32];
                let origin_key_id = [0x62; 32];
                let origin = request_evidence(
                    RequestEntryKind::LeafRecoveryRequest,
                    request_id,
                    actor.clone(),
                    *prior.conversation_id(),
                    received_at,
                    origin_key_id,
                );
                let before_request = RecoveryRequest {
                    request_id,
                    target: actor.clone(),
                    kind: LeafRecoveryKind::Add,
                    source: RecoverySource::Request,
                    bound_coordinate: prior,
                    key_package_ref,
                    received_at,
                    expires_at,
                    status: RecoveryRequestStatus::Open,
                    origin: RecoveryOriginEvidence::Request(origin.clone()),
                    terminal: None,
                };
                let mut after_request = before_request.clone();
                after_request.status = RecoveryRequestStatus::Expired;
                after_request.terminal = terminal.clone();
                let before_reservation = RecoveryReservation {
                    request_id,
                    target: actor.clone(),
                    bound_coordinate: prior,
                    key_package_ref,
                    received_at,
                    expires_at,
                    package_not_after,
                    status: ReservationStatus::Active,
                    terminal: None,
                };
                let mut after_reservation = before_reservation.clone();
                after_reservation.status = ReservationStatus::Expired;
                after_reservation.terminal = terminal;
                plan.effects.recovery_request_changes.push(StateChange {
                    before: Some(before_request),
                    after: Some(after_request.clone()),
                });
                plan.effects.reservation_changes.push(StateChange {
                    before: Some(before_reservation),
                    after: Some(after_reservation.clone()),
                });
                plan.effects.package_transitions.push(PackageTransition {
                    request_id,
                    key_package_ref,
                    from: PackageStatus::Reserved,
                    // Production shape: terminal_time (expires_at) is strictly
                    // before package_not_after, so the real selector at :9984
                    // yields Available. Tests that need the unproducible
                    // Reserved -> Expired mutate this deliberately.
                    to: PackageStatus::Available,
                });
                let mut package_cas = RecoveryPackageCasBinding {
                    transaction_id: plan
                        .effects
                        .head_cas
                        .as_ref()
                        .expect("metadata head")
                        .transaction_id
                        .clone(),
                    conversation_id: *prior.conversation_id(),
                    request_id,
                    target: actor,
                    target_key_id: origin_key_id,
                    target_auth_generation: 3,
                    bound_coordinate: prior,
                    key_package_ref,
                    key_package_wrapper_sha256: [0x63; 32],
                    package_not_after,
                    claimed_at: received_at,
                    expected_status: PackageStatus::Reserved,
                    successor_status: PackageStatus::Available,
                    locked_row_digest: [0x64; 32],
                    authority_digest: [0; 32],
                };
                package_cas.authority_digest = recovery_package_cas_authority_digest(&package_cas);
                plan.effects.recovery_package_cas.push(package_cas);
                plan.state
                    .recovery_requests
                    .push(RecoveryRequestHydrationRow {
                        request_id: after_request.request_id,
                        target: after_request.target,
                        kind: after_request.kind,
                        source: after_request.source,
                        bound_coordinate: after_request.bound_coordinate,
                        key_package_ref: after_request.key_package_ref,
                        received_at: after_request.received_at,
                        expires_at: after_request.expires_at,
                        status: after_request.status,
                        origin: RecoveryOriginHydrationRow::Request(origin),
                        terminal: Some(WorkTerminalHydrationRow::Expiry(expires_at)),
                    });
                plan.state
                    .recovery_reservations
                    .push(RecoveryReservationHydrationRow {
                        request_id: after_reservation.request_id,
                        target: after_reservation.target,
                        bound_coordinate: after_reservation.bound_coordinate,
                        key_package_ref: after_reservation.key_package_ref,
                        received_at: after_reservation.received_at,
                        expires_at: after_reservation.expires_at,
                        package_not_after: after_reservation.package_not_after,
                        status: after_reservation.status,
                        terminal: Some(WorkTerminalHydrationRow::Expiry(expires_at)),
                    });
                expected.requests = 1;
                expected.reservations = 1;
                expected.packages = 1;
            }
            DueExpiryFamily::Reset => {
                let request_id = uuid(0x65);
                let origin = request_evidence(
                    RequestEntryKind::ResetRequest,
                    request_id,
                    actor.clone(),
                    *prior.conversation_id(),
                    received_at,
                    [0x66; 32],
                );
                let before = ResetRequest {
                    request_id,
                    requester: actor,
                    bound_coordinate: prior,
                    received_at,
                    expires_at,
                    status: ResetRequestStatus::Pending,
                    origin: origin.clone(),
                    terminal: None,
                };
                let mut after = before.clone();
                after.status = ResetRequestStatus::Expired;
                after.terminal = terminal;
                plan.effects.reset_request_changes.push(StateChange {
                    before: Some(before),
                    after: Some(after.clone()),
                });
                plan.state.reset_requests.push(ResetRequestHydrationRow {
                    request_id: after.request_id,
                    requester: after.requester,
                    bound_coordinate: after.bound_coordinate,
                    received_at: after.received_at,
                    expires_at: after.expires_at,
                    status: after.status,
                    origin,
                    terminal: Some(WorkTerminalHydrationRow::Expiry(expires_at)),
                });
                expected.reset_requests = 1;
            }
            DueExpiryFamily::Leave => {
                let request_id = uuid(0x67);
                let origin = request_evidence(
                    RequestEntryKind::LeaveRequest,
                    request_id,
                    actor.clone(),
                    *prior.conversation_id(),
                    received_at,
                    [0x68; 32],
                );
                let before = LeaveRequest {
                    request_id,
                    requester: actor,
                    bound_coordinate: prior,
                    received_at,
                    expires_at,
                    status: LeaveRequestStatus::Pending,
                    origin: origin.clone(),
                    terminal: None,
                    fulfilled_participant: None,
                };
                let mut after = before.clone();
                after.status = LeaveRequestStatus::Expired;
                after.terminal = terminal;
                plan.effects.leave_request_changes.push(StateChange {
                    before: Some(before),
                    after: Some(after.clone()),
                });
                plan.state.leave_requests.push(LeaveRequestHydrationRow {
                    request_id: after.request_id,
                    requester: after.requester,
                    bound_coordinate: after.bound_coordinate,
                    received_at: after.received_at,
                    expires_at: after.expires_at,
                    status: after.status,
                    origin,
                    terminal: Some(WorkTerminalHydrationRow::Expiry(expires_at)),
                    fulfilled_participant: None,
                });
                expected.leave_requests = 1;
            }
            DueExpiryFamily::Welcome => {
                let welcome_id = uuid(0x69);
                let key_package_ref = [0x6a; 32];
                let opaque_welcome = vec![0x6b, 0x6c];
                let before = WelcomeWork {
                    welcome_id,
                    recipient: actor.clone(),
                    transition_seq: 5,
                    coordinate: prior,
                    recovery_request_id: uuid(0x6d),
                    key_package_ref,
                    sha256: sha2::Sha256::digest(&opaque_welcome).into(),
                    opaque_welcome,
                    expires_at,
                    status: WelcomeStatus::Pending,
                    terminal: None,
                };
                let mut after = before.clone();
                after.status = WelcomeStatus::Expired;
                after.terminal = terminal;
                plan.effects.welcome_changes.push(StateChange {
                    before: Some(before),
                    after: Some(after.clone()),
                });
                plan.state.welcomes.push(WelcomeHydrationRow {
                    welcome_id: after.welcome_id,
                    recipient: after.recipient.clone(),
                    transition_seq: after.transition_seq,
                    coordinate: after.coordinate,
                    recovery_request_id: after.recovery_request_id,
                    key_package_ref: after.key_package_ref,
                    opaque_welcome: after.opaque_welcome,
                    sha256: after.sha256,
                    expires_at: after.expires_at,
                    status: after.status,
                    terminal: Some(WorkTerminalHydrationRow::Expiry(expires_at)),
                });
                let event_id = Uuid::from_bytes(uuid(0x6e));
                let outbox_id = Uuid::from_bytes(uuid(0x6f));
                context.welcome_dispositions.push(WelcomeDispositionInput {
                    welcome_id: Uuid::from_bytes(welcome_id),
                    // A `Pending->Expired` delta: the recovery work id is part of
                    // its exact shape.
                    recovery_work_id: Some(Uuid::from_bytes(uuid(0x70))),
                    event: EventFanout {
                        event_id,
                        event_kind: EventKind::WelcomeDisposition,
                        payload_bytes: delivery::canonical_welcome_disposition_event_payload(
                            Uuid::from_bytes(welcome_id),
                            "expired",
                        ),
                        recipients: vec![(actor, EventEntitlementKind::Welcome, None)],
                        outbox: vec![(outbox_id, OutboxWorkKind::Stream)],
                    },
                });
                expected.welcomes = 1;
            }
        }

        (plan, context, expected)
    }

    #[test]
    fn metadata_preflight_accepts_the_exact_sealed_transition_and_author() {
        let (plan, context) = exact_fixture();

        let binding =
            preflight_metadata_transition(&plan, &context, Uuid::from_bytes(uuid(0x24)), 6)
                .expect("exact metadata transition must be executable");

        assert_eq!(binding.metadata.metadata_version(), 2);
        assert_eq!(
            binding.author.metadata_snapshot_id,
            Uuid::from_bytes(uuid(0x3a))
        );
    }

    #[test]
    fn metadata_preflight_accepts_exact_fresh_and_reused_avatars() {
        for avatar_fixture in [AvatarFixture::Fresh, AvatarFixture::Reuse] {
            let (plan, context) = exact_fixture_with_avatar(avatar_fixture);
            let binding =
                preflight_metadata_transition(&plan, &context, Uuid::from_bytes(uuid(0x24)), 6)
                    .expect("exact avatar persistence must be executable");
            assert!(binding.avatar.is_some());
        }
    }

    #[test]
    fn metadata_preflight_accepts_due_expiry_families_and_rejects_reserved_to_expired() {
        // INVERTED at the C2 prior-bound correction. This assertion previously
        // accepted all four families, including a Recovery family carrying a
        // `Reserved -> Expired` package edge. Amended design 4.3/4.4 rejects
        // that edge for prior-bound families: it is production-unproducible
        // (MIN_KEY_PACKAGE_REMAINING 600s strictly exceeds
        // RECOVERY_RESERVATION_TTL 300s, so `recovery_expiry`'s `.min()` never
        // clamps) while every reader still accepted it. Closing that
        // writer-cannot-produce / reader-still-accepts asymmetry is the point
        // of the correction, so this assertion must invert.
        // The fixture now emits the PRODUCTION shape (Reserved -> Available), so the
        // unproducible edge has to be constructed deliberately — which is the honest
        // way to assert that it is rejected.
        let (mut plan, context, _) = exact_due_expiry_fixture(DueExpiryFamily::Recovery);
        for edge in plan.effects.package_transitions.iter_mut() {
            if edge.to == PackageStatus::Available {
                edge.to = PackageStatus::Expired;
            }
        }
        for binding in plan.effects.recovery_package_cas.iter_mut() {
            if binding.successor_status == PackageStatus::Available {
                binding.successor_status = PackageStatus::Expired;
                binding.authority_digest = [0; 32];
                binding.authority_digest = recovery_package_cas_authority_digest(binding);
            }
        }
        match preflight_metadata_transition(&plan, &context, Uuid::from_bytes(uuid(0x24)), 6) {
            Err(ExecutorError::InconsistentPlan(_)) => {}
            Ok(_) => panic!("Reserved -> Expired prior-bound package edge was accepted"),
            Err(error) => {
                panic!("Reserved -> Expired rejected with the wrong error: {error:?}")
            }
        }

        for family in [
            DueExpiryFamily::Reset,
            DueExpiryFamily::Leave,
            DueExpiryFamily::Welcome,
        ] {
            let (plan, context, expected) = exact_due_expiry_fixture(family);
            preflight_metadata_transition(&plan, &context, Uuid::from_bytes(uuid(0x24)), 6)
                .expect("exact due-expiry family must be executable");
            reconcile_coordinate_change_families(
                plan.effects(),
                &FamilyCounts {
                    requests: 0,
                    reservations: 0,
                    packages: 0,
                    welcomes: 0,
                    reset_requests: 0,
                    leave_requests: 0,
                },
                &expected,
            )
            .expect("due-expiry family must reconcile without a silent drop");
        }
    }

    /// REGRESSION — the Row B legality proof for the C2 prior-bound correction.
    ///
    /// A due-expiry family whose package returns to `Available` is legal
    /// prior-bound work, and it is what the planner actually emits.
    ///
    /// SCOPE, stated honestly: this exercises `preflight_metadata_transition`, the
    /// ONE arm that always accepted the shape — it passes at sealed e98 too. It is a
    /// non-regression check on the extraction, NOT proof for the other eight arms.
    /// The arms that used to reject this shape are covered by
    /// `fulfillment_arm_tolerates_an_overdue_peer_recovery_family` and
    /// `prior_bound_only_arm_accepts_a_row_b_family`.
    #[test]
    fn prior_bound_row_b_due_expiry_is_accepted_with_a_release_edge() {
        let (plan, context, expected) = exact_due_expiry_fixture(DueExpiryFamily::Recovery);

        // No hand-patching: the fixture already carries the production shape.
        preflight_metadata_transition(&plan, &context, Uuid::from_bytes(uuid(0x24)), 6)
            .expect("a legal Row B due-expiry family must be executable");
        reconcile_coordinate_change_families(
            plan.effects(),
            &FamilyCounts {
                requests: 0,
                reservations: 0,
                packages: 0,
                welcomes: 0,
                reset_requests: 0,
                leave_requests: 0,
            },
            &expected,
        )
        .expect("Row B must reconcile without a silent drop");
    }

    /// Builds one complete prior-bound recovery family (request + reservation +
    /// package edge + sealed CAS binding) onto an existing plan.
    #[allow(clippy::too_many_arguments)]
    fn push_recovery_family(
        plan: &mut ConversationPersistencePlan,
        prior: PublicGroupSnapshotCoordinate,
        actor: DeviceIdentity,
        request_id: [u8; 16],
        key_package_ref: [u8; 32],
        origin_key_id: [u8; 32],
        locked_row_digest: [u8; 32],
        received_at: ServerTimestamp,
        expires_at: ServerTimestamp,
        package_not_after: ServerTimestamp,
        after_request_status: RecoveryRequestStatus,
        after_reservation_status: ReservationStatus,
        terminal: Option<WorkTerminalEvidence>,
        package_to: PackageStatus,
    ) {
        let origin = request_evidence(
            RequestEntryKind::LeafRecoveryRequest,
            request_id,
            actor.clone(),
            *prior.conversation_id(),
            received_at,
            origin_key_id,
        );
        let before_request = RecoveryRequest {
            request_id,
            target: actor.clone(),
            kind: LeafRecoveryKind::Add,
            source: RecoverySource::Request,
            bound_coordinate: prior,
            key_package_ref,
            received_at,
            expires_at,
            status: RecoveryRequestStatus::Open,
            origin: RecoveryOriginEvidence::Request(origin),
            terminal: None,
        };
        let mut after_request = before_request.clone();
        after_request.status = after_request_status;
        after_request.terminal = terminal.clone();
        let before_reservation = RecoveryReservation {
            request_id,
            target: actor.clone(),
            bound_coordinate: prior,
            key_package_ref,
            received_at,
            expires_at,
            package_not_after,
            status: ReservationStatus::Active,
            terminal: None,
        };
        let mut after_reservation = before_reservation.clone();
        after_reservation.status = after_reservation_status;
        after_reservation.terminal = terminal;
        plan.effects.recovery_request_changes.push(StateChange {
            before: Some(before_request),
            after: Some(after_request),
        });
        plan.effects.reservation_changes.push(StateChange {
            before: Some(before_reservation),
            after: Some(after_reservation),
        });
        plan.effects.package_transitions.push(PackageTransition {
            request_id,
            key_package_ref,
            from: PackageStatus::Reserved,
            to: package_to,
        });
        let mut package_cas = RecoveryPackageCasBinding {
            transaction_id: plan
                .effects
                .head_cas
                .as_ref()
                .expect("head cas")
                .transaction_id
                .clone(),
            conversation_id: *prior.conversation_id(),
            request_id,
            target: actor,
            target_key_id: origin_key_id,
            target_auth_generation: 3,
            bound_coordinate: prior,
            key_package_ref,
            key_package_wrapper_sha256: [0x63; 32],
            package_not_after,
            claimed_at: received_at,
            expected_status: PackageStatus::Reserved,
            successor_status: package_to,
            locked_row_digest,
            authority_digest: [0; 32],
        };
        package_cas.authority_digest = recovery_package_cas_authority_digest(&package_cas);
        plan.effects.recovery_package_cas.push(package_cas);
    }

    /// REGRESSION FOR DEFECT 2 — the permanent device wedge.
    ///
    /// `preflight_leaf_recovery_fulfillment` demanded
    /// `terminal_is_exact_transition` of EVERY recovery request and reservation on
    /// the coordinate, so a peer's overdue `Expiry` terminal fell through to the
    /// `_ => illegal direction` arm. Open recovery requests are unique per TARGET
    /// and coordinate-preserving, so peers legitimately stack requests on one
    /// coordinate with staggered `expires_at`. Fulfilling one device while a peer's
    /// request was overdue therefore produced a planner-valid, executor-fatal plan —
    /// and the recovering device wedged PERMANENTLY, because retry re-planned the
    /// identical shape.
    ///
    /// This exercises the classifier that now owns that logic, with exactly the
    /// shape that used to wedge: one own family closing by this producer's
    /// transition, plus one overdue peer family closing by due expiry.
    #[test]
    fn fulfillment_arm_tolerates_an_overdue_peer_recovery_family() {
        let (mut plan, context) = exact_fixture();
        let prior = plan.expected_prior.expect("prior");
        let actor = plan
            .effects
            .authority
            .as_ref()
            .and_then(|authority| match authority {
                PlanAuthority::Transition(transition) => transition.authority.as_ref(),
                _ => None,
            })
            .expect("actor authority")
            .actor
            .clone();
        let producer = plan.state.producer.clone();
        let received_at = ServerTimestamp::from_unix_millis(4_000).unwrap();
        let expires_at = ServerTimestamp::from_unix_millis(5_000).unwrap();
        // Production relation, not the boundary. MIN_KEY_PACKAGE_REMAINING_SECONDS
        // (600) strictly exceeds RECOVERY_RESERVATION_TTL_MILLIS (300_000) and the
        // floor is re-enforced at CLAIM time against claimed_at
        // (repository/core.rs:2994, :3397), so a claimed package always outlives its
        // reservation. A fixture with package_not_after == expires_at sits exactly on
        // `terminal_time >= after.package_not_after` (:9984) and makes the planner
        // emit Reserved -> Expired — a shape production cannot produce.
        let package_not_after = ServerTimestamp::from_unix_millis(305_000).unwrap();

        let own_request_id = uuid(0x60);
        let own_ref = [0x61; 32];
        push_recovery_family(
            &mut plan,
            prior,
            actor.clone(),
            own_request_id,
            own_ref,
            [0x62; 32],
            [0x64; 32],
            received_at,
            expires_at,
            package_not_after,
            RecoveryRequestStatus::Fulfilled,
            ReservationStatus::Consumed,
            Some(WorkTerminalEvidence::Transition(producer)),
            PackageStatus::Consumed,
        );

        // The overdue peer. Different target key/ref, closing by due expiry.
        let peer_request_id = uuid(0x66);
        let peer_ref = [0x67; 32];
        push_recovery_family(
            &mut plan,
            prior,
            actor,
            peer_request_id,
            peer_ref,
            [0x68; 32],
            [0x69; 32],
            received_at,
            expires_at,
            package_not_after,
            RecoveryRequestStatus::Expired,
            ReservationStatus::Expired,
            Some(WorkTerminalEvidence::Expiry(expires_at)),
            PackageStatus::Available,
        );

        // Drive the REAL ARM, not just the extracted classifier. Defect 2 lived in
        // `preflight_leaf_recovery_fulfillment`, which had zero test callers — that
        // absence is why the wedge shipped.
        //
        // SCOPE, stated honestly: this plan is metadata-shaped, so the arm cannot
        // reach Ok — it needs an own pending Welcome it does not carry. What this
        // asserts is exactly the property Defect 2 broke: with an overdue peer
        // present, the arm passes prior-bound classification and reaches a LATER,
        // unrelated guard. Any prior-bound rejection yields a different message and
        // fails this assertion, which is what makes it discriminating.
        match preflight_leaf_recovery_fulfillment(
            &plan,
            plan.effects(),
            plan.state(),
            &context,
            Uuid::from_bytes(uuid(0x24)),
            6,
        ) {
            Err(ExecutorError::InconsistentPlan(message)) => assert_eq!(
                message, "fulfillment carries no own pending welcome",
                "the arm must get PAST prior-bound classification with an overdue \
                     peer present; a prior-bound error here means the wedge is back"
            ),
            Ok(_) => panic!("metadata-shaped plan unexpectedly satisfied the whole arm"),
            Err(error) => panic!("arm failed with an unexpected error: {error:?}"),
        }

        let partition =
            classify_prior_bound_recovery(&plan, &context, OwnFamilyKind::LeafRecoveryFulfillment)
                .expect("classifier agrees with the arm");

        assert_eq!(
            partition.own(),
            Some((own_request_id, own_ref)),
            "the own family must be the fulfilled one, derived by typed shape"
        );
        assert_eq!(
            partition.requests(),
            1,
            "the overdue peer must be classified as prior-bound work, not dropped"
        );
        assert!(
            partition.keys().contains(&(peer_request_id, peer_ref)),
            "the peer family key must be carried to the writer"
        );
    }

    /// The correction must not become permissive in the other direction: the OWN
    /// family closes by THIS producer's transition, never by due expiry. If an own
    /// family could carry an `Expiry` terminal it would be indistinguishable from
    /// prior-bound peer work, and the arm would consume a family it does not own.
    #[test]
    fn fulfillment_own_family_may_not_close_by_due_expiry() {
        let (mut plan, context) = exact_fixture();
        let prior = plan.expected_prior.expect("prior");
        let actor = plan
            .effects
            .authority
            .as_ref()
            .and_then(|authority| match authority {
                PlanAuthority::Transition(transition) => transition.authority.as_ref(),
                _ => None,
            })
            .expect("actor authority")
            .actor
            .clone();
        let received_at = ServerTimestamp::from_unix_millis(4_000).unwrap();
        let expires_at = ServerTimestamp::from_unix_millis(5_000).unwrap();
        // Production relation, not the boundary. MIN_KEY_PACKAGE_REMAINING_SECONDS
        // (600) strictly exceeds RECOVERY_RESERVATION_TTL_MILLIS (300_000) and the
        // floor is re-enforced at CLAIM time against claimed_at
        // (repository/core.rs:2994, :3397), so a claimed package always outlives its
        // reservation. A fixture with package_not_after == expires_at sits exactly on
        // `terminal_time >= after.package_not_after` (:9984) and makes the planner
        // emit Reserved -> Expired — a shape production cannot produce.
        let package_not_after = ServerTimestamp::from_unix_millis(305_000).unwrap();

        // A Fulfilled/Consumed family — the own shape — but terminalized by expiry.
        push_recovery_family(
            &mut plan,
            prior,
            actor,
            uuid(0x60),
            [0x61; 32],
            [0x62; 32],
            [0x64; 32],
            received_at,
            expires_at,
            package_not_after,
            RecoveryRequestStatus::Fulfilled,
            ReservationStatus::Consumed,
            Some(WorkTerminalEvidence::Expiry(expires_at)),
            PackageStatus::Consumed,
        );

        match classify_prior_bound_recovery(&plan, &context, OwnFamilyKind::LeafRecoveryFulfillment)
        {
            Err(ExecutorError::InconsistentPlan(_)) => {}
            Ok(_) => panic!("an own family closing by due expiry was accepted"),
            Err(error) => panic!("rejected with the wrong executor error: {error:?}"),
        }
    }

    /// The sealed fulfillment arm proved its own request and reservation agree
    /// field-for-field ("fulfillment own request/reservation are not bijective").
    /// The extraction dropped target / received_at / expires_at; an independent
    /// review caught it. This pins the restoration.
    #[test]
    fn fulfillment_own_request_and_reservation_must_agree() {
        let (mut plan, context) = exact_fixture();
        let prior = plan.expected_prior.expect("prior");
        let actor = plan
            .effects
            .authority
            .as_ref()
            .and_then(|authority| match authority {
                PlanAuthority::Transition(transition) => transition.authority.as_ref(),
                _ => None,
            })
            .expect("actor authority")
            .actor
            .clone();
        let producer = plan.state.producer.clone();
        let received_at = ServerTimestamp::from_unix_millis(4_000).unwrap();
        let expires_at = ServerTimestamp::from_unix_millis(5_000).unwrap();
        let package_not_after = ServerTimestamp::from_unix_millis(305_000).unwrap();
        push_recovery_family(
            &mut plan,
            prior,
            actor,
            uuid(0x60),
            [0x61; 32],
            [0x62; 32],
            [0x64; 32],
            received_at,
            expires_at,
            package_not_after,
            RecoveryRequestStatus::Fulfilled,
            ReservationStatus::Consumed,
            Some(WorkTerminalEvidence::Transition(producer)),
            PackageStatus::Consumed,
        );

        // Shift BOTH sides of the own reservation so identity-unchanged still holds
        // and its terminal is untouched. The only defect is that it now disagrees
        // with the own request — exactly what sealed proved and the extraction lost.
        let shifted = ServerTimestamp::from_unix_millis(4_500).unwrap();
        {
            let change = &mut plan.effects.reservation_changes[0];
            if let Some(before) = change.before.as_mut() {
                before.expires_at = shifted;
            }
            if let Some(after) = change.after.as_mut() {
                after.expires_at = shifted;
            }
        }

        match classify_prior_bound_recovery(&plan, &context, OwnFamilyKind::LeafRecoveryFulfillment)
        {
            Err(ExecutorError::InconsistentPlan(_)) => {}
            Ok(_) => panic!("an own request/reservation disagreement was accepted"),
            Err(error) => panic!("rejected with the wrong error: {error:?}"),
        }
    }

    /// REGRESSION FOR DEFECT 1, at the level a no-DB test can reach.
    ///
    /// `apply_leave_fulfillment` carried
    /// `reject_if_present("recovery_package_cas", ..)`, which — because
    /// `into_persistence_plan` enforces the CAS <-> edge bijection — meant "reject any
    /// plan carrying any package edge", the exact opposite of the comment above it.
    /// Any leaveCommit on a coordinate with open recovery work was planner-legal and
    /// executor-fatal. That arm is `async` and needs a live transaction, so the
    /// end-to-end proof belongs in the DB packet; what is provable here is the
    /// classification the arm now performs instead of rejecting — and `OwnFamilyKind::None`
    /// carrying real prior-bound work had no direct coverage at all.
    #[test]
    fn leave_fulfillment_preflight_classifies_prior_bound_work() {
        let (mut plan, context) = exact_fixture();
        let prior = plan.expected_prior.expect("prior");
        let actor = plan
            .effects
            .authority
            .as_ref()
            .and_then(|authority| match authority {
                PlanAuthority::Transition(transition) => transition.authority.as_ref(),
                _ => None,
            })
            .expect("actor authority")
            .actor
            .clone();
        let received_at = ServerTimestamp::from_unix_millis(4_000).unwrap();
        let expires_at = ServerTimestamp::from_unix_millis(5_000).unwrap();
        let package_not_after = ServerTimestamp::from_unix_millis(305_000).unwrap();

        // One overdue prior-bound family and nothing owned — the shape a leaveCommit
        // over a coordinate with open recovery work carries.
        let request_id = uuid(0x66);
        let key_package_ref = [0x67; 32];
        push_recovery_family(
            &mut plan,
            prior,
            actor,
            request_id,
            key_package_ref,
            [0x68; 32],
            [0x69; 32],
            received_at,
            expires_at,
            package_not_after,
            RecoveryRequestStatus::Expired,
            ReservationStatus::Expired,
            Some(WorkTerminalEvidence::Expiry(expires_at)),
            PackageStatus::Available,
        );

        // Drive the REAL leave-fulfillment guard block, not just the classifier.
        // Reinstating the shipped `reject_if_present("recovery_package_cas", ..)`
        // makes this fail; before the extraction it stayed green.
        let partition = preflight_leave_fulfillment(&plan, &context)
            .expect("a leaveCommit over open recovery work must not be executor-fatal");
        assert_eq!(partition.own(), None, "this arm owns no recovery family");
        assert_eq!(partition.requests(), 1);
        assert!(
            partition.keys().contains(&(request_id, key_package_ref)),
            "the family must be carried to the writer, not dropped"
        );
    }

    /// ROW-B WEDGE (leave-fulfillment arm).
    ///
    /// THE USER SEQUENCE:
    ///   1. Bob asks to leave. Nobody commits it for 24 hours, so his consent
    ///      lapses and nothing sweeps the row.
    ///   2. Carol now asks to leave, and someone commits HER leave.
    ///   3. That `leaveCommit` must succeed — carol must be able to leave even
    ///      though bob's request went stale.
    ///
    /// Before the fix step 3 failed permanently: bob's lapsed row rode along in
    /// carol's plan as a prior-bound delta the arm refused, and every retry
    /// replanned it identically.
    ///
    /// Past the 24h consent TTL
    /// `resolve_prior_bound_work` emits Row B (`Pending->Expired`), not Row A
    /// (`Pending->Stale`); `classify_prior_bound_staling` proves it and
    /// `write_prior_bound_staling` writes it, but this arm's own partition
    /// accepted only Row A — planner-legal, executor-fatal, and a retry replans the
    /// identical shape. Nothing sweeps overdue leaves, so the wedge is permanent.
    ///
    /// The arm's OWN request can never be Row B: `plan_leave_fulfillment_inner`
    /// rejects an overdue target with `WorkExpired` before planning. So the shape
    /// under test is exactly one `Fulfilled` plus one overdue peer `Expired`.
    #[test]
    fn leave_fulfillment_partition_accepts_an_overdue_prior_bound_leave() {
        let (mut plan, _context, _) = exact_due_expiry_fixture(DueExpiryFamily::Leave);
        let prior = plan.expected_prior.expect("prior");
        // The fixture's overdue peer leave (`Pending->Expired`, exact due expiry).
        let overdue_request_id = uuid(0x67);
        assert_eq!(
            plan.effects.leave_request_changes.len(),
            1,
            "fixture carries exactly the overdue peer leave"
        );

        // The arm's own edge: a DIFFERENT requester's `Pending->Fulfilled`.
        let requester = device(0x71);
        let request_id = uuid(0x72);
        let received_at = ServerTimestamp::from_unix_millis(4_000).unwrap();
        let expires_at = ServerTimestamp::from_unix_millis(90_404_000).unwrap();
        let origin = request_evidence(
            RequestEntryKind::LeaveRequest,
            request_id,
            requester.clone(),
            *prior.conversation_id(),
            received_at,
            [0x73; 32],
        );
        let before = LeaveRequest {
            request_id,
            requester,
            bound_coordinate: prior,
            received_at,
            expires_at,
            status: LeaveRequestStatus::Pending,
            origin,
            terminal: None,
            fulfilled_participant: None,
        };
        let mut after = before.clone();
        after.status = LeaveRequestStatus::Fulfilled;
        plan.effects.leave_request_changes.push(StateChange {
            before: Some(before),
            after: Some(after),
        });

        let fulfilled = partition_leave_fulfillment_requests(plan.effects())
            .expect("an overdue prior-bound peer leave must not wedge the partition");
        assert_eq!(
            fulfilled, request_id,
            "the arm's own fulfilled request, never the overdue peer"
        );
        assert_ne!(fulfilled, overdue_request_id);
    }

    /// Ruling point 3 stays enforced for BOTH prior-bound rows: a delta that
    /// retires the very request being fulfilled is illegal whether it is a staling
    /// or a due expiry. Widening the partition to accept Row B must not open this.
    #[test]
    fn leave_fulfillment_partition_rejects_expiring_the_request_it_fulfills() {
        let (mut plan, _context, _) = exact_due_expiry_fixture(DueExpiryFamily::Leave);
        let overdue = plan.effects.leave_request_changes[0].clone();
        let mut before = overdue.before.expect("overdue before").clone();
        let mut after = overdue.after.expect("overdue after").clone();
        before.status = LeaveRequestStatus::Pending;
        after.status = LeaveRequestStatus::Fulfilled;
        after.terminal = None;
        // Same request id as the fixture's `Pending->Expired` delta.
        plan.effects.leave_request_changes.push(StateChange {
            before: Some(before),
            after: Some(after),
        });

        match partition_leave_fulfillment_requests(plan.effects()) {
            Err(ExecutorError::InconsistentPlan(_)) => {}
            other => panic!("expiring the fulfilled request was accepted: {other:?}"),
        }
    }

    /// One prior-bound family plus the knobs each negative case perturbs.
    fn one_prior_bound_family(digest: [u8; 32]) -> (ConversationPersistencePlan, ExecutionContext) {
        let (mut plan, context) = exact_fixture();
        let prior = plan.expected_prior.expect("prior");
        let actor = plan
            .effects
            .authority
            .as_ref()
            .and_then(|authority| match authority {
                PlanAuthority::Transition(transition) => transition.authority.as_ref(),
                _ => None,
            })
            .expect("actor authority")
            .actor
            .clone();
        let received_at = ServerTimestamp::from_unix_millis(4_000).unwrap();
        let expires_at = ServerTimestamp::from_unix_millis(5_000).unwrap();
        let package_not_after = ServerTimestamp::from_unix_millis(305_000).unwrap();
        push_recovery_family(
            &mut plan,
            prior,
            actor,
            uuid(0x66),
            [0x67; 32],
            [0x68; 32],
            digest,
            received_at,
            expires_at,
            package_not_after,
            RecoveryRequestStatus::Expired,
            ReservationStatus::Expired,
            Some(WorkTerminalEvidence::Expiry(expires_at)),
            PackageStatus::Available,
        );
        (plan, context)
    }

    fn classify_none(
        plan: &ConversationPersistencePlan,
        context: &ExecutionContext,
    ) -> Result<PriorBoundPartition, ExecutorError> {
        classify_prior_bound_recovery(plan, context, OwnFamilyKind::None)
    }

    /// NEGATIVE BATTERY. Each case deletes exactly one classifier guarantee. An
    /// independent review showed every one of these could be removed from the
    /// classifier with the whole suite still green, so each is pinned here.
    #[test]
    fn classifier_rejects_each_prior_bound_drift() {
        // Baseline: the unperturbed family is accepted, so every rejection below is
        // attributable to the perturbation and not to a malformed fixture.
        let (plan, context) = one_prior_bound_family([0x69; 32]);
        classify_none(&plan, &context).expect("the unperturbed family must be accepted");

        // 1. Prior-bound request must come FROM Open.
        let (mut plan, context) = one_prior_bound_family([0x69; 32]);
        if let Some(before) = plan.effects.recovery_request_changes[0].before.as_mut() {
            before.status = RecoveryRequestStatus::Fulfilled;
        }
        assert!(
            classify_none(&plan, &context).is_err(),
            "a prior-bound request not leaving Open must be rejected"
        );

        // 2. Prior-bound family must be bound to the PRIOR coordinate.
        let (mut plan, context) = one_prior_bound_family([0x69; 32]);
        let foreign =
            coordinate_only_successor(&plan.expected_prior.expect("prior")).expect("successor");
        if let Some(before) = plan.effects.recovery_request_changes[0].before.as_mut() {
            before.bound_coordinate = foreign;
        }
        assert!(
            classify_none(&plan, &context).is_err(),
            "a family bound to a foreign coordinate must be rejected"
        );

        // 3. Terminal evidence must be exact: a due-expiry family whose terminal is
        //    absent is not terminalized, it is silently dropped work.
        let (mut plan, context) = one_prior_bound_family([0x69; 32]);
        if let Some(after) = plan.effects.recovery_request_changes[0].after.as_mut() {
            after.terminal = None;
        }
        assert!(
            classify_none(&plan, &context).is_err(),
            "a prior-bound request with no terminal evidence must be rejected"
        );

        // 4. Request and reservation must agree on expires_at — the value
        //    terminal_is_exact_due_expiry tests the terminal against. Sealed proved
        //    this pair directly and the extraction had dropped it.
        let (mut plan, context) = one_prior_bound_family([0x69; 32]);
        let shifted = ServerTimestamp::from_unix_millis(4_500).unwrap();
        // Shift BOTH sides of the reservation and its terminal together, so
        // identity-unchanged holds and its own due-expiry evidence stays exact. The
        // ONLY thing wrong is that it now disagrees with the request. Without this
        // the case is rejected by an earlier guard and proves nothing about the pair.
        if let Some(before) = plan.effects.reservation_changes[0].before.as_mut() {
            before.expires_at = shifted;
        }
        if let Some(after) = plan.effects.reservation_changes[0].after.as_mut() {
            after.expires_at = shifted;
            after.terminal = Some(WorkTerminalEvidence::Expiry(shifted));
        }
        match classify_none(&plan, &context) {
            Err(ExecutorError::InconsistentPlan(message)) => assert_eq!(
                message, "metadata recovery package CAS authority drift",
                "the cross-field expires_at pair must be the rejecting check"
            ),
            Ok(_) => panic!("a request/reservation expires_at disagreement was accepted"),
            Err(error) => panic!("rejected with the wrong error: {error:?}"),
        }

        // 5. The package edge must be Reserved -> Available. Reserved -> Expired is
        //    production-unproducible and every reader used to accept it.
        let (mut plan, context) = one_prior_bound_family([0x69; 32]);
        for edge in plan.effects.package_transitions.iter_mut() {
            edge.to = PackageStatus::Expired;
        }
        for binding in plan.effects.recovery_package_cas.iter_mut() {
            binding.successor_status = PackageStatus::Expired;
            binding.authority_digest = [0; 32];
            binding.authority_digest = recovery_package_cas_authority_digest(binding);
        }
        assert!(
            classify_none(&plan, &context).is_err(),
            "Reserved -> Expired must be rejected for a prior-bound family"
        );

        // 6. The CAS binding must agree with the family it claims to authorize.
        let (mut plan, context) = one_prior_bound_family([0x69; 32]);
        for binding in plan.effects.recovery_package_cas.iter_mut() {
            binding.claimed_at = ServerTimestamp::from_unix_millis(9_000).unwrap();
            binding.authority_digest = [0; 32];
            binding.authority_digest = recovery_package_cas_authority_digest(binding);
        }
        assert!(
            classify_none(&plan, &context).is_err(),
            "a CAS binding whose claimed_at drifts from the family must be rejected"
        );
    }

    /// Check 8-DiD, which this correction introduces and which had no negative test.
    /// `recovery_package_guard_digest` hashes `key_package_ref`, so two bindings with
    /// distinct refs sharing one locked-row digest means the planner reused a guard's
    /// digest across references — real drift, not a hash collision.
    #[test]
    fn check_8_did_rejects_one_locked_row_digest_across_two_refs() {
        let shared = [0x69; 32];
        let (mut plan, context) = one_prior_bound_family(shared);
        let prior = plan.expected_prior.expect("prior");
        let actor = plan.effects.recovery_package_cas[0].target.clone();
        let received_at = ServerTimestamp::from_unix_millis(4_000).unwrap();
        let expires_at = ServerTimestamp::from_unix_millis(5_000).unwrap();
        let package_not_after = ServerTimestamp::from_unix_millis(305_000).unwrap();

        // A second, otherwise-legal family on a DIFFERENT key package reference —
        // but carrying the first family's locked-row digest.
        push_recovery_family(
            &mut plan,
            prior,
            actor,
            uuid(0x71),
            [0x72; 32],
            [0x73; 32],
            shared,
            received_at,
            expires_at,
            package_not_after,
            RecoveryRequestStatus::Expired,
            ReservationStatus::Expired,
            Some(WorkTerminalEvidence::Expiry(expires_at)),
            PackageStatus::Available,
        );

        match classify_none(&plan, &context) {
            Err(ExecutorError::InconsistentPlan(message)) => assert_eq!(
                message, "distinct key package refs share one locked row digest",
                "8-DiD must be the rejecting check"
            ),
            Ok(_) => panic!("two refs sharing one locked-row digest were accepted"),
            Err(error) => panic!("rejected with the wrong error: {error:?}"),
        }

        // Control: distinct digests on the same two families are accepted.
        let (mut plan, context) = one_prior_bound_family([0x69; 32]);
        let prior = plan.expected_prior.expect("prior");
        let actor = plan.effects.recovery_package_cas[0].target.clone();
        push_recovery_family(
            &mut plan,
            prior,
            actor,
            uuid(0x71),
            [0x72; 32],
            [0x73; 32],
            [0x74; 32],
            received_at,
            expires_at,
            package_not_after,
            RecoveryRequestStatus::Expired,
            ReservationStatus::Expired,
            Some(WorkTerminalEvidence::Expiry(expires_at)),
            PackageStatus::Available,
        );
        classify_none(&plan, &context)
            .expect("two families with distinct digests must be accepted");
    }

    /// The keyed write-receipt check (design 5 step 6). `write_prior_bound_supersessions`
    /// SKIPS any delta that is not its exact supersession shape, so a silent drop
    /// is a real failure mode — and a count-only comparison cannot tell a dropped
    /// family from a substituted one. Reachable in production only through the
    /// `apply_*` arms, which need a live transaction, so it is proven here directly.
    #[test]
    fn write_receipt_must_match_the_classified_families_by_key() {
        let key_a = (uuid(0x60), [0x61; 32]);
        let key_b = (uuid(0x66), [0x67; 32]);
        let partition = PriorBoundPartition::for_receipt_test(BTreeSet::from([key_a, key_b]), None);
        let counts = |n: usize| FamilyCounts {
            requests: n,
            reservations: n,
            packages: n,
            welcomes: 0,
            reset_requests: 0,
            leave_requests: 0,
        };

        let reconciled = PriorBoundWriteReceipt::new(counts(2), BTreeSet::from([key_a, key_b]))
            .reconcile_into_counts(&partition)
            .expect("an exact receipt must reconcile");
        assert_eq!(
            reconciled.packages, 2,
            "the counts must survive reconciliation"
        );

        // A dropped family.
        assert!(
            PriorBoundWriteReceipt::new(counts(1), BTreeSet::from([key_a]))
                .reconcile_into_counts(&partition)
                .is_err(),
            "a silently dropped family must be rejected"
        );

        // Right COUNT, wrong identity — the case a count-only fence cannot see.
        assert!(
            PriorBoundWriteReceipt::new(
                counts(2),
                BTreeSet::from([key_a, (uuid(0x77), [0x78; 32])])
            )
            .reconcile_into_counts(&partition)
            .is_err(),
            "a substituted family must be rejected even at the right count"
        );
    }

    /// REGRESSION — the acceptance own family is bound to the SUCCESSOR.
    ///
    /// `plan_accept_conversation_inner` opens its recovery request and reservation
    /// with `bound_coordinate: coordinate_only_successor(prior)` (:13452, :13463),
    /// because the family is created as PART of the coordinate change. A classifier
    /// that compares the own family against `prior` rejects every acceptConversation
    /// before its head CAS, and retry re-plans the identical shape — a permanent
    /// device-can-never-join wedge. This pins the coordinate the own family must
    /// carry, in both directions.
    #[test]
    fn acceptance_own_family_is_bound_to_the_successor_not_the_prior() {
        fn acceptance_plan(
            bind_to_successor: bool,
        ) -> (ConversationPersistencePlan, ExecutionContext) {
            let (mut plan, context) = exact_fixture();
            let prior = plan.expected_prior.expect("prior");
            let successor = coordinate_only_successor(&prior).expect("successor");
            let bound = if bind_to_successor { successor } else { prior };
            let actor = plan
                .effects
                .authority
                .as_ref()
                .and_then(|authority| match authority {
                    PlanAuthority::Transition(transition) => transition.authority.as_ref(),
                    _ => None,
                })
                .expect("actor authority")
                .actor
                .clone();
            let received_at = ServerTimestamp::from_unix_millis(4_000).unwrap();
            let expires_at = ServerTimestamp::from_unix_millis(5_000).unwrap();
            // Production relation, not the boundary: package_not_after strictly
            // outlives expires_at (see the note on exact_due_expiry_fixture).
            let package_not_after = ServerTimestamp::from_unix_millis(305_000).unwrap();
            let request_id = uuid(0x60);
            let key_package_ref = [0x61; 32];
            let origin_key_id = [0x62; 32];
            let origin = request_evidence(
                RequestEntryKind::LeafRecoveryRequest,
                request_id,
                actor.clone(),
                *prior.conversation_id(),
                received_at,
                origin_key_id,
            );
            plan.effects.recovery_request_changes.push(StateChange {
                before: None,
                after: Some(RecoveryRequest {
                    request_id,
                    target: actor.clone(),
                    kind: LeafRecoveryKind::Add,
                    source: RecoverySource::Acceptance,
                    bound_coordinate: bound,
                    key_package_ref,
                    received_at,
                    expires_at,
                    status: RecoveryRequestStatus::Open,
                    origin: RecoveryOriginEvidence::Request(origin),
                    terminal: None,
                }),
            });
            plan.effects.reservation_changes.push(StateChange {
                before: None,
                after: Some(RecoveryReservation {
                    request_id,
                    target: actor.clone(),
                    bound_coordinate: bound,
                    key_package_ref,
                    received_at,
                    expires_at,
                    package_not_after,
                    status: ReservationStatus::Active,
                    terminal: None,
                }),
            });
            plan.effects.package_transitions.push(PackageTransition {
                request_id,
                key_package_ref,
                from: PackageStatus::Available,
                to: PackageStatus::Reserved,
            });
            let mut package_cas = RecoveryPackageCasBinding {
                transaction_id: plan
                    .effects
                    .head_cas
                    .as_ref()
                    .expect("head cas")
                    .transaction_id
                    .clone(),
                conversation_id: *prior.conversation_id(),
                request_id,
                target: actor,
                target_key_id: origin_key_id,
                target_auth_generation: 3,
                bound_coordinate: bound,
                key_package_ref,
                key_package_wrapper_sha256: [0x63; 32],
                package_not_after,
                claimed_at: received_at,
                expected_status: PackageStatus::Available,
                successor_status: PackageStatus::Reserved,
                locked_row_digest: [0x64; 32],
                authority_digest: [0; 32],
            };
            package_cas.authority_digest = recovery_package_cas_authority_digest(&package_cas);
            plan.effects.recovery_package_cas.push(package_cas);
            (plan, context)
        }

        // What the planner actually emits.
        let (plan, context) = acceptance_plan(true);
        classify_prior_bound_recovery(&plan, &context, OwnFamilyKind::Acceptance)
            .expect("the planner's successor-bound acceptance family must be accepted");

        // A prior-bound own family is NOT what acceptance opens, and must not pass.
        let (plan, context) = acceptance_plan(false);
        match classify_prior_bound_recovery(&plan, &context, OwnFamilyKind::Acceptance) {
            Err(ExecutorError::InconsistentPlan(_)) => {}
            Ok(_) => panic!("a prior-bound acceptance own family was accepted"),
            Err(error) => panic!("rejected with the wrong executor error: {error:?}"),
        }
    }

    #[test]
    fn metadata_preflight_rejects_author_column_drift() {
        for (label, group_id, confirmation_tag) in [
            ("group ID", Some([0x91; 32]), None),
            ("confirmation tag", None, Some([0x92; 32])),
        ] {
            let (mut plan, context) = exact_fixture();
            assert_eq!(
                mutate_all_inner_metadata_coordinates(&mut plan, group_id, confirmation_tag),
                5,
                "{label} mutation must cover every inner metadata copy",
            );
            assert!(matches!(
                preflight_metadata_transition(&plan, &context, Uuid::from_bytes(uuid(0x24)), 6,),
                Err(ExecutorError::InconsistentPlan(_))
            ));
        }

        let (plan, mut context) = exact_fixture();
        context
            .metadata_author
            .as_mut()
            .expect("metadata author")
            .author_role = "member".to_owned();

        assert!(matches!(
            preflight_metadata_transition(&plan, &context, Uuid::from_bytes(uuid(0x24)), 6,),
            Err(ExecutorError::InconsistentPlan(_))
        ));
    }

    #[test]
    fn metadata_preflight_rejects_noncanonical_primary_event() {
        let (plan, mut context) = exact_fixture();
        context.events[0].payload_bytes.push(0);

        assert!(matches!(
            preflight_metadata_transition(&plan, &context, Uuid::from_bytes(uuid(0x24)), 6,),
            Err(ExecutorError::InconsistentPlan(_))
        ));
    }

    #[test]
    fn metadata_preflight_rejects_entry_audience_drift() {
        let (plan, mut context) = exact_fixture();
        context
            .entry_recipients
            .push((device(0x41), EntryEntitlementKind::Control));

        assert!(matches!(
            preflight_metadata_transition(&plan, &context, Uuid::from_bytes(uuid(0x24)), 6,),
            Err(ExecutorError::InconsistentPlan(_))
        ));
    }

    #[test]
    fn metadata_preflight_rejects_spine_digest_drift() {
        let (plan, mut context) = exact_fixture();
        context.spine.public_snapshot_bytes.push(0);

        assert!(matches!(
            preflight_metadata_transition(&plan, &context, Uuid::from_bytes(uuid(0x24)), 6,),
            Err(ExecutorError::InconsistentPlan(_))
        ));
    }

    #[test]
    fn metadata_preflight_rejects_unsigned_avatar_context() {
        let (plan, mut context) = exact_fixture();
        context.metadata_avatar = Some(MetadataAvatarPersistence::Reuse {
            snapshot: MetadataAvatarBinding {
                avatar_blob_id: Uuid::from_bytes(uuid(0x42)),
                avatar_ciphertext_sha256: vec![0x43; 32],
                avatar_ciphertext_size: 64,
                avatar_binding_origin_transition_id: Uuid::from_bytes(uuid(0x44)),
                avatar_binding_metadata_version: 1,
                avatar_binding_owner_did: context.actor.user_did.clone(),
                avatar_binding_owner_device_id: context.actor.device_id,
            },
        });

        assert!(matches!(
            preflight_metadata_transition(&plan, &context, Uuid::from_bytes(uuid(0x24)), 6,),
            Err(ExecutorError::InconsistentPlan(_))
        ));
    }

    #[cfg(all(
        feature = "chat-protocol-production-proof",
        not(feature = "server-bin")
    ))]
    pub(super) fn run_production_semantic_proof() -> Result<(), String> {
        let avatar_aad = canonical_metadata_avatar_blob_aad(
            uuid(0x51),
            uuid(0x52),
            7,
            uuid(0x53),
            "image/png",
            48,
        );
        if !avatar_aad.starts_with(b"CATBIRD-CHAT-METADATA-AVATAR-BLOB\0") {
            return Err("metadata avatar AAD omitted its protocol domain".to_owned());
        }
        let expected_avatar_aad_sha256 = [
            0x97, 0x27, 0x75, 0x7f, 0x58, 0x75, 0x13, 0x39, 0x16, 0x32, 0x0d, 0x3c, 0x82, 0xc2,
            0x72, 0xdf, 0x48, 0x0d, 0x41, 0x95, 0xed, 0x3b, 0x57, 0x97, 0xd6, 0x1a, 0xa6, 0x3e,
            0xd0, 0x71, 0x73, 0xb8,
        ];
        let actual_avatar_aad_sha256 = <[u8; 32]>::from(sha2::Sha256::digest(&avatar_aad));
        if actual_avatar_aad_sha256 != expected_avatar_aad_sha256 {
            return Err(format!(
                "metadata avatar AAD canonical payload drifted from the fixed vector: {}",
                hex::encode(actual_avatar_aad_sha256)
            ));
        }

        let (plan, context) = exact_fixture();
        preflight_metadata_transition(&plan, &context, Uuid::from_bytes(uuid(0x24)), 6)
            .map_err(|error| format!("exact metadata preflight failed: {error:?}"))?;
        for (label, avatar_fixture) in [
            ("fresh avatar", AvatarFixture::Fresh),
            ("reused avatar", AvatarFixture::Reuse),
        ] {
            let (plan, context) = exact_fixture_with_avatar(avatar_fixture);
            let binding =
                preflight_metadata_transition(&plan, &context, Uuid::from_bytes(uuid(0x24)), 6)
                    .map_err(|error| format!("{label} preflight failed: {error:?}"))?;
            if binding.avatar.is_none() {
                return Err(format!("{label} lost its persistence authority"));
            }
        }
        // INVERTED at the C2 prior-bound correction, same reason as the
        // cfg(test) assertion above: a Recovery family carrying a
        // `Reserved -> Expired` package edge is production-unproducible and
        // must now be rejected rather than accepted.
        {
            // The fixture emits the PRODUCTION shape (Reserved -> Available), so the
            // unproducible edge is constructed deliberately here.
            let (mut plan, context, _) = exact_due_expiry_fixture(DueExpiryFamily::Recovery);
            for edge in plan.effects.package_transitions.iter_mut() {
                if edge.to == PackageStatus::Available {
                    edge.to = PackageStatus::Expired;
                }
            }
            for binding in plan.effects.recovery_package_cas.iter_mut() {
                if binding.successor_status == PackageStatus::Available {
                    binding.successor_status = PackageStatus::Expired;
                    binding.authority_digest = [0; 32];
                    binding.authority_digest = recovery_package_cas_authority_digest(binding);
                }
            }
            match preflight_metadata_transition(&plan, &context, Uuid::from_bytes(uuid(0x24)), 6) {
                Err(ExecutorError::InconsistentPlan(_)) => {}
                Ok(_) => {
                    return Err("Reserved -> Expired prior-bound package edge was accepted".into())
                }
                Err(error) => {
                    return Err(format!(
                        "Reserved -> Expired rejected with the wrong error: {error:?}"
                    ))
                }
            }
        }
        for (label, family) in [
            ("Reset expiry", DueExpiryFamily::Reset),
            ("Leave expiry", DueExpiryFamily::Leave),
            ("Welcome expiry", DueExpiryFamily::Welcome),
        ] {
            let (plan, context, expected) = exact_due_expiry_fixture(family);
            preflight_metadata_transition(&plan, &context, Uuid::from_bytes(uuid(0x24)), 6)
                .map_err(|error| format!("{label} preflight failed: {error:?}"))?;
            reconcile_coordinate_change_families(
                plan.effects(),
                &FamilyCounts {
                    requests: 0,
                    reservations: 0,
                    packages: 0,
                    welcomes: 0,
                    reset_requests: 0,
                    leave_requests: 0,
                },
                &expected,
            )
            .map_err(|error| format!("{label} reconciliation failed: {error:?}"))?;
        }

        let reject = |label: &str,
                      plan: &ConversationPersistencePlan,
                      context: &ExecutionContext|
         -> Result<(), String> {
            match preflight_metadata_transition(plan, context, Uuid::from_bytes(uuid(0x24)), 6) {
                Err(ExecutorError::InconsistentPlan(_)) => Ok(()),
                Ok(_) => Err(format!("{label} was accepted")),
                Err(error) => Err(format!(
                    "{label} failed with the wrong executor error: {error:?}"
                )),
            }
        };

        for (label, group_id, confirmation_tag) in [
            ("all-inner group ID drift", Some([0x91; 32]), None),
            ("all-inner confirmation-tag drift", None, Some([0x92; 32])),
        ] {
            let (mut plan, context) = exact_fixture();
            if mutate_all_inner_metadata_coordinates(&mut plan, group_id, confirmation_tag) != 5 {
                return Err(format!(
                    "{label} did not mutate all five inner metadata copies"
                ));
            }
            reject(label, &plan, &context)?;
        }

        let (plan, mut context) = exact_fixture();
        context.events[0].payload_bytes.push(0);
        reject("primary event payload drift", &plan, &context)?;

        let (plan, mut context) = exact_fixture();
        context
            .entry_recipients
            .push((device(0x41), EntryEntitlementKind::Control));
        reject("entry audience drift", &plan, &context)?;

        let (plan, mut context) = exact_fixture();
        context.spine.public_snapshot_bytes.push(0);
        reject("spine digest drift", &plan, &context)?;

        let (plan, mut context) = exact_fixture();
        context.metadata_avatar = Some(MetadataAvatarPersistence::Reuse {
            snapshot: MetadataAvatarBinding {
                avatar_blob_id: Uuid::from_bytes(uuid(0x42)),
                avatar_ciphertext_sha256: vec![0x43; 32],
                avatar_ciphertext_size: 64,
                avatar_binding_origin_transition_id: Uuid::from_bytes(uuid(0x44)),
                avatar_binding_metadata_version: 1,
                avatar_binding_owner_did: context.actor.user_did.clone(),
                avatar_binding_owner_device_id: context.actor.device_id,
            },
        });
        reject("unsigned avatar context", &plan, &context)?;

        Ok(())
    }
}

#[cfg(all(
    feature = "chat-protocol-production-proof",
    not(feature = "server-bin")
))]
pub(in crate::chat_protocol) fn run_metadata_semantic_proof() -> Result<(), String> {
    metadata_executor_tests::run_production_semantic_proof()
}
