#![allow(unused_imports)]
use super::*;

pub(in crate::chat_protocol::state_machine) fn require_request_coordinate_binding(
    evidence: &RequestEvidence,
    expected_conversation_id: &[u8; 16],
) -> Result<(), StateMachineError> {
    if evidence.body_binding.as_ref().is_some_and(|binding| {
        matches!(binding, RequestBodyBinding::LeaveCancellation { conversation_id }
            if conversation_id != expected_conversation_id)
    }) {
        return Err(StateMachineError::StaleCoordinates);
    }
    Ok(())
}

pub(in crate::chat_protocol::state_machine) fn request_entry_signed_kind(
    kind: RequestEntryKind,
) -> SignedMutationKind {
    match kind {
        RequestEntryKind::LeafRecoveryRequest => SignedMutationKind::LeafRecoveryRequest,
        RequestEntryKind::LeafRecoveryCancellation => SignedMutationKind::LeafRecoveryCancellation,
        RequestEntryKind::ResetRequest => SignedMutationKind::ResetRequest,
        RequestEntryKind::LeaveRequest => SignedMutationKind::LeaveRequest,
        RequestEntryKind::LeaveCancellation => SignedMutationKind::LeaveCancellation,
        RequestEntryKind::WelcomeAcknowledgement => SignedMutationKind::WelcomeAcknowledgement,
        RequestEntryKind::WelcomeRejection => SignedMutationKind::WelcomeRejection,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AccessIntervalEnd {
    pub(in crate::chat_protocol::state_machine) evidence: TransitionEvidence,
    pub(in crate::chat_protocol::state_machine) kind: CloseKind,
}

impl AccessIntervalEnd {
    pub(crate) fn seq(&self) -> u64 {
        self.evidence.seq
    }

    pub(crate) fn kind(&self) -> CloseKind {
        self.kind
    }

    pub(crate) fn transition_id(&self) -> &[u8; 16] {
        &self.evidence.transition_id
    }

    pub(crate) fn outer_entry_fingerprint(&self) -> &[u8; 32] {
        &self.evidence.outer_entry_fingerprint
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AccessInterval {
    pub(in crate::chat_protocol::state_machine) recipient: DeviceIdentity,
    pub(in crate::chat_protocol::state_machine) generation: u64,
    pub(in crate::chat_protocol::state_machine) opening: TransitionEvidence,
    pub(in crate::chat_protocol::state_machine) opening_kind: OpeningKind,
    pub(in crate::chat_protocol::state_machine) opening_context: PublicGroupSnapshotCoordinate,
    pub(in crate::chat_protocol::state_machine) end: Option<AccessIntervalEnd>,
}

impl AccessInterval {
    pub(crate) fn recipient(&self) -> &DeviceIdentity {
        &self.recipient
    }

    pub(crate) fn opening_seq(&self) -> u64 {
        self.opening.seq
    }

    pub(crate) fn opening_kind(&self) -> OpeningKind {
        self.opening_kind
    }

    pub(crate) fn opening_transition_id(&self) -> &[u8; 16] {
        &self.opening.transition_id
    }

    pub(crate) fn opening_outer_entry_fingerprint(&self) -> &[u8; 32] {
        &self.opening.outer_entry_fingerprint
    }

    pub(crate) fn opening_context(&self) -> &PublicGroupSnapshotCoordinate {
        &self.opening_context
    }

    pub(crate) fn end(&self) -> Option<&AccessIntervalEnd> {
        self.end.as_ref()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ScheduleTerminalProof {
    pub(in crate::chat_protocol::state_machine) recipient: DeviceIdentity,
    pub(in crate::chat_protocol::state_machine) conversation_id: [u8; 16],
    pub(in crate::chat_protocol::state_machine) evidence: TransitionEvidence,
}

impl ScheduleTerminalProof {
    pub(crate) fn recipient(&self) -> &DeviceIdentity {
        &self.recipient
    }

    pub(crate) fn seq(&self) -> u64 {
        self.evidence.seq
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LeafRecoveryKind {
    Add,
    Replace,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecoverySource {
    Request,
    Acceptance,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecoveryRequestStatus {
    Open,
    Fulfilled,
    Cancelled,
    Expired,
    Superseded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReservationStatus {
    Active,
    Consumed,
    Expired,
    Released,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::chat_protocol::state_machine) enum RecoveryOriginEvidence {
    Acceptance(TransitionEvidence),
    Request(RequestEvidence),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResetRequestStatus {
    Pending,
    Stale,
    Consumed,
    Expired,
    /// The requester's own device was revoked while the request was pending.
    /// Ratified 2026-08-15 as the fifth reset-request status; see
    /// `reset_request_status_code` for the canonical encoding.
    Revoked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LeaveRequestStatus {
    Pending,
    Fulfilled,
    Cancelled,
    Expired,
    Stale,
}

#[cfg(test)]
#[derive(Debug)]
pub(crate) enum LeaveFulfillmentTestMutation {
    ManifestDevices(Vec<DeviceIdentity>),
    DropParticipantProof,
    ProofPrincipal(PrincipalId),
    ProofInactive,
    ProofInvalidProvenance,
    ProofWrongTransition,
    ProofWrongSequence,
    ProofWrongTime,
    IntervalLeftOpen(DeviceIdentity),
    IntervalClosedLater(DeviceIdentity),
    IntervalWrongEvidence(DeviceIdentity),
    IntervalWrongKind(DeviceIdentity),
    IntervalOpenedAfterOrigin(DeviceIdentity),
    DuplicatePreTerminalInterval(DeviceIdentity),
    LaterRejoin(DeviceIdentity),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WelcomeStatus {
    Pending,
    Acknowledged,
    Rejected,
    Expired,
    Superseded,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RecoveryRequest {
    pub(in crate::chat_protocol::state_machine) request_id: [u8; 16],
    pub(in crate::chat_protocol::state_machine) target: DeviceIdentity,
    pub(in crate::chat_protocol::state_machine) kind: LeafRecoveryKind,
    pub(in crate::chat_protocol::state_machine) source: RecoverySource,
    pub(in crate::chat_protocol::state_machine) bound_coordinate: PublicGroupSnapshotCoordinate,
    pub(in crate::chat_protocol::state_machine) key_package_ref: [u8; 32],
    pub(in crate::chat_protocol::state_machine) received_at: ServerTimestamp,
    pub(in crate::chat_protocol::state_machine) expires_at: ServerTimestamp,
    pub(in crate::chat_protocol::state_machine) status: RecoveryRequestStatus,
    pub(in crate::chat_protocol::state_machine) origin: RecoveryOriginEvidence,
    pub(in crate::chat_protocol::state_machine) terminal: Option<WorkTerminalEvidence>,
}

impl RecoveryRequest {
    pub(crate) fn request_id(&self) -> &[u8; 16] {
        &self.request_id
    }

    pub(crate) fn target(&self) -> &DeviceIdentity {
        &self.target
    }

    pub(crate) fn kind(&self) -> LeafRecoveryKind {
        self.kind
    }

    pub(crate) fn source(&self) -> RecoverySource {
        self.source
    }

    pub(crate) fn bound_coordinate(&self) -> &PublicGroupSnapshotCoordinate {
        &self.bound_coordinate
    }

    pub(crate) fn key_package_ref(&self) -> &[u8; 32] {
        &self.key_package_ref
    }

    pub(crate) fn received_at(&self) -> &ServerTimestamp {
        &self.received_at
    }

    pub(crate) fn expires_at(&self) -> &ServerTimestamp {
        &self.expires_at
    }

    pub(crate) fn status(&self) -> RecoveryRequestStatus {
        self.status
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RecoveryReservation {
    pub(in crate::chat_protocol::state_machine) request_id: [u8; 16],
    pub(in crate::chat_protocol::state_machine) target: DeviceIdentity,
    pub(in crate::chat_protocol::state_machine) bound_coordinate: PublicGroupSnapshotCoordinate,
    pub(in crate::chat_protocol::state_machine) key_package_ref: [u8; 32],
    pub(in crate::chat_protocol::state_machine) received_at: ServerTimestamp,
    pub(in crate::chat_protocol::state_machine) expires_at: ServerTimestamp,
    pub(in crate::chat_protocol::state_machine) package_not_after: ServerTimestamp,
    pub(in crate::chat_protocol::state_machine) status: ReservationStatus,
    pub(in crate::chat_protocol::state_machine) terminal: Option<WorkTerminalEvidence>,
}

impl RecoveryReservation {
    pub(crate) fn status(&self) -> ReservationStatus {
        self.status
    }

    pub(crate) fn expires_at(&self) -> &ServerTimestamp {
        &self.expires_at
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResetRequest {
    pub(in crate::chat_protocol::state_machine) request_id: [u8; 16],
    pub(in crate::chat_protocol::state_machine) requester: DeviceIdentity,
    pub(in crate::chat_protocol::state_machine) bound_coordinate: PublicGroupSnapshotCoordinate,
    pub(in crate::chat_protocol::state_machine) received_at: ServerTimestamp,
    pub(in crate::chat_protocol::state_machine) expires_at: ServerTimestamp,
    pub(in crate::chat_protocol::state_machine) status: ResetRequestStatus,
    pub(in crate::chat_protocol::state_machine) origin: RequestEvidence,
    pub(in crate::chat_protocol::state_machine) terminal: Option<WorkTerminalEvidence>,
}

impl ResetRequest {
    pub(crate) fn status(&self) -> ResetRequestStatus {
        self.status
    }

    pub(crate) fn expires_at(&self) -> &ServerTimestamp {
        &self.expires_at
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LeaveRequest {
    pub(in crate::chat_protocol::state_machine) request_id: [u8; 16],
    pub(in crate::chat_protocol::state_machine) requester: DeviceIdentity,
    pub(in crate::chat_protocol::state_machine) bound_coordinate: PublicGroupSnapshotCoordinate,
    pub(in crate::chat_protocol::state_machine) received_at: ServerTimestamp,
    pub(in crate::chat_protocol::state_machine) expires_at: ServerTimestamp,
    pub(in crate::chat_protocol::state_machine) status: LeaveRequestStatus,
    pub(in crate::chat_protocol::state_machine) origin: RequestEvidence,
    pub(in crate::chat_protocol::state_machine) terminal: Option<WorkTerminalEvidence>,
    pub(in crate::chat_protocol::state_machine) fulfilled_participant:
        Option<ParticipantRemovalEvidence>,
}

impl LeaveRequest {
    pub(crate) fn request_id(&self) -> &[u8; 16] {
        &self.request_id
    }

    pub(crate) fn requester(&self) -> &DeviceIdentity {
        &self.requester
    }

    pub(crate) fn bound_coordinate(&self) -> &PublicGroupSnapshotCoordinate {
        &self.bound_coordinate
    }

    pub(crate) fn received_at(&self) -> &ServerTimestamp {
        &self.received_at
    }

    pub(crate) fn status(&self) -> LeaveRequestStatus {
        self.status
    }

    pub(crate) fn expires_at(&self) -> &ServerTimestamp {
        &self.expires_at
    }
}

/// Historical proof retained by a fulfilled leave: the exact active
/// participant record removed by the fulfillment and the exact transition that
/// removed it. Both planner and repository hydration construct this sealed
/// value; a period UUID or repository-only boolean is not sufficient authority
/// for aggregate validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ParticipantRemovalEvidence {
    pub(in crate::chat_protocol::state_machine) participant: ParticipantRecord,
    pub(in crate::chat_protocol::state_machine) terminal: TransitionEvidence,
}

impl ParticipantRemovalEvidence {
    pub(crate) fn from_hydration(
        participant: ParticipantHydrationRow,
        terminal: TransitionEvidence,
    ) -> Self {
        Self {
            participant: ParticipantRecord {
                principal: participant.principal,
                status: participant.status,
                role: participant.role,
                role_producer: participant.role_producer,
                invitation: participant
                    .invitation
                    .map(|invitation| InvitationProvenance {
                        transition: invitation.transition,
                        inviter: invitation.inviter,
                    }),
                acceptance: participant.acceptance,
            },
            terminal,
        }
    }

    /// Lossless read-only projection used by the repository's typed locked-graph
    /// digest. No caller can mutate or construct internal participant state
    /// through this seam.
    pub(crate) fn participant_hydration(&self) -> ParticipantHydrationRow {
        ParticipantHydrationRow {
            principal: self.participant.principal.clone(),
            status: self.participant.status,
            role: self.participant.role,
            role_producer: self.participant.role_producer.clone(),
            invitation: self.participant.invitation.as_ref().map(|invitation| {
                InvitationHydrationRow {
                    transition: invitation.transition.clone(),
                    inviter: invitation.inviter.clone(),
                }
            }),
            acceptance: self.participant.acceptance.clone(),
        }
    }

    /// Exact terminal transition retained by this removal proof.
    pub(crate) fn terminal(&self) -> &TransitionEvidence {
        &self.terminal
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WelcomeWork {
    pub(in crate::chat_protocol::state_machine) welcome_id: [u8; 16],
    pub(in crate::chat_protocol::state_machine) recipient: DeviceIdentity,
    pub(in crate::chat_protocol::state_machine) transition_seq: u64,
    pub(in crate::chat_protocol::state_machine) coordinate: PublicGroupSnapshotCoordinate,
    pub(in crate::chat_protocol::state_machine) recovery_request_id: [u8; 16],
    pub(in crate::chat_protocol::state_machine) key_package_ref: [u8; 32],
    pub(in crate::chat_protocol::state_machine) opaque_welcome: Vec<u8>,
    pub(in crate::chat_protocol::state_machine) sha256: [u8; 32],
    pub(in crate::chat_protocol::state_machine) expires_at: ServerTimestamp,
    pub(in crate::chat_protocol::state_machine) status: WelcomeStatus,
    pub(in crate::chat_protocol::state_machine) terminal: Option<WorkTerminalEvidence>,
}

impl WelcomeWork {
    pub(crate) fn welcome_id(&self) -> &[u8; 16] {
        &self.welcome_id
    }
    pub(crate) fn recipient(&self) -> &DeviceIdentity {
        &self.recipient
    }
    pub(crate) fn transition_seq(&self) -> u64 {
        self.transition_seq
    }
    pub(crate) fn status(&self) -> WelcomeStatus {
        self.status
    }

    pub(crate) fn coordinate(&self) -> &PublicGroupSnapshotCoordinate {
        &self.coordinate
    }

    pub(crate) fn expires_at(&self) -> ServerTimestamp {
        self.expires_at
    }

    pub(crate) fn recovery_request_id(&self) -> &[u8; 16] {
        &self.recovery_request_id
    }
    pub(crate) fn key_package_ref(&self) -> &[u8; 32] {
        &self.key_package_ref
    }
    pub(crate) fn opaque_welcome(&self) -> &[u8] {
        &self.opaque_welcome
    }
    pub(crate) fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ConversationState {
    pub(in crate::chat_protocol::state_machine) kind: ConversationKind,
    pub(in crate::chat_protocol::state_machine) coordinate: PublicGroupSnapshotCoordinate,
    pub(in crate::chat_protocol::state_machine) producer: TransitionEvidence,
    pub(in crate::chat_protocol::state_machine) public_state: Option<ActivePublicState>,
    pub(in crate::chat_protocol::state_machine) metadata: Option<MetadataSnapshotBinding>,
    /// Exact signed transition whose body contains the retained metadata
    /// snapshot. This remains stable across coordinate-only transitions.
    pub(in crate::chat_protocol::state_machine) metadata_producer: Option<TransitionEvidence>,
    pub(in crate::chat_protocol::state_machine) participants: Vec<ParticipantRecord>,
    pub(in crate::chat_protocol::state_machine) leaves: Vec<LeafRecord>,
    pub(in crate::chat_protocol::state_machine) intervals: Vec<AccessInterval>,
    pub(in crate::chat_protocol::state_machine) terminal_proofs: Vec<ScheduleTerminalProof>,
    pub(in crate::chat_protocol::state_machine) recovery_requests: Vec<RecoveryRequest>,
    pub(in crate::chat_protocol::state_machine) recovery_reservations: Vec<RecoveryReservation>,
    pub(in crate::chat_protocol::state_machine) reset_requests: Vec<ResetRequest>,
    pub(in crate::chat_protocol::state_machine) leave_requests: Vec<LeaveRequest>,
    pub(in crate::chat_protocol::state_machine) welcomes: Vec<WelcomeWork>,
}

/// Adapter-facing durable graph. Every authority-bearing field is already a
/// sealed projection issued by `HydrationAuthority`; raw signature material
/// cannot be inserted into this graph in production.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(Clone))]
pub(crate) struct ConversationStateHydration {
    pub(crate) kind: ConversationKind,
    pub(crate) coordinate: PublicGroupSnapshotCoordinate,
    pub(crate) producer: TransitionEvidence,
    pub(crate) public_state: Option<ActivePublicState>,
    pub(crate) metadata: Option<MetadataSnapshotBinding>,
    pub(crate) metadata_producer: Option<TransitionEvidence>,
    pub(crate) participants: Vec<ParticipantHydrationRow>,
    pub(crate) leaves: Vec<LeafHydrationRow>,
    pub(crate) intervals: Vec<IntervalHydrationRow>,
    pub(crate) terminal_proofs: Vec<TerminalProofHydrationRow>,
    pub(crate) recovery_requests: Vec<RecoveryRequestHydrationRow>,
    pub(crate) recovery_reservations: Vec<RecoveryReservationHydrationRow>,
    pub(crate) reset_requests: Vec<ResetRequestHydrationRow>,
    pub(crate) leave_requests: Vec<LeaveRequestHydrationRow>,
    pub(crate) welcomes: Vec<WelcomeHydrationRow>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InvitationHydrationRow {
    pub(crate) transition: TransitionEvidence,
    pub(crate) inviter: DeviceIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ParticipantHydrationRow {
    pub(crate) principal: PrincipalId,
    pub(crate) status: ParticipantStatus,
    pub(crate) role: ParticipantRole,
    pub(crate) role_producer: Option<TransitionEvidence>,
    pub(crate) invitation: Option<InvitationHydrationRow>,
    pub(crate) acceptance: Option<TransitionEvidence>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LeafHydrationRow {
    pub(crate) device: DeviceIdentity,
    pub(crate) leaf_index: u32,
    pub(crate) basic_credential: Vec<u8>,
    pub(crate) signature_key: Vec<u8>,
    pub(crate) encryption_key: Vec<u8>,
    pub(crate) key_package_ref: Option<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IntervalEndHydrationRow {
    pub(crate) evidence: TransitionEvidence,
    pub(crate) kind: CloseKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IntervalHydrationRow {
    pub(crate) recipient: DeviceIdentity,
    pub(crate) generation: u64,
    pub(crate) opening: TransitionEvidence,
    pub(crate) opening_kind: OpeningKind,
    pub(crate) opening_context: PublicGroupSnapshotCoordinate,
    pub(crate) end: Option<IntervalEndHydrationRow>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TerminalProofHydrationRow {
    pub(crate) recipient: DeviceIdentity,
    pub(crate) conversation_id: [u8; 16],
    pub(crate) evidence: TransitionEvidence,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum WorkTerminalHydrationRow {
    Transition(TransitionEvidence),
    Request(RequestEvidence),
    DeviceRevocation(DeviceRevocationEvidence),
    Expiry(ServerTimestamp),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RecoveryOriginHydrationRow {
    Acceptance(TransitionEvidence),
    Request(RequestEvidence),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RecoveryRequestHydrationRow {
    pub(crate) request_id: [u8; 16],
    pub(crate) target: DeviceIdentity,
    pub(crate) kind: LeafRecoveryKind,
    pub(crate) source: RecoverySource,
    pub(crate) bound_coordinate: PublicGroupSnapshotCoordinate,
    pub(crate) key_package_ref: [u8; 32],
    pub(crate) received_at: ServerTimestamp,
    pub(crate) expires_at: ServerTimestamp,
    pub(crate) status: RecoveryRequestStatus,
    pub(crate) origin: RecoveryOriginHydrationRow,
    pub(crate) terminal: Option<WorkTerminalHydrationRow>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RecoveryReservationHydrationRow {
    pub(crate) request_id: [u8; 16],
    pub(crate) target: DeviceIdentity,
    pub(crate) bound_coordinate: PublicGroupSnapshotCoordinate,
    pub(crate) key_package_ref: [u8; 32],
    pub(crate) received_at: ServerTimestamp,
    pub(crate) expires_at: ServerTimestamp,
    pub(crate) package_not_after: ServerTimestamp,
    pub(crate) status: ReservationStatus,
    pub(crate) terminal: Option<WorkTerminalHydrationRow>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResetRequestHydrationRow {
    pub(crate) request_id: [u8; 16],
    pub(crate) requester: DeviceIdentity,
    pub(crate) bound_coordinate: PublicGroupSnapshotCoordinate,
    pub(crate) received_at: ServerTimestamp,
    pub(crate) expires_at: ServerTimestamp,
    pub(crate) status: ResetRequestStatus,
    pub(crate) origin: RequestEvidence,
    pub(crate) terminal: Option<WorkTerminalHydrationRow>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LeaveRequestHydrationRow {
    pub(crate) request_id: [u8; 16],
    pub(crate) requester: DeviceIdentity,
    pub(crate) bound_coordinate: PublicGroupSnapshotCoordinate,
    pub(crate) received_at: ServerTimestamp,
    pub(crate) expires_at: ServerTimestamp,
    pub(crate) status: LeaveRequestStatus,
    pub(crate) origin: RequestEvidence,
    pub(crate) terminal: Option<WorkTerminalHydrationRow>,
    pub(crate) fulfilled_participant: Option<ParticipantRemovalEvidence>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WelcomeHydrationRow {
    pub(crate) welcome_id: [u8; 16],
    pub(crate) recipient: DeviceIdentity,
    pub(crate) transition_seq: u64,
    pub(crate) coordinate: PublicGroupSnapshotCoordinate,
    pub(crate) recovery_request_id: [u8; 16],
    pub(crate) key_package_ref: [u8; 32],
    pub(crate) opaque_welcome: Vec<u8>,
    pub(crate) sha256: [u8; 32],
    pub(crate) expires_at: ServerTimestamp,
    pub(crate) status: WelcomeStatus,
    pub(crate) terminal: Option<WorkTerminalHydrationRow>,
}
