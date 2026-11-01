#![allow(unused_imports)]
use super::*;

impl TransitionEffects {
    pub(in crate::chat_protocol::state_machine) fn new(kind: PlanKind) -> Self {
        Self {
            kind,
            opened_intervals: Vec::new(),
            closed_intervals: Vec::new(),
            superseded_recovery_requests: Vec::new(),
            terminal_proof_recipients: Vec::new(),
            complete: false,
            before_counts: StateCounts::default(),
            after_counts: StateCounts::default(),
            metadata_change: None,
            policy_evidence_digest: None,
            participant_changes: Vec::new(),
            leaf_changes: Vec::new(),
            interval_changes: Vec::new(),
            terminal_proof_changes: Vec::new(),
            recovery_request_changes: Vec::new(),
            reservation_changes: Vec::new(),
            reset_request_changes: Vec::new(),
            leave_request_changes: Vec::new(),
            welcome_changes: Vec::new(),
            package_transitions: Vec::new(),
            recovery_package_cas: Vec::new(),
            revocation_package_cas: Vec::new(),
            revocation_target_cas: None,
            welcome_cas: None,
            invitation_quota_cas: None,
            authority: None,
            head_cas: None,
        }
    }

    pub(crate) fn kind(&self) -> PlanKind {
        self.kind
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.complete
    }

    pub(crate) fn opened_intervals(&self) -> &[DeviceIdentity] {
        &self.opened_intervals
    }

    pub(crate) fn closed_intervals(&self) -> &[DeviceIdentity] {
        &self.closed_intervals
    }

    pub(crate) fn superseded_recovery_requests(&self) -> &[[u8; 16]] {
        &self.superseded_recovery_requests
    }

    pub(crate) fn terminal_proof_recipients(&self) -> &[DeviceIdentity] {
        &self.terminal_proof_recipients
    }

    pub(crate) fn before_counts(&self) -> &StateCounts {
        &self.before_counts
    }

    pub(crate) fn after_counts(&self) -> &StateCounts {
        &self.after_counts
    }

    pub(crate) fn metadata_change(&self) -> Option<&StateChange<MetadataSnapshotBinding>> {
        self.metadata_change.as_ref()
    }

    pub(crate) fn policy_evidence_digest(&self) -> Option<&[u8; 32]> {
        self.policy_evidence_digest.as_ref()
    }

    pub(crate) fn participant_changes(&self) -> &[StateChange<ParticipantRecord>] {
        &self.participant_changes
    }

    pub(crate) fn leaf_changes(&self) -> &[StateChange<LeafRecord>] {
        &self.leaf_changes
    }

    pub(crate) fn interval_changes(&self) -> &[StateChange<AccessInterval>] {
        &self.interval_changes
    }

    pub(crate) fn terminal_proof_changes(&self) -> &[StateChange<ScheduleTerminalProof>] {
        &self.terminal_proof_changes
    }

    pub(crate) fn recovery_request_changes(&self) -> &[StateChange<RecoveryRequest>] {
        &self.recovery_request_changes
    }

    pub(crate) fn reservation_changes(&self) -> &[StateChange<RecoveryReservation>] {
        &self.reservation_changes
    }

    pub(crate) fn reset_request_changes(&self) -> &[StateChange<ResetRequest>] {
        &self.reset_request_changes
    }

    pub(crate) fn leave_request_changes(&self) -> &[StateChange<LeaveRequest>] {
        &self.leave_request_changes
    }

    pub(crate) fn welcome_changes(&self) -> &[StateChange<WelcomeWork>] {
        &self.welcome_changes
    }

    pub(crate) fn package_transitions(&self) -> &[PackageTransition] {
        &self.package_transitions
    }

    pub(crate) fn recovery_package_cas(&self) -> &[RecoveryPackageCasBinding] {
        &self.recovery_package_cas
    }

    pub(crate) fn revocation_package_cas(&self) -> &[RevocationPackageCasBinding] {
        &self.revocation_package_cas
    }

    pub(crate) fn revocation_target_cas(&self) -> Option<&RevocationTargetCasBinding> {
        self.revocation_target_cas.as_ref()
    }

    pub(crate) fn welcome_cas(&self) -> Option<&WelcomeCasBinding> {
        self.welcome_cas.as_ref()
    }

    pub(crate) fn invitation_quota_cas(&self) -> Option<&InvitationQuotaCasBinding> {
        self.invitation_quota_cas.as_ref()
    }

    pub(crate) fn authority(&self) -> Option<&PlanAuthority> {
        self.authority.as_ref()
    }

    pub(crate) fn head_cas(&self) -> Option<&ConversationHeadCasBinding> {
        self.head_cas.as_ref()
    }

    pub(in crate::chat_protocol::state_machine) fn complete(
        &mut self,
        before: Option<&ConversationState>,
        after: &ConversationState,
    ) {
        self.before_counts = before.map_or_else(StateCounts::default, state_counts);
        self.after_counts = state_counts(after);
        let before_metadata = before.and_then(|state| state.metadata.clone());
        if before_metadata != after.metadata {
            self.metadata_change = Some(StateChange {
                before: before_metadata,
                after: after.metadata.clone(),
            });
        }
        let empty_participants = &[][..];
        let empty_leaves = &[][..];
        let empty_intervals = &[][..];
        let empty_terminal_proofs = &[][..];
        let empty_recovery = &[][..];
        let empty_reservations = &[][..];
        let empty_resets = &[][..];
        let empty_leaves_requests = &[][..];
        let empty_welcomes = &[][..];
        let before_participants =
            before.map_or(empty_participants, |state| state.participants.as_slice());
        let before_leaves = before.map_or(empty_leaves, |state| state.leaves.as_slice());
        let before_intervals = before.map_or(empty_intervals, |state| state.intervals.as_slice());
        let before_terminal_proofs = before.map_or(empty_terminal_proofs, |state| {
            state.terminal_proofs.as_slice()
        });
        let before_recovery =
            before.map_or(empty_recovery, |state| state.recovery_requests.as_slice());
        let before_reservations = before.map_or(empty_reservations, |state| {
            state.recovery_reservations.as_slice()
        });
        let before_resets = before.map_or(empty_resets, |state| state.reset_requests.as_slice());
        let before_leave_requests = before.map_or(empty_leaves_requests, |state| {
            state.leave_requests.as_slice()
        });
        let before_welcomes = before.map_or(empty_welcomes, |state| state.welcomes.as_slice());

        self.participant_changes = diff_by_key(before_participants, &after.participants, |value| {
            value.principal.clone()
        });
        self.leaf_changes = diff_by_key(before_leaves, &after.leaves, |value| value.device.clone());
        self.interval_changes = diff_by_key(before_intervals, &after.intervals, |value| {
            (value.recipient.clone(), value.opening.seq)
        });
        self.terminal_proof_changes =
            diff_by_key(before_terminal_proofs, &after.terminal_proofs, |value| {
                value.recipient.clone()
            });
        self.recovery_request_changes =
            diff_by_key(before_recovery, &after.recovery_requests, |value| {
                value.request_id
            });
        self.reservation_changes =
            diff_by_key(before_reservations, &after.recovery_reservations, |value| {
                value.request_id
            });
        self.reset_request_changes = diff_by_key(before_resets, &after.reset_requests, |value| {
            value.request_id
        });
        self.leave_request_changes =
            diff_by_key(before_leave_requests, &after.leave_requests, |value| {
                value.request_id
            });
        self.welcome_changes =
            diff_by_key(before_welcomes, &after.welcomes, |value| value.welcome_id);
        self.package_transitions = package_transitions(&self.reservation_changes);
        self.complete = true;
    }
}

pub(in crate::chat_protocol::state_machine) fn complete_effects(
    mut effects: TransitionEffects,
    before: Option<&ConversationState>,
    after: &ConversationState,
) -> TransitionEffects {
    effects.complete(before, after);
    effects
}

pub(in crate::chat_protocol::state_machine) fn state_counts(
    state: &ConversationState,
) -> StateCounts {
    StateCounts {
        participants: state.participants.len(),
        pending_participants: state
            .participants
            .iter()
            .filter(|participant| participant.status == ParticipantStatus::Pending)
            .count(),
        active_participants: state
            .participants
            .iter()
            .filter(|participant| participant.status == ParticipantStatus::Active)
            .count(),
        active_admins: state
            .participants
            .iter()
            .filter(|participant| {
                participant.status == ParticipantStatus::Active
                    && participant.role == ParticipantRole::Admin
            })
            .count(),
        leaves: state.leaves.len(),
        intervals: state.intervals.len(),
        open_intervals: state
            .intervals
            .iter()
            .filter(|interval| interval.end.is_none())
            .count(),
        terminal_proofs: state.terminal_proofs.len(),
        open_recovery_requests: state
            .recovery_requests
            .iter()
            .filter(|request| request.status == RecoveryRequestStatus::Open)
            .count(),
        active_reservations: state
            .recovery_reservations
            .iter()
            .filter(|reservation| reservation.status == ReservationStatus::Active)
            .count(),
        pending_reset_requests: state
            .reset_requests
            .iter()
            .filter(|request| request.status == ResetRequestStatus::Pending)
            .count(),
        pending_leave_requests: state
            .leave_requests
            .iter()
            .filter(|request| request.status == LeaveRequestStatus::Pending)
            .count(),
        pending_welcomes: state
            .welcomes
            .iter()
            .filter(|welcome| welcome.status == WelcomeStatus::Pending)
            .count(),
    }
}

pub(in crate::chat_protocol::state_machine) fn diff_by_key<T, K, F>(
    before: &[T],
    after: &[T],
    key: F,
) -> Vec<StateChange<T>>
where
    T: Clone + PartialEq,
    K: Clone + Ord,
    F: Fn(&T) -> K,
{
    let keys = before
        .iter()
        .map(&key)
        .chain(after.iter().map(&key))
        .collect::<BTreeSet<_>>();
    keys.into_iter()
        .filter_map(|item_key| {
            let before = before.iter().find(|value| key(value) == item_key).cloned();
            let after = after.iter().find(|value| key(value) == item_key).cloned();
            (before != after).then_some(StateChange { before, after })
        })
        .collect()
}

pub(in crate::chat_protocol::state_machine) fn package_transitions(
    reservation_changes: &[StateChange<RecoveryReservation>],
) -> Vec<PackageTransition> {
    reservation_changes
        .iter()
        .filter_map(|change| match (&change.before, &change.after) {
            (None, Some(after)) if after.status == ReservationStatus::Active => {
                Some(PackageTransition {
                    request_id: after.request_id,
                    key_package_ref: after.key_package_ref,
                    from: PackageStatus::Available,
                    to: PackageStatus::Reserved,
                })
            }
            (Some(before), Some(after))
                if before.status == ReservationStatus::Active
                    && after.status != ReservationStatus::Active =>
            {
                let terminal_time = after
                    .terminal
                    .as_ref()
                    .map(work_terminal_time)
                    .unwrap_or(after.expires_at);
                let to = match after.status {
                    ReservationStatus::Consumed => PackageStatus::Consumed,
                    ReservationStatus::Expired | ReservationStatus::Released
                        if matches!(
                            after.terminal.as_ref(),
                            Some(WorkTerminalEvidence::DeviceRevocation(_))
                        ) =>
                    {
                        PackageStatus::Revoked
                    }
                    ReservationStatus::Expired | ReservationStatus::Released
                        if terminal_time >= after.package_not_after =>
                    {
                        PackageStatus::Expired
                    }
                    ReservationStatus::Expired | ReservationStatus::Released => {
                        PackageStatus::Available
                    }
                    ReservationStatus::Active => return None,
                };
                Some(PackageTransition {
                    request_id: after.request_id,
                    key_package_ref: after.key_package_ref,
                    from: PackageStatus::Reserved,
                    to,
                })
            }
            _ => None,
        })
        .collect()
}

pub(in crate::chat_protocol::state_machine) fn package_cas_bijection_valid(
    effects: &TransitionEffects,
) -> bool {
    let Some(head) = effects.head_cas.as_ref() else {
        return false;
    };
    effects.package_transitions.len() == effects.recovery_package_cas.len()
        && effects.package_transitions.iter().all(|edge| {
            effects
                .recovery_package_cas
                .iter()
                .filter(|binding| {
                    binding.transaction_id == head.transaction_id
                        && binding.request_id == edge.request_id
                        && binding.key_package_ref == edge.key_package_ref
                        && binding.expected_status == edge.from
                        && binding.successor_status == edge.to
                })
                .count()
                == 1
        })
        && effects.recovery_package_cas.iter().all(|binding| {
            binding.authority_digest == recovery_package_cas_authority_digest(binding)
                && binding.locked_row_digest != [0; 32]
                && effects
                    .package_transitions
                    .iter()
                    .filter(|edge| {
                        binding.request_id == edge.request_id
                            && binding.key_package_ref == edge.key_package_ref
                            && binding.expected_status == edge.from
                            && binding.successor_status == edge.to
                    })
                    .count()
                    == 1
        })
}

pub(in crate::chat_protocol::state_machine) fn revocation_package_cas_bijection_valid(
    effects: &TransitionEffects,
) -> bool {
    let Some(head) = effects.head_cas.as_ref() else {
        return false;
    };
    effects.recovery_package_cas.is_empty()
        && effects.package_transitions.len() == effects.revocation_package_cas.len()
        && effects.package_transitions.iter().all(|edge| {
            edge.from == PackageStatus::Reserved
                && edge.to == PackageStatus::Revoked
                && effects
                    .revocation_package_cas
                    .iter()
                    .filter(|binding| {
                        binding.transaction_id == head.transaction_id
                            && binding.conversation_id == Some(head.conversation_id)
                            && binding.request_id == Some(edge.request_id)
                            && binding.key_package_ref == edge.key_package_ref
                            && binding.expected_status == edge.from
                            && binding.successor_status == edge.to
                    })
                    .count()
                    == 1
        })
        && effects.revocation_package_cas.iter().all(|binding| {
            effects
                .package_transitions
                .iter()
                .filter(|edge| {
                    binding.request_id == Some(edge.request_id)
                        && binding.key_package_ref == edge.key_package_ref
                        && binding.expected_status == edge.from
                        && binding.successor_status == edge.to
                })
                .count()
                == 1
        })
}

pub(in crate::chat_protocol::state_machine) fn work_terminal_time(
    evidence: &WorkTerminalEvidence,
) -> ServerTimestamp {
    match evidence {
        WorkTerminalEvidence::Transition(value) => value.received_at,
        WorkTerminalEvidence::Request(value) => value.received_at,
        WorkTerminalEvidence::DeviceRevocation(value) => value.accepted_at,
        WorkTerminalEvidence::Expiry(value) => *value,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PlannedTransition {
    pub(in crate::chat_protocol::state_machine) expected_prior:
        Option<PublicGroupSnapshotCoordinate>,
    pub(in crate::chat_protocol::state_machine) retired_coordinate:
        Option<PublicGroupSnapshotCoordinate>,
    pub(in crate::chat_protocol::state_machine) successor_coordinate:
        Option<PublicGroupSnapshotCoordinate>,
    pub(in crate::chat_protocol::state_machine) state: ConversationState,
    pub(in crate::chat_protocol::state_machine) effects: TransitionEffects,
}

/// Exhaustive adapter-facing write plan. The graph projection and its complete
/// delta originate from the same validated successor and must be committed in
/// one transaction after the conversation-head CAS succeeds.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(Clone))]
pub(crate) struct ConversationPersistencePlan {
    pub(in crate::chat_protocol::state_machine) expected_prior:
        Option<PublicGroupSnapshotCoordinate>,
    pub(in crate::chat_protocol::state_machine) retired_coordinate:
        Option<PublicGroupSnapshotCoordinate>,
    pub(in crate::chat_protocol::state_machine) successor_coordinate:
        Option<PublicGroupSnapshotCoordinate>,
    pub(in crate::chat_protocol::state_machine) state: ConversationStateHydration,
    pub(in crate::chat_protocol::state_machine) effects: TransitionEffects,
}

impl DeviceRevocationBatchPersistencePlan {
    pub(crate) fn authority(&self) -> &DeviceRevocationEvidence {
        &self.authority
    }
    pub(crate) fn target_cas(&self) -> &RevocationTargetCasBinding {
        &self.target_cas
    }
    pub(crate) fn revoked_packages(&self) -> &[RevocationPackageCasBinding] {
        &self.revoked_packages
    }
    pub(crate) fn authority_scope_digest(&self) -> &[u8; 32] {
        &self.authority_scope_digest
    }
    pub(crate) fn fanout_manifest_digest(&self) -> &[u8; 32] {
        &self.fanout_manifest_digest
    }
    pub(crate) fn conversations(&self) -> &[ConversationPersistencePlan] {
        &self.conversations
    }
    pub(crate) fn into_parts(
        self,
    ) -> (
        DeviceRevocationEvidence,
        RevocationTargetCasBinding,
        Vec<RevocationPackageCasBinding>,
        [u8; 32],
        Vec<ConversationPersistencePlan>,
    ) {
        (
            self.authority,
            self.target_cas,
            self.revoked_packages,
            self.fanout_manifest_digest,
            self.conversations,
        )
    }

    /// Assemble a batch plan from its parts for the executor batch test (the
    /// production constructor `plan_device_revocation_batch` consumes repository
    /// lock guards). The `fanout_manifest_digest` is a provenance placeholder.
    #[cfg(test)]
    pub(crate) fn for_test(
        authority: DeviceRevocationEvidence,
        target_cas: RevocationTargetCasBinding,
        revoked_packages: Vec<RevocationPackageCasBinding>,
        conversations: Vec<ConversationPersistencePlan>,
    ) -> Self {
        Self {
            authority,
            target_cas,
            revoked_packages,
            authority_scope_digest: [1u8; 32],
            fanout_manifest_digest: [1u8; 32],
            conversations,
        }
    }
}

impl ConversationPersistencePlan {
    pub(crate) fn expected_prior(&self) -> Option<&PublicGroupSnapshotCoordinate> {
        self.expected_prior.as_ref()
    }

    pub(crate) fn retired_coordinate(&self) -> Option<&PublicGroupSnapshotCoordinate> {
        self.retired_coordinate.as_ref()
    }

    pub(crate) fn successor_coordinate(&self) -> Option<&PublicGroupSnapshotCoordinate> {
        self.successor_coordinate.as_ref()
    }

    pub(crate) fn state(&self) -> &ConversationStateHydration {
        &self.state
    }

    pub(crate) fn effects(&self) -> &TransitionEffects {
        &self.effects
    }
}

/// Closed Recovery persistence-plan classification retained beside the digest.
/// `ClientExpiry` and `SchedulerExpiry` intentionally share `Expiry`: the
/// repository witness owns that caller-class distinction and cross-binds it to
/// this fingerprint without widening the state-machine plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryPlanClass {
    Request,
    Cancellation,
    Fulfillment,
    Expiry,
}

/// Version 1 canonical digest of a complete Recovery persistence plan.
///
/// The inner bytes are deliberately private.  Callers can retain and compare a
/// state-machine-issued value, but cannot substitute an untyped digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RecoveryPlanFingerprint {
    pub(in crate::chat_protocol::state_machine) digest: [u8; 32],
    pub(in crate::chat_protocol::state_machine) class: RecoveryPlanClass,
}

impl RecoveryPlanFingerprint {
    pub(crate) fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub(crate) fn class(&self) -> RecoveryPlanClass {
        self.class
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryPlanFingerprintError {
    UnsupportedShape,
    MissingAcceptedControl,
    UnexpectedAcceptedControl,
}

/// Canonicalize and seal one closed Recovery write plan.
///
/// Every scalar is framed as `u64_be(length) || bytes`; collections additionally
/// commit their element count, and options commit an explicit presence byte.
/// This is a private protocol encoding, not serde/Debug output.
pub(crate) fn recovery_plan_fingerprint(
    plan: &ConversationPersistencePlan,
    accepted_control_entry_bytes: Option<&[u8]>,
) -> Result<RecoveryPlanFingerprint, StateMachineError> {
    let class = classify_recovery_plan_shape(plan, accepted_control_entry_bytes)
        .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
    let mut encoder = RecoveryPlanEncoder::new();
    encoder.bytes(b"CATBIRD-CHAT-RECOVERY-PERSISTENCE-PLAN");
    encoder.u64(1);
    encoder.u8(recovery_plan_class_code(class));
    encoder.option(plan.expected_prior.as_ref(), |encoder, value| {
        encoder.coordinate(value)
    });
    encoder.option(plan.retired_coordinate.as_ref(), |encoder, value| {
        encoder.coordinate(value)
    });
    encoder.option(plan.successor_coordinate.as_ref(), |encoder, value| {
        encoder.coordinate(value)
    });
    encoder.option(accepted_control_entry_bytes, |encoder, bytes| {
        encoder.bytes(&<[u8; 32]>::from(Sha256::digest(bytes)));
    });
    encoder.state_hydration(&plan.state);
    encoder.transition_effects(&plan.effects);
    Ok(RecoveryPlanFingerprint {
        class,
        digest: encoder.finish(),
    })
}

pub(in crate::chat_protocol::state_machine) fn recovery_plan_class_code(
    class: RecoveryPlanClass,
) -> u8 {
    match class {
        RecoveryPlanClass::Request => 1,
        RecoveryPlanClass::Cancellation => 2,
        RecoveryPlanClass::Fulfillment => 3,
        RecoveryPlanClass::Expiry => 4,
    }
}

pub(in crate::chat_protocol::state_machine) fn classify_recovery_plan_shape(
    plan: &ConversationPersistencePlan,
    accepted_control_entry_bytes: Option<&[u8]>,
) -> Result<RecoveryPlanClass, RecoveryPlanFingerprintError> {
    let effects = &plan.effects;
    let head = effects
        .head_cas
        .as_ref()
        .ok_or(RecoveryPlanFingerprintError::UnsupportedShape)?;
    let expected = plan
        .expected_prior
        .as_ref()
        .ok_or(RecoveryPlanFingerprintError::UnsupportedShape)?;
    if plan.retired_coordinate.is_some()
        || head.expected_prior.as_ref() != Some(expected)
        || head.conversation_id != *expected.conversation_id()
        || plan.state.coordinate.conversation_id() != expected.conversation_id()
        || !effects.complete
        || !package_cas_bijection_valid(effects)
        || !effects.revocation_package_cas.is_empty()
        || effects.revocation_target_cas.is_some()
        || effects.welcome_cas.is_some()
        || effects.invitation_quota_cas.is_some()
        || !effects.participant_changes.is_empty()
        || !effects.terminal_proof_changes.is_empty()
    {
        return Err(RecoveryPlanFingerprintError::UnsupportedShape);
    }

    let coordinate_unchanged = plan.successor_coordinate.as_ref() == Some(expected)
        && plan.state.coordinate == *expected
        && head.allocated_entry_id.is_none()
        && head.allocated_seq.is_none()
        && head.successor_next_entry_seq == head.expected_next_entry_seq;
    let entryless_families_absent = effects.metadata_change.is_none()
        && effects.leaf_changes.is_empty()
        && effects.interval_changes.is_empty()
        && effects.reset_request_changes.is_empty()
        && effects.leave_request_changes.is_empty()
        && effects.welcome_changes.is_empty()
        && effects.opened_intervals.is_empty()
        && effects.closed_intervals.is_empty()
        && effects.superseded_recovery_requests.is_empty()
        && effects.terminal_proof_recipients.is_empty();

    let class = match (&effects.kind, effects.authority.as_ref()) {
        (PlanKind::RecoveryRequest, Some(PlanAuthority::Request(authority)))
            if authority.kind == RequestEntryKind::LeafRecoveryRequest
                && authority.conversation_id == head.conversation_id
                && coordinate_unchanged
                && entryless_families_absent
                && effects
                    .policy_evidence_digest
                    .is_some_and(|digest| digest != [0; 32])
                && effects.recovery_request_changes.len() == 1
                && effects.reservation_changes.len() == 1
                && effects.package_transitions.len() == 1
                && exact_recovery_request_edge(
                    &effects.recovery_request_changes[0],
                    None,
                    RecoveryRequestStatus::Open,
                )
                && effects.recovery_request_changes[0]
                    .after
                    .as_ref()
                    .is_some_and(|request| {
                        request.request_id == authority.request_id
                            && request.target == authority.actor
                            && request.bound_coordinate == *expected
                    })
                && exact_reservation_edge(
                    &effects.reservation_changes[0],
                    None,
                    ReservationStatus::Active,
                )
                && effects.package_transitions[0].from == PackageStatus::Available
                && effects.package_transitions[0].to == PackageStatus::Reserved =>
        {
            RecoveryPlanClass::Request
        }
        (PlanKind::RecoveryCancellation, Some(PlanAuthority::Request(authority)))
            if authority.kind == RequestEntryKind::LeafRecoveryCancellation
                && authority.conversation_id == head.conversation_id
                && coordinate_unchanged
                && entryless_families_absent
                && effects.policy_evidence_digest.is_none()
                && effects.recovery_request_changes.len() == 1
                && effects.reservation_changes.len() == 1
                && effects.package_transitions.len() == 1
                && exact_recovery_request_edge(
                    &effects.recovery_request_changes[0],
                    Some(RecoveryRequestStatus::Open),
                    RecoveryRequestStatus::Cancelled,
                )
                && effects.recovery_request_changes[0]
                    .after
                    .as_ref()
                    .is_some_and(|request| {
                        request.request_id == authority.request_id
                            && request.target == authority.actor
                    })
                && exact_reservation_edge(
                    &effects.reservation_changes[0],
                    Some(ReservationStatus::Active),
                    ReservationStatus::Released,
                )
                && effects.package_transitions[0].from == PackageStatus::Reserved
                && matches!(
                    effects.package_transitions[0].to,
                    PackageStatus::Available | PackageStatus::Expired
                ) =>
        {
            RecoveryPlanClass::Cancellation
        }
        (PlanKind::RecoveryExpiry, Some(PlanAuthority::RecoveryExpiry(authority)))
            if coordinate_unchanged
                && entryless_families_absent
                && effects.policy_evidence_digest.is_none()
                && effects.recovery_request_changes.len() == 1
                && effects.reservation_changes.len() == 1
                && effects.package_transitions.len() == 1
                && exact_recovery_request_edge(
                    &effects.recovery_request_changes[0],
                    Some(RecoveryRequestStatus::Open),
                    RecoveryRequestStatus::Expired,
                )
                && effects.recovery_request_changes[0]
                    .after
                    .as_ref()
                    .is_some_and(|request| {
                        request.request_id == authority.request_id
                            && request.target == authority.requester
                    })
                && exact_reservation_edge(
                    &effects.reservation_changes[0],
                    Some(ReservationStatus::Active),
                    ReservationStatus::Expired,
                )
                && effects.package_transitions[0].request_id == authority.request_id
                && effects.package_transitions[0].from == PackageStatus::Reserved
                && matches!(
                    effects.package_transitions[0].to,
                    PackageStatus::Available | PackageStatus::Expired
                ) =>
        {
            RecoveryPlanClass::Expiry
        }
        (PlanKind::Commit, Some(PlanAuthority::Transition(authority)))
            if authority.authority.as_ref().is_some_and(|signed| {
                signed.kind == SignedMutationKind::LeafRecoveryFulfillment
            }) && matches!(
                authority.body_binding,
                Some(TransitionBodyBinding::LeafRecoveryFulfillment { .. })
            ) && plan.successor_coordinate.as_ref() == Some(&plan.state.coordinate)
                && plan.state.coordinate.conversation_id() == expected.conversation_id()
                && head.allocated_entry_id == Some(authority.transition_id)
                && head.allocated_seq == Some(authority.seq)
                && head.expected_next_entry_seq.checked_add(1)
                    == Some(head.successor_next_entry_seq)
                && effects
                    .policy_evidence_digest
                    .is_some_and(|digest| digest != [0; 32])
                && effects
                    .metadata_change
                    .as_ref()
                    .and_then(StateChange::after)
                    .is_some()
                && !effects.leaf_changes.is_empty()
                && !effects.interval_changes.is_empty()
                && fulfillment_fingerprint_families_are_closed(effects, authority) =>
        {
            RecoveryPlanClass::Fulfillment
        }
        _ => return Err(RecoveryPlanFingerprintError::UnsupportedShape),
    };

    match (class, accepted_control_entry_bytes) {
        (RecoveryPlanClass::Fulfillment, None) => {
            return Err(RecoveryPlanFingerprintError::MissingAcceptedControl)
        }
        (RecoveryPlanClass::Fulfillment, Some(bytes)) if bytes.is_empty() => {
            return Err(RecoveryPlanFingerprintError::MissingAcceptedControl)
        }
        (RecoveryPlanClass::Fulfillment, Some(_)) => {}
        (_, Some(_)) => return Err(RecoveryPlanFingerprintError::UnexpectedAcceptedControl),
        (_, None) => {}
    }
    Ok(class)
}
