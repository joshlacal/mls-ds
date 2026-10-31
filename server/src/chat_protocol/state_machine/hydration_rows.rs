#![allow(unused_imports)]
use super::*;


impl RecoveryPlanEncoder {
    pub(in crate::chat_protocol::state_machine) fn public_state(&mut self, value: &ActivePublicState) {
        self.coordinate(value.coordinate());
        self.bytes(value.snapshot());
        self.bytes(value.snapshot_sha256());
        let tree = value.binding().tree_summary();
        self.bytes(tree.tree_hash());
        self.slice(tree.leaves(), |encoder, leaf| {
            encoder.u32(leaf.leaf_index());
            encoder.bytes(leaf.basic_credential());
            encoder.bytes(leaf.signature_key());
            encoder.bytes(leaf.encryption_key());
        });
        self.option(value.verified_group_info_sha256(), |encoder, value| {
            encoder.bytes(value)
        });
        self.option(
            value.verified_group_info_signature_key(),
            |encoder, value| encoder.bytes(value),
        );
    }

    pub(in crate::chat_protocol::state_machine) fn participant_hydration(&mut self, value: &ParticipantHydrationRow) {
        self.bytes(value.principal.as_bytes());
        self.u8(participant_status_code(value.status));
        self.u8(participant_role_code(value.role));
        self.option(value.role_producer.as_ref(), Self::transition);
        self.option(value.invitation.as_ref(), |encoder, invitation| {
            encoder.transition(&invitation.transition);
            encoder.device(&invitation.inviter);
        });
        self.option(value.acceptance.as_ref(), Self::transition);
    }

    pub(in crate::chat_protocol::state_machine) fn leaf_hydration(&mut self, value: &LeafHydrationRow) {
        self.device(&value.device);
        self.u32(value.leaf_index);
        self.bytes(&value.basic_credential);
        self.bytes(&value.signature_key);
        self.bytes(&value.encryption_key);
        self.option(value.key_package_ref.as_ref(), |encoder, value| {
            encoder.bytes(value)
        });
    }

    pub(in crate::chat_protocol::state_machine) fn interval_hydration(&mut self, value: &IntervalHydrationRow) {
        self.device(&value.recipient);
        self.u64(value.generation);
        self.transition(&value.opening);
        self.u8(opening_kind_code(value.opening_kind));
        self.coordinate(&value.opening_context);
        self.option(value.end.as_ref(), |encoder, end| {
            encoder.transition(&end.evidence);
            encoder.u8(close_kind_code(end.kind));
        });
    }

    pub(in crate::chat_protocol::state_machine) fn terminal_proof_hydration(&mut self, value: &TerminalProofHydrationRow) {
        self.device(&value.recipient);
        self.bytes(&value.conversation_id);
        self.transition(&value.evidence);
    }

    pub(in crate::chat_protocol::state_machine) fn work_terminal_hydration(&mut self, value: &WorkTerminalHydrationRow) {
        match value {
            WorkTerminalHydrationRow::Transition(value) => {
                self.u8(1);
                self.transition(value);
            }
            WorkTerminalHydrationRow::Request(value) => {
                self.u8(2);
                self.request(value);
            }
            WorkTerminalHydrationRow::DeviceRevocation(value) => {
                self.u8(3);
                self.device_revocation(value);
            }
            WorkTerminalHydrationRow::Expiry(value) => {
                self.u8(4);
                self.timestamp(*value);
            }
        }
    }

    pub(in crate::chat_protocol::state_machine) fn recovery_request_hydration(&mut self, value: &RecoveryRequestHydrationRow) {
        self.bytes(&value.request_id);
        self.device(&value.target);
        self.u8(recovery_kind_code(value.kind));
        self.u8(recovery_source_code(value.source));
        self.coordinate(&value.bound_coordinate);
        self.bytes(&value.key_package_ref);
        self.timestamp(value.received_at);
        self.timestamp(value.expires_at);
        self.u8(recovery_request_status_code(value.status));
        match &value.origin {
            RecoveryOriginHydrationRow::Acceptance(value) => {
                self.u8(1);
                self.transition(value);
            }
            RecoveryOriginHydrationRow::Request(value) => {
                self.u8(2);
                self.request(value);
            }
        }
        self.option(value.terminal.as_ref(), Self::work_terminal_hydration);
    }

    pub(in crate::chat_protocol::state_machine) fn recovery_reservation_hydration(&mut self, value: &RecoveryReservationHydrationRow) {
        self.bytes(&value.request_id);
        self.device(&value.target);
        self.coordinate(&value.bound_coordinate);
        self.bytes(&value.key_package_ref);
        self.timestamp(value.received_at);
        self.timestamp(value.expires_at);
        self.timestamp(value.package_not_after);
        self.u8(reservation_status_code(value.status));
        self.option(value.terminal.as_ref(), Self::work_terminal_hydration);
    }

    pub(in crate::chat_protocol::state_machine) fn reset_hydration(&mut self, value: &ResetRequestHydrationRow) {
        self.bytes(&value.request_id);
        self.device(&value.requester);
        self.coordinate(&value.bound_coordinate);
        self.timestamp(value.received_at);
        self.timestamp(value.expires_at);
        self.u8(reset_request_status_code(value.status));
        self.request(&value.origin);
        self.option(value.terminal.as_ref(), Self::work_terminal_hydration);
    }

    pub(in crate::chat_protocol::state_machine) fn participant_removal(&mut self, value: &ParticipantRemovalEvidence) {
        self.participant_hydration(&value.participant_hydration());
        self.transition(value.terminal());
    }

    pub(in crate::chat_protocol::state_machine) fn leave_hydration(&mut self, value: &LeaveRequestHydrationRow) {
        self.bytes(&value.request_id);
        self.device(&value.requester);
        self.coordinate(&value.bound_coordinate);
        self.timestamp(value.received_at);
        self.timestamp(value.expires_at);
        self.u8(leave_request_status_code(value.status));
        self.request(&value.origin);
        self.option(value.terminal.as_ref(), Self::work_terminal_hydration);
        self.option(
            value.fulfilled_participant.as_ref(),
            Self::participant_removal,
        );
    }

    pub(in crate::chat_protocol::state_machine) fn welcome_hydration(&mut self, value: &WelcomeHydrationRow) {
        self.bytes(&value.welcome_id);
        self.device(&value.recipient);
        self.u64(value.transition_seq);
        self.coordinate(&value.coordinate);
        self.bytes(&value.recovery_request_id);
        self.bytes(&value.key_package_ref);
        self.bytes(&value.opaque_welcome);
        self.bytes(&value.sha256);
        self.timestamp(value.expires_at);
        self.u8(welcome_status_code(value.status));
        self.option(value.terminal.as_ref(), Self::work_terminal_hydration);
    }

    pub(in crate::chat_protocol::state_machine) fn state_hydration(&mut self, value: &ConversationStateHydration) {
        self.bytes(b"successor-state");
        self.u8(conversation_kind_code(value.kind));
        self.coordinate(&value.coordinate);
        self.transition(&value.producer);
        self.option(value.public_state.as_ref(), Self::public_state);
        self.option(value.metadata.as_ref(), Self::metadata);
        self.option(value.metadata_producer.as_ref(), Self::transition);
        self.slice(&value.participants, Self::participant_hydration);
        self.slice(&value.leaves, Self::leaf_hydration);
        self.slice(&value.intervals, Self::interval_hydration);
        self.slice(&value.terminal_proofs, Self::terminal_proof_hydration);
        self.slice(&value.recovery_requests, Self::recovery_request_hydration);
        self.slice(
            &value.recovery_reservations,
            Self::recovery_reservation_hydration,
        );
        self.slice(&value.reset_requests, Self::reset_hydration);
        self.slice(&value.leave_requests, Self::leave_hydration);
        self.slice(&value.welcomes, Self::welcome_hydration);
    }
}

impl RecoveryPlanEncoder {
    pub(in crate::chat_protocol::state_machine) fn work_terminal(&mut self, value: &WorkTerminalEvidence) {
        match value {
            WorkTerminalEvidence::Transition(value) => {
                self.u8(1);
                self.transition(value);
            }
            WorkTerminalEvidence::Request(value) => {
                self.u8(2);
                self.request(value);
            }
            WorkTerminalEvidence::DeviceRevocation(value) => {
                self.u8(3);
                self.device_revocation(value);
            }
            WorkTerminalEvidence::Expiry(value) => {
                self.u8(4);
                self.timestamp(*value);
            }
        }
    }

    pub(in crate::chat_protocol::state_machine) fn participant(&mut self, value: &ParticipantRecord) {
        self.bytes(value.principal.as_bytes());
        self.u8(participant_status_code(value.status));
        self.u8(participant_role_code(value.role));
        self.option(value.role_producer.as_ref(), Self::transition);
        self.option(value.invitation.as_ref(), |encoder, invitation| {
            encoder.transition(&invitation.transition);
            encoder.device(&invitation.inviter);
        });
        self.option(value.acceptance.as_ref(), Self::transition);
    }

    pub(in crate::chat_protocol::state_machine) fn leaf(&mut self, value: &LeafRecord) {
        self.device(&value.device);
        self.u32(value.leaf_index);
        self.bytes(&value.basic_credential);
        self.bytes(&value.signature_key);
        self.bytes(&value.encryption_key);
        self.option(value.key_package_ref.as_ref(), |encoder, value| {
            encoder.bytes(value)
        });
    }

    pub(in crate::chat_protocol::state_machine) fn interval(&mut self, value: &AccessInterval) {
        self.device(&value.recipient);
        self.u64(value.generation);
        self.transition(&value.opening);
        self.u8(opening_kind_code(value.opening_kind));
        self.coordinate(&value.opening_context);
        self.option(value.end.as_ref(), |encoder, end| {
            encoder.transition(&end.evidence);
            encoder.u8(close_kind_code(end.kind));
        });
    }

    pub(in crate::chat_protocol::state_machine) fn terminal_proof(&mut self, value: &ScheduleTerminalProof) {
        self.device(&value.recipient);
        self.bytes(&value.conversation_id);
        self.transition(&value.evidence);
    }

    pub(in crate::chat_protocol::state_machine) fn recovery_request(&mut self, value: &RecoveryRequest) {
        self.bytes(&value.request_id);
        self.device(&value.target);
        self.u8(recovery_kind_code(value.kind));
        self.u8(recovery_source_code(value.source));
        self.coordinate(&value.bound_coordinate);
        self.bytes(&value.key_package_ref);
        self.timestamp(value.received_at);
        self.timestamp(value.expires_at);
        self.u8(recovery_request_status_code(value.status));
        match &value.origin {
            RecoveryOriginEvidence::Acceptance(value) => {
                self.u8(1);
                self.transition(value);
            }
            RecoveryOriginEvidence::Request(value) => {
                self.u8(2);
                self.request(value);
            }
        }
        self.option(value.terminal.as_ref(), Self::work_terminal);
    }

    pub(in crate::chat_protocol::state_machine) fn recovery_reservation(&mut self, value: &RecoveryReservation) {
        self.bytes(&value.request_id);
        self.device(&value.target);
        self.coordinate(&value.bound_coordinate);
        self.bytes(&value.key_package_ref);
        self.timestamp(value.received_at);
        self.timestamp(value.expires_at);
        self.timestamp(value.package_not_after);
        self.u8(reservation_status_code(value.status));
        self.option(value.terminal.as_ref(), Self::work_terminal);
    }

    pub(in crate::chat_protocol::state_machine) fn reset_request(&mut self, value: &ResetRequest) {
        self.bytes(&value.request_id);
        self.device(&value.requester);
        self.coordinate(&value.bound_coordinate);
        self.timestamp(value.received_at);
        self.timestamp(value.expires_at);
        self.u8(reset_request_status_code(value.status));
        self.request(&value.origin);
        self.option(value.terminal.as_ref(), Self::work_terminal);
    }

    pub(in crate::chat_protocol::state_machine) fn leave_request(&mut self, value: &LeaveRequest) {
        self.bytes(&value.request_id);
        self.device(&value.requester);
        self.coordinate(&value.bound_coordinate);
        self.timestamp(value.received_at);
        self.timestamp(value.expires_at);
        self.u8(leave_request_status_code(value.status));
        self.request(&value.origin);
        self.option(value.terminal.as_ref(), Self::work_terminal);
        self.option(
            value.fulfilled_participant.as_ref(),
            Self::participant_removal,
        );
    }

    pub(in crate::chat_protocol::state_machine) fn welcome(&mut self, value: &WelcomeWork) {
        self.bytes(&value.welcome_id);
        self.device(&value.recipient);
        self.u64(value.transition_seq);
        self.coordinate(&value.coordinate);
        self.bytes(&value.recovery_request_id);
        self.bytes(&value.key_package_ref);
        self.bytes(&value.opaque_welcome);
        self.bytes(&value.sha256);
        self.timestamp(value.expires_at);
        self.u8(welcome_status_code(value.status));
        self.option(value.terminal.as_ref(), Self::work_terminal);
    }

    pub(in crate::chat_protocol::state_machine) fn state_counts(&mut self, value: &StateCounts) {
        self.usize(value.participants);
        self.usize(value.pending_participants);
        self.usize(value.active_participants);
        self.usize(value.active_admins);
        self.usize(value.leaves);
        self.usize(value.intervals);
        self.usize(value.open_intervals);
        self.usize(value.terminal_proofs);
        self.usize(value.open_recovery_requests);
        self.usize(value.active_reservations);
        self.usize(value.pending_reset_requests);
        self.usize(value.pending_leave_requests);
        self.usize(value.pending_welcomes);
    }

    pub(in crate::chat_protocol::state_machine) fn state_change<T>(&mut self, value: &StateChange<T>, mut encode: impl FnMut(&mut Self, &T)) {
        self.option(value.before.as_ref(), |encoder, value| {
            encode(encoder, value)
        });
        self.option(value.after.as_ref(), |encoder, value| {
            encode(encoder, value)
        });
    }

    pub(in crate::chat_protocol::state_machine) fn package_transition(&mut self, value: &PackageTransition) {
        self.bytes(&value.request_id);
        self.bytes(&value.key_package_ref);
        self.u8(package_status_code(value.from));
        self.u8(package_status_code(value.to));
    }

    pub(in crate::chat_protocol::state_machine) fn recovery_package_cas(&mut self, value: &RecoveryPackageCasBinding) {
        self.bytes(value.transaction_id.as_bytes());
        self.bytes(&value.conversation_id);
        self.bytes(&value.request_id);
        self.device(&value.target);
        self.bytes(&value.target_key_id);
        self.u64(value.target_auth_generation);
        self.coordinate(&value.bound_coordinate);
        self.bytes(&value.key_package_ref);
        self.bytes(&value.key_package_wrapper_sha256);
        self.timestamp(value.package_not_after);
        self.timestamp(value.claimed_at);
        self.u8(package_status_code(value.expected_status));
        self.u8(package_status_code(value.successor_status));
        self.bytes(&value.locked_row_digest);
        self.bytes(&value.authority_digest);
    }

    pub(in crate::chat_protocol::state_machine) fn revocation_package_cas(&mut self, value: &RevocationPackageCasBinding) {
        self.bytes(value.transaction_id.as_bytes());
        self.device(&value.target);
        self.bytes(&value.target_key_id);
        self.u64(value.target_auth_generation);
        self.bytes(&value.key_package_ref);
        self.bytes(&value.wrapper_sha256);
        self.timestamp(value.package_not_after);
        self.u8(package_status_code(value.expected_status));
        self.u8(package_status_code(value.successor_status));
        self.option(value.conversation_id.as_ref(), |encoder, value| {
            encoder.bytes(value)
        });
        self.option(value.request_id.as_ref(), |encoder, value| {
            encoder.bytes(value)
        });
        self.bytes(&value.revocation_id);
        self.timestamp(value.revoked_at);
        self.bytes(&value.revocation_request_digest);
        self.bytes(&value.revocation_row_digest);
        self.bytes(&value.locked_row_digest);
    }

    pub(in crate::chat_protocol::state_machine) fn revocation_target_cas(&mut self, value: &RevocationTargetCasBinding) {
        self.bytes(value.transaction_id.as_bytes());
        self.device(&value.target);
        self.u64(value.expected_auth_generation);
        self.u8(registration_status_code(value.expected_status));
        self.u8(registration_status_code(value.successor_status));
        self.timestamp(value.locked_at);
        self.bytes(&value.locked_row_digest);
    }

    pub(in crate::chat_protocol::state_machine) fn welcome_cas(&mut self, value: &WelcomeCasBinding) {
        self.bytes(value.transaction_id.as_bytes());
        self.bytes(&value.conversation_id);
        self.bytes(&value.welcome_id);
        self.device(&value.recipient);
        self.u64(value.transition_seq);
        self.coordinate(&value.coordinate);
        self.bytes(&value.recovery_request_id);
        self.bytes(&value.key_package_ref);
        self.bytes(&value.opaque_welcome_sha256);
        self.timestamp(value.expires_at);
        self.u8(welcome_status_code(value.expected_status));
        self.u8(welcome_status_code(value.successor_status));
        self.timestamp(value.locked_at);
        self.bytes(&value.locked_row_digest);
        self.bytes(&value.seal);
    }

    pub(in crate::chat_protocol::state_machine) fn invitation_quota_cas(&mut self, value: &InvitationQuotaCasBinding) {
        self.bytes(value.transaction_id.as_bytes());
        self.bytes(value.inviter.as_bytes());
        self.slice(&value.new_recipients, |encoder, value| {
            encoder.bytes(value.as_bytes())
        });
        self.u64(value.expected_inviter_recent_24h);
        self.u64(value.successor_inviter_recent_24h);
        self.u64(value.inviter_limit);
        self.slice(&value.recipient_facts, |encoder, value| {
            encoder.bytes(value.recipient.as_bytes());
            encoder.u64(value.expected_pair_live);
            encoder.u64(value.successor_pair_live);
            encoder.u64(value.pair_limit);
            encoder.u64(value.expected_recipient_live);
            encoder.u64(value.successor_recipient_live);
            encoder.u64(value.recipient_limit);
        });
        self.timestamp(value.locked_at);
        self.bytes(&value.locked_row_digest);
    }

    pub(in crate::chat_protocol::state_machine) fn head_cas(&mut self, value: &ConversationHeadCasBinding) {
        self.bytes(value.transaction_id.as_bytes());
        self.bytes(&value.conversation_id);
        self.option(value.expected_prior.as_ref(), Self::coordinate);
        self.u64(value.expected_next_entry_seq);
        self.option(value.allocated_entry_id.as_ref(), |encoder, value| {
            encoder.bytes(value)
        });
        self.option(value.allocated_seq.as_ref(), |encoder, value| {
            encoder.u64(*value)
        });
        self.u64(value.successor_next_entry_seq);
        self.timestamp(value.locked_at);
        self.bytes(&value.locked_head_digest);
    }

    pub(in crate::chat_protocol::state_machine) fn transition_effects(&mut self, value: &TransitionEffects) {
        self.bytes(b"transition-effects");
        self.u8(plan_kind_code(value.kind));
        self.slice(&value.opened_intervals, Self::device);
        self.slice(&value.closed_intervals, Self::device);
        self.slice(&value.superseded_recovery_requests, |encoder, value| {
            encoder.bytes(value)
        });
        self.slice(&value.terminal_proof_recipients, Self::device);
        self.bool(value.complete);
        self.state_counts(&value.before_counts);
        self.state_counts(&value.after_counts);
        self.option(value.metadata_change.as_ref(), |encoder, value| {
            encoder.state_change(value, Self::metadata)
        });
        self.option(value.policy_evidence_digest.as_ref(), |encoder, value| {
            encoder.bytes(value)
        });
        self.slice(&value.participant_changes, |encoder, value| {
            encoder.state_change(value, Self::participant)
        });
        self.slice(&value.leaf_changes, |encoder, value| {
            encoder.state_change(value, Self::leaf)
        });
        self.slice(&value.interval_changes, |encoder, value| {
            encoder.state_change(value, Self::interval)
        });
        self.slice(&value.terminal_proof_changes, |encoder, value| {
            encoder.state_change(value, Self::terminal_proof)
        });
        self.slice(&value.recovery_request_changes, |encoder, value| {
            encoder.state_change(value, Self::recovery_request)
        });
        self.slice(&value.reservation_changes, |encoder, value| {
            encoder.state_change(value, Self::recovery_reservation)
        });
        self.slice(&value.reset_request_changes, |encoder, value| {
            encoder.state_change(value, Self::reset_request)
        });
        self.slice(&value.leave_request_changes, |encoder, value| {
            encoder.state_change(value, Self::leave_request)
        });
        self.slice(&value.welcome_changes, |encoder, value| {
            encoder.state_change(value, Self::welcome)
        });
        self.slice(&value.package_transitions, Self::package_transition);
        self.slice(&value.recovery_package_cas, Self::recovery_package_cas);
        self.slice(&value.revocation_package_cas, Self::revocation_package_cas);
        self.option(
            value.revocation_target_cas.as_ref(),
            Self::revocation_target_cas,
        );
        self.option(value.welcome_cas.as_ref(), Self::welcome_cas);
        self.option(
            value.invitation_quota_cas.as_ref(),
            Self::invitation_quota_cas,
        );
        self.option(value.authority.as_ref(), Self::plan_authority);
        self.option(value.head_cas.as_ref(), Self::head_cas);
    }
}

pub(in crate::chat_protocol::state_machine) fn conversation_kind_code(value: ConversationKind) -> u8 {
    match value {
        ConversationKind::Direct => 1,
        ConversationKind::Group => 2,
    }
}

pub(in crate::chat_protocol::state_machine) fn opening_kind_code(value: OpeningKind) -> u8 {
    match value {
        OpeningKind::DirectRequest => 4,
        OpeningKind::Creation => 1,
        OpeningKind::Add => 2,
        OpeningKind::Reset => 3,
    }
}

pub(in crate::chat_protocol::state_machine) fn close_kind_code(value: CloseKind) -> u8 {
    match value {
        CloseKind::DirectRequest => 5,
        CloseKind::Remove => 1,
        CloseKind::Replace => 2,
        CloseKind::Reset => 3,
        CloseKind::Terminal => 4,
    }
}

pub(in crate::chat_protocol::state_machine) fn recovery_source_code(value: RecoverySource) -> u8 {
    match value {
        RecoverySource::Request => 1,
        RecoverySource::Acceptance => 2,
    }
}

pub(in crate::chat_protocol::state_machine) fn recovery_request_status_code(value: RecoveryRequestStatus) -> u8 {
    match value {
        RecoveryRequestStatus::Open => 1,
        RecoveryRequestStatus::Fulfilled => 2,
        RecoveryRequestStatus::Cancelled => 3,
        RecoveryRequestStatus::Expired => 4,
        RecoveryRequestStatus::Superseded => 5,
    }
}

pub(in crate::chat_protocol::state_machine) fn reservation_status_code(value: ReservationStatus) -> u8 {
    match value {
        ReservationStatus::Active => 1,
        ReservationStatus::Consumed => 2,
        ReservationStatus::Expired => 3,
        ReservationStatus::Released => 4,
    }
}

pub(in crate::chat_protocol::state_machine) fn reset_request_status_code(value: ResetRequestStatus) -> u8 {
    match value {
        ResetRequestStatus::Pending => 1,
        ResetRequestStatus::Stale => 2,
        ResetRequestStatus::Consumed => 3,
        ResetRequestStatus::Expired => 4,
        // Ratified 2026-08-15. The four codes above are unchanged, so every
        // digest over a row that is not `revoked` is byte-identical to before;
        // this EXTENDS the domain rather than renumbering it.
        ResetRequestStatus::Revoked => 5,
    }
}

pub(in crate::chat_protocol::state_machine) fn leave_request_status_code(value: LeaveRequestStatus) -> u8 {
    match value {
        LeaveRequestStatus::Pending => 1,
        LeaveRequestStatus::Fulfilled => 2,
        LeaveRequestStatus::Cancelled => 3,
        LeaveRequestStatus::Expired => 4,
        LeaveRequestStatus::Stale => 5,
    }
}

pub(in crate::chat_protocol::state_machine) fn package_status_code(value: PackageStatus) -> u8 {
    match value {
        PackageStatus::Available => 1,
        PackageStatus::Reserved => 2,
        PackageStatus::Consumed => 3,
        PackageStatus::Expired => 4,
        PackageStatus::Revoked => 5,
    }
}

pub(in crate::chat_protocol::state_machine) fn registration_status_code(value: PersistedRegistrationStatus) -> u8 {
    match value {
        PersistedRegistrationStatus::Active => 1,
        PersistedRegistrationStatus::Revoked => 2,
    }
}

pub(in crate::chat_protocol::state_machine) fn plan_kind_code(value: PlanKind) -> u8 {
    match value {
        PlanKind::Creation => 1,
        PlanKind::Policy => 2,
        PlanKind::Acceptance => 3,
        PlanKind::Metadata => 4,
        PlanKind::Commit => 5,
        PlanKind::RecoveryRequest => 6,
        PlanKind::RecoveryCancellation => 7,
        PlanKind::RecoveryExpiry => 8,
        PlanKind::DeviceRevocation => 9,
        PlanKind::ResetRequest => 10,
        PlanKind::ResetActivation => 11,
        PlanKind::LeaveRequest => 12,
        PlanKind::LeaveCancellation => 13,
        PlanKind::ZeroLeafLeave => 14,
        PlanKind::WelcomeAcknowledgement => 15,
        PlanKind::WelcomeRejection => 16,
        PlanKind::WelcomeExpiry => 17,
        PlanKind::Close => 18,
    }
}

pub(in crate::chat_protocol::state_machine) fn participant_status_code(value: ParticipantStatus) -> u8 {
    match value {
        ParticipantStatus::Pending => 1,
        ParticipantStatus::Active => 2,
    }
}

pub(in crate::chat_protocol::state_machine) fn participant_role_code(value: ParticipantRole) -> u8 {
    match value {
        ParticipantRole::Member => 1,
        ParticipantRole::Admin => 2,
    }
}

pub(in crate::chat_protocol::state_machine) fn recovery_kind_code(value: LeafRecoveryKind) -> u8 {
    match value {
        LeafRecoveryKind::Add => 1,
        LeafRecoveryKind::Replace => 2,
    }
}

pub(in crate::chat_protocol::state_machine) fn request_kind_code(value: RequestEntryKind) -> u8 {
    match value {
        RequestEntryKind::LeafRecoveryRequest => 1,
        RequestEntryKind::LeafRecoveryCancellation => 2,
        RequestEntryKind::ResetRequest => 3,
        RequestEntryKind::LeaveRequest => 4,
        RequestEntryKind::LeaveCancellation => 5,
        RequestEntryKind::WelcomeAcknowledgement => 6,
        RequestEntryKind::WelcomeRejection => 7,
    }
}

pub(in crate::chat_protocol::state_machine) fn signed_mutation_kind_code(value: SignedMutationKind) -> u8 {
    match value {
        SignedMutationKind::DirectRequestPublication => 26,
        SignedMutationKind::DirectRequestAcceptance => 27,
        SignedMutationKind::Creation => 1,
        SignedMutationKind::PolicyTransition => 2,
        SignedMutationKind::ParticipantAcceptance => 3,
        SignedMutationKind::MetadataTransition => 4,
        SignedMutationKind::CommitTransition => 5,
        SignedMutationKind::LeafRecoveryRequest => 6,
        SignedMutationKind::LeafRecoveryCancellation => 7,
        SignedMutationKind::ResetRequest => 8,
        SignedMutationKind::ResetActivation => 9,
        SignedMutationKind::LeaveRequest => 10,
        SignedMutationKind::LeaveCancellation => 11,
        SignedMutationKind::ZeroLeafLeave => 12,
        SignedMutationKind::LeaveCommitFulfillment => 13,
        SignedMutationKind::LeafRecoveryFulfillment => 14,
        SignedMutationKind::WelcomeAcknowledgement => 15,
        SignedMutationKind::WelcomeRejection => 16,
        SignedMutationKind::ConversationClose => 17,
        SignedMutationKind::DeviceRevocation => 18,
        SignedMutationKind::ApplicationSend => 19,
        SignedMutationKind::DeviceEnrollment => 20,
        SignedMutationKind::KeyPackageReplenishment => 21,
        SignedMutationKind::BlobUploadPreparation => 23,
        SignedMutationKind::BlobDeletion => 24,
        SignedMutationKind::Typing => 25,
    }
}

pub(in crate::chat_protocol::state_machine) fn invitation_quota_recipient_facts_valid(binding: &InvitationQuotaCasBinding) -> bool {
    binding.recipient_facts.len() == binding.new_recipients.len()
        && binding
            .recipient_facts
            .iter()
            .zip(&binding.new_recipients)
            .all(|(fact, recipient)| {
                fact.recipient == *recipient
                    && fact.expected_pair_live <= MAX_PROTOCOL_INTEGER
                    && fact.expected_recipient_live <= MAX_PROTOCOL_INTEGER
                    && fact.expected_pair_live.checked_add(1) == Some(fact.successor_pair_live)
                    && fact.expected_recipient_live.checked_add(1)
                        == Some(fact.successor_recipient_live)
                    && fact.pair_limit == 5
                    && fact.recipient_limit == 100
                    && fact.successor_pair_live <= fact.pair_limit
                    && fact.successor_recipient_live <= fact.recipient_limit
            })
}
