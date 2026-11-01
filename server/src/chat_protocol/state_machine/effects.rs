#![allow(unused_imports)]
use super::*;

impl PlannedTransition {
    #[cfg(test)]
    pub(crate) fn expected_prior(&self) -> Option<&PublicGroupSnapshotCoordinate> {
        self.expected_prior.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn retired_coordinate(&self) -> Option<&PublicGroupSnapshotCoordinate> {
        self.retired_coordinate.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn successor_coordinate(&self) -> Option<&PublicGroupSnapshotCoordinate> {
        self.successor_coordinate.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn resulting_state(&self) -> &ConversationState {
        &self.state
    }

    #[cfg(test)]
    pub(crate) fn effects(&self) -> &TransitionEffects {
        &self.effects
    }

    #[cfg(test)]
    pub(crate) fn into_state(self) -> ConversationState {
        self.state
    }

    pub(crate) fn bind_transition_authority(
        mut self,
        evidence: TransitionEvidence,
        head: &LockedConversationHeadGuard,
        registration_transaction_id: &str,
        registration_trusted_at: ServerTimestamp,
    ) -> Result<Self, StateMachineError> {
        let authority = evidence
            .authority
            .as_ref()
            .ok_or(StateMachineError::InvalidHydrationAuthority)?;
        let entry_id = authority
            .control_entry_id
            .ok_or(StateMachineError::InvalidHydrationAuthority)?;
        let conversation_id = authority
            .control_conversation_id
            .ok_or(StateMachineError::InvalidHydrationAuthority)?;
        let locked_at = ServerTimestamp::from_unix_millis(head.locked_at().timestamp_millis())?;
        let successor_next_entry_seq = evidence
            .seq
            .checked_add(1)
            .filter(|value| *value <= MAX_PROTOCOL_INTEGER)
            .ok_or(StateMachineError::CoordinateOverflow)?;

        if head.transaction_id() != registration_transaction_id
            || head.conversation_id().as_bytes() != &conversation_id
            || self.state.coordinate.conversation_id() != &conversation_id
            || head.prior_coordinate() != self.expected_prior.as_ref()
            || head.next_entry_seq() != evidence.seq
            || locked_at != registration_trusted_at
            || locked_at != evidence.received_at
            || head.durable_row_digest() == &[0; 32]
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }

        self.effects.authority = Some(PlanAuthority::Transition(evidence));
        self.effects.head_cas = Some(ConversationHeadCasBinding {
            transaction_id: head.transaction_id().to_owned(),
            conversation_id,
            expected_prior: self.expected_prior,
            expected_next_entry_seq: head.next_entry_seq(),
            allocated_entry_id: Some(entry_id),
            allocated_seq: Some(head.next_entry_seq()),
            successor_next_entry_seq,
            locked_at,
            locked_head_digest: *head.durable_row_digest(),
        });
        Ok(self)
    }

    pub(in crate::chat_protocol) fn bind_historical_transition_authority(
        self,
        witness: HistoricalPlanWitness,
        evidence: TransitionEvidence,
        head: &LockedConversationHeadGuard,
        package_cas: Option<RecoveryPackageCasBinding>,
    ) -> Result<ConversationPersistencePlan, StateMachineError> {
        let locked_at = ServerTimestamp::from_unix_millis(head.locked_at().timestamp_millis())?;
        let mut planned =
            self.bind_transition_authority(evidence, head, head.transaction_id(), locked_at)?;
        if let Some(cas) = package_cas {
            planned = planned.bind_recovery_package_cas(cas)?;
        }
        planned.into_historical_persistence_plan(witness)
    }

    pub(in crate::chat_protocol) fn into_historical_persistence_plan(
        self,
        witness: HistoricalPlanWitness,
    ) -> Result<ConversationPersistencePlan, StateMachineError> {
        if self
            .effects
            .head_cas
            .as_ref()
            .and_then(|h| h.allocated_entry_id)
            != Some(*witness.source_entry_id.as_bytes())
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let welcome_authority_valid =
            match self.effects.kind {
                PlanKind::WelcomeAcknowledgement => {
                    matches!(
                        self.effects.authority.as_ref(),
                        Some(PlanAuthority::Request(evidence))
                            if evidence.kind == RequestEntryKind::WelcomeAcknowledgement
                    ) && self.effects.welcome_cas.as_ref().is_some_and(|binding| {
                        binding.successor_status == WelcomeStatus::Acknowledged
                    })
                }
                PlanKind::WelcomeRejection => {
                    matches!(
                        self.effects.authority.as_ref(),
                        Some(PlanAuthority::Request(evidence))
                            if evidence.kind == RequestEntryKind::WelcomeRejection
                    ) && self
                        .effects
                        .welcome_cas
                        .as_ref()
                        .is_some_and(|binding| binding.successor_status == WelcomeStatus::Rejected)
                }
                PlanKind::WelcomeExpiry => {
                    matches!(
                        self.effects.authority.as_ref(),
                        Some(PlanAuthority::WelcomeExpiry(_))
                    ) && self
                        .effects
                        .welcome_cas
                        .as_ref()
                        .is_some_and(|binding| binding.successor_status == WelcomeStatus::Expired)
                }
                _ => self.effects.welcome_cas.is_none(),
            };
        // Under the sealed historical path, Creation and Policy MUST NOT carry present-day invitation quota CAS.
        if self.effects.authority.is_none()
            || self.effects.head_cas.is_none()
            || !welcome_authority_valid
            || self.effects.invitation_quota_cas.is_some()
            || !package_cas_bijection_valid(&self.effects)
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        Ok(ConversationPersistencePlan {
            expected_prior: self.expected_prior,
            retired_coordinate: self.retired_coordinate,
            successor_coordinate: self.successor_coordinate,
            state: ConversationStateHydration::from_state(self.state),
            effects: self.effects,
        })
    }

    pub(in crate::chat_protocol::state_machine) fn bind_control_request_authority(
        mut self,
        evidence: RequestEvidence,
        head: &LockedConversationHeadGuard,
        registration_transaction_id: &str,
        registration_trusted_at: ServerTimestamp,
    ) -> Result<Self, StateMachineError> {
        let entry_id = evidence
            .control_entry_id
            .ok_or(StateMachineError::InvalidHydrationAuthority)?;
        let seq = evidence
            .control_seq
            .ok_or(StateMachineError::InvalidHydrationAuthority)?;
        if evidence.authority.is_none() {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let locked_at = ServerTimestamp::from_unix_millis(head.locked_at().timestamp_millis())?;
        let successor_next_entry_seq = seq
            .checked_add(1)
            .filter(|value| *value <= MAX_PROTOCOL_INTEGER)
            .ok_or(StateMachineError::CoordinateOverflow)?;
        if head.transaction_id() != registration_transaction_id
            || head.conversation_id().as_bytes() != &evidence.conversation_id
            || self.state.coordinate.conversation_id() != &evidence.conversation_id
            || head.prior_coordinate() != self.expected_prior.as_ref()
            || head.next_entry_seq() != seq
            || locked_at != registration_trusted_at
            || locked_at != evidence.received_at
            || head.durable_row_digest() == &[0; 32]
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        self.effects.authority = Some(PlanAuthority::Request(evidence));
        self.effects.head_cas = Some(ConversationHeadCasBinding {
            transaction_id: head.transaction_id().to_owned(),
            conversation_id: *head.conversation_id().as_bytes(),
            expected_prior: self.expected_prior,
            expected_next_entry_seq: seq,
            allocated_entry_id: Some(entry_id),
            allocated_seq: Some(seq),
            successor_next_entry_seq,
            locked_at,
            locked_head_digest: *head.durable_row_digest(),
        });
        Ok(self)
    }

    pub(in crate::chat_protocol::state_machine) fn bind_non_control_request_authority(
        mut self,
        evidence: RequestEvidence,
        head: &LockedConversationHeadGuard,
        registration_transaction_id: &str,
        registration_trusted_at: ServerTimestamp,
    ) -> Result<Self, StateMachineError> {
        let locked_at = ServerTimestamp::from_unix_millis(head.locked_at().timestamp_millis())?;
        if evidence.control_entry_id.is_some()
            || evidence.control_seq.is_some()
            || evidence.authority.is_none()
            || evidence.conversation_id != *self.state.coordinate.conversation_id()
            || head.transaction_id() != registration_transaction_id
            || head.conversation_id().as_bytes() != &evidence.conversation_id
            || head.prior_coordinate() != self.expected_prior.as_ref()
            || locked_at != registration_trusted_at
            || locked_at != evidence.received_at
            || head.durable_row_digest() == &[0; 32]
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let conversation_id = evidence.conversation_id;
        self.effects.authority = Some(PlanAuthority::Request(evidence));
        self.effects.head_cas = Some(ConversationHeadCasBinding {
            transaction_id: head.transaction_id().to_owned(),
            conversation_id,
            expected_prior: self.expected_prior,
            expected_next_entry_seq: head.next_entry_seq(),
            allocated_entry_id: None,
            allocated_seq: None,
            successor_next_entry_seq: head.next_entry_seq(),
            locked_at,
            locked_head_digest: *head.durable_row_digest(),
        });
        Ok(self)
    }

    pub(in crate::chat_protocol::state_machine) fn bind_device_revocation_authority(
        mut self,
        evidence: DeviceRevocationEvidence,
        head: &LockedConversationHeadGuard,
        transaction_id: &str,
        locked_at: ServerTimestamp,
    ) -> Result<Self, StateMachineError> {
        let head_locked_at =
            ServerTimestamp::from_unix_millis(head.locked_at().timestamp_millis())?;
        if head.transaction_id() != transaction_id
            || head.conversation_id().as_bytes() != self.state.coordinate.conversation_id()
            || head.prior_coordinate() != self.expected_prior.as_ref()
            || head_locked_at != locked_at
            || head_locked_at != evidence.accepted_at
            || head.durable_row_digest() == &[0; 32]
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        self.effects.authority = Some(PlanAuthority::DeviceRevocation(evidence));
        self.effects.head_cas = Some(ConversationHeadCasBinding {
            transaction_id: head.transaction_id().to_owned(),
            conversation_id: *head.conversation_id().as_bytes(),
            expected_prior: self.expected_prior,
            expected_next_entry_seq: head.next_entry_seq(),
            allocated_entry_id: None,
            allocated_seq: None,
            successor_next_entry_seq: head.next_entry_seq(),
            locked_at: head_locked_at,
            locked_head_digest: *head.durable_row_digest(),
        });
        Ok(self)
    }

    pub(in crate::chat_protocol::state_machine) fn bind_welcome_expiry_authority(
        mut self,
        evidence: WelcomeExpiryAuthority,
        head: &LockedConversationHeadGuard,
        transaction_id: &str,
    ) -> Result<Self, StateMachineError> {
        let locked_at = ServerTimestamp::from_unix_millis(head.locked_at().timestamp_millis())?;
        if head.transaction_id() != transaction_id
            || head.conversation_id().as_bytes() != self.state.coordinate.conversation_id()
            || head.prior_coordinate() != self.expected_prior.as_ref()
            || locked_at != evidence.observed_at
            || evidence.observed_at < evidence.terminal_at
            || evidence.locked_row_digest == [0; 32]
            || head.durable_row_digest() == &[0; 32]
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        self.effects.authority = Some(PlanAuthority::WelcomeExpiry(evidence));
        self.effects.head_cas = Some(ConversationHeadCasBinding {
            transaction_id: head.transaction_id().to_owned(),
            conversation_id: *head.conversation_id().as_bytes(),
            expected_prior: self.expected_prior,
            expected_next_entry_seq: head.next_entry_seq(),
            allocated_entry_id: None,
            allocated_seq: None,
            successor_next_entry_seq: head.next_entry_seq(),
            locked_at,
            locked_head_digest: *head.durable_row_digest(),
        });
        Ok(self)
    }

    pub(in crate::chat_protocol::state_machine) fn bind_recovery_expiry_authority(
        mut self,
        evidence: RecoveryExpiryPlanAuthority,
        head: &LockedConversationHeadGuard,
        package: LockedRecoveryPackageGuard,
    ) -> Result<Self, StateMachineError> {
        let locked_at = ServerTimestamp::from_unix_millis(head.locked_at().timestamp_millis())?;
        let prior = self
            .expected_prior
            .as_ref()
            .ok_or(StateMachineError::InvalidHydrationAuthority)?;
        let (request, expired_request) = self
            .effects
            .recovery_request_changes
            .iter()
            .find_map(
                |change| match (change.before.as_ref(), change.after.as_ref()) {
                    (Some(before), Some(after))
                        if before.request_id == *evidence.request_id()
                            && before.status == RecoveryRequestStatus::Open
                            && after.status == RecoveryRequestStatus::Expired =>
                    {
                        Some((before, after))
                    }
                    _ => None,
                },
            )
            .ok_or(StateMachineError::InvalidHydrationAuthority)?;
        let (reservation, expired_reservation) = self
            .effects
            .reservation_changes
            .iter()
            .find_map(
                |change| match (change.before.as_ref(), change.after.as_ref()) {
                    (Some(before), Some(after))
                        if before.request_id == *evidence.request_id()
                            && before.status == ReservationStatus::Active
                            && after.status == ReservationStatus::Expired =>
                    {
                        Some((before, after))
                    }
                    _ => None,
                },
            )
            .ok_or(StateMachineError::InvalidHydrationAuthority)?;
        let edge = self
            .effects
            .package_transitions
            .iter()
            .find(|edge| edge.request_id == *evidence.request_id())
            .ok_or(StateMachineError::InvalidHydrationAuthority)?;
        if head.conversation_id().as_bytes() != prior.conversation_id()
            || head.prior_coordinate() != Some(prior)
            || locked_at != evidence.observed_at
            || evidence.observed_at < evidence.terminal_at
            || evidence.locked_read_set_digest == [0; 32]
            || request.target != evidence.requester
            || request.expires_at != evidence.terminal_at
            || expired_request.target != request.target
            || expired_request.expires_at != request.expires_at
            || reservation.target != request.target
            || reservation.key_package_ref != request.key_package_ref
            || reservation.expires_at != request.expires_at
            || expired_reservation.target != reservation.target
            || expired_reservation.expires_at != reservation.expires_at
            || edge.from != PackageStatus::Reserved
            || !matches!(edge.to, PackageStatus::Available | PackageStatus::Expired)
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let package_cas = reserved_package_cas_for_request(
            package,
            request,
            reservation,
            head.transaction_id(),
            edge.to,
        )?;
        self.effects.authority = Some(PlanAuthority::RecoveryExpiry(evidence));
        self.effects.head_cas = Some(ConversationHeadCasBinding {
            transaction_id: head.transaction_id().to_owned(),
            conversation_id: *head.conversation_id().as_bytes(),
            expected_prior: self.expected_prior,
            expected_next_entry_seq: head.next_entry_seq(),
            allocated_entry_id: None,
            allocated_seq: None,
            successor_next_entry_seq: head.next_entry_seq(),
            locked_at,
            locked_head_digest: *head.durable_row_digest(),
        });
        self.bind_recovery_package_cas(package_cas)
    }

    pub(in crate::chat_protocol::state_machine) fn bind_welcome_cas(
        mut self,
        binding: WelcomeCasBinding,
    ) -> Result<Self, StateMachineError> {
        let exact_edge = self.effects.welcome_changes.iter().any(|change| {
            matches!(
                (change.before.as_ref(), change.after.as_ref()),
                (Some(before), Some(after))
                    if before.welcome_id == binding.welcome_id
                        && before.status == binding.expected_status
                        && after.status == binding.successor_status
                        && before.recipient == binding.recipient
                        && before.transition_seq == binding.transition_seq
                        && before.coordinate == binding.coordinate
                        && before.recovery_request_id == binding.recovery_request_id
                        && before.key_package_ref == binding.key_package_ref
                        && before.sha256 == binding.opaque_welcome_sha256
                        && before.expires_at == binding.expires_at
            )
        });
        if !exact_edge
            || self.effects.welcome_changes.len() != 1
            || self.effects.welcome_cas.is_some()
            || binding.expected_status != WelcomeStatus::Pending
            || binding.locked_row_digest == [0; 32]
            || !binding.verify_seal()
            || self.effects.head_cas.as_ref().is_none_or(|head| {
                head.transaction_id != binding.transaction_id
                    || head.conversation_id != binding.conversation_id
                    || head.locked_at != binding.locked_at
            })
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        self.effects.welcome_cas = Some(binding);
        Ok(self)
    }

    pub(crate) fn bind_invitation_quota_cas(
        mut self,
        binding: InvitationQuotaCasBinding,
    ) -> Result<Self, StateMachineError> {
        let mut exact_new_recipients = self
            .effects
            .participant_changes
            .iter()
            .filter_map(
                |change| match (change.before.as_ref(), change.after.as_ref()) {
                    (None, Some(after)) if after.status == ParticipantStatus::Pending => {
                        Some(after.principal.clone())
                    }
                    _ => None,
                },
            )
            .collect::<Vec<_>>();
        exact_new_recipients.sort();
        let recipient_facts_valid = invitation_quota_recipient_facts_valid(&binding);
        if !matches!(self.effects.kind, PlanKind::Creation | PlanKind::Policy)
            || self.effects.invitation_quota_cas.is_some()
            || exact_new_recipients != binding.new_recipients
            || binding.expected_inviter_recent_24h > MAX_PROTOCOL_INTEGER
            || binding.successor_inviter_recent_24h
                != binding
                    .expected_inviter_recent_24h
                    .checked_add(binding.new_recipients.len() as u64)
                    .ok_or(StateMachineError::InvalidHydrationAuthority)?
            || binding.inviter_limit != 100
            || binding.successor_inviter_recent_24h > binding.inviter_limit
            || !recipient_facts_valid
            || binding.locked_row_digest == [0; 32]
            || self.effects.head_cas.as_ref().is_none_or(|head| {
                head.transaction_id != binding.transaction_id || head.locked_at != binding.locked_at
            })
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        self.effects.invitation_quota_cas = Some(binding);
        Ok(self)
    }

    pub(in crate::chat_protocol::state_machine) fn into_revocation_batch_member_plan(
        self,
    ) -> Result<ConversationPersistencePlan, StateMachineError> {
        if !matches!(
            self.effects.authority.as_ref(),
            Some(PlanAuthority::DeviceRevocation(_))
        ) || self.effects.head_cas.is_none()
            || !revocation_package_cas_bijection_valid(&self.effects)
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        Ok(ConversationPersistencePlan {
            expected_prior: self.expected_prior,
            retired_coordinate: self.retired_coordinate,
            successor_coordinate: self.successor_coordinate,
            state: ConversationStateHydration::from_state(self.state),
            effects: self.effects,
        })
    }

    pub(in crate::chat_protocol::state_machine) fn bind_revocation_package_cas(
        mut self,
        binding: RevocationPackageCasBinding,
    ) -> Result<Self, StateMachineError> {
        let matches_semantic_edge = binding.expected_status == PackageStatus::Reserved
            && binding.successor_status == PackageStatus::Revoked
            && binding.conversation_id.is_some()
            && binding.request_id.is_some()
            && self.effects.package_transitions.iter().any(|edge| {
                Some(edge.request_id) == binding.request_id
                    && edge.key_package_ref == binding.key_package_ref
                    && edge.from == binding.expected_status
                    && edge.to == binding.successor_status
            });
        if !matches_semantic_edge
            || binding.revocation_request_digest == [0; 32]
            || binding.revocation_row_digest == [0; 32]
            || binding.locked_row_digest == [0; 32]
            || self.effects.head_cas.as_ref().is_none_or(|head| {
                head.transaction_id != binding.transaction_id
                    || Some(head.conversation_id) != binding.conversation_id
                    || head.locked_at != binding.revoked_at
            })
            || !matches!(
                self.effects.authority.as_ref(),
                Some(PlanAuthority::DeviceRevocation(evidence))
                    if evidence.target == binding.target
                        && evidence.expected_target_auth_generation
                            == binding.target_auth_generation
                        && evidence.revocation_id == binding.revocation_id
                        && evidence.accepted_at == binding.revoked_at
                        && evidence.request_digest == binding.revocation_request_digest
                        && evidence.durable_row_digest == binding.revocation_row_digest
            )
            || self.effects.revocation_package_cas.iter().any(|existing| {
                existing.key_package_ref == binding.key_package_ref
                    || existing.request_id == binding.request_id
            })
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        self.effects.revocation_package_cas.push(binding);
        Ok(self)
    }

    pub(crate) fn bind_recovery_package_cas(
        mut self,
        binding: RecoveryPackageCasBinding,
    ) -> Result<Self, StateMachineError> {
        let matches_semantic_edge = self.effects.package_transitions.iter().any(|edge| {
            edge.request_id == binding.request_id
                && edge.key_package_ref == binding.key_package_ref
                && edge.from == binding.expected_status
                && edge.to == binding.successor_status
        });
        if !matches_semantic_edge
            || self
                .effects
                .head_cas
                .as_ref()
                .is_some_and(|head| head.transaction_id != binding.transaction_id)
            || binding.locked_row_digest == [0; 32]
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        self.effects.recovery_package_cas.push(binding);
        Ok(self)
    }

    pub(in crate::chat_protocol::state_machine) fn bind_terminal_package_guards(
        mut self,
        prior: &ConversationState,
        mut guards: Vec<LockedRecoveryPackageGuard>,
        transaction_id: &str,
    ) -> Result<Self, StateMachineError> {
        guards.sort_by(|left, right| {
            left.request_id()
                .as_bytes()
                .cmp(right.request_id().as_bytes())
        });
        let missing_edges = self
            .effects
            .package_transitions
            .iter()
            .filter(|edge| {
                edge.from == PackageStatus::Reserved
                    && !self.effects.recovery_package_cas.iter().any(|binding| {
                        binding.request_id == edge.request_id
                            && binding.key_package_ref == edge.key_package_ref
                            && binding.expected_status == edge.from
                            && binding.successor_status == edge.to
                    })
            })
            .cloned()
            .collect::<Vec<_>>();
        if missing_edges.len() != guards.len() {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        for guard in guards {
            let request_id = *guard.request_id().as_bytes();
            let edge = missing_edges
                .iter()
                .find(|edge| edge.request_id == request_id)
                .ok_or(StateMachineError::InvalidHydrationAuthority)?;
            let request = prior
                .recovery_request(&request_id)
                .ok_or(StateMachineError::InvalidHydrationAuthority)?;
            let reservation = prior
                .recovery_reservation(&request_id)
                .ok_or(StateMachineError::InvalidHydrationAuthority)?;
            let binding = reserved_package_cas_for_request(
                guard,
                request,
                reservation,
                transaction_id,
                edge.to,
            )?;
            self.effects.recovery_package_cas.push(binding);
        }
        if !package_cas_bijection_valid(&self.effects) {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        Ok(self)
    }

    pub(crate) fn into_persistence_plan(
        self,
    ) -> Result<ConversationPersistencePlan, StateMachineError> {
        let welcome_authority_valid =
            match self.effects.kind {
                PlanKind::WelcomeAcknowledgement => {
                    matches!(
                        self.effects.authority.as_ref(),
                        Some(PlanAuthority::Request(evidence))
                            if evidence.kind == RequestEntryKind::WelcomeAcknowledgement
                    ) && self.effects.welcome_cas.as_ref().is_some_and(|binding| {
                        binding.successor_status == WelcomeStatus::Acknowledged
                    })
                }
                PlanKind::WelcomeRejection => {
                    matches!(
                        self.effects.authority.as_ref(),
                        Some(PlanAuthority::Request(evidence))
                            if evidence.kind == RequestEntryKind::WelcomeRejection
                    ) && self
                        .effects
                        .welcome_cas
                        .as_ref()
                        .is_some_and(|binding| binding.successor_status == WelcomeStatus::Rejected)
                }
                PlanKind::WelcomeExpiry => {
                    matches!(
                        self.effects.authority.as_ref(),
                        Some(PlanAuthority::WelcomeExpiry(_))
                    ) && self
                        .effects
                        .welcome_cas
                        .as_ref()
                        .is_some_and(|binding| binding.successor_status == WelcomeStatus::Expired)
                }
                _ => self.effects.welcome_cas.is_none(),
            };
        let invitation_quota_valid = match self.effects.kind {
            PlanKind::Creation | PlanKind::Policy => self.effects.invitation_quota_cas.is_some(),
            _ => self.effects.invitation_quota_cas.is_none(),
        };
        if self.effects.authority.is_none()
            || self.effects.head_cas.is_none()
            || !package_cas_bijection_valid(&self.effects)
            || !welcome_authority_valid
            || !invitation_quota_valid
            || (matches!(
                self.effects.authority.as_ref(),
                Some(PlanAuthority::DeviceRevocation(_))
            ) && self.effects.revocation_target_cas.is_none())
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        Ok(ConversationPersistencePlan {
            expected_prior: self.expected_prior,
            retired_coordinate: self.retired_coordinate,
            successor_coordinate: self.successor_coordinate,
            state: ConversationStateHydration::from_state(self.state),
            effects: self.effects,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CreationDecision {
    Create(PlannedTransition),
    ExistingDirect {
        conversation_id: [u8; 16],
        coordinate: PublicGroupSnapshotCoordinate,
    },
}

pub(crate) struct CreationCommand {
    pub(crate) kind: ConversationKind,
    pub(crate) creator: DeviceIdentity,
    pub(crate) invitees: Vec<PrincipalId>,
    pub(crate) transition: TransitionEvidence,
    pub(crate) public_state: ActivePublicState,
}

pub(crate) fn plan_creation_inner(
    existing_direct: Option<&ConversationState>,
    command: CreationCommand,
) -> Result<CreationDecision, StateMachineError> {
    require_transition_kind(&command.transition, SignedMutationKind::Creation)?;
    require_transition_actor(&command.transition, &command.creator)?;
    validate_creation_command(&command)?;
    require_creation_body(
        &command.transition,
        command.kind,
        &command.creator,
        &command.invitees,
        &command.public_state,
    )?;
    let proposed_pair = if command.kind == ConversationKind::Direct {
        Some(canonical_pair(
            command.creator.principal(),
            command
                .invitees
                .first()
                .ok_or(StateMachineError::InvalidCreation)?,
        ))
    } else {
        None
    };

    if let Some(existing) = existing_direct {
        if existing.kind == ConversationKind::Direct
            && existing.coordinate.lifecycle() == PublicGroupSnapshotLifecycle::Active
            && existing_direct_pair(existing).as_ref() == proposed_pair.as_ref()
        {
            return Ok(CreationDecision::ExistingDirect {
                conversation_id: *existing.coordinate.conversation_id(),
                coordinate: existing.coordinate,
            });
        }
        if existing.coordinate.lifecycle() == PublicGroupSnapshotLifecycle::Active {
            return Err(StateMachineError::ExistingConversationConflict);
        }
    }

    let creator_leaf = singleton_genesis_leaf(&command.public_state, &command.creator)?;
    let invitation = InvitationProvenance {
        transition: command.transition.clone(),
        inviter: command.creator.clone(),
    };
    let mut participants = Vec::with_capacity(command.invitees.len() + 1);
    participants.push(ParticipantRecord {
        principal: command.creator.principal.clone(),
        status: ParticipantStatus::Active,
        role: ParticipantRole::Admin,
        role_producer: None,
        invitation: None,
        acceptance: None,
    });
    participants.extend(
        command
            .invitees
            .into_iter()
            .map(|principal| ParticipantRecord {
                principal,
                status: ParticipantStatus::Pending,
                role: if command.kind == ConversationKind::Direct {
                    ParticipantRole::Admin
                } else {
                    ParticipantRole::Member
                },
                role_producer: None,
                invitation: Some(invitation.clone()),
                acceptance: None,
            }),
    );
    participants.sort_by(|left, right| left.principal.cmp(&right.principal));

    let coordinate = *command.public_state.coordinate();
    let intervals = vec![AccessInterval {
        recipient: command.creator.clone(),
        generation: coordinate.generation(),
        opening: command.transition.clone(),
        opening_kind: OpeningKind::Creation,
        opening_context: coordinate,
        end: None,
    }];
    let metadata = transition_metadata(&command.transition).cloned();
    let state = ConversationState {
        kind: command.kind,
        coordinate,
        producer: command.transition.clone(),
        public_state: Some(command.public_state),
        metadata_producer: metadata.as_ref().map(|_| command.transition.clone()),
        metadata,
        participants,
        leaves: vec![creator_leaf],
        intervals,
        terminal_proofs: Vec::new(),
        recovery_requests: Vec::new(),
        recovery_reservations: Vec::new(),
        reset_requests: Vec::new(),
        leave_requests: Vec::new(),
        welcomes: Vec::new(),
    };
    validate_state(&state)?;
    let mut effects = TransitionEffects::new(PlanKind::Creation);
    effects.opened_intervals.push(command.creator);
    effects.complete(None, &state);
    Ok(CreationDecision::Create(PlannedTransition {
        expected_prior: None,
        retired_coordinate: None,
        successor_coordinate: Some(coordinate),
        state,
        effects,
    }))
}

pub(in crate::chat_protocol::state_machine) fn validate_creation_command(
    command: &CreationCommand,
) -> Result<(), StateMachineError> {
    let coordinate = command.public_state.coordinate();
    if coordinate.generation() != 0
        || coordinate.state_version() != 0
        || coordinate.epoch() != 0
        || coordinate.lifecycle() != PublicGroupSnapshotLifecycle::Active
        || command.invitees.len() + 1 > MAX_PARTICIPANTS
        || command.invitees.windows(2).any(|pair| pair[0] >= pair[1])
        || command
            .invitees
            .iter()
            .any(|invitee| invitee == command.creator.principal())
        || (command.kind == ConversationKind::Direct && command.invitees.len() != 1)
    {
        return Err(StateMachineError::InvalidCreation);
    }
    Ok(())
}

pub(in crate::chat_protocol::state_machine) fn canonical_pair(
    left: &PrincipalId,
    right: &PrincipalId,
) -> (PrincipalId, PrincipalId) {
    if left <= right {
        (left.clone(), right.clone())
    } else {
        (right.clone(), left.clone())
    }
}

pub(in crate::chat_protocol::state_machine) fn existing_direct_pair(
    state: &ConversationState,
) -> Option<(PrincipalId, PrincipalId)> {
    let [left, right] = state.participants.as_slice() else {
        return None;
    };
    Some(canonical_pair(&left.principal, &right.principal))
}

pub(in crate::chat_protocol::state_machine) fn singleton_genesis_leaf(
    public_state: &ActivePublicState,
    actor: &DeviceIdentity,
) -> Result<LeafRecord, StateMachineError> {
    let [leaf] = public_state.binding().tree_summary().leaves() else {
        return Err(StateMachineError::InvalidPublicState);
    };
    if leaf.basic_credential() != actor.basic_credential() {
        return Err(StateMachineError::InvalidPublicState);
    }
    Ok(LeafRecord {
        device: actor.clone(),
        leaf_index: leaf.leaf_index(),
        basic_credential: leaf.basic_credential().to_vec(),
        signature_key: leaf.signature_key().to_vec(),
        encryption_key: leaf.encryption_key().to_vec(),
        key_package_ref: None,
    })
}

pub(crate) struct PolicyCommand {
    pub(crate) actor: DeviceIdentity,
    pub(crate) transition: TransitionEvidence,
    pub(crate) relationship_evidence_digest: [u8; 32],
}
