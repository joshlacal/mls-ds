#![allow(unused_imports)]
use super::*;

impl HydrationAuthority {
    /// Consume the exact signed Policy body and the complete relationship
    /// projection under the conversation lock. No caller-selected roster or
    /// participant-change command crosses this seam.
    pub(crate) fn plan_policy<T: PublicTransport>(
        &self,
        locked: &LockedConversationStateGuard,
        entry: VerifiedControlEntry,
        registration: &LockedRegistrationProjection,
        terminal_packages: Vec<LockedRecoveryPackageGuard>,
        relationship: &RelationshipProjection,
        relationship_authority: &RelationshipAuthority<T>,
        quota_guard: LockedInvitationQuotaGuard,
        relationship_decision: &LockedRelationshipDecisionGuard,
        trusted_now: &TrustedRequestInstant,
    ) -> Result<PlannedTransition, StateMachineError> {
        self.require_same_locked_conversation(locked)?;
        let prior = locked.state();
        let head = locked.head();
        let transition = self.transition_from_control(&entry)?;
        if !registration.authorizes_transition(&transition) {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let actor = registration.actor().clone();
        let authority = transition.clone();
        let plan = plan_policy_transition(
            prior,
            PolicyCommand {
                actor: actor.clone(),
                transition,
                relationship_evidence_digest: relationship.evidence_digest(),
            },
        )?;
        let roster = plan
            .state
            .participants
            .iter()
            .map(|participant| {
                String::from_utf8(participant.principal.as_bytes().to_vec())
                    .map_err(|_| StateMachineError::InvalidPolicyAuthority)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let pending_recipients = plan
            .effects
            .participant_changes
            .iter()
            .filter_map(|change| match (&change.before, &change.after) {
                (None, Some(after)) if after.status == ParticipantStatus::Pending => {
                    String::from_utf8(after.principal.as_bytes().to_vec()).ok()
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        let request = AdmissionRequest {
            inviter: String::from_utf8(actor.principal().as_bytes().to_vec())
                .map_err(|_| StateMachineError::InvalidPolicyAuthority)?,
            roster,
            pending_recipients,
            operation: AdmissionOperation::Group,
        };
        let quota_cas = invitation_quota_cas_from_guard(
            &quota_guard,
            actor.principal(),
            &request.pending_recipients,
            registration.transaction_id(),
            registration.trusted_read_at(),
        )?;
        consume_locked_pending_add_projection(
            relationship,
            relationship_decision,
            locked,
            &quota_guard,
            registration,
            &request,
            quota_guard.would_exceed(),
            relationship_authority,
        )
        .map_err(relationship_consumption_error)?;
        if registration.trusted_read_at()
            != ServerTimestamp::from_trusted_request_instant(trusted_now)?
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        plan.bind_transition_authority(
            authority,
            head,
            registration.transaction_id(),
            registration.trusted_read_at(),
        )?
        .bind_invitation_quota_cas(quota_cas)?
        .bind_terminal_package_guards(
            prior,
            terminal_packages,
            registration.transaction_id(),
        )
    }

    /// Closed Policy branch for mutations whose signed, deterministic
    /// participant delta adds nobody. The no-admission guard is repository
    /// minted from the same locked head/graph/registration/quota read-set.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn plan_policy_without_pending_admission(
        &self,
        locked: &LockedConversationStateGuard,
        entry: VerifiedControlEntry,
        registration: &LockedRegistrationProjection,
        terminal_packages: Vec<LockedRecoveryPackageGuard>,
        quota_guard: LockedInvitationQuotaGuard,
        no_admission: LockedNoPendingAdmissionGuard,
        trusted_now: &TrustedRequestInstant,
    ) -> Result<PlannedTransition, StateMachineError> {
        self.require_same_locked_conversation(locked)?;
        let prior = locked.state();
        let head = locked.head();
        let transition = self.transition_from_control(&entry)?;
        if !registration.authorizes_transition(&transition)
            || !no_admission.authorizes_non_add_policy(locked, &quota_guard, registration)
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        if matches!(
            transition.body_binding.as_ref(),
            Some(TransitionBodyBinding::Policy {
                participant_changes,
                ..
            }) if participant_changes
                .iter()
                .any(|change| matches!(change, ManifestParticipantChange::Add(_)))
        ) {
            return Err(StateMachineError::InvalidPolicyAuthority);
        }
        let actor = registration.actor().clone();
        let authority = transition.clone();
        let plan = plan_policy_transition(
            prior,
            PolicyCommand {
                actor: actor.clone(),
                transition,
                relationship_evidence_digest: no_admission.evidence_digest(),
            },
        )?;
        let pending_recipients = plan
            .effects
            .participant_changes
            .iter()
            .filter_map(|change| match (&change.before, &change.after) {
                (None, Some(after)) if after.status == ParticipantStatus::Pending => {
                    String::from_utf8(after.principal.as_bytes().to_vec()).ok()
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        if !pending_recipients.is_empty()
            || plan
                .effects
                .participant_changes
                .iter()
                .any(|change| matches!((&change.before, &change.after), (None, Some(_))))
        {
            return Err(StateMachineError::InvalidPolicyAuthority);
        }
        let quota_cas = invitation_quota_cas_from_guard(
            &quota_guard,
            actor.principal(),
            &pending_recipients,
            registration.transaction_id(),
            registration.trusted_read_at(),
        )?;
        if registration.trusted_read_at()
            != ServerTimestamp::from_trusted_request_instant(trusted_now)?
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        plan.bind_transition_authority(
            authority,
            head,
            registration.transaction_id(),
            registration.trusted_read_at(),
        )?
        .bind_invitation_quota_cas(quota_cas)?
        .bind_terminal_package_guards(
            prior,
            terminal_packages,
            registration.transaction_id(),
        )
    }

    /// Consume the exact ParticipantAcceptance control row together with the
    /// locked active registration, the exact locked KeyPackage selection, and
    /// the acceptance-scoped relationship projection.  The retained inviter
    /// remains the consent source and the accepting principal is the sole
    /// declaration recipient even though the successor marks them active.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn plan_acceptance_entry<T: PublicTransport>(
        &self,
        locked: &LockedConversationStateGuard,
        entry: VerifiedControlEntry,
        registration: LockedRegistrationProjection,
        reservation: LockedRecoveryReservationProjection,
        terminal_packages: Vec<LockedRecoveryPackageGuard>,
        relationship: &RelationshipProjection,
        relationship_authority: &RelationshipAuthority<T>,
        relationship_decision: &LockedRelationshipDecisionGuard,
        trusted_now: &TrustedRequestInstant,
    ) -> Result<PlannedTransition, StateMachineError> {
        self.require_same_locked_conversation(locked)?;
        let prior = locked.state();
        let head = locked.head();
        let transition = self.transition_from_control(&entry)?;
        if !registration.authorizes_transition(&transition)
            || !reservation.authorizes_acceptance(&transition)
            || registration.transaction_id() != reservation.transaction_id()
            || registration.trusted_read_at()
                != ServerTimestamp::from_trusted_request_instant(trusted_now)?
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let (recovery_request_id, invitation) = match transition.body_binding.as_ref() {
            Some(TransitionBodyBinding::Acceptance {
                recovery_request_id,
                invitation_provenance,
                ..
            }) => (*recovery_request_id, invitation_provenance),
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        };
        let actor = registration.actor().clone();
        let retained_invitation = prior
            .participant(actor.principal())
            .and_then(|participant| participant.invitation.as_ref())
            .ok_or(StateMachineError::InvitationNotPending)?;
        if retained_invitation.transition.transition_id != invitation.transition_id
            || retained_invitation.inviter != invitation.inviter
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let inviter =
            String::from_utf8(retained_invitation.inviter.principal().as_bytes().to_vec())
                .map_err(|_| StateMachineError::InvalidPolicyAuthority)?;
        let accepting_principal = String::from_utf8(actor.principal().as_bytes().to_vec())
            .map_err(|_| StateMachineError::InvalidPolicyAuthority)?;
        let roster = prior
            .participants
            .iter()
            .map(|participant| {
                String::from_utf8(participant.principal.as_bytes().to_vec())
                    .map_err(|_| StateMachineError::InvalidPolicyAuthority)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let relationship_request = AdmissionRequest {
            inviter,
            roster,
            pending_recipients: vec![accepting_principal],
            operation: if prior.kind == ConversationKind::Direct {
                AdmissionOperation::Direct
            } else {
                AdmissionOperation::Group
            },
        };
        consume_locked_acceptance_projection(
            relationship,
            relationship_decision,
            locked,
            &registration,
            &relationship_request,
            relationship_authority,
        )
        .map_err(relationship_consumption_error)?;
        let key_package_ref = *reservation.key_package_ref();
        let package_not_after = reservation.package_not_after();
        let package_cas = reservation.available_package_cas();
        let relationship_evidence_digest = relationship.evidence_digest();
        let transaction_id = registration.transaction_id().to_owned();
        let trusted_read_at = registration.trusted_read_at();
        let authority = transition.clone();
        let mut plan = plan_accept_conversation_inner(
            prior,
            AcceptConversation {
                actor,
                transition,
                recovery_request_id,
                key_package_ref,
                package_not_after,
            },
        )?;
        plan.effects.policy_evidence_digest = Some(relationship_evidence_digest);
        plan.bind_transition_authority(authority, head, &transaction_id, trusted_read_at)?
            .bind_recovery_package_cas(package_cas)?
            .bind_terminal_package_guards(prior, terminal_packages, &transaction_id)
    }

    /// Process only the generic Commit variant. Recovery and leave
    /// fulfillments have distinct sealed entry points below so their extra
    /// package, target-registration, consent, and work-row authorities cannot
    /// be bypassed by variant dispatch.
    pub(crate) fn plan_commit_entry(
        &self,
        locked: &LockedConversationStateGuard,
        entry: VerifiedControlEntry,
        registration: &LockedRegistrationProjection,
        terminal_packages: Vec<LockedRecoveryPackageGuard>,
    ) -> Result<PlannedTransition, StateMachineError> {
        self.require_same_locked_conversation(locked)?;
        let prior = locked.state();
        let head = locked.head();
        let (commit_bytes, aad, next) = match entry.mutation().projection() {
            VerifiedMutationProjection::CommitTransition(value) => (
                checked_artifact_bytes(&value.commit())?,
                commit_aad_bytes(&value.aad()),
                closed_coordinate(&value.next())?,
            ),
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        };
        let transition = self.transition_from_control(&entry)?;
        if !registration.authorizes_transition(&transition) {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let authority = transition.clone();
        let commit = process_commit(
            prior.public_state(),
            &commit_bytes,
            &aad,
            next,
            trusted_unix_millis_to_seconds(transition.received_at.unix_millis())
                .ok_or(StateMachineError::InvalidServerTime)?,
            MAX_PARTICIPANTS,
        )?;
        let plan = plan_commit_inner(
            prior,
            CommitCommand {
                actor: registration.actor().clone(),
                transition,
                commit,
            },
        )?;
        plan.bind_transition_authority(
            authority,
            head,
            registration.transaction_id(),
            registration.trusted_read_at(),
        )?
        .bind_terminal_package_guards(
            prior,
            terminal_packages,
            registration.transaction_id(),
        )
    }

    /// Final recovery Add: bind the committing actor, the target's current
    /// active registration, the exact reserved KeyPackage row, and a fresh
    /// complete block-only roster projection in one transaction.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn plan_recovery_fulfillment_entry<T: PublicTransport>(
        &self,
        locked: &LockedConversationStateGuard,
        entry: VerifiedControlEntry,
        actor_registration: &LockedRegistrationProjection,
        target_registration: &LockedRegistrationProjection,
        reserved_package: LockedRecoveryPackageGuard,
        terminal_packages: Vec<LockedRecoveryPackageGuard>,
        relationship: &RelationshipProjection,
        relationship_authority: &RelationshipAuthority<T>,
        relationship_decision: &LockedRelationshipDecisionGuard,
        trusted_now: &TrustedRequestInstant,
    ) -> Result<PlannedTransition, StateMachineError> {
        self.require_same_locked_conversation(locked)?;
        let prior = locked.state();
        let head = locked.head();
        let (request_id, commit_bytes, aad, next) = match entry.mutation().projection() {
            VerifiedMutationProjection::LeafRecoveryFulfillment(value) => (
                *value.recovery_request_id().as_bytes(),
                checked_artifact_bytes(&value.commit())?,
                commit_aad_bytes(&value.aad()),
                closed_coordinate(&value.next())?,
            ),
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        };
        let transition = self.transition_from_control(&entry)?;
        if !actor_registration.authorizes_transition(&transition)
            || actor_registration.transaction_id() != target_registration.transaction_id()
            || actor_registration.trusted_read_at() != target_registration.trusted_read_at()
            || actor_registration.trusted_read_at()
                != ServerTimestamp::from_trusted_request_instant(trusted_now)?
            || target_registration.status() != PersistedRegistrationStatus::Active
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let request = prior
            .recovery_request(&request_id)
            .filter(|request| request.status == RecoveryRequestStatus::Open)
            .ok_or(StateMachineError::LeafRecoveryNotFound)?;
        let reservation = prior
            .recovery_reservation(&request_id)
            .filter(|reservation| reservation.status == ReservationStatus::Active)
            .ok_or(StateMachineError::LeafRecoveryNotFound)?;
        let package_cas = reserved_package_cas_for_request(
            reserved_package,
            request,
            reservation,
            actor_registration.transaction_id(),
            PackageStatus::Consumed,
        )?;
        if target_registration.actor() != &request.target
            || target_registration.key_id() != package_cas.target_key_id()
            || target_registration.auth_generation() != package_cas.target_auth_generation()
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let commit = process_commit(
            prior.public_state(),
            &commit_bytes,
            &aad,
            next,
            trusted_unix_millis_to_seconds(transition.received_at.unix_millis())
                .ok_or(StateMachineError::InvalidServerTime)?,
            MAX_PARTICIPANTS,
        )?;
        let signed_welcome = match transition.body_binding.as_ref() {
            Some(TransitionBodyBinding::LeafRecoveryFulfillment { manifest, .. }) => manifest
                .welcome
                .as_ref()
                .ok_or(StateMachineError::InvalidWelcomeMapping)?,
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        };
        let welcome = verify_recovery_welcome(
            &signed_welcome.opaque_welcome,
            request.key_package_ref,
            MAX_WELCOME_WIRE_BYTES,
        )?;
        let authority = transition.clone();
        let mut plan = plan_leaf_recovery_fulfillment_inner(
            prior,
            LeafRecoveryFulfillment {
                actor: actor_registration.actor().clone(),
                target: request.target.clone(),
                recovery_request_id: request_id,
                welcome_id: signed_welcome.welcome_id,
                transition,
                commit,
                welcome,
            },
        )?;
        let roster = plan
            .state
            .participants
            .iter()
            .map(|participant| {
                String::from_utf8(participant.principal.as_bytes().to_vec())
                    .map_err(|_| StateMachineError::InvalidPolicyAuthority)
            })
            .collect::<Result<Vec<_>, _>>()?;
        consume_locked_recovery_projection(
            relationship,
            relationship_decision,
            locked,
            actor_registration,
            ProjectionOperationScope::RecoveryFulfillment,
            &roster,
            relationship_authority,
        )
        .map_err(relationship_consumption_error)?;
        plan.effects.policy_evidence_digest = Some(relationship.evidence_digest());
        plan.bind_transition_authority(
            authority,
            head,
            actor_registration.transaction_id(),
            actor_registration.trusted_read_at(),
        )?
        .bind_recovery_package_cas(package_cas)?
        .bind_terminal_package_guards(
            prior,
            terminal_packages,
            actor_registration.transaction_id(),
        )
    }

    pub(crate) fn plan_leave_fulfillment_entry(
        &self,
        locked: &LockedConversationStateGuard,
        entry: VerifiedControlEntry,
        registration: &LockedRegistrationProjection,
        terminal_packages: Vec<LockedRecoveryPackageGuard>,
    ) -> Result<PlannedTransition, StateMachineError> {
        self.require_same_locked_conversation(locked)?;
        let prior = locked.state();
        let head = locked.head();
        let (request_id, commit_bytes, aad, next) = match entry.mutation().projection() {
            VerifiedMutationProjection::LeaveCommitFulfillment(value) => (
                *value.leave_request_id().as_bytes(),
                checked_artifact_bytes(&value.commit())?,
                commit_aad_bytes(&value.aad()),
                closed_coordinate(&value.next())?,
            ),
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        };
        let transition = self.transition_from_control(&entry)?;
        if !registration.authorizes_transition(&transition) {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let request = prior
            .leave_request(&request_id)
            .ok_or(StateMachineError::LeaveRequestNotFound)?;
        let commit = process_commit(
            prior.public_state(),
            &commit_bytes,
            &aad,
            next,
            trusted_unix_millis_to_seconds(transition.received_at.unix_millis())
                .ok_or(StateMachineError::InvalidServerTime)?,
            MAX_PARTICIPANTS,
        )?;
        let authority = transition.clone();
        let plan = plan_leave_fulfillment_inner(
            prior,
            LeaveFulfillment {
                actor: registration.actor().clone(),
                requester: request.requester.principal().clone(),
                leave_request_id: request_id,
                transition,
                commit,
            },
        )?;
        plan.bind_transition_authority(
            authority,
            head,
            registration.transaction_id(),
            registration.trusted_read_at(),
        )?
        .bind_terminal_package_guards(
            prior,
            terminal_packages,
            registration.transaction_id(),
        )
    }

    pub(crate) fn plan_reset_activation_entry(
        &self,
        locked: &LockedConversationStateGuard,
        entry: VerifiedControlEntry,
        registration: &LockedRegistrationProjection,
        terminal_packages: Vec<LockedRecoveryPackageGuard>,
    ) -> Result<PlannedTransition, StateMachineError> {
        self.require_same_locked_conversation(locked)?;
        let prior = locked.state();
        let head = locked.head();
        let (request_id, successor, group_info_bytes) = match entry.mutation().projection() {
            VerifiedMutationProjection::ResetActivation(value) => (
                *value.reset_request_id().as_bytes(),
                closed_coordinate(&value.successor())?,
                checked_artifact_bytes(&value.genesis_group_info())?,
            ),
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        };
        let transition = self.transition_from_control(&entry)?;
        if !registration.authorizes_transition(&transition) {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let authority = transition.clone();
        let successor_public_state = verify_reset_successor_group_info(
            &group_info_bytes,
            &prior.coordinate,
            ResetSuccessorGroupInfoExpectations {
                coordinate: successor,
                expected_basic_credential: &registration.actor().basic_credential(),
                expected_signature_key: registration.registered_mls_signature_key(),
                now_unix_seconds: trusted_unix_millis_to_seconds(
                    transition.received_at.unix_millis(),
                )
                .ok_or(StateMachineError::InvalidServerTime)?,
                max_wire_bytes: MAX_GROUP_INFO_WIRE_BYTES,
                max_ratchet_tree_bytes: MAX_GROUP_INFO_WIRE_BYTES,
                max_members: MAX_PARTICIPANTS,
            },
        )?;
        let plan = plan_reset_activation_inner(
            prior,
            ResetActivation {
                actor: registration.actor().clone(),
                reset_request_id: request_id,
                transition,
                successor_public_state,
            },
        )?;
        plan.bind_transition_authority(
            authority,
            head,
            registration.transaction_id(),
            registration.trusted_read_at(),
        )?
        .bind_terminal_package_guards(
            prior,
            terminal_packages,
            registration.transaction_id(),
        )
    }

    pub(crate) fn plan_metadata_entry(
        &self,
        locked: &LockedConversationStateGuard,
        entry: VerifiedControlEntry,
        registration: LockedRegistrationProjection,
        terminal_packages: Vec<LockedRecoveryPackageGuard>,
    ) -> Result<PlannedTransition, StateMachineError> {
        self.require_same_locked_conversation(locked)?;
        let prior = locked.state();
        let head = locked.head();
        let transition = self.transition_from_control(&entry)?;
        if !matches!(
            transition.body_binding.as_ref(),
            Some(TransitionBodyBinding::Metadata { .. })
        ) {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let actor = registration.actor().clone();
        let authority = transition.clone();
        let transaction_id = registration.transaction_id().to_owned();
        let trusted_read_at = registration.trusted_read_at();
        let plan = plan_metadata_inner(
            prior,
            MetadataCommand {
                actor,
                transition,
                registration,
            },
        )?;
        plan.bind_transition_authority(authority, head, &transaction_id, trusted_read_at)?
            .bind_terminal_package_guards(prior, terminal_packages, &transaction_id)
    }

    pub(crate) fn plan_zero_leaf_leave_entry(
        &self,
        locked: &LockedConversationStateGuard,
        entry: VerifiedControlEntry,
        registration: &LockedRegistrationProjection,
        terminal_packages: Vec<LockedRecoveryPackageGuard>,
    ) -> Result<PlannedTransition, StateMachineError> {
        self.require_same_locked_conversation(locked)?;
        let prior = locked.state();
        let head = locked.head();
        let transition = self.transition_from_control(&entry)?;
        if !registration.authorizes_transition(&transition)
            || !matches!(
                transition.body_binding.as_ref(),
                Some(TransitionBodyBinding::ZeroLeafLeave { .. })
            )
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let authority = transition.clone();
        let plan = plan_zero_leaf_leave_inner(
            prior,
            ZeroLeafLeave {
                actor: registration.actor().clone(),
                transition,
            },
        )?;
        plan.bind_transition_authority(
            authority,
            head,
            registration.transaction_id(),
            registration.trusted_read_at(),
        )?
        .bind_terminal_package_guards(
            prior,
            terminal_packages,
            registration.transaction_id(),
        )
    }

    pub(crate) fn plan_close_entry(
        &self,
        locked: &LockedConversationStateGuard,
        entry: VerifiedControlEntry,
        registration: &LockedRegistrationProjection,
        terminal_packages: Vec<LockedRecoveryPackageGuard>,
    ) -> Result<PlannedTransition, StateMachineError> {
        self.require_same_locked_conversation(locked)?;
        let prior = locked.state();
        let head = locked.head();
        let transition = self.transition_from_control(&entry)?;
        if !registration.authorizes_transition(&transition)
            || !matches!(
                transition.body_binding.as_ref(),
                Some(TransitionBodyBinding::ConversationClose { .. })
            )
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let authority = transition.clone();
        let plan = plan_close_inner(
            prior,
            CloseConversation {
                actor: registration.actor().clone(),
                transition,
            },
        )?;
        plan.bind_transition_authority(
            authority,
            head,
            registration.transaction_id(),
            registration.trusted_read_at(),
        )?
        .bind_terminal_package_guards(
            prior,
            terminal_packages,
            registration.transaction_id(),
        )
    }

    pub(crate) fn control_request(
        &self,
        entry: VerifiedControlEntry,
    ) -> Result<RequestEvidence, StateMachineError> {
        if entry.conversation_id().as_bytes() != &self.expected_conversation_id {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let locked = self
            .locked_binding()
            .ok_or(StateMachineError::InvalidHydrationAuthority)?;
        if entry.seq() != locked.expected_next_entry_seq
            || canonical_server_timestamp(entry.received_at())? != locked.locked_at
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let (kind, request_id, body_binding) = match entry.mutation().projection() {
            VerifiedMutationProjection::ResetRequest(value) => (
                RequestEntryKind::ResetRequest,
                value.reset_request_id(),
                RequestBodyBinding::ResetRequest {
                    prior: closed_coordinate(&value.prior())?,
                },
            ),
            VerifiedMutationProjection::LeaveRequest(value) => (
                RequestEntryKind::LeaveRequest,
                value.leave_request_id(),
                RequestBodyBinding::LeaveRequest {
                    prior: closed_coordinate(&value.prior())?,
                },
            ),
            VerifiedMutationProjection::LeaveCancellation(value) => (
                RequestEntryKind::LeaveCancellation,
                value.leave_request_id(),
                RequestBodyBinding::LeaveCancellation {
                    conversation_id: *value.conversation_id().as_bytes(),
                },
            ),
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        };
        if matches!(
            &body_binding,
            RequestBodyBinding::ResetRequest { prior }
                | RequestBodyBinding::LeaveRequest { prior }
                if Some(prior) != locked.expected_prior.as_ref()
        ) {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        request_evidence_from_verified(
            kind,
            Some(entry.entry_id().as_bytes()),
            entry.conversation_id().as_bytes(),
            Some(entry.seq()),
            Some(entry.outer_control_projection().to_vec()),
            Some(
                entry
                    .server_fields_dag_cbor()
                    .map_err(|_| StateMachineError::InvalidHydrationAuthority)?,
            ),
            request_id.as_bytes(),
            canonical_server_timestamp(entry.received_at())?,
            *entry.outer_control_fingerprint(),
            entry.mutation(),
            body_binding,
        )
    }

    pub(crate) fn plan_reset_request_entry(
        &self,
        locked: &LockedConversationStateGuard,
        entry: VerifiedControlEntry,
        registration: LockedRegistrationProjection,
    ) -> Result<PlannedTransition, StateMachineError> {
        self.require_same_locked_conversation(locked)?;
        let prior = locked.state();
        let head = locked.head();
        let evidence = self.control_request(entry)?;
        if evidence.kind != RequestEntryKind::ResetRequest || !registration.authorizes(&evidence) {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let authority = evidence.clone();
        let transaction_id = registration.transaction_id().to_owned();
        let trusted_read_at = registration.trusted_read_at();
        let plan = plan_reset_request_inner(
            prior,
            ResetRequestCommand {
                actor: evidence.actor.clone(),
                reset_request_id: evidence.request_id,
                received_at: evidence.received_at,
                evidence,
            },
        )?;
        plan.bind_control_request_authority(authority, head, &transaction_id, trusted_read_at)
    }

    pub(crate) fn plan_leave_request_entry(
        &self,
        locked: &LockedConversationStateGuard,
        entry: VerifiedControlEntry,
        registration: LockedRegistrationProjection,
    ) -> Result<PlannedTransition, StateMachineError> {
        self.require_same_locked_conversation(locked)?;
        let prior = locked.state();
        let head = locked.head();
        let evidence = self.control_request(entry)?;
        if evidence.kind != RequestEntryKind::LeaveRequest || !registration.authorizes(&evidence) {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let authority = evidence.clone();
        let transaction_id = registration.transaction_id().to_owned();
        let trusted_read_at = registration.trusted_read_at();
        let plan = plan_leave_request_inner(
            prior,
            LeaveRequestCommand {
                actor: evidence.actor.clone(),
                leave_request_id: evidence.request_id,
                received_at: evidence.received_at,
                evidence,
                registration,
            },
        )?;
        plan.bind_control_request_authority(authority, head, &transaction_id, trusted_read_at)
    }
}
