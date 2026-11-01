#![allow(unused_imports)]
use super::*;

impl HydrationAuthority {
    #[cfg(test)]
    pub(crate) fn new(expected_conversation_id: [u8; 16]) -> Result<Self, StateMachineError> {
        if !is_uuid_v4(&expected_conversation_id) {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        Ok(Self {
            expected_conversation_id,
            locked: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test_with_locked(
        expected_conversation_id: [u8; 16],
        transaction_id: String,
        expected_prior: Option<PublicGroupSnapshotCoordinate>,
        expected_next_entry_seq: u64,
        locked_at: ServerTimestamp,
        locked_head_digest: [u8; 32],
    ) -> Result<Self, StateMachineError> {
        if !is_uuid_v4(&expected_conversation_id) {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        Ok(Self {
            expected_conversation_id,
            locked: Some(LockedHydrationBinding {
                transaction_id,
                expected_prior,
                expected_next_entry_seq,
                locked_at,
                locked_head_digest,
                locked_graph_digest: None,
                locked_snapshot_digest: None,
            }),
        })
    }

    pub(in crate::chat_protocol) fn plan_historical_creation(
        &self,
        witness: HistoricalPlanWitness,
        entry: VerifiedControlEntry,
        creation_head: &crate::chat_protocol::repository::core::LockedConversationHeadGuard,
    ) -> Result<ConversationPersistencePlan, StateMachineError> {
        let group_info_bytes = match entry.mutation().projection() {
            VerifiedMutationProjection::Creation(value) => {
                checked_artifact_bytes(&value.genesis_group_info())?
            }
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        };
        let transition = self.transition_from_control(&entry)?;
        let (kind, next, manifest) = match transition.body_binding.as_ref() {
            Some(TransitionBodyBinding::Creation {
                kind,
                next,
                manifest,
                ..
            }) => (*kind, *next, manifest),
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        };
        if kind != ConversationKind::Group {
            return Err(StateMachineError::InvalidCreation);
        }
        let creator_device = manifest.actor_leaf.clone();
        let invitees = manifest
            .participants
            .iter()
            .filter(|participant| participant.principal != *creator_device.principal())
            .map(|participant| participant.principal.clone())
            .collect::<Vec<_>>();
        let public_state = verify_genesis_group_info(
            &group_info_bytes,
            GenesisGroupInfoExpectations {
                coordinate: next,
                expected_basic_credential: &creator_device.basic_credential(),
                expected_signature_key: entry.mutation().historical_public_key(),
                now_unix_seconds: trusted_unix_millis_to_seconds(
                    transition.received_at.unix_millis(),
                )
                .ok_or(StateMachineError::InvalidServerTime)?,
                max_wire_bytes: MAX_GROUP_INFO_WIRE_BYTES,
                max_ratchet_tree_bytes: MAX_GROUP_INFO_WIRE_BYTES,
                max_members: MAX_PARTICIPANTS,
            },
        )?;
        let decision = plan_creation_inner(
            None,
            CreationCommand {
                kind,
                creator: creator_device,
                invitees,
                transition: transition.clone(),
                public_state,
            },
        )?;
        let CreationDecision::Create(planned_transition) = decision else {
            return Err(StateMachineError::InvalidCreation);
        };
        planned_transition.bind_historical_transition_authority(
            witness,
            transition,
            creation_head,
            None,
        )
    }

    pub(in crate::chat_protocol) fn plan_historical_policy_add(
        &self,
        witness: HistoricalPlanWitness,
        locked_convo: &crate::chat_protocol::repository::core::LockedConversationStateGuard,
        entry: VerifiedControlEntry,
    ) -> Result<ConversationPersistencePlan, StateMachineError> {
        let transition = self.transition_from_control(&entry)?;
        let changes = match transition.body_binding.as_ref() {
            Some(TransitionBodyBinding::Policy {
                participant_changes,
                ..
            }) => participant_changes,
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        };
        if changes.is_empty()
            || changes
                .iter()
                .any(|change| !matches!(change, ManifestParticipantChange::Add(_)))
        {
            return Err(StateMachineError::InvalidPolicyAuthority);
        }
        let actor = historical_actor(&transition)?;
        let planned_transition = plan_policy_transition(
            locked_convo.state(),
            PolicyCommand {
                actor,
                transition: transition.clone(),
                relationship_evidence_digest: [0; 32],
            },
        )?;
        planned_transition.bind_historical_transition_authority(
            witness,
            transition,
            locked_convo.head(),
            None,
        )
    }

    pub(in crate::chat_protocol) fn plan_historical_acceptance(
        &self,
        witness: HistoricalPlanWitness,
        locked_convo: &crate::chat_protocol::repository::core::LockedConversationStateGuard,
        entry: VerifiedControlEntry,
        package_guard: crate::chat_protocol::repository::core::LockedRecoveryPackageGuard,
    ) -> Result<ConversationPersistencePlan, StateMachineError> {
        let transition = self.transition_from_control(&entry)?;
        let recovery_request_id = match transition.body_binding.as_ref() {
            Some(TransitionBodyBinding::Acceptance {
                recovery_request_id,
                ..
            }) => *recovery_request_id,
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        };
        let actor = historical_actor(&transition)?;
        let key_package_ref = *package_guard.key_package_ref();
        let package_not_after =
            ServerTimestamp::from_unix_millis(package_guard.not_after().timestamp_millis())?;
        let package_cas = historical_available_package_cas(
            package_guard,
            &transition,
            locked_convo.head().transaction_id(),
        )?;
        let planned_transition = plan_accept_conversation_inner(
            locked_convo.state(),
            AcceptConversation {
                actor,
                transition: transition.clone(),
                recovery_request_id,
                key_package_ref,
                package_not_after,
            },
        )?;
        planned_transition.bind_historical_transition_authority(
            witness,
            transition,
            locked_convo.head(),
            Some(package_cas),
        )
    }

    pub(in crate::chat_protocol) fn plan_historical_recovery_fulfillment(
        &self,
        witness: HistoricalPlanWitness,
        locked_convo: &crate::chat_protocol::repository::core::LockedConversationStateGuard,
        entry: VerifiedControlEntry,
        reserved_package: crate::chat_protocol::repository::core::LockedRecoveryPackageGuard,
    ) -> Result<ConversationPersistencePlan, StateMachineError> {
        let transition = self.transition_from_control(&entry)?;
        let (request_id, commit_bytes, aad, next) = match entry.mutation().projection() {
            VerifiedMutationProjection::LeafRecoveryFulfillment(value) => (
                *value.recovery_request_id().as_bytes(),
                checked_artifact_bytes(&value.commit())?,
                commit_aad_bytes(&value.aad()),
                closed_coordinate(&value.next())?,
            ),
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        };
        let request = locked_convo
            .state()
            .recovery_request(&request_id)
            .ok_or(StateMachineError::LeafRecoveryNotFound)?;
        let reservation = locked_convo
            .state()
            .recovery_reservation(&request_id)
            .ok_or(StateMachineError::LeafRecoveryNotFound)?;
        let package_cas = reserved_package_cas_for_request(
            reserved_package,
            request,
            reservation,
            locked_convo.head().transaction_id(),
            PackageStatus::Consumed,
        )?;
        let commit = process_commit(
            locked_convo.state().public_state(),
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
        let actor = historical_actor(&transition)?;
        let planned_transition = plan_leaf_recovery_fulfillment_inner(
            locked_convo.state(),
            LeafRecoveryFulfillment {
                actor,
                target: request.target.clone(),
                recovery_request_id: request_id,
                welcome_id: signed_welcome.welcome_id,
                transition: transition.clone(),
                commit,
                welcome,
            },
        )?;
        planned_transition.bind_historical_transition_authority(
            witness,
            transition,
            locked_convo.head(),
            Some(package_cas),
        )
    }

    #[cfg(test)]
    pub(crate) fn for_test_with_locked_instant(
        expected_conversation_id: [u8; 16],
        instant: &TrustedRequestInstant,
        expected_prior: Option<PublicGroupSnapshotCoordinate>,
    ) -> Result<Self, StateMachineError> {
        if !is_uuid_v4(&expected_conversation_id) {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        Ok(Self {
            expected_conversation_id,
            locked: Some(LockedHydrationBinding {
                transaction_id: "test".to_string(),
                expected_prior,
                expected_next_entry_seq: 1,
                locked_at: ServerTimestamp::from_trusted_request_instant(instant)?,
                locked_head_digest: [1; 32],
                locked_graph_digest: None,
                locked_snapshot_digest: None,
            }),
        })
    }

    pub(crate) fn from_locked_conversation(
        locked: &LockedConversationStateGuard,
    ) -> Result<Self, StateMachineError> {
        let head = locked.head();
        if head.durable_row_digest() == &[0; 32]
            || locked.state().coordinate().conversation_id() != head.conversation_id().as_bytes()
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        Ok(Self {
            expected_conversation_id: *head.conversation_id().as_bytes(),
            locked: Some(LockedHydrationBinding {
                transaction_id: head.transaction_id().to_owned(),
                expected_prior: head.prior_coordinate().copied(),
                expected_next_entry_seq: head.next_entry_seq(),
                locked_at: ServerTimestamp::from_unix_millis(head.locked_at().timestamp_millis())?,
                locked_head_digest: *head.durable_row_digest(),
                locked_graph_digest: Some(*locked.locked_graph_digest()),
                locked_snapshot_digest: locked.locked_snapshot_digest().copied(),
            }),
        })
    }

    pub(crate) fn from_locked_creation_head(
        head: &LockedConversationHeadGuard,
    ) -> Result<Self, StateMachineError> {
        if head.prior_coordinate().is_some()
            || head.next_entry_seq() != 1
            || head.durable_row_digest() == &[0; 32]
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        Ok(Self {
            expected_conversation_id: *head.conversation_id().as_bytes(),
            locked: Some(LockedHydrationBinding {
                transaction_id: head.transaction_id().to_owned(),
                expected_prior: None,
                expected_next_entry_seq: head.next_entry_seq(),
                locked_at: ServerTimestamp::from_unix_millis(head.locked_at().timestamp_millis())?,
                locked_head_digest: *head.durable_row_digest(),
                locked_graph_digest: None,
                locked_snapshot_digest: None,
            }),
        })
    }

    pub(in crate::chat_protocol::state_machine) fn locked_binding(
        &self,
    ) -> Option<&LockedHydrationBinding> {
        self.locked.as_ref()
    }

    #[allow(dead_code)]
    pub(crate) fn from_locked_existing_head(
        head: &LockedConversationHeadGuard,
    ) -> Result<Self, StateMachineError> {
        if head.prior_coordinate().is_none()
            || head.next_entry_seq() < 2
            || head.durable_row_digest() == &[0; 32]
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        Ok(Self {
            expected_conversation_id: *head.conversation_id().as_bytes(),
            locked: Some(LockedHydrationBinding {
                transaction_id: head.transaction_id().to_owned(),
                expected_prior: head.prior_coordinate().copied(),
                expected_next_entry_seq: head.next_entry_seq(),
                locked_at: ServerTimestamp::from_unix_millis(head.locked_at().timestamp_millis())?,
                locked_head_digest: *head.durable_row_digest(),
                locked_graph_digest: None,
                locked_snapshot_digest: None,
            }),
        })
    }

    pub(in crate::chat_protocol::state_machine) fn require_same_locked_conversation(
        &self,
        locked: &LockedConversationStateGuard,
    ) -> Result<(), StateMachineError> {
        let head = locked.head();
        let binding = self
            .locked_binding()
            .ok_or(StateMachineError::InvalidHydrationAuthority)?;
        let locked_at = ServerTimestamp::from_unix_millis(head.locked_at().timestamp_millis())?;
        if head.transaction_id() != binding.transaction_id
            || head.conversation_id().as_bytes() != &self.expected_conversation_id
            || head.prior_coordinate() != binding.expected_prior.as_ref()
            || head.next_entry_seq() != binding.expected_next_entry_seq
            || locked_at != binding.locked_at
            || head.durable_row_digest() != &binding.locked_head_digest
            || binding.locked_graph_digest != Some(*locked.locked_graph_digest())
            || binding.locked_snapshot_digest != locked.locked_snapshot_digest().copied()
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        Ok(())
    }

    pub(in crate::chat_protocol::state_machine) fn require_same_locked_head(
        &self,
        head: &LockedConversationHeadGuard,
    ) -> Result<(), StateMachineError> {
        let locked = self
            .locked_binding()
            .ok_or(StateMachineError::InvalidHydrationAuthority)?;
        let locked_at = ServerTimestamp::from_unix_millis(head.locked_at().timestamp_millis())?;
        if head.transaction_id() != locked.transaction_id
            || head.conversation_id().as_bytes() != &self.expected_conversation_id
            || head.prior_coordinate() != locked.expected_prior.as_ref()
            || head.next_entry_seq() != locked.expected_next_entry_seq
            || locked_at != locked.locked_at
            || head.durable_row_digest() != &locked.locked_head_digest
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        Ok(())
    }

    pub(crate) fn transition_from_control(
        &self,
        entry: &VerifiedControlEntry,
    ) -> Result<TransitionEvidence, StateMachineError> {
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
        let (transition_id, body_binding) = match entry.mutation().projection() {
            VerifiedMutationProjection::Creation(value) => (
                *value.transition_id().as_bytes(),
                TransitionBodyBinding::Creation {
                    kind: parse_conversation_kind(value.conversation_kind())?,
                    next: closed_coordinate(&value.next())?,
                    manifest: parse_roster_manifest(&value.manifest())?,
                    group_info_sha256: checked_artifact_sha256(&value.genesis_group_info())?,
                    metadata: parse_metadata_snapshot(&value.metadata_snapshot())?,
                },
            ),
            VerifiedMutationProjection::CommitTransition(value) => (
                *value.transition_id().as_bytes(),
                TransitionBodyBinding::Commit {
                    prior: closed_coordinate(&value.prior())?,
                    next: closed_coordinate(&value.next())?,
                    aad_digest: commit_aad_sha256(&value.aad()),
                    manifest: parse_transition_manifest(&value.manifest())?,
                    commit_sha256: checked_artifact_sha256(&value.commit())?,
                    metadata: parse_metadata_snapshot(&value.metadata_snapshot())?,
                },
            ),
            VerifiedMutationProjection::PolicyTransition(value) => (
                *value.transition_id().as_bytes(),
                TransitionBodyBinding::Policy {
                    prior: closed_coordinate(&value.prior())?,
                    next: closed_coordinate(&value.next())?,
                    participant_changes: parse_participant_changes(value.participant_changes())?,
                },
            ),
            VerifiedMutationProjection::ParticipantAcceptance(value) => (
                *value.transition_id().as_bytes(),
                TransitionBodyBinding::Acceptance {
                    prior: closed_coordinate(&value.prior())?,
                    next: closed_coordinate(&value.next())?,
                    recovery_request_id: *value.recovery_request_id().as_bytes(),
                    invitation_provenance: parse_invitation(&value.invitation_provenance())?,
                    recovery: parse_acceptance_recovery(&entry.server_fields())?,
                },
            ),
            VerifiedMutationProjection::MetadataTransition(value) => (
                *value.transition_id().as_bytes(),
                TransitionBodyBinding::Metadata {
                    prior: closed_coordinate(&value.prior())?,
                    next: closed_coordinate(&value.next())?,
                    metadata: parse_metadata_snapshot(&value.metadata_snapshot())?,
                },
            ),
            VerifiedMutationProjection::ResetActivation(value) => (
                *value.transition_id().as_bytes(),
                TransitionBodyBinding::ResetActivation {
                    kind: parse_conversation_kind(value.conversation_kind())?,
                    reset_request_id: *value.reset_request_id().as_bytes(),
                    prior: closed_coordinate(&value.prior())?,
                    retired: closed_coordinate(&value.retired())?,
                    successor: closed_coordinate(&value.successor())?,
                    manifest: parse_roster_manifest(&value.manifest())?,
                    group_info_sha256: checked_artifact_sha256(&value.genesis_group_info())?,
                    metadata: parse_metadata_snapshot(&value.metadata_snapshot())?,
                },
            ),
            VerifiedMutationProjection::LeafRecoveryFulfillment(value) => (
                *value.transition_id().as_bytes(),
                TransitionBodyBinding::LeafRecoveryFulfillment {
                    recovery_request_id: *value.recovery_request_id().as_bytes(),
                    prior: closed_coordinate(&value.prior())?,
                    next: closed_coordinate(&value.next())?,
                    aad_digest: commit_aad_sha256(&value.aad()),
                    manifest: parse_transition_manifest(&value.manifest())?,
                    commit_sha256: checked_artifact_sha256(&value.commit())?,
                    metadata: parse_metadata_snapshot(&value.metadata_snapshot())?,
                },
            ),
            VerifiedMutationProjection::ConversationClose(value) => (
                *value.transition_id().as_bytes(),
                TransitionBodyBinding::ConversationClose {
                    kind: parse_conversation_kind(value.conversation_kind())?,
                    prior: closed_coordinate(&value.prior())?,
                    retired: closed_coordinate(&value.retired())?,
                },
            ),
            VerifiedMutationProjection::ZeroLeafLeave(value) => (
                *value.transition_id().as_bytes(),
                TransitionBodyBinding::ZeroLeafLeave {
                    prior: closed_coordinate(&value.prior())?,
                    next: closed_coordinate(&value.next())?,
                },
            ),
            VerifiedMutationProjection::LeaveCommitFulfillment(value) => (
                *value.transition_id().as_bytes(),
                TransitionBodyBinding::LeaveCommitFulfillment {
                    leave_request_id: *value.leave_request_id().as_bytes(),
                    prior: closed_coordinate(&value.prior())?,
                    next: closed_coordinate(&value.next())?,
                    aad_digest: commit_aad_sha256(&value.aad()),
                    manifest: parse_transition_manifest(&value.manifest())?,
                    commit_sha256: checked_artifact_sha256(&value.commit())?,
                    metadata: parse_metadata_snapshot(&value.metadata_snapshot())?,
                },
            ),
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        };
        if !transition_binding_is_route_bound(&body_binding, &self.expected_conversation_id) {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        if transition_body_prior(&body_binding) != locked.expected_prior.as_ref() {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        validate_special_server_fields(entry, &body_binding)?;
        let mut evidence = TransitionEvidence {
            seq: entry.seq(),
            transition_id,
            outer_entry_fingerprint: *entry.outer_control_fingerprint(),
            outer_control_projection: entry.outer_control_projection().to_vec(),
            server_fields_dag_cbor: entry
                .server_fields_dag_cbor()
                .map_err(|_| StateMachineError::InvalidHydrationAuthority)?,
            durable_row_digest: [0; 32],
            received_at: canonical_server_timestamp(entry.received_at())?,
            authority: Some(authenticated_entry(
                Some(entry.entry_id().as_bytes()),
                Some(entry.conversation_id().as_bytes()),
                entry.mutation(),
            )?),
            body_binding: Some(body_binding),
        };
        evidence.durable_row_digest = durable_control_transition_row_digest(&evidence)?;
        Ok(evidence)
    }

    /// Test/persistence hydration seam. Mutation planning in production uses
    /// the variant-specific methods below so evidence cannot be paired with a
    /// separately selected body or MLS artifact.
    #[cfg(test)]
    pub(crate) fn control_transition(
        &self,
        entry: VerifiedControlEntry,
    ) -> Result<TransitionEvidence, StateMachineError> {
        self.transition_from_control(&entry)
    }

    pub(crate) fn plan_creation<T: PublicTransport>(
        &self,
        entry: VerifiedControlEntry,
        registration: &LockedRegistrationProjection,
        head: Option<&LockedConversationHeadGuard>,
        direct_lookup: Option<LockedDirectConversationLookupGuard>,
        relationship: &RelationshipProjection,
        relationship_authority: &RelationshipAuthority<T>,
        quota_guard: LockedInvitationQuotaGuard,
        relationship_decision: &LockedRelationshipDecisionGuard,
        trusted_now: &TrustedRequestInstant,
    ) -> Result<CreationDecision, StateMachineError> {
        let group_info_bytes = match entry.mutation().projection() {
            VerifiedMutationProjection::Creation(value) => {
                checked_artifact_bytes(&value.genesis_group_info())?
            }
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        };
        let transition = self.transition_from_control(&entry)?;
        if !registration.authorizes_transition(&transition) {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let (kind, next, manifest) = match transition.body_binding.as_ref() {
            Some(TransitionBodyBinding::Creation {
                kind,
                next,
                manifest,
                ..
            }) => (*kind, *next, manifest),
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        };
        if manifest.actor_leaf != *registration.actor() {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let invitees = manifest
            .participants
            .iter()
            .filter(|participant| participant.principal != *registration.actor().principal())
            .map(|participant| participant.principal.clone())
            .collect::<Vec<_>>();
        let trusted_at = ServerTimestamp::from_trusted_request_instant(trusted_now)?;
        let head = match (kind, direct_lookup.as_ref(), head) {
            (ConversationKind::Direct, Some(lookup), maybe_head) => {
                let [invitee] = invitees.as_slice() else {
                    return Err(StateMachineError::InvalidCreation);
                };
                let (low, high) = canonical_pair(registration.actor().principal(), invitee);
                if lookup.transaction_id() != registration.transaction_id()
                    || ServerTimestamp::from_unix_millis(lookup.locked_at().timestamp_millis())?
                        != trusted_at
                    || lookup.did_low().as_bytes() != low.as_bytes()
                    || lookup.did_high().as_bytes() != high.as_bytes()
                    || lookup.durable_row_digest() == &[0; 32]
                {
                    return Err(StateMachineError::InvalidHydrationAuthority);
                }
                match lookup.outcome() {
                    LockedDirectLookupOutcome::Existing {
                        conversation_id,
                        coordinate,
                        ..
                    } if maybe_head.is_none()
                        && coordinate.lifecycle() == PublicGroupSnapshotLifecycle::Active =>
                    {
                        return Ok(CreationDecision::ExistingDirect {
                            conversation_id: *conversation_id.as_bytes(),
                            coordinate: *coordinate,
                        });
                    }
                    LockedDirectLookupOutcome::Absent => {
                        maybe_head.ok_or(StateMachineError::InvalidHydrationAuthority)?
                    }
                    _ => return Err(StateMachineError::InvalidHydrationAuthority),
                }
            }
            (ConversationKind::Group, None, Some(head)) => head,
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        };
        self.require_same_locked_head(head)?;
        let public_state = verify_genesis_group_info(
            &group_info_bytes,
            GenesisGroupInfoExpectations {
                coordinate: next,
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
        let authority = transition.clone();
        let decision = plan_creation_inner(
            None,
            CreationCommand {
                kind,
                creator: registration.actor().clone(),
                invitees,
                transition,
                public_state,
            },
        )?;
        let CreationDecision::Create(plan) = decision else {
            return Ok(decision);
        };
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
            .state
            .participants
            .iter()
            .filter(|participant| participant.status == ParticipantStatus::Pending)
            .map(|participant| {
                String::from_utf8(participant.principal.as_bytes().to_vec())
                    .map_err(|_| StateMachineError::InvalidPolicyAuthority)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let request = AdmissionRequest {
            inviter: String::from_utf8(registration.actor().principal().as_bytes().to_vec())
                .map_err(|_| StateMachineError::InvalidPolicyAuthority)?,
            roster,
            pending_recipients,
            operation: if kind == ConversationKind::Direct {
                AdmissionOperation::Direct
            } else {
                AdmissionOperation::Group
            },
        };
        let quota_cas = invitation_quota_cas_from_guard(
            &quota_guard,
            registration.actor().principal(),
            &request.pending_recipients,
            registration.transaction_id(),
            registration.trusted_read_at(),
        )?;
        consume_locked_creation_projection(
            relationship,
            relationship_decision,
            head,
            &quota_guard,
            direct_lookup.as_ref(),
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
        Ok(CreationDecision::Create(
            plan.bind_transition_authority(
                authority,
                head,
                registration.transaction_id(),
                registration.trusted_read_at(),
            )?
            .bind_invitation_quota_cas(quota_cas)?,
        ))
    }

    /// Closed creator-only GROUP Creation branch. The repository guard proves
    /// that the exact locked quota scope is empty; the signed manifest and
    /// deterministic planner must independently derive zero pending
    /// recipients, so this branch cannot bypass admission for an Add.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn plan_creation_without_pending_admission(
        &self,
        entry: VerifiedControlEntry,
        registration: &LockedRegistrationProjection,
        head: &LockedConversationHeadGuard,
        quota_guard: LockedInvitationQuotaGuard,
        no_admission: LockedNoPendingAdmissionGuard,
        trusted_now: &TrustedRequestInstant,
    ) -> Result<CreationDecision, StateMachineError> {
        let group_info_bytes = match entry.mutation().projection() {
            VerifiedMutationProjection::Creation(value) => {
                checked_artifact_bytes(&value.genesis_group_info())?
            }
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        };
        let transition = self.transition_from_control(&entry)?;
        if !registration.authorizes_transition(&transition) {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let (kind, next, manifest) = match transition.body_binding.as_ref() {
            Some(TransitionBodyBinding::Creation {
                kind,
                next,
                manifest,
                ..
            }) => (*kind, *next, manifest),
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        };
        if kind != ConversationKind::Group || manifest.actor_leaf != *registration.actor() {
            return Err(StateMachineError::InvalidCreation);
        }
        let invitees = manifest
            .participants
            .iter()
            .filter(|participant| participant.principal != *registration.actor().principal())
            .map(|participant| participant.principal.clone())
            .collect::<Vec<_>>();
        if !invitees.is_empty()
            || !no_admission.authorizes_creation(head, &quota_guard, registration)
        {
            return Err(StateMachineError::InvalidPolicyAuthority);
        }
        self.require_same_locked_head(head)?;
        let public_state = verify_genesis_group_info(
            &group_info_bytes,
            GenesisGroupInfoExpectations {
                coordinate: next,
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
        let authority = transition.clone();
        let decision = plan_creation_inner(
            None,
            CreationCommand {
                kind,
                creator: registration.actor().clone(),
                invitees,
                transition,
                public_state,
            },
        )?;
        let CreationDecision::Create(plan) = decision else {
            return Err(StateMachineError::InvalidCreation);
        };
        let pending_recipients = plan
            .state
            .participants
            .iter()
            .filter(|participant| participant.status == ParticipantStatus::Pending)
            .map(|participant| {
                String::from_utf8(participant.principal.as_bytes().to_vec())
                    .map_err(|_| StateMachineError::InvalidPolicyAuthority)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if !pending_recipients.is_empty()
            || plan.effects.participant_changes.iter().any(|change| {
                matches!(
                    (&change.before, &change.after),
                    (None, Some(after))
                        if after.principal != *registration.actor().principal()
                            || after.status == ParticipantStatus::Pending
                )
            })
        {
            return Err(StateMachineError::InvalidPolicyAuthority);
        }
        let quota_cas = invitation_quota_cas_from_guard(
            &quota_guard,
            registration.actor().principal(),
            &pending_recipients,
            registration.transaction_id(),
            registration.trusted_read_at(),
        )?;
        if registration.trusted_read_at()
            != ServerTimestamp::from_trusted_request_instant(trusted_now)?
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        Ok(CreationDecision::Create(
            plan.bind_transition_authority(
                authority,
                head,
                registration.transaction_id(),
                registration.trusted_read_at(),
            )?
            .bind_invitation_quota_cas(quota_cas)?,
        ))
    }
}
