#![allow(unused_imports)]
use super::*;


impl ConversationState {
    pub(crate) fn kind(&self) -> ConversationKind {
        self.kind
    }

    pub(crate) fn coordinate(&self) -> &PublicGroupSnapshotCoordinate {
        &self.coordinate
    }

    pub(crate) fn active_public_state(&self) -> Option<&ActivePublicState> {
        self.public_state.as_ref()
    }

    pub(crate) fn metadata(&self) -> Option<&MetadataSnapshotBinding> {
        self.metadata.as_ref()
    }

    pub(crate) fn public_state(&self) -> &ActivePublicState {
        self.public_state
            .as_ref()
            .expect("active state-machine operation requires public state")
    }

    pub(crate) fn participants(&self) -> &[ParticipantRecord] {
        &self.participants
    }

    pub(crate) fn participant(&self, principal: &PrincipalId) -> Option<&ParticipantRecord> {
        self.participants
            .binary_search_by(|candidate| candidate.principal.cmp(principal))
            .ok()
            .map(|index| &self.participants[index])
    }

    pub(crate) fn leaves(&self) -> &[LeafRecord] {
        &self.leaves
    }

    pub(crate) fn leaf(&self, device: &DeviceIdentity) -> Option<&LeafRecord> {
        self.leaves.iter().find(|leaf| &leaf.device == device)
    }

    pub(crate) fn intervals(&self) -> &[AccessInterval] {
        &self.intervals
    }

    pub(crate) fn intervals_for(&self, device: &DeviceIdentity) -> Vec<&AccessInterval> {
        self.intervals
            .iter()
            .filter(|interval| &interval.recipient == device)
            .collect()
    }

    pub(crate) fn terminal_proofs(&self) -> &[ScheduleTerminalProof] {
        &self.terminal_proofs
    }

    pub(crate) fn terminal_proof(&self, device: &DeviceIdentity) -> Option<&ScheduleTerminalProof> {
        self.terminal_proofs
            .iter()
            .find(|proof| &proof.recipient == device)
    }

    pub(crate) fn recovery_request(&self, request_id: &[u8; 16]) -> Option<&RecoveryRequest> {
        self.recovery_requests
            .iter()
            .find(|request| request.request_id == *request_id)
    }

    pub(crate) fn recovery_requests(&self) -> &[RecoveryRequest] {
        &self.recovery_requests
    }

    pub(crate) fn recovery_reservation(
        &self,
        request_id: &[u8; 16],
    ) -> Option<&RecoveryReservation> {
        self.recovery_reservations
            .iter()
            .find(|reservation| reservation.request_id == *request_id)
    }

    pub(crate) fn reset_request(&self, request_id: &[u8; 16]) -> Option<&ResetRequest> {
        self.reset_requests
            .iter()
            .find(|request| request.request_id == *request_id)
    }

    pub(crate) fn leave_request(&self, request_id: &[u8; 16]) -> Option<&LeaveRequest> {
        self.leave_requests
            .iter()
            .find(|request| request.request_id == *request_id)
    }

    pub(crate) fn welcome(&self, welcome_id: &[u8; 16]) -> Option<&WelcomeWork> {
        self.welcomes
            .iter()
            .find(|welcome| welcome.welcome_id == *welcome_id)
    }

    pub(crate) fn welcomes(&self) -> &[WelcomeWork] {
        &self.welcomes
    }

    #[cfg(test)]
    pub(crate) fn for_test_with_state_version(
        &self,
        state_version: u64,
    ) -> Result<Self, StateMachineError> {
        let mut state = self.clone();
        let next = PublicGroupSnapshotCoordinate::new(
            *self.coordinate.conversation_id(),
            self.coordinate.generation(),
            state_version,
            *self.coordinate.group_id(),
            self.coordinate.epoch(),
            *self.coordinate.group_context_hash(),
            *self.coordinate.confirmation_tag(),
            PublicGroupSnapshotLifecycle::Active,
        );
        let template = self
            .public_state
            .as_ref()
            .ok_or(StateMachineError::ConversationClosed)?;
        state.public_state = Some(ActivePublicState::for_test(template, next));
        state.coordinate = next;
        Ok(state)
    }

    #[cfg(test)]
    pub(crate) fn for_test_close_leaf_interval(
        &self,
        device: &DeviceIdentity,
        evidence: TransitionEvidence,
        kind: CloseKind,
    ) -> Result<Self, StateMachineError> {
        let mut state = self.clone();
        close_open_interval(&mut state.intervals, device, &evidence, kind)?;
        state.leaves.retain(|leaf| &leaf.device != device);
        Ok(state)
    }

    #[cfg(test)]
    pub(crate) fn for_test_reverse_intervals(&self) -> Self {
        let mut state = self.clone();
        state.intervals.reverse();
        state
    }

    #[cfg(test)]
    pub(crate) fn for_test_corrupt_first_interval_conversation(
        &self,
        conversation_id: [u8; 16],
    ) -> Self {
        let mut state = self.clone();
        let interval = state.intervals.first_mut().expect("test interval");
        let context = interval.opening_context;
        interval.opening_context = PublicGroupSnapshotCoordinate::new(
            conversation_id,
            context.generation(),
            context.state_version(),
            *context.group_id(),
            context.epoch(),
            *context.group_context_hash(),
            *context.confirmation_tag(),
            context.lifecycle(),
        );
        state
    }

    #[cfg(test)]
    pub(crate) fn for_test_touch_interval(
        &self,
        device: &DeviceIdentity,
        closing: TransitionEvidence,
        opening: TransitionEvidence,
        close_kind: CloseKind,
        opening_kind: OpeningKind,
    ) -> Result<Self, StateMachineError> {
        let mut state = self.clone();
        close_open_interval(&mut state.intervals, device, &closing, close_kind)?;
        open_interval(
            &mut state.intervals,
            device.clone(),
            opening,
            opening_kind,
            state.coordinate,
        )?;
        sort_intervals(&mut state.intervals);
        Ok(state)
    }

    #[cfg(test)]
    pub(crate) fn for_test_corrupt_touching_opening_transition_id(
        &self,
        device: &DeviceIdentity,
    ) -> Self {
        let mut state = self.clone();
        let interval = state
            .intervals
            .iter_mut()
            .filter(|interval| &interval.recipient == device)
            .max_by_key(|interval| interval.opening.seq)
            .expect("test interval");
        interval.opening.transition_id[0] ^= 0x01;
        state
    }

    #[cfg(test)]
    pub(crate) fn for_test_corrupt_touching_opening_fingerprint(
        &self,
        device: &DeviceIdentity,
    ) -> Self {
        let mut state = self.clone();
        let interval = state
            .intervals
            .iter_mut()
            .filter(|interval| &interval.recipient == device)
            .max_by_key(|interval| interval.opening.seq)
            .expect("test interval");
        interval.opening.outer_entry_fingerprint[0] ^= 0x01;
        state
    }

    #[cfg(test)]
    pub(crate) fn for_test_corrupt_touching_opening_received_at(
        &self,
        device: &DeviceIdentity,
    ) -> Self {
        let mut state = self.clone();
        let interval = state
            .intervals
            .iter_mut()
            .filter(|interval| &interval.recipient == device)
            .max_by_key(|interval| interval.opening.seq)
            .expect("test interval");
        interval.opening.received_at = interval
            .opening
            .received_at
            .checked_add_millis(1)
            .expect("test timestamp");
        state
    }

    #[cfg(test)]
    pub(crate) fn for_test_corrupt_touching_close_kind(&self, device: &DeviceIdentity) -> Self {
        let mut state = self.clone();
        let interval = state
            .intervals
            .iter_mut()
            .filter(|interval| &interval.recipient == device)
            .min_by_key(|interval| interval.opening.seq)
            .expect("test interval");
        interval.end.as_mut().expect("test interval end").kind = CloseKind::Remove;
        state
    }

    #[cfg(test)]
    pub(crate) fn for_test_duplicate_terminal_proof(&self) -> Self {
        let mut state = self.clone();
        let proof = state.terminal_proofs.first().expect("test proof").clone();
        state.terminal_proofs.push(proof);
        state
    }

    #[cfg(test)]
    pub(crate) fn for_test_corrupt_first_terminal_proof_conversation(
        &self,
        conversation_id: [u8; 16],
    ) -> Self {
        let mut state = self.clone();
        state
            .terminal_proofs
            .first_mut()
            .expect("test proof")
            .conversation_id = conversation_id;
        state
    }

    #[cfg(test)]
    pub(crate) fn for_test_corrupt_first_terminal_proof_fingerprint(&self) -> Self {
        let mut state = self.clone();
        state
            .terminal_proofs
            .first_mut()
            .expect("test proof")
            .evidence
            .outer_entry_fingerprint[0] ^= 0x01;
        state
    }

    #[cfg(test)]
    pub(crate) fn for_test_drop_first_recovery_reservation(&self) -> Self {
        let mut state = self.clone();
        state.recovery_reservations.remove(0);
        state
    }

    #[cfg(test)]
    pub(crate) fn for_test_leave_fulfillment_matches(&self, request_id: &[u8; 16]) -> bool {
        let Some(request) = self.leave_request(request_id) else {
            return false;
        };
        let Some(WorkTerminalEvidence::Transition(evidence)) = request.terminal.as_ref() else {
            return false;
        };
        leave_fulfillment_matches_request(self, evidence, request)
    }

    #[cfg(test)]
    pub(crate) fn for_test_mutate_leave_fulfillment(
        &self,
        request_id: &[u8; 16],
        mutation: LeaveFulfillmentTestMutation,
    ) -> Self {
        let mut state = self.clone();
        let request_index = state
            .leave_requests
            .iter()
            .position(|request| &request.request_id == request_id)
            .expect("test fulfilled leave");

        match mutation {
            LeaveFulfillmentTestMutation::ManifestDevices(devices) => {
                let request = &state.leave_requests[request_index];
                let WorkTerminalEvidence::Transition(old_terminal) =
                    request.terminal.as_ref().expect("test terminal")
                else {
                    panic!("test leave terminal");
                };
                let old_terminal = old_terminal.clone();
                let metadata = MetadataSnapshotBinding::for_test_creation(
                    *state.coordinate.conversation_id(),
                    state.coordinate.generation(),
                    *state.coordinate.group_id(),
                    state.coordinate.epoch(),
                    *state.coordinate.group_context_hash(),
                    *state.coordinate.confirmation_tag(),
                    old_terminal.transition_id,
                    old_terminal.seq,
                    request.requester.clone(),
                    [0x51; 32],
                    [0x52; 32],
                    1,
                    1,
                    [0x53; 12],
                    vec![0x54],
                );
                let mut replacement = old_terminal.clone();
                replacement.body_binding = Some(TransitionBodyBinding::LeaveCommitFulfillment {
                    leave_request_id: request.request_id,
                    prior: request.bound_coordinate,
                    next: state.coordinate,
                    aad_digest: [0; 32],
                    manifest: TransitionManifestBinding {
                        participant_changes: vec![ManifestParticipantChange::Remove(
                            request.requester.principal().clone(),
                        )],
                        leaf_changes: devices
                            .into_iter()
                            .map(ManifestLeafChange::Remove)
                            .collect(),
                        leaf_recovery_request_id: None,
                        welcome: None,
                    },
                    commit_sha256: [0; 32],
                    metadata,
                });
                let request = &mut state.leave_requests[request_index];
                request.terminal = Some(WorkTerminalEvidence::Transition(replacement.clone()));
                request
                    .fulfilled_participant
                    .as_mut()
                    .expect("test participant proof")
                    .terminal = replacement.clone();
                for interval in &mut state.intervals {
                    if interval.end.as_ref().is_some_and(|end| {
                        end.evidence == old_terminal
                            && interval.recipient.principal() == request.requester.principal()
                    }) {
                        interval.end.as_mut().expect("checked end").evidence = replacement.clone();
                    }
                }
            }
            LeaveFulfillmentTestMutation::DropParticipantProof => {
                state.leave_requests[request_index].fulfilled_participant = None;
            }
            LeaveFulfillmentTestMutation::ProofPrincipal(principal) => {
                state.leave_requests[request_index]
                    .fulfilled_participant
                    .as_mut()
                    .expect("test participant proof")
                    .participant
                    .principal = principal;
            }
            LeaveFulfillmentTestMutation::ProofInactive => {
                state.leave_requests[request_index]
                    .fulfilled_participant
                    .as_mut()
                    .expect("test participant proof")
                    .participant
                    .status = ParticipantStatus::Pending;
            }
            LeaveFulfillmentTestMutation::ProofInvalidProvenance => {
                let proof = state.leave_requests[request_index]
                    .fulfilled_participant
                    .as_mut()
                    .expect("test participant proof");
                proof.participant.acceptance = None;
            }
            LeaveFulfillmentTestMutation::ProofWrongTransition => {
                state.leave_requests[request_index]
                    .fulfilled_participant
                    .as_mut()
                    .expect("test participant proof")
                    .terminal
                    .transition_id[0] ^= 0x01;
            }
            LeaveFulfillmentTestMutation::ProofWrongSequence => {
                state.leave_requests[request_index]
                    .fulfilled_participant
                    .as_mut()
                    .expect("test participant proof")
                    .terminal
                    .seq += 1;
            }
            LeaveFulfillmentTestMutation::ProofWrongTime => {
                let proof = state.leave_requests[request_index]
                    .fulfilled_participant
                    .as_mut()
                    .expect("test participant proof");
                proof.terminal.received_at = proof
                    .terminal
                    .received_at
                    .checked_add_millis(1)
                    .expect("test timestamp");
            }
            LeaveFulfillmentTestMutation::IntervalLeftOpen(device) => {
                state
                    .intervals
                    .iter_mut()
                    .find(|interval| interval.recipient == device)
                    .expect("test requester interval")
                    .end = None;
            }
            LeaveFulfillmentTestMutation::IntervalClosedLater(device) => {
                state
                    .intervals
                    .iter_mut()
                    .find(|interval| interval.recipient == device)
                    .expect("test requester interval")
                    .end
                    .as_mut()
                    .expect("test interval end")
                    .evidence
                    .seq += 1;
            }
            LeaveFulfillmentTestMutation::IntervalWrongEvidence(device) => {
                state
                    .intervals
                    .iter_mut()
                    .find(|interval| interval.recipient == device)
                    .expect("test requester interval")
                    .end
                    .as_mut()
                    .expect("test interval end")
                    .evidence
                    .outer_entry_fingerprint[0] ^= 0x01;
            }
            LeaveFulfillmentTestMutation::IntervalWrongKind(device) => {
                state
                    .intervals
                    .iter_mut()
                    .find(|interval| interval.recipient == device)
                    .expect("test requester interval")
                    .end
                    .as_mut()
                    .expect("test interval end")
                    .kind = CloseKind::Replace;
            }
            LeaveFulfillmentTestMutation::IntervalOpenedAfterOrigin(device) => {
                let origin_seq = state.leave_requests[request_index]
                    .origin
                    .control_seq
                    .expect("test origin seq");
                state
                    .intervals
                    .iter_mut()
                    .find(|interval| interval.recipient == device)
                    .expect("test requester interval")
                    .opening
                    .seq = origin_seq + 1;
            }
            LeaveFulfillmentTestMutation::DuplicatePreTerminalInterval(device) => {
                let interval = state
                    .intervals
                    .iter()
                    .find(|interval| interval.recipient == device)
                    .expect("test requester interval")
                    .clone();
                state.intervals.push(interval);
            }
            LeaveFulfillmentTestMutation::LaterRejoin(device) => {
                let terminal = match state.leave_requests[request_index]
                    .terminal
                    .as_ref()
                    .expect("test terminal")
                {
                    WorkTerminalEvidence::Transition(terminal) => terminal.clone(),
                    _ => panic!("test leave terminal"),
                };
                let mut interval = state
                    .intervals
                    .iter()
                    .find(|interval| interval.recipient == device)
                    .expect("test requester interval")
                    .clone();
                interval.opening = terminal;
                interval.opening.seq += 1;
                interval.opening.transition_id[0] ^= 0x01;
                interval.opening.outer_entry_fingerprint[0] ^= 0x01;
                interval.opening_kind = OpeningKind::Add;
                interval.end = None;
                state.intervals.push(interval);
            }
        }
        state
    }
}

/// The sole state re-entry gate for rows reconstructed from durable storage.
/// Persistence adapters must first re-verify every retained evidence object,
/// then submit the assembled state here before exposing it to a planner.
pub(crate) fn hydrate_conversation_state(
    authority: &HydrationAuthority,
    rows: ConversationStateHydration,
) -> Result<ConversationState, StateMachineError> {
    if rows.coordinate.conversation_id() != &authority.expected_conversation_id {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    let candidate = ConversationState {
        kind: rows.kind,
        coordinate: rows.coordinate,
        producer: rows.producer,
        public_state: rows.public_state,
        metadata: rows.metadata,
        metadata_producer: rows.metadata_producer,
        participants: rows
            .participants
            .into_iter()
            .map(|row| ParticipantRecord {
                principal: row.principal,
                status: row.status,
                role: row.role,
                role_producer: row.role_producer,
                invitation: row.invitation.map(|invitation| InvitationProvenance {
                    transition: invitation.transition,
                    inviter: invitation.inviter,
                }),
                acceptance: row.acceptance,
            })
            .collect(),
        leaves: rows
            .leaves
            .into_iter()
            .map(|row| LeafRecord {
                device: row.device,
                leaf_index: row.leaf_index,
                basic_credential: row.basic_credential,
                signature_key: row.signature_key,
                encryption_key: row.encryption_key,
                key_package_ref: row.key_package_ref,
            })
            .collect(),
        intervals: rows
            .intervals
            .into_iter()
            .map(|row| AccessInterval {
                recipient: row.recipient,
                generation: row.generation,
                opening: row.opening,
                opening_kind: row.opening_kind,
                opening_context: row.opening_context,
                end: row.end.map(|end| AccessIntervalEnd {
                    evidence: end.evidence,
                    kind: end.kind,
                }),
            })
            .collect(),
        terminal_proofs: rows
            .terminal_proofs
            .into_iter()
            .map(|row| ScheduleTerminalProof {
                recipient: row.recipient,
                conversation_id: row.conversation_id,
                evidence: row.evidence,
            })
            .collect(),
        recovery_requests: rows
            .recovery_requests
            .into_iter()
            .map(|row| RecoveryRequest {
                request_id: row.request_id,
                target: row.target,
                kind: row.kind,
                source: row.source,
                bound_coordinate: row.bound_coordinate,
                key_package_ref: row.key_package_ref,
                received_at: row.received_at,
                expires_at: row.expires_at,
                status: row.status,
                origin: match row.origin {
                    RecoveryOriginHydrationRow::Acceptance(value) => {
                        RecoveryOriginEvidence::Acceptance(value)
                    }
                    RecoveryOriginHydrationRow::Request(value) => {
                        RecoveryOriginEvidence::Request(value)
                    }
                },
                terminal: row.terminal.map(work_terminal_from_hydration),
            })
            .collect(),
        recovery_reservations: rows
            .recovery_reservations
            .into_iter()
            .map(|row| RecoveryReservation {
                request_id: row.request_id,
                target: row.target,
                bound_coordinate: row.bound_coordinate,
                key_package_ref: row.key_package_ref,
                received_at: row.received_at,
                expires_at: row.expires_at,
                package_not_after: row.package_not_after,
                status: row.status,
                terminal: row.terminal.map(work_terminal_from_hydration),
            })
            .collect(),
        reset_requests: rows
            .reset_requests
            .into_iter()
            .map(|row| ResetRequest {
                request_id: row.request_id,
                requester: row.requester,
                bound_coordinate: row.bound_coordinate,
                received_at: row.received_at,
                expires_at: row.expires_at,
                status: row.status,
                origin: row.origin,
                terminal: row.terminal.map(work_terminal_from_hydration),
            })
            .collect(),
        leave_requests: rows
            .leave_requests
            .into_iter()
            .map(|row| LeaveRequest {
                request_id: row.request_id,
                requester: row.requester,
                bound_coordinate: row.bound_coordinate,
                received_at: row.received_at,
                expires_at: row.expires_at,
                status: row.status,
                origin: row.origin,
                terminal: row.terminal.map(work_terminal_from_hydration),
                fulfilled_participant: row.fulfilled_participant,
            })
            .collect(),
        welcomes: rows
            .welcomes
            .into_iter()
            .map(|row| WelcomeWork {
                welcome_id: row.welcome_id,
                recipient: row.recipient,
                transition_seq: row.transition_seq,
                coordinate: row.coordinate,
                recovery_request_id: row.recovery_request_id,
                key_package_ref: row.key_package_ref,
                opaque_welcome: row.opaque_welcome,
                sha256: row.sha256,
                expires_at: row.expires_at,
                status: row.status,
                terminal: row.terminal.map(work_terminal_from_hydration),
            })
            .collect(),
    };
    match candidate.coordinate.lifecycle() {
        PublicGroupSnapshotLifecycle::Active => validate_state(&candidate)?,
        PublicGroupSnapshotLifecycle::Superseded => validate_terminal_state(&candidate)?,
    }
    Ok(candidate)
}

pub(in crate::chat_protocol::state_machine) fn work_terminal_from_hydration(row: WorkTerminalHydrationRow) -> WorkTerminalEvidence {
    match row {
        WorkTerminalHydrationRow::Transition(value) => WorkTerminalEvidence::Transition(value),
        WorkTerminalHydrationRow::Request(value) => WorkTerminalEvidence::Request(value),
        WorkTerminalHydrationRow::DeviceRevocation(value) => {
            WorkTerminalEvidence::DeviceRevocation(value)
        }
        WorkTerminalHydrationRow::Expiry(value) => WorkTerminalEvidence::Expiry(value),
    }
}

impl ConversationStateHydration {
    /// Lossless sealed projection used by persistence adapters. Retained
    /// transition/request/revocation evidence is carried verbatim; no row can
    /// be reconstructed from display views or independently selected IDs.
    pub(in crate::chat_protocol::state_machine) fn from_state(state: ConversationState) -> Self {
        Self {
            kind: state.kind,
            coordinate: state.coordinate,
            producer: state.producer,
            public_state: state.public_state,
            metadata: state.metadata,
            metadata_producer: state.metadata_producer,
            participants: state
                .participants
                .into_iter()
                .map(|row| ParticipantHydrationRow {
                    principal: row.principal,
                    status: row.status,
                    role: row.role,
                    role_producer: row.role_producer,
                    invitation: row.invitation.map(|invitation| InvitationHydrationRow {
                        transition: invitation.transition,
                        inviter: invitation.inviter,
                    }),
                    acceptance: row.acceptance,
                })
                .collect(),
            leaves: state
                .leaves
                .into_iter()
                .map(|row| LeafHydrationRow {
                    device: row.device,
                    leaf_index: row.leaf_index,
                    basic_credential: row.basic_credential,
                    signature_key: row.signature_key,
                    encryption_key: row.encryption_key,
                    key_package_ref: row.key_package_ref,
                })
                .collect(),
            intervals: state
                .intervals
                .into_iter()
                .map(|row| IntervalHydrationRow {
                    recipient: row.recipient,
                    generation: row.generation,
                    opening: row.opening,
                    opening_kind: row.opening_kind,
                    opening_context: row.opening_context,
                    end: row.end.map(|end| IntervalEndHydrationRow {
                        evidence: end.evidence,
                        kind: end.kind,
                    }),
                })
                .collect(),
            terminal_proofs: state
                .terminal_proofs
                .into_iter()
                .map(|row| TerminalProofHydrationRow {
                    recipient: row.recipient,
                    conversation_id: row.conversation_id,
                    evidence: row.evidence,
                })
                .collect(),
            recovery_requests: state
                .recovery_requests
                .into_iter()
                .map(|row| RecoveryRequestHydrationRow {
                    request_id: row.request_id,
                    target: row.target,
                    kind: row.kind,
                    source: row.source,
                    bound_coordinate: row.bound_coordinate,
                    key_package_ref: row.key_package_ref,
                    received_at: row.received_at,
                    expires_at: row.expires_at,
                    status: row.status,
                    origin: match row.origin {
                        RecoveryOriginEvidence::Acceptance(value) => {
                            RecoveryOriginHydrationRow::Acceptance(value)
                        }
                        RecoveryOriginEvidence::Request(value) => {
                            RecoveryOriginHydrationRow::Request(value)
                        }
                    },
                    terminal: row.terminal.map(work_terminal_to_hydration),
                })
                .collect(),
            recovery_reservations: state
                .recovery_reservations
                .into_iter()
                .map(|row| RecoveryReservationHydrationRow {
                    request_id: row.request_id,
                    target: row.target,
                    bound_coordinate: row.bound_coordinate,
                    key_package_ref: row.key_package_ref,
                    received_at: row.received_at,
                    expires_at: row.expires_at,
                    package_not_after: row.package_not_after,
                    status: row.status,
                    terminal: row.terminal.map(work_terminal_to_hydration),
                })
                .collect(),
            reset_requests: state
                .reset_requests
                .into_iter()
                .map(|row| ResetRequestHydrationRow {
                    request_id: row.request_id,
                    requester: row.requester,
                    bound_coordinate: row.bound_coordinate,
                    received_at: row.received_at,
                    expires_at: row.expires_at,
                    status: row.status,
                    origin: row.origin,
                    terminal: row.terminal.map(work_terminal_to_hydration),
                })
                .collect(),
            leave_requests: state
                .leave_requests
                .into_iter()
                .map(|row| LeaveRequestHydrationRow {
                    request_id: row.request_id,
                    requester: row.requester,
                    bound_coordinate: row.bound_coordinate,
                    received_at: row.received_at,
                    expires_at: row.expires_at,
                    status: row.status,
                    origin: row.origin,
                    terminal: row.terminal.map(work_terminal_to_hydration),
                    fulfilled_participant: row.fulfilled_participant,
                })
                .collect(),
            welcomes: state
                .welcomes
                .into_iter()
                .map(|row| WelcomeHydrationRow {
                    welcome_id: row.welcome_id,
                    recipient: row.recipient,
                    transition_seq: row.transition_seq,
                    coordinate: row.coordinate,
                    recovery_request_id: row.recovery_request_id,
                    key_package_ref: row.key_package_ref,
                    opaque_welcome: row.opaque_welcome,
                    sha256: row.sha256,
                    expires_at: row.expires_at,
                    status: row.status,
                    terminal: row.terminal.map(work_terminal_to_hydration),
                })
                .collect(),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test_from_state(state: ConversationState) -> Self {
        Self::from_state(state)
    }
}

pub(in crate::chat_protocol::state_machine) fn work_terminal_to_hydration(row: WorkTerminalEvidence) -> WorkTerminalHydrationRow {
    match row {
        WorkTerminalEvidence::Transition(value) => WorkTerminalHydrationRow::Transition(value),
        WorkTerminalEvidence::Request(value) => WorkTerminalHydrationRow::Request(value),
        WorkTerminalEvidence::DeviceRevocation(value) => {
            WorkTerminalHydrationRow::DeviceRevocation(value)
        }
        WorkTerminalEvidence::Expiry(value) => WorkTerminalHydrationRow::Expiry(value),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PlanKind {
    Creation,
    Policy,
    Acceptance,
    Metadata,
    Commit,
    RecoveryRequest,
    RecoveryCancellation,
    RecoveryExpiry,
    DeviceRevocation,
    ResetRequest,
    ResetActivation,
    LeaveRequest,
    LeaveCancellation,
    ZeroLeafLeave,
    WelcomeAcknowledgement,
    WelcomeRejection,
    WelcomeExpiry,
    Close,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PackageStatus {
    Available,
    Reserved,
    Consumed,
    Expired,
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PackageTransition {
    pub(in crate::chat_protocol::state_machine) request_id: [u8; 16],
    pub(in crate::chat_protocol::state_machine) key_package_ref: [u8; 32],
    pub(in crate::chat_protocol::state_machine) from: PackageStatus,
    pub(in crate::chat_protocol::state_machine) to: PackageStatus,
}
