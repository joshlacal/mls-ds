#![allow(unused_imports)]
use super::*;


/// Fingerprint admission must reject every Recovery-fulfillment family splice,
/// not merely find one valid edge inside a larger malformed family. The
/// executor repeats the deeper identity/bijection checks before its first
/// writer; this pure fence keeps the sealed fingerprint contract closed too.
pub(in crate::chat_protocol::state_machine) fn fulfillment_fingerprint_families_are_closed(
    effects: &TransitionEffects,
    producer: &TransitionEvidence,
) -> bool {
    let exact_terminal = |terminal: &Option<WorkTerminalEvidence>| matches!(terminal, Some(WorkTerminalEvidence::Transition(value)) if value == producer);

    let (own_request_id, prior) = match producer.body_binding.as_ref() {
        Some(TransitionBodyBinding::LeafRecoveryFulfillment {
            recovery_request_id,
            prior,
            ..
        }) => (*recovery_request_id, *prior),
        _ => return false,
    };
    let exact_due = |terminal: &Option<WorkTerminalEvidence>, expires_at: ServerTimestamp| {
        expires_at <= producer.received_at
            && matches!(terminal, Some(WorkTerminalEvidence::Expiry(at)) if *at == expires_at)
    };
    let mut own_request = None;
    let mut peer_requests = BTreeMap::new();
    for change in &effects.recovery_request_changes {
        let (Some(before), Some(after)) = (&change.before, &change.after) else {
            return false;
        };
        if before.request_id != after.request_id
            || before.target != after.target
            || before.kind != after.kind
            || before.source != after.source
            || before.bound_coordinate != after.bound_coordinate
            || before.bound_coordinate != prior
            || before.key_package_ref != after.key_package_ref
            || before.received_at != after.received_at
            || before.expires_at != after.expires_at
            || before.origin != after.origin
            || before.status != RecoveryRequestStatus::Open
            || before.terminal.is_some()
        {
            return false;
        }
        let key = (after.request_id, after.key_package_ref);
        if after.request_id == own_request_id {
            if after.status != RecoveryRequestStatus::Fulfilled
                || !exact_terminal(&after.terminal)
                || own_request.replace(key).is_some()
            {
                return false;
            }
        } else {
            let expired = match after.status {
                RecoveryRequestStatus::Superseded if exact_terminal(&after.terminal) => false,
                RecoveryRequestStatus::Expired if exact_due(&after.terminal, after.expires_at) => {
                    true
                }
                _ => return false,
            };
            if peer_requests.insert(key, (after, expired)).is_some() {
                return false;
            }
        }
    }

    let mut own_reservation = None;
    let mut peer_reservations = BTreeMap::new();
    let mut expected_packages = BTreeMap::new();
    for change in &effects.reservation_changes {
        let (Some(before), Some(after)) = (&change.before, &change.after) else {
            return false;
        };
        if before.request_id != after.request_id
            || before.target != after.target
            || before.bound_coordinate != after.bound_coordinate
            || before.bound_coordinate != prior
            || before.key_package_ref != after.key_package_ref
            || before.received_at != after.received_at
            || before.expires_at != after.expires_at
            || before.package_not_after != after.package_not_after
            || before.expires_at > before.package_not_after
            || before.status != ReservationStatus::Active
            || before.terminal.is_some()
        {
            return false;
        }
        let key = (after.request_id, after.key_package_ref);
        let successor = if after.request_id == own_request_id {
            if after.status != ReservationStatus::Consumed
                || !exact_terminal(&after.terminal)
                || own_reservation.replace(key).is_some()
            {
                return false;
            }
            PackageStatus::Consumed
        } else {
            let expired = match after.status {
                ReservationStatus::Released if exact_terminal(&after.terminal) => false,
                ReservationStatus::Expired if exact_due(&after.terminal, after.expires_at) => true,
                _ => return false,
            };
            let Some((request, request_expired)) = peer_requests.get(&key) else {
                return false;
            };
            if *request_expired != expired
                || request.target != after.target
                || request.bound_coordinate != after.bound_coordinate
                || request.received_at != after.received_at
                || request.expires_at != after.expires_at
                || peer_reservations.insert(key, ()).is_some()
            {
                return false;
            }
            // The executor admits only released peer packages. A package-end
            // expiry is not this prior-bound family (minimum remaining package
            // lifetime exceeds the request TTL) and must not enter its seal.
            if expired && after.expires_at == after.package_not_after {
                return false;
            }
            PackageStatus::Available
        };
        if expected_packages.insert(key, successor).is_some() {
            return false;
        }
    }
    let mut actual_packages = BTreeMap::new();
    let mut package_refs = BTreeSet::new();
    for edge in &effects.package_transitions {
        if edge.from != PackageStatus::Reserved
            || !matches!(edge.to, PackageStatus::Consumed | PackageStatus::Available)
            || actual_packages
                .insert((edge.request_id, edge.key_package_ref), edge.to)
                .is_some()
            || !package_refs.insert(edge.key_package_ref)
        {
            return false;
        }
    }

    let mut own_welcomes = 0usize;
    for change in &effects.welcome_changes {
        match (&change.before, &change.after) {
            (None, Some(after))
                if after.status == WelcomeStatus::Pending && after.terminal.is_none() =>
            {
                own_welcomes += 1;
            }
            (Some(before), Some(after))
                if before.status == WelcomeStatus::Pending
                    && before.terminal.is_none()
                    && after.status == WelcomeStatus::Superseded
                    && exact_terminal(&after.terminal)
                    && before.welcome_id == after.welcome_id
                    && before.recipient == after.recipient
                    && before.transition_seq == after.transition_seq
                    && before.coordinate == after.coordinate
                    && before.recovery_request_id == after.recovery_request_id
                    && before.key_package_ref == after.key_package_ref
                    && before.opaque_welcome == after.opaque_welcome
                    && before.sha256 == after.sha256
                    && before.expires_at == after.expires_at => {}
            _ => return false,
        }
    }

    let legal_reset = effects.reset_request_changes.iter().all(|change| {
        matches!(
            (&change.before, &change.after),
            (Some(before), Some(after))
                if before.status == ResetRequestStatus::Pending
                    && before.terminal.is_none()
                    && after.status == ResetRequestStatus::Stale
                    && exact_terminal(&after.terminal)
                    && before.request_id == after.request_id
                    && before.requester == after.requester
                    && before.bound_coordinate == after.bound_coordinate
                    && before.received_at == after.received_at
                    && before.expires_at == after.expires_at
                    && before.origin == after.origin
        )
    });
    let legal_leave = effects.leave_request_changes.iter().all(|change| {
        matches!(
            (&change.before, &change.after),
            (Some(before), Some(after))
                if before.status == LeaveRequestStatus::Pending
                    && before.terminal.is_none()
                    && after.status == LeaveRequestStatus::Stale
                    && exact_terminal(&after.terminal)
                    && before.request_id == after.request_id
                    && before.requester == after.requester
                    && before.bound_coordinate == after.bound_coordinate
                    && before.received_at == after.received_at
                    && before.expires_at == after.expires_at
                    && before.origin == after.origin
                    && before.fulfilled_participant == after.fulfilled_participant
        )
    });

    own_request.is_some()
        && own_request == own_reservation
        && own_welcomes == 1
        && peer_requests.len() == peer_reservations.len()
        && expected_packages == actual_packages
        && legal_reset
        && legal_leave
}

pub(in crate::chat_protocol::state_machine) fn exact_recovery_request_edge(
    change: &StateChange<RecoveryRequest>,
    before_status: Option<RecoveryRequestStatus>,
    after_status: RecoveryRequestStatus,
) -> bool {
    match (&change.before, &change.after, before_status) {
        (None, Some(after), None) => after.status == after_status,
        (Some(before), Some(after), Some(before_status)) => {
            before.request_id == after.request_id
                && before.status == before_status
                && after.status == after_status
        }
        _ => false,
    }
}

pub(in crate::chat_protocol::state_machine) fn exact_reservation_edge(
    change: &StateChange<RecoveryReservation>,
    before_status: Option<ReservationStatus>,
    after_status: ReservationStatus,
) -> bool {
    match (&change.before, &change.after, before_status) {
        (None, Some(after), None) => after.status == after_status,
        (Some(before), Some(after), Some(before_status)) => {
            before.request_id == after.request_id
                && before.status == before_status
                && after.status == after_status
        }
        _ => false,
    }
}

pub(in crate::chat_protocol::state_machine) struct RecoveryPlanEncoder {
    pub(in crate::chat_protocol::state_machine) digest: Sha256,
}

impl RecoveryPlanEncoder {
    pub(in crate::chat_protocol::state_machine) fn new() -> Self {
        Self {
            digest: Sha256::new(),
        }
    }

    pub(in crate::chat_protocol::state_machine) fn finish(self) -> [u8; 32] {
        self.digest.finalize().into()
    }

    pub(in crate::chat_protocol::state_machine) fn bytes(&mut self, bytes: &[u8]) {
        self.digest.update((bytes.len() as u64).to_be_bytes());
        self.digest.update(bytes);
    }

    pub(in crate::chat_protocol::state_machine) fn u8(&mut self, value: u8) {
        self.bytes(&[value]);
    }

    pub(in crate::chat_protocol::state_machine) fn u32(&mut self, value: u32) {
        self.bytes(&value.to_be_bytes());
    }

    pub(in crate::chat_protocol::state_machine) fn u64(&mut self, value: u64) {
        self.bytes(&value.to_be_bytes());
    }

    pub(in crate::chat_protocol::state_machine) fn usize(&mut self, value: usize) {
        self.u64(value as u64);
    }

    pub(in crate::chat_protocol::state_machine) fn i64(&mut self, value: i64) {
        self.bytes(&value.to_be_bytes());
    }

    pub(in crate::chat_protocol::state_machine) fn bool(&mut self, value: bool) {
        self.u8(u8::from(value));
    }

    pub(in crate::chat_protocol::state_machine) fn option<T: ?Sized>(&mut self, value: Option<&T>, encode: impl FnOnce(&mut Self, &T)) {
        match value {
            None => self.u8(0),
            Some(value) => {
                self.u8(1);
                encode(self, value);
            }
        }
    }

    pub(in crate::chat_protocol::state_machine) fn slice<T>(&mut self, values: &[T], mut encode: impl FnMut(&mut Self, &T)) {
        self.u64(values.len() as u64);
        for value in values {
            encode(self, value);
        }
    }

    pub(in crate::chat_protocol::state_machine) fn coordinate(&mut self, value: &PublicGroupSnapshotCoordinate) {
        self.bytes(value.conversation_id());
        self.u64(value.generation());
        self.u64(value.state_version());
        self.bytes(value.group_id());
        self.u64(value.epoch());
        self.bytes(value.group_context_hash());
        self.bytes(value.confirmation_tag());
        self.u8(match value.lifecycle() {
            PublicGroupSnapshotLifecycle::Active => 1,
            PublicGroupSnapshotLifecycle::Superseded => 2,
        });
    }

    pub(in crate::chat_protocol::state_machine) fn device(&mut self, value: &DeviceIdentity) {
        self.bytes(value.principal().as_bytes());
        self.bytes(value.device_id());
    }

    pub(in crate::chat_protocol::state_machine) fn timestamp(&mut self, value: ServerTimestamp) {
        self.i64(value.unix_millis());
    }

    pub(in crate::chat_protocol::state_machine) fn authenticated_entry(&mut self, value: &AuthenticatedEntryEvidence) {
        self.u8(signed_mutation_kind_code(value.kind));
        self.bytes(value.type_id.as_bytes());
        self.bytes(&value.domain);
        self.option(value.control_entry_id.as_ref(), |encoder, value| {
            encoder.bytes(value)
        });
        self.option(value.control_conversation_id.as_ref(), |encoder, value| {
            encoder.bytes(value)
        });
        self.device(&value.actor);
        self.bytes(&value.key_id);
        self.u64(value.auth_generation);
        self.timestamp(value.signed_at);
        self.bytes(&value.request_digest);
        self.bytes(&value.signature);
        self.bytes(&value.signed_request_bytes);
        self.bytes(&value.canonical_projection);
        self.bytes(&value.transcript_bytes);
    }

    pub(in crate::chat_protocol::state_machine) fn transition(&mut self, value: &TransitionEvidence) {
        self.u64(value.seq);
        self.bytes(&value.transition_id);
        self.bytes(&value.outer_entry_fingerprint);
        self.bytes(&value.outer_control_projection);
        self.bytes(&value.server_fields_dag_cbor);
        self.bytes(&value.durable_row_digest);
        self.timestamp(value.received_at);
        self.option(value.authority.as_ref(), Self::authenticated_entry);
        self.option(value.body_binding.as_ref(), Self::transition_body);
    }

    pub(in crate::chat_protocol::state_machine) fn transition_body(&mut self, value: &TransitionBodyBinding) {
        match value {
            TransitionBodyBinding::DirectRequestPublication {
                prior,
                next,
                recipient,
                devices,
                metadata,
            } => {
                self.u8(11);
                self.option(prior.as_ref(), Self::coordinate);
                self.coordinate(next);
                self.bytes(recipient.as_bytes());
                self.slice(devices, Self::device);
                self.metadata(metadata);
            }
            TransitionBodyBinding::DirectRequestAcceptance {
                request_id,
                prior,
                next,
                invitation,
            } => {
                self.u8(12);
                self.bytes(request_id);
                self.coordinate(prior);
                self.coordinate(next);
                self.invitation_binding(invitation);
            }
            TransitionBodyBinding::Creation {
                kind,
                next,
                manifest,
                group_info_sha256,
                metadata,
            } => {
                self.u8(1);
                self.u8(conversation_kind_code(*kind));
                self.coordinate(next);
                self.roster_manifest(manifest);
                self.bytes(group_info_sha256);
                self.metadata(metadata);
            }
            TransitionBodyBinding::Commit {
                prior,
                next,
                aad_digest,
                manifest,
                commit_sha256,
                metadata,
            } => {
                self.u8(2);
                self.coordinate(prior);
                self.coordinate(next);
                self.bytes(aad_digest);
                self.transition_manifest(manifest);
                self.bytes(commit_sha256);
                self.metadata(metadata);
            }
            TransitionBodyBinding::Policy {
                prior,
                next,
                participant_changes,
            } => {
                self.u8(3);
                self.coordinate(prior);
                self.coordinate(next);
                self.slice(participant_changes, Self::manifest_participant_change);
            }
            TransitionBodyBinding::Acceptance {
                prior,
                next,
                recovery_request_id,
                invitation_provenance,
                recovery,
            } => {
                self.u8(4);
                self.coordinate(prior);
                self.coordinate(next);
                self.bytes(recovery_request_id);
                self.invitation_binding(invitation_provenance);
                self.acceptance_recovery(recovery);
            }
            TransitionBodyBinding::Metadata {
                prior,
                next,
                metadata,
            } => {
                self.u8(5);
                self.coordinate(prior);
                self.coordinate(next);
                self.metadata(metadata);
            }
            TransitionBodyBinding::ResetActivation {
                kind,
                reset_request_id,
                prior,
                retired,
                successor,
                manifest,
                group_info_sha256,
                metadata,
            } => {
                self.u8(6);
                self.u8(conversation_kind_code(*kind));
                self.bytes(reset_request_id);
                self.coordinate(prior);
                self.coordinate(retired);
                self.coordinate(successor);
                self.roster_manifest(manifest);
                self.bytes(group_info_sha256);
                self.metadata(metadata);
            }
            TransitionBodyBinding::LeafRecoveryFulfillment {
                recovery_request_id,
                prior,
                next,
                aad_digest,
                manifest,
                commit_sha256,
                metadata,
            } => {
                self.u8(7);
                self.bytes(recovery_request_id);
                self.coordinate(prior);
                self.coordinate(next);
                self.bytes(aad_digest);
                self.transition_manifest(manifest);
                self.bytes(commit_sha256);
                self.metadata(metadata);
            }
            TransitionBodyBinding::ConversationClose {
                kind,
                prior,
                retired,
            } => {
                self.u8(8);
                self.u8(conversation_kind_code(*kind));
                self.coordinate(prior);
                self.coordinate(retired);
            }
            TransitionBodyBinding::ZeroLeafLeave { prior, next } => {
                self.u8(9);
                self.coordinate(prior);
                self.coordinate(next);
            }
            TransitionBodyBinding::LeaveCommitFulfillment {
                leave_request_id,
                prior,
                next,
                aad_digest,
                manifest,
                commit_sha256,
                metadata,
            } => {
                self.u8(10);
                self.bytes(leave_request_id);
                self.coordinate(prior);
                self.coordinate(next);
                self.bytes(aad_digest);
                self.transition_manifest(manifest);
                self.bytes(commit_sha256);
                self.metadata(metadata);
            }
        }
    }

    pub(in crate::chat_protocol::state_machine) fn roster_manifest(&mut self, value: &RosterManifestBinding) {
        self.slice(&value.participants, |encoder, participant| {
            encoder.bytes(participant.principal.as_bytes());
            encoder.u8(participant_status_code(participant.status));
            encoder.u8(participant_role_code(participant.role));
            encoder.option(participant.invitation.as_ref(), Self::invitation_binding);
        });
        self.device(&value.actor_leaf);
    }

    pub(in crate::chat_protocol::state_machine) fn invitation_binding(&mut self, value: &InvitationBinding) {
        self.bytes(&value.transition_id);
        self.device(&value.inviter);
    }

    pub(in crate::chat_protocol::state_machine) fn acceptance_recovery(&mut self, value: &AcceptanceRecoveryBinding) {
        self.bytes(&value.request_id);
        self.bytes(&value.conversation_id);
        self.device(&value.target);
        self.u8(recovery_kind_code(value.kind));
        self.coordinate(&value.bound_coordinate);
        self.bytes(&value.requester_key_id);
        self.u64(value.requester_auth_generation);
        self.bytes(&value.key_package_ref);
        self.bytes(&value.key_package_wrapper);
        self.bytes(&value.key_package_wrapper_sha256);
        self.timestamp(value.requested_at);
        self.timestamp(value.expires_at);
        self.bytes(&value.canonical_digest);
    }

    pub(in crate::chat_protocol::state_machine) fn transition_manifest(&mut self, value: &TransitionManifestBinding) {
        self.slice(
            &value.participant_changes,
            Self::manifest_participant_change,
        );
        self.slice(&value.leaf_changes, Self::manifest_leaf_change);
        self.option(value.leaf_recovery_request_id.as_ref(), |encoder, value| {
            encoder.bytes(value)
        });
        self.option(value.welcome.as_ref(), |encoder, welcome| {
            encoder.bytes(&welcome.welcome_id);
            encoder.bytes(&welcome.opaque_welcome);
            encoder.bytes(&welcome.sha256);
            encoder.device(&welcome.recipient);
            encoder.bytes(&welcome.recovery_request_id);
            encoder.bytes(&welcome.key_package_ref);
        });
    }

    pub(in crate::chat_protocol::state_machine) fn manifest_participant_change(&mut self, value: &ManifestParticipantChange) {
        match value {
            ManifestParticipantChange::Add(principal) => {
                self.u8(1);
                self.bytes(principal.as_bytes());
            }
            ManifestParticipantChange::Remove(principal) => {
                self.u8(2);
                self.bytes(principal.as_bytes());
            }
            ManifestParticipantChange::ChangeRole(principal, role) => {
                self.u8(3);
                self.bytes(principal.as_bytes());
                self.u8(participant_role_code(*role));
            }
        }
    }

    pub(in crate::chat_protocol::state_machine) fn manifest_leaf_change(&mut self, value: &ManifestLeafChange) {
        match value {
            ManifestLeafChange::Add {
                device,
                recovery_request_id,
                key_package_ref,
            } => {
                self.u8(1);
                self.device(device);
                self.bytes(recovery_request_id);
                self.bytes(key_package_ref);
            }
            ManifestLeafChange::Remove(device) => {
                self.u8(2);
                self.device(device);
            }
        }
    }

    pub(in crate::chat_protocol::state_machine) fn request(&mut self, value: &RequestEvidence) {
        self.u8(request_kind_code(value.kind));
        self.option(value.control_entry_id.as_ref(), |encoder, value| {
            encoder.bytes(value)
        });
        self.bytes(&value.conversation_id);
        self.option(value.control_seq.as_ref(), |encoder, value| {
            encoder.u64(*value)
        });
        self.option(
            value.control_outer_entry_fingerprint.as_ref(),
            |encoder, value| encoder.bytes(value),
        );
        self.option(
            value.control_outer_projection.as_deref(),
            |encoder, value| encoder.bytes(value),
        );
        self.option(
            value.control_server_fields_dag_cbor.as_deref(),
            |encoder, value| encoder.bytes(value),
        );
        self.bytes(&value.request_id);
        self.device(&value.actor);
        self.bytes(&value.key_id);
        self.u64(value.auth_generation);
        self.bytes(&value.request_digest);
        self.bytes(&value.signature);
        self.bytes(&value.signed_request_bytes);
        self.bytes(&value.durable_row_digest);
        self.timestamp(value.received_at);
        self.option(value.authority.as_ref(), Self::authenticated_entry);
        self.option(
            value.body_binding.as_ref(),
            |encoder, binding| match binding {
                RequestBodyBinding::LeafRecoveryRequest { prior, kind } => {
                    encoder.u8(1);
                    encoder.coordinate(prior);
                    encoder.u8(recovery_kind_code(*kind));
                }
                RequestBodyBinding::LeafRecoveryCancellation => encoder.u8(2),
                RequestBodyBinding::ResetRequest { prior } => {
                    encoder.u8(3);
                    encoder.coordinate(prior);
                }
                RequestBodyBinding::LeaveRequest { prior } => {
                    encoder.u8(4);
                    encoder.coordinate(prior);
                }
                RequestBodyBinding::LeaveCancellation { conversation_id } => {
                    encoder.u8(5);
                    encoder.bytes(conversation_id);
                }
                RequestBodyBinding::WelcomeResponse {
                    coordinates,
                    transition_seq,
                    rejection_reason,
                } => {
                    encoder.u8(6);
                    encoder.coordinate(coordinates);
                    encoder.u64(*transition_seq);
                    encoder.option(rejection_reason.as_deref(), |encoder, value| {
                        encoder.bytes(value.as_bytes())
                    });
                }
            },
        );
    }

    pub(in crate::chat_protocol::state_machine) fn device_revocation(&mut self, value: &DeviceRevocationEvidence) {
        self.bytes(&value.revocation_id);
        self.device(&value.actor);
        self.device(&value.target);
        self.bytes(&value.actor_key_id);
        self.u64(value.actor_auth_generation);
        self.u64(value.expected_target_auth_generation);
        self.timestamp(value.signed_at);
        self.timestamp(value.accepted_at);
        self.bytes(&value.request_digest);
        self.bytes(&value.signature);
        self.bytes(&value.signed_request_bytes);
        self.bytes(&value.signing_transcript_bytes);
        self.bytes(&value.durable_row_digest);
    }

    pub(in crate::chat_protocol::state_machine) fn plan_authority(&mut self, value: &PlanAuthority) {
        match value {
            PlanAuthority::Transition(value) => {
                self.u8(1);
                self.transition(value);
            }
            PlanAuthority::Request(value) => {
                self.u8(2);
                self.request(value);
            }
            PlanAuthority::DeviceRevocation(value) => {
                self.u8(3);
                self.device_revocation(value);
            }
            PlanAuthority::RecoveryExpiry(value) => {
                self.u8(4);
                self.bytes(&value.request_id);
                self.device(&value.requester);
                self.timestamp(value.terminal_at);
                self.timestamp(value.observed_at);
                self.bytes(&value.locked_read_set_digest);
            }
            PlanAuthority::WelcomeExpiry(value) => {
                self.u8(5);
                self.bytes(&value.welcome_id);
                self.device(&value.recipient);
                self.coordinate(&value.coordinate);
                self.u64(value.transition_seq);
                self.timestamp(value.terminal_at);
                self.timestamp(value.observed_at);
                self.bytes(&value.locked_row_digest);
            }
        }
    }

    pub(in crate::chat_protocol::state_machine) fn metadata(&mut self, value: &MetadataSnapshotBinding) {
        self.bytes(&value.coordinate.conversation_id);
        self.u64(value.coordinate.generation);
        self.u64(value.coordinate.epoch);
        self.bytes(&value.coordinate.group_context_hash);
        self.bytes(&value.origin_transition_id);
        self.u64(value.metadata_version);
        self.bytes(&value.nonce);
        self.bytes(&value.ciphertext);
        self.bytes(&value.ciphertext_sha256);
        self.option(value.avatar_binding.as_ref(), |encoder, value| {
            encoder.bytes(&value.blob_id);
            encoder.bytes(&value.ciphertext_sha256);
            encoder.u64(value.ciphertext_size);
            encoder.bytes(&value.canonical_descriptor);
            encoder.bytes(&value.digest);
        });
        self.device(&value.author_proof.author);
        self.bytes(&value.author_proof.author_key_id);
        self.bytes(&value.author_proof.signature_public_key);
        self.u64(value.author_proof.auth_generation_at_origin);
        self.bytes(&value.author_proof.origin_transition_id);
        self.u64(value.author_proof.origin_seq);
        self.bytes(&value.canonical_snapshot);
        self.bytes(&value.digest);
    }
}
