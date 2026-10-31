#![allow(unused_imports)]
use super::*;


/// Fulfill retained group-leave consent with a different-DID current leaf.
/// The Commit must remove every and only requester leaf and contain no Add.
pub(in crate::chat_protocol::state_machine) fn plan_leave_fulfillment_inner(
    prior: &ConversationState,
    command: LeaveFulfillment,
) -> Result<PlannedTransition, StateMachineError> {
    ensure_active(prior)?;
    require_transition_kind(
        &command.transition,
        SignedMutationKind::LeaveCommitFulfillment,
    )?;
    require_transition_actor(&command.transition, &command.actor)?;
    if prior.kind == ConversationKind::Direct {
        return Err(StateMachineError::DirectParticipantMutationForbidden);
    }
    let request = prior
        .leave_requests
        .iter()
        .find(|request| {
            request.request_id == command.leave_request_id
                && request.status == LeaveRequestStatus::Pending
        })
        .ok_or(StateMachineError::LeaveRequestNotFound)?;
    if request.bound_coordinate != prior.coordinate
        || request.requester.principal() != &command.requester
    {
        return Err(StateMachineError::LeaveRequestNotFound);
    }
    if command.transition.received_at >= request.expires_at {
        return Err(StateMachineError::WorkExpired);
    }
    if command.actor.principal() == &command.requester || prior.leaf(&command.actor).is_none() {
        return Err(StateMachineError::InvalidCommitEffects);
    }
    if command.commit.prior_coordinate() != &prior.coordinate {
        return Err(StateMachineError::StaleCoordinates);
    }
    require_commit_body(
        &command.transition,
        SignedMutationKind::LeaveCommitFulfillment,
        prior,
        &command.commit,
        Some(&command.leave_request_id),
    )?;
    if !command.commit.adds().is_empty() {
        return Err(StateMachineError::InvalidCommitEffects);
    }
    require_commit_manifest(
        prior,
        &command.transition,
        &command.commit,
        CommitManifestForm::Leave {
            requester: &command.requester,
        },
    )?;
    let requester = prior
        .participant(&command.requester)
        .ok_or(StateMachineError::NotParticipant)?;
    if !requester.is_active() {
        return Err(StateMachineError::NotMember);
    }
    let fulfilled_participant = requester.clone();
    if would_remove_last_active_admin(prior, &command.requester) {
        return Err(StateMachineError::LastAdminRequired);
    }
    verify_commit_actor(prior, &command.actor, &command.commit)?;

    let requester_leaves = prior
        .leaves
        .iter()
        .filter(|leaf| leaf.device.principal() == &command.requester)
        .collect::<Vec<_>>();
    if requester_leaves.is_empty() || requester_leaves.len() != command.commit.removes().len() {
        return Err(StateMachineError::InvalidCommitEffects);
    }
    let expected_indices = requester_leaves
        .iter()
        .map(|leaf| leaf.leaf_index)
        .collect::<BTreeSet<_>>();
    let removed_indices = command
        .commit
        .removes()
        .iter()
        .map(|effect| effect.leaf_index())
        .collect::<BTreeSet<_>>();
    if expected_indices != removed_indices {
        return Err(StateMachineError::InvalidCommitEffects);
    }
    for effect in command.commit.removes() {
        let leaf = requester_leaves
            .iter()
            .find(|leaf| leaf.leaf_index == effect.leaf_index())
            .ok_or(StateMachineError::InvalidCommitEffects)?;
        if effect.basic_credential() != leaf.basic_credential
            || effect.signature_key() != leaf.signature_key
        {
            return Err(StateMachineError::InvalidCommitEffects);
        }
    }

    let mut state = prior.clone();
    let mut effects = TransitionEffects::new(PlanKind::Commit);
    for leaf in &requester_leaves {
        close_open_interval(
            &mut state.intervals,
            &leaf.device,
            &command.transition,
            CloseKind::Remove,
        )?;
        effects.closed_intervals.push(leaf.device.clone());
    }
    state.leaves = materialize_next_leaves(prior, &command.commit, None)?;
    state
        .participants
        .retain(|participant| participant.principal != command.requester);
    effects.superseded_recovery_requests = state
        .recovery_requests
        .iter()
        .filter(|request| {
            request.status == RecoveryRequestStatus::Open
                && request.bound_coordinate == prior.coordinate
        })
        .map(|request| request.request_id)
        .collect();
    resolve_prior_bound_work(
        &mut state,
        &prior.coordinate,
        &command.transition,
        None,
        None,
        Some(command.leave_request_id),
    );
    let fulfilled_request = state
        .leave_requests
        .iter_mut()
        .find(|request| request.request_id == command.leave_request_id)
        .ok_or(StateMachineError::InvariantViolation)?;
    fulfilled_request.fulfilled_participant = Some(ParticipantRemovalEvidence {
        participant: fulfilled_participant,
        terminal: command.transition.clone(),
    });
    state.coordinate = *command.commit.next().coordinate();
    state.producer = command.transition.clone();
    state.metadata = transition_metadata(&command.transition).cloned();
    state.metadata_producer = state.metadata.as_ref().map(|_| command.transition.clone());
    state.public_state = Some(command.commit.into_next());
    validate_state(&state)?;
    effects.complete(Some(prior), &state);
    Ok(PlannedTransition {
        expected_prior: Some(prior.coordinate),
        retired_coordinate: None,
        successor_coordinate: Some(state.coordinate),
        state,
        effects,
    })
}

pub(crate) struct CloseConversation {
    pub(crate) actor: DeviceIdentity,
    pub(crate) transition: TransitionEvidence,
}

pub(in crate::chat_protocol::state_machine) fn plan_close_inner(
    prior: &ConversationState,
    command: CloseConversation,
) -> Result<PlannedTransition, StateMachineError> {
    ensure_active(prior)?;
    require_transition_kind(&command.transition, SignedMutationKind::ConversationClose)?;
    require_transition_actor(&command.transition, &command.actor)?;
    let actor = prior
        .participant(command.actor.principal())
        .ok_or(StateMachineError::NotParticipant)?;
    match prior.kind {
        ConversationKind::Direct => {}
        ConversationKind::Group
            if prior.participants.len() == 1
                && actor.status == ParticipantStatus::Active
                && actor.role == ParticipantRole::Admin => {}
        ConversationKind::Group => return Err(StateMachineError::ConversationCloseNotAllowed),
    }
    let latest_historical_seq = prior
        .intervals
        .iter()
        .map(|interval| {
            interval
                .end
                .as_ref()
                .map_or(interval.opening.seq, |end| end.evidence.seq)
        })
        .max()
        .ok_or(StateMachineError::InvalidIntervalBoundary)?;
    if command.transition.seq <= latest_historical_seq {
        return Err(StateMachineError::InvalidIntervalBoundary);
    }
    let retired = retired_coordinate(&prior.coordinate)?;
    require_coordinate_only_body(
        &command.transition,
        SignedMutationKind::ConversationClose,
        prior.kind,
        &prior.coordinate,
        &retired,
    )?;
    let mut state = prior.clone();
    let mut effects = TransitionEffects::new(PlanKind::Close);
    let open_devices = state
        .intervals
        .iter()
        .filter(|interval| interval.end.is_none())
        .map(|interval| interval.recipient.clone())
        .collect::<Vec<_>>();
    for device in &open_devices {
        close_open_interval(
            &mut state.intervals,
            device,
            &command.transition,
            CloseKind::Terminal,
        )?;
    }
    effects.closed_intervals = open_devices;

    let historical_devices = state
        .intervals
        .iter()
        .map(|interval| interval.recipient.clone())
        .collect::<BTreeSet<_>>();
    if historical_devices
        .iter()
        .any(|device| state.terminal_proof(device).is_some())
    {
        return Err(StateMachineError::ConversationClosed);
    }
    state.terminal_proofs = historical_devices
        .iter()
        .cloned()
        .map(|recipient| ScheduleTerminalProof {
            recipient,
            conversation_id: *prior.coordinate.conversation_id(),
            evidence: command.transition.clone(),
        })
        .collect();
    effects.terminal_proof_recipients = historical_devices.into_iter().collect();
    effects.superseded_recovery_requests = state
        .recovery_requests
        .iter()
        .filter(|request| {
            request.status == RecoveryRequestStatus::Open
                && request.bound_coordinate == prior.coordinate
        })
        .map(|request| request.request_id)
        .collect();
    resolve_prior_bound_work(
        &mut state,
        &prior.coordinate,
        &command.transition,
        None,
        None,
        None,
    );
    state.coordinate = retired;
    state.producer = command.transition.clone();
    state.public_state = None;
    state.leaves.clear();
    validate_terminal_state(&state)?;
    effects.complete(Some(prior), &state);
    Ok(PlannedTransition {
        expected_prior: Some(prior.coordinate),
        retired_coordinate: Some(retired),
        successor_coordinate: None,
        state,
        effects,
    })
}

// ---------------------------------------------------------------------------
// Task E2b-3 test-support: build a metadata-bearing creation
// `ConversationPersistencePlan` from the pure planner + a synthesized head CAS,
// so the executor's end-to-end COMMIT path can be exercised from the integration
// harness. These are the minimal `pub(crate)` seams the E2b-2 report anticipated.
//
// FAITHFULNESS: production creation evidence (authenticated) carries a
// `Creation` body whose metadata has `metadata_version == 1`,
// `origin_transition_id == transitionId`, `author == actor`, and
// `roleAtOrigin/deviceStatusAtOrigin == admin/active` (validated during
// `decode_metadata_snapshot`, and re-checked by `require_creation_body` +
// `metadata_author_matches_evidence` whenever `authority.is_some()`). The
// constructors below reproduce exactly that shape. `require_creation_body` skips
// the manifest/author cross-checks when `authority.is_none()` (the test-seam
// case), so a bare roster manifest is legal here; the metadata itself is still
// built to the production shape the COMMIT-time trigger demands. No production
// path (`plan_*`, `require_creation_body`, the decode) is modified.
// ---------------------------------------------------------------------------
#[cfg(test)]
impl MetadataSnapshotBinding {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_test_creation(
        conversation_id: [u8; 16],
        generation: u64,
        group_id: [u8; 32],
        epoch: u64,
        group_context_hash: [u8; 32],
        confirmation_tag: [u8; 32],
        transition_id: [u8; 16],
        origin_seq: u64,
        author: DeviceIdentity,
        author_key_id: [u8; 32],
        signature_public_key: [u8; 32],
        auth_generation: u64,
        metadata_version: u64,
        nonce: [u8; 12],
        ciphertext: Vec<u8>,
    ) -> Self {
        let ciphertext_sha256: [u8; 32] = Sha256::digest(&ciphertext).into();
        // The canonical snapshot/digest are not persisted by the executor for a
        // self-origin snapshot (the DB stores nonce/ciphertext/hash + author cols);
        // use a stable, self-consistent placeholder so equality/debug hold.
        let canonical_snapshot = ciphertext.clone();
        let digest: [u8; 32] = Sha256::digest(&canonical_snapshot).into();
        Self {
            coordinate: MetadataCryptoCoordinate {
                conversation_id,
                generation,
                group_id,
                epoch,
                group_context_hash,
                confirmation_tag,
            },
            origin_transition_id: transition_id,
            metadata_version,
            nonce,
            ciphertext,
            ciphertext_sha256,
            avatar_binding: None,
            author_proof: MetadataAuthorProofBinding {
                author,
                author_key_id,
                signature_public_key,
                auth_generation_at_origin: auth_generation,
                origin_transition_id: transition_id,
                origin_seq,
            },
            canonical_snapshot,
            digest,
        }
    }
}

#[cfg(test)]
impl TransitionEvidence {
    /// A creation `TransitionEvidence` carrying the exact `Creation` body a real
    /// creation produces, including the metadata snapshot the COMMIT-time
    /// `assert_metadata_snapshot_mapping` demands. `authority` stays `None` (the
    /// test seam), which the pure planner accepts; the metadata is nevertheless
    /// built to the production shape.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_test_creation_with_metadata(
        seq: u64,
        transition_id: [u8; 16],
        outer_entry_fingerprint: [u8; 32],
        received_at: ServerTimestamp,
        kind: ConversationKind,
        next: PublicGroupSnapshotCoordinate,
        creator: DeviceIdentity,
        metadata: MetadataSnapshotBinding,
    ) -> Result<Self, StateMachineError> {
        let mut evidence =
            Self::for_test_at(seq, transition_id, outer_entry_fingerprint, received_at)?;
        evidence.body_binding = Some(TransitionBodyBinding::Creation {
            kind,
            next,
            manifest: RosterManifestBinding {
                participants: Vec::new(),
                actor_leaf: creator,
            },
            group_info_sha256: [0u8; 32],
            metadata,
        });
        Ok(evidence)
    }

    /// A `resetActivation` `TransitionEvidence` carrying the exact `ResetActivation`
    /// body a real activation produces (matching kind/reset_request_id/prior/
    /// retired/successor coordinates + the successor metadata snapshot).
    /// `authority` stays `None`, which `require_reset_activation_body` accepts
    /// while still requiring those coordinate fields to match.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_test_reset_activation_with_metadata(
        seq: u64,
        transition_id: [u8; 16],
        outer_entry_fingerprint: [u8; 32],
        received_at: ServerTimestamp,
        kind: ConversationKind,
        reset_request_id: [u8; 16],
        prior: PublicGroupSnapshotCoordinate,
        retired: PublicGroupSnapshotCoordinate,
        successor: PublicGroupSnapshotCoordinate,
        activator: DeviceIdentity,
        metadata: MetadataSnapshotBinding,
    ) -> Result<Self, StateMachineError> {
        let mut evidence =
            Self::for_test_at(seq, transition_id, outer_entry_fingerprint, received_at)?;
        evidence.body_binding = Some(TransitionBodyBinding::ResetActivation {
            kind,
            reset_request_id,
            prior,
            retired,
            successor,
            manifest: RosterManifestBinding {
                participants: Vec::new(),
                actor_leaf: activator,
            },
            group_info_sha256: [0u8; 32],
            metadata,
        });
        Ok(evidence)
    }

    /// An `acceptConversation` `TransitionEvidence` carrying the exact `Acceptance`
    /// body a real acceptance produces: the coordinate-only successor `next`, the
    /// `add` recovery binding bound to `next`, and the retained-invitation
    /// provenance (which must match the pending participant's invitation).
    ///
    /// The signed `authority` is populated because production mints it
    /// UNCONDITIONALLY — `transition_from_control` wraps every accepted control
    /// entry with `authenticated_entry`, and both the hydration fence
    /// (`recovery_acceptance_authority_matches_durable`) and the planner
    /// (`reserved_package_cas_for_request`) reject an acceptance-origin recovery
    /// request whose evidence lacks it. Leaving it `None` produced a shape no
    /// production path can emit, and every follow-on transition that supersedes an
    /// acceptance-opened recovery family reads the origin's `key_id` /
    /// `auth_generation` out of it.
    ///
    /// Two arguments therefore have to be the REAL durable facts, not placeholders:
    ///   * `requester_key_id` / `requester_auth_generation` become the signing
    ///     authority's, which the prior-bound package CAS carries as
    ///     `target_key_id` / `target_auth_generation` and the durable release CAS
    ///     pins against `key_packages.owner_key_id` / `owner_auth_generation` (and
    ///     the request/reservation `requester_*` columns). Pass the acceptor's
    ///     registered key id, decoded from base64url.
    ///   * `key_package_wrapper` must be the exact wrapper bytes of the reserved
    ///     key-package row, because `acceptance_recovery_package_artifact_matches`
    ///     requires the signed body's wrapper digest to equal the locked row's, and
    ///     the release CAS pins `key_packages.wrapper_sha256`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_test_acceptance(
        seq: u64,
        transition_id: [u8; 16],
        entry_id: [u8; 16],
        outer_entry_fingerprint: [u8; 32],
        received_at: ServerTimestamp,
        prior: PublicGroupSnapshotCoordinate,
        recovery_request_id: [u8; 16],
        acceptor: DeviceIdentity,
        invitation_transition_id: [u8; 16],
        inviter: DeviceIdentity,
        key_package_ref: [u8; 32],
        key_package_wrapper: Vec<u8>,
        requester_key_id: [u8; 32],
        requester_auth_generation: u64,
        package_not_after: ServerTimestamp,
    ) -> Result<Self, StateMachineError> {
        let next = coordinate_only_successor(&prior)?;
        let expires_at = recovery_expiry(received_at, package_not_after)?;
        let wrapper_sha256: [u8; 32] = Sha256::digest(&key_package_wrapper).into();
        let mut evidence =
            Self::for_test_at(seq, transition_id, outer_entry_fingerprint, received_at)?;
        evidence.body_binding = Some(TransitionBodyBinding::Acceptance {
            prior,
            next,
            recovery_request_id,
            invitation_provenance: InvitationBinding {
                transition_id: invitation_transition_id,
                inviter,
            },
            recovery: AcceptanceRecoveryBinding {
                request_id: recovery_request_id,
                conversation_id: *prior.conversation_id(),
                target: acceptor.clone(),
                kind: LeafRecoveryKind::Add,
                bound_coordinate: next,
                requester_key_id,
                requester_auth_generation,
                key_package_ref,
                key_package_wrapper,
                key_package_wrapper_sha256: wrapper_sha256,
                requested_at: received_at,
                expires_at,
                canonical_digest: [0x5A_u8; 32],
            },
        });
        // The outer control projection and server fields are opaque here — nothing
        // on this path parses them — but they must be non-empty and covered by the
        // durable row digest, exactly as `validate_transition_evidence` requires of
        // any evidence carrying an authority.
        let kind = SignedMutationKind::ParticipantAcceptance;
        let canonical_projection = vec![0xA1_u8, 0xA2, 0xA3];
        let mut transcript_bytes = kind.domain().to_vec();
        transcript_bytes.extend_from_slice(&canonical_projection);
        evidence.outer_control_projection = vec![0xA4_u8, 0xA5];
        evidence.server_fields_dag_cbor = vec![0xA6_u8, 0xA7];
        evidence.authority = Some(AuthenticatedEntryEvidence {
            kind,
            type_id: kind.type_id(),
            domain: kind.domain().to_vec(),
            control_entry_id: Some(entry_id),
            control_conversation_id: Some(*prior.conversation_id()),
            actor: acceptor,
            key_id: requester_key_id,
            auth_generation: requester_auth_generation,
            signed_at: received_at,
            request_digest: Sha256::digest(&transcript_bytes).into(),
            signature: [0xA8_u8; 64],
            signed_request_bytes: vec![0xA9_u8, 0xAA],
            canonical_projection,
            transcript_bytes,
        });
        evidence.durable_row_digest = durable_control_transition_row_digest(&evidence)?;
        Ok(evidence)
    }

    /// A `signedLeafRecoveryFulfillment` `TransitionEvidence` carrying the exact
    /// `LeafRecoveryFulfillment` body a real signed fulfillment carries: the
    /// prior/next coordinates + recovery_request_id `require_commit_body` matches,
    /// and the Add manifest + welcome binding `require_commit_manifest` validates
    /// against the corpus ADD commit (single add of `target` with the reserved
    /// `key_package_ref`, the welcome bound to that target/request/ref), plus the
    /// mandatory metadata re-encryption snapshot the `leafRecovery` DDL arm demands.
    /// `authority` stays `None` (the test seam), which skips the crypto-digest
    /// cross-checks while still enforcing every coordinate/manifest/welcome field.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_test_leaf_recovery_fulfillment_with_metadata(
        seq: u64,
        transition_id: [u8; 16],
        outer_entry_fingerprint: [u8; 32],
        received_at: ServerTimestamp,
        recovery_request_id: [u8; 16],
        prior: PublicGroupSnapshotCoordinate,
        next: PublicGroupSnapshotCoordinate,
        target: DeviceIdentity,
        key_package_ref: [u8; 32],
        welcome_id: [u8; 16],
        welcome_wire_bytes: Vec<u8>,
        metadata: MetadataSnapshotBinding,
    ) -> Result<Self, StateMachineError> {
        let welcome_sha256: [u8; 32] = Sha256::digest(&welcome_wire_bytes).into();
        let mut evidence =
            Self::for_test_at(seq, transition_id, outer_entry_fingerprint, received_at)?;
        evidence.body_binding = Some(TransitionBodyBinding::LeafRecoveryFulfillment {
            recovery_request_id,
            prior,
            next,
            aad_digest: [0u8; 32],
            manifest: TransitionManifestBinding {
                participant_changes: Vec::new(),
                leaf_changes: vec![ManifestLeafChange::Add {
                    device: target.clone(),
                    recovery_request_id,
                    key_package_ref,
                }],
                leaf_recovery_request_id: Some(recovery_request_id),
                welcome: Some(ManifestWelcomeBinding {
                    welcome_id,
                    opaque_welcome: welcome_wire_bytes,
                    sha256: welcome_sha256,
                    recipient: target,
                    recovery_request_id,
                    key_package_ref,
                }),
            },
            commit_sha256: [0u8; 32],
            metadata,
        });
        Ok(evidence)
    }

    /// The `replace`-shaped leaf-recovery fulfillment `TransitionEvidence`: like
    /// `for_test_leaf_recovery_fulfillment_with_metadata`, but the manifest ALSO
    /// carries a `ManifestLeafChange::Remove(target)` for the rotated leaf, so
    /// `require_commit_manifest`'s `manifest_removed == commit.removes()` invariant
    /// (a `replace` commit removes the target's OLD leaf) holds. The `Recovery`
    /// form still requires exactly one Add for the target; the Remove is validated
    /// only against the commit's removes.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_test_leaf_recovery_replace_fulfillment_with_metadata(
        seq: u64,
        transition_id: [u8; 16],
        outer_entry_fingerprint: [u8; 32],
        received_at: ServerTimestamp,
        recovery_request_id: [u8; 16],
        prior: PublicGroupSnapshotCoordinate,
        next: PublicGroupSnapshotCoordinate,
        target: DeviceIdentity,
        key_package_ref: [u8; 32],
        welcome_id: [u8; 16],
        welcome_wire_bytes: Vec<u8>,
        metadata: MetadataSnapshotBinding,
    ) -> Result<Self, StateMachineError> {
        let welcome_sha256: [u8; 32] = Sha256::digest(&welcome_wire_bytes).into();
        let mut evidence =
            Self::for_test_at(seq, transition_id, outer_entry_fingerprint, received_at)?;
        evidence.body_binding = Some(TransitionBodyBinding::LeafRecoveryFulfillment {
            recovery_request_id,
            prior,
            next,
            aad_digest: [0u8; 32],
            manifest: TransitionManifestBinding {
                participant_changes: Vec::new(),
                leaf_changes: vec![
                    ManifestLeafChange::Remove(target.clone()),
                    ManifestLeafChange::Add {
                        device: target.clone(),
                        recovery_request_id,
                        key_package_ref,
                    },
                ],
                leaf_recovery_request_id: Some(recovery_request_id),
                welcome: Some(ManifestWelcomeBinding {
                    welcome_id,
                    opaque_welcome: welcome_wire_bytes,
                    sha256: welcome_sha256,
                    recipient: target,
                    recovery_request_id,
                    key_package_ref,
                }),
            },
            commit_sha256: [0u8; 32],
            metadata,
        });
        Ok(evidence)
    }

    /// A generic `signedCommitTransition` `TransitionEvidence`: the exact `Commit`
    /// body a real zero-proposal epoch commit carries — prior/next coordinates
    /// (`require_commit_body`), an empty Generic manifest (no participant/leaf
    /// changes, no recovery id, no welcome — `require_commit_manifest` Generic
    /// arm), and the mandatory metadata re-encryption. `authority = None` skips
    /// only the crypto-digest cross-checks.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_test_commit_with_metadata(
        seq: u64,
        transition_id: [u8; 16],
        outer_entry_fingerprint: [u8; 32],
        received_at: ServerTimestamp,
        prior: PublicGroupSnapshotCoordinate,
        next: PublicGroupSnapshotCoordinate,
        metadata: MetadataSnapshotBinding,
    ) -> Result<Self, StateMachineError> {
        let mut evidence =
            Self::for_test_at(seq, transition_id, outer_entry_fingerprint, received_at)?;
        evidence.body_binding = Some(TransitionBodyBinding::Commit {
            prior,
            next,
            aad_digest: [0u8; 32],
            manifest: TransitionManifestBinding {
                participant_changes: Vec::new(),
                leaf_changes: Vec::new(),
                leaf_recovery_request_id: None,
                welcome: None,
            },
            commit_sha256: [0u8; 32],
            metadata,
        });
        Ok(evidence)
    }

    /// A `leaveCommitFulfillment` `TransitionEvidence`: the exact body a real
    /// different-DID leave-fulfilling Commit carries — prior/next coordinates +
    /// `leave_request_id` (`require_commit_body`), and a Leave manifest
    /// (`require_commit_manifest` Leave arm: `participant_changes ==
    /// [Remove(requester)]`, NO Add leaf change, no recovery id, no welcome) plus
    /// the mandatory re-encryption metadata (`leaveCommit` ∈ requires_snapshot).
    /// `authority = None` skips only the crypto-digest cross-checks.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_test_leave_fulfillment_with_metadata(
        seq: u64,
        transition_id: [u8; 16],
        outer_entry_fingerprint: [u8; 32],
        received_at: ServerTimestamp,
        leave_request_id: [u8; 16],
        prior: PublicGroupSnapshotCoordinate,
        next: PublicGroupSnapshotCoordinate,
        requester: DeviceIdentity,
        metadata: MetadataSnapshotBinding,
    ) -> Result<Self, StateMachineError> {
        let mut evidence =
            Self::for_test_at(seq, transition_id, outer_entry_fingerprint, received_at)?;
        evidence.body_binding = Some(TransitionBodyBinding::LeaveCommitFulfillment {
            leave_request_id,
            prior,
            next,
            aad_digest: [0u8; 32],
            manifest: TransitionManifestBinding {
                participant_changes: vec![ManifestParticipantChange::Remove(
                    requester.principal().clone(),
                )],
                leaf_changes: vec![ManifestLeafChange::Remove(requester)],
                leaf_recovery_request_id: None,
                welcome: None,
            },
            commit_sha256: [0u8; 32],
            metadata,
        });
        Ok(evidence)
    }
}

#[cfg(test)]
impl ConversationHeadCasBinding {
    /// The head CAS a creation transaction's conversation-head lock would mint:
    /// true absence (`expected_prior == None`), genesis entry at seq 1, counter
    /// advanced to 2.
    pub(crate) fn for_test_creation(
        conversation_id: [u8; 16],
        entry_id: [u8; 16],
        locked_at: ServerTimestamp,
    ) -> Self {
        Self {
            transaction_id: "e2b3-executor-test".to_owned(),
            conversation_id,
            expected_prior: None,
            expected_next_entry_seq: 1,
            allocated_entry_id: Some(entry_id),
            allocated_seq: Some(1),
            successor_next_entry_seq: 2,
            locked_at,
            locked_head_digest: [1u8; 32],
        }
    }
}
