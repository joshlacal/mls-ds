#![allow(unused_imports)]
use super::*;

pub(in crate::chat_protocol::state_machine) fn require_transition_actor(
    evidence: &TransitionEvidence,
    expected: &DeviceIdentity,
) -> Result<(), StateMachineError> {
    if evidence
        .authority
        .as_ref()
        .is_some_and(|authority| &authority.actor != expected)
    {
        return Err(StateMachineError::InvalidTransition);
    }
    Ok(())
}

pub(in crate::chat_protocol::state_machine) fn require_creation_body(
    evidence: &TransitionEvidence,
    kind: ConversationKind,
    creator: &DeviceIdentity,
    invitees: &[PrincipalId],
    public_state: &ActivePublicState,
) -> Result<(), StateMachineError> {
    match evidence.body_binding.as_ref() {
        Some(TransitionBodyBinding::Creation {
            kind: signed_kind,
            next: signed_next,
            manifest,
            group_info_sha256,
            metadata,
            ..
        }) if *signed_kind == kind
            && signed_next == public_state.coordinate()
            && (evidence.authority.is_none()
                || (public_state.verified_group_info_sha256() == Some(group_info_sha256)
                    && creation_manifest_matches(evidence, manifest, kind, creator, invitees)
                    && metadata_coordinate_matches(metadata, public_state.coordinate())
                    && metadata.metadata_version == 1
                    && metadata.origin_transition_id == evidence.transition_id
                    && metadata_author_matches_evidence(metadata, evidence))) =>
        {
            Ok(())
        }
        Some(_) => Err(StateMachineError::InvalidTransition),
        None => Ok(()),
    }
}

pub(in crate::chat_protocol::state_machine) fn metadata_author_matches_evidence(
    metadata: &MetadataSnapshotBinding,
    evidence: &TransitionEvidence,
) -> bool {
    evidence.authority.as_ref().is_some_and(|authority| {
        metadata.author_proof.author == authority.actor
            && metadata.author_proof.author_key_id == authority.key_id
            && metadata.author_proof.auth_generation_at_origin == authority.auth_generation
            && metadata.author_proof.origin_transition_id == evidence.transition_id
            && metadata.author_proof.origin_seq == evidence.seq
    })
}

pub(in crate::chat_protocol::state_machine) fn transition_metadata(
    evidence: &TransitionEvidence,
) -> Option<&MetadataSnapshotBinding> {
    match evidence.body_binding.as_ref()? {
        TransitionBodyBinding::DirectRequestPublication { metadata, .. }
        | TransitionBodyBinding::Creation { metadata, .. }
        | TransitionBodyBinding::Commit { metadata, .. }
        | TransitionBodyBinding::Metadata { metadata, .. }
        | TransitionBodyBinding::ResetActivation { metadata, .. }
        | TransitionBodyBinding::LeafRecoveryFulfillment { metadata, .. }
        | TransitionBodyBinding::LeaveCommitFulfillment { metadata, .. } => Some(metadata),
        _ => None,
    }
}

/// Read-time accessor exposing the metadata snapshot binding a coordinate
/// transition's verified body carries, for the G1b-2 metadata hydration leg
/// (`repository::core::load_metadata_provenance`).
///
/// Thin `pub(crate)` wrapper over the module-private [`transition_metadata`]
/// classifier — forced in-module because both that fn and every field of
/// [`MetadataSnapshotBinding`] are private here, so `repository::core` cannot
/// introspect a re-minted transition's metadata directly. It lets the core leg
/// derive an existing conversation's `state.metadata` from its re-verified
/// producing transition EXACTLY as every production coordinate-advancing arm
/// does: `state.metadata = transition_metadata(&command.transition).cloned()`
/// (creation `commit_creation`, and the commit / policy / reset-activation /
/// leaf-recovery-fulfillment / leave-fulfillment arms all set it that way, e.g.
/// state_machine.rs:8813 and :9876). The binding is thus PROVENANCE-DERIVED from
/// its producer, never field-reconstructed from the durable `chat.metadata_snapshots`
/// columns (its `canonical_snapshot`/`digest` are not persisted at all, and the
/// only field-literal constructor, `for_test_creation`, is `#[cfg(test)]`).
///
/// DRIFT FENCE (unchanged, not edited): `validate_state`'s
/// [`metadata_provenance_matches`] re-checks
/// `state.metadata == transition_metadata(state.metadata_producer)` at hydration,
/// which this derivation satisfies by construction, so any residual disagreement
/// fails closed downstream (availability, not integrity — the OQ-G1-3 philosophy).
/// Returns `None` when the transition body carries no metadata; the core leg
/// treats that as a fail-closed linkage inconsistency when a durable metadata
/// snapshot row nonetheless names the transition as its producer.
#[allow(dead_code)] // wired by the G1b-2 aggregate.
pub(crate) fn metadata_binding_of_transition(
    evidence: &TransitionEvidence,
) -> Option<MetadataSnapshotBinding> {
    transition_metadata(evidence).cloned()
}

pub(in crate::chat_protocol::state_machine) fn creation_manifest_matches(
    evidence: &TransitionEvidence,
    manifest: &RosterManifestBinding,
    kind: ConversationKind,
    creator: &DeviceIdentity,
    invitees: &[PrincipalId],
) -> bool {
    if manifest.actor_leaf != *creator || manifest.participants.len() != invitees.len() + 1 {
        return false;
    }
    let mut expected_principals = invitees.to_vec();
    expected_principals.push(creator.principal().clone());
    expected_principals.sort();
    if manifest
        .participants
        .iter()
        .map(|participant| &participant.principal)
        .ne(expected_principals.iter())
    {
        return false;
    }
    manifest.participants.iter().all(|participant| {
        if participant.principal == *creator.principal() {
            participant.status == ParticipantStatus::Active
                && participant.role == ParticipantRole::Admin
                && participant.invitation.is_none()
        } else {
            let expected_role = if kind == ConversationKind::Direct {
                ParticipantRole::Admin
            } else {
                ParticipantRole::Member
            };
            participant.status == ParticipantStatus::Pending
                && participant.role == expected_role
                && participant.invitation.as_ref().is_some_and(|invitation| {
                    invitation.transition_id == evidence.transition_id
                        && invitation.inviter == *creator
                })
        }
    })
}

pub(in crate::chat_protocol::state_machine) fn require_commit_body(
    evidence: &TransitionEvidence,
    expected_kind: SignedMutationKind,
    prior_state: &ConversationState,
    commit: &VerifiedCommitPublicState,
    request_id: Option<&[u8; 16]>,
) -> Result<(), StateMachineError> {
    let prior = &prior_state.coordinate;
    let next = commit.next().coordinate();
    let valid = match (expected_kind, evidence.body_binding.as_ref()) {
        (
            SignedMutationKind::CommitTransition,
            Some(TransitionBodyBinding::Commit {
                prior: signed_prior,
                next: signed_next,
                aad_digest,
                commit_sha256,
                metadata,
                ..
            }),
        ) => {
            signed_prior == prior
                && signed_next == next
                && request_id.is_none()
                && (evidence.authority.is_none()
                    || (commit.verified_commit_sha256() == Some(commit_sha256)
                        && commit.verified_aad_sha256() == Some(aad_digest)
                        && commit_metadata_matches(prior_state, metadata, next)))
        }
        (
            SignedMutationKind::LeafRecoveryFulfillment,
            Some(TransitionBodyBinding::LeafRecoveryFulfillment {
                recovery_request_id,
                prior: signed_prior,
                next: signed_next,
                aad_digest,
                commit_sha256,
                metadata,
                ..
            }),
        ) => {
            let c_prior = signed_prior == prior;
            let c_next = signed_next == next;
            let c_req = request_id == Some(recovery_request_id);
            let c_commit_sha = commit.verified_commit_sha256() == Some(commit_sha256);
            let c_aad_sha = commit.verified_aad_sha256() == Some(aad_digest);
            let c_meta = commit_metadata_matches(prior_state, metadata, next);
            tracing::debug!("LeafRecoveryFulfillment check: prior={}, next={}, req={}, commit_sha={}, aad_sha={}, meta={}", c_prior, c_next, c_req, c_commit_sha, c_aad_sha, c_meta);
            if !c_prior {
                tracing::debug!(
                    "prior mismatch: signed_prior={:?} != prior={:?}",
                    signed_prior,
                    prior
                );
            }
            if !c_next {
                tracing::debug!(
                    "next mismatch: signed_next={:?} != next={:?}",
                    signed_next,
                    next
                );
            }
            if !c_commit_sha {
                tracing::debug!(
                    "commit_sha mismatch: verified={:?} != signed={:?}",
                    commit.verified_commit_sha256(),
                    commit_sha256
                );
            }
            if !c_aad_sha {
                tracing::debug!(
                    "aad_sha mismatch: verified={:?} != signed={:?}",
                    commit.verified_aad_sha256(),
                    aad_digest
                );
            }
            c_prior
                && c_next
                && c_req
                && (evidence.authority.is_none() || (c_commit_sha && c_aad_sha && c_meta))
        }
        (
            SignedMutationKind::LeaveCommitFulfillment,
            Some(TransitionBodyBinding::LeaveCommitFulfillment {
                leave_request_id,
                prior: signed_prior,
                next: signed_next,
                aad_digest,
                commit_sha256,
                metadata,
                ..
            }),
        ) => {
            signed_prior == prior
                && signed_next == next
                && request_id == Some(leave_request_id)
                && (evidence.authority.is_none()
                    || (commit.verified_commit_sha256() == Some(commit_sha256)
                        && commit.verified_aad_sha256() == Some(aad_digest)
                        && commit_metadata_matches(prior_state, metadata, next)))
        }
        (_, None) => true,
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(StateMachineError::InvalidTransition)
    }
}

pub(in crate::chat_protocol::state_machine) fn commit_metadata_matches(
    prior: &ConversationState,
    next_metadata: &MetadataSnapshotBinding,
    next_coordinate: &PublicGroupSnapshotCoordinate,
) -> bool {
    let Some(prior_metadata) = prior.metadata.as_ref() else {
        tracing::debug!("commit_metadata_matches: prior.metadata is None");
        return false;
    };
    let c_coord = metadata_coordinate_matches(next_metadata, next_coordinate);
    let c_ver = next_metadata.metadata_version == prior_metadata.metadata_version;
    let c_ot = next_metadata.origin_transition_id == prior_metadata.origin_transition_id;
    let c_len = next_metadata.ciphertext.len() == prior_metadata.ciphertext.len();
    let c_auth = next_metadata.author_proof == prior_metadata.author_proof;
    let c_avatar = next_metadata.avatar_binding == prior_metadata.avatar_binding;
    let c_nonce = next_metadata.nonce != prior_metadata.nonce;
    tracing::debug!(
        "commit_metadata_matches: next_len={}, prior_len={}",
        next_metadata.ciphertext.len(),
        prior_metadata.ciphertext.len()
    );
    tracing::debug!(
        "commit_metadata_matches: coord={}, ver={}, ot={}, len={}, auth={}, avatar={}, nonce={}",
        c_coord,
        c_ver,
        c_ot,
        c_len,
        c_auth,
        c_avatar,
        c_nonce
    );
    if !c_coord {
        tracing::debug!(
            "metadata coordinate mismatch: next_metadata={:?} != next_coord={:?}",
            next_metadata.coordinate,
            next_coordinate
        );
    }
    if !c_auth {
        tracing::debug!(
            "author_proof mismatch: next={:?} != prior={:?}",
            next_metadata.author_proof,
            prior_metadata.author_proof
        );
    }
    c_coord && c_ver && c_ot && c_len && c_auth && c_avatar && c_nonce
}

pub(in crate::chat_protocol::state_machine) enum CommitManifestForm<'a> {
    Generic,
    Recovery {
        target: &'a DeviceIdentity,
        recovery_request_id: &'a [u8; 16],
        key_package_ref: &'a [u8; 32],
        welcome_id: &'a [u8; 16],
        welcome: &'a VerifiedRecoveryWelcome,
    },
    Leave {
        requester: &'a PrincipalId,
    },
}

pub(in crate::chat_protocol::state_machine) fn require_commit_manifest(
    prior: &ConversationState,
    evidence: &TransitionEvidence,
    commit: &VerifiedCommitPublicState,
    form: CommitManifestForm<'_>,
) -> Result<(), StateMachineError> {
    let manifest = match evidence.body_binding.as_ref() {
        Some(TransitionBodyBinding::Commit { manifest, .. }) => manifest,
        Some(TransitionBodyBinding::LeafRecoveryFulfillment { manifest, .. }) => manifest,
        Some(TransitionBodyBinding::LeaveCommitFulfillment { manifest, .. }) => manifest,
        Some(_) => return Err(StateMachineError::InvalidTransition),
        None => return Ok(()),
    };
    let removed_devices = commit
        .removes()
        .iter()
        .map(|effect| {
            prior
                .leaves
                .iter()
                .find(|leaf| leaf.leaf_index == effect.leaf_index())
                .map(|leaf| leaf.device.clone())
                .ok_or(StateMachineError::InvalidCommitEffects)
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let manifest_removed = manifest
        .leaf_changes
        .iter()
        .filter_map(|change| match change {
            ManifestLeafChange::Remove(device) => Some(device.clone()),
            ManifestLeafChange::Add { .. } => None,
        })
        .collect::<BTreeSet<_>>();
    if manifest_removed != removed_devices {
        return Err(StateMachineError::InvalidCommitEffects);
    }

    match form {
        CommitManifestForm::Generic => {
            if !manifest.participant_changes.is_empty()
                || manifest
                    .leaf_changes
                    .iter()
                    .any(|change| matches!(change, ManifestLeafChange::Add { .. }))
                || manifest.leaf_recovery_request_id.is_some()
                || manifest.welcome.is_some()
            {
                return Err(StateMachineError::InvalidCommitEffects);
            }
        }
        CommitManifestForm::Recovery {
            target,
            recovery_request_id,
            key_package_ref,
            welcome_id,
            welcome,
        } => {
            let adds = manifest
                .leaf_changes
                .iter()
                .filter_map(|change| match change {
                    ManifestLeafChange::Add {
                        device,
                        recovery_request_id,
                        key_package_ref,
                    } => Some((device, recovery_request_id, key_package_ref)),
                    ManifestLeafChange::Remove(_) => None,
                })
                .collect::<Vec<_>>();
            let signed_welcome = manifest
                .welcome
                .as_ref()
                .ok_or(StateMachineError::InvalidWelcomeMapping)?;
            let c_pc = manifest.participant_changes.is_empty();
            let c_adds_len = adds.len() == 1;
            let c_adds_tgt = adds.get(0).map(|a| a.0 == target).unwrap_or(false);
            let c_adds_req = adds
                .get(0)
                .map(|a| a.1 == recovery_request_id)
                .unwrap_or(false);
            let c_adds_kp = adds.get(0).map(|a| a.2 == key_package_ref).unwrap_or(false);
            let c_m_req = manifest.leaf_recovery_request_id.as_ref() == Some(recovery_request_id);
            let c_w_id = &signed_welcome.welcome_id == welcome_id;
            let c_w_rcp = &signed_welcome.recipient == target;
            let c_w_req = &signed_welcome.recovery_request_id == recovery_request_id;
            let c_w_kp = &signed_welcome.key_package_ref == key_package_ref;
            let c_w_wire = signed_welcome.opaque_welcome == welcome.wire_bytes();
            let c_w_sha =
                signed_welcome.sha256 == <[u8; 32]>::from(Sha256::digest(welcome.wire_bytes()));
            tracing::debug!("InvalidWelcomeMapping checks: pc={}, adds_len={}, adds_tgt={}, adds_req={}, adds_kp={}, m_req={}, w_id={}, w_rcp={}, w_req={}, w_kp={}, w_wire={}, w_sha={}", c_pc, c_adds_len, c_adds_tgt, c_adds_req, c_adds_kp, c_m_req, c_w_id, c_w_rcp, c_w_req, c_w_kp, c_w_wire, c_w_sha);
            if !c_pc
                || !c_adds_len
                || !c_adds_tgt
                || !c_adds_req
                || !c_adds_kp
                || !c_m_req
                || !c_w_id
                || !c_w_rcp
                || !c_w_req
                || !c_w_kp
                || !c_w_wire
                || !c_w_sha
            {
                return Err(StateMachineError::InvalidWelcomeMapping);
            }
        }
        CommitManifestForm::Leave { requester } => {
            if manifest.participant_changes
                != vec![ManifestParticipantChange::Remove(requester.clone())]
                || manifest
                    .leaf_changes
                    .iter()
                    .any(|change| matches!(change, ManifestLeafChange::Add { .. }))
                || manifest.leaf_recovery_request_id.is_some()
                || manifest.welcome.is_some()
            {
                return Err(StateMachineError::InvalidCommitEffects);
            }
        }
    }
    Ok(())
}

pub(in crate::chat_protocol::state_machine) fn require_acceptance_body(
    evidence: &TransitionEvidence,
    prior: &PublicGroupSnapshotCoordinate,
    next: &PublicGroupSnapshotCoordinate,
    recovery_request_id: &[u8; 16],
    actor: &DeviceIdentity,
    retained_invitation: Option<&InvitationProvenance>,
) -> Result<(), StateMachineError> {
    match evidence.body_binding.as_ref() {
        Some(TransitionBodyBinding::Acceptance {
            prior: signed_prior,
            next: signed_next,
            recovery_request_id: signed_request_id,
            invitation_provenance,
            recovery,
        }) if signed_prior == prior
            && signed_next == next
            && signed_request_id == recovery_request_id
            && recovery.request_id == *recovery_request_id
            && recovery.conversation_id == *prior.conversation_id()
            && recovery.target == *actor
            && recovery.kind == LeafRecoveryKind::Add
            && recovery.bound_coordinate == *next
            && retained_invitation.is_some_and(|retained| {
                invitation_provenance.transition_id == retained.transition.transition_id
                    && invitation_provenance.inviter == retained.inviter
            }) =>
        {
            Ok(())
        }
        Some(_) => Err(StateMachineError::InvalidTransition),
        None => Ok(()),
    }
}

pub(in crate::chat_protocol::state_machine) fn require_metadata_body<'a>(
    prior: &ConversationState,
    evidence: &'a TransitionEvidence,
    next: &PublicGroupSnapshotCoordinate,
) -> Result<&'a MetadataSnapshotBinding, StateMachineError> {
    let previous = prior
        .metadata
        .as_ref()
        .ok_or(StateMachineError::InvalidMetadataAuthority)?;
    let Some(TransitionBodyBinding::Metadata {
        prior: signed_prior,
        next: signed_next,
        metadata,
    }) = evidence.body_binding.as_ref()
    else {
        return Err(StateMachineError::InvalidMetadataAuthority);
    };
    let expected_version = previous
        .metadata_version
        .checked_add(1)
        .filter(|value| *value <= MAX_PROTOCOL_INTEGER)
        .ok_or(StateMachineError::MetadataVersionOverflow)?;
    if signed_prior != &prior.coordinate
        || signed_next != next
        || !metadata_coordinate_matches(metadata, next)
        || metadata.metadata_version != expected_version
        || metadata.origin_transition_id != evidence.transition_id
        || metadata.nonce == previous.nonce
        || !metadata_author_matches_evidence(metadata, evidence)
    {
        return Err(StateMachineError::InvalidMetadataAuthority);
    }
    Ok(metadata)
}

pub(in crate::chat_protocol::state_machine) fn require_reset_activation_body(
    evidence: &TransitionEvidence,
    reset_request_id: &[u8; 16],
    prior: &ConversationState,
    retired: &PublicGroupSnapshotCoordinate,
    actor: &DeviceIdentity,
    successor_public_state: &ActivePublicState,
) -> Result<(), StateMachineError> {
    let successor = successor_public_state.coordinate();
    match evidence.body_binding.as_ref() {
        Some(TransitionBodyBinding::ResetActivation {
            kind: signed_kind,
            reset_request_id: signed_request_id,
            prior: signed_prior,
            retired: signed_retired,
            successor: signed_successor,
            manifest,
            group_info_sha256,
            metadata,
            ..
        }) if *signed_kind == prior.kind
            && signed_request_id == reset_request_id
            && signed_prior == &prior.coordinate
            && signed_retired == retired
            && signed_successor == successor
            && (evidence.authority.is_none()
                || (successor_public_state.verified_group_info_sha256()
                    == Some(group_info_sha256)
                    && reset_manifest_matches(manifest, prior, actor)
                    && reset_metadata_matches(
                        evidence,
                        prior,
                        metadata,
                        successor_public_state.coordinate(),
                    ))) =>
        {
            Ok(())
        }
        Some(TransitionBodyBinding::ResetActivation {
            kind: signed_kind,
            reset_request_id: signed_request_id,
            prior: signed_prior,
            retired: signed_retired,
            successor: signed_successor,
            manifest,
            group_info_sha256,
            metadata,
            ..
        }) => {
            tracing::warn!(
                kind_ok = *signed_kind == prior.kind,
                request_id_ok = signed_request_id == reset_request_id,
                prior_ok = signed_prior == &prior.coordinate,
                retired_ok = signed_retired == retired,
                successor_ok = signed_successor == successor,
                no_authority = evidence.authority.is_none(),
                group_info_ok =
                    successor_public_state.verified_group_info_sha256() == Some(group_info_sha256),
                manifest_ok = reset_manifest_matches(manifest, prior, actor),
                metadata_ok = reset_metadata_matches(
                    evidence,
                    prior,
                    metadata,
                    successor_public_state.coordinate()
                ),
                "reset activation body rejected"
            );
            Err(StateMachineError::InvalidTransition)
        }
        Some(_) => Err(StateMachineError::InvalidTransition),
        None => Ok(()),
    }
}

pub(in crate::chat_protocol::state_machine) fn reset_metadata_matches(
    evidence: &TransitionEvidence,
    prior: &ConversationState,
    next: &MetadataSnapshotBinding,
    successor: &PublicGroupSnapshotCoordinate,
) -> bool {
    let Some(previous) = prior.metadata.as_ref() else {
        return false;
    };
    if !metadata_coordinate_matches(next, successor) || next.nonce == previous.nonce {
        return false;
    }
    let reencrypted = next.metadata_version == previous.metadata_version
        && next.origin_transition_id == previous.origin_transition_id
        && next.author_proof == previous.author_proof
        && next.avatar_binding == previous.avatar_binding;
    let fresh_empty = previous
        .metadata_version
        .checked_add(1)
        .is_some_and(|version| version == next.metadata_version)
        && next.origin_transition_id == evidence.transition_id
        && metadata_author_matches_evidence(next, evidence);
    if !(reencrypted || fresh_empty) {
        let authority = evidence.authority.as_ref();
        tracing::warn!(
            prev_version = previous.metadata_version,
            next_version = next.metadata_version,
            origin_tid_ok = next.origin_transition_id == evidence.transition_id,
            author_ok = authority.is_some_and(|a| next.author_proof.author == a.actor),
            key_ok = authority.is_some_and(|a| next.author_proof.author_key_id == a.key_id),
            auth_gen_ok = authority
                .is_some_and(|a| next.author_proof.auth_generation_at_origin == a.auth_generation),
            proof_tid_ok = next.author_proof.origin_transition_id == evidence.transition_id,
            proof_seq = next.author_proof.origin_seq,
            evidence_seq = evidence.seq,
            "reset metadata snapshot rejected"
        );
    }
    reencrypted || fresh_empty
}

pub(in crate::chat_protocol::state_machine) fn reset_manifest_matches(
    manifest: &RosterManifestBinding,
    prior: &ConversationState,
    actor: &DeviceIdentity,
) -> bool {
    manifest.actor_leaf == *actor
        && manifest.participants.len() == prior.participants.len()
        && manifest
            .participants
            .iter()
            .zip(&prior.participants)
            .all(|(signed, retained)| {
                signed.principal == retained.principal
                    && signed.status == retained.status
                    && signed.role == retained.role
                    && match (&signed.invitation, &retained.invitation) {
                        (None, None) => true,
                        (Some(signed), Some(retained)) => {
                            signed.transition_id == retained.transition.transition_id
                                && signed.inviter == retained.inviter
                        }
                        _ => false,
                    }
            })
}

pub(in crate::chat_protocol::state_machine) fn require_coordinate_only_body(
    evidence: &TransitionEvidence,
    expected_kind: SignedMutationKind,
    kind: ConversationKind,
    prior: &PublicGroupSnapshotCoordinate,
    next: &PublicGroupSnapshotCoordinate,
) -> Result<(), StateMachineError> {
    let valid = match (expected_kind, evidence.body_binding.as_ref()) {
        (
            SignedMutationKind::ZeroLeafLeave,
            Some(TransitionBodyBinding::ZeroLeafLeave {
                prior: signed_prior,
                next: signed_next,
            }),
        ) => signed_prior == prior && signed_next == next,
        (
            SignedMutationKind::ConversationClose,
            Some(TransitionBodyBinding::ConversationClose {
                kind: signed_kind,
                prior: signed_prior,
                retired: signed_retired,
            }),
        ) => *signed_kind == kind && signed_prior == prior && signed_retired == next,
        (_, None) => true,
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(StateMachineError::InvalidTransition)
    }
}

pub(in crate::chat_protocol::state_machine) fn transition_has_one_of_kinds(
    evidence: &TransitionEvidence,
    expected: &[SignedMutationKind],
) -> bool {
    evidence
        .authority
        .as_ref()
        .is_none_or(|authority| expected.contains(&authority.kind))
}

pub(in crate::chat_protocol::state_machine) fn validate_intervals(
    intervals: &[AccessInterval],
    root: &PublicGroupSnapshotCoordinate,
    conversation_kind: ConversationKind,
) -> Result<(), StateMachineError> {
    if intervals.is_empty()
        || intervals.windows(2).any(|pair| {
            pair[0]
                .recipient
                .cmp(&pair[1].recipient)
                .then_with(|| pair[0].opening.seq.cmp(&pair[1].opening.seq))
                != Ordering::Less
        })
        || intervals.iter().enumerate().any(|(index, left)| {
            intervals[index + 1..].iter().any(|right| {
                left.generation == right.generation
                    && left.opening_context.group_id() != right.opening_context.group_id()
            })
        })
    {
        return Err(StateMachineError::InvalidIntervalBoundary);
    }
    for interval in intervals {
        let opening_kind_valid = match interval.opening_kind {
            OpeningKind::DirectRequest => transition_has_one_of_kinds(
                &interval.opening,
                &[SignedMutationKind::DirectRequestPublication],
            ),
            OpeningKind::Creation => {
                transition_has_one_of_kinds(&interval.opening, &[SignedMutationKind::Creation])
            }
            OpeningKind::Add => transition_has_one_of_kinds(
                &interval.opening,
                &[SignedMutationKind::LeafRecoveryFulfillment],
            ),
            OpeningKind::Reset => transition_has_one_of_kinds(
                &interval.opening,
                &[SignedMutationKind::ResetActivation],
            ),
        };
        let end_kind_valid = interval.end.as_ref().is_none_or(|end| match end.kind {
            CloseKind::DirectRequest => transition_has_one_of_kinds(
                &end.evidence,
                &[SignedMutationKind::DirectRequestPublication],
            ),
            CloseKind::Replace => transition_has_one_of_kinds(
                &end.evidence,
                &[SignedMutationKind::LeafRecoveryFulfillment],
            ),
            CloseKind::Reset => {
                transition_has_one_of_kinds(&end.evidence, &[SignedMutationKind::ResetActivation])
            }
            CloseKind::Terminal => {
                transition_has_one_of_kinds(&end.evidence, &[SignedMutationKind::ConversationClose])
            }
            CloseKind::Remove => transition_has_one_of_kinds(
                &end.evidence,
                &[
                    SignedMutationKind::CommitTransition,
                    SignedMutationKind::LeaveCommitFulfillment,
                ],
            ),
        });
        if !validate_transition_evidence(&interval.opening)
            || !opening_kind_valid
            || !opening_matches_interval(interval, conversation_kind, root)
            || !end_kind_valid
            || interval
                .opening
                .authority
                .as_ref()
                .is_some_and(|authority| {
                    authority.control_conversation_id.as_ref() != Some(root.conversation_id())
                })
            || interval.opening_context.lifecycle() != PublicGroupSnapshotLifecycle::Active
            || interval.opening_context.conversation_id() != root.conversation_id()
            || interval.opening_context.generation() != interval.generation
            || interval.generation > root.generation()
            || (interval.generation == root.generation()
                && interval.opening_context.group_id() != root.group_id())
            || interval.end.as_ref().is_some_and(|end| {
                !validate_transition_evidence(&end.evidence)
                    || !end_matches_interval(interval, end, conversation_kind, root)
                    || end.evidence.authority.as_ref().is_some_and(|authority| {
                        authority.control_conversation_id.as_ref() != Some(root.conversation_id())
                    })
                    || end.evidence.seq <= interval.opening.seq
            })
        {
            return Err(StateMachineError::InvalidIntervalBoundary);
        }
    }
    for window in intervals.windows(2) {
        if window[0].recipient != window[1].recipient {
            continue;
        }
        let end = window[0]
            .end
            .as_ref()
            .ok_or(StateMachineError::InvalidIntervalBoundary)?;
        let touching = end.evidence.seq == window[1].opening.seq;
        let valid_touch = match (end.kind, window[1].opening_kind) {
            (CloseKind::DirectRequest, OpeningKind::DirectRequest) => {
                window[0].generation.checked_add(1) == Some(window[1].generation)
                    && window[1].opening_context.state_version() == 1
                    && window[1].opening_context.epoch() == 1
                    && window[1].opening_context.group_id() != window[0].opening_context.group_id()
            }
            (CloseKind::Replace, OpeningKind::Add) => {
                window[1].generation == window[0].generation
                    && window[1].opening_context.group_id() == window[0].opening_context.group_id()
            }
            (CloseKind::Reset, OpeningKind::Reset) => {
                window[0]
                    .generation
                    .checked_add(1)
                    .is_some_and(|generation| generation == window[1].generation)
                    && window[1].opening_context.state_version() == 0
                    && window[1].opening_context.epoch() == 0
                    && window[1].opening_context.group_id() != window[0].opening_context.group_id()
            }
            _ => false,
        };
        if end.evidence.seq > window[1].opening.seq
            || (touching && (!valid_touch || end.evidence != window[1].opening))
            || end.kind == CloseKind::Terminal
        {
            return Err(StateMachineError::InvalidIntervalBoundary);
        }
    }
    Ok(())
}
