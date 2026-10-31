#![allow(unused_imports)]
use super::*;


pub(in crate::chat_protocol::state_machine) fn opening_matches_interval(
    interval: &AccessInterval,
    conversation_kind: ConversationKind,
    root: &PublicGroupSnapshotCoordinate,
) -> bool {
    let evidence = &interval.opening;
    let Some(authority) = evidence.authority.as_ref() else {
        return true;
    };
    match (interval.opening_kind, evidence.body_binding.as_ref()) {
        (
            OpeningKind::DirectRequest,
            Some(TransitionBodyBinding::DirectRequestPublication { next, devices, .. }),
        ) => {
            authority.kind == SignedMutationKind::DirectRequestPublication
                && conversation_kind == ConversationKind::Direct
                && next == &interval.opening_context
                && devices.contains(&interval.recipient)
                && coordinate_is_in_lineage(next, root)
        }

        (
            OpeningKind::Creation,
            Some(TransitionBodyBinding::Creation {
                kind,
                next,
                manifest,
                ..
            }),
        ) => {
            authority.kind == SignedMutationKind::Creation
                && authority.actor == interval.recipient
                && *kind == conversation_kind
                && next == &interval.opening_context
                && manifest.actor_leaf == interval.recipient
                && manifest
                    .participants
                    .iter()
                    .filter(|participant| {
                        participant.principal == *interval.recipient.principal()
                            && participant.status == ParticipantStatus::Active
                            && participant.role == ParticipantRole::Admin
                            && participant.invitation.is_none()
                    })
                    .count()
                    == 1
                && interval.opening_context.generation() == 0
                && interval.opening_context.state_version() == 0
                && interval.opening_context.epoch() == 0
        }
        (
            OpeningKind::Add,
            Some(TransitionBodyBinding::LeafRecoveryFulfillment {
                recovery_request_id,
                prior,
                next,
                manifest,
                ..
            }),
        ) => {
            authority.kind == SignedMutationKind::LeafRecoveryFulfillment
                && next == &interval.opening_context
                && commit_coordinate_edge(prior, next)
                && coordinate_is_in_lineage(next, root)
                && manifest.leaf_recovery_request_id.as_ref() == Some(recovery_request_id)
                && manifest
                    .leaf_changes
                    .iter()
                    .filter(|change| {
                        matches!(change, ManifestLeafChange::Add {
                        device,
                        recovery_request_id: signed_request_id,
                        ..
                    } if device == &interval.recipient
                        && signed_request_id == recovery_request_id)
                    })
                    .count()
                    == 1
        }
        (
            OpeningKind::Reset,
            Some(TransitionBodyBinding::ResetActivation {
                kind,
                prior,
                retired,
                successor,
                manifest,
                ..
            }),
        ) => {
            authority.kind == SignedMutationKind::ResetActivation
                && authority.actor == interval.recipient
                && *kind == conversation_kind
                && successor == &interval.opening_context
                && manifest.actor_leaf == interval.recipient
                && retired_coordinate(prior).is_ok_and(|expected| &expected == retired)
                && reset_successor_edge(prior, successor)
                && coordinate_is_in_lineage(successor, root)
        }
        _ => false,
    }
}

pub(in crate::chat_protocol::state_machine) fn end_matches_interval(
    interval: &AccessInterval,
    end: &AccessIntervalEnd,
    conversation_kind: ConversationKind,
    root: &PublicGroupSnapshotCoordinate,
) -> bool {
    let evidence = &end.evidence;
    let Some(authority) = evidence.authority.as_ref() else {
        return true;
    };
    match (end.kind, authority.kind, evidence.body_binding.as_ref()) {
        (
            CloseKind::DirectRequest,
            SignedMutationKind::DirectRequestPublication,
            Some(TransitionBodyBinding::DirectRequestPublication {
                prior: Some(prior),
                next,
                ..
            }),
        ) => {
            conversation_kind == ConversationKind::Direct
                && coordinate_after_opening(prior, &interval.opening_context)
                && prior.generation().checked_add(1) == Some(next.generation())
                && coordinate_is_in_lineage(next, root)
        }

        (
            CloseKind::Replace,
            SignedMutationKind::LeafRecoveryFulfillment,
            Some(TransitionBodyBinding::LeafRecoveryFulfillment {
                recovery_request_id,
                prior,
                next,
                manifest,
                ..
            }),
        ) => {
            coordinate_after_opening(prior, &interval.opening_context)
                && commit_coordinate_edge(prior, next)
                && coordinate_is_in_lineage(next, root)
                && manifest.leaf_recovery_request_id.as_ref() == Some(recovery_request_id)
                && manifest
                    .leaf_changes
                    .iter()
                    .filter(|change| {
                        matches!(change, ManifestLeafChange::Remove(device)
                        if device == &interval.recipient)
                    })
                    .count()
                    == 1
                && manifest
                    .leaf_changes
                    .iter()
                    .filter(|change| {
                        matches!(change, ManifestLeafChange::Add {
                        device,
                        recovery_request_id: signed_request_id,
                        ..
                    } if device == &interval.recipient
                        && signed_request_id == recovery_request_id)
                    })
                    .count()
                    == 1
        }
        (
            CloseKind::Remove,
            SignedMutationKind::CommitTransition,
            Some(TransitionBodyBinding::Commit {
                prior,
                next,
                manifest,
                ..
            }),
        ) => {
            coordinate_after_opening(prior, &interval.opening_context)
                && commit_coordinate_edge(prior, next)
                && coordinate_is_in_lineage(next, root)
                && manifest
                    .leaf_changes
                    .iter()
                    .filter(|change| {
                        matches!(change, ManifestLeafChange::Remove(device)
                        if device == &interval.recipient)
                    })
                    .count()
                    == 1
        }
        (
            CloseKind::Remove,
            SignedMutationKind::LeaveCommitFulfillment,
            Some(TransitionBodyBinding::LeaveCommitFulfillment {
                prior,
                next,
                manifest,
                ..
            }),
        ) => {
            coordinate_after_opening(prior, &interval.opening_context)
                && commit_coordinate_edge(prior, next)
                && coordinate_is_in_lineage(next, root)
                && manifest
                    .participant_changes
                    .iter()
                    .filter(|change| {
                        matches!(change, ManifestParticipantChange::Remove(principal)
                        if principal == interval.recipient.principal())
                    })
                    .count()
                    == 1
                && manifest
                    .leaf_changes
                    .iter()
                    .filter(|change| {
                        matches!(change, ManifestLeafChange::Remove(device)
                        if device == &interval.recipient)
                    })
                    .count()
                    == 1
        }
        (
            CloseKind::Reset,
            SignedMutationKind::ResetActivation,
            Some(TransitionBodyBinding::ResetActivation {
                kind,
                prior,
                retired,
                successor,
                ..
            }),
        ) => {
            *kind == conversation_kind
                && coordinate_after_opening(prior, &interval.opening_context)
                && retired_coordinate(prior).is_ok_and(|expected| &expected == retired)
                && reset_successor_edge(prior, successor)
                && coordinate_is_in_lineage(successor, root)
        }
        (
            CloseKind::Terminal,
            SignedMutationKind::ConversationClose,
            Some(TransitionBodyBinding::ConversationClose {
                kind,
                prior,
                retired,
            }),
        ) => {
            *kind == conversation_kind
                && coordinate_after_opening(prior, &interval.opening_context)
                && retired_coordinate(prior).is_ok_and(|expected| &expected == retired)
                && retired == root
        }
        _ => false,
    }
}

pub(in crate::chat_protocol::state_machine) fn coordinate_after_opening(
    coordinate: &PublicGroupSnapshotCoordinate,
    opening: &PublicGroupSnapshotCoordinate,
) -> bool {
    coordinate.lifecycle() == PublicGroupSnapshotLifecycle::Active
        && coordinate.conversation_id() == opening.conversation_id()
        && coordinate.generation() == opening.generation()
        && coordinate.group_id() == opening.group_id()
        && coordinate.state_version() >= opening.state_version()
}

pub(in crate::chat_protocol::state_machine) fn commit_coordinate_edge(
    prior: &PublicGroupSnapshotCoordinate,
    next: &PublicGroupSnapshotCoordinate,
) -> bool {
    prior.lifecycle() == PublicGroupSnapshotLifecycle::Active
        && next.lifecycle() == PublicGroupSnapshotLifecycle::Active
        && prior.conversation_id() == next.conversation_id()
        && prior.generation() == next.generation()
        && prior.group_id() == next.group_id()
        && prior.state_version().checked_add(1) == Some(next.state_version())
        && prior.epoch().checked_add(1) == Some(next.epoch())
}

pub(in crate::chat_protocol::state_machine) fn reset_successor_edge(
    prior: &PublicGroupSnapshotCoordinate,
    successor: &PublicGroupSnapshotCoordinate,
) -> bool {
    prior.lifecycle() == PublicGroupSnapshotLifecycle::Active
        && successor.lifecycle() == PublicGroupSnapshotLifecycle::Active
        && prior.conversation_id() == successor.conversation_id()
        && prior.generation().checked_add(1) == Some(successor.generation())
        && successor.state_version() == 0
        && successor.epoch() == 0
        && prior.group_id() != successor.group_id()
}

pub(in crate::chat_protocol::state_machine) fn validate_terminal_proofs(state: &ConversationState) -> Result<(), StateMachineError> {
    if state
        .terminal_proofs
        .windows(2)
        .any(|pair| pair[0].recipient >= pair[1].recipient)
        || state
            .intervals
            .iter()
            .any(|interval| interval.end.is_none())
    {
        return Err(StateMachineError::InvalidIntervalBoundary);
    }
    let recipients = state
        .intervals
        .iter()
        .map(|interval| &interval.recipient)
        .collect::<BTreeSet<_>>();
    let proof_recipients = state
        .terminal_proofs
        .iter()
        .map(|proof| &proof.recipient)
        .collect::<BTreeSet<_>>();
    if state.terminal_proofs.len() != recipients.len() || proof_recipients != recipients {
        return Err(StateMachineError::InvalidIntervalBoundary);
    }
    let mut terminal_evidence: Option<&TransitionEvidence> = None;
    for interval in &state.intervals {
        let end = interval.end.as_ref().expect("checked above");
        if end.kind == CloseKind::Terminal {
            if terminal_evidence.is_some_and(|evidence| evidence != &end.evidence) {
                return Err(StateMachineError::InvalidIntervalBoundary);
            }
            terminal_evidence = Some(&end.evidence);
        }
    }
    let terminal_evidence = terminal_evidence.ok_or(StateMachineError::InvalidIntervalBoundary)?;
    if !validate_transition_evidence(terminal_evidence)
        || !transition_has_one_of_kinds(terminal_evidence, &[SignedMutationKind::ConversationClose])
        || state.terminal_proofs.iter().any(|proof| {
            &proof.conversation_id != state.coordinate.conversation_id()
                || proof.evidence != *terminal_evidence
        })
        || state.intervals.iter().any(|interval| {
            interval.opening.seq >= terminal_evidence.seq
                || interval.end.as_ref().is_some_and(|end| {
                    if end.kind == CloseKind::Terminal {
                        end.evidence != *terminal_evidence
                    } else {
                        end.evidence.seq >= terminal_evidence.seq
                    }
                })
        })
    {
        return Err(StateMachineError::InvalidIntervalBoundary);
    }
    Ok(())
}

pub(in crate::chat_protocol::state_machine) fn coordinate_is_in_lineage(
    coordinate: &PublicGroupSnapshotCoordinate,
    root: &PublicGroupSnapshotCoordinate,
) -> bool {
    coordinate.lifecycle() == PublicGroupSnapshotLifecycle::Active
        && coordinate.conversation_id() == root.conversation_id()
        && coordinate.generation() <= root.generation()
        && (coordinate.generation() != root.generation()
            || (coordinate.group_id() == root.group_id()
                && coordinate.state_version() <= root.state_version()))
}

pub(in crate::chat_protocol::state_machine) fn exact_expiry(
    received_at: ServerTimestamp,
    ttl_millis: i64,
    expires_at: ServerTimestamp,
) -> bool {
    received_at
        .checked_add_millis(ttl_millis)
        .is_ok_and(|expected| expected == expires_at)
}

pub(in crate::chat_protocol::state_machine) fn transition_follows_origin(
    evidence: &TransitionEvidence,
    origin_seq: Option<u64>,
    received_at: ServerTimestamp,
    expires_at: ServerTimestamp,
) -> bool {
    validate_transition_evidence(evidence)
        && origin_seq.is_none_or(|origin_seq| evidence.seq > origin_seq)
        && evidence.received_at >= received_at
        && evidence.received_at < expires_at
}

/// A terminal transition may retire only work bound to the exact coordinate
/// consumed by its signed body. Sequence ordering alone is not authority: it
/// would allow a valid later transition from another branch to be spliced onto
/// the row during hydration.
pub(in crate::chat_protocol::state_machine) fn transition_consumes_coordinate(
    evidence: &TransitionEvidence,
    bound: &PublicGroupSnapshotCoordinate,
) -> bool {
    if !validate_transition_evidence(evidence) {
        return false;
    }
    let Some(authority) = evidence.authority.as_ref() else {
        // Deterministic planner tests use unsealed evidence. Production rows
        // always carry an authority and a closed body binding.
        return true;
    };
    if authority.control_conversation_id.as_ref() != Some(bound.conversation_id()) {
        return false;
    }
    match evidence.body_binding.as_ref() {
        Some(TransitionBodyBinding::DirectRequestPublication {
            prior: Some(prior), ..
        })
        | Some(TransitionBodyBinding::DirectRequestAcceptance { prior, .. })
        | Some(TransitionBodyBinding::Commit { prior, .. })
        | Some(TransitionBodyBinding::Policy { prior, .. })
        | Some(TransitionBodyBinding::Acceptance { prior, .. })
        | Some(TransitionBodyBinding::Metadata { prior, .. })
        | Some(TransitionBodyBinding::ResetActivation { prior, .. })
        | Some(TransitionBodyBinding::LeafRecoveryFulfillment { prior, .. })
        | Some(TransitionBodyBinding::ConversationClose { prior, .. })
        | Some(TransitionBodyBinding::ZeroLeafLeave { prior, .. })
        | Some(TransitionBodyBinding::LeaveCommitFulfillment { prior, .. }) => prior == bound,
        _ => false,
    }
}

pub(in crate::chat_protocol::state_machine) fn recovery_fulfillment_matches_request(
    evidence: &TransitionEvidence,
    request: &RecoveryRequest,
) -> bool {
    recovery_fulfillment_binding_matches(
        evidence,
        &request.request_id,
        &request.target,
        request.kind,
        &request.bound_coordinate,
        &request.key_package_ref,
    )
}

/// Read-time drift fence for a durable fulfilled recovery terminal. This is
/// the same signed-body/manifest predicate used by `validate_recovery_work`,
/// with the terminal timestamp additionally pinned to the exact transition
/// receipt selected from the request/reservation pair.
#[allow(dead_code)]
pub(crate) fn recovery_fulfillment_terminal_matches(
    evidence: &TransitionEvidence,
    request_id: &[u8; 16],
    target: &DeviceIdentity,
    kind: LeafRecoveryKind,
    bound_coordinate: &PublicGroupSnapshotCoordinate,
    key_package_ref: &[u8; 32],
    terminal_at: ServerTimestamp,
) -> bool {
    evidence.received_at() == terminal_at
        && recovery_fulfillment_binding_matches(
            evidence,
            request_id,
            target,
            kind,
            bound_coordinate,
            key_package_ref,
        )
}

/// Read-time drift fence for a durable signed Recovery cancellation.  The
/// cancellation is entry-less, belongs to the same requester device as the
/// open work, binds the exact request identifier, and is retained at the exact
/// database terminal timestamp.
#[allow(dead_code)]
pub(crate) fn recovery_cancellation_terminal_matches(
    evidence: &RequestEvidence,
    request_id: &[u8; 16],
    target: &DeviceIdentity,
    conversation_id: &[u8; 16],
    terminal_at: ServerTimestamp,
) -> bool {
    evidence.kind() == RequestEntryKind::LeafRecoveryCancellation
        && evidence.request_id() == request_id
        && evidence.actor() == target
        && evidence.conversation_id() == conversation_id
        && evidence.received_at() == terminal_at
        && matches!(
            evidence.body_binding.as_ref(),
            Some(RequestBodyBinding::LeafRecoveryCancellation)
        )
}

/// Read-time drift fence for a transition which made Recovery work stale.
/// The transition must consume the exact bound coordinate and its certified
/// receipt time must equal the retained terminal time.
#[allow(dead_code)]
pub(crate) fn recovery_supersession_terminal_matches(
    evidence: &TransitionEvidence,
    bound_coordinate: &PublicGroupSnapshotCoordinate,
    terminal_at: ServerTimestamp,
) -> bool {
    evidence.received_at() == terminal_at
        && transition_consumes_coordinate(evidence, bound_coordinate)
}

pub(in crate::chat_protocol::state_machine) fn recovery_fulfillment_binding_matches(
    evidence: &TransitionEvidence,
    request_id: &[u8; 16],
    target: &DeviceIdentity,
    kind: LeafRecoveryKind,
    bound_coordinate: &PublicGroupSnapshotCoordinate,
    expected_key_package_ref: &[u8; 32],
) -> bool {
    if !transition_consumes_coordinate(evidence, bound_coordinate) {
        return false;
    }
    let Some(authority) = evidence.authority.as_ref() else {
        return true;
    };
    if authority.kind != SignedMutationKind::LeafRecoveryFulfillment {
        return false;
    }
    matches!(
        evidence.body_binding.as_ref(),
        Some(TransitionBodyBinding::LeafRecoveryFulfillment {
            recovery_request_id,
            prior,
            next,
            manifest,
            ..
        }) if recovery_request_id == request_id
            && prior == bound_coordinate
            && commit_coordinate_edge(prior, next)
            && manifest.leaf_recovery_request_id.as_ref() == Some(request_id)
            && manifest.participant_changes.is_empty()
            && manifest.leaf_changes.iter().filter(|change| {
                matches!(change, ManifestLeafChange::Add {
                    device,
                    recovery_request_id,
                    key_package_ref,
                } if device == target
                    && recovery_request_id == request_id
                    && key_package_ref == expected_key_package_ref)
            }).count() == 1
            && match kind {
                LeafRecoveryKind::Add => manifest.leaf_changes.iter().all(|change| {
                    !matches!(change, ManifestLeafChange::Remove(device)
                        if device == target)
                }),
                LeafRecoveryKind::Replace => manifest.leaf_changes.iter().filter(|change| {
                    matches!(change, ManifestLeafChange::Remove(device)
                        if device == target)
                }).count() == 1,
            }
            && manifest.welcome.as_ref().is_some_and(|welcome| {
                welcome.recipient == *target
                    && welcome.recovery_request_id == *request_id
                    && welcome.key_package_ref == *expected_key_package_ref
            })
    )
}

pub(in crate::chat_protocol::state_machine) fn acceptance_origin_matches_recovery(
    evidence: &TransitionEvidence,
    request: &RecoveryRequest,
    reservation: &RecoveryReservation,
    conversation_id: &[u8; 16],
) -> bool {
    if !validate_transition_evidence(evidence)
        || evidence.received_at != request.received_at
        || request.source != RecoverySource::Acceptance
        || request.kind != LeafRecoveryKind::Add
    {
        return false;
    }
    let Some(authority) = evidence.authority.as_ref() else {
        return true;
    };
    if authority.kind != SignedMutationKind::ParticipantAcceptance
        || authority.control_conversation_id.as_ref() != Some(conversation_id)
        || authority.actor != request.target
    {
        return false;
    }
    matches!(
        evidence.body_binding.as_ref(),
        Some(TransitionBodyBinding::Acceptance {
            prior,
            next,
            recovery_request_id,
            invitation_provenance,
            recovery,
        }) if coordinate_only_successor(prior).is_ok_and(|expected| &expected == next)
            && next == &request.bound_coordinate
            && *recovery_request_id == request.request_id
            && is_uuid_v4(&invitation_provenance.transition_id)
            && invitation_provenance.inviter.principal() != request.target.principal()
            && recovery.request_id == request.request_id
            && recovery.conversation_id == *conversation_id
            && recovery.target == request.target
            && recovery.kind == request.kind
            && recovery.bound_coordinate == request.bound_coordinate
            && recovery.requester_key_id == authority.key_id
            && recovery.requester_auth_generation == authority.auth_generation
            && recovery.key_package_ref == request.key_package_ref
            && recovery.key_package_ref == reservation.key_package_ref
            && recovery.requested_at == request.received_at
            && recovery.requested_at == reservation.received_at
            && recovery.expires_at == request.expires_at
            && recovery.expires_at == reservation.expires_at
            && !recovery.key_package_wrapper.is_empty()
            && <[u8; 32]>::from(Sha256::digest(&recovery.key_package_wrapper))
                == recovery.key_package_wrapper_sha256
            && recovery.canonical_digest != [0; 32]
    )
}

pub(in crate::chat_protocol::state_machine) fn reset_activation_matches_request(
    evidence: &TransitionEvidence,
    request: &ResetRequest,
    conversation_kind: ConversationKind,
) -> bool {
    if !transition_consumes_coordinate(evidence, &request.bound_coordinate) {
        return false;
    }
    let Some(authority) = evidence.authority.as_ref() else {
        return true;
    };
    authority.kind == SignedMutationKind::ResetActivation
        && matches!(
            evidence.body_binding.as_ref(),
            Some(TransitionBodyBinding::ResetActivation {
                kind,
                reset_request_id,
                prior,
                retired,
                successor,
                ..
            }) if *kind == conversation_kind
                && *reset_request_id == request.request_id
                && prior == &request.bound_coordinate
                && retired_coordinate(prior).is_ok_and(|expected| &expected == retired)
                && reset_successor_edge(prior, successor)
        )
}

pub(in crate::chat_protocol::state_machine) fn leave_fulfillment_matches_request(
    state: &ConversationState,
    evidence: &TransitionEvidence,
    request: &LeaveRequest,
) -> bool {
    if !transition_consumes_coordinate(evidence, &request.bound_coordinate) {
        return false;
    }
    let Some(proof) = request.fulfilled_participant.as_ref() else {
        return false;
    };
    if proof.participant.principal != *request.requester.principal()
        || proof.participant.status != ParticipantStatus::Active
        || !participant_provenance_matches(state, &proof.participant)
        || proof.terminal != *evidence
    {
        return false;
    }
    let Some(origin_seq) = request.origin.control_seq else {
        return false;
    };
    let terminal_seq = evidence.seq;
    let pre_terminal = state
        .intervals
        .iter()
        .filter(|interval| {
            interval.recipient.principal() == request.requester.principal()
                && interval.opening.seq < terminal_seq
                && interval
                    .end
                    .as_ref()
                    .is_none_or(|end| end.evidence.seq >= terminal_seq)
        })
        .collect::<Vec<_>>();
    let pre_terminal_devices = pre_terminal
        .iter()
        .map(|interval| interval.recipient.clone())
        .collect::<BTreeSet<_>>();
    if pre_terminal.is_empty()
        || pre_terminal_devices.len() != pre_terminal.len()
        || !pre_terminal
            .iter()
            .any(|interval| interval.opening.seq <= origin_seq)
        || !pre_terminal.iter().all(|interval| {
            interval.end.as_ref().is_some_and(|end| {
                end.kind == CloseKind::Remove
                    && end.evidence.seq == terminal_seq
                    && end.evidence == *evidence
            })
        })
    {
        return false;
    }
    if evidence
        .authority
        .as_ref()
        .is_some_and(|authority| authority.kind != SignedMutationKind::LeaveCommitFulfillment)
    {
        return false;
    }
    match evidence.body_binding.as_ref() {
        None => evidence.authority.is_none(),
        body => matches!(
            body,
            Some(TransitionBodyBinding::LeaveCommitFulfillment {
                leave_request_id,
                prior,
                next,
                manifest,
                ..
            }) if *leave_request_id == request.request_id
                && prior == &request.bound_coordinate
                && commit_coordinate_edge(prior, next)
                && manifest.leaf_recovery_request_id.is_none()
                && manifest.welcome.is_none()
                && manifest.participant_changes.len() == 1
                && matches!(&manifest.participant_changes[0],
                    ManifestParticipantChange::Remove(principal)
                        if principal == request.requester.principal())
                && {
                    let removed = manifest.leaf_changes.iter().filter_map(|change| {
                        match change {
                            ManifestLeafChange::Remove(device)
                                if device.principal() == request.requester.principal() =>
                            {
                                Some(device.clone())
                            }
                            _ => None,
                        }
                    }).collect::<BTreeSet<_>>();
                    manifest.leaf_changes.len() == removed.len()
                        && removed == pre_terminal_devices
                }
        ),
    }
}

pub(in crate::chat_protocol::state_machine) fn validate_work(state: &ConversationState, terminal_state: bool) -> Result<(), StateMachineError> {
    validate_recovery_work(state)?;
    validate_reset_work(state)?;
    validate_leave_work(state)?;
    validate_welcome_work(state)?;
    if terminal_state
        && (state
            .recovery_requests
            .iter()
            .any(|request| request.status == RecoveryRequestStatus::Open)
            || state
                .recovery_reservations
                .iter()
                .any(|reservation| reservation.status == ReservationStatus::Active)
            || state
                .reset_requests
                .iter()
                .any(|request| request.status == ResetRequestStatus::Pending)
            || state
                .leave_requests
                .iter()
                .any(|request| request.status == LeaveRequestStatus::Pending)
            || state
                .welcomes
                .iter()
                .any(|welcome| welcome.status == WelcomeStatus::Pending))
    {
        return Err(StateMachineError::InvariantViolation);
    }
    Ok(())
}
