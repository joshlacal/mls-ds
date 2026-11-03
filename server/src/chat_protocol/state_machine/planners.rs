#![allow(unused_imports)]
use super::*;

#[cfg(test)]
pub(crate) fn plan_commit(
    prior: &ConversationState,
    command: CommitCommand,
) -> Result<PlannedTransition, StateMachineError> {
    plan_commit_inner(prior, command)
}

#[cfg(test)]
pub(crate) fn plan_reset_request(
    prior: &ConversationState,
    command: ResetRequestCommand,
) -> Result<PlannedTransition, StateMachineError> {
    plan_reset_request_inner(prior, command)
}

#[cfg(test)]
pub(crate) fn plan_welcome_expiry_for_test(
    prior: &ConversationState,
    welcome_id: [u8; 16],
) -> Result<PlannedTransition, StateMachineError> {
    plan_welcome_expiry(prior, welcome_id)
}

#[cfg(test)]
pub(crate) fn plan_welcome_response_for_test(
    prior: &ConversationState,
    evidence: RequestEvidence,
    successor_status: WelcomeStatus,
) -> Result<PlannedTransition, StateMachineError> {
    plan_welcome_response(prior, evidence, successor_status)
}

#[cfg(test)]
pub(crate) fn plan_reset_activation(
    prior: &ConversationState,
    command: ResetActivation,
) -> Result<PlannedTransition, StateMachineError> {
    plan_reset_activation_inner(prior, command)
}

#[cfg(test)]
pub(crate) fn plan_zero_leaf_leave(
    prior: &ConversationState,
    command: ZeroLeafLeave,
) -> Result<PlannedTransition, StateMachineError> {
    plan_zero_leaf_leave_inner(prior, command)
}

#[cfg(test)]
pub(crate) fn plan_leave_request(
    prior: &ConversationState,
    command: LeaveRequestCommand,
) -> Result<PlannedTransition, StateMachineError> {
    plan_leave_request_inner(prior, command)
}

#[cfg(test)]
pub(crate) fn plan_leave_cancellation(
    prior: &ConversationState,
    command: LeaveCancellation,
) -> Result<PlannedTransition, StateMachineError> {
    plan_leave_cancellation_inner(prior, command)
}

#[cfg(test)]
pub(crate) fn plan_leave_fulfillment(
    prior: &ConversationState,
    command: LeaveFulfillment,
) -> Result<PlannedTransition, StateMachineError> {
    plan_leave_fulfillment_inner(prior, command)
}

#[cfg(test)]
pub(crate) fn plan_close(
    prior: &ConversationState,
    command: CloseConversation,
) -> Result<PlannedTransition, StateMachineError> {
    plan_close_inner(prior, command)
}

pub(in crate::chat_protocol::state_machine) fn ensure_active(
    state: &ConversationState,
) -> Result<(), StateMachineError> {
    if state.coordinate.lifecycle() != PublicGroupSnapshotLifecycle::Active
        || state.public_state.is_none()
    {
        return Err(StateMachineError::ConversationClosed);
    }
    if state.public_state().coordinate() != &state.coordinate {
        tracing::error!(
            "coordinate mismatch: public_state={:?} != state_coord={:?}",
            state.public_state().coordinate(),
            state.coordinate
        );
        return Err(StateMachineError::InvalidPublicState);
    }
    Ok(())
}

pub(in crate::chat_protocol::state_machine) fn resolve_prior_bound_work(
    state: &mut ConversationState,
    prior: &PublicGroupSnapshotCoordinate,
    evidence: &TransitionEvidence,
    fulfilled_recovery: Option<[u8; 16]>,
    consumed_reset: Option<[u8; 16]>,
    fulfilled_leave: Option<[u8; 16]>,
) {
    for request in &mut state.recovery_requests {
        if request.status != RecoveryRequestStatus::Open || &request.bound_coordinate != prior {
            continue;
        }
        if fulfilled_recovery == Some(request.request_id) {
            request.status = RecoveryRequestStatus::Fulfilled;
            request.terminal = Some(WorkTerminalEvidence::Transition(evidence.clone()));
        } else if evidence.received_at >= request.expires_at {
            request.status = RecoveryRequestStatus::Expired;
            request.terminal = Some(WorkTerminalEvidence::Expiry(request.expires_at));
        } else {
            request.status = RecoveryRequestStatus::Superseded;
            request.terminal = Some(WorkTerminalEvidence::Transition(evidence.clone()));
        }
    }
    for reservation in &mut state.recovery_reservations {
        if reservation.status != ReservationStatus::Active || &reservation.bound_coordinate != prior
        {
            continue;
        }
        if fulfilled_recovery == Some(reservation.request_id) {
            reservation.status = ReservationStatus::Consumed;
            reservation.terminal = Some(WorkTerminalEvidence::Transition(evidence.clone()));
        } else if evidence.received_at >= reservation.expires_at {
            reservation.status = ReservationStatus::Expired;
            reservation.terminal = Some(WorkTerminalEvidence::Expiry(reservation.expires_at));
        } else {
            reservation.status = ReservationStatus::Released;
            reservation.terminal = Some(WorkTerminalEvidence::Transition(evidence.clone()));
        }
    }
    for request in &mut state.reset_requests {
        if request.status != ResetRequestStatus::Pending || &request.bound_coordinate != prior {
            continue;
        }
        if consumed_reset == Some(request.request_id) {
            request.status = ResetRequestStatus::Consumed;
            request.terminal = Some(WorkTerminalEvidence::Transition(evidence.clone()));
        } else if evidence.received_at >= request.expires_at {
            request.status = ResetRequestStatus::Expired;
            request.terminal = Some(WorkTerminalEvidence::Expiry(request.expires_at));
        } else {
            request.status = ResetRequestStatus::Stale;
            request.terminal = Some(WorkTerminalEvidence::Transition(evidence.clone()));
        }
    }
    for request in &mut state.leave_requests {
        if request.status != LeaveRequestStatus::Pending || &request.bound_coordinate != prior {
            continue;
        }
        if fulfilled_leave == Some(request.request_id) {
            request.status = LeaveRequestStatus::Fulfilled;
            request.terminal = Some(WorkTerminalEvidence::Transition(evidence.clone()));
        } else if evidence.received_at >= request.expires_at {
            request.status = LeaveRequestStatus::Expired;
            request.terminal = Some(WorkTerminalEvidence::Expiry(request.expires_at));
        } else {
            request.status = LeaveRequestStatus::Stale;
            request.terminal = Some(WorkTerminalEvidence::Transition(evidence.clone()));
        }
    }
    for welcome in &mut state.welcomes {
        if welcome.status != WelcomeStatus::Pending || &welcome.coordinate != prior {
            continue;
        }
        if evidence.received_at >= welcome.expires_at {
            welcome.status = WelcomeStatus::Expired;
            welcome.terminal = Some(WorkTerminalEvidence::Expiry(welcome.expires_at));
        } else {
            welcome.status = WelcomeStatus::Superseded;
            welcome.terminal = Some(WorkTerminalEvidence::Transition(evidence.clone()));
        }
    }
}

/// Expire every past-due `Pending` leave request the incoming request observes
/// on the already-locked aggregate, BEFORE the pending-uniqueness guard reads it.
///
/// This is the leave-family form of the expire-first discipline welcome and
/// recovery already use: `repository/core.rs` classifies a past-due pending
/// welcome as `PendingDue` at the row lock, and `repository/recovery.rs`
/// (`classify_client_terminal_disposition`) maps every `OpenDue` action to
/// `ExpireFirst`. Leave requests live INSIDE the conversation aggregate rather
/// than in a separately locked row, so the equivalent classification point is
/// the planner reading the locked state — the same place `resolve_prior_bound_work`
/// already performs this exact `Pending -> Expired` edge for coordinate-advancing
/// transitions.
///
/// The terminal is `WorkTerminalEvidence::Expiry(request.expires_at)` — the
/// request's OWN deadline, never the observer's instant — which
/// `write_observed_leave_expiries` persists as status `expired` with a NULL
/// terminal transition and digest and `terminal_at = expires_at`, the only shape
/// `leave_requests_terminal_shape_check` accepts. Expiry is therefore an
/// OBSERVATION of the row's DB-enforced TTL that binds nothing about whoever
/// observed it, which is why any member's request may clear a lapsed row and why
/// the sweep is not restricted to the actor's own requests.
///
/// The boundary matches `classify_pending_reset_at` and `classify_locked_recovery`:
/// `observed_at < expires_at` is still live, `observed_at >= expires_at` is due.
/// Returns the number of requests swept.
pub(in crate::chat_protocol::state_machine) fn expire_due_leave_requests(
    state: &mut ConversationState,
    observed_at: ServerTimestamp,
) -> usize {
    let mut swept = 0;
    for request in &mut state.leave_requests {
        if request.status != LeaveRequestStatus::Pending || observed_at < request.expires_at {
            continue;
        }
        request.status = LeaveRequestStatus::Expired;
        request.terminal = Some(WorkTerminalEvidence::Expiry(request.expires_at));
        swept += 1;
    }
    swept
}

pub(in crate::chat_protocol::state_machine) fn coordinate_only_successor(
    prior: &PublicGroupSnapshotCoordinate,
) -> Result<PublicGroupSnapshotCoordinate, StateMachineError> {
    let state_version = prior
        .state_version()
        .checked_add(1)
        .filter(|value| *value <= MAX_PROTOCOL_INTEGER)
        .ok_or(StateMachineError::CoordinateOverflow)?;
    Ok(PublicGroupSnapshotCoordinate::new(
        *prior.conversation_id(),
        prior.generation(),
        state_version,
        *prior.group_id(),
        prior.epoch(),
        *prior.group_context_hash(),
        *prior.confirmation_tag(),
        PublicGroupSnapshotLifecycle::Active,
    ))
}

pub(crate) fn retired_coordinate(
    prior: &PublicGroupSnapshotCoordinate,
) -> Result<PublicGroupSnapshotCoordinate, StateMachineError> {
    let state_version = prior
        .state_version()
        .checked_add(1)
        .filter(|value| *value <= MAX_PROTOCOL_INTEGER)
        .ok_or(StateMachineError::CoordinateOverflow)?;
    Ok(PublicGroupSnapshotCoordinate::new(
        *prior.conversation_id(),
        prior.generation(),
        state_version,
        *prior.group_id(),
        prior.epoch(),
        *prior.group_context_hash(),
        *prior.confirmation_tag(),
        PublicGroupSnapshotLifecycle::Superseded,
    ))
}

pub(in crate::chat_protocol::state_machine) fn open_interval(
    intervals: &mut Vec<AccessInterval>,
    recipient: DeviceIdentity,
    opening: TransitionEvidence,
    opening_kind: OpeningKind,
    opening_context: PublicGroupSnapshotCoordinate,
) -> Result<(), StateMachineError> {
    if opening_context.lifecycle() != PublicGroupSnapshotLifecycle::Active
        || intervals
            .iter()
            .any(|interval| interval.recipient == recipient && interval.end.is_none())
    {
        return Err(StateMachineError::InvalidIntervalBoundary);
    }
    if let Some(previous) = intervals
        .iter()
        .filter(|interval| interval.recipient == recipient)
        .max_by_key(|interval| interval.opening.seq)
    {
        let end = previous
            .end
            .as_ref()
            .ok_or(StateMachineError::InvalidIntervalBoundary)?;
        if end.evidence.seq > opening.seq {
            return Err(StateMachineError::InvalidIntervalBoundary);
        }
        if end.evidence.seq == opening.seq {
            let legal = matches!(
                (end.kind, opening_kind),
                (CloseKind::Replace, OpeningKind::Add) | (CloseKind::Reset, OpeningKind::Reset)
            ) && end.evidence.transition_id == opening.transition_id
                && end.evidence.outer_entry_fingerprint == opening.outer_entry_fingerprint;
            if !legal {
                return Err(StateMachineError::InvalidIntervalBoundary);
            }
        } else if end.kind == CloseKind::Terminal {
            return Err(StateMachineError::InvalidIntervalBoundary);
        }
    }
    intervals.push(AccessInterval {
        recipient,
        generation: opening_context.generation(),
        opening,
        opening_kind,
        opening_context,
        end: None,
    });
    Ok(())
}

pub(in crate::chat_protocol::state_machine) fn close_open_interval(
    intervals: &mut [AccessInterval],
    recipient: &DeviceIdentity,
    evidence: &TransitionEvidence,
    kind: CloseKind,
) -> Result<(), StateMachineError> {
    let interval = intervals
        .iter_mut()
        .filter(|interval| &interval.recipient == recipient && interval.end.is_none())
        .max_by_key(|interval| interval.opening.seq)
        .ok_or(StateMachineError::InvalidIntervalBoundary)?;
    if evidence.seq <= interval.opening.seq {
        return Err(StateMachineError::InvalidIntervalBoundary);
    }
    interval.end = Some(AccessIntervalEnd {
        evidence: evidence.clone(),
        kind,
    });
    Ok(())
}

pub(in crate::chat_protocol::state_machine) fn sort_intervals(intervals: &mut [AccessInterval]) {
    intervals.sort_by(|left, right| {
        left.recipient
            .cmp(&right.recipient)
            .then_with(|| left.opening.seq.cmp(&right.opening.seq))
    });
}

pub(in crate::chat_protocol::state_machine) fn pending_request_leaf_is_bound(
    state: &ConversationState,
    leaf: &LeafRecord,
) -> bool {
    state.kind == ConversationKind::Direct && state.intervals.iter().any(|interval| {
        interval.recipient == leaf.device && interval.end.is_none() && interval.generation == state.coordinate.generation()
        && interval.opening_kind == OpeningKind::DirectRequest
        && interval.opening.authority.as_ref().is_some_and(|a| a.kind == SignedMutationKind::DirectRequestPublication)
        && validate_transition_evidence(&interval.opening)
        && matches!(interval.opening.body_binding.as_ref(), Some(TransitionBodyBinding::DirectRequestPublication { next, recipient, devices, .. })
            if recipient == leaf.device.principal() && devices.contains(&leaf.device) && next == &state.coordinate)
    })
}

pub(in crate::chat_protocol::state_machine) fn validate_state(
    state: &ConversationState,
) -> Result<(), StateMachineError> {
    validate_participants(state)?;
    if !current_state_producer_matches(state)
        || !metadata_provenance_matches(state)
        || state.coordinate.lifecycle() != PublicGroupSnapshotLifecycle::Active
        || state
            .public_state
            .as_ref()
            .map(ActivePublicState::coordinate)
            != Some(&state.coordinate)
        || state
            .metadata
            .as_ref()
            .is_some_and(|metadata| !metadata_coordinate_matches(metadata, &state.coordinate))
        || (state
            .intervals
            .iter()
            .any(|interval| interval.opening.authority.is_some())
            && state.metadata.is_none())
        || !(1..=MAX_LEAVES).contains(&state.leaves.len())
        || !state.terminal_proofs.is_empty()
        || state
            .leaves
            .windows(2)
            .any(|pair| pair[0].leaf_index >= pair[1].leaf_index)
        || state
            .leaves
            .iter()
            .map(|leaf| &leaf.device)
            .collect::<BTreeSet<_>>()
            .len()
            != state.leaves.len()
    {
        return Err(StateMachineError::InvariantViolation);
    }
    for participant in &state.participants {
        let leaf_count = state
            .leaves
            .iter()
            .filter(|leaf| leaf.device.principal() == &participant.principal)
            .count();
        if (participant.status == ParticipantStatus::Pending
            && state
                .leaves
                .iter()
                .filter(|leaf| leaf.device.principal() == &participant.principal)
                .any(|leaf| !pending_request_leaf_is_bound(state, leaf)))
            || leaf_count > MAX_LEAVES_PER_PRINCIPAL
        {
            return Err(StateMachineError::InvariantViolation);
        }
    }
    if state.leaves.iter().any(|leaf| {
        state
            .participant(leaf.device.principal())
            .is_none_or(|participant| {
                !participant.is_active() && !pending_request_leaf_is_bound(state, leaf)
            })
            || leaf.basic_credential != leaf.device.basic_credential()
            || leaf.signature_key.len() != 32
            || leaf.encryption_key.is_empty()
    }) {
        return Err(StateMachineError::InvariantViolation);
    }
    let public_leaves = state.public_state().binding().tree_summary().leaves();
    if public_leaves.len() != state.leaves.len()
        || state
            .leaves
            .iter()
            .zip(public_leaves)
            .any(|(leaf, public_leaf)| {
                leaf.leaf_index != public_leaf.leaf_index()
                    || leaf.basic_credential != public_leaf.basic_credential()
                    || leaf.signature_key != public_leaf.signature_key()
                    || leaf.encryption_key != public_leaf.encryption_key()
            })
    {
        return Err(StateMachineError::InvariantViolation);
    }
    validate_intervals(&state.intervals, &state.coordinate, state.kind)?;
    if state.intervals.iter().any(|interval| {
        interval
            .end
            .as_ref()
            .is_some_and(|end| end.kind == CloseKind::Terminal)
    }) {
        return Err(StateMachineError::InvalidIntervalBoundary);
    }
    let leaf_devices = state
        .leaves
        .iter()
        .map(|leaf| &leaf.device)
        .collect::<BTreeSet<_>>();
    let open_devices = state
        .intervals
        .iter()
        .filter(|interval| interval.end.is_none())
        .map(|interval| &interval.recipient)
        .collect::<BTreeSet<_>>();
    if leaf_devices != open_devices {
        return Err(StateMachineError::InvariantViolation);
    }
    validate_work(state, false)
}

pub(in crate::chat_protocol::state_machine) fn validate_participants(
    state: &ConversationState,
) -> Result<(), StateMachineError> {
    if !(1..=MAX_PARTICIPANTS).contains(&state.participants.len())
        || state
            .participants
            .windows(2)
            .any(|pair| pair[0].principal >= pair[1].principal)
        || state
            .participants
            .iter()
            .any(|participant| !participant_provenance_matches(state, participant))
        || !state.participants.iter().any(|participant| {
            participant.status == ParticipantStatus::Active
                && participant.role == ParticipantRole::Admin
        })
        || (state.kind == ConversationKind::Direct
            && (state.participants.len() != 2
                || state
                    .participants
                    .iter()
                    .any(|participant| participant.role != ParticipantRole::Admin)))
    {
        return Err(StateMachineError::InvariantViolation);
    }
    Ok(())
}

pub(in crate::chat_protocol::state_machine) fn participant_provenance_matches(
    state: &ConversationState,
    participant: &ParticipantRecord,
) -> bool {
    if !participant_role_provenance_matches(state, participant) {
        return false;
    }
    match (
        participant.status,
        participant.invitation.as_ref(),
        participant.acceptance.as_ref(),
    ) {
        (ParticipantStatus::Pending, Some(invitation), None) => {
            invitation_matches_participant(state.kind, participant, invitation)
        }
        (ParticipantStatus::Active, None, None) => true,
        (ParticipantStatus::Active, Some(invitation), Some(acceptance)) => {
            invitation_matches_participant(state.kind, participant, invitation)
                && acceptance_matches_participant(state, participant, invitation, acceptance)
        }
        _ => false,
    }
}

pub(in crate::chat_protocol::state_machine) fn initial_participant_role(
    conversation_kind: ConversationKind,
    participant: &ParticipantRecord,
) -> Option<ParticipantRole> {
    match participant.invitation.as_ref() {
        None => Some(ParticipantRole::Admin),
        Some(invitation) => match invitation.transition.body_binding.as_ref() {
            Some(TransitionBodyBinding::DirectRequestPublication { recipient, .. })
                if conversation_kind == ConversationKind::Direct
                    && recipient == &participant.principal =>
            {
                Some(ParticipantRole::Admin)
            }
            Some(TransitionBodyBinding::Creation { kind, .. }) if *kind == conversation_kind => {
                Some(if conversation_kind == ConversationKind::Direct {
                    ParticipantRole::Admin
                } else {
                    ParticipantRole::Member
                })
            }
            Some(TransitionBodyBinding::Policy {
                participant_changes,
                ..
            }) if participant_changes.iter().any(|change| {
                matches!(change, ManifestParticipantChange::Add(principal)
                    if principal == &participant.principal)
            }) =>
            {
                Some(ParticipantRole::Member)
            }
            _ => None,
        },
    }
}

pub(in crate::chat_protocol::state_machine) fn participant_role_provenance_matches(
    state: &ConversationState,
    participant: &ParticipantRecord,
) -> bool {
    let initial_role = initial_participant_role(state.kind, participant).or_else(|| {
        // Pure planner tests intentionally omit sealed bodies. Production
        // hydration never admits this branch because it retains authority.
        participant.invitation.as_ref().and_then(|invitation| {
            (invitation.transition.body_binding.is_none()
                && invitation.transition.authority.is_none())
            .then_some(participant.role)
        })
    });

    match participant.role_producer.as_ref() {
        None => initial_role == Some(participant.role),
        Some(producer) => {
            if !validate_transition_evidence(producer) {
                return false;
            }
            let Some(authority) = producer.authority.as_ref() else {
                return true;
            };
            authority.kind == SignedMutationKind::PolicyTransition
                && authority.control_conversation_id.as_ref()
                    == Some(state.coordinate.conversation_id())
                && producer.seq <= state.producer.seq
                && producer.received_at <= state.producer.received_at
                && matches!(producer.body_binding.as_ref(),
                    Some(TransitionBodyBinding::Policy {
                        prior,
                        next,
                        participant_changes,
                    }) if coordinate_only_successor(prior).is_ok_and(|expected| &expected == next)
                        && coordinate_is_in_lineage(next, &state.coordinate)
                        && participant_changes.iter().filter(|change| {
                            matches!(change, ManifestParticipantChange::ChangeRole(principal, role)
                                if principal == &participant.principal && *role == participant.role)
                        }).count() == 1)
        }
    }
}

pub(in crate::chat_protocol::state_machine) fn invitation_matches_participant(
    conversation_kind: ConversationKind,
    participant: &ParticipantRecord,
    invitation: &InvitationProvenance,
) -> bool {
    if !validate_transition_evidence(&invitation.transition)
        || invitation.inviter.basic_credential().is_empty()
    {
        return false;
    }
    let Some(authority) = invitation.transition.authority.as_ref() else {
        return true;
    };
    if authority.actor != invitation.inviter {
        return false;
    }
    match invitation.transition.body_binding.as_ref() {
        Some(TransitionBodyBinding::DirectRequestPublication {
            prior: None,
            recipient,
            ..
        }) => {
            authority.kind == SignedMutationKind::DirectRequestPublication
                && conversation_kind == ConversationKind::Direct
                && recipient == &participant.principal
        }
        Some(TransitionBodyBinding::Creation { kind, manifest, .. }) => {
            let invitation_role = if *kind == ConversationKind::Direct {
                ParticipantRole::Admin
            } else {
                ParticipantRole::Member
            };
            authority.kind == SignedMutationKind::Creation
                && *kind == conversation_kind
                && manifest.actor_leaf == invitation.inviter
                && manifest
                    .participants
                    .iter()
                    .filter(|signed| {
                        signed.principal == participant.principal
                            && signed.status == ParticipantStatus::Pending
                            && signed.role == invitation_role
                            && signed.invitation.as_ref().is_some_and(|signed_invitation| {
                                signed_invitation.transition_id
                                    == invitation.transition.transition_id
                                    && signed_invitation.inviter == invitation.inviter
                            })
                    })
                    .count()
                    == 1
        }
        Some(TransitionBodyBinding::Policy {
            participant_changes,
            ..
        }) => {
            authority.kind == SignedMutationKind::PolicyTransition
                && participant_changes
                    .iter()
                    .filter(|change| {
                        matches!(change, ManifestParticipantChange::Add(principal)
                        if principal == &participant.principal)
                    })
                    .count()
                    == 1
        }
        _ => false,
    }
}

pub(in crate::chat_protocol::state_machine) fn acceptance_matches_participant(
    state: &ConversationState,
    participant: &ParticipantRecord,
    invitation: &InvitationProvenance,
    acceptance: &TransitionEvidence,
) -> bool {
    if !validate_transition_evidence(acceptance) {
        return false;
    }
    let Some(authority) = acceptance.authority.as_ref() else {
        return true;
    };
    if let Some(TransitionBodyBinding::DirectRequestAcceptance {
        request_id,
        prior,
        next,
        invitation: signed_invitation,
    }) = acceptance.body_binding.as_ref()
    {
        return authority.kind == SignedMutationKind::DirectRequestAcceptance
            && authority.actor.principal() == &participant.principal
            && signed_invitation.transition_id == invitation.transition.transition_id
            && signed_invitation.inviter == invitation.inviter
            && coordinate_only_successor(prior).is_ok_and(|expected| &expected == next)
            && coordinate_is_in_lineage(next, &state.coordinate)
            && state.intervals.iter().any(|i| i.generation == prior.generation()
                && i.opening.transition_id == *request_id
                && matches!(i.opening.body_binding.as_ref(), Some(TransitionBodyBinding::DirectRequestPublication { recipient, next: published, .. })
                    if recipient == &participant.principal && coordinate_after_opening(prior, published)));
    }
    if authority.kind != SignedMutationKind::ParticipantAcceptance
        || authority.actor.principal() != &participant.principal
    {
        return false;
    }
    let mut matching_requests = state.recovery_requests.iter().filter(|request| {
        request.source == RecoverySource::Acceptance
            && request.target == authority.actor
            && matches!(&request.origin, RecoveryOriginEvidence::Acceptance(origin)
                if origin == acceptance)
    });
    let Some(request) = matching_requests.next() else {
        return false;
    };
    if matching_requests.next().is_some() {
        return false;
    }
    let Some(reservation) = state
        .recovery_reservation(&request.request_id)
        .filter(|reservation| reservation.target == request.target)
    else {
        return false;
    };
    match acceptance.body_binding.as_ref() {
        Some(TransitionBodyBinding::Acceptance {
            next,
            recovery_request_id,
            invitation_provenance,
            recovery,
            ..
        }) => {
            *recovery_request_id == request.request_id
                && invitation_provenance.transition_id == invitation.transition.transition_id
                && invitation_provenance.inviter == invitation.inviter
                && recovery.request_id == request.request_id
                && recovery.conversation_id == *state.coordinate.conversation_id()
                && recovery.target == request.target
                && recovery.kind == LeafRecoveryKind::Add
                && recovery.bound_coordinate == request.bound_coordinate
                && *next == request.bound_coordinate
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
        }
        _ => false,
    }
}

pub(in crate::chat_protocol::state_machine) fn current_state_producer_matches(
    state: &ConversationState,
) -> bool {
    let evidence = &state.producer;
    if !validate_transition_evidence(evidence) {
        return false;
    }
    let Some(authority) = evidence.authority.as_ref() else {
        return true;
    };
    if authority.control_conversation_id.as_ref() != Some(state.coordinate.conversation_id()) {
        return false;
    }
    match (authority.kind, evidence.body_binding.as_ref()) {
        (
            SignedMutationKind::DirectRequestPublication,
            Some(TransitionBodyBinding::DirectRequestPublication { next, metadata, .. }),
        ) => {
            state.kind == ConversationKind::Direct
                && next == &state.coordinate
                && metadata_author_matches_evidence(metadata, evidence)
        }
        (
            SignedMutationKind::DirectRequestAcceptance,
            Some(TransitionBodyBinding::DirectRequestAcceptance { next, .. }),
        ) => state.kind == ConversationKind::Direct && next == &state.coordinate,

        (
            SignedMutationKind::Creation,
            Some(TransitionBodyBinding::Creation { kind, next, .. }),
        ) => *kind == state.kind && next == &state.coordinate,
        (
            SignedMutationKind::CommitTransition,
            Some(TransitionBodyBinding::Commit { next, .. }),
        )
        | (
            SignedMutationKind::PolicyTransition,
            Some(TransitionBodyBinding::Policy { next, .. }),
        )
        | (
            SignedMutationKind::ParticipantAcceptance,
            Some(TransitionBodyBinding::Acceptance { next, .. }),
        )
        | (
            SignedMutationKind::MetadataTransition,
            Some(TransitionBodyBinding::Metadata { next, .. }),
        )
        | (
            SignedMutationKind::LeafRecoveryFulfillment,
            Some(TransitionBodyBinding::LeafRecoveryFulfillment { next, .. }),
        )
        | (
            SignedMutationKind::ZeroLeafLeave,
            Some(TransitionBodyBinding::ZeroLeafLeave { next, .. }),
        )
        | (
            SignedMutationKind::LeaveCommitFulfillment,
            Some(TransitionBodyBinding::LeaveCommitFulfillment { next, .. }),
        ) => next == &state.coordinate,
        (
            SignedMutationKind::ResetActivation,
            Some(TransitionBodyBinding::ResetActivation {
                kind, successor, ..
            }),
        ) => *kind == state.kind && successor == &state.coordinate,
        (
            SignedMutationKind::ConversationClose,
            Some(TransitionBodyBinding::ConversationClose { kind, retired, .. }),
        ) => *kind == state.kind && retired == &state.coordinate,
        _ => false,
    }
}

pub(in crate::chat_protocol::state_machine) fn metadata_provenance_matches(
    state: &ConversationState,
) -> bool {
    match (state.metadata.as_ref(), state.metadata_producer.as_ref()) {
        (None, None) => true,
        (Some(metadata), Some(producer)) => {
            if !validate_transition_evidence(producer)
                || transition_metadata(producer) != Some(metadata)
                || producer.seq > state.producer.seq
                || producer.received_at > state.producer.received_at
            {
                return false;
            }
            producer.authority.as_ref().is_none_or(|authority| {
                (authority.kind != SignedMutationKind::DirectRequestPublication
                    || metadata_author_matches_evidence(metadata, producer))
                    && authority.control_conversation_id.as_ref()
                        == Some(state.coordinate.conversation_id())
                    && matches!(
                        authority.kind,
                        SignedMutationKind::DirectRequestPublication
                            | SignedMutationKind::Creation
                            | SignedMutationKind::CommitTransition
                            | SignedMutationKind::MetadataTransition
                            | SignedMutationKind::ResetActivation
                            | SignedMutationKind::LeafRecoveryFulfillment
                            | SignedMutationKind::LeaveCommitFulfillment
                    )
            })
        }
        _ => false,
    }
}

pub(in crate::chat_protocol::state_machine) fn validate_terminal_state(
    state: &ConversationState,
) -> Result<(), StateMachineError> {
    validate_participants(state)?;
    if !current_state_producer_matches(state)
        || !metadata_provenance_matches(state)
        || state.coordinate.lifecycle() != PublicGroupSnapshotLifecycle::Superseded
        || state.public_state.is_some()
        || !state.leaves.is_empty()
        || state
            .metadata
            .as_ref()
            .is_some_and(|metadata| !metadata_coordinate_matches(metadata, &state.coordinate))
    {
        return Err(StateMachineError::InvariantViolation);
    }
    validate_intervals(&state.intervals, &state.coordinate, state.kind)?;
    validate_terminal_proofs(state)?;
    validate_work(state, true)
}

pub(in crate::chat_protocol::state_machine) fn validate_transition_evidence(
    evidence: &TransitionEvidence,
) -> bool {
    evidence.seq > 0
        && evidence.seq <= MAX_PROTOCOL_INTEGER
        && is_uuid_v4(&evidence.transition_id)
        && evidence.outer_entry_fingerprint != [0; 32]
        && evidence.authority.as_ref().is_none_or(|authority| {
            !evidence.outer_control_projection.is_empty()
                && !evidence.server_fields_dag_cbor.is_empty()
                && evidence.durable_row_digest != [0; 32]
                && durable_control_transition_row_digest(evidence)
                    .is_ok_and(|digest| digest == evidence.durable_row_digest)
                && authority.type_id == authority.kind.type_id()
                && authority.domain == authority.kind.domain()
                && authority
                    .control_entry_id
                    .is_some_and(|entry_id| is_uuid_v4(&entry_id))
                && authority
                    .control_conversation_id
                    .is_some_and(|conversation_id| is_uuid_v4(&conversation_id))
                && authority.auth_generation > 0
                && authority.auth_generation <= MAX_PROTOCOL_INTEGER
                && authority.key_id != [0; 32]
                && authority.request_digest != [0; 32]
                && authority.signature != [0; 64]
                && !authority.signed_request_bytes.is_empty()
                && !authority.canonical_projection.is_empty()
                && !authority.transcript_bytes.is_empty()
                && (authority.signed_at <= evidence.received_at
                    || (authority.kind == SignedMutationKind::DirectRequestPublication
                        && evidence
                            .received_at
                            .checked_add_millis(60_000)
                            .is_ok_and(|deadline| authority.signed_at <= deadline))
                    || (authority.kind == SignedMutationKind::DirectRequestAcceptance
                        && evidence
                            .received_at
                            .checked_add_millis(30_000)
                            .is_ok_and(|deadline| authority.signed_at <= deadline)))
        })
}

pub(in crate::chat_protocol::state_machine) fn require_transition_kind(
    evidence: &TransitionEvidence,
    expected: SignedMutationKind,
) -> Result<(), StateMachineError> {
    if evidence
        .authority
        .as_ref()
        .is_some_and(|authority| authority.kind != expected)
    {
        return Err(StateMachineError::InvalidTransition);
    }
    Ok(())
}
