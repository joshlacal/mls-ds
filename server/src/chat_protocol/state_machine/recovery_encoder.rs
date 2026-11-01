#![allow(unused_imports)]
use super::*;

pub(in crate::chat_protocol::state_machine) fn plan_device_revocation_inner(
    prior: &ConversationState,
    evidence: DeviceRevocationEvidence,
) -> Result<PlannedTransition, StateMachineError> {
    ensure_active(prior)?;
    if !validate_device_revocation_evidence(&evidence) {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    let has_target_leaf = prior.leaf(&evidence.target).is_some();
    let target_request_indices = prior
        .recovery_requests
        .iter()
        .enumerate()
        .filter(|(_, request)| {
            request.target == evidence.target && request.status == RecoveryRequestStatus::Open
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if !has_target_leaf && target_request_indices.is_empty() {
        return Err(StateMachineError::RecoveryDeviceMismatch);
    }
    for index in &target_request_indices {
        let request = &prior.recovery_requests[*index];
        let target_generation = match &request.origin {
            RecoveryOriginEvidence::Acceptance(origin) => origin
                .authority
                .as_ref()
                .map(|authority| authority.auth_generation),
            RecoveryOriginEvidence::Request(origin) => Some(origin.auth_generation),
        }
        .ok_or(StateMachineError::InvalidHydrationAuthority)?;
        if target_generation != evidence.expected_target_auth_generation
            || evidence.accepted_at < request.received_at
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
    }

    let mut state = prior.clone();
    for index in target_request_indices {
        let request_id = state.recovery_requests[index].request_id;
        let terminal = if evidence.accepted_at >= state.recovery_requests[index].expires_at {
            WorkTerminalEvidence::Expiry(state.recovery_requests[index].expires_at)
        } else {
            WorkTerminalEvidence::DeviceRevocation(evidence.clone())
        };
        state.recovery_requests[index].status = match terminal {
            WorkTerminalEvidence::Expiry(_) => RecoveryRequestStatus::Expired,
            _ => RecoveryRequestStatus::Superseded,
        };
        state.recovery_requests[index].terminal = Some(terminal.clone());
        let reservation = state
            .recovery_reservations
            .iter_mut()
            .find(|reservation| {
                reservation.request_id == request_id
                    && reservation.status == ReservationStatus::Active
            })
            .ok_or(StateMachineError::LeafRecoveryNotFound)?;
        reservation.status = ReservationStatus::Released;
        reservation.terminal = Some(WorkTerminalEvidence::DeviceRevocation(evidence.clone()));
    }
    for welcome in state.welcomes.iter_mut().filter(|welcome| {
        welcome.recipient == evidence.target && welcome.status == WelcomeStatus::Pending
    }) {
        if evidence.accepted_at >= welcome.expires_at {
            welcome.status = WelcomeStatus::Expired;
            welcome.terminal = Some(WorkTerminalEvidence::Expiry(welcome.expires_at));
        } else {
            welcome.status = WelcomeStatus::Superseded;
            welcome.terminal = Some(WorkTerminalEvidence::DeviceRevocation(evidence.clone()));
        }
    }
    // Device authentication revocation is immediate authority/delivery state,
    // but it never fabricates an MLS Remove or closes an application interval.
    debug_assert_eq!(state.leaves, prior.leaves);
    debug_assert_eq!(state.intervals, prior.intervals);
    validate_state(&state)?;
    Ok(PlannedTransition {
        expected_prior: Some(prior.coordinate),
        retired_coordinate: None,
        successor_coordinate: Some(prior.coordinate),
        effects: complete_effects(
            TransitionEffects::new(PlanKind::DeviceRevocation),
            Some(prior),
            &state,
        ),
        state,
    })
}

pub(crate) struct LeafRecoveryFulfillment {
    pub(crate) actor: DeviceIdentity,
    pub(crate) target: DeviceIdentity,
    pub(crate) recovery_request_id: [u8; 16],
    pub(crate) welcome_id: [u8; 16],
    pub(crate) transition: TransitionEvidence,
    pub(crate) commit: VerifiedCommitPublicState,
    pub(crate) welcome: VerifiedRecoveryWelcome,
}

pub(crate) fn plan_leaf_recovery_fulfillment_inner(
    prior: &ConversationState,
    command: LeafRecoveryFulfillment,
) -> Result<PlannedTransition, StateMachineError> {
    ensure_active(prior)?;
    require_transition_kind(
        &command.transition,
        SignedMutationKind::LeafRecoveryFulfillment,
    )?;
    require_transition_actor(&command.transition, &command.actor)?;
    if !is_uuid_v4(&command.welcome_id) {
        return Err(StateMachineError::InvalidTransition);
    }
    if command.commit.prior_coordinate() != &prior.coordinate {
        return Err(StateMachineError::StaleCoordinates);
    }
    require_commit_body(
        &command.transition,
        SignedMutationKind::LeafRecoveryFulfillment,
        prior,
        &command.commit,
        Some(&command.recovery_request_id),
    )?;
    let request = prior
        .recovery_request(&command.recovery_request_id)
        .ok_or(StateMachineError::LeafRecoveryNotFound)?;
    if request.status != RecoveryRequestStatus::Open {
        return Err(StateMachineError::LeafRecoveryNotFound);
    }
    if request.bound_coordinate != prior.coordinate {
        return Err(StateMachineError::LeafRecoverySuperseded);
    }
    if command.transition.received_at >= request.expires_at {
        return Err(StateMachineError::WorkExpired);
    }
    let reservation = prior
        .recovery_reservation(&command.recovery_request_id)
        .filter(|reservation| reservation.status == ReservationStatus::Active)
        .ok_or(StateMachineError::LeafRecoveryNotFound)?;
    if reservation.bound_coordinate != request.bound_coordinate
        || reservation.target != request.target
        || reservation.key_package_ref != request.key_package_ref
        || reservation.expires_at != request.expires_at
        || reservation.package_not_after <= command.transition.received_at
    {
        return Err(StateMachineError::LeafRecoverySuperseded);
    }
    require_commit_manifest(
        prior,
        &command.transition,
        &command.commit,
        CommitManifestForm::Recovery {
            target: &command.target,
            recovery_request_id: &command.recovery_request_id,
            key_package_ref: &request.key_package_ref,
            welcome_id: &command.welcome_id,
            welcome: &command.welcome,
        },
    )?;
    if request.target != command.target {
        return Err(StateMachineError::RecoveryDeviceMismatch);
    }
    if prior.leaf(&command.actor).is_none() || command.actor == command.target {
        return Err(StateMachineError::InvalidCommitEffects);
    }
    let target_participant = prior
        .participant(command.target.principal())
        .ok_or(StateMachineError::NotParticipant)?;
    if !target_participant.is_active() {
        return Err(StateMachineError::NotMember);
    }
    let [add] = command.commit.adds() else {
        return Err(StateMachineError::InvalidCommitEffects);
    };
    if add.basic_credential() != command.target.basic_credential()
        || add.key_package_ref() != &request.key_package_ref
        || command.welcome.key_package_ref() != &request.key_package_ref
    {
        return Err(StateMachineError::InvalidWelcomeMapping);
    }
    match request.kind {
        LeafRecoveryKind::Add => {
            if prior.leaf(&command.target).is_some() || !command.commit.removes().is_empty() {
                return Err(StateMachineError::InvalidCommitEffects);
            }
        }
        LeafRecoveryKind::Replace => {
            let [removed] = command.commit.removes() else {
                return Err(StateMachineError::InvalidCommitEffects);
            };
            let existing = prior
                .leaf(&command.target)
                .ok_or(StateMachineError::RecoveryKindMismatch)?;
            if removed.leaf_index() != existing.leaf_index
                || removed.basic_credential() != existing.basic_credential
                || removed.signature_key() != existing.signature_key
            {
                return Err(StateMachineError::InvalidCommitEffects);
            }
        }
    }
    verify_commit_actor(prior, &command.actor, &command.commit)?;
    let welcome_bytes = command.welcome.wire_bytes().to_vec();
    let welcome_sha256: [u8; 32] = Sha256::digest(&welcome_bytes).into();
    let welcome_expires_at = reservation.package_not_after;

    let mut state = prior.clone();
    let mut effects = TransitionEffects::new(PlanKind::Commit);
    if request.kind == LeafRecoveryKind::Replace {
        close_open_interval(
            &mut state.intervals,
            &command.target,
            &command.transition,
            CloseKind::Replace,
        )?;
        effects.closed_intervals.push(command.target.clone());
    }
    state.leaves = materialize_next_leaves(prior, &command.commit, Some(&command.target))?;
    open_interval(
        &mut state.intervals,
        command.target.clone(),
        command.transition.clone(),
        OpeningKind::Add,
        *command.commit.next().coordinate(),
    )?;
    effects.opened_intervals.push(command.target);
    effects.superseded_recovery_requests = state
        .recovery_requests
        .iter()
        .filter(|pending| {
            pending.status == RecoveryRequestStatus::Open
                && pending.request_id != command.recovery_request_id
        })
        .map(|request| request.request_id)
        .collect();
    resolve_prior_bound_work(
        &mut state,
        &prior.coordinate,
        &command.transition,
        Some(command.recovery_request_id),
        None,
        None,
    );
    state.coordinate = *command.commit.next().coordinate();
    state.producer = command.transition.clone();
    state.metadata = transition_metadata(&command.transition).cloned();
    state.metadata_producer = state.metadata.as_ref().map(|_| command.transition.clone());
    state.public_state = Some(command.commit.into_next());
    state.welcomes.push(WelcomeWork {
        welcome_id: command.welcome_id,
        recipient: request.target.clone(),
        transition_seq: command.transition.seq,
        coordinate: state.coordinate,
        recovery_request_id: command.recovery_request_id,
        key_package_ref: request.key_package_ref,
        opaque_welcome: welcome_bytes,
        sha256: welcome_sha256,
        expires_at: welcome_expires_at,
        status: WelcomeStatus::Pending,
        terminal: None,
    });
    state
        .welcomes
        .sort_by(|left, right| left.welcome_id.cmp(&right.welcome_id));
    sort_intervals(&mut state.intervals);
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

pub(crate) struct CommitCommand {
    pub(crate) actor: DeviceIdentity,
    pub(crate) transition: TransitionEvidence,
    pub(crate) commit: VerifiedCommitPublicState,
}

/// Plan a generic Commit. Adds are forbidden here; removals and the mandatory
/// sender update must exactly equal the verified public MLS effects.
pub(in crate::chat_protocol::state_machine) fn plan_commit_inner(
    prior: &ConversationState,
    command: CommitCommand,
) -> Result<PlannedTransition, StateMachineError> {
    ensure_active(prior)?;
    require_transition_kind(&command.transition, SignedMutationKind::CommitTransition)?;
    require_transition_actor(&command.transition, &command.actor)?;
    if command.commit.prior_coordinate() != &prior.coordinate {
        return Err(StateMachineError::StaleCoordinates);
    }
    require_commit_body(
        &command.transition,
        SignedMutationKind::CommitTransition,
        prior,
        &command.commit,
        None,
    )?;
    if !command.commit.adds().is_empty() {
        return Err(StateMachineError::InvalidCommitEffects);
    }
    require_commit_manifest(
        prior,
        &command.transition,
        &command.commit,
        CommitManifestForm::Generic,
    )?;
    verify_commit_actor(prior, &command.actor, &command.commit)?;
    for removed in command.commit.removes() {
        let leaf = prior
            .leaves
            .iter()
            .find(|leaf| leaf.leaf_index == removed.leaf_index())
            .ok_or(StateMachineError::InvalidCommitEffects)?;
        if leaf.device == command.actor
            || leaf.basic_credential != removed.basic_credential()
            || leaf.signature_key != removed.signature_key()
        {
            return Err(StateMachineError::InvalidCommitEffects);
        }
        if leaf.device.principal() != command.actor.principal() {
            let actor = prior
                .participant(command.actor.principal())
                .ok_or(StateMachineError::NotParticipant)?;
            if actor.status != ParticipantStatus::Active || actor.role != ParticipantRole::Admin {
                return Err(StateMachineError::AdminRequired);
            }
        }
    }

    let mut state = prior.clone();
    let removed_devices = command
        .commit
        .removes()
        .iter()
        .filter_map(|removed| {
            prior
                .leaves
                .iter()
                .find(|leaf| leaf.leaf_index == removed.leaf_index())
                .map(|leaf| leaf.device.clone())
        })
        .collect::<Vec<_>>();
    for device in &removed_devices {
        close_open_interval(
            &mut state.intervals,
            device,
            &command.transition,
            CloseKind::Remove,
        )?;
    }
    state.leaves = materialize_next_leaves(prior, &command.commit, None)?;
    if state.leaves.is_empty() {
        return Err(StateMachineError::InvariantViolation);
    }
    let mut effects = TransitionEffects::new(PlanKind::Commit);
    effects.closed_intervals = removed_devices;
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

pub(in crate::chat_protocol::state_machine) fn verify_commit_actor(
    prior: &ConversationState,
    actor: &DeviceIdentity,
    commit: &VerifiedCommitPublicState,
) -> Result<(), StateMachineError> {
    let actor_leaf = prior
        .leaf(actor)
        .ok_or(StateMachineError::InvalidCommitEffects)?;
    let sender = commit.sender_update();
    if sender.leaf_index() != actor_leaf.leaf_index
        || sender.basic_credential() != actor_leaf.basic_credential
        || sender.signature_key() != actor_leaf.signature_key
        || sender.prior_encryption_key() != actor_leaf.encryption_key
    {
        return Err(StateMachineError::InvalidCommitEffects);
    }
    Ok(())
}

pub(in crate::chat_protocol::state_machine) fn materialize_next_leaves(
    prior: &ConversationState,
    commit: &VerifiedCommitPublicState,
    added_target: Option<&DeviceIdentity>,
) -> Result<Vec<LeafRecord>, StateMachineError> {
    let removed_indices = commit
        .removes()
        .iter()
        .map(|remove| remove.leaf_index())
        .collect::<BTreeSet<_>>();
    let sender_index = commit.sender_update().leaf_index();
    let mut expected = prior
        .leaves
        .iter()
        .filter(|leaf| !removed_indices.contains(&leaf.leaf_index))
        .cloned()
        .collect::<Vec<_>>();
    for leaf in &mut expected {
        if leaf.leaf_index == sender_index {
            leaf.encryption_key = commit.sender_update().next_encryption_key().to_vec();
        }
    }
    if let Some(target) = added_target {
        let [add] = commit.adds() else {
            return Err(StateMachineError::InvalidCommitEffects);
        };
        expected.push(LeafRecord {
            device: target.clone(),
            leaf_index: add.leaf_index(),
            basic_credential: add.basic_credential().to_vec(),
            signature_key: add.signature_key().to_vec(),
            encryption_key: add.encryption_key().to_vec(),
            key_package_ref: Some(*add.key_package_ref()),
        });
    } else if !commit.adds().is_empty() {
        return Err(StateMachineError::InvalidCommitEffects);
    }
    expected.sort_by_key(|leaf| leaf.leaf_index);

    let summary = commit.next().binding().tree_summary().leaves();
    if expected.len() != summary.len()
        || !expected.iter().zip(summary).all(|(expected, actual)| {
            expected.leaf_index == actual.leaf_index()
                && expected.basic_credential == actual.basic_credential()
                && expected.signature_key == actual.signature_key()
                && expected.encryption_key == actual.encryption_key()
        })
    {
        return Err(StateMachineError::InvalidCommitEffects);
    }
    Ok(expected)
}

pub(crate) struct ResetRequestCommand {
    pub(crate) actor: DeviceIdentity,
    pub(crate) reset_request_id: [u8; 16],
    pub(crate) received_at: ServerTimestamp,
    pub(crate) evidence: RequestEvidence,
}

pub(in crate::chat_protocol::state_machine) fn plan_reset_request_inner(
    prior: &ConversationState,
    command: ResetRequestCommand,
) -> Result<PlannedTransition, StateMachineError> {
    ensure_active(prior)?;
    validate_request_evidence(
        &command.evidence,
        RequestEntryKind::ResetRequest,
        prior.coordinate.conversation_id(),
        &command.reset_request_id,
        &command.actor,
        command.received_at,
    )?;
    require_request_prior(&command.evidence, &prior.coordinate)?;
    if !is_uuid_v4(&command.reset_request_id) {
        return Err(StateMachineError::InvalidTransition);
    }
    let participant = prior
        .participant(command.actor.principal())
        .ok_or(StateMachineError::NotParticipant)?;
    if !participant.is_active() {
        return Err(StateMachineError::NotMember);
    }
    if prior.kind == ConversationKind::Group && participant.role != ParticipantRole::Admin {
        return Err(StateMachineError::AdminRequired);
    }
    if prior
        .reset_requests
        .iter()
        .any(|request| request.status == ResetRequestStatus::Pending)
    {
        return Err(StateMachineError::ResetAlreadyPending);
    }
    let expires_at = command.received_at.checked_add_millis(CONSENT_TTL_MILLIS)?;
    let mut state = prior.clone();
    state.reset_requests.push(ResetRequest {
        request_id: command.reset_request_id,
        requester: command.actor,
        bound_coordinate: prior.coordinate,
        received_at: command.received_at,
        expires_at,
        status: ResetRequestStatus::Pending,
        origin: command.evidence,
        terminal: None,
    });
    sort_reset_requests(&mut state.reset_requests);
    validate_state(&state)?;
    Ok(PlannedTransition {
        expected_prior: Some(prior.coordinate),
        retired_coordinate: None,
        successor_coordinate: Some(prior.coordinate),
        effects: complete_effects(
            TransitionEffects::new(PlanKind::ResetRequest),
            Some(prior),
            &state,
        ),
        state,
    })
}

pub(crate) struct ResetActivation {
    pub(crate) actor: DeviceIdentity,
    pub(crate) reset_request_id: [u8; 16],
    pub(crate) transition: TransitionEvidence,
    pub(crate) successor_public_state: ActivePublicState,
}

pub(in crate::chat_protocol::state_machine) fn plan_reset_activation_inner(
    prior: &ConversationState,
    command: ResetActivation,
) -> Result<PlannedTransition, StateMachineError> {
    ensure_active(prior)?;
    require_transition_kind(&command.transition, SignedMutationKind::ResetActivation)?;
    require_transition_actor(&command.transition, &command.actor)?;
    let request = prior
        .reset_requests
        .iter()
        .find(|request| {
            request.request_id == command.reset_request_id
                && request.status == ResetRequestStatus::Pending
        })
        .ok_or(StateMachineError::ResetRequestNotFound)?;
    if request.bound_coordinate != prior.coordinate {
        return Err(StateMachineError::ResetRequestStale);
    }
    if command.transition.received_at >= request.expires_at {
        return Err(StateMachineError::WorkExpired);
    }
    let actor = prior
        .participant(command.actor.principal())
        .ok_or(StateMachineError::NotParticipant)?;
    if actor.status != ParticipantStatus::Active || actor.role != ParticipantRole::Admin {
        return Err(StateMachineError::AdminRequired);
    }
    let retired = retired_coordinate(&prior.coordinate)?;
    let successor = *command.successor_public_state.coordinate();
    let expected_generation = prior
        .coordinate
        .generation()
        .checked_add(1)
        .filter(|value| *value <= MAX_PROTOCOL_INTEGER)
        .ok_or(StateMachineError::CoordinateOverflow)?;
    if successor.conversation_id() != prior.coordinate.conversation_id()
        || successor.generation() != expected_generation
        || successor.state_version() != 0
        || successor.epoch() != 0
        || successor.lifecycle() != PublicGroupSnapshotLifecycle::Active
        || successor.group_id() == prior.coordinate.group_id()
    {
        return Err(StateMachineError::ResetSuccessorMismatch);
    }
    require_reset_activation_body(
        &command.transition,
        &command.reset_request_id,
        prior,
        &retired,
        &command.actor,
        &command.successor_public_state,
    )?;
    let actor_leaf = singleton_genesis_leaf(&command.successor_public_state, &command.actor)
        .map_err(|_| StateMachineError::ResetSuccessorMismatch)?;

    let mut state = prior.clone();
    let mut effects = TransitionEffects::new(PlanKind::ResetActivation);
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
            CloseKind::Reset,
        )?;
    }
    effects.closed_intervals = open_devices;
    open_interval(
        &mut state.intervals,
        command.actor.clone(),
        command.transition.clone(),
        OpeningKind::Reset,
        successor,
    )?;
    effects.opened_intervals.push(command.actor);
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
        Some(command.reset_request_id),
        None,
    );
    state.coordinate = successor;
    state.producer = command.transition.clone();
    state.metadata = transition_metadata(&command.transition).cloned();
    state.metadata_producer = state.metadata.as_ref().map(|_| command.transition.clone());
    state.public_state = Some(command.successor_public_state);
    state.leaves = vec![actor_leaf];
    sort_intervals(&mut state.intervals);
    validate_state(&state)?;
    effects.complete(Some(prior), &state);
    Ok(PlannedTransition {
        expected_prior: Some(prior.coordinate),
        retired_coordinate: Some(retired),
        successor_coordinate: Some(successor),
        state,
        effects,
    })
}

pub(crate) struct ZeroLeafLeave {
    pub(crate) actor: DeviceIdentity,
    pub(crate) transition: TransitionEvidence,
}

pub(in crate::chat_protocol::state_machine) fn plan_zero_leaf_leave_inner(
    prior: &ConversationState,
    command: ZeroLeafLeave,
) -> Result<PlannedTransition, StateMachineError> {
    ensure_active(prior)?;
    require_transition_kind(&command.transition, SignedMutationKind::ZeroLeafLeave)?;
    require_transition_actor(&command.transition, &command.actor)?;
    if prior.kind == ConversationKind::Direct {
        return Err(StateMachineError::DirectParticipantMutationForbidden);
    }
    let participant_index = prior
        .participants
        .binary_search_by(|participant| participant.principal.cmp(command.actor.principal()))
        .map_err(|_| StateMachineError::NotParticipant)?;
    if prior
        .leaves
        .iter()
        .any(|leaf| leaf.device.principal() == command.actor.principal())
    {
        return Err(StateMachineError::InvariantViolation);
    }
    if would_remove_last_active_admin(prior, command.actor.principal()) {
        return Err(StateMachineError::LastAdminRequired);
    }
    let next_coordinate = coordinate_only_successor(&prior.coordinate)?;
    require_coordinate_only_body(
        &command.transition,
        SignedMutationKind::ZeroLeafLeave,
        prior.kind,
        &prior.coordinate,
        &next_coordinate,
    )?;
    let public_state = rebind_active_snapshot(prior.public_state(), next_coordinate)?;
    let mut state = prior.clone();
    resolve_prior_bound_work(
        &mut state,
        &prior.coordinate,
        &command.transition,
        None,
        None,
        None,
    );
    state.participants.remove(participant_index);
    state.coordinate = next_coordinate;
    state.producer = command.transition.clone();
    state.public_state = Some(public_state);
    validate_state(&state)?;
    Ok(PlannedTransition {
        expected_prior: Some(prior.coordinate),
        retired_coordinate: None,
        successor_coordinate: Some(next_coordinate),
        effects: complete_effects(
            TransitionEffects::new(PlanKind::ZeroLeafLeave),
            Some(prior),
            &state,
        ),
        state,
    })
}

pub(crate) struct LeaveRequestCommand {
    pub(crate) actor: DeviceIdentity,
    pub(crate) leave_request_id: [u8; 16],
    pub(crate) received_at: ServerTimestamp,
    pub(crate) evidence: RequestEvidence,
    pub(crate) registration: LockedRegistrationProjection,
}

pub(in crate::chat_protocol::state_machine) fn plan_leave_request_inner(
    prior: &ConversationState,
    command: LeaveRequestCommand,
) -> Result<PlannedTransition, StateMachineError> {
    ensure_active(prior)?;
    validate_request_evidence(
        &command.evidence,
        RequestEntryKind::LeaveRequest,
        prior.coordinate.conversation_id(),
        &command.leave_request_id,
        &command.actor,
        command.received_at,
    )?;
    require_request_prior(&command.evidence, &prior.coordinate)?;
    if !command.registration.authorizes(&command.evidence) {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    if prior.kind == ConversationKind::Direct {
        return Err(StateMachineError::DirectParticipantMutationForbidden);
    }
    if !is_uuid_v4(&command.leave_request_id) {
        return Err(StateMachineError::InvalidTransition);
    }
    let participant = prior
        .participant(command.actor.principal())
        .ok_or(StateMachineError::NotParticipant)?;
    if !participant.is_active()
        || !prior
            .leaves
            .iter()
            .any(|leaf| leaf.device.principal() == command.actor.principal())
    {
        return Err(StateMachineError::NotMember);
    }
    if would_remove_last_active_admin(prior, command.actor.principal()) {
        return Err(StateMachineError::LastAdminRequired);
    }
    // Expire-first: a lapsed pending request is dead consent that no longer
    // authorizes a `leaveCommit`, but `leave_requests_one_pending_uq` and the
    // `LeaveAlreadyPending` guard below still see it as pending. Observing its
    // own deadline here — before the guard reads the aggregate — is what keeps a
    // requester from being trapped behind his own lapsed request.
    let mut state = prior.clone();
    expire_due_leave_requests(&mut state, command.received_at);
    if state.leave_requests.iter().any(|request| {
        request.requester.principal() == command.actor.principal()
            && request.status == LeaveRequestStatus::Pending
    }) {
        return Err(StateMachineError::LeaveAlreadyPending);
    }
    let expires_at = command.received_at.checked_add_millis(CONSENT_TTL_MILLIS)?;
    state.leave_requests.push(LeaveRequest {
        request_id: command.leave_request_id,
        requester: command.actor,
        bound_coordinate: prior.coordinate,
        received_at: command.received_at,
        expires_at,
        status: LeaveRequestStatus::Pending,
        origin: command.evidence,
        terminal: None,
        fulfilled_participant: None,
    });
    sort_leave_requests(&mut state.leave_requests);
    validate_state(&state)?;
    Ok(PlannedTransition {
        expected_prior: Some(prior.coordinate),
        retired_coordinate: None,
        successor_coordinate: Some(prior.coordinate),
        effects: complete_effects(
            TransitionEffects::new(PlanKind::LeaveRequest),
            Some(prior),
            &state,
        ),
        state,
    })
}

pub(crate) struct LeaveCancellation {
    pub(crate) actor: DeviceIdentity,
    pub(crate) leave_request_id: [u8; 16],
    pub(crate) received_at: ServerTimestamp,
    pub(crate) evidence: RequestEvidence,
    pub(crate) registration: LockedRegistrationProjection,
}

pub(in crate::chat_protocol::state_machine) fn plan_leave_cancellation_inner(
    prior: &ConversationState,
    command: LeaveCancellation,
) -> Result<PlannedTransition, StateMachineError> {
    ensure_active(prior)?;
    validate_request_evidence(
        &command.evidence,
        RequestEntryKind::LeaveCancellation,
        prior.coordinate.conversation_id(),
        &command.leave_request_id,
        &command.actor,
        command.received_at,
    )?;
    require_request_coordinate_binding(&command.evidence, prior.coordinate.conversation_id())?;
    if !command.registration.authorizes(&command.evidence) {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    let index = prior
        .leave_requests
        .iter()
        .position(|request| {
            request.request_id == command.leave_request_id
                && request.status == LeaveRequestStatus::Pending
        })
        .ok_or(StateMachineError::LeaveRequestNotFound)?;
    let request = &prior.leave_requests[index];
    if request.requester.principal() != command.actor.principal()
        || request.bound_coordinate != prior.coordinate
    {
        return Err(StateMachineError::LeaveRequestNotFound);
    }
    if command.received_at >= request.expires_at {
        return Err(StateMachineError::WorkExpired);
    }
    let Some(cancellation_seq) = command.evidence.control_seq else {
        return Err(StateMachineError::InvalidTransition);
    };
    let Some(origin_seq) = request.origin.control_seq else {
        return Err(StateMachineError::InvariantViolation);
    };
    if cancellation_seq <= origin_seq
        || command.evidence.control_entry_id == request.origin.control_entry_id
    {
        return Err(StateMachineError::InvalidTransition);
    }
    let mut state = prior.clone();
    state.leave_requests[index].status = LeaveRequestStatus::Cancelled;
    state.leave_requests[index].terminal = Some(WorkTerminalEvidence::Request(command.evidence));
    validate_state(&state)?;
    Ok(PlannedTransition {
        expected_prior: Some(prior.coordinate),
        retired_coordinate: None,
        successor_coordinate: Some(prior.coordinate),
        effects: complete_effects(
            TransitionEffects::new(PlanKind::LeaveCancellation),
            Some(prior),
            &state,
        ),
        state,
    })
}

pub(crate) struct LeaveFulfillment {
    pub(crate) actor: DeviceIdentity,
    pub(crate) requester: PrincipalId,
    pub(crate) leave_request_id: [u8; 16],
    pub(crate) transition: TransitionEvidence,
    pub(crate) commit: VerifiedCommitPublicState,
}
