#![allow(unused_imports)]
use super::*;

pub(crate) fn plan_policy_transition(
    prior: &ConversationState,
    command: PolicyCommand,
) -> Result<PlannedTransition, StateMachineError> {
    ensure_active(prior)?;
    require_transition_kind(&command.transition, SignedMutationKind::PolicyTransition)?;
    require_transition_actor(&command.transition, &command.actor)?;
    if prior.kind != ConversationKind::Group {
        return Err(StateMachineError::DirectParticipantMutationForbidden);
    }
    let actor = prior
        .participant(command.actor.principal())
        .ok_or(StateMachineError::NotParticipant)?;
    if actor.status != ParticipantStatus::Active || actor.role != ParticipantRole::Admin {
        return Err(StateMachineError::AdminRequired);
    }
    let next_coordinate = coordinate_only_successor(&prior.coordinate)?;
    let changes = match command.transition.body_binding.as_ref() {
        Some(TransitionBodyBinding::Policy {
            prior: signed_prior,
            next: signed_next,
            participant_changes,
        }) if signed_prior == &prior.coordinate && signed_next == &next_coordinate => {
            participant_changes.clone()
        }
        _ => return Err(StateMachineError::InvalidTransition),
    };

    let mut state = prior.clone();
    for change in changes {
        match change {
            ManifestParticipantChange::Add(principal) => {
                if state.participant(&principal).is_some()
                    || state.participants.len() >= MAX_PARTICIPANTS
                {
                    return Err(StateMachineError::InvariantViolation);
                }
                state.participants.push(ParticipantRecord {
                    principal,
                    status: ParticipantStatus::Pending,
                    role: ParticipantRole::Member,
                    role_producer: None,
                    invitation: Some(InvitationProvenance {
                        transition: command.transition.clone(),
                        inviter: command.actor.clone(),
                    }),
                    acceptance: None,
                });
                state
                    .participants
                    .sort_by(|left, right| left.principal.cmp(&right.principal));
            }
            ManifestParticipantChange::Remove(principal) => {
                if principal == *command.actor.principal()
                    || state
                        .leaves
                        .iter()
                        .any(|leaf| leaf.device.principal() == &principal)
                    || would_remove_last_active_admin(&state, &principal)
                {
                    return Err(StateMachineError::InvalidPolicyAuthority);
                }
                let index = state
                    .participants
                    .binary_search_by(|participant| participant.principal.cmp(&principal))
                    .map_err(|_| StateMachineError::NotParticipant)?;
                state.participants.remove(index);
            }
            ManifestParticipantChange::ChangeRole(principal, role) => {
                let index = state
                    .participants
                    .binary_search_by(|participant| participant.principal.cmp(&principal))
                    .map_err(|_| StateMachineError::NotParticipant)?;
                if state.participants[index].status != ParticipantStatus::Active
                    || (state.participants[index].role == ParticipantRole::Admin
                        && role == ParticipantRole::Member
                        && would_remove_last_active_admin(&state, &principal))
                {
                    return Err(StateMachineError::LastAdminRequired);
                }
                state.participants[index].role = role;
                state.participants[index].role_producer = Some(command.transition.clone());
            }
        }
    }
    resolve_prior_bound_work(
        &mut state,
        &prior.coordinate,
        &command.transition,
        None,
        None,
        None,
    );
    state.coordinate = next_coordinate;
    state.producer = command.transition.clone();
    state.public_state = Some(rebind_active_snapshot(
        prior.public_state(),
        next_coordinate,
    )?);
    validate_state(&state)?;
    let mut effects = TransitionEffects::new(PlanKind::Policy);
    effects.policy_evidence_digest = Some(command.relationship_evidence_digest);
    effects.complete(Some(prior), &state);
    Ok(PlannedTransition {
        expected_prior: Some(prior.coordinate),
        retired_coordinate: None,
        successor_coordinate: Some(next_coordinate),
        state,
        effects,
    })
}

pub(crate) struct AcceptConversation {
    pub(crate) actor: DeviceIdentity,
    pub(crate) transition: TransitionEvidence,
    pub(crate) recovery_request_id: [u8; 16],
    pub(crate) key_package_ref: [u8; 32],
    pub(crate) package_not_after: ServerTimestamp,
}

pub(crate) fn plan_accept_conversation_inner(
    prior: &ConversationState,
    command: AcceptConversation,
) -> Result<PlannedTransition, StateMachineError> {
    ensure_active(prior)?;
    require_transition_kind(
        &command.transition,
        SignedMutationKind::ParticipantAcceptance,
    )?;
    require_transition_actor(&command.transition, &command.actor)?;
    if !is_uuid_v4(&command.recovery_request_id) {
        return Err(StateMachineError::InvalidTransition);
    }
    let participant_index = prior
        .participants
        .binary_search_by(|participant| participant.principal.cmp(command.actor.principal()))
        .map_err(|_| StateMachineError::NotParticipant)?;
    if prior.participants[participant_index].status != ParticipantStatus::Pending {
        return Err(StateMachineError::InvitationNotPending);
    }
    if prior.recovery_requests.iter().any(|request| {
        request.target == command.actor && request.status == RecoveryRequestStatus::Open
    }) {
        return Err(StateMachineError::LeafRecoveryAlreadyOpen);
    }

    let received_at = command.transition.received_at;
    let expires_at = recovery_expiry(received_at, command.package_not_after)?;
    let next_coordinate = coordinate_only_successor(&prior.coordinate)?;
    require_acceptance_body(
        &command.transition,
        &prior.coordinate,
        &next_coordinate,
        &command.recovery_request_id,
        &command.actor,
        prior.participants[participant_index].invitation.as_ref(),
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
    state.coordinate = next_coordinate;
    state.producer = command.transition.clone();
    state.public_state = Some(public_state);
    state.participants[participant_index].status = ParticipantStatus::Active;
    state.participants[participant_index].acceptance = Some(command.transition.clone());
    state.recovery_requests.push(RecoveryRequest {
        request_id: command.recovery_request_id,
        target: command.actor.clone(),
        kind: LeafRecoveryKind::Add,
        source: RecoverySource::Acceptance,
        bound_coordinate: next_coordinate,
        key_package_ref: command.key_package_ref,
        received_at,
        expires_at,
        status: RecoveryRequestStatus::Open,
        origin: RecoveryOriginEvidence::Acceptance(command.transition.clone()),
        terminal: None,
    });
    state.recovery_reservations.push(RecoveryReservation {
        request_id: command.recovery_request_id,
        target: command.actor,
        bound_coordinate: next_coordinate,
        key_package_ref: command.key_package_ref,
        received_at,
        expires_at,
        package_not_after: command.package_not_after,
        status: ReservationStatus::Active,
        terminal: None,
    });
    sort_recovery_requests(&mut state.recovery_requests);
    sort_recovery_reservations(&mut state.recovery_reservations);
    validate_state(&state)?;
    let effects = complete_effects(
        TransitionEffects::new(PlanKind::Acceptance),
        Some(prior),
        &state,
    );
    Ok(PlannedTransition {
        expected_prior: Some(prior.coordinate),
        retired_coordinate: None,
        successor_coordinate: Some(next_coordinate),
        effects,
        state,
    })
}

pub(crate) struct MetadataCommand {
    pub(crate) actor: DeviceIdentity,
    pub(crate) transition: TransitionEvidence,
    pub(crate) registration: LockedRegistrationProjection,
}

pub(in crate::chat_protocol::state_machine) fn plan_metadata_inner(
    prior: &ConversationState,
    command: MetadataCommand,
) -> Result<PlannedTransition, StateMachineError> {
    ensure_active(prior)?;
    require_transition_kind(&command.transition, SignedMutationKind::MetadataTransition)?;
    require_transition_actor(&command.transition, &command.actor)?;
    if !command
        .registration
        .authorizes_transition(&command.transition)
    {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    let participant = prior
        .participant(command.actor.principal())
        .ok_or(StateMachineError::NotParticipant)?;
    if participant.status != ParticipantStatus::Active || participant.role != ParticipantRole::Admin
    {
        return Err(StateMachineError::AdminRequired);
    }
    let next_coordinate = coordinate_only_successor(&prior.coordinate)?;
    let metadata = require_metadata_body(prior, &command.transition, &next_coordinate)?.clone();
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
    state.coordinate = next_coordinate;
    state.producer = command.transition.clone();
    state.public_state = Some(public_state);
    state.metadata = Some(metadata);
    state.metadata_producer = Some(command.transition.clone());
    validate_state(&state)?;
    Ok(PlannedTransition {
        expected_prior: Some(prior.coordinate),
        retired_coordinate: None,
        successor_coordinate: Some(next_coordinate),
        effects: complete_effects(
            TransitionEffects::new(PlanKind::Metadata),
            Some(prior),
            &state,
        ),
        state,
    })
}

pub(crate) struct LeafRecoveryRequestCommand {
    pub(crate) actor: DeviceIdentity,
    pub(crate) recovery_request_id: [u8; 16],
    pub(crate) kind: LeafRecoveryKind,
    pub(crate) key_package_ref: [u8; 32],
    pub(crate) received_at: ServerTimestamp,
    pub(crate) package_not_after: ServerTimestamp,
    pub(crate) evidence: RequestEvidence,
    #[cfg(not(test))]
    pub(crate) registration: LockedRegistrationProjection,
    #[cfg(not(test))]
    pub(crate) reservation: LockedRecoveryReservationProjection,
}

pub(in crate::chat_protocol::state_machine) fn plan_leaf_recovery_request_inner(
    prior: &ConversationState,
    command: LeafRecoveryRequestCommand,
) -> Result<PlannedTransition, StateMachineError> {
    ensure_active(prior)?;
    validate_request_evidence(
        &command.evidence,
        RequestEntryKind::LeafRecoveryRequest,
        prior.coordinate.conversation_id(),
        &command.recovery_request_id,
        &command.actor,
        command.received_at,
    )?;
    require_leaf_recovery_request_binding(&command.evidence, &prior.coordinate, command.kind)?;
    #[cfg(not(test))]
    if !command.registration.authorizes(&command.evidence)
        || !command
            .reservation
            .authorizes_request(&command.evidence, command.kind)
        || command.reservation.request_id != command.recovery_request_id
        || command.reservation.target != command.actor
        || command.reservation.key_package_ref != command.key_package_ref
        || command.reservation.package_not_after != command.package_not_after
    {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    if !is_uuid_v4(&command.recovery_request_id) {
        return Err(StateMachineError::InvalidTransition);
    }
    let participant = prior
        .participant(command.actor.principal())
        .ok_or(StateMachineError::NotParticipant)?;
    if !participant.is_active() {
        return Err(StateMachineError::NotMember);
    }
    if prior.recovery_requests.iter().any(|request| {
        request.target == command.actor && request.status == RecoveryRequestStatus::Open
    }) {
        return Err(StateMachineError::LeafRecoveryAlreadyOpen);
    }
    let has_leaf = prior.leaf(&command.actor).is_some();
    if (command.kind == LeafRecoveryKind::Add && has_leaf)
        || (command.kind == LeafRecoveryKind::Replace && !has_leaf)
    {
        return Err(StateMachineError::RecoveryKindMismatch);
    }
    let expires_at = recovery_expiry(command.received_at, command.package_not_after)?;
    let mut state = prior.clone();
    state.recovery_requests.push(RecoveryRequest {
        request_id: command.recovery_request_id,
        target: command.actor.clone(),
        kind: command.kind,
        source: RecoverySource::Request,
        bound_coordinate: prior.coordinate,
        key_package_ref: command.key_package_ref,
        received_at: command.received_at,
        expires_at,
        status: RecoveryRequestStatus::Open,
        origin: RecoveryOriginEvidence::Request(command.evidence),
        terminal: None,
    });
    state.recovery_reservations.push(RecoveryReservation {
        request_id: command.recovery_request_id,
        target: command.actor,
        bound_coordinate: prior.coordinate,
        key_package_ref: command.key_package_ref,
        received_at: command.received_at,
        expires_at,
        package_not_after: command.package_not_after,
        status: ReservationStatus::Active,
        terminal: None,
    });
    sort_recovery_requests(&mut state.recovery_requests);
    sort_recovery_reservations(&mut state.recovery_reservations);
    validate_state(&state)?;
    let effects = complete_effects(
        TransitionEffects::new(PlanKind::RecoveryRequest),
        Some(prior),
        &state,
    );
    Ok(PlannedTransition {
        expected_prior: Some(prior.coordinate),
        retired_coordinate: None,
        successor_coordinate: Some(prior.coordinate),
        effects,
        state,
    })
}

pub(in crate::chat_protocol::state_machine) fn sort_recovery_requests(
    requests: &mut [RecoveryRequest],
) {
    requests.sort_by(|left, right| {
        left.target
            .cmp(&right.target)
            .then_with(|| left.request_id.cmp(&right.request_id))
    });
}

pub(in crate::chat_protocol::state_machine) fn sort_recovery_reservations(
    reservations: &mut [RecoveryReservation],
) {
    reservations.sort_by(|left, right| {
        left.target
            .cmp(&right.target)
            .then_with(|| left.request_id.cmp(&right.request_id))
    });
}

pub(in crate::chat_protocol::state_machine) fn sort_reset_requests(requests: &mut [ResetRequest]) {
    requests.sort_by_key(|request| request.request_id);
}

pub(in crate::chat_protocol::state_machine) fn sort_leave_requests(requests: &mut [LeaveRequest]) {
    requests.sort_by(|left, right| {
        left.requester
            .cmp(&right.requester)
            .then_with(|| left.request_id.cmp(&right.request_id))
    });
}

pub(in crate::chat_protocol::state_machine) fn recovery_expiry(
    received_at: ServerTimestamp,
    package_not_after: ServerTimestamp,
) -> Result<ServerTimestamp, StateMachineError> {
    if package_not_after <= received_at {
        return Err(StateMachineError::WorkExpired);
    }
    Ok(received_at
        .checked_add_millis(RECOVERY_RESERVATION_TTL_MILLIS)?
        .min(package_not_after))
}

pub(crate) struct LeafRecoveryCancellation {
    pub(crate) actor: DeviceIdentity,
    pub(crate) recovery_request_id: [u8; 16],
    pub(crate) received_at: ServerTimestamp,
    pub(crate) evidence: RequestEvidence,
    #[cfg(not(test))]
    pub(crate) registration: LockedRegistrationProjection,
}

pub(in crate::chat_protocol::state_machine) fn plan_leaf_recovery_cancellation_inner(
    prior: &ConversationState,
    command: LeafRecoveryCancellation,
) -> Result<PlannedTransition, StateMachineError> {
    ensure_active(prior)?;
    validate_request_evidence(
        &command.evidence,
        RequestEntryKind::LeafRecoveryCancellation,
        prior.coordinate.conversation_id(),
        &command.recovery_request_id,
        &command.actor,
        command.received_at,
    )?;
    #[cfg(not(test))]
    if !command.registration.authorizes(&command.evidence) {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    if command
        .evidence
        .body_binding
        .as_ref()
        .is_some_and(|binding| !matches!(binding, RequestBodyBinding::LeafRecoveryCancellation))
    {
        return Err(StateMachineError::InvalidTransition);
    }
    let request = prior
        .recovery_request(&command.recovery_request_id)
        .filter(|request| request.status == RecoveryRequestStatus::Open)
        .ok_or(StateMachineError::LeafRecoveryNotFound)?;
    if request.target != command.actor {
        return Err(StateMachineError::RecoveryDeviceMismatch);
    }
    if request.bound_coordinate != prior.coordinate {
        return Err(StateMachineError::LeafRecoverySuperseded);
    }
    if command.received_at >= request.expires_at {
        return Err(StateMachineError::WorkExpired);
    }
    if command.evidence.received_at <= recovery_origin_received_at(&request.origin)
        || command.evidence.request_digest == recovery_origin_request_digest(&request.origin)
    {
        return Err(StateMachineError::InvalidTransition);
    }
    let reservation = prior
        .recovery_reservation(&command.recovery_request_id)
        .filter(|reservation| reservation.status == ReservationStatus::Active)
        .ok_or(StateMachineError::LeafRecoveryNotFound)?;
    if reservation.target != request.target
        || reservation.bound_coordinate != request.bound_coordinate
        || reservation.key_package_ref != request.key_package_ref
        || reservation.expires_at != request.expires_at
    {
        return Err(StateMachineError::LeafRecoverySuperseded);
    }

    let mut state = prior.clone();
    let evidence = WorkTerminalEvidence::Request(command.evidence);
    let request = state
        .recovery_requests
        .iter_mut()
        .find(|request| request.request_id == command.recovery_request_id)
        .ok_or(StateMachineError::LeafRecoveryNotFound)?;
    request.status = RecoveryRequestStatus::Cancelled;
    request.terminal = Some(evidence.clone());
    let reservation = state
        .recovery_reservations
        .iter_mut()
        .find(|reservation| reservation.request_id == command.recovery_request_id)
        .ok_or(StateMachineError::LeafRecoveryNotFound)?;
    reservation.status = ReservationStatus::Released;
    reservation.terminal = Some(evidence);
    validate_state(&state)?;
    Ok(PlannedTransition {
        expected_prior: Some(prior.coordinate),
        retired_coordinate: None,
        successor_coordinate: Some(prior.coordinate),
        effects: complete_effects(
            TransitionEffects::new(PlanKind::RecoveryCancellation),
            Some(prior),
            &state,
        ),
        state,
    })
}

pub(in crate::chat_protocol::state_machine) fn plan_leaf_recovery_expiry_inner(
    prior: &ConversationState,
    authority: &RecoveryExpiryPlanAuthority,
) -> Result<PlannedTransition, StateMachineError> {
    ensure_active(prior)?;
    if !is_uuid_v4(authority.request_id())
        || authority.observed_at < authority.terminal_at
        || authority.locked_read_set_digest == [0; 32]
    {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    let request = prior
        .recovery_request(authority.request_id())
        .filter(|request| request.status == RecoveryRequestStatus::Open)
        .ok_or(StateMachineError::LeafRecoveryNotFound)?;
    let reservation = prior
        .recovery_reservation(authority.request_id())
        .filter(|reservation| reservation.status == ReservationStatus::Active)
        .ok_or(StateMachineError::LeafRecoveryNotFound)?;
    if request.target != authority.requester
        || request.expires_at != authority.terminal_at
        || reservation.target != request.target
        || reservation.bound_coordinate != request.bound_coordinate
        || reservation.key_package_ref != request.key_package_ref
        || reservation.expires_at != request.expires_at
        || authority.terminal_at > reservation.package_not_after
    {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    let terminal = WorkTerminalEvidence::Expiry(authority.terminal_at);
    let mut state = prior.clone();
    let request = state
        .recovery_requests
        .iter_mut()
        .find(|request| request.request_id == *authority.request_id())
        .ok_or(StateMachineError::LeafRecoveryNotFound)?;
    request.status = RecoveryRequestStatus::Expired;
    request.terminal = Some(terminal.clone());
    let reservation = state
        .recovery_reservations
        .iter_mut()
        .find(|reservation| reservation.request_id == *authority.request_id())
        .ok_or(StateMachineError::LeafRecoveryNotFound)?;
    reservation.status = ReservationStatus::Expired;
    reservation.terminal = Some(terminal);
    validate_state(&state)?;
    Ok(PlannedTransition {
        expected_prior: Some(prior.coordinate),
        retired_coordinate: None,
        successor_coordinate: Some(prior.coordinate),
        effects: complete_effects(
            TransitionEffects::new(PlanKind::RecoveryExpiry),
            Some(prior),
            &state,
        ),
        state,
    })
}

pub(in crate::chat_protocol::state_machine) fn recovery_expiry_plan_authority(
    package: &LockedRecoveryPackageGuard,
    request_id: Uuid,
    terminal_at: chrono::DateTime<chrono::Utc>,
    observed_at: chrono::DateTime<chrono::Utc>,
    locked_read_set_digest: [u8; 32],
) -> Result<RecoveryExpiryPlanAuthority, StateMachineError> {
    let did = BareDid::parse(package.target_did())
        .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
    let requester = DeviceIdentity::new(
        PrincipalId::new(did.as_str().as_bytes().to_vec())?,
        *package.target_device_id().as_bytes(),
    )?;
    if package.request_id() != request_id
        || package.conversation_id().as_bytes() != package.bound_coordinate().conversation_id()
        || package.status() != LockedRecoveryPackageStatus::Reserved
        || package.use_kind() != LockedRecoveryPackageUse::ReservedFulfillment
        || locked_read_set_digest == [0; 32]
    {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    Ok(RecoveryExpiryPlanAuthority {
        request_id: *request_id.as_bytes(),
        requester,
        terminal_at: ServerTimestamp::from_unix_millis(terminal_at.timestamp_millis())?,
        observed_at: ServerTimestamp::from_unix_millis(observed_at.timestamp_millis())?,
        locked_read_set_digest,
    })
}

pub(in crate::chat_protocol::state_machine) fn plan_welcome_response(
    prior: &ConversationState,
    evidence: RequestEvidence,
    successor_status: WelcomeStatus,
) -> Result<PlannedTransition, StateMachineError> {
    ensure_active(prior)?;
    let expected_kind = match successor_status {
        WelcomeStatus::Acknowledged => RequestEntryKind::WelcomeAcknowledgement,
        WelcomeStatus::Rejected => RequestEntryKind::WelcomeRejection,
        _ => return Err(StateMachineError::InvalidHydrationAuthority),
    };
    let welcome = prior
        .welcome(&evidence.request_id)
        .filter(|welcome| welcome.status == WelcomeStatus::Pending)
        .ok_or(StateMachineError::InvalidWelcomeMapping)?;
    validate_request_evidence(
        &evidence,
        expected_kind,
        prior.coordinate.conversation_id(),
        &welcome.welcome_id,
        &welcome.recipient,
        evidence.received_at,
    )?;
    match evidence.body_binding.as_ref() {
        Some(RequestBodyBinding::WelcomeResponse {
            coordinates,
            transition_seq,
            rejection_reason,
        }) if coordinates == &welcome.coordinate
            && *transition_seq == welcome.transition_seq
            && welcome_response_reason_matches(expected_kind, rejection_reason.as_deref()) => {}
        _ => return Err(StateMachineError::InvalidWelcomeMapping),
    }
    if evidence.received_at >= welcome.expires_at {
        return Err(StateMachineError::WorkExpired);
    }
    let mut state = prior.clone();
    let welcome = state
        .welcomes
        .iter_mut()
        .find(|welcome| welcome.welcome_id == evidence.request_id)
        .ok_or(StateMachineError::InvalidWelcomeMapping)?;
    welcome.status = successor_status;
    welcome.terminal = Some(WorkTerminalEvidence::Request(evidence));
    validate_state(&state)?;
    Ok(PlannedTransition {
        expected_prior: Some(prior.coordinate),
        retired_coordinate: None,
        successor_coordinate: Some(prior.coordinate),
        effects: complete_effects(
            TransitionEffects::new(match successor_status {
                WelcomeStatus::Acknowledged => PlanKind::WelcomeAcknowledgement,
                WelcomeStatus::Rejected => PlanKind::WelcomeRejection,
                _ => unreachable!("status checked above"),
            }),
            Some(prior),
            &state,
        ),
        state,
    })
}

pub(in crate::chat_protocol::state_machine) fn plan_welcome_expiry(
    prior: &ConversationState,
    welcome_id: [u8; 16],
) -> Result<PlannedTransition, StateMachineError> {
    ensure_active(prior)?;
    let welcome = prior
        .welcome(&welcome_id)
        .filter(|welcome| welcome.status == WelcomeStatus::Pending)
        .ok_or(StateMachineError::InvalidWelcomeMapping)?;
    let terminal_at = welcome.expires_at;
    let mut state = prior.clone();
    let welcome = state
        .welcomes
        .iter_mut()
        .find(|welcome| welcome.welcome_id == welcome_id)
        .ok_or(StateMachineError::InvalidWelcomeMapping)?;
    welcome.status = WelcomeStatus::Expired;
    welcome.terminal = Some(WorkTerminalEvidence::Expiry(terminal_at));
    validate_state(&state)?;
    Ok(PlannedTransition {
        expected_prior: Some(prior.coordinate),
        retired_coordinate: None,
        successor_coordinate: Some(prior.coordinate),
        effects: complete_effects(
            TransitionEffects::new(PlanKind::WelcomeExpiry),
            Some(prior),
            &state,
        ),
        state,
    })
}

pub(in crate::chat_protocol::state_machine) fn welcome_response_reason_matches(
    kind: RequestEntryKind,
    rejection_reason: Option<&str>,
) -> bool {
    match (kind, rejection_reason) {
        (RequestEntryKind::WelcomeAcknowledgement, None) => true,
        (
            RequestEntryKind::WelcomeRejection,
            Some(
                "noMatchingKeyPackage"
                | "invalidWelcome"
                | "unsupportedCipherSuite"
                | "coordinateMismatch"
                | "localStateConflict",
            ),
        ) => true,
        _ => false,
    }
}

pub(in crate::chat_protocol::state_machine) fn welcome_endpoint_matches(
    evidence: &RequestEvidence,
    welcome_id: &[u8; 16],
    recipient_did: &[u8],
    recipient_device_id: &[u8; 16],
    coordinate: &PublicGroupSnapshotCoordinate,
    transition_seq: u64,
) -> bool {
    matches!(
        evidence.kind(),
        RequestEntryKind::WelcomeAcknowledgement | RequestEntryKind::WelcomeRejection
    ) && evidence.request_id() == welcome_id
        && evidence.conversation_id() == coordinate.conversation_id()
        && evidence.actor().principal().as_bytes() == recipient_did
        && evidence.actor().device_id() == recipient_device_id
        && matches!(
            evidence.body_binding.as_ref(),
            Some(RequestBodyBinding::WelcomeResponse {
                coordinates,
                transition_seq: signed_transition_seq,
                rejection_reason,
            }) if coordinates == coordinate
                && *signed_transition_seq == transition_seq
                && welcome_response_reason_matches(
                    evidence.kind(),
                    rejection_reason.as_deref(),
                )
        )
}

pub(in crate::chat_protocol::state_machine) fn welcome_cas_from_guard(
    prior: &ConversationState,
    guard: &LockedWelcomeGuard,
    successor_status: WelcomeStatus,
) -> Result<WelcomeCasBinding, StateMachineError> {
    let welcome_id = *guard.welcome_id().as_bytes();
    let welcome = prior
        .welcome(&welcome_id)
        .filter(|welcome| welcome.status == WelcomeStatus::Pending)
        .ok_or(StateMachineError::InvalidHydrationAuthority)?;
    let expires_at = ServerTimestamp::from_unix_millis(guard.expires_at().timestamp_millis())?;
    let locked_at = ServerTimestamp::from_unix_millis(guard.locked_at().timestamp_millis())?;
    if guard.conversation_id().as_bytes() != prior.coordinate.conversation_id()
        || guard.recipient_did().as_bytes() != welcome.recipient.principal().as_bytes()
        || guard.recipient_device_id().as_bytes() != welcome.recipient.device_id()
        || guard.transition_seq() != welcome.transition_seq
        || guard.coordinate() != &welcome.coordinate
        || guard.recovery_request_id().as_bytes() != &welcome.recovery_request_id
        || guard.key_package_ref() != &welcome.key_package_ref
        || guard.opaque_welcome() != welcome.opaque_welcome
        || guard.opaque_welcome_sha256() != &welcome.sha256
        || expires_at != welcome.expires_at
        || guard.durable_row_digest() == &[0; 32]
        || !matches!(
            successor_status,
            WelcomeStatus::Acknowledged | WelcomeStatus::Rejected | WelcomeStatus::Expired
        )
    {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    let mut binding = WelcomeCasBinding {
        transaction_id: guard.transaction_id().to_owned(),
        conversation_id: *guard.conversation_id().as_bytes(),
        welcome_id,
        recipient: welcome.recipient.clone(),
        transition_seq: welcome.transition_seq,
        coordinate: welcome.coordinate,
        recovery_request_id: welcome.recovery_request_id,
        key_package_ref: welcome.key_package_ref,
        opaque_welcome_sha256: welcome.sha256,
        expires_at,
        expected_status: WelcomeStatus::Pending,
        successor_status,
        locked_at,
        locked_row_digest: *guard.durable_row_digest(),
        seal: [0; 32],
    };
    binding.seal = welcome_cas_seal(&binding);
    Ok(binding)
}

pub(in crate::chat_protocol::state_machine) fn invitation_quota_cas_from_guard(
    guard: &LockedInvitationQuotaGuard,
    expected_inviter: &PrincipalId,
    expected_new_recipients: &[String],
    transaction_id: &str,
    trusted_at: ServerTimestamp,
) -> Result<InvitationQuotaCasBinding, StateMachineError> {
    let locked_at = ServerTimestamp::from_unix_millis(guard.locked_at().timestamp_millis())?;
    if guard.transaction_id() != transaction_id
        || guard.inviter_did().as_bytes() != expected_inviter.as_bytes()
        || guard.new_recipient_dids() != expected_new_recipients
        || locked_at != trusted_at
        || guard.durable_row_digest() == &[0; 32]
    {
        return Err(StateMachineError::InvalidHydrationAuthority);
    }
    let successor_inviter_recent_24h = guard
        .inviter_recent_24h()
        .checked_add(guard.new_recipient_dids().len() as u64)
        .filter(|value| *value <= MAX_PROTOCOL_INTEGER)
        .ok_or(StateMachineError::InvalidHydrationAuthority)?;
    let new_recipients = guard
        .new_recipient_dids()
        .iter()
        .map(|did| PrincipalId::new(did.as_bytes().to_vec()))
        .collect::<Result<Vec<_>, _>>()?;
    let recipient_facts = guard
        .recipient_facts()
        .iter()
        .map(|fact| {
            Ok(InvitationQuotaRecipientCasFact {
                recipient: PrincipalId::new(fact.recipient_did().as_bytes().to_vec())?,
                expected_pair_live: fact.pair_live(),
                successor_pair_live: fact
                    .pair_live()
                    .checked_add(1)
                    .filter(|value| *value <= MAX_PROTOCOL_INTEGER)
                    .ok_or(StateMachineError::InvalidHydrationAuthority)?,
                pair_limit: fact.pair_limit(),
                expected_recipient_live: fact.recipient_live(),
                successor_recipient_live: fact
                    .recipient_live()
                    .checked_add(1)
                    .filter(|value| *value <= MAX_PROTOCOL_INTEGER)
                    .ok_or(StateMachineError::InvalidHydrationAuthority)?,
                recipient_limit: fact.recipient_limit(),
            })
        })
        .collect::<Result<Vec<_>, StateMachineError>>()?;
    Ok(InvitationQuotaCasBinding {
        transaction_id: transaction_id.to_owned(),
        inviter: expected_inviter.clone(),
        new_recipients,
        expected_inviter_recent_24h: guard.inviter_recent_24h(),
        successor_inviter_recent_24h,
        inviter_limit: guard.inviter_limit(),
        recipient_facts,
        locked_at,
        locked_row_digest: *guard.durable_row_digest(),
    })
}
