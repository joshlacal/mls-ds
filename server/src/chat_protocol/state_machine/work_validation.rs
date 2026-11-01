#![allow(unused_imports)]
use super::*;

pub(in crate::chat_protocol::state_machine) fn validate_recovery_work(
    state: &ConversationState,
) -> Result<(), StateMachineError> {
    if state.recovery_requests.len() != state.recovery_reservations.len()
        || state.recovery_requests.windows(2).any(|pair| {
            pair[0]
                .target
                .cmp(&pair[1].target)
                .then_with(|| pair[0].request_id.cmp(&pair[1].request_id))
                != Ordering::Less
        })
        || state.recovery_reservations.windows(2).any(|pair| {
            pair[0]
                .target
                .cmp(&pair[1].target)
                .then_with(|| pair[0].request_id.cmp(&pair[1].request_id))
                != Ordering::Less
        })
        || state
            .recovery_requests
            .iter()
            .map(|request| request.request_id)
            .collect::<BTreeSet<_>>()
            .len()
            != state.recovery_requests.len()
        || state
            .recovery_reservations
            .iter()
            .map(|reservation| reservation.request_id)
            .collect::<BTreeSet<_>>()
            .len()
            != state.recovery_reservations.len()
        || state
            .recovery_reservations
            .iter()
            .filter(|reservation| reservation.status == ReservationStatus::Active)
            .map(|reservation| reservation.key_package_ref)
            .collect::<BTreeSet<_>>()
            .len()
            != state
                .recovery_reservations
                .iter()
                .filter(|reservation| reservation.status == ReservationStatus::Active)
                .count()
    {
        return Err(StateMachineError::InvariantViolation);
    }
    let mut open_targets = BTreeSet::new();
    for request in &state.recovery_requests {
        if !is_uuid_v4(&request.request_id)
            || !coordinate_is_in_lineage(&request.bound_coordinate, &state.coordinate)
            || request.key_package_ref == [0; 32]
        {
            return Err(StateMachineError::InvariantViolation);
        }
        let reservation = state
            .recovery_reservations
            .iter()
            .find(|reservation| reservation.request_id == request.request_id)
            .ok_or(StateMachineError::InvariantViolation)?;
        let expected_expiry = recovery_expiry(request.received_at, reservation.package_not_after)
            .map_err(|_| StateMachineError::InvariantViolation)?;
        if reservation.target != request.target
            || reservation.bound_coordinate != request.bound_coordinate
            || reservation.key_package_ref != request.key_package_ref
            || reservation.received_at != request.received_at
            || reservation.expires_at != request.expires_at
            || request.expires_at != expected_expiry
            || (!matches!(
                reservation.terminal,
                Some(WorkTerminalEvidence::DeviceRevocation(_))
            ) && reservation.terminal != request.terminal)
        {
            return Err(StateMachineError::InvariantViolation);
        }
        let origin_seq = match (&request.source, &request.origin) {
            (RecoverySource::Acceptance, RecoveryOriginEvidence::Acceptance(evidence))
                if acceptance_origin_matches_recovery(
                    evidence,
                    request,
                    reservation,
                    state.coordinate.conversation_id(),
                ) =>
            {
                Some(evidence.seq)
            }
            (RecoverySource::Request, RecoveryOriginEvidence::Request(evidence)) => {
                validate_request_evidence(
                    evidence,
                    RequestEntryKind::LeafRecoveryRequest,
                    state.coordinate.conversation_id(),
                    &request.request_id,
                    &request.target,
                    request.received_at,
                )?;
                require_leaf_recovery_request_binding(
                    evidence,
                    &request.bound_coordinate,
                    request.kind,
                )?;
                None
            }
            _ => return Err(StateMachineError::InvariantViolation),
        };
        let status_matches = match request.status {
            RecoveryRequestStatus::Open => {
                request.terminal.is_none()
                    && reservation.status == ReservationStatus::Active
                    && request.bound_coordinate == state.coordinate
                    && state
                        .participant(request.target.principal())
                        .is_some_and(ParticipantRecord::is_active)
                    && match request.kind {
                        LeafRecoveryKind::Add => state.leaf(&request.target).is_none(),
                        LeafRecoveryKind::Replace => state.leaf(&request.target).is_some(),
                    }
                    && open_targets.insert(request.target.clone())
            }
            RecoveryRequestStatus::Fulfilled => {
                reservation.status == ReservationStatus::Consumed
                    && request.terminal.as_ref().is_some_and(|terminal| {
                        matches!(terminal, WorkTerminalEvidence::Transition(evidence)
                        if transition_follows_origin(
                            evidence,
                            origin_seq,
                            request.received_at,
                            request.expires_at,
                        ) && recovery_fulfillment_matches_request(evidence, request))
                    })
            }
            RecoveryRequestStatus::Cancelled => {
                reservation.status == ReservationStatus::Released
                    && request.terminal.as_ref().is_some_and(|terminal| {
                        let WorkTerminalEvidence::Request(evidence) = terminal else {
                            return false;
                        };
                        validate_request_evidence(
                            evidence,
                            RequestEntryKind::LeafRecoveryCancellation,
                            state.coordinate.conversation_id(),
                            &request.request_id,
                            &request.target,
                            evidence.received_at,
                        )
                        .is_ok()
                            && evidence.request_digest
                                != recovery_origin_request_digest(&request.origin)
                            && evidence.received_at >= request.received_at
                            && evidence.received_at < request.expires_at
                    })
            }
            RecoveryRequestStatus::Expired => {
                request.terminal == Some(WorkTerminalEvidence::Expiry(request.expires_at))
                    && (reservation.status == ReservationStatus::Expired
                        || (reservation.status == ReservationStatus::Released
                            && reservation.terminal.as_ref().is_some_and(|terminal| {
                                matches!(terminal, WorkTerminalEvidence::DeviceRevocation(evidence)
                                    if validate_device_revocation_evidence(evidence)
                                        && evidence.target == request.target
                                        && evidence.accepted_at >= request.expires_at)
                            })))
            }
            RecoveryRequestStatus::Superseded => {
                request
                    .terminal
                    .as_ref()
                    .is_some_and(|terminal| match terminal {
                        WorkTerminalEvidence::Transition(evidence) => {
                            reservation.status == ReservationStatus::Released
                                && transition_follows_origin(
                                    evidence,
                                    origin_seq,
                                    request.received_at,
                                    request.expires_at,
                                )
                                && transition_consumes_coordinate(
                                    evidence,
                                    &request.bound_coordinate,
                                )
                        }
                        WorkTerminalEvidence::DeviceRevocation(revocation) => {
                            reservation.status == ReservationStatus::Released
                                && reservation.terminal.as_ref() == Some(terminal)
                                && revocation_supersedes_request(revocation, request)
                        }
                        _ => false,
                    })
            }
        };
        if !status_matches {
            return Err(StateMachineError::InvariantViolation);
        }
    }
    Ok(())
}

pub(in crate::chat_protocol::state_machine) fn revocation_supersedes_request(
    evidence: &DeviceRevocationEvidence,
    request: &RecoveryRequest,
) -> bool {
    let target_generation = match &request.origin {
        RecoveryOriginEvidence::Acceptance(origin) => origin
            .authority
            .as_ref()
            .map(|authority| authority.auth_generation),
        RecoveryOriginEvidence::Request(origin) => Some(origin.auth_generation),
    };
    validate_device_revocation_evidence(evidence)
        && evidence.target == request.target
        && target_generation == Some(evidence.expected_target_auth_generation)
        && evidence.accepted_at >= request.received_at
        && evidence.accepted_at < request.expires_at
}

pub(in crate::chat_protocol::state_machine) fn recovery_origin_received_at(
    origin: &RecoveryOriginEvidence,
) -> ServerTimestamp {
    match origin {
        RecoveryOriginEvidence::Acceptance(evidence) => evidence.received_at,
        RecoveryOriginEvidence::Request(evidence) => evidence.received_at,
    }
}

pub(in crate::chat_protocol::state_machine) fn recovery_origin_request_digest(
    origin: &RecoveryOriginEvidence,
) -> [u8; 32] {
    match origin {
        RecoveryOriginEvidence::Acceptance(evidence) => evidence
            .authority
            .as_ref()
            .map_or(evidence.outer_entry_fingerprint, |authority| {
                authority.request_digest
            }),
        RecoveryOriginEvidence::Request(evidence) => evidence.request_digest,
    }
}

pub(in crate::chat_protocol::state_machine) fn validate_reset_work(
    state: &ConversationState,
) -> Result<(), StateMachineError> {
    if state
        .reset_requests
        .windows(2)
        .any(|pair| pair[0].request_id >= pair[1].request_id)
        || state
            .reset_requests
            .iter()
            .filter(|request| request.status == ResetRequestStatus::Pending)
            .count()
            > 1
    {
        return Err(StateMachineError::InvariantViolation);
    }
    for request in &state.reset_requests {
        if !is_uuid_v4(&request.request_id)
            || !coordinate_is_in_lineage(&request.bound_coordinate, &state.coordinate)
            || !exact_expiry(request.received_at, CONSENT_TTL_MILLIS, request.expires_at)
            || validate_request_evidence(
                &request.origin,
                RequestEntryKind::ResetRequest,
                state.coordinate.conversation_id(),
                &request.request_id,
                &request.requester,
                request.received_at,
            )
            .is_err()
            || require_request_prior(&request.origin, &request.bound_coordinate).is_err()
        {
            return Err(StateMachineError::InvariantViolation);
        }
        let valid = match request.status {
            ResetRequestStatus::Pending => {
                request.terminal.is_none()
                    && request.bound_coordinate == state.coordinate
                    && state
                        .participant(request.requester.principal())
                        .is_some_and(ParticipantRecord::is_active)
            }
            ResetRequestStatus::Consumed => request.terminal.as_ref().is_some_and(|terminal| {
                matches!(terminal, WorkTerminalEvidence::Transition(evidence)
                if transition_follows_origin(
                    evidence,
                    request.origin.control_seq,
                    request.received_at,
                    request.expires_at,
                ) && transition_has_one_of_kinds(
                    evidence,
                    &[SignedMutationKind::ResetActivation],
                ) && reset_activation_matches_request(evidence, request, state.kind))
            }),
            ResetRequestStatus::Stale => request.terminal.as_ref().is_some_and(|terminal| {
                matches!(terminal, WorkTerminalEvidence::Transition(evidence)
                if transition_follows_origin(
                    evidence,
                    request.origin.control_seq,
                    request.received_at,
                    request.expires_at,
                ) && transition_consumes_coordinate(evidence, &request.bound_coordinate))
            }),
            ResetRequestStatus::Expired => {
                request.terminal == Some(WorkTerminalEvidence::Expiry(request.expires_at))
            }
            // Mirrors the `revoked` arm of `reset_requests_terminal_shape_check`:
            // the revocation must target this row's own requester, and may fall
            // after the row lapsed — a device can be revoked long after the
            // request it invalidates, so there is deliberately no upper bound.
            ResetRequestStatus::Revoked => request.terminal.as_ref().is_some_and(|terminal| {
                matches!(terminal, WorkTerminalEvidence::DeviceRevocation(evidence)
                if validate_device_revocation_evidence(evidence)
                    && evidence.target == request.requester
                    && evidence.accepted_at >= request.received_at)
            }),
        };
        if !valid {
            return Err(StateMachineError::InvariantViolation);
        }
    }
    Ok(())
}

pub(in crate::chat_protocol::state_machine) fn validate_leave_work(
    state: &ConversationState,
) -> Result<(), StateMachineError> {
    if state.leave_requests.windows(2).any(|pair| {
        pair[0]
            .requester
            .cmp(&pair[1].requester)
            .then_with(|| pair[0].request_id.cmp(&pair[1].request_id))
            != Ordering::Less
    }) || state
        .leave_requests
        .iter()
        .map(|request| request.request_id)
        .collect::<BTreeSet<_>>()
        .len()
        != state.leave_requests.len()
    {
        return Err(StateMachineError::InvariantViolation);
    }
    let mut pending_principals = BTreeSet::new();
    for request in &state.leave_requests {
        if !is_uuid_v4(&request.request_id)
            || !coordinate_is_in_lineage(&request.bound_coordinate, &state.coordinate)
            || !exact_expiry(request.received_at, CONSENT_TTL_MILLIS, request.expires_at)
            || validate_request_evidence(
                &request.origin,
                RequestEntryKind::LeaveRequest,
                state.coordinate.conversation_id(),
                &request.request_id,
                &request.requester,
                request.received_at,
            )
            .is_err()
            || require_request_prior(&request.origin, &request.bound_coordinate).is_err()
            || (request.status == LeaveRequestStatus::Fulfilled)
                != request.fulfilled_participant.is_some()
        {
            return Err(StateMachineError::InvariantViolation);
        }
        let valid = match request.status {
            LeaveRequestStatus::Pending => {
                request.terminal.is_none()
                    && request.bound_coordinate == state.coordinate
                    && state
                        .participant(request.requester.principal())
                        .is_some_and(ParticipantRecord::is_active)
                    && state
                        .leaves
                        .iter()
                        .any(|leaf| leaf.device.principal() == request.requester.principal())
                    && pending_principals.insert(request.requester.principal().clone())
            }
            LeaveRequestStatus::Fulfilled => request.terminal.as_ref().is_some_and(|terminal| {
                matches!(terminal, WorkTerminalEvidence::Transition(evidence)
                if transition_follows_origin(
                    evidence,
                    request.origin.control_seq,
                    request.received_at,
                    request.expires_at,
                ) && transition_has_one_of_kinds(
                    evidence,
                    &[SignedMutationKind::LeaveCommitFulfillment],
                ) && leave_fulfillment_matches_request(state, evidence, request))
            }),
            LeaveRequestStatus::Stale => request.terminal.as_ref().is_some_and(|terminal| {
                matches!(terminal, WorkTerminalEvidence::Transition(evidence)
                if transition_follows_origin(
                    evidence,
                    request.origin.control_seq,
                    request.received_at,
                    request.expires_at,
                ) && transition_consumes_coordinate(evidence, &request.bound_coordinate))
            }),
            LeaveRequestStatus::Cancelled => request.terminal.as_ref().is_some_and(|terminal| {
                let WorkTerminalEvidence::Request(evidence) = terminal else {
                    return false;
                };
                evidence.actor.principal() == request.requester.principal()
                    && validate_request_evidence(
                        evidence,
                        RequestEntryKind::LeaveCancellation,
                        state.coordinate.conversation_id(),
                        &request.request_id,
                        &evidence.actor,
                        evidence.received_at,
                    )
                    .is_ok()
                    && require_request_coordinate_binding(
                        evidence,
                        state.coordinate.conversation_id(),
                    )
                    .is_ok()
                    && evidence
                        .control_seq
                        .zip(request.origin.control_seq)
                        .is_some_and(|(terminal, origin)| terminal > origin)
                    && evidence.control_entry_id != request.origin.control_entry_id
                    && evidence.received_at >= request.received_at
                    && evidence.received_at < request.expires_at
            }),
            LeaveRequestStatus::Expired => {
                request.terminal == Some(WorkTerminalEvidence::Expiry(request.expires_at))
            }
        };
        if !valid {
            return Err(StateMachineError::InvariantViolation);
        }
    }
    Ok(())
}

pub(in crate::chat_protocol::state_machine) fn validate_welcome_work(
    state: &ConversationState,
) -> Result<(), StateMachineError> {
    if state
        .welcomes
        .windows(2)
        .any(|pair| pair[0].welcome_id >= pair[1].welcome_id)
    {
        return Err(StateMachineError::InvariantViolation);
    }
    let mut fulfilled_requests = BTreeSet::new();
    for welcome in &state.welcomes {
        let request = state
            .recovery_request(&welcome.recovery_request_id)
            .ok_or(StateMachineError::InvariantViolation)?;
        let reservation = state
            .recovery_reservation(&welcome.recovery_request_id)
            .ok_or(StateMachineError::InvariantViolation)?;
        let fulfillment = match request.terminal.as_ref() {
            Some(WorkTerminalEvidence::Transition(evidence))
                if transition_has_one_of_kinds(
                    evidence,
                    &[SignedMutationKind::LeafRecoveryFulfillment],
                ) =>
            {
                evidence
            }
            _ => return Err(StateMachineError::InvariantViolation),
        };
        if !is_uuid_v4(&welcome.welcome_id)
            || !fulfilled_requests.insert(welcome.recovery_request_id)
            || !coordinate_is_in_lineage(&welcome.coordinate, &state.coordinate)
            || welcome.opaque_welcome.is_empty()
            || <[u8; 32]>::from(Sha256::digest(&welcome.opaque_welcome)) != welcome.sha256
            || request.status != RecoveryRequestStatus::Fulfilled
            || reservation.status != ReservationStatus::Consumed
            || welcome.recipient != request.target
            || welcome.key_package_ref != request.key_package_ref
            || welcome.expires_at != reservation.package_not_after
            || welcome.transition_seq != fulfillment.seq
            || (fulfillment.authority.is_some()
                && !fulfillment.body_binding.as_ref().is_some_and(|binding| {
                    matches!(
                        binding,
                        TransitionBodyBinding::LeafRecoveryFulfillment {
                            recovery_request_id,
                            next,
                            manifest,
                            ..
                        } if recovery_request_id == &welcome.recovery_request_id
                            && next == &welcome.coordinate
                            && manifest.welcome.as_ref().is_some_and(|signed| {
                                signed.welcome_id == welcome.welcome_id
                                    && signed.recipient == welcome.recipient
                                    && signed.recovery_request_id == welcome.recovery_request_id
                                    && signed.key_package_ref == welcome.key_package_ref
                                    && signed.opaque_welcome == welcome.opaque_welcome
                                    && signed.sha256 == welcome.sha256
                            })
                    )
                }))
        {
            return Err(StateMachineError::InvariantViolation);
        }
        let valid = match welcome.status {
            WelcomeStatus::Pending => {
                welcome.terminal.is_none() && welcome.coordinate == state.coordinate
            }
            WelcomeStatus::Expired => {
                welcome.terminal == Some(WorkTerminalEvidence::Expiry(welcome.expires_at))
            }
            WelcomeStatus::Superseded => {
                welcome
                    .terminal
                    .as_ref()
                    .is_some_and(|terminal| match terminal {
                        WorkTerminalEvidence::Transition(evidence) => {
                            validate_transition_evidence(evidence)
                                && evidence.seq > welcome.transition_seq
                                && evidence.received_at < welcome.expires_at
                                && transition_consumes_coordinate(evidence, &welcome.coordinate)
                        }
                        WorkTerminalEvidence::DeviceRevocation(evidence) => {
                            validate_device_revocation_evidence(evidence)
                                && evidence.target == welcome.recipient
                                && evidence.accepted_at < welcome.expires_at
                        }
                        _ => false,
                    })
            }
            WelcomeStatus::Acknowledged | WelcomeStatus::Rejected => welcome
                .terminal
                .as_ref()
                .is_some_and(|terminal| match terminal {
                    WorkTerminalEvidence::Request(evidence) => {
                        let expected_kind = if welcome.status == WelcomeStatus::Acknowledged {
                            RequestEntryKind::WelcomeAcknowledgement
                        } else {
                            RequestEntryKind::WelcomeRejection
                        };
                        validate_request_evidence(
                            evidence,
                            expected_kind,
                            state.coordinate.conversation_id(),
                            &welcome.welcome_id,
                            &welcome.recipient,
                            evidence.received_at,
                        )
                        .is_ok()
                            && evidence.received_at < welcome.expires_at
                            && matches!(
                                evidence.body_binding.as_ref(),
                                Some(RequestBodyBinding::WelcomeResponse {
                                    coordinates,
                                    transition_seq,
                                    rejection_reason,
                                }) if coordinates == &welcome.coordinate
                                    && *transition_seq == welcome.transition_seq
                                    && welcome_response_reason_matches(
                                        expected_kind,
                                        rejection_reason.as_deref(),
                                    )
                            )
                    }
                    _ => false,
                }),
        };
        if !valid {
            return Err(StateMachineError::InvariantViolation);
        }
    }
    if state
        .recovery_requests
        .iter()
        .filter(|request| request.status == RecoveryRequestStatus::Fulfilled)
        .any(|request| !fulfilled_requests.contains(&request.request_id))
    {
        return Err(StateMachineError::InvariantViolation);
    }
    Ok(())
}

pub(in crate::chat_protocol::state_machine) fn would_remove_last_active_admin(
    state: &ConversationState,
    principal: &PrincipalId,
) -> bool {
    state.participant(principal).is_some_and(|participant| {
        participant.status == ParticipantStatus::Active
            && participant.role == ParticipantRole::Admin
    }) && state
        .participants
        .iter()
        .filter(|participant| {
            participant.status == ParticipantStatus::Active
                && participant.role == ParticipantRole::Admin
        })
        .count()
        == 1
}

#[cfg(test)]
impl DeviceIdentity {
    pub(crate) fn from_did_for_test(did: &str) -> Self {
        Self {
            principal: PrincipalId::new(did.as_bytes().to_vec()).unwrap(),
            device_id: [0; 16],
        }
    }
}

#[cfg(test)]
impl ParticipantRecord {
    pub(crate) fn for_relationship_scope_test(
        did: &str,
        status: ParticipantStatus,
        inviter: Option<DeviceIdentity>,
    ) -> Self {
        Self {
            principal: PrincipalId::new(did.as_bytes().to_vec()).unwrap(),
            status,
            role: ParticipantRole::Member,
            role_producer: None,
            invitation: inviter.map(|inviter| InvitationProvenance {
                transition: TransitionEvidence::new(
                    1,
                    *uuid::Uuid::from_u128(0x01234567_89ab_4cde_8f01_23456789abcd).as_bytes(),
                    [0; 32],
                )
                .unwrap(),
                inviter,
            }),
            acceptance: None,
        }
    }
}

#[cfg(test)]
impl ConversationState {
    pub(crate) fn for_relationship_scope_test(
        kind: ConversationKind,
        conversation_id: [u8; 16],
        participants: Vec<ParticipantRecord>,
    ) -> Self {
        let coordinate = crate::chat_protocol::snapshot::PublicGroupSnapshotCoordinate::new(
            conversation_id,
            1,
            1,
            [0; 32],
            0,
            [0; 32],
            [0; 32],
            crate::chat_protocol::snapshot::PublicGroupSnapshotLifecycle::Active,
        );
        Self {
            kind,
            coordinate,
            producer: TransitionEvidence::new(
                1,
                *uuid::Uuid::from_u128(0x01234567_89ab_4cde_8f01_23456789abcd).as_bytes(),
                [0; 32],
            )
            .unwrap(),
            public_state: None,
            metadata: None,
            metadata_producer: None,
            participants,
            leaves: Vec::new(),
            intervals: Vec::new(),
            terminal_proofs: Vec::new(),
            recovery_requests: Vec::new(),
            recovery_reservations: Vec::new(),
            reset_requests: Vec::new(),
            leave_requests: Vec::new(),
            welcomes: Vec::new(),
        }
    }
}

#[cfg(test)]
impl LockedRegistrationProjection {
    pub(crate) fn for_scope_test(
        transaction_id: &str,
        conversation_id: [u8; 16],
        actor_did: &str,
        status: PersistedRegistrationStatus,
        durable_row_digest: [u8; 32],
    ) -> Self {
        Self {
            transaction_id: transaction_id.to_owned(),
            conversation_id,
            actor: DeviceIdentity::from_did_for_test(actor_did),
            key_id: [0; 32],
            registered_mls_signature_key: [0; 32],
            auth_generation: 1,
            status,
            trusted_read_at: ServerTimestamp::from_unix_millis_for_test(0).unwrap(),
            durable_row_digest,
            authority_scope_digest: [1; 32],
        }
    }
}
