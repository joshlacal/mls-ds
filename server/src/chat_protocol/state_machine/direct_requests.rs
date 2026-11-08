#![allow(unused_imports)]
use super::*;

impl HydrationAuthority {
    pub(crate) fn plan_leave_cancellation_entry(
        &self,
        locked: &LockedConversationStateGuard,
        entry: VerifiedControlEntry,
        registration: LockedRegistrationProjection,
    ) -> Result<PlannedTransition, StateMachineError> {
        self.require_same_locked_conversation(locked)?;
        let prior = locked.state();
        let head = locked.head();
        let evidence = self.control_request(entry)?;
        if evidence.kind != RequestEntryKind::LeaveCancellation
            || !registration.authorizes(&evidence)
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let authority = evidence.clone();
        let transaction_id = registration.transaction_id().to_owned();
        let trusted_read_at = registration.trusted_read_at();
        let plan = plan_leave_cancellation_inner(
            prior,
            LeaveCancellation {
                actor: evidence.actor.clone(),
                leave_request_id: evidence.request_id,
                received_at: evidence.received_at,
                evidence,
                registration,
            },
        )?;
        plan.bind_control_request_authority(authority, head, &transaction_id, trusted_read_at)
    }

    pub(crate) fn signed_request(
        &self,
        envelope: DurableSignedRequestEnvelope,
        mutation: VerifiedSignedMutation,
    ) -> Result<RequestEvidence, StateMachineError> {
        if envelope.conversation_id != self.expected_conversation_id {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let locked = self
            .locked_binding()
            .ok_or(StateMachineError::InvalidHydrationAuthority)?;
        if envelope.received_at != locked.locked_at {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let (kind, request_id, body, body_binding) = match mutation.projection() {
            VerifiedMutationProjection::LeafRecoveryRequest(value) => (
                RequestEntryKind::LeafRecoveryRequest,
                *value.recovery_request_id().as_bytes(),
                value.body(),
                RequestBodyBinding::LeafRecoveryRequest {
                    prior: closed_coordinate(&value.prior())?,
                    kind: match value.recovery_kind() {
                        "add" => LeafRecoveryKind::Add,
                        "replace" => LeafRecoveryKind::Replace,
                        _ => return Err(StateMachineError::InvalidHydrationAuthority),
                    },
                },
            ),
            VerifiedMutationProjection::LeafRecoveryCancellation(value) => (
                RequestEntryKind::LeafRecoveryCancellation,
                *value.recovery_request_id().as_bytes(),
                value.body(),
                RequestBodyBinding::LeafRecoveryCancellation,
            ),
            VerifiedMutationProjection::WelcomeAcknowledgement(value) => (
                RequestEntryKind::WelcomeAcknowledgement,
                closed_uuid(&value.body(), "welcomeId")?,
                value.body(),
                RequestBodyBinding::WelcomeResponse {
                    coordinates: closed_coordinate_from_field(&value.body(), "coordinates")?,
                    transition_seq: closed_integer(&value.body(), "transitionSeq")?,
                    rejection_reason: None,
                },
            ),
            VerifiedMutationProjection::WelcomeRejection(value) => (
                RequestEntryKind::WelcomeRejection,
                closed_uuid(&value.body(), "welcomeId")?,
                value.body(),
                RequestBodyBinding::WelcomeResponse {
                    coordinates: closed_coordinate_from_field(&value.body(), "coordinates")?,
                    transition_seq: closed_integer(&value.body(), "transitionSeq")?,
                    rejection_reason: Some(closed_text(&value.body(), "reason")?.to_owned()),
                },
            ),
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        };
        let embedded_conversation_id = match kind {
            RequestEntryKind::LeafRecoveryRequest => {
                Some(closed_coordinate_conversation_id(body, "prior")?)
            }
            RequestEntryKind::LeafRecoveryCancellation => None,
            RequestEntryKind::WelcomeAcknowledgement | RequestEntryKind::WelcomeRejection => {
                Some(closed_coordinate_conversation_id(body, "coordinates")?)
            }
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        };
        if embedded_conversation_id
            .is_some_and(|conversation_id| conversation_id != self.expected_conversation_id)
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        if match &body_binding {
            RequestBodyBinding::LeafRecoveryRequest { prior, .. } => {
                Some(prior) != locked.expected_prior.as_ref()
            }
            RequestBodyBinding::WelcomeResponse { coordinates, .. } => {
                Some(coordinates) != locked.expected_prior.as_ref()
            }
            RequestBodyBinding::LeafRecoveryCancellation => false,
            _ => true,
        } {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let durable_row_digest =
            durable_signed_request_row_digest(kind, &envelope, &request_id, &mutation)?;
        request_evidence_from_verified(
            kind,
            None,
            &envelope.conversation_id,
            None,
            None,
            None,
            &request_id,
            envelope.received_at,
            durable_row_digest,
            &mutation,
            body_binding,
        )
    }

    /// Admit a non-control leaf-recovery request using the exact signed
    /// wrapper, active device row, transaction-bound KeyPackage selection,
    /// and the complete block-only relationship projection for the current
    /// logical roster. No artificial control entry ID or sequence is minted.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn plan_leaf_recovery_request_entry<T: PublicTransport>(
        &self,
        locked: &LockedConversationStateGuard,
        envelope: DurableSignedRequestEnvelope,
        mutation: VerifiedSignedMutation,
        registration: LockedRegistrationProjection,
        reservation: LockedRecoveryReservationProjection,
        relationship: &RelationshipProjection,
        relationship_authority: &RelationshipAuthority<T>,
        relationship_decision: &LockedRelationshipDecisionGuard,
        trusted_now: &TrustedRequestInstant,
    ) -> Result<PlannedTransition, StateMachineError> {
        self.require_same_locked_conversation(locked)?;
        let prior = locked.state();
        let head = locked.head();
        let evidence = self.signed_request(envelope, mutation)?;
        let kind = match evidence.body_binding.as_ref() {
            Some(RequestBodyBinding::LeafRecoveryRequest { kind, .. }) => *kind,
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        };
        if !registration.authorizes(&evidence)
            || !reservation.authorizes_request(&evidence, kind)
            || registration.transaction_id() != reservation.transaction_id()
            || registration.trusted_read_at()
                != ServerTimestamp::from_trusted_request_instant(trusted_now)?
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let actor = registration.actor().clone();
        let recovery_request_id = *evidence.request_id();
        let received_at = evidence.received_at();
        let key_package_ref = *reservation.key_package_ref();
        let package_not_after = reservation.package_not_after();
        let package_cas = reservation.available_package_cas();
        let relationship_evidence_digest = relationship.evidence_digest();
        let transaction_id = registration.transaction_id().to_owned();
        let trusted_read_at = registration.trusted_read_at();
        let authority = evidence.clone();
        // Opening recovery work cannot change the logical roster; this is the
        // exact roster the deterministic request planner carries forward.
        let roster = prior
            .participants
            .iter()
            .map(|participant| {
                String::from_utf8(participant.principal.as_bytes().to_vec())
                    .map_err(|_| StateMachineError::InvalidPolicyAuthority)
            })
            .collect::<Result<Vec<_>, _>>()?;
        consume_locked_recovery_projection(
            relationship,
            relationship_decision,
            locked,
            &registration,
            ProjectionOperationScope::RecoveryReservation,
            &roster,
            relationship_authority,
        )
        .map_err(relationship_consumption_error)?;
        let mut plan = plan_leaf_recovery_request_inner(
            prior,
            LeafRecoveryRequestCommand {
                actor,
                recovery_request_id,
                kind,
                key_package_ref,
                received_at,
                package_not_after,
                evidence,
                #[cfg(not(test))]
                registration,
                #[cfg(not(test))]
                reservation,
            },
        )?;
        plan.effects.policy_evidence_digest = Some(relationship_evidence_digest);
        plan.bind_non_control_request_authority(authority, head, &transaction_id, trusted_read_at)?
            .bind_recovery_package_cas(package_cas)
    }

    pub(crate) fn plan_leaf_recovery_cancellation_entry(
        &self,
        locked: &LockedConversationStateGuard,
        envelope: DurableSignedRequestEnvelope,
        mutation: VerifiedSignedMutation,
        registration: LockedRegistrationProjection,
        reserved_package: LockedRecoveryPackageGuard,
    ) -> Result<PlannedTransition, StateMachineError> {
        self.require_same_locked_conversation(locked)?;
        let prior = locked.state();
        let head = locked.head();
        let evidence = self.signed_request(envelope, mutation)?;
        if evidence.kind != RequestEntryKind::LeafRecoveryCancellation
            || !registration.authorizes(&evidence)
            || registration.transaction_id() != head.transaction_id()
            || registration.trusted_read_at() != evidence.received_at
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let request = prior
            .recovery_request(evidence.request_id())
            .filter(|request| request.status == RecoveryRequestStatus::Open)
            .ok_or(StateMachineError::LeafRecoveryNotFound)?;
        let reservation = prior
            .recovery_reservation(evidence.request_id())
            .filter(|reservation| reservation.status == ReservationStatus::Active)
            .ok_or(StateMachineError::LeafRecoveryNotFound)?;
        let successor_status = if evidence.received_at >= reservation.package_not_after {
            PackageStatus::Expired
        } else {
            PackageStatus::Available
        };
        let package_cas = reserved_package_cas_for_request(
            reserved_package,
            request,
            reservation,
            registration.transaction_id(),
            successor_status,
        )?;
        let authority = evidence.clone();
        let transaction_id = registration.transaction_id().to_owned();
        let trusted_read_at = registration.trusted_read_at();
        let plan = plan_leaf_recovery_cancellation_inner(
            prior,
            LeafRecoveryCancellation {
                actor: evidence.actor.clone(),
                recovery_request_id: evidence.request_id,
                received_at: evidence.received_at,
                evidence,
                #[cfg(not(test))]
                registration,
            },
        )?;
        plan.bind_non_control_request_authority(authority, head, &transaction_id, trusted_read_at)?
            .bind_recovery_package_cas(package_cas)
    }

    /// Consume the exact request repository input and produce one fully bound
    /// transition. No handler identity, prelude, durable row, or payload enters
    /// this planner as a separate argument.
    pub(crate) fn plan_recovery_request_input<T: PublicTransport>(
        input: RecoveryRequestPlanInput,
        relationship_authority: &RelationshipAuthority<T>,
    ) -> Result<PlannedRecoveryMutation, StateMachineError> {
        let parts = input.into_planner_parts();
        let request_id = match parts.mutation.projection() {
            VerifiedMutationProjection::LeafRecoveryRequest(value) => {
                Uuid::from_bytes(*value.recovery_request_id().as_bytes())
            }
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        };
        if parts.prelude.scope_authority().trusted_instant()
            != parts.trusted_request_instant.datetime()
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let hydration = HydrationAuthority::from_locked_conversation(&parts.aggregate)?;
        let registration =
            hydration.locked_registration_from_scope_authority(parts.prelude.scope_authority())?;
        let reservation =
            hydration.locked_recovery_reservation(parts.execution_package, &registration)?;
        let envelope = DurableSignedRequestEnvelope::new(
            *parts.aggregate.head().conversation_id().as_bytes(),
            &parts.trusted_request_instant,
        )?;
        let transition = hydration.plan_leaf_recovery_request_entry(
            &parts.aggregate,
            envelope,
            parts.mutation,
            registration,
            reservation,
            &parts.relationship,
            relationship_authority,
            &parts.relationship_decision,
            &parts.trusted_request_instant,
        )?;
        let (scope_authority, completion, prewrite) = parts.prelude.into_recovery_execution_parts();
        Ok(PlannedRecoveryMutation {
            transition,
            scope_authority,
            completion,
            prewrite,
            accepted_control_entry_bytes: None,
            canonical_response_entry_bytes: None,
            persistence_witness: parts.persistence_witness,
            kind: RecoveryPlannedKind::Request {
                recovery_request_id: request_id,
            },
        })
    }

    pub(crate) fn plan_recovery_cancellation_input(
        input: RecoveryCancellationPlanInput,
    ) -> Result<PlannedRecoveryMutation, StateMachineError> {
        let parts = input.into_planner_parts();
        let request_id = match parts.mutation.projection() {
            VerifiedMutationProjection::LeafRecoveryCancellation(value) => {
                Uuid::from_bytes(*value.recovery_request_id().as_bytes())
            }
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        };
        if parts.prelude.scope_authority().trusted_instant()
            != parts.trusted_request_instant.datetime()
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let hydration = HydrationAuthority::from_locked_conversation(&parts.aggregate)?;
        let registration =
            hydration.locked_registration_from_scope_authority(parts.prelude.scope_authority())?;
        let envelope = DurableSignedRequestEnvelope::new(
            *parts.aggregate.head().conversation_id().as_bytes(),
            &parts.trusted_request_instant,
        )?;
        let transition = hydration.plan_leaf_recovery_cancellation_entry(
            &parts.aggregate,
            envelope,
            parts.mutation,
            registration,
            parts.execution_package,
        )?;
        let (scope_authority, completion, prewrite) = parts.prelude.into_recovery_execution_parts();
        Ok(PlannedRecoveryMutation {
            transition,
            scope_authority,
            completion,
            prewrite,
            accepted_control_entry_bytes: None,
            canonical_response_entry_bytes: None,
            persistence_witness: parts.persistence_witness,
            kind: RecoveryPlannedKind::Cancellation {
                recovery_request_id: request_id,
            },
        })
    }

    pub(crate) fn plan_client_recovery_expiry_input(
        input: RecoveryClientExpiryPlanInput,
    ) -> Result<PlannedClientRecoveryExpiry, StateMachineError> {
        let parts = input
            .into_planner_parts()
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        if parts.prelude.scope_authority().trusted_instant()
            != parts.trusted_request_instant.datetime()
            || parts.observed_at != parts.trusted_request_instant.datetime()
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        HydrationAuthority::from_locked_conversation(&parts.aggregate)?;
        let authority = recovery_expiry_plan_authority(
            &parts.execution_package,
            parts.request_id,
            parts.terminal_at,
            parts.observed_at,
            parts.locked_read_set_digest,
        )?;
        let transition = plan_leaf_recovery_expiry_inner(parts.aggregate.state(), &authority)?
            .bind_recovery_expiry_authority(
                authority,
                parts.aggregate.head(),
                parts.execution_package,
            )?;
        let terminal_at = ServerTimestamp::from_unix_millis(parts.terminal_at.timestamp_millis())?;
        let (scope_authority, completion, prewrite) = parts.prelude.into_recovery_execution_parts();
        Ok(PlannedClientRecoveryExpiry {
            transition,
            scope_authority,
            completion,
            prewrite,
            recovery_request_id: parts.request_id,
            terminal_at,
            persistence_witness: parts.persistence_witness,
            post_apply_error: parts.post_apply_error,
        })
    }

    pub(crate) fn plan_scheduler_recovery_expiry_input(
        input: RecoverySchedulerExpiryPlanInput,
    ) -> Result<PlannedSchedulerRecoveryExpiry, StateMachineError> {
        let parts = input
            .into_planner_parts()
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        HydrationAuthority::from_locked_conversation(&parts.aggregate)?;
        let authority = recovery_expiry_plan_authority(
            &parts.execution_package,
            parts.request_id,
            parts.terminal_at,
            parts.observed_at,
            parts.locked_read_set_digest,
        )?;
        let transition = plan_leaf_recovery_expiry_inner(parts.aggregate.state(), &authority)?
            .bind_recovery_expiry_authority(
                authority,
                parts.aggregate.head(),
                parts.execution_package,
            )?;
        Ok(PlannedSchedulerRecoveryExpiry {
            transition,
            recovery_request_id: parts.request_id,
            terminal_at: ServerTimestamp::from_unix_millis(parts.terminal_at.timestamp_millis())?,
            persistence_witness: parts.persistence_witness,
        })
    }

    /// Authenticate and exact-bind one signed Welcome endpoint request before
    /// acting on the repository's closed pending/terminal classification.
    pub(crate) fn compose_welcome_terminal(
        &self,
        locked: &LockedConversationStateGuard,
        envelope: DurableSignedRequestEnvelope,
        mutation: VerifiedSignedMutation,
        registration: LockedRegistrationProjection,
        classification: LockedWelcomeTerminal,
    ) -> Result<WelcomeTerminalPlan, StateMachineError> {
        match classification {
            LockedWelcomeTerminal::PendingNotDue(guard) => {
                let plan = match mutation.kind() {
                    SignedMutationKind::WelcomeAcknowledgement => self
                        .plan_welcome_acknowledgement_entry(
                            locked,
                            envelope,
                            mutation,
                            registration,
                            guard,
                        )?,
                    SignedMutationKind::WelcomeRejection => self.plan_welcome_rejection_entry(
                        locked,
                        envelope,
                        mutation,
                        registration,
                        guard,
                    )?,
                    _ => return Err(StateMachineError::InvalidHydrationAuthority),
                };
                Ok(WelcomeTerminalPlan::Planned(plan))
            }
            LockedWelcomeTerminal::PendingDue(guard) => {
                let evidence = self.signed_request(envelope, mutation)?;
                if !registration.authorizes(&evidence)
                    || registration.transaction_id() != locked.head().transaction_id()
                    || registration.transaction_id() != guard.transaction_id()
                    || registration.trusted_read_at() != evidence.received_at()
                    || ServerTimestamp::from_unix_millis(guard.locked_at().timestamp_millis())?
                        != evidence.received_at()
                    || !welcome_endpoint_matches(
                        &evidence,
                        guard.welcome_id().as_bytes(),
                        guard.recipient_did().as_bytes(),
                        guard.recipient_device_id().as_bytes(),
                        guard.coordinate(),
                        guard.transition_seq(),
                    )
                {
                    return Err(StateMachineError::InvalidHydrationAuthority);
                }
                Ok(WelcomeTerminalPlan::DueExpiry(
                    self.plan_welcome_expiry_entry(locked, guard)?,
                ))
            }
            terminal => {
                let mutation_kind = mutation.kind();
                // Brief L223 / L103: a terminal `Rejected` classification
                // historically reverifies the retained reason independent of
                // signature. Capture the new request's closed reason BEFORE
                // `signed_request` consumes `mutation`, so the reason-binding
                // check below cannot fall back on signature-byte comparison.
                let new_rejection_reason: Option<String> = match mutation_kind {
                    SignedMutationKind::WelcomeRejection => match mutation.projection() {
                        VerifiedMutationProjection::WelcomeRejection(value) => {
                            match value.body().get("reason") {
                                Some(CanonicalValueRef::Text(text)) => Some((*text).to_owned()),
                                _ => None,
                            }
                        }
                        _ => None,
                    },
                    _ => None,
                };
                let accepted_wrapper = mutation
                    .accepted_wrapper_bytes()
                    .ok_or(StateMachineError::InvalidHydrationAuthority)?
                    .to_vec();
                let transcript = mutation.transcript_bytes().to_vec();
                let request_digest = *mutation.request_digest();
                let signature = *mutation.signature();
                let evidence = self.signed_request(envelope, mutation)?;
                let (
                    transaction_id,
                    locked_at,
                    row,
                    stored_authorization,
                    stored_kind,
                    stored_reason,
                ) = match &terminal {
                    LockedWelcomeTerminal::Acknowledged {
                        transaction_id,
                        locked_at,
                        row,
                        authorization,
                        ..
                    } => (
                        transaction_id,
                        *locked_at,
                        row,
                        Some(authorization),
                        Some(RequestEntryKind::WelcomeAcknowledgement),
                        None,
                    ),
                    LockedWelcomeTerminal::Rejected {
                        transaction_id,
                        locked_at,
                        row,
                        authorization,
                        reason,
                        ..
                    } => (
                        transaction_id,
                        *locked_at,
                        row,
                        Some(authorization),
                        Some(RequestEntryKind::WelcomeRejection),
                        Some(reason.as_str()),
                    ),
                    LockedWelcomeTerminal::Expired {
                        transaction_id,
                        locked_at,
                        row,
                        ..
                    }
                    | LockedWelcomeTerminal::SupersededByTransition {
                        transaction_id,
                        locked_at,
                        row,
                        ..
                    }
                    | LockedWelcomeTerminal::SupersededByRevocation {
                        transaction_id,
                        locked_at,
                        row,
                        ..
                    } => (transaction_id, *locked_at, row, None, None, None),
                    LockedWelcomeTerminal::PendingNotDue(_)
                    | LockedWelcomeTerminal::PendingDue(_) => unreachable!(),
                };
                if !registration.authorizes(&evidence)
                    || registration.transaction_id() != locked.head().transaction_id()
                    || registration.transaction_id() != transaction_id
                    || registration.trusted_read_at() != evidence.received_at()
                    || ServerTimestamp::from_unix_millis(locked_at.timestamp_millis())?
                        != evidence.received_at()
                    || !welcome_endpoint_matches(
                        &evidence,
                        &row.welcome_id,
                        row.recipient.principal().as_bytes(),
                        row.recipient.device_id(),
                        &row.coordinate,
                        row.transition_seq,
                    )
                {
                    return Err(StateMachineError::InvalidHydrationAuthority);
                }
                let exact_replay = stored_kind == Some(evidence.kind())
                    && stored_authorization.is_some_and(|stored| {
                        stored.signed_request_bytes() == accepted_wrapper
                            && stored.signing_transcript_bytes() == transcript
                            && stored.request_digest() == &request_digest
                            && stored.signature() == &signature
                    });
                // Minimal reason-binding check (brief L56/L103/L223): a
                // terminal `Rejected` classification historically reverifies
                // the retained reason independent of signature. A re-signed
                // rejection carrying a DIFFERENT valid reason is a changed
                // authorization, not a terminal replay; the compositor rejects
                // it before returning a terminal classification rather than
                // letting the handler/idempotency layer treat it as replay.
                // The check only fires against a stored Rejection terminal +
                // a fresh WelcomeRejection request; a stored Acknowledgement
                // terminal stays a (changed) replay classification regardless.
                if mutation_kind == SignedMutationKind::WelcomeRejection
                    && stored_kind == Some(RequestEntryKind::WelcomeRejection)
                    && stored_reason != new_rejection_reason.as_deref()
                {
                    return Err(StateMachineError::InvalidHydrationAuthority);
                }
                Ok(WelcomeTerminalPlan::Terminal {
                    classification: terminal,
                    exact_replay,
                })
            }
        }
    }

    /// Consume a signed, non-control Welcome acknowledgement together with
    /// the recipient's active registration and the exact Pending Welcome row.
    pub(crate) fn plan_welcome_acknowledgement_entry(
        &self,
        locked: &LockedConversationStateGuard,
        envelope: DurableSignedRequestEnvelope,
        mutation: VerifiedSignedMutation,
        registration: LockedRegistrationProjection,
        welcome_guard: LockedWelcomeGuard,
    ) -> Result<PlannedTransition, StateMachineError> {
        self.plan_welcome_response_entry(
            locked,
            envelope,
            mutation,
            registration,
            welcome_guard,
            RequestEntryKind::WelcomeAcknowledgement,
            WelcomeStatus::Acknowledged,
        )
    }

    /// Consume a signed, non-control Welcome rejection under the same exact
    /// row/registration authority used by acknowledgement.
    pub(crate) fn plan_welcome_rejection_entry(
        &self,
        locked: &LockedConversationStateGuard,
        envelope: DurableSignedRequestEnvelope,
        mutation: VerifiedSignedMutation,
        registration: LockedRegistrationProjection,
        welcome_guard: LockedWelcomeGuard,
    ) -> Result<PlannedTransition, StateMachineError> {
        self.plan_welcome_response_entry(
            locked,
            envelope,
            mutation,
            registration,
            welcome_guard,
            RequestEntryKind::WelcomeRejection,
            WelcomeStatus::Rejected,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::chat_protocol::state_machine) fn plan_welcome_response_entry(
        &self,
        locked: &LockedConversationStateGuard,
        envelope: DurableSignedRequestEnvelope,
        mutation: VerifiedSignedMutation,
        registration: LockedRegistrationProjection,
        welcome_guard: LockedWelcomeGuard,
        expected_kind: RequestEntryKind,
        successor_status: WelcomeStatus,
    ) -> Result<PlannedTransition, StateMachineError> {
        self.require_same_locked_conversation(locked)?;
        let prior = locked.state();
        let head = locked.head();
        let evidence = self.signed_request(envelope, mutation)?;
        if evidence.kind != expected_kind
            || !registration.authorizes(&evidence)
            || registration.transaction_id() != head.transaction_id()
            || registration.transaction_id() != welcome_guard.transaction_id()
            || registration.trusted_read_at() != evidence.received_at
            || ServerTimestamp::from_unix_millis(welcome_guard.locked_at().timestamp_millis())?
                != evidence.received_at
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let welcome_cas = welcome_cas_from_guard(prior, &welcome_guard, successor_status)?;
        let transaction_id = registration.transaction_id().to_owned();
        let trusted_read_at = registration.trusted_read_at();
        let authority = evidence.clone();
        plan_welcome_response(prior, evidence, successor_status)?
            .bind_non_control_request_authority(authority, head, &transaction_id, trusted_read_at)?
            .bind_welcome_cas(welcome_cas)
    }

    /// Expiry workers must first identify a due row, then lock the
    /// conversation/head and that exact Pending Welcome in canonical order.
    /// The consumed guard proves both due time and immutable delivery bytes;
    /// there is no direct SQL writer outside this state-machine route.
    pub(crate) fn plan_welcome_expiry_entry(
        &self,
        locked: &LockedConversationStateGuard,
        welcome_guard: LockedWelcomeGuard,
    ) -> Result<PlannedTransition, StateMachineError> {
        self.require_same_locked_conversation(locked)?;
        let prior = locked.state();
        let head = locked.head();
        if head.transaction_id() != welcome_guard.transaction_id()
            || head.locked_at() != welcome_guard.locked_at()
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let welcome_cas = welcome_cas_from_guard(prior, &welcome_guard, WelcomeStatus::Expired)?;
        let observed_at =
            ServerTimestamp::from_unix_millis(welcome_guard.locked_at().timestamp_millis())?;
        if observed_at < welcome_cas.expires_at {
            return Err(StateMachineError::WorkExpired);
        }
        let authority = WelcomeExpiryAuthority {
            welcome_id: welcome_cas.welcome_id,
            recipient: welcome_cas.recipient.clone(),
            coordinate: welcome_cas.coordinate,
            transition_seq: welcome_cas.transition_seq,
            terminal_at: welcome_cas.expires_at,
            observed_at,
            locked_row_digest: welcome_cas.locked_row_digest,
        };
        plan_welcome_expiry(prior, welcome_cas.welcome_id)?
            .bind_welcome_expiry_authority(authority, head, welcome_guard.transaction_id())?
            .bind_welcome_cas(welcome_cas)
    }

    pub(crate) fn device_revocation(
        &self,
        mutation: VerifiedSignedMutation,
        accepted_at: &TrustedRequestInstant,
    ) -> Result<DeviceRevocationEvidence, StateMachineError> {
        Self::device_revocation_at(
            mutation,
            ServerTimestamp::from_trusted_request_instant(accepted_at)?,
        )
    }

    pub(in crate::chat_protocol::state_machine) fn device_revocation_at(
        mutation: VerifiedSignedMutation,
        accepted_at: ServerTimestamp,
    ) -> Result<DeviceRevocationEvidence, StateMachineError> {
        let body = match mutation.projection() {
            VerifiedMutationProjection::DeviceRevocation(value) => value.body(),
            _ => return Err(StateMachineError::InvalidHydrationAuthority),
        };
        let actor = DeviceIdentity::new(
            PrincipalId::new(mutation.actor_did().as_str().as_bytes().to_vec())?,
            *mutation.actor_device_id().as_bytes(),
        )?;
        let target = DeviceIdentity::new(
            actor.principal().clone(),
            closed_uuid(&body, "targetDeviceId")?,
        )?;
        let expected_target_auth_generation = closed_integer(&body, "targetAuthGeneration")?;
        let revocation_id = closed_uuid(&body, "idempotencyKey")?;
        let actor_key_id: [u8; 32] = URL_SAFE_NO_PAD
            .decode(mutation.key_id().as_str())
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?
            .try_into()
            .map_err(|_| StateMachineError::InvalidHydrationAuthority)?;
        let signed_at = canonical_server_timestamp(mutation.signed_at())?;
        let signed_request_bytes = mutation
            .accepted_wrapper_bytes()
            .filter(|bytes| !bytes.is_empty())
            .ok_or(StateMachineError::InvalidHydrationAuthority)?
            .to_vec();
        if expected_target_auth_generation == 0
            || expected_target_auth_generation > MAX_PROTOCOL_INTEGER
        {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        let mut evidence = DeviceRevocationEvidence {
            revocation_id,
            actor,
            target,
            actor_key_id,
            actor_auth_generation: mutation.auth_generation(),
            expected_target_auth_generation,
            signed_at,
            accepted_at,
            request_digest: *mutation.request_digest(),
            signature: *mutation.signature(),
            signed_request_bytes,
            signing_transcript_bytes: mutation.transcript_bytes().to_vec(),
            durable_row_digest: [0; 32],
        };
        evidence.durable_row_digest = device_revocation_row_digest(&evidence);
        if !validate_device_revocation_evidence(&evidence) {
            return Err(StateMachineError::InvalidHydrationAuthority);
        }
        Ok(evidence)
    }
}
