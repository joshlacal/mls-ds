#![allow(unused_imports)]
use super::*;

/// Apply an entry-less `leafRecoveryRequest` internal op. The coordinate and
/// seq counter are UNCHANGED (the head CAS is a prior-coordinate verify); it
/// opens the `add`/`replace` recovery request + reservation and reserves the
/// requester's key package, all bound to the CURRENT coordinate. No entry, no
/// transition, no generation state, no participant change.
#[allow(clippy::too_many_arguments)]
pub(in crate::chat_protocol::state_machine::executor) async fn apply_leaf_recovery_request(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &ConversationPersistencePlan,
    ctx: &ExecutionContext,
    conversation_id: Uuid,
    generation: i64,
    state_version: i64,
    _epoch: i64,
    recovery_write_authority: Option<
        &crate::chat_protocol::repository::recovery::RecoveryExecutorWriteAuthority<'_>,
    >,
) -> Result<AppliedTransition, ExecutorError> {
    let effects = plan.effects();
    #[cfg(test)]
    let applied_at = ctx.applied_at;
    let head = effects
        .head_cas()
        .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
    let expected_prior = head
        .expected_prior()
        .ok_or(ExecutorError::InconsistentPlan(
            "leaf recovery request needs a prior",
        ))?;
    let expected_generation = checked_i64(expected_prior.generation())?;
    let expected_state_version = checked_i64(expected_prior.state_version())?;
    let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;
    let successor_next_entry_seq = checked_i64(head.successor_next_entry_seq())?;

    // Internal op: only a new open recovery request + its reservation + the
    // Available->Reserved package edge. Everything else must be empty.
    reject_if_present("participant_changes", effects.participant_changes())?;
    reject_if_present("leaf_changes", effects.leaf_changes())?;
    reject_if_present("interval_changes", effects.interval_changes())?;
    reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
    reject_if_present("reset_request_changes", effects.reset_request_changes())?;
    reject_if_present("leave_request_changes", effects.leave_request_changes())?;
    reject_if_present("welcome_changes", effects.welcome_changes())?;
    reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
    if effects.metadata_change().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "leaf recovery request metadata change",
        ));
    }
    if effects.revocation_target_cas().is_some()
        || effects.welcome_cas().is_some()
        || effects.invitation_quota_cas().is_some()
    {
        return Err(ExecutorError::UnsupportedEffect(
            "leaf recovery request revocation/welcome/quota CAS",
        ));
    }
    // Internal op MUST NOT change the coordinate or advance the seq counter
    // (E2b-6b review MINOR-2: the head CAS is a pure prior-coordinate verify).
    if successor_next_entry_seq != expected_next_entry_seq {
        return Err(ExecutorError::InconsistentPlan(
            "leaf recovery request must not advance the seq counter",
        ));
    }
    if generation != expected_generation || state_version != expected_state_version {
        return Err(ExecutorError::InconsistentPlan(
            "leaf recovery request must not change the coordinate",
        ));
    }

    let recovery = effects
        .recovery_request_changes()
        .iter()
        .find_map(|change| match (change.before(), change.after()) {
            (None, Some(after)) => Some(after),
            _ => None,
        })
        .ok_or(ExecutorError::InconsistentPlan(
            "leaf recovery request adds no open recovery request",
        ))?;
    if effects.recovery_request_changes().len() != 1
        || effects.reservation_changes().len() != 1
        || effects.package_transitions().len() != 1
    {
        return Err(ExecutorError::InconsistentPlan(
            "leaf recovery request must add exactly one request + reservation + package edge",
        ));
    }
    verify_recovery_package_consistency(
        effects,
        recovery.key_package_ref(),
        PackageStatus::Available,
        PackageStatus::Reserved,
    )?;

    // 1. The repository-owned exact package/request/reservation witness is
    //    the first durable mutation for production Recovery. The test-only
    //    raw executor seam retains its legacy reconstruction path.
    #[cfg(not(test))]
    recovery_write_authority
        .ok_or(ExecutorError::MissingContext(
            "missing validated Recovery executor write authority",
        ))?
        .apply_open(transaction)
        .await?;
    #[cfg(test)]
    if let Some(authority) = recovery_write_authority {
        authority.apply_open(transaction).await?;
    }

    // 2. Head CAS VERIFY — coordinate and seq counter both UNCHANGED
    //    (successor == expected on every column). A drifted head is a typed
    //    conflict; a matched head is a no-op update that pins the read.
    transition::cas_conversation_head(
        transaction,
        &transition::ConversationHeadCas {
            conversation_id,
            expected_generation,
            expected_state_version,
            expected_next_entry_seq,
            successor_generation: generation,
            successor_state_version: state_version,
            successor_next_entry_seq,
            close: None,
        },
    )
    .await?;

    #[cfg(test)]
    if recovery_write_authority.is_none() {
        write_recovery_open(transaction, ctx, recovery, conversation_id, applied_at).await?;
    }

    // 3. No control entry (internal op) -> no entry recipients; only events.
    let event_positions = write_events(transaction, ctx, None).await?;

    Ok(AppliedTransition {
        // No control entry / seq was allocated; echo the unchanged counter.
        allocated_seq: u64::try_from(successor_next_entry_seq).unwrap(),
        entry_id: ctx.entry().entry_id,
        event_positions,
        successor_coordinate: plan.successor_coordinate().copied(),
    })
}

pub(in crate::chat_protocol::state_machine::executor) fn terminal_welcome_context_is_closed(
    ctx: &ExecutionContext,
    response: bool,
) -> Result<(), ExecutorError> {
    if !ctx.opened_leaves.is_empty()
        || ctx.metadata_author.is_some()
        || !ctx.participant_period_ids.is_empty()
        || !ctx.leaf_period_ids.is_empty()
        || !ctx.entry_recipients.is_empty()
        || !ctx.events.is_empty()
        || !ctx.closing_leaf_periods.is_empty()
        || !ctx.closing_participant_periods.is_empty()
        || ctx.reset_request_row.is_some()
        || ctx.recovery_open.is_some()
        || !ctx.welcome_dispositions.is_empty()
        || (response && ctx.welcome_expiry.is_some())
        || (!response && ctx.welcome_response.is_some())
    {
        return Err(ExecutorError::InconsistentPlan(
            "Welcome terminal context carries an unrelated family",
        ));
    }
    Ok(())
}

pub(in crate::chat_protocol::state_machine::executor) fn exact_welcome_actor_role(
    plan: &ConversationPersistencePlan,
    actor: &DeviceIdentity,
) -> Result<TransitionActorRole, ExecutorError> {
    let participant = plan
        .state()
        .participants
        .iter()
        .find(|participant| participant.principal == *actor.principal())
        .ok_or(ExecutorError::InconsistentPlan(
            "Welcome actor has no exact participant role",
        ))?;
    Ok(match participant.role {
        ParticipantRole::Member => TransitionActorRole::Member,
        ParticipantRole::Admin => TransitionActorRole::Admin,
    })
}

pub(in crate::chat_protocol::state_machine::executor) fn repository_welcome_rejection_reason(
    value: &str,
) -> Option<WelcomeRejectionReason> {
    match value {
        "noMatchingKeyPackage" => Some(WelcomeRejectionReason::NoMatchingKeyPackage),
        "invalidWelcome" => Some(WelcomeRejectionReason::InvalidWelcome),
        "unsupportedCipherSuite" => Some(WelcomeRejectionReason::UnsupportedCipherSuite),
        "coordinateMismatch" => Some(WelcomeRejectionReason::CoordinateMismatch),
        "localStateConflict" => Some(WelcomeRejectionReason::LocalStateConflict),
        _ => None,
    }
}

pub(in crate::chat_protocol::state_machine::executor) async fn preflight_welcome_terminal_event(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ctx: &ExecutionContext,
    event: &EventFanout,
    welcome_id: Uuid,
    status: &str,
    recipient: &DeviceIdentity,
) -> Result<(), ExecutorError> {
    let protocol_instance_id: Uuid = sqlx::query_scalar(
        "SELECT protocol_instance_id FROM chat.protocol_instances \
             WHERE singleton FOR SHARE",
    )
    .fetch_one(&mut **transaction)
    .await
    .map_err(DeliveryRepositoryError::from)?;
    if ctx.protocol_instance_id != protocol_instance_id
        || !crate::chat_protocol::state_machine::is_uuid_v4(event.event_id.as_bytes())
        || event.event_kind != EventKind::WelcomeDisposition
        || event.payload_bytes
            != delivery::canonical_welcome_disposition_event_payload(welcome_id, status)
        || event.recipients.len() != 1
        || event.recipients[0].0 != *recipient
        || event.recipients[0].1 != EventEntitlementKind::Welcome
        || event.outbox.len() != 1
        || !crate::chat_protocol::state_machine::is_uuid_v4(event.outbox[0].0.as_bytes())
        || event.outbox[0].1 != OutboxWorkKind::Stream
    {
        return Err(ExecutorError::InconsistentPlan(
            "Welcome terminal event context is not exact",
        ));
    }
    let current_predecessor: Option<i64> = sqlx::query_scalar(
        "SELECT max(event_position) FROM chat.event_recipients \
             WHERE user_did=$1 AND device_id=$2",
    )
    .bind(device_did(recipient)?)
    .bind(device_uuid(recipient))
    .fetch_one(&mut **transaction)
    .await
    .map_err(DeliveryRepositoryError::from)?;
    if event.recipients[0].2 != current_predecessor {
        return Err(ExecutorError::InconsistentPlan(
            "Welcome terminal event predecessor is stale",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(in crate::chat_protocol::state_machine::executor) async fn preflight_welcome_response_execution_context(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &ConversationPersistencePlan,
    ctx: &ExecutionContext,
    head: &crate::chat_protocol::state_machine::ConversationHeadCasBinding,
    welcome_cas: &crate::chat_protocol::state_machine::WelcomeCasBinding,
    responded: &WelcomeWork,
    response: &WelcomeResponseContext,
    successor_status: WelcomeStatus,
) -> Result<(), ExecutorError> {
    terminal_welcome_context_is_closed(ctx, true)?;
    let expected_kind = match successor_status {
        WelcomeStatus::Acknowledged => {
            crate::chat_protocol::state_machine::RequestEntryKind::WelcomeAcknowledgement
        }
        WelcomeStatus::Rejected => {
            crate::chat_protocol::state_machine::RequestEntryKind::WelcomeRejection
        }
        _ => {
            return Err(ExecutorError::InconsistentPlan(
                "Welcome response has an invalid successor",
            ))
        }
    };
    let evidence = match plan.effects().authority() {
        Some(PlanAuthority::Request(evidence)) => evidence,
        _ => {
            return Err(ExecutorError::InconsistentPlan(
                "Welcome response lacks request authority",
            ))
        }
    };
    crate::chat_protocol::state_machine::validate_request_evidence(
        evidence,
        expected_kind,
        welcome_cas.conversation_id(),
        responded.welcome_id(),
        responded.recipient(),
        evidence.received_at,
    )
    .map_err(|_| ExecutorError::InconsistentPlan("Welcome response request evidence is invalid"))?;
    let signed = evidence
        .authority
        .as_ref()
        .ok_or(ExecutorError::MissingContext(
            "authenticated Welcome request evidence",
        ))?;
    let signed_reason = match evidence.body_binding.as_ref() {
        Some(crate::chat_protocol::state_machine::RequestBodyBinding::WelcomeResponse {
            coordinates,
            transition_seq,
            rejection_reason,
        }) if coordinates == responded.coordinate()
            && *transition_seq == responded.transition_seq()
            && crate::chat_protocol::state_machine::welcome_response_reason_matches(
                expected_kind,
                rejection_reason.as_deref(),
            ) =>
        {
            rejection_reason.as_deref()
        }
        _ => {
            return Err(ExecutorError::InconsistentPlan(
                "Welcome response body binding is invalid",
            ))
        }
    };
    let expected_applied_at = server_instant(evidence.received_at)?;
    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await
        .map_err(DeliveryRepositoryError::from)?;
    if transaction_id != head.transaction_id()
        || transaction_id != welcome_cas.transaction_id()
        || head.conversation_id() != welcome_cas.conversation_id()
        || head.expected_prior() != Some(responded.coordinate())
        || head.allocated_entry_id().is_some()
        || head.allocated_seq().is_some()
        || head.expected_next_entry_seq() != head.successor_next_entry_seq()
        || head.locked_at() != evidence.received_at
        || head.locked_at() != welcome_cas.locked_at()
        || head.locked_head_digest() == &[0; 32]
        || welcome_cas.locked_row_digest() == &[0; 32]
        || ctx.applied_at != expected_applied_at
        || ctx.applied_at != server_instant(welcome_cas.locked_at())?
    {
        return Err(ExecutorError::InconsistentPlan(
            "Welcome response transaction/head authority is inconsistent",
        ));
    }
    let entry = match &ctx.authority {
        ExecutionAuthority::ControlEntry(entry) => entry,
        ExecutionAuthority::Entryless { .. } => {
            return Err(ExecutorError::MissingContext(
                "signed Welcome response execution authority",
            ))
        }
    };
    let expected_actor_did = device_did(evidence.actor())?;
    if entry.entry_id.as_bytes() != evidence.request_id()
        || entry.entry_kind != signed.type_id()
        || entry.accepted_payload_bytes != signed.signed_request_bytes()
        || entry.accepted_payload_bytes != evidence.signed_request_bytes
        || entry.accepted_payload_sha256.as_slice()
            != sha2::Sha256::digest(&entry.accepted_payload_bytes).as_slice()
        || entry.signed_request_bytes != signed.signed_request_bytes()
        || entry.unsigned_projection_bytes != signed.canonical_projection()
        || entry.signing_transcript_bytes != signed.transcript_bytes()
        || entry.request_digest != signed.request_digest()
        || entry.signature != signed.signature()
        || !entry.server_fields_bytes.is_empty()
        || entry.outer_entry_fingerprint != evidence.durable_row_digest()
        || ctx.actor.user_did != expected_actor_did
        || ctx.actor.device_id != device_uuid(evidence.actor())
        || ctx.actor.key_id != URL_SAFE_NO_PAD.encode(signed.key_id())
        || u64::try_from(ctx.actor.auth_generation).ok() != Some(signed.auth_generation())
        || ctx.actor.role != exact_welcome_actor_role(plan, evidence.actor())?
        || ctx.actor.device_status != "active"
    {
        return Err(ExecutorError::InconsistentPlan(
            "Welcome response execution authority/context drifted",
        ));
    }
    match successor_status {
        WelcomeStatus::Acknowledged if response.rejection.is_none() => {}
        WelcomeStatus::Rejected => {
            let rejection = response
                .rejection
                .as_ref()
                .ok_or(ExecutorError::MissingContext(
                    "welcome rejection recovery work",
                ))?;
            if !crate::chat_protocol::state_machine::is_uuid_v4(
                rejection.recovery_work_id.as_bytes(),
            ) || signed_reason.and_then(repository_welcome_rejection_reason)
                != Some(rejection.reason)
            {
                return Err(ExecutorError::InconsistentPlan(
                    "Welcome rejection work is not bound to the signed reason",
                ));
            }
        }
        WelcomeStatus::Acknowledged => {
            return Err(ExecutorError::InconsistentPlan(
                "welcome acknowledgement must not carry rejection recovery work",
            ))
        }
        _ => unreachable!("successor status checked above"),
    }
    let status = match successor_status {
        WelcomeStatus::Acknowledged => "acknowledged",
        WelcomeStatus::Rejected => "rejected",
        _ => unreachable!("successor status checked above"),
    };
    preflight_welcome_terminal_event(
        transaction,
        ctx,
        &response.event,
        Uuid::from_bytes(*responded.welcome_id()),
        status,
        responded.recipient(),
    )
    .await
}

pub(in crate::chat_protocol::state_machine::executor) async fn preflight_welcome_expiry_execution_context(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &ConversationPersistencePlan,
    ctx: &ExecutionContext,
    head: &crate::chat_protocol::state_machine::ConversationHeadCasBinding,
    welcome_cas: &crate::chat_protocol::state_machine::WelcomeCasBinding,
    expired: &WelcomeWork,
    expiry: &WelcomeExpiryContext,
) -> Result<(), ExecutorError> {
    terminal_welcome_context_is_closed(ctx, false)?;
    let evidence = match plan.effects().authority() {
        Some(PlanAuthority::WelcomeExpiry(evidence)) => evidence,
        _ => {
            return Err(ExecutorError::InconsistentPlan(
                "Welcome expiry lacks expiry authority",
            ))
        }
    };
    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await
        .map_err(DeliveryRepositoryError::from)?;
    if transaction_id != head.transaction_id()
        || transaction_id != welcome_cas.transaction_id()
        || head.conversation_id() != welcome_cas.conversation_id()
        || head.expected_prior() != Some(expired.coordinate())
        || head.allocated_entry_id().is_some()
        || head.allocated_seq().is_some()
        || head.expected_next_entry_seq() != head.successor_next_entry_seq()
        || head.locked_at() != evidence.observed_at()
        || head.locked_at() != welcome_cas.locked_at()
        || head.locked_head_digest() == &[0; 32]
        || welcome_cas.locked_row_digest() == &[0; 32]
        || evidence.welcome_id() != expired.welcome_id()
        || evidence.recipient() != expired.recipient()
        || evidence.coordinate() != expired.coordinate()
        || evidence.transition_seq() != expired.transition_seq()
        || evidence.terminal_at() != expired.expires_at()
        || evidence.observed_at() < evidence.terminal_at()
        || evidence.locked_row_digest() != welcome_cas.locked_row_digest()
        || ctx.applied_at != server_instant(evidence.terminal_at())?
        || ctx.operation_id().as_bytes() != evidence.welcome_id()
        || ctx.actor.user_did != device_did(evidence.recipient())?
        || ctx.actor.device_id != device_uuid(evidence.recipient())
        || ctx.actor.role != exact_welcome_actor_role(plan, evidence.recipient())?
        || !crate::chat_protocol::state_machine::is_uuid_v4(expiry.recovery_work_id.as_bytes())
    {
        return Err(ExecutorError::InconsistentPlan(
            "Welcome expiry authority/context drifted",
        ));
    }
    preflight_welcome_terminal_event(
        transaction,
        ctx,
        &expiry.event,
        Uuid::from_bytes(*expired.welcome_id()),
        "expired",
        expired.recipient(),
    )
    .await
}

/// Apply an entry-less `welcomeExpiry` op: a server-observed pending Welcome
/// past its `expires_at` is terminalized `expired` and a `welcomeExpired`
/// `recovery_work_items` row is created so the recipient can be re-added later.
/// Coordinate + seq counter UNCHANGED (a pure prior-coordinate verify). NO
/// entry, transition, or membership change. Both the disposition `terminal_at`
/// and the recovery-work `created_at` are the welcome's OWN `expires_at` (the DB
/// `welcome_deliveries.terminal_at = expires_at` and `recovery_work_items.created_at
/// = disposition_terminal_at` cross-checks), NOT `applied_at`; the recovery-work
/// coordinate is the welcome's OWN bound coordinate.
pub(in crate::chat_protocol::state_machine::executor) async fn apply_welcome_expiry(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &ConversationPersistencePlan,
    ctx: &ExecutionContext,
    conversation_id: Uuid,
    generation: i64,
    state_version: i64,
    _epoch: i64,
) -> Result<AppliedTransition, ExecutorError> {
    let effects = plan.effects();
    let head = effects
        .head_cas()
        .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
    let expected_prior = head
        .expected_prior()
        .ok_or(ExecutorError::InconsistentPlan(
            "welcome expiry needs an expected prior",
        ))?;
    let expected_generation = checked_i64(expected_prior.generation())?;
    let expected_state_version = checked_i64(expected_prior.state_version())?;
    let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;
    let successor_next_entry_seq = checked_i64(head.successor_next_entry_seq())?;

    // Only a welcome delivery CAS (Pending -> Expired). Reject every other family.
    reject_if_present("participant_changes", effects.participant_changes())?;
    reject_if_present("leaf_changes", effects.leaf_changes())?;
    reject_if_present("interval_changes", effects.interval_changes())?;
    reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
    reject_if_present(
        "recovery_request_changes",
        effects.recovery_request_changes(),
    )?;
    reject_if_present("reservation_changes", effects.reservation_changes())?;
    reject_if_present("reset_request_changes", effects.reset_request_changes())?;
    reject_if_present("leave_request_changes", effects.leave_request_changes())?;
    reject_if_present("package_transitions", effects.package_transitions())?;
    reject_if_present("recovery_package_cas", effects.recovery_package_cas())?;
    reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
    if effects.metadata_change().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "welcome expiry metadata change",
        ));
    }
    if effects.revocation_target_cas().is_some() || effects.invitation_quota_cas().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "welcome expiry revocation/quota CAS",
        ));
    }
    // A `welcomeExpiry` is the ONE kind that carries `welcome_cas` (the
    // authoritative pending-only CAS binding). The `welcome_changes` delta drives
    // the write; the CAS binding is a LOAD-BEARING witness validated against that
    // delta below (welcome id, recipient, bound coordinate, expiry instant, and
    // the Pending->Expired direction must all agree).
    let welcome_cas = effects
        .welcome_cas()
        .ok_or(ExecutorError::InconsistentPlan(
            "welcome expiry plan missing welcome CAS binding",
        ))?;

    // Pure prior-coordinate verify: coordinate + seq counter UNCHANGED.
    if successor_next_entry_seq != expected_next_entry_seq {
        return Err(ExecutorError::InconsistentPlan(
            "welcome expiry must not advance the seq counter",
        ));
    }
    if generation != expected_generation || state_version != expected_state_version {
        return Err(ExecutorError::InconsistentPlan(
            "welcome expiry must not change the coordinate",
        ));
    }

    // Exactly one Pending -> Expired welcome change.
    if effects.welcome_changes().len() != 1 {
        return Err(ExecutorError::InconsistentPlan(
            "welcome expiry must change exactly one welcome",
        ));
    }
    let expired = effects
        .welcome_changes()
        .iter()
        .find_map(|change| match (change.before(), change.after()) {
            (Some(before), Some(after))
                if before.status() == WelcomeStatus::Pending
                    && after.status() == WelcomeStatus::Expired =>
            {
                Some(after)
            }
            _ => None,
        })
        .ok_or(ExecutorError::InconsistentPlan(
            "welcome expiry must expire a pending welcome",
        ))?;
    let welcome_id = Uuid::from_bytes(*expired.welcome_id());
    if ctx.operation_id() != welcome_id {
        return Err(ExecutorError::MissingContext(
            "exact Welcome expiry operation id",
        ));
    }
    let terminal_at = server_instant(expired.expires_at())?;
    let recipient = expired.recipient().clone();
    let welcome_coordinate = expired.coordinate();
    // Consume the CAS binding as load-bearing: it must bind exactly the pending
    // welcome the delta expires, AND the binding's domain-separated seal must
    // reaffirm every nonsemantic authority family (opaque digest, expiry,
    // locked instant, and locked-row digest) independent of the welcome_change
    // delta. A planner that disagreed, or a drifted binding that the
    // welcome_change delta alone does not surface, is a hard `InconsistentPlan`
    // raised before the head CAS verify or event insert — never a
    // silently-stale witness that first fails at the delivery writer.
    if welcome_cas.welcome_id() != expired.welcome_id()
        || welcome_cas.recipient() != &recipient
        || welcome_cas.coordinate() != welcome_coordinate
        || welcome_cas.expires_at() != expired.expires_at()
        || welcome_cas.expected_status() != WelcomeStatus::Pending
        || welcome_cas.successor_status() != WelcomeStatus::Expired
        || !welcome_cas.verify_seal()
    {
        return Err(ExecutorError::InconsistentPlan(
            "welcome expiry CAS binding disagrees with the welcome change",
        ));
    }
    let expiry = ctx
        .welcome_expiry
        .as_ref()
        .ok_or(ExecutorError::MissingContext("welcome expiry context"))?;
    preflight_welcome_expiry_execution_context(
        transaction,
        plan,
        ctx,
        head,
        welcome_cas,
        expired,
        expiry,
    )
    .await?;
    delivery::preflight_pending_welcome_terminal_cas(
        transaction,
        welcome_cas,
        &WelcomeDisposition::Expired,
        terminal_at,
    )
    .await?;

    // 1. Head CAS VERIFY (coordinate + seq counter both UNCHANGED).
    transition::cas_conversation_head(
        transaction,
        &transition::ConversationHeadCas {
            conversation_id,
            expected_generation,
            expected_state_version,
            expected_next_entry_seq,
            successor_generation: generation,
            successor_state_version: state_version,
            successor_next_entry_seq,
            close: None,
        },
    )
    .await?;

    // 2. Append the `welcomeDisposition` event. Its `created_at` MUST equal the
    //    welcome's `expires_at` (`assert_welcome_disposition_cas`:
    //    `event.created_at = delivery.terminal_at`), NOT `applied_at` — a welcome
    //    expiry is stamped at the deterministic `expires_at`, so this arm uses
    //    `terminal_at` throughout and never `applied_at`.
    let position = delivery::append_event(
        transaction,
        &NewEvent {
            event_id: expiry.event.event_id,
            event_kind: expiry.event.event_kind,
            payload_bytes: expiry.event.payload_bytes.clone(),
            created_at: terminal_at,
            protocol_instance_id: ctx.protocol_instance_id,
        },
    )
    .await?;
    let event_recipients = expiry
        .event
        .recipients
        .iter()
        .map(|(device, kind, predecessor)| {
            Ok(EventRecipient {
                user_did: device_did(device)?,
                device_id: device_uuid(device),
                entitlement_kind: *kind,
                audience_predecessor_position: *predecessor,
            })
        })
        .collect::<Result<Vec<_>, ExecutorError>>()?;
    delivery::insert_event_recipients(transaction, position, &event_recipients).await?;
    for (outbox_id, work_kind) in &expiry.event.outbox {
        delivery::enqueue_outbox(transaction, *outbox_id, position, *work_kind, terminal_at)
            .await?;
    }

    // 3. Terminalize the pending delivery `expired` at its `expires_at`.
    delivery::terminalize_welcome_delivery(
        transaction,
        welcome_cas,
        &WelcomeDisposition::Expired,
        terminal_at,
        position,
    )
    .await?;

    // 4. The `welcomeExpired` recovery work item (created_at == the disposition
    //    terminal_at; coordinate == the welcome's own bound coordinate).
    delivery::insert_recovery_work_item(
        transaction,
        &delivery::NewRecoveryWorkItem {
            recovery_work_id: expiry.recovery_work_id,
            conversation_id,
            recipient_did: device_did(&recipient)?,
            recipient_device_id: device_uuid(&recipient),
            source_kind: delivery::RecoveryWorkSourceKind::WelcomeExpired,
            source_id: welcome_id,
            generation: checked_i64(welcome_coordinate.generation())?,
            state_version: checked_i64(welcome_coordinate.state_version())?,
            created_at: terminal_at,
        },
    )
    .await?;

    Ok(AppliedTransition {
        // No control entry / seq was allocated; echo the unchanged counter.
        allocated_seq: u64::try_from(successor_next_entry_seq).unwrap(),
        entry_id: ctx.operation_id(),
        event_positions: vec![position],
        successor_coordinate: plan.successor_coordinate().copied(),
    })
}
