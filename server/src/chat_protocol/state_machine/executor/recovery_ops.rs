#![allow(unused_imports)]
use super::*;

/// Apply an entry-less `welcomeAcknowledgement` / `welcomeRejection`: a
/// client-authored signed disposition of a pending Welcome. Coordinate + seq
/// counter UNCHANGED (a pure prior-coordinate verify); NO entry / transition /
/// membership change. Terminalizes the delivery `acknowledged` (recipient
/// joined — NO recovery work) or `rejected` (adds a `welcomeRejected`
/// recovery-work item with the closed reason). The disposition row binds the
/// client's signed authorization (from `ctx.entry`). Unlike expiry, every
/// timestamp is the request instant `applied_at` (the client's action time,
/// which the DB requires `< expires_at`), so the disposition event uses
/// `applied_at` (`= terminal_at`). `welcome_cas` is validated load-bearing.
pub(in crate::chat_protocol::state_machine::executor) async fn apply_welcome_response(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &ConversationPersistencePlan,
    ctx: &ExecutionContext,
    conversation_id: Uuid,
    generation: i64,
    state_version: i64,
    _epoch: i64,
) -> Result<AppliedTransition, ExecutorError> {
    let effects = plan.effects();
    let applied_at = ctx.applied_at;
    let head = effects
        .head_cas()
        .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
    let expected_prior = head
        .expected_prior()
        .ok_or(ExecutorError::InconsistentPlan(
            "welcome response needs an expected prior",
        ))?;
    let expected_generation = checked_i64(expected_prior.generation())?;
    let expected_state_version = checked_i64(expected_prior.state_version())?;
    let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;
    let successor_next_entry_seq = checked_i64(head.successor_next_entry_seq())?;

    // Only a welcome delivery CAS. Reject every other family.
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
            "welcome response metadata change",
        ));
    }
    if effects.revocation_target_cas().is_some() || effects.invitation_quota_cas().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "welcome response revocation/quota CAS",
        ));
    }
    let welcome_cas = effects
        .welcome_cas()
        .ok_or(ExecutorError::InconsistentPlan(
            "welcome response plan missing welcome CAS binding",
        ))?;

    // Pure prior-coordinate verify: coordinate + seq counter UNCHANGED.
    if successor_next_entry_seq != expected_next_entry_seq {
        return Err(ExecutorError::InconsistentPlan(
            "welcome response must not advance the seq counter",
        ));
    }
    if generation != expected_generation || state_version != expected_state_version {
        return Err(ExecutorError::InconsistentPlan(
            "welcome response must not change the coordinate",
        ));
    }

    // Exactly one Pending -> {Acknowledged,Rejected} welcome change.
    if effects.welcome_changes().len() != 1 {
        return Err(ExecutorError::InconsistentPlan(
            "welcome response must change exactly one welcome",
        ));
    }
    let responded = effects
        .welcome_changes()
        .iter()
        .find_map(|change| match (change.before(), change.after()) {
            (Some(before), Some(after))
                if before.status() == WelcomeStatus::Pending
                    && matches!(
                        after.status(),
                        WelcomeStatus::Acknowledged | WelcomeStatus::Rejected
                    ) =>
            {
                Some(after)
            }
            _ => None,
        })
        .ok_or(ExecutorError::InconsistentPlan(
            "welcome response must acknowledge or reject a pending welcome",
        ))?;
    let successor_status = responded.status();
    let welcome_id = Uuid::from_bytes(*responded.welcome_id());
    let recipient = responded.recipient().clone();
    let welcome_coordinate = responded.coordinate();
    // Load-bearing welcome CAS validation (mirrors the expiry arm). The
    // binding's domain-separated seal re-affirms every nonsemantic authority
    // family (opaque digest, expiry, locked instant, locked-row digest)
    // independent of the welcome_change delta; a drifted binding that the
    // delta alone does not surface is rejected here, BEFORE the head CAS
    // verify or event insert, rather than first failing at the delivery
    // writer after the event/outbox row is already appended.
    if welcome_cas.welcome_id() != responded.welcome_id()
        || welcome_cas.recipient() != &recipient
        || welcome_cas.coordinate() != welcome_coordinate
        || welcome_cas.expires_at() != responded.expires_at()
        || welcome_cas.expected_status() != WelcomeStatus::Pending
        || welcome_cas.successor_status() != successor_status
        || !welcome_cas.verify_seal()
    {
        return Err(ExecutorError::InconsistentPlan(
            "welcome response CAS binding disagrees with the welcome change",
        ));
    }
    let response = ctx
        .welcome_response
        .as_ref()
        .ok_or(ExecutorError::MissingContext("welcome response context"))?;
    preflight_welcome_response_execution_context(
        transaction,
        plan,
        ctx,
        head,
        welcome_cas,
        responded,
        response,
        successor_status,
    )
    .await?;
    // The client-authored signed authorization the disposition row binds — the
    // signed request's bytes/digest/signature (the signature-shape trigger
    // requires them non-NULL for acknowledged/rejected).
    let authorization = WelcomeClientAuthorization {
        signed_request_bytes: ctx.entry().signed_request_bytes.clone(),
        signing_transcript_bytes: ctx.entry().signing_transcript_bytes.clone(),
        request_digest: ctx.entry().request_digest.clone(),
        signature: ctx.entry().signature.clone(),
    };
    // The disposition shape must match the successor status; a rejection carries
    // the recovery work, an acknowledgement must not.
    let (disposition, rejection_work): (WelcomeDisposition, Option<&WelcomeRejectionWork>) =
        match successor_status {
            WelcomeStatus::Acknowledged => {
                if response.rejection.is_some() {
                    return Err(ExecutorError::InconsistentPlan(
                        "welcome acknowledgement must not carry rejection recovery work",
                    ));
                }
                (WelcomeDisposition::Acknowledged { authorization }, None)
            }
            WelcomeStatus::Rejected => {
                let rejection =
                    response
                        .rejection
                        .as_ref()
                        .ok_or(ExecutorError::MissingContext(
                            "welcome rejection recovery work",
                        ))?;
                (
                    WelcomeDisposition::Rejected {
                        authorization,
                        reason: rejection.reason,
                    },
                    Some(rejection),
                )
            }
            _ => {
                return Err(ExecutorError::InconsistentPlan(
                    "welcome response status must be acknowledged or rejected",
                ))
            }
        };
    delivery::preflight_pending_welcome_terminal_cas(
        transaction,
        welcome_cas,
        &disposition,
        applied_at,
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

    // 2. Append the `welcomeDisposition` event. Its `created_at` (= applied_at)
    //    must equal the delivery terminal_at (= applied_at), so append_one_event
    //    (which stamps applied_at) is correct here.
    let position = append_one_event(transaction, ctx, &response.event).await?;

    // 3. Terminalize the pending delivery at the request instant, binding the
    //    client authorization (+ reason for a rejection).
    delivery::terminalize_welcome_delivery(
        transaction,
        welcome_cas,
        &disposition,
        applied_at,
        position,
    )
    .await?;

    // 4. A rejection additionally creates the `welcomeRejected` recovery work.
    if let Some(rejection) = rejection_work {
        delivery::insert_recovery_work_item(
            transaction,
            &delivery::NewRecoveryWorkItem {
                recovery_work_id: rejection.recovery_work_id,
                conversation_id,
                recipient_did: device_did(&recipient)?,
                recipient_device_id: device_uuid(&recipient),
                source_kind: delivery::RecoveryWorkSourceKind::WelcomeRejected,
                source_id: welcome_id,
                generation: checked_i64(welcome_coordinate.generation())?,
                state_version: checked_i64(welcome_coordinate.state_version())?,
                created_at: applied_at,
            },
        )
        .await?;
    }

    Ok(AppliedTransition {
        allocated_seq: u64::try_from(successor_next_entry_seq).unwrap(),
        entry_id: ctx.entry().entry_id,
        event_positions: vec![position],
        successor_coordinate: plan.successor_coordinate().copied(),
    })
}

/// Apply an entry-less `leafRecoveryCancellation` internal op: terminalize one
/// open recovery request as `cancelled` with its signed cancellation
/// provenance, release its reservation, and RE-ACTIVATE the reserved key
/// package back to `available` (the E2b-6b `PackageSuccessor::Reactivate`
/// writer). The coordinate and seq counter are byte-untouched (head CAS
/// verify). The `assert_recovery_fulfillment_mapping` cancelled-status arm
/// requires the released reservation and request to carry the SAME
/// `terminal_request_digest` + `terminal_at`, and the package to be
/// `available` with all terminal columns NULL — all satisfied here.
#[allow(clippy::too_many_arguments)]
pub(in crate::chat_protocol::state_machine::executor) async fn apply_leaf_recovery_cancellation(
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
            "leaf recovery cancellation needs a prior",
        ))?;
    let expected_generation = checked_i64(expected_prior.generation())?;
    let expected_state_version = checked_i64(expected_prior.state_version())?;
    let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;
    let successor_next_entry_seq = checked_i64(head.successor_next_entry_seq())?;

    // Only a request terminalization + reservation release + package
    // re-activation. Everything else must be empty.
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
            "leaf recovery cancellation metadata change",
        ));
    }
    if effects.revocation_target_cas().is_some()
        || effects.welcome_cas().is_some()
        || effects.invitation_quota_cas().is_some()
    {
        return Err(ExecutorError::UnsupportedEffect(
            "leaf recovery cancellation revocation/welcome/quota CAS",
        ));
    }
    // Internal op MUST NOT change the coordinate or advance the seq counter
    // (E2b-6b review MINOR-2).
    if successor_next_entry_seq != expected_next_entry_seq {
        return Err(ExecutorError::InconsistentPlan(
            "leaf recovery cancellation must not advance the seq counter",
        ));
    }
    if generation != expected_generation || state_version != expected_state_version {
        return Err(ExecutorError::InconsistentPlan(
            "leaf recovery cancellation must not change the coordinate",
        ));
    }

    // Exactly one Open->Cancelled recovery request + one released reservation +
    // one package edge.
    let recovery = effects
        .recovery_request_changes()
        .iter()
        .find_map(|change| match (change.before(), change.after()) {
            (Some(before), Some(after))
                if before.status() == RecoveryRequestStatus::Open
                    && after.status() == RecoveryRequestStatus::Cancelled =>
            {
                Some(after)
            }
            _ => None,
        })
        .ok_or(ExecutorError::InconsistentPlan(
            "cancellation does not cancel an open recovery request",
        ))?;
    if effects.recovery_request_changes().len() != 1
        || effects.reservation_changes().len() != 1
        || effects.package_transitions().len() != 1
    {
        return Err(ExecutorError::InconsistentPlan(
            "cancellation must terminalize exactly one request + reservation + package edge",
        ));
    }
    verify_recovery_package_consistency(
        effects,
        recovery.key_package_ref(),
        PackageStatus::Reserved,
        PackageStatus::Available,
    )?;
    #[cfg(test)]
    let recovery_request_id = Uuid::from_bytes(*recovery.request_id());
    #[cfg(test)]
    let key_package_ref = recovery.key_package_ref().to_vec();
    // The signed cancellation request's digest — the SAME value the released
    // reservation records, per the cancelled-status mapping cross-check.
    #[cfg(test)]
    let terminal_request_digest = ctx.entry().request_digest.clone();

    // 1. Production consumes the Task-4 full-row triple as the first
    //    durable mutation. The enclosing executor savepoint rolls it back
    //    if the later head/event/completion composition fails.
    #[cfg(not(test))]
    recovery_write_authority
        .ok_or(ExecutorError::MissingContext(
            "missing validated Recovery executor write authority",
        ))?
        .apply_terminal(transaction)
        .await?;
    #[cfg(test)]
    if let Some(authority) = recovery_write_authority {
        authority.apply_terminal(transaction).await?;
    }

    // 2. Head CAS VERIFY (coordinate + seq counter unchanged).
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
        // Test-only raw-executor compatibility path.
        transition::terminalize_leaf_recovery_request(
            transaction,
            recovery_request_id,
            &LeafRecoveryTermination::Cancelled {
                terminal_signed_request_bytes: ctx.entry().signed_request_bytes.clone(),
                terminal_signing_transcript_bytes: ctx.entry().signing_transcript_bytes.clone(),
                terminal_request_digest: terminal_request_digest.clone(),
                terminal_signature: ctx.entry().signature.clone(),
                terminal_at: applied_at,
            },
        )
        .await?;
        transition::terminalize_reservation(
            transaction,
            recovery_request_id,
            &ReservationTermination::ReleasedByRequestDigest {
                terminal_request_digest,
                terminal_at: applied_at,
            },
        )
        .await?;
        transition::cas_key_package_status(
            transaction,
            &key_package_ref,
            RepoPackageStatus::Reserved,
            &PackageSuccessor::Reactivate,
        )
        .await?;
    }

    // 5. No control entry (internal op); only events.
    let event_positions = write_events(transaction, ctx, None).await?;

    Ok(AppliedTransition {
        allocated_seq: u64::try_from(successor_next_entry_seq).unwrap(),
        entry_id: ctx.entry().entry_id,
        event_positions,
        successor_coordinate: plan.successor_coordinate().copied(),
    })
}

/// Apply one due Recovery expiry as an entryless exact triple transition.
/// The executor is the sole business writer: request, reservation, package,
/// canonical event, and head verification share this savepoint.
#[allow(clippy::too_many_arguments)]
pub(in crate::chat_protocol::state_machine::executor) async fn apply_leaf_recovery_expiry(
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
    let head = effects
        .head_cas()
        .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
    let expected_prior = head
        .expected_prior()
        .ok_or(ExecutorError::InconsistentPlan(
            "leaf recovery expiry needs a prior",
        ))?;
    let expected_generation = checked_i64(expected_prior.generation())?;
    let expected_state_version = checked_i64(expected_prior.state_version())?;
    let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;
    let successor_next_entry_seq = checked_i64(head.successor_next_entry_seq())?;
    let authority = match effects.authority() {
        Some(PlanAuthority::RecoveryExpiry(authority)) => authority,
        _ => {
            return Err(ExecutorError::InconsistentPlan(
                "leaf recovery expiry lacks authority",
            ))
        }
    };
    let operation_id = match &ctx.authority {
        ExecutionAuthority::Entryless { operation_id } => *operation_id,
        ExecutionAuthority::ControlEntry(_) => {
            return Err(ExecutorError::MissingContext(
                "entryless leaf recovery expiry authority",
            ))
        }
    };
    let terminal_at = server_instant(authority.terminal_at())?;
    if operation_id.as_bytes() != authority.request_id()
        || authority.observed_at() < authority.terminal_at()
        || authority.locked_read_set_digest() == &[0; 32]
        || head.allocated_entry_id().is_some()
        || head.allocated_seq().is_some()
        || head.successor_next_entry_seq() != head.expected_next_entry_seq()
        || head.locked_at() != authority.observed_at()
        || ctx.applied_at != terminal_at
        || generation != expected_generation
        || state_version != expected_state_version
        || successor_next_entry_seq != expected_next_entry_seq
    {
        return Err(ExecutorError::InconsistentPlan(
            "leaf recovery expiry authority/head drifted",
        ));
    }
    reject_if_present("participant_changes", effects.participant_changes())?;
    reject_if_present("leaf_changes", effects.leaf_changes())?;
    reject_if_present("interval_changes", effects.interval_changes())?;
    reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
    reject_if_present("reset_request_changes", effects.reset_request_changes())?;
    reject_if_present("leave_request_changes", effects.leave_request_changes())?;
    reject_if_present("welcome_changes", effects.welcome_changes())?;
    reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
    if effects.metadata_change().is_some()
        || effects.revocation_target_cas().is_some()
        || effects.welcome_cas().is_some()
        || effects.invitation_quota_cas().is_some()
        || effects.recovery_request_changes().len() != 1
        || effects.reservation_changes().len() != 1
        || effects.package_transitions().len() != 1
        || !ctx.entry_recipients.is_empty()
        || !ctx.opened_leaves.is_empty()
        || ctx.metadata_author.is_some()
        || !ctx.participant_period_ids.is_empty()
        || !ctx.leaf_period_ids.is_empty()
        || !ctx.closing_leaf_periods.is_empty()
        || !ctx.closing_participant_periods.is_empty()
        || ctx.reset_request_row.is_some()
        || ctx.recovery_open.is_some()
        || ctx.welcome_expiry.is_some()
        || ctx.welcome_response.is_some()
        || !ctx.welcome_dispositions.is_empty()
    {
        return Err(ExecutorError::InconsistentPlan(
            "leaf recovery expiry carries unrelated effects/context",
        ));
    }
    let expired = effects
        .recovery_request_changes()
        .iter()
        .find_map(|change| match (change.before(), change.after()) {
            (Some(before), Some(after))
                if before.status() == RecoveryRequestStatus::Open
                    && after.status() == RecoveryRequestStatus::Expired
                    && after.request_id() == authority.request_id()
                    && after.target() == authority.requester()
                    && *after.expires_at() == authority.terminal_at() =>
            {
                Some(after)
            }
            _ => None,
        })
        .ok_or(ExecutorError::InconsistentPlan(
            "leaf recovery expiry lacks exact request edge",
        ))?;
    let package_edge =
        effects
            .package_transitions()
            .first()
            .ok_or(ExecutorError::InconsistentPlan(
                "leaf recovery expiry lacks package edge",
            ))?;
    if package_edge.request_id() != authority.request_id()
        || package_edge.key_package_ref() != expired.key_package_ref()
        || package_edge.from() != PackageStatus::Reserved
        || !matches!(
            package_edge.to(),
            PackageStatus::Available | PackageStatus::Expired
        )
    {
        return Err(ExecutorError::InconsistentPlan(
            "leaf recovery expiry package edge is invalid",
        ));
    }
    verify_recovery_package_consistency(
        effects,
        expired.key_package_ref(),
        PackageStatus::Reserved,
        package_edge.to(),
    )?;
    if ctx.events.len() != 1
        || ctx.events[0].event_kind != EventKind::LeafRecovery
        || ctx.events[0].payload_bytes
            != delivery::canonical_leaf_recovery_event_payload(
                operation_id,
                conversation_id,
                delivery::LeafRecoveryEventStatus::Expired,
            )
        || ctx.events[0].outbox.len() != 1
        || ctx.events[0].outbox[0].1 != OutboxWorkKind::Stream
    {
        return Err(ExecutorError::InconsistentPlan(
            "leaf recovery expiry event is not canonical",
        ));
    }

    #[cfg(not(test))]
    recovery_write_authority
        .ok_or(ExecutorError::MissingContext(
            "missing validated Recovery executor write authority",
        ))?
        .apply_terminal(transaction)
        .await?;
    #[cfg(test)]
    if let Some(authority) = recovery_write_authority {
        authority.apply_terminal(transaction).await?;
    }
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
        transition::terminalize_leaf_recovery_request(
            transaction,
            operation_id,
            &LeafRecoveryTermination::Expired { terminal_at },
        )
        .await?;
        transition::terminalize_reservation(
            transaction,
            operation_id,
            &ReservationTermination::Expired { terminal_at },
        )
        .await?;
        let successor = match package_edge.to() {
            PackageStatus::Available => PackageSuccessor::Reactivate,
            PackageStatus::Expired => PackageSuccessor::Expire { terminal_at },
            _ => unreachable!("expiry package successor checked above"),
        };
        transition::cas_key_package_status(
            transaction,
            expired.key_package_ref(),
            RepoPackageStatus::Reserved,
            &successor,
        )
        .await?;
    }
    let event_positions = write_events(transaction, ctx, None).await?;
    Ok(AppliedTransition {
        allocated_seq: u64::try_from(successor_next_entry_seq).unwrap(),
        entry_id: operation_id,
        event_positions,
        successor_coordinate: plan.successor_coordinate().copied(),
    })
}
