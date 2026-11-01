#![allow(unused_imports)]
use super::*;

/// Apply a `zeroLeafLeave` edge: an active but LEAFLESS participant (a pending
/// invitee who never joined) self-removes immediately. `stateVersion+1`, same
/// generation/epoch (a coordinate-only rebind, NO crypto commit and NO metadata
/// snapshot — `leavePolicy` is not in the metadata-required set). It closes the
/// participant period (releasing its invitation-quota slot, which the deferred
/// `enforce_invitation_quota` trigger recomputes), with no leaf/interval change
/// (the leaver had neither). Mirrors `apply_policy`'s coordinate/gen-state CAS
/// spine, but terminalizes the participant instead of adding one.
#[allow(clippy::too_many_arguments)]
pub(in crate::chat_protocol::state_machine::executor) async fn apply_zero_leaf_leave(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &ConversationPersistencePlan,
    ctx: &ExecutionContext,
    conversation_id: Uuid,
    transition_id: Uuid,
    seq_i64: i64,
    successor_next_entry_seq: i64,
    generation: i64,
    state_version: i64,
    epoch: i64,
) -> Result<AppliedTransition, ExecutorError> {
    let effects = plan.effects();
    let hydration = plan.state();
    let coordinate = &hydration.coordinate;
    let applied_at = ctx.applied_at;
    let head = effects
        .head_cas()
        .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
    let expected_prior = head
        .expected_prior()
        .ok_or(ExecutorError::InconsistentPlan(
            "zero-leaf leave needs an expected prior",
        ))?;
    let expected_generation = checked_i64(expected_prior.generation())?;
    let expected_state_version = checked_i64(expected_prior.state_version())?;
    let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;

    // Coordinate-only self-removal: the leaver's OWN delta is one participant
    // close (leafless, so no leaf/interval/proof change). But
    // `plan_zero_leaf_leave_inner` calls `resolve_prior_bound_work`
    // unconditionally, so it CAN carry prior-coordinate open-work SUPERSESSIONS —
    // a co-open recovery request / reservation / reserved package + a prior
    // pending Welcome — which are consumed via the shared writers at the tail
    // (own counts 0), exact-shape checked here (mirroring close/policy).
    reject_if_present("leaf_changes", effects.leaf_changes())?;
    reject_if_present("interval_changes", effects.interval_changes())?;
    reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
    // reset_request_changes: KEPT fail-closed. A leavePolicy transition staling a
    // prior-bound reset request is DB-legal (reset `stale` accepts any kind), but
    // ADR-019 Erratum 01 rules only on LEAVE staling; reset staling on this arm is
    // out of scope and stays rejected pending its own ruling (the planner does not
    // emit it in the reachable zero-leaf-leave flows).
    reject_if_present("reset_request_changes", effects.reset_request_changes())?;
    // leave_request_changes (ADR-019 Erratum 01): a zeroLeafLeave (leavePolicy)
    // owns NO leave request of its own — it removes a leafless invitee via a
    // zeroLeafLeaveEntry, never a leave request. Every leave delta must therefore
    // be a prior-bound terminalization of a DIFFERENT member's predecessor-bound
    // pending leave (own leave count 0): `Pending->Stale` when this coordinate
    // change supersedes it, or `Pending->Expired` when its own 24h `expires_at`
    // had already passed at `evidence.received_at` — `resolve_prior_bound_work`
    // emits the second row unconditionally for an overdue request, and
    // `write_prior_bound_staling` already writes it. Accepting only the first row
    // made an overdue peer leave a permanent wedge. Validate the shape here; the
    // exact terminal evidence for BOTH rows is proved by the shared
    // `classify_prior_bound_staling` below, and the own-DID exclusion is checked
    // once the leaver is resolved. The rows flow through
    // `write_prior_bound_staling` at the tail (own 0 + staled == total).
    for change in effects.leave_request_changes() {
        let (before, after) = match (change.before(), change.after()) {
            (Some(before), Some(after)) => (before, after),
            _ => {
                return Err(ExecutorError::InconsistentPlan(
                    "zero-leaf leave leave-request delta must be a status transition",
                ))
            }
        };
        if before.status() != LeaveRequestStatus::Pending
            || !matches!(
                after.status(),
                LeaveRequestStatus::Stale | LeaveRequestStatus::Expired
            )
        {
            return Err(ExecutorError::InconsistentPlan(
                "zero-leaf leave leave-request delta must be Pending->Stale/Expired",
            ));
        }
        // No re-binding (ruling point 4): staling never moves a request's binding.
        if before.bound_coordinate != after.bound_coordinate {
            return Err(ExecutorError::InconsistentPlan(
                "zero-leaf leave must not re-bind a leave request",
            ));
        }
    }
    reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
    // Prior-bound recovery families. The three shape loops this replaces
    // accepted only Row A (Open->Superseded / Active->Released) and never
    // checked terminal evidence, family identity, or the CAS bindings — so a
    // legal Row B due-expiry family was rejected here exactly as it was in leaf
    // recovery fulfillment. The shared classifier proves both rows, strictly
    // before this arm's first head CAS.
    let partition = classify_prior_bound_recovery(plan, ctx, OwnFamilyKind::None)?; // zero-leaf leave

    // Prior-bound reset / leave / Welcome families. A zero-leaf leave owns none
    // of them (its own consent never reaches a leave-request delta here).
    classify_prior_bound_staling(plan, ctx, OwnStalingKind::None)?;
    if effects.metadata_change().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "zero-leaf leave metadata change",
        ));
    }
    if effects.revocation_target_cas().is_some() || effects.welcome_cas().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "zero-leaf leave revocation/welcome CAS",
        ));
    }
    // A zero-leaf leave releases (never consumes) an invitation slot, so the
    // plan carries NO invitation-quota CAS (only Creation/Policy do); the
    // deferred quota trigger recomputes from the closed participant row.
    if effects.invitation_quota_cas().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "zero-leaf leave invitation quota CAS",
        ));
    }
    // Exactly one participant is closed (Some -> None); records are never
    // deleted, only terminalized.
    if effects.participant_changes().len() != 1 {
        return Err(ExecutorError::InconsistentPlan(
            "zero-leaf leave must change exactly one participant",
        ));
    }
    let removed = effects
        .participant_changes()
        .iter()
        .find_map(|change| match (change.before(), change.after()) {
            (Some(before), None) => Some(before),
            _ => None,
        })
        .ok_or(ExecutorError::InconsistentPlan(
            "zero-leaf leave must close exactly one participant",
        ))?;
    // ADR-019 Erratum 01: a zeroLeafLeave stales only OTHER members' leaves. Any
    // leave delta targeting the leaver's own DID is a hard InconsistentPlan (a
    // zero-leaf leaver holds no leave request of its own).
    for change in effects.leave_request_changes() {
        if let Some(after) = change.after() {
            if after.requester().principal() == removed.principal() {
                return Err(ExecutorError::InconsistentPlan(
                    "zero-leaf leave must not stale its own leave request",
                ));
            }
        }
    }
    let participant_period_id = ctx
        .closing_participant_periods
        .iter()
        .find(|(principal, _)| principal == removed.principal())
        .map(|(_, id)| *id)
        .ok_or(ExecutorError::MissingContext(
            "closing participant period id for the zero-leaf leaver",
        ))?;

    // 1. Head CAS advances the coordinate + counter (single seq authority).
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

    // 2. Advance the generation's state-version pointer (same generation).
    transition::cas_generation_state_version(
        transaction,
        &transition::GenerationStateVersionCas {
            conversation_id,
            generation,
            expected_state_version,
            successor_state_version: state_version,
        },
    )
    .await?;

    // 3. Successor generation state (leavePolicy kind, coordinate-only rebind).
    transition::insert_generation_state_row(
        transaction,
        &NewGenerationState {
            conversation_id,
            generation,
            state_version,
            group_id: coordinate.group_id().to_vec(),
            epoch,
            group_context_hash: coordinate.group_context_hash().to_vec(),
            confirmation_tag: coordinate.confirmation_tag().to_vec(),
            lifecycle: GenerationStateLifecycle::Active,
            state_kind: GenerationStateKind::LeavePolicy,
            producing_transition_id: transition_id,
            public_snapshot_bytes: ctx.spine.public_snapshot_bytes.clone(),
            snapshot_sha256: ctx.spine.public_snapshot_sha256.clone(),
            tree_summary_bytes: ctx.spine.tree_summary_bytes.clone(),
            tree_summary_sha256: ctx.spine.tree_summary_sha256.clone(),
            leaf_count: ctx.spine.leaf_count,
            created_at: applied_at,
        },
    )
    .await?;

    // 4. Entry (zeroLeafLeaveEntry) at the allocated seq.
    let append = build_append_entry(
        ctx,
        conversation_id,
        generation,
        state_version,
        transition_id,
    );
    delivery::append_entry_at(transaction, &append, u64::try_from(seq_i64).unwrap()).await?;

    // 5. Transition (leavePolicy, prior -> next, no metadata snapshot).
    transition::insert_transition_row(
        transaction,
        &NewTransition {
            transition_id,
            conversation_id,
            kind: TransitionKind::LeavePolicy,
            actor_did: ctx.actor.user_did.clone(),
            actor_device_id: ctx.actor.device_id,
            actor_key_id: ctx.actor.key_id.clone(),
            actor_auth_generation: ctx.actor.auth_generation,
            actor_role: ctx.actor.role,
            actor_device_status: ctx.actor.device_status.clone(),
            signed_request_bytes: ctx.entry().signed_request_bytes.clone(),
            unsigned_projection_bytes: ctx.entry().unsigned_projection_bytes.clone(),
            signing_transcript_bytes: ctx.entry().signing_transcript_bytes.clone(),
            request_digest: ctx.entry().request_digest.clone(),
            signature: ctx.entry().signature.clone(),
            coordinates: TransitionCoordinates {
                prior: Some((expected_generation, expected_state_version)),
                next: Some((generation, state_version)),
                retired: None,
                successor: None,
            },
            reset_request_id: None,
            close_transition_id: None,
            metadata_snapshot_id: None,
            entry_seq: seq_i64,
            accepted_at: applied_at,
        },
    )
    .await?;

    // 6. Close the leaver's participant period (invitation-slot release).
    transition::terminalize_participant_period(
        transaction,
        &transition::ParticipantTerminalization {
            participant_period_id,
            removing_transition_id: transition_id,
            removing_seq: seq_i64,
            removed_at: applied_at,
        },
    )
    .await?;

    // 7. Audience + events.
    let recipients = build_entry_recipients(&ctx.entry_recipients)?;
    delivery::insert_entry_recipients(
        transaction,
        conversation_id,
        u64::try_from(seq_i64).unwrap(),
        &recipients,
    )
    .await?;
    let event_positions = write_events(transaction, ctx, None).await?;

    // Supersede prior-coordinate open work the leave retired (an open recovery
    // request / active reservation / reserved package + a prior pending Welcome)
    // AND stale any prior-bound pending LEAVE request of OTHER members (ADR-019
    // Erratum 01). A zero-leaf leave owns NONE of these families (own == default),
    // so every such delta MUST be a supersession/staling the shared writers
    // applied — reconcile rejects any that is neither. reset was rejected above
    // (count 0), so its family trivially reconciles.
    let receipt =
        write_prior_bound_supersessions(transaction, effects, transition_id, applied_at).await?;
    // Design 5 step 6: reconcile the recovery families against the classifier's
    // KEYED expectation immediately, before any other writer runs. No unrelated
    // write may intervene. The counts are reachable ONLY through this call, so the
    // fence cannot be dropped without breaking the build.
    let mut superseded = receipt.reconcile_into_counts(&partition)?;
    superseded.welcomes = write_welcome_supersessions(
        transaction,
        ctx,
        effects,
        WelcomeSupersessionCause::Transition {
            terminal_transition_id: transition_id,
        },
    )
    .await?;
    let staled = write_prior_bound_staling(
        transaction,
        effects,
        transition_id,
        &ctx.entry().request_digest,
        applied_at,
    )
    .await?;
    superseded.leave_requests = staled.leave_requests;
    reconcile_coordinate_change_families(effects, &FamilyCounts::default(), &superseded)?;

    Ok(AppliedTransition {
        allocated_seq: u64::try_from(seq_i64).unwrap(),
        entry_id: ctx.entry().entry_id,
        event_positions,
        successor_coordinate: plan.successor_coordinate().copied(),
    })
}

/// Apply a `closeConversation` edge: `stateVersion+1`, `lifecycle=superseded`,
/// no successor. Closes every still-open interval with a `Terminal` proof,
/// inserts one schedule terminal proof per historical device schedule, closes
/// the genesis leaf, and emits the single conversation-close tombstone event.
#[allow(clippy::too_many_arguments)]
pub(in crate::chat_protocol::state_machine::executor) async fn apply_close(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &ConversationPersistencePlan,
    ctx: &ExecutionContext,
    conversation_id: Uuid,
    transition_id: Uuid,
    seq_i64: i64,
    successor_next_entry_seq: i64,
    generation: i64,
    state_version: i64,
    epoch: i64,
) -> Result<AppliedTransition, ExecutorError> {
    let effects = plan.effects();
    let hydration = plan.state();
    let coordinate = &hydration.coordinate; // retired coordinate (same crypto).
    let applied_at = ctx.applied_at;
    let head = effects
        .head_cas()
        .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
    let expected_prior = head
        .expected_prior()
        .ok_or(ExecutorError::InconsistentPlan(
            "close needs an expected prior",
        ))?;
    let expected_generation = checked_i64(expected_prior.generation())?;
    let expected_state_version = checked_i64(expected_prior.state_version())?;
    let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;

    // Close is coordinate-retire + interval/leaf teardown. It carries NO own
    // recovery/welcome edge, but it DOES supersede prior-coordinate open work:
    // `plan_close_inner` calls `resolve_prior_bound_work` unconditionally, and a
    // close IS reachable while the actor's own (group-of-1 admin) or the other
    // party's (direct 1:1) leaf-recovery request is open — superseding it +
    // releasing the reservation + reactivating the package. Those deltas are
    // consumed below via the shared write_prior_bound_supersessions +
    // write_welcome_supersessions + write_prior_bound_staling + reconcile (own
    // counts 0). A close is likewise reachable while a pending reset/leave request
    // is bound to the prior coordinate — staled below (kind is `closeConversation`,
    // DB-legal for the leave `stale` edge). Families the close genuinely never
    // carries stay fail-closed.
    reject_if_present("participant_changes", effects.participant_changes())?;
    reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
    // Every recovery/reservation/package delta a close carries MUST be a
    // prior-bound supersession (request Open->Superseded, reservation
    // Active->Released, package Reserved->Available) — exact-shape checked here
    // (mirroring the generic-commit arm) and consumed below. `recovery_package_cas`
    // is the production-shape package witness the bijection validates, NOT a
    // rejected family.
    // Prior-bound recovery families. The three shape loops this replaces
    // accepted only Row A (Open->Superseded / Active->Released) and never
    // checked terminal evidence, family identity, or the CAS bindings — so a
    // legal Row B due-expiry family was rejected here exactly as it was in leaf
    // recovery fulfillment. The shared classifier proves both rows, strictly
    // before this arm's first head CAS.
    let partition = classify_prior_bound_recovery(plan, ctx, OwnFamilyKind::None)?; // close

    // Prior-bound reset / leave / Welcome families. A close owns none of them.
    classify_prior_bound_staling(plan, ctx, OwnStalingKind::None)?;
    if effects.metadata_change().is_some() {
        return Err(ExecutorError::UnsupportedEffect("close metadata change"));
    }
    if effects.revocation_target_cas().is_some() || effects.welcome_cas().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "close revocation/welcome CAS",
        ));
    }
    if effects.invitation_quota_cas().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "close invitation quota CAS",
        ));
    }

    // 1. Head CAS to superseded with the exact close coordinate.
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
            close: Some(ConversationHeadClose {
                close_transition_id: transition_id,
                close_generation: generation,
                close_state_version: state_version,
                close_seq: seq_i64,
                closed_at: applied_at,
            }),
        },
    )
    .await?;

    // 2. Supersede the generation (points at the superseded state).
    transition::supersede_generation(
        transaction,
        &GenerationSupersede {
            conversation_id,
            generation,
            expected_state_version,
            successor_state_version: state_version,
            superseded_seq: seq_i64,
            superseded_at: applied_at,
        },
    )
    .await?;

    // 3. Superseded closeConversation generation state (same crypto edge).
    transition::insert_generation_state_row(
        transaction,
        &NewGenerationState {
            conversation_id,
            generation,
            state_version,
            group_id: coordinate.group_id().to_vec(),
            epoch,
            group_context_hash: coordinate.group_context_hash().to_vec(),
            confirmation_tag: coordinate.confirmation_tag().to_vec(),
            lifecycle: GenerationStateLifecycle::Superseded,
            state_kind: GenerationStateKind::CloseConversation,
            producing_transition_id: transition_id,
            public_snapshot_bytes: ctx.spine.public_snapshot_bytes.clone(),
            snapshot_sha256: ctx.spine.public_snapshot_sha256.clone(),
            tree_summary_bytes: ctx.spine.tree_summary_bytes.clone(),
            tree_summary_sha256: ctx.spine.tree_summary_sha256.clone(),
            leaf_count: ctx.spine.leaf_count,
            created_at: applied_at,
        },
    )
    .await?;

    // 4. Entry (conversationCloseEntry) at the close seq.
    let append = build_append_entry(
        ctx,
        conversation_id,
        generation,
        state_version,
        transition_id,
    );
    delivery::append_entry_at(transaction, &append, u64::try_from(seq_i64).unwrap()).await?;

    // 5. Transition (prior -> retired; a close transition references itself).
    transition::insert_transition_row(
        transaction,
        &NewTransition {
            transition_id,
            conversation_id,
            kind: TransitionKind::CloseConversation,
            actor_did: ctx.actor.user_did.clone(),
            actor_device_id: ctx.actor.device_id,
            actor_key_id: ctx.actor.key_id.clone(),
            actor_auth_generation: ctx.actor.auth_generation,
            actor_role: ctx.actor.role,
            actor_device_status: ctx.actor.device_status.clone(),
            signed_request_bytes: ctx.entry().signed_request_bytes.clone(),
            unsigned_projection_bytes: ctx.entry().unsigned_projection_bytes.clone(),
            signing_transcript_bytes: ctx.entry().signing_transcript_bytes.clone(),
            request_digest: ctx.entry().request_digest.clone(),
            signature: ctx.entry().signature.clone(),
            coordinates: TransitionCoordinates {
                prior: Some((expected_generation, expected_state_version)),
                next: Some((generation, state_version)),
                retired: None,
                successor: None,
            },
            reset_request_id: None,
            close_transition_id: Some(transition_id),
            metadata_snapshot_id: None,
            entry_seq: seq_i64,
            accepted_at: applied_at,
        },
    )
    .await?;

    // 6. Close the genesis leaf (leaf_change = Some -> None).
    for change in effects.leaf_changes() {
        let before = match (change.before(), change.after()) {
            (Some(before), None) => before,
            _ => {
                return Err(ExecutorError::UnsupportedEffect(
                    "close leaf change is not a removal",
                ))
            }
        };
        let leaf_period_id = closing_leaf_period(ctx, before.device())?;
        transition::close_leaf_period(
            transaction,
            &LeafClose {
                leaf_period_id,
                removed_state_version: state_version,
                removed_transition_id: transition_id,
                removed_seq: seq_i64,
                removed_at: applied_at,
            },
        )
        .await?;
    }

    // 7. Close every still-open interval with the Terminal proof (from the plan).
    for change in effects.interval_changes() {
        let after = match (change.before(), change.after()) {
            (Some(_), Some(after)) => after,
            _ => {
                return Err(ExecutorError::UnsupportedEffect(
                    "close interval change is not a finite close",
                ))
            }
        };
        let end = after.end().ok_or(ExecutorError::InconsistentPlan(
            "close interval carries no end",
        ))?;
        let leaf_period_id = closing_leaf_period(ctx, after.recipient())?;
        delivery::close_application_interval(
            transaction,
            &ApplicationIntervalClose {
                conversation_id,
                recipient_did: device_did(after.recipient())?,
                recipient_device_id: device_uuid(after.recipient()),
                opening_transition_id: Uuid::from_bytes(*after.opening_transition_id()),
                terminal_seq: checked_i64(end.seq())?,
                closing_state_version: state_version,
                closing_transition_id: Uuid::from_bytes(*end.transition_id()),
                closing_outer_entry_fingerprint: end.outer_entry_fingerprint().to_vec(),
                closing_kind: repo_interval_close_kind(end.kind()),
                closing_leaf_period_id: leaf_period_id,
                removed_at: applied_at,
            },
        )
        .await?;
    }

    // 8. One schedule terminal proof per historical device schedule.
    for change in effects.terminal_proof_changes() {
        let proof = match (change.before(), change.after()) {
            (None, Some(proof)) => proof,
            _ => {
                return Err(ExecutorError::UnsupportedEffect(
                    "schedule proof change is not an insert",
                ))
            }
        };
        delivery::insert_schedule_terminal_proof(
            transaction,
            &NewScheduleTerminalProof {
                conversation_id,
                recipient_did: device_did(proof.recipient())?,
                recipient_device_id: device_uuid(proof.recipient()),
                terminal_seq: seq_i64,
                transition_id,
                outer_entry_fingerprint: ctx.entry().outer_entry_fingerprint.clone(),
                received_at: applied_at,
            },
        )
        .await?;
    }

    // 9. Retained scheduleTerminal audience + the conversation-close event.
    let recipients = build_entry_recipients(&ctx.entry_recipients)?;
    delivery::insert_entry_recipients(
        transaction,
        conversation_id,
        u64::try_from(seq_i64).unwrap(),
        &recipients,
    )
    .await?;
    let event_positions = write_events(transaction, ctx, None).await?;

    // 10. Supersede prior-coordinate open work the close retired: an open
    //     leaf-recovery request (Open->Superseded) + its reservation
    //     (Active->Released) + reserved package (Reserved->Available), any prior
    //     pending welcome, and any prior-bound pending reset/leave request
    //     (Pending->Stale). The close has ZERO own recovery/welcome/reset/leave
    //     edges, so own == default and every such delta MUST be a supersession/
    //     staling the calls below applied — reconcile rejects any that is neither.
    let receipt =
        write_prior_bound_supersessions(transaction, effects, transition_id, applied_at).await?;
    // Design 5 step 6: reconcile the recovery families against the classifier's
    // KEYED expectation immediately, before any other writer runs. No unrelated
    // write may intervene. The counts are reachable ONLY through this call, so the
    // fence cannot be dropped without breaking the build.
    let mut superseded = receipt.reconcile_into_counts(&partition)?;
    superseded.welcomes = write_welcome_supersessions(
        transaction,
        ctx,
        effects,
        WelcomeSupersessionCause::Transition {
            terminal_transition_id: transition_id,
        },
    )
    .await?;
    let staled = write_prior_bound_staling(
        transaction,
        effects,
        transition_id,
        &ctx.entry().request_digest,
        applied_at,
    )
    .await?;
    superseded.reset_requests = staled.reset_requests;
    superseded.leave_requests = staled.leave_requests;
    reconcile_coordinate_change_families(effects, &FamilyCounts::default(), &superseded)?;

    Ok(AppliedTransition {
        allocated_seq: u64::try_from(seq_i64).unwrap(),
        entry_id: ctx.entry().entry_id,
        event_positions,
        successor_coordinate: plan.successor_coordinate().copied(),
    })
}

/// Apply a `reset request` edge: a non-mutating signed intent. It appends the
/// request entry + the `chat.reset_requests` row + the event, and advances the
/// seq counter — but the crypto coordinate is UNCHANGED (no generation state,
/// no transition row, no stateVersion bump).
#[allow(clippy::too_many_arguments)]
pub(in crate::chat_protocol::state_machine::executor) async fn apply_reset_request(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &ConversationPersistencePlan,
    ctx: &ExecutionContext,
    conversation_id: Uuid,
    seq_i64: i64,
    successor_next_entry_seq: i64,
    generation: i64,
    state_version: i64,
    epoch: i64,
) -> Result<AppliedTransition, ExecutorError> {
    let effects = plan.effects();
    let hydration = plan.state();
    let coordinate = &hydration.coordinate; // unchanged coordinate.
    let applied_at = ctx.applied_at;
    let head = effects
        .head_cas()
        .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
    let expected_prior = head
        .expected_prior()
        .ok_or(ExecutorError::InconsistentPlan(
            "reset request needs an expected prior",
        ))?;
    let expected_generation = checked_i64(expected_prior.generation())?;
    let expected_state_version = checked_i64(expected_prior.state_version())?;
    let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;

    // Non-mutating: only a reset-request row changes. Everything else empty.
    reject_if_present("participant_changes", effects.participant_changes())?;
    reject_if_present("leaf_changes", effects.leaf_changes())?;
    reject_if_present("interval_changes", effects.interval_changes())?;
    reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
    reject_if_present(
        "recovery_request_changes",
        effects.recovery_request_changes(),
    )?;
    reject_if_present("reservation_changes", effects.reservation_changes())?;
    reject_if_present("leave_request_changes", effects.leave_request_changes())?;
    reject_if_present("welcome_changes", effects.welcome_changes())?;
    reject_if_present("package_transitions", effects.package_transitions())?;
    reject_if_present("recovery_package_cas", effects.recovery_package_cas())?;
    reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
    if effects.metadata_change().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "reset request metadata change",
        ));
    }
    // Complete defensive dispatch (E2b-4 review): a resetRequest plan carries
    // none of these; production `into_persistence_plan` forces them empty/None.
    // Guarding them keeps this path in the same no-silent-skip class as the rest.
    if effects.revocation_target_cas().is_some() || effects.welcome_cas().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "reset request revocation/welcome CAS",
        ));
    }
    if effects.invitation_quota_cas().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "reset request invitation quota CAS",
        ));
    }
    let row = ctx
        .reset_request_row
        .as_ref()
        .ok_or(ExecutorError::MissingContext("reset request row content"))?;
    // Exactly one new pending reset request in the delta.
    if effects.reset_request_changes().len() != 1 {
        return Err(ExecutorError::InconsistentPlan(
            "reset request must add exactly one pending request",
        ));
    }

    // 1. Head CAS: advance the seq counter, coordinate UNCHANGED.
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

    // 2. The request entry (resetRequestEntry carries no transition_id).
    let mut append =
        build_append_entry(ctx, conversation_id, generation, state_version, Uuid::nil());
    append.generation = None;
    append.state_version = None;
    append.transition_id = None;
    delivery::append_entry_at(transaction, &append, u64::try_from(seq_i64).unwrap()).await?;

    // 3. The pending reset_requests row (signed content from ctx; bound
    //    coordinate from the unchanged current coordinate).
    transition::insert_reset_request(
        transaction,
        &transition::NewResetRequest {
            reset_request_id: row.reset_request_id,
            conversation_id,
            requester_did: ctx.actor.user_did.clone(),
            requester_device_id: ctx.actor.device_id,
            requester_key_id: ctx.actor.key_id.clone(),
            requester_auth_generation: ctx.actor.auth_generation,
            prior_generation: generation,
            prior_state_version: state_version,
            prior_group_id: coordinate.group_id().to_vec(),
            prior_epoch: epoch,
            prior_group_context_hash: coordinate.group_context_hash().to_vec(),
            prior_confirmation_tag: coordinate.confirmation_tag().to_vec(),
            reason: row.reason.clone(),
            signed_request_bytes: row.signed_request_bytes.clone(),
            signing_transcript_bytes: row.signing_transcript_bytes.clone(),
            request_digest: row.request_digest.clone(),
            signature: row.signature.clone(),
            received_at: applied_at,
            expires_at: row.expires_at,
        },
    )
    .await?;

    // 4. Audience + event.
    let recipients = build_entry_recipients(&ctx.entry_recipients)?;
    delivery::insert_entry_recipients(
        transaction,
        conversation_id,
        u64::try_from(seq_i64).unwrap(),
        &recipients,
    )
    .await?;
    let event_positions = write_events(transaction, ctx, None).await?;

    Ok(AppliedTransition {
        allocated_seq: u64::try_from(seq_i64).unwrap(),
        entry_id: ctx.entry().entry_id,
        event_positions,
        successor_coordinate: plan.successor_coordinate().copied(),
    })
}

/// Apply an entry-bearing `leaveRequest` control op. Non-mutating: the head
/// CAS advances ONLY the seq counter (the `(generation,state_version)`
/// coordinate is untouched), it appends the `leaveRequestEntry`, and it inserts
/// a pending 24h-consent `leave_requests` row bound to the current coordinate.
/// The row's signed material is the entry's — `assert_leave_request_mapping`
/// requires the row and its `leaveRequestEntry` to carry byte-equal
/// `signed_request_bytes`/`request_digest`/`signature`/`received_at` — so no
/// side ctx row is needed; the DB `expires_at = received_at + 24h`. Mirrors
/// `apply_reset_request`.
#[allow(clippy::too_many_arguments)]
pub(in crate::chat_protocol::state_machine::executor) async fn apply_leave_request(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &ConversationPersistencePlan,
    ctx: &ExecutionContext,
    conversation_id: Uuid,
    seq_i64: i64,
    successor_next_entry_seq: i64,
    generation: i64,
    state_version: i64,
    epoch: i64,
) -> Result<AppliedTransition, ExecutorError> {
    let effects = plan.effects();
    let hydration = plan.state();
    let coordinate = &hydration.coordinate; // unchanged coordinate.
    let applied_at = ctx.applied_at;
    let head = effects
        .head_cas()
        .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
    let expected_prior = head
        .expected_prior()
        .ok_or(ExecutorError::InconsistentPlan(
            "leave request needs an expected prior",
        ))?;
    let expected_generation = checked_i64(expected_prior.generation())?;
    let expected_state_version = checked_i64(expected_prior.state_version())?;
    let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;

    // Non-mutating: only a leave-request row changes. Everything else empty.
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
    reject_if_present("welcome_changes", effects.welcome_changes())?;
    reject_if_present("package_transitions", effects.package_transitions())?;
    reject_if_present("recovery_package_cas", effects.recovery_package_cas())?;
    reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
    if effects.metadata_change().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "leave request metadata change",
        ));
    }
    if effects.revocation_target_cas().is_some() || effects.welcome_cas().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "leave request revocation/welcome CAS",
        ));
    }
    if effects.invitation_quota_cas().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "leave request invitation quota CAS",
        ));
    }
    // Exactly one new pending leave request, plus the observed expiry of
    // however many past-due pending rows `expire_due_leave_requests` swept at
    // the lock. Any OTHER delta shape is a hard `InconsistentPlan` — the same
    // no-silent-drop discipline `reconcile_coordinate_change_families` enforces
    // for the coordinate-changing arms.
    let changes = effects.leave_request_changes();
    let openings = changes
        .iter()
        .filter(|change| {
            matches!(
                (change.before(), change.after()),
                (None, Some(after)) if after.status() == LeaveRequestStatus::Pending
            )
        })
        .count();
    let observed_expiries = changes
        .iter()
        .filter(|change| {
            matches!(
                (change.before(), change.after()),
                (Some(before), Some(after))
                    if before.status() == LeaveRequestStatus::Pending
                        && after.status() == LeaveRequestStatus::Expired
            )
        })
        .count();
    if openings != 1 || openings + observed_expiries != changes.len() {
        return Err(ExecutorError::InconsistentPlan(
            "leave request must open exactly one pending request and observe only expiries",
        ));
    }
    let request = changes
        .iter()
        .find_map(|change| match (change.before(), change.after()) {
            (None, Some(after)) if after.status() == LeaveRequestStatus::Pending => Some(after),
            _ => None,
        })
        .ok_or(ExecutorError::InconsistentPlan(
            "leave request must open exactly one pending request",
        ))?;
    let leave_request_id = Uuid::from_bytes(request.request_id);

    // 1. Head CAS: advance the seq counter, coordinate UNCHANGED.
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

    // 2. The request entry (leaveRequestEntry carries no transition_id).
    let mut append =
        build_append_entry(ctx, conversation_id, generation, state_version, Uuid::nil());
    append.generation = None;
    append.state_version = None;
    append.transition_id = None;
    delivery::append_entry_at(transaction, &append, u64::try_from(seq_i64).unwrap()).await?;

    // 3. Observed expiry of every past-due pending row the planner swept.
    //    MUST precede the insert: `leave_requests_one_pending_uq` is a plain
    //    partial unique index, NOT a deferrable constraint, so a same-requester
    //    replacement would collide the moment the insert lands while the lapsed
    //    row is still `pending`.
    let written_expiries = write_observed_leave_expiries(transaction, effects).await?;
    if written_expiries != observed_expiries {
        return Err(ExecutorError::InconsistentPlan(
            "leave request observed expiry write count drift",
        ));
    }

    // 4. The pending leave_requests row. Signed material is the entry's (the
    //    entry<->row mapping trigger requires byte-equality); the bound
    //    coordinate is the unchanged current coordinate; `expires_at` is the
    //    DB-required `received_at + 24h`.
    transition::insert_leave_request(
        transaction,
        &NewLeaveRequest {
            leave_request_id,
            conversation_id,
            requester_did: ctx.actor.user_did.clone(),
            requester_device_id: ctx.actor.device_id,
            requester_key_id: ctx.actor.key_id.clone(),
            requester_auth_generation: ctx.actor.auth_generation,
            prior_generation: generation,
            prior_state_version: state_version,
            prior_group_id: coordinate.group_id().to_vec(),
            prior_epoch: epoch,
            prior_group_context_hash: coordinate.group_context_hash().to_vec(),
            prior_confirmation_tag: coordinate.confirmation_tag().to_vec(),
            signed_request_bytes: ctx.entry().signed_request_bytes.clone(),
            signing_transcript_bytes: ctx.entry().signing_transcript_bytes.clone(),
            request_digest: ctx.entry().request_digest.clone(),
            signature: ctx.entry().signature.clone(),
            received_at: applied_at,
            expires_at: applied_at + chrono::Duration::hours(24),
        },
    )
    .await?;

    // 5. Audience + event.
    let recipients = build_entry_recipients(&ctx.entry_recipients)?;
    delivery::insert_entry_recipients(
        transaction,
        conversation_id,
        u64::try_from(seq_i64).unwrap(),
        &recipients,
    )
    .await?;
    let event_positions = write_events(transaction, ctx, None).await?;

    Ok(AppliedTransition {
        allocated_seq: u64::try_from(seq_i64).unwrap(),
        entry_id: ctx.entry().entry_id,
        event_positions,
        successor_coordinate: plan.successor_coordinate().copied(),
    })
}
