#![allow(unused_imports)]
use super::*;

/// Apply an entry-bearing `leaveCancellation` control op. Non-mutating (the
/// requester withdraws their own pending leave consent): the head CAS advances
/// only the seq counter, it appends the `leaveCancellationEntry`, and it
/// terminalizes the pending `leave_requests` row as `cancelled`. The cancelled
/// row's `terminal_request_digest` == the cancellation entry's `request_digest`
/// and `terminal_at` == its `received_at` (`= applied_at`), exactly as the
/// cancelled-status arms of `assert_leave_request_mapping` /
/// `assert_control_request_entry` cross-check. No transition (non-mutating).
#[allow(clippy::too_many_arguments)]
pub(in crate::chat_protocol::state_machine::executor) async fn apply_leave_cancellation(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &ConversationPersistencePlan,
    ctx: &ExecutionContext,
    conversation_id: Uuid,
    seq_i64: i64,
    successor_next_entry_seq: i64,
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
            "leave cancellation needs an expected prior",
        ))?;
    let expected_generation = checked_i64(expected_prior.generation())?;
    let expected_state_version = checked_i64(expected_prior.state_version())?;
    let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;

    // Non-mutating: only a leave-request row is terminalized. Everything else empty.
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
            "leave cancellation metadata change",
        ));
    }
    if effects.revocation_target_cas().is_some() || effects.welcome_cas().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "leave cancellation revocation/welcome CAS",
        ));
    }
    if effects.invitation_quota_cas().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "leave cancellation invitation quota CAS",
        ));
    }
    // Exactly one pending -> cancelled leave request in the delta.
    if effects.leave_request_changes().len() != 1 {
        return Err(ExecutorError::InconsistentPlan(
            "leave cancellation must change exactly one request",
        ));
    }
    let cancelled = effects
        .leave_request_changes()
        .iter()
        .find_map(|change| match (change.before(), change.after()) {
            (Some(before), Some(after))
                if before.status() == LeaveRequestStatus::Pending
                    && after.status() == LeaveRequestStatus::Cancelled =>
            {
                Some(after)
            }
            _ => None,
        })
        .ok_or(ExecutorError::InconsistentPlan(
            "leave cancellation must cancel exactly one pending request",
        ))?;
    let leave_request_id = Uuid::from_bytes(cancelled.request_id);

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

    // 2. The cancellation entry (leaveCancellationEntry carries no transition_id).
    let mut append =
        build_append_entry(ctx, conversation_id, generation, state_version, Uuid::nil());
    append.generation = None;
    append.state_version = None;
    append.transition_id = None;
    delivery::append_entry_at(transaction, &append, u64::try_from(seq_i64).unwrap()).await?;

    // 3. Terminalize the pending request as `cancelled`, bound to the
    //    cancellation entry's digest + instant (the mapping cross-check).
    transition::terminalize_leave_request(
        transaction,
        leave_request_id,
        &LeaveRequestTermination::Cancelled {
            terminal_request_digest: ctx.entry().request_digest.clone(),
            terminal_at: applied_at,
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

/// Apply a `resetActivation` edge: retire the old generation and activate a
/// fresh one. Retired gen_state (`stateVersion+1`, superseded) + a new
/// generation at `generation+1` (epoch 0, fresh group/hash/tag) + successor
/// gen_state (sv 0, active) + head CAS to the successor pointer; close every
/// still-open old interval at the reset seq and open ONLY the activator's
/// successor interval at the same seq (touching `Reset -> Reset`); close every
/// old-generation leaf and install the activator's new genesis leaf;
/// terminalize the pending reset request as consumed.
#[allow(clippy::too_many_arguments)]
pub(in crate::chat_protocol::state_machine::executor) async fn apply_reset_activation(
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
    let coordinate = &hydration.coordinate; // successor coordinate.
    let applied_at = ctx.applied_at;
    let head = effects
        .head_cas()
        .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
    let prior = head
        .expected_prior()
        .ok_or(ExecutorError::InconsistentPlan(
            "reset activation needs a prior",
        ))?;
    let retired = plan
        .retired_coordinate()
        .ok_or(ExecutorError::InconsistentPlan(
            "reset activation needs a retired coordinate",
        ))?;
    let prior_generation = checked_i64(prior.generation())?;
    let prior_state_version = checked_i64(prior.state_version())?;
    let retired_generation = checked_i64(retired.generation())?;
    let retired_state_version = checked_i64(retired.state_version())?;
    let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;
    let successor_public_state =
        hydration
            .public_state
            .as_ref()
            .ok_or(ExecutorError::InconsistentPlan(
                "reset successor has no verified public state",
            ))?;
    let successor_tree = encode_public_tree_summary(
        successor_public_state.binding().tree_summary(),
    )
    .map_err(|_| ExecutorError::InconsistentPlan("reset successor tree is not canonical"))?;

    // Reset activation carries no participant change and no OWN recovery edge.
    // Its ONE own request edge is the named reset request it CONSUMES
    // (Pending->Consumed, step 11 below). It DOES supersede prior-coordinate open
    // work: a retired generation's pending welcome / open recovery request /
    // active reservation / reserved package are all resolved to superseded/
    // released by the plan and consumed below via write_prior_bound_supersessions
    // + write_welcome_supersessions + reconcile (own counts 0 for those). It also
    // stales a prior-bound pending LEAVE request the retirement retired
    // (Pending->Stale; kind is `resetActivation`, DB-legal for the leave `stale`
    // edge — the one-pending index means no SECOND reset request can be staled).
    // Families the reset genuinely never carries stay fail-closed.
    reject_if_present("participant_changes", effects.participant_changes())?;
    reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
    reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
    // Every recovery/reservation/package delta a reset carries MUST be a
    // prior-bound supersession (mirroring the generic-commit / close arms):
    // request Open->Superseded, reservation Active->Released, package
    // Reserved->Available. `recovery_package_cas` is the production-shape witness
    // the bijection validates, NOT a rejected family — so a reset that retires a
    // generation with an OPEN recovery request (reserved package) is composed,
    // not hard-errored.
    // Prior-bound recovery families. The three shape loops this replaces
    // accepted only Row A (Open->Superseded / Active->Released) and never
    // checked terminal evidence, family identity, or the CAS bindings — so a
    // legal Row B due-expiry family was rejected here exactly as it was in leaf
    // recovery fulfillment. The shared classifier proves both rows, strictly
    // before this arm's first head CAS.
    let partition = classify_prior_bound_recovery(plan, ctx, OwnFamilyKind::None)?; // reset activation
    if effects.revocation_target_cas().is_some() || effects.welcome_cas().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "reset revocation/welcome CAS",
        ));
    }
    if effects.metadata_change().is_none() {
        return Err(ExecutorError::InconsistentPlan(
            "reset activation carries no metadata",
        ));
    }
    if effects.invitation_quota_cas().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "reset invitation quota CAS",
        ));
    }
    let metadata = effects
        .metadata_change()
        .and_then(StateChange::after)
        .ok_or(ExecutorError::InconsistentPlan(
            "reset activation carries no metadata",
        ))?;
    let author_cols = ctx
        .metadata_author
        .as_ref()
        .ok_or(ExecutorError::MissingContext(
            "reset metadata author columns",
        ))?;
    let reset_request_id =
        preflight_reset_activation(plan, ctx, prior, retired, transition_id, seq_i64)?;

    // 1. Head CAS to the successor pointer (generation+1, stateVersion 0).
    transition::cas_conversation_head(
        transaction,
        &transition::ConversationHeadCas {
            conversation_id,
            expected_generation: prior_generation,
            expected_state_version: prior_state_version,
            expected_next_entry_seq,
            successor_generation: generation,
            successor_state_version: state_version,
            successor_next_entry_seq,
            close: None,
        },
    )
    .await?;

    // 2. Supersede the old generation (points at the retired state).
    transition::supersede_generation(
        transaction,
        &GenerationSupersede {
            conversation_id,
            generation: prior_generation,
            expected_state_version: prior_state_version,
            successor_state_version: retired_state_version,
            superseded_seq: seq_i64,
            superseded_at: applied_at,
        },
    )
    .await?;

    // 3. Retired generation state (old crypto, superseded, resetRetirement).
    transition::insert_generation_state_row(
        transaction,
        &NewGenerationState {
            conversation_id,
            generation: retired_generation,
            state_version: retired_state_version,
            group_id: prior.group_id().to_vec(),
            epoch: checked_i64(prior.epoch())?,
            group_context_hash: prior.group_context_hash().to_vec(),
            confirmation_tag: prior.confirmation_tag().to_vec(),
            lifecycle: GenerationStateLifecycle::Superseded,
            state_kind: GenerationStateKind::ResetRetirement,
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

    // 4. Fresh successor generation (epoch 0, fresh group id).
    transition::insert_generation(
        transaction,
        &NewGeneration {
            conversation_id,
            generation,
            group_id: coordinate.group_id().to_vec(),
            genesis_group_info_bytes: ctx.spine.genesis_group_info_bytes.clone(),
            genesis_group_info_sha256: ctx.spine.genesis_group_info_sha256.clone(),
            current_state_version: state_version,
            activated_seq: seq_i64,
            activated_at: applied_at,
        },
    )
    .await?;

    // 5. Successor generation state (fresh crypto, active, resetSuccessor).
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
            state_kind: GenerationStateKind::ResetSuccessor,
            producing_transition_id: transition_id,
            public_snapshot_bytes: successor_public_state.snapshot().to_vec(),
            snapshot_sha256: successor_public_state.snapshot_sha256().to_vec(),
            tree_summary_bytes: successor_tree.bytes().to_vec(),
            tree_summary_sha256: successor_tree.sha256().to_vec(),
            leaf_count: i64::try_from(
                successor_public_state
                    .binding()
                    .tree_summary()
                    .leaves()
                    .len(),
            )
            .map_err(|_| ExecutorError::ValueOutOfRange)?,
            created_at: applied_at,
        },
    )
    .await?;

    // 6. Entry (resetActivationEntry).
    let append = build_append_entry(
        ctx,
        conversation_id,
        generation,
        state_version,
        transition_id,
    );
    delivery::append_entry_at(transaction, &append, u64::try_from(seq_i64).unwrap()).await?;

    // 7. Transition (prior -> retired + successor; carries the reset request).
    transition::insert_transition_row(
        transaction,
        &NewTransition {
            transition_id,
            conversation_id,
            kind: TransitionKind::ResetActivation,
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
                // resetActivation: next == successor (both point at the fresh
                // generation), retired == (prior_gen, prior_sv + 1).
                prior: Some((prior_generation, prior_state_version)),
                next: Some((generation, state_version)),
                retired: Some((retired_generation, retired_state_version)),
                successor: Some((generation, state_version)),
            },
            reset_request_id: Some(reset_request_id),
            close_transition_id: None,
            metadata_snapshot_id: Some(author_cols.metadata_snapshot_id),
            entry_seq: seq_i64,
            accepted_at: applied_at,
        },
    )
    .await?;

    // 8. Successor metadata snapshot (self-origin, version from the binding).
    write_creation_metadata_snapshot(
        transaction,
        metadata,
        author_cols,
        &ctx.actor,
        conversation_id,
        generation,
        state_version,
        epoch,
        &coordinate.group_id().to_vec(),
        &coordinate.group_context_hash().to_vec(),
        &coordinate.confirmation_tag().to_vec(),
        transition_id,
        seq_i64,
        applied_at,
    )
    .await?;

    // 9. Close every old-generation leaf (facade-supplied) and install the
    //    successor genesis leaf(s). `leaf_changes` is a same-content diff that
    //    under-reports the generation change (the activator's new leaf has the
    //    same credential/index/keys as its old leaf), so the reset leaf ops are
    //    driven authoritatively by ctx.closing_leaf_periods + the successor
    //    hydration leaves rather than by the delta.
    for (device, old_leaf) in &ctx.closing_leaf_periods {
        let _ = device;
        transition::close_leaf_period(
            transaction,
            &LeafClose {
                leaf_period_id: *old_leaf,
                removed_state_version: retired_state_version,
                removed_transition_id: transition_id,
                removed_seq: seq_i64,
                removed_at: applied_at,
            },
        )
        .await?;
    }
    for (index, row) in hydration.leaves.iter().enumerate() {
        let leaf_period_id = *ctx
            .leaf_period_ids
            .get(index)
            .ok_or(ExecutorError::MissingContext("successor leaf period id"))?;
        write_successor_leaf(
            transaction,
            ctx,
            hydration,
            row,
            leaf_period_id,
            conversation_id,
            generation,
            transition_id,
            state_version,
            seq_i64,
            applied_at,
        )
        .await?;
    }

    // 10. Close old open intervals (Reset), open the activator's new one (Reset).
    for change in effects.interval_changes() {
        match (change.before(), change.after()) {
            (Some(_), Some(after)) => {
                let end = after.end().ok_or(ExecutorError::InconsistentPlan(
                    "reset closed interval has no end",
                ))?;
                let leaf = closing_leaf_period(ctx, after.recipient())?;
                delivery::close_application_interval(
                    transaction,
                    &ApplicationIntervalClose {
                        conversation_id,
                        recipient_did: device_did(after.recipient())?,
                        recipient_device_id: device_uuid(after.recipient()),
                        opening_transition_id: Uuid::from_bytes(*after.opening_transition_id()),
                        terminal_seq: checked_i64(end.seq())?,
                        closing_state_version: retired_state_version,
                        closing_transition_id: Uuid::from_bytes(*end.transition_id()),
                        closing_outer_entry_fingerprint: end.outer_entry_fingerprint().to_vec(),
                        closing_kind: repo_interval_close_kind(end.kind()),
                        closing_leaf_period_id: leaf,
                        removed_at: applied_at,
                    },
                )
                .await?;
            }
            (None, Some(after)) => {
                let opening_context = after.opening_context();
                let opening_leaf_period_id =
                    *ctx.leaf_period_ids
                        .first()
                        .ok_or(ExecutorError::MissingContext(
                            "successor interval leaf period",
                        ))?;
                delivery::insert_application_interval(
                    transaction,
                    &NewApplicationInterval {
                        membership_interval_id: Uuid::from_bytes(*after.opening_transition_id()),
                        conversation_id,
                        generation: checked_i64(opening_context.generation())?,
                        recipient_did: device_did(after.recipient())?,
                        recipient_device_id: device_uuid(after.recipient()),
                        start_seq: checked_i64(after.opening_seq())?,
                        opening_kind: IntervalOpeningKind::Reset,
                        opening_transition_id: Uuid::from_bytes(*after.opening_transition_id()),
                        opening_outer_entry_fingerprint: after
                            .opening_outer_entry_fingerprint()
                            .to_vec(),
                        opening_state_version: checked_i64(opening_context.state_version())?,
                        opening_group_id: opening_context.group_id().to_vec(),
                        opening_epoch: checked_i64(opening_context.epoch())?,
                        opening_group_context_hash: opening_context.group_context_hash().to_vec(),
                        opening_confirmation_tag: opening_context.confirmation_tag().to_vec(),
                        opening_leaf_period_id,
                        created_at: applied_at,
                    },
                )
                .await?;
            }
            _ => {
                return Err(ExecutorError::UnsupportedEffect(
                    "reset interval change shape",
                ))
            }
        }
    }

    // 11. Terminalize the pending reset request as consumed.
    transition::terminalize_reset_request(
        transaction,
        reset_request_id,
        &ResetRequestTermination::Consumed {
            terminal_transition_id: transition_id,
            terminal_at: applied_at,
        },
    )
    .await?;

    // 12. Audience + event.
    let recipients = build_entry_recipients(&ctx.entry_recipients)?;
    delivery::insert_entry_recipients(
        transaction,
        conversation_id,
        u64::try_from(seq_i64).unwrap(),
        &recipients,
    )
    .await?;
    let event_positions = write_events(transaction, ctx, None).await?;

    // 13. Supersede prior-coordinate open work the reset retired: the retired
    //     generation's pending welcome(s) + any open recovery request / active
    //     reservation / reserved package bound to the prior coordinate, and stale
    //     any prior-bound pending LEAVE request. The reset has ZERO own recovery/
    //     welcome/leave edges (its ONE own request edge is the reset request
    //     CONSUMED in step 11, counted as own below), so every recovery/welcome/
    //     leave delta MUST be a supersession/staling the calls below applied —
    //     reconcile rejects any that is neither (silent-drop guard). The reset
    //     loop in write_prior_bound_staling skips the own Pending->Consumed edge.
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
    reconcile_coordinate_change_families(
        effects,
        &FamilyCounts {
            reset_requests: 1,
            ..FamilyCounts::default()
        },
        &superseded,
    )?;

    Ok(AppliedTransition {
        allocated_seq: u64::try_from(seq_i64).unwrap(),
        entry_id: ctx.entry().entry_id,
        event_positions,
        successor_coordinate: plan.successor_coordinate().copied(),
    })
}

/// Apply an `acceptConversation` edge: promote a pending invitee to active and
/// atomically open the `add` leaf-recovery request + reservation bound to the
/// NEXT coordinate, reserving the acceptor's key package. `stateVersion+1`,
/// same crypto edge, no metadata / leaf / interval change.
#[allow(clippy::too_many_arguments)]
pub(in crate::chat_protocol::state_machine::executor) async fn apply_acceptance(
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
    historical_write_authority: Option<&HistoricalExecutionWriteAuthority>,
) -> Result<AppliedTransition, ExecutorError> {
    let effects = plan.effects();
    let hydration = plan.state();
    let coordinate = &hydration.coordinate; // next coordinate (same crypto, sv+1).
    let applied_at = ctx.applied_at;
    let head = effects
        .head_cas()
        .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
    let expected_prior = head
        .expected_prior()
        .ok_or(ExecutorError::InconsistentPlan(
            "acceptance needs an expected prior",
        ))?;
    let expected_generation = checked_i64(expected_prior.generation())?;
    let expected_state_version = checked_i64(expected_prior.state_version())?;
    let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;

    // Acceptance OWNS: one pending->active participant, one new open recovery
    // request (None->Open), one new active reservation (None->Active), one
    // Available->Reserved package transition. It ALSO calls
    // `resolve_prior_bound_work` (via `plan_accept_conversation_inner`), so it CAN
    // carry (a legal interleaving) prior-coordinate open-work SUPERSESSIONS — a
    // DIFFERENT member's open recovery request (Open->Superseded) + reservation
    // (Active->Released) + reserved package (Reserved->Available), a prior pending
    // Welcome (Pending->Superseded), AND a prior-bound pending reset/leave request
    // (Pending->Stale). The own vs superseded partition is proven by the own-counts
    // below + the reconciliation; acceptance owns NO reset/leave edge (own 0 for
    // both). The `acceptConversation` kind is DB-LEGAL as the terminal authority
    // for both stale edges — reset staling has no kind restriction, and
    // `assert_leave_request_mapping` forbids only `leaveCommit`/`leavePolicy` (the
    // deferred Concerns 1/3 wall applies to zero-leaf-leave + leave-fulfillment
    // ONLY, not acceptance). So reset/leave staling is wired here exactly like
    // apply_policy. Every family the acceptance never carries is a hard error.
    reject_if_present("leaf_changes", effects.leaf_changes())?;
    reject_if_present("interval_changes", effects.interval_changes())?;
    reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
    reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
    if effects.metadata_change().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "acceptance metadata change",
        ));
    }
    if effects.revocation_target_cas().is_some() || effects.welcome_cas().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "acceptance revocation/welcome CAS",
        ));
    }
    if effects.invitation_quota_cas().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "acceptance invitation quota CAS",
        ));
    }
    // Exactly one pending->active participant.
    let participant_change = {
        let changes = effects.participant_changes();
        if changes.len() != 1 {
            return Err(ExecutorError::InconsistentPlan(
                "acceptance must change exactly one participant",
            ));
        }
        match (changes[0].before(), changes[0].after()) {
            (Some(before), Some(after))
                if before.status() == ParticipantStatus::Pending
                    && after.status() == ParticipantStatus::Active =>
            {
                after
            }
            _ => {
                return Err(ExecutorError::UnsupportedEffect(
                    "acceptance participant change is not pending->active",
                ))
            }
        }
    };
    // Exactly one new open recovery request + one new active reservation +
    // one package transition (Available->Reserved).
    let recovery = effects
        .recovery_request_changes()
        .iter()
        .find_map(|change| match (change.before(), change.after()) {
            (None, Some(after)) => Some(after),
            _ => None,
        })
        .ok_or(ExecutorError::InconsistentPlan(
            "acceptance adds no open recovery request",
        ))?;
    // Exactly ONE own edge per family (None->Open recovery, None->Active
    // reservation, Available->Reserved package). Any OTHER recovery/reservation/
    // package delta must be a prior-bound supersession (Open->Superseded /
    // Active->Released / Reserved->Available), consumed by
    // write_prior_bound_supersessions and proven by the tail reconciliation.
    let own_open = effects
        .recovery_request_changes()
        .iter()
        .filter(|change| matches!((change.before(), change.after()), (None, Some(_))))
        .count();
    let own_reserved = effects
        .reservation_changes()
        .iter()
        .filter(|change| {
            matches!((change.before(), change.after()), (None, Some(a))
                    if a.status() == ReservationStatus::Active)
        })
        .count();
    let own_package = effects
        .package_transitions()
        .iter()
        .filter(|edge| edge.from == PackageStatus::Available && edge.to == PackageStatus::Reserved)
        .count();
    if own_open != 1 || own_reserved != 1 || own_package != 1 {
        return Err(ExecutorError::InconsistentPlan(
            "acceptance must add exactly one own recovery request + reservation + package edge",
        ));
    }
    // Load-bearing recovery-package CAS bijection (over ALL edges) + the OWN
    // package edge's driven-ref + direction; any prior-bound Reserved->Available
    // supersession edges are validated by write_prior_bound_supersessions.
    verify_recovery_package_consistency(
        effects,
        recovery.key_package_ref(),
        PackageStatus::Available,
        PackageStatus::Reserved,
    )?;

    // Prior-bound recovery families. Acceptance previously proved only its OWN
    // family and left every prior-bound supersession to the writer, unproven
    // before the head CAS. The classifier derives the own family independently
    // by exact typed shape and proves every other family, Row A and Row B.
    let partition = classify_prior_bound_recovery(plan, ctx, OwnFamilyKind::Acceptance)?;

    // 1. Head CAS advances the coordinate + counter (sv+1, same generation).
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

    // 3. Successor generation state (acceptConversation, identical crypto edge).
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
            state_kind: GenerationStateKind::AcceptConversation,
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

    // 4. Entry (participantAcceptanceEntry) at the allocated seq.
    let append = build_append_entry(
        ctx,
        conversation_id,
        generation,
        state_version,
        transition_id,
    );
    delivery::append_entry_at(transaction, &append, u64::try_from(seq_i64).unwrap()).await?;

    // 5. Transition (prior -> next).
    transition::insert_transition_row(
        transaction,
        &NewTransition {
            transition_id,
            conversation_id,
            kind: TransitionKind::AcceptConversation,
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

    // 6. Promote the pending participant to active with acceptance provenance.
    let open = ctx
        .recovery_open
        .as_ref()
        .ok_or(ExecutorError::MissingContext("recovery open context"))?;
    let participant_period_id = open
        .participant_period_id
        .ok_or(ExecutorError::MissingContext(
            "acceptance participant period id",
        ))?;
    transition::cas_participant_pending_to_active(
        transaction,
        &ParticipantAcceptanceCas {
            participant_period_id,
            conversation_id,
            user_did: principal_did(participant_change.principal())?,
            acceptance: ParticipantAcceptance {
                acceptance_transition_id: transition_id,
                acceptance_entry_id: ctx.entry().entry_id,
                accepted_at: applied_at,
            },
        },
    )
    .await?;

    // 7-9. The atomic recovery open (request + reservation + package reserve),
    //      bound to the NEXT coordinate; requester = recipient = the acceptor.
    write_recovery_open(transaction, ctx, recovery, conversation_id, applied_at).await?;

    // 10. Audience + events.
    let recipients = build_entry_recipients(&ctx.entry_recipients)?;
    if !recipients.is_empty() {
        delivery::insert_entry_recipients(
            transaction,
            conversation_id,
            u64::try_from(seq_i64).unwrap(),
            &recipients,
        )
        .await?;
    }
    let event_positions = write_events(transaction, ctx, historical_write_authority).await?;

    // 11. Supersede any prior-coordinate open work a DIFFERENT member left bound
    //     to the retired coordinate (Open->Superseded recovery / Active->Released
    //     reservation / Reserved->Available package + Pending->Superseded welcome).
    //     Acceptance's OWN edges are the None->Open recovery / None->Active
    //     reservation / Available->Reserved package applied by write_recovery_open
    //     above (own counts {1,1,1}); write_prior_bound_supersessions SKIPS those
    //     (they are not the supersession shape), so it consumes ONLY the other
    //     member's work, and reconcile proves own + superseded == total.
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
    // Stale any prior-bound pending reset/leave request the acceptance retired
    // (own 0 — acceptance creates/consumes neither; kind `acceptConversation` is
    // DB-legal for both stale edges), exactly like apply_policy.
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
    reconcile_coordinate_change_families(
        effects,
        &FamilyCounts {
            requests: 1,
            reservations: 1,
            packages: 1,
            welcomes: 0,
            reset_requests: 0,
            leave_requests: 0,
        },
        &superseded,
    )?;

    Ok(AppliedTransition {
        allocated_seq: u64::try_from(seq_i64).unwrap(),
        entry_id: ctx.entry().entry_id,
        event_positions,
        successor_coordinate: plan.successor_coordinate().copied(),
    })
}
