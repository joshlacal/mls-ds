#![allow(unused_imports)]
use super::*;

#[allow(clippy::too_many_arguments)]
pub(in crate::chat_protocol::state_machine::executor) async fn apply_creation(
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
    let coordinate = &hydration.coordinate;
    let applied_at = ctx.applied_at;
    let group_id = coordinate.group_id().to_vec();
    let group_context_hash = coordinate.group_context_hash().to_vec();
    let confirmation_tag = coordinate.confirmation_tag().to_vec();

    // Creation carries no prior; every side family is a pure insert. Reject
    // any family this path does not translate so nothing is silently dropped.
    reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
    reject_if_present(
        "recovery_request_changes",
        effects.recovery_request_changes(),
    )?;
    reject_if_present("reservation_changes", effects.reservation_changes())?;
    reject_if_present("reset_request_changes", effects.reset_request_changes())?;
    reject_if_present("leave_request_changes", effects.leave_request_changes())?;
    reject_if_present("welcome_changes", effects.welcome_changes())?;
    reject_if_present("package_transitions", effects.package_transitions())?;
    reject_if_present("recovery_package_cas", effects.recovery_package_cas())?;
    reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
    if effects.revocation_target_cas().is_some() {
        return Err(ExecutorError::UnsupportedEffect("revocation_target_cas"));
    }
    if effects.welcome_cas().is_some() {
        return Err(ExecutorError::UnsupportedEffect("welcome_cas"));
    }
    // invitation_quota_cas: EXPLICITLY consumed, not written. It is the
    // WITNESS of the planner's locked live-pending-invitation counts for the
    // newly pending recipients; there is no row for the executor to persist.
    // The invitation quota is enforced by the `enforce_invitation_quota`
    // DEFERRED trigger, which independently re-counts live pending
    // invitations under `FOR UPDATE` at COMMIT. Production
    // `into_persistence_plan` requires EVERY Creation/Policy plan to carry
    // this binding (else `InvalidHydrationAuthority`); a missing binding here
    // is an `InconsistentPlan`, so this family is consumed — never silently
    // dropped — exactly as the exhaustive-dispatch contract demands. A
    // reconstructed historical prefix carries no live quota binding at all.
    if historical_write_authority.is_none() {
        let _invitation_quota_witness =
            effects
                .invitation_quota_cas()
                .ok_or(ExecutorError::InconsistentPlan(
                    "creation plan missing invitation quota CAS binding",
                ))?;
    }
    // effects.authority() is likewise deliberately unread: it is the sealed
    // control/request/revocation authority that JUSTIFIED the plan
    // (provenance/witness), not a persistable row family. The signed bytes it
    // attests to reach the durable rows through `ExecutionContext` (the entry
    // + transition signed material), which is caller-supplied input.

    // 1. Head (INSERT — true absence; the seq counter starts already advanced
    //    past the genesis entry).
    let head_kind = match hydration.kind {
        ConversationKind::Group => ConversationHeadKind::Group,
        ConversationKind::Direct => {
            let (low, high) = direct_pair(&hydration.participants)?;
            ConversationHeadKind::Direct {
                direct_did_low: low,
                direct_did_high: high,
            }
        }
    };
    transition::insert_conversation_head(
        transaction,
        &transition::NewConversationHead {
            conversation_id,
            kind: head_kind,
            current_generation: generation,
            current_state_version: state_version,
            next_entry_seq: successor_next_entry_seq,
            created_at: applied_at,
            is_remote: ctx.is_remote,
            sequencer_ds: ctx.sequencer_ds.clone(),
            sequencer_term: ctx.sequencer_term,
        },
    )
    .await?;

    // 2. Generation (activated at the genesis seq/instant).
    transition::insert_generation(
        transaction,
        &NewGeneration {
            conversation_id,
            generation,
            group_id: group_id.clone(),
            genesis_group_info_bytes: ctx.spine.genesis_group_info_bytes.clone(),
            genesis_group_info_sha256: ctx.spine.genesis_group_info_sha256.clone(),
            current_state_version: state_version,
            activated_seq: seq_i64,
            activated_at: applied_at,
        },
        crate::identity::service_did_base_opt().as_deref(),
    )
    .await?;

    // 3. Generation state (the produced `creation` public coordinate).
    transition::insert_generation_state_row(
        transaction,
        &NewGenerationState {
            conversation_id,
            generation,
            state_version,
            group_id: group_id.clone(),
            epoch,
            group_context_hash: group_context_hash.clone(),
            confirmation_tag: confirmation_tag.clone(),
            lifecycle: GenerationStateLifecycle::Active,
            state_kind: GenerationStateKind::Creation,
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

    // 4. Entry at the exact allocated seq (the head already advanced the
    //    counter). Immediate FK targets for the transition's `entry_seq`.
    let append = build_append_entry(
        ctx,
        conversation_id,
        generation,
        state_version,
        transition_id,
    );
    delivery::append_entry_at(transaction, &append, u64::try_from(seq_i64).unwrap()).await?;

    // 5. Metadata snapshot — REQUIRED for creation by the deferred mapping.
    let metadata = effects
        .metadata_change()
        .and_then(StateChange::after)
        .ok_or(ExecutorError::InconsistentPlan(
            "creation plan carries no metadata snapshot",
        ))?;
    let author_cols = ctx
        .metadata_author
        .as_ref()
        .ok_or(ExecutorError::MissingContext("metadata author columns"))?;
    write_creation_metadata_snapshot(
        transaction,
        metadata,
        author_cols,
        &ctx.actor,
        conversation_id,
        generation,
        state_version,
        epoch,
        &group_id,
        &group_context_hash,
        &confirmation_tag,
        transition_id,
        seq_i64,
        applied_at,
    )
    .await?;

    // 6. Transition row (needs entry_seq; entry written above).
    transition::insert_transition_row(
        transaction,
        &NewTransition {
            transition_id,
            conversation_id,
            kind: TransitionKind::Creation,
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
                prior: None,
                next: Some((generation, state_version)),
                retired: None,
                successor: None,
            },
            reset_request_id: None,
            close_transition_id: None,
            metadata_snapshot_id: Some(author_cols.metadata_snapshot_id),
            entry_seq: seq_i64,
            accepted_at: applied_at,
        },
    )
    .await?;

    // 7. Participant periods, then leaves, then intervals — every change is a
    //    pure insert for creation; a non-insert shape is a hard error.
    write_participants(
        transaction,
        ctx,
        hydration,
        effects,
        transition_id,
        applied_at,
        false,
    )
    .await?;
    let leaf_ids = write_creation_leaves(
        transaction,
        ctx,
        hydration,
        effects,
        conversation_id,
        generation,
        transition_id,
        state_version,
        seq_i64,
        applied_at,
    )
    .await?;
    write_creation_intervals(transaction, effects, &leaf_ids, conversation_id, applied_at).await?;

    // 8. Frozen control-entry audience.
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

    // 9. Events + audience + outbox.
    let event_positions = write_events(transaction, ctx, historical_write_authority).await?;

    Ok(AppliedTransition {
        allocated_seq: u64::try_from(seq_i64).unwrap(),
        entry_id: ctx.entry().entry_id,
        event_positions,
        successor_coordinate: plan.successor_coordinate().copied(),
    })
}

/// Apply a group `policy` addParticipant edge: same crypto coordinate,
/// `stateVersion+1`, no metadata / leaf / interval change. Reuses the head
/// CAS (existing conversation), the generation-pointer CAS, and the
/// participant-insert path that creation uses; the only new participant is
/// the added `pending/member` (the `StateChange` diff).
#[allow(clippy::too_many_arguments)]
pub(in crate::chat_protocol::state_machine::executor) async fn apply_policy(
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
    let coordinate = &hydration.coordinate;
    let applied_at = ctx.applied_at;
    let head = effects
        .head_cas()
        .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
    let expected_prior = head
        .expected_prior()
        .ok_or(ExecutorError::InconsistentPlan(
            "policy needs an expected prior",
        ))?;
    let expected_generation = checked_i64(expected_prior.generation())?;
    let expected_state_version = checked_i64(expected_prior.state_version())?;
    let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;
    validate_policy_participant_writes(effects, hydration, ctx, expected_prior, transition_id)?;

    // Policy is a coordinate-only participant edge. It carries NO leaf /
    // interval / terminal-proof change, but `plan_policy_transition` calls
    // `resolve_prior_bound_work` unconditionally, so it CAN carry (a legal
    // interleaving) prior-coordinate open-work SUPERSESSIONS — a co-open
    // leaf-recovery request (Open->Superseded) + its reservation (Active->Released)
    // + reserved package (Reserved->Available), a prior pending Welcome
    // (Pending->Superseded), and prior-bound reset/leave STALING (Pending->Stale).
    // Policy owns NONE of those (own counts 0); every such delta MUST be a
    // supersession/staling the shared writers apply at the tail, exact-shape
    // checked here (mirroring the close/commit arms). `recovery_package_cas` is the
    // production-shape package witness the bijection validates, NOT a rejected
    // family. (kind is `policy`, DB-legal for the recovery/welcome/leave edges.)
    reject_if_present("leaf_changes", effects.leaf_changes())?;
    reject_if_present("interval_changes", effects.interval_changes())?;
    reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
    reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
    // Prior-bound recovery families. The three shape loops this replaces
    // accepted only Row A (Open->Superseded / Active->Released) and never
    // checked terminal evidence, family identity, or the CAS bindings — so a
    // legal Row B due-expiry family was rejected here exactly as it was in leaf
    // recovery fulfillment. The shared classifier proves both rows, strictly
    // before this arm's first head CAS.
    let partition = classify_prior_bound_recovery(plan, ctx, OwnFamilyKind::None)?; // policy

    // Prior-bound reset / leave / Welcome families. Policy owns none of them.
    classify_prior_bound_staling(plan, ctx, OwnStalingKind::None)?;
    if effects.metadata_change().is_some() {
        return Err(ExecutorError::UnsupportedEffect("policy metadata change"));
    }
    if effects.revocation_target_cas().is_some() {
        return Err(ExecutorError::UnsupportedEffect("revocation_target_cas"));
    }
    if effects.welcome_cas().is_some() {
        return Err(ExecutorError::UnsupportedEffect("welcome_cas"));
    }
    // invitation_quota_cas: consumed as witness (see apply_creation) — a
    // group policy addParticipant edge is the other kind production requires
    // to carry it. The quota itself is enforced by the deferred
    // `enforce_invitation_quota` trigger; a missing binding is InconsistentPlan.
    // A reconstructed historical prefix carries no live quota binding at all.
    if historical_write_authority.is_none() {
        let _invitation_quota_witness =
            effects
                .invitation_quota_cas()
                .ok_or(ExecutorError::InconsistentPlan(
                    "policy plan missing invitation quota CAS binding",
                ))?;
    }

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

    // 3. Successor generation state (policy kind, identical crypto edge).
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
            state_kind: GenerationStateKind::Policy,
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

    // 4. Entry at the allocated seq.
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
            kind: TransitionKind::Policy,
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

    // 6. Apply the already-classified pending inserts and/or exact active
    //    role CAS updates. Role changes consume no participant-period IDs.
    write_participants(
        transaction,
        ctx,
        hydration,
        effects,
        transition_id,
        applied_at,
        true,
    )
    .await?;
    terminalize_policy_participants(
        transaction,
        effects,
        ctx,
        transition_id,
        seq_i64,
        applied_at,
    )
    .await?;

    // 7. Audience + events.
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

    // 8. Supersede prior-coordinate open work the policy edge retired (an open
    //    recovery request / active reservation / reserved package + a prior pending
    //    Welcome) AND stale any prior-bound pending reset/leave request. Policy owns
    //    NONE of these families (own == default), so every such delta MUST be a
    //    supersession/staling the shared writers below applied — reconcile rejects
    //    any that is neither (silent-drop guard).
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

/// Apply a `signedMetadataTransition`: same MLS crypto coordinate,
/// `stateVersion+1`, one self-origin/version-advancing encrypted metadata
/// snapshot, and no membership/leaf/interval mutation.
#[allow(clippy::too_many_arguments)]
pub(in crate::chat_protocol::state_machine::executor) async fn apply_metadata_transition(
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
            "metadata transition needs an expected prior",
        ))?;
    let expected_generation = checked_i64(expected_prior.generation())?;
    let expected_state_version = checked_i64(expected_prior.state_version())?;
    let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;
    let binding = preflight_metadata_transition(plan, ctx, transition_id, seq_i64)?;
    let partition = &binding.prior_bound;

    // 1. Serialize and advance the exact head coordinate + entry counter.
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

    // 2. Advance the active generation's state-version pointer.
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

    // 3. Append the coordinate-only metadata successor state.
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
            state_kind: GenerationStateKind::Metadata,
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

    // 4. Persist the canonical control entry at the head-allocated sequence.
    let append = build_append_entry(
        ctx,
        conversation_id,
        generation,
        state_version,
        transition_id,
    );
    delivery::append_entry_at(transaction, &append, u64::try_from(seq_i64).unwrap()).await?;

    // 5. Persist the exact self-origin metadata snapshot (1A: Space-backed avatar).
    write_metadata_update_snapshot(
        transaction,
        binding.metadata,
        binding.author,
        binding.avatar.map(MetadataAvatarPersistence::snapshot),
        conversation_id,
        generation,
        state_version,
        epoch,
        coordinate.group_id(),
        coordinate.group_context_hash(),
        coordinate.confirmation_tag(),
        transition_id,
        seq_i64,
        applied_at,
    )
    .await?;

    // 6. Persist the signed transition and bind it to that snapshot.
    transition::insert_transition_row(
        transaction,
        &NewTransition {
            transition_id,
            conversation_id,
            kind: TransitionKind::Metadata,
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
            metadata_snapshot_id: Some(binding.author.metadata_snapshot_id),
            entry_seq: seq_i64,
            accepted_at: applied_at,
        },
    )
    .await?;

    // 7. Frozen entry audience + canonical server event schedule.
    let recipients = build_entry_recipients(&ctx.entry_recipients)?;
    delivery::insert_entry_recipients(
        transaction,
        conversation_id,
        u64::try_from(seq_i64).unwrap(),
        &recipients,
    )
    .await?;
    let event_positions = write_events(transaction, ctx, None).await?;

    // 8. Terminalize every prior-coordinate work item retired by this
    // coordinate change, then prove no family was silently skipped.
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
