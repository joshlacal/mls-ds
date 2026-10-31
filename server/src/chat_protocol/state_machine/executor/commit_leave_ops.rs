#![allow(unused_imports)]
use super::*;


/// Apply a generic `signedCommitTransition` (zero Adds): an epoch-changing
/// crypto commit that may carry canonical RemoveLeaf effects. sv+1 AND epoch+1
/// with a fresh hash/tag, metadata re-encryption, exact removed leaf-period and
/// application-interval closes, and no participant terminalization or own
/// welcome/recovery work. Distinguished from a fulfillment by the ABSENCE of a
/// new Welcome (a recovery fulfillment always emits exactly one), backstopped
/// by the exact-shape and bijection guards below.
#[allow(clippy::too_many_arguments)]
pub(in crate::chat_protocol::state_machine::executor) async fn apply_generic_commit(
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
    let coordinate = &hydration.coordinate; // successor (sv+1, epoch+1).
    let applied_at = ctx.applied_at;
    let head = effects
        .head_cas()
        .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
    let expected_prior = head
        .expected_prior()
        .ok_or(ExecutorError::InconsistentPlan(
            "generic commit needs a prior",
        ))?;
    let expected_generation = checked_i64(expected_prior.generation())?;
    let expected_state_version = checked_i64(expected_prior.state_version())?;
    let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;

    // A generic no-Add commit changes the crypto coordinate + re-encrypted
    // metadata, MAY close signed RemoveLeaf devices and their intervals, and MAY
    // carry legal prior-coordinate open-work supersession/staling. It has no
    // participant change and no OWN recovery/reset/leave work.
    reject_if_present("participant_changes", effects.participant_changes())?;
    reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
    reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
    // recovery_request_changes / reservation_changes / package_transitions /
    // welcome_changes: NOT rejected — a coordinate-changing commit supersedes
    // prior-coordinate open work (request->Superseded, reservation->Released,
    // package Reserved->Available) and a prior pending Welcome. Handled by
    // write_prior_bound_supersessions + write_welcome_supersessions; every such
    // delta MUST be a supersession shape (exact-shape checks below).
    // Prior-bound recovery families. The three shape loops this replaces
    // accepted only Row A (Open->Superseded / Active->Released) and never
    // checked terminal evidence, family identity, or the CAS bindings — so a
    // legal Row B due-expiry family was rejected here exactly as it was in leaf
    // recovery fulfillment. The shared classifier proves both rows, strictly
    // before this arm's first head CAS.
    let partition = classify_prior_bound_recovery(plan, ctx, OwnFamilyKind::None)?; // generic commit

    // Prior-bound reset / leave / Welcome families. A generic commit owns none of
    // them, so every such delta must be an exact terminalization of prior-bound
    // work. The tail reconciliation only counts what the writers consumed, and
    // both writers accept a `Pending->Expired` shape, so an incoherent expiry
    // used to commit here.
    classify_prior_bound_staling(plan, ctx, OwnStalingKind::None)?;
    if effects.revocation_target_cas().is_some()
        || effects.welcome_cas().is_some()
        || effects.invitation_quota_cas().is_some()
    {
        return Err(ExecutorError::UnsupportedEffect(
            "generic commit revocation/welcome/quota CAS",
        ));
    }
    // Validate the leaf/interval/context three-way bijection before the first
    // write. Some->None is a real signed Remove. Some->Some is tolerated only
    // for the actor's stable leaf identity/key material (the public tree's
    // sender encryption-key update is not stored in member_devices). Adds,
    // empty deltas, foreign/duplicate context, and every unmatched close reject.
    let mut removed_devices = BTreeSet::new();
    for change in effects.leaf_changes() {
        match (change.before(), change.after()) {
            (Some(before), None) => {
                if !removed_devices.insert(before.device.clone()) {
                    return Err(ExecutorError::InconsistentPlan(
                        "generic commit duplicates a removed leaf",
                    ));
                }
            }
            (Some(before), Some(after))
                if before.device == after.device
                    && before.leaf_index == after.leaf_index
                    && before.basic_credential == after.basic_credential
                    && before.signature_key == after.signature_key
                    && before.key_package_ref == after.key_package_ref
                    && device_did(&before.device)? == ctx.actor.user_did
                    && device_uuid(&before.device) == ctx.actor.device_id => {}
            (None, Some(_)) => {
                return Err(ExecutorError::InconsistentPlan(
                    "generic commit must not add a leaf",
                ))
            }
            (None, None) => {
                return Err(ExecutorError::InconsistentPlan(
                    "generic commit carries an empty leaf delta",
                ))
            }
            (Some(_), Some(_)) => {
                return Err(ExecutorError::InconsistentPlan(
                    "generic commit carries a non-sender leaf update",
                ))
            }
        }
    }
    let declared_closed = effects
        .closed_intervals()
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if !effects.opened_intervals().is_empty() || declared_closed != removed_devices {
        return Err(ExecutorError::InconsistentPlan(
            "generic commit removed-leaf and closed-interval declarations disagree",
        ));
    }
    let mut interval_devices = BTreeSet::new();
    for change in effects.interval_changes() {
        let (before, after) = match (change.before(), change.after()) {
            (Some(before), Some(after)) => (before, after),
            _ => {
                return Err(ExecutorError::InconsistentPlan(
                    "generic commit interval delta is not an exact close",
                ))
            }
        };
        let end = after.end.as_ref().ok_or(ExecutorError::InconsistentPlan(
            "generic commit interval close has no end",
        ))?;
        if before.recipient != after.recipient
            || before.generation != after.generation
            || before.opening != after.opening
            || before.opening_kind != after.opening_kind
            || before.opening_context != after.opening_context
            || before.end.is_some()
            || end.kind != CloseKind::Remove
            || end.evidence != hydration.producer
            || !removed_devices.contains(&after.recipient)
            || !interval_devices.insert(after.recipient.clone())
        {
            return Err(ExecutorError::InconsistentPlan(
                "generic commit interval close mismatches its removed leaf",
            ));
        }
    }
    if interval_devices != removed_devices {
        return Err(ExecutorError::InconsistentPlan(
            "generic commit removal lacks exactly one matching interval close",
        ));
    }
    let mut context_devices = BTreeSet::new();
    let mut context_periods = BTreeSet::new();
    for (device, period_id) in &ctx.closing_leaf_periods {
        if !removed_devices.contains(device)
            || !context_devices.insert(device.clone())
            || !context_periods.insert(*period_id)
        {
            return Err(ExecutorError::InconsistentPlan(
                "generic commit closing leaf context is foreign or duplicated",
            ));
        }
    }
    for device in &removed_devices {
        if !context_devices.contains(device) {
            return Err(ExecutorError::MissingContext(
                "closing leaf period id for generic Remove",
            ));
        }
    }
    // Metadata re-encryption is MANDATORY (DDL requires_snapshot ∋ commit).
    let metadata = effects
        .metadata_change()
        .and_then(StateChange::after)
        .ok_or(ExecutorError::InconsistentPlan(
            "generic commit carries no metadata re-encryption",
        ))?;
    let author_cols = ctx
        .metadata_author
        .as_ref()
        .ok_or(ExecutorError::MissingContext(
            "generic commit metadata author",
        ))?;
    let leaf_period_bindings = removed_devices
        .iter()
        .map(|device| {
            Ok(ActiveLeafPeriodBinding {
                leaf_period_id: closing_leaf_period(ctx, device)?,
                conversation_id,
                generation: expected_generation,
                user_did: device_did(device)?,
                device_id: device_uuid(device),
            })
        })
        .collect::<Result<Vec<_>, ExecutorError>>()?;
    if !transition::lock_active_leaf_period_bindings(transaction, &leaf_period_bindings).await? {
        return Err(ExecutorError::InconsistentPlan(
            "generic commit closing leaf period mismatches its removed device",
        ));
    }

    // 1. Head CAS sv+1 (the epoch bump lives in the gen_state).
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

    // 2. Generation state-version pointer CAS (same generation).
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

    // 3. `commit`/active gen_state at the NEW epoch (fresh hash/tag).
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
            state_kind: GenerationStateKind::Commit,
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

    // 4. Entry (commitEntry).
    let append = build_append_entry(
        ctx,
        conversation_id,
        generation,
        state_version,
        transition_id,
    );
    delivery::append_entry_at(transaction, &append, u64::try_from(seq_i64).unwrap()).await?;

    // 5. Transition (kind commit, prior -> next).
    transition::insert_transition_row(
        transaction,
        &NewTransition {
            transition_id,
            conversation_id,
            kind: TransitionKind::Commit,
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
            metadata_snapshot_id: Some(author_cols.metadata_snapshot_id),
            entry_seq: seq_i64,
            accepted_at: applied_at,
        },
    )
    .await?;

    // 6. Metadata re-encryption snapshot (carry-forward author/origin/version).
    write_commit_metadata_snapshot(
        transaction,
        metadata,
        author_cols,
        conversation_id,
        generation,
        state_version,
        epoch,
        &coordinate.group_id().to_vec(),
        &coordinate.group_context_hash().to_vec(),
        &coordinate.confirmation_tag().to_vec(),
        transition_id,
        applied_at,
    )
    .await?;

    // 7. Close every removed leaf period and its one exact Remove interval.
    for change in effects.leaf_changes() {
        if let (Some(before), None) = (change.before(), change.after()) {
            transition::close_leaf_period(
                transaction,
                &LeafClose {
                    leaf_period_id: closing_leaf_period(ctx, before.device())?,
                    removed_state_version: state_version,
                    removed_transition_id: transition_id,
                    removed_seq: seq_i64,
                    removed_at: applied_at,
                },
            )
            .await?;
        }
    }
    for change in effects.interval_changes() {
        let after = change.after().ok_or(ExecutorError::InconsistentPlan(
            "validated generic interval close disappeared",
        ))?;
        let end = after.end().ok_or(ExecutorError::InconsistentPlan(
            "validated generic interval end disappeared",
        ))?;
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
                closing_leaf_period_id: closing_leaf_period(ctx, after.recipient())?,
                removed_at: applied_at,
            },
        )
        .await?;
    }

    // 8. Audience + events.
    let recipients = build_entry_recipients(&ctx.entry_recipients)?;
    delivery::insert_entry_recipients(
        transaction,
        conversation_id,
        u64::try_from(seq_i64).unwrap(),
        &recipients,
    )
    .await?;
    let event_positions = write_events(transaction, ctx, None).await?;
    // Supersede prior-coordinate open work (requests/reservations/packages) +
    // any prior pending Welcome the epoch change retired.
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
    // Durably stale any prior-bound pending reset/leave request the epoch change
    // retired (kind is `commit`, DB-legal for the leave `stale` edge).
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
    // Silent-drop guard: a generic commit has NO own recovery/reservation/package/
    // welcome/reset/leave edge — every such delta MUST be a supersession/staling the
    // calls above applied. The per-delta shape loops above already reject a malformed
    // recovery/reservation/package delta; this additionally catches a malformed
    // welcome delta (e.g. Pending->Expired) or a non-Pending->Stale reset/leave delta
    // that the writers skip, closing the last silent-drop path.
    reconcile_coordinate_change_families(effects, &FamilyCounts::default(), &superseded)?;

    Ok(AppliedTransition {
        allocated_seq: u64::try_from(seq_i64).unwrap(),
        entry_id: ctx.entry().entry_id,
        event_positions,
        successor_coordinate: plan.successor_coordinate().copied(),
    })
}

/// Apply a `leaveCommitFulfillment` (`PlanKind::Commit`): a DIFFERENT-DID
/// current member commits a Remove of every requester leaf, fulfilling the
/// requester's retained group-leave consent. `sv+1` AND `epoch+1` (fresh
/// hash/tag), metadata re-encryption carry-forward (`leaveCommit` ∈
/// requires_snapshot), every requester leaf closed + its interval closed
/// (`Remove`, inclusive at the fulfillment seq), the requester participant
/// terminalized, and the pending leave request marked `fulfilled` (bound to
/// this `leaveCommit` transition). Coordinate-changing, so it runs the SHARED
/// prior-bound supersession path WITH the reconciliation from the start — the
/// fulfillment-scenario prior carries a pending Welcome the epoch change
/// supersedes (own welcome 0 + superseded 1). The committer's own key rotation
/// surfaces as a `(Some,Some)` leaf change with no DS row impact (tolerated).
#[allow(clippy::too_many_arguments)]
/// The synchronous family guards `apply_leave_fulfillment` runs before its first
/// writer, extracted so they are reachable without a database.
///
/// DEFECT 1 lived here: the second line used to be
/// `reject_if_present("recovery_package_cas", ..)`, which — because
/// `into_persistence_plan` enforces the CAS <-> edge bijection — meant "reject any
/// plan carrying any package edge", the exact opposite of the arm's own comment.
/// Any `leaveCommit` on a coordinate with open recovery work was planner-legal and
/// executor-fatal. `apply_leave_fulfillment` is `async` and needs a live transaction,
/// so before this extraction the shipped defect could be reinstated with the whole
/// suite still green. It is now pinned by
/// `leave_fulfillment_preflight_classifies_prior_bound_work`.
pub(in crate::chat_protocol::state_machine::executor) fn preflight_leave_fulfillment(
    plan: &ConversationPersistencePlan,
    ctx: &ExecutionContext,
) -> Result<PriorBoundPartition, ExecutorError> {
    let effects = plan.effects();
    reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
    // Prior-bound package work is CLASSIFIED, not rejected.
    let partition = classify_prior_bound_recovery(plan, ctx, OwnFamilyKind::None)?;
    // Prior-bound reset / leave / Welcome families. The arm's ONE own leave edge
    // (Pending->Fulfilled) is selected out by kind; every other delta must be an
    // exact terminalization of prior-bound work.
    classify_prior_bound_staling(plan, ctx, OwnStalingKind::LeaveFulfillment)?;
    reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
    if effects.revocation_target_cas().is_some()
        || effects.welcome_cas().is_some()
        || effects.invitation_quota_cas().is_some()
    {
        return Err(ExecutorError::UnsupportedEffect(
            "leave fulfillment revocation/welcome/quota CAS",
        ));
    }
    Ok(partition)
}

/// Partition `apply_leave_fulfillment`'s leave-request deltas and return the ONE
/// request the commit fulfills (ADR-019 Erratum 01).
///
/// Extracted so it is reachable WITHOUT a database, for the same reason
/// `preflight_leave_fulfillment` was: `apply_leave_fulfillment` is `async` and
/// needs a live transaction, so a shipped defect in this partition could be
/// reinstated with the whole suite still green. Pinned by
/// `leave_fulfillment_partition_accepts_an_overdue_prior_bound_leave`.
pub(in crate::chat_protocol::state_machine::executor) fn partition_leave_fulfillment_requests(
    effects: &TransitionEffects,
) -> Result<[u8; 16], ExecutorError> {
    // Partition the leave-request deltas (ADR-019 Erratum 01). A leaveCommit
    // fulfills EXACTLY ONE requester's leave (its own Pending->Fulfilled edge) and
    // MAY additionally retire any number of OTHER members' predecessor-bound
    // pending leaves — `Pending->Stale` when the commit supersedes them, or
    // `Pending->Expired` when their own 24h `expires_at` had already passed at
    // `evidence.received_at` (`resolve_prior_bound_work` picks the row; the
    // OVERDUE case is Row B). Both are legal prior-bound terminalizations that the
    // shared `classify_prior_bound_staling` proves exactly and
    // `write_prior_bound_staling` already writes, so both must be accepted here or
    // an overdue peer leave permanently wedges every leaveCommit on the
    // coordinate. This arm's OWN request can never be Row B:
    // `plan_leave_fulfillment_inner` rejects an overdue target with `WorkExpired`
    // before planning.
    //
    // Reject every other shape: a non-transition delta, a request that did not
    // start Pending, a re-binding (ruling point 4), a second Fulfilled, or a
    // retirement that targets the fulfilled request itself (ruling point 3 — the
    // fulfilled request is `fulfilled`, never `stale`/`expired`). The retired
    // others flow through `write_prior_bound_staling` at the tail; reconcile
    // own(1) + staled == total.
    let mut fulfilled_request_id: Option<[u8; 16]> = None;
    for change in effects.leave_request_changes() {
        let (before, after) = match (change.before(), change.after()) {
            (Some(before), Some(after)) => (before, after),
            _ => {
                return Err(ExecutorError::InconsistentPlan(
                    "leave fulfillment leave-request delta must be a status transition",
                ))
            }
        };
        if before.status() != LeaveRequestStatus::Pending {
            return Err(ExecutorError::InconsistentPlan(
                "leave fulfillment leave-request delta must start Pending",
            ));
        }
        if before.bound_coordinate != after.bound_coordinate {
            return Err(ExecutorError::InconsistentPlan(
                "leave fulfillment must not re-bind a leave request",
            ));
        }
        match after.status() {
            LeaveRequestStatus::Fulfilled => {
                if fulfilled_request_id.is_some() {
                    return Err(ExecutorError::InconsistentPlan(
                        "leave fulfillment must fulfill exactly one leave request",
                    ));
                }
                fulfilled_request_id = Some(after.request_id);
            }
            LeaveRequestStatus::Stale | LeaveRequestStatus::Expired => {}
            _ => {
                return Err(ExecutorError::InconsistentPlan(
                    "leave fulfillment leave-request delta must be Fulfilled, Stale or Expired",
                ))
            }
        }
    }
    let fulfilled_request_id = fulfilled_request_id.ok_or(ExecutorError::InconsistentPlan(
        "leave fulfillment must fulfill a pending leave request",
    ))?;
    // Ruling point 3: no prior-bound retirement may target the request being
    // fulfilled — neither a staling nor a due expiry.
    for change in effects.leave_request_changes() {
        if let Some(after) = change.after() {
            if matches!(
                after.status(),
                LeaveRequestStatus::Stale | LeaveRequestStatus::Expired
            ) && after.request_id == fulfilled_request_id
            {
                return Err(ExecutorError::InconsistentPlan(
                    "leave fulfillment must not retire the request it fulfills",
                ));
            }
        }
    }
    Ok(fulfilled_request_id)
}

pub(in crate::chat_protocol::state_machine::executor) async fn apply_leave_fulfillment(
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
    let coordinate = &hydration.coordinate; // successor (sv+1, epoch+1).
    let applied_at = ctx.applied_at;
    let head = effects
        .head_cas()
        .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
    let expected_prior = head
        .expected_prior()
        .ok_or(ExecutorError::InconsistentPlan(
            "leave fulfillment needs a prior",
        ))?;
    let expected_generation = checked_i64(expected_prior.generation())?;
    let expected_state_version = checked_i64(expected_prior.state_version())?;
    let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;

    // Guards. Leave fulfillment carries participant/leaf/interval/leave-request/
    // metadata changes + (a legal interleaving) prior-bound recovery/welcome
    // SUPERSESSIONS + prior-bound reset/leave STALING. It has NO own recovery/
    // reservation/package edge and no terminal-proof/revocation change; those
    // recovery families flow ONLY through the shared supersession path (own
    // counts 0, verified by the reconciliation). Its OWN leave-request edge is the
    // single Pending->Fulfilled fulfilled below; per ADR-019 Erratum 01 the same
    // leaveCommit MAY additionally stale OTHER members' predecessor-bound pending
    // leaves (the partition check below enforces exactly-one-fulfilled + others-
    // only Pending->Stale). Reject the families it never carries.
    let partition = preflight_leave_fulfillment(plan, ctx)?;

    // Metadata re-encryption is MANDATORY (DDL requires_snapshot ∋ leaveCommit).
    let metadata = effects
        .metadata_change()
        .and_then(StateChange::after)
        .ok_or(ExecutorError::InconsistentPlan(
            "leave fulfillment carries no metadata re-encryption",
        ))?;
    let author_cols = ctx
        .metadata_author
        .as_ref()
        .ok_or(ExecutorError::MissingContext(
            "leave fulfillment commit metadata author",
        ))?;

    let fulfilled_request_id = partition_leave_fulfillment_requests(effects)?;
    let leave_request_id = Uuid::from_bytes(fulfilled_request_id);

    // Exactly one participant is removed (the requester).
    if effects.participant_changes().len() != 1 {
        return Err(ExecutorError::InconsistentPlan(
            "leave fulfillment must remove exactly one participant",
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
            "leave fulfillment must close the requester participant",
        ))?;
    let participant_period_id = ctx
        .closing_participant_periods
        .iter()
        .find(|(principal, _)| principal == removed.principal())
        .map(|(_, id)| *id)
        .ok_or(ExecutorError::MissingContext(
            "closing participant period id for the leave requester",
        ))?;

    // 1. Head CAS sv+1.
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

    // 2. Generation state-version pointer CAS (same generation).
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

    // 3. `commit`/active gen_state at the NEW epoch (fresh hash/tag).
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
            state_kind: GenerationStateKind::Commit,
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

    // 4. Entry (leaveCommitFulfillmentEntry).
    let append = build_append_entry(
        ctx,
        conversation_id,
        generation,
        state_version,
        transition_id,
    );
    delivery::append_entry_at(transaction, &append, u64::try_from(seq_i64).unwrap()).await?;

    // 5. Transition (kind leaveCommit, prior -> next).
    transition::insert_transition_row(
        transaction,
        &NewTransition {
            transition_id,
            conversation_id,
            kind: TransitionKind::LeaveCommit,
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
            metadata_snapshot_id: Some(author_cols.metadata_snapshot_id),
            entry_seq: seq_i64,
            accepted_at: applied_at,
        },
    )
    .await?;

    // 6. Metadata re-encryption snapshot (carry-forward author/origin/version).
    write_commit_metadata_snapshot(
        transaction,
        metadata,
        author_cols,
        conversation_id,
        generation,
        state_version,
        epoch,
        &coordinate.group_id().to_vec(),
        &coordinate.group_context_hash().to_vec(),
        &coordinate.confirmation_tag().to_vec(),
        transition_id,
        applied_at,
    )
    .await?;

    // 7. Close every requester leaf. A `(Some,None)` is a real removal; the
    //    committer's own key rotation is a tolerated `(Some,Some)` (no DS row);
    //    an add `(None,Some)` is not a leave and is a hard error.
    let mut removed_leaves = 0usize;
    for change in effects.leaf_changes() {
        match (change.before(), change.after()) {
            (Some(before), None) => {
                let leaf = closing_leaf_period(ctx, before.device())?;
                transition::close_leaf_period(
                    transaction,
                    &LeafClose {
                        leaf_period_id: leaf,
                        removed_state_version: state_version,
                        removed_transition_id: transition_id,
                        removed_seq: seq_i64,
                        removed_at: applied_at,
                    },
                )
                .await?;
                removed_leaves += 1;
            }
            (Some(_), Some(_)) => {}
            (None, Some(_)) => {
                return Err(ExecutorError::InconsistentPlan(
                    "leave fulfillment must not add a leaf",
                ))
            }
            (None, None) => {}
        }
    }
    if removed_leaves == 0 {
        return Err(ExecutorError::InconsistentPlan(
            "leave fulfillment removed no leaf",
        ));
    }

    // 8. Close every removed device's interval inclusively at the fulfillment
    //    seq (`Remove`), sourcing the closing leaf period from ctx.
    for change in effects.interval_changes() {
        match (change.before(), change.after()) {
            (Some(_), Some(after)) => {
                let end = after.end().ok_or(ExecutorError::InconsistentPlan(
                    "leave-closed interval has no end",
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
                        closing_state_version: state_version,
                        closing_transition_id: Uuid::from_bytes(*end.transition_id()),
                        closing_outer_entry_fingerprint: end.outer_entry_fingerprint().to_vec(),
                        closing_kind: repo_interval_close_kind(end.kind()),
                        closing_leaf_period_id: leaf,
                        removed_at: applied_at,
                    },
                )
                .await?;
            }
            _ => {
                return Err(ExecutorError::InconsistentPlan(
                    "leave fulfillment interval change must close an open interval",
                ))
            }
        }
    }

    // 9. Terminalize the requester's participant period.
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

    // 10. Mark the leave request `fulfilled`, bound to this leaveCommit
    //     transition (the assert_leave_request_mapping fulfilled arm cross-checks
    //     kind ∈ leaveCommit/leavePolicy + prior coordinate + digest + instant).
    transition::terminalize_leave_request(
        transaction,
        leave_request_id,
        &LeaveRequestTermination::Fulfilled {
            terminal_request_digest: ctx.entry().request_digest.clone(),
            terminal_transition_id: transition_id,
            terminal_at: applied_at,
        },
    )
    .await?;

    // 11. Audience + events.
    let recipients = build_entry_recipients(&ctx.entry_recipients)?;
    delivery::insert_entry_recipients(
        transaction,
        conversation_id,
        u64::try_from(seq_i64).unwrap(),
        &recipients,
    )
    .await?;
    let event_positions = write_events(transaction, ctx, None).await?;

    // 12. Shared prior-bound supersession + welcome supersession + reset/leave
    //     STALING + the silent-drop reconciliation (own recovery/reservation/
    //     package/welcome edges are ALL zero for a leave fulfillment; its ONE own
    //     leave edge is the Pending->Fulfilled handled above — every OTHER delta
    //     must be a supersession/staling the calls below applied). Per ADR-019
    //     Erratum 01 `write_prior_bound_staling` now also terminalizes any
    //     Pending->Stale leaves of OTHER members the leaveCommit retired (bound to
    //     this transition + the commit's request digest); reconcile own(1) +
    //     staled == total.
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
            leave_requests: 1,
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
