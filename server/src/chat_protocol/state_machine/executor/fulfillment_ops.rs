#![allow(unused_imports)]
use super::*;


/// Apply a `signedLeafRecoveryFulfillment` edge (kind `leafRecovery`): the
/// epoch-changing commit that adds the recovered target by KeyPackage and emits
/// its Welcome. sv+1, epoch+1 (new hash/tag), same generation. Composes: head
/// CAS + gen-state-version CAS + `commit`/active gen_state (epoch+1) +
/// leafRecoveryFulfillmentEntry + transition (`leafRecovery`) + metadata
/// RE-ENCRYPTION snapshot + exactly one `addLeafByRecovery` (the target's leaf
/// period, `keyPackage` origin with join provenance, + its `add`-opened interval
/// at the fulfillment seq) + request `fulfilled` / reservation `consumed` /
/// package `consumed` + Welcome bundle + delivery (`expires_at` == consumed
/// package `not_after`) + audience + `welcomeAvailable` event.
///
/// SCOPE: the single-request Add fulfillment (what the frozen corpus commit
/// exercises). Prior-coordinate open-request supersession (multiple
/// recovery/reservation/package changes) and a `replace` close are NOT composed
/// here — the exact-count guards below turn either into a hard `InconsistentPlan`
/// rather than a silent drop; they are a bounded follow-on once a corpus with a
/// second open request / a Remove-capable commit exists.
#[allow(clippy::too_many_arguments)]
pub(in crate::chat_protocol::state_machine::executor) async fn apply_leaf_recovery_fulfillment(
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
    recovery_write_authority: Option<
        &crate::chat_protocol::repository::recovery::RecoveryExecutorWriteAuthority<'_>,
    >,
    historical_write_authority: Option<&HistoricalExecutionWriteAuthority>,
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
        .ok_or(ExecutorError::InconsistentPlan("fulfillment needs a prior"))?;
    let expected_generation = checked_i64(expected_prior.generation())?;
    let expected_state_version = checked_i64(expected_prior.state_version())?;
    let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;

    // Guards: fulfillment carries leaf / interval / welcome / recovery-request /
    // reservation / package / metadata changes + (a legal interleaving)
    // prior-bound reset/leave STALING; reject the families it never has.
    reject_if_present("participant_changes", effects.participant_changes())?;
    reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
    reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
    if effects.revocation_target_cas().is_some()
        || effects.welcome_cas().is_some()
        || effects.invitation_quota_cas().is_some()
    {
        return Err(ExecutorError::UnsupportedEffect(
            "fulfillment revocation/welcome/quota CAS",
        ));
    }
    // Metadata re-encryption is MANDATORY (DDL requires_snapshot ∋ leafRecovery).
    let metadata = effects
        .metadata_change()
        .and_then(StateChange::after)
        .ok_or(ExecutorError::InconsistentPlan(
            "fulfillment carries no metadata re-encryption",
        ))?;
    let author_cols = ctx
        .metadata_author
        .as_ref()
        .ok_or(ExecutorError::MissingContext(
            "fulfillment commit metadata author",
        ))?;

    // Exact-SHAPE: exactly ONE own Open->Fulfilled recovery request +
    // Active->Consumed reservation + Reserved->Consumed package edge + one new
    // pending welcome. Any OTHER recovery/reservation/package delta must be a
    // prior-bound supersession (Open->Superseded / Active->Released /
    // Reserved->Available), consumed by write_prior_bound_supersessions.
    let own_fulfilled = effects
        .recovery_request_changes()
        .iter()
        .filter(|change| {
            matches!((change.before(), change.after()), (Some(b), Some(a))
                    if b.status() == RecoveryRequestStatus::Open
                        && a.status() == RecoveryRequestStatus::Fulfilled)
        })
        .count();
    let own_consumed = effects
        .reservation_changes()
        .iter()
        .filter(|change| {
            matches!((change.before(), change.after()), (Some(b), Some(a))
                    if b.status() == ReservationStatus::Active
                        && a.status() == ReservationStatus::Consumed)
        })
        .count();
    // Exactly ONE own NEW pending welcome. A `replace` fulfillment ALSO
    // supersedes the target's prior-bound pending welcome (a (Some,Some)
    // Pending->Superseded change consumed by write_welcome_supersessions +
    // reconcile), so the total welcome-change count is NOT constrained here —
    // only the own new-pending count is.
    let own_new_welcomes = effects
        .welcome_changes()
        .iter()
        .filter(|change| {
            matches!((change.before(), change.after()), (None, Some(a))
                    if a.status() == WelcomeStatus::Pending)
        })
        .count();
    if own_fulfilled != 1 || own_consumed != 1 || own_new_welcomes != 1 {
        return Err(ExecutorError::InconsistentPlan(
                "fulfillment must carry exactly one own fulfilled request + consumed reservation + welcome",
            ));
    }
    let fulfilled = effects
        .recovery_request_changes()
        .iter()
        .find_map(|change| match (change.before(), change.after()) {
            (Some(before), Some(after))
                if before.status() == RecoveryRequestStatus::Open
                    && after.status() == RecoveryRequestStatus::Fulfilled =>
            {
                Some(after)
            }
            _ => None,
        })
        .ok_or(ExecutorError::InconsistentPlan(
            "fulfillment fulfills no open recovery request",
        ))?;
    let recovery_request_id = Uuid::from_bytes(*fulfilled.request_id());
    let reserved_ref = *fulfilled.key_package_ref();
    // The OWN Reserved -> Consumed package edge (bijection + driven-ref +
    // direction); any other edges are Reserved->Available supersessions.
    verify_recovery_package_consistency(
        effects,
        &reserved_ref,
        PackageStatus::Reserved,
        PackageStatus::Consumed,
    )?;
    // Exactly one new pending welcome.
    let welcome = effects
        .welcome_changes()
        .iter()
        .find_map(|change| match (change.before(), change.after()) {
            (None, Some(after)) if after.status() == WelcomeStatus::Pending => Some(after),
            _ => None,
        })
        .ok_or(ExecutorError::InconsistentPlan(
            "fulfillment adds no pending welcome",
        ))?;
    let (preflight_prior_bound, partition) =
        preflight_leaf_recovery_fulfillment(plan, effects, hydration, ctx, transition_id, seq_i64)?;

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

    // 4. Entry (leafRecoveryFulfillmentEntry).
    let append = build_append_entry(
        ctx,
        conversation_id,
        generation,
        state_version,
        transition_id,
    );
    delivery::append_entry_at(transaction, &append, u64::try_from(seq_i64).unwrap()).await?;

    // 5. Transition (kind leafRecovery, prior -> next, carries the request).
    transition::insert_transition_row(
        transaction,
        &NewTransition {
            transition_id,
            conversation_id,
            kind: TransitionKind::LeafRecovery,
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

    // 7. The target's recovered leaf. An `add` fulfillment opens a fresh
    //    (None,Some) leaf for a target that had none; a `replace` fulfillment
    //    ROTATES an existing target leaf — because the diff is keyed by DEVICE
    //    (not leaf index), the rotation surfaces as ONE (Some,Some) change for
    //    the target (the whole `LeafRecord` differs: new signature/encryption
    //    key + key-package origin), which must close the OLD leaf period and
    //    open a fresh one. A NON-target (Some,Some) is the committer's own
    //    tolerated key rotation — the DS `member_devices` row stores no
    //    ephemeral encryption key, so it needs no write. Any other leaf delta
    //    (a non-target add, or a full removal) is a hard error.
    let target = fulfilled.target().clone();
    let mut target_leaf: Option<(bool, &LeafRecord)> = None;
    for change in effects.leaf_changes() {
        match (change.before(), change.after()) {
            (None, Some(after)) if after.device() == &target => {
                if target_leaf.replace((false, after)).is_some() {
                    return Err(ExecutorError::InconsistentPlan(
                        "fulfillment carries more than one target leaf change",
                    ));
                }
            }
            (Some(_), Some(after)) if after.device() == &target => {
                if target_leaf.replace((true, after)).is_some() {
                    return Err(ExecutorError::InconsistentPlan(
                        "fulfillment carries more than one target leaf change",
                    ));
                }
            }
            (Some(_), Some(_)) => {}
            (None, Some(_)) | (Some(_), None) | (None, None) => {
                return Err(ExecutorError::InconsistentPlan(
                    "fulfillment carries an unexpected leaf change",
                ))
            }
        }
    }
    let (is_replace, new_leaf_change) = target_leaf.ok_or(ExecutorError::InconsistentPlan(
        "fulfillment carries no target leaf change",
    ))?;
    debug_assert_eq!(new_leaf_change.device(), &target);
    let leaf_row = hydration
        .leaves
        .iter()
        .find(|row| row.device == target)
        .ok_or(ExecutorError::InconsistentPlan(
            "recovered leaf not in hydration",
        ))?;
    let leaf_cols = ctx
        .opened_leaves
        .iter()
        .find(|cols| cols.device == target)
        .ok_or(ExecutorError::MissingContext("recovered leaf columns"))?;
    let leaf_period_id = *ctx
        .leaf_period_ids
        .first()
        .ok_or(ExecutorError::MissingContext("recovered leaf period id"))?;
    let participant_period_id = participant_period_for(ctx, hydration, target.principal())?;
    // A `replace` closes the target's OLD leaf period FIRST (a single active
    // leaf per device), sourcing the period id from ctx.closing_leaf_periods,
    // before the fresh period below reuses the vacated slot.
    if is_replace {
        let old_leaf_period = closing_leaf_period(ctx, &target)?;
        transition::close_leaf_period(
            transaction,
            &LeafClose {
                leaf_period_id: old_leaf_period,
                removed_state_version: state_version,
                removed_transition_id: transition_id,
                removed_seq: seq_i64,
                removed_at: applied_at,
            },
        )
        .await?;
    }
    transition::insert_leaf_period(
        transaction,
        &NewLeafPeriod {
            leaf_period_id,
            participant_period_id,
            conversation_id,
            generation,
            user_did: device_did(&target)?,
            device_id: device_uuid(&target),
            leaf_index: checked_i64(u64::from(leaf_row.leaf_index))?,
            basic_credential: leaf_row.basic_credential.clone(),
            leaf_signature_key: leaf_row.signature_key.clone(),
            leaf_key_id: leaf_cols.leaf_key_id.clone(),
            leaf_auth_generation: leaf_cols.leaf_auth_generation,
            origin: LeafOrigin::KeyPackage {
                key_package_ref: reserved_ref.to_vec(),
            },
            joined_state_version: state_version,
            joined_transition_id: transition_id,
            joined_seq: seq_i64,
            created_at: applied_at,
        },
    )
    .await?;

    // 8. Intervals. The target's fresh `add` interval opens at the fulfillment
    //    seq (keyed on the new opening seq). A `replace` ADDITIONALLY carries
    //    the target's PRIOR interval as a (Some,Some) close (keyed on the old
    //    opening seq), `Replace`-closed inclusively at the fulfillment seq —
    //    the removed old leaf period sources the close. Every interval change
    //    must be consumed; the counts are asserted against the request kind.
    let mut opened_intervals = 0usize;
    let mut closed_intervals = 0usize;
    for change in effects.interval_changes() {
        match (change.before(), change.after()) {
            (None, Some(after)) => {
                if after.recipient() != &target
                    || after.opening_kind() != crate::chat_protocol::state_machine::OpeningKind::Add
                    || after.end().is_some()
                {
                    return Err(ExecutorError::InconsistentPlan(
                        "fulfillment opens an unexpected interval",
                    ));
                }
                let opening_context = after.opening_context();
                delivery::insert_application_interval(
                    transaction,
                    &NewApplicationInterval {
                        membership_interval_id: Uuid::from_bytes(*after.opening_transition_id()),
                        conversation_id,
                        generation: checked_i64(opening_context.generation())?,
                        recipient_did: device_did(after.recipient())?,
                        recipient_device_id: device_uuid(after.recipient()),
                        start_seq: checked_i64(after.opening_seq())?,
                        opening_kind: IntervalOpeningKind::Add,
                        opening_transition_id: Uuid::from_bytes(*after.opening_transition_id()),
                        opening_outer_entry_fingerprint: after
                            .opening_outer_entry_fingerprint()
                            .to_vec(),
                        opening_state_version: checked_i64(opening_context.state_version())?,
                        opening_group_id: opening_context.group_id().to_vec(),
                        opening_epoch: checked_i64(opening_context.epoch())?,
                        opening_group_context_hash: opening_context.group_context_hash().to_vec(),
                        opening_confirmation_tag: opening_context.confirmation_tag().to_vec(),
                        opening_leaf_period_id: leaf_period_id,
                        created_at: applied_at,
                    },
                )
                .await?;
                opened_intervals += 1;
            }
            (Some(_), Some(after)) => {
                let end = after.end().ok_or(ExecutorError::InconsistentPlan(
                    "fulfillment replace-close carries no interval end",
                ))?;
                if after.recipient() != &target || end.kind() != CloseKind::Replace {
                    return Err(ExecutorError::InconsistentPlan(
                        "fulfillment closes an unexpected interval",
                    ));
                }
                let old_leaf_period = closing_leaf_period(ctx, after.recipient())?;
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
                        closing_leaf_period_id: old_leaf_period,
                        removed_at: applied_at,
                    },
                )
                .await?;
                closed_intervals += 1;
            }
            (Some(_), None) | (None, None) => {
                return Err(ExecutorError::InconsistentPlan(
                    "fulfillment carries an unexpected interval change",
                ))
            }
        }
    }
    let expected_closed = usize::from(is_replace);
    if opened_intervals != 1 || closed_intervals != expected_closed {
        return Err(ExecutorError::InconsistentPlan(
            "fulfillment interval changes do not match the request kind",
        ));
    }

    // 9. Terminalize the exact full-row triple. This remains after the
    //    transition insert because the fulfilled rows reference it, while
    //    the prewrite reread already rejected all triple drift before the
    //    savepoint's first mutation.
    if let Some(authority) = recovery_write_authority {
        authority.apply_terminal(transaction).await?;
    } else {
        // No live Recovery write authority exists for a reconstructed historical
        // prefix, so replay terminalizes the triple directly; test builds share
        // that path, and production without either authority fails closed.
        #[cfg(not(test))]
        {
            if historical_write_authority.is_none() {
                return Err(ExecutorError::MissingContext(
                    "missing validated Recovery executor write authority",
                ));
            }
        }
        transition::terminalize_leaf_recovery_request(
            transaction,
            recovery_request_id,
            &LeafRecoveryTermination::Fulfilled {
                fulfilling_transition_id: transition_id,
                terminal_at: applied_at,
            },
        )
        .await?;
        transition::terminalize_reservation(
            transaction,
            recovery_request_id,
            &ReservationTermination::Consumed {
                consumed_transition_id: transition_id,
                terminal_at: applied_at,
            },
        )
        .await?;
        transition::cas_key_package_status(
            transaction,
            &reserved_ref,
            RepoPackageStatus::Reserved,
            &PackageSuccessor::Consume {
                terminal_transition_id: transition_id,
                terminal_at: applied_at,
            },
        )
        .await?;
    }

    // 10. Welcome bundle + delivery (expires_at == consumed package not_after).
    let welcome_id = Uuid::from_bytes(*welcome.welcome_id());
    delivery::insert_welcome_bundle(
        transaction,
        &NewWelcomeBundle {
            welcome_id,
            conversation_id,
            transition_id,
            entry_seq: seq_i64,
            generation,
            state_version,
            group_id: coordinate.group_id().to_vec(),
            epoch,
            group_context_hash: coordinate.group_context_hash().to_vec(),
            confirmation_tag: coordinate.confirmation_tag().to_vec(),
            wrapper_bytes: welcome.opaque_welcome().to_vec(),
            wrapper_sha256: welcome.sha256().to_vec(),
            created_at: applied_at,
        },
    )
    .await?;
    delivery::insert_welcome_delivery(
        transaction,
        &NewWelcomeDelivery {
            welcome_id,
            recipient_did: device_did(welcome.recipient())?,
            recipient_device_id: device_uuid(welcome.recipient()),
            recovery_request_id,
            key_package_ref: welcome.key_package_ref().to_vec(),
            expires_at: server_instant(welcome.expires_at())?,
        },
    )
    .await?;
    let recipient_did_str = device_did(welcome.recipient())?;
    let participant_row: Option<Option<String>> = sqlx::query_scalar(
        "SELECT ds_did FROM chat.participants \
         WHERE conversation_id = $1 AND user_did = $2 \
           AND current_membership = TRUE AND status IN ('pending', 'active')",
    )
    .bind(conversation_id)
    .bind(&recipient_did_str)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|e| ExecutorError::Delivery(DeliveryRepositoryError::Database(e)))?;

    let ds_did_opt = match participant_row {
        None => {
            tracing::error!(
                conversation_id = %crate::crypto::redact_for_log(&conversation_id.hyphenated().to_string()),
                recipient_did = %crate::crypto::redact_for_log(&recipient_did_str),
                "welcome emission failed: recipient participant is absent from conversation"
            );
            return Err(ExecutorError::InconsistentPlan(
                "recipient participant not found in conversation for welcome emission",
            ));
        }
        Some(ds_did_opt) => ds_did_opt,
    };

    let is_local = match &ds_did_opt {
        None => true,
        Some(ds) => {
            let self_base = crate::identity::service_did_base();
            let canonical_ds = crate::identity::canonical_did(ds);
            crate::identity::dids_equivalent(&canonical_ds, &self_base)
        }
    };

    if is_local || historical_write_authority.is_some() {
        tracing::debug!(
            conversation_id = %crate::crypto::redact_for_log(&conversation_id.hyphenated().to_string()),
            recipient_did = %crate::crypto::redact_for_log(&recipient_did_str),
            "welcome emission: recipient is local participant or historical reconstruction, skipping remote federation enqueue"
        );
    } else {
        let target_ds_did = ds_did_opt.unwrap();
        let pub_snap_sha: [u8; 32] = ctx
            .spine
            .public_snapshot_sha256
            .as_slice()
            .try_into()
            .map_err(|_| ExecutorError::InconsistentPlan("invalid public snapshot sha256"))?;
        let tree_sum_sha: [u8; 32] = ctx
            .spine
            .tree_summary_sha256
            .as_slice()
            .try_into()
            .map_err(|_| ExecutorError::InconsistentPlan("invalid tree summary sha256"))?;

        let coordinates = catbird_atproto::generated::blue_catbird::chat::ConversationCoordinates {
            conversation_id: jacquard_common::deps::smol_str::SmolStr::from(
                conversation_id.hyphenated().to_string(),
            ),
            generation,
            state_version,
            epoch,
            group_id: jacquard_common::deps::bytes::Bytes::copy_from_slice(coordinate.group_id()),
            group_context_hash: jacquard_common::deps::bytes::Bytes::copy_from_slice(
                coordinate.group_context_hash(),
            ),
            confirmation_tag: jacquard_common::deps::bytes::Bytes::copy_from_slice(
                coordinate.confirmation_tag(),
            ),
            lifecycle: jacquard_common::deps::smol_str::SmolStr::from(
                match coordinate.lifecycle() {
                    crate::chat_protocol::snapshot::PublicGroupSnapshotLifecycle::Active => {
                        "active"
                    }
                    crate::chat_protocol::snapshot::PublicGroupSnapshotLifecycle::Superseded => {
                        "superseded"
                    }
                },
            ),
            extra_data: None,
        };

        crate::chat_protocol::repository::federation::enqueue_federated_welcome_job(
            transaction,
            conversation_id,
            &target_ds_did,
            &recipient_did_str,
            device_uuid(welcome.recipient()),
            welcome_id,
            recovery_request_id,
            &reserved_ref,
            welcome.opaque_welcome(),
            welcome.sha256(),
            &append,
            u64::try_from(seq_i64).unwrap(),
            coordinates,
            &pub_snap_sha,
            &tree_sum_sha,
            ctx.sequencer_term as u64,
        )
        .await
        .map_err(|e| {
            tracing::error!(?e, "failed to enqueue federated welcome job");
            ExecutorError::InconsistentPlan("failed to enqueue federated welcome job")
        })?;
    }

    // 11. Audience + events.
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
    // Prior-coordinate open-work supersession (a legal interleaving): the corpus
    // fulfillment carries none, but the path composes it for the general case.
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
    // Durably stale any prior-bound pending reset/leave request the coordinate
    // change retired (this arm owns none — kind is `leafRecovery`, DB-legal for
    // the leave `stale` edge).
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
    if superseded != preflight_prior_bound {
        return Err(ExecutorError::InconsistentPlan(
            "fulfillment applied prior-bound counts disagree with preflight",
        ));
    }
    // Silent-drop guard: this arm's OWN edges are exactly one fulfilled request +
    // consumed reservation + Reserved->Consumed package + new pending welcome; every
    // OTHER delta MUST be a supersession/staling the calls above applied. Reject any
    // delta that is neither (e.g. an Open->Expired request) rather than dropping it.
    reconcile_coordinate_change_families(
        effects,
        &FamilyCounts {
            requests: 1,
            reservations: 1,
            packages: 1,
            welcomes: 1,
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
