#![allow(unused_imports)]
use super::*;


#[derive(Debug)]
pub(in crate::chat_protocol::state_machine::executor) struct MetadataExecutionBinding<'a> {
    pub(in crate::chat_protocol::state_machine::executor) metadata: &'a MetadataSnapshotBinding,
    pub(in crate::chat_protocol::state_machine::executor) author: &'a MetadataAuthorColumns,
    pub(in crate::chat_protocol::state_machine::executor) avatar: Option<&'a MetadataAvatarPersistence>,
    /// The classified prior-bound families, carried to `apply_metadata_transition`
    /// so it reconciles the writer's receipt against them before any other writer
    /// runs (design 5 step 6).
    pub(in crate::chat_protocol::state_machine::executor) prior_bound: PriorBoundPartition,
}

/// Re-derive the complete metadata-transition contract from the sealed plan
/// and repository-hydrated context before the first writer runs.
///
/// A metadata transition is a coordinate-only successor: same generation
/// and MLS crypto coordinate, `state_version + 1`, one signed self-origin
/// metadata snapshot, and no membership/leaf/interval mutation. It may
/// terminalize work bound to the retired coordinate; every such family is
/// classified here and reconciled again after its writer runs.
pub(in crate::chat_protocol::state_machine::executor) fn preflight_metadata_transition<'a>(
    plan: &'a ConversationPersistencePlan,
    ctx: &'a ExecutionContext,
    transition_id: Uuid,
    seq_i64: i64,
) -> Result<MetadataExecutionBinding<'a>, ExecutorError> {
    let effects = plan.effects();
    let hydration = plan.state();
    let head = effects
        .head_cas()
        .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
    let prior = head
        .expected_prior()
        .ok_or(ExecutorError::InconsistentPlan(
            "metadata transition needs an expected prior",
        ))?;
    let expected_next = coordinate_only_successor(prior).map_err(|_| {
        ExecutorError::InconsistentPlan("metadata successor is not coordinate-only")
    })?;
    if effects.kind() != PlanKind::Metadata
        || plan.expected_prior.as_ref() != Some(prior)
        || plan.retired_coordinate.is_some()
        || plan.successor_coordinate.as_ref() != Some(&expected_next)
        || hydration.coordinate != expected_next
        || head.conversation_id() != prior.conversation_id()
        || head.allocated_entry_id() != Some(transition_id.as_bytes())
        || head
            .allocated_seq()
            .and_then(|value| i64::try_from(value).ok())
            != Some(seq_i64)
        || head
            .expected_next_entry_seq()
            .checked_add(1)
            .filter(|value| *value == head.successor_next_entry_seq())
            .is_none()
    {
        return Err(ExecutorError::InconsistentPlan(
            "metadata plan/head/coordinate binding drifted",
        ));
    }

    let producer = &hydration.producer;
    let authority = match effects.authority() {
        Some(PlanAuthority::Transition(authority)) if authority == producer => authority,
        _ => {
            return Err(ExecutorError::InconsistentPlan(
                "metadata plan lacks its exact transition authority",
            ))
        }
    };
    let signed = authority
        .authority
        .as_ref()
        .ok_or(ExecutorError::InconsistentPlan(
            "metadata transition lacks signed authority",
        ))?;
    let actor_did = device_did(&signed.actor)?;
    let actor_key_id = URL_SAFE_NO_PAD.encode(signed.key_id);
    if signed.kind != SignedMutationKind::MetadataTransition
        || signed.control_entry_id != Some(*transition_id.as_bytes())
        || signed.control_conversation_id != Some(*prior.conversation_id())
        || authority.transition_id != *transition_id.as_bytes()
        || i64::try_from(authority.seq).ok() != Some(seq_i64)
        || authority.received_at != head.locked_at()
        || ctx.applied_at != server_instant(authority.received_at)?
        || ctx.entry().entry_id != transition_id
        || ctx.entry().signed_request_bytes != signed.signed_request_bytes
        || ctx.entry().unsigned_projection_bytes != signed.canonical_projection
        || ctx.entry().signing_transcript_bytes != signed.transcript_bytes
        || ctx.entry().request_digest.as_slice() != signed.request_digest
        || ctx.entry().signature.as_slice() != signed.signature
        || ctx.entry().outer_entry_fingerprint.as_slice() != authority.outer_entry_fingerprint
        || ctx.entry().server_fields_bytes != authority.server_fields_dag_cbor
        || ctx.actor.user_did != actor_did
        || ctx.actor.device_id != device_uuid(&signed.actor)
        || ctx.actor.key_id != actor_key_id
        || u64::try_from(ctx.actor.auth_generation).ok() != Some(signed.auth_generation)
        || ctx.actor.role != TransitionActorRole::Admin
        || ctx.actor.device_status != "active"
    {
        return Err(ExecutorError::InconsistentPlan(
            "metadata signed/control/actor authority drifted",
        ));
    }

    let metadata_change = effects
        .metadata_change()
        .ok_or(ExecutorError::InconsistentPlan(
            "metadata transition has no metadata delta",
        ))?;
    let (Some(before), Some(after)) = (metadata_change.before(), metadata_change.after()) else {
        return Err(ExecutorError::InconsistentPlan(
            "metadata transition delta is not a replacement",
        ));
    };
    let signed_metadata = match authority.body_binding.as_ref() {
        Some(TransitionBodyBinding::Metadata {
            prior: signed_prior,
            next: signed_next,
            metadata,
        }) if signed_prior == prior && signed_next == &expected_next => metadata,
        _ => {
            return Err(ExecutorError::InconsistentPlan(
                "metadata transition body binding drifted",
            ))
        }
    };
    let expected_version = before.metadata_version().checked_add(1);
    if after != signed_metadata
        || hydration.metadata.as_ref() != Some(after)
        || hydration.metadata_producer.as_ref() != Some(authority)
        || !metadata_coordinate_matches(before, prior)
        || !metadata_coordinate_matches(after, &expected_next)
        || expected_version != Some(after.metadata_version())
        || after.origin_transition_id() != transition_id.as_bytes()
        || after.author_origin_transition_id() != transition_id.as_bytes()
        || i64::try_from(after.author_origin_seq()).ok() != Some(seq_i64)
        || after.nonce() == before.nonce()
        || after.author() != &signed.actor
        || !metadata_author_matches_evidence(after, authority)
    {
        return Err(ExecutorError::InconsistentPlan(
            "metadata snapshot provenance/version/nonce drifted",
        ));
    }
    let author = ctx
        .metadata_author
        .as_ref()
        .ok_or(ExecutorError::MissingContext(
            "metadata transition author columns",
        ))?;
    if author.author_role != "admin"
        || author.author_device_status != "active"
        || author.author_key_id != actor_key_id
        || author.author_public_key != after.signature_public_key()
        || u64::try_from(ctx.actor.auth_generation).ok()
            != Some(after.author_auth_generation_at_origin())
    {
        return Err(ExecutorError::InconsistentPlan(
            "metadata author columns disagree with signed provenance",
        ));
    }
    let avatar = match (after.avatar_binding(), ctx.metadata_avatar.as_ref()) {
        (None, None) => None,
        (Some(signed_avatar), Some(persistence)) => {
            let durable = persistence.snapshot();
            if durable.avatar_blob_id.as_bytes() != signed_avatar.blob_id()
                || durable.avatar_ciphertext_sha256.as_slice() != signed_avatar.ciphertext_sha256()
                || u64::try_from(durable.avatar_ciphertext_size).ok()
                    != Some(signed_avatar.ciphertext_size())
            {
                return Err(ExecutorError::InconsistentPlan(
                    "metadata avatar durable columns disagree with signed descriptor",
                ));
            }
            match persistence {
                MetadataAvatarPersistence::Reuse { .. } => {
                    if !before
                        .avatar_binding()
                        .is_some_and(|prior| prior == signed_avatar)
                    {
                        return Err(ExecutorError::InconsistentPlan(
                            "metadata avatar reuse lacks an exact signed predecessor",
                        ));
                    }
                }
                MetadataAvatarPersistence::Fresh { .. } => {
                    if before
                        .avatar_binding()
                        .is_some_and(|prior| prior.blob_id() == signed_avatar.blob_id())
                        || durable.avatar_binding_origin_transition_id != transition_id
                        || u64::try_from(durable.avatar_binding_metadata_version).ok()
                            != Some(after.metadata_version())
                        || durable.avatar_binding_owner_did != actor_did
                        || durable.avatar_binding_owner_device_id != device_uuid(after.author())
                        || !(17..=10_485_760).contains(&durable.avatar_ciphertext_size)
                    {
                        return Err(ExecutorError::InconsistentPlan(
                            "metadata fresh avatar lock/binding authority drifted",
                        ));
                    }
                }
            }
            Some(persistence)
        }
        _ => {
            return Err(ExecutorError::InconsistentPlan(
                "metadata avatar signed/context presence drifted",
            ))
        }
    };

    reject_if_present("participant_changes", effects.participant_changes())?;
    reject_if_present("leaf_changes", effects.leaf_changes())?;
    reject_if_present("interval_changes", effects.interval_changes())?;
    reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
    reject_if_present("opened_intervals", effects.opened_intervals())?;
    reject_if_present("closed_intervals", effects.closed_intervals())?;
    reject_if_present(
        "terminal_proof_recipients",
        effects.terminal_proof_recipients(),
    )?;
    reject_if_present(
        "superseded_recovery_requests",
        effects.superseded_recovery_requests(),
    )?;
    reject_if_present("revocation_package_cas", effects.revocation_package_cas())?;
    if effects.policy_evidence_digest().is_some()
        || effects.revocation_target_cas().is_some()
        || effects.welcome_cas().is_some()
        || effects.invitation_quota_cas().is_some()
    {
        return Err(ExecutorError::UnsupportedEffect(
            "metadata transition carries unrelated authority effects",
        ));
    }
    if !ctx.opened_leaves.is_empty()
        || !ctx.participant_period_ids.is_empty()
        || !ctx.leaf_period_ids.is_empty()
        || !ctx.closing_leaf_periods.is_empty()
        || !ctx.closing_participant_periods.is_empty()
        || ctx.reset_request_row.is_some()
        || ctx.recovery_open.is_some()
        || ctx.welcome_expiry.is_some()
        || ctx.welcome_response.is_some()
        || !ctx.spine.genesis_group_info_bytes.is_empty()
        || !ctx.spine.genesis_group_info_sha256.is_empty()
        || sha2::Sha256::digest(&ctx.spine.public_snapshot_bytes).as_slice()
            != ctx.spine.public_snapshot_sha256
        || sha2::Sha256::digest(&ctx.spine.tree_summary_bytes).as_slice()
            != ctx.spine.tree_summary_sha256
    {
        return Err(ExecutorError::InconsistentPlan(
            "metadata transition carries unrelated or invalid execution context",
        ));
    }

    // Prior-bound recovery families. This block WAS the reference
    // implementation; it is now the shared classifier every one of the nine
    // coordinate-changing arms calls, strictly before its own first head CAS.
    let prior_bound_partition = classify_prior_bound_recovery(plan, ctx, OwnFamilyKind::None)?;
    // Prior-bound reset / leave / Welcome families. This block WAS the reference
    // implementation too; it is now `classify_prior_bound_staling`, shared with
    // the five arms that previously proved none of it.
    let welcome_ids = classify_prior_bound_staling(plan, ctx, OwnStalingKind::None)?;
    let disposition_ids = ctx
        .welcome_dispositions
        .iter()
        .map(|input| *input.welcome_id.as_bytes())
        .collect::<BTreeSet<_>>();
    if welcome_ids != disposition_ids || disposition_ids.len() != ctx.welcome_dispositions.len() {
        return Err(ExecutorError::InconsistentPlan(
            "metadata Welcome dispositions are not complete/bijective",
        ));
    }

    let expected_entry_devices = hydration
        .leaves
        .iter()
        .map(|leaf| leaf.device.clone())
        .collect::<BTreeSet<_>>();
    let entry_devices = ctx
        .entry_recipients
        .iter()
        .map(|(device, entitlement)| {
            if *entitlement != EntryEntitlementKind::Control {
                return Err(ExecutorError::InconsistentPlan(
                    "metadata entry recipient has the wrong entitlement",
                ));
            }
            Ok(device.clone())
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if entry_devices != expected_entry_devices || entry_devices.len() != ctx.entry_recipients.len()
    {
        return Err(ExecutorError::InconsistentPlan(
            "metadata entry audience is not complete/bijective",
        ));
    }
    let mut disposition_devices = BTreeSet::new();
    for input in &ctx.welcome_dispositions {
        let welcome = effects
            .welcome_changes()
            .iter()
            .find_map(|change| {
                change.after().filter(|after| {
                    after.welcome_id == *input.welcome_id.as_bytes()
                        && matches!(
                            after.status,
                            WelcomeStatus::Superseded | WelcomeStatus::Expired
                        )
                })
            })
            .ok_or(ExecutorError::InconsistentPlan(
                "metadata Welcome disposition has no exact terminal delta",
            ))?;
        let status = if welcome.status == WelcomeStatus::Expired {
            "expired"
        } else {
            "superseded"
        };
        let event = &input.event;
        if !crate::chat_protocol::state_machine::is_uuid_v4(event.event_id.as_bytes())
            || event.event_kind != EventKind::WelcomeDisposition
            || event.payload_bytes
                != delivery::canonical_welcome_disposition_event_payload(input.welcome_id, status)
            || event.recipients.len() != 1
            || event.recipients[0].0 != welcome.recipient
            || event.recipients[0].1 != EventEntitlementKind::Welcome
            || event.outbox.len() != 1
            || !crate::chat_protocol::state_machine::is_uuid_v4(event.outbox[0].0.as_bytes())
            || event.outbox[0].1 != OutboxWorkKind::Stream
            || !disposition_devices.insert(welcome.recipient.clone())
        {
            return Err(ExecutorError::InconsistentPlan(
                "metadata Welcome disposition event has an illegal shape",
            ));
        }
    }
    let primary = ctx.events.first().ok_or(ExecutorError::MissingContext(
        "metadata conversationChanged event",
    ))?;
    let primary_devices = primary
        .recipients
        .iter()
        .map(|(device, entitlement, _)| {
            if *entitlement != EventEntitlementKind::Participant {
                return Err(ExecutorError::InconsistentPlan(
                    "metadata primary event has the wrong entitlement",
                ));
            }
            Ok(device.clone())
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected_primary = entry_devices
        .difference(&disposition_devices)
        .cloned()
        .collect::<BTreeSet<_>>();
    let canonical_primary = format!(
        r#"{{"$type":"blue.catbird.chat.defs#conversationChangedEvent","conversationId":"{}"}}"#,
        Uuid::from_bytes(*prior.conversation_id()).hyphenated(),
    )
    .into_bytes();
    if ctx.events.len() != 1
        || !crate::chat_protocol::state_machine::is_uuid_v4(primary.event_id.as_bytes())
        || primary.event_kind != EventKind::ConversationChanged
        || primary.payload_bytes != canonical_primary
        || primary_devices != expected_primary
        || primary_devices.len() != primary.recipients.len()
        || primary.outbox.len() != 1
        || !crate::chat_protocol::state_machine::is_uuid_v4(primary.outbox[0].0.as_bytes())
        || primary.outbox[0].1 != OutboxWorkKind::Stream
        || usize::try_from(ctx.spine.leaf_count).ok() != Some(hydration.leaves.len())
        || ctx.spine.public_snapshot_bytes.is_empty()
        || ctx.spine.tree_summary_bytes.is_empty()
    {
        return Err(ExecutorError::InconsistentPlan(
            "metadata primary event/audience/spine shape drifted",
        ));
    }

    Ok(MetadataExecutionBinding {
        prior_bound: prior_bound_partition,
        metadata: after,
        author,
        avatar,
    })
}

/// Apply one `ConversationPersistencePlan` inside the caller's transaction.
///
/// Transaction-scoped: never begins or commits. Ordered per the E2b-2 design
/// (head → generation → generation_state → entry → transition → metadata →
/// families → audience → events). Every effect family is consumed
/// exhaustively; a non-empty family this path does not handle is a hard
/// `UnsupportedEffect`, never a silent skip.
pub(in crate::chat_protocol::state_machine::executor) async fn apply_conversation_persistence_plan_inner(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &ConversationPersistencePlan,
    ctx: &ExecutionContext,
    recovery_write_authority: Option<
        &crate::chat_protocol::repository::recovery::RecoveryExecutorWriteAuthority<'_>,
    >,
    historical_write_authority: Option<&HistoricalExecutionWriteAuthority>,
) -> Result<AppliedTransition, ExecutorError> {
    let effects = plan.effects();
    require_execution_authority(effects.kind(), &ctx.authority)?;
    let head = effects
        .head_cas()
        .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
    let hydration = plan.state();
    let coordinate = &hydration.coordinate;
    let conversation_id = Uuid::from_bytes(*coordinate.conversation_id());
    let transition_id = Uuid::from_bytes(*hydration.producer.transition_id());
    let generation = checked_i64(coordinate.generation())?;
    let state_version = checked_i64(coordinate.state_version())?;
    let epoch = checked_i64(coordinate.epoch())?;

    // Dispatch split: entry-less internal ops vs entry-bearing edges.
    //
    // `leafRecoveryRequest` / `leafRecoveryCancellation` are INTERNAL — there
    // is no control-entry kind for them (`bind_non_control_request_authority`:
    // `allocated_seq == None`, `successor_next_entry_seq == expected`), so they
    // append NO entry and allocate NO seq, and their head CAS is a
    // prior-coordinate VERIFY that advances neither the coordinate nor the
    // counter. Branch on these BEFORE the entry-bearing `allocated_seq`
    // extraction (which would otherwise `InconsistentPlan` on their `None`
    // seq). Every OTHER plan kind is entry-bearing (creation / policy / accept
    // / commit / close / reset-activation / fulfillment) and allocates a seq.
    match effects.kind() {
        PlanKind::RecoveryRequest => {
            return apply_leaf_recovery_request(
                transaction,
                plan,
                ctx,
                conversation_id,
                generation,
                state_version,
                epoch,
                recovery_write_authority,
            )
            .await;
        }
        PlanKind::RecoveryCancellation => {
            return apply_leaf_recovery_cancellation(
                transaction,
                plan,
                ctx,
                conversation_id,
                generation,
                state_version,
                epoch,
                recovery_write_authority,
            )
            .await;
        }
        PlanKind::RecoveryExpiry => {
            return apply_leaf_recovery_expiry(
                transaction,
                plan,
                ctx,
                conversation_id,
                generation,
                state_version,
                epoch,
                recovery_write_authority,
            )
            .await;
        }
        // `welcomeExpiry` is ALSO entry-less (server-observed pending-only CAS,
        // `bind_welcome_expiry_authority`: `allocated_seq == None`, coordinate +
        // seq counter UNCHANGED) — dispatch it here before the `allocated_seq`
        // extraction would `InconsistentPlan` on its `None` seq.
        PlanKind::WelcomeExpiry => {
            return apply_welcome_expiry(
                transaction,
                plan,
                ctx,
                conversation_id,
                generation,
                state_version,
                epoch,
            )
            .await;
        }
        // `welcomeAcknowledgement` / `welcomeRejection` are entry-less signed
        // non-control responses (`bind_non_control_request_authority`:
        // `allocated_seq == None`, coordinate + seq UNCHANGED) — dispatch here.
        PlanKind::WelcomeAcknowledgement | PlanKind::WelcomeRejection => {
            return apply_welcome_response(
                transaction,
                plan,
                ctx,
                conversation_id,
                generation,
                state_version,
                epoch,
            )
            .await;
        }
        // `deviceRevocation` is entry-less and coordinate-UNCHANGED (a global
        // signed authority op; `bind_device_revocation_authority`:
        // `allocated_seq == None`, successor coordinate == prior). It closes
        // NO leaf / interval — it only supersedes the target's own recovery
        // requests / reservations / welcomes and revokes their packages, all
        // bound to the revocation id. Dispatch here before the entry-bearing
        // `allocated_seq` extraction would `InconsistentPlan` on its `None` seq.
        PlanKind::DeviceRevocation => {
            return apply_device_revocation(
                transaction,
                plan,
                ctx,
                conversation_id,
                generation,
                state_version,
                epoch,
                None,
            )
            .await;
        }
        _ => {}
    }

    let allocated_seq = head.allocated_seq().ok_or(ExecutorError::InconsistentPlan(
        "head CAS has no allocated seq",
    ))?;
    let seq_i64 = checked_i64(allocated_seq)?;
    let successor_next_entry_seq = checked_i64(head.successor_next_entry_seq())?;

    match effects.kind() {
        PlanKind::Creation => {
            apply_creation(
                transaction,
                plan,
                ctx,
                conversation_id,
                transition_id,
                seq_i64,
                successor_next_entry_seq,
                generation,
                state_version,
                epoch,
                historical_write_authority,
            )
            .await
        }
        PlanKind::Policy => {
            apply_policy(
                transaction,
                plan,
                ctx,
                conversation_id,
                transition_id,
                seq_i64,
                successor_next_entry_seq,
                generation,
                state_version,
                epoch,
                historical_write_authority,
            )
            .await
        }
        // Every other plan kind is a real, planned edge this executor slice
        // does not yet compose. It is a HARD error (never a silent skip), so a
        // caller cannot mistake "not implemented" for "applied". The
        // remaining kinds (acceptConversation, metadata, commit, reset
        // request/activation, leave family, welcome dispositions, device
        // revocation, close) are the E2b-3 remainder — see the report.
        PlanKind::Acceptance => {
            apply_acceptance(
                transaction,
                plan,
                ctx,
                conversation_id,
                transition_id,
                seq_i64,
                successor_next_entry_seq,
                generation,
                state_version,
                epoch,
                historical_write_authority,
            )
            .await
        }
        PlanKind::Metadata => {
            apply_metadata_transition(
                transaction,
                plan,
                ctx,
                conversation_id,
                transition_id,
                seq_i64,
                successor_next_entry_seq,
                generation,
                state_version,
                epoch,
            )
            .await
        }
        PlanKind::Commit => {
            // Three `PlanKind::Commit` shapes, partitioned by their own edges.
            //
            // PARTITION PROOF (exhaustive + mutually exclusive by construction —
            // the planners are the authority):
            //   * A LEAVE fulfillment is the ONLY `Commit` whose planner
            //     (`plan_leave_fulfillment_inner`) terminalizes a leave request as
            //     FULFILLED (`Pending->Fulfilled`); it removes members and emits NO
            //     new Welcome. The discriminator matches that exact edge — NOT any
            //     leave-request delta: EVERY coordinate-advancing commit (generic /
            //     recovery / leave) may ALSO carry a prior-bound `Pending->Stale`
            //     leave staling (a co-pending leave request the coordinate change
            //     retired), which must NOT be read as a fulfillment.
            //   * A leaf-recovery fulfillment (`plan_leaf_recovery_fulfillment_inner`)
            //     ALWAYS emits exactly one NEW Welcome (`None->Some`, how the
            //     recovered target joins) and NEVER FULFILLS a leave request (though
            //     it may stale one).
            //   * A generic commit (`plan_commit_inner`) does NEITHER — no leave
            //     FULFILLMENT and no `None->Some` welcome. It may canonically remove
            //     leaves (closing their application intervals), and its only welcome
            //     delta is a prior-bound `Pending->Superseded`.
            // The two predicates are therefore disjoint (a Pending->Fulfilled leave
            // edge vs. a None->Some welcome are never both set) and exhaustive
            // (their negation is exactly the generic commit). Each branch's own
            // exact-shape guards (leave requires exactly one leave-request +
            // participant close; recovery requires exactly one own request/
            // reservation/package/new welcome; generic rejects participant and Add
            // membership deltas while enforcing Remove/interval bijection) HARD-error
            // a mis-partitioned plan rather than mis-applying it —
            // the discriminator is backstopped, never load-bearing alone.
            let is_leave_fulfillment = effects.leave_request_changes().iter().any(|change| {
                matches!(
                    (change.before(), change.after()),
                    (Some(before), Some(after))
                        if before.status() == LeaveRequestStatus::Pending
                            && after.status() == LeaveRequestStatus::Fulfilled
                )
            });
            let is_recovery_fulfillment = effects
                .welcome_changes()
                .iter()
                .any(|change| matches!((change.before(), change.after()), (None, Some(_))));
            if is_leave_fulfillment {
                apply_leave_fulfillment(
                    transaction,
                    plan,
                    ctx,
                    conversation_id,
                    transition_id,
                    seq_i64,
                    successor_next_entry_seq,
                    generation,
                    state_version,
                    epoch,
                )
                .await
            } else if is_recovery_fulfillment {
                apply_leaf_recovery_fulfillment(
                    transaction,
                    plan,
                    ctx,
                    conversation_id,
                    transition_id,
                    seq_i64,
                    successor_next_entry_seq,
                    generation,
                    state_version,
                    epoch,
                    recovery_write_authority,
                    historical_write_authority,
                )
                .await
            } else {
                apply_generic_commit(
                    transaction,
                    plan,
                    ctx,
                    conversation_id,
                    transition_id,
                    seq_i64,
                    successor_next_entry_seq,
                    generation,
                    state_version,
                    epoch,
                )
                .await
            }
        }
        // Entry-less internal ops are dispatched (and returned) above, before
        // the entry-bearing `allocated_seq` extraction.
        PlanKind::RecoveryRequest | PlanKind::RecoveryCancellation | PlanKind::RecoveryExpiry => {
            unreachable!("entry-less recovery ops are dispatched before this match")
        }
        // Entry-less; dispatched (and returned) above.
        PlanKind::DeviceRevocation => {
            unreachable!("entry-less device revocation is dispatched before this match")
        }
        PlanKind::ResetRequest => {
            apply_reset_request(
                transaction,
                plan,
                ctx,
                conversation_id,
                seq_i64,
                successor_next_entry_seq,
                generation,
                state_version,
                epoch,
            )
            .await
        }
        PlanKind::ResetActivation => {
            apply_reset_activation(
                transaction,
                plan,
                ctx,
                conversation_id,
                transition_id,
                seq_i64,
                successor_next_entry_seq,
                generation,
                state_version,
                epoch,
            )
            .await
        }
        PlanKind::LeaveRequest => {
            apply_leave_request(
                transaction,
                plan,
                ctx,
                conversation_id,
                seq_i64,
                successor_next_entry_seq,
                generation,
                state_version,
                epoch,
            )
            .await
        }
        PlanKind::LeaveCancellation => {
            apply_leave_cancellation(
                transaction,
                plan,
                ctx,
                conversation_id,
                seq_i64,
                successor_next_entry_seq,
                generation,
                state_version,
                epoch,
            )
            .await
        }
        PlanKind::ZeroLeafLeave => {
            apply_zero_leaf_leave(
                transaction,
                plan,
                ctx,
                conversation_id,
                transition_id,
                seq_i64,
                successor_next_entry_seq,
                generation,
                state_version,
                epoch,
            )
            .await
        }
        // Entry-less; dispatched (and returned) above.
        PlanKind::WelcomeAcknowledgement | PlanKind::WelcomeRejection | PlanKind::WelcomeExpiry => {
            unreachable!("entry-less welcome disposition ops are dispatched before this match")
        }
        PlanKind::Close => {
            apply_close(
                transaction,
                plan,
                ctx,
                conversation_id,
                transition_id,
                seq_i64,
                successor_next_entry_seq,
                generation,
                state_version,
                epoch,
            )
            .await
        }
    }
}

/// Apply one repository-prepared plan inside a nested SQL savepoint.
///
/// Every returned body error explicitly rolls the savepoint back before the
/// caller regains the outer transaction. Cancellation or panic drops SQLx's
/// live nested `Transaction`, which queues `ROLLBACK TO SAVEPOINT` on this
/// same PostgreSQL connection. The caller may reuse the outer transaction
/// only after a same-connection round trip succeeds and therefore drains
/// that queued rollback. Transaction-identity or savepoint infrastructure
/// errors still require the outer transaction to be abandoned.
pub(crate) async fn apply_conversation_persistence_plan(
    prepared: PreparedConversationExecution<'_, '_, '_>,
) -> Result<AppliedTransition, ExecutorError> {
    let PreparedConversationExecution {
        transaction,
        plan,
        context,
        expected_transaction_id,
        recovery_write_authority,
        historical_write_authority,
        _proof,
        #[cfg(any(
            test,
            all(
                feature = "chat-protocol-production-proof",
                not(feature = "server-bin")
            )
        ))]
        drop_safety_probe,
    } = prepared;
    let mut savepoint = transaction
        .begin()
        .await
        .map_err(ExecutorError::SavepointBegin)?;
    let live_transaction_id: Result<String, sqlx::Error> =
        sqlx::query_scalar("SELECT txid_current()::text")
            .fetch_one(&mut *savepoint)
            .await;
    let operation = match live_transaction_id {
        Ok(live_transaction_id)
            if live_transaction_id == expected_transaction_id.as_ref()
                && plan_transaction_bindings_match(plan, expected_transaction_id.as_ref()) =>
        {
            apply_conversation_persistence_plan_inner(
                &mut savepoint,
                plan,
                &context,
                recovery_write_authority.as_ref(),
                historical_write_authority.as_ref(),
            )
            .await
        }
        Ok(_) => Err(ExecutorError::TransactionBindingMismatch),
        Err(error) => Err(ExecutorError::TransactionIdentity(error)),
    };
    match operation {
        Ok(applied) => {
            #[cfg(any(
                test,
                all(
                    feature = "chat-protocol-production-proof",
                    not(feature = "server-bin")
                )
            ))]
            if let Some(probe) = drop_safety_probe {
                probe.reach().await;
            }
            savepoint
                .commit()
                .await
                .map_err(ExecutorError::SavepointRelease)?;
            Ok(applied)
        }
        Err(operation) => match savepoint.rollback().await {
            Ok(()) => Err(operation),
            Err(rollback) => Err(ExecutorError::SavepointRollback {
                operation: Box::new(operation),
                rollback,
            }),
        },
    }
}

/// Raw executor seam retained only for cfg(test) mutation/shape harnesses.
/// Its explicit name prevents it from shadowing or being counted as the
/// production prepared-capsule path above.
#[cfg(test)]
pub(crate) async fn apply_conversation_persistence_plan_unscoped_for_test(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &ConversationPersistencePlan,
    context: &ExecutionContext,
) -> Result<AppliedTransition, ExecutorError> {
    apply_conversation_persistence_plan_inner(transaction, plan, context, None, None).await
}

