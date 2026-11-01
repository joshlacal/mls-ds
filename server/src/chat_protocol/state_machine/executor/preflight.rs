#![allow(unused_imports)]
use super::*;

/// Complete logical-shape fence for ResetActivation. This runs before the
/// head CAS; applied-row reconciliation remains a second fence.
pub(in crate::chat_protocol::state_machine::executor) fn preflight_reset_activation(
    plan: &ConversationPersistencePlan,
    ctx: &ExecutionContext,
    prior: &PublicGroupSnapshotCoordinate,
    retired: &PublicGroupSnapshotCoordinate,
    transition_id: Uuid,
    seq_i64: i64,
) -> Result<Uuid, ExecutorError> {
    let effects = plan.effects();
    let hydration = plan.state();
    let producer = &hydration.producer;
    if producer.transition_id != *transition_id.as_bytes()
        || i64::try_from(producer.seq).ok() != Some(seq_i64)
    {
        return Err(ExecutorError::InconsistentPlan(
            "reset producer disagrees with allocated transition/sequence",
        ));
    }
    let (signed_request_id, signed_metadata) = match producer.body_binding.as_ref() {
        Some(crate::chat_protocol::state_machine::TransitionBodyBinding::ResetActivation {
            reset_request_id,
            prior: bound_prior,
            retired: bound_retired,
            successor,
            metadata,
            ..
        }) if bound_prior == prior
            && bound_retired == retired
            && successor == &hydration.coordinate =>
        {
            (*reset_request_id, metadata)
        }
        _ => {
            return Err(ExecutorError::InconsistentPlan(
                "reset producer coordinates/request binding drift",
            ))
        }
    };

    // Prior-bound reset / leave / Welcome work this generation retirement
    // retires, proved by the SHARED classifier — the same one every other
    // coordinate-changing arm calls, and the only place these three families are
    // shape-checked.
    //
    // The four hand-rolled loops this replaces accepted only Row A
    // (`Pending->Stale` / `Pending->Superseded`, terminal evidence = this
    // transition) and duplicated, more narrowly, checks the arm already performs.
    // But `resolve_prior_bound_work` emits Row B — status `Expired` with
    // `Expiry(expires_at)` — for ANY prior-bound reset / leave / Welcome whose
    // `expires_at` had already passed at `evidence.received_at`, and
    // `write_prior_bound_staling` / `write_welcome_supersessions` already write
    // that row. So an `activateReset` over a coordinate carrying a peer's overdue
    // pending leave (24h TTL, never swept) or an overdue pending Welcome was
    // planner-legal and executor-fatal, and a retry replanned the identical
    // shape: a permanent wedge. The classifier proves BOTH rows exactly —
    // identity unchanged, `before` Pending, `before` bound to this exact prior,
    // Row A's terminal the exact producer, Row B's terminal an exact DUE expiry
    // (`applied_at >= expires_at`) — so accepting it here is the executor
    // accepting its own planner's output, not a relaxation.
    //
    // The recovery request / reservation / package / `recovery_package_cas`
    // loops are gone for the same reason: `apply_reset_activation` already calls
    // `classify_prior_bound_recovery` (strictly before this preflight), which
    // proves those four families as a strict superset — both rows, the
    // request/reservation/package bijection, the `Reserved->Available` package
    // edge, and every CAS field equality. The `PriorBoundPartition` it returns has
    // no public constructor, so that call cannot be dropped without a compile
    // error.
    let welcome_ids = classify_prior_bound_staling(plan, ctx, OwnStalingKind::ResetActivation)?;

    // The arm's OWN edge, which the classifier deliberately leaves to it: exactly
    // one `Pending->Consumed` reset request, and it must be the exact request the
    // signed producer body names. It can never be Row B —
    // `plan_reset_activation_inner` rejects an overdue target with `WorkExpired`
    // before planning.
    let mut own_reset = None;
    for change in effects.reset_request_changes() {
        let (Some(before), Some(after)) = (change.before(), change.after()) else {
            return Err(ExecutorError::InconsistentPlan(
                "reset request delta is not terminal",
            ));
        };
        if after.status != ResetRequestStatus::Consumed {
            continue;
        }
        if after.request_id != signed_request_id
            || !reset_request_identity_is_unchanged(before, after)
            || before.status != ResetRequestStatus::Pending
            || before.bound_coordinate != *prior
            || !terminal_is_exact_transition(&after.terminal, producer)
            || own_reset.replace(after).is_some()
        {
            return Err(ExecutorError::InconsistentPlan(
                "reset own request identity/binding/terminal drift",
            ));
        }
    }
    let _own_reset = own_reset.ok_or(ExecutorError::InconsistentPlan(
        "reset consumes no exact signed pending request",
    ))?;

    let disposition_ids = ctx
        .welcome_dispositions
        .iter()
        .map(|input| *input.welcome_id.as_bytes())
        .collect::<BTreeSet<_>>();
    if welcome_ids != disposition_ids || disposition_ids.len() != ctx.welcome_dispositions.len() {
        return Err(ExecutorError::InconsistentPlan(
            "reset Welcome dispositions are not complete/bijective",
        ));
    }

    if hydration.leaves.len() != 1
        || ctx.opened_leaves.len() != 1
        || ctx.leaf_period_ids.len() != 1
        || ctx.participant_period_ids.len() != hydration.participants.len()
        || effects.opened_intervals().len() != 1
        || ctx.closing_leaf_periods.len() != effects.closed_intervals().len()
        || usize::try_from(ctx.spine.leaf_count).ok() != Some(ctx.closing_leaf_periods.len())
        || hydration
            .public_state
            .as_ref()
            .map(|state| state.binding().tree_summary().leaves().len())
            != Some(1)
        || ctx.events.len() != 1
        || ctx.metadata_author.is_none()
        || ctx.spine.leaf_count < 1
        || sha2::Sha256::digest(&ctx.spine.public_snapshot_bytes).as_slice()
            != ctx.spine.public_snapshot_sha256
        || sha2::Sha256::digest(&ctx.spine.tree_summary_bytes).as_slice()
            != ctx.spine.tree_summary_sha256
        || ctx.spine.genesis_group_info_bytes.is_empty()
        || sha2::Sha256::digest(&ctx.spine.genesis_group_info_bytes).as_slice()
            != ctx.spine.genesis_group_info_sha256
    {
        return Err(ExecutorError::InconsistentPlan(
            "reset execution context/spine cardinality or digest mismatch",
        ));
    }
    if hydration.leaves[0].device != ctx.opened_leaves[0].device
        || device_did(&hydration.leaves[0].device)? != ctx.actor.user_did
        || device_uuid(&hydration.leaves[0].device) != ctx.actor.device_id
        || effects.opened_intervals()[0] != hydration.leaves[0].device
    {
        return Err(ExecutorError::InconsistentPlan(
            "reset successor is not the singleton activator leaf/interval",
        ));
    }
    let closed_devices = effects
        .closed_intervals()
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let closing_context_devices = ctx
        .closing_leaf_periods
        .iter()
        .map(|(device, _)| device.clone())
        .collect::<BTreeSet<_>>();
    if closed_devices != closing_context_devices
        || closing_context_devices.len() != ctx.closing_leaf_periods.len()
    {
        return Err(ExecutorError::InconsistentPlan(
            "reset old leaf/interval closure context is incomplete",
        ));
    }

    // Validate every actual leaf delta. Reset closes the complete prior
    // generation and installs one successor leaf. `diff_by_key` may omit
    // the activator when its leaf bytes are identical across generations,
    // so completeness is the closed-device set minus at most that one
    // unchanged activator; every delta that is present remains fully
    // load-bearing.
    let successor_device = &hydration.leaves[0].device;
    let mut changed_before_devices = BTreeSet::new();
    let mut changed_after_devices = BTreeSet::new();
    for change in effects.leaf_changes() {
        match (change.before(), change.after()) {
            (Some(before), None)
                if before.device != *successor_device
                    && closed_devices.contains(&before.device) =>
            {
                if !changed_before_devices.insert(before.device.clone()) {
                    return Err(ExecutorError::InconsistentPlan(
                        "reset repeats an old leaf delta",
                    ));
                }
            }
            (Some(before), Some(after))
                if before.device == *successor_device
                    && after.device == *successor_device
                    && before != after
                    && leaf_matches_hydration(after, &hydration.leaves[0])
                    && closed_devices.contains(&before.device) =>
            {
                if !changed_before_devices.insert(before.device.clone())
                    || !changed_after_devices.insert(after.device.clone())
                {
                    return Err(ExecutorError::InconsistentPlan(
                        "reset repeats the successor leaf delta",
                    ));
                }
            }
            _ => {
                return Err(ExecutorError::InconsistentPlan(
                    "reset leaf change has an illegal shape/content",
                ))
            }
        }
    }
    let mut accounted_old_leaves = changed_before_devices;
    accounted_old_leaves.insert(successor_device.clone());
    if accounted_old_leaves != closed_devices || changed_after_devices.len() > 1 {
        return Err(ExecutorError::InconsistentPlan(
            "reset leaf deltas do not account for the prior/successor leaves",
        ));
    }

    // Validate every actual interval delta, including the complete
    // TransitionEvidence value. This is deliberately before the head CAS:
    // writers must never persist a caller-mutated closing fingerprint.
    let mut closed_interval_devices = BTreeSet::new();
    let mut opened_interval_devices = BTreeSet::new();
    for change in effects.interval_changes() {
        match (change.before(), change.after()) {
            (Some(before), Some(after))
                if interval_identity_is_unchanged(before, after)
                    && before.generation == prior.generation()
                    && after.end.as_ref().is_some_and(|end| {
                        end.kind == CloseKind::Reset && end.evidence == *producer
                    }) =>
            {
                if !closed_interval_devices.insert(after.recipient.clone()) {
                    return Err(ExecutorError::InconsistentPlan(
                        "reset repeats a closed interval",
                    ));
                }
            }
            (None, Some(after))
                if after.recipient == *successor_device
                    && after.generation == hydration.coordinate.generation()
                    && after.opening == *producer
                    && after.opening_kind
                        == crate::chat_protocol::state_machine::OpeningKind::Reset
                    && after.opening_context == hydration.coordinate
                    && after.end.is_none() =>
            {
                if !opened_interval_devices.insert(after.recipient.clone()) {
                    return Err(ExecutorError::InconsistentPlan(
                        "reset repeats the successor interval",
                    ));
                }
            }
            _ => {
                return Err(ExecutorError::InconsistentPlan(
                    "reset interval change has an illegal shape/evidence",
                ))
            }
        }
    }
    if closed_interval_devices != closed_devices
        || opened_interval_devices != BTreeSet::from([successor_device.clone()])
        || effects.interval_changes().len()
            != closed_devices
                .len()
                .checked_add(1)
                .ok_or(ExecutorError::ValueOutOfRange)?
    {
        return Err(ExecutorError::InconsistentPlan(
            "reset interval changes are not complete/bijective",
        ));
    }

    // The actual metadata delta must be the exact signed ResetActivation
    // binding and the context columns must be the same authenticated author.
    let metadata_change = effects
        .metadata_change()
        .ok_or(ExecutorError::InconsistentPlan(
            "reset metadata change is missing",
        ))?;
    let (Some(before_metadata), Some(after_metadata)) =
        (metadata_change.before(), metadata_change.after())
    else {
        return Err(ExecutorError::InconsistentPlan(
            "reset metadata change is not a complete replacement",
        ));
    };
    let metadata_author = ctx
        .metadata_author
        .as_ref()
        .ok_or(ExecutorError::MissingContext(
            "reset metadata author columns",
        ))?;
    if after_metadata != signed_metadata
        || before_metadata == after_metadata
        || after_metadata.coordinate_conversation_id() != hydration.coordinate.conversation_id()
        || after_metadata.coordinate_generation() != hydration.coordinate.generation()
        || after_metadata.coordinate_group_id() != hydration.coordinate.group_id()
        || after_metadata.coordinate_epoch() != hydration.coordinate.epoch()
        || after_metadata.coordinate_group_context_hash()
            != hydration.coordinate.group_context_hash()
        || after_metadata.coordinate_confirmation_tag() != hydration.coordinate.confirmation_tag()
        || after_metadata.author() != successor_device
        || metadata_author.author_role != "admin"
        || metadata_author.author_device_status != "active"
        || metadata_author.author_key_id != URL_SAFE_NO_PAD.encode(after_metadata.author_key_id())
        || metadata_author.author_public_key != after_metadata.signature_public_key()
        || u64::try_from(ctx.actor.auth_generation).ok()
            != Some(after_metadata.author_auth_generation_at_origin())
    {
        return Err(ExecutorError::InconsistentPlan(
            "reset metadata delta/context does not bind the signed successor",
        ));
    }

    // Validate entry/event shapes exhaustively. UUIDs and predecessors are
    // server-minted, but every security-relevant recipient, entitlement,
    // event kind, and outbox direction is fixed here before any write.
    let entry_devices = ctx
        .entry_recipients
        .iter()
        .map(|(device, entitlement)| {
            if *entitlement != EntryEntitlementKind::IntervalClose {
                return Err(ExecutorError::InconsistentPlan(
                    "reset entry recipient has the wrong entitlement",
                ));
            }
            Ok(device.clone())
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if entry_devices != closed_devices || entry_devices.len() != ctx.entry_recipients.len() {
        return Err(ExecutorError::InconsistentPlan(
            "reset entry audience is not complete/bijective",
        ));
    }
    let disposition_devices = ctx
        .welcome_dispositions
        .iter()
        .map(|input| {
            let welcome = effects
                .welcome_changes()
                .iter()
                .find_map(|change| {
                    change.after().filter(|after| {
                        // BOTH terminal rows carry a `welcomeDisposition` event.
                        // Which row this is was already proved exactly by
                        // `classify_prior_bound_staling` above; here we only need
                        // the delta the disposition event belongs to, so pinning
                        // `Superseded` alone rejected the legal due-expiry row.
                        after.welcome_id == *input.welcome_id.as_bytes()
                            && matches!(
                                after.status,
                                WelcomeStatus::Superseded | WelcomeStatus::Expired
                            )
                    })
                })
                .ok_or(ExecutorError::InconsistentPlan(
                    "reset Welcome disposition has no exact delta",
                ))?;
            let event = &input.event;
            if !crate::chat_protocol::state_machine::is_uuid_v4(event.event_id.as_bytes())
                || event.event_kind != EventKind::WelcomeDisposition
                || event.payload_bytes.is_empty()
                || event.recipients.len() != 1
                || event.recipients[0].0 != welcome.recipient
                || event.recipients[0].1 != EventEntitlementKind::Welcome
                || event.outbox.len() != 1
                || !crate::chat_protocol::state_machine::is_uuid_v4(event.outbox[0].0.as_bytes())
                || event.outbox[0].1 != OutboxWorkKind::Stream
            {
                return Err(ExecutorError::InconsistentPlan(
                    "reset Welcome disposition event has an illegal shape",
                ));
            }
            Ok(welcome.recipient.clone())
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let primary = &ctx.events[0];
    let primary_devices = primary
        .recipients
        .iter()
        .map(|(device, entitlement, _)| {
            if *entitlement != EventEntitlementKind::Participant {
                return Err(ExecutorError::InconsistentPlan(
                    "reset primary event has the wrong entitlement",
                ));
            }
            Ok(device.clone())
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected_primary = entry_devices
        .difference(&disposition_devices)
        .cloned()
        .collect::<BTreeSet<_>>();
    if !crate::chat_protocol::state_machine::is_uuid_v4(primary.event_id.as_bytes())
        || primary.event_kind != EventKind::ConversationChanged
        || primary.payload_bytes.is_empty()
        || primary_devices != expected_primary
        || primary_devices.len() != primary.recipients.len()
        || primary.outbox.len() != 1
        || !crate::chat_protocol::state_machine::is_uuid_v4(primary.outbox[0].0.as_bytes())
        || primary.outbox[0].1 != OutboxWorkKind::Stream
    {
        return Err(ExecutorError::InconsistentPlan(
            "reset primary event has an illegal shape/audience",
        ));
    }
    Ok(Uuid::from_bytes(signed_request_id))
}

/// Pure, complete effect-family validation for a leaf-recovery fulfillment.
/// This runs before the first repository writer. It classifies the arm's four
/// own edges and every legal prior-bound supersession/staling edge, proves the
/// cross-family request/package bijections, and validates the target leaf /
/// interval shape. The write phase retains applied-count reconciliation as a
/// second fence.
pub(in crate::chat_protocol::state_machine::executor) fn preflight_leaf_recovery_fulfillment(
    plan: &ConversationPersistencePlan,
    effects: &TransitionEffects,
    hydration: &ConversationStateHydration,
    ctx: &ExecutionContext,
    transition_id: Uuid,
    seq_i64: i64,
) -> Result<(FamilyCounts, PriorBoundPartition), ExecutorError> {
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
    if effects
        .metadata_change()
        .and_then(StateChange::after)
        .is_none()
        || ctx.metadata_author.is_none()
    {
        return Err(ExecutorError::InconsistentPlan(
            "fulfillment carries no complete metadata re-encryption",
        ));
    }

    let producer = &hydration.producer;
    if producer.transition_id != *transition_id.as_bytes()
        || i64::try_from(producer.seq).ok() != Some(seq_i64)
    {
        return Err(ExecutorError::InconsistentPlan(
            "fulfillment producer disagrees with allocated transition/sequence",
        ));
    }

    // DEFECT 2 FIX. The two blocks this replaces demanded
    // `terminal_is_exact_transition` of EVERY recovery request and reservation
    // on the coordinate, so a peer's overdue `Expiry` terminal fell through to
    // the `_ => illegal direction` arm. Open recovery requests are unique per
    // TARGET and coordinate-preserving, so peers stack requests on one
    // coordinate with staggered `expires_at`; fulfilling one device while a
    // peer's request was overdue produced a planner-valid, executor-fatal plan,
    // and the recovering device wedged PERMANENTLY because retry re-planned the
    // identical shape. Prior-bound families are now classified, not rejected.
    let partition =
        classify_prior_bound_recovery(plan, ctx, OwnFamilyKind::LeafRecoveryFulfillment)?;
    let own_key = partition.own().ok_or(ExecutorError::InconsistentPlan(
        "fulfillment carries no own recovery family",
    ))?;
    let own_request = effects
        .recovery_request_changes()
        .iter()
        .filter_map(StateChange::after)
        .find(|request| (request.request_id, request.key_package_ref) == own_key)
        .ok_or(ExecutorError::InconsistentPlan(
            "fulfillment carries no own fulfilled recovery request",
        ))?;
    let own_reservation = effects
        .reservation_changes()
        .iter()
        .filter_map(StateChange::after)
        .find(|reservation| (reservation.request_id, reservation.key_package_ref) == own_key)
        .ok_or(ExecutorError::InconsistentPlan(
            "fulfillment carries no own consumed reservation",
        ))?;

    // Retained: the own package edge's driven-ref and direction check.
    verify_recovery_package_consistency(
        effects,
        &own_request.key_package_ref,
        PackageStatus::Reserved,
        PackageStatus::Consumed,
    )?;

    let own_cas = effects
        .recovery_package_cas()
        .iter()
        .filter(|binding| {
            binding.request_id == own_request.request_id
                && binding.key_package_ref == own_request.key_package_ref
                && binding.expected_status == PackageStatus::Reserved
                && binding.successor_status == PackageStatus::Consumed
        })
        .collect::<Vec<_>>();
    if own_cas.len() != 1
        || own_cas[0].target != own_request.target
        || own_cas[0].bound_coordinate != own_request.bound_coordinate
        || own_cas[0].package_not_after != own_reservation.package_not_after
    {
        return Err(ExecutorError::InconsistentPlan(
            "fulfillment package CAS disagrees with own open work",
        ));
    }

    let mut own_welcome: Option<&WelcomeWork> = None;
    let mut superseded_welcomes = BTreeSet::new();
    for change in effects.welcome_changes() {
        match (change.before(), change.after()) {
            (None, Some(after))
                if after.status == WelcomeStatus::Pending && after.terminal.is_none() =>
            {
                if own_welcome.replace(after).is_some() {
                    return Err(ExecutorError::InconsistentPlan(
                        "fulfillment carries multiple own pending welcomes",
                    ));
                }
            }
            (Some(before), Some(after))
                if welcome_identity_is_unchanged(before, after)
                    && before.status == WelcomeStatus::Pending
                    && after.status == WelcomeStatus::Superseded
                    && terminal_is_exact_transition(&after.terminal, producer) =>
            {
                if !superseded_welcomes.insert(after.welcome_id) {
                    return Err(ExecutorError::InconsistentPlan(
                        "fulfillment repeats a superseded Welcome",
                    ));
                }
            }
            _ => {
                return Err(ExecutorError::InconsistentPlan(
                    "fulfillment welcome change has an illegal shape",
                ))
            }
        }
    }
    let own_welcome = own_welcome.ok_or(ExecutorError::InconsistentPlan(
        "fulfillment carries no own pending welcome",
    ))?;
    if own_welcome.recipient != own_request.target
        || own_welcome.recovery_request_id != own_request.request_id
        || own_welcome.key_package_ref != own_request.key_package_ref
        || own_welcome.coordinate != hydration.coordinate
        || i64::try_from(own_welcome.transition_seq).ok() != Some(seq_i64)
        || own_welcome.expires_at != own_reservation.package_not_after
        || own_welcome.sha256 != <[u8; 32]>::from(sha2::Sha256::digest(&own_welcome.opaque_welcome))
    {
        return Err(ExecutorError::InconsistentPlan(
            "fulfillment pending Welcome is not bijective with own work/successor",
        ));
    }
    let disposition_welcomes = ctx
        .welcome_dispositions
        .iter()
        .map(|input| *input.welcome_id.as_bytes())
        .collect::<BTreeSet<_>>();
    if disposition_welcomes.len() != ctx.welcome_dispositions.len()
        || disposition_welcomes != superseded_welcomes
    {
        return Err(ExecutorError::InconsistentPlan(
            "fulfillment Welcome dispositions are not bijective",
        ));
    }

    let mut staled_resets = BTreeSet::new();
    for change in effects.reset_request_changes() {
        let (Some(before), Some(after)) = (change.before(), change.after()) else {
            return Err(ExecutorError::InconsistentPlan(
                "fulfillment reset request change is not terminal",
            ));
        };
        if !reset_request_identity_is_unchanged(before, after)
            || before.status != ResetRequestStatus::Pending
            || after.status != ResetRequestStatus::Stale
            || !terminal_is_exact_transition(&after.terminal, producer)
        {
            return Err(ExecutorError::InconsistentPlan(
                "fulfillment reset request change is not exact prior-bound staling",
            ));
        }
        if !staled_resets.insert(after.request_id) {
            return Err(ExecutorError::InconsistentPlan(
                "fulfillment repeats a staled reset request",
            ));
        }
    }
    let mut staled_leaves = BTreeSet::new();
    for change in effects.leave_request_changes() {
        let (Some(before), Some(after)) = (change.before(), change.after()) else {
            return Err(ExecutorError::InconsistentPlan(
                "fulfillment leave request change is not terminal",
            ));
        };
        if !leave_request_identity_is_unchanged(before, after)
            || before.status != LeaveRequestStatus::Pending
            || after.status != LeaveRequestStatus::Stale
            || !terminal_is_exact_transition(&after.terminal, producer)
        {
            return Err(ExecutorError::InconsistentPlan(
                "fulfillment leave request change is not exact prior-bound staling",
            ));
        }
        if !staled_leaves.insert(after.request_id) {
            return Err(ExecutorError::InconsistentPlan(
                "fulfillment repeats a staled leave request",
            ));
        }
    }

    let target = &own_request.target;
    let mut target_leaf_is_replace = None;
    let mut changed_leaf_devices = BTreeSet::new();
    for change in effects.leaf_changes() {
        match (change.before(), change.after()) {
            (None, Some(after))
                if after.device() == target
                    && hydration
                        .leaves
                        .iter()
                        .any(|row| leaf_matches_hydration(after, row)) =>
            {
                if target_leaf_is_replace.replace(false).is_some() {
                    return Err(ExecutorError::InconsistentPlan(
                        "fulfillment repeats the target leaf change",
                    ));
                }
            }
            (Some(before), Some(after))
                if before.device() == target
                    && after.device() == target
                    && before != after
                    && hydration
                        .leaves
                        .iter()
                        .any(|row| leaf_matches_hydration(after, row)) =>
            {
                if target_leaf_is_replace.replace(true).is_some() {
                    return Err(ExecutorError::InconsistentPlan(
                        "fulfillment repeats the target leaf change",
                    ));
                }
            }
            (Some(before), Some(after))
                if before.device() == after.device()
                    && hydration
                        .leaves
                        .iter()
                        .any(|row| leaf_matches_hydration(after, row)) => {}
            _ => {
                return Err(ExecutorError::InconsistentPlan(
                    "fulfillment carries an unexpected leaf change",
                ))
            }
        }
        let device = change
            .after()
            .expect("every accepted fulfillment leaf change has an after")
            .device()
            .clone();
        if !changed_leaf_devices.insert(device) {
            return Err(ExecutorError::InconsistentPlan(
                "fulfillment repeats a changed leaf device",
            ));
        }
    }
    let is_replace = target_leaf_is_replace.ok_or(ExecutorError::InconsistentPlan(
        "fulfillment carries no target leaf change",
    ))?;
    if is_replace != (own_request.kind == LeafRecoveryKind::Replace)
        || (!is_replace && own_request.kind != LeafRecoveryKind::Add)
        || hydration
            .leaves
            .iter()
            .filter(|leaf| &leaf.device == target)
            .count()
            != 1
        || ctx.opened_leaves.len() != 1
        || ctx
            .opened_leaves
            .iter()
            .filter(|leaf| &leaf.device == target)
            .count()
            != 1
        || ctx.leaf_period_ids.len() != 1
        || ctx.closing_leaf_periods.len() != usize::from(is_replace)
    {
        return Err(ExecutorError::InconsistentPlan(
            "fulfillment target leaf/context shape disagrees with request kind",
        ));
    }

    let mut opened_intervals = 0usize;
    let mut closed_intervals = 0usize;
    for change in effects.interval_changes() {
        match (change.before(), change.after()) {
            (None, Some(after))
                if after.recipient() == target
                    && after.opening_kind()
                        == crate::chat_protocol::state_machine::OpeningKind::Add
                    && after.opening == *producer
                    && after.generation == hydration.coordinate.generation()
                    && after.end().is_none()
                    && after.opening_context() == &hydration.coordinate =>
            {
                opened_intervals += 1;
            }
            (Some(before), Some(after))
                if interval_identity_is_unchanged(before, after)
                    && before.recipient() == target
                    && after.recipient() == target
                    && after.end().is_some_and(|end| {
                        end.kind() == CloseKind::Replace && end.evidence == *producer
                    }) =>
            {
                closed_intervals += 1;
            }
            _ => {
                return Err(ExecutorError::InconsistentPlan(
                    "fulfillment interval change has an illegal shape/binding",
                ))
            }
        }
    }
    if opened_intervals != 1 || closed_intervals != usize::from(is_replace) {
        return Err(ExecutorError::InconsistentPlan(
            "fulfillment interval changes do not match the request kind",
        ));
    }

    let prior_bound = FamilyCounts {
        // Rebuilt from the classifier's typed partition, over ALL classified
        // prior-bound keys (Row A and Row B). welcomes/reset_requests/
        // leave_requests keep their own locals — those families are outside
        // the classifier's scope, and zeroing them would fail the fence.
        requests: partition.requests(),
        reservations: partition.reservations(),
        packages: partition.packages(),
        welcomes: superseded_welcomes.len(),
        reset_requests: staled_resets.len(),
        leave_requests: staled_leaves.len(),
    };
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
        &prior_bound,
    )?;
    Ok((prior_bound, partition))
}
