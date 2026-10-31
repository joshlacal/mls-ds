#![allow(unused_imports)]
use super::*;

/// Apply an entry-less `deviceRevocation` op for ONE conversation. The
/// coordinate + seq counter are UNCHANGED (a pure prior-coordinate verify);
/// there is NO MLS Remove and NO interval close. It supersedes the TARGET's
/// own open recovery requests (Open->Superseded), releases their reservations
/// (Active->Released), revokes their reserved packages (Reserved->Revoked),
/// and supersedes their pending welcomes (Pending->Superseded) — ALL bound to
/// the revocation id at `terminal_at == accepted_at`. The immutable
/// `device_revocations` row + the registration revoke are batch-level
/// (`apply_device_revocation_batch_prefix`); this arm owns only the
/// per-conversation work terminalizations. Modeled on
/// `apply_leaf_recovery_request`.
#[allow(clippy::too_many_arguments)]
pub(in crate::chat_protocol::state_machine::executor) async fn apply_device_revocation(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &ConversationPersistencePlan,
    ctx: &ExecutionContext,
    conversation_id: Uuid,
    generation: i64,
    state_version: i64,
    _epoch: i64,
    mut event_cursor: Option<&mut EventChainCursor>,
) -> Result<AppliedTransition, ExecutorError> {
    let effects = plan.effects();
    let head = effects
        .head_cas()
        .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
    let expected_prior = head
        .expected_prior()
        .ok_or(ExecutorError::InconsistentPlan(
            "device revocation needs a prior",
        ))?;
    let expected_generation = checked_i64(expected_prior.generation())?;
    let expected_state_version = checked_i64(expected_prior.state_version())?;
    let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;
    let successor_next_entry_seq = checked_i64(head.successor_next_entry_seq())?;

    // The revocation identity comes from the plan authority — the revocation
    // id + accepted_at every terminalization binds (all `terminal_at`).
    let evidence = match effects.authority() {
        Some(PlanAuthority::DeviceRevocation(evidence)) => evidence,
        _ => {
            return Err(ExecutorError::InconsistentPlan(
                "device revocation plan missing revocation authority",
            ))
        }
    };
    let revocation_id = Uuid::from_bytes(*evidence.revocation_id());
    if ctx.operation_id() != revocation_id {
        return Err(ExecutorError::MissingContext(
            "exact device revocation operation id",
        ));
    }
    let accepted_at = server_instant(evidence.accepted_at())?;

    // Only the target's own work is terminalized; every other family empty.
    // recovery_request / reservation / package / welcome deltas are the
    // revocation-bound supersessions (handled below); everything else is a
    // hard error, never a silent drop.
    reject_if_present("participant_changes", effects.participant_changes())?;
    reject_if_present("leaf_changes", effects.leaf_changes())?;
    reject_if_present("interval_changes", effects.interval_changes())?;
    reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
    reject_if_present("reset_request_changes", effects.reset_request_changes())?;
    reject_if_present("leave_request_changes", effects.leave_request_changes())?;
    reject_if_present("recovery_package_cas", effects.recovery_package_cas())?;
    if effects.metadata_change().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "device revocation metadata change",
        ));
    }
    if effects.welcome_cas().is_some()
        || effects.revocation_target_cas().is_some()
        || effects.invitation_quota_cas().is_some()
    {
        return Err(ExecutorError::UnsupportedEffect(
            "device revocation welcome/target/quota CAS",
        ));
    }
    // Internal op MUST NOT change the coordinate or advance the seq counter.
    if successor_next_entry_seq != expected_next_entry_seq {
        return Err(ExecutorError::InconsistentPlan(
            "device revocation must not advance the seq counter",
        ));
    }
    if generation != expected_generation || state_version != expected_state_version {
        return Err(ExecutorError::InconsistentPlan(
            "device revocation must not change the coordinate",
        ));
    }
    // The package edges are Reserved->Revoked, load-bearing-bound to the
    // `revocation_package_cas` witnesses (bijective per the plan seam). An
    // empty package set (a target with only welcomes) is legal.
    if !effects.package_transitions().is_empty() && !revocation_package_cas_bijection_valid(effects)
    {
        return Err(ExecutorError::InconsistentPlan(
            "device revocation package CAS is not bijective with the Reserved->Revoked edges",
        ));
    }

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

    // 2. Revocation-bound terminalizations of the target's OWN work.
    let mut superseded =
        write_revocation_bound_supersessions(transaction, effects, revocation_id, accepted_at)
            .await?;
    // 3. The target's pending welcomes (Pending->Superseded), each bound to a
    //    `welcomeDisposition` event (stamped at ctx.applied_at == accepted_at).
    superseded.welcomes = write_welcome_supersessions_with_cursor(
        transaction,
        ctx,
        effects,
        WelcomeSupersessionCause::Revocation {
            terminal_revocation_id: revocation_id,
        },
        event_cursor.as_deref_mut(),
    )
    .await?;
    // 4. Silent-drop guard: a device revocation FULFILLS nothing (own == 0),
    //    so every delta MUST be a revocation-bound supersession.
    reconcile_coordinate_change_families(effects, &FamilyCounts::default(), &superseded)?;

    // 5. No control entry (internal op) -> no entry recipients; only events.
    let event_positions =
        write_events_with_cursor(transaction, ctx, event_cursor.as_deref_mut(), None).await?;

    Ok(AppliedTransition {
        // No control entry / seq was allocated; echo the unchanged counter.
        allocated_seq: u64::try_from(successor_next_entry_seq).unwrap(),
        entry_id: ctx.operation_id(),
        event_positions,
        successor_coordinate: plan.successor_coordinate().copied(),
    })
}

/// A single member whose complete rejectable semantics were checked before
/// the batch prefix. The fields are private and the type is held only by the
/// opaque batch, so application cannot receive a newly substituted plan or
/// context after the first write.
#[derive(Debug)]
pub(in crate::chat_protocol::state_machine::executor) struct PreparedRevocationMember<'plan> {
    pub(in crate::chat_protocol::state_machine::executor) plan: &'plan ConversationPersistencePlan,
    pub(in crate::chat_protocol::state_machine::executor) context: ExecutionContext,
    pub(in crate::chat_protocol::state_machine::executor) conversation_id: Uuid,
    pub(in crate::chat_protocol::state_machine::executor) generation: i64,
    pub(in crate::chat_protocol::state_machine::executor) state_version: i64,
    pub(in crate::chat_protocol::state_machine::executor) next_entry_seq: i64,
    pub(in crate::chat_protocol::state_machine::executor) revocation_id: Uuid,
    pub(in crate::chat_protocol::state_machine::executor) accepted_at: DateTime<Utc>,
}

/// Opaque state-machine half of the G6 capsule. Raw members, cursors and
/// symbolic events never cross the module boundary.
#[must_use = "prepared revocation members must be consumed atomically"]
pub(crate) struct PreparedDeviceRevocationBatchMembers<'plan> {
    pub(in crate::chat_protocol::state_machine::executor) plan: &'plan DeviceRevocationBatchPersistencePlan,
    pub(in crate::chat_protocol::state_machine::executor) members: Vec<PreparedRevocationMember<'plan>>,
    pub(in crate::chat_protocol::state_machine::executor) cursor: EventChainCursor,
    pub(in crate::chat_protocol::state_machine::executor) binding_digest: [u8; 32],
}

impl PreparedDeviceRevocationBatchMembers<'_> {
    pub(crate) fn binding_digest(&self) -> &[u8; 32] {
        &self.binding_digest
    }

    pub(crate) fn binding_is_intact(&self) -> bool {
        self.cursor.initial_binding_is_intact()
            && self.binding_digest
                == prepared_device_revocation_members_binding_digest(
                    self.plan,
                    &self.members,
                    &self.cursor,
                )
    }
}

/// Typestate returned only after the immutable/device-global prefix has
/// succeeded. It remains opaque and can be consumed exactly once.
pub(crate) struct PrefixedDeviceRevocationBatchMembers<'plan> {
    pub(in crate::chat_protocol::state_machine::executor) members: Vec<PreparedRevocationMember<'plan>>,
    pub(in crate::chat_protocol::state_machine::executor) cursor: EventChainCursor,
}

/// Complete SQL-free preflight for every semantic rejection formerly
/// reachable from `apply_device_revocation`. In particular, this validates
/// every family edge and requires an exact bijection between superseded
/// Welcome IDs and disposition artifacts.
pub(in crate::chat_protocol::state_machine::executor) fn preflight_device_revocation_plan_and_context<'plan>(
    plan: &'plan ConversationPersistencePlan,
    context: ExecutionContext,
    batch_revocation_id: Uuid,
) -> Result<PreparedRevocationMember<'plan>, ExecutorError> {
    let effects = plan.effects();
    if effects.kind() != PlanKind::DeviceRevocation {
        return Err(ExecutorError::InconsistentPlan(
            "prepared revocation member has non-revocation plan",
        ));
    }
    let head = effects
        .head_cas()
        .ok_or(ExecutorError::InconsistentPlan("missing head CAS binding"))?;
    let expected_prior = head
        .expected_prior()
        .ok_or(ExecutorError::InconsistentPlan(
            "device revocation needs a prior",
        ))?;
    let expected_generation = checked_i64(expected_prior.generation())?;
    let expected_state_version = checked_i64(expected_prior.state_version())?;
    let expected_next_entry_seq = checked_i64(head.expected_next_entry_seq())?;
    let successor_next_entry_seq = checked_i64(head.successor_next_entry_seq())?;
    let evidence = match effects.authority() {
        Some(PlanAuthority::DeviceRevocation(evidence)) => evidence,
        _ => {
            return Err(ExecutorError::InconsistentPlan(
                "device revocation plan missing revocation authority",
            ))
        }
    };
    let revocation_id = Uuid::from_bytes(*evidence.revocation_id());
    if revocation_id != batch_revocation_id || context.operation_id() != revocation_id {
        return Err(ExecutorError::MissingContext(
            "exact device revocation operation id",
        ));
    }
    let accepted_at = server_instant(evidence.accepted_at())?;
    if context.applied_at != accepted_at {
        return Err(ExecutorError::InconsistentPlan(
            "device revocation context instant disagrees with authority",
        ));
    }

    reject_if_present("participant_changes", effects.participant_changes())?;
    reject_if_present("leaf_changes", effects.leaf_changes())?;
    reject_if_present("interval_changes", effects.interval_changes())?;
    reject_if_present("terminal_proof_changes", effects.terminal_proof_changes())?;
    reject_if_present("reset_request_changes", effects.reset_request_changes())?;
    reject_if_present("leave_request_changes", effects.leave_request_changes())?;
    reject_if_present("recovery_package_cas", effects.recovery_package_cas())?;
    if effects.metadata_change().is_some() {
        return Err(ExecutorError::UnsupportedEffect(
            "device revocation metadata change",
        ));
    }
    if effects.welcome_cas().is_some()
        || effects.revocation_target_cas().is_some()
        || effects.invitation_quota_cas().is_some()
    {
        return Err(ExecutorError::UnsupportedEffect(
            "device revocation welcome/target/quota CAS",
        ));
    }
    let coordinate = &plan.state().coordinate;
    let generation = checked_i64(coordinate.generation())?;
    let state_version = checked_i64(coordinate.state_version())?;
    let _epoch = checked_i64(coordinate.epoch())?;
    if successor_next_entry_seq != expected_next_entry_seq {
        return Err(ExecutorError::InconsistentPlan(
            "device revocation must not advance the seq counter",
        ));
    }
    if generation != expected_generation || state_version != expected_state_version {
        return Err(ExecutorError::InconsistentPlan(
            "device revocation must not change the coordinate",
        ));
    }
    if !effects.package_transitions().is_empty() && !revocation_package_cas_bijection_valid(effects)
    {
        return Err(ExecutorError::InconsistentPlan(
            "device revocation package CAS is not bijective with the Reserved->Revoked edges",
        ));
    }
    if effects.recovery_request_changes().iter().any(|change| {
        !matches!(
            (change.before(), change.after()),
            (Some(before), Some(after))
                if before.status() == RecoveryRequestStatus::Open
                    && after.status() == RecoveryRequestStatus::Superseded
        )
    }) {
        return Err(ExecutorError::InconsistentPlan(
            "device revocation recovery request family is not exact Open->Superseded",
        ));
    }
    if effects.reservation_changes().iter().any(|change| {
        !matches!(
            (change.before(), change.after()),
            (Some(before), Some(after))
                if before.status() == ReservationStatus::Active
                    && after.status() == ReservationStatus::Released
        )
    }) {
        return Err(ExecutorError::InconsistentPlan(
            "device revocation reservation family is not exact Active->Released",
        ));
    }
    if effects
        .package_transitions()
        .iter()
        .any(|edge| edge.from != PackageStatus::Reserved || edge.to != PackageStatus::Revoked)
    {
        return Err(ExecutorError::InconsistentPlan(
            "device revocation package family is not exact Reserved->Revoked",
        ));
    }

    let mut welcome_ids = BTreeSet::new();
    for change in effects.welcome_changes() {
        let (before, after) = match (change.before(), change.after()) {
            (Some(before), Some(after))
                if before.status() == WelcomeStatus::Pending
                    && after.status() == WelcomeStatus::Superseded =>
            {
                (before, after)
            }
            _ => {
                return Err(ExecutorError::InconsistentPlan(
                    "device revocation Welcome family is not exact Pending->Superseded",
                ))
            }
        };
        if before.welcome_id() != after.welcome_id()
            || !welcome_ids.insert(Uuid::from_bytes(*after.welcome_id()))
        {
            return Err(ExecutorError::InconsistentPlan(
                "device revocation Welcome family repeats or changes identity",
            ));
        }
    }
    let mut disposition_ids = BTreeSet::new();
    for disposition in &context.welcome_dispositions {
        if !disposition_ids.insert(disposition.welcome_id) {
            return Err(ExecutorError::MissingContext(
                "unique welcome disposition event per superseded welcome",
            ));
        }
    }
    if welcome_ids != disposition_ids {
        return Err(ExecutorError::MissingContext(
            "exact welcome disposition events for superseded welcomes",
        ));
    }

    Ok(PreparedRevocationMember {
        plan,
        context,
        conversation_id: Uuid::from_bytes(*coordinate.conversation_id()),
        generation,
        state_version,
        next_entry_seq: successor_next_entry_seq,
        revocation_id,
        accepted_at,
    })
}

/// Mint the opaque state-machine batch only after repository hydration has
/// produced the unforgeable proof. All member preflights and the complete
/// event schedule are frozen before this returns.
pub(crate) fn prepare_device_revocation_batch_members<'plan>(
    plan: &'plan DeviceRevocationBatchPersistencePlan,
    contexts: Vec<ExecutionContext>,
    prelude_digest: [u8; 32],
    devices: Vec<DeviceIdentity>,
    initial_tails: Vec<Option<i64>>,
    _proof: crate::chat_protocol::repository::execution_context::RevocationBatchHydrationProof,
) -> Result<PreparedDeviceRevocationBatchMembers<'plan>, ExecutorError> {
    if plan.conversations().len() != contexts.len() {
        return Err(ExecutorError::InconsistentPlan(
            "device revocation batch needs one execution context per conversation",
        ));
    }
    let revocation_id = preflight_device_revocation_batch(plan)?;
    let slots = devices
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, device)| {
            let slot = u32::try_from(index)
                .map(EventChainSlot)
                .map_err(|_| ExecutorError::EventChain(EventChainCursorError::UnknownSlot))?;
            Ok((device, slot))
        })
        .collect::<Result<BTreeMap<_, _>, ExecutorError>>()?;
    let mut members = Vec::with_capacity(contexts.len());
    let mut schedule = Vec::new();
    for (member_plan, context) in plan.conversations().iter().zip(contexts) {
        let member =
            preflight_device_revocation_plan_and_context(member_plan, context, revocation_id)?;
        for disposition in &member.context.welcome_dispositions {
            schedule.push(prepared_revocation_event_from_fanout(
                &disposition.event,
                &slots,
            )?);
        }
        for event in &member.context.events {
            schedule.push(prepared_revocation_event_from_fanout(event, &slots)?);
        }
        members.push(member);
    }
    let cursor = EventChainCursor::new(prelude_digest, devices, initial_tails, schedule)
        .map_err(ExecutorError::EventChain)?;
    let binding_digest = prepared_device_revocation_members_binding_digest(plan, &members, &cursor);
    Ok(PreparedDeviceRevocationBatchMembers {
        plan,
        members,
        cursor,
        binding_digest,
    })
}

pub(in crate::chat_protocol::state_machine::executor) fn prepared_device_revocation_members_binding_digest(
    plan: &DeviceRevocationBatchPersistencePlan,
    members: &[PreparedRevocationMember<'_>],
    cursor: &EventChainCursor,
) -> [u8; 32] {
    let mut digest = sha2::Sha256::new();
    digest.update(b"CATBIRD-CHAT-G6-PREPARED-MEMBERS\0");
    let plan_projection = format!("{plan:?}");
    digest.update((plan_projection.len() as u64).to_be_bytes());
    digest.update(plan_projection.as_bytes());
    digest.update((members.len() as u64).to_be_bytes());
    for member in members {
        let member_projection = format!("{member:?}");
        digest.update((member_projection.len() as u64).to_be_bytes());
        digest.update(member_projection.as_bytes());
    }
    digest.update(cursor.initial_binding_digest());
    digest.finalize().into()
}

pub(in crate::chat_protocol::state_machine::executor) fn prepared_revocation_event_from_fanout(
    event: &EventFanout,
    slots: &BTreeMap<DeviceIdentity, EventChainSlot>,
) -> Result<PreparedRevocationEvent, ExecutorError> {
    let recipients = event
        .recipients
        .iter()
        .map(|(device, entitlement, _)| {
            let slot = slots.get(device).copied().ok_or(ExecutorError::EventChain(
                EventChainCursorError::UnknownSlot,
            ))?;
            Ok(PreparedRevocationRecipient {
                slot,
                entitlement: *entitlement,
            })
        })
        .collect::<Result<Vec<_>, ExecutorError>>()?;
    PreparedRevocationEvent::new(
        event.event_id,
        event.event_kind,
        event.payload_bytes.clone(),
        recipients,
        event.outbox.clone(),
    )
    .map_err(ExecutorError::EventChain)
}

pub(in crate::chat_protocol::state_machine::executor) async fn apply_prepared_device_revocation_member(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    member: PreparedRevocationMember<'_>,
    event_cursor: &mut EventChainCursor,
) -> Result<AppliedTransition, ExecutorError> {
    let effects = member.plan.effects();
    transition::cas_conversation_head(
        transaction,
        &transition::ConversationHeadCas {
            conversation_id: member.conversation_id,
            expected_generation: member.generation,
            expected_state_version: member.state_version,
            expected_next_entry_seq: member.next_entry_seq,
            successor_generation: member.generation,
            successor_state_version: member.state_version,
            successor_next_entry_seq: member.next_entry_seq,
            close: None,
        },
    )
    .await?;
    write_revocation_bound_supersessions(
        transaction,
        effects,
        member.revocation_id,
        member.accepted_at,
    )
    .await?;
    for change in effects.welcome_changes() {
        let after = change
            .after()
            .expect("prepared revocation Welcome has an after image");
        let welcome_id = Uuid::from_bytes(*after.welcome_id());
        let disposition = member
            .context
            .welcome_dispositions
            .iter()
            .find(|input| input.welcome_id == welcome_id)
            .expect("prepared revocation has exact Welcome dispositions");
        let position = append_one_event_with_cursor(
            transaction,
            &member.context,
            &disposition.event,
            Some(event_cursor),
        )
        .await?;
        delivery::terminalize_welcome_delivery_for_supersession(
            transaction,
            welcome_id,
            &WelcomeDisposition::SupersededByRevocation {
                terminal_revocation_id: member.revocation_id,
            },
            member.context.applied_at,
            position,
        )
        .await?;
    }
    let event_positions =
        write_events_with_cursor(transaction, &member.context, Some(event_cursor), None).await?;
    Ok(AppliedTransition {
        allocated_seq: u64::try_from(member.next_entry_seq)
            .expect("prepared next entry sequence is nonnegative"),
        entry_id: member.revocation_id,
        event_positions,
        successor_coordinate: member.plan.successor_coordinate().copied(),
    })
}

/// Consume the state-machine half of the opaque capsule. The only errors
/// after the prefix are durable SQL/CAS failures or violations of the
/// already-frozen event-position cursor; no plan/context semantics are
/// revalidated here.
pub(crate) async fn apply_prepared_device_revocation_prefix<'plan>(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    prepared: PreparedDeviceRevocationBatchMembers<'plan>,
) -> Result<PrefixedDeviceRevocationBatchMembers<'plan>, ExecutorError> {
    if !prepared.binding_is_intact() {
        return Err(ExecutorError::InconsistentPlan(
            "prepared revocation member binding changed before the prefix",
        ));
    }
    let PreparedDeviceRevocationBatchMembers {
        plan,
        members,
        cursor,
        binding_digest: _,
    } = prepared;
    apply_device_revocation_batch_prefix(transaction, plan).await?;
    Ok(PrefixedDeviceRevocationBatchMembers { members, cursor })
}

pub(crate) async fn apply_prepared_device_revocation_members(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    prepared: PrefixedDeviceRevocationBatchMembers<'_>,
) -> Result<Vec<AppliedTransition>, ExecutorError> {
    let PrefixedDeviceRevocationBatchMembers {
        members,
        mut cursor,
    } = prepared;
    let mut applied = Vec::with_capacity(members.len());
    for member in members {
        applied
            .push(apply_prepared_device_revocation_member(transaction, member, &mut cursor).await?);
    }
    cursor.finish().map_err(ExecutorError::EventChain)?;
    Ok(applied)
}

/// Terminalize the target's OWN open recovery requests / active reservations /
/// reserved packages, all bound to `revocation_id` at `terminal_at`. Mirrors
/// `write_prior_bound_supersessions` but binds a REVOCATION (not a transition)
/// and drives packages Reserved->**Revoked** (not Reserved->Available). Returns
/// the per-family counts (welcomes left 0 — the caller adds them) so the caller
/// reconciles `own + superseded == total`. A delta that is NOT one of these
/// exact shapes is skipped here and caught by that reconciliation, never
/// silently dropped.
pub(in crate::chat_protocol::state_machine::executor) async fn write_revocation_bound_supersessions(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    effects: &TransitionEffects,
    revocation_id: Uuid,
    terminal_at: DateTime<Utc>,
) -> Result<FamilyCounts, ExecutorError> {
    let mut counts = FamilyCounts::default();
    for change in effects.recovery_request_changes() {
        if let (Some(before), Some(after)) = (change.before(), change.after()) {
            if before.status() == RecoveryRequestStatus::Open
                && after.status() == RecoveryRequestStatus::Superseded
            {
                transition::terminalize_leaf_recovery_request(
                    transaction,
                    Uuid::from_bytes(*after.request_id()),
                    &LeafRecoveryTermination::SupersededByRevocation {
                        terminal_revocation_id: revocation_id,
                        terminal_at,
                    },
                )
                .await?;
                counts.requests += 1;
            }
        }
    }
    for change in effects.reservation_changes() {
        if let (Some(before), Some(after)) = (change.before(), change.after()) {
            if before.status() == ReservationStatus::Active
                && after.status() == ReservationStatus::Released
            {
                transition::terminalize_reservation(
                    transaction,
                    Uuid::from_bytes(after.request_id),
                    &ReservationTermination::ReleasedByRevocation {
                        terminal_revocation_id: revocation_id,
                        terminal_at,
                    },
                )
                .await?;
                counts.reservations += 1;
            }
        }
    }
    for edge in effects.package_transitions() {
        if edge.from == PackageStatus::Reserved && edge.to == PackageStatus::Revoked {
            transition::cas_key_package_status(
                transaction,
                &edge.key_package_ref,
                RepoPackageStatus::Reserved,
                &PackageSuccessor::Revoke {
                    terminal_revocation_id: revocation_id,
                    terminal_at,
                },
            )
            .await?;
            counts.packages += 1;
        }
    }
    Ok(counts)
}

pub(in crate::chat_protocol::state_machine::executor) fn preflight_device_revocation_batch(
    plan: &DeviceRevocationBatchPersistencePlan,
) -> Result<Uuid, ExecutorError> {
    let revocation_id = Uuid::from_bytes(*plan.authority().revocation_id());
    let mut conversation_ids = BTreeSet::new();
    for conversation in plan.conversations() {
        if conversation.effects().kind() != PlanKind::DeviceRevocation {
            return Err(ExecutorError::InconsistentPlan(
                "device revocation batch contains a non-revocation conversation plan",
            ));
        }
        let conversation_evidence = match conversation.effects().authority() {
            Some(PlanAuthority::DeviceRevocation(evidence)) => evidence,
            _ => {
                return Err(ExecutorError::InconsistentPlan(
                    "device revocation batch conversation lacks revocation authority",
                ))
            }
        };
        if Uuid::from_bytes(*conversation_evidence.revocation_id()) != revocation_id {
            return Err(ExecutorError::InconsistentPlan(
                "device revocation batch conversation authority disagrees",
            ));
        }
        let conversation_id = Uuid::from_bytes(*conversation.state().coordinate.conversation_id());
        if !conversation_ids.insert(conversation_id) {
            return Err(ExecutorError::InconsistentPlan(
                "device revocation batch repeats a conversation",
            ));
        }
    }
    Ok(revocation_id)
}

/// Apply the immutable/device-global prefix of a planned revocation batch:
/// insert the revocation row, revoke the registration once, and revoke every
/// conversation-less package (available, or request-scope reserved). The
/// caller owns the open transaction and must next hydrate + apply each
/// conversation in the plan's canonical order.
///
/// This function never begins, commits, or rolls back a transaction. The
/// eventual handler owns the idempotency receipt required by the deferred
/// revocation mapping.
pub(in crate::chat_protocol::state_machine::executor) async fn apply_device_revocation_batch_prefix(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &DeviceRevocationBatchPersistencePlan,
) -> Result<(), ExecutorError> {
    let revocation_id = preflight_device_revocation_batch(plan)?;
    let evidence = plan.authority();
    let accepted_at = server_instant(evidence.accepted_at())?;
    let revocation_row = NewDeviceRevocation {
        revocation_id,
        actor_did: device_did(evidence.actor())?,
        actor_device_id: device_uuid(evidence.actor()),
        actor_key_id: URL_SAFE_NO_PAD.encode(evidence.actor_key_id()),
        actor_auth_generation: checked_i64(evidence.actor_auth_generation())?,
        target_did: device_did(evidence.target())?,
        target_device_id: device_uuid(evidence.target()),
        target_auth_generation: checked_i64(evidence.expected_target_auth_generation())?,
        accepted_request_bytes: evidence.signed_request_bytes().to_vec(),
        signing_transcript_bytes: evidence.signing_transcript_bytes().to_vec(),
        request_digest: evidence.request_digest().to_vec(),
        signature: evidence.signature().to_vec(),
        signed_at: server_instant(evidence.signed_at())?,
        accepted_at,
    };
    let target_cas = plan.target_cas();
    let registration_revoke = RegistrationRevoke {
        target_did: device_did(target_cas.target())?,
        target_device_id: device_uuid(target_cas.target()),
        expected_auth_generation: checked_i64(target_cas.expected_auth_generation())?,
        revocation_id,
        revoked_at: accepted_at,
    };

    insert_device_revocation(transaction, &revocation_row).await?;
    cas_registration_revoke(transaction, &registration_revoke).await?;
    // After the revocation row and the revoked registration both exist, so the
    // deferred composite FK into chat.device_revocations resolves at COMMIT.
    transition::terminalize_reset_requests_for_revoked_device(
        transaction,
        &registration_revoke.target_did,
        registration_revoke.target_device_id,
        revocation_id,
        accepted_at,
    )
    .await?;
    for binding in plan.revoked_packages() {
        if binding.conversation_id().is_none() {
            let expected = match binding.expected_status() {
                PackageStatus::Available => RepoPackageStatus::Available,
                // Request-scope held/retired package: no conversation owns it.
                PackageStatus::Reserved => RepoPackageStatus::Reserved,
                _ => {
                    return Err(ExecutorError::InconsistentPlan(
                        "conversation-less revoked package is neither available nor reserved",
                    ))
                }
            };
            transition::cas_key_package_status(
                transaction,
                binding.key_package_ref(),
                expected,
                &PackageSuccessor::Revoke {
                    terminal_revocation_id: revocation_id,
                    terminal_at: accepted_at,
                },
            )
            .await?;
        }
    }
    Ok(())
}

/// Compatibility seam for executor harnesses that construct contexts
/// directly. Production callers cannot prehydrate a revocation batch.
#[cfg(test)]
pub(crate) async fn apply_device_revocation_batch_unscoped_for_test(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &DeviceRevocationBatchPersistencePlan,
    conversation_ctxs: &[ExecutionContext],
) -> Result<Vec<AppliedTransition>, ExecutorError> {
    if plan.conversations().len() != conversation_ctxs.len() {
        return Err(ExecutorError::InconsistentPlan(
            "device revocation batch needs one execution context per conversation",
        ));
    }
    let revocation_id = preflight_device_revocation_batch(plan)?;
    for ctx in conversation_ctxs {
        let operation_id = require_execution_authority(PlanKind::DeviceRevocation, &ctx.authority)?;
        if operation_id != revocation_id {
            return Err(ExecutorError::MissingContext(
                "exact device revocation operation id",
            ));
        }
    }
    apply_device_revocation_batch_prefix(transaction, plan).await?;
    let mut applied = Vec::with_capacity(plan.conversations().len());
    for (conversation, ctx) in plan.conversations().iter().zip(conversation_ctxs) {
        applied.push(
            apply_conversation_persistence_plan_unscoped_for_test(transaction, conversation, ctx)
                .await?,
        );
    }
    Ok(applied)
}

