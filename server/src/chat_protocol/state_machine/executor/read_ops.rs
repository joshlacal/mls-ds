#![allow(unused_imports)]
use super::*;

pub(in crate::chat_protocol::state_machine::executor) fn principal_did(principal: &PrincipalId) -> Result<String, ExecutorError> {
    String::from_utf8(principal.as_bytes().to_vec()).map_err(|_| ExecutorError::ValueOutOfRange)
}

pub(in crate::chat_protocol::state_machine::executor) fn device_did(device: &DeviceIdentity) -> Result<String, ExecutorError> {
    principal_did(device.principal())
}

pub(in crate::chat_protocol::state_machine::executor) fn device_uuid(device: &DeviceIdentity) -> Uuid {
    Uuid::from_bytes(*device.device_id())
}

pub(in crate::chat_protocol::state_machine::executor) fn checked_i64(value: u64) -> Result<i64, ExecutorError> {
    i64::try_from(value).map_err(|_| ExecutorError::ValueOutOfRange)
}

pub(in crate::chat_protocol::state_machine::executor) fn require_execution_authority(
    kind: PlanKind,
    authority: &ExecutionAuthority,
) -> Result<Uuid, ExecutorError> {
    match (kind, authority) {
        (
            PlanKind::WelcomeExpiry | PlanKind::RecoveryExpiry | PlanKind::DeviceRevocation,
            ExecutionAuthority::Entryless { operation_id },
        ) => Ok(*operation_id),
        (
            PlanKind::WelcomeExpiry | PlanKind::RecoveryExpiry | PlanKind::DeviceRevocation,
            ExecutionAuthority::ControlEntry(_),
        ) => Err(ExecutorError::MissingContext(
            "entryless operation authority",
        )),
        (_, ExecutionAuthority::ControlEntry(entry)) => Ok(entry.entry_id),
        (_, ExecutionAuthority::Entryless { .. }) => {
            Err(ExecutorError::MissingContext("control-entry authority"))
        }
    }
}

pub(in crate::chat_protocol::state_machine::executor) fn server_instant(value: ServerTimestamp) -> Result<DateTime<Utc>, ExecutorError> {
    DateTime::<Utc>::from_timestamp_millis(value.unix_millis())
        .ok_or(ExecutorError::ValueOutOfRange)
}

pub(in crate::chat_protocol::state_machine::executor) fn repo_participant_status(status: ParticipantStatus) -> RepoParticipantStatus {
    match status {
        ParticipantStatus::Pending => RepoParticipantStatus::Pending,
        ParticipantStatus::Active => RepoParticipantStatus::Active,
    }
}

pub(in crate::chat_protocol::state_machine::executor) fn repo_participant_role(role: ParticipantRole) -> RepoParticipantRole {
    match role {
        ParticipantRole::Member => RepoParticipantRole::Member,
        ParticipantRole::Admin => RepoParticipantRole::Admin,
    }
}

pub(in crate::chat_protocol::state_machine::executor) fn old_role_provenance_matches(
    participant: &ParticipantRecord,
    conversation_kind: ConversationKind,
    expected_prior: &PublicGroupSnapshotCoordinate,
    current: &crate::chat_protocol::state_machine::TransitionEvidence,
) -> bool {
    let Some(old) = participant.role_producer.as_ref() else {
        return initial_participant_role(conversation_kind, participant) == Some(participant.role)
            && participant.invitation.as_ref().is_none_or(|invitation| {
                invitation_matches_participant(conversation_kind, participant, invitation)
            });
    };
    if !validate_transition_evidence(old)
        || old.seq >= current.seq
        || old.received_at > current.received_at
        || old.authority.as_ref().is_none_or(|authority| {
            authority.kind != SignedMutationKind::PolicyTransition
                || authority.control_conversation_id != Some(*expected_prior.conversation_id())
        })
        || !matches!(
            classify_role_producer(old.clone(), participant.principal(), participant.role),
            Ok(Some(classified)) if classified == *old
        )
    {
        return false;
    }
    matches!(old.body_binding.as_ref(),
            Some(TransitionBodyBinding::Policy { prior, next, .. })
                if coordinate_only_successor(prior).is_ok_and(|expected| &expected == next)
                    && coordinate_is_in_lineage(next, expected_prior))
}

/// Exhaustively classify the policy's complete participant delta before the
/// executor performs its first write. This is the write-side counterpart to
/// the unchanged aggregate role-provenance validator.
pub(in crate::chat_protocol::state_machine::executor) fn validate_policy_participant_writes(
    effects: &TransitionEffects,
    hydration: &ConversationStateHydration,
    ctx: &ExecutionContext,
    expected_prior: &PublicGroupSnapshotCoordinate,
    transition_id: Uuid,
) -> Result<(), ExecutorError> {
    let current = &hydration.producer;
    if !validate_transition_evidence(current)
        || current.transition_id() != transition_id.as_bytes()
        || current.outer_entry_fingerprint() != ctx.entry().outer_entry_fingerprint.as_slice()
    {
        return Err(ExecutorError::InconsistentPlan(
            "policy producer does not bind the current transition",
        ));
    }
    let body_changes = match current.body_binding.as_ref() {
        Some(TransitionBodyBinding::Policy {
            prior,
            next,
            participant_changes,
        }) if prior == expected_prior && next == &hydration.coordinate => participant_changes,
        _ => {
            return Err(ExecutorError::InconsistentPlan(
                "policy producer body does not bind the plan coordinates",
            ))
        }
    };
    if body_changes.len() != effects.participant_changes().len() {
        return Err(ExecutorError::InconsistentPlan(
            "policy body and participant delta counts differ",
        ));
    }

    let signed_authority = current.authority.as_ref();
    if let Some(authority) = signed_authority {
        if authority.kind != SignedMutationKind::PolicyTransition
            || authority.control_entry_id != Some(*ctx.entry().entry_id.as_bytes())
            || authority.control_conversation_id != Some(*hydration.coordinate.conversation_id())
            || authority.actor.principal().as_bytes() != ctx.actor.user_did.as_bytes()
            || Uuid::from_bytes(*authority.actor.device_id()) != ctx.actor.device_id
            || authority.signed_request_bytes != ctx.entry().signed_request_bytes
            || authority.request_digest.as_slice() != ctx.entry().request_digest
            || authority.signature.as_slice() != ctx.entry().signature
        {
            return Err(ExecutorError::InconsistentPlan(
                "policy signed authority does not bind execution context",
            ));
        }
    }

    let mut add_count = 0usize;
    let mut removed_principals = BTreeSet::new();
    for change in effects.participant_changes() {
        match (change.before(), change.after()) {
            (None, Some(after)) => {
                let matching_adds = body_changes
                    .iter()
                    .filter(|body| {
                        matches!(body, ManifestParticipantChange::Add(principal)
                                if principal == after.principal())
                    })
                    .count();
                let invitation = after.invitation.as_ref();
                if matching_adds != 1
                    || after.status != ParticipantStatus::Pending
                    || after.role != ParticipantRole::Member
                    || after.role_producer.is_some()
                    || after.acceptance.is_some()
                    || !invitation.is_some_and(|invitation| {
                        invitation.transition == *current
                            && invitation.inviter.principal().as_bytes()
                                == ctx.actor.user_did.as_bytes()
                            && Uuid::from_bytes(*invitation.inviter.device_id())
                                == ctx.actor.device_id
                    })
                {
                    return Err(ExecutorError::InconsistentPlan(
                        "policy Add participant delta is not exact",
                    ));
                }
                add_count += 1;
            }
            (Some(before), Some(after)) => {
                // A role change requires genuine signed current authority;
                // authority-less test evidence is never sufficient to update
                // an existing durable participant row.
                if signed_authority.is_none() {
                    return Err(ExecutorError::InconsistentPlan(
                        "policy ChangeRole lacks signed authority",
                    ));
                }
                let matching_role_changes = body_changes
                    .iter()
                    .filter(|body| {
                        matches!(body,
                                ManifestParticipantChange::ChangeRole(principal, role)
                                    if principal == after.principal() && *role == after.role)
                    })
                    .count();
                if matching_role_changes != 1
                    || before.principal != after.principal
                    || before.status != ParticipantStatus::Active
                    || after.status != ParticipantStatus::Active
                    || before.role == after.role
                    || before.invitation != after.invitation
                    || before.acceptance != after.acceptance
                    || !old_role_provenance_matches(before, hydration.kind, expected_prior, current)
                    || after.role_producer.as_ref() != Some(current)
                {
                    return Err(ExecutorError::InconsistentPlan(
                        "policy ChangeRole participant delta is not exact",
                    ));
                }
            }
            (Some(before), None) => {
                if signed_authority.is_none() {
                    return Err(ExecutorError::InconsistentPlan(
                        "policy Remove lacks signed authority",
                    ));
                }
                let matching_removes = body_changes
                    .iter()
                    .filter(|body| {
                        matches!(body, ManifestParticipantChange::Remove(principal)
                                if principal == before.principal())
                    })
                    .count();
                if matching_removes != 1 || !removed_principals.insert(before.principal().clone()) {
                    return Err(ExecutorError::InconsistentPlan(
                        "policy Remove participant delta is not exact",
                    ));
                }
            }
            (None, None) => {
                return Err(ExecutorError::InconsistentPlan(
                    "policy participant delta is empty",
                ))
            }
        }
    }
    if ctx.participant_period_ids.len() != add_count {
        return Err(ExecutorError::InconsistentPlan(
            "policy participant period ids do not match Add deltas",
        ));
    }
    if ctx.closing_participant_periods.len() != removed_principals.len()
        || ctx
            .closing_participant_periods
            .iter()
            .any(|(principal, _)| {
                !removed_principals.contains(principal)
                    || ctx
                        .closing_participant_periods
                        .iter()
                        .filter(|(candidate, _)| candidate == principal)
                        .count()
                        != 1
            })
    {
        return Err(ExecutorError::InconsistentPlan(
            "policy closing participant periods do not match Remove deltas",
        ));
    }
    Ok(())
}

pub(in crate::chat_protocol::state_machine::executor) async fn terminalize_policy_participants(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    effects: &TransitionEffects,
    ctx: &ExecutionContext,
    transition_id: Uuid,
    seq_i64: i64,
    applied_at: DateTime<Utc>,
) -> Result<(), ExecutorError> {
    for removed in effects.participant_changes().iter().filter_map(|change| {
        match (change.before(), change.after()) {
            (Some(before), None) => Some(before),
            _ => None,
        }
    }) {
        let participant_period_id = ctx
            .closing_participant_periods
            .iter()
            .find(|(principal, _)| principal == removed.principal())
            .map(|(_, period_id)| *period_id)
            .ok_or(ExecutorError::MissingContext(
                "closing participant period id for policy Remove",
            ))?;
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
    }
    Ok(())
}

/// Reject any non-empty effect family the executor does not (yet) persist,
/// so nothing is ever silently dropped. Called for every family this
/// composition path does not translate.
pub(in crate::chat_protocol::state_machine::executor) fn reject_if_present<T>(family: &'static str, changes: &[T]) -> Result<(), ExecutorError> {
    if changes.is_empty() {
        Ok(())
    } else {
        Err(ExecutorError::UnsupportedEffect(family))
    }
}

/// Make the `recovery_package_cas` binding load-bearing (E2b-6b review MINOR-1),
/// mirroring the invitation-quota discipline: production requires it to be
/// BIJECTIVE with `package_transitions` (`package_cas_bijection_valid`), and
/// `persistence_plan_for_test` now synthesizes it, so this asserts the
/// bijection rather than silently reading the witness. Additionally
/// cross-validates (MINOR-4) that the exact key-package ref the executor drives
/// through `cas_key_package_status` equals every semantic package edge's own
/// ref — a planner that disagreed would be a hard error, never a silent skip.
/// The `recovery_package_cas` <-> `package_transitions` bijection production
/// requires (`package_cas_bijection_valid`), made load-bearing (E2b-6b MINOR-1).
pub(in crate::chat_protocol::state_machine::executor) fn verify_recovery_package_bijection(effects: &TransitionEffects) -> Result<(), ExecutorError> {
    let edges = effects.package_transitions();
    let cas = effects.recovery_package_cas();
    if edges.len() != cas.len() {
        return Err(ExecutorError::InconsistentPlan(
            "recovery package CAS is not bijective with package_transitions",
        ));
    }
    for edge in edges {
        let unique = cas
            .iter()
            .filter(|binding| {
                binding.request_id == edge.request_id
                    && binding.key_package_ref == edge.key_package_ref
                    && binding.expected_status == edge.from
                    && binding.successor_status == edge.to
            })
            .count();
        if unique != 1 {
            return Err(ExecutorError::InconsistentPlan(
                "recovery package CAS binding missing/duplicated for a package edge",
            ));
        }
    }
    if cas.iter().any(|binding| {
        binding.authority_digest != recovery_package_cas_authority_digest(binding)
            || binding.locked_row_digest == [0; 32]
    }) {
        return Err(ExecutorError::InconsistentPlan(
            "recovery package CAS authority seal or locked-row digest drift",
        ));
    }
    Ok(())
}

/// Bijection + the OWN package edge's driven-ref (MINOR-4) and direction
/// (MINOR-2) — for an arm that drives exactly ONE own package edge. Any OTHER
/// edges (prior-bound `Reserved->Available` supersessions) are validated by
/// `write_prior_bound_supersessions`; here only the own edge is direction-checked.
pub(in crate::chat_protocol::state_machine::executor) fn verify_recovery_package_consistency(
    effects: &TransitionEffects,
    driven_key_package_ref: &[u8; 32],
    expected_from: PackageStatus,
    expected_to: PackageStatus,
) -> Result<(), ExecutorError> {
    verify_recovery_package_bijection(effects)?;
    let own = effects
        .package_transitions()
        .iter()
        .filter(|edge| edge.key_package_ref == *driven_key_package_ref)
        .count();
    if own != 1 {
        return Err(ExecutorError::InconsistentPlan(
            "exactly one package edge must match the executor's driven ref",
        ));
    }
    let own_edge = effects
        .package_transitions()
        .iter()
        .find(|edge| edge.key_package_ref == *driven_key_package_ref)
        .expect("own edge exists");
    if own_edge.from != expected_from || own_edge.to != expected_to {
        return Err(ExecutorError::InconsistentPlan(
            "the driven package edge's direction disagrees with the executor's CAS",
        ));
    }
    Ok(())
}

pub(in crate::chat_protocol::state_machine::executor) fn terminal_is_exact_transition(
    terminal: &Option<WorkTerminalEvidence>,
    producer: &crate::chat_protocol::state_machine::TransitionEvidence,
) -> bool {
    matches!(terminal, Some(WorkTerminalEvidence::Transition(value)) if value == producer)
}

pub(in crate::chat_protocol::state_machine::executor) fn terminal_is_exact_due_expiry(
    terminal: &Option<WorkTerminalEvidence>,
    expires_at: ServerTimestamp,
    applied_at: DateTime<Utc>,
) -> bool {
    matches!(terminal, Some(WorkTerminalEvidence::Expiry(value)) if *value == expires_at)
        && server_instant(expires_at).is_ok_and(|expiry| applied_at >= expiry)
}

/// Which reset / leave / Welcome edge, if any, the calling arm terminalizes
/// itself. Everything else in those three families is prior-bound work the
/// arm's coordinate change retires.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(in crate::chat_protocol::state_machine::executor) enum OwnStalingKind {
    /// The arm terminalizes none of these families itself.
    None,
    /// `apply_leave_fulfillment` fulfills its requester's leave
    /// (`Pending -> Fulfilled`); per ADR-019 Erratum 01 the same `leaveCommit`
    /// MAY additionally stale other members' prior-bound pending leaves.
    LeaveFulfillment,
    /// `apply_reset_activation` consumes the exact signed reset request it
    /// activates (`Pending -> Consumed`). Every other prior-bound reset / leave /
    /// Welcome in the plan is work its generation retirement retires. The own
    /// edge's cardinality and its binding to the signed request id stay
    /// `preflight_reset_activation`'s own pre-CAS check.
    ResetActivation,
}

/// The single prior-bound reset / leave / Welcome classifier, shared by the
/// coordinate-changing executor arms and called by each strictly BEFORE its own
/// first head compare-and-set. Returns the terminalized Welcome ids so a caller
/// can prove its disposition bijection against them.
///
/// Extracted from `preflight_metadata_transition`, the only arm that proved
/// these shapes. The others relied on `reconcile_coordinate_change_families`,
/// but that fence runs AFTER the writers and only counts what they consumed —
/// and both `write_welcome_supersessions` and `write_prior_bound_staling`
/// accept a `Pending->Expired` delta. An incoherent expiry (transition evidence
/// carried on an `Expired` status, or an expiry not yet due at `applied_at`)
/// therefore reconciled cleanly and COMMITTED, terminalizing a live Welcome
/// delivery / reset / leave request that was never actually due.
///
/// Derives every comparand from `plan` and `ctx` — the prior coordinate from
/// the head CAS, the producer from the hydrated successor state. `own_kind`
/// selects the arm's own edge by exact typed shape, never by a caller-supplied
/// id or predicate; that edge's cardinality stays the arm's own pre-CAS check.
pub(in crate::chat_protocol::state_machine::executor) fn classify_prior_bound_staling(
    plan: &ConversationPersistencePlan,
    ctx: &ExecutionContext,
    own_kind: OwnStalingKind,
) -> Result<BTreeSet<[u8; 16]>, ExecutorError> {
    let effects = plan.effects();
    let head = effects.head_cas().ok_or(ExecutorError::InconsistentPlan(
        "prior-bound staling needs a head CAS binding",
    ))?;
    let prior = head
        .expected_prior()
        .ok_or(ExecutorError::InconsistentPlan(
            "prior-bound staling needs an expected prior",
        ))?;
    let producer = &plan.state().producer;

    for change in effects.reset_request_changes() {
        let (Some(before), Some(after)) = (change.before(), change.after()) else {
            return Err(ExecutorError::InconsistentPlan(
                "prior-bound reset request delta is not terminal",
            ));
        };
        // The arm's own consumption edge binds the exact signed request id, so it
        // is not a staling. Select it out here exactly as the leave loop below
        // selects out a fulfillment; its cardinality and signed-id binding stay
        // `preflight_reset_activation`'s own pre-CAS check.
        if own_kind == OwnStalingKind::ResetActivation
            && after.status == ResetRequestStatus::Consumed
        {
            continue;
        }
        let exact_terminal = match after.status {
            ResetRequestStatus::Stale => terminal_is_exact_transition(&after.terminal, producer),
            ResetRequestStatus::Expired => {
                terminal_is_exact_due_expiry(&after.terminal, after.expires_at, ctx.applied_at)
            }
            _ => false,
        };
        if !reset_request_identity_is_unchanged(before, after)
            || before.status != ResetRequestStatus::Pending
            || before.bound_coordinate != *prior
            || !exact_terminal
        {
            return Err(ExecutorError::InconsistentPlan(
                "prior-bound reset request staling drifted",
            ));
        }
    }

    for change in effects.leave_request_changes() {
        let (Some(before), Some(after)) = (change.before(), change.after()) else {
            return Err(ExecutorError::InconsistentPlan(
                "prior-bound leave request delta is not terminal",
            ));
        };
        // The arm's own fulfillment edge binds a fulfilled participant, so it is
        // neither identity-unchanged nor a staling. Select it out here; its
        // cardinality and exact shape stay `apply_leave_fulfillment`'s own
        // pre-CAS partition (exactly one Fulfilled, never also staled).
        if own_kind == OwnStalingKind::LeaveFulfillment
            && after.status == LeaveRequestStatus::Fulfilled
        {
            continue;
        }
        let exact_terminal = match after.status {
            LeaveRequestStatus::Stale => terminal_is_exact_transition(&after.terminal, producer),
            LeaveRequestStatus::Expired => {
                terminal_is_exact_due_expiry(&after.terminal, after.expires_at, ctx.applied_at)
            }
            _ => false,
        };
        if !leave_request_identity_is_unchanged(before, after)
            || before.status != LeaveRequestStatus::Pending
            || before.bound_coordinate != *prior
            || !exact_terminal
        {
            return Err(ExecutorError::InconsistentPlan(
                "prior-bound leave request staling drifted",
            ));
        }
    }
    let mut welcome_ids = BTreeSet::new();
    for change in effects.welcome_changes() {
        let (Some(before), Some(after)) = (change.before(), change.after()) else {
            return Err(ExecutorError::InconsistentPlan(
                "prior-bound Welcome delta is not terminal",
            ));
        };
        let exact_terminal = match after.status {
            WelcomeStatus::Superseded => terminal_is_exact_transition(&after.terminal, producer),
            WelcomeStatus::Expired => {
                terminal_is_exact_due_expiry(&after.terminal, after.expires_at, ctx.applied_at)
            }
            _ => false,
        };
        if !welcome_identity_is_unchanged(before, after)
            || before.status != WelcomeStatus::Pending
            || before.coordinate != *prior
            || !exact_terminal
            || !welcome_ids.insert(after.welcome_id)
        {
            return Err(ExecutorError::InconsistentPlan(
                "prior-bound Welcome supersession drifted",
            ));
        }
    }
    Ok(welcome_ids)
}
