#![allow(unused_imports)]
use super::*;

/// Assemble a `ConversationPersistencePlan` from a pure-planner `PlannedTransition`
/// plus a synthesized head CAS, mirroring what `into_persistence_plan` produces in
/// production (which is `#[cfg(not(test))]` and unreachable from the test build).
///
/// For a `Creation`/`Policy` plan this ALSO synthesizes the
/// `InvitationQuotaCasBinding` that `into_persistence_plan` (state_machine.rs
/// `invitation_quota_valid`) requires every such plan to carry — modeled on
/// `bind_invitation_quota_cas`: the sorted newly-pending recipients, the inviter
/// (the sole/first active admin), the prior/successor live-pending counts, a
/// generous limit, and a non-zero locked-row digest bound to the head lock. Test
/// plans therefore mirror real plans, so the executor's invitation-quota consume
/// arm is exercised (removing it now fails the suite).
#[cfg(test)]
pub(crate) fn persistence_plan_for_test(
    transition: PlannedTransition,
    head_cas: ConversationHeadCasBinding,
) -> ConversationPersistencePlan {
    let mut effects = transition.effects;
    if matches!(effects.kind, PlanKind::Creation | PlanKind::Policy) {
        let mut new_recipients: Vec<PrincipalId> = effects
            .participant_changes
            .iter()
            .filter_map(|change| match (change.before(), change.after()) {
                (None, Some(after)) if after.status() == ParticipantStatus::Pending => {
                    Some(after.principal().clone())
                }
                _ => None,
            })
            .collect();
        new_recipients.sort();
        let expected_inviter_recent_24h = 0;
        let successor_inviter_recent_24h = new_recipients.len() as u64;
        let inviter = transition
            .state
            .participants()
            .iter()
            .find(|participant| {
                participant.status() == ParticipantStatus::Active
                    && participant.role() == ParticipantRole::Admin
            })
            .map(|participant| participant.principal().clone())
            .unwrap_or_else(|| {
                new_recipients
                    .first()
                    .cloned()
                    .unwrap_or_else(dummy_principal)
            });
        let recipient_facts = new_recipients
            .iter()
            .cloned()
            .map(|recipient| InvitationQuotaRecipientCasFact {
                recipient,
                expected_pair_live: 0,
                successor_pair_live: 1,
                pair_limit: 5,
                expected_recipient_live: 0,
                successor_recipient_live: 1,
                recipient_limit: 100,
            })
            .collect();
        effects.invitation_quota_cas = Some(InvitationQuotaCasBinding {
            transaction_id: head_cas.transaction_id.clone(),
            inviter,
            new_recipients,
            expected_inviter_recent_24h,
            successor_inviter_recent_24h,
            inviter_limit: 100,
            recipient_facts,
            locked_at: head_cas.locked_at,
            locked_row_digest: [1u8; 32],
        });
    }
    // E2b-6b MINOR-1: synthesize the recovery-package CAS bijection production
    // requires for any plan carrying `package_transitions` (mirroring
    // `bind_recovery_package_cas`), so the executor's now-load-bearing bijection
    // assert is genuinely exercised. Only request_id / key_package_ref / from / to
    // are read by that assert (and by production's `package_cas_bijection_valid`);
    // the remaining authority columns are provenance placeholders here.
    if effects.recovery_package_cas.is_empty() && !effects.package_transitions.is_empty() {
        for edge in effects.package_transitions.clone() {
            if let Some(request) = effects
                .recovery_request_changes
                .iter()
                .filter_map(|change| change.after())
                .find(|request| request.request_id == edge.request_id)
            {
                // The shared prior-bound classifier proves the FULL binding identity, so
                // these can no longer be placeholders: derive the origin key id and auth
                // generation from the request exactly as production does. A zeroed
                // `target_key_id` is what the durable CAS rejects via `owner_key_id = $6`.
                //
                // The Acceptance branch is a hard failure, never a fallback. Production
                // mints the signing authority unconditionally
                // (`transition_from_control`), and both the hydration fence and
                // `reserved_package_cas_for_request` refuse an acceptance-origin request
                // without it, so a fixture that lacks one is simply invalid. Substituting
                // a zeroed key id here only hid that: it produced a binding the executor's
                // prior-bound classifier rejects with "acceptance has no signing
                // authority" and, had it got that far, a durable CAS that matches no row.
                let (origin_key_id, origin_auth_generation) = match &request.origin {
                    RecoveryOriginEvidence::Acceptance(value) => {
                        let authority = value.authority.as_ref().expect(
                            "acceptance-origin recovery request must carry its signing \
                             authority; production mints it unconditionally",
                        );
                        (authority.key_id, authority.auth_generation)
                    }
                    RecoveryOriginEvidence::Request(value) => (value.key_id, value.auth_generation),
                };
                // Production reads this from the LOCKED key-package row
                // (`*guard.wrapper_sha256()`), which it separately proves equal to the
                // wrapper the acceptance signed. An acceptance-origin request therefore
                // carries the digest out of its own signed body; a request-origin one has
                // no such comparand in the plan and keeps the existing placeholder.
                let key_package_wrapper_sha256 = match &request.origin {
                    RecoveryOriginEvidence::Acceptance(value) => {
                        match value.body_binding.as_ref() {
                            Some(TransitionBodyBinding::Acceptance { recovery, .. }) => {
                                recovery.key_package_wrapper_sha256
                            }
                            _ => [0u8; 32],
                        }
                    }
                    RecoveryOriginEvidence::Request(_) => [0u8; 32],
                };
                effects.recovery_package_cas.push({
                    let mut binding = RecoveryPackageCasBinding {
                        transaction_id: head_cas.transaction_id.clone(),
                        conversation_id: *request.bound_coordinate.conversation_id(),
                        request_id: edge.request_id,
                        target: request.target.clone(),
                        target_key_id: origin_key_id,
                        target_auth_generation: origin_auth_generation,
                        bound_coordinate: request.bound_coordinate,
                        key_package_ref: edge.key_package_ref,
                        key_package_wrapper_sha256,
                        package_not_after: effects
                            .reservation_changes
                            .iter()
                            .filter_map(|change| change.after())
                            .find(|reservation| {
                                reservation.request_id == edge.request_id
                                    && reservation.key_package_ref == edge.key_package_ref
                            })
                            .map(|reservation| reservation.package_not_after)
                            .unwrap_or(request.expires_at),
                        claimed_at: request.received_at,
                        expected_status: edge.from,
                        successor_status: edge.to,
                        // Per-binding, never a constant. Production's
                        // `recovery_package_guard_digest` (repository/core.rs:3322-3336)
                        // covers the key package ref, its status, its use kind and
                        // `claimed_at`, so two guards for distinct refs necessarily carry
                        // distinct digests. Synthesizing one shared constant made every
                        // multi-family test plan violate that, which check 8-DiD rejects as
                        // "distinct key package refs share one locked row digest" the moment
                        // a plan carries two recovery families -- as acceptance does, pairing
                        // a prior open request with its own new one.
                        //
                        // Only uniqueness and non-zero-ness are load-bearing here: the
                        // durable release CAS binds 19 parameters and this digest is not
                        // among them (repository/transition.rs:1711-1729); its sole durable
                        // use is the non-zero rejection at :1633. So this needs to be a
                        // faithful *shape*, not a value matching any stored row.
                        locked_row_digest: {
                            let mut digest = Sha256::new();
                            digest.update(b"CATBIRD-CHAT-TEST-LOCKED-RECOVERY-ROW\0");
                            digest.update(edge.key_package_ref);
                            digest.update([edge.from as u8, edge.to as u8]);
                            digest.update(request.received_at.unix_millis().to_be_bytes());
                            digest.finalize().into()
                        },
                        authority_digest: [0u8; 32],
                    };
                    binding.authority_digest = recovery_package_cas_authority_digest(&binding);
                    binding
                });
            }
        }
    }
    // Synthesize the welcome-disposition CAS binding production requires for a
    // welcome terminalization edge (expiry / acknowledge / reject), mirroring
    // `welcome_cas_from_guard`. The executor consumes it as a LOAD-BEARING witness
    // (it must match the welcome_change), and production carries it via
    // `bind_welcome_cas`, so synthesizing it here keeps the test plan
    // production-shaped. Only the identity/coordinate/status columns are read by the
    // executor; the locked-row digest is a provenance placeholder.
    //
    // ONLY for those three plan kinds. `into_persistence_plan`'s
    // `welcome_authority_valid` requires `welcome_cas.is_none()` on every other kind,
    // so a coordinate-changing commit NEVER carries one — including when its
    // prior-bound welcome delta is a due `Pending->Expired`. Synthesizing one there
    // built a plan production cannot produce, and every commit arm correctly rejected
    // it as `UnsupportedEffect(".. welcome .. CAS")` — which made the whole
    // prior-bound expiry path untestable through this seam.
    if effects.welcome_cas.is_none()
        && matches!(
            effects.kind,
            PlanKind::WelcomeExpiry | PlanKind::WelcomeAcknowledgement | PlanKind::WelcomeRejection
        )
    {
        if let Some((before, after)) = effects.welcome_changes.iter().find_map(|change| {
            match (change.before.as_ref(), change.after.as_ref()) {
                (Some(before), Some(after))
                    if before.status == WelcomeStatus::Pending
                        && matches!(
                            after.status,
                            WelcomeStatus::Expired
                                | WelcomeStatus::Acknowledged
                                | WelcomeStatus::Rejected
                        ) =>
                {
                    Some((before, after))
                }
                _ => None,
            }
        }) {
            let mut binding = WelcomeCasBinding {
                transaction_id: head_cas.transaction_id.clone(),
                conversation_id: *after.coordinate.conversation_id(),
                welcome_id: after.welcome_id,
                recipient: after.recipient.clone(),
                transition_seq: after.transition_seq,
                coordinate: after.coordinate,
                recovery_request_id: after.recovery_request_id,
                key_package_ref: after.key_package_ref,
                opaque_welcome_sha256: after.sha256,
                expires_at: after.expires_at,
                expected_status: before.status,
                successor_status: after.status,
                locked_at: head_cas.locked_at,
                locked_row_digest: [1u8; 32],
                seal: [0; 32],
            };
            binding.seal = welcome_cas_seal(&binding);
            effects.welcome_cas = Some(binding);
        }
    }
    effects.head_cas = Some(head_cas);
    ConversationPersistencePlan {
        expected_prior: transition.expected_prior,
        retired_coordinate: transition.retired_coordinate,
        successor_coordinate: transition.successor_coordinate,
        state: ConversationStateHydration::from_state(transition.state),
        effects,
    }
}

/// A syntactically-valid placeholder principal for the (unreachable) case where a
/// Creation/Policy plan has neither an active admin nor a pending recipient.
#[cfg(test)]
pub(in crate::chat_protocol::state_machine) fn dummy_principal() -> PrincipalId {
    PrincipalId::new(b"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".to_vec()).expect("valid placeholder DID")
}

#[cfg(test)]
pub(crate) enum PolicyPlanMutation {
    Principal,
    Status,
    RoleProducer,
    OldRoleProducer(TransitionEvidence),
    DuplicateDelta,
    Remove,
}

#[cfg(test)]
impl ConversationPersistencePlan {
    /// G6 test-only bridge: integration harnesses compile the pure planners,
    /// while production binds `effects.authority` by consuming repository lock
    /// guards. This additive seam lets genuine, cryptographically reverified
    /// authority exercise the production ExecutionContext facade without
    /// widening or changing any production constructor.
    pub(crate) fn with_execution_context_authority_for_test(
        mut self,
        authority: PlanAuthority,
    ) -> Self {
        self.effects.authority = Some(authority);
        self
    }

    pub(crate) fn with_policy_mutation_for_test(mut self, mutation: PolicyPlanMutation) -> Self {
        if matches!(&mutation, PolicyPlanMutation::DuplicateDelta) {
            self.effects
                .participant_changes
                .push(self.effects.participant_changes[0].clone());
            return self;
        }
        let change = self.effects.participant_changes.first_mut().unwrap();
        match mutation {
            PolicyPlanMutation::Principal => {
                change.after.as_mut().unwrap().principal =
                    PrincipalId::new(b"did:plc:zzzzzzzzzzzzzzzzzzzzzzzz".to_vec()).unwrap();
            }
            PolicyPlanMutation::Status => {
                change.after.as_mut().unwrap().status = ParticipantStatus::Pending;
            }
            PolicyPlanMutation::RoleProducer => {
                change
                    .after
                    .as_mut()
                    .unwrap()
                    .role_producer
                    .as_mut()
                    .unwrap()
                    .transition_id[0] ^= 0x01;
            }
            PolicyPlanMutation::OldRoleProducer(producer) => {
                change.before.as_mut().unwrap().role_producer = Some(producer);
            }
            PolicyPlanMutation::DuplicateDelta => unreachable!(),
            PolicyPlanMutation::Remove => change.after = None,
        }
        self
    }

    pub(crate) fn with_generic_remove_add_for_test(mut self) -> Self {
        if let Some(before) = self
            .effects
            .leaf_changes
            .iter()
            .find_map(|change| change.before.clone())
        {
            self.effects.leaf_changes.push(StateChange {
                before: None,
                after: Some(before),
            });
        }
        self
    }

    pub(crate) fn with_generic_remove_empty_leaf_delta_for_test(mut self) -> Self {
        self.effects.leaf_changes.push(StateChange {
            before: None,
            after: None,
        });
        self
    }

    pub(crate) fn with_generic_remove_interval_dropped_for_test(mut self) -> Self {
        self.effects.interval_changes.clear();
        self
    }

    pub(crate) fn with_generic_remove_leaf_dropped_for_test(mut self) -> Self {
        self.effects
            .leaf_changes
            .retain(|change| change.after.is_some());
        self
    }

    pub(crate) fn with_generic_remove_interval_duplicated_for_test(mut self) -> Self {
        if let Some(change) = self.effects.interval_changes.first().cloned() {
            self.effects.interval_changes.push(change);
        }
        self
    }

    pub(crate) fn with_generic_remove_close_kind_corrupted_for_test(mut self) -> Self {
        if let Some(end) = self
            .effects
            .interval_changes
            .first_mut()
            .and_then(|change| change.after.as_mut())
            .and_then(|interval| interval.end.as_mut())
        {
            end.kind = CloseKind::Replace;
        }
        self
    }

    pub(crate) fn with_generic_remove_close_fingerprint_corrupted_for_test(mut self) -> Self {
        if let Some(end) = self
            .effects
            .interval_changes
            .first_mut()
            .and_then(|change| change.after.as_mut())
            .and_then(|interval| interval.end.as_mut())
        {
            end.evidence.outer_entry_fingerprint[0] ^= 0xFF;
        }
        self
    }

    pub(crate) fn with_generic_remove_interval_coordinate_corrupted_for_test(mut self) -> Self {
        if let Some(after) = self
            .effects
            .interval_changes
            .first_mut()
            .and_then(|change| change.after.as_mut())
        {
            let coordinate = after.opening_context;
            after.opening_context = PublicGroupSnapshotCoordinate::new(
                *coordinate.conversation_id(),
                coordinate.generation(),
                coordinate.state_version() + 1,
                *coordinate.group_id(),
                coordinate.epoch(),
                *coordinate.group_context_hash(),
                *coordinate.confirmation_tag(),
                coordinate.lifecycle(),
            );
        }
        self
    }

    /// Drop the invitation-quota CAS binding, producing a plan production would
    /// reject as `InvalidHydrationAuthority` and the executor rejects as
    /// `InconsistentPlan`. Used to make the executor's invitation-quota consume
    /// arm an executable contract (removing the arm fails the negative test).
    pub(crate) fn with_invitation_quota_cleared_for_test(mut self) -> Self {
        self.effects.invitation_quota_cas = None;
        self
    }

    /// Drop the recovery-package CAS binding, desyncing it from
    /// `package_transitions` — production requires the two to be bijective
    /// (`package_cas_bijection_valid`) and the executor's
    /// `verify_recovery_package_consistency` rejects the desync as
    /// `InconsistentPlan`. Makes that (otherwise-always-bijective-by-construction)
    /// assert an executable contract: removing the assert fails the negative test.
    pub(crate) fn with_recovery_package_cas_cleared_for_test(mut self) -> Self {
        self.effects.recovery_package_cas.clear();
        self
    }

    /// Bind the REAL durable wrapper digest onto every synthesized recovery-package
    /// CAS binding, re-sealing each authority digest.
    ///
    /// `persistence_plan_for_test` cannot derive this: only an `Acceptance` origin
    /// carries wrapper material, so a `Request`-origin plan leaves it `[0u8; 32]`.
    /// The durable release pins `kp.wrapper_sha256 = $3`, so a fixture that seeds a
    /// real key package must hand its digest back to the plan or the compare-and-set
    /// conflicts.
    pub(crate) fn with_recovery_package_wrapper_sha256_for_test(
        mut self,
        wrapper_sha256: [u8; 32],
    ) -> Self {
        for binding in &mut self.effects.recovery_package_cas {
            binding.key_package_wrapper_sha256 = wrapper_sha256;
            binding.authority_digest = [0u8; 32];
            binding.authority_digest = recovery_package_cas_authority_digest(binding);
        }
        self
    }

    /// Drift one immutable, non-semantic field of the exact reserved-package
    /// guard while preserving request/ref/status bijection. Reset must reject
    /// this before its head CAS; a verifier that consults only PackageTransition
    /// summaries will incorrectly accept it.
    pub(crate) fn with_reset_recovery_package_wrapper_digest_corrupted_for_test(mut self) -> Self {
        if let Some(binding) = self.effects.recovery_package_cas.first_mut() {
            binding.key_package_wrapper_sha256[0] ^= 0x40;
        }
        self
    }

    /// Inject an EXTRA recovery-request delta that is neither the arm's own edge
    /// (`Open->Fulfilled`) nor a valid supersession (`Open->Superseded`): an
    /// `Open->Expired` change cloned from the plan's first request. A
    /// coordinate-changing arm must REJECT it (`reconcile_coordinate_change_families`),
    /// never silently drop it — removing that reconciliation fails the negative test.
    pub(crate) fn with_extra_untracked_recovery_request_for_test(mut self) -> Self {
        if let Some(open) = self
            .effects
            .recovery_request_changes
            .first()
            .and_then(|change| change.before.clone())
        {
            let mut expired = open.clone();
            expired.status = RecoveryRequestStatus::Expired;
            self.effects.recovery_request_changes.push(StateChange {
                before: Some(open),
                after: Some(expired),
            });
        }
        self
    }

    /// Corrupt the plan's first welcome supersession into a non-supersession shape
    /// (`Pending->Superseded` -> `Pending->Expired`). `write_welcome_supersessions`
    /// SKIPS it, so a coordinate-changing arm must catch it in the reconciliation
    /// rather than silently leave the durable Welcome delivery un-terminalized —
    /// removing the welcome reconciliation fails the negative test.
    pub(crate) fn with_welcome_supersession_corrupted_for_test(mut self) -> Self {
        if let Some(after) = self
            .effects
            .welcome_changes
            .first_mut()
            .and_then(|change| change.after.as_mut())
        {
            after.status = WelcomeStatus::Expired;
        }
        self
    }

    /// Corrupt one field of the Reset arm's closed-interval transition
    /// evidence. The plan remains cardinality- and identity-coherent, so only
    /// an exhaustive pre-CAS validation of the actual interval changes can
    /// reject it before any durable writer runs.
    pub(crate) fn with_reset_interval_evidence_corrupted_for_test(mut self) -> Self {
        if let Some(end) = self
            .effects
            .interval_changes
            .iter_mut()
            .find_map(|change| change.after.as_mut()?.end.as_mut())
        {
            end.evidence.outer_entry_fingerprint[0] ^= 0x80;
        }
        self
    }

    /// Corrupt the plan's first reset-request staling into a non-staling shape
    /// (`Pending->Stale` -> `Pending->Expired`). `write_prior_bound_staling` SKIPS
    /// it (it consumes only the exact `Pending->Stale` edge), so a coordinate-
    /// advancing arm must catch it in `reconcile_coordinate_change_families` rather
    /// than silently leave the durable reset request un-terminalized — removing the
    /// reset-family reconciliation fails the negative test.
    pub(crate) fn with_reset_staling_corrupted_for_test(mut self) -> Self {
        if let Some(after) = self
            .effects
            .reset_request_changes
            .first_mut()
            .and_then(|change| change.after.as_mut())
        {
            after.status = ResetRequestStatus::Expired;
        }
        self
    }

    /// Corrupt the plan's first leave-request staling into a non-staling shape
    /// (`Pending->Stale` -> `Pending->Expired`), exercising the leave-family half of
    /// the silent-drop guard exactly as `with_reset_staling_corrupted_for_test` does
    /// for the reset family.
    pub(crate) fn with_leave_staling_corrupted_for_test(mut self) -> Self {
        if let Some(after) = self
            .effects
            .leave_request_changes
            .first_mut()
            .and_then(|change| change.after.as_mut())
        {
            after.status = LeaveRequestStatus::Expired;
        }
        self
    }

    /// Corrupt the `welcome_cas` binding so it disagrees with the `welcome_changes`
    /// delta (flip a byte of its bound welcome id). The welcome-disposition arms
    /// validate the binding LOAD-BEARING against the delta (welcome id / recipient /
    /// coordinate / expiry / direction), so a corrupted binding must be a hard
    /// `InconsistentPlan` — removing that validation fails the negative test. Since
    /// `persistence_plan_for_test` always synthesizes a MATCHING binding, this is the
    /// only way to drive the validation red.
    pub(crate) fn with_welcome_cas_corrupted_for_test(mut self) -> Self {
        if let Some(binding) = self.effects.welcome_cas.as_mut() {
            binding.welcome_id[0] ^= 0xFF;
        }
        self
    }

    /// Per-family CAS drift (brief L227-228). Each helper mutates EXACTLY ONE
    /// nonsemantic `WelcomeCasBinding` authority family while leaving the
    /// stored seal untouched, so a recomputed `welcome_cas_seal` over the
    /// mutated binding disagrees with the retained seal. The executor prewrite
    /// fence `!binding.verify_seal()` catches the drift BEFORE the head CAS
    /// verify or event insert. Without that fence, the corrupted binding would
    /// first surface at the delivery `terminalize_welcome_delivery` SQL
    /// predicate (rows_affected != 1) AFTER the event/outbox row is appended,
    /// leaving a stale partial graph. These seams are `#[cfg(test)]`-gated and
    /// never reach production.
    pub(crate) fn with_welcome_cas_opaque_digest_drift_for_test(mut self) -> Self {
        if let Some(binding) = self.effects.welcome_cas.as_mut() {
            binding.opaque_welcome_sha256[0] ^= 0xFF;
        }
        self
    }

    pub(crate) fn with_welcome_cas_expiry_drift_for_test(mut self) -> Self {
        if let Some(binding) = self.effects.welcome_cas.as_mut() {
            binding.expires_at.0 = binding.expires_at.0.wrapping_add(1);
        }
        self
    }

    pub(crate) fn with_welcome_cas_locked_instant_drift_for_test(mut self) -> Self {
        if let Some(binding) = self.effects.welcome_cas.as_mut() {
            binding.locked_at.0 = binding.locked_at.0.wrapping_add(1);
        }
        self
    }

    pub(crate) fn with_welcome_cas_locked_row_digest_drift_for_test(mut self) -> Self {
        if let Some(binding) = self.effects.welcome_cas.as_mut() {
            binding.locked_row_digest[0] ^= 0xFF;
        }
        self
    }

    /// Duplicate-recovery-work family drift (brief L231): append a SECOND
    /// `Pending -> Rejected` welcome_change. The executor prewrite fence
    /// `welcome_changes().len() != 1 -> InconsistentPlan` rejects the plan
    /// before any disposition or recovery-work row is written; without that
    /// fence, `apply_welcome_response` would only ever consume the FIRST
    /// welcome_change and silently drop the second (and its recovery work),
    /// persisting a partial graph. `#[cfg(test)]`-gated only.
    pub(crate) fn with_welcome_rejection_duplicate_for_test(mut self) -> Self {
        if let Some(duplicate) = self
            .effects
            .welcome_changes
            .iter()
            .find(|change| matches!((change.before(), change.after()), (Some(b), Some(a)) if b.status() == WelcomeStatus::Pending && a.status() == WelcomeStatus::Rejected))
            .cloned()
        {
            self.effects.welcome_changes.push(duplicate);
        }
        self
    }

    /// ADR-019 Erratum 01 desync (leave-fulfillment): append a second leave delta
    /// that STALES the very request the plan FULFILLS (same `request_id`), cloning
    /// its Pending predecessor and flipping the successor to `Stale`. `apply_leave_
    /// fulfillment`'s partition check must reject this as `InconsistentPlan` (ruling
    /// point 3 — the fulfilled request is `fulfilled`, never `stale`); the count-only
    /// reconciliation cannot catch it (staled+own would still equal total), so the
    /// explicit same-request guard is load-bearing.
    pub(crate) fn with_leave_fulfillment_own_staled_for_test(mut self) -> Self {
        if let Some(fulfilled_before) = self
            .effects
            .leave_request_changes
            .iter()
            .find(|change| {
                matches!(
                    (&change.before, &change.after),
                    (Some(b), Some(a))
                        if b.status == LeaveRequestStatus::Pending
                            && a.status == LeaveRequestStatus::Fulfilled
                )
            })
            .and_then(|change| change.before.clone())
        {
            let mut staled = fulfilled_before.clone();
            staled.status = LeaveRequestStatus::Stale;
            self.effects.leave_request_changes.push(StateChange {
                before: Some(fulfilled_before),
                after: Some(staled),
            });
        }
        self
    }

    /// ADR-019 Erratum 01 desync (zero-leaf-leave): flip the plan's first leave
    /// staling from `Pending->Stale` to `Pending->Fulfilled`. A zeroLeafLeave
    /// (leavePolicy) owns no leave request of its own, so ANY `Fulfilled` leave delta
    /// is illegal — `apply_zero_leaf_leave` must reject it as `InconsistentPlan`
    /// (shape guard: every leave delta must be `Pending->Stale`).
    pub(crate) fn with_leave_staling_flipped_to_fulfilled_for_test(mut self) -> Self {
        if let Some(after) = self
            .effects
            .leave_request_changes
            .first_mut()
            .and_then(|change| change.after.as_mut())
        {
            after.status = LeaveRequestStatus::Fulfilled;
        }
        self
    }
}

#[cfg(test)]
impl TransitionEvidence {
    /// A group `policy` addParticipant `TransitionEvidence`: authority-less test
    /// seam carrying the exact `Policy` body a real add produces (prior/next
    /// coordinate-only successor + `Add` changes).
    pub(crate) fn for_test_policy_add(
        seq: u64,
        transition_id: [u8; 16],
        outer_entry_fingerprint: [u8; 32],
        received_at: ServerTimestamp,
        prior: PublicGroupSnapshotCoordinate,
        added: Vec<PrincipalId>,
    ) -> Result<Self, StateMachineError> {
        let next = coordinate_only_successor(&prior)?;
        let mut evidence =
            Self::for_test_at(seq, transition_id, outer_entry_fingerprint, received_at)?;
        evidence.body_binding = Some(TransitionBodyBinding::Policy {
            prior,
            next,
            participant_changes: added
                .into_iter()
                .map(ManifestParticipantChange::Add)
                .collect(),
        });
        Ok(evidence)
    }
}

#[cfg(test)]
impl ConversationHeadCasBinding {
    /// The head CAS an INTERNAL (entry-less) op's head lock would mint: the prior
    /// coordinate verified, NO seq allocated, the counter UNCHANGED
    /// (`bind_non_control_request_authority` shape).
    pub(crate) fn for_test_internal(
        conversation_id: [u8; 16],
        prior: PublicGroupSnapshotCoordinate,
        next_entry_seq: u64,
        locked_at: ServerTimestamp,
    ) -> Self {
        Self::for_test_internal_with_transaction_id(
            "e2b6-executor-test".to_owned(),
            conversation_id,
            prior,
            next_entry_seq,
            locked_at,
        )
    }

    /// Exact-transaction variant used only by integration proofs that exercise
    /// production facade transaction binding. The value must come from
    /// `txid_current()` on the caller-owned PostgreSQL transaction.
    pub(crate) fn for_test_internal_with_transaction_id(
        transaction_id: String,
        conversation_id: [u8; 16],
        prior: PublicGroupSnapshotCoordinate,
        next_entry_seq: u64,
        locked_at: ServerTimestamp,
    ) -> Self {
        Self {
            transaction_id,
            conversation_id,
            expected_prior: Some(prior),
            expected_next_entry_seq: next_entry_seq,
            allocated_entry_id: None,
            allocated_seq: None,
            successor_next_entry_seq: next_entry_seq,
            locked_at,
            locked_head_digest: [1u8; 32],
        }
    }

    /// The head CAS an existing-conversation edge's head lock would mint: the
    /// prior coordinate, the entry at `allocated_seq`, counter advanced by one.
    pub(crate) fn for_test_edge(
        conversation_id: [u8; 16],
        entry_id: [u8; 16],
        prior: PublicGroupSnapshotCoordinate,
        allocated_seq: u64,
        locked_at: ServerTimestamp,
    ) -> Self {
        Self::for_test_edge_with_transaction_id(
            "e2b3-executor-test".to_owned(),
            conversation_id,
            entry_id,
            prior,
            allocated_seq,
            locked_at,
        )
    }

    /// Exact-transaction variant used only by integration proofs that exercise
    /// production facade transaction binding. The value must come from
    /// `txid_current()` on the caller-owned PostgreSQL transaction.
    pub(crate) fn for_test_edge_with_transaction_id(
        transaction_id: String,
        conversation_id: [u8; 16],
        entry_id: [u8; 16],
        prior: PublicGroupSnapshotCoordinate,
        allocated_seq: u64,
        locked_at: ServerTimestamp,
    ) -> Self {
        Self {
            transaction_id,
            conversation_id,
            expected_prior: Some(prior),
            expected_next_entry_seq: allocated_seq,
            allocated_entry_id: Some(entry_id),
            allocated_seq: Some(allocated_seq),
            successor_next_entry_seq: allocated_seq + 1,
            locked_at,
            locked_head_digest: [1u8; 32],
        }
    }
}

#[cfg(test)]
pub(crate) fn plan_policy(
    prior: &ConversationState,
    actor: DeviceIdentity,
    transition: TransitionEvidence,
    relationship_evidence_digest: [u8; 32],
) -> Result<PlannedTransition, StateMachineError> {
    plan_policy_transition(
        prior,
        PolicyCommand {
            actor,
            transition,
            relationship_evidence_digest,
        },
    )
}

// The deterministic pure planners are intentionally reachable only from the
// test build. Production callers must enter through HydrationAuthority's
// route-specific methods, which consume repository lock/auth witnesses.
#[cfg(test)]
pub(crate) fn plan_creation(
    existing_direct: Option<&ConversationState>,
    command: CreationCommand,
) -> Result<CreationDecision, StateMachineError> {
    plan_creation_inner(existing_direct, command)
}

#[cfg(test)]
pub(crate) fn plan_accept_conversation(
    prior: &ConversationState,
    command: AcceptConversation,
) -> Result<PlannedTransition, StateMachineError> {
    plan_accept_conversation_inner(prior, command)
}

#[cfg(test)]
pub(crate) fn plan_metadata(
    prior: &ConversationState,
    command: MetadataCommand,
) -> Result<PlannedTransition, StateMachineError> {
    plan_metadata_inner(prior, command)
}

#[cfg(test)]
pub(crate) fn plan_leaf_recovery_request(
    prior: &ConversationState,
    command: LeafRecoveryRequestCommand,
) -> Result<PlannedTransition, StateMachineError> {
    plan_leaf_recovery_request_inner(prior, command)
}

#[cfg(test)]
pub(crate) fn plan_leaf_recovery_cancellation(
    prior: &ConversationState,
    command: LeafRecoveryCancellation,
) -> Result<PlannedTransition, StateMachineError> {
    plan_leaf_recovery_cancellation_inner(prior, command)
}

#[cfg(test)]
pub(crate) fn plan_leaf_recovery_expiry(
    prior: &ConversationState,
    authority: RecoveryExpiryPlanAuthority,
) -> Result<PlannedTransition, StateMachineError> {
    plan_leaf_recovery_expiry_inner(prior, &authority)
}

#[cfg(test)]
pub(crate) fn plan_device_revocation(
    prior: &ConversationState,
    evidence: DeviceRevocationEvidence,
) -> Result<PlannedTransition, StateMachineError> {
    plan_device_revocation_inner(prior, evidence)
}

/// The per-conversation revocation `ConversationPersistencePlan` a test drives
/// through the entry-less `apply_device_revocation` arm. Sets the entry-less
/// head CAS + `DeviceRevocation` authority and synthesizes the
/// `revocation_package_cas` bijection production requires (mirroring
/// `bind_device_revocation_authority` + `bind_revocation_package_cas`), so the
/// executor's load-bearing `revocation_package_cas_bijection_valid` check is
/// genuinely exercised. Only identity/coordinate/status columns are read by the
/// arm; the digest columns are provenance placeholders.
#[cfg(test)]
pub(crate) fn device_revocation_plan_for_test(
    transition: PlannedTransition,
    head_cas: ConversationHeadCasBinding,
    evidence: DeviceRevocationEvidence,
) -> ConversationPersistencePlan {
    let mut effects = transition.effects;
    debug_assert_eq!(effects.kind, PlanKind::DeviceRevocation);
    for edge in effects.package_transitions.clone() {
        debug_assert_eq!(edge.from, PackageStatus::Reserved);
        debug_assert_eq!(edge.to, PackageStatus::Revoked);
        effects
            .revocation_package_cas
            .push(RevocationPackageCasBinding {
                transaction_id: head_cas.transaction_id.clone(),
                target: evidence.target.clone(),
                target_key_id: [0u8; 32],
                target_auth_generation: evidence.expected_target_auth_generation,
                key_package_ref: edge.key_package_ref,
                wrapper_sha256: [0u8; 32],
                package_not_after: evidence.accepted_at,
                expected_status: PackageStatus::Reserved,
                successor_status: PackageStatus::Revoked,
                conversation_id: Some(head_cas.conversation_id),
                request_id: Some(edge.request_id),
                revocation_id: evidence.revocation_id,
                revoked_at: evidence.accepted_at,
                revocation_request_digest: evidence.request_digest,
                revocation_row_digest: evidence.durable_row_digest,
                locked_row_digest: [1u8; 32],
            });
    }
    effects.authority = Some(PlanAuthority::DeviceRevocation(evidence));
    effects.head_cas = Some(head_cas);
    ConversationPersistencePlan {
        expected_prior: transition.expected_prior,
        retired_coordinate: transition.retired_coordinate,
        successor_coordinate: transition.successor_coordinate,
        state: ConversationStateHydration::from_state(transition.state),
        effects,
    }
}

#[cfg(test)]
pub(crate) fn plan_leaf_recovery_fulfillment(
    prior: &ConversationState,
    command: LeafRecoveryFulfillment,
) -> Result<PlannedTransition, StateMachineError> {
    plan_leaf_recovery_fulfillment_inner(prior, command)
}
