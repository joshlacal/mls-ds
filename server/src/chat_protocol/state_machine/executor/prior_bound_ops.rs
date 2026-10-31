#![allow(unused_imports)]
use super::*;


/// Everything the nine executor arms may know about prior-bound recovery work.
///
/// `PriorBoundPartition`'s fields are private to this module and it has no public
/// constructor, so `classify_prior_bound_recovery` is the ONLY way an arm can obtain
/// one. Deleting the classifier call from an arm is therefore a compile error, not a
/// silent skip. An independent review demonstrated the need: with the partition a
/// plain struct, an arm could hand-derive an equivalent value and the type-enforced
/// write-receipt fence still reconciled cleanly — proving only that the writer agreed
/// with SOME partition, never that the classifier had run.
pub(in crate::chat_protocol::state_machine::executor) mod prior_bound {
    use super::*;

    /// Which coordinate-changing recovery family, if any, the calling arm drives
    /// itself. Everything the arm does NOT drive is prior-bound work it must
    /// supersede, and is classified by `classify_prior_bound_recovery`.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub(in crate::chat_protocol::state_machine::executor) enum OwnFamilyKind {
        /// Seven of the nine arms drive no recovery family of their own.
        None,
        /// `apply_acceptance` opens exactly one family:
        /// `(None -> Open, None -> Active, Available -> Reserved)`.
        Acceptance,
        /// `preflight_leaf_recovery_fulfillment` closes exactly one family:
        /// `(Open -> Fulfilled, Active -> Consumed, Reserved -> Consumed)`.
        LeafRecoveryFulfillment,
    }

    /// Typed partition of a plan's recovery families, produced by
    /// `classify_prior_bound_recovery`.
    ///
    /// Every prior-bound family contributes **exactly one** request, one
    /// reservation and one package edge — the classifier rejects the plan
    /// otherwise — so the per-family counts are the key count, and
    /// `requests()`/`reservations()`/`packages()` are exact rather than
    /// approximate. Callers rebuild their `FamilyCounts` recovery fields from
    /// these accessors so the pre-writer fence stays load-bearing instead of
    /// becoming tautological.
    #[derive(Debug)]
    pub(in crate::chat_protocol::state_machine::executor) struct PriorBoundPartition {
        /// One entry per prior-bound family, `(request_id, key_package_ref)`.
        keys: BTreeSet<([u8; 16], [u8; 32])>,
        /// The arm's own family key, when `OwnFamilyKind` is not `None`.
        own: Option<([u8; 16], [u8; 32])>,
    }

    impl PriorBoundPartition {
        pub(in crate::chat_protocol::state_machine::executor) fn requests(&self) -> usize {
            self.keys.len()
        }

        pub(in crate::chat_protocol::state_machine::executor) fn reservations(&self) -> usize {
            self.keys.len()
        }

        pub(in crate::chat_protocol::state_machine::executor) fn packages(&self) -> usize {
            self.keys.len()
        }

        /// The arm's own family key, when `OwnFamilyKind` is not `None`.
        pub(in crate::chat_protocol::state_machine::executor) fn own(&self) -> Option<([u8; 16], [u8; 32])> {
            self.own
        }

        /// Build a partition directly, for tests that exercise the write-receipt
        /// fence itself. Gated exactly like the regression module, so it exists in
        /// neither shipping binary and cannot be used to bypass the classifier in
        /// production code.
        #[cfg(any(
            test,
            all(
                feature = "chat-protocol-production-proof",
                not(feature = "server-bin")
            )
        ))]
        pub(in crate::chat_protocol::state_machine::executor) fn for_receipt_test(
            keys: BTreeSet<([u8; 16], [u8; 32])>,
            own: Option<([u8; 16], [u8; 32])>,
        ) -> Self {
            Self { keys, own }
        }

        pub(in crate::chat_protocol::state_machine::executor) fn keys(&self) -> &BTreeSet<([u8; 16], [u8; 32])> {
            &self.keys
        }
    }

    pub(in crate::chat_protocol::state_machine::executor) use prior_bound_receipt::PriorBoundWriteReceipt;

    /// The write receipt lives in its own module so its fields are UNREACHABLE from the
    /// nine executor arms. An arm cannot obtain the counts it needs without calling
    /// `reconcile_into_counts`, so deleting the design 5 step 6 fence is a COMPILE
    /// ERROR rather than a silent skip. An independent review demonstrated the need:
    /// with the fence expressed as a discardable `verify(&receipt)?` call, removing all
    /// nine left the entire suite green.
    mod prior_bound_receipt {
        use super::{BTreeSet, ExecutorError, FamilyCounts, PriorBoundPartition};

        /// What `write_prior_bound_supersessions` actually wrote: the per-family counts
        /// each arm folds into its `FamilyCounts`, plus the exact keys — kept DISTINCT
        /// so the key set never leaks into the welcome / reset / leave counts the tail
        /// fence consumes.
        pub(in crate::chat_protocol::state_machine::executor) struct PriorBoundWriteReceipt {
            counts: FamilyCounts,
            keys: BTreeSet<([u8; 16], [u8; 32])>,
        }

        impl PriorBoundWriteReceipt {
            pub(in crate::chat_protocol::state_machine::executor) fn new(
                counts: FamilyCounts,
                keys: BTreeSet<([u8; 16], [u8; 32])>,
            ) -> Self {
                Self { counts, keys }
            }

            /// Design 5 step 6. The ONLY way to reach the counts. Compares what the
            /// writer actually wrote against what the classifier approved, by KEY and
            /// not merely by count: `write_prior_bound_supersessions` SKIPS any delta
            /// that is not its exact supersession shape, so a silent drop is the real
            /// failure mode, and a count-only comparison cannot tell a dropped family
            /// from a substituted one.
            pub(in crate::chat_protocol::state_machine::executor) fn reconcile_into_counts(
                self,
                expected: &PriorBoundPartition,
            ) -> Result<FamilyCounts, ExecutorError> {
                if self.keys != *expected.keys() {
                    return Err(ExecutorError::InconsistentPlan(
                        "prior-bound writer key set disagrees with the classified families",
                    ));
                }
                if self.counts.requests != expected.requests()
                    || self.counts.reservations != expected.reservations()
                    || self.counts.packages != expected.packages()
                {
                    return Err(ExecutorError::InconsistentPlan(
                        "prior-bound writer counts disagree with the classified families",
                    ));
                }
                Ok(self.counts)
            }
        }
    }

    /// The single prior-bound recovery classifier, shared by all nine
    /// coordinate-changing executor arms and called by each strictly BEFORE its
    /// own first head compare-and-set.
    ///
    /// Extracted from `preflight_metadata_transition`, which was the only arm
    /// that proved these properties. The other eight either rejected every plan
    /// carrying package work outright or accepted it unproven, which is what
    /// wedged device recovery: a fulfillment whose peer's request is overdue is
    /// planner-legal and was executor-fatal, and retry re-planned the identical
    /// shape.
    ///
    /// Derives every comparand internally from `plan` and `ctx` — design 4.5
    /// forbids trusting caller-supplied loose effects, prior coordinates,
    /// producer IDs, due times, CAS lists, status filters, or exemption
    /// predicates. `own_kind` selects the arm's own family by exact typed shape
    /// and cardinality; it is not an exemption set.
    ///
    /// Only the properties common to all nine arms are validated here. Each
    /// arm's successor generation / state-version / epoch / close shape remains
    /// that arm's own pre-CAS check.
    pub(in crate::chat_protocol::state_machine::executor) fn classify_prior_bound_recovery(
        plan: &ConversationPersistencePlan,
        ctx: &ExecutionContext,
        own_kind: OwnFamilyKind,
    ) -> Result<PriorBoundPartition, ExecutorError> {
        let effects = plan.effects();
        let head = effects.head_cas().ok_or(ExecutorError::InconsistentPlan(
            "prior-bound classification needs a head CAS binding",
        ))?;
        let prior = head
            .expected_prior()
            .ok_or(ExecutorError::InconsistentPlan(
                "prior-bound classification needs an expected prior",
            ))?;
        let producer = &plan.state().producer;

        // Properties common to all nine arms. Arm-specific successor shape
        // (reset advances generation+1 / stateVersion 0; close retires the
        // coordinate; commit and fulfillment bump state-version and epoch) stays
        // in each arm's existing check.
        if head.conversation_id() != prior.conversation_id()
            || plan.expected_prior.as_ref() != Some(prior)
            || plan
                .successor_coordinate
                .as_ref()
                .is_some_and(|successor| successor.conversation_id() != prior.conversation_id())
        {
            return Err(ExecutorError::InconsistentPlan(
                "prior-bound classification: plan/head coordinate binding drifted",
            ));
        }

        // The arm's own family, derived by exact typed shape and cardinality.
        let own = match own_kind {
            OwnFamilyKind::None => None,
            OwnFamilyKind::Acceptance => Some(classify_own_acceptance_family(effects, prior)?),
            OwnFamilyKind::LeafRecoveryFulfillment => {
                Some(classify_own_fulfillment_family(effects, prior, producer)?)
            }
        };

        let mut request_keys: BTreeMap<([u8; 16], [u8; 32]), bool> = BTreeMap::new();
        for change in effects.recovery_request_changes() {
            let (Some(before_request), Some(after_request)) = (change.before(), change.after())
            else {
                // A creation or deletion is only legal as the arm's own family;
                // `classify_own_acceptance_family` has already proved that shape.
                if own_kind == OwnFamilyKind::Acceptance && change.before().is_none() {
                    continue;
                }
                return Err(ExecutorError::InconsistentPlan(
                    "metadata recovery request delta is not terminal",
                ));
            };
            let key = (after_request.request_id, after_request.key_package_ref);
            if own == Some(key) {
                continue;
            }
            let expired = match after_request.status {
                RecoveryRequestStatus::Superseded
                    if terminal_is_exact_transition(&after_request.terminal, producer) =>
                {
                    false
                }
                RecoveryRequestStatus::Expired
                    if terminal_is_exact_due_expiry(
                        &after_request.terminal,
                        after_request.expires_at,
                        ctx.applied_at,
                    ) =>
                {
                    true
                }
                _ => {
                    return Err(ExecutorError::InconsistentPlan(
                        "metadata recovery request has an illegal terminal shape",
                    ))
                }
            };
            if !recovery_request_identity_is_unchanged(before_request, after_request)
                || before_request.status != RecoveryRequestStatus::Open
                || before_request.bound_coordinate != *prior
                || request_keys.insert(key, expired).is_some()
            {
                return Err(ExecutorError::InconsistentPlan(
                    "metadata recovery request terminalization drifted",
                ));
            }
        }

        let mut reservation_keys: BTreeMap<([u8; 16], [u8; 32]), bool> = BTreeMap::new();
        for change in effects.reservation_changes() {
            let (Some(before_reservation), Some(after_reservation)) =
                (change.before(), change.after())
            else {
                if own_kind == OwnFamilyKind::Acceptance && change.before().is_none() {
                    continue;
                }
                return Err(ExecutorError::InconsistentPlan(
                    "metadata reservation delta is not terminal",
                ));
            };
            let key = (
                after_reservation.request_id,
                after_reservation.key_package_ref,
            );
            if own == Some(key) {
                continue;
            }
            let expired = match after_reservation.status {
                ReservationStatus::Released
                    if terminal_is_exact_transition(&after_reservation.terminal, producer) =>
                {
                    false
                }
                ReservationStatus::Expired
                    if terminal_is_exact_due_expiry(
                        &after_reservation.terminal,
                        after_reservation.expires_at,
                        ctx.applied_at,
                    ) =>
                {
                    true
                }
                _ => {
                    return Err(ExecutorError::InconsistentPlan(
                        "metadata reservation has an illegal terminal shape",
                    ))
                }
            };
            if !recovery_reservation_identity_is_unchanged(before_reservation, after_reservation)
                || before_reservation.status != ReservationStatus::Active
                || before_reservation.bound_coordinate != *prior
                || reservation_keys.insert(key, expired).is_some()
            {
                return Err(ExecutorError::InconsistentPlan(
                    "metadata reservation terminalization drifted",
                ));
            }
        }

        // Own/prior key collision is a hard rejection, never a silent skip
        // (design 4.5). The `continue` arms above skip the own key by exact
        // match; a planner that also emitted it as prior-bound work would be
        // caught here.
        if let Some(own_key) = own {
            if request_keys.contains_key(&own_key) || reservation_keys.contains_key(&own_key) {
                return Err(ExecutorError::InconsistentPlan(
                    "own recovery family also appears as prior-bound work",
                ));
            }
        }

        let package_keys = effects
            .package_transitions()
            .iter()
            .filter(|edge| own != Some((edge.request_id, edge.key_package_ref)))
            .map(|edge| {
                (
                    (edge.request_id, edge.key_package_ref),
                    (edge.from, edge.to),
                )
            })
            .collect::<BTreeMap<_, _>>();
        verify_recovery_package_bijection(effects)?;
        let own_edges = usize::from(own.is_some());
        if request_keys != reservation_keys
                || request_keys.len() != package_keys.len()
                || package_keys.len() + own_edges != effects.package_transitions().len()
                // Design 4.3: `Reserved -> Expired` is rejected for prior-bound
                // families. It is production-unproducible — MIN_KEY_PACKAGE_REMAINING
                // (600s) strictly exceeds RECOVERY_RESERVATION_TTL (300s), so
                // `recovery_expiry`'s `.min()` never clamps — but readers still
                // accepted it. Both Row A and Row B terminalize the package to
                // `Available`; only the request/reservation terminal shape differs.
                || request_keys.keys().any(|key| {
                    !matches!(
                        package_keys.get(key),
                        Some((PackageStatus::Reserved, PackageStatus::Available))
                    )
                })
        {
            return Err(ExecutorError::InconsistentPlan(
                "metadata recovery request/reservation/package families are not bijective",
            ));
        }

        for binding in effects.recovery_package_cas() {
            let key = (binding.request_id, binding.key_package_ref);
            if own == Some(key) {
                continue;
            }
            let request = effects
                .recovery_request_changes()
                .iter()
                .filter_map(StateChange::after)
                .find(|request| {
                    request.request_id == binding.request_id
                        && request.key_package_ref == binding.key_package_ref
                })
                .ok_or(ExecutorError::InconsistentPlan(
                    "metadata package authority has no exact recovery request",
                ))?;
            let reservation = effects
                .reservation_changes()
                .iter()
                .filter_map(StateChange::after)
                .find(|reservation| {
                    reservation.request_id == binding.request_id
                        && reservation.key_package_ref == binding.key_package_ref
                })
                .ok_or(ExecutorError::InconsistentPlan(
                    "metadata package authority has no exact reservation",
                ))?;
            let (origin_key_id, origin_auth_generation) = match &request.origin {
                RecoveryOriginEvidence::Acceptance(value) => {
                    let authority =
                        value
                            .authority
                            .as_ref()
                            .ok_or(ExecutorError::InconsistentPlan(
                                "metadata recovery acceptance has no signing authority",
                            ))?;
                    (authority.key_id, authority.auth_generation)
                }
                RecoveryOriginEvidence::Request(value) => (value.key_id, value.auth_generation),
            };
            // Amended design 4.4 check 8. The wrapper SHA has a comparand on the
            // `Acceptance` branch only; on the `Request` branch check 8 reads
            // neither the body binding nor the signed authority, and their
            // absence is NOT a rejection ground — `RequestEvidence.key_id` and
            // `.auth_generation` are non-Optional and are taken directly above.
            // A universal fail-closed rule would be a different truth table than
            // the sealed base and would strand design 6.4 positive rows 2/3/4.
            if let RecoveryOriginEvidence::Acceptance(value) = &request.origin {
                let recovery = match value.body_binding.as_ref() {
                    Some(TransitionBodyBinding::Acceptance { recovery, .. }) => recovery,
                    _ => {
                        return Err(ExecutorError::InconsistentPlan(
                            "prior-bound recovery acceptance has no acceptance body binding",
                        ))
                    }
                };
                if binding.key_package_wrapper_sha256 != recovery.key_package_wrapper_sha256
                    || <[u8; 32]>::from(sha2::Sha256::digest(&recovery.key_package_wrapper))
                        != recovery.key_package_wrapper_sha256
                {
                    return Err(ExecutorError::InconsistentPlan(
                        "prior-bound recovery package wrapper digest drift",
                    ));
                }
            }
            if binding.transaction_id != head.transaction_id
                    || binding.conversation_id != *prior.conversation_id()
                    || binding.target != request.target
                    || binding.target != reservation.target
                    || binding.target_key_id != origin_key_id
                    || binding.target_auth_generation != origin_auth_generation
                    || binding.bound_coordinate != *prior
                    || binding.bound_coordinate != request.bound_coordinate
                    || binding.bound_coordinate != reservation.bound_coordinate
                    || binding.package_not_after != reservation.package_not_after
                    || binding.claimed_at != request.received_at
                    || binding.claimed_at != reservation.received_at
                    // Sealed proved this pair directly; the binding pins every other
                    // cross-field equality but not `expires_at`, which is what
                    // `terminal_is_exact_due_expiry` tests the terminal against. A
                    // request and reservation disagreeing here could have one due and
                    // the other not.
                    || request.expires_at != reservation.expires_at
                    || binding.expected_status != PackageStatus::Reserved
                    || binding.successor_status
                        != package_keys
                            .get(&key)
                            .map(|(_, successor)| *successor)
                            .ok_or(ExecutorError::InconsistentPlan(
                                "metadata package authority has no semantic edge",
                            ))?
            {
                return Err(ExecutorError::InconsistentPlan(
                    "metadata recovery package CAS authority drift",
                ));
            }
        }

        // Amended design 4.4 check 8-DiD (defence in depth; mandatory here, not a
        // 6.4 matrix row). `recovery_package_guard_digest` hashes
        // `key_package_ref` with every variable-length input length-prefixed, so
        // distinct refs imply distinct digests absent a SHA-256 collision. This
        // fires on planner digest-reuse across two references.
        let mut seen_row_digests: BTreeMap<[u8; 32], [u8; 32]> = BTreeMap::new();
        for binding in effects.recovery_package_cas() {
            if let Some(previous_ref) =
                seen_row_digests.insert(binding.locked_row_digest, binding.key_package_ref)
            {
                if previous_ref != binding.key_package_ref {
                    return Err(ExecutorError::InconsistentPlan(
                        "distinct key package refs share one locked row digest",
                    ));
                }
            }
        }

        Ok(PriorBoundPartition {
            keys: request_keys.into_keys().collect(),
            own,
        })
    }

    /// `apply_acceptance`'s own family: exactly one
    /// `(None -> Open, None -> Active, Available -> Reserved)` triple, keyed
    /// `(request_id, key_package_ref)`. Derived by exact typed shape and
    /// cardinality — never by a caller-supplied exemption set.
    fn classify_own_acceptance_family(
        effects: &TransitionEffects,
        prior: &PublicGroupSnapshotCoordinate,
    ) -> Result<([u8; 16], [u8; 32]), ExecutorError> {
        // CRITICAL: the acceptance own family is opened as PART of the coordinate
        // change, so `plan_accept_conversation_inner` binds both the request and the
        // reservation to `coordinate_only_successor(prior)`, never to `prior` itself.
        // Comparing against `prior` here rejects every acceptConversation before its
        // head CAS, and retry re-plans the identical shape — a permanent
        // device-can-never-join wedge. Only the PRIOR-BOUND families are prior-bound.
        let own_bound = coordinate_only_successor(prior).map_err(|_| {
            ExecutorError::InconsistentPlan("acceptance successor is not coordinate-only")
        })?;
        let mut own: Option<([u8; 16], [u8; 32])> = None;
        for change in effects.recovery_request_changes() {
            let (None, Some(after)) = (change.before(), change.after()) else {
                continue;
            };
            if after.status != RecoveryRequestStatus::Open
                || after.bound_coordinate != own_bound
                || after.terminal.is_some()
            {
                return Err(ExecutorError::InconsistentPlan(
                    "acceptance own recovery request has an illegal shape",
                ));
            }
            if own
                .replace((after.request_id, after.key_package_ref))
                .is_some()
            {
                return Err(ExecutorError::InconsistentPlan(
                    "acceptance carries multiple own recovery requests",
                ));
            }
        }
        let own = own.ok_or(ExecutorError::InconsistentPlan(
            "acceptance carries no own opened recovery request",
        ))?;

        let mut reservations = 0usize;
        for change in effects.reservation_changes() {
            let (None, Some(after)) = (change.before(), change.after()) else {
                continue;
            };
            if (after.request_id, after.key_package_ref) != own
                || after.status != ReservationStatus::Active
                || after.bound_coordinate != own_bound
                || after.terminal.is_some()
            {
                return Err(ExecutorError::InconsistentPlan(
                    "acceptance own reservation has an illegal shape",
                ));
            }
            reservations += 1;
        }
        if reservations != 1 {
            return Err(ExecutorError::InconsistentPlan(
                "acceptance must open exactly one reservation",
            ));
        }

        let own_edges = effects
            .package_transitions()
            .iter()
            .filter(|edge| (edge.request_id, edge.key_package_ref) == own)
            .collect::<Vec<_>>();
        if own_edges.len() != 1
            || own_edges[0].from != PackageStatus::Available
            || own_edges[0].to != PackageStatus::Reserved
        {
            return Err(ExecutorError::InconsistentPlan(
                "acceptance must drive exactly one Available -> Reserved package edge",
            ));
        }
        Ok(own)
    }

    /// `preflight_leaf_recovery_fulfillment`'s own family: exactly one
    /// `(Open -> Fulfilled, Active -> Consumed, Reserved -> Consumed)` triple.
    /// Its terminal must be the exact producer transition — an `Expiry` terminal
    /// is never the fulfilling device's own work.
    fn classify_own_fulfillment_family(
        effects: &TransitionEffects,
        prior: &PublicGroupSnapshotCoordinate,
        producer: &crate::chat_protocol::state_machine::TransitionEvidence,
    ) -> Result<([u8; 16], [u8; 32]), ExecutorError> {
        let mut own: Option<&RecoveryRequest> = None;
        for change in effects.recovery_request_changes() {
            let (Some(before), Some(after)) = (change.before(), change.after()) else {
                continue;
            };
            if before.status != RecoveryRequestStatus::Open
                || after.status != RecoveryRequestStatus::Fulfilled
            {
                continue;
            }
            if !recovery_request_identity_is_unchanged(before, after)
                    || before.bound_coordinate != *prior
                    // The own family closes by THIS producer's transition. An `Expiry`
                    // terminal is never the fulfilling device's own work; it belongs to
                    // a prior-bound peer family and is classified as such.
                    || !terminal_is_exact_transition(&after.terminal, producer)
            {
                return Err(ExecutorError::InconsistentPlan(
                    "fulfillment own recovery request identity/terminal drift",
                ));
            }
            if own.replace(after).is_some() {
                return Err(ExecutorError::InconsistentPlan(
                    "fulfillment carries multiple own recovery requests",
                ));
            }
        }
        let own_request = own.ok_or(ExecutorError::InconsistentPlan(
            "fulfillment carries no own fulfilled recovery request",
        ))?;
        let own = (own_request.request_id, own_request.key_package_ref);

        let mut reservations = 0usize;
        for change in effects.reservation_changes() {
            let (Some(before), Some(after)) = (change.before(), change.after()) else {
                continue;
            };
            if (after.request_id, after.key_package_ref) != own {
                continue;
            }
            if before.status != ReservationStatus::Active
                    || after.status != ReservationStatus::Consumed
                    || !recovery_reservation_identity_is_unchanged(before, after)
                    || before.bound_coordinate != *prior
                    || !terminal_is_exact_transition(&after.terminal, producer)
                    // Sealed proved the own request and reservation agree field-for-field
                    // ("fulfillment own request/reservation are not bijective"). The
                    // key and request id are implied by the `own` match above; target,
                    // received_at and expires_at are not.
                    || after.target != own_request.target
                    || after.received_at != own_request.received_at
                    || after.expires_at != own_request.expires_at
            {
                return Err(ExecutorError::InconsistentPlan(
                    "fulfillment own reservation has an illegal shape",
                ));
            }
            reservations += 1;
        }
        if reservations != 1 {
            return Err(ExecutorError::InconsistentPlan(
                "fulfillment must consume exactly one own reservation",
            ));
        }

        let own_edges = effects
            .package_transitions()
            .iter()
            .filter(|edge| (edge.request_id, edge.key_package_ref) == own)
            .collect::<Vec<_>>();
        if own_edges.len() != 1
            || own_edges[0].from != PackageStatus::Reserved
            || own_edges[0].to != PackageStatus::Consumed
        {
            return Err(ExecutorError::InconsistentPlan(
                "fulfillment must drive exactly one Reserved -> Consumed package edge",
            ));
        }
        Ok(own)
    }
}

use prior_bound::{
    classify_prior_bound_recovery, OwnFamilyKind, PriorBoundPartition, PriorBoundWriteReceipt,
};

pub(in crate::chat_protocol::state_machine::executor) fn recovery_request_identity_is_unchanged(
    before: &RecoveryRequest,
    after: &RecoveryRequest,
) -> bool {
    before.request_id == after.request_id
        && before.target == after.target
        && before.kind == after.kind
        && before.source == after.source
        && before.bound_coordinate == after.bound_coordinate
        && before.key_package_ref == after.key_package_ref
        && before.received_at == after.received_at
        && before.expires_at == after.expires_at
        && before.terminal.is_none()
}

pub(in crate::chat_protocol::state_machine::executor) fn recovery_reservation_identity_is_unchanged(
    before: &RecoveryReservation,
    after: &RecoveryReservation,
) -> bool {
    before.request_id == after.request_id
        && before.target == after.target
        && before.bound_coordinate == after.bound_coordinate
        && before.key_package_ref == after.key_package_ref
        && before.received_at == after.received_at
        && before.expires_at == after.expires_at
        && before.package_not_after == after.package_not_after
        && before.terminal.is_none()
}

pub(in crate::chat_protocol::state_machine::executor) fn reset_request_identity_is_unchanged(before: &ResetRequest, after: &ResetRequest) -> bool {
    before.request_id == after.request_id
        && before.requester == after.requester
        && before.bound_coordinate == after.bound_coordinate
        && before.received_at == after.received_at
        && before.expires_at == after.expires_at
        && before.origin == after.origin
        && before.terminal.is_none()
}

pub(in crate::chat_protocol::state_machine::executor) fn leave_request_identity_is_unchanged(
    before: &crate::chat_protocol::state_machine::LeaveRequest,
    after: &crate::chat_protocol::state_machine::LeaveRequest,
) -> bool {
    before.request_id == after.request_id
        && before.requester == after.requester
        && before.bound_coordinate == after.bound_coordinate
        && before.received_at == after.received_at
        && before.expires_at == after.expires_at
        && before.origin == after.origin
        && before.fulfilled_participant == after.fulfilled_participant
        && before.terminal.is_none()
}

pub(in crate::chat_protocol::state_machine::executor) fn welcome_identity_is_unchanged(before: &WelcomeWork, after: &WelcomeWork) -> bool {
    before.welcome_id == after.welcome_id
        && before.recipient == after.recipient
        && before.transition_seq == after.transition_seq
        && before.coordinate == after.coordinate
        && before.recovery_request_id == after.recovery_request_id
        && before.key_package_ref == after.key_package_ref
        && before.opaque_welcome == after.opaque_welcome
        && before.sha256 == after.sha256
        && before.expires_at == after.expires_at
        && before.terminal.is_none()
}

pub(in crate::chat_protocol::state_machine::executor) fn interval_identity_is_unchanged(
    before: &crate::chat_protocol::state_machine::AccessInterval,
    after: &crate::chat_protocol::state_machine::AccessInterval,
) -> bool {
    before.recipient == after.recipient
        && before.generation == after.generation
        && before.opening == after.opening
        && before.opening_kind == after.opening_kind
        && before.opening_context == after.opening_context
        && before.end.is_none()
}

pub(in crate::chat_protocol::state_machine::executor) fn leaf_matches_hydration(leaf: &LeafRecord, row: &LeafHydrationRow) -> bool {
    leaf.device == row.device
        && leaf.leaf_index == row.leaf_index
        && leaf.basic_credential == row.basic_credential
        && leaf.signature_key == row.signature_key
        && leaf.encryption_key == row.encryption_key
        && leaf.key_package_ref == row.key_package_ref
}
