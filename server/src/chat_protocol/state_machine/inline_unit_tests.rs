#![allow(unused_imports)]
use super::*;


#[cfg(test)]
mod invitation_quota_binding_tests {
    use super::*;

    #[test]
    fn overflow_cannot_wrap_to_a_zero_successor_fact() {
        let recipient = PrincipalId::new(b"did:plc:bbbbbbbbbbbbbbbbbbbbbbbb".to_vec()).unwrap();
        let binding = InvitationQuotaCasBinding {
            transaction_id: "4242".to_owned(),
            inviter: PrincipalId::new(b"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".to_vec()).unwrap(),
            new_recipients: vec![recipient.clone()],
            expected_inviter_recent_24h: 0,
            successor_inviter_recent_24h: 1,
            inviter_limit: 100,
            recipient_facts: vec![InvitationQuotaRecipientCasFact {
                recipient,
                expected_pair_live: u64::MAX,
                successor_pair_live: 0,
                pair_limit: 5,
                expected_recipient_live: u64::MAX,
                successor_recipient_live: 0,
                recipient_limit: 100,
            }],
            locked_at: ServerTimestamp::from_unix_millis(1).unwrap(),
            locked_row_digest: [1; 32],
        };
        assert!(!invitation_quota_recipient_facts_valid(&binding));
    }
}

#[cfg(test)]
mod recovery_plan_fingerprint_tests {
    use super::*;

    fn coordinate(state_version: u64, epoch: u64, marker: u8) -> PublicGroupSnapshotCoordinate {
        PublicGroupSnapshotCoordinate::new(
            uuid_from_test_byte(0x31),
            1,
            state_version,
            [0x41; 32],
            epoch,
            [marker; 32],
            [marker.wrapping_add(1); 32],
            PublicGroupSnapshotLifecycle::Active,
        )
    }

    fn device(marker: u8) -> DeviceIdentity {
        DeviceIdentity::new(
            PrincipalId::new(format!("did:plc:fingerprint{marker:02x}aaaaaaaaaa").into_bytes())
                .unwrap(),
            uuid_from_test_byte(marker),
        )
        .unwrap()
    }

    fn request_evidence(
        kind: RequestEntryKind,
        request_id: [u8; 16],
        actor: DeviceIdentity,
        prior: PublicGroupSnapshotCoordinate,
        marker: u8,
    ) -> RequestEvidence {
        let mut evidence = RequestEvidence::for_test(
            kind,
            7,
            request_id,
            actor,
            *prior.conversation_id(),
            ServerTimestamp::from_unix_millis(10_000 + i64::from(marker)).unwrap(),
            marker,
        )
        .unwrap();
        evidence.control_entry_id = None;
        evidence.control_seq = None;
        evidence.body_binding = Some(match kind {
            RequestEntryKind::LeafRecoveryRequest => RequestBodyBinding::LeafRecoveryRequest {
                prior,
                kind: LeafRecoveryKind::Add,
            },
            RequestEntryKind::LeafRecoveryCancellation => {
                RequestBodyBinding::LeafRecoveryCancellation
            }
            _ => unreachable!(),
        });
        evidence
    }

    fn recovery_package_cas(
        transaction_id: &str,
        request: &RecoveryRequest,
        reservation: &RecoveryReservation,
        expected_status: PackageStatus,
        successor_status: PackageStatus,
    ) -> RecoveryPackageCasBinding {
        let mut binding = RecoveryPackageCasBinding {
            transaction_id: transaction_id.to_owned(),
            conversation_id: *request.bound_coordinate.conversation_id(),
            request_id: request.request_id,
            target: request.target.clone(),
            target_key_id: [0x51; 32],
            target_auth_generation: 3,
            bound_coordinate: request.bound_coordinate,
            key_package_ref: request.key_package_ref,
            key_package_wrapper_sha256: [0x52; 32],
            package_not_after: reservation.package_not_after,
            claimed_at: reservation.received_at,
            expected_status,
            successor_status,
            locked_row_digest: [0x53; 32],
            authority_digest: [0; 32],
        };
        binding.authority_digest = recovery_package_cas_authority_digest(&binding);
        binding
    }

    fn request_plan() -> ConversationPersistencePlan {
        let prior = coordinate(5, 8, 0x61);
        let actor = device(0x42);
        let request_id = uuid_from_test_byte(0x43);
        let evidence = request_evidence(
            RequestEntryKind::LeafRecoveryRequest,
            request_id,
            actor.clone(),
            prior,
            0x44,
        );
        let received_at = evidence.received_at;
        let expires_at = ServerTimestamp::from_unix_millis(20_000).unwrap();
        let request = RecoveryRequest {
            request_id,
            target: actor.clone(),
            kind: LeafRecoveryKind::Add,
            source: RecoverySource::Request,
            bound_coordinate: prior,
            key_package_ref: [0x45; 32],
            received_at,
            expires_at,
            status: RecoveryRequestStatus::Open,
            origin: RecoveryOriginEvidence::Request(evidence.clone()),
            terminal: None,
        };
        let reservation = RecoveryReservation {
            request_id,
            target: actor,
            bound_coordinate: prior,
            key_package_ref: request.key_package_ref,
            received_at,
            expires_at,
            package_not_after: ServerTimestamp::from_unix_millis(30_000).unwrap(),
            status: ReservationStatus::Active,
            terminal: None,
        };
        let transaction_id = "recovery-fingerprint-tx";
        let package_transition = PackageTransition {
            request_id,
            key_package_ref: request.key_package_ref,
            from: PackageStatus::Available,
            to: PackageStatus::Reserved,
        };
        let package_cas = recovery_package_cas(
            transaction_id,
            &request,
            &reservation,
            PackageStatus::Available,
            PackageStatus::Reserved,
        );
        let producer = TransitionEvidence::new(6, uuid_from_test_byte(0x46), [0x47; 32]).unwrap();
        ConversationPersistencePlan {
            expected_prior: Some(prior),
            retired_coordinate: None,
            successor_coordinate: Some(prior),
            state: ConversationStateHydration {
                kind: ConversationKind::Group,
                coordinate: prior,
                producer,
                public_state: None,
                metadata: None,
                metadata_producer: None,
                participants: Vec::new(),
                leaves: Vec::new(),
                intervals: Vec::new(),
                terminal_proofs: Vec::new(),
                recovery_requests: vec![RecoveryRequestHydrationRow {
                    request_id,
                    target: request.target.clone(),
                    kind: request.kind,
                    source: request.source,
                    bound_coordinate: prior,
                    key_package_ref: request.key_package_ref,
                    received_at,
                    expires_at,
                    status: RecoveryRequestStatus::Open,
                    origin: RecoveryOriginHydrationRow::Request(evidence.clone()),
                    terminal: None,
                }],
                recovery_reservations: vec![RecoveryReservationHydrationRow {
                    request_id,
                    target: reservation.target.clone(),
                    bound_coordinate: prior,
                    key_package_ref: reservation.key_package_ref,
                    received_at,
                    expires_at,
                    package_not_after: reservation.package_not_after,
                    status: ReservationStatus::Active,
                    terminal: None,
                }],
                reset_requests: Vec::new(),
                leave_requests: Vec::new(),
                welcomes: Vec::new(),
            },
            effects: TransitionEffects {
                kind: PlanKind::RecoveryRequest,
                opened_intervals: Vec::new(),
                closed_intervals: Vec::new(),
                superseded_recovery_requests: Vec::new(),
                terminal_proof_recipients: Vec::new(),
                complete: true,
                before_counts: StateCounts::default(),
                after_counts: StateCounts {
                    open_recovery_requests: 1,
                    active_reservations: 1,
                    ..StateCounts::default()
                },
                metadata_change: None,
                policy_evidence_digest: Some([0x48; 32]),
                participant_changes: Vec::new(),
                leaf_changes: Vec::new(),
                interval_changes: Vec::new(),
                terminal_proof_changes: Vec::new(),
                recovery_request_changes: vec![StateChange {
                    before: None,
                    after: Some(request),
                }],
                reservation_changes: vec![StateChange {
                    before: None,
                    after: Some(reservation),
                }],
                reset_request_changes: Vec::new(),
                leave_request_changes: Vec::new(),
                welcome_changes: Vec::new(),
                package_transitions: vec![package_transition],
                recovery_package_cas: vec![package_cas],
                revocation_package_cas: Vec::new(),
                revocation_target_cas: None,
                welcome_cas: None,
                invitation_quota_cas: None,
                authority: Some(PlanAuthority::Request(evidence)),
                head_cas: Some(ConversationHeadCasBinding {
                    transaction_id: transaction_id.to_owned(),
                    conversation_id: *prior.conversation_id(),
                    expected_prior: Some(prior),
                    expected_next_entry_seq: 7,
                    allocated_entry_id: None,
                    allocated_seq: None,
                    successor_next_entry_seq: 7,
                    locked_at: received_at,
                    locked_head_digest: [0x49; 32],
                }),
            },
        }
    }

    fn fulfillment_plan() -> ConversationPersistencePlan {
        let mut plan = request_plan();
        let prior = plan.expected_prior.unwrap();
        let next = coordinate(prior.state_version() + 1, prior.epoch() + 1, 0x71);
        let mut before_request = plan.effects.recovery_request_changes[0]
            .after
            .clone()
            .unwrap();
        let mut before_reservation = plan.effects.reservation_changes[0].after.clone().unwrap();
        let target = before_request.target.clone();
        let actor = device(0x58);
        let transition_id = uuid_from_test_byte(0x59);
        let welcome_id = uuid_from_test_byte(0x5a);
        let applied_at = ServerTimestamp::from_unix_millis(12_000).unwrap();
        let metadata = MetadataSnapshotBinding::for_test_creation(
            *prior.conversation_id(),
            next.generation(),
            *next.group_id(),
            next.epoch(),
            *next.group_context_hash(),
            *next.confirmation_tag(),
            transition_id,
            7,
            actor.clone(),
            [0x5b; 32],
            [0x5c; 32],
            2,
            4,
            [0x5d; 12],
            vec![0x5e, 0x5f],
        );
        let mut producer = TransitionEvidence::for_test_leaf_recovery_fulfillment_with_metadata(
            7,
            transition_id,
            [0x60; 32],
            applied_at,
            before_request.request_id,
            prior,
            next,
            target.clone(),
            before_request.key_package_ref,
            welcome_id,
            vec![0x61, 0x62],
            metadata.clone(),
        )
        .unwrap();
        producer.authority = Some(AuthenticatedEntryEvidence {
            kind: SignedMutationKind::LeafRecoveryFulfillment,
            type_id: "leafRecoveryFulfillmentBody",
            domain: b"CATBIRD-CHAT-LEAF-RECOVERY-FULFILL\0".to_vec(),
            control_entry_id: Some(transition_id),
            control_conversation_id: Some(*prior.conversation_id()),
            actor,
            key_id: [0x63; 32],
            auth_generation: 2,
            signed_at: applied_at,
            request_digest: [0x64; 32],
            signature: [0x65; 64],
            signed_request_bytes: vec![0x66],
            canonical_projection: vec![0x67],
            transcript_bytes: vec![0x68],
        });
        let terminal = WorkTerminalEvidence::Transition(producer.clone());
        let mut after_request = before_request.clone();
        after_request.status = RecoveryRequestStatus::Fulfilled;
        after_request.terminal = Some(terminal.clone());
        let mut after_reservation = before_reservation.clone();
        after_reservation.status = ReservationStatus::Consumed;
        after_reservation.terminal = Some(terminal.clone());
        let leaf = LeafRecord {
            device: target.clone(),
            leaf_index: 3,
            basic_credential: target.basic_credential(),
            signature_key: vec![0x69; 32],
            encryption_key: vec![0x6a; 32],
            key_package_ref: Some(before_request.key_package_ref),
        };
        let interval = AccessInterval {
            recipient: target.clone(),
            generation: next.generation(),
            opening: producer.clone(),
            opening_kind: OpeningKind::Add,
            opening_context: next,
            end: None,
        };
        let welcome = WelcomeWork {
            welcome_id,
            recipient: target.clone(),
            transition_seq: producer.seq,
            coordinate: next,
            recovery_request_id: before_request.request_id,
            key_package_ref: before_request.key_package_ref,
            opaque_welcome: vec![0x61, 0x62],
            sha256: Sha256::digest([0x61, 0x62]).into(),
            expires_at: before_reservation.package_not_after,
            status: WelcomeStatus::Pending,
            terminal: None,
        };
        let transaction_id = plan
            .effects
            .head_cas
            .as_ref()
            .unwrap()
            .transaction_id
            .clone();
        let package_cas = recovery_package_cas(
            &transaction_id,
            &after_request,
            &after_reservation,
            PackageStatus::Reserved,
            PackageStatus::Consumed,
        );

        before_request.status = RecoveryRequestStatus::Open;
        before_request.terminal = None;
        before_reservation.status = ReservationStatus::Active;
        before_reservation.terminal = None;
        plan.successor_coordinate = Some(next);
        plan.state.coordinate = next;
        plan.state.producer = producer.clone();
        plan.state.metadata = Some(metadata.clone());
        plan.state.metadata_producer = Some(producer.clone());
        plan.state.leaves = vec![LeafHydrationRow {
            device: leaf.device.clone(),
            leaf_index: leaf.leaf_index,
            basic_credential: leaf.basic_credential.clone(),
            signature_key: leaf.signature_key.clone(),
            encryption_key: leaf.encryption_key.clone(),
            key_package_ref: leaf.key_package_ref,
        }];
        plan.state.intervals = vec![IntervalHydrationRow {
            recipient: interval.recipient.clone(),
            generation: interval.generation,
            opening: interval.opening.clone(),
            opening_kind: interval.opening_kind,
            opening_context: interval.opening_context,
            end: None,
        }];
        plan.state.recovery_requests[0].status = RecoveryRequestStatus::Fulfilled;
        plan.state.recovery_requests[0].terminal =
            Some(WorkTerminalHydrationRow::Transition(producer.clone()));
        plan.state.recovery_reservations[0].status = ReservationStatus::Consumed;
        plan.state.recovery_reservations[0].terminal =
            Some(WorkTerminalHydrationRow::Transition(producer.clone()));
        plan.state.welcomes = vec![WelcomeHydrationRow {
            welcome_id,
            recipient: welcome.recipient.clone(),
            transition_seq: welcome.transition_seq,
            coordinate: next,
            recovery_request_id: welcome.recovery_request_id,
            key_package_ref: welcome.key_package_ref,
            opaque_welcome: welcome.opaque_welcome.clone(),
            sha256: welcome.sha256,
            expires_at: welcome.expires_at,
            status: welcome.status,
            terminal: None,
        }];

        plan.effects.kind = PlanKind::Commit;
        plan.effects.opened_intervals = vec![target];
        plan.effects.metadata_change = Some(StateChange {
            before: None,
            after: Some(metadata),
        });
        plan.effects.leaf_changes = vec![StateChange {
            before: None,
            after: Some(leaf),
        }];
        plan.effects.interval_changes = vec![StateChange {
            before: None,
            after: Some(interval),
        }];
        plan.effects.recovery_request_changes = vec![StateChange {
            before: Some(before_request),
            after: Some(after_request.clone()),
        }];
        plan.effects.reservation_changes = vec![StateChange {
            before: Some(before_reservation),
            after: Some(after_reservation),
        }];
        plan.effects.welcome_changes = vec![StateChange {
            before: None,
            after: Some(welcome),
        }];
        plan.effects.package_transitions = vec![PackageTransition {
            request_id: after_request.request_id,
            key_package_ref: after_request.key_package_ref,
            from: PackageStatus::Reserved,
            to: PackageStatus::Consumed,
        }];
        plan.effects.recovery_package_cas = vec![package_cas];
        plan.effects.authority = Some(PlanAuthority::Transition(producer.clone()));
        plan.effects.head_cas = Some(ConversationHeadCasBinding {
            transaction_id,
            conversation_id: *prior.conversation_id(),
            expected_prior: Some(prior),
            expected_next_entry_seq: producer.seq,
            allocated_entry_id: Some(transition_id),
            allocated_seq: Some(producer.seq),
            successor_next_entry_seq: producer.seq + 1,
            locked_at: applied_at,
            locked_head_digest: [0x6b; 32],
        });
        plan
    }

    fn fingerprint(plan: &ConversationPersistencePlan) -> RecoveryPlanFingerprint {
        recovery_plan_fingerprint(plan, None).expect("valid Recovery request fingerprint")
    }

    #[test]
    fn recovery_plan_fingerprint_binds_authority_head_and_coordinates() {
        let plan = request_plan();
        let baseline = fingerprint(&plan);
        assert_eq!(baseline.class(), RecoveryPlanClass::Request);

        let mut authority_drift = plan.clone();
        let Some(PlanAuthority::Request(authority)) = authority_drift.effects.authority.as_mut()
        else {
            unreachable!()
        };
        authority.request_digest[0] ^= 1;
        assert_ne!(baseline.digest(), fingerprint(&authority_drift).digest());

        let mut head_drift = plan.clone();
        head_drift
            .effects
            .head_cas
            .as_mut()
            .unwrap()
            .locked_head_digest[0] ^= 1;
        assert_ne!(baseline.digest(), fingerprint(&head_drift).digest());

        let mut coordinate_drift = plan.clone();
        coordinate_drift.state.producer.outer_entry_fingerprint[0] ^= 1;
        assert_ne!(baseline.digest(), fingerprint(&coordinate_drift).digest());
    }

    #[test]
    fn recovery_plan_fingerprint_binds_successor_state_and_every_effect_summary() {
        let plan = request_plan();
        let baseline = fingerprint(&plan);

        let mut state_drift = plan.clone();
        state_drift.state.recovery_requests[0].key_package_ref[0] ^= 1;
        assert_ne!(baseline.digest(), fingerprint(&state_drift).digest());

        let mut effects_drift = plan.clone();
        effects_drift.effects.after_counts.active_reservations += 1;
        assert_ne!(baseline.digest(), fingerprint(&effects_drift).digest());
    }

    #[test]
    fn recovery_plan_fingerprint_binds_complete_package_cas_authority() {
        let plan = request_plan();
        let baseline = fingerprint(&plan);
        let mut drift = plan.clone();
        let binding = &mut drift.effects.recovery_package_cas[0];
        binding.locked_row_digest[0] ^= 1;
        binding.authority_digest = recovery_package_cas_authority_digest(binding);
        assert_ne!(baseline.digest(), fingerprint(&drift).digest());
    }

    #[test]
    fn recovery_plan_fingerprint_rejects_control_bytes_and_cross_shape_splices() {
        let plan = request_plan();
        assert!(recovery_plan_fingerprint(&plan, Some(b"caller control bytes")).is_err());

        let mut cross_shape = plan.clone();
        cross_shape.effects.kind = PlanKind::RecoveryCancellation;
        assert!(recovery_plan_fingerprint(&cross_shape, None).is_err());

        let mut forbidden_family = plan;
        forbidden_family.effects.leaf_changes.push(StateChange {
            before: None,
            after: Some(LeafRecord {
                device: device(0x55),
                leaf_index: 1,
                basic_credential: vec![1],
                signature_key: vec![2],
                encryption_key: vec![3],
                key_package_ref: Some([4; 32]),
            }),
        });
        assert!(recovery_plan_fingerprint(&forbidden_family, None).is_err());
    }

    #[test]
    fn relationship_evidence_is_mandatory_for_request_and_fulfillment() {
        let mut request = request_plan();
        request.effects.policy_evidence_digest = None;
        assert!(recovery_plan_fingerprint(&request, None).is_err());

        let mut fulfillment = fulfillment_plan();
        fulfillment.effects.policy_evidence_digest = Some([0; 32]);
        assert!(recovery_plan_fingerprint(&fulfillment, Some(b"canonical-control")).is_err());
    }

    #[test]
    fn fulfillment_requires_control_bytes_and_binds_their_sha256() {
        let plan = fulfillment_plan();
        assert!(recovery_plan_fingerprint(&plan, None).is_err());
        let first = recovery_plan_fingerprint(&plan, Some(b"canonical-control-a")).unwrap();
        let second = recovery_plan_fingerprint(&plan, Some(b"canonical-control-b")).unwrap();
        assert_eq!(first.class(), RecoveryPlanClass::Fulfillment);
        assert_ne!(first.digest(), second.digest());
    }

    #[test]
    fn fulfillment_fingerprint_rejects_extra_family_splices() {
        let plan = fulfillment_plan();

        let mut duplicate_own_request = plan.clone();
        duplicate_own_request
            .effects
            .recovery_request_changes
            .push(duplicate_own_request.effects.recovery_request_changes[0].clone());
        assert!(
            recovery_plan_fingerprint(&duplicate_own_request, Some(b"canonical-control")).is_err()
        );

        let mut illegal_welcome = plan;
        let mut malformed = illegal_welcome.effects.welcome_changes[0].clone();
        malformed.before = malformed.after.clone();
        malformed.after.as_mut().expect("fixture Welcome").status = WelcomeStatus::Expired;
        illegal_welcome.effects.welcome_changes.push(malformed);
        assert!(recovery_plan_fingerprint(&illegal_welcome, Some(b"canonical-control")).is_err());
    }

    fn fulfillment_with_due_peer(package_ends_at_deadline: bool) -> ConversationPersistencePlan {
        let mut plan = fulfillment_plan();
        let mut before = plan.effects.recovery_request_changes[0]
            .before
            .clone()
            .unwrap();
        let prior = before.bound_coordinate;
        before.request_id = uuid_from_test_byte(0x78);
        before.target = device(0x79);
        before.key_package_ref = [0x7a; 32];
        let origin = request_evidence(
            RequestEntryKind::LeafRecoveryRequest,
            before.request_id,
            before.target.clone(),
            prior,
            0x7b,
        );
        before.received_at = origin.received_at;
        before.expires_at = ServerTimestamp::from_unix_millis(11_000).unwrap();
        before.origin = RecoveryOriginEvidence::Request(origin.clone());
        let mut after = before.clone();
        after.status = RecoveryRequestStatus::Expired;
        after.terminal = Some(WorkTerminalEvidence::Expiry(after.expires_at));
        let mut reservation = plan.effects.reservation_changes[0].before.clone().unwrap();
        reservation.request_id = before.request_id;
        reservation.target = before.target.clone();
        reservation.key_package_ref = before.key_package_ref;
        reservation.received_at = before.received_at;
        reservation.expires_at = before.expires_at;
        if package_ends_at_deadline {
            reservation.package_not_after = before.expires_at;
        }
        let mut terminal_reservation = reservation.clone();
        terminal_reservation.status = ReservationStatus::Expired;
        terminal_reservation.terminal = Some(WorkTerminalEvidence::Expiry(before.expires_at));
        let successor = if package_ends_at_deadline {
            PackageStatus::Expired
        } else {
            PackageStatus::Available
        };
        let transaction_id = plan
            .effects
            .head_cas
            .as_ref()
            .unwrap()
            .transaction_id
            .clone();
        let cas = recovery_package_cas(
            &transaction_id,
            &before,
            &reservation,
            PackageStatus::Reserved,
            successor,
        );
        plan.effects.recovery_request_changes.push(StateChange {
            before: Some(before.clone()),
            after: Some(after.clone()),
        });
        plan.effects.reservation_changes.push(StateChange {
            before: Some(reservation.clone()),
            after: Some(terminal_reservation),
        });
        plan.effects.package_transitions.push(PackageTransition {
            request_id: before.request_id,
            key_package_ref: before.key_package_ref,
            from: PackageStatus::Reserved,
            to: successor,
        });
        plan.effects.recovery_package_cas.push(cas);
        plan.state
            .recovery_requests
            .push(RecoveryRequestHydrationRow {
                request_id: before.request_id,
                target: before.target.clone(),
                kind: before.kind,
                source: before.source,
                bound_coordinate: prior,
                key_package_ref: before.key_package_ref,
                received_at: before.received_at,
                expires_at: before.expires_at,
                status: after.status,
                origin: RecoveryOriginHydrationRow::Request(origin),
                terminal: Some(WorkTerminalHydrationRow::Expiry(before.expires_at)),
            });
        plan.state
            .recovery_reservations
            .push(RecoveryReservationHydrationRow {
                request_id: reservation.request_id,
                target: reservation.target,
                bound_coordinate: prior,
                key_package_ref: reservation.key_package_ref,
                received_at: reservation.received_at,
                expires_at: reservation.expires_at,
                package_not_after: reservation.package_not_after,
                status: ReservationStatus::Expired,
                terminal: Some(WorkTerminalHydrationRow::Expiry(reservation.expires_at)),
            });
        plan
    }

    #[test]
    fn fulfillment_fingerprint_accepts_exact_due_peer_release() {
        let plan = fulfillment_with_due_peer(false);
        assert_eq!(
            recovery_plan_fingerprint(&plan, Some(b"canonical-control"))
                .unwrap()
                .class(),
            RecoveryPlanClass::Fulfillment
        );
    }

    #[test]
    fn fulfillment_fingerprint_rejects_due_family_splices() {
        let baseline = fulfillment_with_due_peer(false);
        let rejected = |plan: &ConversationPersistencePlan| {
            let Some(PlanAuthority::Transition(producer)) = plan.effects.authority.as_ref() else {
                panic!("fixture authority");
            };
            assert!(
                !fulfillment_fingerprint_families_are_closed(&plan.effects, producer),
                "the closed-family fence itself must reject, independently of CAS validation"
            );
            assert!(recovery_plan_fingerprint(plan, Some(b"canonical-control")).is_err());
        };
        let mut own_expiry = baseline.clone();
        let own = own_expiry.effects.recovery_request_changes[0]
            .after
            .as_mut()
            .unwrap();
        own.status = RecoveryRequestStatus::Expired;
        own.terminal = Some(WorkTerminalEvidence::Expiry(own.expires_at));
        rejected(&own_expiry);
        let mut early = baseline.clone();
        let deadline = ServerTimestamp::from_unix_millis(13_000).unwrap();
        let change = &mut early.effects.recovery_request_changes[1];
        for value in [&mut change.before, &mut change.after] {
            value.as_mut().unwrap().expires_at = deadline;
        }
        change.after.as_mut().unwrap().terminal = Some(WorkTerminalEvidence::Expiry(deadline));
        let change = &mut early.effects.reservation_changes[1];
        for value in [&mut change.before, &mut change.after] {
            value.as_mut().unwrap().expires_at = deadline;
        }
        change.after.as_mut().unwrap().terminal = Some(WorkTerminalEvidence::Expiry(deadline));
        for row in &mut early.state.recovery_requests[1..] {
            row.expires_at = deadline;
            row.terminal = Some(WorkTerminalHydrationRow::Expiry(deadline));
        }
        for row in &mut early.state.recovery_reservations[1..] {
            row.expires_at = deadline;
            row.terminal = Some(WorkTerminalHydrationRow::Expiry(deadline));
        }
        rejected(&early);
        let mut wrong_terminal = baseline.clone();
        wrong_terminal.effects.recovery_request_changes[1]
            .after
            .as_mut()
            .unwrap()
            .terminal = Some(WorkTerminalEvidence::Expiry(
            ServerTimestamp::from_unix_millis(10_999).unwrap(),
        ));
        rejected(&wrong_terminal);
        let mut wrong_cause = baseline.clone();
        let terminal = wrong_cause.effects.recovery_request_changes[0]
            .after
            .as_ref()
            .unwrap()
            .terminal
            .clone();
        wrong_cause.effects.recovery_request_changes[1]
            .after
            .as_mut()
            .unwrap()
            .terminal = terminal.clone();
        wrong_cause.effects.reservation_changes[1]
            .after
            .as_mut()
            .unwrap()
            .terminal = terminal;
        rejected(&wrong_cause);
        let mut mismatched_deadline = baseline.clone();
        let change = &mut mismatched_deadline.effects.reservation_changes[1];
        for value in [&mut change.before, &mut change.after] {
            value.as_mut().unwrap().expires_at = ServerTimestamp::from_unix_millis(10_999).unwrap();
        }
        change.after.as_mut().unwrap().terminal = Some(WorkTerminalEvidence::Expiry(
            ServerTimestamp::from_unix_millis(10_999).unwrap(),
        ));
        rejected(&mismatched_deadline);
        for package_status in [PackageStatus::Consumed, PackageStatus::Expired] {
            let mut wrong_package = baseline.clone();
            wrong_package.effects.package_transitions[1].to = package_status;
            let cas = &mut wrong_package.effects.recovery_package_cas[1];
            cas.successor_status = package_status;
            cas.authority_digest = recovery_package_cas_authority_digest(cas);
            assert!(package_cas_bijection_valid(&wrong_package.effects));
            rejected(&wrong_package);
        }
        let package_end = fulfillment_with_due_peer(true);
        assert!(package_cas_bijection_valid(&package_end.effects));
        rejected(&package_end);
        let mut package_end_released = package_end.clone();
        package_end_released.effects.package_transitions[1].to = PackageStatus::Available;
        let cas = &mut package_end_released.effects.recovery_package_cas[1];
        cas.successor_status = PackageStatus::Available;
        cas.authority_digest = recovery_package_cas_authority_digest(cas);
        assert!(package_cas_bijection_valid(&package_end_released.effects));
        rejected(&package_end_released);
        let mut duplicate = baseline.clone();
        duplicate
            .effects
            .recovery_request_changes
            .push(duplicate.effects.recovery_request_changes[1].clone());
        rejected(&duplicate);
        let mut duplicate_reservation = baseline.clone();
        duplicate_reservation
            .effects
            .reservation_changes
            .push(duplicate_reservation.effects.reservation_changes[1].clone());
        rejected(&duplicate_reservation);
        let mut duplicate_package = baseline.clone();
        duplicate_package
            .effects
            .package_transitions
            .push(duplicate_package.effects.package_transitions[1].clone());
        rejected(&duplicate_package);
        let mut identity = baseline.clone();
        identity.effects.reservation_changes[1]
            .after
            .as_mut()
            .unwrap()
            .target = device(0x7c);
        rejected(&identity);
        let mut peer_coordinate = baseline.clone();
        peer_coordinate.effects.recovery_request_changes[1]
            .after
            .as_mut()
            .unwrap()
            .bound_coordinate = coordinate(6, 9, 0x72);
        rejected(&peer_coordinate);
    }
}

/// Pure coverage for the epoch-commit metadata carry-forward rule. The commit
/// arm of `chat.assert_metadata_snapshot_mapping` is a DEFERRED trigger, so a
/// field it pins but the planner does not reject only fails at COMMIT, as a
/// 23514 storage error rather than a typed rejection.
#[cfg(test)]
mod commit_metadata_carry_forward_tests {
    use super::*;

    fn uuid_v4_bytes(byte: u8) -> [u8; 16] {
        let mut value = [byte; 16];
        value[6] = 0x40 | (byte & 0x0f);
        value[8] = 0x80 | (byte & 0x3f);
        value
    }

    fn coordinate() -> PublicGroupSnapshotCoordinate {
        PublicGroupSnapshotCoordinate::new(
            uuid_v4_bytes(0x11),
            0,
            1,
            [0x22; 32],
            0,
            [0x33; 32],
            [0x44; 32],
            PublicGroupSnapshotLifecycle::Active,
        )
    }

    fn metadata(nonce_byte: u8, ciphertext_len: usize) -> MetadataSnapshotBinding {
        let coordinate = coordinate();
        let ciphertext = vec![0x5a; ciphertext_len];
        let author = DeviceIdentity::new(
            PrincipalId::new(b"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".to_vec()).unwrap(),
            uuid_v4_bytes(0x55),
        )
        .unwrap();
        MetadataSnapshotBinding {
            coordinate: MetadataCryptoCoordinate {
                conversation_id: *coordinate.conversation_id(),
                generation: coordinate.generation(),
                group_id: *coordinate.group_id(),
                epoch: coordinate.epoch(),
                group_context_hash: *coordinate.group_context_hash(),
                confirmation_tag: *coordinate.confirmation_tag(),
            },
            origin_transition_id: uuid_v4_bytes(0x66),
            metadata_version: 4,
            nonce: [nonce_byte; 12],
            ciphertext_sha256: sha2::Sha256::digest(&ciphertext).into(),
            ciphertext,
            avatar_binding: None,
            author_proof: MetadataAuthorProofBinding {
                author,
                author_key_id: [0x77; 32],
                signature_public_key: [0x88; 32],
                auth_generation_at_origin: 3,
                origin_transition_id: uuid_v4_bytes(0x66),
                origin_seq: 1,
            },
            canonical_snapshot: Vec::new(),
            digest: [0x99; 32],
        }
    }

    /// A prior state carrying `prior_metadata`; only `metadata` is read here.
    fn prior_state(prior_metadata: MetadataSnapshotBinding) -> ConversationState {
        ConversationState {
            kind: ConversationKind::Direct,
            coordinate: coordinate(),
            producer: TransitionEvidence::for_test_at(
                1,
                uuid_v4_bytes(0xa1),
                [0xa1; 32],
                ServerTimestamp::from_unix_millis(1).unwrap(),
            )
            .unwrap(),
            public_state: None,
            metadata: Some(prior_metadata),
            metadata_producer: None,
            participants: Vec::new(),
            leaves: Vec::new(),
            intervals: Vec::new(),
            terminal_proofs: Vec::new(),
            recovery_requests: Vec::new(),
            recovery_reservations: Vec::new(),
            reset_requests: Vec::new(),
            leave_requests: Vec::new(),
            welcomes: Vec::new(),
        }
    }

    #[test]
    fn a_same_length_re_encryption_is_accepted() {
        let prior = prior_state(metadata(0x01, 48));
        assert!(commit_metadata_matches(
            &prior,
            &metadata(0x02, 48),
            &coordinate()
        ));
    }

    #[test]
    fn a_re_encryption_of_a_different_length_is_rejected() {
        // The DDL carries ciphertext_size forward IS NOT DISTINCT FROM the prior
        // snapshot, so this must be refused during planning rather than becoming
        // a deferred 23514 at COMMIT.
        let prior = prior_state(metadata(0x01, 48));
        assert!(!commit_metadata_matches(
            &prior,
            &metadata(0x02, 64),
            &coordinate()
        ));
        assert!(!commit_metadata_matches(
            &prior,
            &metadata(0x02, 32),
            &coordinate()
        ));
    }

    #[test]
    fn a_reused_nonce_is_still_rejected() {
        let prior = prior_state(metadata(0x01, 48));
        assert!(!commit_metadata_matches(
            &prior,
            &metadata(0x01, 48),
            &coordinate()
        ));
    }
}

#[cfg(test)]
mod direct_request_history_tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::{json, Value};

    fn vector(kind: &str) -> Value {
        let vectors: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/direct_request_vectors.json"
        ))
        .unwrap();
        vectors["signed"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["kind"] == kind)
            .unwrap()["body"]
            .clone()
    }
    fn publication_body(key: &SigningKey) -> Value {
        let mut body = vector("Publish");
        let key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(key.verifying_key().as_bytes()));
        body["keyId"] = json!(key_id);
        body["recipientDid"] = json!("did:plc:bbbbbbbbbbbbbbbbbbbbbbbb");
        body["next"]["stateVersion"] = json!(1);
        body["next"]["epoch"] = json!(1);
        let mut delivery = body["artifacts"]["welcome"]["deliveries"][0].clone();
        delivery["recipientDid"] = body["recipientDid"].clone();
        delivery["recipientDeviceId"] = json!("00000000-0000-4000-8000-000000000001");
        body["artifacts"]["welcome"]["deliveries"] = json!([delivery]);
        let next = body["next"].clone();
        let request = body["requestId"].clone();
        let metadata = &mut body["artifacts"]["metadataSnapshot"];
        metadata.as_object_mut().unwrap().remove("avatarBinding");
        metadata["coordinate"]["conversationId"] = json!(STANDARD.encode(
            uuid::Uuid::parse_str(next["conversationId"].as_str().unwrap())
                .unwrap()
                .as_bytes()
        ));
        metadata["coordinate"]["epoch"] = json!(1);
        metadata["originTransitionId"] = request.clone();
        metadata["metadataVersion"] = json!(1);
        let ciphertext = STANDARD
            .decode(metadata["ciphertext"].as_str().unwrap())
            .unwrap();
        metadata["ciphertextSize"] = json!(ciphertext.len());
        metadata["ciphertextSha256"] = json!(STANDARD.encode(Sha256::digest(ciphertext)));
        metadata["authorProof"]["authorKeyId"] = json!(key_id);
        metadata["authorProof"]["signaturePublicKey"] =
            json!(STANDARD.encode(key.verifying_key().as_bytes()));
        metadata["authorProof"]["originTransitionId"] = request;
        body
    }
    fn hydrate(
        body: Value,
        kind: &str,
        key: &SigningKey,
        seq: u64,
        expected_valid: bool,
    ) -> (TransitionEvidence, Vec<u8>, Vec<u8>) {
        use crate::chat_protocol::direct_request_transcript::{
            direct_request_signing_bytes, DirectRequestKind,
        };
        let direct_kind = if kind == "directRequestEntry" {
            DirectRequestKind::Publish
        } else {
            DirectRequestKind::Accept
        };
        let bytes =
            direct_request_signing_bytes(direct_kind, &serde_json::to_vec(&body).unwrap()).unwrap();
        let wrapper = json!({"body":body,"signature":STANDARD.encode(key.sign(&bytes).to_bytes())});
        let conversation = if kind == "directRequestEntry" {
            &wrapper["body"]["conversationId"]
        } else {
            &wrapper["body"]["prior"]["conversationId"]
        };
        let entry = json!({"$type":format!("blue.catbird.chat.defs#{kind}"),"entryId":"00000000-0000-4000-8000-000000000009","conversationId":conversation,"seq":seq,"signedRequest":wrapper,"receivedAt":"2026-09-19T12:00:00.000Z"});
        let row = serde_json::to_vec(&entry).unwrap();
        let signed = serde_json::to_vec(&wrapper).unwrap();
        // Dedicated admission remains mandatory; historical kinds are never v1 mutations.
        assert!(crate::chat_protocol::transcript::decode_canonical_signed_mutation(&signed).is_err());
        let authority = HistoricalRehydrationAuthority::new(
            *uuid::Uuid::parse_str(conversation.as_str().unwrap())
                .unwrap()
                .as_bytes(),
            seq + 1,
        )
        .unwrap();
        let evidence = authority
            .hydrate_historical_control_from_durable_bytes(
                row.clone(),
                signed.clone(),
                key.verifying_key().as_bytes(),
            )
            .unwrap()
            .into_transition()
            .unwrap();
        assert_eq!(validate_transition_evidence(&evidence), expected_valid);
        let mut wire = entry.clone();
        wire.as_object_mut().unwrap().remove("$type");
        let wire = serde_json::to_vec(&wire).unwrap();
        let expected = if kind == "directRequestEntry" {
            crate::chat_protocol::direct_request_transcript::direct_request_entry_hash(&wire).unwrap()
        } else {
            crate::chat_protocol::direct_request_transcript::direct_request_acceptance_entry_hash(&wire)
                .unwrap()
        };
        assert_eq!(evidence.outer_entry_fingerprint, expected);
        (evidence, row, signed)
    }

    #[test]
    fn future_signed_direct_request_publication_respects_admission_skew() {
        let key = SigningKey::from_bytes(&[7; 32]);
        for (signed_at, expected_valid) in [
            ("2026-09-19T12:00:45.000Z", true),
            ("2026-09-19T12:01:00.000Z", true),
            ("2026-09-19T12:01:00.001Z", false),
        ] {
            let mut body = publication_body(&key);
            body["signedAt"] = json!(signed_at);
            let (evidence, _, _) = hydrate(body, "directRequestEntry", &key, 1, expected_valid);
            if expected_valid {
                let mut tampered = evidence.clone();
                tampered.durable_row_digest = [0; 32];
                assert!(!validate_transition_evidence(&tampered));
            }
        }
    }
    #[test]
    fn direct_request_history_binds_metadata_pending_leaves_and_recipient_acceptance() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let body = publication_body(&key);
        let (publication, row, signed) = hydrate(body.clone(), "directRequestEntry", &key, 1, true);
        let Some(TransitionBodyBinding::DirectRequestPublication {
            next,
            recipient,
            devices,
            metadata,
            ..
        }) = publication.body_binding.as_ref()
        else {
            panic!("publication binding");
        };
        assert!(metadata_author_matches_evidence(metadata, &publication));
        let recipient_device = devices
            .iter()
            .find(|d| d.principal() == recipient)
            .unwrap()
            .clone();
        let inviter = publication.authority.as_ref().unwrap().actor.clone();
        let invitation = InvitationProvenance {
            transition: publication.clone(),
            inviter: inviter.clone(),
        };
        let mut participant = ParticipantRecord {
            principal: recipient.clone(),
            status: ParticipantStatus::Pending,
            role: ParticipantRole::Admin,
            role_producer: None,
            invitation: Some(invitation.clone()),
            acceptance: None,
        };
        assert!(invitation_matches_participant(
            ConversationKind::Direct,
            &participant,
            &invitation
        ));
        let interval = AccessInterval {
            recipient: recipient_device.clone(),
            generation: next.generation(),
            opening: publication.clone(),
            opening_kind: OpeningKind::DirectRequest,
            opening_context: *next,
            end: None,
        };
        assert!(opening_matches_interval(
            &interval,
            ConversationKind::Direct,
            next
        ));
        let mut state = ConversationState {
            kind: ConversationKind::Direct,
            coordinate: *next,
            producer: publication.clone(),
            public_state: None,
            metadata: Some(metadata.clone()),
            metadata_producer: Some(publication.clone()),
            participants: vec![],
            leaves: vec![],
            intervals: vec![interval],
            terminal_proofs: vec![],
            recovery_requests: vec![],
            recovery_reservations: vec![],
            reset_requests: vec![],
            leave_requests: vec![],
            welcomes: vec![],
        };
        let leaf = LeafRecord {
            device: recipient_device.clone(),
            leaf_index: 1,
            basic_credential: recipient_device.basic_credential(),
            signature_key: vec![1; 32],
            encryption_key: vec![2; 32],
            key_package_ref: Some([3; 32]),
        };
        // Exercise the complete production invariant gate with a test-only public
        // snapshot binding; crypto validity is covered by the separate real corpus.
        state.leaves = vec![
            LeafRecord {
                device: inviter.clone(),
                leaf_index: 0,
                basic_credential: inviter.basic_credential(),
                signature_key: key.verifying_key().as_bytes().to_vec(),
                encryption_key: vec![4; 32],
                key_package_ref: None,
            },
            leaf.clone(),
        ];
        state.participants = vec![
            ParticipantRecord {
                principal: inviter.principal().clone(),
                status: ParticipantStatus::Active,
                role: ParticipantRole::Admin,
                role_producer: None,
                invitation: None,
                acceptance: None,
            },
            participant.clone(),
        ];
        state.intervals.insert(
            0,
            AccessInterval {
                recipient: inviter.clone(),
                generation: next.generation(),
                opening: publication.clone(),
                opening_kind: OpeningKind::DirectRequest,
                opening_context: *next,
                end: None,
            },
        );
        let snapshot = vec![1, 2, 3];
        let tree = crate::chat_protocol::snapshot::PublicGroupSnapshotTreeSummary::new(
            [5; 32],
            state
                .leaves
                .iter()
                .map(|l| {
                    crate::chat_protocol::snapshot::PublicGroupSnapshotLeaf::new(
                        l.leaf_index,
                        l.basic_credential.clone(),
                        l.signature_key.clone(),
                        l.encryption_key.clone(),
                    )
                })
                .collect(),
        );
        let binding = crate::chat_protocol::snapshot::PublicGroupSnapshotBinding::new(
            *next.conversation_id(),
            next.generation(),
            next.state_version(),
            *next.group_id(),
            next.epoch(),
            *next.group_context_hash(),
            *next.confirmation_tag(),
            next.lifecycle(),
            Sha256::digest(&snapshot).into(),
            tree,
        );
        state.public_state =
            Some(ActivePublicState::for_test_from_persisted_binding(snapshot, binding).unwrap());
        assert!(validate_state(&state).is_ok());
        assert!(pending_request_leaf_is_bound(&state, &leaf));
        state.intervals[1].opening_kind = OpeningKind::Add;
        assert!(!pending_request_leaf_is_bound(&state, &leaf));
        state.intervals[1].opening_kind = OpeningKind::DirectRequest;
        let mut accept = vector("Accept");
        accept["actorDid"] = body["recipientDid"].clone();
        accept["actorDeviceId"] =
            json!(uuid::Uuid::from_bytes(*recipient_device.device_id()).to_string());
        accept["keyId"] = body["keyId"].clone();
        accept["prior"] = body["next"].clone();
        accept["next"] = body["next"].clone();
        accept["next"]["stateVersion"] = json!(2);
        accept["invitationProvenance"] = json!({"invitationTransitionId":body["requestId"],"invitedByDid":body["actorDid"],"invitedByDeviceId":body["actorDeviceId"]});
        let (accepted, _, _) = hydrate(accept, "directRequestAcceptanceEntry", &key, 2, true);
        state.coordinate = coordinate_only_successor(next).unwrap();
        state.producer = accepted.clone();
        participant.status = ParticipantStatus::Active;
        participant.acceptance = Some(accepted.clone());
        state.participants[1] = participant.clone();
        state.public_state = Some(ActivePublicState::for_test(
            state.public_state.as_ref().unwrap(),
            state.coordinate,
        ));
        assert!(validate_state(&state).is_ok());
        assert!(acceptance_matches_participant(
            &state,
            &participant,
            &invitation,
            &accepted
        ));
        assert!(current_state_producer_matches(&state));
        assert!(metadata_provenance_matches(&state));
        // A later accepted coordinate preserves provenance; no recovery request is fabricated.
        state.coordinate = coordinate_only_successor(&state.coordinate).unwrap();
        assert!(acceptance_matches_participant(
            &state,
            &participant,
            &invitation,
            &accepted
        ));
        assert!(opening_matches_interval(
            &state.intervals[0],
            ConversationKind::Direct,
            &state.coordinate
        ));
        // A normal v1 close after v2 acceptance keeps historical v2 evidence.
        let mut prior_json = body["next"].clone();
        prior_json["stateVersion"] = json!(2);
        let mut retired_json = prior_json.clone();
        retired_json["stateVersion"] = json!(3);
        retired_json["lifecycle"] = json!("superseded");
        let close_body = json!({"$type":"blue.catbird.chat.defs#conversationCloseBody","signatureDomain":"CATBIRD-CHAT-CLOSE\0","transitionId":"00000000-0000-4000-8000-000000000003","conversationKind":"direct","actorDid":body["actorDid"],"actorDeviceId":body["actorDeviceId"],"keyId":body["keyId"],"authGeneration":1,"prior":prior_json,"retired":retired_json,"idempotencyKey":"00000000-0000-4000-8000-000000000004","signedAt":body["signedAt"]});
        let mut wrapper = json!({"body":close_body,"signature":STANDARD.encode([0;64])});
        let canonical = crate::chat_protocol::transcript::decode_canonical_signed_mutation(
            &serde_json::to_vec(&wrapper).unwrap(),
        )
        .unwrap();
        wrapper["signature"] =
            json!(STANDARD.encode(key.sign(canonical.transcript_bytes()).to_bytes()));
        let close_row = json!({"$type":"blue.catbird.chat.defs#conversationCloseEntry","entryId":"00000000-0000-4000-8000-000000000005","conversationId":body["conversationId"],"seq":3,"signedRequest":wrapper,"receivedAt":body["signedAt"],"tombstone":{"conversationId":body["conversationId"],"conversationKind":"direct","retired":retired_json,"closedByDid":body["actorDid"],"closedByDeviceId":body["actorDeviceId"],"terminalSeq":3,"closedAt":body["signedAt"]}});
        let history = HistoricalRehydrationAuthority::new(*next.conversation_id(), 4).unwrap();
        let close = history
            .hydrate_historical_control_from_durable_bytes(
                serde_json::to_vec(&close_row).unwrap(),
                serde_json::to_vec(&wrapper).unwrap(),
                key.verifying_key().as_bytes(),
            )
            .unwrap()
            .into_transition()
            .unwrap();
        let Some(TransitionBodyBinding::ConversationClose { prior, retired, .. }) =
            close.body_binding.as_ref()
        else {
            panic!("close binding");
        };
        assert!(recovery_supersession_terminal_matches(
            &close,
            prior,
            close.received_at
        ));
        state.coordinate = *retired;
        state.producer = close.clone();
        state.public_state = None;
        state.leaves.clear();
        for interval in &mut state.intervals {
            interval.end = Some(AccessIntervalEnd {
                evidence: close.clone(),
                kind: CloseKind::Terminal,
            });
        }
        state.terminal_proofs = state
            .intervals
            .iter()
            .map(|i| ScheduleTerminalProof {
                recipient: i.recipient.clone(),
                conversation_id: *next.conversation_id(),
                evidence: close.clone(),
            })
            .collect();
        assert!(validate_terminal_state(&state).is_ok());
        // Frozen entry/head and exact-wrapper splice rejection.
        let authority = HistoricalRehydrationAuthority::new(*next.conversation_id(), 2).unwrap();
        let mut tampered: Value = serde_json::from_slice(&row).unwrap();
        tampered["seq"] = json!(2);
        assert!(authority
            .hydrate_historical_control_from_durable_bytes(
                serde_json::to_vec(&tampered).unwrap(),
                signed.clone(),
                key.verifying_key().as_bytes()
            )
            .is_err());
        let mut tampered: Value = serde_json::from_slice(&signed).unwrap();
        tampered["body"]["recipientDid"] = body["actorDid"].clone();
        assert!(authority
            .hydrate_historical_control_from_durable_bytes(
                row,
                serde_json::to_vec(&tampered).unwrap(),
                key.verifying_key().as_bytes()
            )
            .is_err());
    }
}
