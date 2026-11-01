use super::*;

#[cfg(test)]
mod authority_shape_tests {
    use super::*;

    fn cursor_device(seed: u8) -> DeviceIdentity {
        let mut device_id = [seed; 16];
        device_id[6] = (device_id[6] & 0x0f) | 0x40;
        device_id[8] = (device_id[8] & 0x3f) | 0x80;
        DeviceIdentity::new(
            PrincipalId::new(format!("did:plc:cursorproof{seed:02}xxxxxxxx").into_bytes())
                .expect("valid cursor DID"),
            device_id,
        )
        .expect("valid cursor device")
    }

    fn prepared_cursor_event(event_id: Uuid, slot: u32, payload: &[u8]) -> PreparedRevocationEvent {
        PreparedRevocationEvent::new(
            event_id,
            EventKind::ConversationChanged,
            payload.to_vec(),
            vec![PreparedRevocationRecipient {
                slot: EventChainSlot(slot),
                entitlement: EventEntitlementKind::Participant,
            }],
            vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        )
        .expect("valid prepared cursor event")
    }

    #[test]
    fn revocation_event_cursor_rejects_shape_and_state_mutations() {
        let first_id = Uuid::new_v4();
        let second_id = Uuid::new_v4();
        let first = prepared_cursor_event(first_id, 0, b"first");
        let second = prepared_cursor_event(second_id, 0, b"second");
        let devices = vec![cursor_device(1)];

        let mut cursor = EventChainCursor::new(
            [7; 32],
            devices.clone(),
            vec![Some(41)],
            vec![first.clone(), second.clone()],
        )
        .expect("valid cursor");
        let recipients = cursor.begin_event(&first).expect("first event begins");
        assert_eq!(recipients.len(), 1);
        assert_eq!(recipients[0].audience_predecessor_position, Some(41));
        assert!(matches!(
            cursor.begin_event(&first),
            Err(EventChainCursorError::EventAlreadyPending)
        ));
        assert!(matches!(
            cursor.complete_event(first_id, 41),
            Err(EventChainCursorError::PositionNotMonotonic)
        ));
        cursor
            .complete_event(first_id, 42)
            .expect("first event completes");
        assert!(matches!(
            cursor.finish_for_test(),
            Err(EventChainCursorError::IncompleteSchedule)
        ));
        let recipients = cursor.begin_event(&second).expect("second event begins");
        assert_eq!(
            recipients[0].audience_predecessor_position,
            Some(42),
            "the first prepared event must advance the shared device tail"
        );
        cursor
            .complete_event(second_id, 43)
            .expect("second event completes");
        cursor.finish().expect("complete schedule finishes");

        let mut reordered = EventChainCursor::new(
            [7; 32],
            devices.clone(),
            vec![Some(41)],
            vec![first.clone(), second.clone()],
        )
        .expect("valid cursor");
        assert!(matches!(
            reordered.begin_event(&second),
            Err(EventChainCursorError::UnexpectedEvent)
        ));

        let changed = prepared_cursor_event(first_id, 0, b"changed");
        let mut changed_cursor = EventChainCursor::new(
            [7; 32],
            devices.clone(),
            vec![Some(41)],
            vec![first.clone()],
        )
        .expect("valid cursor");
        assert!(matches!(
            changed_cursor.begin_event(&changed),
            Err(EventChainCursorError::EventShapeMismatch)
        ));

        let unknown = prepared_cursor_event(first_id, 1, b"first");
        assert!(matches!(
            EventChainCursor::new([7; 32], devices, vec![Some(41)], vec![unknown]),
            Err(EventChainCursorError::UnknownSlot)
        ));

        let duplicate = PreparedRevocationEvent::new(
            first_id,
            EventKind::ConversationChanged,
            b"first".to_vec(),
            vec![
                PreparedRevocationRecipient {
                    slot: EventChainSlot(0),
                    entitlement: EventEntitlementKind::Participant,
                },
                PreparedRevocationRecipient {
                    slot: EventChainSlot(0),
                    entitlement: EventEntitlementKind::Participant,
                },
            ],
            vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        );
        assert!(matches!(
            duplicate,
            Err(EventChainCursorError::DuplicateRecipient)
        ));

        let mut no_pending =
            EventChainCursor::new([7; 32], vec![cursor_device(1)], vec![None], vec![])
                .expect("empty schedule cursor");
        assert!(matches!(
            no_pending.complete_event(first_id, 1),
            Err(EventChainCursorError::NoPendingEvent)
        ));
    }

    #[test]
    fn revocation_event_cursor_preserves_exact_historical_welcome_recipient() {
        let current_participant = cursor_device(1);
        // This slot models an inactive/historical target device retained
        // solely because a pending Welcome names it exactly.
        let historical_welcome_recipient = cursor_device(2);
        let event_id = Uuid::new_v4();
        let outbox = vec![(Uuid::new_v4(), OutboxWorkKind::Stream)];
        let prepared = PreparedRevocationEvent::new(
            event_id,
            EventKind::WelcomeDisposition,
            b"exact historical Welcome".to_vec(),
            vec![PreparedRevocationRecipient {
                slot: EventChainSlot(1),
                entitlement: EventEntitlementKind::Welcome,
            }],
            outbox.clone(),
        )
        .expect("exact historical Welcome schedule");
        let live = EventFanout {
            event_id,
            event_kind: EventKind::WelcomeDisposition,
            payload_bytes: b"exact historical Welcome".to_vec(),
            recipients: vec![(
                historical_welcome_recipient.clone(),
                EventEntitlementKind::Welcome,
                Some(999), // Ignored: the locked prelude owns the true tail.
            )],
            outbox,
        };
        let mut cursor = EventChainCursor::new(
            [9; 32],
            vec![current_participant, historical_welcome_recipient.clone()],
            vec![Some(40), Some(73)],
            vec![prepared],
        )
        .expect("cursor retains historical Welcome recipient slot");
        let recipients = cursor
            .begin_fanout(&live)
            .expect("exact historical Welcome event matches");
        assert_eq!(recipients.len(), 1);
        assert_eq!(
            recipients[0].device_id,
            Uuid::from_bytes(*historical_welcome_recipient.device_id())
        );
        assert_eq!(
            recipients[0].entitlement_kind,
            EventEntitlementKind::Welcome
        );
        assert_eq!(recipients[0].audience_predecessor_position, Some(73));
        cursor.complete_event(event_id, 74).expect("event advances");
        cursor.finish().expect("exact Welcome schedule consumed");
    }

    #[test]
    fn transaction_identity_failure_requires_outer_abort() {
        assert!(ExecutorError::TransactionIdentity(sqlx::Error::RowNotFound).requires_outer_abort());
        assert!(!ExecutorError::TransactionBindingMismatch.requires_outer_abort());
    }

    #[test]
    fn welcome_expiry_authority_is_entryless_and_retains_exact_welcome_id() {
        let welcome_id =
            Uuid::parse_str("6d5b4f71-5ff3-4ac2-89a9-8bcfd1675e61").expect("fixed Welcome UUID");
        let authority = ExecutionAuthority::Entryless {
            operation_id: welcome_id,
        };

        let operation_id = require_execution_authority(PlanKind::WelcomeExpiry, &authority)
            .expect("Welcome expiry accepts exact entryless authority");

        assert_eq!(operation_id, welcome_id);
        assert!(
            authority.control_entry().is_none(),
            "server-authored expiry must carry no control content"
        );
    }

    #[test]
    fn entry_bearing_plan_rejects_entryless_authority() {
        let authority = ExecutionAuthority::Entryless {
            operation_id: Uuid::parse_str("78b7734f-7423-46a5-85f8-ac86a2527ee0")
                .expect("fixed operation UUID"),
        };

        assert!(matches!(
            require_execution_authority(PlanKind::Policy, &authority),
            Err(ExecutorError::MissingContext("control-entry authority"))
        ));
    }

    #[test]
    fn entryless_plan_rejects_control_entry_authority() {
        let authority = ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id: Uuid::parse_str("3afcbca2-89c9-4454-ae41-2450dac4f845")
                .expect("fixed entry UUID"),
            entry_kind: "blue.catbird.chat.defs#policyEntry".to_owned(),
            accepted_payload_bytes: vec![1],
            accepted_payload_sha256: vec![2; 32],
            signed_request_bytes: vec![3],
            unsigned_projection_bytes: vec![4],
            signing_transcript_bytes: vec![5],
            request_digest: vec![6; 32],
            signature: vec![7; 64],
            server_fields_bytes: vec![8],
            outer_entry_fingerprint: vec![9; 32],
        });

        assert!(matches!(
            require_execution_authority(PlanKind::DeviceRevocation, &authority),
            Err(ExecutorError::MissingContext(
                "entryless operation authority"
            ))
        ));
    }
}

#[cfg(any(
    test,
    all(
        feature = "chat-protocol-production-proof",
        not(feature = "server-bin")
    )
))]
pub(in crate::chat_protocol::state_machine::executor) mod metadata_executor_tests {
    use super::*;
    use crate::chat_protocol::state_machine::{
        AuthenticatedEntryEvidence, ConversationPersistencePlan, ConversationStateHydration,
        LeaveRequest, LeaveRequestHydrationRow, MetadataAvatarDescriptorBinding,
        MetadataCryptoCoordinate, MetadataSnapshotBinding, PackageTransition, PlanAuthority,
        PublicGroupSnapshotLifecycle, RecoveryOriginHydrationRow, RecoveryPackageCasBinding,
        RecoveryRequestHydrationRow, RecoveryReservationHydrationRow, RequestEntryKind,
        RequestEvidence, ResetRequestHydrationRow, StateChange, StateCounts, TransitionBodyBinding,
        TransitionEffects, WelcomeHydrationRow, WorkTerminalHydrationRow,
    };

    fn uuid(marker: u8) -> [u8; 16] {
        let mut value = [marker; 16];
        value[6] = 0x40 | (marker & 0x0f);
        value[8] = 0x80 | (marker & 0x3f);
        value
    }

    fn device(marker: u8) -> DeviceIdentity {
        DeviceIdentity::new(
            PrincipalId::new(format!("did:plc:metadataexecutor{marker:02x}aaaaaa").into_bytes())
                .expect("valid test DID"),
            uuid(marker),
        )
        .expect("valid test device")
    }

    fn coordinate(conversation_id: [u8; 16], state_version: u64) -> PublicGroupSnapshotCoordinate {
        PublicGroupSnapshotCoordinate::new(
            conversation_id,
            1,
            state_version,
            [0x31; 32],
            4,
            [0x32; 32],
            [0x33; 32],
            PublicGroupSnapshotLifecycle::Active,
        )
    }

    fn snapshot(
        coordinate: PublicGroupSnapshotCoordinate,
        transition_id: [u8; 16],
        seq: u64,
        actor: DeviceIdentity,
        key_id: [u8; 32],
        public_key: [u8; 32],
        version: u64,
        nonce: [u8; 12],
        avatar_binding: Option<MetadataAvatarDescriptorBinding>,
    ) -> MetadataSnapshotBinding {
        let ciphertext = vec![version as u8, 0x51, 0x52];
        let ciphertext_sha256 = sha2::Sha256::digest(&ciphertext).into();
        let canonical_snapshot = ciphertext.clone();
        MetadataSnapshotBinding {
            coordinate: MetadataCryptoCoordinate {
                conversation_id: *coordinate.conversation_id(),
                generation: coordinate.generation(),
                group_id: *coordinate.group_id(),
                epoch: coordinate.epoch(),
                group_context_hash: *coordinate.group_context_hash(),
                confirmation_tag: *coordinate.confirmation_tag(),
            },
            origin_transition_id: transition_id,
            metadata_version: version,
            nonce,
            ciphertext,
            ciphertext_sha256,
            avatar_binding,
            author_proof: crate::chat_protocol::state_machine::MetadataAuthorProofBinding {
                author: actor,
                author_key_id: key_id,
                signature_public_key: public_key,
                auth_generation_at_origin: 3,
                origin_transition_id: transition_id,
                origin_seq: seq,
            },
            digest: sha2::Sha256::digest(&canonical_snapshot).into(),
            canonical_snapshot,
        }
    }

    #[derive(Clone, Copy)]
    enum AvatarFixture {
        None,
        Fresh,
        Reuse,
    }

    #[derive(Clone, Copy)]
    enum DueExpiryFamily {
        Recovery,
        Reset,
        Leave,
        Welcome,
    }

    fn request_evidence(
        kind: RequestEntryKind,
        request_id: [u8; 16],
        actor: DeviceIdentity,
        conversation_id: [u8; 16],
        received_at: ServerTimestamp,
        key_id: [u8; 32],
    ) -> RequestEvidence {
        RequestEvidence {
            kind,
            control_entry_id: Some(uuid(0x70)),
            conversation_id,
            control_seq: Some(4),
            control_outer_entry_fingerprint: Some([0x71; 32]),
            control_outer_projection: Some(vec![0x72]),
            control_server_fields_dag_cbor: Some(vec![0x73]),
            request_id,
            actor,
            key_id,
            auth_generation: 3,
            request_digest: [0x74; 32],
            signature: [0x75; 64],
            signed_request_bytes: vec![0x76],
            durable_row_digest: [0x77; 32],
            received_at,
            authority: None,
            body_binding: None,
        }
    }

    fn avatar_descriptor() -> MetadataAvatarDescriptorBinding {
        let canonical_descriptor = vec![0xa4, 0x01, 0x02, 0x03];
        MetadataAvatarDescriptorBinding {
            blob_id: uuid(0x45),
            ciphertext_sha256: [0x46; 32],
            ciphertext_size: 64,
            digest: sha2::Sha256::digest(&canonical_descriptor).into(),
            canonical_descriptor,
        }
    }

    fn exact_fixture() -> (ConversationPersistencePlan, ExecutionContext) {
        exact_fixture_with_avatar(AvatarFixture::None)
    }

    fn exact_fixture_with_avatar(
        avatar_fixture: AvatarFixture,
    ) -> (ConversationPersistencePlan, ExecutionContext) {
        let conversation_id = uuid(0x21);
        let prior = coordinate(conversation_id, 7);
        let next = coordinate(conversation_id, 8);
        let actor = device(0x22);
        let prior_transition_id = uuid(0x23);
        let transition_id = uuid(0x24);
        let key_id = [0x25; 32];
        let public_key = [0x26; 32];
        let avatar = (!matches!(avatar_fixture, AvatarFixture::None)).then(avatar_descriptor);
        let prior_metadata = snapshot(
            prior,
            prior_transition_id,
            5,
            actor.clone(),
            key_id,
            public_key,
            1,
            [0x27; 12],
            matches!(avatar_fixture, AvatarFixture::Reuse)
                .then(|| avatar.clone().expect("reuse avatar")),
        );
        let next_metadata = snapshot(
            next,
            transition_id,
            6,
            actor.clone(),
            key_id,
            public_key,
            2,
            [0x28; 12],
            avatar.clone(),
        );
        let received_at = ServerTimestamp::from_unix_millis(6_000).unwrap();
        let mut producer = crate::chat_protocol::state_machine::TransitionEvidence::for_test_at(
            6,
            transition_id,
            [0x29; 32],
            received_at,
        )
        .unwrap();
        producer.authority = Some(AuthenticatedEntryEvidence {
            kind: SignedMutationKind::MetadataTransition,
            type_id: SignedMutationKind::MetadataTransition.type_id(),
            domain: SignedMutationKind::MetadataTransition.domain().to_vec(),
            control_entry_id: Some(transition_id),
            control_conversation_id: Some(conversation_id),
            actor: actor.clone(),
            key_id,
            auth_generation: 3,
            signed_at: received_at,
            request_digest: [0x2a; 32],
            signature: [0x2b; 64],
            signed_request_bytes: vec![0x2c],
            canonical_projection: vec![0x2d],
            transcript_bytes: vec![0x2e],
        });
        producer.body_binding = Some(TransitionBodyBinding::Metadata {
            prior,
            next,
            metadata: next_metadata.clone(),
        });
        producer.outer_control_projection = vec![0x2f];
        producer.server_fields_dag_cbor = vec![0x30];

        let mut effects = TransitionEffects::new(PlanKind::Metadata);
        effects.complete = true;
        effects.before_counts = StateCounts::default();
        effects.after_counts = StateCounts::default();
        effects.metadata_change = Some(StateChange {
            before: Some(prior_metadata),
            after: Some(next_metadata.clone()),
        });
        effects.authority = Some(PlanAuthority::Transition(producer.clone()));
        effects.head_cas = Some(
            crate::chat_protocol::state_machine::ConversationHeadCasBinding {
                transaction_id: "metadata-executor-test-tx".to_owned(),
                conversation_id,
                expected_prior: Some(prior),
                expected_next_entry_seq: 6,
                allocated_entry_id: Some(transition_id),
                allocated_seq: Some(6),
                successor_next_entry_seq: 7,
                locked_at: received_at,
                locked_head_digest: [0x34; 32],
            },
        );
        let plan = ConversationPersistencePlan {
            expected_prior: Some(prior),
            retired_coordinate: None,
            successor_coordinate: Some(next),
            state: ConversationStateHydration {
                kind: ConversationKind::Group,
                coordinate: next,
                producer: producer.clone(),
                public_state: None,
                metadata: Some(next_metadata),
                metadata_producer: Some(producer),
                participants: Vec::new(),
                leaves: Vec::new(),
                intervals: Vec::new(),
                terminal_proofs: Vec::new(),
                recovery_requests: Vec::new(),
                recovery_reservations: Vec::new(),
                reset_requests: Vec::new(),
                leave_requests: Vec::new(),
                welcomes: Vec::new(),
            },
            effects,
        };
        let key_id_text = URL_SAFE_NO_PAD.encode(key_id);
        let actor_did = String::from_utf8(actor.principal().as_bytes().to_vec()).unwrap();
        let applied_at = DateTime::<Utc>::from_timestamp_millis(received_at.unix_millis()).unwrap();
        let metadata_avatar = avatar.as_ref().map(|signed_avatar| {
            let snapshot = MetadataAvatarBinding {
                avatar_blob_id: Uuid::from_bytes(*signed_avatar.blob_id()),
                avatar_ciphertext_sha256: signed_avatar.ciphertext_sha256().to_vec(),
                avatar_ciphertext_size: i64::try_from(signed_avatar.ciphertext_size())
                    .expect("fixture avatar size"),
                avatar_binding_origin_transition_id: Uuid::from_bytes(
                    if matches!(avatar_fixture, AvatarFixture::Reuse) {
                        prior_transition_id
                    } else {
                        transition_id
                    },
                ),
                avatar_binding_metadata_version: if matches!(avatar_fixture, AvatarFixture::Reuse) {
                    1
                } else {
                    2
                },
                avatar_binding_owner_did: actor_did.clone(),
                avatar_binding_owner_device_id: Uuid::from_bytes(*actor.device_id()),
            };
            if matches!(avatar_fixture, AvatarFixture::Reuse) {
                MetadataAvatarPersistence::Reuse { snapshot }
            } else {
                MetadataAvatarPersistence::Fresh { snapshot }
            }
        });
        let context = ExecutionContext {
                protocol_instance_id: Uuid::from_bytes(uuid(0x35)),
                applied_at,
                actor: ExecutionActor {
                    user_did: actor_did,
                    device_id: Uuid::from_bytes(*actor.device_id()),
                    key_id: key_id_text.clone(),
                    auth_generation: 3,
                    role: TransitionActorRole::Admin,
                    device_status: "active".to_owned(),
                },
                authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
                    entry_id: Uuid::from_bytes(transition_id),
                    entry_kind: "blue.catbird.chat.defs#transitionEntry".to_owned(),
                    accepted_payload_bytes: vec![0x36],
                    accepted_payload_sha256: vec![0x37; 32],
                    signed_request_bytes: vec![0x2c],
                    unsigned_projection_bytes: vec![0x2d],
                    signing_transcript_bytes: vec![0x2e],
                    request_digest: vec![0x2a; 32],
                    signature: vec![0x2b; 64],
                    server_fields_bytes: vec![0x30],
                    outer_entry_fingerprint: vec![0x29; 32],
                }),
                spine: SpineArtifacts {
                    public_snapshot_bytes: vec![0x38],
                    public_snapshot_sha256: sha2::Sha256::digest([0x38]).to_vec(),
                    tree_summary_bytes: vec![0x39],
                    tree_summary_sha256: sha2::Sha256::digest([0x39]).to_vec(),
                    leaf_count: 0,
                    genesis_group_info_bytes: Vec::new(),
                    genesis_group_info_sha256: Vec::new(),
                },
                opened_leaves: Vec::new(),
                metadata_author: Some(MetadataAuthorColumns {
                    author_role: "admin".to_owned(),
                    author_device_status: "active".to_owned(),
                    author_public_key: public_key.to_vec(),
                    author_key_id: key_id_text,
                    metadata_snapshot_id: Uuid::from_bytes(uuid(0x3a)),
                }),
                metadata_avatar,
                participant_period_ids: Vec::new(),
                leaf_period_ids: Vec::new(),
                is_remote: false,
                sequencer_ds: None,
                sequencer_term: 0,
                participant_ds_dids: std::collections::HashMap::new(),
                entry_recipients: Vec::new(),
                events: vec![EventFanout {
                    event_id: Uuid::from_bytes(uuid(0x3b)),
                    event_kind: EventKind::ConversationChanged,
                    payload_bytes: format!(
                        r#"{{"$type":"blue.catbird.chat.defs#conversationChangedEvent","conversationId":"{}"}}"#,
                        Uuid::from_bytes(conversation_id).hyphenated(),
                    )
                    .into_bytes(),
                    recipients: Vec::new(),
                    outbox: vec![(Uuid::from_bytes(uuid(0x3c)), OutboxWorkKind::Stream)],
                }],
                closing_leaf_periods: Vec::new(),
                closing_participant_periods: Vec::new(),
                reset_request_row: None,
                recovery_open: None,
                welcome_expiry: None,
                welcome_response: None,
                welcome_dispositions: Vec::new(),
            };
        (plan, context)
    }

    fn mutate_all_inner_metadata_coordinates(
        plan: &mut ConversationPersistencePlan,
        group_id: Option<[u8; 32]>,
        confirmation_tag: Option<[u8; 32]>,
    ) -> usize {
        fn mutate(
            metadata: &mut MetadataSnapshotBinding,
            group_id: Option<[u8; 32]>,
            confirmation_tag: Option<[u8; 32]>,
        ) {
            if let Some(group_id) = group_id {
                metadata.coordinate.group_id = group_id;
            }
            if let Some(confirmation_tag) = confirmation_tag {
                metadata.coordinate.confirmation_tag = confirmation_tag;
            }
        }

        let mut copies = 0;
        mutate(
            plan.effects
                .metadata_change
                .as_mut()
                .and_then(|change| change.after.as_mut())
                .expect("metadata delta after binding"),
            group_id,
            confirmation_tag,
        );
        copies += 1;
        let PlanAuthority::Transition(evidence) = plan
            .effects
            .authority
            .as_mut()
            .expect("metadata plan authority")
        else {
            panic!("metadata plan authority is a transition");
        };
        let Some(TransitionBodyBinding::Metadata { metadata, .. }) = evidence.body_binding.as_mut()
        else {
            panic!("metadata plan authority has a metadata body");
        };
        mutate(metadata, group_id, confirmation_tag);
        copies += 1;
        mutate(
            plan.state
                .metadata
                .as_mut()
                .expect("hydrated metadata binding"),
            group_id,
            confirmation_tag,
        );
        copies += 1;
        for evidence in [
            &mut plan.state.producer,
            plan.state
                .metadata_producer
                .as_mut()
                .expect("metadata producer"),
        ] {
            let Some(TransitionBodyBinding::Metadata { metadata, .. }) =
                evidence.body_binding.as_mut()
            else {
                panic!("metadata producer has a metadata body");
            };
            mutate(metadata, group_id, confirmation_tag);
            copies += 1;
        }
        copies
    }

    fn exact_due_expiry_fixture(
        family: DueExpiryFamily,
    ) -> (ConversationPersistencePlan, ExecutionContext, FamilyCounts) {
        let (mut plan, mut context) = exact_fixture();
        let prior = plan.expected_prior.expect("metadata prior");
        let actor = plan
            .effects
            .authority
            .as_ref()
            .and_then(|authority| match authority {
                PlanAuthority::Transition(transition) => transition.authority.as_ref(),
                _ => None,
            })
            .expect("metadata actor authority")
            .actor
            .clone();
        let received_at = ServerTimestamp::from_unix_millis(4_000).unwrap();
        let expires_at = ServerTimestamp::from_unix_millis(5_000).unwrap();
        // Production relation, not the boundary. MIN_KEY_PACKAGE_REMAINING_SECONDS
        // (600) strictly exceeds RECOVERY_RESERVATION_TTL_MILLIS (300_000) and the
        // floor is re-enforced at CLAIM time against claimed_at
        // (repository/core.rs:2994, :3397), so a claimed package always outlives its
        // reservation. A fixture with package_not_after == expires_at sits exactly on
        // `terminal_time >= after.package_not_after` (:9984) and makes the planner
        // emit Reserved -> Expired — a shape production cannot produce.
        let package_not_after = ServerTimestamp::from_unix_millis(305_000).unwrap();
        let terminal = Some(WorkTerminalEvidence::Expiry(expires_at));
        let mut expected = FamilyCounts {
            requests: 0,
            reservations: 0,
            packages: 0,
            welcomes: 0,
            reset_requests: 0,
            leave_requests: 0,
        };

        match family {
            DueExpiryFamily::Recovery => {
                let request_id = uuid(0x60);
                let key_package_ref = [0x61; 32];
                let origin_key_id = [0x62; 32];
                let origin = request_evidence(
                    RequestEntryKind::LeafRecoveryRequest,
                    request_id,
                    actor.clone(),
                    *prior.conversation_id(),
                    received_at,
                    origin_key_id,
                );
                let before_request = RecoveryRequest {
                    request_id,
                    target: actor.clone(),
                    kind: LeafRecoveryKind::Add,
                    source: RecoverySource::Request,
                    bound_coordinate: prior,
                    key_package_ref,
                    received_at,
                    expires_at,
                    status: RecoveryRequestStatus::Open,
                    origin: RecoveryOriginEvidence::Request(origin.clone()),
                    terminal: None,
                };
                let mut after_request = before_request.clone();
                after_request.status = RecoveryRequestStatus::Expired;
                after_request.terminal = terminal.clone();
                let before_reservation = RecoveryReservation {
                    request_id,
                    target: actor.clone(),
                    bound_coordinate: prior,
                    key_package_ref,
                    received_at,
                    expires_at,
                    package_not_after,
                    status: ReservationStatus::Active,
                    terminal: None,
                };
                let mut after_reservation = before_reservation.clone();
                after_reservation.status = ReservationStatus::Expired;
                after_reservation.terminal = terminal;
                plan.effects.recovery_request_changes.push(StateChange {
                    before: Some(before_request),
                    after: Some(after_request.clone()),
                });
                plan.effects.reservation_changes.push(StateChange {
                    before: Some(before_reservation),
                    after: Some(after_reservation.clone()),
                });
                plan.effects.package_transitions.push(PackageTransition {
                    request_id,
                    key_package_ref,
                    from: PackageStatus::Reserved,
                    // Production shape: terminal_time (expires_at) is strictly
                    // before package_not_after, so the real selector at :9984
                    // yields Available. Tests that need the unproducible
                    // Reserved -> Expired mutate this deliberately.
                    to: PackageStatus::Available,
                });
                let mut package_cas = RecoveryPackageCasBinding {
                    transaction_id: plan
                        .effects
                        .head_cas
                        .as_ref()
                        .expect("metadata head")
                        .transaction_id
                        .clone(),
                    conversation_id: *prior.conversation_id(),
                    request_id,
                    target: actor,
                    target_key_id: origin_key_id,
                    target_auth_generation: 3,
                    bound_coordinate: prior,
                    key_package_ref,
                    key_package_wrapper_sha256: [0x63; 32],
                    package_not_after,
                    claimed_at: received_at,
                    expected_status: PackageStatus::Reserved,
                    successor_status: PackageStatus::Available,
                    locked_row_digest: [0x64; 32],
                    authority_digest: [0; 32],
                };
                package_cas.authority_digest = recovery_package_cas_authority_digest(&package_cas);
                plan.effects.recovery_package_cas.push(package_cas);
                plan.state
                    .recovery_requests
                    .push(RecoveryRequestHydrationRow {
                        request_id: after_request.request_id,
                        target: after_request.target,
                        kind: after_request.kind,
                        source: after_request.source,
                        bound_coordinate: after_request.bound_coordinate,
                        key_package_ref: after_request.key_package_ref,
                        received_at: after_request.received_at,
                        expires_at: after_request.expires_at,
                        status: after_request.status,
                        origin: RecoveryOriginHydrationRow::Request(origin),
                        terminal: Some(WorkTerminalHydrationRow::Expiry(expires_at)),
                    });
                plan.state
                    .recovery_reservations
                    .push(RecoveryReservationHydrationRow {
                        request_id: after_reservation.request_id,
                        target: after_reservation.target,
                        bound_coordinate: after_reservation.bound_coordinate,
                        key_package_ref: after_reservation.key_package_ref,
                        received_at: after_reservation.received_at,
                        expires_at: after_reservation.expires_at,
                        package_not_after: after_reservation.package_not_after,
                        status: after_reservation.status,
                        terminal: Some(WorkTerminalHydrationRow::Expiry(expires_at)),
                    });
                expected.requests = 1;
                expected.reservations = 1;
                expected.packages = 1;
            }
            DueExpiryFamily::Reset => {
                let request_id = uuid(0x65);
                let origin = request_evidence(
                    RequestEntryKind::ResetRequest,
                    request_id,
                    actor.clone(),
                    *prior.conversation_id(),
                    received_at,
                    [0x66; 32],
                );
                let before = ResetRequest {
                    request_id,
                    requester: actor,
                    bound_coordinate: prior,
                    received_at,
                    expires_at,
                    status: ResetRequestStatus::Pending,
                    origin: origin.clone(),
                    terminal: None,
                };
                let mut after = before.clone();
                after.status = ResetRequestStatus::Expired;
                after.terminal = terminal;
                plan.effects.reset_request_changes.push(StateChange {
                    before: Some(before),
                    after: Some(after.clone()),
                });
                plan.state.reset_requests.push(ResetRequestHydrationRow {
                    request_id: after.request_id,
                    requester: after.requester,
                    bound_coordinate: after.bound_coordinate,
                    received_at: after.received_at,
                    expires_at: after.expires_at,
                    status: after.status,
                    origin,
                    terminal: Some(WorkTerminalHydrationRow::Expiry(expires_at)),
                });
                expected.reset_requests = 1;
            }
            DueExpiryFamily::Leave => {
                let request_id = uuid(0x67);
                let origin = request_evidence(
                    RequestEntryKind::LeaveRequest,
                    request_id,
                    actor.clone(),
                    *prior.conversation_id(),
                    received_at,
                    [0x68; 32],
                );
                let before = LeaveRequest {
                    request_id,
                    requester: actor,
                    bound_coordinate: prior,
                    received_at,
                    expires_at,
                    status: LeaveRequestStatus::Pending,
                    origin: origin.clone(),
                    terminal: None,
                    fulfilled_participant: None,
                };
                let mut after = before.clone();
                after.status = LeaveRequestStatus::Expired;
                after.terminal = terminal;
                plan.effects.leave_request_changes.push(StateChange {
                    before: Some(before),
                    after: Some(after.clone()),
                });
                plan.state.leave_requests.push(LeaveRequestHydrationRow {
                    request_id: after.request_id,
                    requester: after.requester,
                    bound_coordinate: after.bound_coordinate,
                    received_at: after.received_at,
                    expires_at: after.expires_at,
                    status: after.status,
                    origin,
                    terminal: Some(WorkTerminalHydrationRow::Expiry(expires_at)),
                    fulfilled_participant: None,
                });
                expected.leave_requests = 1;
            }
            DueExpiryFamily::Welcome => {
                let welcome_id = uuid(0x69);
                let key_package_ref = [0x6a; 32];
                let opaque_welcome = vec![0x6b, 0x6c];
                let before = WelcomeWork {
                    welcome_id,
                    recipient: actor.clone(),
                    transition_seq: 5,
                    coordinate: prior,
                    recovery_request_id: uuid(0x6d),
                    key_package_ref,
                    sha256: sha2::Sha256::digest(&opaque_welcome).into(),
                    opaque_welcome,
                    expires_at,
                    status: WelcomeStatus::Pending,
                    terminal: None,
                };
                let mut after = before.clone();
                after.status = WelcomeStatus::Expired;
                after.terminal = terminal;
                plan.effects.welcome_changes.push(StateChange {
                    before: Some(before),
                    after: Some(after.clone()),
                });
                plan.state.welcomes.push(WelcomeHydrationRow {
                    welcome_id: after.welcome_id,
                    recipient: after.recipient.clone(),
                    transition_seq: after.transition_seq,
                    coordinate: after.coordinate,
                    recovery_request_id: after.recovery_request_id,
                    key_package_ref: after.key_package_ref,
                    opaque_welcome: after.opaque_welcome,
                    sha256: after.sha256,
                    expires_at: after.expires_at,
                    status: after.status,
                    terminal: Some(WorkTerminalHydrationRow::Expiry(expires_at)),
                });
                let event_id = Uuid::from_bytes(uuid(0x6e));
                let outbox_id = Uuid::from_bytes(uuid(0x6f));
                context.welcome_dispositions.push(WelcomeDispositionInput {
                    welcome_id: Uuid::from_bytes(welcome_id),
                    // A `Pending->Expired` delta: the recovery work id is part of
                    // its exact shape.
                    recovery_work_id: Some(Uuid::from_bytes(uuid(0x70))),
                    event: EventFanout {
                        event_id,
                        event_kind: EventKind::WelcomeDisposition,
                        payload_bytes: delivery::canonical_welcome_disposition_event_payload(
                            Uuid::from_bytes(welcome_id),
                            "expired",
                        ),
                        recipients: vec![(actor, EventEntitlementKind::Welcome, None)],
                        outbox: vec![(outbox_id, OutboxWorkKind::Stream)],
                    },
                });
                expected.welcomes = 1;
            }
        }

        (plan, context, expected)
    }

    #[test]
    fn metadata_preflight_accepts_the_exact_sealed_transition_and_author() {
        let (plan, context) = exact_fixture();

        let binding =
            preflight_metadata_transition(&plan, &context, Uuid::from_bytes(uuid(0x24)), 6)
                .expect("exact metadata transition must be executable");

        assert_eq!(binding.metadata.metadata_version(), 2);
        assert_eq!(
            binding.author.metadata_snapshot_id,
            Uuid::from_bytes(uuid(0x3a))
        );
    }

    #[test]
    fn metadata_preflight_accepts_exact_fresh_and_reused_avatars() {
        for avatar_fixture in [AvatarFixture::Fresh, AvatarFixture::Reuse] {
            let (plan, context) = exact_fixture_with_avatar(avatar_fixture);
            let binding =
                preflight_metadata_transition(&plan, &context, Uuid::from_bytes(uuid(0x24)), 6)
                    .expect("exact avatar persistence must be executable");
            assert!(binding.avatar.is_some());
        }
    }

    #[test]
    fn metadata_preflight_accepts_due_expiry_families_and_rejects_reserved_to_expired() {
        // INVERTED at the C2 prior-bound correction. This assertion previously
        // accepted all four families, including a Recovery family carrying a
        // `Reserved -> Expired` package edge. Amended design 4.3/4.4 rejects
        // that edge for prior-bound families: it is production-unproducible
        // (MIN_KEY_PACKAGE_REMAINING 600s strictly exceeds
        // RECOVERY_RESERVATION_TTL 300s, so `recovery_expiry`'s `.min()` never
        // clamps) while every reader still accepted it. Closing that
        // writer-cannot-produce / reader-still-accepts asymmetry is the point
        // of the correction, so this assertion must invert.
        // The fixture now emits the PRODUCTION shape (Reserved -> Available), so the
        // unproducible edge has to be constructed deliberately — which is the honest
        // way to assert that it is rejected.
        let (mut plan, context, _) = exact_due_expiry_fixture(DueExpiryFamily::Recovery);
        for edge in plan.effects.package_transitions.iter_mut() {
            if edge.to == PackageStatus::Available {
                edge.to = PackageStatus::Expired;
            }
        }
        for binding in plan.effects.recovery_package_cas.iter_mut() {
            if binding.successor_status == PackageStatus::Available {
                binding.successor_status = PackageStatus::Expired;
                binding.authority_digest = [0; 32];
                binding.authority_digest = recovery_package_cas_authority_digest(binding);
            }
        }
        match preflight_metadata_transition(&plan, &context, Uuid::from_bytes(uuid(0x24)), 6) {
            Err(ExecutorError::InconsistentPlan(_)) => {}
            Ok(_) => panic!("Reserved -> Expired prior-bound package edge was accepted"),
            Err(error) => {
                panic!("Reserved -> Expired rejected with the wrong error: {error:?}")
            }
        }

        for family in [
            DueExpiryFamily::Reset,
            DueExpiryFamily::Leave,
            DueExpiryFamily::Welcome,
        ] {
            let (plan, context, expected) = exact_due_expiry_fixture(family);
            preflight_metadata_transition(&plan, &context, Uuid::from_bytes(uuid(0x24)), 6)
                .expect("exact due-expiry family must be executable");
            reconcile_coordinate_change_families(
                plan.effects(),
                &FamilyCounts {
                    requests: 0,
                    reservations: 0,
                    packages: 0,
                    welcomes: 0,
                    reset_requests: 0,
                    leave_requests: 0,
                },
                &expected,
            )
            .expect("due-expiry family must reconcile without a silent drop");
        }
    }

    /// REGRESSION — the Row B legality proof for the C2 prior-bound correction.
    ///
    /// A due-expiry family whose package returns to `Available` is legal
    /// prior-bound work, and it is what the planner actually emits.
    ///
    /// SCOPE, stated honestly: this exercises `preflight_metadata_transition`, the
    /// ONE arm that always accepted the shape — it passes at sealed e98 too. It is a
    /// non-regression check on the extraction, NOT proof for the other eight arms.
    /// The arms that used to reject this shape are covered by
    /// `fulfillment_arm_tolerates_an_overdue_peer_recovery_family` and
    /// `prior_bound_only_arm_accepts_a_row_b_family`.
    #[test]
    fn prior_bound_row_b_due_expiry_is_accepted_with_a_release_edge() {
        let (plan, context, expected) = exact_due_expiry_fixture(DueExpiryFamily::Recovery);

        // No hand-patching: the fixture already carries the production shape.
        preflight_metadata_transition(&plan, &context, Uuid::from_bytes(uuid(0x24)), 6)
            .expect("a legal Row B due-expiry family must be executable");
        reconcile_coordinate_change_families(
            plan.effects(),
            &FamilyCounts {
                requests: 0,
                reservations: 0,
                packages: 0,
                welcomes: 0,
                reset_requests: 0,
                leave_requests: 0,
            },
            &expected,
        )
        .expect("Row B must reconcile without a silent drop");
    }

    /// Builds one complete prior-bound recovery family (request + reservation +
    /// package edge + sealed CAS binding) onto an existing plan.
    #[allow(clippy::too_many_arguments)]
    fn push_recovery_family(
        plan: &mut ConversationPersistencePlan,
        prior: PublicGroupSnapshotCoordinate,
        actor: DeviceIdentity,
        request_id: [u8; 16],
        key_package_ref: [u8; 32],
        origin_key_id: [u8; 32],
        locked_row_digest: [u8; 32],
        received_at: ServerTimestamp,
        expires_at: ServerTimestamp,
        package_not_after: ServerTimestamp,
        after_request_status: RecoveryRequestStatus,
        after_reservation_status: ReservationStatus,
        terminal: Option<WorkTerminalEvidence>,
        package_to: PackageStatus,
    ) {
        let origin = request_evidence(
            RequestEntryKind::LeafRecoveryRequest,
            request_id,
            actor.clone(),
            *prior.conversation_id(),
            received_at,
            origin_key_id,
        );
        let before_request = RecoveryRequest {
            request_id,
            target: actor.clone(),
            kind: LeafRecoveryKind::Add,
            source: RecoverySource::Request,
            bound_coordinate: prior,
            key_package_ref,
            received_at,
            expires_at,
            status: RecoveryRequestStatus::Open,
            origin: RecoveryOriginEvidence::Request(origin),
            terminal: None,
        };
        let mut after_request = before_request.clone();
        after_request.status = after_request_status;
        after_request.terminal = terminal.clone();
        let before_reservation = RecoveryReservation {
            request_id,
            target: actor.clone(),
            bound_coordinate: prior,
            key_package_ref,
            received_at,
            expires_at,
            package_not_after,
            status: ReservationStatus::Active,
            terminal: None,
        };
        let mut after_reservation = before_reservation.clone();
        after_reservation.status = after_reservation_status;
        after_reservation.terminal = terminal;
        plan.effects.recovery_request_changes.push(StateChange {
            before: Some(before_request),
            after: Some(after_request),
        });
        plan.effects.reservation_changes.push(StateChange {
            before: Some(before_reservation),
            after: Some(after_reservation),
        });
        plan.effects.package_transitions.push(PackageTransition {
            request_id,
            key_package_ref,
            from: PackageStatus::Reserved,
            to: package_to,
        });
        let mut package_cas = RecoveryPackageCasBinding {
            transaction_id: plan
                .effects
                .head_cas
                .as_ref()
                .expect("head cas")
                .transaction_id
                .clone(),
            conversation_id: *prior.conversation_id(),
            request_id,
            target: actor,
            target_key_id: origin_key_id,
            target_auth_generation: 3,
            bound_coordinate: prior,
            key_package_ref,
            key_package_wrapper_sha256: [0x63; 32],
            package_not_after,
            claimed_at: received_at,
            expected_status: PackageStatus::Reserved,
            successor_status: package_to,
            locked_row_digest,
            authority_digest: [0; 32],
        };
        package_cas.authority_digest = recovery_package_cas_authority_digest(&package_cas);
        plan.effects.recovery_package_cas.push(package_cas);
    }

    /// REGRESSION FOR DEFECT 2 — the permanent device wedge.
    ///
    /// `preflight_leaf_recovery_fulfillment` demanded
    /// `terminal_is_exact_transition` of EVERY recovery request and reservation on
    /// the coordinate, so a peer's overdue `Expiry` terminal fell through to the
    /// `_ => illegal direction` arm. Open recovery requests are unique per TARGET
    /// and coordinate-preserving, so peers legitimately stack requests on one
    /// coordinate with staggered `expires_at`. Fulfilling one device while a peer's
    /// request was overdue therefore produced a planner-valid, executor-fatal plan —
    /// and the recovering device wedged PERMANENTLY, because retry re-planned the
    /// identical shape.
    ///
    /// This exercises the classifier that now owns that logic, with exactly the
    /// shape that used to wedge: one own family closing by this producer's
    /// transition, plus one overdue peer family closing by due expiry.
    #[test]
    fn fulfillment_arm_tolerates_an_overdue_peer_recovery_family() {
        let (mut plan, context) = exact_fixture();
        let prior = plan.expected_prior.expect("prior");
        let actor = plan
            .effects
            .authority
            .as_ref()
            .and_then(|authority| match authority {
                PlanAuthority::Transition(transition) => transition.authority.as_ref(),
                _ => None,
            })
            .expect("actor authority")
            .actor
            .clone();
        let producer = plan.state.producer.clone();
        let received_at = ServerTimestamp::from_unix_millis(4_000).unwrap();
        let expires_at = ServerTimestamp::from_unix_millis(5_000).unwrap();
        // Production relation, not the boundary. MIN_KEY_PACKAGE_REMAINING_SECONDS
        // (600) strictly exceeds RECOVERY_RESERVATION_TTL_MILLIS (300_000) and the
        // floor is re-enforced at CLAIM time against claimed_at
        // (repository/core.rs:2994, :3397), so a claimed package always outlives its
        // reservation. A fixture with package_not_after == expires_at sits exactly on
        // `terminal_time >= after.package_not_after` (:9984) and makes the planner
        // emit Reserved -> Expired — a shape production cannot produce.
        let package_not_after = ServerTimestamp::from_unix_millis(305_000).unwrap();

        let own_request_id = uuid(0x60);
        let own_ref = [0x61; 32];
        push_recovery_family(
            &mut plan,
            prior,
            actor.clone(),
            own_request_id,
            own_ref,
            [0x62; 32],
            [0x64; 32],
            received_at,
            expires_at,
            package_not_after,
            RecoveryRequestStatus::Fulfilled,
            ReservationStatus::Consumed,
            Some(WorkTerminalEvidence::Transition(producer)),
            PackageStatus::Consumed,
        );

        // The overdue peer. Different target key/ref, closing by due expiry.
        let peer_request_id = uuid(0x66);
        let peer_ref = [0x67; 32];
        push_recovery_family(
            &mut plan,
            prior,
            actor,
            peer_request_id,
            peer_ref,
            [0x68; 32],
            [0x69; 32],
            received_at,
            expires_at,
            package_not_after,
            RecoveryRequestStatus::Expired,
            ReservationStatus::Expired,
            Some(WorkTerminalEvidence::Expiry(expires_at)),
            PackageStatus::Available,
        );

        // Drive the REAL ARM, not just the extracted classifier. Defect 2 lived in
        // `preflight_leaf_recovery_fulfillment`, which had zero test callers — that
        // absence is why the wedge shipped.
        //
        // SCOPE, stated honestly: this plan is metadata-shaped, so the arm cannot
        // reach Ok — it needs an own pending Welcome it does not carry. What this
        // asserts is exactly the property Defect 2 broke: with an overdue peer
        // present, the arm passes prior-bound classification and reaches a LATER,
        // unrelated guard. Any prior-bound rejection yields a different message and
        // fails this assertion, which is what makes it discriminating.
        match preflight_leaf_recovery_fulfillment(
            &plan,
            plan.effects(),
            plan.state(),
            &context,
            Uuid::from_bytes(uuid(0x24)),
            6,
        ) {
            Err(ExecutorError::InconsistentPlan(message)) => assert_eq!(
                message, "fulfillment carries no own pending welcome",
                "the arm must get PAST prior-bound classification with an overdue \
                     peer present; a prior-bound error here means the wedge is back"
            ),
            Ok(_) => panic!("metadata-shaped plan unexpectedly satisfied the whole arm"),
            Err(error) => panic!("arm failed with an unexpected error: {error:?}"),
        }

        let partition =
            classify_prior_bound_recovery(&plan, &context, OwnFamilyKind::LeafRecoveryFulfillment)
                .expect("classifier agrees with the arm");

        assert_eq!(
            partition.own(),
            Some((own_request_id, own_ref)),
            "the own family must be the fulfilled one, derived by typed shape"
        );
        assert_eq!(
            partition.requests(),
            1,
            "the overdue peer must be classified as prior-bound work, not dropped"
        );
        assert!(
            partition.keys().contains(&(peer_request_id, peer_ref)),
            "the peer family key must be carried to the writer"
        );
    }

    /// The correction must not become permissive in the other direction: the OWN
    /// family closes by THIS producer's transition, never by due expiry. If an own
    /// family could carry an `Expiry` terminal it would be indistinguishable from
    /// prior-bound peer work, and the arm would consume a family it does not own.
    #[test]
    fn fulfillment_own_family_may_not_close_by_due_expiry() {
        let (mut plan, context) = exact_fixture();
        let prior = plan.expected_prior.expect("prior");
        let actor = plan
            .effects
            .authority
            .as_ref()
            .and_then(|authority| match authority {
                PlanAuthority::Transition(transition) => transition.authority.as_ref(),
                _ => None,
            })
            .expect("actor authority")
            .actor
            .clone();
        let received_at = ServerTimestamp::from_unix_millis(4_000).unwrap();
        let expires_at = ServerTimestamp::from_unix_millis(5_000).unwrap();
        // Production relation, not the boundary. MIN_KEY_PACKAGE_REMAINING_SECONDS
        // (600) strictly exceeds RECOVERY_RESERVATION_TTL_MILLIS (300_000) and the
        // floor is re-enforced at CLAIM time against claimed_at
        // (repository/core.rs:2994, :3397), so a claimed package always outlives its
        // reservation. A fixture with package_not_after == expires_at sits exactly on
        // `terminal_time >= after.package_not_after` (:9984) and makes the planner
        // emit Reserved -> Expired — a shape production cannot produce.
        let package_not_after = ServerTimestamp::from_unix_millis(305_000).unwrap();

        // A Fulfilled/Consumed family — the own shape — but terminalized by expiry.
        push_recovery_family(
            &mut plan,
            prior,
            actor,
            uuid(0x60),
            [0x61; 32],
            [0x62; 32],
            [0x64; 32],
            received_at,
            expires_at,
            package_not_after,
            RecoveryRequestStatus::Fulfilled,
            ReservationStatus::Consumed,
            Some(WorkTerminalEvidence::Expiry(expires_at)),
            PackageStatus::Consumed,
        );

        match classify_prior_bound_recovery(&plan, &context, OwnFamilyKind::LeafRecoveryFulfillment)
        {
            Err(ExecutorError::InconsistentPlan(_)) => {}
            Ok(_) => panic!("an own family closing by due expiry was accepted"),
            Err(error) => panic!("rejected with the wrong executor error: {error:?}"),
        }
    }

    /// The sealed fulfillment arm proved its own request and reservation agree
    /// field-for-field ("fulfillment own request/reservation are not bijective").
    /// The extraction dropped target / received_at / expires_at; an independent
    /// review caught it. This pins the restoration.
    #[test]
    fn fulfillment_own_request_and_reservation_must_agree() {
        let (mut plan, context) = exact_fixture();
        let prior = plan.expected_prior.expect("prior");
        let actor = plan
            .effects
            .authority
            .as_ref()
            .and_then(|authority| match authority {
                PlanAuthority::Transition(transition) => transition.authority.as_ref(),
                _ => None,
            })
            .expect("actor authority")
            .actor
            .clone();
        let producer = plan.state.producer.clone();
        let received_at = ServerTimestamp::from_unix_millis(4_000).unwrap();
        let expires_at = ServerTimestamp::from_unix_millis(5_000).unwrap();
        let package_not_after = ServerTimestamp::from_unix_millis(305_000).unwrap();
        push_recovery_family(
            &mut plan,
            prior,
            actor,
            uuid(0x60),
            [0x61; 32],
            [0x62; 32],
            [0x64; 32],
            received_at,
            expires_at,
            package_not_after,
            RecoveryRequestStatus::Fulfilled,
            ReservationStatus::Consumed,
            Some(WorkTerminalEvidence::Transition(producer)),
            PackageStatus::Consumed,
        );

        // Shift BOTH sides of the own reservation so identity-unchanged still holds
        // and its terminal is untouched. The only defect is that it now disagrees
        // with the own request — exactly what sealed proved and the extraction lost.
        let shifted = ServerTimestamp::from_unix_millis(4_500).unwrap();
        {
            let change = &mut plan.effects.reservation_changes[0];
            if let Some(before) = change.before.as_mut() {
                before.expires_at = shifted;
            }
            if let Some(after) = change.after.as_mut() {
                after.expires_at = shifted;
            }
        }

        match classify_prior_bound_recovery(&plan, &context, OwnFamilyKind::LeafRecoveryFulfillment)
        {
            Err(ExecutorError::InconsistentPlan(_)) => {}
            Ok(_) => panic!("an own request/reservation disagreement was accepted"),
            Err(error) => panic!("rejected with the wrong error: {error:?}"),
        }
    }

    /// REGRESSION FOR DEFECT 1, at the level a no-DB test can reach.
    ///
    /// `apply_leave_fulfillment` carried
    /// `reject_if_present("recovery_package_cas", ..)`, which — because
    /// `into_persistence_plan` enforces the CAS <-> edge bijection — meant "reject any
    /// plan carrying any package edge", the exact opposite of the comment above it.
    /// Any leaveCommit on a coordinate with open recovery work was planner-legal and
    /// executor-fatal. That arm is `async` and needs a live transaction, so the
    /// end-to-end proof belongs in the DB packet; what is provable here is the
    /// classification the arm now performs instead of rejecting — and `OwnFamilyKind::None`
    /// carrying real prior-bound work had no direct coverage at all.
    #[test]
    fn leave_fulfillment_preflight_classifies_prior_bound_work() {
        let (mut plan, context) = exact_fixture();
        let prior = plan.expected_prior.expect("prior");
        let actor = plan
            .effects
            .authority
            .as_ref()
            .and_then(|authority| match authority {
                PlanAuthority::Transition(transition) => transition.authority.as_ref(),
                _ => None,
            })
            .expect("actor authority")
            .actor
            .clone();
        let received_at = ServerTimestamp::from_unix_millis(4_000).unwrap();
        let expires_at = ServerTimestamp::from_unix_millis(5_000).unwrap();
        let package_not_after = ServerTimestamp::from_unix_millis(305_000).unwrap();

        // One overdue prior-bound family and nothing owned — the shape a leaveCommit
        // over a coordinate with open recovery work carries.
        let request_id = uuid(0x66);
        let key_package_ref = [0x67; 32];
        push_recovery_family(
            &mut plan,
            prior,
            actor,
            request_id,
            key_package_ref,
            [0x68; 32],
            [0x69; 32],
            received_at,
            expires_at,
            package_not_after,
            RecoveryRequestStatus::Expired,
            ReservationStatus::Expired,
            Some(WorkTerminalEvidence::Expiry(expires_at)),
            PackageStatus::Available,
        );

        // Drive the REAL leave-fulfillment guard block, not just the classifier.
        // Reinstating the shipped `reject_if_present("recovery_package_cas", ..)`
        // makes this fail; before the extraction it stayed green.
        let partition = preflight_leave_fulfillment(&plan, &context)
            .expect("a leaveCommit over open recovery work must not be executor-fatal");
        assert_eq!(partition.own(), None, "this arm owns no recovery family");
        assert_eq!(partition.requests(), 1);
        assert!(
            partition.keys().contains(&(request_id, key_package_ref)),
            "the family must be carried to the writer, not dropped"
        );
    }

    /// ROW-B WEDGE (leave-fulfillment arm).
    ///
    /// THE USER SEQUENCE:
    ///   1. Bob asks to leave. Nobody commits it for 24 hours, so his consent
    ///      lapses and nothing sweeps the row.
    ///   2. Carol now asks to leave, and someone commits HER leave.
    ///   3. That `leaveCommit` must succeed — carol must be able to leave even
    ///      though bob's request went stale.
    ///
    /// Before the fix step 3 failed permanently: bob's lapsed row rode along in
    /// carol's plan as a prior-bound delta the arm refused, and every retry
    /// replanned it identically.
    ///
    /// Past the 24h consent TTL
    /// `resolve_prior_bound_work` emits Row B (`Pending->Expired`), not Row A
    /// (`Pending->Stale`); `classify_prior_bound_staling` proves it and
    /// `write_prior_bound_staling` writes it, but this arm's own partition
    /// accepted only Row A — planner-legal, executor-fatal, and a retry replans the
    /// identical shape. Nothing sweeps overdue leaves, so the wedge is permanent.
    ///
    /// The arm's OWN request can never be Row B: `plan_leave_fulfillment_inner`
    /// rejects an overdue target with `WorkExpired` before planning. So the shape
    /// under test is exactly one `Fulfilled` plus one overdue peer `Expired`.
    #[test]
    fn leave_fulfillment_partition_accepts_an_overdue_prior_bound_leave() {
        let (mut plan, _context, _) = exact_due_expiry_fixture(DueExpiryFamily::Leave);
        let prior = plan.expected_prior.expect("prior");
        // The fixture's overdue peer leave (`Pending->Expired`, exact due expiry).
        let overdue_request_id = uuid(0x67);
        assert_eq!(
            plan.effects.leave_request_changes.len(),
            1,
            "fixture carries exactly the overdue peer leave"
        );

        // The arm's own edge: a DIFFERENT requester's `Pending->Fulfilled`.
        let requester = device(0x71);
        let request_id = uuid(0x72);
        let received_at = ServerTimestamp::from_unix_millis(4_000).unwrap();
        let expires_at = ServerTimestamp::from_unix_millis(90_404_000).unwrap();
        let origin = request_evidence(
            RequestEntryKind::LeaveRequest,
            request_id,
            requester.clone(),
            *prior.conversation_id(),
            received_at,
            [0x73; 32],
        );
        let before = LeaveRequest {
            request_id,
            requester,
            bound_coordinate: prior,
            received_at,
            expires_at,
            status: LeaveRequestStatus::Pending,
            origin,
            terminal: None,
            fulfilled_participant: None,
        };
        let mut after = before.clone();
        after.status = LeaveRequestStatus::Fulfilled;
        plan.effects.leave_request_changes.push(StateChange {
            before: Some(before),
            after: Some(after),
        });

        let fulfilled = partition_leave_fulfillment_requests(plan.effects())
            .expect("an overdue prior-bound peer leave must not wedge the partition");
        assert_eq!(
            fulfilled, request_id,
            "the arm's own fulfilled request, never the overdue peer"
        );
        assert_ne!(fulfilled, overdue_request_id);
    }

    /// Ruling point 3 stays enforced for BOTH prior-bound rows: a delta that
    /// retires the very request being fulfilled is illegal whether it is a staling
    /// or a due expiry. Widening the partition to accept Row B must not open this.
    #[test]
    fn leave_fulfillment_partition_rejects_expiring_the_request_it_fulfills() {
        let (mut plan, _context, _) = exact_due_expiry_fixture(DueExpiryFamily::Leave);
        let overdue = plan.effects.leave_request_changes[0].clone();
        let mut before = overdue.before.expect("overdue before").clone();
        let mut after = overdue.after.expect("overdue after").clone();
        before.status = LeaveRequestStatus::Pending;
        after.status = LeaveRequestStatus::Fulfilled;
        after.terminal = None;
        // Same request id as the fixture's `Pending->Expired` delta.
        plan.effects.leave_request_changes.push(StateChange {
            before: Some(before),
            after: Some(after),
        });

        match partition_leave_fulfillment_requests(plan.effects()) {
            Err(ExecutorError::InconsistentPlan(_)) => {}
            other => panic!("expiring the fulfilled request was accepted: {other:?}"),
        }
    }

    /// One prior-bound family plus the knobs each negative case perturbs.
    fn one_prior_bound_family(digest: [u8; 32]) -> (ConversationPersistencePlan, ExecutionContext) {
        let (mut plan, context) = exact_fixture();
        let prior = plan.expected_prior.expect("prior");
        let actor = plan
            .effects
            .authority
            .as_ref()
            .and_then(|authority| match authority {
                PlanAuthority::Transition(transition) => transition.authority.as_ref(),
                _ => None,
            })
            .expect("actor authority")
            .actor
            .clone();
        let received_at = ServerTimestamp::from_unix_millis(4_000).unwrap();
        let expires_at = ServerTimestamp::from_unix_millis(5_000).unwrap();
        let package_not_after = ServerTimestamp::from_unix_millis(305_000).unwrap();
        push_recovery_family(
            &mut plan,
            prior,
            actor,
            uuid(0x66),
            [0x67; 32],
            [0x68; 32],
            digest,
            received_at,
            expires_at,
            package_not_after,
            RecoveryRequestStatus::Expired,
            ReservationStatus::Expired,
            Some(WorkTerminalEvidence::Expiry(expires_at)),
            PackageStatus::Available,
        );
        (plan, context)
    }

    fn classify_none(
        plan: &ConversationPersistencePlan,
        context: &ExecutionContext,
    ) -> Result<PriorBoundPartition, ExecutorError> {
        classify_prior_bound_recovery(plan, context, OwnFamilyKind::None)
    }

    /// NEGATIVE BATTERY. Each case deletes exactly one classifier guarantee. An
    /// independent review showed every one of these could be removed from the
    /// classifier with the whole suite still green, so each is pinned here.
    #[test]
    fn classifier_rejects_each_prior_bound_drift() {
        // Baseline: the unperturbed family is accepted, so every rejection below is
        // attributable to the perturbation and not to a malformed fixture.
        let (plan, context) = one_prior_bound_family([0x69; 32]);
        classify_none(&plan, &context).expect("the unperturbed family must be accepted");

        // 1. Prior-bound request must come FROM Open.
        let (mut plan, context) = one_prior_bound_family([0x69; 32]);
        if let Some(before) = plan.effects.recovery_request_changes[0].before.as_mut() {
            before.status = RecoveryRequestStatus::Fulfilled;
        }
        assert!(
            classify_none(&plan, &context).is_err(),
            "a prior-bound request not leaving Open must be rejected"
        );

        // 2. Prior-bound family must be bound to the PRIOR coordinate.
        let (mut plan, context) = one_prior_bound_family([0x69; 32]);
        let foreign =
            coordinate_only_successor(&plan.expected_prior.expect("prior")).expect("successor");
        if let Some(before) = plan.effects.recovery_request_changes[0].before.as_mut() {
            before.bound_coordinate = foreign;
        }
        assert!(
            classify_none(&plan, &context).is_err(),
            "a family bound to a foreign coordinate must be rejected"
        );

        // 3. Terminal evidence must be exact: a due-expiry family whose terminal is
        //    absent is not terminalized, it is silently dropped work.
        let (mut plan, context) = one_prior_bound_family([0x69; 32]);
        if let Some(after) = plan.effects.recovery_request_changes[0].after.as_mut() {
            after.terminal = None;
        }
        assert!(
            classify_none(&plan, &context).is_err(),
            "a prior-bound request with no terminal evidence must be rejected"
        );

        // 4. Request and reservation must agree on expires_at — the value
        //    terminal_is_exact_due_expiry tests the terminal against. Sealed proved
        //    this pair directly and the extraction had dropped it.
        let (mut plan, context) = one_prior_bound_family([0x69; 32]);
        let shifted = ServerTimestamp::from_unix_millis(4_500).unwrap();
        // Shift BOTH sides of the reservation and its terminal together, so
        // identity-unchanged holds and its own due-expiry evidence stays exact. The
        // ONLY thing wrong is that it now disagrees with the request. Without this
        // the case is rejected by an earlier guard and proves nothing about the pair.
        if let Some(before) = plan.effects.reservation_changes[0].before.as_mut() {
            before.expires_at = shifted;
        }
        if let Some(after) = plan.effects.reservation_changes[0].after.as_mut() {
            after.expires_at = shifted;
            after.terminal = Some(WorkTerminalEvidence::Expiry(shifted));
        }
        match classify_none(&plan, &context) {
            Err(ExecutorError::InconsistentPlan(message)) => assert_eq!(
                message, "metadata recovery package CAS authority drift",
                "the cross-field expires_at pair must be the rejecting check"
            ),
            Ok(_) => panic!("a request/reservation expires_at disagreement was accepted"),
            Err(error) => panic!("rejected with the wrong error: {error:?}"),
        }

        // 5. The package edge must be Reserved -> Available. Reserved -> Expired is
        //    production-unproducible and every reader used to accept it.
        let (mut plan, context) = one_prior_bound_family([0x69; 32]);
        for edge in plan.effects.package_transitions.iter_mut() {
            edge.to = PackageStatus::Expired;
        }
        for binding in plan.effects.recovery_package_cas.iter_mut() {
            binding.successor_status = PackageStatus::Expired;
            binding.authority_digest = [0; 32];
            binding.authority_digest = recovery_package_cas_authority_digest(binding);
        }
        assert!(
            classify_none(&plan, &context).is_err(),
            "Reserved -> Expired must be rejected for a prior-bound family"
        );

        // 6. The CAS binding must agree with the family it claims to authorize.
        let (mut plan, context) = one_prior_bound_family([0x69; 32]);
        for binding in plan.effects.recovery_package_cas.iter_mut() {
            binding.claimed_at = ServerTimestamp::from_unix_millis(9_000).unwrap();
            binding.authority_digest = [0; 32];
            binding.authority_digest = recovery_package_cas_authority_digest(binding);
        }
        assert!(
            classify_none(&plan, &context).is_err(),
            "a CAS binding whose claimed_at drifts from the family must be rejected"
        );
    }

    /// Check 8-DiD, which this correction introduces and which had no negative test.
    /// `recovery_package_guard_digest` hashes `key_package_ref`, so two bindings with
    /// distinct refs sharing one locked-row digest means the planner reused a guard's
    /// digest across references — real drift, not a hash collision.
    #[test]
    fn check_8_did_rejects_one_locked_row_digest_across_two_refs() {
        let shared = [0x69; 32];
        let (mut plan, context) = one_prior_bound_family(shared);
        let prior = plan.expected_prior.expect("prior");
        let actor = plan.effects.recovery_package_cas[0].target.clone();
        let received_at = ServerTimestamp::from_unix_millis(4_000).unwrap();
        let expires_at = ServerTimestamp::from_unix_millis(5_000).unwrap();
        let package_not_after = ServerTimestamp::from_unix_millis(305_000).unwrap();

        // A second, otherwise-legal family on a DIFFERENT key package reference —
        // but carrying the first family's locked-row digest.
        push_recovery_family(
            &mut plan,
            prior,
            actor,
            uuid(0x71),
            [0x72; 32],
            [0x73; 32],
            shared,
            received_at,
            expires_at,
            package_not_after,
            RecoveryRequestStatus::Expired,
            ReservationStatus::Expired,
            Some(WorkTerminalEvidence::Expiry(expires_at)),
            PackageStatus::Available,
        );

        match classify_none(&plan, &context) {
            Err(ExecutorError::InconsistentPlan(message)) => assert_eq!(
                message, "distinct key package refs share one locked row digest",
                "8-DiD must be the rejecting check"
            ),
            Ok(_) => panic!("two refs sharing one locked-row digest were accepted"),
            Err(error) => panic!("rejected with the wrong error: {error:?}"),
        }

        // Control: distinct digests on the same two families are accepted.
        let (mut plan, context) = one_prior_bound_family([0x69; 32]);
        let prior = plan.expected_prior.expect("prior");
        let actor = plan.effects.recovery_package_cas[0].target.clone();
        push_recovery_family(
            &mut plan,
            prior,
            actor,
            uuid(0x71),
            [0x72; 32],
            [0x73; 32],
            [0x74; 32],
            received_at,
            expires_at,
            package_not_after,
            RecoveryRequestStatus::Expired,
            ReservationStatus::Expired,
            Some(WorkTerminalEvidence::Expiry(expires_at)),
            PackageStatus::Available,
        );
        classify_none(&plan, &context)
            .expect("two families with distinct digests must be accepted");
    }

    /// The keyed write-receipt check (design 5 step 6). `write_prior_bound_supersessions`
    /// SKIPS any delta that is not its exact supersession shape, so a silent drop
    /// is a real failure mode — and a count-only comparison cannot tell a dropped
    /// family from a substituted one. Reachable in production only through the
    /// `apply_*` arms, which need a live transaction, so it is proven here directly.
    #[test]
    fn write_receipt_must_match_the_classified_families_by_key() {
        let key_a = (uuid(0x60), [0x61; 32]);
        let key_b = (uuid(0x66), [0x67; 32]);
        let partition = PriorBoundPartition::for_receipt_test(BTreeSet::from([key_a, key_b]), None);
        let counts = |n: usize| FamilyCounts {
            requests: n,
            reservations: n,
            packages: n,
            welcomes: 0,
            reset_requests: 0,
            leave_requests: 0,
        };

        let reconciled = PriorBoundWriteReceipt::new(counts(2), BTreeSet::from([key_a, key_b]))
            .reconcile_into_counts(&partition)
            .expect("an exact receipt must reconcile");
        assert_eq!(
            reconciled.packages, 2,
            "the counts must survive reconciliation"
        );

        // A dropped family.
        assert!(
            PriorBoundWriteReceipt::new(counts(1), BTreeSet::from([key_a]))
                .reconcile_into_counts(&partition)
                .is_err(),
            "a silently dropped family must be rejected"
        );

        // Right COUNT, wrong identity — the case a count-only fence cannot see.
        assert!(
            PriorBoundWriteReceipt::new(
                counts(2),
                BTreeSet::from([key_a, (uuid(0x77), [0x78; 32])])
            )
            .reconcile_into_counts(&partition)
            .is_err(),
            "a substituted family must be rejected even at the right count"
        );
    }

    /// REGRESSION — the acceptance own family is bound to the SUCCESSOR.
    ///
    /// `plan_accept_conversation_inner` opens its recovery request and reservation
    /// with `bound_coordinate: coordinate_only_successor(prior)` (:13452, :13463),
    /// because the family is created as PART of the coordinate change. A classifier
    /// that compares the own family against `prior` rejects every acceptConversation
    /// before its head CAS, and retry re-plans the identical shape — a permanent
    /// device-can-never-join wedge. This pins the coordinate the own family must
    /// carry, in both directions.
    #[test]
    fn acceptance_own_family_is_bound_to_the_successor_not_the_prior() {
        fn acceptance_plan(
            bind_to_successor: bool,
        ) -> (ConversationPersistencePlan, ExecutionContext) {
            let (mut plan, context) = exact_fixture();
            let prior = plan.expected_prior.expect("prior");
            let successor = coordinate_only_successor(&prior).expect("successor");
            let bound = if bind_to_successor { successor } else { prior };
            let actor = plan
                .effects
                .authority
                .as_ref()
                .and_then(|authority| match authority {
                    PlanAuthority::Transition(transition) => transition.authority.as_ref(),
                    _ => None,
                })
                .expect("actor authority")
                .actor
                .clone();
            let received_at = ServerTimestamp::from_unix_millis(4_000).unwrap();
            let expires_at = ServerTimestamp::from_unix_millis(5_000).unwrap();
            // Production relation, not the boundary: package_not_after strictly
            // outlives expires_at (see the note on exact_due_expiry_fixture).
            let package_not_after = ServerTimestamp::from_unix_millis(305_000).unwrap();
            let request_id = uuid(0x60);
            let key_package_ref = [0x61; 32];
            let origin_key_id = [0x62; 32];
            let origin = request_evidence(
                RequestEntryKind::LeafRecoveryRequest,
                request_id,
                actor.clone(),
                *prior.conversation_id(),
                received_at,
                origin_key_id,
            );
            plan.effects.recovery_request_changes.push(StateChange {
                before: None,
                after: Some(RecoveryRequest {
                    request_id,
                    target: actor.clone(),
                    kind: LeafRecoveryKind::Add,
                    source: RecoverySource::Acceptance,
                    bound_coordinate: bound,
                    key_package_ref,
                    received_at,
                    expires_at,
                    status: RecoveryRequestStatus::Open,
                    origin: RecoveryOriginEvidence::Request(origin),
                    terminal: None,
                }),
            });
            plan.effects.reservation_changes.push(StateChange {
                before: None,
                after: Some(RecoveryReservation {
                    request_id,
                    target: actor.clone(),
                    bound_coordinate: bound,
                    key_package_ref,
                    received_at,
                    expires_at,
                    package_not_after,
                    status: ReservationStatus::Active,
                    terminal: None,
                }),
            });
            plan.effects.package_transitions.push(PackageTransition {
                request_id,
                key_package_ref,
                from: PackageStatus::Available,
                to: PackageStatus::Reserved,
            });
            let mut package_cas = RecoveryPackageCasBinding {
                transaction_id: plan
                    .effects
                    .head_cas
                    .as_ref()
                    .expect("head cas")
                    .transaction_id
                    .clone(),
                conversation_id: *prior.conversation_id(),
                request_id,
                target: actor,
                target_key_id: origin_key_id,
                target_auth_generation: 3,
                bound_coordinate: bound,
                key_package_ref,
                key_package_wrapper_sha256: [0x63; 32],
                package_not_after,
                claimed_at: received_at,
                expected_status: PackageStatus::Available,
                successor_status: PackageStatus::Reserved,
                locked_row_digest: [0x64; 32],
                authority_digest: [0; 32],
            };
            package_cas.authority_digest = recovery_package_cas_authority_digest(&package_cas);
            plan.effects.recovery_package_cas.push(package_cas);
            (plan, context)
        }

        // What the planner actually emits.
        let (plan, context) = acceptance_plan(true);
        classify_prior_bound_recovery(&plan, &context, OwnFamilyKind::Acceptance)
            .expect("the planner's successor-bound acceptance family must be accepted");

        // A prior-bound own family is NOT what acceptance opens, and must not pass.
        let (plan, context) = acceptance_plan(false);
        match classify_prior_bound_recovery(&plan, &context, OwnFamilyKind::Acceptance) {
            Err(ExecutorError::InconsistentPlan(_)) => {}
            Ok(_) => panic!("a prior-bound acceptance own family was accepted"),
            Err(error) => panic!("rejected with the wrong executor error: {error:?}"),
        }
    }

    #[test]
    fn metadata_preflight_rejects_author_column_drift() {
        for (label, group_id, confirmation_tag) in [
            ("group ID", Some([0x91; 32]), None),
            ("confirmation tag", None, Some([0x92; 32])),
        ] {
            let (mut plan, context) = exact_fixture();
            assert_eq!(
                mutate_all_inner_metadata_coordinates(&mut plan, group_id, confirmation_tag),
                5,
                "{label} mutation must cover every inner metadata copy",
            );
            assert!(matches!(
                preflight_metadata_transition(&plan, &context, Uuid::from_bytes(uuid(0x24)), 6,),
                Err(ExecutorError::InconsistentPlan(_))
            ));
        }

        let (plan, mut context) = exact_fixture();
        context
            .metadata_author
            .as_mut()
            .expect("metadata author")
            .author_role = "member".to_owned();

        assert!(matches!(
            preflight_metadata_transition(&plan, &context, Uuid::from_bytes(uuid(0x24)), 6,),
            Err(ExecutorError::InconsistentPlan(_))
        ));
    }

    #[test]
    fn metadata_preflight_rejects_noncanonical_primary_event() {
        let (plan, mut context) = exact_fixture();
        context.events[0].payload_bytes.push(0);

        assert!(matches!(
            preflight_metadata_transition(&plan, &context, Uuid::from_bytes(uuid(0x24)), 6,),
            Err(ExecutorError::InconsistentPlan(_))
        ));
    }

    #[test]
    fn metadata_preflight_rejects_entry_audience_drift() {
        let (plan, mut context) = exact_fixture();
        context
            .entry_recipients
            .push((device(0x41), EntryEntitlementKind::Control));

        assert!(matches!(
            preflight_metadata_transition(&plan, &context, Uuid::from_bytes(uuid(0x24)), 6,),
            Err(ExecutorError::InconsistentPlan(_))
        ));
    }

    #[test]
    fn metadata_preflight_rejects_spine_digest_drift() {
        let (plan, mut context) = exact_fixture();
        context.spine.public_snapshot_bytes.push(0);

        assert!(matches!(
            preflight_metadata_transition(&plan, &context, Uuid::from_bytes(uuid(0x24)), 6,),
            Err(ExecutorError::InconsistentPlan(_))
        ));
    }

    #[test]
    fn metadata_preflight_rejects_unsigned_avatar_context() {
        let (plan, mut context) = exact_fixture();
        context.metadata_avatar = Some(MetadataAvatarPersistence::Reuse {
            snapshot: MetadataAvatarBinding {
                avatar_blob_id: Uuid::from_bytes(uuid(0x42)),
                avatar_ciphertext_sha256: vec![0x43; 32],
                avatar_ciphertext_size: 64,
                avatar_binding_origin_transition_id: Uuid::from_bytes(uuid(0x44)),
                avatar_binding_metadata_version: 1,
                avatar_binding_owner_did: context.actor.user_did.clone(),
                avatar_binding_owner_device_id: context.actor.device_id,
            },
        });

        assert!(matches!(
            preflight_metadata_transition(&plan, &context, Uuid::from_bytes(uuid(0x24)), 6,),
            Err(ExecutorError::InconsistentPlan(_))
        ));
    }

    #[cfg(all(
        feature = "chat-protocol-production-proof",
        not(feature = "server-bin")
    ))]
    pub(super) fn run_production_semantic_proof() -> Result<(), String> {
        let avatar_aad = canonical_metadata_avatar_blob_aad(
            uuid(0x51),
            uuid(0x52),
            7,
            uuid(0x53),
            "image/png",
            48,
        );
        if !avatar_aad.starts_with(b"CATBIRD-CHAT-METADATA-AVATAR-BLOB\0") {
            return Err("metadata avatar AAD omitted its protocol domain".to_owned());
        }
        let expected_avatar_aad_sha256 = [
            0x97, 0x27, 0x75, 0x7f, 0x58, 0x75, 0x13, 0x39, 0x16, 0x32, 0x0d, 0x3c, 0x82, 0xc2,
            0x72, 0xdf, 0x48, 0x0d, 0x41, 0x95, 0xed, 0x3b, 0x57, 0x97, 0xd6, 0x1a, 0xa6, 0x3e,
            0xd0, 0x71, 0x73, 0xb8,
        ];
        let actual_avatar_aad_sha256 = <[u8; 32]>::from(sha2::Sha256::digest(&avatar_aad));
        if actual_avatar_aad_sha256 != expected_avatar_aad_sha256 {
            return Err(format!(
                "metadata avatar AAD canonical payload drifted from the fixed vector: {}",
                hex::encode(actual_avatar_aad_sha256)
            ));
        }

        let (plan, context) = exact_fixture();
        preflight_metadata_transition(&plan, &context, Uuid::from_bytes(uuid(0x24)), 6)
            .map_err(|error| format!("exact metadata preflight failed: {error:?}"))?;
        for (label, avatar_fixture) in [
            ("fresh avatar", AvatarFixture::Fresh),
            ("reused avatar", AvatarFixture::Reuse),
        ] {
            let (plan, context) = exact_fixture_with_avatar(avatar_fixture);
            let binding =
                preflight_metadata_transition(&plan, &context, Uuid::from_bytes(uuid(0x24)), 6)
                    .map_err(|error| format!("{label} preflight failed: {error:?}"))?;
            if binding.avatar.is_none() {
                return Err(format!("{label} lost its persistence authority"));
            }
        }
        // INVERTED at the C2 prior-bound correction, same reason as the
        // cfg(test) assertion above: a Recovery family carrying a
        // `Reserved -> Expired` package edge is production-unproducible and
        // must now be rejected rather than accepted.
        {
            // The fixture emits the PRODUCTION shape (Reserved -> Available), so the
            // unproducible edge is constructed deliberately here.
            let (mut plan, context, _) = exact_due_expiry_fixture(DueExpiryFamily::Recovery);
            for edge in plan.effects.package_transitions.iter_mut() {
                if edge.to == PackageStatus::Available {
                    edge.to = PackageStatus::Expired;
                }
            }
            for binding in plan.effects.recovery_package_cas.iter_mut() {
                if binding.successor_status == PackageStatus::Available {
                    binding.successor_status = PackageStatus::Expired;
                    binding.authority_digest = [0; 32];
                    binding.authority_digest = recovery_package_cas_authority_digest(binding);
                }
            }
            match preflight_metadata_transition(&plan, &context, Uuid::from_bytes(uuid(0x24)), 6) {
                Err(ExecutorError::InconsistentPlan(_)) => {}
                Ok(_) => {
                    return Err("Reserved -> Expired prior-bound package edge was accepted".into())
                }
                Err(error) => {
                    return Err(format!(
                        "Reserved -> Expired rejected with the wrong error: {error:?}"
                    ))
                }
            }
        }
        for (label, family) in [
            ("Reset expiry", DueExpiryFamily::Reset),
            ("Leave expiry", DueExpiryFamily::Leave),
            ("Welcome expiry", DueExpiryFamily::Welcome),
        ] {
            let (plan, context, expected) = exact_due_expiry_fixture(family);
            preflight_metadata_transition(&plan, &context, Uuid::from_bytes(uuid(0x24)), 6)
                .map_err(|error| format!("{label} preflight failed: {error:?}"))?;
            reconcile_coordinate_change_families(
                plan.effects(),
                &FamilyCounts {
                    requests: 0,
                    reservations: 0,
                    packages: 0,
                    welcomes: 0,
                    reset_requests: 0,
                    leave_requests: 0,
                },
                &expected,
            )
            .map_err(|error| format!("{label} reconciliation failed: {error:?}"))?;
        }

        let reject = |label: &str,
                      plan: &ConversationPersistencePlan,
                      context: &ExecutionContext|
         -> Result<(), String> {
            match preflight_metadata_transition(plan, context, Uuid::from_bytes(uuid(0x24)), 6) {
                Err(ExecutorError::InconsistentPlan(_)) => Ok(()),
                Ok(_) => Err(format!("{label} was accepted")),
                Err(error) => Err(format!(
                    "{label} failed with the wrong executor error: {error:?}"
                )),
            }
        };

        for (label, group_id, confirmation_tag) in [
            ("all-inner group ID drift", Some([0x91; 32]), None),
            ("all-inner confirmation-tag drift", None, Some([0x92; 32])),
        ] {
            let (mut plan, context) = exact_fixture();
            if mutate_all_inner_metadata_coordinates(&mut plan, group_id, confirmation_tag) != 5 {
                return Err(format!(
                    "{label} did not mutate all five inner metadata copies"
                ));
            }
            reject(label, &plan, &context)?;
        }

        let (plan, mut context) = exact_fixture();
        context.events[0].payload_bytes.push(0);
        reject("primary event payload drift", &plan, &context)?;

        let (plan, mut context) = exact_fixture();
        context
            .entry_recipients
            .push((device(0x41), EntryEntitlementKind::Control));
        reject("entry audience drift", &plan, &context)?;

        let (plan, mut context) = exact_fixture();
        context.spine.public_snapshot_bytes.push(0);
        reject("spine digest drift", &plan, &context)?;

        let (plan, mut context) = exact_fixture();
        context.metadata_avatar = Some(MetadataAvatarPersistence::Reuse {
            snapshot: MetadataAvatarBinding {
                avatar_blob_id: Uuid::from_bytes(uuid(0x42)),
                avatar_ciphertext_sha256: vec![0x43; 32],
                avatar_ciphertext_size: 64,
                avatar_binding_origin_transition_id: Uuid::from_bytes(uuid(0x44)),
                avatar_binding_metadata_version: 1,
                avatar_binding_owner_did: context.actor.user_did.clone(),
                avatar_binding_owner_device_id: context.actor.device_id,
            },
        });
        reject("unsigned avatar context", &plan, &context)?;

        Ok(())
    }
}
