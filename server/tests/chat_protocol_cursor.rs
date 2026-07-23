#[allow(dead_code)]
#[path = "../src/chat_protocol/model.rs"]
mod model;
#[allow(dead_code)]
#[path = "../src/chat_protocol/validation.rs"]
mod validation;

#[allow(dead_code)]
mod repository {
    pub(crate) mod inventory {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/repository/inventory.rs"
        ));
    }
}

#[allow(dead_code)]
mod cursor {
    include!("../src/chat_protocol/cursor.rs");
}

mod cursor_tests {
    use super::cursor::{
        self, CursorCodec, CursorCodecError, DeviceCursorBinding, EventCursor,
        InventoryPageBinding, InventoryPageDomain, InventorySessionBinding, InventorySessionId,
        OwnDeviceCursorBinding,
    };
    use super::validation::{BareDid, KeyThumbprint};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use hmac::{Hmac, Mac as _};
    use sha2::Sha256;
    use uuid::Uuid;
    use zeroize::Zeroizing;

    const DID: &str = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";
    const DEVICE_ID: &str = "3b241101-e2bb-4255-8caf-4136c566a962";
    const PROTOCOL_INSTANCE: &str = "018f3f6a-7b2c-4d91-8a5e-0f123456789a";

    fn codec() -> CursorCodec {
        CursorCodec::new(
            Uuid::parse_str(PROTOCOL_INSTANCE).unwrap(),
            &URL_SAFE_NO_PAD.encode([0x41; 32]),
            Zeroizing::new([0xA5; 32]),
        )
        .unwrap()
    }

    fn thumbprint(seed: u8) -> KeyThumbprint {
        KeyThumbprint::parse(&URL_SAFE_NO_PAD.encode([seed; 32])).unwrap()
    }

    fn bound_device(
        did: &str,
        device_id: &str,
        auth_generation: u64,
        jkt_seed: u8,
    ) -> DeviceCursorBinding {
        let did = BareDid::parse(did).unwrap();
        let jkt = thumbprint(jkt_seed);
        DeviceCursorBinding::new(
            &did,
            Uuid::parse_str(device_id).unwrap(),
            auth_generation,
            &jkt,
        )
        .unwrap()
    }

    fn device() -> DeviceCursorBinding {
        bound_device(DID, DEVICE_ID, 7, 0x61)
    }

    fn snapshot_event_cursor(codec: &CursorCodec) -> EventCursor {
        codec
            .issue_event_cursor(&device(), 42, 10, 1_700_000_000, 1_700_000_300)
            .unwrap()
    }

    fn inventory_page_binding(
        codec: &CursorCodec,
        domain: InventoryPageDomain,
    ) -> InventoryPageBinding {
        let snapshot_event_cursor = snapshot_event_cursor(codec);
        let session_binding = inventory_session_binding(codec, &snapshot_event_cursor);
        let inventory_session = codec
            .issue_inventory_session_id(&session_binding, 1_700_000_000, 10, 42)
            .unwrap();
        codec
            .bind_inventory_page(
                &session_binding,
                &inventory_session,
                &snapshot_event_cursor,
                domain,
                b"closed-filter-v1",
                1_700_000_001,
                10,
                42,
            )
            .unwrap()
    }

    fn inventory_session_binding(
        codec: &CursorCodec,
        snapshot_event_cursor: &EventCursor,
    ) -> InventorySessionBinding {
        codec
            .bind_inventory_session(
                device(),
                Uuid::parse_str("44444444-4444-4444-8444-444444444444").unwrap(),
                snapshot_event_cursor,
                42,
                1_700_000_300,
                1_700_000_001,
                10,
                42,
            )
            .unwrap()
    }

    #[test]
    fn inventory_page_phase_two_requires_locked_repository_evidence() {
        let source = include_str!("../src/chat_protocol/cursor.rs");
        let phase_two = source
            .split_once("fn verify_located_inventory_page_cursor")
            .expect("inventory page phase-two verifier exists")
            .1
            .split_once("fn verify_inventory_page_cursor")
            .expect("raw inventory page verifier follows phase two")
            .0;

        assert!(
            phase_two.contains("LockedInventoryCursorEvidence"),
            "phase two must consume evidence minted from a locked durable session row"
        );
        assert!(
            !phase_two.contains("expected: &InventoryPageBinding"),
            "a caller-assembled binding must not authorize inventory paging"
        );
    }

    fn own_device_binding() -> OwnDeviceCursorBinding {
        OwnDeviceCursorBinding::new(
            device(),
            Uuid::parse_str("66666666-6666-4666-a666-666666666666").unwrap(),
            17,
            b"include-revoked=true",
            1_700_000_300,
        )
        .unwrap()
    }

    fn signed_body_mutation(encoded: &str, mutate: impl FnOnce(&mut Vec<u8>)) -> String {
        let mut authenticated = URL_SAFE_NO_PAD.decode(encoded).unwrap();
        authenticated.truncate(authenticated.len() - 32);
        mutate(&mut authenticated);

        let mut mac = Hmac::<Sha256>::new_from_slice(&[0xA5; 32]).unwrap();
        mac.update(&authenticated);
        authenticated.extend_from_slice(&mac.finalize().into_bytes());
        URL_SAFE_NO_PAD.encode(authenticated)
    }

    fn unauthenticated_body_mutation(encoded: &str, offset: usize) -> String {
        let mut authenticated = URL_SAFE_NO_PAD.decode(encoded).unwrap();
        authenticated[offset] ^= 1;
        URL_SAFE_NO_PAD.encode(authenticated)
    }

    fn noncanonical_base64url(encoded: &str) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

        let mut bytes = encoded.as_bytes().to_vec();
        let last = bytes.last_mut().unwrap();
        let index = ALPHABET
            .iter()
            .position(|candidate| candidate == last)
            .unwrap();
        let replacement = match encoded.len() % 4 {
            2 => index | 1,
            3 => index | 1,
            remainder => panic!("encoded value has no unused trailing bits: {remainder}"),
        };
        *last = ALPHABET[replacement];
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn event_cursor_round_trips_exact_device_stream_position() {
        let codec = codec();
        let device = device();
        let cursor = codec
            .issue_event_cursor(&device, 42, 10, 1_700_000_000, 1_700_000_300)
            .unwrap();

        assert!(cursor.as_str().is_ascii());
        assert!(!cursor.as_str().contains('='));
        assert!(cursor.as_str().len() <= cursor::MAX_OPAQUE_CURSOR_ASCII_BYTES);

        let verified = codec
            .verify_event_cursor(cursor.as_str(), &device, 1_700_000_001, 10, 42)
            .unwrap();
        assert_eq!(verified.position(), 42);
        assert_eq!(verified.retained_floor(), 10);
        assert_eq!(verified.expires_at(), 1_700_000_300);
    }

    #[test]
    fn event_cursor_allows_floor_advancement_until_the_position_is_expired() {
        let codec = codec();
        let device = device();
        let cursor = codec
            .issue_event_cursor(&device, 42, 10, 1_700_000_000, 1_700_000_300)
            .unwrap();

        let still_retained = codec
            .verify_event_cursor(cursor.as_str(), &device, 1_700_000_001, 11, 42)
            .unwrap();
        assert_eq!(still_retained.position(), 42);
        assert_eq!(still_retained.retained_floor(), 10);
        assert_eq!(
            codec
                .verify_event_cursor(cursor.as_str(), &device, 1_700_000_001, 43, 43)
                .unwrap_err(),
            CursorCodecError::BelowRetentionFloor
        );
    }

    #[test]
    fn inventory_session_id_round_trips_exact_fence_and_has_db_hash() {
        let codec = codec();
        let device = device();
        let snapshot_cursor = codec
            .issue_event_cursor(&device, 42, 10, 1_700_000_000, 1_700_000_300)
            .unwrap();
        let binding = codec
            .bind_inventory_session(
                device,
                Uuid::parse_str("44444444-4444-4444-8444-444444444444").unwrap(),
                &snapshot_cursor,
                42,
                1_700_000_300,
                1_700_000_001,
                10,
                42,
            )
            .unwrap();
        let session = codec
            .issue_inventory_session_id(&binding, 1_700_000_000, 10, 42)
            .unwrap();

        fn requires_inventory_session_id(_: &InventorySessionId) {}
        requires_inventory_session_id(&session);
        assert!((32..=cursor::MAX_OPAQUE_CURSOR_ASCII_BYTES).contains(&session.as_str().len()));
        assert_eq!(
            session.binding_hash(),
            cursor::opaque_binding_hash(session.as_str().as_bytes()).unwrap()
        );

        let verified = codec
            .verify_inventory_session_id(session.as_str(), &binding, 1_700_000_001, 10, 42)
            .unwrap();
        assert_eq!(verified.session_id(), binding.session_id());
        assert_eq!(verified.snapshot_event_position(), 42);
        assert_eq!(
            verified.snapshot_event_cursor_hash(),
            binding.snapshot_event_cursor_hash()
        );
        assert_eq!(verified.expires_at(), 1_700_000_300);
    }

    #[test]
    fn inventory_page_cursor_round_trips_each_exact_session_domain() {
        for domain in [
            InventoryPageDomain::Conversations,
            InventoryPageDomain::PendingWelcomes,
            InventoryPageDomain::LeafRecovery,
        ] {
            let codec = codec();
            let binding = inventory_page_binding(&codec, domain);
            let item_key = *Uuid::parse_str("55555555-5555-4555-8555-555555555555")
                .unwrap()
                .as_bytes();
            let page = codec
                .issue_inventory_page_cursor(&binding, 9, &item_key, 1_700_000_010, 10, 42)
                .unwrap();

            assert!(page.as_str().len() <= cursor::MAX_OPAQUE_CURSOR_ASCII_BYTES);
            let verified = codec
                .verify_inventory_page_cursor_for_test(
                    page.as_str(),
                    &binding,
                    1_700_000_011,
                    10,
                    42,
                )
                .unwrap();
            assert_eq!(verified.domain(), domain);
            assert_eq!(verified.last_ordinal(), 9);
            assert_eq!(
                verified.item_key_hash(),
                cursor::inventory_item_key_hash(domain, &item_key).unwrap()
            );
            assert_eq!(verified.expires_at(), 1_700_000_300);
        }
    }

    #[test]
    fn own_device_cursor_uses_its_separate_principal_fence_domain() {
        let codec = codec();
        let binding = OwnDeviceCursorBinding::new(
            device(),
            Uuid::parse_str("66666666-6666-4666-a666-666666666666").unwrap(),
            17,
            b"include-revoked=true",
            1_700_000_300,
        )
        .unwrap();
        let subject_device = *Uuid::parse_str("77777777-7777-4777-b777-777777777777")
            .unwrap()
            .as_bytes();
        let page = codec
            .issue_own_device_cursor(&binding, 3, &subject_device, 1_700_000_020)
            .unwrap();

        let verified = codec
            .verify_own_device_cursor(page.as_str(), &binding, 1_700_000_021, 17)
            .unwrap();
        assert_eq!(verified.device_inventory_session_id(), binding.session_id());
        assert_eq!(verified.fence_revision(), 17);
        assert_eq!(verified.last_ordinal(), 3);
        assert_eq!(
            verified.item_key_hash(),
            cursor::own_device_item_key_hash(&subject_device).unwrap()
        );
        assert_eq!(verified.expires_at(), 1_700_000_300);
    }

    #[test]
    fn event_cursor_rejects_tampering_noncanonical_encoding_and_signed_wire_changes() {
        let codec = codec();
        let device = device();
        let cursor = codec
            .issue_event_cursor(&device, 42, 10, 1_700_000_000, 1_700_000_300)
            .unwrap();
        let verify =
            |encoded: &str| codec.verify_event_cursor(encoded, &device, 1_700_000_001, 10, 42);

        assert_eq!(
            verify(&unauthenticated_body_mutation(cursor.as_str(), 70)).unwrap_err(),
            CursorCodecError::AuthenticationFailed
        );
        assert_eq!(
            verify(&format!("{}=", cursor.as_str())).unwrap_err(),
            CursorCodecError::InvalidEncoding
        );
        assert_eq!(
            verify(&noncanonical_base64url(cursor.as_str())).unwrap_err(),
            CursorCodecError::InvalidEncoding
        );
        assert_eq!(
            verify(&"A".repeat(cursor::MAX_OPAQUE_CURSOR_ASCII_BYTES + 1)).unwrap_err(),
            CursorCodecError::TooLong
        );
        assert_eq!(verify("").unwrap_err(), CursorCodecError::InvalidEncoding);
        assert_eq!(
            verify("not+a-token").unwrap_err(),
            CursorCodecError::InvalidEncoding
        );
        assert_eq!(
            verify(&signed_body_mutation(cursor.as_str(), |body| body.push(0))).unwrap_err(),
            CursorCodecError::InvalidEncoding
        );
        assert_eq!(
            verify(&signed_body_mutation(cursor.as_str(), |body| body[0] ^= 1)).unwrap_err(),
            CursorCodecError::InvalidEncoding
        );
        assert_eq!(
            verify(&signed_body_mutation(cursor.as_str(), |body| body[4] = 2)).unwrap_err(),
            CursorCodecError::UnsupportedVersion
        );
        assert_eq!(
            verify(&signed_body_mutation(cursor.as_str(), |body| body[5] = 99)).unwrap_err(),
            CursorCodecError::WrongDomain
        );
        assert_eq!(
            verify(&signed_body_mutation(cursor.as_str(), |body| body[22] ^= 1)).unwrap_err(),
            CursorCodecError::WrongKey
        );
        assert_eq!(
            verify(&signed_body_mutation(cursor.as_str(), |body| {
                body[6..22].copy_from_slice(
                    Uuid::parse_str("aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa")
                        .unwrap()
                        .as_bytes(),
                );
            }))
            .unwrap_err(),
            CursorCodecError::WrongProtocolInstance
        );
    }

    #[test]
    fn cursor_types_and_all_inventory_subdomains_are_noninterchangeable() {
        let codec = codec();
        let device = device();
        let event = codec
            .issue_event_cursor(&device, 42, 10, 1_700_000_000, 1_700_000_300)
            .unwrap();
        let session_binding = inventory_session_binding(&codec, &event);
        let session = codec
            .issue_inventory_session_id(&session_binding, 1_700_000_000, 10, 42)
            .unwrap();
        let conversations_binding =
            inventory_page_binding(&codec, InventoryPageDomain::Conversations);
        let welcomes_binding = inventory_page_binding(&codec, InventoryPageDomain::PendingWelcomes);
        let recovery_binding = inventory_page_binding(&codec, InventoryPageDomain::LeafRecovery);
        let conversations = codec
            .issue_inventory_page_cursor(
                &conversations_binding,
                1,
                b"conversation-key",
                1_700_000_000,
                10,
                42,
            )
            .unwrap();
        let welcomes = codec
            .issue_inventory_page_cursor(
                &welcomes_binding,
                1,
                b"welcome-key",
                1_700_000_000,
                10,
                42,
            )
            .unwrap();
        let recovery = codec
            .issue_inventory_page_cursor(
                &recovery_binding,
                1,
                b"recovery-key",
                1_700_000_000,
                10,
                42,
            )
            .unwrap();
        let own_binding = own_device_binding();
        let own = codec
            .issue_own_device_cursor(&own_binding, 1, b"own-device-key", 1_700_000_000)
            .unwrap();

        for foreign in [
            session.as_str(),
            conversations.as_str(),
            welcomes.as_str(),
            recovery.as_str(),
            own.as_str(),
        ] {
            assert_eq!(
                codec
                    .verify_event_cursor(foreign, &device, 1_700_000_001, 10, 42)
                    .unwrap_err(),
                CursorCodecError::WrongDomain
            );
        }

        for (foreign, expected) in [
            (event.as_str(), &conversations_binding),
            (welcomes.as_str(), &conversations_binding),
            (recovery.as_str(), &conversations_binding),
            (conversations.as_str(), &welcomes_binding),
            (conversations.as_str(), &recovery_binding),
        ] {
            assert_eq!(
                codec
                    .verify_inventory_page_cursor_for_test(
                        foreign,
                        expected,
                        1_700_000_001,
                        10,
                        42,
                    )
                    .unwrap_err(),
                CursorCodecError::WrongDomain
            );
        }

        assert_eq!(
            codec
                .verify_inventory_session_id(
                    event.as_str(),
                    &session_binding,
                    1_700_000_001,
                    10,
                    42
                )
                .unwrap_err(),
            CursorCodecError::WrongDomain
        );
        assert_eq!(
            codec
                .verify_own_device_cursor(event.as_str(), &own_binding, 1_700_000_001, 17)
                .unwrap_err(),
            CursorCodecError::WrongDomain
        );
    }

    #[test]
    fn event_cursor_enforces_time_safe_integer_floor_and_future_bounds() {
        const ABOVE_SAFE_INTEGER: u64 = 9_007_199_254_740_992;

        let codec = codec();
        let device = device();
        let cursor = codec
            .issue_event_cursor(&device, 42, 10, 1_700_000_000, 1_700_000_300)
            .unwrap();

        assert_eq!(
            codec
                .verify_event_cursor(cursor.as_str(), &device, 1_699_999_999, 10, 42)
                .unwrap_err(),
            CursorCodecError::IssuedInFuture
        );
        assert_eq!(
            codec
                .verify_event_cursor(cursor.as_str(), &device, 1_700_000_300, 10, 42)
                .unwrap_err(),
            CursorCodecError::Expired
        );
        assert_eq!(
            codec
                .verify_event_cursor(cursor.as_str(), &device, 1_700_000_001, 10, 41)
                .unwrap_err(),
            CursorCodecError::PositionInFuture
        );
        assert_eq!(
            codec
                .verify_event_cursor(cursor.as_str(), &device, 1_700_000_001, 43, 42)
                .unwrap_err(),
            CursorCodecError::InvalidField
        );

        let future_floor = codec
            .issue_event_cursor(&device, 42, 11, 1_700_000_000, 1_700_000_300)
            .unwrap();
        assert_eq!(
            codec
                .verify_event_cursor(future_floor.as_str(), &device, 1_700_000_001, 10, 42)
                .unwrap_err(),
            CursorCodecError::PositionInFuture
        );
        assert_eq!(
            codec
                .issue_event_cursor(&device, 9, 10, 1_700_000_000, 1_700_000_300)
                .unwrap_err(),
            CursorCodecError::BelowRetentionFloor
        );
        assert_eq!(
            codec
                .issue_event_cursor(
                    &device,
                    ABOVE_SAFE_INTEGER,
                    10,
                    1_700_000_000,
                    1_700_000_300,
                )
                .unwrap_err(),
            CursorCodecError::InvalidField
        );
        assert_eq!(
            codec
                .verify_event_cursor(cursor.as_str(), &device, ABOVE_SAFE_INTEGER, 10, 42)
                .unwrap_err(),
            CursorCodecError::InvalidField
        );
    }

    #[test]
    fn event_cursor_recomputes_exact_did_and_jkt_bindings_and_checks_every_device_field() {
        let codec = codec();
        let original = device();
        let cursor = codec
            .issue_event_cursor(&original, 42, 10, 1_700_000_000, 1_700_000_300)
            .unwrap();
        let alternatives = [
            bound_device("did:plc:dwvi7nxzyoun6zhxrhs64oiz", DEVICE_ID, 7, 0x61),
            bound_device(DID, "88888888-8888-4888-a888-888888888888", 7, 0x61),
            bound_device(DID, DEVICE_ID, 8, 0x61),
            bound_device(DID, DEVICE_ID, 7, 0x62),
        ];

        for expected in alternatives {
            assert_eq!(
                codec
                    .verify_event_cursor(cursor.as_str(), &expected, 1_700_000_001, 10, 42)
                    .unwrap_err(),
                CursorCodecError::BindingMismatch
            );
        }

        for invalid in [
            "d".repeat(11),
            "d".repeat(262),
            "did:plc:invalid-é".to_owned(),
        ] {
            assert!(BareDid::parse(&invalid).is_err());
        }
        assert!(KeyThumbprint::parse("not-a-canonical-thumbprint").is_err());

        let did = BareDid::parse(DID).unwrap();
        let jkt = thumbprint(0x61);
        assert_eq!(
            DeviceCursorBinding::new(&did, Uuid::nil(), 1, &jkt).unwrap_err(),
            CursorCodecError::InvalidField
        );
        assert_eq!(
            DeviceCursorBinding::new(&did, Uuid::parse_str(DEVICE_ID).unwrap(), 0, &jkt)
                .unwrap_err(),
            CursorCodecError::InvalidField
        );
    }

    #[test]
    fn inventory_session_id_enforces_exact_binding_time_and_snapshot_bounds() {
        let codec = codec();
        let snapshot_event_cursor = snapshot_event_cursor(&codec);
        let alternate_snapshot_event_cursor = codec
            .issue_event_cursor(&device(), 42, 10, 1_700_000_001, 1_700_000_300)
            .unwrap();
        let binding = inventory_session_binding(&codec, &snapshot_event_cursor);
        let session = codec
            .issue_inventory_session_id(&binding, 1_700_000_000, 10, 42)
            .unwrap();
        let other_device = bound_device("did:plc:dwvi7nxzyoun6zhxrhs64oiz", DEVICE_ID, 7, 0x61);
        let other_device_snapshot = codec
            .issue_event_cursor(&other_device, 42, 10, 1_700_000_000, 1_700_000_300)
            .unwrap();
        let future_snapshot = codec
            .issue_event_cursor(&device(), 43, 10, 1_700_000_000, 1_700_000_300)
            .unwrap();
        let later_expiry_snapshot = codec
            .issue_event_cursor(&device(), 42, 10, 1_700_000_000, 1_700_000_301)
            .unwrap();
        let alternatives = [
            codec
                .bind_inventory_session(
                    other_device,
                    Uuid::parse_str("44444444-4444-4444-8444-444444444444").unwrap(),
                    &other_device_snapshot,
                    42,
                    1_700_000_300,
                    1_700_000_001,
                    10,
                    43,
                )
                .unwrap(),
            codec
                .bind_inventory_session(
                    device(),
                    Uuid::parse_str("99999999-9999-4999-a999-999999999999").unwrap(),
                    &snapshot_event_cursor,
                    42,
                    1_700_000_300,
                    1_700_000_001,
                    10,
                    43,
                )
                .unwrap(),
            codec
                .bind_inventory_session(
                    device(),
                    Uuid::parse_str("44444444-4444-4444-8444-444444444444").unwrap(),
                    &future_snapshot,
                    43,
                    1_700_000_300,
                    1_700_000_001,
                    10,
                    43,
                )
                .unwrap(),
            codec
                .bind_inventory_session(
                    device(),
                    Uuid::parse_str("44444444-4444-4444-8444-444444444444").unwrap(),
                    &alternate_snapshot_event_cursor,
                    42,
                    1_700_000_300,
                    1_700_000_001,
                    10,
                    43,
                )
                .unwrap(),
            codec
                .bind_inventory_session(
                    device(),
                    Uuid::parse_str("44444444-4444-4444-8444-444444444444").unwrap(),
                    &later_expiry_snapshot,
                    42,
                    1_700_000_301,
                    1_700_000_001,
                    10,
                    43,
                )
                .unwrap(),
        ];
        for expected in alternatives {
            assert_eq!(
            codec
                .verify_inventory_session_id(session.as_str(), &expected, 1_700_000_001, 10, 43,)
                .unwrap_err(),
            CursorCodecError::BindingMismatch
        );
        }

        assert_eq!(
            codec
                .verify_inventory_session_id(session.as_str(), &binding, 1_699_999_999, 10, 42)
                .unwrap_err(),
            CursorCodecError::IssuedInFuture
        );
        assert_eq!(
            codec
                .verify_inventory_session_id(session.as_str(), &binding, 1_700_000_300, 10, 42)
                .unwrap_err(),
            CursorCodecError::Expired
        );
        assert_eq!(
            codec
                .verify_inventory_session_id(session.as_str(), &binding, 1_700_000_001, 43, 43)
                .unwrap_err(),
            CursorCodecError::BelowRetentionFloor
        );
        assert_eq!(
            codec
                .verify_inventory_session_id(session.as_str(), &binding, 1_700_000_001, 10, 41)
                .unwrap_err(),
            CursorCodecError::PositionInFuture
        );
        assert_eq!(
            codec
                .verify_inventory_session_id(session.as_str(), &binding, 1_700_000_001, 43, 42)
                .unwrap_err(),
            CursorCodecError::InvalidField
        );

        let expiring_snapshot = codec
            .issue_event_cursor(&device(), 42, 10, 1_699_999_999, 1_700_000_000)
            .unwrap();
        let expired_at_issue = codec
            .bind_inventory_session(
                device(),
                Uuid::parse_str("44444444-4444-4444-8444-444444444444").unwrap(),
                &expiring_snapshot,
                42,
                1_700_000_000,
                1_699_999_999,
                10,
                42,
            )
            .unwrap();
        assert_eq!(
            codec
                .issue_inventory_session_id(&expired_at_issue, 1_700_000_000, 10, 42)
                .unwrap_err(),
            CursorCodecError::InvalidField
        );
    }

    #[test]
    fn inventory_page_locator_only_selects_the_hash_bound_session_before_full_verification() {
        let codec = codec();
        let snapshot_event_cursor = snapshot_event_cursor(&codec);
        let session_binding = inventory_session_binding(&codec, &snapshot_event_cursor);
        let session = codec
            .issue_inventory_session_id(&session_binding, 1_700_000_000, 10, 43)
            .unwrap();
        let binding = codec
            .bind_inventory_page(
                &session_binding,
                &session,
                &snapshot_event_cursor,
                InventoryPageDomain::Conversations,
                b"closed-filter-v1",
                1_700_000_001,
                10,
                43,
            )
            .unwrap();
        let page = codec
            .issue_inventory_page_cursor(&binding, 9, b"conversation-key", 1_700_000_001, 10, 43)
            .unwrap();

        let locator = codec
            .locate_inventory_page_cursor(
                page.as_str(),
                InventoryPageDomain::Conversations,
                1_700_000_001,
            )
            .unwrap();
        assert_eq!(locator.session_token_hash(), session.binding_hash());
        assert_eq!(
            locator.authenticated_cursor_hash(),
            cursor::opaque_binding_hash(page.as_str().as_bytes()).unwrap()
        );

        let later_page = codec
            .issue_inventory_page_cursor(
                &binding,
                10,
                b"later-conversation-key",
                1_700_000_001,
                10,
                43,
            )
            .unwrap();
        let first_locator = codec
            .locate_inventory_page_cursor(
                page.as_str(),
                InventoryPageDomain::Conversations,
                1_700_000_001,
            )
            .unwrap();
        assert_ne!(
            first_locator.authenticated_cursor_hash(),
            cursor::opaque_binding_hash(later_page.as_str().as_bytes()).unwrap(),
            "the locator is bound to one exact page-cursor spelling"
        );

        assert_eq!(
            codec
                .locate_inventory_page_cursor(
                    page.as_str(),
                    InventoryPageDomain::PendingWelcomes,
                    1_700_000_001,
                )
                .unwrap_err(),
            CursorCodecError::WrongDomain
        );
        assert_eq!(
            codec
                .locate_inventory_page_cursor(
                    page.as_str(),
                    InventoryPageDomain::Conversations,
                    1_700_000_300,
                )
                .unwrap_err(),
            CursorCodecError::Expired
        );

        let tampered = unauthenticated_body_mutation(page.as_str(), 96);
        assert_eq!(
            codec
                .locate_inventory_page_cursor(
                    &tampered,
                    InventoryPageDomain::Conversations,
                    1_700_000_001,
                )
                .unwrap_err(),
            CursorCodecError::AuthenticationFailed
        );
    }

    #[test]
    fn inventory_page_cursor_enforces_exact_session_fence_filter_and_expiry() {
        let codec = codec();
        let snapshot_event_cursor = snapshot_event_cursor(&codec);
        let session_binding = inventory_session_binding(&codec, &snapshot_event_cursor);
        let session = codec
            .issue_inventory_session_id(&session_binding, 1_700_000_000, 10, 43)
            .unwrap();
        let binding = codec
            .bind_inventory_page(
                &session_binding,
                &session,
                &snapshot_event_cursor,
                InventoryPageDomain::Conversations,
                b"closed-filter-v1",
                1_700_000_001,
                10,
                43,
            )
            .unwrap();
        let page = codec
            .issue_inventory_page_cursor(&binding, 9, b"conversation-key", 1_700_000_001, 10, 43)
            .unwrap();

        let other_device = bound_device("did:plc:dwvi7nxzyoun6zhxrhs64oiz", DEVICE_ID, 7, 0x61);
        let other_device_snapshot = codec
            .issue_event_cursor(&other_device, 42, 10, 1_700_000_000, 1_700_000_300)
            .unwrap();
        let other_device_session_binding = codec
            .bind_inventory_session(
                other_device,
                session_binding.session_id(),
                &other_device_snapshot,
                42,
                1_700_000_300,
                1_700_000_001,
                10,
                43,
            )
            .unwrap();
        let other_device_session = codec
            .issue_inventory_session_id(&other_device_session_binding, 1_700_000_001, 10, 43)
            .unwrap();
        let other_device_binding = codec
            .bind_inventory_page(
                &other_device_session_binding,
                &other_device_session,
                &other_device_snapshot,
                InventoryPageDomain::Conversations,
                b"closed-filter-v1",
                1_700_000_001,
                10,
                43,
            )
            .unwrap();

        let alternate_session_binding = codec
            .bind_inventory_session(
                device(),
                Uuid::parse_str("99999999-9999-4999-a999-999999999999").unwrap(),
                &snapshot_event_cursor,
                42,
                1_700_000_300,
                1_700_000_001,
                10,
                43,
            )
            .unwrap();
        let alternate_session = codec
            .issue_inventory_session_id(&alternate_session_binding, 1_700_000_001, 10, 43)
            .unwrap();
        let alternate_session_page_binding = codec
            .bind_inventory_page(
                &alternate_session_binding,
                &alternate_session,
                &snapshot_event_cursor,
                InventoryPageDomain::Conversations,
                b"closed-filter-v1",
                1_700_000_001,
                10,
                43,
            )
            .unwrap();

        let future_snapshot = codec
            .issue_event_cursor(&device(), 43, 10, 1_700_000_000, 1_700_000_300)
            .unwrap();
        let future_session_binding = codec
            .bind_inventory_session(
                device(),
                session_binding.session_id(),
                &future_snapshot,
                43,
                1_700_000_300,
                1_700_000_001,
                10,
                43,
            )
            .unwrap();
        let future_session = codec
            .issue_inventory_session_id(&future_session_binding, 1_700_000_001, 10, 43)
            .unwrap();
        let future_binding = codec
            .bind_inventory_page(
                &future_session_binding,
                &future_session,
                &future_snapshot,
                InventoryPageDomain::Conversations,
                b"closed-filter-v1",
                1_700_000_001,
                10,
                43,
            )
            .unwrap();

        let alternate_snapshot_event_cursor = codec
            .issue_event_cursor(&device(), 42, 10, 1_700_000_001, 1_700_000_300)
            .unwrap();
        let alternate_snapshot_session_binding = codec
            .bind_inventory_session(
                device(),
                session_binding.session_id(),
                &alternate_snapshot_event_cursor,
                42,
                1_700_000_300,
                1_700_000_001,
                10,
                43,
            )
            .unwrap();
        let alternate_snapshot_session = codec
            .issue_inventory_session_id(&alternate_snapshot_session_binding, 1_700_000_001, 10, 43)
            .unwrap();
        let alternate_snapshot_binding = codec
            .bind_inventory_page(
                &alternate_snapshot_session_binding,
                &alternate_snapshot_session,
                &alternate_snapshot_event_cursor,
                InventoryPageDomain::Conversations,
                b"closed-filter-v1",
                1_700_000_001,
                10,
                43,
            )
            .unwrap();

        let later_expiry_snapshot = codec
            .issue_event_cursor(&device(), 42, 10, 1_700_000_000, 1_700_000_301)
            .unwrap();
        let later_expiry_session_binding = codec
            .bind_inventory_session(
                device(),
                session_binding.session_id(),
                &later_expiry_snapshot,
                42,
                1_700_000_301,
                1_700_000_001,
                10,
                43,
            )
            .unwrap();
        let later_expiry_session = codec
            .issue_inventory_session_id(&later_expiry_session_binding, 1_700_000_001, 10, 43)
            .unwrap();
        let later_expiry_binding = codec
            .bind_inventory_page(
                &later_expiry_session_binding,
                &later_expiry_session,
                &later_expiry_snapshot,
                InventoryPageDomain::Conversations,
                b"closed-filter-v1",
                1_700_000_001,
                10,
                43,
            )
            .unwrap();

        let alternate_filter_binding = codec
            .bind_inventory_page(
                &session_binding,
                &session,
                &snapshot_event_cursor,
                InventoryPageDomain::Conversations,
                b"open-filter-v1",
                1_700_000_001,
                10,
                43,
            )
            .unwrap();

        let alternatives = [
            other_device_binding,
            alternate_session_page_binding,
            future_binding,
            alternate_snapshot_binding,
            alternate_filter_binding,
            later_expiry_binding,
        ];
        for expected in alternatives {
            assert_eq!(
                codec
                    .verify_inventory_page_cursor_for_test(
                        page.as_str(),
                        &expected,
                        1_700_000_001,
                        10,
                        43,
                    )
                    .unwrap_err(),
                CursorCodecError::BindingMismatch
            );
        }

        assert_eq!(
            codec
                .verify_inventory_page_cursor_for_test(
                    page.as_str(),
                    &binding,
                    1_699_999_999,
                    10,
                    42,
                )
                .unwrap_err(),
            CursorCodecError::IssuedInFuture
        );
        assert_eq!(
            codec
                .verify_inventory_page_cursor_for_test(
                    page.as_str(),
                    &binding,
                    1_700_000_300,
                    10,
                    42,
                )
                .unwrap_err(),
            CursorCodecError::Expired
        );
        assert_eq!(
            codec
                .verify_inventory_page_cursor_for_test(
                    page.as_str(),
                    &binding,
                    1_700_000_001,
                    43,
                    43,
                )
                .unwrap_err(),
            CursorCodecError::BelowRetentionFloor
        );
        assert_eq!(
            codec
                .verify_inventory_page_cursor_for_test(
                    page.as_str(),
                    &binding,
                    1_700_000_001,
                    10,
                    41,
                )
                .unwrap_err(),
            CursorCodecError::PositionInFuture
        );
        assert_eq!(
            codec
                .issue_inventory_page_cursor(
                    &binding,
                    9_007_199_254_740_992,
                    b"conversation-key",
                    1_700_000_001,
                    10,
                    43,
                )
                .unwrap_err(),
            CursorCodecError::InvalidField
        );
    }

    #[test]
    fn own_device_cursor_enforces_exact_principal_fence_filter_and_expiry() {
        let codec = codec();
        let binding = own_device_binding();
        let page = codec
            .issue_own_device_cursor(&binding, 3, b"own-device-key", 1_700_000_000)
            .unwrap();
        let alternatives = [
            OwnDeviceCursorBinding::new(
                bound_device("did:plc:dwvi7nxzyoun6zhxrhs64oiz", DEVICE_ID, 7, 0x61),
                Uuid::parse_str("66666666-6666-4666-a666-666666666666").unwrap(),
                17,
                b"include-revoked=true",
                1_700_000_300,
            )
            .unwrap(),
            OwnDeviceCursorBinding::new(
                device(),
                Uuid::parse_str("aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa").unwrap(),
                17,
                b"include-revoked=true",
                1_700_000_300,
            )
            .unwrap(),
            OwnDeviceCursorBinding::new(
                device(),
                Uuid::parse_str("66666666-6666-4666-a666-666666666666").unwrap(),
                18,
                b"include-revoked=true",
                1_700_000_300,
            )
            .unwrap(),
            OwnDeviceCursorBinding::new(
                device(),
                Uuid::parse_str("66666666-6666-4666-a666-666666666666").unwrap(),
                17,
                b"include-revoked=false",
                1_700_000_300,
            )
            .unwrap(),
            OwnDeviceCursorBinding::new(
                device(),
                Uuid::parse_str("66666666-6666-4666-a666-666666666666").unwrap(),
                17,
                b"include-revoked=true",
                1_700_000_301,
            )
            .unwrap(),
        ];
        for expected in alternatives {
            assert_eq!(
                codec
                    .verify_own_device_cursor(page.as_str(), &expected, 1_700_000_001, 18)
                    .unwrap_err(),
                CursorCodecError::BindingMismatch
            );
        }

        assert_eq!(
            codec
                .verify_own_device_cursor(page.as_str(), &binding, 1_699_999_999, 17)
                .unwrap_err(),
            CursorCodecError::IssuedInFuture
        );
        assert_eq!(
            codec
                .verify_own_device_cursor(page.as_str(), &binding, 1_700_000_300, 17)
                .unwrap_err(),
            CursorCodecError::Expired
        );
        assert_eq!(
            codec
                .verify_own_device_cursor(page.as_str(), &binding, 1_700_000_001, 16)
                .unwrap_err(),
            CursorCodecError::PositionInFuture
        );
        assert_eq!(
            codec
                .issue_own_device_cursor(
                    &binding,
                    9_007_199_254_740_992,
                    b"own-device-key",
                    1_700_000_000,
                )
                .unwrap_err(),
            CursorCodecError::InvalidField
        );
    }

    #[test]
    fn codec_configuration_is_exact_and_key_and_instance_fail_closed() {
        let good_key_id = URL_SAFE_NO_PAD.encode([0x41; 32]);
        let protocol_instance = Uuid::parse_str(PROTOCOL_INSTANCE).unwrap();
        assert_eq!(
            CursorCodec::new(protocol_instance, &good_key_id, Zeroizing::new([0; 32]))
                .err()
                .unwrap(),
            CursorCodecError::InvalidConfiguration
        );
        assert_eq!(
            CursorCodec::new(Uuid::nil(), &good_key_id, Zeroizing::new([0xA5; 32]),)
                .err()
                .unwrap(),
            CursorCodecError::InvalidConfiguration
        );
        for invalid_key_id in [
            format!("{good_key_id}="),
            URL_SAFE_NO_PAD.encode([0x41; 31]),
            noncanonical_base64url(&good_key_id),
        ] {
            assert_eq!(
                CursorCodec::new(
                    protocol_instance,
                    &invalid_key_id,
                    Zeroizing::new([0xA5; 32]),
                )
                .err()
                .unwrap(),
                CursorCodecError::InvalidConfiguration
            );
        }

        let issuer = codec();
        let device = device();
        let cursor = issuer
            .issue_event_cursor(&device, 42, 10, 1_700_000_000, 1_700_000_300)
            .unwrap();
        let wrong_key = CursorCodec::new(
            protocol_instance,
            &URL_SAFE_NO_PAD.encode([0x42; 32]),
            Zeroizing::new([0xA5; 32]),
        )
        .unwrap();
        assert_eq!(
            wrong_key
                .verify_event_cursor(cursor.as_str(), &device, 1_700_000_001, 10, 42)
                .unwrap_err(),
            CursorCodecError::WrongKey
        );
        let wrong_instance = CursorCodec::new(
            Uuid::parse_str("bbbbbbbb-bbbb-4bbb-abbb-bbbbbbbbbbbb").unwrap(),
            &good_key_id,
            Zeroizing::new([0xA5; 32]),
        )
        .unwrap();
        assert_eq!(
            wrong_instance
                .verify_event_cursor(cursor.as_str(), &device, 1_700_000_001, 10, 42)
                .unwrap_err(),
            CursorCodecError::WrongProtocolInstance
        );
        let wrong_secret =
            CursorCodec::new(protocol_instance, &good_key_id, Zeroizing::new([0xA6; 32])).unwrap();
        assert_eq!(
            wrong_secret
                .verify_event_cursor(cursor.as_str(), &device, 1_700_000_001, 10, 42)
                .unwrap_err(),
            CursorCodecError::AuthenticationFailed
        );
    }

    #[test]
    fn hashes_and_filters_are_domain_separated_and_strictly_bounded() {
        let codec = codec();
        let snapshot_event_cursor = snapshot_event_cursor(&codec);
        let session_binding = inventory_session_binding(&codec, &snapshot_event_cursor);
        let inventory_session = codec
            .issue_inventory_session_id(&session_binding, 1_700_000_000, 10, 42)
            .unwrap();

        assert!(cursor::opaque_binding_hash(&[0x11; 512]).is_ok());
        assert_eq!(
            cursor::opaque_binding_hash(&[]).unwrap_err(),
            CursorCodecError::InvalidField
        );
        assert_eq!(
            cursor::opaque_binding_hash(&[0x11; 513]).unwrap_err(),
            CursorCodecError::InvalidField
        );

        for domain in [
            InventoryPageDomain::Conversations,
            InventoryPageDomain::PendingWelcomes,
            InventoryPageDomain::LeafRecovery,
        ] {
            assert!(cursor::inventory_item_key_hash(domain, &[0x22; 512]).is_ok());
            assert_eq!(
                cursor::inventory_item_key_hash(domain, &[]).unwrap_err(),
                CursorCodecError::InvalidField
            );
            assert_eq!(
                cursor::inventory_item_key_hash(domain, &[0x22; 513]).unwrap_err(),
                CursorCodecError::InvalidField
            );
        }
        let conversation_hash =
            cursor::inventory_item_key_hash(InventoryPageDomain::Conversations, b"same").unwrap();
        let welcome_hash =
            cursor::inventory_item_key_hash(InventoryPageDomain::PendingWelcomes, b"same").unwrap();
        let recovery_hash =
            cursor::inventory_item_key_hash(InventoryPageDomain::LeafRecovery, b"same").unwrap();
        assert_ne!(conversation_hash, welcome_hash);
        assert_ne!(conversation_hash, recovery_hash);
        assert_ne!(welcome_hash, recovery_hash);
        assert_ne!(
            conversation_hash,
            cursor::own_device_item_key_hash(b"same").unwrap()
        );

        assert!(codec
            .bind_inventory_page(
                &session_binding,
                &inventory_session,
                &snapshot_event_cursor,
                InventoryPageDomain::Conversations,
                &[0x33; 1_024],
                1_700_000_001,
                10,
                42,
            )
            .is_ok());
        assert_eq!(
            codec
                .bind_inventory_page(
                    &session_binding,
                    &inventory_session,
                    &snapshot_event_cursor,
                    InventoryPageDomain::Conversations,
                    &[0x33; 1_025],
                    1_700_000_001,
                    10,
                    42,
                )
                .unwrap_err(),
            CursorCodecError::InvalidField
        );
        assert!(cursor::own_device_item_key_hash(&[0x44; 512]).is_ok());
        assert_eq!(
            cursor::own_device_item_key_hash(&[]).unwrap_err(),
            CursorCodecError::InvalidField
        );
        assert_eq!(
            cursor::own_device_item_key_hash(&[0x44; 513]).unwrap_err(),
            CursorCodecError::InvalidField
        );
        assert!(OwnDeviceCursorBinding::new(
            device(),
            Uuid::parse_str("66666666-6666-4666-a666-666666666666").unwrap(),
            17,
            &[0x55; 1_024],
            1_700_000_300,
        )
        .is_ok());
        assert_eq!(
            OwnDeviceCursorBinding::new(
                device(),
                Uuid::parse_str("66666666-6666-4666-a666-666666666666").unwrap(),
                17,
                &[0x55; 1_025],
                1_700_000_300,
            )
            .unwrap_err(),
            CursorCodecError::InvalidField
        );
    }

    #[test]
    fn opaque_values_have_redacted_debug_and_remain_within_the_public_limit() {
        let codec = codec();
        let event = codec
            .issue_event_cursor(&device(), 42, 10, 1_700_000_000, 1_700_000_300)
            .unwrap();
        let session_binding = inventory_session_binding(&codec, &event);
        let session = codec
            .issue_inventory_session_id(&session_binding, 1_700_000_000, 10, 42)
            .unwrap();
        let page = codec
            .issue_inventory_page_cursor(
                &inventory_page_binding(&codec, InventoryPageDomain::Conversations),
                9,
                &[0x66; 512],
                1_700_000_000,
                10,
                42,
            )
            .unwrap();
        let own = codec
            .issue_own_device_cursor(&own_device_binding(), 3, &[0x77; 512], 1_700_000_000)
            .unwrap();

        for (encoded, debugged) in [
            (event.as_str(), format!("{event:?}")),
            (session.as_str(), format!("{session:?}")),
            (page.as_str(), format!("{page:?}")),
            (own.as_str(), format!("{own:?}")),
        ] {
            assert!(encoded.len() <= cursor::MAX_OPAQUE_CURSOR_ASCII_BYTES);
            assert!(!debugged.contains(encoded));
            assert!(debugged.contains("REDACTED"));
        }
    }

    #[test]
    fn inventory_session_issuance_rejects_mismatched_nested_event_evidence() {
        let codec = codec();
        let snapshot = snapshot_event_cursor(&codec);
        let other_device = bound_device(DID, "88888888-8888-4888-a888-888888888888", 7, 0x61);
        let session_id = Uuid::parse_str("44444444-4444-4444-8444-444444444444").unwrap();

        for (expected_device, expected_position, expected_expiry) in [
            (other_device, 42, 1_700_000_300),
            (device(), 41, 1_700_000_300),
            (device(), 42, 1_700_000_299),
        ] {
            assert_eq!(
                codec
                    .bind_inventory_session(
                        expected_device,
                        session_id,
                        &snapshot,
                        expected_position,
                        expected_expiry,
                        1_700_000_001,
                        10,
                        42,
                    )
                    .unwrap_err(),
                CursorCodecError::BindingMismatch
            );
        }

        let binding = inventory_session_binding(&codec, &snapshot);
        let key_id = URL_SAFE_NO_PAD.encode([0x41; 32]);
        let wrong_secret = CursorCodec::new(
            Uuid::parse_str(PROTOCOL_INSTANCE).unwrap(),
            &key_id,
            Zeroizing::new([0xA6; 32]),
        )
        .unwrap();
        assert_eq!(
            wrong_secret
                .issue_inventory_session_id(&binding, 1_700_000_001, 10, 42)
                .unwrap_err(),
            CursorCodecError::AuthenticationFailed
        );
        let wrong_key = CursorCodec::new(
            Uuid::parse_str(PROTOCOL_INSTANCE).unwrap(),
            &URL_SAFE_NO_PAD.encode([0x42; 32]),
            Zeroizing::new([0xA5; 32]),
        )
        .unwrap();
        assert_eq!(
            wrong_key
                .issue_inventory_session_id(&binding, 1_700_000_001, 10, 42)
                .unwrap_err(),
            CursorCodecError::WrongKey
        );
        let wrong_instance = CursorCodec::new(
            Uuid::parse_str("bbbbbbbb-bbbb-4bbb-abbb-bbbbbbbbbbbb").unwrap(),
            &key_id,
            Zeroizing::new([0xA5; 32]),
        )
        .unwrap();
        assert_eq!(
            wrong_instance
                .issue_inventory_session_id(&binding, 1_700_000_001, 10, 42)
                .unwrap_err(),
            CursorCodecError::WrongProtocolInstance
        );
    }

    #[test]
    fn inventory_page_issuance_rejects_mismatched_nested_session_and_event_evidence() {
        let codec = codec();
        let snapshot = snapshot_event_cursor(&codec);
        let session_binding = inventory_session_binding(&codec, &snapshot);
        let session = codec
            .issue_inventory_session_id(&session_binding, 1_700_000_000, 10, 42)
            .unwrap();
        let other_snapshot = codec
            .issue_event_cursor(&device(), 41, 10, 1_700_000_000, 1_700_000_300)
            .unwrap();
        let other_session_binding = codec
            .bind_inventory_session(
                device(),
                Uuid::parse_str("99999999-9999-4999-a999-999999999999").unwrap(),
                &other_snapshot,
                41,
                1_700_000_300,
                1_700_000_001,
                10,
                42,
            )
            .unwrap();
        let other_session = codec
            .issue_inventory_session_id(&other_session_binding, 1_700_000_001, 10, 42)
            .unwrap();
        let other_device = bound_device(DID, "88888888-8888-4888-a888-888888888888", 7, 0x61);
        let other_device_snapshot = codec
            .issue_event_cursor(&other_device, 42, 10, 1_700_000_000, 1_700_000_300)
            .unwrap();
        let other_device_session_binding = codec
            .bind_inventory_session(
                other_device,
                session_binding.session_id(),
                &other_device_snapshot,
                42,
                1_700_000_300,
                1_700_000_001,
                10,
                42,
            )
            .unwrap();

        for result in [
            codec.bind_inventory_page(
                &session_binding,
                &session,
                &other_snapshot,
                InventoryPageDomain::Conversations,
                b"closed-filter-v1",
                1_700_000_001,
                10,
                42,
            ),
            codec.bind_inventory_page(
                &session_binding,
                &other_session,
                &snapshot,
                InventoryPageDomain::Conversations,
                b"closed-filter-v1",
                1_700_000_001,
                10,
                42,
            ),
            codec.bind_inventory_page(
                &other_session_binding,
                &session,
                &other_snapshot,
                InventoryPageDomain::Conversations,
                b"closed-filter-v1",
                1_700_000_001,
                10,
                42,
            ),
            codec.bind_inventory_page(
                &other_device_session_binding,
                &other_session,
                &other_device_snapshot,
                InventoryPageDomain::Conversations,
                b"closed-filter-v1",
                1_700_000_001,
                10,
                42,
            ),
        ] {
            assert_eq!(result.unwrap_err(), CursorCodecError::BindingMismatch);
        }

        let binding = codec
            .bind_inventory_page(
                &session_binding,
                &session,
                &snapshot,
                InventoryPageDomain::Conversations,
                b"closed-filter-v1",
                1_700_000_001,
                10,
                42,
            )
            .unwrap();
        let key_id = URL_SAFE_NO_PAD.encode([0x41; 32]);
        let wrong_secret = CursorCodec::new(
            Uuid::parse_str(PROTOCOL_INSTANCE).unwrap(),
            &key_id,
            Zeroizing::new([0xA6; 32]),
        )
        .unwrap();
        assert_eq!(
            wrong_secret
                .issue_inventory_page_cursor(
                    &binding,
                    9,
                    b"conversation-key",
                    1_700_000_001,
                    10,
                    42,
                )
                .unwrap_err(),
            CursorCodecError::AuthenticationFailed
        );
        let wrong_key = CursorCodec::new(
            Uuid::parse_str(PROTOCOL_INSTANCE).unwrap(),
            &URL_SAFE_NO_PAD.encode([0x42; 32]),
            Zeroizing::new([0xA5; 32]),
        )
        .unwrap();
        assert_eq!(
            wrong_key
                .issue_inventory_page_cursor(
                    &binding,
                    9,
                    b"conversation-key",
                    1_700_000_001,
                    10,
                    42,
                )
                .unwrap_err(),
            CursorCodecError::WrongKey
        );
        let wrong_instance = CursorCodec::new(
            Uuid::parse_str("bbbbbbbb-bbbb-4bbb-abbb-bbbbbbbbbbbb").unwrap(),
            &key_id,
            Zeroizing::new([0xA5; 32]),
        )
        .unwrap();
        assert_eq!(
            wrong_instance
                .issue_inventory_page_cursor(
                    &binding,
                    9,
                    b"conversation-key",
                    1_700_000_001,
                    10,
                    42,
                )
                .unwrap_err(),
            CursorCodecError::WrongProtocolInstance
        );
    }

    #[test]
    fn event_cursor_rehydrates_after_restart_from_exact_bytes_digest_and_binding() {
        let issuer = codec();
        let device = device();
        let issued = issuer
            .issue_event_cursor(&device, 42, 10, 1_700_000_000, 1_700_000_300)
            .unwrap();
        let persisted_bytes = issued.as_str().as_bytes().to_vec();
        let persisted_sha256 = issued.binding_hash();
        drop(issuer);
        drop(issued);

        let restarted = codec();
        let hydrated = restarted
            .hydrate_event_cursor(
                &persisted_bytes,
                persisted_sha256,
                &device,
                42,
                1_700_000_300,
                1_700_000_001,
                10,
                42,
            )
            .unwrap();

        assert_eq!(hydrated.as_str().as_bytes(), persisted_bytes);
        assert_eq!(hydrated.binding_hash(), persisted_sha256);
    }

    #[test]
    fn event_cursor_restart_hydration_rejects_digest_device_position_and_expiry_mismatches() {
        let issuer = codec();
        let expected_device = device();
        let issued = issuer
            .issue_event_cursor(&expected_device, 42, 10, 1_700_000_000, 1_700_000_300)
            .unwrap();
        let persisted_bytes = issued.as_str().as_bytes().to_vec();
        let persisted_sha256 = issued.binding_hash();
        let restarted = codec();
        let wrong_device = bound_device(DID, "88888888-8888-4888-a888-888888888888", 7, 0x61);
        let mut wrong_sha256 = persisted_sha256;
        wrong_sha256[0] ^= 1;

        assert_eq!(
            restarted
                .hydrate_event_cursor(
                    &persisted_bytes,
                    wrong_sha256,
                    &expected_device,
                    42,
                    1_700_000_300,
                    1_700_000_001,
                    10,
                    42,
                )
                .unwrap_err(),
            CursorCodecError::DigestMismatch
        );
        for (device, position, expires_at) in [
            (&wrong_device, 42, 1_700_000_300),
            (&expected_device, 41, 1_700_000_300),
            (&expected_device, 42, 1_700_000_299),
        ] {
            assert_eq!(
                restarted
                    .hydrate_event_cursor(
                        &persisted_bytes,
                        persisted_sha256,
                        device,
                        position,
                        expires_at,
                        1_700_000_001,
                        10,
                        42,
                    )
                    .unwrap_err(),
                CursorCodecError::BindingMismatch
            );
        }
    }

    #[test]
    fn inventory_session_token_rehydrates_after_restart_only_from_exact_nested_evidence() {
        let issuer = codec();
        let device = device();
        let snapshot = snapshot_event_cursor(&issuer);
        let session_id = Uuid::parse_str("44444444-4444-4444-8444-444444444444").unwrap();
        let binding = issuer
            .bind_inventory_session(
                device.clone(),
                session_id,
                &snapshot,
                42,
                1_700_000_300,
                1_700_000_001,
                10,
                42,
            )
            .unwrap();
        let issued = issuer
            .issue_inventory_session_id(&binding, 1_700_000_001, 10, 42)
            .unwrap();
        let event_bytes = snapshot.as_str().as_bytes().to_vec();
        let event_sha256 = snapshot.binding_hash();
        let session_bytes = issued.as_str().as_bytes().to_vec();
        let session_sha256 = issued.binding_hash();
        drop(issuer);
        drop(binding);
        drop(snapshot);
        drop(issued);

        let restarted = codec();
        let hydrated_event = restarted
            .hydrate_event_cursor(
                &event_bytes,
                event_sha256,
                &device,
                42,
                1_700_000_300,
                1_700_000_002,
                10,
                42,
            )
            .unwrap();
        let hydrated_binding = restarted
            .bind_inventory_session(
                device,
                session_id,
                &hydrated_event,
                42,
                1_700_000_300,
                1_700_000_002,
                10,
                42,
            )
            .unwrap();
        let hydrated_session = restarted
            .hydrate_inventory_session_token(
                &session_bytes,
                session_sha256,
                &hydrated_binding,
                1_700_000_002,
                10,
                42,
            )
            .unwrap();

        assert_eq!(hydrated_session.as_str().as_bytes(), session_bytes);
        assert_eq!(hydrated_session.binding_hash(), session_sha256);
    }

    #[test]
    fn inventory_session_restart_hydration_rejects_digest_and_session_mismatches() {
        let codec = codec();
        let snapshot = snapshot_event_cursor(&codec);
        let session_id = Uuid::parse_str("44444444-4444-4444-8444-444444444444").unwrap();
        let binding = codec
            .bind_inventory_session(
                device(),
                session_id,
                &snapshot,
                42,
                1_700_000_300,
                1_700_000_001,
                10,
                42,
            )
            .unwrap();
        let session = codec
            .issue_inventory_session_id(&binding, 1_700_000_001, 10, 42)
            .unwrap();
        let persisted_bytes = session.as_str().as_bytes().to_vec();
        let persisted_sha256 = session.binding_hash();
        let mut wrong_sha256 = persisted_sha256;
        wrong_sha256[0] ^= 1;

        assert_eq!(
            codec
                .hydrate_inventory_session_token(
                    &persisted_bytes,
                    wrong_sha256,
                    &binding,
                    1_700_000_002,
                    10,
                    42,
                )
                .unwrap_err(),
            CursorCodecError::DigestMismatch
        );

        let other_binding = codec
            .bind_inventory_session(
                device(),
                Uuid::parse_str("99999999-9999-4999-a999-999999999999").unwrap(),
                &snapshot,
                42,
                1_700_000_300,
                1_700_000_002,
                10,
                42,
            )
            .unwrap();
        assert_eq!(
            codec
                .hydrate_inventory_session_token(
                    &persisted_bytes,
                    persisted_sha256,
                    &other_binding,
                    1_700_000_002,
                    10,
                    42,
                )
                .unwrap_err(),
            CursorCodecError::BindingMismatch
        );
    }
}
