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

// The HMAC codec surface is retained byte-stable for the lane D-2 rewiring
// and the own-device codec for lane F; this test crate exercises it only
// through the kept own-device and hash tests.
#[allow(dead_code)]
mod cursor {
    include!("../src/chat_protocol/cursor.rs");
}

mod cursor_tests {
    use super::cursor::{
        self, decode_capability_token, mint_capability_token, CapabilityToken, CursorCodec,
        CursorCodecError, CursorSealer, DeviceCursorBinding, EventCursor, InventoryPageDomain,
        InventorySessionBinding, OsSecureRandom, OwnDeviceCursorBinding, SealedCapability,
        SealerBinding, SealerError, SecureRandom, SecureRandomError,
    };
    use super::validation::{BareDid, KeyThumbprint};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use sha2::{Digest as _, Sha256};
    use uuid::Uuid;
    use zeroize::Zeroizing;

    const DID: &str = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";
    const DEVICE_ID: &str = "3b241101-e2bb-4255-8caf-4136c566a962";
    const PROTOCOL_INSTANCE: &str = "018f3f6a-7b2c-4d91-8a5e-0f123456789a";
    const SESSION_ID: &str = "44444444-4444-4444-8444-444444444444";
    const ENDPOINT_NSID: &str = "blue.catbird.mls.getInventoryConversations";

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

    fn inventory_session_binding(
        codec: &CursorCodec,
        snapshot_event_cursor: &EventCursor,
    ) -> InventorySessionBinding {
        codec
            .bind_inventory_session(
                device(),
                Uuid::parse_str(SESSION_ID).unwrap(),
                snapshot_event_cursor,
                42,
                1_700_000_300,
                1_700_000_001,
                10,
                42,
            )
            .unwrap()
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

    fn sealer() -> CursorSealer {
        CursorSealer::new([0x41; 32], Zeroizing::new([0xA5; 32]))
            .expect("a non-zero sealing secret is a valid configuration")
    }

    /// Deterministic `SecureRandom` for reproducible tests. xorshift64* is
    /// bijective, so every fill starts from a distinct state and consecutive
    /// 12-byte nonce windows are distinct.
    struct DeterministicRandom {
        state: u64,
    }

    impl DeterministicRandom {
        fn new(seed: u64) -> Self {
            Self { state: seed }
        }
    }

    impl SecureRandom for DeterministicRandom {
        fn fill(&mut self, out: &mut [u8]) -> Result<(), SecureRandomError> {
            for chunk in out.chunks_mut(8) {
                self.state ^= self.state >> 12;
                self.state ^= self.state << 25;
                self.state ^= self.state >> 27;
                self.state = self.state.wrapping_mul(0x2545_F491_4F6C_DD1D);
                let bytes = self.state.to_be_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
            Ok(())
        }
    }

    /// Receipt-row-shaped page binding with every AAD field, mirroring an
    /// `inventory_page_receipts` row; individual fields are mutable so a test
    /// can vary exactly one AAD field at a time.
    #[allow(dead_code)]
    struct PageSpec {
        domain: Vec<u8>,
        endpoint_nsid: Vec<u8>,
        cursor_format_version: u16,
        inventory_session_id: Uuid,
        user_did: Vec<u8>,
        device_id: Uuid,
        jkt: Vec<u8>,
        auth_generation: u64,
        protocol_instance_id: Uuid,
        cursor_key_id: Vec<u8>,
        snapshot_event_position: u64,
        snapshot_event_cursor_sha256: [u8; 32],
        snapshot_retained_floor: u64,
        canonical_filter_sha256: [u8; 32],
        page_limit: u16,
        after_ordinal: Option<u64>,
        successor_cursor_hash: Option<[u8; 32]>,
        created_at: u64,
        expires_at: u64,
    }

    impl PageSpec {
        fn default() -> Self {
            Self {
                domain: b"conversations".to_vec(),
                endpoint_nsid: ENDPOINT_NSID.as_bytes().to_vec(),
                cursor_format_version: 1,
                inventory_session_id: Uuid::parse_str(SESSION_ID).unwrap(),
                user_did: DID.as_bytes().to_vec(),
                device_id: Uuid::parse_str(DEVICE_ID).unwrap(),
                jkt: URL_SAFE_NO_PAD.encode([0x61; 32]).into_bytes(),
                auth_generation: 7,
                protocol_instance_id: Uuid::parse_str(PROTOCOL_INSTANCE).unwrap(),
                cursor_key_id: URL_SAFE_NO_PAD.encode([0x41; 32]).into_bytes(),
                snapshot_event_position: 42,
                snapshot_event_cursor_sha256: [0x11; 32],
                snapshot_retained_floor: 10,
                canonical_filter_sha256: [0x22; 32],
                page_limit: 100,
                after_ordinal: Some(9),
                successor_cursor_hash: None,
                created_at: 1_700_000_000,
                expires_at: 1_700_000_300,
            }
        }

        fn try_to_binding(&self) -> Result<SealerBinding, SealerError> {
            SealerBinding::for_page_receipt(
                &self.domain,
                &self.endpoint_nsid,
                self.cursor_format_version,
                self.inventory_session_id,
                &self.user_did,
                self.device_id,
                &self.jkt,
                self.auth_generation,
                self.protocol_instance_id,
                &self.cursor_key_id,
                self.snapshot_event_position,
                self.snapshot_event_cursor_sha256,
                self.snapshot_retained_floor,
                self.canonical_filter_sha256,
                self.page_limit,
                self.after_ordinal,
                self.successor_cursor_hash,
                self.created_at,
                self.expires_at,
            )
        }

        fn to_binding(&self) -> SealerBinding {
            self.try_to_binding().unwrap()
        }
    }

    fn page_binding(successor_hash: Option<[u8; 32]>) -> SealerBinding {
        let mut spec = PageSpec::default();
        spec.successor_cursor_hash = successor_hash;
        spec.to_binding()
    }

    fn event_binding() -> SealerBinding {
        SealerBinding::for_event_cursor_receipt(
            Uuid::parse_str(SESSION_ID).unwrap(),
            DID.as_bytes(),
            Uuid::parse_str(DEVICE_ID).unwrap(),
            URL_SAFE_NO_PAD.encode([0x61; 32]).as_bytes(),
            7,
            Uuid::parse_str(PROTOCOL_INSTANCE).unwrap(),
            URL_SAFE_NO_PAD.encode([0x41; 32]).as_bytes(),
            42,
            None,
            10,
            1_700_000_000,
            1_700_000_300,
        )
        .unwrap()
    }

    fn noncanonical_trailing_bits(encoded: &str) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

        let mut bytes = encoded.as_bytes().to_vec();
        let last = bytes.last_mut().unwrap();
        let index = ALPHABET
            .iter()
            .position(|candidate| candidate == last)
            .unwrap();
        let replacement = match encoded.len() % 4 {
            2 | 3 => index | 1,
            remainder => panic!("encoded value has no unused trailing bits: {remainder}"),
        };
        *last = ALPHABET[replacement];
        String::from_utf8(bytes).unwrap()
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
    fn capability_minting_uses_exactly_32_csprng_bytes_and_43_char_base64url() {
        let mut os = OsSecureRandom::new();
        let mut deterministic = DeterministicRandom::new(0x5EED);
        for random in [&mut os as &mut dyn SecureRandom, &mut deterministic] {
            let token = mint_capability_token(random).unwrap();
            assert_eq!(token.as_bytes().len(), 32);
            let encoded = token.encode();
            assert_eq!(encoded.len(), 43);
            assert!(encoded.is_ascii());
            assert!(!encoded.contains('='));
            assert_eq!(URL_SAFE_NO_PAD.decode(&encoded).unwrap().len(), 32);
            let decoded = decode_capability_token(&encoded).unwrap();
            assert_eq!(decoded.as_bytes(), token.as_bytes());
        }
    }

    #[test]
    fn capability_lookup_is_sha256_only_and_public_token_leaks_no_binding_fields() {
        let mut random = DeterministicRandom::new(0xCAFE);
        let token = mint_capability_token(&mut random).unwrap();
        let encoded = token.encode();
        let lookup = token.lookup_hash();

        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        assert_eq!(lookup, digest);

        let fields = [
            b"conversations".as_slice(),
            ENDPOINT_NSID.as_bytes(),
            SESSION_ID.as_bytes(),
            DID.as_bytes(),
            DEVICE_ID.as_bytes(),
            PROTOCOL_INSTANCE.as_bytes(),
        ];
        for field in fields {
            assert!(
                !encoded
                    .as_bytes()
                    .windows(field.len())
                    .any(|window| window == field),
                "the public token must not carry binding material"
            );
        }

        let decoded = decode_capability_token(&encoded).unwrap();
        assert_eq!(decoded.as_bytes(), token.as_bytes());
        assert_eq!(decoded.lookup_hash(), lookup);
        let unrelated: [u8; 32] = Sha256::digest(b"conversations").into();
        assert_ne!(lookup, unrelated);
    }

    #[test]
    fn sealed_successors_verify_round_trip_byte_exact() {
        let mut random = DeterministicRandom::new(0x0123);
        let sealer = sealer();
        let successor = mint_capability_token(&mut random).unwrap();
        let binding = page_binding(Some(successor.lookup_hash()));
        let sealed = sealer
            .seal_successor(successor.as_bytes(), &binding, &mut random)
            .unwrap();

        let verified = sealer.verify_successor(&sealed, &binding).unwrap();
        assert_eq!(verified.as_slice(), successor.as_bytes());

        let replayed = sealer.verify_successor(&sealed, &binding).unwrap();
        assert_eq!(replayed.as_slice(), verified.as_slice());
        assert_eq!(replayed.as_slice(), successor.as_bytes());
    }

    #[test]
    fn seal_generates_a_fresh_unique_nonce_per_successor() {
        let mut deterministic = DeterministicRandom::new(0xBEAD);
        let sealer = sealer();
        let mut nonces = std::collections::HashSet::new();
        for _ in 0..128 {
            let successor = mint_capability_token(&mut deterministic).unwrap();
            let binding = page_binding(Some(successor.lookup_hash()));
            let sealed = sealer
                .seal_successor(successor.as_bytes(), &binding, &mut deterministic)
                .unwrap();
            assert!(nonces.insert(sealed.nonce), "nonce must be unique per seal");
            assert!((17..=cursor::MAX_SEALED_CIPHERTEXT_BYTES).contains(&sealed.ciphertext.len()));
        }

        let mut os = OsSecureRandom::new();
        let mut os_nonces = std::collections::HashSet::new();
        for _ in 0..32 {
            let successor = mint_capability_token(&mut os).unwrap();
            let binding = page_binding(Some(successor.lookup_hash()));
            let sealed = sealer
                .seal_successor(successor.as_bytes(), &binding, &mut os)
                .unwrap();
            assert!(
                os_nonces.insert(sealed.nonce),
                "nonce must be unique per seal"
            );
        }
    }

    #[test]
    fn verify_rejects_wrong_secret_key() {
        let mut random = DeterministicRandom::new(0x1111);
        let issuer = sealer();
        let successor = mint_capability_token(&mut random).unwrap();
        let binding = page_binding(Some(successor.lookup_hash()));
        let sealed = issuer
            .seal_successor(successor.as_bytes(), &binding, &mut random)
            .unwrap();

        let wrong_secret = CursorSealer::new([0x41; 32], Zeroizing::new([0xA6; 32]))
            .expect("a non-zero sealing secret is a valid configuration");
        assert_eq!(
            wrong_secret
                .verify_successor(&sealed, &binding)
                .unwrap_err(),
            SealerError::AuthenticationFailed
        );
    }

    #[test]
    fn seal_and_verify_reject_wrong_key_id() {
        let mut random = DeterministicRandom::new(0x2222);
        let issuer = sealer();
        let successor = mint_capability_token(&mut random).unwrap();
        let binding = page_binding(Some(successor.lookup_hash()));
        let sealed = issuer
            .seal_successor(successor.as_bytes(), &binding, &mut random)
            .unwrap();

        let wrong_key_id = CursorSealer::new([0x42; 32], Zeroizing::new([0xA5; 32]))
            .expect("a non-zero sealing secret is a valid configuration");
        assert_eq!(
            wrong_key_id
                .verify_successor(&sealed, &binding)
                .unwrap_err(),
            SealerError::WrongKey
        );
        assert_eq!(
            wrong_key_id
                .seal_successor(successor.as_bytes(), &binding, &mut random)
                .unwrap_err(),
            SealerError::WrongKey
        );
    }

    #[test]
    fn verify_rejects_wrong_domain_binding() {
        let mut random = DeterministicRandom::new(0x3333);
        let sealer = sealer();
        let successor = mint_capability_token(&mut random).unwrap();
        let binding = page_binding(Some(successor.lookup_hash()));
        let sealed = sealer
            .seal_successor(successor.as_bytes(), &binding, &mut random)
            .unwrap();

        let mut spec = PageSpec::default();
        spec.domain = b"recovery".to_vec();
        spec.successor_cursor_hash = Some(successor.lookup_hash());
        assert_eq!(
            sealer
                .verify_successor(&sealed, &spec.to_binding())
                .unwrap_err(),
            SealerError::AuthenticationFailed
        );
    }

    #[test]
    fn verify_rejects_every_wrong_aad_field() {
        let mut random = DeterministicRandom::new(0x4444);
        let sealer = sealer();
        let successor = mint_capability_token(&mut random).unwrap();
        let mut reference = PageSpec::default();
        reference.successor_cursor_hash = Some(successor.lookup_hash());
        let binding = reference.to_binding();
        let sealed = sealer
            .seal_successor(successor.as_bytes(), &binding, &mut random)
            .unwrap();

        let variants: Vec<Box<dyn FnOnce(&mut PageSpec)>> = vec![
            Box::new(|spec| spec.domain = b"welcomes".to_vec()),
            Box::new(|spec| spec.endpoint_nsid = b"blue.catbird.mls.getInventoryRecovery".to_vec()),
            Box::new(|spec| spec.cursor_format_version = 2),
            Box::new(|spec| {
                spec.inventory_session_id =
                    Uuid::parse_str("99999999-9999-4999-a999-999999999999").unwrap()
            }),
            Box::new(|spec| spec.user_did = b"did:plc:dwvi7nxzyoun6zhxrhs64oiz".to_vec()),
            Box::new(|spec| {
                spec.device_id = Uuid::parse_str("88888888-8888-4888-a888-888888888888").unwrap()
            }),
            Box::new(|spec| spec.jkt = URL_SAFE_NO_PAD.encode([0x62; 32]).into_bytes()),
            Box::new(|spec| spec.auth_generation = 8),
            Box::new(|spec| {
                spec.protocol_instance_id =
                    Uuid::parse_str("bbbbbbbb-bbbb-4bbb-abbb-bbbbbbbbbbbb").unwrap()
            }),
            Box::new(|spec| spec.snapshot_event_position = 43),
            Box::new(|spec| spec.snapshot_event_cursor_sha256 = [0x12; 32]),
            Box::new(|spec| spec.snapshot_retained_floor = 11),
            Box::new(|spec| spec.canonical_filter_sha256 = [0x23; 32]),
            Box::new(|spec| spec.page_limit = 50),
            Box::new(|spec| spec.after_ordinal = Some(10)),
            Box::new(|spec| spec.after_ordinal = None),
            Box::new(|spec| spec.created_at = 1_700_000_001),
            Box::new(|spec| spec.expires_at = 1_700_000_301),
        ];
        for mutate in variants {
            let mut spec = PageSpec::default();
            spec.successor_cursor_hash = Some(successor.lookup_hash());
            mutate(&mut spec);
            assert_eq!(
                sealer
                    .verify_successor(&sealed, &spec.to_binding())
                    .unwrap_err(),
                SealerError::AuthenticationFailed,
                "every AAD field must be exact; one-field drift must fail closed"
            );
        }
    }

    #[test]
    fn verify_rejects_tag_corruption_and_ciphertext_and_nonce_mutation() {
        let mut random = DeterministicRandom::new(0x5555);
        let sealer = sealer();
        let successor = mint_capability_token(&mut random).unwrap();
        let binding = page_binding(Some(successor.lookup_hash()));
        let sealed = sealer
            .seal_successor(successor.as_bytes(), &binding, &mut random)
            .unwrap();

        let mut tag_corrupt = sealed.clone();
        let last = tag_corrupt.ciphertext.last_mut().unwrap();
        *last ^= 1;
        assert_eq!(
            sealer.verify_successor(&tag_corrupt, &binding).unwrap_err(),
            SealerError::AuthenticationFailed
        );

        let mut ciphertext_corrupt = sealed.clone();
        ciphertext_corrupt.ciphertext[0] ^= 1;
        assert_eq!(
            sealer
                .verify_successor(&ciphertext_corrupt, &binding)
                .unwrap_err(),
            SealerError::AuthenticationFailed
        );

        let mut nonce_corrupt = sealed.clone();
        nonce_corrupt.nonce[0] ^= 1;
        assert_eq!(
            sealer
                .verify_successor(&nonce_corrupt, &binding)
                .unwrap_err(),
            SealerError::AuthenticationFailed
        );
    }

    #[test]
    fn seal_rejects_successor_hash_mismatch_and_missing_hash() {
        let mut random = DeterministicRandom::new(0x6666);
        let sealer = sealer();
        let successor = mint_capability_token(&mut random).unwrap();

        let mut flipped = PageSpec::default();
        let mut wrong_hash = successor.lookup_hash();
        wrong_hash[0] ^= 1;
        flipped.successor_cursor_hash = Some(wrong_hash);
        assert_eq!(
            sealer
                .seal_successor(successor.as_bytes(), &flipped.to_binding(), &mut random)
                .unwrap_err(),
            SealerError::SuccessorHashMismatch
        );

        let missing = page_binding(None);
        assert_eq!(
            sealer
                .seal_successor(successor.as_bytes(), &missing, &mut random)
                .unwrap_err(),
            SealerError::SuccessorHashMismatch
        );
    }

    #[test]
    fn noncanonical_public_capability_tokens_fail_decode() {
        let mut random = DeterministicRandom::new(0x7777);
        let token = mint_capability_token(&mut random).unwrap();
        let encoded = token.encode();

        assert_eq!(
            decode_capability_token(&format!("{encoded}=")).unwrap_err(),
            CursorCodecError::InvalidEncoding
        );
        assert_eq!(
            decode_capability_token(&noncanonical_trailing_bits(&encoded)).unwrap_err(),
            CursorCodecError::InvalidEncoding
        );
        assert_eq!(
            decode_capability_token("").unwrap_err(),
            CursorCodecError::InvalidEncoding
        );
        assert_eq!(
            decode_capability_token("not+a-token").unwrap_err(),
            CursorCodecError::InvalidEncoding
        );
        assert_eq!(
            decode_capability_token("A".repeat(512).as_str()).unwrap_err(),
            CursorCodecError::InvalidEncoding
        );
        assert_eq!(
            decode_capability_token("A".repeat(513).as_str()).unwrap_err(),
            CursorCodecError::TooLong
        );
        assert_eq!(
            decode_capability_token(&format!("{encoded}{encoded}")).unwrap_err(),
            CursorCodecError::InvalidEncoding
        );
    }

    #[test]
    fn event_cursor_binding_seals_verifies_and_fails_closed_on_every_field() {
        let mut random = DeterministicRandom::new(0x8888);
        let sealer = sealer();
        let capability = mint_capability_token(&mut random).unwrap();
        let binding = event_binding();
        let sealed = sealer
            .seal_successor(capability.as_bytes(), &binding, &mut random)
            .unwrap();

        let verified = sealer.verify_successor(&sealed, &binding).unwrap();
        assert_eq!(verified.as_slice(), capability.as_bytes());

        let wrong_position = SealerBinding::for_event_cursor_receipt(
            Uuid::parse_str(SESSION_ID).unwrap(),
            DID.as_bytes(),
            Uuid::parse_str(DEVICE_ID).unwrap(),
            URL_SAFE_NO_PAD.encode([0x61; 32]).as_bytes(),
            7,
            Uuid::parse_str(PROTOCOL_INSTANCE).unwrap(),
            URL_SAFE_NO_PAD.encode([0x41; 32]).as_bytes(),
            43,
            None,
            10,
            1_700_000_000,
            1_700_000_300,
        )
        .unwrap();
        let wrong_device = SealerBinding::for_event_cursor_receipt(
            Uuid::parse_str(SESSION_ID).unwrap(),
            DID.as_bytes(),
            Uuid::parse_str("88888888-8888-4888-a888-888888888888").unwrap(),
            URL_SAFE_NO_PAD.encode([0x61; 32]).as_bytes(),
            7,
            Uuid::parse_str(PROTOCOL_INSTANCE).unwrap(),
            URL_SAFE_NO_PAD.encode([0x41; 32]).as_bytes(),
            42,
            None,
            10,
            1_700_000_000,
            1_700_000_300,
        )
        .unwrap();
        let wrong_floor = SealerBinding::for_event_cursor_receipt(
            Uuid::parse_str(SESSION_ID).unwrap(),
            DID.as_bytes(),
            Uuid::parse_str(DEVICE_ID).unwrap(),
            URL_SAFE_NO_PAD.encode([0x61; 32]).as_bytes(),
            7,
            Uuid::parse_str(PROTOCOL_INSTANCE).unwrap(),
            URL_SAFE_NO_PAD.encode([0x41; 32]).as_bytes(),
            42,
            None,
            11,
            1_700_000_000,
            1_700_000_300,
        )
        .unwrap();
        let with_predecessor = SealerBinding::for_event_cursor_receipt(
            Uuid::parse_str(SESSION_ID).unwrap(),
            DID.as_bytes(),
            Uuid::parse_str(DEVICE_ID).unwrap(),
            URL_SAFE_NO_PAD.encode([0x61; 32]).as_bytes(),
            7,
            Uuid::parse_str(PROTOCOL_INSTANCE).unwrap(),
            URL_SAFE_NO_PAD.encode([0x41; 32]).as_bytes(),
            42,
            Some([0xAB; 32]),
            10,
            1_700_000_000,
            1_700_000_300,
        )
        .unwrap();
        let wrong_expiry = SealerBinding::for_event_cursor_receipt(
            Uuid::parse_str(SESSION_ID).unwrap(),
            DID.as_bytes(),
            Uuid::parse_str(DEVICE_ID).unwrap(),
            URL_SAFE_NO_PAD.encode([0x61; 32]).as_bytes(),
            7,
            Uuid::parse_str(PROTOCOL_INSTANCE).unwrap(),
            URL_SAFE_NO_PAD.encode([0x41; 32]).as_bytes(),
            42,
            None,
            10,
            1_700_000_000,
            1_700_000_301,
        )
        .unwrap();
        for wrong in [
            wrong_position,
            wrong_device,
            wrong_floor,
            with_predecessor,
            wrong_expiry,
        ] {
            assert_eq!(
                sealer.verify_successor(&sealed, &wrong).unwrap_err(),
                SealerError::AuthenticationFailed
            );
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn sealer_binding_validation_is_fail_closed() {
        let binding = PageSpec::default().to_binding();
        assert_eq!(
            sealer()
                .seal_successor(
                    b"capability-bytes",
                    &binding,
                    &mut DeterministicRandom::new(1)
                )
                .unwrap_err(),
            SealerError::SuccessorHashMismatch,
            "a page binding without the exact successor hash must not seal"
        );

        let invalid_limits: Vec<(&str, Box<dyn FnOnce(&mut PageSpec)>)> = vec![
            ("page_limit=0", Box::new(|s| s.page_limit = 0)),
            ("page_limit=101", Box::new(|s| s.page_limit = 101)),
            ("empty domain", Box::new(|s| s.domain.clear())),
            ("domain too long", Box::new(|s| s.domain = vec![0x41; 65])),
            ("empty endpoint", Box::new(|s| s.endpoint_nsid.clear())),
            (
                "endpoint too long",
                Box::new(|s| s.endpoint_nsid = vec![0x41; 257]),
            ),
            (
                "zero format version",
                Box::new(|s| s.cursor_format_version = 0),
            ),
            (
                "nil session",
                Box::new(|s| s.inventory_session_id = Uuid::nil()),
            ),
            ("nil device", Box::new(|s| s.device_id = Uuid::nil())),
            ("empty user did", Box::new(|s| s.user_did.clear())),
            ("empty jkt", Box::new(|s| s.jkt.clear())),
            ("zero auth generation", Box::new(|s| s.auth_generation = 0)),
            (
                "nil protocol instance",
                Box::new(|s| s.protocol_instance_id = Uuid::nil()),
            ),
            ("empty cursor key id", Box::new(|s| s.cursor_key_id.clear())),
            (
                "position below floor",
                Box::new(|s| s.snapshot_event_position = 9),
            ),
            (
                "position above safe integer",
                Box::new(|s| s.snapshot_event_position = 9_007_199_254_740_992),
            ),
            (
                "floor above safe integer",
                Box::new(|s| s.snapshot_retained_floor = 9_007_199_254_740_992),
            ),
            (
                "created at equals expires at",
                Box::new(|s| s.expires_at = s.created_at),
            ),
            (
                "created at after expires at",
                Box::new(|s| s.created_at = s.expires_at + 1),
            ),
            (
                "after ordinal above safe integer",
                Box::new(|s| s.after_ordinal = Some(9_007_199_254_740_992)),
            ),
        ];
        for (name, mutate) in invalid_limits {
            let mut spec = PageSpec::default();
            mutate(&mut spec);
            assert!(
                matches!(spec.try_to_binding(), Err(SealerError::InvalidBinding)),
                "{name} must be rejected"
            );
        }

        let mut event = DeterministicRandom::new(1);
        let bad_event = SealerBinding::for_event_cursor_receipt(
            Uuid::nil(),
            DID.as_bytes(),
            Uuid::parse_str(DEVICE_ID).unwrap(),
            URL_SAFE_NO_PAD.encode([0x61; 32]).as_bytes(),
            7,
            Uuid::parse_str(PROTOCOL_INSTANCE).unwrap(),
            URL_SAFE_NO_PAD.encode([0x41; 32]).as_bytes(),
            42,
            None,
            10,
            1_700_000_000,
            1_700_000_300,
        );
        assert_eq!(bad_event.unwrap_err(), SealerError::InvalidBinding);
        assert_eq!(
            SealerBinding::for_event_cursor_receipt(
                Uuid::parse_str(SESSION_ID).unwrap(),
                DID.as_bytes(),
                Uuid::parse_str(DEVICE_ID).unwrap(),
                URL_SAFE_NO_PAD.encode([0x61; 32]).as_bytes(),
                0,
                Uuid::parse_str(PROTOCOL_INSTANCE).unwrap(),
                URL_SAFE_NO_PAD.encode([0x41; 32]).as_bytes(),
                42,
                None,
                10,
                1_700_000_000,
                1_700_000_300,
            )
            .unwrap_err(),
            SealerError::InvalidBinding
        );
        assert_eq!(
            SealerBinding::for_event_cursor_receipt(
                Uuid::parse_str(SESSION_ID).unwrap(),
                DID.as_bytes(),
                Uuid::parse_str(DEVICE_ID).unwrap(),
                URL_SAFE_NO_PAD.encode([0x61; 32]).as_bytes(),
                7,
                Uuid::parse_str(PROTOCOL_INSTANCE).unwrap(),
                URL_SAFE_NO_PAD.encode([0x41; 32]).as_bytes(),
                9,
                None,
                10,
                1_700_000_000,
                1_700_000_300,
            )
            .unwrap_err(),
            SealerError::InvalidBinding
        );
        let _ = event;
    }

    #[test]
    fn new_security_types_have_redacted_debug() {
        let mut random = DeterministicRandom::new(0x9999);
        let sealer = sealer();
        let token = mint_capability_token(&mut random).unwrap();
        let binding = page_binding(Some(token.lookup_hash()));
        let sealed = sealer
            .seal_successor(token.as_bytes(), &binding, &mut random)
            .unwrap();
        let event_binding = event_binding();
        let error = SealerError::AuthenticationFailed;
        let random_error = SecureRandomError;
        let os = OsSecureRandom::new();

        let capability_hex = hex(token.as_bytes());
        let ciphertext_hex = hex(&sealed.ciphertext);
        let debugged = [
            format!("{sealer:?}"),
            format!("{binding:?}"),
            format!("{event_binding:?}"),
            format!("{sealed:?}"),
            format!("{token:?}"),
            format!("{os:?}"),
            format!("{error:?}"),
            format!("{random_error:?}"),
        ];
        for value in &debugged {
            assert!(
                !value.contains(&capability_hex),
                "capability bytes must never print"
            );
            assert!(
                !value.contains(&ciphertext_hex),
                "sealed ciphertext must never print"
            );
        }
        for (value, redacted) in [
            (format!("{sealer:?}"), "REDACTED"),
            (format!("{binding:?}"), "REDACTED"),
            (format!("{event_binding:?}"), "REDACTED"),
            (format!("{sealed:?}"), "REDACTED"),
            (format!("{token:?}"), "REDACTED"),
        ] {
            assert!(
                value.contains(redacted),
                "opaque types must be redacted in Debug"
            );
        }
        assert_eq!(format!("{error:?}"), "AuthenticationFailed");
        assert_eq!(format!("{random_error:?}"), "SecureRandomError");
        assert!(!format!("{error}").contains("secret"));
        assert!(!format!("{random_error}").contains("secret"));
    }

    #[test]
    fn sealer_rejects_an_all_zero_secret() {
        // The failure mode is the same static `InvalidConfiguration` error as
        // `CursorCodec::new` — fail closed, no panic, no key material.
        assert!(matches!(
            CursorSealer::new([0x41; 32], Zeroizing::new([0; 32])),
            Err(CursorCodecError::InvalidConfiguration)
        ));
    }

    #[test]
    fn sealed_capability_rejects_undersized_and_oversized_ciphertext() {
        let mut random = DeterministicRandom::new(0xAAAA);
        let sealer = sealer();
        let token = mint_capability_token(&mut random).unwrap();
        let binding = page_binding(Some(token.lookup_hash()));

        let oversized = SealedCapability {
            nonce: [0; 12],
            ciphertext: vec![0x42; cursor::MAX_SEALED_CIPHERTEXT_BYTES + 1],
        };
        assert_eq!(
            sealer.verify_successor(&oversized, &binding).unwrap_err(),
            SealerError::TooLong
        );

        let undersized = SealedCapability {
            nonce: [0; 12],
            ciphertext: vec![0x42; 16],
        };
        assert_eq!(
            sealer.verify_successor(&undersized, &binding).unwrap_err(),
            SealerError::InvalidField
        );

        let too_long = vec![0x42; 497];
        assert_eq!(
            sealer
                .seal_successor(&too_long, &binding, &mut random)
                .unwrap_err(),
            SealerError::TooLong
        );
        assert_eq!(
            sealer
                .seal_successor(&[], &binding, &mut random)
                .unwrap_err(),
            SealerError::InvalidField
        );
    }
}
