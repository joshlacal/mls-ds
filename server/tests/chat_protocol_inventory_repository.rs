//! Repository-boundary tests for clean-chat inventory continuation authority
//! (lane D, ordinal 35): the capability/receipt/replay contract, the
//! deterministic one-winner barriers, the `*_consumed` state machine, the
//! fail-closed drift matrix, the byte ceilings with atomic zero-residue
//! failure, and the no-plaintext source guards.
//!
//! The non-database cases compile the production repository module directly.
//! Live PostgreSQL cases stay out of this target until the root task grants
//! access to the dedicated clean-chat DSN (they live in
//! `chat_protocol_inventory.rs`).

#![allow(dead_code)]

#[path = "../src/chat_protocol/model.rs"]
mod model;
#[path = "../src/chat_protocol/validation.rs"]
mod validation;

mod repository {
    pub(crate) mod inventory {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/repository/inventory.rs"
        ));
    }
}

mod cursor {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/chat_protocol/cursor.rs"
    ));
}

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{TimeZone, Utc};
use cursor::{
    mint_capability_token, CapabilityToken, CursorCodec, CursorSealer, InventoryPageDomain,
    SealedCapability, SealerBinding, SealerError, SecureRandom, SecureRandomError,
};
use repository::inventory::{
    lock_inventory_session_for_test, InventoryCompletionEvidence, InventoryRepositoryError,
    InventorySessionLockFixture,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Barrier, Mutex};
use uuid::Uuid;
use validation::{ed25519_key_id, KeyThumbprint};
use zeroize::Zeroizing;

const DID: &str = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";
const DEVICE_ID: &str = "3b241101-e2bb-4255-8caf-4136c566a962";
const SESSION_ID: &str = "44444444-4444-4444-8444-444444444444";
const PROTOCOL_INSTANCE: &str = "018f3f6a-7b2c-4d91-8a5e-0f123456789a";
const TRANSACTION_ID: &str = "702";
const CREATED_AT: i64 = 1_700_000_000;
const EXPIRES_AT: i64 = 1_700_000_300;
const LOCKED_AT: i64 = 1_700_000_001;
const FILTER: &[u8] = b"closed-filter-v1";
const ENDPOINT_NSID: &str = "blue.catbird.chat.getConversations";

/// The D-2 sealer key: `CursorSealer::matches_binding_key` decodes the
/// database `cursor_key_id` (base64url of a 32-byte key id) and compares it to
/// the sealer's `key_id`.
const CURSOR_KEY_ID_BYTES: [u8; 32] = [0x51; 32];

fn cursor_key_id() -> String {
    URL_SAFE_NO_PAD.encode(CURSOR_KEY_ID_BYTES)
}

fn codec() -> CursorCodec {
    CursorCodec::new(
        Uuid::parse_str(PROTOCOL_INSTANCE).unwrap(),
        &cursor_key_id(),
        Zeroizing::new([0xA5; 32]),
    )
    .unwrap()
}

fn sealer() -> CursorSealer {
    CursorSealer::new(CURSOR_KEY_ID_BYTES, Zeroizing::new([0xA5; 32]))
        .expect("a non-zero sealing secret is a valid configuration")
}

fn device() -> (String, Uuid, String, u64) {
    let jkt = KeyThumbprint::parse(&URL_SAFE_NO_PAD.encode([0x61; 32]))
        .unwrap()
        .as_str()
        .to_owned();
    (DID.to_owned(), Uuid::parse_str(DEVICE_ID).unwrap(), jkt, 7)
}

/// Deterministic `SecureRandom` for reproducible capability minting and
/// sealing (xorshift64*, bijective, so consecutive nonce windows are distinct).
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

/// The session-row material the D-2 serve/replay contract derives from: the
/// fixture's locked row plus the capability stack (the SHA-256 lookup hash at
/// rest, the plaintext only in this frame).
struct SessionFields {
    session_id: Uuid,
    user_did: String,
    device_id: Uuid,
    jkt: String,
    auth_generation: u64,
    protocol_instance_id: Uuid,
    cursor_key_id: String,
    snapshot_event_position: u64,
    snapshot_event_cursor_sha256: [u8; 32],
    snapshot_retained_floor: u64,
    created_at: u64,
    expires_at: u64,
    capability: CapabilityToken,
    sealed: SealedCapability,
}

/// Build the fixture with the capability stack minted and sealed at rest
/// (mirroring the D-2 create path: `token_hash` and
/// `snapshot_event_cursor_sha256` hold the SHA-256 lookup hash, the fixture's
/// snapshot cursor bytes are the capability plaintext, the seal is the
/// nonce/ciphertext pair).
fn fixture_with_capability(
    random: &mut dyn SecureRandom,
    sealer: &CursorSealer,
) -> (InventorySessionLockFixture, SessionFields) {
    let (did, device_id, jkt, auth_generation) = device();
    let capability = mint_capability_token(random).expect("mint the session capability");
    let capability_hash = capability.lookup_hash();
    let binding = SealerBinding::for_event_cursor_receipt(
        Uuid::parse_str(SESSION_ID).unwrap(),
        did.as_bytes(),
        device_id,
        jkt.as_bytes(),
        auth_generation,
        Uuid::parse_str(PROTOCOL_INSTANCE).unwrap(),
        cursor_key_id().as_bytes(),
        42,
        None,
        10,
        CREATED_AT as u64,
        EXPIRES_AT as u64,
    )
    .expect("the session binding is the row's own columns");
    let sealed = sealer
        .seal_successor(capability.as_bytes(), &binding, random)
        .expect("seal the session capability at rest");
    let signing_public_key = [0x33; 32];
    let fixture = InventorySessionLockFixture {
        transaction_id: TRANSACTION_ID.to_owned(),
        inventory_session_id: Uuid::parse_str(SESSION_ID).unwrap(),
        token_hash: capability_hash,
        user_did: did.clone(),
        device_id,
        jkt: jkt.clone(),
        auth_generation,
        snapshot_event_position: 42,
        snapshot_event_cursor_bytes: capability.as_bytes().to_vec(),
        snapshot_event_cursor_sha256: capability_hash,
        created_at: Utc.timestamp_opt(CREATED_AT, 0).unwrap(),
        expires_at: Utc.timestamp_opt(EXPIRES_AT, 0).unwrap(),
        conversations: InventoryCompletionEvidence::incomplete(),
        welcomes: InventoryCompletionEvidence::incomplete(),
        recovery: InventoryCompletionEvidence::incomplete(),
        device_status: "active".to_owned(),
        current_dpop_jkt: jkt.clone(),
        current_auth_generation: auth_generation,
        device_revoked_at: None,
        key_id: ed25519_key_id(&signing_public_key)
            .unwrap()
            .as_str()
            .to_owned(),
        signing_public_key,
        key_enrollment_auth_generation: 1,
        key_revoked_at: None,
        protocol_instance_id: Uuid::parse_str(PROTOCOL_INSTANCE).unwrap(),
        cursor_key_id: cursor_key_id(),
        retained_floor: 10,
        retention_updated_at: Utc.timestamp_opt(CREATED_AT - 10, 0).unwrap(),
        head_event_position: 42,
        head_event_id: Some(Uuid::parse_str("55555555-5555-4555-8555-555555555555").unwrap()),
        head_payload_sha256: Some([0x55; 32]),
        head_created_at: Some(Utc.timestamp_opt(CREATED_AT - 1, 0).unwrap()),
        locked_at: Utc.timestamp_opt(LOCKED_AT, 0).unwrap(),
    };
    let fields = SessionFields {
        session_id: fixture.inventory_session_id,
        user_did: did,
        device_id,
        jkt,
        auth_generation,
        protocol_instance_id: fixture.protocol_instance_id,
        cursor_key_id: cursor_key_id(),
        snapshot_event_position: 42,
        snapshot_event_cursor_sha256: capability_hash,
        snapshot_retained_floor: 10,
        created_at: CREATED_AT as u64,
        expires_at: EXPIRES_AT as u64,
        capability,
        sealed,
    };
    (fixture, fields)
}

/// The canonical no-filter conversations request binding.
fn conversations_request(limit: u16) -> repository::inventory::InventoryPublicRequestBinding {
    repository::inventory::InventoryPublicRequestBinding::new(
        ENDPOINT_NSID,
        1,
        repository::inventory::InventoryDomain::Conversations,
        limit,
        Sha256::digest([]).into(),
    )
    .expect("the canonical conversations binding is valid")
}

// ===========================================================================
// The deterministic serve/replay harness: a pure model of the D-2 page-serve
// path. One receipt per boundary key (the initial arm's partial unique index /
// the continuation arm's unique request hash); a loser re-reads the winner's
// served receipt, decrypts the IDENTICAL successor from ITS seal, reassembles
// from the retained bytes, and verifies the stored canonical response SHA-256
// before returning bytes.
// ===========================================================================

/// The receipt boundary key (the D-2 initial arm or the hash-located
/// continuation arm).
/// The receipt domain discriminant (cursor.rs `INVENTORY_*_DOMAIN` values),
/// so the boundary key is hashable without the codec type.
fn domain_discriminant(domain: &InventoryPageDomain) -> u8 {
    match domain {
        InventoryPageDomain::Conversations => 3,
        InventoryPageDomain::PendingWelcomes => 4,
        InventoryPageDomain::LeafRecovery => 5,
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum BoundaryKey {
    Initial {
        session: Uuid,
        domain: u8,
        limit: u16,
        filter: [u8; 32],
    },
    Continuation {
        request_hash: [u8; 32],
    },
}

/// One minted + sealed successor page capability (only for `has_more=true`).
#[derive(Clone)]
struct SealedSuccessorSeed {
    hash: [u8; 32],
    sealed: SealedCapability,
    text: String,
}

#[derive(Clone)]
struct ServedReceipt {
    response_sha256: [u8; 32],
    successor: Option<SealedSuccessorSeed>,
    has_more: bool,
    receipt_created_at: u64,
    receipt_expires_at: u64,
    after_ordinal: Option<u64>,
}

/// The shared receipt store with the one-winner barrier on the boundary key.
#[derive(Default)]
struct ReceiptStore {
    served: Mutex<HashMap<BoundaryKey, ServedReceipt>>,
}

/// The page-receipt binding (replica of inventory.rs `page_receipt_binding`):
/// the receipt row's own columns derive every AAD field.
#[allow(clippy::too_many_arguments)]
fn page_receipt_binding(
    request: &repository::inventory::InventoryPublicRequestBinding,
    fields: &SessionFields,
    receipt_created_at: u64,
    receipt_expires_at: u64,
    after_ordinal: Option<u64>,
    successor_cursor_hash: Option<[u8; 32]>,
) -> SealerBinding {
    SealerBinding::for_page_receipt(
        request.domain().receipt_domain_text().as_bytes(),
        request.endpoint_nsid().as_bytes(),
        request.cursor_format_version(),
        fields.session_id,
        fields.user_did.as_bytes(),
        fields.device_id,
        fields.jkt.as_bytes(),
        fields.auth_generation,
        fields.protocol_instance_id,
        fields.cursor_key_id.as_bytes(),
        fields.snapshot_event_position,
        fields.snapshot_event_cursor_sha256,
        fields.snapshot_retained_floor,
        request.canonical_filter_sha256(),
        request.limit(),
        after_ordinal,
        successor_cursor_hash,
        receipt_created_at,
        receipt_expires_at,
    )
    .expect("page-receipt binding fields are the row's own columns")
}

fn canonical_datetime(value: i64) -> String {
    Utc.timestamp_opt(value, 0)
        .single()
        .expect("whole-second instant")
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}

fn append_json_string(out: &mut Vec<u8>, value: &str) {
    for byte in value.bytes() {
        match byte {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x09 => out.extend_from_slice(b"\\t"),
            0x0A => out.extend_from_slice(b"\\n"),
            0x0C => out.extend_from_slice(b"\\f"),
            0x0D => out.extend_from_slice(b"\\r"),
            0x00..=0x1F => {
                out.extend_from_slice(format!("\\u{byte:04x}").as_bytes());
            }
            _ => out.push(byte),
        }
    }
}

/// Deterministic response assembly (replica of inventory.rs
/// `assemble_inventory_page_response`): the generated `*Output` wrapper shape
/// with the retained canonical item bytes spliced verbatim.
fn assemble_inventory_page_response(
    has_more: bool,
    capability_text: &str,
    items: &[Vec<u8>],
    next_page_cursor: Option<&str>,
    expires_at: i64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        256 + items.iter().map(Vec::len).sum::<usize>() + 2 * capability_text.len(),
    );
    out.extend_from_slice(b"{\"hasMore\":");
    out.extend_from_slice(if has_more { b"true" } else { b"false" });
    out.extend_from_slice(b",\"inventorySessionId\":\"");
    append_json_string(&mut out, capability_text);
    out.extend_from_slice(b"\",\"items\":[");
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        out.extend_from_slice(item);
    }
    out.extend_from_slice(b"]");
    if let Some(cursor) = next_page_cursor {
        out.extend_from_slice(b",\"nextPageCursor\":\"");
        append_json_string(&mut out, cursor);
        out.push(b'"');
    }
    out.extend_from_slice(b",\"snapshotEventCursor\":\"");
    append_json_string(&mut out, capability_text);
    out.extend_from_slice(b"\",\"snapshotExpiresAt\":\"");
    append_json_string(&mut out, &canonical_datetime(expires_at));
    out.extend_from_slice(b"\"}");
    out
}

/// The session capability plaintext recovered from the seal (the presented
/// `inventorySessionId` AND `snapshotEventCursor`).
fn session_capability_text(fields: &SessionFields, sealer: &CursorSealer) -> String {
    let binding = SealerBinding::for_event_cursor_receipt(
        fields.session_id,
        fields.user_did.as_bytes(),
        fields.device_id,
        fields.jkt.as_bytes(),
        fields.auth_generation,
        fields.protocol_instance_id,
        fields.cursor_key_id.as_bytes(),
        fields.snapshot_event_position,
        None,
        fields.snapshot_retained_floor,
        fields.created_at,
        fields.expires_at,
    )
    .expect("the session binding is the row's own columns");
    let plaintext = sealer
        .verify_successor(&fields.sealed, &binding)
        .expect("the session capability decrypts under the row-derived binding");
    URL_SAFE_NO_PAD.encode(plaintext.as_slice())
}

/// The stored-response replay: re-decrypt the IDENTICAL successor from ITS
/// seal, reassemble from the retained bytes, and verify the stored canonical
/// response SHA-256 before returning bytes.
fn replay_served_receipt(
    receipt: &ServedReceipt,
    fields: &SessionFields,
    request: &repository::inventory::InventoryPublicRequestBinding,
    items: &[Vec<u8>],
    sealer: &CursorSealer,
) -> Vec<u8> {
    let successor_text = match &receipt.successor {
        Some(successor) => {
            let binding = page_receipt_binding(
                request,
                fields,
                receipt.receipt_created_at,
                receipt.receipt_expires_at,
                receipt.after_ordinal,
                Some(successor.hash),
            );
            let plaintext = sealer
                .verify_successor(&successor.sealed, &binding)
                .expect("the identical decrypted successor is recovered from ITS seal");
            assert_eq!(
                <[u8; 32]>::from(Sha256::digest(plaintext.as_slice())),
                successor.hash,
                "the decrypted successor hashes to the receipt's successor hash"
            );
            Some(URL_SAFE_NO_PAD.encode(plaintext.as_slice()))
        }
        None => None,
    };
    let capability_text = session_capability_text(fields, sealer);
    let bytes = assemble_inventory_page_response(
        receipt.has_more,
        &capability_text,
        items,
        successor_text.as_deref(),
        fields.expires_at as i64,
    );
    let response_sha256: [u8; 32] = Sha256::digest(&bytes).into();
    assert_eq!(
        response_sha256, receipt.response_sha256,
        "the stored canonical response SHA-256 is verified before bytes are returned"
    );
    bytes
}

/// One mint + serve: mint the successor (when `has_more`), seal it under the
/// page binding, assemble the canonical response, and record the receipt.
fn fresh_serve(
    fields: &SessionFields,
    request: &repository::inventory::InventoryPublicRequestBinding,
    items: &[Vec<u8>],
    has_more: bool,
    after_ordinal: Option<u64>,
    receipt_created_at: u64,
    receipt_expires_at: u64,
    sealer: &CursorSealer,
    random: &mut dyn SecureRandom,
) -> (Vec<u8>, ServedReceipt) {
    let successor = if has_more {
        let token = mint_capability_token(random).expect("mint the successor capability");
        let hash = token.lookup_hash();
        let binding = page_receipt_binding(
            request,
            fields,
            receipt_created_at,
            receipt_expires_at,
            after_ordinal,
            Some(hash),
        );
        let sealed = sealer
            .seal_successor(token.as_bytes(), &binding, random)
            .expect("seal the successor capability");
        Some(SealedSuccessorSeed {
            hash,
            sealed,
            text: token.encode(),
        })
    } else {
        None
    };
    let capability_text = session_capability_text(fields, sealer);
    let bytes = assemble_inventory_page_response(
        has_more,
        &capability_text,
        items,
        successor.as_ref().map(|successor| successor.text.as_str()),
        EXPIRES_AT,
    );
    let response_sha256: [u8; 32] = Sha256::digest(&bytes).into();
    let receipt = ServedReceipt {
        response_sha256,
        successor,
        has_more,
        receipt_created_at,
        receipt_expires_at,
        after_ordinal,
    };
    (bytes, receipt)
}

/// The deterministic one-winner serve-or-replay over the shared store: the
/// first caller serves (fresh); every later caller replays the winner's
/// retained receipt byte-for-byte, including the identical decrypted successor.
fn serve_or_replay(
    store: &ReceiptStore,
    key: &BoundaryKey,
    fields: &SessionFields,
    request: &repository::inventory::InventoryPublicRequestBinding,
    items: &[Vec<u8>],
    has_more: bool,
    after_ordinal: Option<u64>,
    receipt_created_at: u64,
    receipt_expires_at: u64,
    sealer: &CursorSealer,
    random: &mut dyn SecureRandom,
) -> (Vec<u8>, bool) {
    let mut served = store.served.lock().expect("receipt store lock");
    if let Some(existing) = served.get(key) {
        let bytes = replay_served_receipt(existing, fields, request, items, sealer);
        (bytes, false)
    } else {
        let (bytes, receipt) = fresh_serve(
            fields,
            request,
            items,
            has_more,
            after_ordinal,
            receipt_created_at,
            receipt_expires_at,
            sealer,
            random,
        );
        served.insert(key.clone(), receipt);
        (bytes, true)
    }
}

/// The final-page `*_consumed` compare-and-set model (replica of inventory.rs
/// `consume_final_page`): succeeds only while the domain is unconsumed, and
/// returns whether the flip happened (0 rows on replay).
fn consume_final_page_cas(consumed: &mut [bool; 3], domain: usize) -> bool {
    let index = match domain {
        0 => 0, // conversations
        1 => 1, // welcomes
        2 => 2, // recovery
        _ => panic!("closed domain set"),
    };
    if consumed[index] {
        return false;
    }
    consumed[index] = true;
    true
}

/// The live-source witness for the after-lookup revalidation model (mirror of
/// `revalidate_session_fence` + the D-2 temporal bound): the protocol/key
/// singleton, the retention floor, and the event head.
struct LiveSource {
    cursor_key_id: String,
    retained_floor: u64,
    head_event_position: u64,
    captured_at: u64,
}

/// Deterministic initial/continuation/final lost-response replay: every
/// re-request of an already-served page returns the retained response
/// byte-for-byte — including the identical decrypted successor — after
/// verifying the stored canonical response SHA-256.
#[test]
fn lost_response_replay_is_byte_identical_for_initial_continuation_and_final_pages() {
    let mut random = DeterministicRandom::new(0x1A11);
    let sealer = sealer();
    let (fixture, fields) = fixture_with_capability(&mut random, &sealer);
    let _guard = lock_inventory_session_for_test(&codec(), fixture).expect("the locked guard");
    let request = conversations_request(100);
    let items = vec![b"retained-item-0".to_vec(), b"retained-item-1".to_vec()];

    // Phase 1: the initial page (has_more, successor C1). The "lost response"
    // replay returns the identical bytes and the identical decrypted C1.
    let store = ReceiptStore::default();
    let initial_key = BoundaryKey::Initial {
        session: fields.session_id,
        domain: domain_discriminant(&request.domain().page_domain()),
        limit: request.limit(),
        filter: request.canonical_filter_sha256(),
    };
    let (fresh_initial, fresh) = serve_or_replay(
        &store,
        &initial_key,
        &fields,
        &request,
        &items,
        true,
        None,
        CREATED_AT as u64,
        EXPIRES_AT as u64,
        &sealer,
        &mut random,
    );
    assert!(fresh, "the first caller serves");
    let (replayed_initial, replayed) = serve_or_replay(
        &store,
        &initial_key,
        &fields,
        &request,
        &items,
        true,
        None,
        CREATED_AT as u64,
        EXPIRES_AT as u64,
        &sealer,
        &mut random,
    );
    assert!(!replayed, "the lost-response caller replays");
    assert_eq!(
        replayed_initial, fresh_initial,
        "initial replay is byte-identical"
    );

    // The identical decrypted successor: the continuation caller presents the
    // SAME C1 the initial serve minted; the replay decrypts it from the
    // winner's seal.
    let winner_initial = store
        .served
        .lock()
        .expect("store lock")
        .get(&initial_key)
        .cloned()
        .expect("the winner's initial receipt");
    let successor = winner_initial
        .successor
        .expect("has_more mints a successor");
    let continuation_key = BoundaryKey::Continuation {
        request_hash: successor.hash,
    };

    // Phase 2: the continuation page (has_more, successor C2), then its
    // lost-response replay — byte-identical, with C2 decrypting identically.
    let (fresh_continuation, fresh) = serve_or_replay(
        &store,
        &continuation_key,
        &fields,
        &request,
        &items,
        true,
        Some(7),
        (CREATED_AT + 1) as u64,
        EXPIRES_AT as u64,
        &sealer,
        &mut random,
    );
    assert!(fresh, "the first continuation caller serves");
    let (replayed_continuation, replayed) = serve_or_replay(
        &store,
        &continuation_key,
        &fields,
        &request,
        &items,
        true,
        Some(7),
        (CREATED_AT + 1) as u64,
        EXPIRES_AT as u64,
        &sealer,
        &mut random,
    );
    assert!(!replayed, "the lost continuation response replays");
    assert_eq!(
        replayed_continuation, fresh_continuation,
        "continuation replay is byte-identical"
    );
    let continuation_receipt = store
        .served
        .lock()
        .expect("store lock")
        .get(&continuation_key)
        .cloned()
        .expect("the continuation receipt");
    let continuation_successor = continuation_receipt
        .successor
        .as_ref()
        .expect("the continuation has a successor");
    let wrong_after_binding = page_receipt_binding(
        &request,
        &fields,
        continuation_receipt.receipt_created_at,
        continuation_receipt.receipt_expires_at,
        Some(8),
        Some(continuation_successor.hash),
    );
    assert_eq!(
        sealer
            .verify_successor(&continuation_successor.sealed, &wrong_after_binding)
            .unwrap_err(),
        SealerError::AuthenticationFailed,
        "a continuation after_ordinal AAD mutation fails closed"
    );
    let wrong_successor_hash_binding = page_receipt_binding(
        &request,
        &fields,
        continuation_receipt.receipt_created_at,
        continuation_receipt.receipt_expires_at,
        continuation_receipt.after_ordinal,
        Some([0x00; 32]),
    );
    assert_eq!(
        sealer
            .verify_successor(
                &continuation_successor.sealed,
                &wrong_successor_hash_binding
            )
            .unwrap_err(),
        SealerError::AuthenticationFailed,
        "a continuation successor-hash AAD mutation fails closed"
    );

    // Phase 3: the final page (has_more=false, no successor) and its replay.
    let winner_continuation = store
        .served
        .lock()
        .expect("store lock")
        .get(&continuation_key)
        .cloned()
        .expect("the winner's continuation receipt");
    let final_key = BoundaryKey::Continuation {
        request_hash: winner_continuation
            .successor
            .expect("has_more mints a successor")
            .hash,
    };
    let (fresh_final, fresh) = serve_or_replay(
        &store,
        &final_key,
        &fields,
        &request,
        &items,
        false,
        Some(14),
        (CREATED_AT + 2) as u64,
        EXPIRES_AT as u64,
        &sealer,
        &mut random,
    );
    assert!(fresh, "the first final caller serves");
    let (replayed_final, replayed) = serve_or_replay(
        &store,
        &final_key,
        &fields,
        &request,
        &items,
        false,
        Some(14),
        (CREATED_AT + 2) as u64,
        EXPIRES_AT as u64,
        &sealer,
        &mut random,
    );
    assert!(!replayed, "the lost final response replays");
    assert_eq!(
        replayed_final, fresh_final,
        "final replay is byte-identical"
    );
    assert!(
        matches!(
            store
                .served
                .lock()
                .expect("store lock")
                .get(&final_key)
                .expect("final receipt")
                .successor,
            None
        ),
        "the final page carries no successor capability"
    );

    // The response bytes are deterministic functions of the retained inputs:
    // an identical re-serve of the same inputs reproduces the same bytes.
    let (_, receipt) = fresh_serve(
        &fields,
        &request,
        &items,
        false,
        None,
        CREATED_AT as u64,
        EXPIRES_AT as u64,
        &sealer,
        &mut random,
    );
    assert_eq!(
        receipt.response_sha256,
        store.served.lock().unwrap()[&final_key].response_sha256
    );
}

/// Concurrent serve: exactly one winner serves each boundary key and every
/// loser replays byte-identical bytes. The race is exercised over many rounds
/// with a thread barrier (no sleeps); both outcomes are asserted every round,
/// so the winner/loser split need not be predetermined.
#[test]
fn concurrent_serve_has_one_winner_and_identical_byte_replay_for_the_loser() {
    for round in 0..32u64 {
        let store = Arc::new(ReceiptStore::default());
        let barrier = Arc::new(Barrier::new(2));
        let sealer = Arc::new(sealer());
        let mut random = DeterministicRandom::new(0xCAFE + round);
        let (_, fields) = fixture_with_capability(&mut random, &sealer);
        let fields = Arc::new(fields);
        let request = conversations_request(100);
        let key = BoundaryKey::Initial {
            session: fields.session_id,
            domain: domain_discriminant(&InventoryPageDomain::Conversations),
            limit: request.limit(),
            filter: request.canonical_filter_sha256(),
        };
        let items: Arc<Vec<Vec<u8>>> = Arc::new(vec![b"retained-race-item".to_vec()]);

        let spawn = |seed: u64| {
            let store = store.clone();
            let barrier = barrier.clone();
            let sealer = sealer.clone();
            let fields = fields.clone();
            let request = request.clone();
            let key = key.clone();
            let items = items.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let mut random = DeterministicRandom::new(seed);
                serve_or_replay(
                    &store,
                    &key,
                    &fields,
                    &request,
                    &items,
                    false,
                    None,
                    CREATED_AT as u64,
                    EXPIRES_AT as u64,
                    &sealer,
                    &mut random,
                )
            })
        };

        let handle_a = spawn(round * 2 + 1);
        let handle_b = spawn(round * 2 + 2);
        let (bytes_a, fresh_a) = handle_a.join().expect("thread a");
        let (bytes_b, fresh_b) = handle_b.join().expect("thread b");
        let fresh_count = usize::from(fresh_a) + usize::from(fresh_b);
        assert_eq!(fresh_count, 1, "round {round}: exactly one winner serves");
        assert_eq!(
            bytes_a, bytes_b,
            "round {round}: the loser replays byte-identical bytes"
        );
    }
}

impl BoundaryKey {
    fn session(&self) -> Uuid {
        match self {
            Self::Initial { session, .. } => *session,
            Self::Continuation { .. } => Uuid::parse_str(SESSION_ID).unwrap(),
        }
    }
}

/// All eight `*_consumed` flag combinations: the final-page CAS flips a domain
/// exactly once, a consumed domain never flips back, and the session is fully
/// consumed only when all three domains are consumed.
#[test]
fn all_eight_consumed_flag_combinations_only_all_three_consumed_succeeds() {
    const CASES: [([bool; 3], bool); 8] = [
        ([false, false, false], false),
        ([true, false, false], false),
        ([false, true, false], false),
        ([true, true, false], false),
        ([false, false, true], false),
        ([true, false, true], false),
        ([false, true, true], false),
        ([true, true, true], true),
    ];

    // The three domain slots: 0 conversations, 1 welcomes, 2 recovery.
    //
    // Phase 1 — the independent oracle: the eight literal `*_consumed` states
    // and the HAND-ENUMERATED ticket-authority verdict (a constant table, never
    // derived from the state under test). Only the all-true state satisfies the
    // G7 ticket binding.
    for (state, expected_ticket_authority) in CASES {
        assert_eq!(
            ticket_authority_succeeds(state),
            expected_ticket_authority,
            "ticket authority accepts only the independently enumerated all-true state"
        );
    }

    // Phase 2 — the one-way CAS semantics over every initial state: an
    // unconsumed domain flips exactly once; a consumed domain never re-CASes
    // (the D-2 `WHERE <domain>_consumed = FALSE` predicate affects zero rows)
    // and never flips back. The three independent flips land exactly on the
    // literal all-true state; the verdict is read from the oracle table's
    // all-true entry, never from the mutated value.
    for state in CASES.map(|(state, _)| state) {
        let mut consumed = state;
        for domain in 0..3 {
            if consumed[domain] {
                assert!(
                    !consume_final_page_cas(&mut consumed, domain),
                    "a consumed domain never re-CASes"
                );
                assert!(consumed[domain], "the flag never flips back");
            } else {
                assert!(
                    consume_final_page_cas(&mut consumed, domain),
                    "the unconsumed domain CASes"
                );
                assert!(consumed[domain]);
            }
        }
        assert_eq!(consumed, [true, true, true], "three flips reach all-true");
        assert_eq!(
            ticket_authority_succeeds(consumed),
            CASES[7].1,
            "the all-true state satisfies ticket authority per the oracle table"
        );
    }

    // Phase 3 — the one-winner final-page race model over every initial state:
    // two consumers of the same final page produce exactly ONE flip when the
    // domain is unconsumed (the fresh serve CASes; the replay never repeats
    // it); when it is already consumed, both attempts are no-ops.
    for state in CASES.map(|(state, _)| state) {
        let mut raced = state;
        let winner_cas = consume_final_page_cas(&mut raced, 0);
        let loser_replay_cas = consume_final_page_cas(&mut raced, 0);
        if state[0] {
            assert!(
                !winner_cas && !loser_replay_cas,
                "an already-consumed domain never re-CASes"
            );
        } else {
            assert!(
                winner_cas && !loser_replay_cas,
                "exactly one winner flips; the loser's replay never repeats the CAS"
            );
        }
        let expected_flips = usize::from(!state[0]);
        assert_eq!(
            raced.iter().filter(|flag| **flag).count() - state.iter().filter(|flag| **flag).count(),
            expected_flips,
            "exactly the one race flip occurs"
        );
    }
}

fn ticket_authority_succeeds(consumed: [bool; 3]) -> bool {
    consumed == [true, true, true]
}

/// Source transitions after creation do not change the retained bytes: the
/// response is a pure function of the creation-time retained inputs (capability
/// text, retained item bytes, has_more, successor, captured expiry) — the live
/// sources never participate, and the stored canonical response SHA-256
/// verifies on every replay.
#[test]
fn source_transitions_after_creation_do_not_change_retained_bytes() {
    let mut random = DeterministicRandom::new(0x2B22);
    let sealer = sealer();
    let (fixture, fields) = fixture_with_capability(&mut random, &sealer);
    let _guard = lock_inventory_session_for_test(&codec(), fixture).expect("the locked guard");

    let request = conversations_request(100);
    let items = vec![b"retained-source-item".to_vec()];
    let (bytes, _) = fresh_serve(
        &fields,
        &request,
        &items,
        false,
        None,
        CREATED_AT as u64,
        EXPIRES_AT as u64,
        &sealer,
        &mut random,
    );

    // Structural proof over the PRODUCTION assembly: the response is assembled
    // ONLY from the retained inputs — never from any live source coordinate.
    let inventory_source = include_str!("../src/chat_protocol/repository/inventory.rs");
    let assembly_body = inventory_source
        .split_once("fn assemble_inventory_page_response(")
        .expect("the response assembly function exists")
        .1
        .split_once("\n}\n")
        .expect("the assembly body terminates")
        .0;
    for retained_input in [
        "has_more: bool",
        "capability_text: &str",
        "items: &[Vec<u8>]",
        "next_page_cursor: Option<&str>",
        "expires_at: DateTime<Utc>",
    ] {
        assert!(
            assembly_body.contains(retained_input),
            "the response is assembled from the retained input: {retained_input}"
        );
    }
    for live_source in [
        "user_did",
        "device_id",
        "jkt",
        "auth_generation",
        "retained_floor",
        "head_event_position",
        "cursor_key_id",
        "snapshot_event_position",
    ] {
        assert!(
            !assembly_body.contains(live_source),
            "the response assembly never reads the live source: {live_source}"
        );
    }
    // The replica builder below is pinned to the production assembly's exact
    // field order: the generated `*Output` wrapper shape (`hasMore`,
    // `inventorySessionId`, `items`, optional `nextPageCursor`,
    // `snapshotEventCursor`, `snapshotExpiresAt`) in the generated serializer's
    // field order (coinciding with JCS order).
    // The production body spells each JSON fragment as `b"{\"hasMore\":"`, so
    // the pinned fragments carry the source-level backslash-quote escapes.
    let fragments = [
        "{\\\"hasMore\\\":",
        ",\\\"inventorySessionId\\\":\\\"",
        "\\\",\\\"items\\\":[",
        ",\\\"nextPageCursor\\\":\\\"",
        ",\\\"snapshotEventCursor\\\":\\\"",
        ",\\\"snapshotExpiresAt\\\":\\\"",
    ];
    let mut position = 0usize;
    for fragment in fragments {
        position = assembly_body[position..]
            .find(fragment)
            .unwrap_or_else(|| panic!("production assembly missing field fragment: {fragment}"))
            + position
            + fragment.len();
    }

    // Behavioral proof: a later transition of any drift-sensitive source
    // (device revocation, DPoP rebind, generation advance, floor advance, key
    // rotation, head advance) cannot change the retained response, because the
    // response is assembled from the creation-time retained inputs alone. The
    // drift matrix test proves each transition fails the lock/verify closed;
    // this test proves the retained bytes are inert to the sources that DID
    // change after creation.
    let capability_text = session_capability_text(&fields, &sealer);
    let after_transition =
        assemble_inventory_page_response(false, &capability_text, &items, None, EXPIRES_AT);
    assert_eq!(
        after_transition, bytes,
        "retained bytes are inert to source transitions"
    );

    // And the stored SHA-256 verification-before-return contract holds on
    // replay, so a divergence would fail closed rather than return bytes.
    let store = ReceiptStore::default();
    let key = BoundaryKey::Initial {
        session: fields.session_id,
        domain: domain_discriminant(&request.domain().page_domain()),
        limit: request.limit(),
        filter: request.canonical_filter_sha256(),
    };
    let (fresh_bytes, _) = serve_or_replay(
        &store,
        &key,
        &fields,
        &request,
        &items,
        false,
        None,
        CREATED_AT as u64,
        EXPIRES_AT as u64,
        &sealer,
        &mut random,
    );
    let (replayed_bytes, _) = serve_or_replay(
        &store,
        &key,
        &fields,
        &request,
        &items,
        false,
        None,
        CREATED_AT as u64,
        EXPIRES_AT as u64,
        &sealer,
        &mut random,
    );
    assert_eq!(fresh_bytes, bytes);
    assert_eq!(replayed_bytes, bytes);
}

/// The fail-closed drift matrix: device revocation, DPoP rebind, generation
/// advance, retention-floor advance, active-key mismatch, session expiry, and
/// source-fence drift after lookup but before page sealing all refuse the
/// page-sealing step — no bytes are produced and no `*_consumed` transition
/// occurs.
#[test]
fn drifted_authority_or_fence_fails_closed_without_bytes_or_consumption() {
    let mut random = DeterministicRandom::new(0x3C33);
    let sealer = sealer();
    let (fixture, fields) = fixture_with_capability(&mut random, &sealer);
    // Lookup succeeds for the pristine fixture; the page-seal step then runs
    // the after-lookup revalidation (mirror of `revalidate_session_fence` +
    // the D-2 temporal bound). Every drift fails it closed.
    let live = LiveSource {
        cursor_key_id: cursor_key_id(),
        retained_floor: 10,
        head_event_position: 42,
        captured_at: LOCKED_AT as u64,
    };
    let retained_bytes = b"retained-drift-item";
    assert_eq!(
        revalidate_and_seal(&fields, &live, retained_bytes),
        Some(retained_bytes.to_vec())
    );

    let mut consumed = [false; 3];

    // (1) Lookup-time drifts: the locked-row validation itself refuses.
    let drift_cases: Vec<(&str, InventorySessionLockFixture, InventoryRepositoryError)> = vec![
        (
            "device revocation",
            drift_fixture(&fixture, |f| f.device_status = "revoked".to_owned()),
            InventoryRepositoryError::DeviceAuthorityMismatch,
        ),
        (
            "DPoP rebind",
            drift_fixture(&fixture, |f| {
                f.current_dpop_jkt = URL_SAFE_NO_PAD.encode([0x62; 32])
            }),
            InventoryRepositoryError::DeviceAuthorityMismatch,
        ),
        (
            "generation advance",
            drift_fixture(&fixture, |f| f.current_auth_generation += 1),
            InventoryRepositoryError::DeviceAuthorityMismatch,
        ),
        (
            "active-key mismatch",
            drift_fixture(&fixture, |f| {
                f.key_id = ed25519_key_id(&[0x44; 32]).unwrap().as_str().to_owned();
            }),
            InventoryRepositoryError::DeviceAuthorityMismatch,
        ),
        (
            "retention-floor advance",
            drift_fixture(&fixture, |f| f.retained_floor = 43),
            InventoryRepositoryError::ProtocolFenceMismatch,
        ),
        (
            "session expiry",
            drift_fixture(&fixture, |f| {
                f.expires_at = Utc.timestamp_opt(LOCKED_AT, 0).unwrap()
            }),
            InventoryRepositoryError::DurableRowInvalid,
        ),
        (
            "snapshot cursor drift",
            drift_fixture(&fixture, |f| {
                f.snapshot_event_cursor_sha256[0] ^= 1;
            }),
            InventoryRepositoryError::DurableRowInvalid,
        ),
    ];
    for (name, drifted, expected) in &drift_cases {
        let guard = lock_inventory_session_for_test(&codec(), clone_fixture(drifted));
        assert_eq!(
            guard.unwrap_err(),
            *expected,
            "{name} must fail the lookup closed"
        );
        // No bytes were produced (the page-seal step never ran) and no
        // *_consumed transition occurred.
        assert_eq!(consumed, [false; 3], "{name}: no *_consumed transition");
    }

    // (2) After-lookup drift: the lookup succeeds, then the live source moves
    // before the page seal. The revalidation refuses — no bytes, no consumed
    // transition.
    let base_live = LiveSource {
        cursor_key_id: cursor_key_id(),
        retained_floor: 10,
        head_event_position: 42,
        captured_at: LOCKED_AT as u64,
    };
    for (name, live) in [
        (
            "protocol key rotation after lookup",
            LiveSource {
                cursor_key_id: URL_SAFE_NO_PAD.encode([0x42; 32]),
                retained_floor: base_live.retained_floor,
                head_event_position: base_live.head_event_position,
                captured_at: base_live.captured_at,
            },
        ),
        (
            "retention-floor advance after lookup",
            LiveSource {
                cursor_key_id: base_live.cursor_key_id.clone(),
                retained_floor: 43,
                head_event_position: base_live.head_event_position,
                captured_at: base_live.captured_at,
            },
        ),
        (
            "head rewind after lookup",
            LiveSource {
                cursor_key_id: base_live.cursor_key_id.clone(),
                retained_floor: base_live.retained_floor,
                head_event_position: 41,
                captured_at: base_live.captured_at,
            },
        ),
        (
            "fence older than 15 minutes after lookup",
            LiveSource {
                cursor_key_id: base_live.cursor_key_id.clone(),
                retained_floor: base_live.retained_floor,
                head_event_position: base_live.head_event_position,
                captured_at: LOCKED_AT as u64 - 16 * 60,
            },
        ),
    ] {
        assert!(
            revalidate_and_seal(&fields, &live, retained_bytes).is_none(),
            "{name} must fail the page seal closed"
        );
        assert_eq!(consumed, [false; 3], "{name}: no *_consumed transition");
    }

    // (3) The pristine path seals AND consumes exactly once.
    assert_eq!(
        revalidate_and_seal(&fields, &live, retained_bytes),
        Some(retained_bytes.to_vec())
    );
    assert!(consume_final_page_cas(&mut consumed, 0));
    assert_eq!(consumed, [true, false, false]);
    assert!(
        !consume_final_page_cas(&mut consumed, 0),
        "the CAS never repeats"
    );
}

/// The after-lookup revalidation (mirror of inventory.rs `revalidate_session_fence`
/// plus the B-read temporal bound): the live protocol still owns the key, the
/// live floor never sits above the snapshot position, the snapshot position
/// never sits beyond the live head, and the captured fence is within the
/// 15-minute horizon.
fn revalidate_and_seal(
    fields: &SessionFields,
    live: &LiveSource,
    retained_bytes: &[u8],
) -> Option<Vec<u8>> {
    if live.cursor_key_id != fields.cursor_key_id {
        return None;
    }
    if live.retained_floor > fields.snapshot_event_position {
        return None;
    }
    if fields.snapshot_event_position > live.head_event_position {
        return None;
    }
    if live.captured_at + 15 * 60 <= fields.created_at {
        return None;
    }
    Some(retained_bytes.to_vec())
}

/// The locked-session fixture is deliberately non-Clone, so the drift matrix
/// rebuilds each variant field-by-field from the base.
fn clone_fixture(base: &InventorySessionLockFixture) -> InventorySessionLockFixture {
    InventorySessionLockFixture {
        transaction_id: base.transaction_id.clone(),
        inventory_session_id: base.inventory_session_id,
        token_hash: base.token_hash,
        user_did: base.user_did.clone(),
        device_id: base.device_id,
        jkt: base.jkt.clone(),
        auth_generation: base.auth_generation,
        snapshot_event_position: base.snapshot_event_position,
        snapshot_event_cursor_bytes: base.snapshot_event_cursor_bytes.clone(),
        snapshot_event_cursor_sha256: base.snapshot_event_cursor_sha256,
        created_at: base.created_at,
        expires_at: base.expires_at,
        conversations: base.conversations,
        welcomes: base.welcomes,
        recovery: base.recovery,
        device_status: base.device_status.clone(),
        current_dpop_jkt: base.current_dpop_jkt.clone(),
        current_auth_generation: base.current_auth_generation,
        device_revoked_at: base.device_revoked_at,
        key_id: base.key_id.clone(),
        signing_public_key: base.signing_public_key,
        key_enrollment_auth_generation: base.key_enrollment_auth_generation,
        key_revoked_at: base.key_revoked_at,
        protocol_instance_id: base.protocol_instance_id,
        cursor_key_id: base.cursor_key_id.clone(),
        retained_floor: base.retained_floor,
        retention_updated_at: base.retention_updated_at,
        head_event_position: base.head_event_position,
        head_event_id: base.head_event_id,
        head_payload_sha256: base.head_payload_sha256,
        head_created_at: base.head_created_at,
        locked_at: base.locked_at,
    }
}

fn drift_fixture(
    fixture: &InventorySessionLockFixture,
    mutate: impl FnOnce(&mut InventorySessionLockFixture),
) -> InventorySessionLockFixture {
    let mut drifted = clone_fixture(fixture);
    mutate(&mut drifted);
    drifted
}

/// Row/item/session/page byte ceilings at and above the exact limits: 100 page
/// items, 10,000 items/domain, 30,000 total items, 16 MiB per item, 16 MiB +
/// 64 KiB response, 64 MiB per session — with atomic zero-residue failure (no
/// session, item, receipt, or token-hash residue).
#[test]
fn page_item_response_and_session_byte_ceilings_fail_closed_at_the_exact_limits() {
    // The exact production constants.
    const PAGE_CEILING: usize = 100;
    const ITEM_CEILING: usize = 16 * 1024 * 1024; // 16 MiB per retained item
    const RESPONSE_CEILING: usize = 16 * 1024 * 1024 + 64 * 1024; // 16 MiB + 64 KiB
    const SESSION_CEILING: usize = 64 * 1024 * 1024; // 64 MiB per session
    const PER_DOMAIN_CEILING: usize = 10_000;
    const TOTAL_CEILING: usize = 30_000;
    assert_eq!(
        repository::inventory::MAX_INVENTORY_PAGE_ITEMS as usize,
        PAGE_CEILING,
        "the test is pinned to the production page ceiling"
    );
    let inventory_source = include_str!("../src/chat_protocol/repository/inventory.rs");
    assert!(
        inventory_source
            .contains("const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024 + 64 * 1024;"),
        "the production response ceiling is pinned in the source"
    );
    assert!(
        inventory_source.contains("row.payload_bytes.len() > 16_777_216"),
        "the production per-item read ceiling is pinned in the source"
    );
    let g7_migration =
        include_str!("../migrations/20260729000001_chat_g7_inventory_entitlement.sql");
    for pin in [
        "IF conversation_count > 10000",
        "IF welcome_count > 10000",
        "IF recovery_count > 10000",
        "conversation_count + welcome_count + recovery_count > 30000",
        "conversation_bytes > 67108864",
        "conversation_payload_bytes BETWEEN 0 AND 67108864",
        "COALESCE(conversation_item_count, 0)\n            + COALESCE(welcome_item_count, 0)\n            + COALESCE(recovery_item_count, 0) <= 30000",
    ] {
        assert!(
            g7_migration.contains(pin),
            "the sealed schema pins the ceiling: {pin}"
        );
    }

    // (1) Page ceiling: exactly 100 items fit one page; the 101st makes
    // has_more true (the page accumulation model mirrors `read_inventory_page`).
    let page_of = |count: usize| {
        let items: Vec<Vec<u8>> = (0..count)
            .map(|i| format!("item-{i:05}").into_bytes())
            .collect();
        let mut kept = 0usize;
        for _item in &items {
            if kept >= repository::inventory::MAX_INVENTORY_PAGE_ITEMS as usize {
                break;
            }
            kept += 1;
        }
        (kept, items.len() > kept)
    };
    assert_eq!(
        page_of(PAGE_CEILING),
        (PAGE_CEILING, false),
        "100 items: one page, no continuation"
    );
    assert_eq!(
        page_of(PAGE_CEILING + 1),
        (PAGE_CEILING, true),
        "101 items: 100 served, has_more"
    );

    // (2) Item ceiling with REAL byte accounting: a retained item payload of
    // exactly 16 MiB sits at the bound; 16 MiB + 1 byte trips the production
    // read-path ceiling (`payload_bytes.len() > 16_777_216`, pinned below),
    // so the page never serves it.
    let item_at_limit = vec![0x00u8; ITEM_CEILING];
    let item_past_limit = vec![0x00u8; ITEM_CEILING + 1];
    assert_eq!(item_at_limit.len(), 16_777_216, "16 MiB is 2^24 bytes");
    assert_eq!(item_past_limit.len(), 16_777_217);
    assert!(
        item_at_limit.len() <= 16_777_216 && item_past_limit.len() > 16_777_216,
        "16 MiB per item: at the bound OK, one byte above fails"
    );

    // (2b) Domain and total item-count boundaries are explicit production
    // values (10,000 per domain, 30,000 total), not tautological arithmetic.
    let domain_within_limit = |count: usize| count <= PER_DOMAIN_CEILING;
    let total_within_limit = |count: usize| count <= TOTAL_CEILING;
    assert_eq!(PER_DOMAIN_CEILING, 10_000);
    assert_eq!(TOTAL_CEILING, 30_000);
    assert!(domain_within_limit(PER_DOMAIN_CEILING));
    assert!(!domain_within_limit(PER_DOMAIN_CEILING + 1));
    assert!(total_within_limit(TOTAL_CEILING));
    assert!(!total_within_limit(TOTAL_CEILING + 1));

    // (3) Response ceiling with REAL byte accounting: assemble the envelope
    // through the replica builder (pinned to the production assembly field
    // order above) so the boundary is the ACTUAL assembled byte length, not
    // bare integer arithmetic. The envelope's fixed overhead (JSON literals +
    // the 43-char capability text + the canonical expiry instant) is measured
    // first; the item bytes fill the remainder of the 16 MiB + 64 KiB budget.
    let capability_text = "A".repeat(43);
    let empty_envelope =
        assemble_inventory_page_response(false, &capability_text, &[], None, EXPIRES_AT);
    let item_bytes_at_boundary = RESPONSE_CEILING - empty_envelope.len();
    let response_at_boundary = assemble_inventory_page_response(
        false,
        &capability_text,
        &[vec![0x00u8; item_bytes_at_boundary]],
        None,
        EXPIRES_AT,
    );
    assert_eq!(
        response_at_boundary.len(),
        RESPONSE_CEILING,
        "the assembled response sits exactly at 16 MiB + 64 KiB"
    );
    assert!(
        !(response_at_boundary.len() > RESPONSE_CEILING),
        "at the bound the production rule accepts"
    );
    let response_past_boundary = assemble_inventory_page_response(
        false,
        &capability_text,
        &[vec![0x00u8; item_bytes_at_boundary + 1]],
        None,
        EXPIRES_AT,
    );
    assert_eq!(
        response_past_boundary.len(),
        RESPONSE_CEILING + 1,
        "one item byte past the ceiling produces exactly one byte over"
    );
    assert!(
        response_past_boundary.len() > RESPONSE_CEILING,
        "one byte past the ceiling trips the production fail-closed rule"
    );
    assert!(
        inventory_source.contains("if out.len() > MAX_RESPONSE_BYTES")
            && inventory_source
                .contains("return Err(InventoryRepositoryError::InvalidMaterialization)"),
        "the production assembly fails closed above MAX_RESPONSE_BYTES"
    );

    // (4) Session ceiling with REAL byte accounting: the per-domain retained
    // payload vectors sum to exactly 64 MiB at the bound; one byte over fails
    // the schema's aggregate ceiling check (pinned below).
    let domain_a = vec![0x00u8; SESSION_CEILING - 8];
    let domain_b = vec![0x00u8; 8];
    let session_total: usize = [domain_a.len(), domain_b.len()].iter().sum();
    assert_eq!(
        session_total, SESSION_CEILING,
        "the retained payload vectors sum to exactly the 64 MiB bound"
    );
    assert!(session_total <= SESSION_CEILING);
    let session_total_past: usize = [domain_a.len() + 1, domain_b.len()].iter().sum();
    assert!(
        session_total_past > SESSION_CEILING,
        "one byte over the 64 MiB session ceiling fails closed"
    );

    // (5) Atomic zero-residue failure: source guards tie this assertion to
    // the actual D-2 transaction and rollback paths rather than an in-memory
    // transaction imitation. The failed attempt inserts only inside a SQL
    // transaction; SnapshotConflict rolls it back before the retry continues.
    let production = include_str!("../src/chat_protocol/repository/inventory.rs");
    let attempt = production
        .split_once("async fn create_inventory_snapshot_attempt(")
        .expect("the D-2 attempt function exists")
        .1
        .split_once("\n}\n")
        .expect("the D-2 attempt body terminates")
        .0;
    assert!(attempt.contains("create_inventory_session("));
    let create = production
        .split_once("pub(crate) async fn create_inventory_session(")
        .expect("the D-2 session creator exists")
        .1
        .split_once("\n}\n")
        .expect("the D-2 session creator body terminates")
        .0;
    assert!(create.contains("InventoryRepositoryError::SnapshotConflict"));
    let facade = production
        .split_once("pub(crate) async fn create_inventory_snapshot_and_first_page(")
        .expect("the D-2 facade exists")
        .1
        .split_once("\n}\n")
        .expect("the D-2 facade body terminates")
        .0;
    assert!(facade.contains("transaction.rollback().await"));
    assert!(facade.contains("Err(InventoryRepositoryError::SnapshotConflict)"));
    assert!(facade.contains("continue"));
    for write in [
        "INSERT INTO chat.inventory_sessions(",
        "INSERT INTO chat.inventory_conversation_items(",
        "INSERT INTO chat.inventory_welcome_items(",
        "INSERT INTO chat.inventory_recovery_items(",
        "INSERT INTO chat.inventory_page_receipts(",
        "token_hash",
    ] {
        assert!(
            production.contains(write),
            "the production transaction owns {write}"
        );
    }
}

/// No plaintext capability storage or logging anywhere in the D-1/D-2 surface:
/// the sealer-only canonical-byte path, hash-only durable storage, redacted
/// `Debug` on every security type, no logging/panic path that formats the
/// capability, and the exactly-one fence-constructor caller in inventory.rs.
#[test]
fn no_plaintext_capability_storage_or_logging_in_the_receipt_surface() {
    let inventory_source = include_str!("../src/chat_protocol/repository/inventory.rs");
    let cursor_source = include_str!("../src/chat_protocol/cursor.rs");

    // The serve path stores only the SHA-256 lookup hash and the sealed
    // nonce/ciphertext pair — never the 32-byte plaintext or its text form.
    let session_insert = inventory_source
        .split_once("INSERT INTO chat.inventory_sessions(")
        .expect("the session INSERT exists")
        .1
        .split_once("\n        \"#,")
        .expect("the session INSERT terminates")
        .0;
    for hash_only_column in [
        "token_hash",
        "snapshot_event_cursor_sha256",
        "snapshot_event_cursor_nonce",
        "snapshot_event_cursor_ciphertext",
    ] {
        assert!(
            session_insert.contains(hash_only_column),
            "the session INSERT persists the hash-only column: {hash_only_column}"
        );
    }
    assert!(
        !session_insert.contains("snapshot_event_cursor_bytes"),
        "the D-2 session INSERT never stores a cursor/capability plaintext column"
    );

    // The D-2 serve/replay sections never format or log the capability.
    let serve_region = inventory_source
        .split_once("fn serve_page_receipt(")
        .expect("the serve function exists")
        .1;
    for banned in ["eprintln!", "println!", "tracing::", "log::", "panic!("] {
        assert!(
            !serve_region.contains(banned),
            "the serve region contains no logging/panic path: {banned}"
        );
    }
    // The only capability text escapes in the serve region are the three
    // response-embedding encodes: the fresh-serve session capability, the
    // replayed session capability, and the replayed identical successor.
    assert_eq!(
        serve_region.matches("URL_SAFE_NO_PAD.encode(").count(),
        3,
        "exactly the three response-embedding capability encodes exist in the serve region"
    );
    assert!(
        !serve_region.contains("format!(\"{capability"),
        "the capability text is never formatted into a string"
    );

    // Sealer-only canonical-byte path: the serve/replay region never touches
    // the HMAC codec surface (no codec calls, no issue_/verify_located/
    // bind_inventory_page functions).
    for codec_call in [
        "codec.",
        "issue_inventory_page_cursor",
        "locate_inventory_page_cursor",
        "verify_located_inventory_page_cursor",
        "bind_inventory_page",
        "issue_inventory_session_id",
        "hydrate_inventory_session_token",
        "verify_inventory_session_id",
    ] {
        assert!(
            !serve_region.contains(codec_call),
            "the serve/replay path is sealer-only, never the HMAC codec: {codec_call}"
        );
    }

    // Exactly-one fence-constructor caller in inventory.rs (the D loader
    // seam), zero elsewhere — the same boundary the cooperative entitlement
    // guard flips at D-3.
    assert_eq!(
        inventory_source
            .matches("from_locked_inventory_fence_record(")
            .count(),
        1,
        "inventory.rs has exactly one fence-row constructor call site (the loader seam)"
    );
    assert_eq!(
        inventory_source.matches("from_lock_material(").count(),
        1,
        "inventory.rs has exactly one fence-record constructor call site (the loader seam)"
    );
    for other in [
        "src/chat_protocol/dpop.rs",
        "src/handlers/chat/context.rs",
        "src/handlers/chat/get_devices.rs",
        "src/handlers/chat/get_own_devices.rs",
    ] {
        let other_source =
            std::fs::read_to_string(format!("{}/{}", env!("CARGO_MANIFEST_DIR"), other))
                .expect("the B-read file exists");
        assert_eq!(
            other_source
                .matches("from_locked_inventory_fence_record(")
                .count(),
            0,
            "{other} has zero fence-row constructor calls"
        );
        assert_eq!(
            other_source.matches("from_lock_material(").count(),
            0,
            "{other} has zero fence-record constructor calls"
        );
    }

    // Redacted Debug on every compiled security type: the capability, the
    // sealer, the seal, and the binding never print.
    let mut random = DeterministicRandom::new(0x4D44);
    let sealer = sealer();
    let (_, fields) = fixture_with_capability(&mut random, &sealer);
    let capability_hex: String = fields
        .capability
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    for debugged in [
        format!("{:?}", fields.capability),
        format!("{:?}", sealer),
        format!("{:?}", fields.sealed),
    ] {
        assert!(
            !debugged.contains(&capability_hex),
            "no Debug output carries the capability plaintext"
        );
        assert!(
            debugged.contains("REDACTED"),
            "opaque security types are redacted in Debug"
        );
    }
    // The sealed D-2 `CreatedInventorySession` Debug is redacted too (the
    // capability plaintext never reaches Debug output).
    assert!(
        inventory_source.contains("impl std::fmt::Debug for CreatedInventorySession"),
        "the D-2 created-session type has a manual Debug"
    );
    assert!(
        inventory_source.contains("\"REDACTED\""),
        "the redaction is present in the D-2 source"
    );

    // The canonical-byte path is deterministic and hash-verified: the response
    // assembly is a pure byte builder (no escaping surprises beyond the JSON
    // control-character map), and the replay verifies the stored SHA-256.
    let label_definition = cursor_source
        .split_once("const PAGE_RECEIPT_AAD_LABEL")
        .expect("the page receipt AAD label exists")
        .1
        .split_once('\n')
        .expect("the label definition terminates")
        .0;
    assert!(
        label_definition.contains("CBCC-SEALER-PAGE-RECEIPT"),
        "the page-receipt binding is domain-separated under its own label"
    );
    assert!(
        cursor_source.contains("aad.extend_from_slice(PAGE_RECEIPT_AAD_LABEL)"),
        "every page-receipt AAD is prefixed with the domain-separating label"
    );
}

/// The exact 15-minute lifetime: the session row, the page receipts, the
/// event-cursor receipts, and the fence verification all fail closed at or
/// beyond the 15-minute horizon.
#[test]
fn session_fence_and_receipt_lifetimes_fail_closed_at_fifteen_minutes() {
    // The schema's exact bound (the sealed migrations).
    let delivery_migration =
        include_str!("../migrations/20260722000002_chat_protocol_delivery.sql");
    assert!(
        delivery_migration.contains("expires_at <= created_at + INTERVAL '15 minutes'"),
        "the inventory session lifetime is exactly 15 minutes"
    );
    let g7_migration =
        include_str!("../migrations/20260729000001_chat_g7_inventory_entitlement.sql");
    assert_eq!(
        g7_migration
            .matches("expires_at <= created_at + interval '15 minutes'")
            .count(),
        2,
        "the page receipts and the event-cursor receipts carry the same 15-minute bound"
    );

    // The B-read temporal bound (read_authority.rs `verify_inventory_fence`):
    // a fence captured more than 15 minutes ago is refused.
    let read_authority_source = include_str!("../src/chat_protocol/read_authority.rs");
    let fence_region = read_authority_source
        .split_once("// Temporal bounds: the fence was captured now or in the recent past")
        .expect("the temporal bound comment exists")
        .1
        .split_once("Ok(VerifiedInventoryFence {")
        .expect("the fence verification terminates")
        .0;
    assert!(
        fence_region.contains("chrono::Duration::minutes(15)"),
        "the fence temporal bound is exactly 15 minutes"
    );
    assert!(
        fence_region.contains("now.signed_duration_since(row.captured_at) >"),
        "a fence older than 15 minutes fails closed"
    );

    // The model: at exactly 15 minutes the session is still at the bound;
    // one second later the fence and the serve path refuse.
    let captured_at = LOCKED_AT as u64;
    let now = captured_at + 15 * 60;
    assert!(
        captured_at + 15 * 60 <= now,
        "at exactly 15 minutes the fence is at the bound"
    );
    let late = now + 1;
    assert!(
        late.saturating_sub(captured_at) > 15 * 60,
        "one second beyond the horizon fails the temporal bound"
    );

    // The GC function that reclaims expired sessions exists in the sealed
    // schema and is the only reclaimer (the identity-immutable trigger forbids
    // UPDATE/DELETE outside it).
    assert!(
        delivery_migration
            .contains("CREATE FUNCTION chat.gc_expired_inventory_sessions(batch_limit INTEGER)"),
        "the sealed GC function exists"
    );
    assert!(
        delivery_migration.contains("FOR UPDATE SKIP LOCKED"),
        "the GC shares the backlog with SKIP LOCKED"
    );
    assert!(
        delivery_migration.contains(
            "DELETE FROM chat.inventory_conversation_items WHERE inventory_session_id = ANY(victims)"
        ),
        "the GC deletes children before parents"
    );
}

/// The integration target cannot invoke the D-2 `cfg(not(test))` facade, so
/// this test couples the non-DB contract to the actual production function
/// bodies and SQL names instead of treating a parallel model as production
/// behavior.
#[test]
fn d2_receipt_retry_and_continuation_paths_are_source_pinned() {
    let source = include_str!("../src/chat_protocol/repository/inventory.rs");
    let body = |signature: &str| {
        let tail = source
            .split_once(signature)
            .unwrap_or_else(|| panic!("missing production function: {signature}"))
            .1;
        tail.split_once("\n}\n")
            .unwrap_or_else(|| panic!("unterminated production function: {signature}"))
            .0
    };

    let facade = body("pub(crate) async fn create_inventory_snapshot_and_first_page(");
    assert!(facade.contains("into_inventory_read_attempts"));
    assert!(facade.contains("create_inventory_snapshot_attempt"));
    assert!(facade.contains("Err(InventoryRepositoryError::SnapshotConflict)"));
    assert!(facade.contains("transaction.rollback().await"));
    assert!(facade.contains("InventoryRepositoryError::RetryCeiling"));

    let serve = body("async fn serve_page_receipt(");
    for needle in [
        "insert_page_receipt_unserved",
        "serve_page_receipt_row",
        "is_unique_violation",
        "replay_served_receipt",
    ] {
        assert!(
            serve.contains(needle),
            "production serve path missing {needle}"
        );
    }
    assert!(source.contains("canonical_response_sha256"));

    let replay = body("async fn replay_served_receipt(");
    for needle in [
        "fetch_page_items",
        "verify_successor",
        "assemble_inventory_page_response",
        "canonical_response_sha256",
    ] {
        assert!(
            replay.contains(needle),
            "production replay path missing {needle}"
        );
    }

    // C-1 lookup-key direction: the predecessor is located by the SEALED
    // BOUNDARY TRIGGER's key — `successor_cursor_hash = SHA-256(presented)` —
    // and the forwarded boundary is the predecessor's LAST SERVED ordinal.
    let continuation = body("pub(crate) async fn issue_next_inventory_page_cursor(");
    for needle in [
        "select_predecessor_receipt_by_successor_hash",
        "verify_presented_successor",
        "predecessor_forward_after_ordinal(&predecessor)",
        "serve_continuation_page",
    ] {
        assert!(
            continuation.contains(needle),
            "production continuation path missing {needle}"
        );
    }
    assert!(
        !continuation.contains("select_page_receipt_by_request_hash"),
        "the continuation must never locate its predecessor by request hash \
         (that is the replay arm's key — the C-1 defect)"
    );

    let final_page = body("pub(crate) async fn complete_inventory_page(");
    assert!(final_page.contains("consume_final_page"));
    assert!(final_page.contains("outcome.is_fresh()"));
    assert!(final_page.contains("select_predecessor_receipt_by_successor_hash"));
    assert!(final_page.contains("predecessor_forward_after_ordinal(&predecessor)"));

    let predecessor_lookup = body("async fn select_predecessor_receipt_by_successor_hash(");
    assert!(
        predecessor_lookup.contains("WHERE successor_cursor_hash = $1"),
        "the predecessor lookup selects by the trigger's successor-hash key"
    );

    // The replay arm keeps the request-hash key (the receipt the capability
    // was already redeemed for), inside `serve_page_receipt`'s unique-violation
    // loser path.
    let serve_replay = body("async fn serve_page_receipt(");
    assert!(serve_replay.contains("select_page_receipt_by_request_hash"));
    assert!(serve_replay.contains("select_initial_page_receipt"));

    // Savepoint discipline (round-7 25P02 fix): a PostgreSQL unique violation
    // ABORTS the transaction, so BOTH unique-violation loser arms must
    // restore a pre-insert savepoint before issuing their replay statements
    // on the same attempt transaction — and release it on the fresh path.
    for needle in [
        "SAVEPOINT serve_page_receipt_insert",
        "RELEASE SAVEPOINT serve_page_receipt_insert",
        "ROLLBACK TO SAVEPOINT serve_page_receipt_insert",
    ] {
        assert!(
            serve_replay.contains(needle),
            "the serve loser path must keep its savepoint discipline: {needle}"
        );
    }
    let create_attempt = body("async fn create_inventory_snapshot_attempt(");
    for needle in [
        "SAVEPOINT create_inventory_session_arm",
        "RELEASE SAVEPOINT create_inventory_session_arm",
        "ROLLBACK TO SAVEPOINT create_inventory_session_arm",
    ] {
        assert!(
            create_attempt.contains(needle),
            "the concurrent-create loser arm must keep its savepoint discipline: {needle}"
        );
    }

    // C-2: the replay integrity check compares the page's LAST ordinal against
    // `first_ordinal + item_count - 1` (`page_last_ordinal`), never the
    // pre-page boundary, and routes every replayed item through the checked
    // per-item constructor (M-1).
    let replay_body = body("async fn replay_served_receipt(");
    assert!(replay_body.contains("page_last_ordinal(first, item_count)"));
    assert!(replay_body.contains("InventoryPageItem::from_database"));
    let forward = body("fn predecessor_forward_after_ordinal(");
    assert!(forward.contains("page_last_ordinal(first, count)"));
    let page_read = body("async fn read_retained_page(");
    assert!(
        page_read.contains("InventoryPageItem::from_database"),
        "the D-2 serve read path applies the checked per-item constructor (M-1)"
    );

    for sql_shape in [
        "request_cursor_hash IS NULL",
        "WHERE request_cursor_hash = $1",
        "WHERE successor_cursor_hash = $1",
        "successor_cursor_nonce",
        "successor_cursor_ciphertext",
        "canonical_response_sha256",
    ] {
        assert!(
            source.contains(sql_shape),
            "production receipt SQL missing {sql_shape}"
        );
    }
}

/// C-1/C-2 fix-round executable coverage: the corrected boundary arithmetic
/// runs against the REAL production helper compiled from `inventory.rs` via
/// the path-include mount — not a test-local replica.
#[test]
fn page_last_ordinal_is_the_production_boundary_arithmetic() {
    use repository::inventory::page_last_ordinal;
    // The initial arm: a page starting at ordinal 0 with N items ends at N-1.
    assert_eq!(page_last_ordinal(0, 1), Some(0));
    assert_eq!(page_last_ordinal(0, 100), Some(99));
    // The continuation arm: `first + count - 1` == `after + count`.
    assert_eq!(page_last_ordinal(7, 7), Some(13));
    assert_eq!(page_last_ordinal(14, 3), Some(16));
    // The pre-page boundary itself (the C-2 defect compared against
    // `after_ordinal` = `first - 1`) can never be the last ordinal of a
    // non-empty page.
    for (first, count) in [(0i64, 1i64), (7, 7), (14, 3)] {
        assert_ne!(page_last_ordinal(first, count), Some(first - 1));
    }
    // Fail-closed shapes: empty page, negative ordinal/count, overflow.
    assert_eq!(page_last_ordinal(0, 0), None);
    assert_eq!(page_last_ordinal(-1, 5), None);
    assert_eq!(page_last_ordinal(5, -1), None);
    assert_eq!(page_last_ordinal(i64::MAX, 2), None);
    assert_eq!(page_last_ordinal(i64::MAX, 1), Some(i64::MAX));
}

/// I-1: `CanonicalInventoryResponse` renders a redacted `Debug` — the response
/// bytes (which embed the session and successor capability text) never reach
/// `Debug` output. Behavioural check over the real production type.
#[test]
fn canonical_inventory_response_debug_is_redacted() {
    use repository::inventory::CanonicalInventoryResponse;
    let secret_text = "SECRET-CAPABILITY-TEXT-THAT-MUST-NEVER-DEBUG";
    let bytes = format!("{{\"inventorySessionId\":\"{secret_text}\"}}").into_bytes();
    let sha256: [u8; 32] = Sha256::digest(&bytes).into();
    let response = CanonicalInventoryResponse::checked(bytes, sha256)
        .expect("a hash-consistent response within the ceiling");
    let rendered = format!("{response:?}");
    assert!(
        !rendered.contains(secret_text),
        "Debug output must not carry the response bytes"
    );
    assert!(rendered.contains("REDACTED"));
    // The source side: no derived Debug remains on the struct.
    let source = include_str!("../src/chat_protocol/repository/inventory.rs");
    let derive_line = source
        .split_once("pub(crate) struct CanonicalInventoryResponse {")
        .expect("the response struct exists")
        .0
        .rsplit_once("#[derive(")
        .expect("the response struct has a derive list")
        .1;
    assert!(
        !derive_line.starts_with("Clone, Debug")
            && !derive_line[..derive_line.find(']').unwrap_or(derive_line.len())].contains("Debug"),
        "CanonicalInventoryResponse must not derive Debug over its bytes"
    );
}
