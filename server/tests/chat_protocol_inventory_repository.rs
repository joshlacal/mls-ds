//! Repository-boundary tests for clean-chat inventory continuation authority.
//!
//! The non-database cases compile the production repository module directly.
//! Live PostgreSQL cases stay out of this target until the root task grants
//! access to the dedicated clean-chat DSN.

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
    CursorCodec, DeviceCursorBinding, EventCursor, InventoryPageDomain, InventorySessionBinding,
    InventorySessionToken,
};
use repository::inventory::{
    lock_inventory_session_for_test, seal_conversation_inventory_page,
    seal_pending_welcome_inventory_page, seal_recovery_inventory_page, InventoryCompletionEvidence,
    InventoryRepositoryError, InventorySessionLockFixture,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use validation::{ed25519_key_id, BareDid, KeyThumbprint};
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

fn codec() -> CursorCodec {
    CursorCodec::new(
        Uuid::parse_str(PROTOCOL_INSTANCE).unwrap(),
        &URL_SAFE_NO_PAD.encode([0x41; 32]),
        Zeroizing::new([0xA5; 32]),
    )
    .unwrap()
}

fn device() -> DeviceCursorBinding {
    DeviceCursorBinding::new(
        &BareDid::parse(DID).unwrap(),
        Uuid::parse_str(DEVICE_ID).unwrap(),
        7,
        &KeyThumbprint::parse(&URL_SAFE_NO_PAD.encode([0x61; 32])).unwrap(),
    )
    .unwrap()
}

struct IssuedInventory {
    event_cursor: EventCursor,
    session_binding: InventorySessionBinding,
    session_token: InventorySessionToken,
}

fn issued_inventory(codec: &CursorCodec) -> IssuedInventory {
    let event_cursor = codec
        .issue_event_cursor(&device(), 42, 10, CREATED_AT as u64, EXPIRES_AT as u64)
        .unwrap();
    let session_binding = codec
        .bind_inventory_session(
            device(),
            Uuid::parse_str(SESSION_ID).unwrap(),
            &event_cursor,
            42,
            EXPIRES_AT as u64,
            LOCKED_AT as u64,
            10,
            42,
        )
        .unwrap();
    let session_token = codec
        .issue_inventory_session_id(&session_binding, CREATED_AT as u64, 10, 42)
        .unwrap();
    IssuedInventory {
        event_cursor,
        session_binding,
        session_token,
    }
}

fn fixture(issued: &IssuedInventory) -> InventorySessionLockFixture {
    let signing_public_key = [0x33; 32];
    InventorySessionLockFixture {
        transaction_id: TRANSACTION_ID.to_owned(),
        inventory_session_id: Uuid::parse_str(SESSION_ID).unwrap(),
        token_hash: issued.session_token.binding_hash(),
        user_did: DID.to_owned(),
        device_id: Uuid::parse_str(DEVICE_ID).unwrap(),
        jkt: URL_SAFE_NO_PAD.encode([0x61; 32]),
        auth_generation: 7,
        snapshot_event_position: 42,
        snapshot_event_cursor_bytes: issued.event_cursor.as_str().as_bytes().to_vec(),
        snapshot_event_cursor_sha256: Sha256::digest(issued.event_cursor.as_str().as_bytes())
            .into(),
        created_at: Utc.timestamp_opt(CREATED_AT, 0).unwrap(),
        expires_at: Utc.timestamp_opt(EXPIRES_AT, 0).unwrap(),
        conversations: InventoryCompletionEvidence::incomplete(),
        welcomes: InventoryCompletionEvidence::incomplete(),
        recovery: InventoryCompletionEvidence::incomplete(),
        device_status: "active".to_owned(),
        current_dpop_jkt: URL_SAFE_NO_PAD.encode([0x61; 32]),
        current_auth_generation: 7,
        device_revoked_at: None,
        key_id: ed25519_key_id(&signing_public_key)
            .unwrap()
            .as_str()
            .to_owned(),
        signing_public_key,
        key_enrollment_auth_generation: 1,
        key_revoked_at: None,
        protocol_instance_id: Uuid::parse_str(PROTOCOL_INSTANCE).unwrap(),
        cursor_key_id: URL_SAFE_NO_PAD.encode([0x41; 32]),
        retained_floor: 10,
        retention_updated_at: Utc.timestamp_opt(CREATED_AT - 10, 0).unwrap(),
        head_event_position: 42,
        head_event_id: Some(Uuid::parse_str("55555555-5555-4555-8555-555555555555").unwrap()),
        head_payload_sha256: Some([0x55; 32]),
        head_created_at: Some(Utc.timestamp_opt(CREATED_AT - 1, 0).unwrap()),
        locked_at: Utc.timestamp_opt(LOCKED_AT, 0).unwrap(),
    }
}

fn page_cursor(
    codec: &CursorCodec,
    issued: &IssuedInventory,
    domain: InventoryPageDomain,
    ordinal: u64,
    item_key: &[u8],
) -> String {
    let binding = codec
        .bind_inventory_page(
            &issued.session_binding,
            &issued.session_token,
            &issued.event_cursor,
            domain,
            FILTER,
            LOCKED_AT as u64,
            10,
            42,
        )
        .unwrap();
    codec
        .issue_inventory_page_cursor(&binding, ordinal, item_key, LOCKED_AT as u64, 10, 42)
        .unwrap()
        .as_str()
        .to_owned()
}

#[test]
fn conversation_continuation_consumes_hash_selected_locked_row() {
    let codec = codec();
    let issued = issued_inventory(&codec);
    let encoded = page_cursor(
        &codec,
        &issued,
        InventoryPageDomain::Conversations,
        9,
        b"conversation-key",
    );
    let locator = codec
        .locate_inventory_page_cursor(
            &encoded,
            InventoryPageDomain::Conversations,
            LOCKED_AT as u64,
        )
        .unwrap();
    let guard = lock_inventory_session_for_test(&codec, fixture(&issued)).unwrap();

    let authority =
        seal_conversation_inventory_page(&codec, &encoded, locator, guard, FILTER).unwrap();
    assert_eq!(
        authority.inventory_session_id(),
        Uuid::parse_str(SESSION_ID).unwrap()
    );
    assert_eq!(authority.domain(), InventoryPageDomain::Conversations);
    assert_eq!(authority.last_ordinal(), 9);
    authority
        .validate_boundary_item_for_test(TRANSACTION_ID, 9, b"conversation-key")
        .unwrap();
    assert_eq!(
        authority
            .validate_boundary_item_for_test(TRANSACTION_ID, 9, b"different-key")
            .unwrap_err(),
        InventoryRepositoryError::BoundaryItemMismatch
    );
    assert_eq!(
        authority
            .validate_boundary_item_for_test("703", 9, b"conversation-key")
            .unwrap_err(),
        InventoryRepositoryError::TransactionMismatch
    );
}

#[test]
fn welcome_and_recovery_continuations_require_the_exact_raw_session_id() {
    let codec = codec();
    let issued = issued_inventory(&codec);

    for (domain, item_key) in [
        (
            InventoryPageDomain::PendingWelcomes,
            b"welcome-key".as_slice(),
        ),
        (
            InventoryPageDomain::LeafRecovery,
            b"recovery-key".as_slice(),
        ),
    ] {
        let encoded = page_cursor(&codec, &issued, domain, 3, item_key);
        let locator = codec
            .locate_inventory_page_cursor(&encoded, domain, LOCKED_AT as u64)
            .unwrap();
        let guard = lock_inventory_session_for_test(&codec, fixture(&issued)).unwrap();
        let exact = match domain {
            InventoryPageDomain::PendingWelcomes => seal_pending_welcome_inventory_page(
                &codec,
                &encoded,
                locator,
                guard,
                issued.session_token.as_str(),
                FILTER,
            ),
            InventoryPageDomain::LeafRecovery => seal_recovery_inventory_page(
                &codec,
                &encoded,
                locator,
                guard,
                issued.session_token.as_str(),
                FILTER,
            ),
            InventoryPageDomain::Conversations => unreachable!(),
        };
        assert!(exact.is_ok());

        let encoded = page_cursor(&codec, &issued, domain, 3, item_key);
        let locator = codec
            .locate_inventory_page_cursor(&encoded, domain, LOCKED_AT as u64)
            .unwrap();
        let guard = lock_inventory_session_for_test(&codec, fixture(&issued)).unwrap();
        let wrong = match domain {
            InventoryPageDomain::PendingWelcomes => seal_pending_welcome_inventory_page(
                &codec,
                &encoded,
                locator,
                guard,
                "not-the-inventory-session",
                FILTER,
            ),
            InventoryPageDomain::LeafRecovery => seal_recovery_inventory_page(
                &codec,
                &encoded,
                locator,
                guard,
                "not-the-inventory-session",
                FILTER,
            ),
            InventoryPageDomain::Conversations => unreachable!(),
        };
        assert_eq!(
            wrong.unwrap_err(),
            InventoryRepositoryError::SessionPresentationMismatch
        );
    }
}

#[test]
fn restart_rehydrates_exact_persisted_cursor_and_rejects_row_drift() {
    let issuing_codec = codec();
    let issued = issued_inventory(&issuing_codec);
    let encoded = page_cursor(
        &issuing_codec,
        &issued,
        InventoryPageDomain::Conversations,
        2,
        b"restart-key",
    );

    let restarted_codec = codec();
    let locator = restarted_codec
        .locate_inventory_page_cursor(
            &encoded,
            InventoryPageDomain::Conversations,
            LOCKED_AT as u64,
        )
        .unwrap();
    let guard = lock_inventory_session_for_test(&restarted_codec, fixture(&issued)).unwrap();
    assert!(
        seal_conversation_inventory_page(&restarted_codec, &encoded, locator, guard, FILTER)
            .is_ok()
    );

    let mut drifted = fixture(&issued);
    drifted.snapshot_event_cursor_bytes[0] ^= 1;
    assert_eq!(
        lock_inventory_session_for_test(&restarted_codec, drifted).unwrap_err(),
        InventoryRepositoryError::DurableRowInvalid
    );

    let mut stale_auth = fixture(&issued);
    stale_auth.current_auth_generation += 1;
    assert_eq!(
        lock_inventory_session_for_test(&restarted_codec, stale_auth).unwrap_err(),
        InventoryRepositoryError::DeviceAuthorityMismatch
    );
}

#[test]
fn completed_domain_and_wrong_protocol_fence_cannot_mint_page_authority() {
    let codec = codec();
    let issued = issued_inventory(&codec);
    let encoded = page_cursor(
        &codec,
        &issued,
        InventoryPageDomain::Conversations,
        1,
        b"already-complete-key",
    );

    let mut completed = fixture(&issued);
    completed.conversations = InventoryCompletionEvidence::complete(2, [0x72; 32]).unwrap();
    let locator = codec
        .locate_inventory_page_cursor(
            &encoded,
            InventoryPageDomain::Conversations,
            LOCKED_AT as u64,
        )
        .unwrap();
    let guard = lock_inventory_session_for_test(&codec, completed).unwrap();
    assert_eq!(
        seal_conversation_inventory_page(&codec, &encoded, locator, guard, FILTER).unwrap_err(),
        InventoryRepositoryError::DomainAlreadyComplete
    );

    let mut wrong_instance = fixture(&issued);
    wrong_instance.protocol_instance_id = Uuid::new_v4();
    assert_eq!(
        lock_inventory_session_for_test(&codec, wrong_instance).unwrap_err(),
        InventoryRepositoryError::ProtocolFenceMismatch
    );

    let mut stale_floor = fixture(&issued);
    stale_floor.retained_floor = 43;
    assert_eq!(
        lock_inventory_session_for_test(&codec, stale_floor).unwrap_err(),
        InventoryRepositoryError::ProtocolFenceMismatch
    );
}

#[test]
fn final_page_completion_is_exact_and_transaction_bound() {
    let codec = codec();
    let issued = issued_inventory(&codec);
    let encoded = page_cursor(
        &codec,
        &issued,
        InventoryPageDomain::Conversations,
        9,
        b"final-boundary-key",
    );
    let locator = codec
        .locate_inventory_page_cursor(
            &encoded,
            InventoryPageDomain::Conversations,
            LOCKED_AT as u64,
        )
        .unwrap();
    let guard = lock_inventory_session_for_test(&codec, fixture(&issued)).unwrap();
    let authority =
        seal_conversation_inventory_page(&codec, &encoded, locator, guard, FILTER).unwrap();
    let completion = authority
        .seal_final_page_completion_for_test(TRANSACTION_ID, 10, [0x91; 32])
        .unwrap();
    completion
        .validate_transaction_for_test(TRANSACTION_ID)
        .unwrap();

    let locator = codec
        .locate_inventory_page_cursor(
            &encoded,
            InventoryPageDomain::Conversations,
            LOCKED_AT as u64,
        )
        .unwrap();
    let guard = lock_inventory_session_for_test(&codec, fixture(&issued)).unwrap();
    let authority =
        seal_conversation_inventory_page(&codec, &encoded, locator, guard, FILTER).unwrap();
    assert_eq!(
        authority
            .seal_final_page_completion_for_test("703", 10, [0x91; 32])
            .unwrap_err(),
        InventoryRepositoryError::TransactionMismatch
    );
}

#[test]
fn production_sql_locks_and_consumes_exact_inventory_authority() {
    let source = include_str!("../src/chat_protocol/repository/inventory.rs");

    for required in [
        "WHERE token_hash = $1",
        "FOR UPDATE",
        "FROM chat.protocol_instances",
        "FROM chat.event_retention",
        "FROM chat.events",
        "FROM chat.devices",
        "JOIN chat.device_keys",
        "SELECT txid_current()::text",
        "snapshot_event_cursor_bytes",
        "snapshot_event_cursor_sha256",
        "rows_affected() != 1",
        // Every per-arm completion column is wired into the consume query. The
        // FALSE/IS NULL (incomplete) and TRUE/= (complete) invariants are now
        // emitted by `push_completion_predicate`, so the exact predicate
        // templates are asserted separately below rather than inline per column.
        "conversations_complete",
        "conversation_item_count",
        "conversation_items_sha256",
        "welcomes_complete",
        "welcome_item_count",
        "welcome_items_sha256",
        "recovery_complete",
        "recovery_item_count",
        "recovery_items_sha256",
        " = FALSE AND ",
        " IS NULL AND ",
        " IS NULL",
        " = TRUE AND ",
    ] {
        assert!(
            source.contains(required),
            "missing production invariant: {required}"
        );
    }

    // Bound the guard to its own struct body (the fields between `{` and the
    // closing `}`). Unrelated repository structs now sit between the guard
    // declaration and its `impl`, so anchoring on the struct's closing brace
    // keeps this contract focused on the guard definition itself.
    let guard = source
        .split_once("pub(crate) struct LockedInventorySessionGuard")
        .expect("locked session guard exists")
        .1
        .split_once("\n}")
        .expect("guard struct body is closed")
        .0;
    assert!(!guard.contains("InventorySessionToken"));
    assert!(!guard.contains("raw_inventory_session"));
    assert!(guard.contains("token_hash"));
    assert!(guard.contains("durable_row_digest"));
}
