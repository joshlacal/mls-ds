//! Integration tests for the bootstrapResetGroup endpoint.
//!
//! Phase 3 of MLS auto-reset (2026-04-26) needs first-responder bootstrap to
//! complete a post-auto-reset conversation in place. This is distinct from
//! createConvo, which INSERTs at id = input.groupId — calling that for the
//! post-reset newGroupId would orphan the existing row sitting at
//! id = originalConvoId.
//!
//! These tests exercise the SQL state machine the handler depends on:
//!   - target row lookup by (id, group_id) pair
//!   - liveness sentinel (group_info IS NULL → bootstrap-eligible)
//!   - membership gate against the preserved roster
//!   - in-place UPDATE
//!
//! Mirrors the test pattern in `tests/db_tests.rs` and
//! `tests/create_convo_collision.rs`. Requires TEST_DATABASE_URL pointing at
//! a Postgres with the catbird schema applied.

use catbird_server::db::*;
use chrono::Utc;
use sqlx::PgPool;
use std::time::Duration;

const ALICE: &str = "did:plc:alice4444444444444444444";
const BOB: &str = "did:plc:bob44444444444444444444444";
const CHARLIE: &str = "did:plc:charlie444444444444444444";
const ORIGINAL_CONVO_ID: &str = "convo-bootstrap-test-0001";
const NEW_GROUP_ID: &str = "deadbeefcafebabe1234567890abcdef";

async fn setup_test_db() -> PgPool {
    let database_url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://localhost/catbird_test".to_string());

    let config = DbConfig {
        database_url,
        max_connections: 4,
        min_connections: 1,
        acquire_timeout: Duration::from_secs(30),
        idle_timeout: Duration::from_secs(600),
    };

    init_db(config)
        .await
        .expect("Failed to initialize test database")
}

async fn cleanup(pool: &PgPool, convo_id: &str) {
    let _ = sqlx::query("DELETE FROM welcome_messages WHERE convo_id = $1")
        .bind(convo_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM members WHERE convo_id = $1")
        .bind(convo_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM conversations WHERE id = $1")
        .bind(convo_id)
        .execute(pool)
        .await;
}

/// Sets up a post-auto-reset conversation: the row exists with
/// id = originalConvoId, group_id = newGroupId, group_info = NULL,
/// current_epoch = 0, and the member roster preserved.
async fn setup_post_reset_convo(pool: &PgPool, members: &[&str]) {
    let now = Utc::now();
    sqlx::query(
        "INSERT INTO conversations \
            (id, creator_did, current_epoch, created_at, updated_at, cipher_suite, is_remote, \
             group_id, group_info, last_reset_at, reset_count) \
         VALUES ($1, $2, 0, $3, $3, $4, false, $5, NULL, $3, 1) \
         ON CONFLICT (id) DO UPDATE SET \
            group_id = EXCLUDED.group_id, \
            group_info = NULL, \
            current_epoch = 0, \
            last_reset_at = EXCLUDED.last_reset_at",
    )
    .bind(ORIGINAL_CONVO_ID)
    .bind(members[0])
    .bind(&now)
    .bind("MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519")
    .bind(NEW_GROUP_ID)
    .execute(pool)
    .await
    .expect("setup conversations row");

    for member in members {
        sqlx::query(
            "INSERT INTO members (convo_id, member_did, user_did, joined_at, is_admin) \
             VALUES ($1, $2, $2, $3, $4) \
             ON CONFLICT (convo_id, member_did) DO NOTHING",
        )
        .bind(ORIGINAL_CONVO_ID)
        .bind(member)
        .bind(&now)
        .bind(member == &members[0])
        .execute(pool)
        .await
        .expect("setup members row");
    }
}

/// Mirrors the discrimination logic the handler runs. The boundary captured
/// here is: lookup target by (id, group_id), gate on caller membership, and
/// detect race-loss via group_info presence.
#[derive(Debug, PartialEq, Eq)]
enum BootstrapClassification {
    /// Caller is a member, target row exists with group_info NULL — proceed.
    Proceed,
    /// Caller is a member but target was already bootstrapped (race-loss).
    AlreadyBootstrapped,
    /// (id, group_id) pair has no matching row.
    TargetNotFound,
    /// Caller is not in the existing roster.
    NotMember,
}

async fn classify(
    pool: &PgPool,
    convo_id: &str,
    new_group_id: &str,
    caller_did: &str,
) -> BootstrapClassification {
    // 1. Membership gate
    let is_member: bool = sqlx::query_scalar(
        "SELECT EXISTS(\
            SELECT 1 FROM members \
            WHERE convo_id = $1 AND (user_did = $2 OR member_did = $2) AND left_at IS NULL\
        )",
    )
    .bind(convo_id)
    .bind(caller_did)
    .fetch_one(pool)
    .await
    .expect("member check");

    if !is_member {
        return BootstrapClassification::NotMember;
    }

    // 2. Target row + sentinel
    let target: Option<(Option<Vec<u8>>,)> =
        sqlx::query_as("SELECT group_info FROM conversations WHERE id = $1 AND group_id = $2")
            .bind(convo_id)
            .bind(new_group_id)
            .fetch_optional(pool)
            .await
            .expect("target lookup");

    match target {
        None => BootstrapClassification::TargetNotFound,
        Some((Some(_),)) => BootstrapClassification::AlreadyBootstrapped,
        Some((None,)) => BootstrapClassification::Proceed,
    }
}

#[tokio::test]
async fn bootstrap_member_finds_proceed_state() {
    let pool = setup_test_db().await;
    cleanup(&pool, ORIGINAL_CONVO_ID).await;
    setup_post_reset_convo(&pool, &[ALICE, BOB]).await;

    let result = classify(&pool, ORIGINAL_CONVO_ID, NEW_GROUP_ID, ALICE).await;
    assert_eq!(
        result,
        BootstrapClassification::Proceed,
        "alice (member, post-reset row, group_info NULL) must be cleared to bootstrap"
    );

    cleanup(&pool, ORIGINAL_CONVO_ID).await;
}

#[tokio::test]
async fn bootstrap_race_loss_when_group_info_already_populated() {
    let pool = setup_test_db().await;
    cleanup(&pool, ORIGINAL_CONVO_ID).await;
    setup_post_reset_convo(&pool, &[ALICE, BOB]).await;

    // Simulate the race winner having already bootstrapped: populate group_info.
    sqlx::query(
        "UPDATE conversations SET group_info = $1, group_info_epoch = 1, current_epoch = 1 \
         WHERE id = $2",
    )
    .bind(b"\x01\x02\x03\x04winner-group-info".as_slice())
    .bind(ORIGINAL_CONVO_ID)
    .execute(&pool)
    .await
    .expect("simulate race winner");

    let result = classify(&pool, ORIGINAL_CONVO_ID, NEW_GROUP_ID, BOB).await;
    assert_eq!(
        result,
        BootstrapClassification::AlreadyBootstrapped,
        "bob (member, but row already has group_info) must be told he lost the race"
    );

    cleanup(&pool, ORIGINAL_CONVO_ID).await;
}

#[tokio::test]
async fn bootstrap_not_member_rejected() {
    let pool = setup_test_db().await;
    cleanup(&pool, ORIGINAL_CONVO_ID).await;
    setup_post_reset_convo(&pool, &[ALICE, BOB]).await;

    let result = classify(&pool, ORIGINAL_CONVO_ID, NEW_GROUP_ID, CHARLIE).await;
    assert_eq!(
        result,
        BootstrapClassification::NotMember,
        "charlie (not in roster) must be rejected before any bootstrap state is touched"
    );

    cleanup(&pool, ORIGINAL_CONVO_ID).await;
}

#[tokio::test]
async fn bootstrap_target_not_found_when_group_id_overwritten() {
    let pool = setup_test_db().await;
    cleanup(&pool, ORIGINAL_CONVO_ID).await;
    setup_post_reset_convo(&pool, &[ALICE]).await;

    // Simulate a subsequent reset that overwrote group_id to a third value,
    // making the original (id, NEW_GROUP_ID) pair no longer match anything.
    sqlx::query("UPDATE conversations SET group_id = $1 WHERE id = $2")
        .bind("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        .bind(ORIGINAL_CONVO_ID)
        .execute(&pool)
        .await
        .expect("simulate subsequent reset");

    let result = classify(&pool, ORIGINAL_CONVO_ID, NEW_GROUP_ID, ALICE).await;
    assert_eq!(
        result,
        BootstrapClassification::TargetNotFound,
        "alice asking for a stale newGroupId must get BootstrapTargetNotFound, not Proceed"
    );

    cleanup(&pool, ORIGINAL_CONVO_ID).await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Deeper handler test — drives `handle()` directly to lock down the actual
// UPDATE + welcome insertion + ConvoView shape (the SQL classification tests
// above only verify the read-side discrimination).
// ─────────────────────────────────────────────────────────────────────────────

use catbird_server::auth::{AtProtoClaims, AuthUser};
use catbird_server::generated::blue_catbird::mlsChat::bootstrap_reset_group::BootstrapResetGroup;
use catbird_server::handlers::mls_chat::bootstrap_reset_group::handle as bootstrap_handle;
use catbird_server::sqlx_jacquard::string_to_did;

fn test_auth_user(did: &str) -> AuthUser {
    AuthUser {
        did: did.to_string(),
        claims: AtProtoClaims {
            iss: did.to_string(),
            aud: "did:web:test.catbird.blue".to_string(),
            exp: 9_999_999_999,
            iat: Some(0),
            sub: Some(did.to_string()),
            lxm: Some("blue.catbird.mlsChat.bootstrapResetGroup".to_string()),
            jti: Some(format!("test-jti-{}", uuid::Uuid::new_v4())),
        },
    }
}

#[tokio::test]
async fn bootstrap_handle_updates_row_and_returns_view() {
    let pool = setup_test_db().await;
    cleanup(&pool, ORIGINAL_CONVO_ID).await;
    setup_post_reset_convo(&pool, &[ALICE, BOB]).await;

    let group_info_payload = bytes::Bytes::from_static(b"test-group-info-bytes");
    let input = BootstrapResetGroup {
        original_convo_id: ORIGINAL_CONVO_ID.into(),
        new_group_id: NEW_GROUP_ID.into(),
        cipher_suite: "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519".into(),
        group_info: group_info_payload.clone(),
        members: vec![string_to_did(ALICE), string_to_did(BOB)],
        welcome_message: None,
        key_package_hashes: None,
        current_epoch: Some(1),
        extra_data: Default::default(),
    };

    let result = bootstrap_handle(pool.clone(), test_auth_user(ALICE), &input).await;
    assert!(
        result.is_ok(),
        "bootstrap_handle should succeed; err = {:?}",
        result.as_ref().err().map(|_| "Response")
    );

    // Inspect the persisted row directly to confirm UPDATE side effects.
    // current_epoch is INT4 in the schema — must decode as i32 to satisfy sqlx.
    let (group_info_persisted, group_info_epoch, current_epoch_persisted, cipher_suite_persisted): (
        Option<Vec<u8>>,
        Option<i32>,
        i32,
        Option<String>,
    ) = sqlx::query_as(
        "SELECT group_info, group_info_epoch, current_epoch, cipher_suite FROM conversations WHERE id = $1",
    )
    .bind(ORIGINAL_CONVO_ID)
    .fetch_one(&pool)
    .await
    .expect("post-bootstrap row read");

    assert_eq!(
        group_info_persisted.as_deref(),
        Some(group_info_payload.as_ref()),
        "group_info column must reflect the input bytes"
    );
    assert_eq!(
        group_info_epoch,
        Some(1),
        "group_info_epoch must be set to 1"
    );
    assert_eq!(
        current_epoch_persisted, 1,
        "current_epoch must advance from 0 to 1"
    );
    assert_eq!(
        cipher_suite_persisted.as_deref(),
        Some("MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519"),
    );

    // Inspect ConvoView shape via the returned output.
    let output = result.unwrap();
    assert_eq!(output.convo.epoch, 1);
    assert_eq!(output.convo.conversation_id.as_ref(), ORIGINAL_CONVO_ID);
    assert_eq!(output.convo.group_id.as_ref(), NEW_GROUP_ID);
    assert_eq!(output.convo.members.len(), 2, "preserved 2-member roster");

    cleanup(&pool, ORIGINAL_CONVO_ID).await;
}

#[tokio::test]
async fn bootstrap_handle_with_welcome_inserts_per_recipient_envelopes() {
    let pool = setup_test_db().await;
    cleanup(&pool, ORIGINAL_CONVO_ID).await;
    setup_post_reset_convo(&pool, &[ALICE, BOB]).await;

    let welcome_payload = bytes::Bytes::from_static(b"welcome-envelope-bytes");
    let input = BootstrapResetGroup {
        original_convo_id: ORIGINAL_CONVO_ID.into(),
        new_group_id: NEW_GROUP_ID.into(),
        cipher_suite: "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519".into(),
        group_info: bytes::Bytes::from_static(b"gi-bytes"),
        members: vec![string_to_did(ALICE), string_to_did(BOB)],
        welcome_message: Some(welcome_payload.clone()),
        key_package_hashes: None,
        current_epoch: Some(1),
        extra_data: Default::default(),
    };

    let result = bootstrap_handle(pool.clone(), test_auth_user(ALICE), &input).await;
    assert!(result.is_ok());

    let recipients: Vec<String> = sqlx::query_scalar(
        "SELECT recipient_did FROM welcome_messages WHERE convo_id = $1 ORDER BY recipient_did",
    )
    .bind(ORIGINAL_CONVO_ID)
    .fetch_all(&pool)
    .await
    .expect("welcome rows");

    assert_eq!(recipients.len(), 2, "one welcome row per existing member");
    assert!(recipients.iter().any(|d| d == ALICE));
    assert!(recipients.iter().any(|d| d == BOB));

    cleanup(&pool, ORIGINAL_CONVO_ID).await;
}
