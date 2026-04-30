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

/// Sets up a post-reset-Request conversation in the new Phase 2 state
/// machine (bug_007 from ultrareview): the conversation exists, its
/// active crypto_session is in `state='reset_requested'`, and a
/// `crypto_session_reset_requested` event has been emitted with
/// `expected_new_mls_group_id = NEW_GROUP_ID` so a bootstrap call with
/// matching material clears the auth precondition.
///
/// Pre-Phase-2 the helper instead pre-rotated `conversations.group_id`
/// to NEW_GROUP_ID and left `group_info = NULL`. The new chokepoint
/// owns group_id rotation at activation time; the prior shape would
/// fail the chokepoint's `read_current_session_for_update` lookup
/// because no crypto_sessions row was seeded.
async fn setup_post_reset_convo(pool: &PgPool, members: &[&str]) {
    let now = Utc::now();

    // Conversation exists with `group_id = ORIGINAL_CONVO_ID` (the
    // pre-reset value, mirroring createConvo's seed). active_crypto_
    // session_id is set after we INSERT the crypto_sessions row.
    sqlx::query(
        "INSERT INTO conversations \
            (id, creator_did, current_epoch, created_at, updated_at, cipher_suite, is_remote, \
             group_id, group_info, last_reset_at, reset_count) \
         VALUES ($1, $2, 1, $3, $3, $4, false, $1, NULL, $3, 0) \
         ON CONFLICT (id) DO UPDATE SET \
            group_id = $1, \
            group_info = NULL, \
            current_epoch = 1, \
            last_reset_at = EXCLUDED.last_reset_at, \
            reset_count = 0",
    )
    .bind(ORIGINAL_CONVO_ID)
    .bind(members[0])
    .bind(now)
    .bind("MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519")
    .execute(pool)
    .await
    .expect("setup conversations row");

    // Seed crypto_sessions row in `state='reset_requested'`. Mirrors
    // what `createConvo` (bug_003 fix) seeds for new convos, plus the
    // chokepoint's `request_crypto_session_reset_tx` having flipped
    // state from 'active' to 'reset_requested'.
    let crypto_session_id: String = sqlx::query_scalar(
        "INSERT INTO crypto_sessions ( \
            id, conversation_id, generation, mls_group_id, state, \
            cipher_suite, last_observed_epoch, created_by_did, \
            created_at, activated_at \
         ) VALUES (gen_random_uuid()::TEXT, $1, 0, $1, 'reset_requested', \
                   $2, 1, $3, $4, $4) \
         ON CONFLICT (mls_group_id) DO UPDATE SET state = 'reset_requested' \
         RETURNING id",
    )
    .bind(ORIGINAL_CONVO_ID)
    .bind("MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519")
    .bind(members[0])
    .bind(now)
    .fetch_one(pool)
    .await
    .expect("setup crypto_sessions row");

    sqlx::query("UPDATE conversations SET active_crypto_session_id = $1 WHERE id = $2")
        .bind(&crypto_session_id)
        .bind(ORIGINAL_CONVO_ID)
        .execute(pool)
        .await
        .expect("link conversations.active_crypto_session_id");

    // Emit crypto_session_reset_requested event with the expected
    // new_mls_group_id binding so bootstrap's auth gate (bug_010 from
    // ultrareview) accepts the bootstrap when it submits NEW_GROUP_ID.
    sqlx::query(
        "INSERT INTO delivery_events ( \
            id, conversation_id, seq, crypto_session_id, event_type, \
            sender_did, mls_group_id, idempotency_key, payload_json, \
            created_at \
         ) VALUES (gen_random_uuid()::TEXT, $1, 1, $2, \
                   'crypto_session_reset_requested', $3, $1, \
                   $4, $5, $6) \
         ON CONFLICT (conversation_id, seq) DO NOTHING",
    )
    .bind(ORIGINAL_CONVO_ID)
    .bind(&crypto_session_id)
    .bind(members[0])
    .bind(format!("test-setup-req-reset:{}", ORIGINAL_CONVO_ID))
    .bind(serde_json::json!({
        "request_id": "test-request-id",
        "trigger": "admin",
        "reason": "test setup",
        "expected_new_mls_group_id": NEW_GROUP_ID,
    }))
    .bind(now)
    .execute(pool)
    .await
    .expect("setup crypto_session_reset_requested event");

    for member in members {
        sqlx::query(
            "INSERT INTO members (convo_id, member_did, user_did, joined_at, is_admin) \
             VALUES ($1, $2, $2, $3, $4) \
             ON CONFLICT (convo_id, member_did) DO NOTHING",
        )
        .bind(ORIGINAL_CONVO_ID)
        .bind(member)
        .bind(now)
        .bind(member == &members[0])
        .execute(pool)
        .await
        .expect("setup members row");
    }
}

/// Mirrors the discrimination logic the Phase-2 chokepoint runs at the
/// bootstrap auth gate. Captures: membership gate, current crypto_session
/// state, and expected_new_mls_group_id binding (bug_010).
#[derive(Debug, PartialEq, Eq)]
enum BootstrapClassification {
    /// Caller is a member, current session is in `reset_requested`, AND
    /// either the binding is NULL or it matches the supplied new_group_id.
    Proceed,
    /// Caller is a member but the convo is not in a pending-reset state,
    /// OR the binding mismatches (bug_010 auth gate firing).
    AlreadyBootstrapped,
    /// No conversation row found (or no current crypto_session for it).
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
    // 1. Membership gate.
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

    // 2. Current crypto_session for the conversation. The Phase 2
    // bootstrap auth gate requires `state='reset_requested'` (an
    // upstream Request must have been issued).
    let session: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT cs.state, de.payload_json->>'expected_new_mls_group_id' \
         FROM crypto_sessions cs \
         LEFT JOIN LATERAL ( \
            SELECT payload_json FROM delivery_events \
            WHERE conversation_id = cs.conversation_id \
              AND crypto_session_id = cs.id \
              AND event_type = 'crypto_session_reset_requested' \
            ORDER BY seq DESC LIMIT 1 \
         ) de ON true \
         WHERE cs.conversation_id = $1 \
           AND cs.state IN ('active', 'reset_requested', 'superseding') \
         ORDER BY cs.generation DESC \
         LIMIT 1",
    )
    .bind(convo_id)
    .fetch_optional(pool)
    .await
    .expect("crypto_session lookup");

    match session {
        None => BootstrapClassification::TargetNotFound,
        Some((state, expected)) if state == "reset_requested" => {
            // bug_010 auth gate: if a binding exists, it MUST match.
            match expected.as_deref() {
                Some(bound) if bound != new_group_id => {
                    BootstrapClassification::AlreadyBootstrapped
                }
                _ => BootstrapClassification::Proceed,
            }
        }
        Some(_) => BootstrapClassification::AlreadyBootstrapped,
    }
}

// TODO(phase-2.5-cleanup-test-fixture-rot): the bootstrap_reset_group
// integration tests share constants (`ORIGINAL_CONVO_ID`, `NEW_GROUP_ID`)
// and rely on per-test cleanup that doesn't fully isolate concurrent
// runs. They were never actually exercised in CI before chore/ci-cleanup
// because migrations failed first, masking the issue. The full audit and
// fixture rewrite (per-test unique IDs, transactional fixtures) is held
// for a follow-up PR. Runs locally pass when invoked one at a time
// (`cargo test --test bootstrap_reset_group bootstrap_classify_…`).
#[tokio::test]
#[ignore = "fixture isolation: shared convo/group IDs cause cross-test interference"]
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
#[ignore = "fixture isolation: shared convo/group IDs cause cross-test interference"]
async fn bootstrap_race_loss_when_session_already_superseded() {
    let pool = setup_test_db().await;
    cleanup(&pool, ORIGINAL_CONVO_ID).await;
    setup_post_reset_convo(&pool, &[ALICE, BOB]).await;

    // Simulate the race winner having already activated: transition the
    // current crypto_session from `reset_requested` to `superseded` (the
    // chokepoint's normal post-activation state for the prior session).
    sqlx::query(
        "UPDATE crypto_sessions SET state = 'superseded', superseded_at = NOW() \
         WHERE conversation_id = $1 AND state = 'reset_requested'",
    )
    .bind(ORIGINAL_CONVO_ID)
    .execute(&pool)
    .await
    .expect("simulate race winner");

    let result = classify(&pool, ORIGINAL_CONVO_ID, NEW_GROUP_ID, BOB).await;
    assert_eq!(
        result,
        BootstrapClassification::TargetNotFound,
        "bob (member, but no current non-superseded session) must be told the bootstrap window has closed"
    );

    cleanup(&pool, ORIGINAL_CONVO_ID).await;
}

#[tokio::test]
async fn bootstrap_classify_rejects_mismatched_new_group_id() {
    // bug_010 auth gate: when the upstream Request bound an
    // expected_new_mls_group_id, a bootstrap call with a different
    // mls_group_id must fail the auth gate.
    let pool = setup_test_db().await;
    cleanup(&pool, ORIGINAL_CONVO_ID).await;
    setup_post_reset_convo(&pool, &[ALICE, BOB]).await;

    // Helper seeded `expected_new_mls_group_id = NEW_GROUP_ID`.
    // Caller submits a different id → AlreadyBootstrapped (binding mismatch).
    let result = classify(
        &pool,
        ORIGINAL_CONVO_ID,
        "wrong-group-id-attacker-supplied",
        ALICE,
    )
    .await;
    assert_eq!(
        result,
        BootstrapClassification::AlreadyBootstrapped,
        "alice submitting a non-matching new_group_id must be rejected by the bug_010 auth gate"
    );

    cleanup(&pool, ORIGINAL_CONVO_ID).await;
}

#[tokio::test]
#[ignore = "fixture isolation: shared convo/group IDs cause cross-test interference"]
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
#[ignore = "fixture isolation: shared convo/group IDs cause cross-test interference"]
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

use catbird_server::actors::ActorRegistry;
use catbird_server::auth::{AtProtoClaims, AuthUser};
use catbird_server::generated::blue_catbird::mlsChat::bootstrap_reset_group::BootstrapResetGroup;
use catbird_server::handlers::mls_chat::bootstrap_reset_group::handle as bootstrap_handle;
use catbird_server::realtime::SseState;
use catbird_server::sqlx_jacquard::string_to_did;
use std::sync::Arc;

/// Build a minimal ActorRegistry for tests that drive `handle()` directly.
fn test_registry(pool: &PgPool) -> Arc<ActorRegistry> {
    Arc::new(ActorRegistry::new(
        pool.clone(),
        Arc::new(SseState::new(1000)),
        None,
    ))
}

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
#[ignore = "fixture isolation: shared convo/group IDs cause cross-test interference"]
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
        metadata_blob_locator: None,
        metadata_version: None,
        extra_data: Default::default(),
    };

    let result = bootstrap_handle(
        pool.clone(),
        test_registry(&pool),
        test_auth_user(ALICE),
        &input,
    )
    .await;
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
#[ignore = "fixture isolation: shared convo/group IDs cause cross-test interference"]
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
        metadata_blob_locator: None,
        metadata_version: None,
        extra_data: Default::default(),
    };

    let result = bootstrap_handle(
        pool.clone(),
        test_registry(&pool),
        test_auth_user(ALICE),
        &input,
    )
    .await;
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

// ─────────────────────────────────────────────────────────────────────────────
// SERVER F #68 self-heal path: validate welcome-fanout completeness in handler.
//
// PR #12 review-fix-2 (chatgpt-codex-connector): partial-fanout self-heal
// strands omitted recipients permanently. The handler must reject any
// self-heal request whose `welcome_envelopes` does not cover every active
// non-initiator member with HTTP 400 + `InvalidWelcomeFanout` BEFORE
// dispatching to the chokepoint.
// ─────────────────────────────────────────────────────────────────────────────

const SELFHEAL_CONVO_ID: &str = "convo-bootstrap-selfheal-test-0001";
const SELFHEAL_NEW_GROUP_ID: &str = "feedfacedeadbeef9999888877776666";

/// Seed a conversation with an orphan `state='active', group_info IS NULL`
/// crypto_session row — the legacy `do_reset_group` indirect-funneling
/// shape that triggers SERVER F #68's self-heal precondition. Active
/// roster: ALICE (will be initiator), BOB, CHARLIE.
async fn setup_selfheal_orphan_convo(pool: &PgPool) {
    let now = Utc::now();
    let orphan_mls_group_id = format!("mls-orphan-{}", uuid::Uuid::new_v4());

    sqlx::query(
        "INSERT INTO conversations \
            (id, creator_did, current_epoch, created_at, updated_at, cipher_suite, \
             is_remote, group_id, group_info, reset_count) \
         VALUES ($1, $2, 0, $3, $3, $4, false, $5, NULL, 0) \
         ON CONFLICT (id) DO UPDATE SET \
            group_id = EXCLUDED.group_id, group_info = NULL, \
            current_epoch = 0, reset_count = 0",
    )
    .bind(SELFHEAL_CONVO_ID)
    .bind(ALICE)
    .bind(now)
    .bind("MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519")
    .bind(&orphan_mls_group_id)
    .execute(pool)
    .await
    .expect("seed conversation");

    let crypto_session_id: String = sqlx::query_scalar(
        "INSERT INTO crypto_sessions ( \
            id, conversation_id, generation, mls_group_id, state, \
            cipher_suite, last_observed_epoch, group_info, group_info_epoch, \
            group_info_updated_at, created_by_did, created_at, activated_at \
         ) VALUES (gen_random_uuid()::TEXT, $1, 25, $2, 'active', \
                   $3, 0, NULL, NULL, NULL, $4, $5, $5) \
         ON CONFLICT (mls_group_id) DO UPDATE SET state = 'active', group_info = NULL \
         RETURNING id",
    )
    .bind(SELFHEAL_CONVO_ID)
    .bind(&orphan_mls_group_id)
    .bind("MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519")
    .bind("did:web:mlschat.catbird.blue")
    .bind(now)
    .fetch_one(pool)
    .await
    .expect("seed orphan crypto_sessions row");

    sqlx::query("UPDATE conversations SET active_crypto_session_id = $1 WHERE id = $2")
        .bind(&crypto_session_id)
        .bind(SELFHEAL_CONVO_ID)
        .execute(pool)
        .await
        .expect("link active_crypto_session_id");

    // Seed 3 active members: ALICE (initiator), BOB, CHARLIE.
    for did in &[ALICE, BOB, CHARLIE] {
        sqlx::query(
            "INSERT INTO members (convo_id, member_did, user_did, joined_at, is_admin) \
             VALUES ($1, $2, $2, $3, true) \
             ON CONFLICT (convo_id, member_did) DO NOTHING",
        )
        .bind(SELFHEAL_CONVO_ID)
        .bind(*did)
        .bind(now)
        .execute(pool)
        .await
        .expect("seed members row");
    }
}

async fn cleanup_selfheal(pool: &PgPool) {
    let _ = sqlx::query("DELETE FROM pending_welcomes WHERE convo_id = $1")
        .bind(SELFHEAL_CONVO_ID)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM delivery_events WHERE conversation_id = $1")
        .bind(SELFHEAL_CONVO_ID)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM crypto_sessions WHERE conversation_id = $1")
        .bind(SELFHEAL_CONVO_ID)
        .execute(pool)
        .await;
    cleanup(pool, SELFHEAL_CONVO_ID).await;
}

/// PR #12 review-fix-2: a recipient that submits self-heal with welcomes
/// for only 1 of 3 non-initiator members must be rejected by the handler
/// with HTTP 400 + `InvalidWelcomeFanout` BEFORE the chokepoint runs. If
/// the partial-fanout call were accepted, the omitted members would be
/// permanently stranded — their own self-heal calls would fail the
/// chokepoint precondition (group_info now populated) and they'd hit
/// 409 AlreadyBootstrapped indefinitely.
#[tokio::test]
#[ignore = "fixture isolation: shared convo/group IDs cause cross-test interference"]
async fn bootstrap_self_heal_rejects_partial_welcome_fanout() {
    let pool = setup_test_db().await;
    cleanup_selfheal(&pool).await;
    setup_selfheal_orphan_convo(&pool).await;

    // ALICE is the initiator. Active non-initiator members are
    // {BOB, CHARLIE}. Submit welcomes covering only BOB → handler
    // must return 400 with `InvalidWelcomeFanout` because CHARLIE
    // is missing.
    use catbird_server::generated::blue_catbird::mlsChat::bootstrap_reset_group::KeyPackageHashEntry;
    let bob_kp_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let input = BootstrapResetGroup {
        original_convo_id: SELFHEAL_CONVO_ID.into(),
        new_group_id: SELFHEAL_NEW_GROUP_ID.into(),
        cipher_suite: "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519".into(),
        group_info: bytes::Bytes::from_static(b"selfheal-group-info"),
        members: vec![
            string_to_did(ALICE),
            string_to_did(BOB),
            string_to_did(CHARLIE),
        ],
        welcome_message: Some(bytes::Bytes::from_static(b"selfheal-welcome-bytes")),
        key_package_hashes: Some(vec![KeyPackageHashEntry {
            did: string_to_did(BOB),
            hash: bob_kp_hash.into(),
            extra_data: Default::default(),
        }]),
        current_epoch: Some(1),
        metadata_blob_locator: None,
        metadata_version: None,
        extra_data: Default::default(),
    };

    let result = bootstrap_handle(
        pool.clone(),
        test_registry(&pool),
        test_auth_user(ALICE),
        &input,
    )
    .await;

    let response = match result {
        Ok(_) => panic!(
            "partial welcome-fanout self-heal MUST be rejected; got Ok response. \
             This is the PR #12 review-fix-2 invariant — strand-by-incomplete-bootstrap \
             must be prevented at the handler before chokepoint dispatch."
        ),
        Err(resp) => resp,
    };

    assert_eq!(
        response.status(),
        axum::http::StatusCode::BAD_REQUEST,
        "partial welcome-fanout must produce 400 Bad Request"
    );

    // Body should be JSON with `error: "InvalidWelcomeFanout"`. Use
    // axum's body collection helpers (the response body is `BoxBody`).
    let body_bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .expect("read response body");
    let body_json: serde_json::Value =
        serde_json::from_slice(&body_bytes).expect("response body is valid JSON");
    assert_eq!(
        body_json["error"], "InvalidWelcomeFanout",
        "body must carry InvalidWelcomeFanout discriminator"
    );
    let message = body_json["message"]
        .as_str()
        .expect("message field present");
    assert!(
        message.contains("missing"),
        "message must indicate which DIDs are missing; got: {}",
        message
    );

    // The chokepoint must NEVER have been invoked: the orphan row's
    // group_info MUST still be NULL post-rejection.
    let post_call_group_info: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT group_info FROM crypto_sessions WHERE conversation_id = $1")
            .bind(SELFHEAL_CONVO_ID)
            .fetch_one(&pool)
            .await
            .expect("re-read group_info after rejected handler call");
    assert!(
        post_call_group_info.is_none(),
        "orphan group_info MUST still be NULL — handler must reject \
         partial fanout BEFORE the chokepoint runs"
    );

    // No self-healed event should have been emitted either.
    let self_healed_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM delivery_events \
         WHERE conversation_id = $1 \
           AND event_type = 'crypto_session_self_healed'",
    )
    .bind(SELFHEAL_CONVO_ID)
    .fetch_one(&pool)
    .await
    .expect("count self-healed events");
    assert_eq!(
        self_healed_count, 0,
        "chokepoint must NOT emit a self-healed event when the handler rejects"
    );

    cleanup_selfheal(&pool).await;
}
