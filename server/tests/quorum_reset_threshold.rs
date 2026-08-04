//! Integration tests for the Phase 2 ADR-008 D1 client-report quorum path
//! in `ConversationActor::handle_record_reset_vote`.
//!
//! Each test:
//!   1. Spawns a `ConversationActor` with a custom `QuorumConfig` injected via
//!      `ConvoActorArgs::quorum_config` (so we don't race on process-global
//!      env vars across parallel test runs).
//!   2. Seeds a `conversations` row, member rows, and an
//!      `epoch_authenticators` row matching the auth used by `cast_vote`.
//!   3. Drives `RecordResetVote` messages with explicit `failure_mode` values
//!      to exercise the Mode A vs Mode B exclusion.
//!   4. Asserts on the actor's outcome AND the resulting raw SQL state of
//!      `conversations` (`group_id` rotated, `last_reset_by`, `reset_count`).
//!
//! Mirrors the test patterns in `tests/commit_group_change_health_counters.rs`
//! and `src/actors/tests/conversation_tests.rs`. These tests are `#[ignore]`'d
//! by default — they require a live Postgres with the catbird schema applied,
//! including migration `20260418_001` (reset_votes/auto_reset_history) and
//! `20260426_002` (commit-health columns). Run with:
//!   TEST_DATABASE_URL=postgres://… \
//!   SERVICE_DID=did:web:mls.test \
//!     cargo test -p catbird-server --test quorum_reset_threshold -- --ignored
//!
//! Plan: docs/superpowers/plans/2026-04-26-mls-auto-reset-phase2.md (Task 4)

mod common;

use catbird_server::actors::{ConversationActor, ConvoActorArgs, ConvoMessage};
use catbird_server::config::QuorumConfig;
use catbird_server::realtime::SseState;
use ractor::{Actor, ActorRef};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::oneshot;

const AUTH: &str = "deadbeef00cafe";

fn expected_service_did() -> String {
    std::env::var("SERVICE_DID")
        .expect("SERVICE_DID must be set for quorum_reset_threshold ignored tests")
}

async fn wipe(pool: &PgPool, convo_id: &str) {
    for table in &[
        "envelopes",
        "messages",
        "welcome_messages",
        "pending_device_additions",
        "reset_votes",
        "epoch_authenticators",
        "auto_reset_history",
        "members",
    ] {
        let _ = sqlx::query(&format!("DELETE FROM {} WHERE convo_id = $1", table))
            .bind(convo_id)
            .execute(pool)
            .await;
    }
    let _ = sqlx::query("DELETE FROM conversations WHERE id = $1")
        .bind(convo_id)
        .execute(pool)
        .await;
}

async fn seed_convo(
    pool: &PgPool,
    convo_id: &str,
    initial_group_id: &str,
    current_epoch: i32,
    members: &[(&str, &str)],
) {
    let now = chrono::Utc::now();
    sqlx::query(
        "INSERT INTO conversations \
            (id, creator_did, current_epoch, created_at, updated_at, cipher_suite, \
             is_remote, group_id) \
         VALUES ($1, 'did:plc:creator', $2, $3, $3, $4, false, $5) \
         ON CONFLICT (id) DO UPDATE SET \
             current_epoch = EXCLUDED.current_epoch, \
             group_id = EXCLUDED.group_id, \
             reset_count = 0, last_reset_at = NULL, last_reset_by = NULL",
    )
    .bind(convo_id)
    .bind(current_epoch)
    .bind(now)
    .bind("MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519")
    .bind(initial_group_id)
    .execute(pool)
    .await
    .expect("seed convo");

    sqlx::query(
        "INSERT INTO epoch_authenticators (convo_id, epoch, authenticator, recorded_at) \
         VALUES ($1, $2, $3, NOW()) ON CONFLICT DO NOTHING",
    )
    .bind(convo_id)
    .bind(current_epoch)
    .bind(AUTH)
    .execute(pool)
    .await
    .expect("seed authenticator");

    for (user_did, member_did) in members {
        sqlx::query(
            "INSERT INTO members (convo_id, member_did, user_did, joined_at) \
             VALUES ($1, $2, $3, NOW()) \
             ON CONFLICT (convo_id, member_did) DO UPDATE \
                 SET user_did = EXCLUDED.user_did, left_at = NULL",
        )
        .bind(convo_id)
        .bind(*member_did)
        .bind(*user_did)
        .execute(pool)
        .await
        .expect("seed member");
    }
}

async fn spawn_actor(
    pool: &PgPool,
    convo_id: &str,
    quorum_config: QuorumConfig,
) -> ActorRef<ConvoMessage> {
    let args = ConvoActorArgs {
        sse_state: Arc::new(SseState::new(1000)),
        notification_service: None,
        convo_id: convo_id.to_string(),
        db_pool: pool.clone(),
        quorum_config,
    };
    let (actor, _h) = Actor::spawn(None, ConversationActor, args)
        .await
        .expect("spawn ConversationActor");
    actor
}

async fn cast_vote(
    actor: &ActorRef<ConvoMessage>,
    device_did: &str,
    identity_did: &str,
    failure_mode: Option<&str>,
) -> catbird_server::actors::RecordResetVoteOutcome {
    let (tx, rx) = oneshot::channel();
    actor
        .cast(ConvoMessage::RecordResetVote {
            device_did: device_did.to_string(),
            identity_did: identity_did.to_string(),
            epoch_authenticator: AUTH.to_string(),
            failure_type: "external_commit_exhausted".to_string(),
            failure_mode: failure_mode.map(|s| s.to_string()),
            reply: tx,
        })
        .expect("cast RecordResetVote");
    rx.await.expect("rx vote").expect("vote outcome ok")
}

#[derive(sqlx::FromRow, Debug)]
struct ConvoState {
    group_id: Option<String>,
    last_reset_by: Option<String>,
    reset_count: Option<i32>,
}

async fn fetch_state(pool: &PgPool, convo_id: &str) -> ConvoState {
    sqlx::query_as::<_, ConvoState>(
        "SELECT group_id, last_reset_by, reset_count FROM conversations WHERE id = $1",
    )
    .bind(convo_id)
    .fetch_one(pool)
    .await
    .expect("fetch convo state")
}

// =========================================================================
// Test 1: 5-member group, two Mode B votes trigger reset under enforce=true
// =========================================================================
#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL) with A7 + Phase 2 schema"]
async fn two_mode_b_reports_on_5_member_group_trigger_reset_when_enforce_flag_true() {
    let (pool, _database) = common::setup_test_db().await;
    let convo_id = "test-quorum-5mem-2b";
    let initial_group_id = "initial0001000010000100001000010000";
    wipe(&pool, convo_id).await;
    seed_convo(
        &pool,
        convo_id,
        initial_group_id,
        5,
        &[
            ("did:plc:alice", "did:plc:alice#d1"),
            ("did:plc:bob", "did:plc:bob#d1"),
            ("did:plc:carol", "did:plc:carol#d1"),
            ("did:plc:dave", "did:plc:dave#d1"),
            ("did:plc:eve", "did:plc:eve#d1"),
        ],
    )
    .await;

    // pct=0.4, min=2 ⇒ ceil(5*0.4)=2; max(2,2)=2 → quorum threshold 2.
    let cfg = QuorumConfig {
        group_pct: 0.4,
        group_min: 2,
        dm: 1,
        window_secs: 600,
        enforce_failure_mode: true,
    };
    let actor = spawn_actor(&pool, convo_id, cfg).await;

    let o1 = cast_vote(
        &actor,
        "did:plc:alice#d1",
        "did:plc:alice",
        Some("group_state_unrecoverable"),
    )
    .await;
    assert!(o1.recorded, "Mode B vote should record");
    assert!(!o1.auto_reset_triggered, "1 vote < threshold 2");

    let o2 = cast_vote(
        &actor,
        "did:plc:bob#d1",
        "did:plc:bob",
        Some("group_state_unrecoverable"),
    )
    .await;
    assert!(o2.recorded);
    assert!(o2.auto_reset_triggered, "2 Mode B votes hit threshold");
    assert!(o2.new_group_id.is_some(), "rotated group_id returned");
    assert_ne!(o2.new_group_id.as_deref(), Some(initial_group_id));

    let state = fetch_state(&pool, convo_id).await;
    assert_eq!(
        state.group_id.as_deref(),
        o2.new_group_id.as_deref(),
        "group_id rotated in DB"
    );
    assert_ne!(state.group_id.as_deref(), Some(initial_group_id));
    let service_did = expected_service_did();
    assert_eq!(
        state.last_reset_by.as_deref(),
        Some(service_did.as_str()),
        "Phase 2 marker"
    );
    assert_eq!(state.reset_count, Some(1));

    actor.stop(None);
    wipe(&pool, convo_id).await;
}

// =========================================================================
// Test 2: Mixed Mode A + Mode B does NOT trigger when only 1 Mode B vote
// =========================================================================
#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL) with A7 + Phase 2 schema"]
async fn mixed_mode_a_and_b_does_not_trigger_when_only_one_b() {
    let (pool, _database) = common::setup_test_db().await;
    let convo_id = "test-quorum-5mem-mix";
    let initial_group_id = "initial0002000020000200002000020000";
    wipe(&pool, convo_id).await;
    seed_convo(
        &pool,
        convo_id,
        initial_group_id,
        5,
        &[
            ("did:plc:alice", "did:plc:alice#d1"),
            ("did:plc:bob", "did:plc:bob#d1"),
            ("did:plc:carol", "did:plc:carol#d1"),
            ("did:plc:dave", "did:plc:dave#d1"),
            ("did:plc:eve", "did:plc:eve#d1"),
        ],
    )
    .await;

    let cfg = QuorumConfig {
        group_pct: 0.4,
        group_min: 2,
        dm: 1,
        window_secs: 600,
        enforce_failure_mode: true,
    };
    let actor = spawn_actor(&pool, convo_id, cfg).await;

    // Member 0: Mode A (local_state_loss) — must NOT count under enforce=true.
    let oa = cast_vote(
        &actor,
        "did:plc:alice#d1",
        "did:plc:alice",
        Some("local_state_loss"),
    )
    .await;
    assert!(oa.recorded);
    assert!(!oa.auto_reset_triggered);

    // Member 1: Mode B — counts as 1, threshold is 2, no reset.
    let ob = cast_vote(
        &actor,
        "did:plc:bob#d1",
        "did:plc:bob",
        Some("group_state_unrecoverable"),
    )
    .await;
    assert!(ob.recorded);
    assert!(
        !ob.auto_reset_triggered,
        "only 1 Mode B vote — Mode A excluded under enforce=true"
    );

    let state = fetch_state(&pool, convo_id).await;
    assert_eq!(
        state.group_id.as_deref(),
        Some(initial_group_id),
        "group_id unchanged"
    );
    assert_eq!(state.reset_count, Some(0));
    assert!(state.last_reset_by.is_none());

    actor.stop(None);
    wipe(&pool, convo_id).await;
}

// =========================================================================
// Test 3: 1:1 (DM), single Mode B report fires reset (dm=1)
// =========================================================================
#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL) with A7 + Phase 2 schema"]
async fn single_mode_b_in_dm_triggers_reset() {
    let (pool, _database) = common::setup_test_db().await;
    let convo_id = "test-quorum-dm-1b";
    let initial_group_id = "initial0003000030000300003000030000";
    wipe(&pool, convo_id).await;
    seed_convo(
        &pool,
        convo_id,
        initial_group_id,
        7,
        &[
            ("did:plc:alice", "did:plc:alice#d1"),
            ("did:plc:bob", "did:plc:bob#d1"),
        ],
    )
    .await;

    let cfg = QuorumConfig {
        group_pct: 0.4,
        group_min: 2,
        dm: 1,
        window_secs: 600,
        enforce_failure_mode: true,
    };
    let actor = spawn_actor(&pool, convo_id, cfg).await;

    let o = cast_vote(
        &actor,
        "did:plc:alice#d1",
        "did:plc:alice",
        Some("group_state_unrecoverable"),
    )
    .await;
    assert!(o.recorded);
    assert!(o.auto_reset_triggered, "DM single Mode B vote suffices");
    assert!(o.new_group_id.is_some());
    assert_eq!(o.reset_count, Some(1));

    let state = fetch_state(&pool, convo_id).await;
    assert_ne!(state.group_id.as_deref(), Some(initial_group_id));
    let service_did = expected_service_did();
    assert_eq!(state.last_reset_by.as_deref(), Some(service_did.as_str()));

    actor.stop(None);
    wipe(&pool, convo_id).await;
}

// =========================================================================
// Test 4: enforce_failure_mode = false — both modes count toward quorum
// =========================================================================
#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL) with A7 + Phase 2 schema"]
async fn flag_disabled_counts_both_modes() {
    let (pool, _database) = common::setup_test_db().await;
    let convo_id = "test-quorum-5mem-disabled";
    let initial_group_id = "initial0004000040000400004000040000";
    wipe(&pool, convo_id).await;
    seed_convo(
        &pool,
        convo_id,
        initial_group_id,
        9,
        &[
            ("did:plc:alice", "did:plc:alice#d1"),
            ("did:plc:bob", "did:plc:bob#d1"),
            ("did:plc:carol", "did:plc:carol#d1"),
            ("did:plc:dave", "did:plc:dave#d1"),
            ("did:plc:eve", "did:plc:eve#d1"),
        ],
    )
    .await;

    let cfg = QuorumConfig {
        group_pct: 0.4,
        group_min: 2,
        dm: 1,
        window_secs: 600,
        enforce_failure_mode: false,
    };
    let actor = spawn_actor(&pool, convo_id, cfg).await;

    // Member 0: Mode A — counts when enforce=false.
    let oa = cast_vote(
        &actor,
        "did:plc:alice#d1",
        "did:plc:alice",
        Some("local_state_loss"),
    )
    .await;
    assert!(oa.recorded);
    assert!(!oa.auto_reset_triggered, "1 vote < threshold 2");

    // Member 1: Mode B — total is 2, threshold met.
    let ob = cast_vote(
        &actor,
        "did:plc:bob#d1",
        "did:plc:bob",
        Some("group_state_unrecoverable"),
    )
    .await;
    assert!(ob.recorded);
    assert!(
        ob.auto_reset_triggered,
        "Mode A + Mode B both count under enforce=false"
    );

    let state = fetch_state(&pool, convo_id).await;
    assert_ne!(state.group_id.as_deref(), Some(initial_group_id));
    let service_did = expected_service_did();
    assert_eq!(state.last_reset_by.as_deref(), Some(service_did.as_str()));
    assert_eq!(state.reset_count, Some(1));

    actor.stop(None);
    wipe(&pool, convo_id).await;
}
