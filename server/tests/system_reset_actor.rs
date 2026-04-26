//! Integration tests for the Phase 2 (Stage 4) `ConvoMessage::TriggerSystemReset`
//! actor variant — the server-sweep counterpart to the client-quorum reset
//! exercised by `quorum_reset_threshold.rs`.
//!
//! Each test:
//!   1. Spawns a `ConversationActor` (default `QuorumConfig` — quorum knobs
//!      do not affect the system-reset path).
//!   2. Seeds a `conversations` row with whatever pre-conditions the test
//!      requires (cooldown engaged or not, etc.).
//!   3. Casts a `TriggerSystemReset` message at the actor.
//!   4. Asserts on the resulting raw SQL state of `conversations`
//!      (`group_id` rotated or unchanged, `last_reset_by`, `current_epoch`,
//!      `group_info`, `reset_count`).
//!
//! Mirrors `tests/quorum_reset_threshold.rs` exactly — `#[tokio::test]`
//! with `#[ignore]` so they only run when a Postgres is available via
//! `TEST_DATABASE_URL`. Run with:
//!   TEST_DATABASE_URL=postgres://… \
//!     cargo test -p catbird-server --test system_reset_actor -- --ignored
//!
//! Plan: docs/superpowers/plans/2026-04-26-mls-auto-reset-phase2.md (Task 11)

use catbird_server::actors::{ConversationActor, ConvoActorArgs, ConvoMessage};
use catbird_server::config::QuorumConfig;
use catbird_server::db::{init_db, DbConfig};
use catbird_server::realtime::SseState;
use ractor::{Actor, ActorRef};
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;

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

async fn seed_convo(pool: &PgPool, convo_id: &str, initial_group_id: &str, current_epoch: i32) {
    let now = chrono::Utc::now();
    sqlx::query(
        "INSERT INTO conversations \
            (id, creator_did, current_epoch, created_at, updated_at, cipher_suite, \
             is_remote, group_id, group_info) \
         VALUES ($1, 'did:plc:creator', $2, $3, $3, $4, false, $5, $6) \
         ON CONFLICT (id) DO UPDATE SET \
             current_epoch = EXCLUDED.current_epoch, \
             group_id = EXCLUDED.group_id, \
             group_info = EXCLUDED.group_info, \
             reset_count = 0, last_reset_at = NULL, last_reset_by = NULL, \
             auto_reset_disabled_at = NULL",
    )
    .bind(convo_id)
    .bind(current_epoch)
    .bind(now)
    .bind("MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519")
    .bind(initial_group_id)
    .bind(b"placeholder groupinfo".to_vec())
    .execute(pool)
    .await
    .expect("seed convo");
}

async fn spawn_actor(pool: &PgPool, convo_id: &str) -> ActorRef<ConvoMessage> {
    let args = ConvoActorArgs {
        sse_state: Arc::new(SseState::new(1000)),
        notification_service: None,
        convo_id: convo_id.to_string(),
        db_pool: pool.clone(),
        quorum_config: QuorumConfig::default(),
    };
    let (actor, _h) = Actor::spawn(None, ConversationActor, args)
        .await
        .expect("spawn ConversationActor");
    actor
}

#[derive(sqlx::FromRow, Debug)]
struct ConvoState {
    group_id: Option<String>,
    last_reset_by: Option<String>,
    current_epoch: i32,
    group_info: Option<Vec<u8>>,
    reset_count: Option<i32>,
}

async fn fetch_state(pool: &PgPool, convo_id: &str) -> ConvoState {
    sqlx::query_as::<_, ConvoState>(
        "SELECT group_id, last_reset_by, current_epoch, group_info, reset_count \
         FROM conversations WHERE id = $1",
    )
    .bind(convo_id)
    .fetch_one(pool)
    .await
    .expect("fetch convo state")
}

// =========================================================================
// Test 1: TriggerSystemReset rotates group_id, sets system marker, clears
// group_info, resets epoch.
// =========================================================================
#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL) with A7 + Phase 2 schema"]
async fn trigger_system_reset_rotates_group_id_and_sets_marker() {
    let pool = setup_test_db().await;
    let convo_id = "test-system-reset-rotate";
    let initial_group_id = "sysreset0001000010000100001000010000";
    wipe(&pool, convo_id).await;
    seed_convo(&pool, convo_id, initial_group_id, 1228).await;

    let actor = spawn_actor(&pool, convo_id).await;

    actor
        .cast(ConvoMessage::TriggerSystemReset {
            reason: "server_sweep".to_string(),
            staleness_epochs: 1228,
            quiet_duration_secs: 4200,
        })
        .expect("cast TriggerSystemReset");

    // Wait briefly for the actor to process the message + commit the
    // reset transaction.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let post = fetch_state(&pool, convo_id).await;
    assert_ne!(
        post.group_id.as_deref(),
        Some(initial_group_id),
        "group_id must rotate"
    );
    assert_eq!(
        post.last_reset_by.as_deref(),
        Some("system:server_sweep"),
        "last_reset_by must carry the system:<reason> marker"
    );
    assert!(
        post.group_info.is_none(),
        "group_info must be cleared (post-reset bootstrap will repopulate it)"
    );
    assert_eq!(post.current_epoch, 0, "current_epoch must reset to 0");
    assert_eq!(post.reset_count, Some(1), "lifetime reset counter bumped");

    actor.stop(None);
    wipe(&pool, convo_id).await;
}

// =========================================================================
// Test 2: TriggerSystemReset respects the 1h cooldown gate even when the
// circuit breaker is clear.
// =========================================================================
#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL) with A7 + Phase 2 schema"]
async fn trigger_system_reset_respects_cooldown() {
    let pool = setup_test_db().await;
    let convo_id = "test-system-reset-cooldown";
    let initial_group_id = "sysreset0002000020000200002000020000";
    wipe(&pool, convo_id).await;
    seed_convo(&pool, convo_id, initial_group_id, 999).await;

    // Pre-set last_reset_at to 5 minutes ago — well inside the 1 h cooldown
    // gate enforced inside `handle_trigger_system_reset`.
    sqlx::query(
        "UPDATE conversations SET last_reset_at = NOW() - INTERVAL '5 minutes' WHERE id = $1",
    )
    .bind(convo_id)
    .execute(&pool)
    .await
    .expect("pre-set last_reset_at");

    let actor = spawn_actor(&pool, convo_id).await;
    actor
        .cast(ConvoMessage::TriggerSystemReset {
            reason: "server_sweep".to_string(),
            staleness_epochs: 1228,
            quiet_duration_secs: 4200,
        })
        .expect("cast TriggerSystemReset");
    tokio::time::sleep(Duration::from_millis(300)).await;

    let post = fetch_state(&pool, convo_id).await;
    assert_eq!(
        post.group_id.as_deref(),
        Some(initial_group_id),
        "cooldown must block sweep-triggered reset within the 1 h window"
    );
    assert!(
        post.last_reset_by.is_none(),
        "no reset means last_reset_by must remain unset"
    );
    assert_eq!(
        post.current_epoch, 999,
        "epoch must remain at the seeded value"
    );

    actor.stop(None);
    wipe(&pool, convo_id).await;
}

// =========================================================================
// Test 3: Circuit breaker (`auto_reset_disabled_at IS NOT NULL`) blocks the
// system-reset path.
// =========================================================================
#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL) with A7 + Phase 2 schema"]
async fn trigger_system_reset_respects_circuit_breaker() {
    let pool = setup_test_db().await;
    let convo_id = "test-system-reset-breaker";
    let initial_group_id = "sysreset0003000030000300003000030000";
    wipe(&pool, convo_id).await;
    seed_convo(&pool, convo_id, initial_group_id, 500).await;

    sqlx::query("UPDATE conversations SET auto_reset_disabled_at = NOW() WHERE id = $1")
        .bind(convo_id)
        .execute(&pool)
        .await
        .expect("pre-set auto_reset_disabled_at");

    let actor = spawn_actor(&pool, convo_id).await;
    actor
        .cast(ConvoMessage::TriggerSystemReset {
            reason: "server_sweep".to_string(),
            staleness_epochs: 1228,
            quiet_duration_secs: 4200,
        })
        .expect("cast TriggerSystemReset");
    tokio::time::sleep(Duration::from_millis(300)).await;

    let post = fetch_state(&pool, convo_id).await;
    assert_eq!(
        post.group_id.as_deref(),
        Some(initial_group_id),
        "tripped circuit breaker must block sweep-triggered reset"
    );
    assert!(post.last_reset_by.is_none());

    actor.stop(None);
    wipe(&pool, convo_id).await;
}
