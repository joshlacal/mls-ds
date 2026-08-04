//! Integration tests for `auto_detect_failed_groups::sweep_once` — the
//! Phase 2 (Stage 4) Path B sweep query and dispatch.
//!
//! Each test:
//!   1. Seeds a `conversations` row to satisfy (or deliberately violate) the
//!      sweep's 7 predicates.
//!   2. Optionally inserts a recent `reset_votes` row to exercise the
//!      Mode A exclusion window.
//!   3. Calls `sweep_once` directly and asserts on the dispatch count + the
//!      resulting convo state.
//!
//! Mirrors `tests/quorum_reset_threshold.rs` (`#[tokio::test] #[ignore]` so
//! Postgres is only required when explicitly requested via
//! `TEST_DATABASE_URL`). Run with:
//!   TEST_DATABASE_URL=postgres://… \
//!   SERVICE_DID=did:web:mls.test \
//!     cargo test -p catbird-server --test sweep_finds_stale_convos -- --ignored
//!
//! Plan: docs/superpowers/plans/2026-04-26-mls-auto-reset-phase2.md (Task 12)

mod common;

use catbird_server::actors::ActorRegistry;
use catbird_server::config::SweepConfig;
use catbird_server::jobs::auto_detect_failed_groups::sweep_once;
use catbird_server::realtime::SseState;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;

fn expected_service_did() -> String {
    std::env::var("SERVICE_DID")
        .expect("SERVICE_DID must be set for sweep_finds_stale_convos ignored tests")
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

/// Insert a `conversations` row that satisfies ALL 7 sweep predicates with
/// healthy margin. Tests then optionally violate ONE predicate to verify
/// the sweep correctly skips.
async fn seed_stale_convo(pool: &PgPool, convo_id: &str, initial_group_id: &str) {
    let now = chrono::Utc::now();
    sqlx::query(
        "INSERT INTO conversations \
            (id, creator_did, current_epoch, group_info_epoch, group_info, \
             created_at, updated_at, cipher_suite, is_remote, group_id) \
         VALUES ($1, 'did:plc:creator', 1500, 100, $2, $3, $3, $4, false, $5) \
         ON CONFLICT (id) DO UPDATE SET \
             current_epoch = EXCLUDED.current_epoch, \
             group_info_epoch = EXCLUDED.group_info_epoch, \
             group_info = EXCLUDED.group_info, \
             group_id = EXCLUDED.group_id, \
             reset_count = 0, last_reset_at = NULL, last_reset_by = NULL, \
             auto_reset_disabled_at = NULL",
    )
    .bind(convo_id)
    .bind(b"old groupinfo bytes".to_vec())
    .bind(now)
    .bind("MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519")
    .bind(initial_group_id)
    .execute(pool)
    .await
    .expect("seed convo row");

    // Set the health-counter columns so all 4 commit-health predicates fire.
    sqlx::query(
        "UPDATE conversations \
         SET last_successful_commit_at = NOW() - INTERVAL '2 hours', \
             recent_commit_409_count = 25, \
             last_commit_409_at = NOW() - INTERVAL '5 minutes', \
             last_reset_at = NOW() - INTERVAL '2 hours', \
             auto_reset_disabled_at = NULL \
         WHERE id = $1",
    )
    .bind(convo_id)
    .execute(pool)
    .await
    .expect("seed health counters");
}

async fn fetch_group_id(pool: &PgPool, convo_id: &str) -> Option<String> {
    sqlx::query_scalar::<_, Option<String>>("SELECT group_id FROM conversations WHERE id = $1")
        .bind(convo_id)
        .fetch_one(pool)
        .await
        .expect("fetch group_id")
}

async fn fetch_last_reset_by(pool: &PgPool, convo_id: &str) -> Option<String> {
    sqlx::query_scalar::<_, Option<String>>("SELECT last_reset_by FROM conversations WHERE id = $1")
        .bind(convo_id)
        .fetch_one(pool)
        .await
        .expect("fetch last_reset_by")
}

fn make_registry(pool: &PgPool) -> Arc<ActorRegistry> {
    Arc::new(ActorRegistry::new(
        pool.clone(),
        Arc::new(SseState::new(1000)),
        None,
    ))
}

// =========================================================================
// Test 1: All 7 conditions met → sweep dispatches and reset lands.
// =========================================================================
#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL) with A7 + Phase 2 schema"]
async fn sweep_picks_up_convo_matching_all_conditions() {
    let (pool, _database) = common::setup_test_db().await;
    let convo_id = "test-sweep-all-conditions";
    let initial_group_id = "sweepall000100001000010000100001000";
    wipe(&pool, convo_id).await;
    seed_stale_convo(&pool, convo_id, initial_group_id).await;

    let registry = make_registry(&pool);
    let cfg = SweepConfig::test_defaults();
    let dispatched = sweep_once(&pool, &registry, &cfg)
        .await
        .expect("sweep_once");
    assert_eq!(dispatched, 1, "exactly one stale convo should fire");

    // Wait for the actor to process the dispatched message.
    tokio::time::sleep(Duration::from_millis(400)).await;

    let post_group_id = fetch_group_id(&pool, convo_id).await;
    let post_last_reset_by = fetch_last_reset_by(&pool, convo_id).await;
    let service_did = expected_service_did();
    assert_eq!(
        post_last_reset_by.as_deref(),
        Some(service_did.as_str()),
        "last_reset_by must carry the configured service DID"
    );
    assert_ne!(
        post_group_id.as_deref(),
        Some(initial_group_id),
        "group_id must rotate after sweep-driven reset"
    );

    wipe(&pool, convo_id).await;
}

// =========================================================================
// Test 2: A recent Mode A reset_vote (within mode_a_exclusion_window_secs)
// must defer to the client-quorum path → sweep skips.
// =========================================================================
#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL) with A7 + Phase 2 schema"]
async fn sweep_skips_convo_with_recent_mode_a_report() {
    let (pool, _database) = common::setup_test_db().await;
    let convo_id = "test-sweep-mode-a-skip";
    let initial_group_id = "sweepmodea0001000010000100001000010";
    wipe(&pool, convo_id).await;
    seed_stale_convo(&pool, convo_id, initial_group_id).await;

    // Insert a Mode A vote 2 minutes ago — well inside the default 5-min
    // exclusion window. The sweep query's NOT EXISTS clause should reject
    // this conversation.
    sqlx::query(
        "INSERT INTO reset_votes \
            (convo_id, device_did, identity_did, epoch_authenticator, \
             failure_type, failure_mode, voted_at, expires_at) \
         VALUES ($1, 'did:plc:test#d1', 'did:plc:test', 'deadbeef', \
                 'external_commit_exhausted', 'local_state_loss', \
                 NOW() - INTERVAL '2 minutes', NOW() + INTERVAL '24 hours')",
    )
    .bind(convo_id)
    .execute(&pool)
    .await
    .expect("insert mode A vote");

    let registry = make_registry(&pool);
    let cfg = SweepConfig::test_defaults();
    let dispatched = sweep_once(&pool, &registry, &cfg)
        .await
        .expect("sweep_once");
    assert_eq!(
        dispatched, 0,
        "sweep must skip when a Mode A report is recent"
    );

    let post_group_id = fetch_group_id(&pool, convo_id).await;
    assert_eq!(
        post_group_id.as_deref(),
        Some(initial_group_id),
        "group_id must NOT rotate"
    );

    wipe(&pool, convo_id).await;
}

// =========================================================================
// Test 3: `last_reset_at` newer than `min_reset_gap_secs` → sweep skips
// (defense against re-resetting too soon).
// =========================================================================
#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL) with A7 + Phase 2 schema"]
async fn sweep_skips_convo_within_reset_cooldown() {
    let (pool, _database) = common::setup_test_db().await;
    let convo_id = "test-sweep-cooldown-skip";
    let initial_group_id = "sweepcd00010000100001000010000100001";
    wipe(&pool, convo_id).await;
    seed_stale_convo(&pool, convo_id, initial_group_id).await;

    // Pre-set last_reset_at to 30 minutes ago — half the default 1 h cooldown.
    sqlx::query(
        "UPDATE conversations SET last_reset_at = NOW() - INTERVAL '30 minutes' WHERE id = $1",
    )
    .bind(convo_id)
    .execute(&pool)
    .await
    .expect("pre-set last_reset_at");

    let registry = make_registry(&pool);
    let cfg = SweepConfig::test_defaults();
    let dispatched = sweep_once(&pool, &registry, &cfg)
        .await
        .expect("sweep_once");
    assert_eq!(
        dispatched, 0,
        "sweep must skip when last_reset_at < min_reset_gap"
    );

    wipe(&pool, convo_id).await;
}

// =========================================================================
// Test 4: A tripped circuit breaker filters the convo out of the sweep
// query (auto_reset_disabled_at IS NOT NULL).
// =========================================================================
#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL) with A7 + Phase 2 schema"]
async fn sweep_skips_convo_with_tripped_circuit_breaker() {
    let (pool, _database) = common::setup_test_db().await;
    let convo_id = "test-sweep-breaker-skip";
    let initial_group_id = "sweepbrk00010000100001000010000100001";
    wipe(&pool, convo_id).await;
    seed_stale_convo(&pool, convo_id, initial_group_id).await;

    sqlx::query("UPDATE conversations SET auto_reset_disabled_at = NOW() WHERE id = $1")
        .bind(convo_id)
        .execute(&pool)
        .await
        .expect("trip breaker");

    let registry = make_registry(&pool);
    let cfg = SweepConfig::test_defaults();
    let dispatched = sweep_once(&pool, &registry, &cfg)
        .await
        .expect("sweep_once");
    assert_eq!(
        dispatched, 0,
        "sweep must skip convos with auto_reset_disabled_at set"
    );

    wipe(&pool, convo_id).await;
}
