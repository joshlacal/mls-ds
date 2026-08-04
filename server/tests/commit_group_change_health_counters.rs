//! Integration tests for the Phase 2 commit-health counter helpers used by
//! `commitGroupChange`.
//!
//! These tests assert on the SQL state-machine behaviour of:
//!   - `db::mark_commit_success_tx` — invoked on every accepted commit
//!     (addMembers, externalCommit, removeMember, commit, updateMetadata).
//!     Sets `last_successful_commit_at = NOW()` and zeroes
//!     `recent_commit_409_count`.
//!   - `db::record_commit_409` — invoked on every CAS-failure or stale
//!     wire-epoch 409 from the same handler. Bumps
//!     `recent_commit_409_count` by 1 and sets `last_commit_409_at = NOW()`.
//!
//! Mirrors the test pattern in `tests/bootstrap_reset_group.rs` and
//! `tests/db_tests.rs`: requires `TEST_DATABASE_URL` pointing at a Postgres
//! with the catbird schema applied (including the
//! `20260426_002_commit_health_columns.sql` migration). The handler itself
//! is exercised via these helpers — we don't spin up an axum router for
//! Stage 1 plumbing tests, matching how `bootstrap_reset_group.rs` asserts
//! handler-adjacent SQL contracts.
//!
//! Plan: docs/superpowers/plans/2026-04-26-mls-auto-reset-phase2.md
//! (Stage 1, Task 2)

mod common;

use catbird_server::db::*;
use chrono::Utc;
use sqlx::PgPool;

const CREATOR: &str = "did:plc:health1111111111111111111";
const CONVO_SUCCESS: &str = "convo-health-success-0001";
const CONVO_409: &str = "convo-health-409-0001";

/// Insert a minimal `conversations` row sufficient for exercising the
/// health-counter helpers. Mirrors the column set used by
/// `bootstrap_reset_group::setup_post_reset_convo`, plus an explicit
/// non-zero `recent_commit_409_count` so the success-path zero-reset is
/// observable.
///
/// `group_id` is derived from `convo_id` so each test's row is unique
/// under `idx_conversations_group_id_unique` (the previous shared
/// constant caused cross-test collisions whenever an earlier test
/// panicked before its end-of-test cleanup ran).
async fn insert_convo_with_409_count(pool: &PgPool, convo_id: &str, initial_409_count: i32) {
    let now = Utc::now();
    let group_id = format!("gid-{convo_id}");
    sqlx::query(
        "INSERT INTO conversations \
            (id, creator_did, current_epoch, created_at, updated_at, cipher_suite, is_remote, \
             group_id, recent_commit_409_count) \
         VALUES ($1, $2, 0, $3, $3, $4, false, $5, $6) \
         ON CONFLICT (id) DO UPDATE SET \
            recent_commit_409_count = EXCLUDED.recent_commit_409_count, \
            last_successful_commit_at = NULL, \
            last_commit_409_at = NULL",
    )
    .bind(convo_id)
    .bind(CREATOR)
    .bind(now)
    .bind("MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519")
    .bind(&group_id)
    .bind(initial_409_count)
    .execute(pool)
    .await
    .expect("setup conversations row");
}

#[derive(sqlx::FromRow, Debug)]
struct HealthRow {
    last_successful_commit_at: Option<chrono::DateTime<chrono::Utc>>,
    recent_commit_409_count: i32,
    last_commit_409_at: Option<chrono::DateTime<chrono::Utc>>,
}

async fn fetch_health(pool: &PgPool, convo_id: &str) -> HealthRow {
    sqlx::query_as::<_, HealthRow>(
        "SELECT last_successful_commit_at, recent_commit_409_count, last_commit_409_at \
         FROM conversations WHERE id = $1",
    )
    .bind(convo_id)
    .fetch_one(pool)
    .await
    .expect("fetch health row")
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 1 — success path zeroes 409 counter and sets timestamp
// ─────────────────────────────────────────────────────────────────────────────

/// On every accepted commit `mark_commit_success_tx` MUST:
///   1. Set `last_successful_commit_at` to ~now.
///   2. Zero `recent_commit_409_count` even if it was previously >0
///      (i.e. a stretch of failed commits has just ended).
///
/// Why this matters: the Stage-4 sweep job uses `recent_commit_409_count`
/// as a proxy for "currently failing". If we don't zero on success, a
/// recovered conversation would still look operationally dead.
// Fixture isolation fixed (N14): `group_id` is now derived per-convo in
// `insert_convo_with_409_count`, so tests no longer collide on
// `idx_conversations_group_id_unique`.
#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn successful_commit_sets_last_successful_commit_at_and_zeroes_409_count() {
    let (pool, _database) = common::setup_test_db().await;
    common::cleanup(&pool, CONVO_SUCCESS).await;
    insert_convo_with_409_count(&pool, CONVO_SUCCESS, 5).await;

    // Sanity: the row is in the "currently failing" state we set up.
    let pre = fetch_health(&pool, CONVO_SUCCESS).await;
    assert_eq!(
        pre.recent_commit_409_count, 5,
        "precondition: counter pre-set to 5"
    );
    assert!(
        pre.last_successful_commit_at.is_none(),
        "precondition: no prior success"
    );

    // Capture a "before" wall-clock to check the timestamp is fresh.
    let before = chrono::Utc::now();

    // Exercise: simulate the success branch of commit_group_change by running
    // mark_commit_success_tx inside a transaction, then committing. This is
    // exactly how the handler invokes it (bundled into the epoch-CAS tx).
    let mut tx = pool.begin().await.expect("begin tx");
    mark_commit_success_tx(&mut tx, CONVO_SUCCESS)
        .await
        .expect("mark commit success");
    tx.commit().await.expect("commit tx");

    let post = fetch_health(&pool, CONVO_SUCCESS).await;
    assert_eq!(
        post.recent_commit_409_count, 0,
        "successful commit must zero recent_commit_409_count (was 5)"
    );
    let success_at = post
        .last_successful_commit_at
        .expect("last_successful_commit_at must be set after mark_commit_success_tx");
    assert!(
        success_at >= before - chrono::Duration::seconds(2),
        "timestamp must be ~now (got {success_at}, before window starts at {before})"
    );
    assert!(
        success_at <= chrono::Utc::now() + chrono::Duration::seconds(2),
        "timestamp must not be in the future"
    );

    common::cleanup(&pool, CONVO_SUCCESS).await;
}

/// Atomicity check: if the wrapping tx rolls back (mirroring a downstream
/// failure inside the handler — e.g. the commit-message INSERT errors after
/// the success UPDATE), the health-counter mutation MUST also roll back.
/// This is the "atomicity matters" requirement from the self-review.
#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn mark_commit_success_rolls_back_when_wrapping_tx_aborts() {
    let (pool, _database) = common::setup_test_db().await;
    let convo_id = "convo-health-success-rollback-0001";
    common::cleanup(&pool, convo_id).await;
    insert_convo_with_409_count(&pool, convo_id, 7).await;

    let mut tx = pool.begin().await.expect("begin tx");
    mark_commit_success_tx(&mut tx, convo_id)
        .await
        .expect("mark commit success");
    // Roll back the wrapping tx — simulating a downstream error inside the
    // handler that aborts the entire epoch-CAS transaction.
    tx.rollback().await.expect("rollback tx");

    let post = fetch_health(&pool, convo_id).await;
    assert_eq!(
        post.recent_commit_409_count, 7,
        "counter must NOT be zeroed when the wrapping tx rolls back"
    );
    assert!(
        post.last_successful_commit_at.is_none(),
        "last_successful_commit_at must NOT be set when the wrapping tx rolls back"
    );

    common::cleanup(&pool, convo_id).await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2 — 409 path increments counter and sets timestamp
// ─────────────────────────────────────────────────────────────────────────────

/// On every CAS-failure / stale-wire-epoch 409 from the handler,
/// `record_commit_409` MUST:
///   1. Bump `recent_commit_409_count` by exactly 1 (0→1, then 1→2).
///   2. Set `last_commit_409_at` to ~now.
///
/// Pool-level UPDATE (NOT inside the failed tx) so the increment commits
/// independently of the rejected commit attempt — see the self-review
/// requirement: "the 409-path UPDATE uses a separate connection from the
/// pool".
#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn epoch_mismatch_409_increments_counter_and_sets_timestamp() {
    let (pool, _database) = common::setup_test_db().await;
    common::cleanup(&pool, CONVO_409).await;
    insert_convo_with_409_count(&pool, CONVO_409, 0).await;

    let pre = fetch_health(&pool, CONVO_409).await;
    assert_eq!(
        pre.recent_commit_409_count, 0,
        "precondition: counter starts at 0"
    );
    assert!(
        pre.last_commit_409_at.is_none(),
        "precondition: no prior 409"
    );

    let before_first = chrono::Utc::now();

    // First 409.
    record_commit_409(&pool, CONVO_409)
        .await
        .expect("record first 409");

    let after_first = fetch_health(&pool, CONVO_409).await;
    assert_eq!(
        after_first.recent_commit_409_count, 1,
        "counter must increment 0 → 1 on first 409"
    );
    let first_at = after_first
        .last_commit_409_at
        .expect("last_commit_409_at must be set after record_commit_409");
    assert!(
        first_at >= before_first - chrono::Duration::seconds(2),
        "timestamp must be ~now (got {first_at}, before window starts at {before_first})"
    );

    // Second 409 — verify monotonic increment (1 → 2).
    record_commit_409(&pool, CONVO_409)
        .await
        .expect("record second 409");

    let after_second = fetch_health(&pool, CONVO_409).await;
    assert_eq!(
        after_second.recent_commit_409_count, 2,
        "counter must increment 1 → 2 on second 409"
    );
    // Timestamp on second call should be at-or-after the first.
    let second_at = after_second
        .last_commit_409_at
        .expect("last_commit_409_at must remain set after second record_commit_409");
    assert!(
        second_at >= first_at,
        "second 409 timestamp ({second_at}) must be ≥ first 409 timestamp ({first_at})"
    );

    common::cleanup(&pool, CONVO_409).await;
}

/// Independence check: a 409 recorded against one conversation MUST NOT
/// touch another conversation's counters. Catches regressions where someone
/// drops the WHERE clause.
#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn record_commit_409_only_touches_target_convo() {
    let (pool, _database) = common::setup_test_db().await;
    let convo_a = "convo-health-409-isolation-a";
    let convo_b = "convo-health-409-isolation-b";
    common::cleanup(&pool, convo_a).await;
    common::cleanup(&pool, convo_b).await;
    insert_convo_with_409_count(&pool, convo_a, 0).await;
    insert_convo_with_409_count(&pool, convo_b, 3).await;

    record_commit_409(&pool, convo_a)
        .await
        .expect("record 409 on convo_a");

    let post_a = fetch_health(&pool, convo_a).await;
    let post_b = fetch_health(&pool, convo_b).await;

    assert_eq!(post_a.recent_commit_409_count, 1, "convo_a should be 0 → 1");
    assert!(
        post_a.last_commit_409_at.is_some(),
        "convo_a timestamp must be set"
    );
    assert_eq!(
        post_b.recent_commit_409_count, 3,
        "convo_b counter MUST be untouched by record_commit_409 on convo_a"
    );
    assert!(
        post_b.last_commit_409_at.is_none(),
        "convo_b timestamp MUST be untouched by record_commit_409 on convo_a"
    );

    common::cleanup(&pool, convo_a).await;
    common::cleanup(&pool, convo_b).await;
}

/// Cross-path interaction: a successful commit AFTER a streak of 409s must
/// reset the counter back to 0. This is the "recovery" signal the Stage-4
/// sweep job depends on.
#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn success_after_409_streak_resets_counter() {
    let (pool, _database) = common::setup_test_db().await;
    let convo_id = "convo-health-success-after-409";
    common::cleanup(&pool, convo_id).await;
    insert_convo_with_409_count(&pool, convo_id, 0).await;

    // Three 409s in a row.
    for _ in 0..3 {
        record_commit_409(&pool, convo_id)
            .await
            .expect("record 409");
    }
    let after_streak = fetch_health(&pool, convo_id).await;
    assert_eq!(
        after_streak.recent_commit_409_count, 3,
        "streak should bring counter to 3"
    );

    // Then a successful commit lands.
    let mut tx = pool.begin().await.expect("begin tx");
    mark_commit_success_tx(&mut tx, convo_id)
        .await
        .expect("mark success");
    tx.commit().await.expect("commit tx");

    let after_recovery = fetch_health(&pool, convo_id).await;
    assert_eq!(
        after_recovery.recent_commit_409_count, 0,
        "successful commit must zero the 409 streak"
    );
    assert!(
        after_recovery.last_successful_commit_at.is_some(),
        "successful commit must set the success timestamp"
    );
    // last_commit_409_at is intentionally NOT cleared on success — it
    // remains as a historical marker so the sweep can distinguish "never
    // seen a 409" from "seen one recently but recovering".
    assert!(
        after_recovery.last_commit_409_at.is_some(),
        "last_commit_409_at MUST be preserved across success (historical marker)"
    );

    common::cleanup(&pool, convo_id).await;
}

// =============================================================================
// Layer 1 Robustness — Section 1.1 KP-publish gate (integration)
// Plan: ~/.claude/plans/rippling-greeting-whale.md §Layer 1
// =============================================================================

/// `count_available_key_packages_for_device` MUST return 0 when the device
/// has no available, non-expired key packages, and `>= 1` once a single
/// matching row exists. This is the query backing the externalCommit
/// pre-flight gate (§1.1).
///
/// Marked `#[ignore]` for the same fixture-isolation reason as the rest of
/// this file — shared `convo_id` / `owner_did` constants risk collision
/// against `idx_conversations_group_id_unique`. Run manually:
///   `cargo test --test commit_group_change_health_counters -- --ignored`
#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn kp_publish_gate_zero_for_unpublished_device() {
    use catbird_server::db::count_available_key_packages_for_device;
    let (pool, _database) = common::setup_test_db().await;
    let user_did = "did:plc:layer1kpgate0001";
    let device_id = "device-layer1-001";
    sqlx::query("DELETE FROM key_packages WHERE owner_did = $1")
        .bind(user_did)
        .execute(&pool)
        .await
        .ok();
    // key_packages.owner_did has a FK to users(did) — seed the owner row.
    sqlx::query(
        "INSERT INTO users (did, created_at, last_seen_at) VALUES ($1, NOW(), NOW()) \
         ON CONFLICT (did) DO NOTHING",
    )
    .bind(user_did)
    .execute(&pool)
    .await
    .expect("seed users row");

    let count_before = count_available_key_packages_for_device(&pool, user_did, device_id)
        .await
        .expect("count query");
    assert_eq!(
        count_before, 0,
        "no KPs published yet — gate must observe count == 0"
    );

    // Insert one available, non-expired key package for this device.
    // Column set mirrors tests/key_package_bulk_claim.rs (the schema column
    // is `key_package`, and `id` is a required text PK with no default).
    let kp_hash = "deadbeefcafe1234";
    sqlx::query(
        "INSERT INTO key_packages
            (id, owner_did, device_id, key_package_hash, key_package, cipher_suite, state, expires_at, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, 'available', NOW() + INTERVAL '7 days', NOW())
         ON CONFLICT DO NOTHING",
    )
    .bind("kp-layer1-gate-0001")
    .bind(user_did)
    .bind(device_id)
    .bind(kp_hash)
    .bind(b"\x00\x01\x02\x03".as_slice())
    .bind("MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519")
    .execute(&pool)
    .await
    .expect("insert KP");

    let count_after = count_available_key_packages_for_device(&pool, user_did, device_id)
        .await
        .expect("count query");
    assert!(
        count_after >= 1,
        "after publishing 1 KP, gate must observe count >= 1 (got {count_after})"
    );

    sqlx::query("DELETE FROM key_packages WHERE owner_did = $1")
        .bind(user_did)
        .execute(&pool)
        .await
        .ok();
}

// =============================================================================
// Layer 1 Robustness — Section 1.3 freeze threshold (pure logic)
// =============================================================================

/// `should_freeze` is the pure-logic decision for the epoch-storm circuit
/// breaker. No DB needed — runs unconditionally.
#[test]
fn should_freeze_within_window_above_threshold() {
    use catbird_server::db::should_freeze;
    let now = Utc::now();
    let window = chrono::Duration::seconds(60);
    let window_start = Some(now - chrono::Duration::seconds(30)); // 30s into a 60s window

    // Threshold = 6, count = 7 (post-increment) → freeze.
    assert!(
        should_freeze(7, window_start, now, 6, window),
        "post-inc count > threshold within active window must freeze"
    );

    // count == threshold → must NOT freeze (strict > comparison).
    assert!(
        !should_freeze(6, window_start, now, 6, window),
        "count == threshold must NOT freeze (strict >)"
    );

    // Window rolled over → never freeze regardless of count.
    let stale_start = Some(now - chrono::Duration::seconds(120));
    assert!(
        !should_freeze(100, stale_start, now, 6, window),
        "stale window must NOT freeze regardless of count"
    );

    // No prior window (None) → never freeze (this is the first advance).
    assert!(
        !should_freeze(100, None, now, 6, window),
        "first-ever advance (window_start is None) must NOT freeze"
    );
}
