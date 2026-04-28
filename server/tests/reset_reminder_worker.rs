//! Phase 2.5 §7 R3 — integration test for the reset-reminder backstop worker.
//!
//! Test plan:
//!   1. Seed a `conversations` row + a `crypto_sessions` row in
//!      `state='reset_requested'` with a synthetic
//!      `crypto_session_reset_requested` `delivery_events` row dated >1h
//!      in the past.
//!   2. Run one tick of `reset_reminder::reminder_tick`.
//!   3. Assert that:
//!        - A NEW `delivery_events` row exists with `event_type =
//!          'crypto_session_reset_requested'` AND
//!          `idempotency_key = 'reset-reminder:{cs_id}:1'`.
//!        - `reset_reminder_state.attempt_count = 1`,
//!          `last_attempt_at IS NOT NULL`, and `next_attempt_at` is
//!          shifted ~6h into the future (the second backoff interval).
//!        - `escalated_at IS NULL` (only one attempt so far).
//!
//! Test mirrors the gating pattern used in
//! `tests/sweep_finds_stale_convos.rs`: `#[ignore =
//! "requires TEST_DATABASE_URL"]` so CI without a live Postgres
//! sees PASS-by-skip. Run with:
//!     TEST_DATABASE_URL=postgres://… \
//!       cargo test -p catbird-server \
//!         --test reset_reminder_worker -- --ignored
//!
//! Plan: `docs/plans (phase-2-5-indirect-funneling.md)` §7 R3.

use catbird_server::db::{init_db, DbConfig};
use catbird_server::jobs::reset_reminder::reminder_tick;
use catbird_server::realtime::SseState;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;

const ALICE: &str = "did:plc:r3alice000000000000000000";

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

/// Wipe rows for the test convo across all tables that reference it.
/// `delivery_events` uses `conversation_id`; everything else under the
/// historical `convo_id` naming.
async fn wipe(pool: &PgPool, convo_id: &str) {
    let _ = sqlx::query("DELETE FROM event_stream WHERE convo_id = $1")
        .bind(convo_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM delivery_events WHERE conversation_id = $1")
        .bind(convo_id)
        .execute(pool)
        .await;
    for table in &[
        "envelopes",
        "messages",
        "welcome_messages",
        "pending_welcomes",
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
    let _ = sqlx::query("UPDATE conversations SET active_crypto_session_id = NULL WHERE id = $1")
        .bind(convo_id)
        .execute(pool)
        .await;
    // reset_reminder_state CASCADEs from crypto_sessions, but be explicit
    // for safety — `crypto_session_id` is the PK there.
    let _ = sqlx::query(
        "DELETE FROM reset_reminder_state WHERE crypto_session_id IN \
         (SELECT id FROM crypto_sessions WHERE conversation_id = $1)",
    )
    .bind(convo_id)
    .execute(pool)
    .await;
    let _ = sqlx::query("DELETE FROM crypto_sessions WHERE conversation_id = $1")
        .bind(convo_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM conversations WHERE id = $1")
        .bind(convo_id)
        .execute(pool)
        .await;
}

/// Seed a conversation + a crypto_session in `state='reset_requested'` +
/// the original `crypto_session_reset_requested` delivery_event with
/// `created_at` in the past.
///
/// Returns the crypto_session_id.
async fn seed_stuck_session(
    pool: &PgPool,
    convo_id: &str,
    initial_group_id: &str,
    request_age_secs: i64,
) -> String {
    let now = chrono::Utc::now();
    let request_at = now - chrono::Duration::seconds(request_age_secs);

    sqlx::query(
        "INSERT INTO conversations \
            (id, creator_did, current_epoch, created_at, updated_at, cipher_suite, \
             is_remote, group_id, group_info, reset_count) \
         VALUES ($1, $2, 0, $3, $3, $4, false, $5, $6, 0) \
         ON CONFLICT (id) DO UPDATE SET \
             group_id = EXCLUDED.group_id",
    )
    .bind(convo_id)
    .bind(ALICE)
    .bind(now)
    .bind("MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519")
    .bind(initial_group_id)
    .bind(b"placeholder groupinfo".to_vec())
    .execute(pool)
    .await
    .expect("seed convo");

    // Seed the crypto_session directly in `reset_requested` so we don't
    // depend on the chokepoint state-machine to flip it for us.
    let session_id: String = sqlx::query_scalar(
        "INSERT INTO crypto_sessions ( \
            id, conversation_id, generation, mls_group_id, state, \
            cipher_suite, last_observed_epoch, created_by_did, \
            created_at, activated_at \
         ) VALUES (gen_random_uuid()::TEXT, $1, 0, $2, 'reset_requested', $3, 0, $4, $5, $5) \
         RETURNING id",
    )
    .bind(convo_id)
    .bind(initial_group_id)
    .bind("MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519")
    .bind(ALICE)
    .bind(request_at)
    .fetch_one(pool)
    .await
    .expect("seed crypto_session");

    sqlx::query("UPDATE conversations SET active_crypto_session_id = $1 WHERE id = $2")
        .bind(&session_id)
        .bind(convo_id)
        .execute(pool)
        .await
        .expect("link active_crypto_session_id");

    // Insert the original Request event (the "thing the worker is going
    // to re-broadcast"). Use `created_at = request_at` so the bootstrap
    // bootstrap_pending_state will compute `next_attempt_at = request_at +
    // 1h` — which is in the past for our request_age_secs > 3600 setup.
    let payload = serde_json::json!({
        "request_id": uuid::Uuid::new_v4().to_string(),
        "trigger": "quorum_vote",
        "reason": "r3 backstop test seed",
        "expected_new_mls_group_id": null,
        "allowed_responders": [ALICE],
    });
    sqlx::query(
        "INSERT INTO delivery_events ( \
            id, conversation_id, seq, crypto_session_id, event_type, \
            sender_did, mls_group_id, idempotency_key, payload_json, created_at \
         ) VALUES ($1, $2, 0, $3, 'crypto_session_reset_requested', \
                   $4, $5, $6, $7, $8)",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(convo_id)
    .bind(&session_id)
    .bind(ALICE)
    .bind(initial_group_id)
    .bind(format!("seed-original:{convo_id}"))
    .bind(payload)
    .bind(request_at)
    .execute(pool)
    .await
    .expect("seed original Request event");

    session_id
}

// ====================================================================
// Test: Stuck reset_requested for >1h → one tick produces a reminder.
// ====================================================================
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn r3_stuck_session_reminder_after_one_hour() {
    let pool = setup_test_db().await;
    let convo_id = "p2_5-r3-stuck-1h";
    wipe(&pool, convo_id).await;

    let session_id = seed_stuck_session(
        &pool,
        convo_id,
        "r3stuck1h0000000000000000000000",
        // > 1h (3600s) old → bootstrap sets next_attempt_at = original + 1h
        // which is now in the past → the tick should re-emit immediately.
        2 * 60 * 60, // 2h ago
    )
    .await;

    let sse_state = Arc::new(SseState::new(1000));

    // Run one tick.
    reminder_tick(&pool, &sse_state)
        .await
        .expect("reminder_tick succeeds");

    // Assertion 1: a NEW `crypto_session_reset_requested` delivery_event
    // exists with `idempotency_key = reset-reminder:{cs_id}:1`.
    let expected_idemp = format!("reset-reminder:{}:1", session_id);
    let reminder_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM delivery_events \
         WHERE conversation_id = $1 \
           AND event_type = 'crypto_session_reset_requested' \
           AND idempotency_key = $2",
    )
    .bind(convo_id)
    .bind(&expected_idemp)
    .fetch_one(&pool)
    .await
    .expect("count reminder events");
    assert_eq!(
        reminder_count, 1,
        "expected exactly one reminder event with idempotency_key={expected_idemp}; got {reminder_count}"
    );

    // Assertion 2: state row updated.
    let state: (
        i32,
        Option<chrono::DateTime<chrono::Utc>>,
        chrono::DateTime<chrono::Utc>,
        Option<chrono::DateTime<chrono::Utc>>,
    ) = sqlx::query_as(
        "SELECT attempt_count, last_attempt_at, next_attempt_at, escalated_at \
         FROM reset_reminder_state WHERE crypto_session_id = $1",
    )
    .bind(&session_id)
    .fetch_one(&pool)
    .await
    .expect("fetch state row");
    let (attempt_count, last_attempt_at, next_attempt_at, escalated_at) = state;
    assert_eq!(
        attempt_count, 1,
        "expected attempt_count=1 after first reminder; got {attempt_count}"
    );
    assert!(
        last_attempt_at.is_some(),
        "expected last_attempt_at to be set after a successful reminder broadcast"
    );
    assert!(
        escalated_at.is_none(),
        "first attempt must not escalate; got escalated_at={:?}",
        escalated_at
    );
    // next_attempt_at should be ~6h in the future (REMINDER_DELAYS_SECS[1] =
    // 6 * 3600). Allow ±5 minutes of drift to absorb the test runtime.
    let expected_next = chrono::Utc::now() + chrono::Duration::seconds(6 * 60 * 60);
    let drift = (next_attempt_at - expected_next).num_seconds().abs();
    assert!(
        drift < 5 * 60,
        "next_attempt_at expected ~6h ahead; got drift {drift}s ({next_attempt_at} vs expected {expected_next})"
    );

    // Assertion 3: idempotency — running the tick AGAIN should NOT
    // produce a second reminder for this attempt (the state row's
    // next_attempt_at is now ~6h in the future, so the row is no
    // longer "due"). The total reminder count should stay at 1.
    reminder_tick(&pool, &sse_state)
        .await
        .expect("second tick succeeds");
    let reminder_count_after_second_tick: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM delivery_events \
         WHERE conversation_id = $1 \
           AND event_type = 'crypto_session_reset_requested' \
           AND idempotency_key LIKE 'reset-reminder:%'",
    )
    .bind(convo_id)
    .fetch_one(&pool)
    .await
    .expect("count after second tick");
    assert_eq!(
        reminder_count_after_second_tick, 1,
        "second tick must not produce a second reminder; got {reminder_count_after_second_tick}"
    );

    wipe(&pool, convo_id).await;
}
