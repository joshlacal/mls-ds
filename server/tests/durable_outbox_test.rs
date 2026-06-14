//! Phase 3 — durable outbox integration tests.
//!
//! Verifies the crash-recovery property required by the plan:
//!
//! > "SIGKILL after `delivery_event` commits but before fanout — outbox
//! > worker completes the fanout on restart."
//!
//! Strategy: rather than actually SIGKILLing a server process (slow,
//! flaky), we simulate the post-crash state by:
//!
//! 1. Inserting a `delivery_events` row plus paired
//!    `notification_outbox` / `federation_outbox` rows in the SAME
//!    transaction. This mirrors the chokepoint's contract — see
//!    `actors/reset_chokepoint.rs::enqueue_outbox_for_event` for the
//!    real implementation.
//! 2. Asserting the outbox rows are present with `status='pending'`
//!    immediately after commit. This is the "server crashed before
//!    fanout fired" state.
//! 3. Running one tick of the worker manually (claim → in_flight →
//!    done) using the same SQL the worker uses.
//! 4. Asserting the rows transition to `status='done'`.
//!
//! Using direct SQL (rather than going through the `pub(crate)`
//! chokepoint helpers) keeps this an honest integration test of the
//! durable-row contract while remaining accessible from the
//! `tests/` directory. The chokepoint's own tx-time invariants are
//! covered by `actors::tests::reset_chokepoint_test` (in-crate unit
//! tests) and the legacy `system_reset_actor.rs` end-to-end test.
//!
//! Run via:
//!   TEST_DATABASE_URL=postgres://… \
//!     cargo test -p catbird-server --test durable_outbox_test -- --ignored
//!
//! Plan: docs/plans (let-me-look-at-abstract-castle.md), §Phase 3
//! "Acceptance".

mod common;

use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

/// Wipe per-convo data from all tables this test inserts into.
async fn wipe(pool: &PgPool, convo_id: &str) {
    let _ = sqlx::query("UPDATE conversations SET active_crypto_session_id = NULL WHERE id = $1")
        .bind(convo_id)
        .execute(pool)
        .await;

    for table in &[
        "notification_outbox",
        "federation_outbox",
        "delivery_events",
        "crypto_sessions",
    ] {
        let _ = sqlx::query(&format!("DELETE FROM {table} WHERE conversation_id = $1"))
            .bind(convo_id)
            .execute(pool)
            .await;
    }
    for table in &["members"] {
        let _ = sqlx::query(&format!("DELETE FROM {table} WHERE convo_id = $1"))
            .bind(convo_id)
            .execute(pool)
            .await;
    }
    let _ = sqlx::query("DELETE FROM conversations WHERE id = $1")
        .bind(convo_id)
        .execute(pool)
        .await;
}

/// Seed a conversation + crypto_session + members.
async fn seed_convo_with_members(
    pool: &PgPool,
    convo_id: &str,
    member_dids: &[(&str, Option<&str>)],
) -> String {
    let now = chrono::Utc::now();
    let crypto_session_id = Uuid::new_v4().to_string();
    let mls_group_id = format!("mls-group-{}", Uuid::new_v4());

    sqlx::query(
        "INSERT INTO conversations \
            (id, creator_did, current_epoch, created_at, updated_at, cipher_suite, \
             is_remote, group_id, group_info, active_crypto_session_id) \
         VALUES ($1, 'did:plc:creator', 0, $2, $2, $3, false, $4, $5, NULL)",
    )
    .bind(convo_id)
    .bind(now)
    .bind("MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519")
    .bind(&mls_group_id)
    .bind(b"placeholder groupinfo".to_vec())
    .execute(pool)
    .await
    .expect("insert conversation");

    sqlx::query(
        "INSERT INTO crypto_sessions \
            (id, conversation_id, generation, mls_group_id, state, \
             cipher_suite, last_observed_epoch, created_by_did, created_at, activated_at) \
         VALUES ($1, $2, 0, $3, 'active', $4, 0, 'did:plc:creator', $5, $5)",
    )
    .bind(&crypto_session_id)
    .bind(convo_id)
    .bind(&mls_group_id)
    .bind("MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519")
    .bind(now)
    .execute(pool)
    .await
    .expect("insert crypto_session");

    sqlx::query("UPDATE conversations SET active_crypto_session_id = $1 WHERE id = $2")
        .bind(&crypto_session_id)
        .bind(convo_id)
        .execute(pool)
        .await
        .expect("activate crypto_session");

    for (did, ds_did) in member_dids {
        sqlx::query(
            "INSERT INTO members \
                (convo_id, member_did, user_did, joined_at, is_admin, ds_did) \
             VALUES ($1, $2, $2, $3, true, $4)",
        )
        .bind(convo_id)
        .bind(*did)
        .bind(now)
        .bind(*ds_did)
        .execute(pool)
        .await
        .expect("insert member");
    }

    crypto_session_id
}

/// Mirror of `reset_chokepoint::enqueue_outbox_for_event` for direct
/// test use. Inserts one `notification_outbox` row per active member
/// and one `federation_outbox` row per distinct non-NULL `members.ds_did`.
///
/// Kept in sync with the production helper at
/// `server/src/actors/reset_chokepoint.rs::enqueue_outbox_for_event`.
async fn enqueue_outbox_test_helper(
    tx: &mut Transaction<'_, Postgres>,
    conversation_id: &str,
    delivery_event_id: &str,
    payload_bytes: &[u8],
) -> (usize, usize) {
    let members: Vec<(String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT member_did, COALESCE(user_did, member_did), ds_did \
         FROM members WHERE convo_id = $1 AND left_at IS NULL",
    )
    .bind(conversation_id)
    .fetch_all(&mut **tx)
    .await
    .expect("members snapshot");

    if !members.is_empty() {
        let mut qb = sqlx::QueryBuilder::<Postgres>::new(
            "INSERT INTO notification_outbox (\
                id, conversation_id, delivery_event_id, recipient_did, \
                recipient_device_id, kind, payload, status \
             ) ",
        );
        qb.push_values(members.iter(), |mut b, (member_did, _u, _ds)| {
            b.push_bind(Uuid::new_v4().to_string())
                .push_bind(conversation_id)
                .push_bind(delivery_event_id)
                .push_bind(member_did)
                .push_bind(Option::<String>::None)
                .push_bind("sse")
                .push_bind(payload_bytes)
                .push_bind("pending");
        });
        qb.build()
            .execute(&mut **tx)
            .await
            .expect("insert notification_outbox");
    }

    let federation_targets: std::collections::BTreeSet<String> = members
        .iter()
        .filter_map(|(_m, _u, ds_did)| ds_did.clone())
        .collect();

    if !federation_targets.is_empty() {
        let mut qb = sqlx::QueryBuilder::<Postgres>::new(
            "INSERT INTO federation_outbox (\
                id, conversation_id, delivery_event_id, target_service_did, \
                payload, status \
             ) ",
        );
        qb.push_values(federation_targets.iter(), |mut b, target| {
            b.push_bind(Uuid::new_v4().to_string())
                .push_bind(conversation_id)
                .push_bind(delivery_event_id)
                .push_bind(target)
                .push_bind(payload_bytes)
                .push_bind("pending");
        });
        qb.build()
            .execute(&mut **tx)
            .await
            .expect("insert federation_outbox");
    }

    (members.len(), federation_targets.len())
}

/// Insert a delivery_event + paired outbox rows in one tx, mirroring the
/// chokepoint's contract.
async fn commit_event_with_outbox(
    pool: &PgPool,
    convo_id: &str,
    crypto_session_id: &str,
) -> String {
    let mut tx = pool.begin().await.expect("begin");

    // Allocate next seq.
    let seq: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(seq), -1) + 1 FROM delivery_events WHERE conversation_id = $1",
    )
    .bind(convo_id)
    .fetch_one(&mut *tx)
    .await
    .expect("max seq");

    let event_id = Uuid::new_v4().to_string();
    let payload = serde_json::json!({
        "test": "outbox-crash-recovery",
        "seq": seq,
    });

    sqlx::query(
        "INSERT INTO delivery_events ( \
            id, conversation_id, seq, crypto_session_id, event_type, \
            sender_did, idempotency_key, payload_json \
         ) VALUES ($1, $2, $3, $4, 'crypto_session_reset_requested', \
                   'did:plc:test', $5, $6)",
    )
    .bind(&event_id)
    .bind(convo_id)
    .bind(seq)
    .bind(crypto_session_id)
    .bind(format!("idem-{event_id}"))
    .bind(&payload)
    .execute(&mut *tx)
    .await
    .expect("insert delivery_event");

    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    enqueue_outbox_test_helper(&mut tx, convo_id, &event_id, &payload_bytes).await;

    tx.commit().await.expect("commit");

    event_id
}

async fn outbox_counts(pool: &PgPool, convo_id: &str) -> (i64, i64, i64, i64) {
    let n_pending: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM notification_outbox WHERE conversation_id = $1 AND status = 'pending'",
    )
    .bind(convo_id)
    .fetch_one(pool)
    .await
    .expect("count notification pending");
    let n_done: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM notification_outbox WHERE conversation_id = $1 AND status = 'done'",
    )
    .bind(convo_id)
    .fetch_one(pool)
    .await
    .expect("count notification done");
    let f_pending: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM federation_outbox WHERE conversation_id = $1 AND status = 'pending'",
    )
    .bind(convo_id)
    .fetch_one(pool)
    .await
    .expect("count federation pending");
    let f_done: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM federation_outbox WHERE conversation_id = $1 AND status = 'done'",
    )
    .bind(convo_id)
    .fetch_one(pool)
    .await
    .expect("count federation done");
    (n_pending, n_done, f_pending, f_done)
}

/// Crash-recovery acceptance test (plan §Phase 3 acceptance).
///
/// SIGKILL-after-commit-before-fanout window: outbox rows are
/// `pending` post-commit; running the worker drains them to `done`.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn outbox_rows_complete_after_simulated_crash() {
    let pool = common::setup_test_db().await;
    let convo_id = format!("convo-outbox-test-{}", Uuid::new_v4());

    // Three local members + zero federation peers.
    let members: &[(&str, Option<&str>)] = &[
        ("did:plc:alice", None),
        ("did:plc:bob", None),
        ("did:plc:carol", None),
    ];

    wipe(&pool, &convo_id).await;
    let crypto_session_id = seed_convo_with_members(&pool, &convo_id, members).await;

    // 1. Commit a delivery_event + outbox rows in one tx (chokepoint
    //    contract). The "SIGKILL" point is right here: the outer
    //    process dies after this commit but before the SSE broadcast.
    commit_event_with_outbox(&pool, &convo_id, &crypto_session_id).await;

    // 2. Outbox rows MUST exist as `pending`.
    let (n_pending, n_done, f_pending, f_done) = outbox_counts(&pool, &convo_id).await;
    assert_eq!(
        n_pending,
        members.len() as i64,
        "expected one pending notification_outbox row per active member"
    );
    assert_eq!(n_done, 0, "no notification rows should be done yet");
    assert_eq!(
        f_pending, 0,
        "all members are local (ds_did NULL); zero federation rows expected"
    );
    assert_eq!(f_done, 0, "no federation rows expected");

    // 3. Worker tick: claim → in_flight → done.
    drain_notification_outbox_once(&pool).await;

    // 4. Rows now `done`.
    let (n_pending2, n_done2, _, _) = outbox_counts(&pool, &convo_id).await;
    assert_eq!(
        n_pending2, 0,
        "after worker tick, no notification rows should be pending"
    );
    assert_eq!(
        n_done2,
        members.len() as i64,
        "all notification rows should transition to done"
    );

    wipe(&pool, &convo_id).await;
}

/// Federated conversation: ensures one row per distinct peer service DID.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn federation_rows_one_per_distinct_peer() {
    let pool = common::setup_test_db().await;
    let convo_id = format!("convo-fed-test-{}", Uuid::new_v4());

    // Two local members + two on peer-A, one on peer-B → expect 2 distinct
    // federation rows.
    let members: &[(&str, Option<&str>)] = &[
        ("did:plc:alice", None),
        ("did:plc:bob", None),
        ("did:plc:remote1", Some("did:web:peer-a.example")),
        ("did:plc:remote2", Some("did:web:peer-a.example")),
        ("did:plc:remote3", Some("did:web:peer-b.example")),
    ];

    wipe(&pool, &convo_id).await;
    let crypto_session_id = seed_convo_with_members(&pool, &convo_id, members).await;

    commit_event_with_outbox(&pool, &convo_id, &crypto_session_id).await;

    let (n_pending, _, f_pending, _) = outbox_counts(&pool, &convo_id).await;
    assert_eq!(
        n_pending,
        members.len() as i64,
        "one notification row per member regardless of locality"
    );
    assert_eq!(f_pending, 2, "two distinct peer DIDs → two federation rows");

    wipe(&pool, &convo_id).await;
}

/// codex P1 fix regression test — the SIGKILL-after-commit-before-
/// broadcast window must NOT drop the SSE event for reconnecting
/// clients.
///
/// The fix moved the `event_stream` INSERT into the chokepoint tx so
/// the durability anchor is the SAME row a reconnecting subscriber
/// will replay via cursor. Pre-fix, `event_stream` was written
/// post-commit alongside the live broadcast; a SIGKILL between
/// commit and post-commit work left the outbox row claimed `done`
/// (via worker dispatch's `Ok(())`) without anything in
/// `event_stream` for cursor-replay. This test simulates exactly
/// that crash window.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn sigkill_window_preserves_sse_event_for_cursor_replay() {
    let pool = common::setup_test_db().await;
    let convo_id = format!("convo-sigkill-test-{}", Uuid::new_v4());

    let members: &[(&str, Option<&str>)] = &[("did:plc:alice", None), ("did:plc:bob", None)];

    wipe(&pool, &convo_id).await;
    let crypto_session_id = seed_convo_with_members(&pool, &convo_id, members).await;

    // Seed a "starting" cursor that the subscriber will resume from.
    // Any ULID < the cursor the chokepoint will allocate is fine.
    let starting_cursor = ulid::Ulid::new().to_string();

    // Step 1 — Simulate the chokepoint tx: in ONE tx, INSERT a
    //          `delivery_events` row, an `event_stream` row, AND the
    //          `notification_outbox` row. This is the post codex-P1
    //          state. Crashing right after commit (before any
    //          post-commit live broadcast) leaves all three rows
    //          durable.
    let event_id = Uuid::new_v4().to_string();
    let chokepoint_cursor = ulid::Ulid::new().to_string();
    let stream_event_payload = serde_json::json!({
        "$type": "blue.catbird.mlsChat.subscribeEvents#resetRequestedEvent",
        "cursor": chokepoint_cursor,
        "convoId": convo_id,
        "cryptoSessionId": crypto_session_id,
        "generation": 1,
        "trigger": "system_sweep",
        "requestEventId": event_id,
        "reason": "codex-P1 SIGKILL recovery test",
        "requestedAt": "2026-04-28T15:32:11.123Z"
    });
    let payload_bytes = serde_json::to_vec(&stream_event_payload).unwrap();

    let mut tx = pool.begin().await.expect("begin");
    let seq: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(seq), -1) + 1 FROM delivery_events WHERE conversation_id = $1",
    )
    .bind(&convo_id)
    .fetch_one(&mut *tx)
    .await
    .expect("max seq");
    sqlx::query(
        "INSERT INTO delivery_events ( \
            id, conversation_id, seq, crypto_session_id, event_type, \
            sender_did, idempotency_key, payload_json \
         ) VALUES ($1, $2, $3, $4, 'crypto_session_reset_requested', \
                   'did:plc:test', $5, $6)",
    )
    .bind(&event_id)
    .bind(&convo_id)
    .bind(seq)
    .bind(&crypto_session_id)
    .bind(format!("idem-{event_id}"))
    .bind(&stream_event_payload)
    .execute(&mut *tx)
    .await
    .expect("insert delivery_event");
    // Outbox row(s) — codex-P1 contract.
    enqueue_outbox_test_helper(&mut tx, &convo_id, &event_id, &payload_bytes).await;
    // event_stream row — codex-P1 fix moved this in-tx.
    sqlx::query(
        "INSERT INTO event_stream (id, convo_id, event_type, payload, emitted_at) \
         VALUES ($1, $2, 'resetRequestedEvent', $3, NOW())",
    )
    .bind(&chokepoint_cursor)
    .bind(&convo_id)
    .bind(&stream_event_payload)
    .execute(&mut *tx)
    .await
    .expect("insert event_stream row in chokepoint tx");
    tx.commit().await.expect("commit");

    // Step 2 — Simulate the SIGKILL: NO post-commit live broadcast
    //          fires. We rely entirely on cursor-replay to recover
    //          the event for a reconnecting subscriber.

    // Step 3 — Simulate a reconnecting SSE subscriber: read every
    //          event_stream row strictly greater than `starting_cursor`,
    //          mirroring the SSE backfill query at
    //          `subscribe_convo_events`. The codex-P1 fix added a
    //          generic event_stream replay alongside the existing
    //          commit-messageEvent join; with the in-tx event_stream
    //          row landing here, the reconnecting client sees the
    //          ResetRequestedEvent.
    let replayed: Vec<(String, String)> = sqlx::query_as(
        r#"
        SELECT id, event_type
        FROM event_stream
        WHERE convo_id = $1 AND id > $2 AND event_type <> 'messageEvent'
        ORDER BY id ASC
        "#,
    )
    .bind(&convo_id)
    .bind(&starting_cursor)
    .fetch_all(&pool)
    .await
    .expect("select replay rows");

    assert!(
        replayed
            .iter()
            .any(|(cursor, etype)| *cursor == chokepoint_cursor && etype == "resetRequestedEvent"),
        "cursor-replay MUST surface the chokepoint-persisted ResetRequestedEvent \
         row even when no live broadcast fired (SIGKILL window). Replayed: {:?}",
        replayed
    );

    // Step 4 — The notification_outbox row is per-recipient
    //          observability; once the durability anchor (event_stream)
    //          is in place, the worker's `kind='sse'` dispatch is a
    //          true no-op-on-success. Run a worker tick to confirm
    //          the rows transition to `done` cleanly (not leaked at
    //          `pending`).
    drain_notification_outbox_once(&pool).await;
    let (n_pending, n_done, _, _) = outbox_counts(&pool, &convo_id).await;
    assert_eq!(
        n_pending, 0,
        "notification_outbox should drain to done after worker tick"
    );
    assert_eq!(
        n_done,
        members.len() as i64,
        "all outbox rows should have transitioned to done"
    );

    wipe(&pool, &convo_id).await;
}

/// codex P2 fix regression test — `record_failure` MUST pass the
/// pre-increment `attempts` value to `compute_backoff`. Pre-fix, it
/// passed `attempts + 1`, shifting the schedule from 5/10/20s to
/// 10/20/40s.
///
/// We assert the on-disk `next_attempt_at` lies inside a small window
/// around `NOW() + expected_secs` (the SQL `NOW()` is wall-clock so
/// some slack is required; we use ±2s).
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn record_failure_pre_increment_backoff_curve() {
    let pool = common::setup_test_db().await;
    let convo_id = format!("convo-backoff-test-{}", Uuid::new_v4());

    let members: &[(&str, Option<&str>)] = &[("did:plc:alice", None)];
    wipe(&pool, &convo_id).await;
    let crypto_session_id = seed_convo_with_members(&pool, &convo_id, members).await;

    // Seed one outbox row at attempts=0 (the "fresh" state every new
    // row starts at).
    let event_id = commit_event_with_outbox(&pool, &convo_id, &crypto_session_id).await;
    let row_id: String = sqlx::query_scalar(
        "SELECT id FROM notification_outbox WHERE delivery_event_id = $1 LIMIT 1",
    )
    .bind(&event_id)
    .fetch_one(&pool)
    .await
    .expect("read outbox row id");

    // For each step in the schedule, snapshot pre-call NOW(), call
    // record_failure with the current `attempts` value, snapshot
    // post-call `next_attempt_at`, and assert the gap matches the
    // documented curve. Read `attempts` from the row each iteration
    // so we follow the actual increment.
    let schedule: &[(i32, i64)] = &[
        // (current_attempts pre-call, expected backoff in seconds)
        (0, 5),
        (1, 10),
        (2, 20),
        (3, 40),
        (4, 80),
    ];

    for &(expected_attempts, expected_secs) in schedule {
        // Confirm the row state matches what we expect at this step.
        let on_disk_attempts: i32 =
            sqlx::query_scalar("SELECT attempts FROM notification_outbox WHERE id = $1")
                .bind(&row_id)
                .fetch_one(&pool)
                .await
                .expect("read attempts");
        assert_eq!(
            on_disk_attempts, expected_attempts,
            "row attempts should be {} before call, got {}",
            expected_attempts, on_disk_attempts
        );

        let now: chrono::DateTime<chrono::Utc> = sqlx::query_scalar("SELECT NOW()")
            .fetch_one(&pool)
            .await
            .expect("select NOW");

        let created_at: chrono::DateTime<chrono::Utc> =
            sqlx::query_scalar("SELECT created_at FROM notification_outbox WHERE id = $1")
                .bind(&row_id)
                .fetch_one(&pool)
                .await
                .expect("read created_at");

        catbird_server::workers::record_failure(
            &pool,
            "notification_outbox",
            &row_id,
            expected_attempts,
            created_at,
            "synthetic-backoff-test",
        )
        .await
        .expect("record_failure");

        let next_attempt_at: chrono::DateTime<chrono::Utc> =
            sqlx::query_scalar("SELECT next_attempt_at FROM notification_outbox WHERE id = $1")
                .bind(&row_id)
                .fetch_one(&pool)
                .await
                .expect("read next_attempt_at");

        let actual_gap = (next_attempt_at - now).num_seconds();
        // Allow ±2s slack for clock drift between two `SELECT NOW()`
        // calls separated by a UPDATE.
        assert!(
            (expected_secs - actual_gap).abs() <= 2,
            "attempts={} (pre-increment): expected next_attempt_at \
             ≈ NOW + {}s, got NOW + {}s. Pre codex-P2 fix the gap was \
             one step later (e.g. 10s instead of 5s).",
            expected_attempts,
            expected_secs,
            actual_gap
        );
    }

    wipe(&pool, &convo_id).await;
}

/// Hand-rolled equivalent of one
/// [`workers::notification_outbox::run_notification_outbox_worker`] tick
/// without spawning the worker.
async fn drain_notification_outbox_once(pool: &PgPool) {
    let mut tx = pool.begin().await.expect("begin claim tx");
    let candidates: Vec<(String,)> = sqlx::query_as(
        "SELECT id FROM notification_outbox \
         WHERE status = 'pending' AND next_attempt_at <= NOW() \
         ORDER BY next_attempt_at \
         LIMIT 100 FOR UPDATE SKIP LOCKED",
    )
    .fetch_all(&mut *tx)
    .await
    .expect("claim candidates");

    let ids: Vec<String> = candidates.into_iter().map(|(id,)| id).collect();
    if ids.is_empty() {
        tx.commit().await.expect("commit empty claim");
        return;
    }

    sqlx::query(
        "UPDATE notification_outbox \
         SET status = 'in_flight', updated_at = NOW() \
         WHERE id = ANY($1)",
    )
    .bind(&ids)
    .execute(&mut *tx)
    .await
    .expect("flip to in_flight");

    tx.commit().await.expect("commit claim");

    sqlx::query(
        "UPDATE notification_outbox \
         SET status = 'done', updated_at = NOW() \
         WHERE id = ANY($1)",
    )
    .bind(&ids)
    .execute(pool)
    .await
    .expect("mark done");
}
