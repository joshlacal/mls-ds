//! Type-level smoke tests for the Phase 2 §2.2 two-phase reset surface.
//!
//! Real semantic verification of the `request_crypto_session_reset_tx` and
//! `activate_crypto_session_tx` contracts (idempotency, tie-break,
//! legacy-column sync, pending_welcomes binding) defers to #11 acceptance
//! tests against a real Postgres. These tests pin the type surface so
//! refactors that accidentally change the message shape, the
//! `ResetTrigger` enum, or the `ActivationResult` variants surface as
//! compile errors immediately.
//!
//! See `repository_fake_test.rs` for the trait-level idempotency
//! contracts that the chokepoint relies on.

use crate::actors::messages::{ConvoMessage, ResetRequest, ResetTrigger, WelcomeEnvelope};

#[test]
fn reset_trigger_str_repr_round_trips_all_variants() {
    // The chokepoint persists `trigger` in delivery_events.payload_json
    // via `ResetTrigger::as_str()`. Pinning the repr so a future enum
    // shuffle doesn't silently break audit-log readers.
    assert_eq!(ResetTrigger::Admin.as_str(), "admin");
    assert_eq!(ResetTrigger::QuorumVote.as_str(), "quorum_vote");
    assert_eq!(ResetTrigger::SystemSweep.as_str(), "system_sweep");
    assert_eq!(ResetTrigger::Bootstrap.as_str(), "bootstrap");
    assert_eq!(ResetTrigger::InlineCommit409.as_str(), "inline_commit_409");
    assert_eq!(
        ResetTrigger::InlineGroupInfo404.as_str(),
        "inline_groupinfo_404"
    );
}

#[test]
fn reset_trigger_null_binding_allowlist() {
    // Phase 2.5 §7 R1 Mitigation #1: only indirect callers may emit
    // a RequestCryptoSessionReset with expected_new_mls_group_id =
    // None. Direct callers (Admin, Bootstrap) MUST always supply
    // Some(_).
    assert!(
        !ResetTrigger::Admin.permits_null_binding(),
        "Admin must not emit NULL-binding Requests"
    );
    assert!(
        !ResetTrigger::Bootstrap.permits_null_binding(),
        "Bootstrap must not emit NULL-binding Requests"
    );
    assert!(
        ResetTrigger::QuorumVote.permits_null_binding(),
        "QuorumVote must permit NULL-binding"
    );
    assert!(
        ResetTrigger::SystemSweep.permits_null_binding(),
        "SystemSweep must permit NULL-binding"
    );
    assert!(
        ResetTrigger::InlineCommit409.permits_null_binding(),
        "InlineCommit409 must permit NULL-binding"
    );
    assert!(
        ResetTrigger::InlineGroupInfo404.permits_null_binding(),
        "InlineGroupInfo404 must permit NULL-binding"
    );
}

#[test]
fn reset_request_constructs_with_owned_strings() {
    let r = ResetRequest {
        request_id: "req-1".to_string(),
        conversation_id: "convo-1".to_string(),
        initiator_did: "did:plc:alice".to_string(),
        reason: "manual_admin".to_string(),
    };
    assert_eq!(r.request_id, "req-1");
    assert_eq!(r.conversation_id, "convo-1");
}

#[test]
fn welcome_envelope_recipient_did_is_in_memory_field() {
    // The DB column is `target_did`; this struct uses `recipient_did`.
    // The mapping happens at the SQL boundary in the activate chokepoint.
    // This test pins the field name so a renaming refactor must be
    // accompanied by an audit of the chokepoint INSERT.
    let w = WelcomeEnvelope {
        recipient_did: "did:plc:bob".to_string(),
        recipient_device_id: Some("device-1".to_string()),
        welcome_data: vec![1, 2, 3],
        key_package_hash: Some("hash".to_string()),
    };
    assert_eq!(w.recipient_did, "did:plc:bob");
    assert_eq!(w.recipient_device_id.as_deref(), Some("device-1"));
}

#[tokio::test]
async fn convo_message_request_reset_constructs_with_oneshot() {
    // Pinning the variant shape so renaming a field surfaces here.
    let (tx, _rx) = tokio::sync::oneshot::channel();
    let msg = ConvoMessage::RequestCryptoSessionReset {
        trigger: ResetTrigger::Admin,
        initiator_did: "did:plc:admin".to_string(),
        reason: "spec test".to_string(),
        idempotency_key: "test-key-1".to_string(),
        expected_new_mls_group_id: Some("mls-group-XYZ".to_string()),
        reply: tx,
    };
    // The variant is constructed; pattern-match to verify destructuring.
    match msg {
        ConvoMessage::RequestCryptoSessionReset {
            trigger,
            initiator_did,
            reason,
            idempotency_key,
            expected_new_mls_group_id,
            ..
        } => {
            assert_eq!(trigger, ResetTrigger::Admin);
            assert_eq!(initiator_did, "did:plc:admin");
            assert_eq!(reason, "spec test");
            assert_eq!(idempotency_key, "test-key-1");
            assert_eq!(expected_new_mls_group_id.as_deref(), Some("mls-group-XYZ"));
        }
        _ => panic!("expected RequestCryptoSessionReset"),
    }
}

#[tokio::test]
async fn convo_message_activate_constructs_with_welcomes() {
    let (tx, _rx) = tokio::sync::oneshot::channel();
    let welcomes = vec![WelcomeEnvelope {
        recipient_did: "did:plc:bob".to_string(),
        recipient_device_id: None,
        welcome_data: vec![],
        key_package_hash: None,
    }];
    let msg = ConvoMessage::ActivateCryptoSession {
        reset_request_id: Some("req-1".to_string()),
        trigger: ResetTrigger::Bootstrap,
        new_mls_group_id: "mls-group-X".to_string(),
        new_group_info: Some(vec![0xaa]),
        welcomes,
        initiator_did: "did:plc:bob".to_string(),
        idempotency_key: "act-key-1".to_string(),
        reply: tx,
    };
    match msg {
        ConvoMessage::ActivateCryptoSession {
            reset_request_id,
            trigger,
            new_mls_group_id,
            new_group_info,
            welcomes,
            ..
        } => {
            assert_eq!(reset_request_id.as_deref(), Some("req-1"));
            assert_eq!(trigger, ResetTrigger::Bootstrap);
            assert_eq!(new_mls_group_id, "mls-group-X");
            assert_eq!(new_group_info.as_deref(), Some(&[0xaa][..]));
            assert_eq!(welcomes.len(), 1);
            assert_eq!(welcomes[0].recipient_did, "did:plc:bob");
        }
        _ => panic!("expected ActivateCryptoSession"),
    }
}

// =============================================================================
// Phase 3 — durable outbox writes from the chokepoint.
//
// These DB-backed tests verify that calling
// `request_crypto_session_reset_tx` (the production chokepoint)
// commits `notification_outbox` rows in the SAME tx as the
// `delivery_events` insert. This is the load-bearing assertion behind
// the Phase 3 "SIGKILL after delivery_event commit" acceptance:
// without these rows being written by the chokepoint itself, the
// outbox-only integration test would pass while production silently
// regressed.
//
// `#[ignore]` so they only run when a Postgres is available via
// `TEST_DATABASE_URL`. Run with:
//   TEST_DATABASE_URL=postgres://… \
//     cargo test -p catbird-server --lib actors::tests::reset_chokepoint_test -- --ignored
// =============================================================================

#[cfg(test)]
mod outbox_db_tests {
    use crate::actors::messages::ResetTrigger;
    use crate::db::{init_db, DbConfig};
    // `reset_chokepoint` is a private module of `crate::actors`; the test
    // sits inside `crate::actors::tests`, so reach via `super::super::`.
    use super::super::super::reset_chokepoint::request_crypto_session_reset_tx;
    use sqlx::PgPool;
    use std::time::Duration;
    use uuid::Uuid;

    async fn setup_test_db() -> PgPool {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://catbird:changeme@localhost:5433/catbird".to_string());

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
        let _ = sqlx::query("DELETE FROM members WHERE convo_id = $1")
            .bind(convo_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM conversations WHERE id = $1")
            .bind(convo_id)
            .execute(pool)
            .await;
    }

    /// Seed conversation + active crypto_session + members (3 local).
    async fn seed(pool: &PgPool, convo_id: &str) {
        let now = chrono::Utc::now();
        let cs_id = Uuid::new_v4().to_string();
        let mls_group_id = format!("mls-{}", Uuid::new_v4());

        sqlx::query(
            "INSERT INTO conversations \
                (id, creator_did, current_epoch, created_at, updated_at, cipher_suite, \
                 is_remote, group_id, group_info, active_crypto_session_id) \
             VALUES ($1, 'did:plc:creator', 0, $2, $2, $3, false, $4, $5, $6)",
        )
        .bind(convo_id)
        .bind(now)
        .bind("MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519")
        .bind(&mls_group_id)
        .bind(b"placeholder".to_vec())
        .bind(&cs_id)
        .execute(pool)
        .await
        .expect("seed conversation");

        sqlx::query(
            "INSERT INTO crypto_sessions \
                (id, conversation_id, generation, mls_group_id, state, \
                 cipher_suite, last_observed_epoch, created_by_did, \
                 created_at, activated_at) \
             VALUES ($1, $2, 0, $3, 'active', $4, 0, 'did:plc:creator', $5, $5)",
        )
        .bind(&cs_id)
        .bind(convo_id)
        .bind(&mls_group_id)
        .bind("MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519")
        .bind(now)
        .execute(pool)
        .await
        .expect("seed crypto_session");

        // seed event so allocate_seq lands at seq=1
        sqlx::query(
            "INSERT INTO delivery_events \
                (id, conversation_id, seq, crypto_session_id, event_type, \
                 mls_group_id, mls_epoch, idempotency_key, created_at) \
             VALUES (gen_random_uuid()::TEXT, $1, 0, $2, \
                     'crypto_session_created', $3, 1, $4, $5)",
        )
        .bind(convo_id)
        .bind(&cs_id)
        .bind(&mls_group_id)
        .bind(format!("seed:{convo_id}"))
        .bind(now)
        .execute(pool)
        .await
        .expect("seed delivery_event");

        // 3 local members (ds_did = NULL → no federation rows).
        for did in &["did:plc:alice", "did:plc:bob", "did:plc:carol"] {
            sqlx::query(
                "INSERT INTO members \
                    (convo_id, member_did, user_did, joined_at, is_admin, ds_did) \
                 VALUES ($1, $2, $2, $3, true, NULL)",
            )
            .bind(convo_id)
            .bind(*did)
            .bind(now)
            .execute(pool)
            .await
            .expect("seed member");
        }
    }

    /// Plan §Phase 3 acceptance:
    /// "Chokepoint writes outbox rows in same Postgres tx as
    /// `delivery_event` insert."
    ///
    /// Calls `request_crypto_session_reset_tx` directly, commits, and
    /// SELECTs from `notification_outbox` to verify one `pending` row
    /// per active member exists immediately after commit. Without this
    /// test, deleting `enqueue_outbox_for_event` from the chokepoint
    /// would leave the integration test green while production
    /// silently regressed.
    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL (and migration 20260429000003 applied)"]
    async fn chokepoint_request_writes_outbox_rows_same_tx() {
        let pool = setup_test_db().await;
        let convo_id = format!("convo-chokepoint-outbox-{}", Uuid::new_v4());
        wipe(&pool, &convo_id).await;
        seed(&pool, &convo_id).await;

        // Call the chokepoint directly — this is the production write path.
        {
            let mut tx = pool.begin().await.expect("begin");
            let _ = request_crypto_session_reset_tx(
                &mut tx,
                &convo_id,
                ResetTrigger::QuorumVote,
                "did:plc:alice",
                "test reset for outbox tx coupling",
                &format!("chokepoint-outbox-{}", Uuid::new_v4()),
                None,
                // codex P1 fix: opt out of in-tx event_stream insert
                // for this test — it asserts outbox row counts only.
                None,
            )
            .await
            .expect("chokepoint request");
            tx.commit().await.expect("commit chokepoint tx");
        }

        // 3 local members → 3 pending notification_outbox rows.
        let n_pending: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM notification_outbox \
             WHERE conversation_id = $1 AND status = 'pending'",
        )
        .bind(&convo_id)
        .fetch_one(&pool)
        .await
        .expect("count pending");
        assert_eq!(
            n_pending, 3,
            "chokepoint must write one pending notification_outbox row per active member \
             in the same tx as the delivery_event insert (Phase 3 acceptance)"
        );

        // No federation peers → 0 federation_outbox rows.
        let f_pending: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM federation_outbox \
             WHERE conversation_id = $1",
        )
        .bind(&convo_id)
        .fetch_one(&pool)
        .await
        .expect("count federation");
        assert_eq!(
            f_pending, 0,
            "no remote ds_did members → zero federation_outbox rows"
        );

        // Each notification row must carry the correct delivery_event_id
        // (the chokepoint passed `event_id` from `insert_event`).
        let event_id_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM notification_outbox no \
             JOIN delivery_events de ON de.id = no.delivery_event_id \
             WHERE no.conversation_id = $1 \
               AND de.event_type = 'crypto_session_reset_requested'",
        )
        .bind(&convo_id)
        .fetch_one(&pool)
        .await
        .expect("join check");
        assert_eq!(
            event_id_count, 3,
            "every notification_outbox row must reference the delivery_event \
             via delivery_event_id"
        );

        wipe(&pool, &convo_id).await;
    }
}
