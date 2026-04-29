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
    // SERVER F (#68) audit-log discriminator. Distinct from
    // `bootstrap` so audit-log readers can tell apart the standard
    // two-phase activator from the orphan-row first-responder
    // self-heal path.
    assert_eq!(
        ResetTrigger::SelfHealFirstResponder.as_str(),
        "self_heal_first_responder"
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
    // SERVER F (#68): SelfHealFirstResponder never goes through the
    // RequestCryptoSessionReset path — it goes direct via
    // SelfHealOrphanSession to UPDATE the orphan row in place. There
    // is no upstream Request with `expected_new_mls_group_id = None`
    // to bind, so this trigger MUST NOT be in the null-binding
    // allowlist.
    assert!(
        !ResetTrigger::SelfHealFirstResponder.permits_null_binding(),
        "SelfHealFirstResponder must not emit NULL-binding Requests \
         (it bypasses the Request phase entirely)"
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

// =============================================================================
// SERVER F (#68) — self-heal orphan crypto_session row.
//
// Acceptance test for `self_heal_orphan_session_tx`. Seeds a conversation
// with a `state='active', group_info IS NULL` row (the orphan condition
// produced by the legacy do_reset_group indirect-funneling flow when no
// admin follow-up arrives) and asserts:
//
//   (a) The chokepoint UPDATEs the row in place — same `id`, same
//       `generation`, mls_group_id swapped to recipient's, group_info
//       populated.
//   (b) A `crypto_session_self_healed` event is appended to delivery_events
//       referencing the same crypto_session_id (the orphan row's id).
//   (c) Welcomes are bound to the orphan session_id via pending_welcomes.
//   (d) A second concurrent submitter sees the UPDATE-WHERE clause match
//       zero rows and returns `Lost` → handler maps to 409.
//
// Mirrors `chokepoint_request_writes_outbox_rows_same_tx` shape:
// `#[ignore]` so it only runs with `TEST_DATABASE_URL` set.
// =============================================================================

#[cfg(test)]
mod self_heal_db_tests {
    use crate::actors::messages::WelcomeEnvelope;
    use crate::actors::reset_chokepoint::{self_heal_orphan_session_tx, ActivationResult};
    use crate::db::{init_db, DbConfig};
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
            "pending_welcomes",
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

    /// Seed a conversation with an orphan `state='active', group_info IS
    /// NULL` crypto_session row. Returns `(orphan_session_id,
    /// orphan_mls_group_id)` so the test can assert id-preservation
    /// semantics post-self-heal.
    async fn seed_orphan(pool: &PgPool, convo_id: &str) -> (String, String) {
        let now = chrono::Utc::now();
        let cs_id = Uuid::new_v4().to_string();
        // The orphan's mls_group_id is the seed value from
        // do_reset_group; the recipient's bootstrap will replace it.
        let orphan_mls_group_id = format!("mls-orphan-{}", Uuid::new_v4());

        sqlx::query(
            "INSERT INTO conversations \
                (id, creator_did, current_epoch, created_at, updated_at, cipher_suite, \
                 is_remote, group_id, group_info, active_crypto_session_id, reset_count) \
             VALUES ($1, 'did:plc:creator', 0, $2, $2, $3, false, $4, NULL, $5, 25)",
        )
        .bind(convo_id)
        .bind(now)
        .bind("MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519")
        .bind(&orphan_mls_group_id)
        .bind(&cs_id)
        .execute(pool)
        .await
        .expect("seed conversation");

        // The orphan row: state='active' AND group_info IS NULL. This is
        // the production shape from `do_reset_group:2272-2291` (Phase
        // 2.5 Stage 1 indirect-funneling flow).
        sqlx::query(
            "INSERT INTO crypto_sessions \
                (id, conversation_id, generation, mls_group_id, state, \
                 cipher_suite, last_observed_epoch, group_info, group_info_epoch, \
                 group_info_updated_at, created_by_did, \
                 created_at, activated_at) \
             VALUES ($1, $2, 25, $3, 'active', $4, 0, NULL, NULL, NULL, \
                     'did:web:mlschat.catbird.blue', $5, $5)",
        )
        .bind(&cs_id)
        .bind(convo_id)
        .bind(&orphan_mls_group_id)
        .bind("MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519")
        .bind(now)
        .execute(pool)
        .await
        .expect("seed orphan crypto_session");

        // Seed a crypto_session_created event so allocate_seq lands at
        // a stable starting point for the self-heal event.
        sqlx::query(
            "INSERT INTO delivery_events \
                (id, conversation_id, seq, crypto_session_id, event_type, \
                 mls_group_id, mls_epoch, idempotency_key, created_at) \
             VALUES (gen_random_uuid()::TEXT, $1, 0, $2, \
                     'crypto_session_created', $3, 1, $4, $5)",
        )
        .bind(convo_id)
        .bind(&cs_id)
        .bind(&orphan_mls_group_id)
        .bind(format!("seed-orphan:{convo_id}"))
        .bind(now)
        .execute(pool)
        .await
        .expect("seed delivery_event");

        // Active members: 4 members like 4b2cdbaa (recipient + 3 others).
        for did in &[
            "did:plc:recipient",
            "did:plc:alice",
            "did:plc:bob",
            "did:plc:carol",
        ] {
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

        (cs_id, orphan_mls_group_id)
    }

    /// SERVER F (#68) acceptance test: the chokepoint UPDATEs the orphan
    /// row in place, populates group_info, swaps mls_group_id, and
    /// distributes Welcomes via pending_welcomes — all in the same tx.
    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn self_heal_chokepoint_updates_orphan_row_in_place() {
        let pool = setup_test_db().await;
        let convo_id = format!("convo-self-heal-{}", Uuid::new_v4());
        wipe(&pool, &convo_id).await;
        let (orphan_id, orphan_mls_group_id) = seed_orphan(&pool, &convo_id).await;

        // Recipient submits a NEW mls_group_id and group_info bytes plus
        // Welcomes for the other 3 members.
        let new_mls_group_id = format!("mls-recipient-{}", Uuid::new_v4());
        let new_group_info = b"recipient-fresh-group-info-bytes".to_vec();
        let welcomes = vec![
            WelcomeEnvelope {
                recipient_did: "did:plc:alice".to_string(),
                recipient_device_id: None,
                welcome_data: b"welcome-for-alice".to_vec(),
                key_package_hash: None,
            },
            WelcomeEnvelope {
                recipient_did: "did:plc:bob".to_string(),
                recipient_device_id: None,
                welcome_data: b"welcome-for-bob".to_vec(),
                key_package_hash: None,
            },
            WelcomeEnvelope {
                recipient_did: "did:plc:carol".to_string(),
                recipient_device_id: None,
                welcome_data: b"welcome-for-carol".to_vec(),
                key_package_hash: None,
            },
        ];

        let idempotency_key = format!("selfheal:{}-{}", convo_id, new_mls_group_id);

        // Drive the chokepoint directly.
        let outcome = {
            let mut tx = pool.begin().await.expect("begin");
            let result = self_heal_orphan_session_tx(
                &mut tx,
                &convo_id,
                &new_mls_group_id,
                &new_group_info,
                &welcomes,
                "did:plc:recipient",
                &idempotency_key,
                None, // skip in-tx event_stream insert for this test
            )
            .await
            .expect("self-heal chokepoint");
            tx.commit().await.expect("commit");
            result
        };

        // (a) Outcome variant: Won.
        let won = match outcome {
            ActivationResult::Won(o) => o,
            other => panic!("expected Won, got {:?}", other),
        };
        // Generation preserved (no advance).
        assert_eq!(
            won.generation, 25,
            "self-heal must preserve generation, not advance it"
        );

        // (a) Row UPDATEd in place — same id, generation unchanged.
        let row: (String, i32, String, Option<Vec<u8>>, String) = sqlx::query_as(
            "SELECT id, generation, mls_group_id, group_info, state \
             FROM crypto_sessions WHERE conversation_id = $1",
        )
        .bind(&convo_id)
        .fetch_one(&pool)
        .await
        .expect("fetch post-self-heal row");
        let (post_id, post_gen, post_mls_group_id, post_group_info, post_state) = row;
        assert_eq!(
            post_id, orphan_id,
            "id MUST be preserved (same row UPDATEd)"
        );
        assert_eq!(post_gen, 25, "generation MUST be preserved");
        assert_eq!(
            post_mls_group_id, new_mls_group_id,
            "mls_group_id MUST be swapped to recipient's"
        );
        assert_ne!(
            post_mls_group_id, orphan_mls_group_id,
            "orphan mls_group_id MUST be replaced"
        );
        assert!(post_group_info.is_some(), "group_info MUST be populated");
        assert_eq!(post_group_info.unwrap(), new_group_info);
        assert_eq!(post_state, "active", "state MUST remain 'active'");

        // (b) crypto_session_self_healed event written referencing the
        // orphan session id.
        let event_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM delivery_events \
             WHERE conversation_id = $1 \
               AND event_type = 'crypto_session_self_healed' \
               AND crypto_session_id = $2",
        )
        .bind(&convo_id)
        .bind(&orphan_id)
        .fetch_one(&pool)
        .await
        .expect("count self-healed event");
        assert_eq!(
            event_count, 1,
            "exactly one crypto_session_self_healed event must reference the orphan session id"
        );

        // (c) Welcomes distributed via pending_welcomes, bound to the
        // orphan session id.
        let pw_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pending_welcomes \
             WHERE convo_id = $1 AND crypto_session_id = $2",
        )
        .bind(&convo_id)
        .bind(&orphan_id)
        .fetch_one(&pool)
        .await
        .expect("count pending_welcomes");
        assert_eq!(
            pw_count, 3,
            "pending_welcomes rows must be inserted for each non-self member"
        );

        // (d) A second submitter with a different idempotency_key but
        // facing the same convo sees `group_info IS NOT NULL` and the
        // UPDATE WHERE matches zero rows → returns Lost. We use a
        // distinct caller_did so the find_existing_event idempotency
        // path doesn't short-circuit.
        let second_mls_group_id = format!("mls-second-{}", Uuid::new_v4());
        let second_idempotency_key = format!("selfheal:{}-{}", convo_id, second_mls_group_id);
        let second_outcome = {
            let mut tx = pool.begin().await.expect("begin second");
            let result = self_heal_orphan_session_tx(
                &mut tx,
                &convo_id,
                &second_mls_group_id,
                b"second-group-info",
                &[],
                "did:plc:alice", // different caller for distinct idempotency
                &second_idempotency_key,
                None,
            )
            .await
            .expect("second self-heal chokepoint");
            tx.commit().await.expect("commit second");
            result
        };
        match second_outcome {
            ActivationResult::Lost {
                attempted_generation,
                ..
            } => {
                assert_eq!(
                    attempted_generation, 25,
                    "Lost must reference the preserved orphan generation"
                );
            }
            other => panic!(
                "expected second submitter to return Lost (group_info already populated), \
                 got {:?}",
                other
            ),
        }

        // Audit: the loser's candidate_rejected event is persisted.
        let rejected_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM delivery_events \
             WHERE conversation_id = $1 \
               AND event_type = 'crypto_session_candidate_rejected' \
               AND idempotency_key = $2",
        )
        .bind(&convo_id)
        .bind(&second_idempotency_key)
        .fetch_one(&pool)
        .await
        .expect("count rejected");
        assert_eq!(
            rejected_count, 1,
            "second submitter's candidate_rejected event must be persisted for audit"
        );

        // The orphan row's group_info must NOT have been clobbered by
        // the loser path.
        let final_group_info: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT group_info FROM crypto_sessions WHERE id = $1")
                .bind(&orphan_id)
                .fetch_one(&pool)
                .await
                .expect("re-read group_info");
        assert_eq!(
            final_group_info.expect("still populated"),
            new_group_info,
            "orphan row's group_info must remain the FIRST writer's bytes"
        );

        wipe(&pool, &convo_id).await;
    }

    /// Idempotent replay: a retry with the same idempotency_key returns
    /// `CachedReplay` rather than a second UPDATE attempt. This is the
    /// safety net for client-side retries where the recipient's first
    /// call succeeded but the response was lost in transit.
    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn self_heal_chokepoint_idempotent_replay() {
        let pool = setup_test_db().await;
        let convo_id = format!("convo-self-heal-replay-{}", Uuid::new_v4());
        wipe(&pool, &convo_id).await;
        let (orphan_id, _) = seed_orphan(&pool, &convo_id).await;

        let new_mls_group_id = format!("mls-recipient-{}", Uuid::new_v4());
        let new_group_info = b"recipient-fresh-group-info".to_vec();
        let idempotency_key = format!("selfheal:{}-{}", convo_id, new_mls_group_id);

        // First call: Won.
        {
            let mut tx = pool.begin().await.expect("begin");
            let result = self_heal_orphan_session_tx(
                &mut tx,
                &convo_id,
                &new_mls_group_id,
                &new_group_info,
                &[],
                "did:plc:recipient",
                &idempotency_key,
                None,
            )
            .await
            .expect("first self-heal");
            tx.commit().await.expect("commit");
            assert!(matches!(result, ActivationResult::Won(_)));
        }

        // Second call with SAME idempotency_key: CachedReplay — same
        // session, no second UPDATE.
        let replay_outcome = {
            let mut tx = pool.begin().await.expect("begin replay");
            let result = self_heal_orphan_session_tx(
                &mut tx,
                &convo_id,
                &new_mls_group_id,
                &new_group_info,
                &[],
                "did:plc:recipient",
                &idempotency_key,
                None,
            )
            .await
            .expect("replay self-heal");
            tx.commit().await.expect("commit replay");
            result
        };
        match replay_outcome {
            ActivationResult::CachedReplay(o) => {
                assert_eq!(o.session.id, orphan_id, "replay must return same session");
                assert_eq!(o.generation, 25);
            }
            other => panic!("expected CachedReplay, got {:?}", other),
        }

        // Exactly one self-healed event — replay does NOT re-emit.
        let event_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM delivery_events \
             WHERE conversation_id = $1 \
               AND event_type = 'crypto_session_self_healed'",
        )
        .bind(&convo_id)
        .fetch_one(&pool)
        .await
        .expect("count");
        assert_eq!(
            event_count, 1,
            "idempotent replay MUST NOT append a second self-healed event"
        );

        wipe(&pool, &convo_id).await;
    }

    /// Pre-existing pending_welcomes from a failed admin attempt are
    /// DELETEd before the recipient's fresh INSERT. Without this, stale
    /// admin-attempt welcomes (bound to the SAME session_id but with
    /// admin's mls_group_id, which won't decrypt for the recipient's
    /// new MLS group) would leak forward and get redelivered to
    /// confused recipients.
    ///
    /// Also covers the loser-path safety: after the winner commits
    /// fresh pending_welcomes, a sequential second submitter (who
    /// loses the UPDATE-WHERE-zero-rows tie-break) must NOT persist a
    /// DELETE that clobbers the winner's welcomes. This is the PR #12
    /// review-fix-1 invariant: every destructive write in the
    /// chokepoint runs only on the winner's `rows_affected == 1`
    /// branch, so the loser's tx has no DELETE to commit.
    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn self_heal_clears_stale_pending_welcomes() {
        let pool = setup_test_db().await;
        let convo_id = format!("convo-self-heal-stale-pw-{}", Uuid::new_v4());
        wipe(&pool, &convo_id).await;
        let (orphan_id, _) = seed_orphan(&pool, &convo_id).await;

        // Inject a stale pending_welcomes row tied to the orphan
        // session (e.g. from an admin attempt that ran the chokepoint
        // up to step 7 then failed before completing).
        sqlx::query(
            "INSERT INTO pending_welcomes ( \
                id, convo_id, target_did, welcome_message, created_by_did, \
                crypto_session_id, generation, recipient_device_id \
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, NULL)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&convo_id)
        .bind("did:plc:alice")
        .bind(b"stale-admin-attempt-welcome".to_vec())
        .bind("did:plc:admin")
        .bind(&orphan_id)
        .bind(25_i32)
        .execute(&pool)
        .await
        .expect("inject stale pending_welcomes");

        let new_mls_group_id = format!("mls-recipient-{}", Uuid::new_v4());
        let welcomes = vec![WelcomeEnvelope {
            recipient_did: "did:plc:alice".to_string(),
            recipient_device_id: None,
            welcome_data: b"recipient-fresh-welcome".to_vec(),
            key_package_hash: None,
        }];
        let idempotency_key = format!("selfheal:{}-{}", convo_id, new_mls_group_id);

        // ── Phase 1: winner self-heals, displaces stale admin welcome ─
        {
            let mut tx = pool.begin().await.expect("begin");
            let result = self_heal_orphan_session_tx(
                &mut tx,
                &convo_id,
                &new_mls_group_id,
                b"new-group-info",
                &welcomes,
                "did:plc:recipient",
                &idempotency_key,
                None,
            )
            .await
            .expect("self-heal winner");
            tx.commit().await.expect("commit winner");
            assert!(
                matches!(result, ActivationResult::Won(_)),
                "first self-heal must Win"
            );
        }

        // Verify only the recipient's fresh Welcome remains; the stale
        // admin-attempt Welcome is gone.
        let pw_rows: Vec<(String, Vec<u8>)> = sqlx::query_as(
            "SELECT target_did, welcome_message \
             FROM pending_welcomes WHERE crypto_session_id = $1",
        )
        .bind(&orphan_id)
        .fetch_all(&pool)
        .await
        .expect("fetch pending_welcomes");
        assert_eq!(pw_rows.len(), 1, "exactly one Welcome must survive");
        assert_eq!(pw_rows[0].0, "did:plc:alice");
        assert_eq!(
            pw_rows[0].1, b"recipient-fresh-welcome",
            "stale admin Welcome bytes MUST be replaced by the recipient's fresh Welcome"
        );

        // ── Phase 2: PR #12 review-fix-1 — the loser's tx must NOT
        //    persist a DELETE that clobbers the winner's
        //    pending_welcomes.
        //
        // Set up: a second submitter (different caller_did and
        // idempotency_key, distinct from the winner's so the
        // find_existing_event idempotency-replay paths don't short-
        // circuit) calls the chokepoint AFTER the winner committed.
        // The winner's UPDATE has populated `group_info`, so the
        // loser's UPDATE-tie-break (`WHERE state='active' AND
        // group_info IS NULL`) matches zero rows. The chokepoint must
        // return `Lost` after emitting only a `candidate_rejected`
        // audit event — no DELETE, no INSERT, no UPDATE conversations.
        //
        // Critically: even if the loser's caller commits the
        // returned tx (Lost is `Ok(...)`, not Err — caller does NOT
        // auto-rollback), the persisted pending_welcomes from the
        // winner must remain unchanged. With the pre-fix code, the
        // loser's pre-tie-break DELETE would have committed and
        // wiped the winner's row.
        //
        // We use a loser welcome targeting a different DID
        // (did:plc:bob) so we can prove a hypothetical loser-INSERT
        // doesn't land either; the chokepoint should perform NO writes
        // for the loser other than the audit event.
        let loser_mls_group_id = format!("mls-loser-{}", Uuid::new_v4());
        let loser_welcomes = vec![WelcomeEnvelope {
            recipient_did: "did:plc:bob".to_string(),
            recipient_device_id: None,
            welcome_data: b"loser-bob-welcome".to_vec(),
            key_package_hash: None,
        }];
        let loser_idempotency_key = format!("selfheal:{}-{}", convo_id, loser_mls_group_id);

        let loser_outcome = {
            let mut tx = pool.begin().await.expect("begin loser");
            let result = self_heal_orphan_session_tx(
                &mut tx,
                &convo_id,
                &loser_mls_group_id,
                b"loser-group-info",
                &loser_welcomes,
                "did:plc:bob", // distinct caller_did from winner
                &loser_idempotency_key,
                None,
            )
            .await
            .expect("self-heal loser chokepoint must return Ok(Lost), not Err");
            tx.commit().await.expect("commit loser tx");
            result
        };
        match loser_outcome {
            ActivationResult::Lost {
                attempted_generation,
                ..
            } => {
                assert_eq!(
                    attempted_generation, 25,
                    "Lost must reference the preserved orphan generation"
                );
            }
            other => panic!(
                "expected loser to return Lost (group_info already populated), got {:?}",
                other
            ),
        }

        // Re-query pending_welcomes — winner's row MUST still be
        // there; loser must NOT have committed a DELETE.
        let pw_rows_after_loser: Vec<(String, Vec<u8>)> = sqlx::query_as(
            "SELECT target_did, welcome_message \
             FROM pending_welcomes WHERE crypto_session_id = $1 \
             ORDER BY target_did",
        )
        .bind(&orphan_id)
        .fetch_all(&pool)
        .await
        .expect("re-fetch pending_welcomes after loser commit");
        assert_eq!(
            pw_rows_after_loser.len(),
            1,
            "winner's pending_welcomes row MUST survive the loser's committed tx \
             (PR #12 review-fix-1: loser must not persist a DELETE)"
        );
        assert_eq!(pw_rows_after_loser[0].0, "did:plc:alice");
        assert_eq!(
            pw_rows_after_loser[0].1, b"recipient-fresh-welcome",
            "winner's welcome_message bytes MUST be intact (not replaced by loser's INSERT)"
        );

        // The loser also must NOT have written its own welcome
        // (no INSERT in the loser branch).
        let bob_welcome_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pending_welcomes \
             WHERE crypto_session_id = $1 AND target_did = 'did:plc:bob'",
        )
        .bind(&orphan_id)
        .fetch_one(&pool)
        .await
        .expect("count bob welcomes");
        assert_eq!(
            bob_welcome_count, 0,
            "loser branch must not INSERT pending_welcomes (no destructive writes \
             on the rows_affected == 0 path)"
        );

        // The loser's audit event MUST be persisted for diagnostics.
        let loser_audit_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM delivery_events \
             WHERE conversation_id = $1 \
               AND event_type = 'crypto_session_candidate_rejected' \
               AND idempotency_key = $2",
        )
        .bind(&convo_id)
        .bind(&loser_idempotency_key)
        .fetch_one(&pool)
        .await
        .expect("count loser audit");
        assert_eq!(
            loser_audit_count, 1,
            "loser must persist exactly one candidate_rejected audit event"
        );

        // The orphan row's group_info must still be the winner's bytes.
        let final_group_info: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT group_info FROM crypto_sessions WHERE id = $1")
                .bind(&orphan_id)
                .fetch_one(&pool)
                .await
                .expect("re-read group_info after loser");
        assert_eq!(
            final_group_info.expect("still populated"),
            b"new-group-info",
            "winner's group_info bytes MUST remain (loser's UPDATE matched 0 rows)"
        );

        wipe(&pool, &convo_id).await;
    }
}
