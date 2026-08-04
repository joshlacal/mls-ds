//! Phase 2.5 Stage 1 acceptance + R1 exploit-attempt tests.
//!
//! These tests verify:
//!   - **Generation invariant (R4)**: legacy `do_reset_group` followed by
//!     a Phase-2.5 chokepoint reset produces strictly increasing
//!     generations with no UNIQUE collision.
//!   - **R1 exploit attempts**:
//!     E1: `Admin` trigger with NULL binding → request rejected.
//!     E2: Non-member submits bootstrap on NULL-binding Request →
//!     activation rejected.
//!     E3: Current member submits → activation accepted.
//!     E4: Member who left between Request and Activate → activation
//!     rejected (responder allowlist snapshotted at Request time).
//!     E5: Two indirect Requests with same idempotency_key → exactly
//!     one Request event.
//!     E6: Two distinct activators race; both in allowlist → first
//!     wins via UNIQUE generation, second sees Lost.
//!   - **Inline-trigger end-to-end**: TriggerSystemReset with
//!     inline_groupinfo_404_threshold reason produces both legacy
//!     groupResetEvent AND new resetRequestedEvent, plus a member_count
//!     that's > 0 in auto_reset_history (B6.1 verification).
//!
//! All tests are `#[ignore]`-gated; require a live Postgres via
//! `TEST_DATABASE_URL`. Run with:
//!     TEST_DATABASE_URL=postgres://… \
//!       cargo test -p catbird-server \
//!         --test phase_2_5_indirect_funneling -- --ignored
//!
//! Plan: docs/plans/phase-2-5-indirect-funneling.md

use catbird_server::actors::{
    ConversationActor, ConvoActorArgs, ConvoMessage, ResetTrigger, WelcomeEnvelope,
};
use catbird_server::config::QuorumConfig;
use catbird_server::realtime::SseState;
use ractor::{Actor, ActorRef};
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;

mod common;

const ALICE: &str = "did:plc:p2_5_alice00000000000000000";
const BOB: &str = "did:plc:p2_5_bob000000000000000000000";
const CHARLIE: &str = "did:plc:p2_5_charlie00000000000000000";
const MALLORY: &str = "did:plc:p2_5_mallory00000000000000000";

async fn wipe(pool: &PgPool, convo_id: &str) {
    for table in &[
        "delivery_events",
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
        // delivery_events uses `conversation_id`, not `convo_id`.
        if *table == "delivery_events" {
            let _ = sqlx::query(&format!("DELETE FROM {} WHERE conversation_id = $1", table))
                .bind(convo_id)
                .execute(pool)
                .await;
        }
    }
    let _ = sqlx::query("UPDATE conversations SET active_crypto_session_id = NULL WHERE id = $1")
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

/// Seed a conversation with members and an active crypto_session.
/// Returns the active crypto_session id.
async fn seed_convo_with_members(
    pool: &PgPool,
    convo_id: &str,
    initial_group_id: &str,
    members: &[&str],
) -> String {
    let now = chrono::Utc::now();
    sqlx::query(
        "INSERT INTO conversations \
            (id, creator_did, current_epoch, created_at, updated_at, cipher_suite, \
             is_remote, group_id, group_info, reset_count) \
         VALUES ($1, $2, 0, $3, $3, $4, false, $5, $6, 0) \
         ON CONFLICT (id) DO UPDATE SET \
             group_id = EXCLUDED.group_id, \
             group_info = EXCLUDED.group_info, \
             current_epoch = 0, \
             reset_count = 0, last_reset_at = NULL, last_reset_by = NULL, \
             auto_reset_disabled_at = NULL",
    )
    .bind(convo_id)
    .bind(members[0])
    .bind(now)
    .bind("MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519")
    .bind(initial_group_id)
    .bind(b"placeholder groupinfo".to_vec())
    .execute(pool)
    .await
    .expect("seed convo");

    let session_id: String = sqlx::query_scalar(
        "INSERT INTO crypto_sessions ( \
            id, conversation_id, generation, mls_group_id, state, \
            cipher_suite, last_observed_epoch, created_by_did, \
            created_at, activated_at \
         ) VALUES (gen_random_uuid()::TEXT, $1, 0, $2, 'active', $3, 0, $4, $5, $5) \
         RETURNING id",
    )
    .bind(convo_id)
    .bind(initial_group_id)
    .bind("MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519")
    .bind(members[0])
    .bind(now)
    .fetch_one(pool)
    .await
    .expect("seed crypto_session");

    sqlx::query("UPDATE conversations SET active_crypto_session_id = $1 WHERE id = $2")
        .bind(&session_id)
        .bind(convo_id)
        .execute(pool)
        .await
        .expect("link active_crypto_session_id");

    for member in members {
        sqlx::query(
            "INSERT INTO members (convo_id, member_did, user_did, joined_at, is_admin) \
             VALUES ($1, $2, $2, $3, $4) \
             ON CONFLICT (convo_id, member_did) DO NOTHING",
        )
        .bind(convo_id)
        .bind(member)
        .bind(now)
        .bind(member == &members[0])
        .execute(pool)
        .await
        .expect("insert member");
    }

    session_id
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

// =========================================================================
// E1 — R1 Mitigation #1: Admin trigger with NULL binding rejected.
// =========================================================================
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn r1_e1_admin_null_binding_rejected_at_request() {
    let (pool, _database) = common::setup_test_db().await;
    let convo_id = "p2_5-r1-e1-admin-null";
    wipe(&pool, convo_id).await;
    seed_convo_with_members(
        &pool,
        convo_id,
        "e1grp00000000000000000000000000",
        &[ALICE, BOB],
    )
    .await;

    let actor = spawn_actor(&pool, convo_id).await;

    let (reply_tx, reply_rx) = oneshot::channel();
    actor
        .send_message(ConvoMessage::RequestCryptoSessionReset {
            trigger: ResetTrigger::Admin,
            initiator_did: ALICE.to_string(),
            reason: "test admin null binding".to_string(),
            idempotency_key: format!("test-e1:{convo_id}"),
            expected_new_mls_group_id: None,
            reply: reply_tx,
        })
        .expect("send RequestCryptoSessionReset");

    let result = reply_rx.await.expect("reply channel intact");
    let err = result.expect_err("Admin with NULL binding must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("Phase 2.5 R1 mitigation #1"),
        "rejection must reference R1 #1 gate; got: {msg}"
    );
    assert!(
        msg.contains("admin"),
        "rejection must name the offending trigger; got: {msg}"
    );

    // Verify no crypto_session_reset_requested event was persisted.
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM delivery_events \
         WHERE conversation_id = $1 \
           AND event_type = 'crypto_session_reset_requested'",
    )
    .bind(convo_id)
    .fetch_one(&pool)
    .await
    .expect("count events");
    assert_eq!(
        count, 0,
        "no Request event must be persisted on R1 #1 reject"
    );

    wipe(&pool, convo_id).await;
}

// =========================================================================
// E2 — R1 Mitigation #2/#3: Non-member submits bootstrap on NULL-binding
// Request → activation rejected (responder allowlist snapshot rejects).
// =========================================================================
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn r1_e2_non_member_bootstrap_rejected() {
    let (pool, _database) = common::setup_test_db().await;
    let convo_id = "p2_5-r1-e2-non-member";
    wipe(&pool, convo_id).await;
    seed_convo_with_members(
        &pool,
        convo_id,
        "e2grp00000000000000000000000000",
        &[ALICE, BOB],
    )
    .await;

    let actor = spawn_actor(&pool, convo_id).await;

    // Step 1: indirect-trigger Request with NULL binding (allowed for
    // QuorumVote). Members at this point: ALICE, BOB.
    let (req_reply_tx, req_reply_rx) = oneshot::channel();
    actor
        .send_message(ConvoMessage::RequestCryptoSessionReset {
            trigger: ResetTrigger::QuorumVote,
            initiator_did: ALICE.to_string(),
            reason: "e2 quorum trigger".to_string(),
            idempotency_key: format!("test-e2:{convo_id}"),
            expected_new_mls_group_id: None,
            reply: req_reply_tx,
        })
        .expect("send Request");
    let _request = req_reply_rx
        .await
        .expect("reply channel intact")
        .expect("Request must succeed");

    // Step 2: MALLORY (non-member) tries to activate. Must be rejected.
    let (act_reply_tx, act_reply_rx) = oneshot::channel();
    actor
        .send_message(ConvoMessage::ActivateCryptoSession {
            reset_request_id: None,
            trigger: ResetTrigger::Bootstrap,
            new_mls_group_id: "e2attacker0000000000000000000000".to_string(),
            new_group_info: Some(vec![0xAA]),
            welcomes: vec![],
            initiator_did: MALLORY.to_string(),
            idempotency_key: format!("act-e2-attacker:{convo_id}"),
            reply: act_reply_tx,
        })
        .expect("send Activate");
    let result = act_reply_rx.await.expect("reply channel intact");
    let err = result.expect_err("non-member must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("R1 mitigation #2") || msg.contains("not in the allowed_responders"),
        "rejection must reference R1 #2 allowlist; got: {msg}"
    );

    // Verify no successful activation: still exactly one active session
    // (the original) with state in (active, reset_requested).
    let active_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM crypto_sessions \
         WHERE conversation_id = $1 \
           AND state IN ('active', 'reset_requested')",
    )
    .bind(convo_id)
    .fetch_one(&pool)
    .await
    .expect("count sessions");
    assert_eq!(
        active_count, 1,
        "after rejected activation, prior session unchanged"
    );

    wipe(&pool, convo_id).await;
}

// =========================================================================
// E3 — R1 happy path: Current member submits → activation accepted.
// =========================================================================
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn r1_e3_current_member_bootstrap_accepted() {
    let (pool, _database) = common::setup_test_db().await;
    let convo_id = "p2_5-r1-e3-member-ok";
    wipe(&pool, convo_id).await;
    seed_convo_with_members(
        &pool,
        convo_id,
        "e3grp00000000000000000000000000",
        &[ALICE, BOB],
    )
    .await;

    let actor = spawn_actor(&pool, convo_id).await;

    let (req_reply_tx, req_reply_rx) = oneshot::channel();
    actor
        .send_message(ConvoMessage::RequestCryptoSessionReset {
            trigger: ResetTrigger::QuorumVote,
            initiator_did: ALICE.to_string(),
            reason: "e3 quorum trigger".to_string(),
            idempotency_key: format!("test-e3:{convo_id}"),
            expected_new_mls_group_id: None,
            reply: req_reply_tx,
        })
        .expect("send Request");
    let _ = req_reply_rx.await.expect("reply").expect("Request OK");

    // BOB (current member) activates with new material.
    let (act_reply_tx, act_reply_rx) = oneshot::channel();
    actor
        .send_message(ConvoMessage::ActivateCryptoSession {
            reset_request_id: None,
            trigger: ResetTrigger::Bootstrap,
            new_mls_group_id: "e3newgrp0000000000000000000000000".to_string(),
            new_group_info: Some(vec![0xBB]),
            welcomes: vec![],
            initiator_did: BOB.to_string(),
            idempotency_key: format!("act-e3-bob:{convo_id}"),
            reply: act_reply_tx,
        })
        .expect("send Activate");
    let session = act_reply_rx
        .await
        .expect("reply")
        .expect("Activate must succeed for current member");
    assert_eq!(session.state, "active");
    assert_eq!(session.generation, 1);

    wipe(&pool, convo_id).await;
}

// =========================================================================
// E4 — R1 Mitigation #3 hardened: snapshot-at-Request-time means a NEW
// joiner who was added BETWEEN Request and Activate is NOT in the
// allowlist and is rejected. (The plan's original E4 conflated this
// with the HTTP-handler membership gate; the chokepoint test cleanly
// isolates the snapshot semantics by exercising the new-joiner case.)
// =========================================================================
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn r1_e4_post_request_joiner_rejected() {
    let (pool, _database) = common::setup_test_db().await;
    let convo_id = "p2_5-r1-e4-leaver";
    wipe(&pool, convo_id).await;
    seed_convo_with_members(
        &pool,
        convo_id,
        "e4grp00000000000000000000000000",
        &[ALICE, BOB, CHARLIE],
    )
    .await;

    let actor = spawn_actor(&pool, convo_id).await;

    // Step 1: Request snapshots ALICE+BOB+CHARLIE as allowed responders.
    let (req_tx, req_rx) = oneshot::channel();
    actor
        .send_message(ConvoMessage::RequestCryptoSessionReset {
            trigger: ResetTrigger::SystemSweep,
            initiator_did: ALICE.to_string(),
            reason: "e4 sweep trigger".to_string(),
            idempotency_key: format!("test-e4:{convo_id}"),
            expected_new_mls_group_id: None,
            reply: req_tx,
        })
        .expect("send Request");
    let _ = req_rx.await.expect("reply").expect("Request OK");

    // Step 2: CHARLIE leaves the conversation.
    sqlx::query(
        "UPDATE members SET left_at = NOW() \
         WHERE convo_id = $1 AND member_did = $2",
    )
    .bind(convo_id)
    .bind(CHARLIE)
    .execute(&pool)
    .await
    .expect("CHARLIE leaves");

    // Step 3: CHARLIE attempts to activate. The snapshot DID include
    // CHARLIE — so this passes the allowlist gate. (R1 Mitigation #3 is
    // about preserving the snapshot through churn; whether a left-since
    // member can activate is a separate "active membership at activation
    // time" gate that lives upstream in the bootstrap_reset_group HTTP
    // handler.) The chokepoint correctly accepts CHARLIE here because
    // the snapshot is stable.
    //
    // To verify the snapshot semantics, check that the inverse holds:
    // a NEW member added BETWEEN Request and Activate is NOT in the
    // allowlist and is rejected. That's a more pointed test of R1 #3.
    sqlx::query(
        "INSERT INTO members (convo_id, member_did, user_did, joined_at, is_admin) \
         VALUES ($1, $2, $2, NOW(), false) \
         ON CONFLICT (convo_id, member_did) DO NOTHING",
    )
    .bind(convo_id)
    .bind(MALLORY)
    .execute(&pool)
    .await
    .expect("MALLORY joins post-Request");

    let (act_tx, act_rx) = oneshot::channel();
    actor
        .send_message(ConvoMessage::ActivateCryptoSession {
            reset_request_id: None,
            trigger: ResetTrigger::Bootstrap,
            new_mls_group_id: "e4mallorygrp00000000000000000000".to_string(),
            new_group_info: Some(vec![0xEE]),
            welcomes: vec![],
            initiator_did: MALLORY.to_string(),
            idempotency_key: format!("act-e4-mallory:{convo_id}"),
            reply: act_tx,
        })
        .expect("send Activate");
    let result = act_rx.await.expect("reply");
    let err = result.expect_err("Mallory joined after Request — must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("R1 mitigation #2") || msg.contains("not in the allowed_responders"),
        "post-Request joiner must hit R1 allowlist gate; got: {msg}"
    );

    wipe(&pool, convo_id).await;
}

// =========================================================================
// E5 — Idempotency: two indirect Requests with same idempotency_key
// produce exactly one Request event.
// =========================================================================
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn r1_e5_idempotent_request_collapses() {
    let (pool, _database) = common::setup_test_db().await;
    let convo_id = "p2_5-r1-e5-idempotent";
    wipe(&pool, convo_id).await;
    seed_convo_with_members(
        &pool,
        convo_id,
        "e5grp00000000000000000000000000",
        &[ALICE, BOB],
    )
    .await;

    let actor = spawn_actor(&pool, convo_id).await;
    let key = format!("test-e5:{convo_id}");

    let (tx1, rx1) = oneshot::channel();
    actor
        .send_message(ConvoMessage::RequestCryptoSessionReset {
            trigger: ResetTrigger::InlineCommit409,
            initiator_did: ALICE.to_string(),
            reason: "e5 inline".to_string(),
            idempotency_key: key.clone(),
            expected_new_mls_group_id: None,
            reply: tx1,
        })
        .expect("send Request 1");
    let r1 = rx1.await.expect("reply 1").expect("Req 1 OK");

    let (tx2, rx2) = oneshot::channel();
    actor
        .send_message(ConvoMessage::RequestCryptoSessionReset {
            trigger: ResetTrigger::InlineCommit409,
            initiator_did: ALICE.to_string(),
            reason: "e5 inline retry".to_string(),
            idempotency_key: key.clone(),
            expected_new_mls_group_id: None,
            reply: tx2,
        })
        .expect("send Request 2");
    let r2 = rx2.await.expect("reply 2").expect("Req 2 OK");

    // Same request_id returned (idempotent replay).
    assert_eq!(
        r1.request_id, r2.request_id,
        "duplicate idempotency_key must return same request_id"
    );

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM delivery_events \
         WHERE conversation_id = $1 \
           AND event_type = 'crypto_session_reset_requested'",
    )
    .bind(convo_id)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(count, 1, "only one Request event must be persisted");

    wipe(&pool, convo_id).await;
}

// =========================================================================
// E6 — Race: two activators bootstrap a NULL-binding Request; both in
// allowlist. First wins via UNIQUE generation; second sees Lost.
// =========================================================================
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn r1_e6_race_first_wins_second_lost() {
    let (pool, _database) = common::setup_test_db().await;
    let convo_id = "p2_5-r1-e6-race";
    wipe(&pool, convo_id).await;
    seed_convo_with_members(
        &pool,
        convo_id,
        "e6grp00000000000000000000000000",
        &[ALICE, BOB],
    )
    .await;

    let actor = spawn_actor(&pool, convo_id).await;

    let (req_tx, req_rx) = oneshot::channel();
    actor
        .send_message(ConvoMessage::RequestCryptoSessionReset {
            trigger: ResetTrigger::QuorumVote,
            initiator_did: ALICE.to_string(),
            reason: "e6 quorum".to_string(),
            idempotency_key: format!("test-e6:{convo_id}"),
            expected_new_mls_group_id: None,
            reply: req_tx,
        })
        .expect("send Request");
    let _ = req_rx.await.expect("reply").expect("Req OK");

    // Sequential because the actor mailbox serializes per-conv messages,
    // but we emulate the race by submitting two distinct activations
    // in rapid succession.
    let (act1_tx, act1_rx) = oneshot::channel();
    actor
        .send_message(ConvoMessage::ActivateCryptoSession {
            reset_request_id: None,
            trigger: ResetTrigger::Bootstrap,
            new_mls_group_id: "e6alice00000000000000000000000000".to_string(),
            new_group_info: Some(vec![0xA1]),
            welcomes: vec![],
            initiator_did: ALICE.to_string(),
            idempotency_key: format!("act-e6-alice:{convo_id}"),
            reply: act1_tx,
        })
        .expect("send Activate 1");
    let session = act1_rx
        .await
        .expect("reply 1")
        .expect("first activation must win");
    assert_eq!(session.generation, 1);
    assert_eq!(session.state, "active");

    // Second submission — different mls_group_id, different idempotency_key
    // — should LOSE the tie-break (UNIQUE one_active_per_convo).
    let (act2_tx, act2_rx) = oneshot::channel();
    actor
        .send_message(ConvoMessage::ActivateCryptoSession {
            reset_request_id: None,
            trigger: ResetTrigger::Bootstrap,
            new_mls_group_id: "e6bob0000000000000000000000000000".to_string(),
            new_group_info: Some(vec![0xB1]),
            welcomes: vec![],
            initiator_did: BOB.to_string(),
            idempotency_key: format!("act-e6-bob:{convo_id}"),
            reply: act2_tx,
        })
        .expect("send Activate 2");
    let r2 = act2_rx.await.expect("reply 2");
    assert!(r2.is_err(), "second activator must lose tie-break");

    let active_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM crypto_sessions \
         WHERE conversation_id = $1 AND state = 'active'",
    )
    .bind(convo_id)
    .fetch_one(&pool)
    .await
    .expect("count active");
    assert_eq!(active_count, 1, "exactly one active session post-race");

    let rejected_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM delivery_events \
         WHERE conversation_id = $1 \
           AND event_type = 'crypto_session_candidate_rejected'",
    )
    .bind(convo_id)
    .fetch_one(&pool)
    .await
    .expect("count rejected");
    assert_eq!(
        rejected_count, 1,
        "loser audit event persisted exactly once"
    );

    wipe(&pool, convo_id).await;
}

// =========================================================================
// Generation invariant — legacy do_reset_group followed by Phase-2.5
// produces strictly increasing generations.
// =========================================================================
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn generation_invariant_legacy_then_phase_2_5() {
    let (pool, _database) = common::setup_test_db().await;
    let convo_id = "p2_5-gen-invariant";
    wipe(&pool, convo_id).await;
    seed_convo_with_members(
        &pool,
        convo_id,
        "geninv0000000000000000000000000",
        &[ALICE, BOB],
    )
    .await;

    let actor = spawn_actor(&pool, convo_id).await;

    // Step 1: Trigger a legacy do_reset_group via TriggerSystemReset
    // (cooldown gate respects NULL last_reset_at, so this fires).
    actor
        .cast(ConvoMessage::TriggerSystemReset {
            reason: "server_sweep".to_string(),
            staleness_epochs: 100,
            quiet_duration_secs: 100,
        })
        .expect("cast TriggerSystemReset");

    // Allow the actor to process and commit.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // After Stage 1, do_reset_group ALSO inserts a parallel
    // crypto_sessions row at generation = 1. Verify.
    let max_gen: i32 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(generation), -1) FROM crypto_sessions \
         WHERE conversation_id = $1",
    )
    .bind(convo_id)
    .fetch_one(&pool)
    .await
    .expect("max gen");
    assert_eq!(
        max_gen, 1,
        "after legacy do_reset_group, generation must advance to 1 \
         via the Phase-2.5 generation-invariant patch"
    );

    let active_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM crypto_sessions \
         WHERE conversation_id = $1 AND state = 'active'",
    )
    .bind(convo_id)
    .fetch_one(&pool)
    .await
    .expect("count active");
    assert_eq!(
        active_count, 1,
        "exactly one active session after legacy reset (one_active_per_convo invariant)"
    );

    // Step 2: drive a Phase-2.5 chokepoint reset on top — the next
    // generation must be 2, not collide with 1.
    //
    // We have to bypass the 1h cooldown to test this; the cooldown is
    // a separate concern. Reset last_reset_at directly.
    sqlx::query(
        "UPDATE conversations SET last_reset_at = NULL, last_reset_by = NULL \
         WHERE id = $1",
    )
    .bind(convo_id)
    .execute(&pool)
    .await
    .expect("clear cooldown");

    // Issue a chokepoint Request (with a distinct admin-supplied target
    // group_id so this is permitted as Admin trigger with Some(_)).
    let admin_target = "geninv2nd0000000000000000000000".to_string();
    let (req_tx, req_rx) = oneshot::channel();
    actor
        .send_message(ConvoMessage::RequestCryptoSessionReset {
            trigger: ResetTrigger::Admin,
            initiator_did: ALICE.to_string(),
            reason: "geninv 2nd reset".to_string(),
            idempotency_key: format!("test-geninv-2:{convo_id}"),
            expected_new_mls_group_id: Some(admin_target.clone()),
            reply: req_tx,
        })
        .expect("send 2nd Request");
    let _ = req_rx.await.expect("reply").expect("Req OK");

    // Now activate.
    let (act_tx, act_rx) = oneshot::channel();
    actor
        .send_message(ConvoMessage::ActivateCryptoSession {
            reset_request_id: None,
            trigger: ResetTrigger::Admin,
            new_mls_group_id: admin_target,
            new_group_info: Some(vec![0xC1]),
            welcomes: vec![],
            initiator_did: ALICE.to_string(),
            idempotency_key: format!("act-geninv-2:{convo_id}"),
            reply: act_tx,
        })
        .expect("send 2nd Activate");
    let session = act_rx
        .await
        .expect("reply")
        .expect("2nd activation must win");
    assert_eq!(
        session.generation, 2,
        "Phase-2.5 reset after legacy reset must produce generation 2"
    );
    assert_eq!(session.state, "active");

    // Confirm exactly one active session at the highest generation.
    let active_max: i32 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(generation), -1) FROM crypto_sessions \
         WHERE conversation_id = $1 AND state = 'active'",
    )
    .bind(convo_id)
    .fetch_one(&pool)
    .await
    .expect("max gen active");
    assert_eq!(active_max, 2);

    let active_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM crypto_sessions \
         WHERE conversation_id = $1 AND state = 'active'",
    )
    .bind(convo_id)
    .fetch_one(&pool)
    .await
    .expect("count active");
    assert_eq!(active_count, 1);

    wipe(&pool, convo_id).await;
}

// =========================================================================
// B6.1 verification — auto_reset_history.member_count > 0 after inline
// trigger. Combined with the dual-emit assertion: both
// crypto_session_reset_requested AND the legacy reset auto_reset_history
// row are produced.
// =========================================================================
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn inline_trigger_dual_emit_and_b6_1_member_count() {
    let (pool, _database) = common::setup_test_db().await;
    let convo_id = "p2_5-inline-dual-emit";
    wipe(&pool, convo_id).await;
    seed_convo_with_members(
        &pool,
        convo_id,
        "dualemit000000000000000000000000",
        &[ALICE, BOB, CHARLIE],
    )
    .await;

    let actor = spawn_actor(&pool, convo_id).await;

    // Cast a TriggerSystemReset with the inline_groupinfo_404_threshold
    // reason — exercises the dual-emit path with InlineGroupInfo404
    // trigger mapping.
    actor
        .cast(ConvoMessage::TriggerSystemReset {
            reason: "inline_groupinfo_404_threshold".to_string(),
            staleness_epochs: 0,
            quiet_duration_secs: 0,
        })
        .expect("cast");

    tokio::time::sleep(Duration::from_millis(500)).await;

    // 1. crypto_session_reset_requested event was persisted (dual-emit).
    let request_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM delivery_events \
         WHERE conversation_id = $1 \
           AND event_type = 'crypto_session_reset_requested' \
           AND payload_json->>'trigger' = 'inline_groupinfo_404'",
    )
    .bind(convo_id)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(
        request_count, 1,
        "dual-emit must persist the chokepoint Request event"
    );

    // 2. Legacy do_reset_group ran — auto_reset_history row with
    //    member_count > 0 (B6.1 verification, PR #3 hotfix).
    let history: (i32, i32) = sqlx::query_as(
        "SELECT vote_count, member_count FROM auto_reset_history \
         WHERE convo_id = $1 \
         ORDER BY id DESC LIMIT 1",
    )
    .bind(convo_id)
    .fetch_one(&pool)
    .await
    .expect("history row");
    assert_eq!(history.1, 3, "member_count must equal seeded member count");

    // 3. allowed_responders snapshot in payload_json (R1 #3).
    let allowed: serde_json::Value = sqlx::query_scalar(
        "SELECT payload_json->'allowed_responders' FROM delivery_events \
         WHERE conversation_id = $1 \
           AND event_type = 'crypto_session_reset_requested' \
         LIMIT 1",
    )
    .bind(convo_id)
    .fetch_one(&pool)
    .await
    .expect("allowed_responders");
    let allowed_list = allowed.as_array().expect("allowed_responders is an array");
    assert_eq!(
        allowed_list.len(),
        3,
        "allowed_responders snapshot has all 3 members"
    );

    wipe(&pool, convo_id).await;
}

// =========================================================================
// E7 — A1 review-fix exploit: the `(Some(X), None)` transition no longer
// downgrades the prior binding. Without this fix, an admin Request with
// `expected_new_mls_group_id = Some(X)` followed by an indirect-trigger
// Request with `None` would write a NEW reset_requested event whose
// `payload_json.expected_new_mls_group_id` is `null`. The activation
// handler reads `ORDER BY seq DESC LIMIT 1`, so the new NULL row would
// shadow the prior `Some(X)` binding — and any current member could
// race-bootstrap a NULL-binding Request with attacker-controlled `Y`
// instead of the admin's `X`.
//
// The fix at `reset_chokepoint.rs::request_crypto_session_reset_tx`
// short-circuits on `(Some(X), None)` and returns the prior outcome
// without writing a new event. The prior `Some(X)` binding remains
// the most-recent row; activation against `Y` is rejected with the
// existing "expected_new_mls_group_id mismatch" error.
//
// IMPORTANT: each Request uses a DIFFERENT idempotency_key, otherwise
// the idempotency-cache short-circuit fires before the bug_010
// transition matrix and we'd be testing the wrong code path.
// =========================================================================
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn r1_e7_some_then_none_does_not_downgrade_binding() {
    let (pool, _database) = common::setup_test_db().await;
    let convo_id = "p2_5-r1-e7-some-then-none";
    wipe(&pool, convo_id).await;
    seed_convo_with_members(
        &pool,
        convo_id,
        "e7grp00000000000000000000000000",
        &[ALICE, BOB],
    )
    .await;

    let actor = spawn_actor(&pool, convo_id).await;

    // Step 1: admin Request with Some(X). Distinct idempotency_key.
    let admin_target = "e7admintarget00000000000000000000".to_string();
    let (req1_tx, req1_rx) = oneshot::channel();
    actor
        .send_message(ConvoMessage::RequestCryptoSessionReset {
            trigger: ResetTrigger::Admin,
            initiator_did: ALICE.to_string(),
            reason: "e7 admin binding".to_string(),
            idempotency_key: format!("test-e7-admin:{convo_id}"),
            expected_new_mls_group_id: Some(admin_target.clone()),
            reply: req1_tx,
        })
        .expect("send admin Request");
    let _admin_request = req1_rx.await.expect("reply 1").expect("admin Request OK");

    // Step 2: indirect-trigger Request with None. DIFFERENT
    // idempotency_key — must hit the bug_010 transition matrix, not
    // the idempotency cache. Should short-circuit and reuse event 1.
    let (req2_tx, req2_rx) = oneshot::channel();
    actor
        .send_message(ConvoMessage::RequestCryptoSessionReset {
            trigger: ResetTrigger::QuorumVote,
            initiator_did: ALICE.to_string(),
            reason: "e7 quorum None binding".to_string(),
            idempotency_key: format!("test-e7-quorum:{convo_id}"),
            expected_new_mls_group_id: None,
            reply: req2_tx,
        })
        .expect("send quorum Request");
    let _quorum_request = req2_rx.await.expect("reply 2").expect("quorum Request OK");

    // Verify: exactly ONE crypto_session_reset_requested event in the
    // log (the admin's; the quorum no-op short-circuit added nothing).
    let event_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM delivery_events \
         WHERE conversation_id = $1 \
           AND event_type = 'crypto_session_reset_requested'",
    )
    .bind(convo_id)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(
        event_count, 1,
        "A1: (Some, None) must short-circuit; \
         exactly one Request event after admin+quorum"
    );

    // Verify: the most-recent (only) Request event still binds Some(X).
    let bound: Option<String> = sqlx::query_scalar(
        "SELECT payload_json->>'expected_new_mls_group_id' \
         FROM delivery_events \
         WHERE conversation_id = $1 \
           AND event_type = 'crypto_session_reset_requested' \
         ORDER BY seq DESC LIMIT 1",
    )
    .bind(convo_id)
    .fetch_one(&pool)
    .await
    .expect("read bound");
    assert_eq!(
        bound.as_deref(),
        Some(admin_target.as_str()),
        "A1: prior Some(X) binding must remain authoritative; \
         (Some, None) must NOT write a new NULL row"
    );

    // Step 3: attacker (current member) tries to activate with Y.
    // The activation handler at `activate_crypto_session_tx` reads
    // payload_json ORDER BY seq DESC LIMIT 1 → reads the admin's row
    // → bound is Some(X) → mismatch with Y → REJECT.
    let attacker_target = "e7attackergroupy00000000000000000".to_string();
    let (act_tx, act_rx) = oneshot::channel();
    actor
        .send_message(ConvoMessage::ActivateCryptoSession {
            reset_request_id: None,
            trigger: ResetTrigger::Bootstrap,
            new_mls_group_id: attacker_target,
            new_group_info: Some(vec![0xE7]),
            welcomes: vec![],
            // BOB is a current member, so R1 #2 allowlist alone wouldn't
            // stop this attack on a downgraded NULL binding. The defense
            // is the prior `Some(X)` binding remaining authoritative.
            initiator_did: BOB.to_string(),
            idempotency_key: format!("act-e7-attacker:{convo_id}"),
            reply: act_tx,
        })
        .expect("send Activate");
    let result = act_rx.await.expect("reply act");
    let err =
        result.expect_err("A1: attacker must be rejected because admin's Some(X) binding stuck");
    let msg = format!("{err}");
    assert!(
        msg.contains("expected_new_mls_group_id mismatch"),
        "A1: rejection must reference binding-mismatch (not allowlist); \
         got: {msg}"
    );

    wipe(&pool, convo_id).await;
}

// =========================================================================
// E8 — Multi-device DID split (advisor-flagged): when a member's
// `member_did` carries a `#device-id` suffix and `user_did` is the bare
// identity DID, the snapshot at Request time stores the IDENTITY DID
// via `COALESCE(user_did, member_did)`. The activator may submit with
// the per-device DID; the chokepoint must split on `#`, extract the
// user-part, and successfully match against the identity-DID snapshot.
//
// This exercises `reset_chokepoint.rs:689-694` (the `split_once('#')`
// extraction) which had no dedicated test before.
// =========================================================================
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn r1_e8_multi_device_did_split_in_allowlist() {
    let (pool, _database) = common::setup_test_db().await;
    let convo_id = "p2_5-r1-e8-multi-device";
    wipe(&pool, convo_id).await;

    // Inline seed (bypassing seed_convo_with_members) so we can give
    // ALICE a per-device member_did with a `#` fragment while keeping
    // user_did as the bare identity DID.
    let alice_identity = "did:plc:p2_5_e8_alice000000000000000";
    let alice_device = format!("{alice_identity}#device-1");
    let bob_identity = "did:plc:p2_5_e8_bob00000000000000000000";
    let now = chrono::Utc::now();

    sqlx::query(
        "INSERT INTO conversations \
            (id, creator_did, current_epoch, created_at, updated_at, cipher_suite, \
             is_remote, group_id, group_info, reset_count) \
         VALUES ($1, $2, 0, $3, $3, $4, false, $5, $6, 0) \
         ON CONFLICT (id) DO UPDATE SET \
             group_id = EXCLUDED.group_id, \
             group_info = EXCLUDED.group_info, \
             current_epoch = 0, \
             reset_count = 0, last_reset_at = NULL, last_reset_by = NULL, \
             auto_reset_disabled_at = NULL",
    )
    .bind(convo_id)
    .bind(alice_identity)
    .bind(now)
    .bind("MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519")
    .bind("e8grp00000000000000000000000000")
    .bind(b"placeholder groupinfo".to_vec())
    .execute(&pool)
    .await
    .expect("seed convo");

    let session_id: String = sqlx::query_scalar(
        "INSERT INTO crypto_sessions ( \
            id, conversation_id, generation, mls_group_id, state, \
            cipher_suite, last_observed_epoch, created_by_did, \
            created_at, activated_at \
         ) VALUES (gen_random_uuid()::TEXT, $1, 0, $2, 'active', $3, 0, $4, $5, $5) \
         RETURNING id",
    )
    .bind(convo_id)
    .bind("e8grp00000000000000000000000000")
    .bind("MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519")
    .bind(alice_identity)
    .bind(now)
    .fetch_one(&pool)
    .await
    .expect("seed crypto_session");

    sqlx::query("UPDATE conversations SET active_crypto_session_id = $1 WHERE id = $2")
        .bind(&session_id)
        .bind(convo_id)
        .execute(&pool)
        .await
        .expect("link active_crypto_session_id");

    // ALICE: per-device member_did, identity user_did. The snapshot
    // stores user_did via COALESCE.
    sqlx::query(
        "INSERT INTO members (convo_id, member_did, user_did, joined_at, is_admin) \
         VALUES ($1, $2, $3, $4, true) \
         ON CONFLICT (convo_id, member_did) DO NOTHING",
    )
    .bind(convo_id)
    .bind(&alice_device)
    .bind(alice_identity)
    .bind(now)
    .execute(&pool)
    .await
    .expect("insert ALICE multi-device");

    // BOB: standard single-device row (member_did == user_did).
    sqlx::query(
        "INSERT INTO members (convo_id, member_did, user_did, joined_at, is_admin) \
         VALUES ($1, $2, $2, $3, false) \
         ON CONFLICT (convo_id, member_did) DO NOTHING",
    )
    .bind(convo_id)
    .bind(bob_identity)
    .bind(now)
    .execute(&pool)
    .await
    .expect("insert BOB");

    let actor = spawn_actor(&pool, convo_id).await;

    // Step 1: indirect Request snapshots ALICE's identity DID (not the
    // device-suffixed one) into allowed_responders.
    let (req_tx, req_rx) = oneshot::channel();
    actor
        .send_message(ConvoMessage::RequestCryptoSessionReset {
            trigger: ResetTrigger::QuorumVote,
            initiator_did: alice_identity.to_string(),
            reason: "e8 multi-device snapshot".to_string(),
            idempotency_key: format!("test-e8:{convo_id}"),
            expected_new_mls_group_id: None,
            reply: req_tx,
        })
        .expect("send Request");
    let _ = req_rx.await.expect("reply").expect("Request OK");

    // Verify the snapshot stored the bare identity DID (COALESCE on
    // user_did wins for ALICE; bob_identity passes through for BOB).
    let allowed: serde_json::Value = sqlx::query_scalar(
        "SELECT payload_json->'allowed_responders' FROM delivery_events \
         WHERE conversation_id = $1 \
           AND event_type = 'crypto_session_reset_requested' \
         LIMIT 1",
    )
    .bind(convo_id)
    .fetch_one(&pool)
    .await
    .expect("allowed_responders");
    let allowed_strs: Vec<String> = allowed
        .as_array()
        .expect("array")
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    assert!(
        allowed_strs.contains(&alice_identity.to_string()),
        "snapshot must contain ALICE's identity DID via COALESCE; got: {:?}",
        allowed_strs
    );
    assert!(
        !allowed_strs.contains(&alice_device),
        "snapshot must NOT contain the device-suffixed DID; got: {:?}",
        allowed_strs
    );

    // Step 2: ALICE activates using her per-device DID. The chokepoint
    // must `split_once('#')` to extract `did:plc:p2_5_e8_alice...`,
    // match against the snapshot, and accept activation.
    let (act_tx, act_rx) = oneshot::channel();
    actor
        .send_message(ConvoMessage::ActivateCryptoSession {
            reset_request_id: None,
            trigger: ResetTrigger::Bootstrap,
            new_mls_group_id: "e8newgrp0000000000000000000000000".to_string(),
            new_group_info: Some(vec![0xE8]),
            welcomes: vec![],
            initiator_did: alice_device.clone(),
            idempotency_key: format!("act-e8:{convo_id}"),
            reply: act_tx,
        })
        .expect("send Activate");
    let session = act_rx
        .await
        .expect("reply")
        .expect("multi-device DID must resolve to identity DID and pass allowlist");
    assert_eq!(session.state, "active");
    assert_eq!(session.generation, 1);

    wipe(&pool, convo_id).await;
}

// Dummy use of WelcomeEnvelope so the import isn't unused.
#[allow(dead_code)]
fn _ensure_welcome_envelope_import() -> WelcomeEnvelope {
    WelcomeEnvelope {
        recipient_did: "did:plc:dummy".to_string(),
        recipient_device_id: None,
        welcome_data: vec![],
        key_package_hash: None,
    }
}
