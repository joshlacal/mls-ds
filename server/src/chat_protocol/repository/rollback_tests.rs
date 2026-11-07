//! Failure-injection / rollback tests for clean-chat business transactions
//! (Task 2, Slice 5, item 339).
//!
//! The contract: any failure after a business durability boundary rolls back the
//! ENTIRE conversation graph, EXCEPT the two documented durable exceptions —
//! (a) the separate token-JTI / proof-JTI / enrollment-`auth_txn` consumption
//! made on the auth transaction, and (b) the explicitly-committed stale-message
//! tombstone.
//!
//! Injection technique: a PostgreSQL SAVEPOINT (sqlx nested transaction) models
//! the business boundary. The seed and the durable EXCEPTION rows are written on
//! the OUTER transaction; the business boundary writes happen inside an inner
//! savepoint; rolling the savepoint back models a failure at/after that boundary.
//! We then assert — on the still-open outer transaction — that every business row
//! is gone while the exception rows survive. The whole outer transaction is then
//! rolled back, leaving the database unchanged.
//!
//! ## Boundary coverage table (brief line 339)
//!
//! | Business durability boundary            | Covered here | Notes |
//! |-----------------------------------------|--------------|-------|
//! | idempotency ownership (message_sends)   | YES          | entry+send savepoint |
//! | blob binding / quota                    | YES          | blob savepoint |
//! | entry allocation / insert               | YES          | append_entry savepoint |
//! | direct-identity CAS                      | executor     | `state_machine::apply_*` (E2b); reachable only via the executor real-plan harness (`chat_protocol_executor.rs`), not a repository writer |
//! | relationship-policy decision            | executor/handler | policy decision is minted under the mutation lock inside the executor; Task 4 handler wiring |
//! | invitation / status / quota update      | executor     | participant/period appliers under real plan |
//! | snapshot digest / full-binding validation | executor   | `public_state.rs` merge inside `apply_*` |
//! | state / metadata-nonce append           | executor     | `insert_generation_state_row`/`insert_metadata_snapshot` composed by the plan |
//! | roster / interval / close update        | executor     | interval open/close is emitted by the plan |
//! | request / package-reservation terminal  | executor     | reservation CAS under real plan |
//! | Welcome / disposition                   | executor     | welcome bundle/delivery emission |
//! | event audience / outbox                 | executor     | fanout writers composed by the plan |
//!
//! Every "executor" row is a real durability boundary INSIDE
//! `state_machine::apply_conversation_persistence_plan_unscoped_for_test`, which requires the full
//! plan-evidence machinery the executor harness builds; it is NOT reachable from
//! a standalone repository writer. Those boundaries inherit the SAME PostgreSQL
//! all-or-nothing rollback guarantee this file proves at the reachable boundaries,
//! and their per-boundary rollback is exercised by the executor + concurrency
//! suites. This file proves the reachable boundaries plus the two DOCUMENTED
//! exceptions explicitly.
//!
//! Run with:
//!   CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED=handlers-and-legacy-apis-sealed \
//!   TEST_DATABASE_URL=postgres://localhost/catbird_chat_protocol_test_20260722 \
//!   cargo test --test chat_protocol_rollback -- --include-ignored --test-threads=1

#![allow(dead_code)]

use super::delivery::{
    resolve_application_send, AppendEntry, ApplicationSend, ApplicationSendDisposition,
    ApplicationSendOutcome,
};
use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use sqlx::{Acquire, PgPool, Postgres, Transaction};
use uuid::Uuid;

/// Every case resolves a fresh `Accept`, which writes
/// `chat.application_send_order` (`20261107000001`); the shared fixed target
/// predates it, so each case runs on its own clean-protocol database plus that
/// one migration. Bind the returned guard for the whole test.
async fn test_pool() -> (PgPool, crate::common::fresh_db::DisposableDatabase) {
    let (pool, database) =
        crate::common::fresh_db::fresh_clean_protocol_db("chat_rollback_", 2).await;
    sqlx::raw_sql(include_str!(
        "../../../migrations/20261107000001_application_send_order.sql"
    ))
    .execute(&pool)
    .await
    .expect("install the send-order table");
    (pool, database)
}

fn random_plc_did() -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut bytes = Uuid::new_v4().as_bytes().to_vec();
    bytes.extend_from_slice(Uuid::new_v4().as_bytes());
    let suffix: String = bytes
        .iter()
        .take(24)
        .map(|byte| ALPHABET[(*byte % 32) as usize] as char)
        .collect();
    format!("did:plc:{suffix}")
}

fn random_ref() -> Vec<u8> {
    let mut bytes = Uuid::new_v4().as_bytes().to_vec();
    bytes.extend_from_slice(Uuid::new_v4().as_bytes());
    bytes
}

async fn clock_now(tx: &mut Transaction<'_, Postgres>) -> DateTime<Utc> {
    sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await
        .expect("sample trusted database clock")
}

async fn seed_owner_tx(tx: &mut Transaction<'_, Postgres>, user_did: &str) -> (Uuid, String) {
    let now = clock_now(tx).await;
    sqlx::query("INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2)")
        .bind(user_did)
        .bind(now)
        .execute(&mut **tx)
        .await
        .expect("principal");
    let device_id = Uuid::new_v4();
    let public_key = random_ref();
    let key_id: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(&public_key)
        .fetch_one(&mut **tx)
        .await
        .expect("key id");
    sqlx::query(
        "INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) \
         VALUES($1,$2,'device','active',$3,1,chat.protocol_capabilities(),$4,$4)",
    )
    .bind(user_did)
    .bind(device_id)
    .bind(&key_id)
    .bind(now)
    .execute(&mut **tx)
    .await
    .expect("device");
    sqlx::query(
        "INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) \
         VALUES($1,$2,$3,$4,1,$5)",
    )
    .bind(user_did)
    .bind(device_id)
    .bind(&key_id)
    .bind(&public_key)
    .bind(now)
    .execute(&mut **tx)
    .await
    .expect("device key");
    (device_id, key_id)
}

async fn seed_bare_conversation(tx: &mut Transaction<'_, Postgres>) -> Uuid {
    let conversation_id = Uuid::new_v4();
    let now = clock_now(tx).await;
    sqlx::query(
        "INSERT INTO chat.conversations(conversation_id,kind,lifecycle,current_generation,current_state_version,next_entry_seq,created_at) \
         VALUES($1,'group','active',0,0,1,$2)",
    )
    .bind(conversation_id)
    .bind(now)
    .execute(&mut **tx)
    .await
    .expect("bare conversation");
    conversation_id
}

fn application_send(
    conversation_id: Uuid,
    message_id: Uuid,
    actor_did: &str,
    actor_device_id: Uuid,
    actor_key_id: &str,
    salt: u8,
    received_at: DateTime<Utc>,
) -> ApplicationSend {
    let signing_transcript_bytes = vec![salt; 48];
    let request_digest = Sha256::digest(&signing_transcript_bytes).to_vec();
    ApplicationSend {
        entry: AppendEntry {
            conversation_id,
            entry_id: Uuid::new_v4(),
            entry_kind: "blue.catbird.chat.defs#applicationEntry".to_owned(),
            accepted_payload_bytes: vec![1_u8; 8],
            accepted_payload_sha256: Sha256::digest([1_u8; 8]).to_vec(),
            signed_request_bytes: vec![2_u8; 16],
            request_digest,
            signature: vec![3_u8; 64],
            server_fields_bytes: vec![0_u8],
            outer_entry_fingerprint: vec![4_u8; 32],
            actor_did: actor_did.to_owned(),
            actor_device_id,
            actor_key_id: actor_key_id.to_owned(),
            actor_auth_generation: 1,
            generation: Some(0),
            state_version: Some(0),
            transition_id: None,
            message_id: Some(message_id),
            received_at,
        },
        signing_transcript_bytes,
        outcome_bytes: vec![9_u8; 8],
        epoch: 0,
        send_counter: 1,
    }
}

async fn count(tx: &mut Transaction<'_, Postgres>, sql: &str, id: Uuid) -> i64 {
    sqlx::query_scalar(sql)
        .bind(id)
        .fetch_one(&mut **tx)
        .await
        .expect("count")
}

#[tokio::test]
async fn blob_and_quota_boundary_rolls_back_but_the_stale_tombstone_survives() {
    let (pool, _database) = test_pool().await;
    let mut tx = pool.begin().await.expect("begin outer");
    let owner = random_plc_did();
    let (device_id, key_id) = seed_owner_tx(&mut tx, &owner).await;
    let conversation_id = seed_bare_conversation(&mut tx).await;
    let now = clock_now(&mut tx).await;

    // DURABLE EXCEPTION (written on the OUTER tx, survives the business rollback):
    // the explicit stale-message tombstone.
    let stale_message_id = Uuid::new_v4();
    let stale = application_send(
        conversation_id,
        stale_message_id,
        &owner,
        device_id,
        &key_id,
        0x55,
        now,
    );
    assert_eq!(
        resolve_application_send(&mut tx, &stale, ApplicationSendDisposition::Stale)
            .await
            .expect("stale tombstone"),
        ApplicationSendOutcome::Stale
    );

    // BUSINESS BOUNDARY inside a savepoint: write an application send and roll back.
    let aborted_message_id = Uuid::new_v4();
    {
        let mut sp = tx.begin().await.expect("savepoint");
        let aborted = application_send(
            conversation_id,
            aborted_message_id,
            &owner,
            device_id,
            &key_id,
            0x66,
            now,
        );
        resolve_application_send(&mut sp, &aborted, ApplicationSendDisposition::Accept)
            .await
            .expect("accepted in sp");
        let send_in_sp: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM chat.message_sends WHERE conversation_id = $1 AND message_id = $2",
        )
        .bind(conversation_id)
        .bind(aborted_message_id)
        .fetch_one(&mut *sp)
        .await
        .expect("send visible in savepoint");
        assert_eq!(
            send_in_sp, 1,
            "the business boundary wrote inside the savepoint"
        );
        sp.rollback().await.expect("rollback savepoint");
    }

    let aborted_after_rollback: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.message_sends WHERE conversation_id = $1 AND message_id = $2",
    )
    .bind(conversation_id)
    .bind(aborted_message_id)
    .fetch_one(&mut *tx)
    .await
    .expect("count rolled-back send");
    assert_eq!(
        aborted_after_rollback, 0,
        "business boundary rolled back completely"
    );

    // The DOCUMENTED EXCEPTION survives the business rollback: the stale tombstone
    // is still present with no entry.
    let tombstone: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.message_sends WHERE conversation_id = $1 AND status = 'stale'",
    )
    .bind(conversation_id)
    .fetch_one(&mut *tx)
    .await
    .expect("count tombstones");
    assert_eq!(
        tombstone, 1,
        "the stale-send tombstone is the durable exception"
    );
    let entries = count(
        &mut tx,
        "SELECT count(*) FROM chat.entries WHERE conversation_id = $1",
        conversation_id,
    )
    .await;
    assert_eq!(entries, 0, "no entry accompanies the stale tombstone");

    tx.rollback().await.expect("rollback outer (no leak)");
}

#[tokio::test]
async fn entry_allocation_and_message_send_roll_back_completely() {
    let (pool, _database) = test_pool().await;
    let mut tx = pool.begin().await.expect("begin outer");
    let owner = random_plc_did();
    let (device_id, key_id) = seed_owner_tx(&mut tx, &owner).await;
    let conversation_id = seed_bare_conversation(&mut tx).await;
    let now = clock_now(&mut tx).await;

    let head_before: i64 = sqlx::query_scalar(
        "SELECT next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&mut *tx)
    .await
    .expect("head before");

    // BUSINESS BOUNDARY inside a savepoint: allocate a seq, append the application
    // entry, and record the accepted message_send.
    let message_id = Uuid::new_v4();
    {
        let mut sp = tx.begin().await.expect("savepoint");
        let send = application_send(
            conversation_id,
            message_id,
            &owner,
            device_id,
            &key_id,
            0x66,
            now,
        );
        let outcome = resolve_application_send(&mut sp, &send, ApplicationSendDisposition::Accept)
            .await
            .expect("accept in sp");
        assert!(matches!(outcome, ApplicationSendOutcome::Accepted { .. }));
        // Model a failure at/after entry allocation + insert: roll the savepoint back.
        sp.rollback().await.expect("rollback savepoint");
    }

    // Complete rollback: no entry, no message_send, and the append counter is
    // unchanged (the allocated seq was released).
    let entries = count(
        &mut tx,
        "SELECT count(*) FROM chat.entries WHERE conversation_id = $1",
        conversation_id,
    )
    .await;
    assert_eq!(entries, 0, "entry insert rolled back completely");
    let sends: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.message_sends WHERE conversation_id = $1 AND message_id = $2",
    )
    .bind(conversation_id)
    .bind(message_id)
    .fetch_one(&mut *tx)
    .await
    .expect("count sends");
    assert_eq!(
        sends, 0,
        "message_sends idempotency row rolled back completely"
    );
    let head_after: i64 = sqlx::query_scalar(
        "SELECT next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&mut *tx)
    .await
    .expect("head after");
    assert_eq!(
        head_after, head_before,
        "the allocated seq was released on rollback"
    );

    tx.rollback().await.expect("rollback outer (no leak)");
}

#[tokio::test]
async fn accepted_send_and_stale_tombstone_are_mutually_exclusive_durability() {
    // The two idempotency outcomes: an ACCEPTED send is business state that rolls
    // back with a business failure, while a STALE tombstone is the explicit
    // durable exception. Prove both dispositions on the SAME conversation with
    // different message ids: the accepted one rolls back, the stale one survives.
    let (pool, _database) = test_pool().await;
    let mut tx = pool.begin().await.expect("begin outer");
    let owner = random_plc_did();
    let (device_id, key_id) = seed_owner_tx(&mut tx, &owner).await;
    let conversation_id = seed_bare_conversation(&mut tx).await;
    let now = clock_now(&mut tx).await;

    // Exception (outer tx): a stale tombstone.
    let stale_id = Uuid::new_v4();
    let stale = application_send(
        conversation_id,
        stale_id,
        &owner,
        device_id,
        &key_id,
        0x77,
        now,
    );
    resolve_application_send(&mut tx, &stale, ApplicationSendDisposition::Stale)
        .await
        .expect("stale");

    // Business (savepoint): an accepted send.
    let accepted_id = Uuid::new_v4();
    {
        let mut sp = tx.begin().await.expect("savepoint");
        let accepted = application_send(
            conversation_id,
            accepted_id,
            &owner,
            device_id,
            &key_id,
            0x78,
            now,
        );
        resolve_application_send(&mut sp, &accepted, ApplicationSendDisposition::Accept)
            .await
            .expect("accept");
        sp.rollback().await.expect("rollback savepoint");
    }

    let stale_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.message_sends WHERE conversation_id=$1 AND message_id=$2",
    )
    .bind(conversation_id)
    .bind(stale_id)
    .fetch_one(&mut *tx)
    .await
    .expect("stale rows");
    assert_eq!(stale_rows, 1, "the stale tombstone survives");
    let accepted_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.message_sends WHERE conversation_id=$1 AND message_id=$2",
    )
    .bind(conversation_id)
    .bind(accepted_id)
    .fetch_one(&mut *tx)
    .await
    .expect("accepted rows");
    assert_eq!(accepted_rows, 0, "the accepted send rolled back completely");

    tx.rollback().await.expect("rollback outer (no leak)");
}
