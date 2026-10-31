//! Clean-slate Labyrinth retention suite (`G6`, `I14`, `2A`, `L-F01`):
//! - `purgeMailbox` & `deleteAccountData` purge `labyrinth.epoch_heads` while advancing
//!   `labyrinth.epoch_head_floors`, leaving other accounts untouched;
//! - `labyrinth.operations` idempotency records survive `deleteAccountData` so replays answer
//!   from cached response bytes without recreating purged rows, then expire after 7 days via `run_gc`;
//! - `labyrinth.open_retention_scope()` guards all rows against ordinary SQL `DELETE`/`UPDATE`;
//! - all retired server-batch, MEK, redaction, attachment-ref, ORF, and virtual-device endpoints
//!   return `404 Not Found`.

mod common;

#[path = "common/labyrinth_harness.rs"]
mod harness;

#[path = "common/labyrinth_chain.rs"]
mod chain;

use axum::http::StatusCode;
use catbird_server::labyrinth::repo::retention::run_gc;
use chrono::Duration;
use harness::*;
use serde_json::{json, Value};

fn publish(epoch: &Value) -> Value {
    json!({ "epoch": epoch })
}

async fn count(env: &Env, table: &str, column: &str, did: &str) -> i64 {
    sqlx::query_scalar(&format!(
        "SELECT count(*) FROM labyrinth.{table} WHERE {column} = $1"
    ))
    .bind(did)
    .fetch_one(&env.pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn purge_mailbox_resets_the_account_advances_floor_and_leaves_others_untouched() {
    let env = Env::new().await;
    let v = vectors();
    let d0 = env.device_for(&v.did, v.seeds[0]).await;
    let d1 = env.device_for(&v.did, v.seeds[1]).await;
    let bob = env.account().await;

    d0.call("publishEpochHead", &publish(&v.chain[0]))
        .await
        .ok();
    d0.call("publishEpochHead", &publish(&v.chain[1]))
        .await
        .ok();
    d1.call("publishEpochHead", &publish(&v.chain[2]))
        .await
        .ok();

    let (bob_e0, _) = chain::epoch_public(&bob, 0, [0xB1; 32], None, None);
    bob.call("publishEpochHead", &publish(&bob_e0)).await.ok();

    d0.call("purgeMailbox", &json!({})).await.ok();
    assert_eq!(count(&env, "epoch_heads", "did", &v.did).await, 0);
    assert_eq!(
        count(&env, "epoch_heads", "did", &bob.did).await,
        1,
        "other accounts must remain untouched"
    );

    let floor: i64 = sqlx::query_scalar(
        "SELECT max_epoch_number FROM labyrinth.epoch_head_floors WHERE did = $1",
    )
    .bind(&v.did)
    .fetch_one(&env.pool)
    .await
    .unwrap();
    assert_eq!(floor, 2, "high-water floor must advance to prior max epoch");

    d0.query("getEpochHead", &[("did", v.did.clone())])
        .await
        .fails(404, "EpochNotFound");

    // Epoch <= floor is blocked; restarting strictly at floor + 1 (3) succeeds.
    d0.call("publishEpochHead", &publish(&v.chain[0]))
        .await
        .fails(400, "InvalidEpochChain");
    let (restarted, _) = chain::epoch_public(&d0, 3, [0x99; 32], None, None);
    d0.call("publishEpochHead", &publish(&restarted)).await.ok();

    // Idempotent replay and empty-chain no-op purge both succeed.
    d0.call_op("purgeMailbox", &json!({}), [0x77; 16])
        .await
        .ok();
    d0.call_op("purgeMailbox", &json!({}), [0x77; 16])
        .await
        .ok();
    d0.call("purgeMailbox", &json!({})).await.ok();
}

#[tokio::test]
async fn delete_account_data_purges_heads_and_preserves_idempotency_operations() {
    let env = Env::new().await;
    let alice = env.account().await;
    let (genesis, g_link) = chain::epoch_public(&alice, 0, [0x11; 32], None, None);
    let (epoch1, _) = chain::epoch_public(&alice, 1, [0x22; 32], Some(g_link), None);

    let op_id = [0x0B; 16];
    let before = alice
        .call_op("publishEpochHead", &publish(&genesis), op_id)
        .await;
    before.ok();
    alice
        .call("publishEpochHead", &publish(&epoch1))
        .await
        .ok();

    alice.call("deleteAccountData", &json!({})).await.ok();
    assert_eq!(count(&env, "epoch_heads", "did", &alice.did).await, 0);

    // Pre-deletion operation idempotency records survive deletion so a replayed pre-deletion
    // write returns its cached response and does NOT recreate purged rows.
    let ops = count(&env, "operations", "owner_did", &alice.did).await;
    assert!(ops >= 3, "operations kept across deleteAccountData: {ops}");

    let replay = alice
        .call_op("publishEpochHead", &publish(&genesis), op_id)
        .await;
    assert_eq!(replay.status, StatusCode::OK);
    assert_eq!(replay.bytes, before.bytes);
    assert_eq!(
        count(&env, "epoch_heads", "did", &alice.did).await,
        0,
        "idempotency replay must not recreate purged epoch_heads"
    );
}

#[tokio::test]
async fn retention_scope_blocks_raw_sql_mutations_and_gc_expires_operations_after_7_days() {
    let env = Env::new().await;
    let alice = env.account().await;
    let (genesis, _) = chain::epoch_public(&alice, 0, [0x44; 32], None, None);
    alice
        .call("publishEpochHead", &publish(&genesis))
        .await
        .ok();

    // Ordinary SQL outside `labyrinth.open_retention_scope()` cannot DELETE or UPDATE rows.
    assert!(
        sqlx::query("DELETE FROM labyrinth.epoch_heads")
            .execute(&env.pool)
            .await
            .is_err(),
        "raw DELETE on labyrinth.epoch_heads must be rejected by retention scope trigger"
    );
    assert!(
        sqlx::query("UPDATE labyrinth.epoch_heads SET received_at = now()")
            .execute(&env.pool)
            .await
            .is_err(),
        "raw UPDATE on labyrinth.epoch_heads must be rejected by immutability trigger"
    );
    assert!(
        sqlx::query("DELETE FROM labyrinth.operations")
            .execute(&env.pool)
            .await
            .is_err(),
        "raw DELETE on labyrinth.operations must be rejected outside retention scope"
    );

    let now = env.now().await;
    // Before 7 days, GC removes 0 operations.
    let early = run_gc(&env.pool, now + Duration::days(6), 500)
        .await
        .unwrap();
    assert_eq!(early.operations, 0);
    assert_eq!(count(&env, "operations", "owner_did", &alice.did).await, 1);

    // Past 7 days, GC reclaims expired operation idempotency records.
    let expired = run_gc(&env.pool, now + Duration::days(8), 500)
        .await
        .unwrap();
    assert_eq!(expired.operations, 1);
    assert_eq!(count(&env, "operations", "owner_did", &alice.did).await, 0);
}

#[tokio::test]
async fn retired_content_redaction_attachment_and_bundle_routes_return_404() {
    let env = Env::new().await;
    let alice = env.account().await;

    for proc_name in [
        "createMek",
        "appendBatch",
        "appendOwnerBatch",
        "redactMessage",
        "putAttachmentRef",
        "createVirtualDevice",
        "touchVirtualDevice",
        "deleteVirtualDevice",
        "registerOrfState",
        "deleteOrfState",
        "purgeAuthor",
    ] {
        let reply = alice.call(proc_name, &json!({})).await;
        assert_eq!(
            reply.status,
            StatusCode::NOT_FOUND,
            "retired procedure {proc_name} must return 404"
        );
    }

    for query_name in [
        "listBatches",
        "listMeks",
        "listOwnerBatches",
        "getAttachmentBlob",
        "getVirtualDevice",
        "listVirtualDevices",
        "evaluateOrf",
    ] {
        let reply = alice.query(query_name, &[]).await;
        assert_eq!(
            reply.status,
            StatusCode::NOT_FOUND,
            "retired query {query_name} must return 404"
        );
    }
}
