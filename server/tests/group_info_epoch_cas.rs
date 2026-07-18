//! Regression test for finding F63: concurrent `updateConvo` GroupInfo
//! uploads could roll the cached `group_info` / `group_info_epoch` backward.
//!
//! `update_convo.rs` performs a read-then-write (`get_group_info` →
//! `store_group_info`) that is not atomic: two racing requests can both pass
//! the "epoch must strictly increase" pre-check against the same
//! `existing_epoch`, after which the *last* writer wins regardless of epoch
//! ordering. The fix pushes the epoch comparison into the UPDATE's WHERE
//! clause (a compare-and-set), so a stale write is a no-op at the database
//! level no matter how requests interleave.
//!
//! This test models the losing interleaving directly: the DB already holds
//! GroupInfo at epoch 5, and a stale writer calls `store_group_info` with
//! epoch 3. Before the fix the UPDATE clobbers the newer row (RED); after
//! the fix the row is untouched (GREEN).
//!
//! Requires live Postgres via `TEST_DATABASE_URL` (same harness as
//! `tests/group_info_store_helper.rs`).

// `store_group_info` is deprecated in favor of the ADR-011 transition path,
// but it is still the live write path for `updateConvo`'s uploadGroupInfo
// action — which is exactly the surface F63 is about.
#![allow(deprecated)]

mod common;

use chrono::Utc;
use common::{cleanup, setup_test_db};
use sqlx::PgPool;

const CIPHER_SUITE: &str = "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519";
const CREATOR: &str = "did:plc:gicas1111111111111111";

async fn seed_convo(pool: &PgPool, convo_id: &str, group_info: &[u8], group_info_epoch: i32) {
    let now = Utc::now();
    sqlx::query(
        "INSERT INTO conversations \
            (id, creator_did, current_epoch, created_at, updated_at, cipher_suite, is_remote, \
             group_id, group_info, group_info_epoch, group_info_updated_at) \
         VALUES ($1, $2, 0, $3, $3, $4, false, $1, $5, $6, $3)",
    )
    .bind(convo_id)
    .bind(CREATOR)
    .bind(now)
    .bind(CIPHER_SUITE)
    .bind(group_info)
    .bind(group_info_epoch)
    .execute(pool)
    .await
    .expect("seed conversations row");
}

async fn fetch_group_info(pool: &PgPool, convo_id: &str) -> (Vec<u8>, i32) {
    sqlx::query_as::<_, (Vec<u8>, i32)>(
        "SELECT group_info, group_info_epoch FROM conversations WHERE id = $1",
    )
    .bind(convo_id)
    .fetch_one(pool)
    .await
    .expect("fetch group_info row")
}

#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn stale_epoch_write_cannot_roll_group_info_backward() {
    let pool = setup_test_db().await;
    let convo_id = format!("convo-gi-cas-{}", uuid::Uuid::new_v4());
    cleanup(&pool, &convo_id).await;

    // DB state as left by the winning writer: GroupInfo at epoch 5.
    let newer = vec![0xBB_u8; 256];
    seed_convo(&pool, &convo_id, &newer, 5).await;

    // The losing writer of the read-then-write race now lands its UPDATE
    // with an OLDER epoch (3 < 5). It already passed the handler's
    // pre-check before the winner committed, so the only remaining guard
    // is the UPDATE itself.
    let stale = vec![0xAA_u8; 256];
    let _ = catbird_server::group_info::store_group_info(&pool, &convo_id, &stale, 3).await;

    let (bytes, epoch) = fetch_group_info(&pool, &convo_id).await;
    assert_eq!(
        epoch, 5,
        "stale write must not roll group_info_epoch backward (F63)"
    );
    assert_eq!(
        bytes, newer,
        "stale write must not clobber newer GroupInfo bytes (F63)"
    );

    // Equal epoch must also be rejected ("strictly increase" contract).
    let equal = vec![0xDD_u8; 256];
    let _ = catbird_server::group_info::store_group_info(&pool, &convo_id, &equal, 5).await;
    let (bytes, epoch) = fetch_group_info(&pool, &convo_id).await;
    assert_eq!(epoch, 5, "equal-epoch write must be a no-op");
    assert_eq!(bytes, newer, "equal-epoch write must not replace bytes");

    // A genuinely advancing write still lands.
    let next = vec![0xCC_u8; 256];
    let _ = catbird_server::group_info::store_group_info(&pool, &convo_id, &next, 6).await;
    let (bytes, epoch) = fetch_group_info(&pool, &convo_id).await;
    assert_eq!(epoch, 6, "advancing write must be applied");
    assert_eq!(bytes, next, "advancing write must replace bytes");

    cleanup(&pool, &convo_id).await;
}
