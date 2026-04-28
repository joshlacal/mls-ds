//! Concurrent key-package claim race test.
//!
//! Asserts the atomic claim primitive (`UPDATE ... WHERE state='available'`
//! plus `FOR UPDATE SKIP LOCKED` on the row picker) lets exactly one of two
//! racing claimants take a single available row. The other must observe
//! state_after = "no_match" — never both succeed.
//!
//! Requires `TEST_DATABASE_URL` (defaults to localhost:5433/catbird). The
//! test creates and tears down its own user + key_package row.

use chrono::{Duration, Utc};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::Barrier;
use uuid::Uuid;

async fn setup_test_db() -> PgPool {
    let db_url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://catbird:changeme@localhost:5433/catbird".to_string());

    let config = catbird_server::db::DbConfig {
        database_url: db_url,
        max_connections: 8,
        min_connections: 2,
        acquire_timeout: std::time::Duration::from_secs(10),
        idle_timeout: std::time::Duration::from_secs(60),
    };

    catbird_server::db::init_db(config)
        .await
        .expect("Failed to initialize test database")
}

async fn ensure_user(pool: &PgPool, did: &str) {
    sqlx::query(
        "INSERT INTO users (did, created_at, last_seen_at) \
         VALUES ($1, NOW(), NOW()) \
         ON CONFLICT (did) DO NOTHING",
    )
    .bind(did)
    .execute(pool)
    .await
    .expect("ensure_user");
}

async fn insert_available_key_package(
    pool: &PgPool,
    owner_did: &str,
    cipher_suite: &str,
) -> String {
    let id = Uuid::new_v4().to_string();
    let kp_hash = format!("test-{}", &id[..16]);
    let kp_bytes = vec![0u8; 32];
    let expires_at = Utc::now() + Duration::days(30);

    sqlx::query(
        "INSERT INTO key_packages \
           (id, owner_did, cipher_suite, key_package, key_package_hash, \
            created_at, expires_at, state, is_last_resort) \
         VALUES ($1, $2, $3, $4, $5, NOW(), $6, 'available', false)",
    )
    .bind(&id)
    .bind(owner_did)
    .bind(cipher_suite)
    .bind(&kp_bytes)
    .bind(&kp_hash)
    .bind(expires_at)
    .execute(pool)
    .await
    .expect("insert_available_key_package");

    id
}

async fn cleanup(pool: &PgPool, owner_did: &str) {
    let _ = sqlx::query("DELETE FROM key_packages WHERE owner_did = $1")
        .bind(owner_did)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM users WHERE did = $1")
        .bind(owner_did)
        .execute(pool)
        .await;
}

/// Direct copy of the atomic claim SQL emitted by the
/// `claim_available_key_packages` helper in
/// `handlers/mls_chat/get_key_packages.rs`. We invoke the SQL directly here
/// rather than calling the handler to keep the test focused on the
/// atomicity invariant.
async fn try_claim_one(
    pool: &PgPool,
    owner_did: &str,
    cipher_suite: &str,
) -> sqlx::Result<Vec<(String, String, Vec<u8>, Option<String>)>> {
    sqlx::query_as::<_, (String, String, Vec<u8>, Option<String>)>(
        "UPDATE key_packages \
         SET state = 'claimed', consumed_at = NOW() \
         WHERE id IN ( \
           SELECT DISTINCT ON (COALESCE(device_id, '')) id \
           FROM key_packages \
           WHERE owner_did = $1 \
             AND state = 'available' \
             AND expires_at > NOW() \
             AND is_last_resort = false \
             AND cipher_suite = $2 \
           ORDER BY COALESCE(device_id, ''), created_at ASC \
           FOR UPDATE SKIP LOCKED \
         ) \
         AND state = 'available' \
         RETURNING owner_did, cipher_suite, key_package, key_package_hash",
    )
    .bind(owner_did)
    .bind(cipher_suite)
    .fetch_all(pool)
    .await
}

#[tokio::test]
async fn test_concurrent_claim_exactly_one_winner() {
    let pool = setup_test_db().await;

    let owner_did = format!("did:plc:test-claim-race-{}", Uuid::new_v4());
    let cipher_suite = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519";

    ensure_user(&pool, &owner_did).await;
    let _kp_id = insert_available_key_package(&pool, &owner_did, cipher_suite).await;

    let barrier = Arc::new(Barrier::new(2));

    let pool_a = pool.clone();
    let owner_a = owner_did.clone();
    let cs_a = cipher_suite.to_string();
    let bar_a = barrier.clone();
    let task_a = tokio::spawn(async move {
        bar_a.wait().await;
        try_claim_one(&pool_a, &owner_a, &cs_a).await
    });

    let pool_b = pool.clone();
    let owner_b = owner_did.clone();
    let cs_b = cipher_suite.to_string();
    let bar_b = barrier.clone();
    let task_b = tokio::spawn(async move {
        bar_b.wait().await;
        try_claim_one(&pool_b, &owner_b, &cs_b).await
    });

    let res_a = task_a.await.expect("task_a join").expect("task_a sql");
    let res_b = task_b.await.expect("task_b join").expect("task_b sql");

    let a_won = !res_a.is_empty();
    let b_won = !res_b.is_empty();

    assert!(
        a_won ^ b_won,
        "expected exactly one winner; task_a returned {} rows, task_b returned {} rows",
        res_a.len(),
        res_b.len(),
    );

    // The winner returns exactly the row we inserted; the loser returns zero
    // rows (the no_match outcome the handler would translate into a metric
    // increment + "missing" entry).
    let (winner_rows, loser_rows) = if a_won {
        (res_a, res_b)
    } else {
        (res_b, res_a)
    };
    assert_eq!(winner_rows.len(), 1);
    assert_eq!(winner_rows[0].0, owner_did);
    assert_eq!(winner_rows[0].1, cipher_suite);
    assert!(
        loser_rows.is_empty(),
        "loser must observe zero rows; got {} rows",
        loser_rows.len()
    );

    // Repeat-claim sanity: the row is now `claimed`, so a third try returns
    // zero rows. This is what the metric `key_package_claim_total{state_after="no_match"}`
    // increments on in production.
    let after = try_claim_one(&pool, &owner_did, cipher_suite)
        .await
        .expect("post-claim sql");
    assert!(
        after.is_empty(),
        "post-claim try should find no available row; got {} rows",
        after.len()
    );

    cleanup(&pool, &owner_did).await;
}
