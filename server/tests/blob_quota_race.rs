//! Regression tests for finding F39: concurrent `uploadBlob` requests could
//! bypass the per-user byte quota (TOCTOU).
//!
//! `upload_blob.rs` computed `SUM(size_bytes)` in one statement, compared it
//! to the quota in application code, then INSERTed the blob row in a second
//! statement — no transaction, no lock, no atomic conditional insert.
//! Concurrent uploads both passed the check against the same snapshot and
//! both inserted, exceeding the quota by up to `max_blob_size` per extra
//! in-flight request.
//!
//! The fix extracts the quota check + insert into
//! `catbird_server::db::insert_blob_within_quota`, which serializes on a
//! per-owner `pg_advisory_xact_lock` and performs the sum + conditional
//! insert inside one transaction.
//!
//! RED state note (repo TDD convention, see `tests/group_info_store_helper.rs`):
//! before the fix lands the `use` below fails to compile — that IS the
//! failing-test state, since the defect is precisely that no atomic
//! check-and-insert primitive exists and the handler cannot be exercised
//! without a live S3 BlobStore.
//!
//! Requires live Postgres via `TEST_DATABASE_URL`.

mod common;

use catbird_server::db::insert_blob_within_quota;
use chrono::{Duration, Utc};
use common::setup_test_db;
use sqlx::PgPool;

async fn used_bytes(pool: &PgPool, owner_did: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COALESCE(SUM(size_bytes), 0)::BIGINT FROM blobs \
         WHERE owner_did = $1 AND deleted_at IS NULL",
    )
    .bind(owner_did)
    .fetch_one(pool)
    .await
    .expect("sum blob bytes")
}

async fn cleanup_blobs(pool: &PgPool, owner_did: &str) {
    let _ = sqlx::query("DELETE FROM blobs WHERE owner_did = $1")
        .bind(owner_did)
        .execute(pool)
        .await;
}

#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn sequential_over_quota_insert_is_rejected() {
    let pool = setup_test_db().await;
    let owner = format!("did:plc:blobquota-seq-{}", uuid::Uuid::new_v4());
    cleanup_blobs(&pool, &owner).await;

    let quota: i64 = 10_000;
    let expires = Utc::now() + Duration::days(1);

    let first = insert_blob_within_quota(
        &pool,
        &uuid::Uuid::new_v4().to_string(),
        &owner,
        "convo-blob-quota",
        6_000,
        quota,
        expires,
    )
    .await
    .expect("first insert");
    assert!(first, "first blob fits within quota and must be accepted");

    let second = insert_blob_within_quota(
        &pool,
        &uuid::Uuid::new_v4().to_string(),
        &owner,
        "convo-blob-quota",
        6_000,
        quota,
        expires,
    )
    .await
    .expect("second insert");
    assert!(
        !second,
        "second blob would exceed the quota and must be rejected"
    );

    assert!(
        used_bytes(&pool, &owner).await <= quota,
        "stored bytes must never exceed the quota"
    );

    cleanup_blobs(&pool, &owner).await;
}

#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn concurrent_uploads_cannot_exceed_quota() {
    let pool = setup_test_db().await;
    let owner = format!("did:plc:blobquota-race-{}", uuid::Uuid::new_v4());
    cleanup_blobs(&pool, &owner).await;

    let quota: i64 = 10_000;
    let size: i64 = 6_000; // only ONE of these fits under the quota
    let expires = Utc::now() + Duration::days(1);

    // Fire 8 concurrent uploads for the same owner — the F39 TOCTOU shape.
    let mut handles = Vec::new();
    for _ in 0..8 {
        let pool = pool.clone();
        let owner = owner.clone();
        handles.push(tokio::spawn(async move {
            insert_blob_within_quota(
                &pool,
                &uuid::Uuid::new_v4().to_string(),
                &owner,
                "convo-blob-quota-race",
                size,
                quota,
                expires,
            )
            .await
            .expect("insert_blob_within_quota must not error")
        }));
    }

    let mut accepted = 0;
    for handle in handles {
        if handle.await.expect("task join") {
            accepted += 1;
        }
    }

    assert_eq!(
        accepted, 1,
        "exactly one concurrent upload fits under the quota (F39 TOCTOU)"
    );
    assert!(
        used_bytes(&pool, &owner).await <= quota,
        "concurrent uploads must never push stored bytes past the quota (F39)"
    );

    cleanup_blobs(&pool, &owner).await;
}
