//! Regression test for finding F9: group metadata blobs had no aggregate
//! quota or retention bound — every `putGroupMetadataBlob` call inserted a
//! new row into `group_metadata_blobs` and nothing ever pruned superseded
//! blobs for a live conversation (the cleanup worker only removes blobs for
//! *deleted* conversations), so a member could accumulate unbounded storage
//! (1 MB per call) forever.
//!
//! The fix adds retention-on-write: after a successful insert, the handler
//! prunes the oldest rows for the same conversation beyond
//! `MAX_METADATA_BLOBS_PER_CONVO` (newest kept), bounding per-convo
//! accumulation to `MAX_METADATA_BLOBS_PER_CONVO * MAX_METADATA_BLOB_SIZE`.
//!
//! Drives the real handler (`put_group_metadata_blob`) directly, same
//! pattern as `tests/bootstrap_reset_group.rs`. Requires live Postgres via
//! `TEST_DATABASE_URL`.

mod common;

use axum::body::Bytes;
use axum::extract::{Query, State};
use catbird_server::auth::{AtProtoClaims, AuthUser};
use catbird_server::handlers::mls_chat::put_group_metadata_blob::{
    put_group_metadata_blob, PutGroupMetadataBlobParams,
};
use chrono::Utc;
use common::{cleanup, setup_test_db};
use sqlx::PgPool;

const NSID: &str = "blue.catbird.mlsChat.putGroupMetadataBlob";

/// Retention bound the fix must enforce (mirrors
/// `MAX_METADATA_BLOBS_PER_CONVO` in `put_group_metadata_blob.rs`; kept as a
/// literal here so this test compiles — and fails at runtime — against the
/// pre-fix handler).
const RETENTION_BOUND: i64 = 64;
const CIPHER_SUITE: &str = "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519";
const MEMBER: &str = "did:plc:gmbretention111111111";

fn test_auth_user(did: &str) -> AuthUser {
    AuthUser {
        did: did.to_string(),
        claims: AtProtoClaims {
            iss: did.to_string(),
            aud: "did:web:test.catbird.blue".to_string(),
            exp: 9_999_999_999,
            iat: Some(0),
            sub: Some(did.to_string()),
            lxm: Some(NSID.to_string()),
            jti: Some(format!("test-jti-{}", uuid::Uuid::new_v4())),
        },
    }
}

async fn seed_convo_with_member(pool: &PgPool, convo_id: &str, member_did: &str) {
    let now = Utc::now();
    sqlx::query(
        "INSERT INTO conversations \
            (id, creator_did, current_epoch, created_at, updated_at, cipher_suite, is_remote, group_id) \
         VALUES ($1, $2, 0, $3, $3, $4, false, $1)",
    )
    .bind(convo_id)
    .bind(member_did)
    .bind(now)
    .bind(CIPHER_SUITE)
    .execute(pool)
    .await
    .expect("seed conversations row");

    sqlx::query(
        "INSERT INTO members (convo_id, member_did, user_did, joined_at, is_admin) \
         VALUES ($1, $2, $2, $3, true)",
    )
    .bind(convo_id)
    .bind(member_did)
    .bind(now)
    .execute(pool)
    .await
    .expect("seed members row");
}

async fn cleanup_metadata_blobs(pool: &PgPool, convo_id: &str) {
    let _ = sqlx::query("DELETE FROM group_metadata_blobs WHERE convo_id = $1 OR group_id = $1")
        .bind(convo_id)
        .execute(pool)
        .await;
}

#[tokio::test]
#[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
async fn metadata_blob_accumulation_is_bounded_per_convo() {
    let (pool, _database) = setup_test_db().await;
    let convo_id = format!("convo-gmb-retention-{}", uuid::Uuid::new_v4());
    cleanup_metadata_blobs(&pool, &convo_id).await;
    cleanup(&pool, &convo_id).await;
    seed_convo_with_member(&pool, &convo_id, MEMBER).await;

    // Upload well past the retention bound. Each blob is tiny; the point is
    // row-count accumulation, which is what carries the up-to-1MB payloads
    // in production.
    let total = RETENTION_BOUND + 16;
    let mut last_locator = String::new();
    for i in 0..total {
        let locator = uuid::Uuid::new_v4().to_string();
        last_locator = locator.clone();
        let params = PutGroupMetadataBlobParams {
            blob_locator: locator,
            group_id: convo_id.clone(),
            convo_id: Some(convo_id.clone()),
            reset_generation: None,
            metadata_version: Some(i + 1),
            kind: None,
        };
        let result = put_group_metadata_blob(
            State(pool.clone()),
            test_auth_user(MEMBER),
            Query(params),
            Bytes::from(vec![0u8; 128]),
        )
        .await;
        assert!(
            result.is_ok(),
            "putGroupMetadataBlob upload {i} should succeed, got {:?}",
            result.err()
        );
    }

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM group_metadata_blobs WHERE convo_id = $1 OR group_id = $1",
    )
    .bind(&convo_id)
    .fetch_one(&pool)
    .await
    .expect("count metadata blobs");

    assert!(
        count <= RETENTION_BOUND,
        "per-convo metadata blob accumulation must be bounded (F9): \
         expected <= {RETENTION_BOUND} rows, found {count}"
    );

    // The newest blob (the live metadata) must survive pruning.
    let newest_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM group_metadata_blobs WHERE blob_locator = $1)",
    )
    .bind(&last_locator)
    .fetch_one(&pool)
    .await
    .expect("check newest blob");
    assert!(
        newest_exists,
        "retention pruning must keep the newest metadata blob"
    );

    cleanup_metadata_blobs(&pool, &convo_id).await;
    cleanup(&pool, &convo_id).await;
}
