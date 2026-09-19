//! Real PostgreSQL storage-invariant checks. Synthetic terminal receipt bytes
//! here deliberately do not claim signature, MLS, or HTTP-facade qualification.
#![allow(dead_code)]
#[path = "common/chat_protocol.rs"]
pub mod chat_protocol_baseline;
mod common {
    pub use super::chat_protocol_baseline as chat_protocol;
    pub mod direct_request_database;
}

use sha2::{Digest, Sha256};
use uuid::Uuid;

#[tokio::test]
async fn published_attempt_cannot_commit_without_canonical_request_graph() {
    let pool = common::direct_request_database::setup().await;
    let mut tx = pool.begin().await.unwrap();
    let receipt = b"synthetic-storage-receipt-not-signature-proof";
    let request = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO chat.direct_request_attempts(request_id,actor_did,actor_device_id,\
         actor_key_id,actor_auth_generation,recipient_did,prepare_digest,status,terminal_at,\
         terminal_response,terminal_response_sha256,publication_digest,created_at) \
         VALUES($1,'did:plc:aaaaaaaaaaaaaaaaaaaaaaaa',$2,\
         'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',1,'did:plc:bbbbbbbbbbbbbbbbbbbbbbbb',\
         $3,'published',clock_timestamp(),$4,$5,$6,clock_timestamp())",
    )
    .bind(request)
    .bind(Uuid::new_v4())
    .bind(vec![1_u8; 32])
    .bind(receipt.as_slice())
    .bind(Sha256::digest(receipt).to_vec())
    .bind(vec![2_u8; 32])
    .execute(&mut *tx)
    .await
    .unwrap();
    let error = tx.commit().await.expect_err("publication must be atomic");
    let database = error.as_database_error().expect("database invariant error");
    assert_eq!(database.code().as_deref(), Some("23514"));
    assert!(database.message().contains("lacks canonical publication"));
    let survived: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat.direct_request_attempts WHERE request_id=$1)",
    )
    .bind(request)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        !survived,
        "failed publication must not leave an outcome row"
    );
}

#[tokio::test]
async fn unknown_device_cannot_acquire_pending_preview_authority() {
    let pool = common::direct_request_database::setup().await;
    let proof: (bool, bool) = sqlx::query_as(
        "SELECT chat.direct_request_leaf_has_provenance($1),\
                chat.is_authorized_pending_request_leaf($1)",
    )
    .bind(Uuid::new_v4())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(proof, (false, false));
}
