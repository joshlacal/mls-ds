//! Actual sealed own-device reads and PostgreSQL lock/FK regression.
#![cfg(all(
    feature = "chat-protocol-production-proof",
    not(feature = "server-bin")
))]
mod common;

#[tokio::test]
async fn own_device_snapshots_follow_canonical_subject_lock_order() {
    let (pool, _database) = common::fresh_db::fresh_proof_pool(6).await;
    catbird_server::chat_protocol::production_proof::run_inventory_lock_order(&pool).await
        .expect("signed snapshots must avoid mutation/FK and sibling cycles while preserving revocation fencing");
}
