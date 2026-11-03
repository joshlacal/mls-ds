//! Real repository lock-scope proofs against a private, fully migrated proof database.
#![cfg(all(
    feature = "chat-protocol-production-proof",
    not(feature = "server-bin")
))]
mod common;

#[tokio::test]
async fn prospective_account_devices_are_locked_and_drift_rejects() {
    let (pool, _database) = common::fresh_db::fresh_proof_pool(6).await;
    catbird_server::chat_protocol::production_proof::run_control_prospective_scope_and_drift(&pool)
        .await
        .unwrap();
}
#[tokio::test]
async fn genuine_pending_welcome_recipient_remains_in_reset_scope() {
    let (pool, _database) = common::fresh_db::fresh_proof_pool(6).await;
    catbird_server::chat_protocol::production_proof::run_control_pending_welcome_scope(&pool)
        .await
        .unwrap();
}
#[tokio::test]
async fn signed_close_historical_schedule_retains_exact_recipient_scope() {
    let (pool, _database) = common::fresh_db::fresh_proof_pool(6).await;
    catbird_server::chat_protocol::production_proof::run_control_close_historical_scope(&pool)
        .await
        .unwrap();
}
