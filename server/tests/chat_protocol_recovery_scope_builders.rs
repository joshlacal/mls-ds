//! The existing proof builders use the same complete identity prefix as the facade.
#![cfg(all(
    feature = "chat-protocol-production-proof",
    not(feature = "server-bin")
))]
mod common;

async fn ready_pool() -> (sqlx::PgPool, common::fresh_db::DisposableDatabase) {
    let (pool, database) = common::fresh_db::fresh_proof_pool(4).await;
    let suffix: String = uuid::Uuid::new_v4()
        .simple()
        .to_string()
        .chars()
        .take(24)
        .map(|c| char::from(b'a' + c.to_digit(16).unwrap() as u8))
        .collect();
    catbird_server::chat_protocol::production_proof::mint_singleton_recovery_reservation_fallback(
        &pool,
        &format!("did:plc:{suffix}"),
    )
    .await
    .expect("fresh production relationship fallback");
    (pool, database)
}
#[tokio::test]
async fn request_scope_builder_preserves_real_completion() {
    let (pool, _database) = ready_pool().await;
    catbird_server::chat_protocol::production_proof::run_request_leaf_recovery_happy_path(&pool)
        .await
        .expect("full event scope must preserve real request completion");
}
#[tokio::test]
async fn request_scope_builder_still_rejects_authority_drift_before_writes() {
    let (pool, _database) = ready_pool().await;
    catbird_server::chat_protocol::production_proof::run_request_leaf_recovery_scope_drift_negative(&pool)
        .await.expect("canonical scope authority drift must still reject before writes");
}
#[tokio::test]
async fn request_scope_builder_still_rejects_operation_claim_drift_before_writes() {
    let (pool, _database) = ready_pool().await;
    catbird_server::chat_protocol::production_proof::run_request_leaf_recovery_operation_claim_drift_negative(&pool)
        .await.expect("operation claim drift must still reject before writes");
}
