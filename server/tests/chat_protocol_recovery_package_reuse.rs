//! Signed production-facade regression on a private, fully migrated proof database.
#![cfg(all(
    feature = "chat-protocol-production-proof",
    not(feature = "server-bin")
))]
mod common;

#[tokio::test]
async fn superseded_recovery_same_package_renewal_and_fulfillment_hydrate_complete_aggregate() {
    let (pool, _database) = common::fresh_db::fresh_proof_pool(4).await;
    catbird_server::chat_protocol::production_proof::run_superseded_recovery_package_reuse(&pool)
        .await
        .expect("same-package renewal and fulfillment must preserve superseded terminal proof");
}
#[tokio::test]
async fn cancelled_recovery_same_package_renewal_and_fulfillment_hydrate_complete_aggregate() {
    let (pool, _database) = common::fresh_db::fresh_proof_pool(4).await;
    catbird_server::chat_protocol::production_proof::run_cancelled_recovery_package_reuse(&pool)
        .await
        .expect("same-package renewal and fulfillment must preserve cancelled terminal proof");
}
