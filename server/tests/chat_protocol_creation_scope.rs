//! Signed creation must prelock enrolled siblings without adding them to MLS.
#![cfg(all(
    feature = "chat-protocol-production-proof",
    not(feature = "server-bin")
))]
mod common;

#[tokio::test]
async fn signed_creation_prelocks_siblings_without_expanding_control_delivery() {
    let (pool, _database) = common::fresh_db::fresh_proof_pool(4).await;
    catbird_server::chat_protocol::production_proof::run_creation_with_enrolled_sibling(&pool)
        .await
        .expect("creation must acquire complete event locks and retain exact leaf delivery");
}
