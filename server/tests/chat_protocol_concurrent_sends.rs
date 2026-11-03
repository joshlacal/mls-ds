//! Real signed sends against a private, fully migrated proof database.
#![cfg(all(
    feature = "chat-protocol-production-proof",
    not(feature = "server-bin")
))]
mod common;

#[tokio::test]
async fn concurrent_actors_append_without_deadlock_or_event_chain_forks() {
    let (pool, _database) = common::fresh_db::fresh_proof_pool(6).await;
    catbird_server::chat_protocol::production_proof::run_concurrent_signed_sends(&pool)
        .await
        .expect("concurrent signed sends must both commit with one device-global event chain");
}

#[tokio::test]
async fn stale_actor_only_scope_rejects_peer_fanout_before_append() {
    let (pool, _database) = common::fresh_db::fresh_proof_pool(4).await;
    catbird_server::chat_protocol::production_proof::run_unlocked_send_audience_rejected(&pool).await.expect("a newly discovered recipient cannot acquire an out-of-order lock or receive an unscoped append");
}
