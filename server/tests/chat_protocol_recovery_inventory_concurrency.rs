//! Authenticated inventory and signed recovery exercise the production facades.
#![cfg(all(
    feature = "chat-protocol-production-proof",
    not(feature = "server-bin")
))]
mod common;

#[tokio::test]
async fn request_recovery_and_recipient_inventory_do_not_deadlock() {
    // The inventory projection names this DS as sequencer of local
    // conversations (`identity::service_did_base`, required since 65f33db1e);
    // production refuses to boot without it, so the proof configures it too.
    std::env::set_var("SERVICE_DID", "did:web:chat.catbird.blue");
    let (pool, _database) = common::fresh_db::fresh_proof_pool(4).await;
    catbird_server::chat_protocol::production_proof::run_request_inventory_concurrency(&pool)
        .await
        .expect(
            "request recovery and recipient inventory must both commit without a device/head cycle",
        );
}
