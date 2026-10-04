//! Authenticated inventory and signed recovery exercise the production facades.
#![cfg(all(
    feature = "chat-protocol-production-proof",
    not(feature = "server-bin")
))]
#[tokio::test]
async fn request_recovery_and_recipient_inventory_do_not_deadlock() {
    let url = std::env::var("TEST_DATABASE_URL").expect("explicit local gate required");
    assert_eq!(
        url,
        "postgresql://127.0.0.1:5432/catbird_chat_protocol_test_20260722"
    );
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    catbird_server::chat_protocol::production_proof::run_request_inventory_concurrency(&pool)
        .await
        .expect(
            "request recovery and recipient inventory must both commit without a device/head cycle",
        );
}
