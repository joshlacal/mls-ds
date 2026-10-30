//! Signed production-facade regression using only the installed local gate.
#![cfg(all(
    feature = "chat-protocol-production-proof",
    not(feature = "server-bin")
))]
async fn pool() -> sqlx::PgPool {
    let url = std::env::var("TEST_DATABASE_URL").expect("explicit local test database required");
    assert_eq!(
        url,
        "postgresql://127.0.0.1:5432/catbird_chat_protocol_test_20260722"
    );
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap()
}
#[tokio::test]
async fn superseded_recovery_same_package_renewal_and_fulfillment_hydrate_complete_aggregate() {
    catbird_server::chat_protocol::production_proof::run_superseded_recovery_package_reuse(
        &pool().await,
    )
    .await
    .expect("same-package renewal and fulfillment must preserve superseded terminal proof");
}
#[tokio::test]
async fn cancelled_recovery_same_package_renewal_and_fulfillment_hydrate_complete_aggregate() {
    catbird_server::chat_protocol::production_proof::run_cancelled_recovery_package_reuse(
        &pool().await,
    )
    .await
    .expect("same-package renewal and fulfillment must preserve cancelled terminal proof");
}
