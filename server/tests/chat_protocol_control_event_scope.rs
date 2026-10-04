//! Real repository lock-scope proofs against the explicitly gated local DB.
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
        .max_connections(6)
        .connect(&url)
        .await
        .unwrap()
}
#[tokio::test]
async fn prospective_account_devices_are_locked_and_drift_rejects() {
    catbird_server::chat_protocol::production_proof::run_control_prospective_scope_and_drift(
        &pool().await,
    )
    .await
    .unwrap();
}
#[tokio::test]
async fn genuine_pending_welcome_recipient_remains_in_reset_scope() {
    catbird_server::chat_protocol::production_proof::run_control_pending_welcome_scope(
        &pool().await,
    )
    .await
    .unwrap();
}
#[tokio::test]
async fn signed_close_historical_schedule_retains_exact_recipient_scope() {
    catbird_server::chat_protocol::production_proof::run_control_close_historical_scope(
        &pool().await,
    )
    .await
    .unwrap();
}
