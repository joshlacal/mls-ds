//! Actual sealed own-device reads and PostgreSQL lock/FK regression.
#![cfg(all(
    feature = "chat-protocol-production-proof",
    not(feature = "server-bin")
))]
#[tokio::test]
async fn own_device_snapshots_follow_canonical_subject_lock_order() {
    let url = std::env::var("TEST_DATABASE_URL").expect("explicit local test database required");
    assert_eq!(
        url,
        "postgresql://127.0.0.1:5432/catbird_chat_protocol_test_20260722"
    );
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(6)
        .connect(&url)
        .await
        .unwrap();
    catbird_server::chat_protocol::production_proof::run_inventory_lock_order(&pool).await
        .expect("signed snapshots must avoid mutation/FK and sibling cycles while preserving revocation fencing");
}
