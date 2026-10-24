//! Signed creation must prelock enrolled siblings without adding them to MLS.
#![cfg(all(
    feature = "chat-protocol-production-proof",
    not(feature = "server-bin")
))]
#[tokio::test]
async fn signed_creation_prelocks_siblings_without_expanding_control_delivery() {
    let url = std::env::var("TEST_DATABASE_URL").expect("explicit local test database required");
    assert_eq!(
        url,
        "postgresql://127.0.0.1:5432/catbird_chat_protocol_test_20260722"
    );
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    catbird_server::chat_protocol::production_proof::run_creation_with_enrolled_sibling(&pool)
        .await
        .expect("creation must acquire complete event locks and retain exact leaf delivery");
}
