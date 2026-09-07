//! Real signed sends against the existing owned local PostgreSQL proof database.
#![cfg(all(feature="chat-protocol-production-proof",not(feature="server-bin")))]
#[tokio::test]
async fn concurrent_actors_append_without_deadlock_or_event_chain_forks() {
    let url=std::env::var("TEST_DATABASE_URL").expect("explicit local proof database required");
    assert_eq!(url,"postgresql://127.0.0.1:5432/catbird_chat_protocol_test_20260722");
    let pool=sqlx::postgres::PgPoolOptions::new().max_connections(6).connect(&url).await.unwrap();
    catbird_server::chat_protocol::production_proof::run_concurrent_signed_sends(&pool).await.expect("concurrent signed sends must both commit with one device-global event chain");
}

#[tokio::test]
async fn stale_actor_only_scope_rejects_peer_fanout_before_append() {
    let url=std::env::var("TEST_DATABASE_URL").expect("explicit local proof database required");
    assert_eq!(url,"postgresql://127.0.0.1:5432/catbird_chat_protocol_test_20260722");
    let pool=sqlx::postgres::PgPoolOptions::new().max_connections(4).connect(&url).await.unwrap();
    catbird_server::chat_protocol::production_proof::run_unlocked_send_audience_rejected(&pool).await.expect("a newly discovered recipient cannot acquire an out-of-order lock or receive an unscoped append");
}
