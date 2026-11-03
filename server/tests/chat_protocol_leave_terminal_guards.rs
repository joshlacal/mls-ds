//! Real signed facade regressions on private, fully migrated proof databases.
//!
//! Run with `TEST_DATABASE_URL=postgresql://127.0.0.1:5432/catbird_chat_protocol_test_20260722`
//! (the validated maintenance literal; each case mints its own `chat_proof_` database),
//! `CHAT_LEAVE_PROOF_ACCEPTING_DID` set to an opted-in test account, and:
//! `cargo test --no-default-features --features namespace-bluecatbird,chat-protocol-production-proof
//! --test chat_protocol_leave_terminal_guards -- --test-threads=1`.
//! Acceptance reads that account's public declaration and relationships through
//! the production policy collector; all fixture writes stay in the private database.
#![cfg(all(
    feature = "chat-protocol-production-proof",
    not(feature = "server-bin")
))]
mod common;

// The production-proof entrypoint additionally checks that the database is a
// local, owned `chat_proof_<32 hex>` database before any fixture write.
async fn pool() -> (sqlx::PgPool, common::fresh_db::DisposableDatabase) {
    common::fresh_db::fresh_proof_pool(4).await
}

#[tokio::test]
async fn leafless_direct_close_releases_open_recovery_reservation() {
    let (pool, _database) = pool().await;
    catbird_server::chat_protocol::production_proof::run_leafless_direct_close_with_open_recovery(
        &pool,
    )
    .await
    .expect("leafless direct close must atomically supersede reserved recovery");
}

#[tokio::test]
async fn zero_leaf_group_leave_releases_open_recovery_reservation() {
    let (pool, _database) = pool().await;
    catbird_server::chat_protocol::production_proof::run_zero_leaf_leave_with_open_recovery(&pool)
        .await
        .expect("zero-leaf leave must atomically supersede reserved recovery");
}

#[tokio::test]
async fn acceptance_releases_prior_recovery_and_preserves_own_successor_reservation() {
    let (pool, _database) = pool().await;
    catbird_server::chat_protocol::production_proof::run_acceptance_with_open_recovery(&pool)
        .await
        .expect(
            "acceptance must release prior recovery while preserving its successor reservation",
        );
}

#[tokio::test]
async fn signed_operation_expiry_distinguishes_absence_from_completed_replay() {
    let (pool, _database) = pool().await;
    catbird_server::chat_protocol::production_proof::run_signed_operation_age_fence(&pool).await
        .expect("expired absent operation must be distinguishable while completed replay preserves exact bytes");
}

#[tokio::test]
async fn removed_device_can_read_only_its_finite_terminal_controls() {
    let (pool, _database) = pool().await;
    catbird_server::chat_protocol::production_proof::run_removed_device_terminal_entry_read(&pool).await
        .expect("removed device must fetch authenticated terminal control without historical message access");
}
