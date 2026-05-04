//! Shared test helpers for `mls-ds/server` integration tests.
//!
//! Each integration test file (`tests/*.rs`) is its own crate, so common
//! helpers must be exposed via `mod common;` + this `tests/common/mod.rs`
//! convention. Naming the file `mod.rs` (rather than `tests/common.rs`)
//! tells Cargo not to treat it as its own integration test target.
//!
//! Helpers are marked `#[allow(dead_code)]` because not every consuming
//! test file uses every helper — Rust would otherwise emit per-target
//! warnings for the unused ones.

use catbird_server::db::{init_db, DbConfig};
use sqlx::PgPool;
use std::time::Duration;

#[allow(dead_code)]
pub async fn setup_test_db() -> PgPool {
    let database_url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://localhost/catbird_test".to_string());

    let config = DbConfig {
        database_url,
        max_connections: 4,
        min_connections: 1,
        acquire_timeout: Duration::from_secs(30),
        idle_timeout: Duration::from_secs(600),
    };

    init_db(config)
        .await
        .expect("Failed to initialize test database")
}

#[allow(dead_code)]
pub async fn cleanup(pool: &PgPool, convo_id: &str) {
    let _ = sqlx::query("DELETE FROM members WHERE convo_id = $1")
        .bind(convo_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM conversations WHERE id = $1")
        .bind(convo_id)
        .execute(pool)
        .await;
}
