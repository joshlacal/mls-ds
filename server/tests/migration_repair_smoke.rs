//! Smoke test for the chore/ci-cleanup `_sqlx_migrations` version repair
//! (see `db.rs::repair_2026_04_migration_versions`).
//!
//! The test mints its own private, fully migrated database, rewrites its
//! `_sqlx_migrations` rows to the legacy `YYYYMMDD_NNN_*` version numbers, and
//! then calls `init_db` to confirm the in-binary repair maps them back to the
//! new 14-digit form before sqlx's migrator runs.
//!
//! This target used to do all of that against whatever `TEST_DATABASE_URL`
//! named. It is the sharpest case in the sweep: it does not merely *migrate* a
//! database it does not own, it deliberately **rewrites that database's
//! migration ledger** to a legacy shape and then runs the whole ~56-migration
//! legacy set over it. Pointed at the shared clean-chat database it took the
//! reviewed 13-row ledger to 69 and disabled every clean-chat suite — while
//! passing. The ledger surgery below is only sound on a database this test
//! created, so that is what it now gets.

mod common;

use catbird_server::db::{init_db, DbConfig};
use std::time::Duration;

/// Reserved per-run database prefix owned by this target.
const TEST_DB_PREFIX: &str = "mlsds_migrepair_";

#[tokio::test]
#[ignore = "requires the reviewed local Postgres target (TEST_DATABASE_URL)"]
async fn legacy_migration_versions_are_repaired_in_place() {
    // Mint and fully migrate a private database. `_database` reaps it on drop,
    // on the normal path and during panic unwind alike.
    let _database = common::fresh_db::fresh_fully_migrated_db(TEST_DB_PREFIX).await;
    let database_url = _database.url().to_owned();

    let config = DbConfig {
        database_url: database_url.clone(),
        max_connections: 4,
        min_connections: 1,
        acquire_timeout: Duration::from_secs(10),
        idle_timeout: Duration::from_secs(30),
    };

    // Connect once and rewrite any post-rename rows back to the legacy
    // versions, so the test starts from the "production DB on chore/ci-cleanup
    // first deploy" shape.
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .expect("connect to the disposable per-test database");
    sqlx::query(
        "UPDATE _sqlx_migrations SET version = 20260403, description = '001 drop read receipts' WHERE version = 20260403100000;"
    ).execute(&pool).await.unwrap();
    sqlx::query(
        "UPDATE _sqlx_migrations SET version = 20260404, description = '001 add confirmation tag' WHERE version = 20260404100000;"
    ).execute(&pool).await.unwrap();
    sqlx::query(
        "UPDATE _sqlx_migrations SET version = 20260405, description = '001 group reset support' WHERE version = 20260405100000;"
    ).execute(&pool).await.unwrap();
    sqlx::query(
        "UPDATE _sqlx_migrations SET version = 20260406, description = '001 drop message reactions' WHERE version = 20260406100000;"
    ).execute(&pool).await.unwrap();
    sqlx::query(
        "UPDATE _sqlx_migrations SET version = 20260407, description = '001 recovery failures' WHERE version = 20260407100000;"
    ).execute(&pool).await.unwrap();
    sqlx::query(
        "UPDATE _sqlx_migrations SET version = 20260418, description = '001 reset votes and epoch authenticators' WHERE version = 20260418100000;"
    ).execute(&pool).await.unwrap();
    sqlx::query(
        "UPDATE _sqlx_migrations SET version = 20260425, description = '001 messages wire epoch' WHERE version = 20260425100000;"
    ).execute(&pool).await.unwrap();
    sqlx::query(
        "UPDATE _sqlx_migrations SET version = 20260426, description = '001 reset votes failure mode' WHERE version = 20260426100000;"
    ).execute(&pool).await.unwrap();
    sqlx::query(
        "UPDATE _sqlx_migrations SET version = 20260427, description = '001 commit health columns' WHERE version = 20260427100000;"
    ).execute(&pool).await.unwrap();
    sqlx::query(
        "UPDATE _sqlx_migrations SET version = 20260428, description = '001 groupinfo 404 health columns' WHERE version = 20260428100000;"
    ).execute(&pool).await.unwrap();

    drop(pool);

    // Now: this would FAIL with "previously applied but is missing" if the
    // binary did not run the repair before invoking `sqlx::migrate!.run()`.
    init_db(config)
        .await
        .expect("init_db must succeed against a DB with legacy migration versions");

    // Verify each legacy version is now under the new 14-digit form.
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .expect("re-connect");
    let leftover: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM _sqlx_migrations \
         WHERE version BETWEEN 20260400 AND 20260499 AND version < 20260400000000",
    )
    .fetch_one(&pool)
    .await
    .expect("count legacy rows");
    assert_eq!(
        leftover.0, 0,
        "legacy YYYYMMDD versions remain in _sqlx_migrations after repair"
    );

    let new_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM _sqlx_migrations WHERE version IN (
            20260403100000, 20260404100000, 20260405100000, 20260406100000,
            20260407100000, 20260418100000, 20260425100000, 20260426100000,
            20260427100000, 20260428100000
        )",
    )
    .fetch_one(&pool)
    .await
    .expect("count new rows");
    assert_eq!(
        new_count.0, 10,
        "all 10 repaired rows present at new versions"
    );
}
