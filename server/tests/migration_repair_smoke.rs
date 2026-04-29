//! Smoke test for the chore/ci-cleanup `_sqlx_migrations` version repair
//! (see `db.rs::repair_2026_04_migration_versions`).
//!
//! Requires a Postgres URL in `TEST_DATABASE_URL`. The test pre-populates a
//! migrated DB with the legacy `YYYYMMDD_NNN_*` version numbers and then
//! calls `init_db` to confirm the in-binary repair maps them to the new
//! 14-digit form before sqlx's migrator runs.
//!
//! Skipped automatically when no `TEST_DATABASE_URL` is set, so it stays
//! out of the way of contributors without a local Postgres.

use catbird_server::db::{init_db, DbConfig};
use std::time::Duration;

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing at a fully-migrated test DB"]
async fn legacy_migration_versions_are_repaired_in_place() {
    let database_url = match std::env::var("TEST_DATABASE_URL") {
        Ok(url) => url,
        Err(_) => {
            eprintln!("Skipping: TEST_DATABASE_URL not set");
            return;
        }
    };

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
        .expect("connect to TEST_DATABASE_URL");
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
