use sqlx::{
    migrate::{Migration, MigrationType, Migrator},
    postgres::PgPoolOptions,
    PgPool,
};
use std::borrow::Cow;

#[path = "direct_request_migrations.rs"]
mod direct_request_migrations;

pub async fn setup() -> PgPool {
    let url = std::env::var("REQUEST_TEST_DATABASE_URL")
        .expect("explicit REQUEST_TEST_DATABASE_URL required");
    assert_eq!(
        url, "postgresql://127.0.0.1:5432/catbird_direct_requests_test_20260919",
        "refusing non-dedicated local DB"
    );
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .expect("connect dedicated request DB");
    let (name,user,owner,host):(String,String,String,Option<String>)=sqlx::query_as("SELECT current_database(),current_user,pg_get_userbyid(datdba),host(inet_server_addr()) FROM pg_database WHERE datname=current_database()")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(name, "catbird_direct_requests_test_20260919");
    assert_eq!(user, owner);
    assert_eq!(host.as_deref(), Some("127.0.0.1"));
    direct_request_migrations::assert_current_migration_frontier(std::path::Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/migrations"
    )));
    // Both harnesses install and validate the same complete reviewed ledger.
    // A server-only prefix made e2e -> server fail with VersionMissing.
    use sha2::Digest as _;
    let migrations: Vec<_> = direct_request_migrations::reviewed_migrations()
        .map(|entry| {
            assert_eq!(
                format!("{:x}", sha2::Sha384::digest(entry.sql.as_bytes())),
                entry.reviewed_sha384,
                "reviewed migration checksum drift for {}",
                entry.filename
            );
            Migration::new(
                entry.version,
                Cow::Borrowed(entry.description),
                MigrationType::Simple,
                Cow::Borrowed(entry.sql),
            )
        })
        .collect();
    assert!(migrations
        .windows(2)
        .all(|pair| pair[0].version < pair[1].version));
    let migrator = Migrator {
        migrations: Cow::Owned(migrations),
        ignore_missing: false,
        locking: true,
    };
    let mut connection = pool.acquire().await.unwrap();
    sqlx::query("SELECT pg_advisory_lock(hashtext('direct_request_database_setup'))")
        .execute(&mut *connection)
        .await
        .unwrap();
    sqlx::query("SET chat.operation_claim_activation_approved='handlers-and-legacy-apis-sealed'")
        .execute(&mut *connection)
        .await
        .unwrap();
    sqlx::raw_sql(direct_request_migrations::FEDERATION_CACHE_SCHEMA)
        .execute(&mut *connection)
        .await
        .expect("install reviewed federation-cache prerequisite");
    let migrate_result = migrator.run_direct(&mut *connection).await;
    let _ = sqlx::query("RESET chat.operation_claim_activation_approved")
        .execute(&mut *connection)
        .await;
    let _ = sqlx::query("SELECT pg_advisory_unlock(hashtext('direct_request_database_setup'))")
        .execute(&mut *connection)
        .await;
    migrate_result.expect("apply reviewed additive migration on guarded local DB");
    drop(connection);
    let inventory_gc_contract: (bool, bool) = sqlx::query_as(
        "SELECT position('device_inventory_items' in immutable.prosrc)>0 AND position('session_replication_role' in immutable.prosrc)=0, count(gc.oid)=2 AND bool_and(position('session_replication_role' in gc.prosrc)=0) FROM pg_proc immutable JOIN pg_namespace immutable_ns ON immutable_ns.oid=immutable.pronamespace LEFT JOIN pg_proc gc ON gc.pronamespace=immutable.pronamespace AND gc.proname IN ('gc_expired_inventory_sessions','gc_expired_device_inventory_sessions') WHERE immutable_ns.nspname='chat' AND immutable.proname='enforce_immutable_identity' GROUP BY immutable.prosrc",
    )
    .fetch_one(&pool)
    .await
    .expect("read inventory GC contract");
    assert_eq!(inventory_gc_contract, (true, true));
    pool
}
