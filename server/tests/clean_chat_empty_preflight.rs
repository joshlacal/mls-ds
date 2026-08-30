//! Integration tests for Clean Chat zero-state preflight gate.
//!
//! Tests both pre-cutover (75 migrations, max 20260824000001) and
//! post-migration (84 migrations, max 20260828000005) modes against disposable
//! PostgreSQL databases.
//!
//! Verifies:
//!   - GREEN exact pre-cutover and post-migration modes.
//!   - Strict read-only verification (explicit READ ONLY transaction, zero mutations, row snapshots preserved).
//!   - GREEN on legacy non-UUID rows in public transport tables.
//!   - RED on infrastructure anomalies and NULL drift.
//!   - RED on dirty semantic tables: devices (independently without principal), key_packages,
//!     generation_states, relationship_projection_relationships, relationship_projection_declarations,
//!     transitions, entries, welcome_bundles, outbox, conversations, federation_delivery_receipts.
//!   - RED on migration catalog / checksum / dirty / count drift.
//!   - RED on unexpected or missing tables / views in chat schema.
//!   - RED on Clean Chat lowercase UUIDv4 rows in federation_outbox, outbound_queue,
//!     federation_sync_state across all reachable statuses in both post-migration and pre-cutover modes.
//!   - RED on missing public transport tables, missing identifier columns, or non-text-compatible column types.

mod common;

use common::fresh_db::{DisposableDatabase, SHARED_LEGACY_DB_PREFIX};
use sqlx::error::BoxDynError;
use sqlx::migrate::{Migration, MigrationSource, Migrator};
use sqlx::PgPool;
use uuid::Uuid;

const PREFLIGHT_SQL: &str = include_str!("../scripts/assert_clean_chat_empty.sql");
const CURSOR_KEY_ID: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// Apply `migrator` to a fresh disposable database, then initialize the infrastructure rows
/// the preflight requires: the protocol singleton and its bound zero-floor retention row.
async fn setup_db(migrator: Migrator) -> (PgPool, DisposableDatabase) {
    let _migration_guard = common::fresh_db::acquire_migration_lock().await;
    let database = DisposableDatabase::mint(SHARED_LEGACY_DB_PREFIX).await;
    let pool = database.connect(5).await;
    let mut conn = pool
        .acquire()
        .await
        .expect("acquire connection for migration");

    sqlx::query("SET chat.operation_claim_activation_approved = 'handlers-and-legacy-apis-sealed'")
        .execute(&mut *conn)
        .await
        .expect("authorize operation claim activation");

    migrator
        .run_direct(&mut *conn)
        .await
        .expect("apply migrations");

    sqlx::query("RESET chat.operation_claim_activation_approved")
        .execute(&mut *conn)
        .await
        .expect("reset activation");

    let protocol_instance_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO chat.protocol_instances (singleton, protocol_version, protocol_instance_id, cursor_key_id)
         VALUES (TRUE, '1', $1, $2)",
    )
    .bind(protocol_instance_id)
    .bind(CURSOR_KEY_ID)
    .execute(&mut *conn)
    .await
    .expect("insert protocol instance singleton");

    sqlx::query(
        "INSERT INTO chat.event_retention (protocol_instance_id, retained_floor, updated_at)
         VALUES ($1, 0, clock_timestamp())",
    )
    .bind(protocol_instance_id)
    .execute(&mut *conn)
    .await
    .expect("insert event retention row");

    (pool, database)
}

#[derive(Debug)]
struct MigrationSliceSource(Vec<Migration>);

impl<'s> MigrationSource<'s> for MigrationSliceSource {
    fn resolve(self) -> futures::future::BoxFuture<'s, Result<Vec<Migration>, BoxDynError>> {
        Box::pin(async move { Ok(self.0) })
    }
}

/// Set up a disposable database with pre-cutover migrations (75 migrations up to 20260824000001).
async fn setup_pre_cutover_db() -> (PgPool, DisposableDatabase) {
    let full_migrator = sqlx::migrate!("./migrations");
    let pre_cutover_entries: Vec<Migration> = full_migrator
        .migrations
        .iter()
        .filter(|m| m.version <= 20260824000001)
        .cloned()
        .collect();
    assert_eq!(
        pre_cutover_entries.len(),
        75,
        "pre-cutover catalog must contain exactly 75 migrations"
    );
    let migrator = Migrator::new(MigrationSliceSource(pre_cutover_entries))
        .await
        .expect("build pre-cutover migrator");

    setup_db(migrator).await
}

/// Set up a disposable database with post-migration migrations (all 84 migrations).
async fn setup_post_migration_db() -> (PgPool, DisposableDatabase) {
    let migrator = sqlx::migrate!("./migrations");
    assert_eq!(
        migrator.migrations.len(),
        84,
        "post-migration catalog must contain exactly 84 migrations"
    );
    setup_db(migrator).await
}

/// Execute the preflight SQL gate.
async fn run_preflight(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::raw_sql(PREFLIGHT_SQL).execute(pool).await.map(|_| ())
}

/// Insert one row into `chat.<table_name>` by unbinding its triggers and constraints, then
/// assert the preflight rejects that table as dirty.
async fn assert_dirty_semantic_table_rejected(pool: &PgPool, table_name: &str, insert_sql: &str) {
    let unbind_sql = format!(
        "DO $$
        DECLARE
            r RECORD;
        BEGIN
            FOR r IN (SELECT tgname FROM pg_trigger WHERE tgrelid = 'chat.{table_name}'::regclass AND NOT tgisinternal) LOOP
                EXECUTE format('DROP TRIGGER IF EXISTS %I ON chat.{table_name} CASCADE', r.tgname);
            END LOOP;
            FOR r IN (SELECT conname FROM pg_constraint WHERE conrelid = 'chat.{table_name}'::regclass) LOOP
                EXECUTE format('ALTER TABLE chat.{table_name} DROP CONSTRAINT IF EXISTS %I CASCADE', r.conname);
            END LOOP;
        END $$;"
    );
    sqlx::raw_sql(&unbind_sql)
        .execute(pool)
        .await
        .expect("unbind triggers and constraints");
    sqlx::raw_sql(insert_sql)
        .execute(pool)
        .await
        .expect("insert dirty row into semantic table");

    let err = run_preflight(pool)
        .await
        .expect_err(&format!("preflight must fail on dirty {table_name} table"));
    assert!(
        err.to_string()
            .contains(&format!("semantic table chat.{table_name} is dirty")),
        "unexpected error: {err}"
    );
}

// =============================================================================
// Positive / GREEN Tests
// =============================================================================

#[tokio::test]
async fn test_preflight_passes_on_pristine_pre_cutover_database() {
    let (pool, _db) = setup_pre_cutover_db().await;
    let result = run_preflight(&pool).await;
    assert!(
        result.is_ok(),
        "preflight must pass on pristine pre-cutover database: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_preflight_passes_on_pristine_post_migration_database() {
    let (pool, _db) = setup_post_migration_db().await;
    let result = run_preflight(&pool).await;
    assert!(
        result.is_ok(),
        "preflight must pass on pristine post-migration database: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_preflight_is_strictly_read_only_and_preserves_database_state() {
    let (pool, _db) = setup_post_migration_db().await;

    // Seed legacy non-UUID transport rows so data tables have rows to preserve
    sqlx::query(
        "INSERT INTO public.federation_outbox (id, conversation_id, target_service_did, payload, status)
         VALUES ('outbox-ro-1', 'legacy-convo-read-only', 'did:web:target.example.com', decode('', 'hex'), 'pending')
         ON CONFLICT (id) DO NOTHING;",
    )
    .execute(&pool)
    .await
    .expect("insert legacy federation_outbox row");

    sqlx::query(
        "INSERT INTO public.outbound_queue (id, target_ds_did, target_endpoint, method, payload, convo_id, status)
         VALUES ('queue-ro-1', 'did:web:ds.example.com', 'https://ds.example.com', 'deliverMessage', decode('', 'hex'), 'legacy-convo-read-only', 'delivered')
         ON CONFLICT (id) DO NOTHING;",
    )
    .execute(&pool)
    .await
    .expect("insert legacy outbound_queue row");

    sqlx::query(
        "INSERT INTO public.federation_sync_state (convo_id, sequencer_ds_did, status)
         VALUES ('legacy-convo-read-only', 'did:web:example.com', 'healthy')
         ON CONFLICT (convo_id, sequencer_ds_did) DO NOTHING;",
    )
    .execute(&pool)
    .await
    .expect("insert legacy federation_sync_state row");

    // Snapshot migration ledger
    let ledger_before: Vec<(i64, String, bool, Vec<u8>)> = sqlx::query_as(
        "SELECT version, description, success, checksum FROM public._sqlx_migrations ORDER BY version",
    )
    .fetch_all(&pool)
    .await
    .expect("read ledger before");
    // Snapshot table list in chat schema
    let tables_before: Vec<(String, String)> = sqlx::query_as(
        "SELECT c.relname, c.relkind::text
         FROM pg_catalog.pg_class c
         JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'chat' AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
         ORDER BY c.relname",
    )
    .fetch_all(&pool)
    .await
    .expect("read tables before");

    // Snapshot infrastructure tables
    let proto_before: Vec<(bool, String, Uuid, String)> = sqlx::query_as(
        "SELECT singleton, protocol_version, protocol_instance_id, cursor_key_id FROM chat.protocol_instances",
    )
    .fetch_all(&pool)
    .await
    .expect("read protocol instances before");

    let retention_before: Vec<(Uuid, i64)> =
        sqlx::query_as("SELECT protocol_instance_id, retained_floor FROM chat.event_retention")
            .fetch_all(&pool)
            .await
            .expect("read event retention before");

    let completeness_before: Vec<(bool, i64)> = sqlx::query_as(
        "SELECT singleton, legacy_receipt_count FROM chat.operation_claim_completeness_cutover",
    )
    .fetch_all(&pool)
    .await
    .expect("read completeness before");

    // Snapshot public transport tables
    let outbox_before: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT id, conversation_id, status FROM public.federation_outbox ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .expect("read federation_outbox before");

    let queue_before: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT id, target_ds_did, convo_id, status FROM public.outbound_queue ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .expect("read outbound_queue before");

    let sync_state_before: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT convo_id, sequencer_ds_did, status FROM public.federation_sync_state ORDER BY convo_id",
    )
    .fetch_all(&pool)
    .await
    .expect("read federation_sync_state before");

    // Execute preflight through one acquired connection in an explicit PostgreSQL READ ONLY transaction
    let mut conn = pool
        .acquire()
        .await
        .expect("acquire connection for read-only preflight execution");

    sqlx::raw_sql("BEGIN TRANSACTION READ ONLY;")
        .execute(&mut *conn)
        .await
        .expect("begin read-only transaction");

    sqlx::raw_sql(PREFLIGHT_SQL)
        .execute(&mut *conn)
        .await
        .expect("execute preflight in read-only transaction");

    sqlx::raw_sql("COMMIT;")
        .execute(&mut *conn)
        .await
        .expect("commit read-only transaction");

    drop(conn);

    // Verify migration ledger unchanged
    let ledger_after: Vec<(i64, String, bool, Vec<u8>)> = sqlx::query_as(
        "SELECT version, description, success, checksum FROM public._sqlx_migrations ORDER BY version",
    )
    .fetch_all(&pool)
    .await
    .expect("read ledger after");
    assert_eq!(
        ledger_before, ledger_after,
        "migration ledger must be byte-for-byte unchanged"
    );

    // Verify chat relations unchanged
    let tables_after: Vec<(String, String)> = sqlx::query_as(
        "SELECT c.relname, c.relkind::text
         FROM pg_catalog.pg_class c
         JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'chat' AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
         ORDER BY c.relname",
    )
    .fetch_all(&pool)
    .await
    .expect("read tables after");
    assert_eq!(
        tables_before, tables_after,
        "relations in chat schema must be unchanged"
    );

    // Verify infrastructure unchanged
    let proto_after: Vec<(bool, String, Uuid, String)> = sqlx::query_as(
        "SELECT singleton, protocol_version, protocol_instance_id, cursor_key_id FROM chat.protocol_instances",
    )
    .fetch_all(&pool)
    .await
    .expect("read protocol instances after");
    assert_eq!(
        proto_before, proto_after,
        "protocol_instances must be unchanged"
    );

    let retention_after: Vec<(Uuid, i64)> =
        sqlx::query_as("SELECT protocol_instance_id, retained_floor FROM chat.event_retention")
            .fetch_all(&pool)
            .await
            .expect("read event retention after");
    assert_eq!(
        retention_before, retention_after,
        "event_retention must be unchanged"
    );

    let completeness_after: Vec<(bool, i64)> = sqlx::query_as(
        "SELECT singleton, legacy_receipt_count FROM chat.operation_claim_completeness_cutover",
    )
    .fetch_all(&pool)
    .await
    .expect("read completeness after");
    assert_eq!(
        completeness_before, completeness_after,
        "operation_claim_completeness_cutover must be unchanged"
    );

    // Verify public transport rows unchanged
    let outbox_after: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT id, conversation_id, status FROM public.federation_outbox ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .expect("read federation_outbox after");
    assert_eq!(
        outbox_before, outbox_after,
        "federation_outbox rows must be unchanged"
    );

    let queue_after: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT id, target_ds_did, convo_id, status FROM public.outbound_queue ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .expect("read outbound_queue after");
    assert_eq!(
        queue_before, queue_after,
        "outbound_queue rows must be unchanged"
    );

    let sync_state_after: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT convo_id, sequencer_ds_did, status FROM public.federation_sync_state ORDER BY convo_id",
    )
    .fetch_all(&pool)
    .await
    .expect("read federation_sync_state after");
    assert_eq!(
        sync_state_before, sync_state_after,
        "federation_sync_state rows must be unchanged"
    );
}

#[tokio::test]
async fn test_preflight_allows_legacy_non_uuid_rows_in_public_transport_tables() {
    let (pool, _db) = setup_post_migration_db().await;

    // Seed non-UUID legacy rows
    sqlx::query(
        "INSERT INTO public.federation_outbox (id, conversation_id, target_service_did, payload, status)
         VALUES ('outbox-1', 'legacy-convo-id-12345', 'did:web:target.example.com', decode('', 'hex'), 'pending'),
                ('outbox-2', 'not_a_uuid_at_all', 'did:web:target.example.com', decode('', 'hex'), 'done')
         ON CONFLICT (id) DO NOTHING;",
    )
    .execute(&pool)
    .await
    .expect("insert legacy federation_outbox rows");

    sqlx::query(
        "INSERT INTO public.outbound_queue (id, target_ds_did, target_endpoint, method, payload, convo_id, status)
         VALUES ('queue-1', 'did:web:ds.example.com', 'https://ds.example.com', 'deliverMessage', decode('', 'hex'), 'legacy-convo-999', 'delivered'),
                ('queue-2', 'did:web:ds.example.com', 'https://ds.example.com', 'deliverMessage', decode('', 'hex'), 'convo_legacy_group', 'dead')
         ON CONFLICT (id) DO NOTHING;",
    )
    .execute(&pool)
    .await
    .expect("insert legacy outbound_queue rows");

    sqlx::query(
        "INSERT INTO public.federation_sync_state (convo_id, sequencer_ds_did, status)
         VALUES ('legacy-convo-sync-1', 'did:web:example.com', 'healthy')
         ON CONFLICT (convo_id, sequencer_ds_did) DO NOTHING;",
    )
    .execute(&pool)
    .await
    .expect("insert legacy federation_sync_state rows");
    let result = run_preflight(&pool).await;
    assert!(
        result.is_ok(),
        "preflight must pass when public transport tables have only non-UUID rows: {:?}",
        result.err()
    );
}

// =============================================================================
// Negative / RED Tests: Infrastructure Anomalies and NULL Drift
// =============================================================================

#[tokio::test]
async fn test_preflight_fails_when_protocol_singleton_is_missing() {
    let (pool, _db) = setup_post_migration_db().await;
    sqlx::query("ALTER TABLE chat.event_retention DISABLE TRIGGER ALL;")
        .execute(&pool)
        .await
        .expect("disable retention trigger");
    sqlx::query("DELETE FROM chat.event_retention;")
        .execute(&pool)
        .await
        .expect("delete event retention");
    sqlx::query(
        "ALTER TABLE chat.protocol_instances DISABLE TRIGGER protocol_instances_immutable;",
    )
    .execute(&pool)
    .await
    .expect("disable trigger");
    sqlx::query("DELETE FROM chat.protocol_instances;")
        .execute(&pool)
        .await
        .expect("delete protocol singleton");
    sqlx::query("ALTER TABLE chat.protocol_instances ENABLE TRIGGER protocol_instances_immutable;")
        .execute(&pool)
        .await
        .expect("enable trigger");

    let result = run_preflight(&pool).await;
    let err = result.expect_err("preflight must fail when protocol singleton is missing");
    assert!(
        err.to_string()
            .contains("chat.protocol_instances must contain exactly 1 row"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn test_preflight_fails_when_protocol_version_is_not_v1() {
    let (pool, _db) = setup_post_migration_db().await;
    sqlx::query(
        "ALTER TABLE chat.protocol_instances DISABLE TRIGGER protocol_instances_immutable;",
    )
    .execute(&pool)
    .await
    .expect("disable trigger");
    sqlx::query("ALTER TABLE chat.protocol_instances DROP CONSTRAINT protocol_instances_protocol_version_check;")
        .execute(&pool)
        .await
        .expect("drop check");
    sqlx::query("UPDATE chat.protocol_instances SET protocol_version = '2';")
        .execute(&pool)
        .await
        .expect("update version");

    let result = run_preflight(&pool).await;
    let err = result.expect_err("preflight must fail when protocol_version is not '1'");
    assert!(
        err.to_string().contains("protocol_version must be '1'"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn test_preflight_fails_when_protocol_version_is_null() {
    let (pool, _db) = setup_post_migration_db().await;
    sqlx::query(
        "ALTER TABLE chat.protocol_instances DISABLE TRIGGER protocol_instances_immutable;",
    )
    .execute(&pool)
    .await
    .expect("disable trigger");
    sqlx::query("ALTER TABLE chat.protocol_instances DROP CONSTRAINT IF EXISTS protocol_instances_protocol_version_check;")
        .execute(&pool)
        .await
        .expect("drop check");
    sqlx::query("ALTER TABLE chat.protocol_instances ALTER COLUMN protocol_version DROP NOT NULL;")
        .execute(&pool)
        .await
        .expect("drop not null");
    sqlx::query("UPDATE chat.protocol_instances SET protocol_version = NULL;")
        .execute(&pool)
        .await
        .expect("update version to null");

    let result = run_preflight(&pool).await;
    let err = result.expect_err("preflight must fail when protocol_version is NULL");
    assert!(
        err.to_string().contains("protocol_version must be '1'"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn test_preflight_fails_when_event_retention_floor_is_nonzero() {
    let (pool, _db) = setup_post_migration_db().await;
    sqlx::query(
        "ALTER TABLE chat.event_retention DISABLE TRIGGER event_retention_identity_immutable;",
    )
    .execute(&pool)
    .await
    .expect("disable trigger");
    sqlx::query(
        "ALTER TABLE chat.event_retention DISABLE TRIGGER event_retention_lifecycle_monotonic;",
    )
    .execute(&pool)
    .await
    .expect("disable monotonic trigger");
    sqlx::query("UPDATE chat.event_retention SET retained_floor = 100;")
        .execute(&pool)
        .await
        .expect("update floor");

    let result = run_preflight(&pool).await;
    let err = result.expect_err("preflight must fail when retained_floor is nonzero");
    assert!(
        err.to_string().contains("retained_floor must be 0"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn test_preflight_fails_when_event_retention_floor_is_null() {
    let (pool, _db) = setup_post_migration_db().await;
    sqlx::query(
        "ALTER TABLE chat.event_retention DISABLE TRIGGER event_retention_identity_immutable;",
    )
    .execute(&pool)
    .await
    .expect("disable trigger");
    sqlx::query(
        "ALTER TABLE chat.event_retention DISABLE TRIGGER event_retention_lifecycle_monotonic;",
    )
    .execute(&pool)
    .await
    .expect("disable monotonic trigger");
    sqlx::query("ALTER TABLE chat.event_retention ALTER COLUMN retained_floor DROP NOT NULL;")
        .execute(&pool)
        .await
        .expect("drop not null");
    sqlx::query("UPDATE chat.event_retention SET retained_floor = NULL;")
        .execute(&pool)
        .await
        .expect("update floor to null");

    let result = run_preflight(&pool).await;
    let err = result.expect_err("preflight must fail when retained_floor is NULL");
    assert!(
        err.to_string().contains("retained_floor must be 0"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn test_preflight_fails_when_event_retention_is_unlinked() {
    let (pool, _db) = setup_post_migration_db().await;
    sqlx::query(
        "ALTER TABLE chat.event_retention DISABLE TRIGGER event_retention_identity_immutable;",
    )
    .execute(&pool)
    .await
    .expect("disable trigger");
    sqlx::query("ALTER TABLE chat.event_retention DROP CONSTRAINT event_retention_instance_fk;")
        .execute(&pool)
        .await
        .expect("drop fk");
    let unlinked_id = Uuid::new_v4();
    sqlx::query("UPDATE chat.event_retention SET protocol_instance_id = $1;")
        .bind(unlinked_id)
        .execute(&pool)
        .await
        .expect("update unlinked id");

    let result = run_preflight(&pool).await;
    let err = result.expect_err("preflight must fail when event_retention is unlinked");
    assert!(
        err.to_string()
            .contains("does not match chat.protocol_instances singleton"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn test_preflight_fails_when_event_retention_instance_id_is_null() {
    let (pool, _db) = setup_post_migration_db().await;
    sqlx::query("ALTER TABLE chat.event_retention DISABLE TRIGGER ALL;")
        .execute(&pool)
        .await
        .expect("disable trigger");
    sqlx::query(
        "ALTER TABLE chat.event_retention DROP CONSTRAINT IF EXISTS event_retention_pkey CASCADE;",
    )
    .execute(&pool)
    .await
    .expect("drop pkey");
    sqlx::query("ALTER TABLE chat.event_retention DROP CONSTRAINT IF EXISTS event_retention_instance_fk CASCADE;")
        .execute(&pool)
        .await
        .expect("drop fk");
    sqlx::query(
        "ALTER TABLE chat.event_retention ALTER COLUMN protocol_instance_id DROP NOT NULL;",
    )
    .execute(&pool)
    .await
    .expect("drop not null");
    sqlx::query("UPDATE chat.event_retention SET protocol_instance_id = NULL;")
        .execute(&pool)
        .await
        .expect("update instance id to null");

    let result = run_preflight(&pool).await;
    let err =
        result.expect_err("preflight must fail when event_retention protocol_instance_id is NULL");
    assert!(
        err.to_string()
            .contains("does not match chat.protocol_instances singleton"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn test_preflight_fails_when_completeness_cutover_has_nonzero_receipts() {
    let (pool, _db) = setup_post_migration_db().await;
    sqlx::query("ALTER TABLE chat.operation_claim_completeness_cutover DISABLE TRIGGER operation_claim_completeness_cutover_immutable;")
        .execute(&pool)
        .await
        .expect("disable trigger");
    sqlx::query("UPDATE chat.operation_claim_completeness_cutover SET legacy_receipt_count = 5;")
        .execute(&pool)
        .await
        .expect("update legacy count");

    let result = run_preflight(&pool).await;
    let err = result.expect_err("preflight must fail when legacy_receipt_count is nonzero");
    assert!(
        err.to_string().contains("legacy_receipt_count must be 0"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn test_preflight_fails_when_completeness_cutover_legacy_receipt_count_is_null() {
    let (pool, _db) = setup_post_migration_db().await;
    sqlx::query("ALTER TABLE chat.operation_claim_completeness_cutover DISABLE TRIGGER operation_claim_completeness_cutover_immutable;")
        .execute(&pool)
        .await
        .expect("disable trigger");
    sqlx::query("ALTER TABLE chat.operation_claim_completeness_cutover ALTER COLUMN legacy_receipt_count DROP NOT NULL;")
        .execute(&pool)
        .await
        .expect("drop not null");
    sqlx::query(
        "UPDATE chat.operation_claim_completeness_cutover SET legacy_receipt_count = NULL;",
    )
    .execute(&pool)
    .await
    .expect("update legacy count to null");

    let result = run_preflight(&pool).await;
    let err = result.expect_err("preflight must fail when legacy_receipt_count is NULL");
    assert!(
        err.to_string().contains("legacy_receipt_count must be 0"),
        "unexpected error: {err}"
    );
}

// =============================================================================
// Negative / RED Tests: Dirty Semantic Tables (Explicit Step 1 Set)
// =============================================================================

#[tokio::test]
async fn test_preflight_fails_when_devices_table_is_dirty() {
    let (pool, _db) = setup_post_migration_db().await;
    let dev_id = Uuid::new_v4();

    // Insert ONLY into chat.devices without any principal row (unbinding constraints/triggers)
    let insert_sql = format!(
        "INSERT INTO chat.devices (user_did, device_id, device_name, status, dpop_jkt, auth_generation, capabilities, created_at, updated_at)
         VALUES ('did:web:alice.example.com', '{dev_id}', 'phone', 'active', '{cursor_key}', 1, chat.protocol_capabilities(), clock_timestamp(), clock_timestamp());",
        cursor_key = CURSOR_KEY_ID
    );

    assert_dirty_semantic_table_rejected(&pool, "devices", &insert_sql).await;
}

#[tokio::test]
async fn test_preflight_fails_when_key_packages_table_is_dirty() {
    let (pool, _db) = setup_post_migration_db().await;
    let insert_sql = format!(
        "INSERT INTO chat.key_packages (
            key_package_ref, wrapper_bytes, wrapper_sha256, init_key,
            owner_did, owner_device_id, owner_key_id, owner_auth_generation,
            not_before, not_after, status, created_at
        ) VALUES (
            decode('0000000000000000000000000000000000000000000000000000000000000000', 'hex'),
            decode('0102030405060708', 'hex'),
            decode('0000000000000000000000000000000000000000000000000000000000000000', 'hex'),
            decode('0102', 'hex'),
            'did:web:alice.example.com',
            '{dev_id}',
            '{cursor_key}',
            1,
            clock_timestamp(),
            clock_timestamp() + interval '1 hour',
            'available',
            clock_timestamp()
        );",
        dev_id = Uuid::new_v4(),
        cursor_key = CURSOR_KEY_ID
    );

    assert_dirty_semantic_table_rejected(&pool, "key_packages", &insert_sql).await;
}

#[tokio::test]
async fn test_preflight_fails_when_generation_states_table_is_dirty() {
    let (pool, _db) = setup_post_migration_db().await;
    let insert_sql = format!(
        "INSERT INTO chat.generation_states (
            conversation_id, generation, state_version, group_id, epoch,
            group_context_hash, confirmation_tag, lifecycle, state_kind,
            producing_transition_id, public_snapshot_bytes, snapshot_sha256,
            tree_summary_bytes, tree_summary_sha256, leaf_count, created_at
        ) VALUES (
            '{convo_id}', 1, 1,
            decode('0000000000000000000000000000000000000000000000000000000000000000', 'hex'), 1,
            decode('0000000000000000000000000000000000000000000000000000000000000000', 'hex'),
            decode('0000000000000000000000000000000000000000000000000000000000000000', 'hex'),
            'active', 'full',
            '{trans_id}',
            decode('0102', 'hex'),
            decode('0000000000000000000000000000000000000000000000000000000000000000', 'hex'),
            decode('0102', 'hex'),
            decode('0000000000000000000000000000000000000000000000000000000000000000', 'hex'),
            1, clock_timestamp()
        );",
        convo_id = Uuid::new_v4(),
        trans_id = Uuid::new_v4()
    );

    assert_dirty_semantic_table_rejected(&pool, "generation_states", &insert_sql).await;
}

#[tokio::test]
async fn test_preflight_fails_when_relationship_projection_relationships_table_is_dirty() {
    let (pool, _db) = setup_post_migration_db().await;
    let insert_sql = format!(
        "INSERT INTO chat.relationship_projection_relationships (
            projection_id, actor_did, other_did, blocking, blocked_by, blocking_by_list,
            blocked_by_list, following, followed_by, batch_ordinal, fetch_revision,
            request_digest, response_digest, evidence_kind, fetched_at
        ) VALUES (
            '{proj_id}', 'did:web:alice.example.com', 'did:web:bob.example.com', false, false, false,
            false, false, false, 0, 1,
            decode('0000000000000000000000000000000000000000000000000000000000000000', 'hex'),
            decode('0000000000000000000000000000000000000000000000000000000000000000', 'hex'),
            'live', clock_timestamp()
        );",
        proj_id = Uuid::new_v4()
    );

    assert_dirty_semantic_table_rejected(
        &pool,
        "relationship_projection_relationships",
        &insert_sql,
    )
    .await;
}

#[tokio::test]
async fn test_preflight_fails_when_relationship_projection_declarations_table_is_dirty() {
    let (pool, _db) = setup_post_migration_db().await;
    let insert_sql = format!(
        "INSERT INTO chat.relationship_projection_declarations (
            projection_id, recipient_did, resolved_pds_origin, service_id, fetch_revision,
            did_request_digest, did_document_digest, record_request_digest, record_response_digest,
            record_evidence_kind, incoming_policy, resolved_group_policy, evidence_kind, fetched_at
        ) VALUES (
            '{proj_id}', 'did:web:alice.example.com', 'https://pds.example.com', '#atproto_pds', 1,
            decode('0000000000000000000000000000000000000000000000000000000000000000', 'hex'),
            decode('0000000000000000000000000000000000000000000000000000000000000000', 'hex'),
            decode('0000000000000000000000000000000000000000000000000000000000000000', 'hex'),
            decode('0000000000000000000000000000000000000000000000000000000000000000', 'hex'),
            'live', 'allow', 'allow', 'live', clock_timestamp()
        );",
        proj_id = Uuid::new_v4()
    );

    assert_dirty_semantic_table_rejected(
        &pool,
        "relationship_projection_declarations",
        &insert_sql,
    )
    .await;
}

#[tokio::test]
async fn test_preflight_fails_when_transitions_table_is_dirty() {
    let (pool, _db) = setup_post_migration_db().await;
    let insert_sql = format!(
        "INSERT INTO chat.transitions (
            transition_id, conversation_id, kind, actor_did, actor_device_id,
            actor_key_id, actor_auth_generation, actor_role, actor_device_status,
            signed_request_bytes, unsigned_projection_bytes, signing_transcript_bytes,
            request_digest, signature, entry_seq, accepted_at
        ) VALUES (
            '{trans_id}', '{convo_id}', 'creation', 'did:web:alice.example.com', '{dev_id}',
            '{cursor_key}', 1, 'creator', 'active',
            decode('0102', 'hex'), decode('0102', 'hex'), decode('0102', 'hex'),
            decode('0000000000000000000000000000000000000000000000000000000000000000', 'hex'),
            decode('00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'hex'),
            1, clock_timestamp()
        );",
        trans_id = Uuid::new_v4(),
        convo_id = Uuid::new_v4(),
        dev_id = Uuid::new_v4(),
        cursor_key = CURSOR_KEY_ID
    );

    assert_dirty_semantic_table_rejected(&pool, "transitions", &insert_sql).await;
}

#[tokio::test]
async fn test_preflight_fails_when_entries_table_is_dirty() {
    let (pool, _db) = setup_post_migration_db().await;
    let insert_sql = format!(
        "INSERT INTO chat.entries (
            conversation_id, seq, entry_id, entry_kind,
            accepted_payload_bytes, accepted_payload_sha256, signed_request_bytes,
            request_digest, signature, server_fields_bytes, outer_entry_fingerprint,
            actor_did, actor_device_id, actor_key_id, actor_auth_generation, received_at
        ) VALUES (
            '{convo_id}', 1, '{entry_id}', 'blue.catbird.chat.defs#applicationEntry',
            decode('0102', 'hex'),
            decode('0000000000000000000000000000000000000000000000000000000000000000', 'hex'),
            decode('0102', 'hex'),
            decode('0000000000000000000000000000000000000000000000000000000000000000', 'hex'),
            decode('00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'hex'),
            decode('0102', 'hex'),
            decode('0000000000000000000000000000000000000000000000000000000000000000', 'hex'),
            'did:web:alice.example.com', '{dev_id}', '{cursor_key}', 1, clock_timestamp()
        );",
        convo_id = Uuid::new_v4(),
        entry_id = Uuid::new_v4(),
        dev_id = Uuid::new_v4(),
        cursor_key = CURSOR_KEY_ID
    );

    assert_dirty_semantic_table_rejected(&pool, "entries", &insert_sql).await;
}

#[tokio::test]
async fn test_preflight_fails_when_welcome_bundles_table_is_dirty() {
    let (pool, _db) = setup_post_migration_db().await;
    let insert_sql = format!(
        "INSERT INTO chat.welcome_bundles (
            welcome_id, conversation_id, transition_id, entry_seq, generation, state_version,
            group_id, epoch, group_context_hash, confirmation_tag,
            wrapper_bytes, wrapper_sha256, created_at
        ) VALUES (
            '{welcome_id}', '{convo_id}', '{trans_id}', 1, 1, 1,
            decode('0000000000000000000000000000000000000000000000000000000000000000', 'hex'), 1,
            decode('0000000000000000000000000000000000000000000000000000000000000000', 'hex'),
            decode('0000000000000000000000000000000000000000000000000000000000000000', 'hex'),
            decode('0102', 'hex'),
            decode('0000000000000000000000000000000000000000000000000000000000000000', 'hex'),
            clock_timestamp()
        );",
        welcome_id = Uuid::new_v4(),
        convo_id = Uuid::new_v4(),
        trans_id = Uuid::new_v4()
    );

    assert_dirty_semantic_table_rejected(&pool, "welcome_bundles", &insert_sql).await;
}

#[tokio::test]
async fn test_preflight_fails_when_outbox_table_is_dirty() {
    let (pool, _db) = setup_post_migration_db().await;
    let insert_sql = format!(
        "INSERT INTO chat.outbox (
            outbox_id, event_position, work_kind, status, attempt_count, next_attempt_at, created_at
        ) VALUES (
            '{outbox_id}', 1, 'stream', 'pending', 0, clock_timestamp(), clock_timestamp()
        );",
        outbox_id = Uuid::new_v4()
    );

    assert_dirty_semantic_table_rejected(&pool, "outbox", &insert_sql).await;
}

#[tokio::test]
async fn test_preflight_fails_when_conversations_table_is_dirty() {
    let (pool, _db) = setup_post_migration_db().await;
    let insert_sql = format!(
        "INSERT INTO chat.conversations (
            conversation_id, kind, lifecycle, current_generation, current_state_version,
            next_entry_seq, direct_did_low, direct_did_high, created_at
        ) VALUES (
            '{convo_id}', 'direct', 'active', 1, 1, 1,
            'did:web:alice.example.com', 'did:web:bob.example.com', clock_timestamp()
        );",
        convo_id = Uuid::new_v4()
    );

    assert_dirty_semantic_table_rejected(&pool, "conversations", &insert_sql).await;
}

#[tokio::test]
async fn test_preflight_fails_when_federation_delivery_receipts_is_dirty() {
    let (pool, _db) = setup_post_migration_db().await;
    let insert_sql = format!(
        "INSERT INTO chat.federation_delivery_receipts (
            delivery_id, endpoint_nsid, conversation_id, sender_ds_did, receiver_ds_did,
            sequencer_did, sequencer_term, envelope_sha256, result_sha256,
            source_entry_id, source_entry_seq, source_entry_fingerprint,
            response_bytes, response_sha256, receipt_signature, completed_at
        ) VALUES (
            '{deliv_id}', 'blue.catbird.mlsDS.deliverMessage', '{convo_id}',
            'did:web:sender.example.com', 'did:web:receiver.example.com', 'did:web:seq.example.com', 1,
            decode('0000000000000000000000000000000000000000000000000000000000000000', 'hex'),
            decode('0000000000000000000000000000000000000000000000000000000000000000', 'hex'),
            '{entry_id}', 1,
            decode('0000000000000000000000000000000000000000000000000000000000000000', 'hex'),
            decode('01020304', 'hex'),
            decode('0000000000000000000000000000000000000000000000000000000000000000', 'hex'),
            decode('00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'hex'),
            clock_timestamp()
        );",
        deliv_id = Uuid::new_v4(),
        convo_id = Uuid::new_v4(),
        entry_id = Uuid::new_v4()
    );

    assert_dirty_semantic_table_rejected(&pool, "federation_delivery_receipts", &insert_sql).await;
}

// =============================================================================
// Negative / RED Tests: Catalog and Migration Drift
// =============================================================================

#[tokio::test]
async fn test_preflight_fails_on_dirty_unsuccessful_migration() {
    let (pool, _db) = setup_post_migration_db().await;
    sqlx::query(
        "UPDATE public._sqlx_migrations SET success = FALSE WHERE version = 20260828000001;",
    )
    .execute(&pool)
    .await
    .expect("set migration dirty");

    let result = run_preflight(&pool).await;
    let err = result.expect_err("preflight must fail on dirty migration in ledger");
    assert!(
        err.to_string().contains("dirty/unsuccessful migration"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn test_preflight_fails_on_checksum_mismatch() {
    let (pool, _db) = setup_post_migration_db().await;
    sqlx::query("UPDATE public._sqlx_migrations SET checksum = decode('000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'hex') WHERE version = 20260828000001;")
        .execute(&pool)
        .await
        .expect("corrupt checksum");

    let result = run_preflight(&pool).await;
    let err = result.expect_err("preflight must fail on checksum mismatch");
    assert!(
        err.to_string().contains("migration checksum mismatch"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn test_preflight_fails_on_description_mismatch() {
    let (pool, _db) = setup_post_migration_db().await;
    sqlx::query("UPDATE public._sqlx_migrations SET description = 'tampered description' WHERE version = 20260828000001;")
        .execute(&pool)
        .await
        .expect("tamper description");

    let result = run_preflight(&pool).await;
    let err = result.expect_err("preflight must fail on description mismatch");
    assert!(
        err.to_string().contains("migration description mismatch"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn test_preflight_fails_on_unexpected_extra_migration() {
    let (pool, _db) = setup_post_migration_db().await;
    sqlx::query(
        "INSERT INTO public._sqlx_migrations (version, description, installed_on, success, checksum, execution_time)
         VALUES (20260901000001, 'unauthorized future migration', clock_timestamp(), TRUE, decode('000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'hex'), 100);",
    )
    .execute(&pool)
    .await
    .expect("insert extra migration");

    let result = run_preflight(&pool).await;
    let err = result.expect_err("preflight must fail on extra migration");
    assert!(
        err.to_string()
            .contains("unrecognized _sqlx_migrations catalog"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn test_preflight_fails_on_missing_migration() {
    let (pool, _db) = setup_post_migration_db().await;
    sqlx::query("DELETE FROM public._sqlx_migrations WHERE version = 20260828000001;")
        .execute(&pool)
        .await
        .expect("delete migration");

    let result = run_preflight(&pool).await;
    let err = result.expect_err("preflight must fail on missing migration");
    assert!(
        err.to_string()
            .contains("unrecognized _sqlx_migrations catalog"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn test_preflight_fails_on_unexpected_extra_table_in_chat_schema() {
    let (pool, _db) = setup_post_migration_db().await;
    sqlx::query("CREATE TABLE chat.unauthorized_extra_table (id INT PRIMARY KEY);")
        .execute(&pool)
        .await
        .expect("create unauthorized table");

    let result = run_preflight(&pool).await;
    let err = result.expect_err("preflight must fail on unexpected table");
    assert!(
        err.to_string()
            .contains("unexpected relation chat.unauthorized_extra_table"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn test_preflight_fails_on_unexpected_view_in_chat_schema() {
    let (pool, _db) = setup_post_migration_db().await;
    sqlx::query("CREATE VIEW chat.unauthorized_view AS SELECT 1 AS id;")
        .execute(&pool)
        .await
        .expect("create unauthorized view");

    let result = run_preflight(&pool).await;
    let err = result.expect_err("preflight must fail on unexpected view in chat schema");
    assert!(
        err.to_string()
            .contains("unexpected relation chat.unauthorized_view (relkind=v)"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn test_preflight_fails_on_missing_table_in_chat_schema() {
    let (pool, _db) = setup_post_migration_db().await;
    sqlx::query("DROP TABLE chat.service_auth_admissions CASCADE;")
        .execute(&pool)
        .await
        .expect("drop table");

    let result = run_preflight(&pool).await;
    let err = result.expect_err("preflight must fail on missing table");
    assert!(
        err.to_string()
            .contains("missing expected table chat.service_auth_admissions"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn test_pre_cutover_fails_if_post_table_federation_delivery_receipts_exists() {
    let (pool, _db) = setup_pre_cutover_db().await;
    sqlx::query("CREATE TABLE chat.federation_delivery_receipts (id INT PRIMARY KEY);")
        .execute(&pool)
        .await
        .expect("create post table in pre-cutover mode");

    let result = run_preflight(&pool).await;
    let err = result
        .expect_err("preflight must fail when post-migration table exists in pre-cutover mode");
    assert!(
        err.to_string().contains(
            "unexpected relation chat.federation_delivery_receipts (relkind=r) in pre-cutover mode"
        ),
        "unexpected error: {err}"
    );
}

// =============================================================================
// Negative / RED Tests: Public Transport UUIDv4 Row Traps (Post-Migration & Pre-Cutover)
// =============================================================================

#[tokio::test]
async fn test_preflight_fails_on_clean_chat_uuid_in_federation_outbox_for_all_statuses() {
    for status in ["pending", "in_flight", "done", "failed", "dead"] {
        let (pool, _db) = setup_post_migration_db().await;
        let clean_convo_uuid = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO public.federation_outbox (id, conversation_id, target_service_did, payload, status)
             VALUES ($1, $2, 'did:web:target.example.com', decode('', 'hex'), $3);",
        )
        .bind(format!("outbox-{status}"))
        .bind(&clean_convo_uuid)
        .bind(status)
        .execute(&pool)
        .await
        .expect("insert clean convo row into federation_outbox");

        let result = run_preflight(&pool).await;
        let err = result.expect_err(&format!(
            "preflight must fail on UUIDv4 in federation_outbox with status={status}"
        ));
        assert!(
            err.to_string()
                .contains("public.federation_outbox contains"),
            "unexpected error for status {status}: {err}"
        );
    }
}

#[tokio::test]
async fn test_preflight_fails_on_clean_chat_uuid_in_outbound_queue_for_all_statuses() {
    for status in ["pending", "in_flight", "delivered", "failed", "dead"] {
        let (pool, _db) = setup_post_migration_db().await;
        let clean_convo_uuid = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO public.outbound_queue (id, target_ds_did, target_endpoint, method, payload, convo_id, status)
             VALUES ($1, 'did:web:ds.example.com', 'https://ds.example.com', 'deliverMessage', decode('', 'hex'), $2, $3);",
        )
        .bind(format!("queue-{status}"))
        .bind(&clean_convo_uuid)
        .bind(status)
        .execute(&pool)
        .await
        .expect("insert clean convo row into outbound_queue");

        let result = run_preflight(&pool).await;
        let err = result.expect_err(&format!(
            "preflight must fail on UUIDv4 in outbound_queue with status={status}"
        ));
        assert!(
            err.to_string().contains("public.outbound_queue contains"),
            "unexpected error for status {status}: {err}"
        );
    }
}

#[tokio::test]
async fn test_preflight_fails_on_clean_chat_uuid_in_federation_sync_state_for_all_statuses() {
    for status in ["healthy", "quarantined"] {
        let (pool, _db) = setup_post_migration_db().await;
        let clean_convo_uuid = Uuid::new_v4().to_string();

        if status == "healthy" {
            sqlx::query(
                "INSERT INTO public.federation_sync_state (convo_id, sequencer_ds_did, status)
                 VALUES ($1, 'did:web:example.com', $2);",
            )
            .bind(&clean_convo_uuid)
            .bind(status)
            .execute(&pool)
            .await
            .expect("insert clean convo row into federation_sync_state");
        } else {
            sqlx::query(
                "INSERT INTO public.federation_sync_state (convo_id, sequencer_ds_did, status, quarantined_at, quarantine_reason, first_mismatch_seq)
                 VALUES ($1, 'did:web:example.com', $2, clock_timestamp(), 'prefix_mismatch', 1);",
            )
            .bind(&clean_convo_uuid)
            .bind(status)
            .execute(&pool)
            .await
            .expect("insert clean convo row into federation_sync_state");
        }

        let result = run_preflight(&pool).await;
        let err = result.expect_err(&format!(
            "preflight must fail on UUIDv4 in federation_sync_state with status={status}"
        ));
        assert!(
            err.to_string()
                .contains("public.federation_sync_state contains"),
            "unexpected error for status {status}: {err}"
        );
    }
}

#[tokio::test]
async fn test_pre_cutover_fails_on_clean_chat_uuid_in_public_transport_tables() {
    // 1. federation_outbox in pre-cutover mode
    {
        let (pool, _db) = setup_pre_cutover_db().await;
        let clean_convo_uuid = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO public.conversations (id, group_id, creator_did)
             VALUES ('legacy-convo-pre', decode('0000000000000000000000000000000000000000000000000000000000000000', 'hex'), 'did:web:creator')
             ON CONFLICT (id) DO NOTHING;",
        )
        .execute(&pool)
        .await
        .expect("insert legacy conversation");

        sqlx::query(
            "INSERT INTO public.delivery_events (id, conversation_id, seq, event_type, payload)
             VALUES ('legacy-event-pre', 'legacy-convo-pre', 1, 'message', decode('', 'hex'))
             ON CONFLICT (id) DO NOTHING;",
        )
        .execute(&pool)
        .await
        .expect("insert legacy delivery event");

        sqlx::query(
            "INSERT INTO public.federation_outbox (id, conversation_id, delivery_event_id, target_service_did, payload, status)
             VALUES ('outbox-pre-1', $1, 'legacy-event-pre', 'did:web:target.example.com', decode('', 'hex'), 'pending');",
        )
        .bind(&clean_convo_uuid)
        .execute(&pool)
        .await
        .expect("insert clean convo into federation_outbox");

        let result = run_preflight(&pool).await;
        let err = result
            .expect_err("preflight must fail on UUIDv4 in federation_outbox in pre-cutover mode");
        assert!(
            err.to_string()
                .contains("public.federation_outbox contains"),
            "unexpected error: {err}"
        );
    }

    // 2. outbound_queue in pre-cutover mode
    {
        let (pool, _db) = setup_pre_cutover_db().await;
        let clean_convo_uuid = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO public.outbound_queue (id, target_ds_did, target_endpoint, method, payload, convo_id, status)
             VALUES ('queue-pre-1', 'did:web:ds.example.com', 'https://ds.example.com', 'deliverMessage', decode('', 'hex'), $1, 'pending');",
        )
        .bind(&clean_convo_uuid)
        .execute(&pool)
        .await
        .expect("insert clean convo into outbound_queue");

        let result = run_preflight(&pool).await;
        let err = result
            .expect_err("preflight must fail on UUIDv4 in outbound_queue in pre-cutover mode");
        assert!(
            err.to_string().contains("public.outbound_queue contains"),
            "unexpected error: {err}"
        );
    }

    // 3. federation_sync_state in pre-cutover mode
    {
        let (pool, _db) = setup_pre_cutover_db().await;
        let clean_convo_uuid = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO public.federation_sync_state (convo_id, sequencer_ds_did)
             VALUES ($1, 'did:web:example.com');",
        )
        .bind(&clean_convo_uuid)
        .execute(&pool)
        .await
        .expect("insert clean convo into federation_sync_state");

        let result = run_preflight(&pool).await;
        let err = result.expect_err(
            "preflight must fail on UUIDv4 in federation_sync_state in pre-cutover mode",
        );
        assert!(
            err.to_string()
                .contains("public.federation_sync_state contains"),
            "unexpected error: {err}"
        );
    }
}

// =============================================================================
// Negative / RED Tests: Public Transport Table / Column / Type Drift
// =============================================================================

#[tokio::test]
async fn test_preflight_fails_when_public_transport_table_is_missing() {
    let (pool, _db) = setup_post_migration_db().await;
    sqlx::query("DROP TABLE public.federation_outbox CASCADE;")
        .execute(&pool)
        .await
        .expect("drop federation_outbox table");

    let result = run_preflight(&pool).await;
    let err =
        result.expect_err("preflight must fail when required public transport table is missing");
    assert!(
        err.to_string()
            .contains("required public transport table public.federation_outbox is missing"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn test_preflight_fails_when_public_transport_identifier_column_is_missing() {
    let (pool, _db) = setup_post_migration_db().await;
    sqlx::query("ALTER TABLE public.outbound_queue DROP COLUMN convo_id CASCADE;")
        .execute(&pool)
        .await
        .expect("drop convo_id column from outbound_queue");

    let result = run_preflight(&pool).await;
    let err = result.expect_err("preflight must fail when identifier column is missing");
    assert!(
        err.to_string()
            .contains("required identifier column outbound_queue.convo_id is missing"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn test_preflight_fails_when_public_transport_identifier_column_type_is_not_text_compatible()
{
    let (pool, _db) = setup_post_migration_db().await;
    sqlx::query(
        "ALTER TABLE public.federation_sync_state ALTER COLUMN convo_id TYPE integer USING 1;",
    )
    .execute(&pool)
    .await
    .expect("alter convo_id to integer");

    let result = run_preflight(&pool).await;
    let err = result.expect_err("preflight must fail when identifier column is non-text");
    assert!(
        err.to_string()
            .contains("column federation_sync_state.convo_id in public.federation_sync_state is not text-compatible (type=int4)"),
        "unexpected error: {err}"
    );
}
