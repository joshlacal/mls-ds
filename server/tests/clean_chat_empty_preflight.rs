//! Integration tests for Clean Chat zero-state preflight gate.
//!
//! Tests both pre-cutover (19 migrations, max 20260821000001) and
//! post-migration (23 migrations, max 20260824000005) modes against disposable
//! PostgreSQL databases.
//!
//! Verifies:
//!   - GREEN exact pre-cutover and post-migration modes.
//!   - RED on dirty semantic tables: devices, key_packages, generation_states,
//!     relationship_projection_relationships, relationship_projection_declarations,
//!     transitions, entries, welcome_bundles, outbox, federation_delivery_receipts.
//!   - RED on infrastructure anomalies.
//!   - RED on migration catalog / checksum / dirty drift.
//!   - RED on unexpected or missing tables in chat schema.
//!   - RED on Clean Chat lowercase UUIDv4 rows in federation_outbox, outbound_queue,
//!     federation_sync_state across all reachable statuses.
//!   - GREEN on legacy non-UUID rows in public transport tables.
//!   - Strict read-only verification (zero database mutations).

mod common;

use common::chat_protocol::{reviewed_clean_protocol_migrator, CLEAN_PROTOCOL_13_MANIFEST};
use common::fresh_db::{DisposableDatabase, SHARED_LEGACY_DB_PREFIX};
use sqlx::error::BoxDynError;
use sqlx::migrate::{Migration, MigrationSource, Migrator};
use sqlx::PgPool;
use uuid::Uuid;

const PREFLIGHT_SQL: &str = include_str!("../scripts/assert_clean_chat_empty.sql");
const CURSOR_KEY_ID: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

async fn ensure_public_transport_prerequisites(conn: &mut sqlx::PgConnection) {
    sqlx::raw_sql(
        "CREATE TABLE IF NOT EXISTS public.delivery_events (
            id TEXT PRIMARY KEY,
            created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
        );
        CREATE TABLE IF NOT EXISTS public.federation_outbox (
            id TEXT PRIMARY KEY,
            conversation_id TEXT NOT NULL,
            delivery_event_id TEXT REFERENCES public.delivery_events(id),
            status TEXT NOT NULL DEFAULT 'pending',
            next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            attempts INT NOT NULL DEFAULT 0,
            max_attempts INT NOT NULL DEFAULT 10,
            last_error TEXT,
            backoff_exponent INT NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS public.outbound_queue (
            id TEXT PRIMARY KEY,
            target_ds_did TEXT NOT NULL,
            target_endpoint TEXT NOT NULL,
            convo_id TEXT NOT NULL,
            payload BYTEA NOT NULL DEFAULT decode('', 'hex'),
            created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            next_retry_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            retry_count INT NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'pending',
            error TEXT
        );
        CREATE TABLE IF NOT EXISTS public.federation_sync_state (
            convo_id TEXT PRIMARY KEY,
            sequencer_ds_did TEXT NOT NULL,
            sequencer_term BIGINT NOT NULL DEFAULT 0,
            last_synced_event_id TEXT,
            last_synced_seq BIGINT,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
        );",
    )
    .execute(&mut *conn)
    .await
    .expect("create public transport tables prerequisites");
}

/// Apply `migrator` to a fresh disposable database, then initialize the infrastructure rows
/// the preflight requires: the protocol singleton and its bound zero-floor retention row.
async fn setup_db(migrator: Migrator) -> (PgPool, DisposableDatabase) {
    let database = DisposableDatabase::mint(SHARED_LEGACY_DB_PREFIX).await;
    let pool = database.connect(5).await;
    let mut conn = pool
        .acquire()
        .await
        .expect("acquire connection for migration");

    ensure_public_transport_prerequisites(&mut conn).await;

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

/// Set up a disposable database with pre-cutover migrations (first 19 migrations).
async fn setup_pre_cutover_db() -> (PgPool, DisposableDatabase) {
    #[derive(Debug)]
    struct PreCutoverSource(Vec<Migration>);
    impl<'s> MigrationSource<'s> for PreCutoverSource {
        fn resolve(self) -> futures::future::BoxFuture<'s, Result<Vec<Migration>, BoxDynError>> {
            Box::pin(async move { Ok(self.0) })
        }
    }

    let pre_cutover_entries = CLEAN_PROTOCOL_13_MANIFEST[0..19]
        .iter()
        .map(|entry| entry.migration.clone())
        .collect();
    let migrator = Migrator::new(PreCutoverSource(pre_cutover_entries))
        .await
        .expect("build pre-cutover migrator");

    setup_db(migrator).await
}

/// Set up a disposable database with post-migration migrations (all 23 migrations).
async fn setup_post_migration_db() -> (PgPool, DisposableDatabase) {
    let migrator = reviewed_clean_protocol_migrator()
        .await
        .expect("build post-migration migrator");

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

    // Snapshot migration ledger
    let ledger_before: Vec<(i64, String, bool, Vec<u8>)> = sqlx::query_as(
        "SELECT version, description, success, checksum FROM public._sqlx_migrations ORDER BY version",
    )
    .fetch_all(&pool)
    .await
    .expect("read ledger before");

    // Snapshot table list in chat schema
    let tables_before: Vec<String> = sqlx::query_scalar(
        "SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname = 'chat' ORDER BY tablename",
    )
    .fetch_all(&pool)
    .await
    .expect("read tables before");

    // Execute preflight
    let result = run_preflight(&pool).await;
    assert!(result.is_ok(), "preflight must pass");

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

    // Verify tables unchanged
    let tables_after: Vec<String> = sqlx::query_scalar(
        "SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname = 'chat' ORDER BY tablename",
    )
    .fetch_all(&pool)
    .await
    .expect("read tables after");
    assert_eq!(
        tables_before, tables_after,
        "tables in chat schema must be unchanged"
    );
}

#[tokio::test]
async fn test_preflight_allows_legacy_non_uuid_rows_in_public_transport_tables() {
    let (pool, _db) = setup_post_migration_db().await;

    // Seed non-UUID legacy rows
    sqlx::query(
        "INSERT INTO public.federation_outbox (id, conversation_id, status)
         VALUES ('outbox-1', 'legacy-convo-id-12345', 'pending'),
                ('outbox-2', 'not_a_uuid_at_all', 'done')
         ON CONFLICT (id) DO NOTHING;",
    )
    .execute(&pool)
    .await
    .expect("insert legacy federation_outbox rows");

    sqlx::query(
        "INSERT INTO public.outbound_queue (id, target_ds_did, target_endpoint, convo_id, status)
         VALUES ('queue-1', 'did:web:ds.example.com', 'https://ds.example.com', 'legacy-convo-999', 'delivered'),
                ('queue-2', 'did:web:ds.example.com', 'https://ds.example.com', 'convo_legacy_group', 'dead')
         ON CONFLICT (id) DO NOTHING;",
    )
    .execute(&pool)
    .await
    .expect("insert legacy outbound_queue rows");

    sqlx::query(
        "INSERT INTO public.federation_sync_state (convo_id, sequencer_ds_did, status)
         VALUES ('legacy-convo-sync-1', 'did:web:example.com', 'healthy')
         ON CONFLICT (convo_id) DO NOTHING;",
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
// Negative / RED Tests: Infrastructure Anomalies
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

// =============================================================================
// Negative / RED Tests: Dirty Semantic Tables (Explicit Step 1 Set)
// =============================================================================

#[tokio::test]
async fn test_preflight_fails_when_devices_table_is_dirty() {
    let (pool, _db) = setup_post_migration_db().await;
    let did = "did:web:alice.example.com";
    let dev_id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO chat.principals (user_did, created_at) VALUES ($1, clock_timestamp());",
    )
    .bind(did)
    .execute(&pool)
    .await
    .expect("insert principal");

    sqlx::query(
        "INSERT INTO chat.devices (user_did, device_id, device_name, status, dpop_jkt, auth_generation, capabilities, created_at, updated_at)
         VALUES ($1, $2, 'phone', 'active', $3, 1, chat.protocol_capabilities(), clock_timestamp(), clock_timestamp());",
    )
    .bind(did)
    .bind(dev_id)
    .bind(CURSOR_KEY_ID)
    .execute(&pool)
    .await
    .expect("insert device");

    let result = run_preflight(&pool).await;
    let err = result.expect_err("preflight must fail on dirty devices table");
    assert!(
        err.to_string()
            .contains("semantic table chat.devices is dirty")
            || err
                .to_string()
                .contains("semantic table chat.principals is dirty"),
        "unexpected error: {err}"
    );
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
        "UPDATE public._sqlx_migrations SET success = FALSE WHERE version = 20260824000005;",
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
    sqlx::query("UPDATE public._sqlx_migrations SET checksum = decode('000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'hex') WHERE version = 20260824000005;")
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
    sqlx::query("UPDATE public._sqlx_migrations SET description = 'tampered description' WHERE version = 20260824000005;")
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
    sqlx::query("DELETE FROM public._sqlx_migrations WHERE version = 20260824000005;")
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
            .contains("unexpected table chat.unauthorized_extra_table"),
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
        err.to_string()
            .contains("unexpected table chat.federation_delivery_receipts in pre-cutover mode"),
        "unexpected error: {err}"
    );
}

// =============================================================================
// Negative / RED Tests: Public Transport UUIDv4 Row Traps
// =============================================================================

#[tokio::test]
async fn test_preflight_fails_on_clean_chat_uuid_in_federation_outbox_for_all_statuses() {
    for status in ["pending", "in_flight", "done", "failed", "dead"] {
        let (pool, _db) = setup_post_migration_db().await;
        let clean_convo_uuid = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO public.federation_outbox (id, conversation_id, status)
             VALUES ($1, $2, $3);",
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
            "INSERT INTO public.outbound_queue (id, target_ds_did, target_endpoint, convo_id, status)
             VALUES ($1, 'did:web:ds.example.com', 'https://ds.example.com', $2, $3);",
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
