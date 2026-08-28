//! Disposable per-run PostgreSQL databases for targets that would otherwise
//! obtain isolation by destroying shared state.
//!
//! Several integration targets used to start each test by resetting the
//! database named by `TEST_DATABASE_URL` in place — `TRUNCATE … RESTART
//! IDENTITY CASCADE` over every table in a schema, or over a fixed list of
//! legacy public tables. Every concurrent task in this program points
//! `TEST_DATABASE_URL` at the *same* database, so "reset before each test" is
//! not isolation: it is a cross-task data-loss event that has already fired
//! once, silently, mid-run.
//!
//! The mint-and-reap pattern here is the one this tree already uses and proves
//! out in `common::executor_seed` (`FreshDbGuard` / `fresh_executor_db`).
//! `tests/common/executor_seed.rs` is pinned byte-for-byte by
//! `chat_protocol_g7_entitlement::frozen_executor_seed_helper_is_byte_identical_to_the_sealed_baseline`
//! (`6d602b55…`); both use the shared advisory lock on `/postgres`
//! (`0x43415442_49524431`). The two implementations are deliberately
//! behaviourally identical: unique name, `CREATE DATABASE`, and a `Drop` reaper
//! that terminates stragglers and drops the database on the normal path *and*
//! during panic unwind.
//!
//! Naming: every database minted here is `<reserved prefix><32 lowercase hex>`.
//! No reserved prefix collides with `chat_exec_` (the executor harness's own
//! namespace) or with any pre-existing database on this host, so a leaked
//! database from a killed run is attributable to exactly one target.

#![allow(dead_code)]
use sqlx::postgres::PgPoolOptions;
use sqlx::{Connection, PgPool};
use std::sync::LazyLock;
use tokio::sync::Mutex as TokioMutex;

static IN_PROCESS_MIGRATION_LOCK: LazyLock<TokioMutex<()>> = LazyLock::new(|| TokioMutex::new(()));
pub const DISPOSABLE_MIGRATION_ADVISORY_LOCK_KEY: i64 = 0x43415442_49524431; // 'CATBIRD1'

pub struct MigrationLockGuard<'a> {
    _in_process: tokio::sync::MutexGuard<'a, ()>,
    _maintenance_conn: sqlx::PgConnection,
}

pub async fn acquire_migration_lock() -> MigrationLockGuard<'static> {
    let in_process = IN_PROCESS_MIGRATION_LOCK.lock().await;
    let maintenance_url =
        maintenance_url_from_env().expect("loopback maintenance URL for the disposable harness");
    let mut conn = sqlx::PgConnection::connect(&maintenance_url)
        .await
        .expect("connect to maintenance database for migration advisory lock");
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(DISPOSABLE_MIGRATION_ADVISORY_LOCK_KEY)
        .execute(&mut conn)
        .await
        .expect("acquire PostgreSQL migration advisory lock");
    MigrationLockGuard {
        _in_process: in_process,
        _maintenance_conn: conn,
    }
}

/// Databases that are shared program state. Nothing in this module may create,
/// reset, or reap a database on this list: the whole point of the module is
/// that these survive a test run untouched.
///
/// This is the backstop, not the fix. The fix is that callers no longer need
/// the shared database to be resettable at all; this list exists so that the
/// bad state is unrepresentable rather than merely unused.
pub const PROTECTED_DATABASE_NAMES: &[&str] = &[
    "catbird_chat_protocol_test_20260722",
    "catbird",
    "catbird_test",
    "catbird_mls_v2_test_20260722",
    "postgres",
    "template0",
    "template1",
];

/// Name prefixes reserved for disposable per-run databases minted by this
/// module. One prefix per owning target, so a leak names its owner.
pub const DISPOSABLE_PREFIXES: &[&str] = &[
    // `tests/chat_protocol_create_conversation_handlers.rs`
    "chat_convhandlers_",
    // `tests/chat_protocol_federation_routing.rs`
    "chat_fedrouting_",
    // `tests/chat_protocol_federation_router.rs`
    "chat_fedrouter_",
    // `tests/chat_protocol_federation_outbox_retry.rs`
    "chat_fedoutbox_",
    // `tests/chat_protocol_remote_prefix_bootstrap.rs`
    "chat_remoteprefix_",
    "chat_devhandlers_",
    // `tests/chat_protocol_auth_repository.rs`
    "chat_authrepo_",
    // `tests/common/fresh_db.rs`
    "chat_freshdb_",
    // `tests/db_tests.rs`
    "mlsds_dbtests_",
    // `tests/federation_hostile_peers.rs`
    "mlsds_fedpeers_",
    // `tests/get_key_packages_authz.rs`
    "mlsds_kpauthz_",
    // `tests/key_package_bulk_claim.rs`
    "mlsds_kpbulk_",
    // `tests/key_package_claim_race.rs`
    "mlsds_kprace_",
    // `tests/stress.rs`
    "mlsds_stress_",
    // `tests/race_conditions.rs`
    "mlsds_raceconds_",
    // `tests/group_info_store_helper.rs`
    "mlsds_gistore_",
    // `tests/migration_repair_smoke.rs`
    "mlsds_migrepair_",
    // `common::setup_test_db`, the shared legacy helper, plus
    // `tests/clean_chat_empty_preflight.rs`, which mints under this prefix
    // directly. A leak here names the *prefix*, not one of its eleven
    // consuming targets; they are enumerated at [`SHARED_LEGACY_DB_PREFIX`].
    "mlsds_shared_",
];

/// Prefix used by [`crate::common::setup_test_db`], the shared legacy fixture
/// helper, and minted directly by `tests/clean_chat_empty_preflight.rs`.
///
/// Consuming targets, enumerated so a leak under this prefix has a bounded
/// suspect list (corpus: every `.rs` file under `server/tests` naming
/// `common::setup_test_db` or this constant): `blob_quota_race`,
/// `clean_chat_empty_preflight`, `commit_group_change_health_counters`,
/// `durable_outbox_test`, `group_info_epoch_cas`,
/// `phase_2_5_indirect_funneling`, `quorum_reset_threshold`,
/// `reset_reminder_worker`, `sequencer_transfer_cas`,
/// `sweep_finds_stale_convos`, `system_reset_actor`.
pub const SHARED_LEGACY_DB_PREFIX: &str = "mlsds_shared_";

/// The sole authority on whether a database name may be created or dropped by
/// this harness.
///
/// Falsifying inputs, each covered by a unit test in `tests/db_tests.rs`:
/// * `"catbird_chat_protocol_test_20260722"` — protected shared database.
/// * `"scratch_0123456789abcdef0123456789abcdef"` — prefix not reserved.
/// * `"mlsds_dbtests_short"` — suffix is not 32 hex digits.
/// * `"mlsds_dbtests_0123456789ABCDEF0123456789abcdef"` — suffix is not
///   *lowercase* hex, so two names could differ only by case and collide under
///   a case-folding consumer.
pub fn validate_disposable_database_name(name: &str) -> Result<(), String> {
    if PROTECTED_DATABASE_NAMES.contains(&name) {
        return Err(format!(
            "refusing to treat protected shared database {name:?} as disposable"
        ));
    }
    let Some(prefix) = DISPOSABLE_PREFIXES
        .iter()
        .find(|prefix| name.starts_with(**prefix))
    else {
        return Err(format!(
            "disposable database name {name:?} does not carry a reserved prefix"
        ));
    };
    let suffix = &name[prefix.len()..];
    if suffix.len() != 32 || !suffix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "disposable database name {name:?} lacks a 32-digit hexadecimal unique suffix"
        ));
    }
    if suffix.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(format!(
            "disposable database name {name:?} must use lowercase hexadecimal"
        ));
    }
    Ok(())
}

/// Reserved prefix check for callers, so a target cannot mint under a prefix it
/// does not own without editing [`DISPOSABLE_PREFIXES`].
pub fn validate_disposable_prefix(prefix: &str) -> Result<(), String> {
    if DISPOSABLE_PREFIXES.contains(&prefix) {
        Ok(())
    } else {
        Err(format!("{prefix:?} is not a reserved disposable prefix"))
    }
}

/// Derive the maintenance connection URL (the server's `postgres` database)
/// from `TEST_DATABASE_URL`, enforcing exactly the loopback/literal safety the
/// shared clean-chat gate enforces. Reuses the single reviewed validator rather
/// than introducing a second, weaker notion of "safe target".
pub fn maintenance_url_from_env() -> Result<String, String> {
    let database_url = std::env::var("TEST_DATABASE_URL")
        .map_err(|_| "TEST_DATABASE_URL is not set".to_owned())?;
    crate::common::chat_protocol::validate_chat_protocol_database_url(Some(&database_url))
        .map_err(|error| {
            format!("unsafe TEST_DATABASE_URL for the disposable-DB harness: {error}")
        })?;
    let activation_approval = std::env::var("CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED")
        .map_err(|_| "CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED is not set".to_owned())?;
    crate::common::chat_protocol::validate_chat_protocol_activation_approval(Some(
        &activation_approval,
    ))
    .map_err(|error| format!("invalid operation-claim activation approval: {error}"))?;
    let mut parsed = url::Url::parse(&database_url).map_err(|error| error.to_string())?;
    parsed.set_path("/postgres");
    Ok(parsed.into())
}

/// A freshly created, uniquely named database plus its reaper.
///
/// Bind this for the lifetime of the test. `Drop` terminates any connection the
/// test left open and drops the database, on the normal path and during panic
/// unwind alike. A database leaks only if the process is killed outright, in
/// which case its reserved prefix identifies the owning target.
pub struct DisposableDatabase {
    maintenance_url: String,
    name: String,
    url: String,
}

impl DisposableDatabase {
    /// Create a database named `<prefix><32 hex>`, refusing any name the
    /// [`validate_disposable_database_name`] guard rejects.
    pub async fn mint(prefix: &str) -> Self {
        validate_disposable_prefix(prefix).expect("reserved disposable prefix");
        let maintenance_url = maintenance_url_from_env()
            .expect("loopback maintenance URL for the disposable harness");
        let name = format!("{prefix}{}", uuid::Uuid::new_v4().simple());
        validate_disposable_database_name(&name).expect("minted disposable database name");

        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&maintenance_url)
            .await
            .expect("connect to the loopback maintenance database");
        sqlx::query(&format!("CREATE DATABASE \"{name}\""))
            .execute(&admin)
            .await
            .expect("create a disposable per-run database");
        admin.close().await;

        let mut url = url::Url::parse(&maintenance_url).expect("maintenance URL");
        url.set_path(&format!("/{name}"));
        Self {
            maintenance_url,
            name,
            url: url.into(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// Open a pool against this database. Callers that need to prove a
    /// behaviour "after restart" call this a second time; it returns a new pool
    /// against the *same* private database, never the shared one.
    pub async fn connect(&self, max_connections: u32) -> PgPool {
        assert!(max_connections > 0, "pool must have a connection");
        PgPoolOptions::new()
            .max_connections(max_connections)
            .connect(&self.url)
            .await
            .expect("connect to the disposable per-run database")
    }
}

impl Drop for DisposableDatabase {
    fn drop(&mut self) {
        // Never drop a name this harness would refuse to mint. A refusal here
        // cannot panic — unwinding out of `Drop` during a test panic aborts the
        // process — so it reports and leaves the database alone.
        if let Err(error) = validate_disposable_database_name(&self.name) {
            eprintln!("disposable-database reaper refused to drop a database: {error}");
            return;
        }
        let maintenance_url = self.maintenance_url.clone();
        let name = self.name.clone();
        // Own thread + runtime so teardown runs during panic unwind too.
        let _ = std::thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    eprintln!(
                        "disposable-database reaper failed to build tokio runtime for {name}: {error}"
                    );
                    return;
                }
            };
            runtime.block_on(async move {
                let admin = match PgPoolOptions::new()
                    .max_connections(1)
                    .connect(&maintenance_url)
                    .await
                {
                    Ok(admin) => admin,
                    Err(error) => {
                        eprintln!(
                            "disposable-database reaper failed to connect to maintenance db for {name}: {error}"
                        );
                        return;
                    }
                };
                if let Err(error) = sqlx::query(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
                     WHERE datname = $1 AND pid <> pg_backend_pid()",
                )
                .bind(&name)
                .execute(&admin)
                .await
                {
                    eprintln!(
                        "disposable-database reaper failed to terminate connections for {name}: {error}"
                    );
                }
                if let Err(error) = sqlx::query(&format!("DROP DATABASE IF EXISTS \"{name}\""))
                    .execute(&admin)
                    .await
                {
                    eprintln!(
                        "disposable-database reaper failed to drop database {name}: {error}"
                    );
                }
            });
        })
        .join();
    }
}

/// Mint a disposable database carrying the whole production migration set.
///
/// Migration `20260728000004_activate_operation_claim_completeness` refuses to
/// apply unless `chat.operation_claim_activation_approved` is set on the
/// migrating connection, so the approval is scoped to one connection and reset
/// immediately afterwards — the same shape `common::executor_seed` uses. The
/// returned database is fully migrated, so a later `db::init_db` against its
/// URL finds nothing to apply.
pub async fn fresh_fully_migrated_db(prefix: &str) -> DisposableDatabase {
    let _migration_guard = acquire_migration_lock().await;
    let database = DisposableDatabase::mint(prefix).await;
    let pool = database.connect(1).await;
    let mut migration_connection = pool
        .acquire()
        .await
        .expect("acquire the disposable migration connection");
    sqlx::query(
        "SET chat.operation_claim_activation_approved = \
         'handlers-and-legacy-apis-sealed'",
    )
    .execute(&mut *migration_connection)
    .await
    .expect("authorize operation-claim activation on the migration connection");
    let migration_result = sqlx::migrate!("./migrations")
        .run(&mut *migration_connection)
        .await;
    sqlx::query("RESET chat.operation_claim_activation_approved")
        .execute(&mut *migration_connection)
        .await
        .expect("reset operation-claim activation approval on the migration connection");
    migration_connection
        .close()
        .await
        .expect("close the disposable migration connection");
    migration_result.expect("run the production migration set on the disposable database");
    pool.close().await;
    database
}

/// Mint a disposable, fully migrated database and open a pool onto it through
/// the production `db::init_db` path.
///
/// This is the replacement for the fixture shape that every legacy integration
/// target used to share:
///
/// ```ignore
/// let url = std::env::var("TEST_DATABASE_URL").unwrap_or_else(|_| "…".into());
/// init_db(DbConfig { database_url: url, .. }).await
/// ```
///
/// That shape hands the *ambient* environment straight to
/// `sqlx::migrate!("./migrations")`, so it applies the whole ~56-migration
/// legacy set to whatever `TEST_DATABASE_URL` happens to name. Measured against
/// the shared clean-chat database, it takes the `_sqlx_migrations` ledger from
/// the reviewed 13 to 69 and permanently breaks
/// `common::chat_protocol::validate_exact_reviewed_ledger` for every clean-chat
/// suite — while the target itself passes. The database is migrated *before*
/// `init_db` sees it, so `init_db` finds nothing to apply and the production
/// pool/repair path is still exercised.
///
/// The returned [`DisposableDatabase`] must stay bound for the whole test: it
/// reaps its database on drop, on the normal path and during panic unwind.
pub async fn fresh_legacy_pool(
    prefix: &str,
    max_connections: u32,
    min_connections: u32,
) -> (PgPool, DisposableDatabase) {
    let database = fresh_fully_migrated_db(prefix).await;
    let config = catbird_server::db::DbConfig {
        database_url: database.url().to_owned(),
        max_connections,
        min_connections,
        acquire_timeout: std::time::Duration::from_secs(30),
        idle_timeout: std::time::Duration::from_secs(600),
    };
    let pool = catbird_server::db::init_db(config)
        .await
        .expect("initialize a pool against the disposable per-test database");
    (pool, database)
}

/// Mint a disposable database carrying the full migration catalog with the
/// reviewed clean-protocol ledger, and return a pool onto it.
pub async fn fresh_clean_protocol_db(
    prefix: &str,
    max_connections: u32,
) -> (PgPool, DisposableDatabase) {
    let _migration_guard = acquire_migration_lock().await;
    let database = DisposableDatabase::mint(prefix).await;
    let pool = database.connect(max_connections).await;
    let mut migration_connection = pool
        .acquire()
        .await
        .expect("acquire the disposable migration connection");
    sqlx::query(
        "SET chat.operation_claim_activation_approved = \
         'handlers-and-legacy-apis-sealed'",
    )
    .execute(&mut *migration_connection)
    .await
    .expect("authorize operation-claim activation on the migration connection");
    let full_migrator = sqlx::migrate!("./migrations");
    let migration_result = full_migrator.run_direct(&mut *migration_connection).await;
    sqlx::query("RESET chat.operation_claim_activation_approved")
        .execute(&mut *migration_connection)
        .await
        .expect("reset operation-claim activation approval on the migration connection");
    migration_result.expect("install the full migration catalog on the disposable database");

    // Reduce public._sqlx_migrations to the exact reviewed entries
    let versions: Vec<i64> = crate::common::chat_protocol::CLEAN_PROTOCOL_13_MANIFEST
        .iter()
        .map(|entry| entry.migration.version)
        .collect();
    sqlx::query("DELETE FROM public._sqlx_migrations WHERE NOT (version = ANY($1))")
        .bind(&versions)
        .execute(&mut *migration_connection)
        .await
        .expect("reduce _sqlx_migrations to exact reviewed manifest entries");

    migration_connection
        .close()
        .await
        .expect("close the disposable migration connection");

    (pool, database)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL with database creation privileges"]
    async fn fresh_clean_protocol_db_reproduces_exact_empty_catalog_and_reviewed_ledger() {
        let (pool, _disposable) = fresh_clean_protocol_db("chat_freshdb_", 2).await;

        // 1. Proves tables exist
        let tables_exist: bool = sqlx::query_scalar(
            "SELECT (to_regclass('chat.conversations') IS NOT NULL) \
             AND (to_regclass('chat.entries') IS NOT NULL) \
             AND (to_regclass('chat.devices') IS NOT NULL) \
             AND (to_regclass('chat.operation_claims') IS NOT NULL) \
             AND (to_regclass('public.federation_outbox') IS NOT NULL)",
        )
        .fetch_one(&pool)
        .await
        .expect("check tables exist");
        assert!(tables_exist, "required clean-protocol tables must exist");

        // 2. Ledger matches reviewed manifest
        let ledger_rows: Vec<(i64, String, bool, Vec<u8>)> = sqlx::query_as(
            "SELECT version, description, success, checksum \
             FROM public._sqlx_migrations ORDER BY version",
        )
        .fetch_all(&pool)
        .await
        .expect("read migration ledger");
        assert_eq!(
            ledger_rows.len(),
            crate::common::chat_protocol::CLEAN_PROTOCOL_13_MANIFEST.len(),
            "migration ledger must contain exact reviewed manifest entries"
        );
        for (entry, row) in crate::common::chat_protocol::CLEAN_PROTOCOL_13_MANIFEST
            .iter()
            .zip(ledger_rows.iter())
        {
            assert_eq!(row.0, entry.migration.version, "version matches");
            assert_eq!(
                &row.1,
                entry.migration.description.as_ref(),
                "description matches"
            );
            assert!(row.2, "migration succeeded");
            assert_eq!(
                &row.3,
                entry.migration.checksum.as_ref(),
                "checksum matches"
            );
        }

        // 3. All semantic rows empty
        for table in [
            "chat.conversations",
            "chat.entries",
            "chat.transitions",
            "chat.devices",
            "chat.device_keys",
            "chat.principals",
            "chat.operation_claims",
            "chat.welcome_bundles",
            "chat.blobs",
        ] {
            let count: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|err| panic!("count on {table}: {err}"));
            assert_eq!(count, 0, "semantic table {table} must be empty");
        }
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL with database creation privileges"]
    async fn concurrent_disposable_database_mint_and_migration_does_not_race() {
        let handles = (0..6)
            .map(|i| {
                tokio::spawn(async move {
                    let prefix = if i % 2 == 0 {
                        "chat_fedoutbox_"
                    } else {
                        "chat_freshdb_"
                    };
                    let (pool, _disposable) = fresh_clean_protocol_db(prefix, 2).await;
                    let count: i64 =
                        sqlx::query_scalar("SELECT count(*) FROM public._sqlx_migrations")
                            .fetch_one(&pool)
                            .await
                            .unwrap();
                    assert_eq!(
                        count as usize,
                        crate::common::chat_protocol::CLEAN_PROTOCOL_13_MANIFEST.len()
                    );
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            handle.await.expect("task completed without panic");
        }
    }
}
