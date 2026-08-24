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
//! out in `common::executor_seed` (`FreshDbGuard` / `fresh_executor_db`). It is
//! re-expressed here rather than extended in place because
//! `tests/common/executor_seed.rs` is pinned byte-for-byte by
//! `chat_protocol_g7_entitlement::frozen_executor_seed_helper_is_byte_identical_to_the_sealed_baseline`
//! (`f2d0f424…`); editing it would break that seal. The two implementations are
//! deliberately behaviourally identical: unique name, `CREATE DATABASE`, and a
//! `Drop` reaper that terminates stragglers and drops the database on the normal
//! path *and* during panic unwind.
//!
//! Naming: every database minted here is `<reserved prefix><32 lowercase hex>`.
//! No reserved prefix collides with `chat_exec_` (the executor harness's own
//! namespace) or with any pre-existing database on this host, so a leaked
//! database from a killed run is attributable to exactly one target.

#![allow(dead_code)]

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

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
    // `tests/chat_protocol_device_handlers.rs`
    "chat_devhandlers_",
    // `tests/chat_protocol_auth_repository.rs`
    "chat_authrepo_",
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
    // `common::setup_test_db`, the shared legacy helper. A leak under this
    // prefix names the *helper*, not one of its fourteen consuming targets;
    // the consumers are enumerated at [`SHARED_LEGACY_DB_PREFIX`].
    "mlsds_shared_",
];

/// Prefix used by [`crate::common::setup_test_db`], the shared legacy fixture
/// helper.
///
/// Consuming targets, enumerated so a leak under this prefix has a bounded
/// suspect list (corpus: every `.rs` file under `server/tests` containing
/// `common::setup_test_db`, swept untruncated with `rg --no-ignore --hidden`):
/// `blob_quota_race`, `bootstrap_reset_group`,
/// `commit_group_change_health_counters`, `create_convo_collision`,
/// `durable_outbox_test`, `group_info_epoch_cas`, `metadata_blob_retention`,
/// `per_device_routing_helpers`, `phase_2_5_indirect_funneling`,
/// `quorum_reset_threshold`, `reset_reminder_worker`, `sequencer_transfer_cas`,
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
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            runtime.block_on(async move {
                let Ok(admin) = PgPoolOptions::new()
                    .max_connections(1)
                    .connect(&maintenance_url)
                    .await
                else {
                    return;
                };
                let _ = sqlx::query(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
                     WHERE datname = $1 AND pid <> pg_backend_pid()",
                )
                .bind(&name)
                .execute(&admin)
                .await;
                let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS \"{name}\""))
                    .execute(&admin)
                    .await;
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

/// Mint a disposable database carrying exactly the reviewed clean-protocol
/// schema, and return a pool onto it.
///
/// Uses the same reviewed migrator factory the shared fixed-target helper uses,
/// so the installed schema is the reviewed 13 and nothing else — the property
/// the shared database's ledger gate enforces, obtained here without depending
/// on the shared database.
pub async fn fresh_clean_protocol_db(
    prefix: &str,
    max_connections: u32,
) -> (PgPool, DisposableDatabase) {
    let database = DisposableDatabase::mint(prefix).await;
    let migrator = crate::common::chat_protocol::reviewed_clean_protocol_migrator()
        .await
        .expect("validate the exact reviewed clean-protocol migration manifest");
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
    let migration_result = migrator.run_direct(&mut *migration_connection).await;
    sqlx::query("RESET chat.operation_claim_activation_approved")
        .execute(&mut *migration_connection)
        .await
        .expect("reset operation-claim activation approval on the migration connection");
    migration_connection
        .close()
        .await
        .expect("close the disposable migration connection");
    migration_result.expect("install the reviewed exact-13 schema on the disposable database");
    (pool, database)
}
