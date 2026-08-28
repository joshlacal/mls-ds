// Disposable per-run PostgreSQL databases for inline unit and integration tests under `src/`.
//
// Provides isolated, uniquely named per-test databases that are created, migrated
// under an advisory lock on the maintenance connection, and automatically dropped on RAII cleanup
// (including on panic unwinding).

use sqlx::postgres::PgPoolOptions;
use sqlx::{Connection, PgConnection, PgPool};
use std::time::Duration;

pub const CHAT_PROTOCOL_TEST_DATABASE_NAME: &str = "catbird_chat_protocol_test_20260722";
pub const CHAT_PROTOCOL_TEST_DATABASE_URL: &str =
    "postgresql://127.0.0.1:5432/catbird_chat_protocol_test_20260722";
pub const CHAT_OPERATION_CLAIM_ACTIVATION_APPROVAL: &str = "handlers-and-legacy-apis-sealed";

/// Databases that are shared program state. Nothing in this module may create,
/// reset, or reap a database on this list.
pub const PROTECTED_DATABASE_NAMES: &[&str] = &[
    "catbird_chat_protocol_test_20260722",
    "catbird",
    "catbird_test",
    "catbird_mls_v2_test_20260722",
    "postgres",
    "template0",
    "template1",
];

/// Name prefixes reserved for disposable per-run databases minted by this module.
pub const DISPOSABLE_PREFIXES: &[&str] = &[
    "auth_device_",
    "repo_crypto_",
    "fed_resolver_",
    "fed_queue_",
    "fed_upstream_",
    "db_mod_",
    "actor_convo_",
    "actor_reg_",
    "actor_choke_",
    "ds_fetchkp_",
    "chat_creation_",
    "chat_blobs_",
    "src_legacy_",
];

/// Advisory lock key on `/postgres` used across all full catalog migration runs.
pub const DISPOSABLE_MIGRATION_ADVISORY_LOCK_KEY: i64 = 0x43415442_49524431;

static IN_PROCESS_MIGRATION_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

/// Validates whether a database name is permissible to mint or drop.
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

/// Validates whether a prefix is reserved for disposable databases.
pub fn validate_disposable_prefix(prefix: &str) -> Result<(), String> {
    if DISPOSABLE_PREFIXES.contains(&prefix) {
        Ok(())
    } else {
        Err(format!("{prefix:?} is not a reserved disposable prefix"))
    }
}

/// Validates that a connection string points to the exact reviewed literal local clean-chat target.
pub fn validate_chat_protocol_database_url(
    value: Option<&str>,
) -> Result<&'static str, &'static str> {
    match value {
        Some(CHAT_PROTOCOL_TEST_DATABASE_URL) => Ok(CHAT_PROTOCOL_TEST_DATABASE_NAME),
        _ => Err("TEST_DATABASE_URL must exactly equal the reviewed literal local clean-chat target"),
    }
}

/// Validates that the operation-claim activation approval token matches the reviewed value.
pub fn validate_chat_protocol_activation_approval(
    value: Option<&str>,
) -> Result<(), &'static str> {
    match value {
        Some(CHAT_OPERATION_CLAIM_ACTIVATION_APPROVAL) => Ok(()),
        _ => Err(
            "CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED must exactly equal \
             handlers-and-legacy-apis-sealed",
        ),
    }
}

/// Derives the maintenance connection URL (`/postgres`) from `TEST_DATABASE_URL`.
pub fn maintenance_url_from_env() -> Result<String, String> {
    let database_url = std::env::var("TEST_DATABASE_URL")
        .map_err(|_| "TEST_DATABASE_URL is not set".to_owned())?;
    validate_chat_protocol_database_url(Some(&database_url))
        .map_err(|error| format!("unsafe TEST_DATABASE_URL for the disposable-DB harness: {error}"))?;
    let activation_approval = std::env::var("CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED")
        .map_err(|_| "CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED is not set".to_owned())?;
    validate_chat_protocol_activation_approval(Some(&activation_approval))
        .map_err(|error| format!("invalid operation-claim activation approval: {error}"))?;
    let mut parsed = url::Url::parse(&database_url).map_err(|error| error.to_string())?;
    parsed.set_path("/postgres");
    Ok(parsed.into())
}

pub struct MigrationLockGuard<'a> {
    _in_process: tokio::sync::MutexGuard<'a, ()>,
    _maintenance_conn: PgConnection,
}

/// Acquires both the process-local mutex and the PostgreSQL session advisory lock on `/postgres`.
pub async fn acquire_migration_lock() -> MigrationLockGuard<'static> {
    let in_process = IN_PROCESS_MIGRATION_LOCK.lock().await;
    let maintenance_url = maintenance_url_from_env().expect("loopback maintenance URL");
    let mut conn = PgConnection::connect(&maintenance_url)
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

/// A freshly created, uniquely named disposable database plus RAII reaper.
pub struct DisposableDatabase {
    maintenance_url: String,
    name: String,
    url: String,
}

impl DisposableDatabase {
    /// Create a database named `<prefix><32 hex>`, refusing any name rejected by
    /// [`validate_disposable_database_name`].
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

    /// Open a connection pool against this disposable database.
    pub async fn connect(&self, max_connections: u32) -> PgPool {
        assert!(max_connections > 0, "pool must have at least one connection");
        PgPoolOptions::new()
            .max_connections(max_connections)
            .connect(&self.url)
            .await
            .expect("connect to the disposable per-run database")
    }
}

impl Drop for DisposableDatabase {
    fn drop(&mut self) {
        if let Err(error) = validate_disposable_database_name(&self.name) {
            eprintln!("disposable-database reaper refused to drop a database: {error}");
            return;
        }
        let maintenance_url = self.maintenance_url.clone();
        let name = self.name.clone();
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
                    eprintln!("disposable-database reaper failed to drop database {name}: {error}");
                }
            });
        })
        .join();
    }
}

/// Mint a disposable database and run the full migration catalog under the migration advisory lock.
pub async fn fresh_fully_migrated_db(prefix: &str) -> DisposableDatabase {
    let database = DisposableDatabase::mint(prefix).await;
    {
        let _lock = acquire_migration_lock().await;
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
    }
    database
}

/// Mint a disposable, fully migrated database and open a pool directly.
pub async fn fresh_legacy_pool(
    prefix: &str,
    max_connections: u32,
    min_connections: u32,
) -> (PgPool, DisposableDatabase) {
    let database = fresh_fully_migrated_db(prefix).await;
    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .min_connections(min_connections)
        .acquire_timeout(Duration::from_secs(30))
        .idle_timeout(Duration::from_secs(600))
        .connect(database.url())
        .await
        .expect("initialize a pool against the disposable per-test database");
    (pool, database)
}

/// Mint a disposable database, run the full catalog, and return an open connection pool.
pub async fn fresh_full_catalog_pool(
    prefix: &str,
    max_connections: u32,
) -> (PgPool, DisposableDatabase) {
    let database = fresh_fully_migrated_db(prefix).await;
    let pool = database.connect(max_connections).await;
    (pool, database)
}

