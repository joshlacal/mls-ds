use anyhow::{Context, Result};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::time::Duration;

pub type DbPool = PgPool;

/// Database configuration
#[derive(Debug, Clone)]
pub struct DbConfig {
    pub database_url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub acquire_timeout: Duration,
    pub idle_timeout: Duration,
}

impl Default for DbConfig {
    fn default() -> Self {
        Self {
            database_url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://localhost/catbird".to_string()),
            max_connections: std::env::var("DATABASE_MAX_CONNECTIONS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(90),
            min_connections: 2,
            acquire_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(600),
        }
    }
}

/// Initialize database connection pool with configuration
pub async fn init_db(config: DbConfig) -> Result<DbPool> {
    let pool = PgPoolOptions::new()
        .max_connections(config.max_connections)
        .min_connections(config.min_connections)
        .acquire_timeout(config.acquire_timeout)
        .idle_timeout(config.idle_timeout)
        .connect(&config.database_url)
        .await
        .context("Failed to connect to database")?;

    tracing::warn!(
        "Database pool initialized with max_connections={}, min_connections={}, acquire_timeout={:?}",
        config.max_connections,
        config.min_connections,
        config.acquire_timeout
    );

    if std::env::var("SKIP_MIGRATIONS").is_ok() {
        tracing::warn!("SKIP_MIGRATIONS set — skipping migration check");
    } else {
        repair_2026_04_migration_versions(&pool).await?;

        let mut migration_connection = pool
            .acquire()
            .await
            .context("acquire migration connection")?;
        if std::env::var("CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED").as_deref()
            == Ok("handlers-and-legacy-apis-sealed")
        {
            sqlx::query(
                "SET chat.operation_claim_activation_approved = 'handlers-and-legacy-apis-sealed'",
            )
            .execute(&mut *migration_connection)
            .await
            .context("authorize operation-claim activation on the migration connection")?;
        }
        let migration_result = sqlx::migrate!("./migrations")
            .run(&mut *migration_connection)
            .await;
        if std::env::var("CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED").as_deref()
            == Ok("handlers-and-legacy-apis-sealed")
        {
            sqlx::query("RESET chat.operation_claim_activation_approved")
                .execute(&mut *migration_connection)
                .await
                .context("reset operation-claim activation approval on the migration connection")?;
        }
        migration_connection
            .close()
            .await
            .context("close the migration connection")?;
        migration_result.context("Failed to run migrations")?;
    }

    Ok(pool)
}

async fn repair_2026_04_migration_versions(pool: &DbPool) -> Result<()> {
    let repairs: &[(i64, i64, &str)] = &[
        (20260403, 20260403100000, "drop read receipts"),
        (20260404, 20260404100000, "add confirmation tag"),
        (20260405, 20260405100000, "group reset support"),
        (20260406, 20260406100000, "drop message reactions"),
        (20260407, 20260407100000, "recovery failures"),
        (
            20260418,
            20260418100000,
            "reset votes and epoch authenticators",
        ),
        (20260425, 20260425100000, "messages wire epoch"),
        (20260426, 20260426100000, "reset votes failure mode"),
        (20260427, 20260427100000, "commit health columns"),
        (20260428, 20260428100000, "groupinfo 404 health columns"),
    ];

    let table_exists: (bool,) = sqlx::query_as(
        "SELECT EXISTS (
            SELECT 1 FROM information_schema.tables
            WHERE table_schema = current_schema()
              AND table_name = '_sqlx_migrations'
        )",
    )
    .fetch_one(pool)
    .await
    .context("Failed to probe _sqlx_migrations existence")?;
    if !table_exists.0 {
        return Ok(());
    }

    let mut tx = pool
        .begin()
        .await
        .context("Failed to begin migration repair tx")?;

    let mut total_updated: u64 = 0;
    for (legacy_version, new_version, new_description) in repairs {
        sqlx::query(
            "DELETE FROM _sqlx_migrations \
             WHERE version = $1 \
               AND EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = $2)",
        )
        .bind(new_version)
        .bind(legacy_version)
        .execute(&mut *tx)
        .await
        .with_context(|| {
            format!(
                "Failed to drop bootstrap-inserted _sqlx_migrations row for new version {}",
                new_version
            )
        })?;

        let result = sqlx::query(
            "UPDATE _sqlx_migrations \
             SET version = $1, description = $2 \
             WHERE version = $3",
        )
        .bind(new_version)
        .bind(new_description)
        .bind(legacy_version)
        .execute(&mut *tx)
        .await
        .with_context(|| {
            format!(
                "Failed to repair _sqlx_migrations row for legacy version {}",
                legacy_version
            )
        })?;
        total_updated += result.rows_affected();
    }

    tx.commit()
        .await
        .context("Failed to commit migration repair tx")?;

    if total_updated > 0 {
        tracing::warn!(
            updated_rows = total_updated,
            "Migrated {} legacy `_sqlx_migrations` rows to 14-digit versions \
             (chore/ci-cleanup repair). One-time bridge from the \
             YYYYMMDD_NNN_*.sql naming format.",
            total_updated
        );
    }

    Ok(())
}

/// Initialize database with default configuration
pub async fn init_db_default() -> Result<DbPool> {
    init_db(DbConfig::default()).await
}

/// Check database connectivity.
pub async fn health_check(pool: &DbPool) -> Result<bool> {
    let one: i32 = sqlx::query_scalar("SELECT 1")
        .fetch_one(pool)
        .await
        .context("health check SELECT 1")?;
    Ok(one == 1)
}
