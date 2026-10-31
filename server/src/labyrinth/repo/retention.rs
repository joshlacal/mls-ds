//! Retention for the clean-slate `labyrinth` directory (`purgeMailbox`, `deleteAccountData`,
//! and 7-day idempotency GC on `labyrinth.operations`).

use chrono::{DateTime, Duration, Utc};
use sqlx::PgConnection;

use crate::labyrinth::error::LabyrinthResult;
use crate::storage::DbPool;

/// Idempotency records in `labyrinth.operations` are kept for 7 days.
pub const OPERATION_RETENTION_DAYS: i64 = 7;

/// `purgeMailbox`: raise `labyrinth.epoch_head_floors` to `MAX(epoch_number)` and delete
/// `labyrinth.epoch_heads` for `did` so any reset must restart strictly at `floor + 1` (`L-F01`).
pub async fn purge_mailbox(conn: &mut PgConnection, did: &str) -> LabyrinthResult<()> {
    super::advisory_lock(conn, &format!("labyrinth.epoch_heads:{did}")).await?;
    sqlx::query("SELECT labyrinth.purge_mailbox($1)")
        .bind(did)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// `deleteAccountData`: purge the account's epoch-head directory chain while retaining
/// 7-day `labyrinth.operations` idempotency records so pre-deletion replays answer from
/// their stored response rather than re-executing.
pub async fn purge_account(
    conn: &mut PgConnection,
    did: &str,
    _at: DateTime<Utc>,
) -> LabyrinthResult<()> {
    purge_mailbox(conn, did).await
}

/// Counts removed by one retention GC pass.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct GcCounts {
    pub operations: i64,
}

/// Expire `labyrinth.operations` older than [`OPERATION_RETENTION_DAYS`], up to `batch` rows.
pub async fn run_gc(pool: &DbPool, now: DateTime<Utc>, batch: i32) -> LabyrinthResult<GcCounts> {
    let mut tx = pool.begin().await?;
    let operations: i32 = sqlx::query_scalar("SELECT labyrinth.gc_operations($1, $2)")
        .bind(now - Duration::days(OPERATION_RETENTION_DAYS))
        .bind(batch)
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(GcCounts {
        operations: i64::from(operations),
    })
}

/// Run [`run_gc`] every `interval` for the life of the process.
pub async fn gc_worker(pool: DbPool, interval: std::time::Duration) {
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        match run_gc(&pool, Utc::now(), 500).await {
            Ok(counts) if counts != GcCounts::default() => {
                tracing::info!(?counts, "labyrinth retention pass");
            }
            Ok(_) => {}
            Err(error) => tracing::warn!(%error, "labyrinth retention pass failed"),
        }
    }
}
