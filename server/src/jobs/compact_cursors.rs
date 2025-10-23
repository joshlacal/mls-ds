use anyhow::Result;
use sqlx::PgPool;
use std::time::Duration;
use tokio::time::interval;
use tracing::{info, warn};

/// Compaction configuration
pub struct CompactionConfig {
    /// Retention window for messageEvents (in seconds)
    pub message_retention_secs: i64,
    /// Retention window for ephemeral events (typing) in seconds
    pub ephemeral_retention_secs: i64,
    /// How often to run compaction (in seconds)
    pub interval_secs: u64,
}

impl Default for CompactionConfig {
    fn default() -> Self {
        // 20GB / 100 bytes per event ≈ 200M events
        // At 10M events/day, that's ~20 days
        // Use 14 days for messages, 1 day for ephemeral
        Self {
            message_retention_secs: 14 * 24 * 60 * 60, // 14 days
            ephemeral_retention_secs: 24 * 60 * 60,    // 1 day
            interval_secs: 24 * 60 * 60,               // Run daily
        }
    }
}

/// Background worker for cursor compaction and retention enforcement
pub async fn run_compaction_worker(pool: PgPool, config: CompactionConfig) {
    let mut ticker = interval(Duration::from_secs(config.interval_secs));

    info!(
        message_retention_days = config.message_retention_secs / 86400,
        ephemeral_retention_hours = config.ephemeral_retention_secs / 3600,
        interval_hours = config.interval_secs / 3600,
        "Starting cursor compaction worker"
    );

    loop {
        ticker.tick().await;

        info!("Running cursor compaction");

        if let Err(e) = compact_events(&pool, &config).await {
            warn!(error = ?e, "Compaction failed");
        }
    }
}

/// Perform compaction: delete old ephemeral and message events
async fn compact_events(pool: &PgPool, config: &CompactionConfig) -> Result<()> {
    let now = chrono::Utc::now();

    // Delete ephemeral events (typingEvent) older than retention
    let ephemeral_cutoff = now - chrono::Duration::seconds(config.ephemeral_retention_secs);
    let ephemeral_deleted = sqlx::query!(
        r#"
        DELETE FROM event_stream
        WHERE event_type = 'typingEvent'
          AND emitted_at < $1
        "#,
        ephemeral_cutoff
    )
    .execute(pool)
    .await?
    .rows_affected();

    info!(
        deleted = ephemeral_deleted,
        cutoff = %ephemeral_cutoff,
        "Compacted ephemeral events"
    );

    // Delete old messageEvents beyond retention window
    let message_cutoff = now - chrono::Duration::seconds(config.message_retention_secs);
    let message_deleted = sqlx::query!(
        r#"
        DELETE FROM event_stream
        WHERE event_type IN ('messageEvent', 'reactionEvent')
          AND emitted_at < $1
        "#,
        message_cutoff
    )
    .execute(pool)
    .await?
    .rows_affected();

    info!(
        deleted = message_deleted,
        cutoff = %message_cutoff,
        "Compacted message/reaction events"
    );

    // Clean up stale cursors (no activity in 2x retention window)
    let cursor_cutoff = now - chrono::Duration::seconds(config.message_retention_secs * 2);
    let cursors_deleted = sqlx::query!(
        r#"
        DELETE FROM cursors
        WHERE updated_at < $1
        "#,
        cursor_cutoff
    )
    .execute(pool)
    .await?
    .rows_affected();

    info!(
        deleted = cursors_deleted,
        cutoff = %cursor_cutoff,
        "Cleaned stale cursors"
    );

    // Calculate total event_stream size for monitoring
    let size_result = sqlx::query!(
        r#"
        SELECT COUNT(*) as count,
               pg_total_relation_size('event_stream') as size_bytes
        FROM event_stream
        "#
    )
    .fetch_one(pool)
    .await?;

    let total_events = size_result.count.unwrap_or(0);
    let size_bytes = size_result.size_bytes.unwrap_or(0);
    let size_gb = size_bytes as f64 / (1024.0 * 1024.0 * 1024.0);

    info!(
        total_events = total_events,
        size_gb = format!("{:.2}", size_gb),
        "Event stream size after compaction"
    );

    if size_gb > 20.0 {
        warn!(
            size_gb = format!("{:.2}", size_gb),
            "Event stream exceeds 20GB threshold"
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = CompactionConfig::default();
        assert_eq!(config.message_retention_secs, 14 * 24 * 60 * 60);
        assert_eq!(config.ephemeral_retention_secs, 24 * 60 * 60);
        assert_eq!(config.interval_secs, 24 * 60 * 60);
    }
}
