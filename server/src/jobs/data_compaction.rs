use anyhow::Result;
use sqlx::PgPool;
use std::time::Duration;
use tokio::time::interval;
use tracing::{error, info};

/// Background worker for data compaction
/// Deletes old messages and events to comply with data retention policy
pub async fn run_compaction_worker(pool: PgPool) {
    let mut ticker = interval(Duration::from_secs(3600)); // Run every hour

    info!("Starting data compaction worker (runs every hour)");

    loop {
        ticker.tick().await;

        info!("Starting compaction worker");

        // Get TTL from env (default 30 days for messages, 7 days for events)
        let message_ttl = std::env::var("MESSAGE_TTL_DAYS")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(30);

        let event_ttl = std::env::var("EVENT_STREAM_TTL_DAYS")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(7);

        // Compact messages
        match crate::db::compact_messages(&pool, message_ttl).await {
            Ok(count) if count > 0 => {
                info!("Compacted {} old messages (older than {} days)", count, message_ttl);
            }
            Ok(_) => {
                info!("No messages to compact");
            }
            Err(e) => {
                error!("Message compaction failed: {}", e);
            }
        }

        // Compact event stream
        match crate::db::compact_event_stream(&pool, event_ttl).await {
            Ok(count) if count > 0 => {
                info!("Compacted {} old events (older than {} days)", count, event_ttl);
            }
            Ok(_) => {
                info!("No events to compact");
            }
            Err(e) => {
                error!("Event compaction failed: {}", e);
            }
        }

        // Compact welcome messages
        match crate::db::compact_welcome_messages(&pool).await {
            Ok(count) if count > 0 => {
                info!("Compacted {} old consumed welcome messages (older than 24 hours)", count);
            }
            Ok(_) => {
                info!("No welcome messages to compact");
            }
            Err(e) => {
                error!("Welcome message compaction failed: {}", e);
            }
        }

        info!("Compaction worker complete");
    }
}
