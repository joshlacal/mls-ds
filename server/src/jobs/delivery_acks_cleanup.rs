use sqlx::PgPool;
use std::time::Duration;
use tokio::time::interval;
use tracing::{error, info, warn};

const DEFAULT_CLEANUP_INTERVAL_SECS: u64 = 86_400;

fn cleanup_interval_secs() -> u64 {
    match std::env::var("CLEANUP_INTERVAL_SECS") {
        Ok(raw) => match raw.parse::<u64>() {
            Ok(parsed) if parsed > 0 => parsed,
            _ => {
                warn!(value = %raw, fallback = DEFAULT_CLEANUP_INTERVAL_SECS, "Invalid CLEANUP_INTERVAL_SECS, using default");
                DEFAULT_CLEANUP_INTERVAL_SECS
            }
        },
        Err(_) => DEFAULT_CLEANUP_INTERVAL_SECS,
    }
}

/// Periodically removes delivery ACK records older than 30 days.
pub async fn run_delivery_acks_cleanup_worker(pool: PgPool) {
    let interval_secs = cleanup_interval_secs();
    let mut ticker = interval(Duration::from_secs(interval_secs));
    info!("Starting delivery ACKs cleanup worker (30-day retention)");
    info!(interval_secs, "Delivery ACK cleanup interval configured");

    loop {
        ticker.tick().await;

        match sqlx::query_scalar::<_, i64>(
            "WITH deleted AS (
                DELETE FROM delivery_acks
                WHERE received_at < NOW() - INTERVAL '30 days'
                RETURNING 1
            ) SELECT COUNT(*) FROM deleted",
        )
        .fetch_one(&pool)
        .await
        {
            Ok(count) if count > 0 => {
                info!(deleted = count, "Cleaned up old delivery ACKs");
            }
            Ok(_) => {} // Nothing to clean
            Err(e) => {
                error!(error = %e, "Failed to clean up delivery ACKs");
            }
        }
    }
}
