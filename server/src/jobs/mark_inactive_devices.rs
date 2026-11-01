use anyhow::Result;
use chrono::Utc;
use sqlx::PgPool;
use std::time::Duration;
use tokio::time::interval;
use tracing::{error, info};

/// Stale-device dormancy cutoff in days (Spec §6.5 / Gate 8).
pub const DEVICE_DORMANCY_DAYS: i64 = 60;

/// Background worker to mark devices dormant after 60 days without activity
/// (`last_ack_at` / `updated_at`), excluding them from active delivery-ack
/// pruning quorums until they next acknowledge or replenish.
pub async fn run_mark_inactive_devices_worker(pool: PgPool) {
    let mut ticker = interval(Duration::from_secs(86_400));

    info!("Starting mark inactive devices worker (runs every 24 hours, 60-day dormancy)");

    loop {
        ticker.tick().await;

        match mark_inactive_devices(&pool).await {
            Ok(count) if count > 0 => {
                info!(
                    count,
                    "Marked devices dormant after 60+ days without activity"
                );
            }
            Ok(_) => {
                info!("No devices due for 60-day dormancy");
            }
            Err(e) => {
                error!("Failed to mark dormant devices: {}", e);
            }
        }
    }
}

/// Mark active `chat.devices` dormant when `COALESCE(last_ack_at, updated_at, enrolled_at)`
/// is older than 60 days (`now - 60 days`).
pub async fn mark_inactive_devices(pool: &PgPool) -> Result<u64> {
    mark_inactive_devices_at(pool, Utc::now()).await
}

/// Deterministic clock seam for integration tests.
pub async fn mark_inactive_devices_at(pool: &PgPool, now: chrono::DateTime<Utc>) -> Result<u64> {
    let cutoff = now - chrono::Duration::days(DEVICE_DORMANCY_DAYS);

    let result = sqlx::query(
        r#"
        UPDATE chat.devices
           SET dormant_at = $1,
               updated_at = $1
         WHERE status = 'active'
           AND dormant_at IS NULL
           AND COALESCE(last_ack_at, updated_at, enrolled_at) < $2
        "#,
    )
    .bind(now)
    .bind(cutoff)
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as ChronoDuration;

    #[test]
    fn test_cutoff_calculation_is_60_days() {
        let now = Utc::now();
        let cutoff = now - ChronoDuration::days(DEVICE_DORMANCY_DAYS);
        let diff = now.signed_duration_since(cutoff);
        assert_eq!(diff.num_days(), 60);
    }
}
