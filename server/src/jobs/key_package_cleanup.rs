use anyhow::Result;
use sqlx::PgPool;
use std::time::Duration;
use tokio::time::interval;
use tracing::{error, info};

/// Background worker for key package cleanup
/// Deletes expired or consumed key packages to reduce storage and improve queries
pub async fn run_key_package_cleanup_worker(pool: PgPool) {
    let mut ticker = interval(Duration::from_secs(1800)); // Run every 30 minutes

    info!("Starting key package cleanup worker (runs every 30 minutes)");

    loop {
        ticker.tick().await;

        info!("Starting key package cleanup");

        // Get max packages per device from env (default 200)
        let max_per_device = std::env::var("MAX_KEY_PACKAGES_PER_DEVICE")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(200);

        // Cleanup expired key packages
        match crate::db::delete_expired_key_packages(&pool).await {
            Ok(count) if count > 0 => {
                info!("Cleaned up {} expired key packages", count);
            }
            Ok(_) => {
                info!("No expired key packages to clean up");
            }
            Err(e) => {
                error!("Expired key package cleanup failed: {}", e);
            }
        }

        // Cleanup consumed key packages older than 24 hours
        match crate::db::delete_consumed_key_packages(&pool, 24).await {
            Ok(count) if count > 0 => {
                info!("Cleaned up {} consumed key packages (older than 24 hours)", count);
            }
            Ok(_) => {
                info!("No consumed key packages to clean up");
            }
            Err(e) => {
                error!("Consumed key package cleanup failed: {}", e);
            }
        }

        // Cleanup old unconsumed key packages (older than 7 days)
        match crate::db::delete_old_unconsumed_key_packages(&pool, 7).await {
            Ok(count) if count > 0 => {
                info!("Cleaned up {} unconsumed key packages (older than 7 days)", count);
            }
            Ok(_) => {
                info!("No old unconsumed key packages to clean up");
            }
            Err(e) => {
                error!("Old unconsumed key package cleanup failed: {}", e);
            }
        }

        // Enforce per-device limit
        match crate::db::enforce_key_package_limit(&pool, max_per_device).await {
            Ok(count) if count > 0 => {
                info!("Enforced limit of {} packages per device, removed {} excess key packages", max_per_device, count);
            }
            Ok(_) => {
                info!("All devices within key package limit of {}", max_per_device);
            }
            Err(e) => {
                error!("Key package limit enforcement failed: {}", e);
            }
        }

        info!("Key package cleanup complete");
    }
}
