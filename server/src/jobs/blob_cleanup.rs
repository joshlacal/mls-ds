use sqlx::PgPool;
use std::time::Duration;
use tokio::time::interval;
use tracing::{error, info};

use crate::blob_store::BlobStore;

/// Background worker for blob garbage collection.
///
/// Runs every hour and performs three cleanup phases:
/// 1. Soft-delete blobs that have passed their TTL (expires_at < now)
/// 2. Hard-delete blobs (S3 + DB) that were soft-deleted >1 day ago
/// 3. Clean up orphaned group metadata blobs for deleted conversations
pub async fn run_blob_cleanup_worker(pool: PgPool, blob_store: BlobStore) {
    let mut ticker = interval(Duration::from_secs(3600));

    info!("Starting blob cleanup worker (runs every hour)");

    loop {
        ticker.tick().await;

        // Phase 1: Soft-delete expired blobs
        match sqlx::query(
            "UPDATE blobs SET deleted_at = now() WHERE expires_at < now() AND deleted_at IS NULL",
        )
        .execute(&pool)
        .await
        {
            Ok(result) => {
                if result.rows_affected() > 0 {
                    info!("Soft-deleted {} expired blobs", result.rows_affected());
                }
            }
            Err(e) => error!("Blob TTL soft-delete failed: {}", e),
        }

        // Phase 2: Hard-delete blobs soft-deleted >1 day ago (S3 + DB)
        let to_purge: Vec<String> = match sqlx::query_scalar(
            "SELECT id FROM blobs WHERE deleted_at IS NOT NULL AND deleted_at < now() - INTERVAL '1 day'",
        )
        .fetch_all(&pool)
        .await
        {
            Ok(ids) => ids,
            Err(e) => {
                error!("Blob purge query failed: {}", e);
                continue;
            }
        };

        for blob_id in &to_purge {
            if let Err(e) = blob_store.delete(blob_id).await {
                error!("Failed to delete blob {} from S3: {}", blob_id, e);
                continue;
            }
            if let Err(e) = sqlx::query("DELETE FROM blobs WHERE id = $1")
                .bind(blob_id)
                .execute(&pool)
                .await
            {
                error!("Failed to hard-delete blob {} metadata: {}", blob_id, e);
            }
        }

        if !to_purge.is_empty() {
            info!("Purged {} expired blobs from S3", to_purge.len());
        }

        // Phase 3: Clean up orphaned group metadata blobs
        // Remove metadata blobs whose conversations no longer exist.
        match sqlx::query(
            r#"
            DELETE FROM group_metadata_blobs
            WHERE group_id NOT IN (SELECT id FROM conversations)
            "#,
        )
        .execute(&pool)
        .await
        {
            Ok(result) => {
                if result.rows_affected() > 0 {
                    info!(
                        "Cleaned up {} orphaned group metadata blobs",
                        result.rows_affected()
                    );
                }
            }
            Err(e) => error!("Group metadata blob cleanup failed: {}", e),
        }
    }
}
