use std::sync::Arc;
use std::time::Duration;

use sqlx::PgPool;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use super::outbound::{OutboundClient, OutboundError};
use crate::auth::AuthMiddleware;

// ---------------------------------------------------------------------------
// Queue item
// ---------------------------------------------------------------------------

/// A single row from the `outbound_queue` table.
#[derive(Debug, Clone)]
pub struct QueueItem {
    pub id: String,
    pub target_ds_did: String,
    pub target_endpoint: String,
    pub method: String,
    pub payload: Vec<u8>,
    pub convo_id: String,
    pub retry_count: i32,
    pub max_retries: i32,
}

// ---------------------------------------------------------------------------
// Queue stats (monitoring)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct QueueStats {
    pub pending: i64,
    pub delivered: i64,
    pub failed: i64,
    pub total: i64,
}

// ---------------------------------------------------------------------------
// OutboundQueue
// ---------------------------------------------------------------------------

/// Manages the persistent outbound delivery retry queue backed by PostgreSQL.
pub struct OutboundQueue {
    pool: PgPool,
    auth_middleware: AuthMiddleware,
}

impl OutboundQueue {
    pub fn new(pool: PgPool, auth_middleware: AuthMiddleware) -> Self {
        Self {
            pool,
            auth_middleware,
        }
    }

    // -- Enqueue ----------------------------------------------------------------

    /// Enqueue a failed delivery for later retry.
    pub async fn enqueue(
        &self,
        target_ds_did: &str,
        target_endpoint: &str,
        method: &str,
        payload: &[u8],
        convo_id: &str,
        error_msg: &str,
    ) -> Result<String, sqlx::Error> {
        let id = ulid::Ulid::new().to_string();
        let initial_delay_secs: f64 = 5.0;

        sqlx::query(
            "INSERT INTO outbound_queue \
               (id, target_ds_did, target_endpoint, method, payload, convo_id, last_error, next_retry_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, NOW() + make_interval(secs => $8))",
        )
        .bind(&id)
        .bind(target_ds_did)
        .bind(target_endpoint)
        .bind(method)
        .bind(payload)
        .bind(convo_id)
        .bind(error_msg)
        .bind(initial_delay_secs)
        .execute(&self.pool)
        .await?;

        debug!(queue_id = %id, target_ds_did, method, convo_id, "Enqueued for retry");
        Ok(id)
    }

    // -- Background worker ------------------------------------------------------

    /// Run the background retry worker. Call from server startup; it returns
    /// when `shutdown` is cancelled.
    pub async fn run_worker(
        &self,
        outbound: Arc<OutboundClient>,
        auth_sign: Arc<dyn Fn(&str, &str) -> Result<String, String> + Send + Sync>,
        shutdown: CancellationToken,
    ) {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        info!("Outbound queue worker started");

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match self.process_pending_batch(&outbound, auth_sign.as_ref()).await {
                        Ok(0) => {}
                        Ok(n) => debug!(processed = n, "Processed outbound queue items"),
                        Err(e) => error!(error = %e, "Outbound queue worker error"),
                    }
                }
                _ = shutdown.cancelled() => {
                    info!("Outbound queue worker shutting down");
                    break;
                }
            }
        }
    }

    // -- Batch processing -------------------------------------------------------

    async fn process_pending_batch(
        &self,
        outbound: &OutboundClient,
        auth_sign: &(dyn Fn(&str, &str) -> Result<String, String> + Send + Sync),
    ) -> Result<usize, sqlx::Error> {
        let rows: Vec<(String, String, String, String, Vec<u8>, String, i32, i32)> =
            sqlx::query_as(
                "SELECT id, target_ds_did, target_endpoint, method, payload, convo_id, \
                    retry_count, max_retries \
             FROM outbound_queue \
             WHERE status = 'pending' AND next_retry_at <= NOW() \
             ORDER BY next_retry_at ASC \
             LIMIT 10",
            )
            .fetch_all(&self.pool)
            .await?;

        let count = rows.len();
        for (
            id,
            target_ds_did,
            target_endpoint,
            method,
            payload,
            convo_id,
            retry_count,
            max_retries,
        ) in rows
        {
            let item = QueueItem {
                id,
                target_ds_did,
                target_endpoint,
                method,
                payload,
                convo_id,
                retry_count,
                max_retries,
            };
            self.process_item(&item, outbound, auth_sign).await;
        }
        Ok(count)
    }

    // -- Single item processing -------------------------------------------------

    async fn process_item(
        &self,
        item: &QueueItem,
        outbound: &OutboundClient,
        auth_sign: &(dyn Fn(&str, &str) -> Result<String, String> + Send + Sync),
    ) {
        let target_endpoint = match self.resolve_target_endpoint(item).await {
            Ok(endpoint) => endpoint,
            Err(e) => {
                error!(
                    queue_id = %item.id,
                    target_ds = %item.target_ds_did,
                    error = %e,
                    "Unable to resolve target endpoint for queued delivery"
                );
                let _ = self.mark_failed(&item.id, &e.to_string()).await;
                return;
            }
        };

        let token = match auth_sign(&item.target_ds_did, &item.method) {
            Ok(t) => t,
            Err(e) => {
                error!(queue_id = %item.id, error = %e, "Failed to sign outbound request");
                let _ = self
                    .mark_failed(&item.id, &format!("Auth signing failed: {e}"))
                    .await;
                return;
            }
        };

        let body: serde_json::Value = match serde_json::from_slice(&item.payload) {
            Ok(v) => v,
            Err(e) => {
                error!(queue_id = %item.id, error = %e, "Invalid payload in queue");
                let _ = self
                    .mark_failed(&item.id, &format!("Invalid payload: {e}"))
                    .await;
                return;
            }
        };

        match outbound
            .call_procedure(&target_endpoint, &item.method, &token, &body)
            .await
        {
            Ok(resp) if resp.accepted => {
                debug!(queue_id = %item.id, "Retry delivery succeeded");
                if let Some(ref ack) = resp.ack {
                    // Validate ACK fields match the delivery we sent
                    let fields_valid =
                        ack.receiver_ds_did == item.target_ds_did && ack.convo_id == item.convo_id;
                    if !fields_valid {
                        warn!(
                            queue_id = %item.id,
                            expected_ds = %item.target_ds_did,
                            got_ds = %ack.receiver_ds_did,
                            expected_convo = %item.convo_id,
                            got_convo = %ack.convo_id,
                            "Delivery ACK field mismatch — possible forgery, skipping storage"
                        );
                    } else {
                        // Attempt DID-doc-based signature verification
                        match self.auth_middleware.resolve_did(&ack.receiver_ds_did).await {
                            Ok(did_doc) => {
                                if let Some(verifying_key) = crate::auth::extract_p256_key(&did_doc)
                                {
                                    if ack.verify(&verifying_key) {
                                        debug!(
                                            queue_id = %item.id,
                                            "ACK signature verified for queue item"
                                        );
                                        if let Err(e) =
                                            crate::db::store_delivery_ack(&self.pool, ack).await
                                        {
                                            warn!(queue_id = %item.id, error = %e, "Failed to store delivery ack");
                                        }
                                    } else {
                                        warn!(
                                            queue_id = %item.id,
                                            remote_ds = %crate::crypto::redact_for_log(&ack.receiver_ds_did),
                                            "ACK signature verification FAILED — skipping storage"
                                        );
                                    }
                                } else {
                                    warn!(
                                        queue_id = %item.id,
                                        remote_ds = %crate::crypto::redact_for_log(&ack.receiver_ds_did),
                                        "No P-256 key found in DID doc — storing ACK field-validated only"
                                    );
                                    if let Err(e) =
                                        crate::db::store_delivery_ack(&self.pool, ack).await
                                    {
                                        warn!(queue_id = %item.id, error = %e, "Failed to store delivery ack");
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(
                                    queue_id = %item.id,
                                    error = %e,
                                    "DID resolution failed for ACK verification — storing field-validated only"
                                );
                                if let Err(e) = crate::db::store_delivery_ack(&self.pool, ack).await
                                {
                                    warn!(queue_id = %item.id, error = %e, "Failed to store delivery ack");
                                }
                            }
                        }
                    }
                }
                let _ = self.mark_delivered(&item.id).await;
            }
            Ok(resp) => {
                let reason = resp.message.unwrap_or_else(|| "rejected".to_string());
                warn!(queue_id = %item.id, reason = %reason, "Remote DS rejected delivery");
                let _ = self.mark_failed(&item.id, &reason).await;
            }
            Err(e) if e.is_retryable() && item.retry_count < item.max_retries => {
                let delay = backoff_delay(item.retry_count);
                warn!(
                    queue_id = %item.id,
                    retry = item.retry_count + 1,
                    next_retry_secs = delay.as_secs(),
                    error = %e,
                    "Retryable failure, scheduling next attempt"
                );
                let _ = self
                    .schedule_retry(&item.id, item.retry_count + 1, &e.to_string(), delay)
                    .await;
            }
            Err(e) => {
                error!(
                    queue_id = %item.id,
                    retries = item.retry_count,
                    error = %e,
                    "Non-retryable or max retries exceeded"
                );
                let _ = self.mark_failed(&item.id, &e.to_string()).await;
            }
        }
    }

    async fn resolve_target_endpoint(&self, item: &QueueItem) -> Result<String, OutboundError> {
        if !item.target_endpoint.trim().is_empty() {
            return Ok(item.target_endpoint.clone());
        }

        let cached_endpoint = sqlx::query_scalar::<_, String>(
            "SELECT endpoint FROM ds_endpoints WHERE did = $1 AND expires_at > NOW()",
        )
        .bind(&item.target_ds_did)
        .fetch_optional(&self.pool)
        .await
        .ok()
        .flatten();

        if let Some(endpoint) = cached_endpoint {
            return Ok(endpoint);
        }

        if let Some(derived_endpoint) = did_web_to_endpoint(&item.target_ds_did) {
            return Ok(derived_endpoint);
        }

        Err(OutboundError::RequestFailed {
            endpoint: item.target_ds_did.clone(),
            reason: "target endpoint missing and DS endpoint could not be resolved".to_string(),
        })
    }

    // -- Status mutations -------------------------------------------------------

    async fn mark_delivered(&self, id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE outbound_queue SET status = 'delivered' WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn mark_failed(&self, id: &str, error_msg: &str) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE outbound_queue SET status = 'failed', last_error = $2 WHERE id = $1")
            .bind(id)
            .bind(error_msg)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn schedule_retry(
        &self,
        id: &str,
        new_count: i32,
        error_msg: &str,
        delay: Duration,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE outbound_queue \
             SET retry_count = $2, last_error = $3, \
                 next_retry_at = NOW() + make_interval(secs => $4) \
             WHERE id = $1",
        )
        .bind(id)
        .bind(new_count)
        .bind(error_msg)
        .bind(delay.as_secs() as f64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // -- Maintenance ------------------------------------------------------------

    /// Delete old delivered/failed items older than `max_age_hours`.
    pub async fn cleanup_old(&self, max_age_hours: i64) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            "DELETE FROM outbound_queue \
             WHERE status IN ('delivered', 'failed') \
               AND created_at < NOW() - make_interval(hours => $1)",
        )
        .bind(max_age_hours as f64)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Queue statistics for monitoring / health endpoints.
    pub async fn stats(&self) -> Result<QueueStats, sqlx::Error> {
        let row: (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT \
                COUNT(*) FILTER (WHERE status = 'pending'), \
                COUNT(*) FILTER (WHERE status = 'delivered'), \
                COUNT(*) FILTER (WHERE status = 'failed'), \
                COUNT(*) \
             FROM outbound_queue",
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(QueueStats {
            pending: row.0,
            delivered: row.1,
            failed: row.2,
            total: row.3,
        })
    }
}

// ---------------------------------------------------------------------------
// Backoff
// ---------------------------------------------------------------------------

/// Exponential backoff: 5 s → 10 s → 20 s → 40 s → 80 s (capped at 5 min).
fn backoff_delay(retry_count: i32) -> Duration {
    let base = 5u64;
    let delay = base.saturating_mul(2u64.saturating_pow(retry_count as u32));
    Duration::from_secs(delay.min(300))
}

fn did_web_to_endpoint(did: &str) -> Option<String> {
    let web_path = did.strip_prefix("did:web:")?;
    let domain = web_path.replace(':', "/");
    Some(format!("https://{}", domain))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_values() {
        assert_eq!(backoff_delay(0), Duration::from_secs(5));
        assert_eq!(backoff_delay(1), Duration::from_secs(10));
        assert_eq!(backoff_delay(2), Duration::from_secs(20));
        assert_eq!(backoff_delay(3), Duration::from_secs(40));
        assert_eq!(backoff_delay(4), Duration::from_secs(80));
        assert_eq!(backoff_delay(5), Duration::from_secs(160));
        assert_eq!(backoff_delay(6), Duration::from_secs(300)); // capped
        assert_eq!(backoff_delay(10), Duration::from_secs(300)); // still capped
    }

    #[test]
    fn derive_endpoint_from_did_web() {
        assert_eq!(
            did_web_to_endpoint("did:web:ds.example.com"),
            Some("https://ds.example.com".to_string())
        );
        assert_eq!(
            did_web_to_endpoint("did:web:example.com:mls"),
            Some("https://example.com/mls".to_string())
        );
        assert_eq!(did_web_to_endpoint("did:plc:abc123"), None);
    }
}
