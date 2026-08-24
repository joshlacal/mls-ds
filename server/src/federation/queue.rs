use std::sync::Arc;
use std::time::Duration;

use sqlx::PgPool;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::auth::AuthMiddleware;
use crate::identity::canonical_did;
use super::errors::FederationError;
use super::outbound::{DsResponse, OutboundClient, OutboundError};
use super::peer_policy;
use super::resolver::{DsResolver, ValidatedRemoteDestination};

const OUTBOUND_QUEUE_PER_PEER_PENDING_CAP_ENV: &str =
    "FEDERATION_OUTBOUND_QUEUE_PER_PEER_PENDING_CAP";
const OUTBOUND_QUEUE_PER_CONVO_PEER_PENDING_CAP_ENV: &str =
    "FEDERATION_OUTBOUND_QUEUE_PER_CONVO_PEER_PENDING_CAP";
const OUTBOUND_QUEUE_PER_PEER_PENDING_CAP_DEFAULT: i64 = 500;
const OUTBOUND_QUEUE_PER_CONVO_PEER_PENDING_CAP_DEFAULT: i64 = 100;
const OUTBOUND_QUEUE_PENDING_CAP_MAX: i64 = 100_000;

fn parse_pending_cap(raw: Option<&str>, default: i64) -> i64 {
    raw.and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(default)
        .clamp(1, OUTBOUND_QUEUE_PENDING_CAP_MAX)
}

fn pending_cap_from_env(var_name: &str, default: i64) -> i64 {
    parse_pending_cap(std::env::var(var_name).ok().as_deref(), default)
}

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
    resolver: Arc<DsResolver>,
    per_peer_pending_cap: i64,
    per_convo_peer_pending_cap: i64,
}

impl OutboundQueue {
    pub fn new(
        pool: PgPool,
        auth_middleware: AuthMiddleware,
        resolver: Arc<DsResolver>,
    ) -> Self {
        let per_peer_pending_cap = pending_cap_from_env(
            OUTBOUND_QUEUE_PER_PEER_PENDING_CAP_ENV,
            OUTBOUND_QUEUE_PER_PEER_PENDING_CAP_DEFAULT,
        );
        let per_convo_peer_pending_cap = pending_cap_from_env(
            OUTBOUND_QUEUE_PER_CONVO_PEER_PENDING_CAP_ENV,
            OUTBOUND_QUEUE_PER_CONVO_PEER_PENDING_CAP_DEFAULT,
        );
        info!(
            per_peer_pending_cap,
            per_convo_peer_pending_cap, "Outbound queue resource fencing configured"
        );
        Self {
            pool,
            auth_middleware,
            resolver,
            per_peer_pending_cap,
            per_convo_peer_pending_cap,
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
    ) -> Result<String, FederationError> {
        let canonical_target_ds_did = canonical_did(target_ds_did).to_string();
        let policy =
            peer_policy::enforce_outbound_peer_policy(&self.pool, &canonical_target_ds_did).await?;
        self.enforce_pending_caps(&canonical_target_ds_did, convo_id, &policy)
            .await?;

        let id = ulid::Ulid::new().to_string();
        let initial_delay_secs: f64 = 5.0;

        sqlx::query(
            "INSERT INTO outbound_queue \
               (id, target_ds_did, target_endpoint, method, payload, convo_id, last_error, next_retry_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, NOW() + make_interval(secs => $8))",
        )
        .bind(&id)
        .bind(&canonical_target_ds_did)
        .bind(target_endpoint)
        .bind(method)
        .bind(payload)
        .bind(convo_id)
        .bind(error_msg)
        .bind(initial_delay_secs)
        .execute(&self.pool)
        .await
        .map_err(FederationError::Database)?;

        debug!(
            queue_id = %id,
            target_ds_did = %canonical_target_ds_did,
            method,
            convo_id,
            "Enqueued for retry"
        );
        Ok(id)
    }

    async fn enforce_pending_caps(
        &self,
        target_ds_did: &str,
        convo_id: &str,
        policy: &peer_policy::PeerPolicy,
    ) -> Result<(), FederationError> {
        let cap_ratio = policy
            .configured_max_requests_per_minute
            .zip(policy.max_requests_per_minute)
            .map(|(configured, effective)| {
                (effective as f64 / configured.max(1) as f64).clamp(0.05, 1.0)
            })
            .unwrap_or_else(|| match policy.risk_tier {
                peer_policy::RiskTier::Low => 1.0,
                peer_policy::RiskTier::Medium => 0.75,
                peer_policy::RiskTier::High => 0.5,
                peer_policy::RiskTier::Critical => 0.25,
            });
        let adaptive_peer_cap = ((self.per_peer_pending_cap as f64) * cap_ratio)
            .floor()
            .max(1.0) as i64;
        let adaptive_convo_peer_cap = ((self.per_convo_peer_pending_cap as f64) * cap_ratio)
            .floor()
            .max(1.0) as i64;

        let (peer_pending, convo_peer_pending): (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*)::BIGINT AS peer_pending, \
                    COUNT(*) FILTER (WHERE convo_id = $2)::BIGINT AS convo_peer_pending \
             FROM outbound_queue \
             WHERE status = 'pending' AND target_ds_did = $1",
        )
        .bind(target_ds_did)
        .bind(convo_id)
        .fetch_one(&self.pool)
        .await
        .map_err(FederationError::Database)?;

        if peer_pending >= adaptive_peer_cap {
            crate::metrics::record_federation_queue_capacity_rejection(
                "peer",
                policy.risk_tier.as_str(),
            );
            crate::metrics::record_federation_rejection_reason("queue_capacity_exceeded");
            warn!(
                event = "federation_outbound_queue_enqueue_rejected",
                scope = "peer",
                target_ds = %crate::crypto::redact_for_log(target_ds_did),
                convo_id = %crate::crypto::redact_for_log(convo_id),
                risk_tier = %policy.risk_tier.as_str(),
                pending = peer_pending,
                cap = adaptive_peer_cap,
                configured_cap = self.per_peer_pending_cap,
                "Rejected outbound queue enqueue: per-peer pending cap exceeded"
            );
            if peer_policy::federation_alerts_enabled() {
                error!(
                    event = "federation_alert_hook",
                    alert_type = "queue_capacity_rejection",
                    scope = "peer",
                    target_ds = %crate::crypto::redact_for_log(target_ds_did),
                    risk_tier = %policy.risk_tier.as_str(),
                    pending = peer_pending,
                    cap = adaptive_peer_cap,
                    "Federation alert hook emitted"
                );
            }
            return Err(FederationError::OutboundQueuePeerCapExceeded {
                target_ds_did: target_ds_did.to_string(),
                pending: peer_pending,
                limit: adaptive_peer_cap,
            });
        }

        if convo_peer_pending >= adaptive_convo_peer_cap {
            crate::metrics::record_federation_queue_capacity_rejection(
                "conversation_peer",
                policy.risk_tier.as_str(),
            );
            crate::metrics::record_federation_rejection_reason("queue_capacity_exceeded");
            warn!(
                event = "federation_outbound_queue_enqueue_rejected",
                scope = "conversation_peer",
                target_ds = %crate::crypto::redact_for_log(target_ds_did),
                convo_id = %crate::crypto::redact_for_log(convo_id),
                risk_tier = %policy.risk_tier.as_str(),
                pending = convo_peer_pending,
                cap = adaptive_convo_peer_cap,
                configured_cap = self.per_convo_peer_pending_cap,
                "Rejected outbound queue enqueue: per-conversation per-peer pending cap exceeded"
            );
            if peer_policy::federation_alerts_enabled() {
                error!(
                    event = "federation_alert_hook",
                    alert_type = "queue_capacity_rejection",
                    scope = "conversation_peer",
                    target_ds = %crate::crypto::redact_for_log(target_ds_did),
                    convo_id = %crate::crypto::redact_for_log(convo_id),
                    risk_tier = %policy.risk_tier.as_str(),
                    pending = convo_peer_pending,
                    cap = adaptive_convo_peer_cap,
                    "Federation alert hook emitted"
                );
            }
            return Err(FederationError::OutboundQueueConvoPeerCapExceeded {
                target_ds_did: target_ds_did.to_string(),
                convo_id: convo_id.to_string(),
                pending: convo_peer_pending,
                limit: adaptive_convo_peer_cap,
            });
        }

        Ok(())
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
        // 1. Recheck peer policy immediately before send; denial stops/cancels delivery
        if let Err(e) = peer_policy::enforce_outbound_peer_policy(&self.pool, &item.target_ds_did).await {
            warn!(
                queue_id = %item.id,
                target_ds = %item.target_ds_did,
                error = %e,
                "Peer policy denied outbound delivery for queued item; cancelling delivery"
            );
            let _ = self.mark_failed(&item.id, &format!("Peer policy denied: {e}")).await;
            return;
        }

        // 2. Revalidate and resolve pinned destination on every retry
        let destination = match self.resolve_target_destination(item).await {
            Ok(dest) => dest,
            Err(e) => {
                error!(
                    queue_id = %item.id,
                    target_ds = %item.target_ds_did,
                    error = %e,
                    "Unable to resolve pinned target destination for queued delivery"
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
        let expected_sequencer_term = extract_expected_sequencer_term(&item.method, &body);

        match outbound
            .call_procedure_pinned(&destination, &item.method, &token, &body)
            .await
        {
            Ok(resp) if resp.accepted => {
                debug!(queue_id = %item.id, "Retry delivery succeeded");
                if let Some(ref ack) = resp.ack {
                    // Validate ACK fields match the delivery we sent
                    let fields_valid = ack.receiver_ds_did == item.target_ds_did
                        && ack.convo_id == item.convo_id
                        && expected_sequencer_term
                            .map(|term| ack.sequencer_term == term)
                            .unwrap_or(true);
                    if !fields_valid {
                        warn!(
                            queue_id = %item.id,
                            expected_ds = %item.target_ds_did,
                            got_ds = %ack.receiver_ds_did,
                            expected_convo = %item.convo_id,
                            got_convo = %ack.convo_id,
                            expected_term = ?expected_sequencer_term,
                            got_term = ack.sequencer_term,
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
                                            crate::db::store_delivery_ack(&self.pool, ack, true)
                                                .await
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
                                        "ACK stored as UNVERIFIED — no P-256 key found in DID doc for {}",
                                        crate::crypto::redact_for_log(&ack.receiver_ds_did),
                                    );
                                    if let Err(e) =
                                        crate::db::store_delivery_ack(&self.pool, ack, false).await
                                    {
                                        warn!(queue_id = %item.id, error = %e, "Failed to store delivery ack");
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(
                                    queue_id = %item.id,
                                    error = %e,
                                    "ACK stored as UNVERIFIED — DID resolution failed for {}",
                                    crate::crypto::redact_for_log(&ack.receiver_ds_did),
                                );
                                if let Err(e) =
                                    crate::db::store_delivery_ack(&self.pool, ack, false).await
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
                let rejection_category = classify_remote_rejection_category(
                    resp.reason_code.as_deref(),
                    resp.error.as_deref(),
                    resp.message.as_deref(),
                );
                crate::metrics::record_federation_rejection_reason(rejection_category);
                let reason = resp
                    .reason_code
                    .or(resp.message)
                    .unwrap_or_else(|| "rejected".to_string());
                warn!(
                    queue_id = %item.id,
                    reason = %reason,
                    rejection_category,
                    "Remote DS rejected delivery"
                );
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
    async fn resolve_target_destination(&self, item: &QueueItem) -> Result<ValidatedRemoteDestination, OutboundError> {
        let canonical_target_ds_did = canonical_did(&item.target_ds_did).to_string();

        if !canonical_target_ds_did.is_empty() {
            match self.resolver.resolve_ds_destination(&canonical_target_ds_did).await {
                Ok(dest) => return Ok(dest),
                Err(e) => {
                    debug!(
                        queue_id = %item.id,
                        target_ds = %item.target_ds_did,
                        error = %e,
                        "resolve_ds_destination failed, attempting stored endpoint"
                    );
                }
            }
        }

        if !item.target_endpoint.is_empty() {
            return self.resolver.resolve_endpoint_destination(&item.target_endpoint).await.map_err(|e| OutboundError::RequestFailed {
                endpoint: item.target_endpoint.clone(),
                reason: format!("Could not validate and resolve destination: {e}"),
            });
        }

        Err(OutboundError::RequestFailed {
            endpoint: canonical_target_ds_did,
            reason: "Could not resolve target DS DID to pinned destination".to_string(),
        })
    }

    pub(crate) async fn resolve_target_endpoint(&self, item: &QueueItem) -> Result<String, OutboundError> {
        let dest = self.resolve_target_destination(item).await?;
        Ok(dest.url.as_str().trim_end_matches('/').to_string())
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

fn extract_expected_sequencer_term(method: &str, body: &serde_json::Value) -> Option<u64> {
    match method {
        "blue.catbird.mlsDS.deliverMessage" | "blue.catbird.mlsDS.submitCommit" => body
            .get("sequencerTerm")
            .and_then(serde_json::Value::as_u64),
        _ => None,
    }
}

fn classify_remote_rejection_category(
    reason_code: Option<&str>,
    error: Option<&str>,
    message: Option<&str>,
) -> &'static str {
    if let Some(code) = reason_code {
        return match code {
            "rate_limited" => "rate_limited",
            "auth_failed" => "auth_failed",
            "not_sequencer" | "term_stale" | "conflict" => "conflict",
            "queue_capacity_exceeded" => "queue_capacity_exceeded",
            "invalid_payload" => "invalid_payload",
            _ => "remote_rejected",
        };
    }

    let context = error.or(message).unwrap_or_default().to_ascii_lowercase();
    if context.contains("rate") && context.contains("limit") {
        "rate_limited"
    } else if context.contains("auth") || context.contains("token") {
        "auth_failed"
    } else if context.contains("queue") || context.contains("capacity") {
        "queue_capacity_exceeded"
    } else if context.contains("conflict") || context.contains("stale") {
        "conflict"
    } else if context.contains("invalid") || context.contains("payload") {
        "invalid_payload"
    } else {
        "remote_rejected"
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_cap_uses_default_for_invalid_or_missing_values() {
        assert_eq!(parse_pending_cap(None, 123), 123);
        assert_eq!(parse_pending_cap(Some("invalid"), 123), 123);
    }

    #[test]
    fn pending_cap_is_clamped_to_safe_range() {
        assert_eq!(parse_pending_cap(Some("0"), 123), 1);
        assert_eq!(
            parse_pending_cap(Some("999999999"), 123),
            OUTBOUND_QUEUE_PENDING_CAP_MAX
        );
    }

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

    #[tokio::test]
    async fn outbound_queue_resolves_target_endpoint_via_injected_resolver() {
        std::env::set_var("FEDERATION_ALLOW_INSECURE_HTTP", "true");
        std::env::set_var("APP_ENV", "test");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused:unused@127.0.0.1/unused")
            .unwrap();
        let http = reqwest::Client::new();
        let resolver = Arc::new(DsResolver::new(
            pool.clone(),
            http,
            "did:web:self.example.com".to_string(),
            "https://self.example.com".to_string(),
            None,
            3600,
        ));
        let queue = OutboundQueue::new(pool, AuthMiddleware::new(), resolver);

        let item = QueueItem {
            id: "item-1".to_string(),
            target_ds_did: "did:web:127.0.0.1%3A3001".to_string(),
            target_endpoint: String::new(),
            method: "blue.catbird.mlsDS.deliverMessage".to_string(),
            payload: vec![],
            convo_id: "convo-1".to_string(),
            retry_count: 0,
            max_retries: 5,
        };

        let endpoint = queue.resolve_target_endpoint(&item).await.unwrap();
        assert_eq!(endpoint, "https://127.0.0.1:3001");
    }

    #[tokio::test]
    async fn test_outbound_queue_stops_delivery_when_peer_policy_revoked_after_enqueue() {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL is required for queue policy revocation test");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .expect("connect to test db");
        let mut conn = pool.acquire().await.expect("acquire migration connection");
        let _ = sqlx::query("SET chat.operation_claim_activation_approved = 'handlers-and-legacy-apis-sealed'")
            .execute(&mut *conn)
            .await;
        sqlx::migrate!("./migrations")
            .run(&mut *conn)
            .await
            .expect("migrations must succeed");
        let _ = sqlx::query("RESET chat.operation_claim_activation_approved")
            .execute(&mut *conn)
            .await;
        let peer_did = format!("did:web:revoked-{}.example.com", uuid::Uuid::new_v4().as_simple());

        // 1. Peer is initially allowed in federation_peers
        sqlx::query(
            "INSERT INTO federation_peers (ds_did, status, trust_score, created_at, updated_at) \
             VALUES ($1, 'allow', 100, NOW(), NOW()) \
             ON CONFLICT (ds_did) DO UPDATE SET status = 'allow'",
        )
        .bind(&peer_did)
        .execute(&pool)
        .await
        .unwrap();

        let http = reqwest::Client::new();
        let resolver = Arc::new(DsResolver::new(
            pool.clone(),
            http,
            "did:web:self.example.com".to_string(),
            "https://self.example.com".to_string(),
            None,
            3600,
        ));
        let queue = OutboundQueue::new(pool.clone(), AuthMiddleware::new(), resolver);

        let item_id = format!("queue-item-{}", uuid::Uuid::new_v4().as_simple());
        let payload = serde_json::to_vec(&serde_json::json!({"test": "value"})).unwrap();

        // 2. Insert item into outbound_queue
        sqlx::query(
            "INSERT INTO outbound_queue (id, target_ds_did, target_endpoint, method, payload, convo_id, status, retry_count, max_retries, next_retry_at) \
             VALUES ($1, $2, $3, $4, $5, $6, 'pending', 0, 5, NOW() - INTERVAL '1 second')",
        )
        .bind(&item_id)
        .bind(&peer_did)
        .bind("https://revoked.example.com")
        .bind("blue.catbird.mlsDS.deliverMessage")
        .bind(&payload)
        .bind("convo-test-revocation")
        .execute(&pool)
        .await
        .unwrap();

        // 3. Revoke peer policy in database after enqueue
        sqlx::query("UPDATE federation_peers SET status = 'block' WHERE ds_did = $1")
            .bind(&peer_did)
            .execute(&pool)
            .await
            .unwrap();

        // 4. Process pending batch with OutboundClient
        let outbound = OutboundClient::new(5, 5);
        let auth_sign = Arc::new(|_target: &str, _method: &str| Ok("test-jwt".to_string()));

        let processed = queue.process_pending_batch(&outbound, auth_sign.as_ref()).await.unwrap();
        assert!(processed >= 1);

        // 5. Verify the item status is now 'failed' with peer policy denial
        let (status, last_error): (String, Option<String>) = sqlx::query_as(
            "SELECT status, last_error FROM outbound_queue WHERE id = $1",
        )
        .bind(&item_id)
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(status, "failed");
        assert!(last_error.unwrap_or_default().contains("Peer policy denied"));
    }
}
