use std::sync::Arc;
use std::time::Duration;

use sqlx::{PgPool, Postgres};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use super::errors::FederationError;
use super::outbound::{OutboundClient, OutboundError};
use super::peer_policy;
use super::resolver::{validate_endpoint_url, validate_resolved_host_is_public, DsResolver};
use crate::auth::AuthMiddleware;
use crate::identity::{canonical_did, did_web_service_endpoint};

const OUTBOUND_QUEUE_PER_PEER_PENDING_CAP_ENV: &str =
    "FEDERATION_OUTBOUND_QUEUE_PER_PEER_PENDING_CAP";
const OUTBOUND_QUEUE_PER_CONVO_PEER_PENDING_CAP_ENV: &str =
    "FEDERATION_OUTBOUND_QUEUE_PER_CONVO_PEER_PENDING_CAP";
const OUTBOUND_QUEUE_PER_PEER_PENDING_CAP_DEFAULT: i64 = 500;
const OUTBOUND_QUEUE_PER_CONVO_PEER_PENDING_CAP_DEFAULT: i64 = 100;
const OUTBOUND_QUEUE_PENDING_CAP_MAX: i64 = 100_000;

const OUTBOUND_QUEUE_PER_PEER_PENDING_BYTES_CAP_ENV: &str =
    "FEDERATION_OUTBOUND_QUEUE_PER_PEER_PENDING_BYTES_CAP";
const OUTBOUND_QUEUE_PER_CONVO_PEER_PENDING_BYTES_CAP_ENV: &str =
    "FEDERATION_OUTBOUND_QUEUE_PER_CONVO_PEER_PENDING_BYTES_CAP";
const OUTBOUND_QUEUE_PER_PEER_PENDING_BYTES_CAP_DEFAULT: i64 = 50 * 1024 * 1024; // 50 MiB
const OUTBOUND_QUEUE_PER_CONVO_PEER_PENDING_BYTES_CAP_DEFAULT: i64 = 10 * 1024 * 1024; // 10 MiB
const OUTBOUND_QUEUE_PENDING_BYTES_CAP_MAX: i64 = 1024 * 1024 * 1024; // 1 GiB

fn parse_pending_cap(raw: Option<&str>, default: i64) -> i64 {
    raw.and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(default)
        .clamp(1, OUTBOUND_QUEUE_PENDING_CAP_MAX)
}

fn pending_cap_from_env(var_name: &str, default: i64) -> i64 {
    parse_pending_cap(std::env::var(var_name).ok().as_deref(), default)
}

fn parse_pending_bytes_cap(raw: Option<&str>, default: i64) -> i64 {
    raw.and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(default)
        .clamp(1, OUTBOUND_QUEUE_PENDING_BYTES_CAP_MAX)
}

fn pending_bytes_cap_from_env(var_name: &str, default: i64) -> i64 {
    parse_pending_bytes_cap(std::env::var(var_name).ok().as_deref(), default)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdaptiveCaps {
    pub peer_row_cap: i64,
    pub convo_row_cap: i64,
    pub peer_bytes_cap: i64,
    pub convo_bytes_cap: i64,
}

pub fn compute_adaptive_caps(
    base_peer_rows: i64,
    base_convo_rows: i64,
    base_peer_bytes: i64,
    base_convo_bytes: i64,
    policy: &peer_policy::PeerPolicy,
) -> AdaptiveCaps {
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

    let peer_row_cap = ((base_peer_rows as f64) * cap_ratio).floor().max(1.0) as i64;
    let convo_row_cap = ((base_convo_rows as f64) * cap_ratio).floor().max(1.0) as i64;
    let peer_bytes_cap = ((base_peer_bytes as f64) * cap_ratio).floor().max(1.0) as i64;
    let convo_bytes_cap = ((base_convo_bytes as f64) * cap_ratio).floor().max(1.0) as i64;

    AdaptiveCaps {
        peer_row_cap,
        convo_row_cap,
        peer_bytes_cap,
        convo_bytes_cap,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnqueueBinding<'a> {
    pub target_ds_did: &'a str,
    pub target_endpoint: &'a str,
    pub method: &'a str,
    pub payload: &'a [u8],
    pub convo_id: &'a str,
}

pub fn check_idempotent_replay(
    id: &str,
    existing: Option<&EnqueueBinding<'_>>,
    requested: &EnqueueBinding<'_>,
) -> Result<bool, FederationError> {
    match existing {
        Some(existing) => {
            if existing.target_ds_did == requested.target_ds_did
                && existing.target_endpoint == requested.target_endpoint
                && existing.method == requested.method
                && existing.payload == requested.payload
                && existing.convo_id == requested.convo_id
            {
                Ok(true)
            } else {
                Err(FederationError::InvalidRequest(format!(
                    "Outbound queue item '{id}' already exists with conflicting binding or payload"
                )))
            }
        }
        None => Ok(false),
    }
}

pub fn check_capacity_bounds(
    target_ds_did: &str,
    convo_id: &str,
    payload_len: usize,
    peer_pending_rows: i64,
    peer_pending_bytes: i64,
    convo_peer_pending_rows: i64,
    convo_peer_pending_bytes: i64,
    caps: &AdaptiveCaps,
    policy: &peer_policy::PeerPolicy,
) -> Result<(), FederationError> {
    let payload_bytes = payload_len as i64;

    if peer_pending_rows >= caps.peer_row_cap {
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
            pending = peer_pending_rows,
            cap = caps.peer_row_cap,
            "Rejected outbound queue enqueue: per-peer pending cap exceeded"
        );
        if peer_policy::federation_alerts_enabled() {
            error!(
                event = "federation_alert_hook",
                alert_type = "queue_capacity_rejection",
                scope = "peer",
                target_ds = %crate::crypto::redact_for_log(target_ds_did),
                risk_tier = %policy.risk_tier.as_str(),
                pending = peer_pending_rows,
                cap = caps.peer_row_cap,
                "Federation alert hook emitted"
            );
        }
        return Err(FederationError::OutboundQueuePeerCapExceeded {
            target_ds_did: target_ds_did.to_string(),
            pending: peer_pending_rows,
            limit: caps.peer_row_cap,
        });
    }

    if peer_pending_bytes.saturating_add(payload_bytes) > caps.peer_bytes_cap {
        crate::metrics::record_federation_queue_capacity_rejection(
            "peer_bytes",
            policy.risk_tier.as_str(),
        );
        crate::metrics::record_federation_rejection_reason("queue_capacity_exceeded");
        warn!(
            event = "federation_outbound_queue_enqueue_rejected",
            scope = "peer_bytes",
            target_ds = %crate::crypto::redact_for_log(target_ds_did),
            convo_id = %crate::crypto::redact_for_log(convo_id),
            risk_tier = %policy.risk_tier.as_str(),
            pending_bytes = peer_pending_bytes,
            incoming_bytes = payload_bytes,
            cap = caps.peer_bytes_cap,
            "Rejected outbound queue enqueue: per-peer pending bytes cap exceeded"
        );
        if peer_policy::federation_alerts_enabled() {
            error!(
                event = "federation_alert_hook",
                alert_type = "queue_capacity_rejection",
                scope = "peer_bytes",
                target_ds = %crate::crypto::redact_for_log(target_ds_did),
                risk_tier = %policy.risk_tier.as_str(),
                pending = peer_pending_bytes,
                cap = caps.peer_bytes_cap,
                "Federation alert hook emitted"
            );
        }
        return Err(FederationError::OutboundQueuePeerCapExceeded {
            target_ds_did: target_ds_did.to_string(),
            pending: peer_pending_bytes.saturating_add(payload_bytes),
            limit: caps.peer_bytes_cap,
        });
    }

    if !convo_id.is_empty() {
        if convo_peer_pending_rows >= caps.convo_row_cap {
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
                pending = convo_peer_pending_rows,
                cap = caps.convo_row_cap,
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
                    pending = convo_peer_pending_rows,
                    cap = caps.convo_row_cap,
                    "Federation alert hook emitted"
                );
            }
            return Err(FederationError::OutboundQueueConvoPeerCapExceeded {
                target_ds_did: target_ds_did.to_string(),
                convo_id: convo_id.to_string(),
                pending: convo_peer_pending_rows,
                limit: caps.convo_row_cap,
            });
        }

        if convo_peer_pending_bytes.saturating_add(payload_bytes) > caps.convo_bytes_cap {
            crate::metrics::record_federation_queue_capacity_rejection(
                "conversation_peer_bytes",
                policy.risk_tier.as_str(),
            );
            crate::metrics::record_federation_rejection_reason("queue_capacity_exceeded");
            warn!(
                event = "federation_outbound_queue_enqueue_rejected",
                scope = "conversation_peer_bytes",
                target_ds = %crate::crypto::redact_for_log(target_ds_did),
                convo_id = %crate::crypto::redact_for_log(convo_id),
                risk_tier = %policy.risk_tier.as_str(),
                pending_bytes = convo_peer_pending_bytes,
                incoming_bytes = payload_bytes,
                cap = caps.convo_bytes_cap,
                "Rejected outbound queue enqueue: per-conversation per-peer pending bytes cap exceeded"
            );
            if peer_policy::federation_alerts_enabled() {
                error!(
                    event = "federation_alert_hook",
                    alert_type = "queue_capacity_rejection",
                    scope = "conversation_peer_bytes",
                    target_ds = %crate::crypto::redact_for_log(target_ds_did),
                    convo_id = %crate::crypto::redact_for_log(convo_id),
                    risk_tier = %policy.risk_tier.as_str(),
                    pending = convo_peer_pending_bytes,
                    cap = caps.convo_bytes_cap,
                    "Federation alert hook emitted"
                );
            }
            return Err(FederationError::OutboundQueueConvoPeerCapExceeded {
                target_ds_did: target_ds_did.to_string(),
                convo_id: convo_id.to_string(),
                pending: convo_peer_pending_bytes.saturating_add(payload_bytes),
                limit: caps.convo_bytes_cap,
            });
        }
    }

    Ok(())
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
    per_peer_pending_cap: i64,
    per_convo_peer_pending_cap: i64,
    per_peer_pending_bytes_cap: i64,
    per_convo_peer_pending_bytes_cap: i64,
    resolver: Arc<DsResolver>,
}

impl OutboundQueue {
    pub fn new(pool: PgPool, auth_middleware: AuthMiddleware) -> Self {
        let per_peer_pending_cap = pending_cap_from_env(
            OUTBOUND_QUEUE_PER_PEER_PENDING_CAP_ENV,
            OUTBOUND_QUEUE_PER_PEER_PENDING_CAP_DEFAULT,
        );
        let per_convo_peer_pending_cap = pending_cap_from_env(
            OUTBOUND_QUEUE_PER_CONVO_PEER_PENDING_CAP_ENV,
            OUTBOUND_QUEUE_PER_CONVO_PEER_PENDING_CAP_DEFAULT,
        );
        let per_peer_pending_bytes_cap = pending_bytes_cap_from_env(
            OUTBOUND_QUEUE_PER_PEER_PENDING_BYTES_CAP_ENV,
            OUTBOUND_QUEUE_PER_PEER_PENDING_BYTES_CAP_DEFAULT,
        );
        let per_convo_peer_pending_bytes_cap = pending_bytes_cap_from_env(
            OUTBOUND_QUEUE_PER_CONVO_PEER_PENDING_BYTES_CAP_ENV,
            OUTBOUND_QUEUE_PER_CONVO_PEER_PENDING_BYTES_CAP_DEFAULT,
        );
        info!(
            per_peer_pending_cap,
            per_convo_peer_pending_cap,
            per_peer_pending_bytes_cap,
            per_convo_peer_pending_bytes_cap,
            "Outbound queue resource fencing configured"
        );
        let http = super::resolver::build_resolver_http_client();
        let cache_ttl: u64 = std::env::var("ENDPOINT_CACHE_TTL")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3600);
        let resolver = Arc::new(DsResolver::new(
            pool.clone(),
            http,
            crate::identity::service_did(),
            crate::identity::self_endpoint(),
            std::env::var("DEFAULT_DS_ENDPOINT").ok(),
            cache_ttl,
        ));
        Self {
            pool,
            auth_middleware,
            per_peer_pending_cap,
            per_convo_peer_pending_cap,
            per_peer_pending_bytes_cap,
            per_convo_peer_pending_bytes_cap,
            resolver,
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
        self.enforce_pending_caps(&canonical_target_ds_did, convo_id, payload.len(), &policy)
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
        payload_len: usize,
        policy: &peer_policy::PeerPolicy,
    ) -> Result<(), FederationError> {
        let caps = compute_adaptive_caps(
            self.per_peer_pending_cap,
            self.per_convo_peer_pending_cap,
            self.per_peer_pending_bytes_cap,
            self.per_convo_peer_pending_bytes_cap,
            policy,
        );

        let (peer_pending_rows, peer_pending_bytes, convo_peer_pending_rows, convo_peer_pending_bytes): (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT COUNT(*)::BIGINT AS peer_pending_rows, \
                    COALESCE(SUM(octet_length(payload)), 0)::BIGINT AS peer_pending_bytes, \
                    COUNT(*) FILTER (WHERE convo_id = $2)::BIGINT AS convo_peer_pending_rows, \
                    COALESCE(SUM(octet_length(payload)) FILTER (WHERE convo_id = $2), 0)::BIGINT AS convo_peer_pending_bytes \
             FROM outbound_queue \
             WHERE status = 'pending' AND target_ds_did = $1",
        )
        .bind(target_ds_did)
        .bind(convo_id)
        .fetch_one(&self.pool)
        .await
        .map_err(FederationError::Database)?;

        check_capacity_bounds(
            target_ds_did,
            convo_id,
            payload_len,
            peer_pending_rows,
            peer_pending_bytes,
            convo_peer_pending_rows,
            convo_peer_pending_bytes,
            &caps,
            policy,
        )
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
        let tick_ms: u64 = std::env::var("OUTBOUND_QUEUE_TICK_INTERVAL_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5000);
        let mut interval = tokio::time::interval(Duration::from_millis(tick_ms));
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
                "WITH oldest_pending AS ( \
                     SELECT DISTINCT ON (CASE WHEN convo_id = '' THEN id ELSE convo_id END, target_ds_did) \
                         id, target_ds_did, target_endpoint, method, payload, convo_id, \
                         retry_count, max_retries, created_at, next_retry_at \
                     FROM outbound_queue \
                     WHERE status = 'pending' \
                     ORDER BY (CASE WHEN convo_id = '' THEN id ELSE convo_id END), target_ds_did, \
                         CASE \
                             WHEN method = 'blue.catbird.mlsDS.deliverDirectRequest' THEN 1 \
                             WHEN method = 'blue.catbird.mlsDS.deliverAcceptanceEntry' THEN 2 \
                             WHEN method = 'blue.catbird.mlsDS.deliverMessageEntry' THEN \
                                 COALESCE( \
                                     (substring(encode(payload, 'escape') from '\"seq\"[[:space:]]*:[[:space:]]*([0-9]+)'))::bigint, \
                                     (substring(id from '-([0-9]+)$'))::bigint, \
                                     9223372036854775807 \
                                 ) \
                             ELSE NULL \
                         END ASC NULLS LAST, \
                         created_at ASC, id ASC \
                 ) \
                 SELECT id, target_ds_did, target_endpoint, method, payload, convo_id, \
                        retry_count, max_retries \
                 FROM oldest_pending \
                 WHERE next_retry_at <= NOW() \
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
            Err(e)
                if e.is_retryable()
                    && (is_c33_method(&item.method) || item.retry_count < item.max_retries) =>
            {
                let delay = backoff_delay(item.retry_count);
                warn!(
                    queue_id = %item.id,
                    target_ds = %item.target_ds_did,
                    retry = item.retry_count.saturating_add(1),
                    next_retry_secs = delay.as_secs(),
                    error = %e,
                    "Transient endpoint resolution failure; scheduling retry"
                );
                let _ = self
                    .schedule_retry(
                        &item.id,
                        item.retry_count.saturating_add(1),
                        &e.to_string(),
                        delay,
                    )
                    .await;
                return;
            }
            Err(e) => {
                error!(
                    queue_id = %item.id,
                    target_ds = %item.target_ds_did,
                    retries = item.retry_count,
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
        let expected_sequencer_term = extract_expected_sequencer_term(&item.method, &body);

        match outbound
            .call_procedure(&target_endpoint, &item.method, &token, &body)
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
                let reason = resp.reason_code.as_deref()
                    .or(resp.message.as_deref())
                    .unwrap_or("rejected");
                if is_predecessor_error(&reason)
                    || resp.error.as_deref().map(is_predecessor_error).unwrap_or(false)
                {
                    let delay = backoff_delay(item.retry_count);
                    warn!(
                        queue_id = %item.id,
                        retry = item.retry_count,
                        next_retry_secs = delay.as_secs(),
                        reason = %reason,
                        "Predecessor missing for queued item; scheduling retry without exhausting"
                    );
                    let _ = self
                        .schedule_retry(&item.id, item.retry_count, &reason, delay)
                        .await;
                } else {
                    let rejection_category = classify_remote_rejection_category(
                        resp.reason_code.as_deref(),
                        resp.error.as_deref(),
                        None,
                    );
                    crate::metrics::record_federation_rejection_reason(rejection_category);
                    warn!(
                        queue_id = %item.id,
                        reason = %reason,
                        rejection_category,
                        "Remote DS rejected delivery"
                    );
                    let _ = self.mark_failed(&item.id, &reason).await;
                }
            }
            Err(e) if is_outbound_predecessor_error(&e) => {
                let delay = backoff_delay(item.retry_count);
                let reason = e
                    .predecessor_reason()
                    .map(|r| r.to_string())
                    .unwrap_or_else(|| e.to_string());
                warn!(
                    queue_id = %item.id,
                    retry = item.retry_count,
                    next_retry_secs = delay.as_secs(),
                    reason = %reason,
                    error = %e,
                    "Predecessor missing on remote DS; scheduling retry without exhausting"
                );
                let _ = self
                    .schedule_retry(&item.id, item.retry_count, &reason, delay)
                    .await;
            }
            Err(e) if e.is_retryable()
                && (is_c33_method(&item.method) || item.retry_count < item.max_retries) =>
            {
                let delay = backoff_delay(item.retry_count);
                warn!(
                    queue_id = %item.id,
                    retry = item.retry_count.saturating_add(1),
                    next_retry_secs = delay.as_secs(),
                    error = %e,
                    "Retryable failure, scheduling next attempt"
                );
                let _ = self
                    .schedule_retry(&item.id, item.retry_count.saturating_add(1), &e.to_string(), delay)
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
        let canonical_target_ds_did = canonical_did(&item.target_ds_did).to_string();

        if is_c33_method(&item.method) {
            let endpoint_info = self
                .resolver
                .resolve_authority_ds_endpoint(&canonical_target_ds_did)
                .await
                .map_err(|error| classify_resolution_error(&canonical_target_ds_did, error))?;

            if canonical_did(&endpoint_info.did) != canonical_target_ds_did {
                return Err(OutboundError::ResolutionFailed {
                    endpoint: endpoint_info.endpoint,
                    reason: format!(
                        "Resolved authority DID mismatch: expected {canonical_target_ds_did}, got {}",
                        endpoint_info.did
                    ),
                    retryable: false,
                });
            }

            return self
                .validate_endpoint_candidate(&endpoint_info.endpoint, &canonical_target_ds_did)
                .await;
        }

        let cached_endpoint = sqlx::query_scalar::<_, String>(
            "SELECT endpoint FROM ds_endpoints WHERE did = $1 AND expires_at > NOW()",
        )
        .bind(&canonical_target_ds_did)
        .fetch_optional(&self.pool)
        .await
        .ok()
        .flatten();

        if let Some(endpoint) = cached_endpoint {
            return self
                .validate_endpoint_candidate(&endpoint, &canonical_target_ds_did)
                .await;
        }

        if let Some(derived_endpoint) = did_web_service_endpoint(&canonical_target_ds_did) {
            return self
                .validate_endpoint_candidate(&derived_endpoint, &canonical_target_ds_did)
                .await;
        }

        Err(OutboundError::ResolutionFailed {
            endpoint: canonical_target_ds_did,
            reason: "target endpoint missing and DS endpoint could not be resolved".to_string(),
            retryable: false,
        })
    }


    async fn validate_endpoint_candidate(
        &self,
        endpoint: &str,
        target_ds_did: &str,
    ) -> Result<String, OutboundError> {
        let parsed = validate_endpoint_url(endpoint).map_err(|e| OutboundError::ResolutionFailed {
            endpoint: endpoint.to_string(),
            reason: format!("SSRF validation failed for {target_ds_did}: {e}"),
            retryable: false,
        })?;
        validate_resolved_host_is_public(&parsed)
            .await
            .map_err(|e| {
                let reason = format!("SSRF validation failed for {target_ds_did}: {e}");
                let lower = e.to_string().to_ascii_lowercase();
                let retryable = lower.contains("dns lookup timed out")
                    || lower.contains("failed to resolve host")
                    || lower.contains("deadline exceeded")
                    || lower.contains("connection refused")
                    || lower.contains("temporary failure")
                    || lower.contains("timed out")
                    || lower.contains("timeout");
                OutboundError::ResolutionFailed {
                    endpoint: endpoint.to_string(),
                    reason,
                    retryable,
                }
            })?;
        Ok(endpoint.to_string())
    }

    // -- Status mutations -------------------------------------------------------

    pub async fn mark_delivered(&self, id: &str) -> Result<(), sqlx::Error> {
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

/// Enqueue a C33 delivery item within an existing PostgreSQL transaction.
///
/// Enforces:
/// 1. Outbound peer policy (rejecting non-allowlisted, blocked, or pending peers).
/// 2. Peer-scoped advisory transaction lock (`pg_advisory_xact_lock`) ensuring
///    serialized, race-free capacity accounting and insertion per target peer.
/// 3. Deterministic-id idempotency: if an entry with `id` already exists:
///    - If the stored payload exactly matches `payload`, returns `Ok(())` (idempotent replay at cap).
///    - If the stored payload differs, returns `Err(FederationError::InvalidRequest(...))`
///      to preserve exact payload integrity.
/// 4. Atomic row and byte capacity limits:
///    - Per-peer pending rows and pending bytes limits.
///    - Per-conversation pending rows and pending bytes limits (when `convo_id` is non-empty).
///    Both scaled adaptively by the peer's policy risk tier and rate limits.
/// 5. Shared-transaction admission: runs inside caller's `tx`, guaranteeing that a full
///    queue rolls back the caller's transaction and never strands already committed work.
pub async fn enqueue_c33_in_tx(
    pool: &PgPool,
    tx: &mut sqlx::Transaction<'_, Postgres>,
    id: &str,
    target_ds_did: &str,
    target_endpoint: &str,
    method: &str,
    payload: &[u8],
    convo_id: &str,
    error_msg: &str,
) -> Result<(), FederationError> {
    let canonical_target_ds_did = canonical_did(target_ds_did).to_string();
    let policy = peer_policy::enforce_outbound_peer_policy(pool, &canonical_target_ds_did).await?;

    // Peer-scoped advisory transaction lock to serialize queue operations for this peer
    let lock_key = format!("federation-outbound-peer:{canonical_target_ds_did}");
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(&lock_key)
        .execute(&mut **tx)
        .await
        .map_err(FederationError::Database)?;

    // Check if ID already exists (under peer advisory lock)
    let existing: Option<(String, String, String, Vec<u8>, String, String)> = sqlx::query_as(
        "SELECT target_ds_did, target_endpoint, method, payload, convo_id, status FROM outbound_queue WHERE id = $1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(FederationError::Database)?;

    let requested_binding = EnqueueBinding {
        target_ds_did: &canonical_target_ds_did,
        target_endpoint,
        method,
        payload,
        convo_id,
    };

    let existing_binding = existing.as_ref().map(|(ds, ep, m, p, c, _)| EnqueueBinding {
        target_ds_did: ds.as_str(),
        target_endpoint: ep.as_str(),
        method: m.as_str(),
        payload: p.as_slice(),
        convo_id: c.as_str(),
    });

    let is_replay = check_idempotent_replay(
        id,
        existing_binding.as_ref(),
        &requested_binding,
    )?;

    if is_replay {
        debug!(
            queue_id = %id,
            target_ds_did = %canonical_target_ds_did,
            "Idempotent C33 replay of exact binding and payload accepted"
        );
        return Ok(());
    }

    // New item: enforce capacity bounds
    let base_peer_rows = pending_cap_from_env(
        OUTBOUND_QUEUE_PER_PEER_PENDING_CAP_ENV,
        OUTBOUND_QUEUE_PER_PEER_PENDING_CAP_DEFAULT,
    );
    let base_convo_rows = pending_cap_from_env(
        OUTBOUND_QUEUE_PER_CONVO_PEER_PENDING_CAP_ENV,
        OUTBOUND_QUEUE_PER_CONVO_PEER_PENDING_CAP_DEFAULT,
    );
    let base_peer_bytes = pending_bytes_cap_from_env(
        OUTBOUND_QUEUE_PER_PEER_PENDING_BYTES_CAP_ENV,
        OUTBOUND_QUEUE_PER_PEER_PENDING_BYTES_CAP_DEFAULT,
    );
    let base_convo_bytes = pending_bytes_cap_from_env(
        OUTBOUND_QUEUE_PER_CONVO_PEER_PENDING_BYTES_CAP_ENV,
        OUTBOUND_QUEUE_PER_CONVO_PEER_PENDING_BYTES_CAP_DEFAULT,
    );

    let caps = compute_adaptive_caps(
        base_peer_rows,
        base_convo_rows,
        base_peer_bytes,
        base_convo_bytes,
        &policy,
    );

    let (peer_pending_rows, peer_pending_bytes, convo_peer_pending_rows, convo_peer_pending_bytes): (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT COUNT(*)::BIGINT AS peer_pending_rows, \
                COALESCE(SUM(octet_length(payload)), 0)::BIGINT AS peer_pending_bytes, \
                COUNT(*) FILTER (WHERE convo_id = $2)::BIGINT AS convo_peer_pending_rows, \
                COALESCE(SUM(octet_length(payload)) FILTER (WHERE convo_id = $2), 0)::BIGINT AS convo_peer_pending_bytes \
         FROM outbound_queue \
         WHERE status = 'pending' AND target_ds_did = $1",
    )
    .bind(&canonical_target_ds_did)
    .bind(convo_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(FederationError::Database)?;

    check_capacity_bounds(
        &canonical_target_ds_did,
        convo_id,
        payload.len(),
        peer_pending_rows,
        peer_pending_bytes,
        convo_peer_pending_rows,
        convo_peer_pending_bytes,
        &caps,
        &policy,
    )?;

    sqlx::query(
        "INSERT INTO outbound_queue \
           (id, target_ds_did, target_endpoint, method, payload, convo_id, last_error, next_retry_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, NOW() + INTERVAL '5 seconds')",
    )
    .bind(id)
    .bind(&canonical_target_ds_did)
    .bind(target_endpoint)
    .bind(method)
    .bind(payload)
    .bind(convo_id)
    .bind(error_msg)
    .execute(&mut **tx)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(db_err) if db_err.code().as_deref() == Some("23505") => {
            FederationError::InvalidRequest(format!(
                "Outbound queue item '{id}' already exists with conflicting binding"
            ))
        }
        other => FederationError::Database(other),
    })?;

    debug!(
        queue_id = %id,
        target_ds_did = %canonical_target_ds_did,
        method,
        convo_id,
        "C33 delivery enqueued in transaction"
    );

    Ok(())
}

/// Mark an outbound queue item as delivered by ID using a connection pool.
pub async fn mark_delivered_by_id(pool: &PgPool, id: &str) -> Result<(), FederationError> {
    sqlx::query("UPDATE outbound_queue SET status = 'delivered' WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .map_err(FederationError::Database)?;
    Ok(())
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

fn backoff_delay(retry_count: i32) -> Duration {
    if let Ok(ms) = std::env::var("OUTBOUND_QUEUE_RETRY_DELAY_MS") {
        if let Ok(parsed) = ms.parse::<u64>() {
            return Duration::from_millis(parsed);
        }
    }
    let base = 5u64;
    let delay = base.saturating_mul(2u64.saturating_pow(retry_count as u32));
    Duration::from_secs(delay.min(300))
}

fn is_c33_method(method: &str) -> bool {
    matches!(
        method,
        "blue.catbird.mlsDS.deliverDirectRequest"
            | "blue.catbird.mlsDS.deliverAcceptanceEntry"
            | "blue.catbird.mlsDS.deliverMessageEntry"
    )
}

fn is_predecessor_error(err_str: &str) -> bool {
    let lower = err_str.to_ascii_lowercase();
    lower.contains("predecessor")
}

fn is_outbound_predecessor_error(err: &OutboundError) -> bool {
    if let Some(reason) = err.predecessor_reason() {
        return is_predecessor_error(reason);
    }
    match err {
        OutboundError::RemoteError {
            body,
            predecessor_reason,
            ..
        } => {
            predecessor_reason
                .as_deref()
                .map(is_predecessor_error)
                .unwrap_or(false)
                || is_predecessor_error(body)
        }
        _ => false,
    }
}

fn classify_resolution_error(target_ds_did: &str, error: FederationError) -> OutboundError {
    match error {
        FederationError::Http(e) => {
            if e.is_timeout() {
                OutboundError::Timeout {
                    endpoint: target_ds_did.to_string(),
                    method: "resolve_authority_ds_endpoint".to_string(),
                }
            } else if e.is_connect() {
                OutboundError::ConnectionFailed {
                    endpoint: target_ds_did.to_string(),
                    reason: e.to_string(),
                }
            } else if let Some(status) = e.status() {
                let retryable =
                    status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS;
                OutboundError::ResolutionFailed {
                    endpoint: target_ds_did.to_string(),
                    reason: format!("authority DID document server returned status {status}"),
                    retryable,
                }
            } else {
                OutboundError::ResolutionFailed {
                    endpoint: target_ds_did.to_string(),
                    reason: format!("authority resolution HTTP error: {e}"),
                    retryable: true,
                }
            }
        }
        FederationError::DsUnreachable { endpoint, reason } => {
            OutboundError::ConnectionFailed { endpoint, reason }
        }
        FederationError::ResolutionFailed { did, reason } => {
            let lower = reason.to_ascii_lowercase();
            let is_malformed_doc = lower.contains("invalid did document json")
                || lower.contains("no atprotomlsdeliveryservice")
                || lower.contains("resolved authority did mismatch")
                || lower.contains("invalid did:web identifier")
                || lower.contains("unsupported did method");
            let is_ssrf_or_invalid_url = lower.contains("ssrf")
                || lower.contains("blocked private address")
                || lower.contains("invalid url")
                || lower.contains("scheme must be https")
                || lower.contains("http federation endpoint rejected");

            let (is_transient_status, is_permanent_status) = if let Some(idx) = lower.find("status ")
            {
                let status_str = &lower[idx + 7..];
                let code_digits: String =
                    status_str.chars().take_while(|c| c.is_ascii_digit()).collect();
                if let Ok(code) = code_digits.parse::<u16>() {
                    (code >= 500 || code == 429, code >= 400 && code < 500 && code != 429)
                } else {
                    (false, false)
                }
            } else {
                (false, false)
            };

            let is_transient_network = lower.contains("deadline exceeded")
                || lower.contains("timed out")
                || lower.contains("timeout")
                || lower.contains("connection refused")
                || lower.contains("connection reset")
                || lower.contains("dns resolution")
                || lower.contains("temporary failure")
                || lower.contains("connect error");

            let retryable = if is_malformed_doc || is_ssrf_or_invalid_url || is_permanent_status {
                false
            } else if is_transient_status || is_transient_network {
                true
            } else {
                false
            };

            OutboundError::ResolutionFailed {
                endpoint: if did.is_empty() {
                    target_ds_did.to_string()
                } else {
                    did
                },
                reason,
                retryable,
            }
        }
        FederationError::Database(e) => OutboundError::ResolutionFailed {
            endpoint: target_ds_did.to_string(),
            reason: format!("Database error during resolution: {e}"),
            retryable: true,
        },
        FederationError::Storage(e) => OutboundError::ResolutionFailed {
            endpoint: target_ds_did.to_string(),
            reason: format!("Storage error during resolution: {e}"),
            retryable: true,
        },
        other => OutboundError::ResolutionFailed {
            endpoint: target_ds_did.to_string(),
            reason: other.to_string(),
            retryable: false,
        },
    }
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

    #[test]
    fn c33_method_matching() {
        assert!(is_c33_method("blue.catbird.mlsDS.deliverDirectRequest"));
        assert!(is_c33_method("blue.catbird.mlsDS.deliverAcceptanceEntry"));
        assert!(is_c33_method("blue.catbird.mlsDS.deliverMessageEntry"));
        assert!(!is_c33_method("blue.catbird.mlsDS.deliverMessage"));
        assert!(!is_c33_method("blue.catbird.mls.sendMessage"));
    }

    #[test]
    fn predecessor_error_detection() {
        assert!(is_predecessor_error("missing signed predecessor entry"));
        assert!(is_predecessor_error("predecessor entry missing"));
        assert!(is_predecessor_error("Predecessor chain mismatch"));
        assert!(!is_predecessor_error("rate limited"));
        assert!(!is_predecessor_error("invalid auth"));
    }

    #[test]
    fn test_classify_resolution_error() {
        let transient_err = FederationError::ResolutionFailed {
            did: "did:web:peer.example.com".into(),
            reason: "DID resolution HTTP error: deadline exceeded".into(),
        };
        let classified = classify_resolution_error("did:web:peer.example.com", transient_err);
        assert!(classified.is_retryable());

        let status503_err = FederationError::ResolutionFailed {
            did: "did:web:peer.example.com".into(),
            reason: "DID document server returned status 503 Service Unavailable".into(),
        };
        let classified = classify_resolution_error("did:web:peer.example.com", status503_err);
        assert!(classified.is_retryable());

        let malformed_err = FederationError::ResolutionFailed {
            did: "did:web:peer.example.com".into(),
            reason: "Invalid DID document JSON: syntax error".into(),
        };
        let classified = classify_resolution_error("did:web:peer.example.com", malformed_err);
        assert!(!classified.is_retryable());

        let ssrf_err = FederationError::ResolutionFailed {
            did: "did:web:peer.example.com".into(),
            reason: "Blocked private address: 127.0.0.1".into(),
        };
        let classified = classify_resolution_error("did:web:peer.example.com", ssrf_err);
        assert!(!classified.is_retryable());

        let status404_err = FederationError::ResolutionFailed {
            did: "did:web:peer.example.com".into(),
            reason: "DID document server returned status 404 Not Found".into(),
        };
        let classified = classify_resolution_error("did:web:peer.example.com", status404_err);
        assert!(!classified.is_retryable());
    }

    #[test]
    fn test_is_outbound_predecessor_error() {
        let err_with_typed_reason = OutboundError::RemoteError {
            status: 400,
            body: "declared_bytes=None, observed_at_least_bytes=80, truncated=false".into(),
            endpoint: "remote DS".into(),
            method: "blue.catbird.mlsDS.deliverMessageEntry".into(),
            predecessor_reason: Some("missing signed predecessor entry".into()),
        };
        assert!(is_outbound_predecessor_error(&err_with_typed_reason));

        let err_without_predecessor = OutboundError::RemoteError {
            status: 400,
            body: "declared_bytes=None, observed_at_least_bytes=50, truncated=false".into(),
            endpoint: "remote DS".into(),
            method: "blue.catbird.mlsDS.deliverMessageEntry".into(),
            predecessor_reason: None,
        };
        assert!(!is_outbound_predecessor_error(&err_without_predecessor));
    }

    #[test]
    fn pending_bytes_cap_uses_default_for_invalid_or_missing_values() {
        assert_eq!(parse_pending_bytes_cap(None, 52_428_800), 52_428_800);
        assert_eq!(parse_pending_bytes_cap(Some("invalid"), 52_428_800), 52_428_800);
    }

    #[test]
    fn pending_bytes_cap_is_clamped_to_safe_range() {
        assert_eq!(parse_pending_bytes_cap(Some("0"), 52_428_800), 1);
        assert_eq!(
            parse_pending_bytes_cap(Some("999999999999"), 52_428_800),
            OUTBOUND_QUEUE_PENDING_BYTES_CAP_MAX
        );
    }

    #[test]
    fn compute_adaptive_caps_scales_by_risk_tier() {
        let base_peer_rows = 500;
        let base_convo_rows = 100;
        let base_peer_bytes = 50 * 1024 * 1024;
        let base_convo_bytes = 10 * 1024 * 1024;

        let low_policy = peer_policy::PeerPolicy {
            status: peer_policy::PeerStatus::Allow,
            risk_tier: peer_policy::RiskTier::Low,
            max_requests_per_minute: None,
            configured_max_requests_per_minute: None,
            trust_score: 100,
        };
        let caps = compute_adaptive_caps(
            base_peer_rows,
            base_convo_rows,
            base_peer_bytes,
            base_convo_bytes,
            &low_policy,
        );
        assert_eq!(caps.peer_row_cap, 500);
        assert_eq!(caps.convo_row_cap, 100);
        assert_eq!(caps.peer_bytes_cap, 50 * 1024 * 1024);
        assert_eq!(caps.convo_bytes_cap, 10 * 1024 * 1024);

        let med_policy = peer_policy::PeerPolicy {
            status: peer_policy::PeerStatus::Allow,
            risk_tier: peer_policy::RiskTier::Medium,
            max_requests_per_minute: None,
            configured_max_requests_per_minute: None,
            trust_score: 75,
        };
        let caps = compute_adaptive_caps(
            base_peer_rows,
            base_convo_rows,
            base_peer_bytes,
            base_convo_bytes,
            &med_policy,
        );
        assert_eq!(caps.peer_row_cap, 375);
        assert_eq!(caps.convo_row_cap, 75);

        let high_policy = peer_policy::PeerPolicy {
            status: peer_policy::PeerStatus::Allow,
            risk_tier: peer_policy::RiskTier::High,
            max_requests_per_minute: None,
            configured_max_requests_per_minute: None,
            trust_score: 50,
        };
        let caps = compute_adaptive_caps(
            base_peer_rows,
            base_convo_rows,
            base_peer_bytes,
            base_convo_bytes,
            &high_policy,
        );
        assert_eq!(caps.peer_row_cap, 250);
        assert_eq!(caps.convo_row_cap, 50);

        let crit_policy = peer_policy::PeerPolicy {
            status: peer_policy::PeerStatus::Allow,
            risk_tier: peer_policy::RiskTier::Critical,
            max_requests_per_minute: None,
            configured_max_requests_per_minute: None,
            trust_score: 10,
        };
        let caps = compute_adaptive_caps(
            base_peer_rows,
            base_convo_rows,
            base_peer_bytes,
            base_convo_bytes,
            &crit_policy,
        );
        assert_eq!(caps.peer_row_cap, 125);
        assert_eq!(caps.convo_row_cap, 25);
    }

    #[test]
    fn compute_adaptive_caps_scales_by_rate_limit_ratio() {
        let policy = peer_policy::PeerPolicy {
            status: peer_policy::PeerStatus::Allow,
            risk_tier: peer_policy::RiskTier::Low,
            max_requests_per_minute: Some(30),
            configured_max_requests_per_minute: Some(60),
            trust_score: 100,
        };
        let caps = compute_adaptive_caps(100, 20, 1000, 200, &policy);
        assert_eq!(caps.peer_row_cap, 50);
        assert_eq!(caps.convo_row_cap, 10);
        assert_eq!(caps.peer_bytes_cap, 500);
        assert_eq!(caps.convo_bytes_cap, 100);
    }

    #[test]
    fn check_capacity_bounds_peer_row_quota_boundary() {
        let caps = AdaptiveCaps {
            peer_row_cap: 10,
            convo_row_cap: 5,
            peer_bytes_cap: 1000,
            convo_bytes_cap: 500,
        };
        let policy = peer_policy::PeerPolicy {
            status: peer_policy::PeerStatus::Allow,
            risk_tier: peer_policy::RiskTier::Low,
            max_requests_per_minute: None,
            configured_max_requests_per_minute: None,
            trust_score: 100,
        };

        // At cap - 1: succeeds
        assert!(check_capacity_bounds(
            "did:web:peer", "convo-1", 50, 9, 400, 2, 100, &caps, &policy
        ).is_ok());

        // At cap: fails
        let err = check_capacity_bounds(
            "did:web:peer", "convo-1", 50, 10, 400, 2, 100, &caps, &policy
        ).unwrap_err();
        match err {
            FederationError::OutboundQueuePeerCapExceeded { pending, limit, .. } => {
                assert_eq!(pending, 10);
                assert_eq!(limit, 10);
            }
            other => panic!("expected OutboundQueuePeerCapExceeded, got {other:?}"),
        }
    }

    #[test]
    fn check_capacity_bounds_peer_bytes_quota_boundary() {
        let caps = AdaptiveCaps {
            peer_row_cap: 100,
            convo_row_cap: 50,
            peer_bytes_cap: 1000,
            convo_bytes_cap: 500,
        };
        let policy = peer_policy::PeerPolicy {
            status: peer_policy::PeerStatus::Allow,
            risk_tier: peer_policy::RiskTier::Low,
            max_requests_per_minute: None,
            configured_max_requests_per_minute: None,
            trust_score: 100,
        };

        // Exactly at cap (950 + 50 = 1000): succeeds
        assert!(check_capacity_bounds(
            "did:web:peer", "convo-1", 50, 5, 950, 1, 50, &caps, &policy
        ).is_ok());

        // 1 byte over cap (951 + 50 = 1001): fails
        let err = check_capacity_bounds(
            "did:web:peer", "convo-1", 50, 5, 951, 1, 50, &caps, &policy
        ).unwrap_err();
        match err {
            FederationError::OutboundQueuePeerCapExceeded { pending, limit, .. } => {
                assert_eq!(pending, 1001);
                assert_eq!(limit, 1000);
            }
            other => panic!("expected OutboundQueuePeerCapExceeded, got {other:?}"),
        }
    }

    #[test]
    fn check_capacity_bounds_convo_quotas_and_empty_convo_bypass() {
        let caps = AdaptiveCaps {
            peer_row_cap: 100,
            convo_row_cap: 5,
            peer_bytes_cap: 10000,
            convo_bytes_cap: 500,
        };
        let policy = peer_policy::PeerPolicy {
            status: peer_policy::PeerStatus::Allow,
            risk_tier: peer_policy::RiskTier::Low,
            max_requests_per_minute: None,
            configured_max_requests_per_minute: None,
            trust_score: 100,
        };

        // Convo row cap exceeded
        let err = check_capacity_bounds(
            "did:web:peer", "convo-1", 50, 10, 500, 5, 200, &caps, &policy
        ).unwrap_err();
        match err {
            FederationError::OutboundQueueConvoPeerCapExceeded { pending, limit, .. } => {
                assert_eq!(pending, 5);
                assert_eq!(limit, 5);
            }
            other => panic!("expected OutboundQueueConvoPeerCapExceeded, got {other:?}"),
        }

        // Convo byte cap exceeded
        let err = check_capacity_bounds(
            "did:web:peer", "convo-1", 100, 10, 500, 2, 450, &caps, &policy
        ).unwrap_err();
        match err {
            FederationError::OutboundQueueConvoPeerCapExceeded { pending, limit, .. } => {
                assert_eq!(pending, 550);
                assert_eq!(limit, 500);
            }
            other => panic!("expected OutboundQueueConvoPeerCapExceeded, got {other:?}"),
        }

        // Empty convo_id bypasses convo limits even if values exceed convo caps
        assert!(check_capacity_bounds(
            "did:web:peer", "", 100, 10, 500, 999, 9999, &caps, &policy
        ).is_ok());
    }

    #[test]
    fn check_idempotent_replay_semantics() {
        let binding_a = EnqueueBinding {
            target_ds_did: "did:web:ds1.example.com",
            target_endpoint: "https://ds1.example.com/rpc",
            method: "blue.catbird.mlsDS.deliverMessageEntry",
            payload: b"serialized-entry-content-alpha",
            convo_id: "convo-123",
        };
        let binding_same = EnqueueBinding {
            target_ds_did: "did:web:ds1.example.com",
            target_endpoint: "https://ds1.example.com/rpc",
            method: "blue.catbird.mlsDS.deliverMessageEntry",
            payload: b"serialized-entry-content-alpha",
            convo_id: "convo-123",
        };
        let binding_diff_payload = EnqueueBinding {
            payload: b"serialized-entry-content-beta",
            ..binding_a.clone()
        };
        let binding_diff_peer = EnqueueBinding {
            target_ds_did: "did:web:ds2.example.com",
            ..binding_a.clone()
        };
        let binding_diff_method = EnqueueBinding {
            method: "blue.catbird.mlsDS.deliverAcceptanceEntry",
            ..binding_a.clone()
        };
        let binding_diff_endpoint = EnqueueBinding {
            target_endpoint: "https://ds2.example.com/rpc",
            ..binding_a.clone()
        };
        let binding_diff_convo = EnqueueBinding {
            convo_id: "convo-456",
            ..binding_a.clone()
        };

        // New item (no prior row) -> Ok(false)
        assert_eq!(
            check_idempotent_replay("queue-id-1", None, &binding_a).unwrap(),
            false
        );

        // Same ID + exact same binding and payload -> Ok(true) (idempotent replay)
        assert_eq!(
            check_idempotent_replay("queue-id-1", Some(&binding_a), &binding_same).unwrap(),
            true
        );

        // Same ID + conflicting payload -> Err(InvalidRequest)
        let err = check_idempotent_replay("queue-id-1", Some(&binding_a), &binding_diff_payload).unwrap_err();
        match err {
            FederationError::InvalidRequest(reason) => {
                assert!(reason.contains("queue-id-1"));
                assert!(reason.contains("conflicting"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }

        // Same ID + conflicting peer -> Err(InvalidRequest)
        let err = check_idempotent_replay("queue-id-1", Some(&binding_a), &binding_diff_peer).unwrap_err();
        match err {
            FederationError::InvalidRequest(reason) => {
                assert!(reason.contains("queue-id-1"));
                assert!(reason.contains("conflicting"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }

        // Same ID + conflicting method -> Err(InvalidRequest)
        let err = check_idempotent_replay("queue-id-1", Some(&binding_a), &binding_diff_method).unwrap_err();
        match err {
            FederationError::InvalidRequest(reason) => {
                assert!(reason.contains("queue-id-1"));
                assert!(reason.contains("conflicting"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }

        // Same ID + conflicting endpoint -> Err(InvalidRequest)
        let err = check_idempotent_replay("queue-id-1", Some(&binding_a), &binding_diff_endpoint).unwrap_err();
        match err {
            FederationError::InvalidRequest(reason) => {
                assert!(reason.contains("queue-id-1"));
                assert!(reason.contains("conflicting"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }

        // Same ID + conflicting convo -> Err(InvalidRequest)
        let err = check_idempotent_replay("queue-id-1", Some(&binding_a), &binding_diff_convo).unwrap_err();
        match err {
            FederationError::InvalidRequest(reason) => {
                assert!(reason.contains("queue-id-1"));
                assert!(reason.contains("conflicting"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn test_classify_resolution_error_transient_db_error() {
        let db_err = FederationError::Database(sqlx::Error::PoolTimedOut);
        let classified = classify_resolution_error("did:web:peer.example.com", db_err);
        assert!(classified.is_retryable());

        let storage_err = FederationError::Storage("transient io error".into());
        let classified = classify_resolution_error("did:web:peer.example.com", storage_err);
        assert!(classified.is_retryable());
    }
}
