use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use super::envelope::{
    verify_receipt, DELIVER_MESSAGE_NSID, DELIVER_WELCOME_NSID, SUBMIT_COMMIT_NSID,
};
use super::errors::FederationError;
use super::receipt::result_bytes_for_receipt;
use super::outbound::{DsResponse, OutboundClient, OutboundError};
use super::peer_policy;
use super::resolver::{DsResolver, ValidatedRemoteDestination};
use crate::auth::AuthMiddleware;
use crate::identity::{canonical_did, dids_equivalent, service_did_base};
use catbird_atproto::generated::blue_catbird::mlsDS::FederationReceiptV1;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use uuid::Uuid;
pub const OUTBOUND_QUEUE_PER_PEER_PENDING_CAP_ENV: &str =
    "FEDERATION_OUTBOUND_QUEUE_PER_PEER_PENDING_CAP";
pub const OUTBOUND_QUEUE_PER_CONVO_PEER_PENDING_CAP_ENV: &str =
    "FEDERATION_OUTBOUND_QUEUE_PER_CONVO_PEER_PENDING_CAP";
pub const OUTBOUND_QUEUE_PER_PEER_PENDING_CAP_DEFAULT: i64 = 500;
pub const OUTBOUND_QUEUE_PER_CONVO_PEER_PENDING_CAP_DEFAULT: i64 = 100;
pub const OUTBOUND_QUEUE_PENDING_CAP_MAX: i64 = 100_000;

pub fn parse_pending_cap(raw: Option<&str>, default: i64) -> i64 {
    raw.and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(default)
        .clamp(1, OUTBOUND_QUEUE_PENDING_CAP_MAX)
}

pub fn pending_cap_from_env(var_name: &str, default: i64) -> i64 {
    parse_pending_cap(std::env::var(var_name).ok().as_deref(), default)
}

pub fn current_pending_caps_from_env() -> (i64, i64) {
    let per_peer = pending_cap_from_env(
        OUTBOUND_QUEUE_PER_PEER_PENDING_CAP_ENV,
        OUTBOUND_QUEUE_PER_PEER_PENDING_CAP_DEFAULT,
    );
    let per_convo = pending_cap_from_env(
        OUTBOUND_QUEUE_PER_CONVO_PEER_PENDING_CAP_ENV,
        OUTBOUND_QUEUE_PER_CONVO_PEER_PENDING_CAP_DEFAULT,
    );
    (per_peer, per_convo)
}

// ---------------------------------------------------------------------------
// Queue item
// ---------------------------------------------------------------------------

/// A single row from the `outbound_queue` table.
#[derive(Debug, Clone)]
pub struct QueueItem {
    pub id: String,
    pub target_ds_did: String,
    /// Pinned target endpoint URL (e.g. `https://ds.example.com`).
    /// If empty (`""`), the endpoint is dynamically resolved and pinned from `target_ds_did` at attempt/send time via `DsResolver`.
    pub target_endpoint: String,
    pub method: String,
    pub payload: Vec<u8>,
    pub convo_id: String,
    pub retry_count: i32,
    pub max_retries: i32,
    pub payload_sha256: Option<Vec<u8>>,
    pub envelope_version: i32,
    pub claim_token: Option<Uuid>,
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
    pub fn new(pool: PgPool, auth_middleware: AuthMiddleware, resolver: Arc<DsResolver>) -> Self {
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
    ///
    /// Pass an empty string `""` for `target_endpoint` to dynamically resolve and pin the endpoint
    /// from `target_ds_did` at attempt time via `DsResolver`.
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
        enforce_pending_caps_with_pool(
            &self.pool,
            target_ds_did,
            convo_id,
            policy,
            self.per_peer_pending_cap,
            self.per_convo_peer_pending_cap,
        )
        .await
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
        self.run_worker_with_intervals(
            outbound,
            auth_sign,
            Duration::from_secs(5),
            Duration::from_secs(300),
            crate::workers::DEAD_ROWS_MAX_AGE,
            168,
            shutdown,
        )
        .await;
    }

    /// Run the background retry worker with configurable intervals and retention limits.
    pub async fn run_worker_with_intervals(
        &self,
        outbound: Arc<OutboundClient>,
        auth_sign: Arc<dyn Fn(&str, &str) -> Result<String, String> + Send + Sync>,
        poll_interval: Duration,
        cleanup_interval: Duration,
        dead_rows_max_age: Duration,
        old_rows_max_age_hours: i64,
        shutdown: CancellationToken,
    ) {
        let mut interval = tokio::time::interval(poll_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let mut cleanup_timer = tokio::time::interval(cleanup_interval);
        cleanup_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

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
                _ = cleanup_timer.tick() => {
                    match self.cleanup_dead(dead_rows_max_age).await {
                        Ok(n) if n > 0 => info!(purged = n, "Cleaned up dead outbound queue rows"),
                        Ok(_) => {}
                        Err(e) => error!(error = %e, "Outbound queue cleanup_dead failed"),
                    }
                    match self.cleanup_old(old_rows_max_age_hours).await {
                        Ok(n) if n > 0 => info!(purged = n, "Cleaned up old outbound queue rows"),
                        Ok(_) => {}
                        Err(e) => error!(error = %e, "Outbound queue cleanup_old failed"),
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

    pub async fn claim_due_batch(&self, limit: i64) -> Result<Vec<QueueItem>, sqlx::Error> {
        let mut tx = self.pool.begin().await?;

        let candidates: Vec<(String,)> = sqlx::query_as(
            "SELECT id FROM outbound_queue \
             WHERE status = 'pending' AND next_retry_at <= NOW() \
             ORDER BY next_retry_at ASC \
             LIMIT $1 \
             FOR UPDATE SKIP LOCKED",
        )
        .bind(limit)
        .fetch_all(&mut *tx)
        .await?;

        if candidates.is_empty() {
            tx.commit().await?;
            return Ok(Vec::new());
        }

        let ids: Vec<String> = candidates.into_iter().map(|(id,)| id).collect();
        let claim_token = Uuid::new_v4();
        let lease_secs = 120.0;

        let rows: Vec<(
            String,
            String,
            String,
            String,
            Vec<u8>,
            String,
            i32,
            i32,
            Option<Vec<u8>>,
            i32,
            Option<Uuid>,
        )> = sqlx::query_as(
            "UPDATE outbound_queue \
             SET status = 'in_flight', \
                 claim_token = $2, \
                 claim_expires_at = NOW() + make_interval(secs => $3) \
             WHERE id = ANY($1) \
             RETURNING id, target_ds_did, target_endpoint, method, payload, convo_id, \
                       retry_count, max_retries, payload_sha256, envelope_version, claim_token",
        )
        .bind(&ids)
        .bind(claim_token)
        .bind(lease_secs)
        .fetch_all(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(rows
            .into_iter()
            .map(
                |(
                    id,
                    target_ds_did,
                    target_endpoint,
                    method,
                    payload,
                    convo_id,
                    retry_count,
                    max_retries,
                    payload_sha256,
                    envelope_version,
                    claim_token,
                )| QueueItem {
                    id,
                    target_ds_did,
                    target_endpoint,
                    method,
                    payload,
                    convo_id,
                    retry_count,
                    max_retries,
                    payload_sha256,
                    envelope_version,
                    claim_token,
                },
            )
            .collect())
    }

    pub async fn reclaim_stuck_in_flight(&self) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE outbound_queue \
             SET status = 'pending', claim_token = NULL, claim_expires_at = NULL \
             WHERE status = 'in_flight' \
               AND (claim_expires_at <= NOW() OR (claim_expires_at IS NULL AND created_at < NOW() - make_interval(secs => 120)))",
        )
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    pub async fn process_pending_batch(
        &self,
        outbound: &OutboundClient,
        auth_sign: &(dyn Fn(&str, &str) -> Result<String, String> + Send + Sync),
    ) -> Result<usize, sqlx::Error> {
        let _ = self.reclaim_stuck_in_flight().await;
        let items = self.claim_due_batch(10).await?;
        let count = items.len();
        for item in &items {
            self.process_item(item, outbound, auth_sign).await;
        }
        Ok(count)
    }

    // -- Single item processing -------------------------------------------------

    async fn handle_failure(&self, item: &QueueItem, error_msg: &str, is_transient: bool) {
        if is_transient && item.retry_count < item.max_retries {
            let delay = backoff_delay(item.retry_count);
            warn!(
                queue_id = %item.id,
                retry = item.retry_count + 1,
                next_retry_secs = delay.as_secs(),
                error = %error_msg,
                "Transient failure, scheduling next attempt"
            );
            let _ = self
                .schedule_retry(
                    &item.id,
                    item.claim_token,
                    item.retry_count + 1,
                    error_msg,
                    delay,
                )
                .await;
        } else {
            if is_transient {
                warn!(
                    queue_id = %item.id,
                    retries = item.retry_count,
                    error = %error_msg,
                    "Transient failure exceeded max retries, marking dead"
                );
            } else {
                warn!(
                    queue_id = %item.id,
                    error = %error_msg,
                    "Permanent hostile failure, marking dead immediately (no resend)"
                );
            }
            let _ = self.mark_dead(&item.id, item.claim_token, error_msg).await;
        }
    }

    pub async fn process_item(
        &self,
        item: &QueueItem,
        outbound: &OutboundClient,
        auth_sign: &(dyn Fn(&str, &str) -> Result<String, String> + Send + Sync),
    ) {
        // 1. Recheck peer policy immediately before send; denial stops/cancels delivery
        if let Err(e) =
            peer_policy::enforce_outbound_peer_policy(&self.pool, &item.target_ds_did).await
        {
            warn!(
                queue_id = %item.id,
                target_ds = %item.target_ds_did,
                error = %e,
                "Peer policy denied outbound delivery for queued item; cancelling delivery"
            );
            let _ = self
                .mark_failed(
                    &item.id,
                    item.claim_token,
                    &format!("Peer policy denied: {e}"),
                )
                .await;
            return;
        }

        // 2. Revalidate and resolve pinned destination on every retry
        let destination = match self.resolve_target_destination(item).await {
            Ok(dest) => dest,
            Err(e) if e.is_retryable() && item.retry_count < item.max_retries => {
                let delay = backoff_delay(item.retry_count);
                warn!(
                    queue_id = %item.id,
                    target_ds = %item.target_ds_did,
                    retry = item.retry_count + 1,
                    next_retry_secs = delay.as_secs(),
                    error = %e,
                    "Retryable destination resolution failure, scheduling next attempt"
                );
                let _ = self
                    .schedule_retry(
                        &item.id,
                        item.claim_token,
                        item.retry_count + 1,
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
                    "Non-retryable destination resolution failure or max retries exceeded"
                );
                let _ = self
                    .mark_failed(&item.id, item.claim_token, &e.to_string())
                    .await;
                return;
            }
        };

        let token = match auth_sign(&item.target_ds_did, &item.method) {
            Ok(t) => t,
            Err(e) => {
                error!(queue_id = %item.id, error = %e, "Failed to sign outbound request");
                let _ = self
                    .mark_failed(
                        &item.id,
                        item.claim_token,
                        &format!("Auth signing failed: {e}"),
                    )
                    .await;
                return;
            }
        };

        let body: serde_json::Value = match serde_json::from_slice(&item.payload) {
            Ok(v) => v,
            Err(e) => {
                error!(queue_id = %item.id, error = %e, "Invalid payload in queue");
                let _ = self
                    .mark_failed(&item.id, item.claim_token, &format!("Invalid payload: {e}"))
                    .await;
                return;
            }
        };
        let expected_sequencer_term = extract_expected_sequencer_term(&item.method, &body);

        // 3. Recheck peer policy immediately before call_procedure_pinned after resolution and token prep
        if let Err(e) =
            peer_policy::enforce_outbound_peer_policy(&self.pool, &item.target_ds_did).await
        {
            warn!(
                queue_id = %item.id,
                target_ds = %item.target_ds_did,
                error = %e,
                "Peer policy denied outbound delivery immediately before procedure call; cancelling delivery"
            );
            let _ = self
                .mark_failed(
                    &item.id,
                    item.claim_token,
                    &format!("Peer policy denied: {e}"),
                )
                .await;
            return;
        }

        match outbound
            .call_procedure_pinned(&destination, &item.method, &token, &body)
            .await
        {
            Ok(resp) => {
                let is_clean_endpoint = matches!(
                    item.method.as_str(),
                    DELIVER_MESSAGE_NSID | DELIVER_WELCOME_NSID | SUBMIT_COMMIT_NSID
                );

                if is_clean_endpoint {
                    let Some(receipt) = resp.clean_receipt() else {
                        warn!(
                            queue_id = %item.id,
                            target_ds = %item.target_ds_did,
                            method = %item.method,
                            "Clean federation response missing FederationReceiptV1"
                        );
                        self.handle_failure(
                            item,
                            "Clean federation response missing FederationReceiptV1",
                            true,
                        )
                        .await;
                        return;
                    };

                    // Resolve receiver DS DID document
                    let did_doc = match self
                        .auth_middleware
                        .resolve_did(receipt.receiver_ds_did.as_str())
                        .await
                    {
                        Ok(doc) => doc,
                        Err(e) => {
                            let is_transient = matches!(
                                e,
                                crate::auth::AuthError::DidResolutionFailed(_)
                                    | crate::auth::AuthError::RateLimitExceeded { .. }
                            );
                            warn!(queue_id = %item.id, error = %e, "Failed to resolve receiver DID");
                            self.handle_failure(
                                item,
                                &format!(
                                    "DID resolution failed for {}: {e}",
                                    receipt.receiver_ds_did.as_str()
                                ),
                                is_transient,
                            )
                            .await;
                            return;
                        }
                    };

                    let Some(verifying_key) = crate::auth::extract_p256_key(&did_doc) else {
                        let error_msg = format!(
                            "No P-256 key found in DID document for {}",
                            receipt.receiver_ds_did.as_str()
                        );
                        warn!(queue_id = %item.id, error = %error_msg, "Missing P-256 key in DID doc");
                        self.handle_failure(item, &error_msg, false).await;
                        return;
                    };

                    // Verify cryptographic signature of receipt
                    match verify_receipt(&receipt, &verifying_key) {
                        Ok(true) => {}
                        Ok(false) => {
                            let error_msg =
                                "Receipt signature verification FAILED — invalid signature"
                                    .to_string();
                            warn!(queue_id = %item.id, remote_ds = %receipt.receiver_ds_did.as_str(), "Receipt signature verification FAILED");
                            self.handle_failure(item, &error_msg, false).await;
                            return;
                        }
                        Err(e) => {
                            let error_msg = format!("Receipt verification error: {e}");
                            warn!(queue_id = %item.id, error = %error_msg, "Receipt verification error");
                            self.handle_failure(item, &error_msg, false).await;
                            return;
                        }
                    }

                    // Receipt signature is cryptographically valid.
                    // Validate receipt fields against outbound item.
                    // Any field mismatch on a signed receipt is permanent hostile -> dead immediately, no resend.
                    if receipt.endpoint.as_str() != item.method {
                        let error_msg = format!(
                            "Receipt endpoint mismatch: expected {}, got {}",
                            item.method,
                            receipt.endpoint.as_str()
                        );
                        warn!(queue_id = %item.id, error = %error_msg, "Delivery ACK field mismatch — possible forgery");
                        self.handle_failure(item, &error_msg, false).await;
                        return;
                    }

                    if receipt.delivery_id.as_str() != item.id {
                        let error_msg = format!(
                            "Receipt deliveryId mismatch: expected {}, got {}",
                            item.id,
                            receipt.delivery_id.as_str()
                        );
                        warn!(queue_id = %item.id, error = %error_msg, "Delivery ACK field mismatch — possible forgery");
                        self.handle_failure(item, &error_msg, false).await;
                        return;
                    }

                    if receipt.conversation_id.as_str() != item.convo_id {
                        let error_msg = format!(
                            "Receipt conversationId mismatch: expected {}, got {}",
                            item.convo_id,
                            receipt.conversation_id.as_str()
                        );
                        warn!(queue_id = %item.id, error = %error_msg, "Delivery ACK field mismatch — possible forgery");
                        self.handle_failure(item, &error_msg, false).await;
                        return;
                    }

                    if !dids_equivalent(receipt.receiver_ds_did.as_str(), &item.target_ds_did) {
                        let error_msg = format!(
                            "Receipt receiverDsDid mismatch: expected {}, got {}",
                            item.target_ds_did,
                            receipt.receiver_ds_did.as_str()
                        );
                        warn!(queue_id = %item.id, error = %error_msg, "Delivery ACK field mismatch — possible forgery");
                        self.handle_failure(item, &error_msg, false).await;
                        return;
                    }

                    if let Some(expected_term) = expected_sequencer_term {
                        if receipt.sequencer_term as u64 != expected_term {
                            let error_msg = format!(
                                "Receipt sequencerTerm mismatch: expected {}, got {}",
                                expected_term, receipt.sequencer_term
                            );
                            warn!(queue_id = %item.id, error = %error_msg, "Delivery ACK field mismatch — possible forgery");
                            self.handle_failure(item, &error_msg, false).await;
                            return;
                        }
                    }

                    // Recompute endpoint envelope digest from item.payload and compare against receipt.envelope_sha256
                    let expected_envelope_digest = match recompute_envelope_digest_from_payload(
                        &item.method,
                        &item.payload,
                    ) {
                        Ok(digest) => digest,
                        Err(e) => {
                            let error_msg =
                                format!("Failed to recompute envelope digest from payload: {e}");
                            warn!(queue_id = %item.id, error = %error_msg, "Payload in queue could not be parsed for envelope digest");
                            self.handle_failure(item, &error_msg, false).await;
                            return;
                        }
                    };

                    if receipt.envelope_sha256.as_ref() != &expected_envelope_digest[..] {
                        let error_msg = format!(
                            "Receipt envelope_sha256 mismatch: expected {}, got {}",
                            hex::encode(expected_envelope_digest),
                            hex::encode(receipt.envelope_sha256.as_ref()),
                        );
                        warn!(queue_id = %item.id, error = %error_msg, "Receipt envelope digest mismatch — possible forgery");
                        self.handle_failure(item, &error_msg, false).await;
                        return;
                    }
                    let result_bytes = match result_bytes_for_receipt(&item.method, &resp.response_bytes) {
                        Ok(b) => b,
                        Err(e) => {
                            let error_msg = format!("Failed to reconstruct result bytes for receipt: {e}");
                            warn!(queue_id = %item.id, error = %error_msg, "Response could not be parsed for result verification");
                            self.handle_failure(item, &error_msg, false).await;
                            return;
                        }
                    };
                    let result_sha256: [u8; 32] = sha2::Sha256::digest(&result_bytes).into();
                    if receipt.result_sha256.as_ref() != &result_sha256[..] {
                        let error_msg = format!(
                            "Receipt result_sha256 mismatch: expected {}, got {}",
                            hex::encode(result_sha256),
                            hex::encode(receipt.result_sha256.as_ref()),
                        );
                        warn!(queue_id = %item.id, error = %error_msg, "Receipt result digest mismatch — possible forgery / permanent hostile response");
                        self.handle_failure(item, &error_msg, false).await;
                        return;
                    }

                    debug!(queue_id = %item.id, "Receipt signature, fields, envelope digest, and result digest verified successfully");
                    match self
                        .persist_receipt_and_mark_delivered(item, &receipt, &resp.response_bytes)
                        .await
                    {
                        Ok(true) => {
                            debug!(queue_id = %item.id, "Receipt persisted and queue item marked delivered atomically");
                        }
                        Ok(false) => {
                            warn!(queue_id = %item.id, "Queue item claim lost before marking delivered; skipping");
                        }
                        Err(e) => {
                            error!(queue_id = %item.id, error = %e, "Failed to persist verified receipt or mark delivered in DB");
                            self.handle_failure(
                                item,
                                &format!("Receipt DB persistence failure: {e}"),
                                true,
                            )
                            .await;
                            return;
                        }
                    }
                } else if resp.accepted {
                    // Legacy delivery ack verification
                    if let Some(ref ack) = resp.ack {
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
                                "Delivery ACK field mismatch — possible forgery"
                            );
                        } else if let Ok(did_doc) =
                            self.auth_middleware.resolve_did(&ack.receiver_ds_did).await
                        {
                            if let Some(verifying_key) = crate::auth::extract_p256_key(&did_doc) {
                                if ack.verify(&verifying_key) {
                                    let _ =
                                        crate::db::store_delivery_ack(&self.pool, ack, true).await;
                                }
                            }
                        }
                    }
                    let _ = self.mark_delivered(&item.id, item.claim_token).await;
                } else {
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
                    let _ = self.mark_failed(&item.id, item.claim_token, &reason).await;
                }
            }
            Err(e) if e.is_retryable() => {
                self.handle_failure(item, &e.to_string(), true).await;
            }
            Err(e) => {
                self.handle_failure(item, &e.to_string(), false).await;
            }
        }
    }
    /// Resolve and pin target remote destination for a queue item.
    ///
    /// If `target_endpoint` is empty (`""`), resolves and pins dynamically from `target_ds_did` via `DsResolver`.
    /// If `target_endpoint` is present, attempts `resolve_ds_destination` first, falling back to resolving from the endpoint.
    async fn resolve_target_destination(
        &self,
        item: &QueueItem,
    ) -> Result<ValidatedRemoteDestination, OutboundError> {
        let canonical_target_ds_did = canonical_did(&item.target_ds_did).to_string();

        let mut last_error = None;
        if !canonical_target_ds_did.is_empty() {
            match self
                .resolver
                .resolve_ds_destination(&canonical_target_ds_did)
                .await
            {
                Ok(dest) => return Ok(dest),
                Err(e) => {
                    debug!(
                        queue_id = %item.id,
                        target_ds = %item.target_ds_did,
                        error = %e,
                        "resolve_ds_destination failed, attempting stored endpoint"
                    );
                    last_error = Some(e);
                }
            }
        }

        if !item.target_endpoint.is_empty() {
            match self
                .resolver
                .resolve_endpoint_destination(&item.target_endpoint)
                .await
            {
                Ok(dest) => return Ok(dest),
                Err(e) => {
                    debug!(
                        queue_id = %item.id,
                        target_endpoint = %item.target_endpoint,
                        error = %e,
                        "resolve_endpoint_destination failed"
                    );
                    if !e.is_retryable() || last_error.is_none() {
                        last_error = Some(e);
                    }
                }
            }
        }

        let err = last_error.unwrap_or_else(|| FederationError::ResolutionFailed {
            did: canonical_target_ds_did.clone(),
            kind: crate::federation::ResolutionFailureKind::Permanent(
                "Could not resolve target DS DID to pinned destination".to_string(),
            ),
        });

        Err(Self::outbound_error_from_federation_error(
            &err,
            &item.target_ds_did,
        ))
    }

    fn outbound_error_from_federation_error(
        err: &FederationError,
        target_ds: &str,
    ) -> OutboundError {
        match err {
            FederationError::DsUnreachable { endpoint, reason } => {
                OutboundError::ConnectionFailed {
                    endpoint: endpoint.clone(),
                    reason: reason.clone(),
                }
            }
            FederationError::RemoteError { status, body } => OutboundError::RemoteError {
                status: *status,
                body: body.clone(),
                endpoint: target_ds.to_string(),
                method: "resolve".to_string(),
            },
            FederationError::Http(e) => {
                if e.is_timeout() {
                    OutboundError::Timeout {
                        endpoint: target_ds.to_string(),
                        method: "resolve".to_string(),
                    }
                } else if e.is_connect() {
                    OutboundError::ConnectionFailed {
                        endpoint: target_ds.to_string(),
                        reason: e.to_string(),
                    }
                } else if let Some(status) = e.status() {
                    OutboundError::RemoteError {
                        status: status.as_u16(),
                        body: e.to_string(),
                        endpoint: target_ds.to_string(),
                        method: "resolve".to_string(),
                    }
                } else {
                    OutboundError::RequestFailed {
                        endpoint: target_ds.to_string(),
                        reason: e.to_string(),
                    }
                }
            }
            FederationError::ResolutionFailed { did, kind } => OutboundError::ResolutionFailed {
                did: did.clone(),
                kind: kind.clone(),
            },
            other => {
                if other.is_retryable() {
                    OutboundError::RequestFailed {
                        endpoint: target_ds.to_string(),
                        reason: other.to_string(),
                    }
                } else {
                    OutboundError::InvalidResponse {
                        reason: format!("Non-retryable resolution error for {target_ds}: {other}"),
                    }
                }
            }
        }
    }

    pub(crate) async fn resolve_target_endpoint(
        &self,
        item: &QueueItem,
    ) -> Result<String, OutboundError> {
        let dest = self.resolve_target_destination(item).await?;
        Ok(dest.url.as_str().trim_end_matches('/').to_string())
    }
    // -- Status mutations -------------------------------------------------------

    pub async fn mark_delivered(
        &self,
        id: &str,
        claim_token: Option<Uuid>,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE outbound_queue \
             SET status = 'delivered', claim_token = NULL, claim_expires_at = NULL \
             WHERE id = $1 AND ($2::uuid IS NULL OR claim_token = $2)",
        )
        .bind(id)
        .bind(claim_token)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }
    pub async fn persist_receipt_and_mark_delivered(
        &self,
        item: &QueueItem,
        receipt: &FederationReceiptV1,
        response_bytes: &[u8],
    ) -> Result<bool, sqlx::Error> {
        let mut tx = self.pool.begin().await?;

        store_federation_receipt_conn(&mut *tx, receipt, response_bytes).await?;

        let result = sqlx::query(
            "UPDATE outbound_queue \
             SET status = 'delivered', claim_token = NULL, claim_expires_at = NULL \
             WHERE id = $1 AND ($2::uuid IS NULL OR claim_token = $2)",
        )
        .bind(&item.id)
        .bind(item.claim_token)
        .execute(&mut *tx)
        .await?;

        if result.rows_affected() == 0 {
            return Ok(false);
        }

        tx.commit().await?;
        Ok(true)
    }

    pub async fn mark_failed(
        &self,
        id: &str,
        claim_token: Option<Uuid>,
        error_msg: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE outbound_queue \
             SET status = 'failed', last_error = $2, claim_token = NULL, claim_expires_at = NULL \
             WHERE id = $1 AND ($3::uuid IS NULL OR claim_token = $3)",
        )
        .bind(id)
        .bind(error_msg)
        .bind(claim_token)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn mark_dead(
        &self,
        id: &str,
        claim_token: Option<Uuid>,
        error_msg: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE outbound_queue \
             SET status = 'dead', last_error = $2, claim_token = NULL, claim_expires_at = NULL \
             WHERE id = $1 AND ($3::uuid IS NULL OR claim_token = $3)",
        )
        .bind(id)
        .bind(error_msg)
        .bind(claim_token)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn schedule_retry(
        &self,
        id: &str,
        claim_token: Option<Uuid>,
        new_count: i32,
        error_msg: &str,
        delay: Duration,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE outbound_queue \
             SET status = 'pending', retry_count = $2, last_error = $3, \
                 next_retry_at = NOW() + make_interval(secs => $4), \
                 claim_token = NULL, claim_expires_at = NULL \
             WHERE id = $1 AND ($5::uuid IS NULL OR claim_token = $5)",
        )
        .bind(id)
        .bind(new_count)
        .bind(error_msg)
        .bind(delay.as_secs() as f64)
        .bind(claim_token)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }
    // -- Maintenance ------------------------------------------------------------

    /// Delete old delivered/failed/dead items older than `max_age_hours`.
    pub async fn cleanup_old(&self, max_age_hours: i64) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            "DELETE FROM outbound_queue \
             WHERE status IN ('delivered', 'failed', 'dead') \
               AND created_at < NOW() - make_interval(hours => $1::integer)",
        )
        .bind(max_age_hours as i32)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Delete dead rows older than `max_age`.
    pub async fn cleanup_dead(&self, max_age: Duration) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            "DELETE FROM outbound_queue \
             WHERE status = 'dead' \
               AND created_at < NOW() - make_interval(secs => $1)",
        )
        .bind(max_age.as_secs() as f64)
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
        DELIVER_MESSAGE_NSID | DELIVER_WELCOME_NSID | SUBMIT_COMMIT_NSID => body
            .get("header")
            .and_then(|h| h.get("sequencerTerm"))
            .and_then(serde_json::Value::as_u64)
            .or_else(|| {
                body.get("sequencerTerm")
                    .and_then(serde_json::Value::as_u64)
            }),
        _ => None,
    }
}

pub fn recompute_envelope_digest_from_payload(
    method: &str,
    payload_bytes: &[u8],
) -> Result<[u8; 32], FederationError> {
    use super::envelope::{
        compute_commit_envelope_digest, compute_message_envelope_digest,
        compute_welcome_envelope_digest, validate_entry_locator, validate_envelope_header,
    };
    use catbird_atproto::generated::blue_catbird::mlsDS::{
        deliver_message::DeliverMessage, deliver_welcome::DeliverWelcome,
        submit_commit::SubmitCommit,
    };

    match method {
        DELIVER_MESSAGE_NSID => {
            let msg: DeliverMessage<jacquard_common::DefaultStr> =
                serde_json::from_slice(payload_bytes).map_err(FederationError::Json)?;
            let header = validate_envelope_header(&msg.header)?;
            let locator = validate_entry_locator(&msg.entry_locator)?;
            compute_message_envelope_digest(
                &header,
                msg.recipient_did.as_str(),
                &locator,
                msg.entry_bytes.as_ref(),
                msg.signed_request_bytes.as_ref(),
            )
        }
        DELIVER_WELCOME_NSID => {
            let msg: DeliverWelcome<jacquard_common::DefaultStr> =
                serde_json::from_slice(payload_bytes).map_err(FederationError::Json)?;
            let header = validate_envelope_header(&msg.header)?;
            let locator = validate_entry_locator(&msg.entry_locator)?;
            let recipient_device_id =
                Uuid::from_str(msg.recipient_device_id.as_str()).map_err(|_| {
                    FederationError::InvalidEnvelope {
                        reason: "invalid recipientDeviceId".to_string(),
                    }
                })?;
            let welcome_id = Uuid::from_str(msg.welcome_id.as_str()).map_err(|_| {
                FederationError::InvalidEnvelope {
                    reason: "invalid welcomeId".to_string(),
                }
            })?;
            let recovery_request_id =
                Uuid::from_str(msg.recovery_request_id.as_str()).map_err(|_| {
                    FederationError::InvalidEnvelope {
                        reason: "invalid recoveryRequestId".to_string(),
                    }
                })?;
            if msg.key_package_ref.len() != 32
                || msg.welcome_sha256.len() != 32
                || msg.public_snapshot_sha256.len() != 32
                || msg.tree_summary_sha256.len() != 32
            {
                return Err(FederationError::InvalidEnvelope {
                    reason: "invalid crypto byte array length in deliverWelcome payload"
                        .to_string(),
                });
            }
            let mut key_package_ref = [0u8; 32];
            key_package_ref.copy_from_slice(&msg.key_package_ref);
            let mut welcome_sha256 = [0u8; 32];
            welcome_sha256.copy_from_slice(&msg.welcome_sha256);
            let mut public_snapshot_sha256 = [0u8; 32];
            public_snapshot_sha256.copy_from_slice(&msg.public_snapshot_sha256);
            let mut tree_summary_sha256 = [0u8; 32];
            tree_summary_sha256.copy_from_slice(&msg.tree_summary_sha256);

            compute_welcome_envelope_digest(
                &header,
                msg.recipient_did.as_str(),
                recipient_device_id,
                welcome_id,
                recovery_request_id,
                &key_package_ref,
                msg.welcome_bytes.as_ref(),
                &welcome_sha256,
                msg.entry_bytes.as_ref(),
                msg.signed_request_bytes.as_ref(),
                &locator,
                &msg.coordinates,
                &public_snapshot_sha256,
                &tree_summary_sha256,
            )
        }
        SUBMIT_COMMIT_NSID => {
            let msg: SubmitCommit<jacquard_common::DefaultStr> =
                serde_json::from_slice(payload_bytes).map_err(FederationError::Json)?;
            let header = validate_envelope_header(&msg.header)?;
            compute_commit_envelope_digest(&header, msg.signed_request_bytes.as_ref())
        }
        _ => Err(FederationError::InvalidEnvelope {
            reason: format!("unsupported clean federation method: {method}"),
        }),
    }
}

pub async fn store_federation_receipt_conn(
    conn: &mut sqlx::PgConnection,
    receipt: &FederationReceiptV1,
    response_bytes: &[u8],
) -> Result<(), sqlx::Error> {
    let delivery_id = match Uuid::from_str(receipt.delivery_id.as_str()) {
        Ok(u) => u,
        Err(e) => {
            return Err(sqlx::Error::Protocol(format!(
                "invalid delivery_id in receipt: {e}"
            )))
        }
    };
    let conversation_id = match Uuid::from_str(receipt.conversation_id.as_str()) {
        Ok(u) => u,
        Err(e) => {
            return Err(sqlx::Error::Protocol(format!(
                "invalid conversation_id in receipt: {e}"
            )))
        }
    };
    let source_entry_id = match Uuid::from_str(receipt.source_locator.entry_id.as_str()) {
        Ok(u) => u,
        Err(e) => {
            return Err(sqlx::Error::Protocol(format!(
                "invalid source_entry_id in receipt: {e}"
            )))
        }
    };
    let completed_at = match DateTime::parse_from_rfc3339(receipt.completed_at.as_str()) {
        Ok(dt) => dt.with_timezone(&Utc),
        Err(e) => {
            return Err(sqlx::Error::Protocol(format!(
                "invalid completed_at in receipt: {e}"
            )))
        }
    };
    let response_sha256: [u8; 32] = Sha256::digest(response_bytes).into();

    let existing: Option<(
        String,
        Uuid,
        String,
        String,
        String,
        i64,
        Vec<u8>,
        Vec<u8>,
        Uuid,
        i64,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    )> = sqlx::query_as(
        "SELECT endpoint_nsid, conversation_id, sender_ds_did, receiver_ds_did, \
                sequencer_did, sequencer_term, envelope_sha256, result_sha256, \
                source_entry_id, source_entry_seq, source_entry_fingerprint, \
                response_bytes, response_sha256, receipt_signature \
           FROM chat.federation_delivery_receipts \
          WHERE delivery_id = $1",
    )
    .bind(delivery_id)
    .fetch_optional(&mut *conn)
    .await?;

    if let Some((
        stored_endpoint,
        stored_convo,
        stored_sender,
        stored_receiver,
        stored_sequencer,
        stored_term,
        stored_envelope_sha256,
        stored_result_sha256,
        stored_source_entry_id,
        stored_source_entry_seq,
        stored_source_entry_fingerprint,
        stored_response_bytes,
        stored_response_sha256,
        stored_signature,
    )) = existing
    {
        if stored_endpoint != receipt.endpoint.as_str()
            || stored_convo != conversation_id
            || stored_sender != receipt.sender_ds_did.as_str()
            || stored_receiver != receipt.receiver_ds_did.as_str()
            || stored_sequencer != receipt.sequencer_did.as_str()
            || stored_term != receipt.sequencer_term as i64
            || stored_envelope_sha256 != receipt.envelope_sha256.as_ref()
            || stored_result_sha256 != receipt.result_sha256.as_ref()
            || stored_source_entry_id != source_entry_id
            || stored_source_entry_seq != receipt.source_locator.seq as i64
            || stored_source_entry_fingerprint
                != receipt.source_locator.outer_entry_fingerprint.as_ref()
            || stored_response_bytes != response_bytes
            || stored_response_sha256 != &response_sha256[..]
            || stored_signature != receipt.signature.as_ref()
        {
            return Err(sqlx::Error::Protocol(format!(
                "Receipt conflict for delivery_id {delivery_id}: existing receipt bytes or metadata differ"
            )));
        }
        return Ok(());
    }

    let insert_res = sqlx::query(
        "INSERT INTO chat.federation_delivery_receipts ( \
            delivery_id, endpoint_nsid, conversation_id, sender_ds_did, receiver_ds_did, \
            sequencer_did, sequencer_term, envelope_sha256, result_sha256, \
            source_entry_id, source_entry_seq, source_entry_fingerprint, \
            response_bytes, response_sha256, receipt_signature, completed_at \
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)",
    )
    .bind(delivery_id)
    .bind(receipt.endpoint.as_str())
    .bind(conversation_id)
    .bind(receipt.sender_ds_did.as_str())
    .bind(receipt.receiver_ds_did.as_str())
    .bind(receipt.sequencer_did.as_str())
    .bind(receipt.sequencer_term as i64)
    .bind(receipt.envelope_sha256.as_ref())
    .bind(receipt.result_sha256.as_ref())
    .bind(source_entry_id)
    .bind(receipt.source_locator.seq as i64)
    .bind(receipt.source_locator.outer_entry_fingerprint.as_ref())
    .bind(response_bytes)
    .bind(&response_sha256[..])
    .bind(receipt.signature.as_ref())
    .bind(completed_at)
    .execute(&mut *conn)
    .await;

    match insert_res {
        Ok(_) => Ok(()),
        Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
            let row: Option<(
                String,
                Uuid,
                String,
                String,
                String,
                i64,
                Vec<u8>,
                Vec<u8>,
                Uuid,
                i64,
                Vec<u8>,
                Vec<u8>,
                Vec<u8>,
                Vec<u8>,
            )> = sqlx::query_as(
                "SELECT endpoint_nsid, conversation_id, sender_ds_did, receiver_ds_did, \
                        sequencer_did, sequencer_term, envelope_sha256, result_sha256, \
                        source_entry_id, source_entry_seq, source_entry_fingerprint, \
                        response_bytes, response_sha256, receipt_signature \
                   FROM chat.federation_delivery_receipts \
                  WHERE delivery_id = $1",
            )
            .bind(delivery_id)
            .fetch_optional(&mut *conn)
            .await?;

            if let Some((
                stored_endpoint,
                stored_convo,
                stored_sender,
                stored_receiver,
                stored_sequencer,
                stored_term,
                stored_envelope_sha256,
                stored_result_sha256,
                stored_source_entry_id,
                stored_source_entry_seq,
                stored_source_entry_fingerprint,
                stored_response_bytes,
                stored_response_sha256,
                stored_signature,
            )) = row
            {
                if stored_endpoint != receipt.endpoint.as_str()
                    || stored_convo != conversation_id
                    || stored_sender != receipt.sender_ds_did.as_str()
                    || stored_receiver != receipt.receiver_ds_did.as_str()
                    || stored_sequencer != receipt.sequencer_did.as_str()
                    || stored_term != receipt.sequencer_term as i64
                    || stored_envelope_sha256 != receipt.envelope_sha256.as_ref()
                    || stored_result_sha256 != receipt.result_sha256.as_ref()
                    || stored_source_entry_id != source_entry_id
                    || stored_source_entry_seq != receipt.source_locator.seq as i64
                    || stored_source_entry_fingerprint
                        != receipt.source_locator.outer_entry_fingerprint.as_ref()
                    || stored_response_bytes != response_bytes
                    || stored_response_sha256 != &response_sha256[..]
                    || stored_signature != receipt.signature.as_ref()
                {
                    return Err(sqlx::Error::Protocol(format!(
                        "Receipt conflict on concurrent insert for delivery_id {delivery_id}"
                    )));
                }
                Ok(())
            } else {
                Err(sqlx::Error::Database(db_err))
            }
        }
        Err(e) => Err(e),
    }
}
pub async fn store_federation_receipt(
    pool: &PgPool,
    receipt: &FederationReceiptV1,
    response_bytes: &[u8],
) -> Result<(), sqlx::Error> {
    let mut conn = pool.acquire().await?;
    store_federation_receipt_conn(&mut conn, receipt, response_bytes).await
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
            payload_sha256: None,
            envelope_version: 1,
            claim_token: None,
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
        let _ = sqlx::query(
            "SET chat.operation_claim_activation_approved = 'handlers-and-legacy-apis-sealed'",
        )
        .execute(&mut *conn)
        .await;
        let mut migrator = sqlx::migrate!("./migrations");
        migrator.set_ignore_missing(true);
        migrator
            .run(&mut *conn)
            .await
            .expect("migrations must succeed");
        let _ = sqlx::query("RESET chat.operation_claim_activation_approved")
            .execute(&mut *conn)
            .await;
        let peer_did = format!(
            "did:web:revoked-{}.example.com",
            uuid::Uuid::new_v4().as_simple()
        );

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

        let processed = queue
            .process_pending_batch(&outbound, auth_sign.as_ref())
            .await
            .unwrap();
        assert!(processed >= 1);

        // 5. Verify the item status is now 'failed' with peer policy denial
        let (status, last_error): (String, Option<String>) =
            sqlx::query_as("SELECT status, last_error FROM outbound_queue WHERE id = $1")
                .bind(&item_id)
                .fetch_one(&pool)
                .await
                .unwrap();

        assert_eq!(status, "failed");
        assert!(last_error
            .unwrap_or_default()
            .contains("Peer policy denied"));
    }

    #[tokio::test]
    async fn test_outbound_queue_retries_on_injected_dns_temporary_and_timeout() {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL is required for queue transient DNS test");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .expect("connect to test db");
        let mut conn = pool.acquire().await.expect("acquire migration connection");
        let _ = sqlx::query(
            "SET chat.operation_claim_activation_approved = 'handlers-and-legacy-apis-sealed'",
        )
        .execute(&mut *conn)
        .await;
        let mut migrator = sqlx::migrate!("./migrations");
        migrator.set_ignore_missing(true);
        migrator
            .run(&mut *conn)
            .await
            .expect("migrations must succeed");
        let _ = sqlx::query("RESET chat.operation_claim_activation_approved")
            .execute(&mut *conn)
            .await;

        let peer_did = format!(
            "did:web:injected-dns-{}.example.com",
            uuid::Uuid::new_v4().as_simple()
        );

        // Peer is allowed in federation_peers
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
        let resolver = Arc::new(
            DsResolver::new(
                pool.clone(),
                http,
                "did:web:self.example.com".to_string(),
                "https://self.example.com".to_string(),
                None,
                3600,
            )
            .with_destination_resolver_hook(Arc::new(|_endpoint| {
                Some(Box::pin(async {
                    Err(FederationError::ResolutionFailed {
                        did: "injected-peer".to_string(),
                        kind: crate::federation::ResolutionFailureKind::DnsTemporary(
                            "Injected EAI_AGAIN temporary DNS failure".to_string(),
                        ),
                    })
                }))
            })),
        );
        let queue = OutboundQueue::new(pool.clone(), AuthMiddleware::new(), resolver);

        let item_id = format!("queue-item-dns-temp-{}", uuid::Uuid::new_v4().as_simple());
        let payload = serde_json::to_vec(&serde_json::json!({"test": "dns-temp-retry"})).unwrap();

        sqlx::query(
            "INSERT INTO outbound_queue (id, target_ds_did, target_endpoint, method, payload, convo_id, status, retry_count, max_retries, next_retry_at) \
             VALUES ($1, $2, $3, $4, $5, $6, 'pending', 0, 5, NOW() - INTERVAL '1 second')",
        )
        .bind(&item_id)
        .bind(&peer_did)
        .bind("https://injected.example.com")
        .bind("blue.catbird.mlsDS.deliverMessage")
        .bind(&payload)
        .bind("convo-test-dns-temp")
        .execute(&pool)
        .await
        .unwrap();

        let item = QueueItem {
            id: item_id.clone(),
            target_ds_did: peer_did.clone(),
            target_endpoint: "https://injected.example.com".to_string(),
            method: "blue.catbird.mlsDS.deliverMessage".to_string(),
            payload: payload.clone(),
            convo_id: "convo-test-dns-temp".to_string(),
            retry_count: 0,
            max_retries: 5,
            payload_sha256: None,
            envelope_version: 1,
            claim_token: None,
        };
        let outbound = OutboundClient::new(1, 1);
        let auth_sign = Arc::new(|_target: &str, _method: &str| Ok("test-jwt".to_string()));

        queue
            .process_item(&item, &outbound, auth_sign.as_ref())
            .await;
        // Verify item status is STILL 'pending', retry_count is 1, and next_retry_at is scheduled in future
        let (status, retry_count, next_retry_at, last_error): (String, i32, chrono::DateTime<chrono::Utc>, Option<String>) = sqlx::query_as(
            "SELECT status, retry_count, next_retry_at, last_error FROM outbound_queue WHERE id = $1",
        )
        .bind(&item_id)
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(
            status, "pending",
            "Transient DNS failure must remain pending for retry"
        );
        assert_eq!(retry_count, 1, "Retry count must increment to 1");
        assert!(
            next_retry_at > chrono::Utc::now(),
            "next_retry_at must be in the future"
        );
        let err_msg = last_error.unwrap_or_default();
        assert!(err_msg.contains("Injected EAI_AGAIN") || err_msg.contains("temporary"));
    }

    #[tokio::test]
    async fn test_outbound_queue_fails_immediately_on_injected_dns_nxdomain_permanent() {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL is required for queue NXDOMAIN test");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .expect("connect to test db");
        let mut conn = pool.acquire().await.expect("acquire migration connection");
        let _ = sqlx::query(
            "SET chat.operation_claim_activation_approved = 'handlers-and-legacy-apis-sealed'",
        )
        .execute(&mut *conn)
        .await;
        let mut migrator = sqlx::migrate!("./migrations");
        migrator.set_ignore_missing(true);
        migrator
            .run(&mut *conn)
            .await
            .expect("migrations must succeed");
        let _ = sqlx::query("RESET chat.operation_claim_activation_approved")
            .execute(&mut *conn)
            .await;

        let peer_did = format!(
            "did:web:nxdomain-{}.example.com",
            uuid::Uuid::new_v4().as_simple()
        );

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
        let resolver = Arc::new(
            DsResolver::new(
                pool.clone(),
                http,
                "did:web:self.example.com".to_string(),
                "https://self.example.com".to_string(),
                None,
                3600,
            )
            .with_destination_resolver_hook(Arc::new(|_endpoint| {
                Some(Box::pin(async {
                    Err(FederationError::ResolutionFailed {
                        did: "nxdomain-peer".to_string(),
                        kind: crate::federation::ResolutionFailureKind::DnsNxdomain(
                            "Injected host not found (NXDOMAIN)".to_string(),
                        ),
                    })
                }))
            })),
        );
        let queue = OutboundQueue::new(pool.clone(), AuthMiddleware::new(), resolver);

        let item_id = format!("queue-item-nxdomain-{}", uuid::Uuid::new_v4().as_simple());
        let payload = serde_json::to_vec(&serde_json::json!({"test": "nxdomain"})).unwrap();

        sqlx::query(
            "INSERT INTO outbound_queue (id, target_ds_did, target_endpoint, method, payload, convo_id, status, retry_count, max_retries, next_retry_at) \
             VALUES ($1, $2, $3, $4, $5, $6, 'pending', 0, 5, NOW() - INTERVAL '1 second')",
        )
        .bind(&item_id)
        .bind(&peer_did)
        .bind("https://nxdomain.example.com")
        .bind("blue.catbird.mlsDS.deliverMessage")
        .bind(&payload)
        .bind("convo-test-nxdomain")
        .execute(&pool)
        .await
        .unwrap();

        let item = QueueItem {
            id: item_id.clone(),
            target_ds_did: peer_did.clone(),
            target_endpoint: "https://nxdomain.example.com".to_string(),
            method: "blue.catbird.mlsDS.deliverMessage".to_string(),
            payload: payload.clone(),
            convo_id: "convo-test-nxdomain".to_string(),
            retry_count: 0,
            max_retries: 5,
            payload_sha256: None,
            envelope_version: 1,
            claim_token: None,
        };
        let outbound = OutboundClient::new(1, 1);
        let auth_sign = Arc::new(|_target: &str, _method: &str| Ok("test-jwt".to_string()));

        queue
            .process_item(&item, &outbound, auth_sign.as_ref())
            .await;
        let (status, retry_count, last_error): (String, i32, Option<String>) = sqlx::query_as(
            "SELECT status, retry_count, last_error FROM outbound_queue WHERE id = $1",
        )
        .bind(&item_id)
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(
            status, "failed",
            "NXDOMAIN resolution error must be marked failed immediately"
        );
        assert_eq!(retry_count, 0, "Retry count must remain 0");
        let err_msg = last_error.unwrap_or_default();
        assert!(err_msg.contains("NXDOMAIN") || err_msg.contains("not found"));
    }

    #[tokio::test]
    async fn test_outbound_queue_distinguishes_injected_http_status_codes() {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL is required for queue HTTP status test");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .expect("connect to test db");
        let mut conn = pool.acquire().await.expect("acquire migration connection");
        let _ = sqlx::query(
            "SET chat.operation_claim_activation_approved = 'handlers-and-legacy-apis-sealed'",
        )
        .execute(&mut *conn)
        .await;
        let mut migrator = sqlx::migrate!("./migrations");
        migrator.set_ignore_missing(true);
        migrator
            .run(&mut *conn)
            .await
            .expect("migrations must succeed");
        let _ = sqlx::query("RESET chat.operation_claim_activation_approved")
            .execute(&mut *conn)
            .await;

        let peer_did = format!(
            "did:web:status-{}.example.com",
            uuid::Uuid::new_v4().as_simple()
        );

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
        // 1. Resolver returning HTTP 503 (transient / retryable)
        let resolver_503 = Arc::new(
            DsResolver::new(
                pool.clone(),
                http.clone(),
                "did:web:self.example.com".to_string(),
                "https://self.example.com".to_string(),
                None,
                3600,
            )
            .with_destination_resolver_hook(Arc::new(|_endpoint| {
                Some(Box::pin(async {
                    Err(FederationError::ResolutionFailed {
                        did: "status-503-peer".to_string(),
                        kind: crate::federation::ResolutionFailureKind::HttpStatus {
                            status: 503,
                            message: "Service Unavailable".to_string(),
                        },
                    })
                }))
            })),
        );
        let queue_503 = OutboundQueue::new(pool.clone(), AuthMiddleware::new(), resolver_503);

        let item_503_id = format!("queue-item-503-{}", uuid::Uuid::new_v4().as_simple());
        let payload = serde_json::to_vec(&serde_json::json!({"test": "503"})).unwrap();

        sqlx::query(
            "INSERT INTO outbound_queue (id, target_ds_did, target_endpoint, method, payload, convo_id, status, retry_count, max_retries, next_retry_at) \
             VALUES ($1, $2, $3, $4, $5, $6, 'pending', 0, 5, NOW() - INTERVAL '1 second')",
        )
        .bind(&item_503_id)
        .bind(&peer_did)
        .bind("https://status503.example.com")
        .bind("blue.catbird.mlsDS.deliverMessage")
        .bind(&payload)
        .bind("convo-test-503")
        .execute(&pool)
        .await
        .unwrap();

        let item_503 = QueueItem {
            id: item_503_id.clone(),
            target_ds_did: peer_did.clone(),
            target_endpoint: "https://status503.example.com".to_string(),
            method: "blue.catbird.mlsDS.deliverMessage".to_string(),
            payload: payload.clone(),
            convo_id: "convo-test-503".to_string(),
            retry_count: 0,
            max_retries: 5,
            payload_sha256: None,
            envelope_version: 1,
            claim_token: None,
        };
        let outbound = OutboundClient::new(1, 1);
        let auth_sign = Arc::new(|_target: &str, _method: &str| Ok("test-jwt".to_string()));

        queue_503
            .process_item(&item_503, &outbound, auth_sign.as_ref())
            .await;
        let (status_503, retry_count_503, next_retry_503): (
            String,
            i32,
            chrono::DateTime<chrono::Utc>,
        ) = sqlx::query_as(
            "SELECT status, retry_count, next_retry_at FROM outbound_queue WHERE id = $1",
        )
        .bind(&item_503_id)
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(status_503, "pending", "503 must remain pending for retry");
        assert_eq!(
            retry_count_503, 1,
            "Retry count must increment to 1 for 503"
        );
        assert!(
            next_retry_503 > chrono::Utc::now(),
            "next_retry_at must be in the future"
        );

        // 2. Resolver returning HTTP 404 (permanent / non-retryable)
        let resolver_404 = Arc::new(
            DsResolver::new(
                pool.clone(),
                http,
                "did:web:self.example.com".to_string(),
                "https://self.example.com".to_string(),
                None,
                3600,
            )
            .with_destination_resolver_hook(Arc::new(|_endpoint| {
                Some(Box::pin(async {
                    Err(FederationError::ResolutionFailed {
                        did: "status-404-peer".to_string(),
                        kind: crate::federation::ResolutionFailureKind::HttpStatus {
                            status: 404,
                            message: "Not Found".to_string(),
                        },
                    })
                }))
            })),
        );
        let queue_404 = OutboundQueue::new(pool.clone(), AuthMiddleware::new(), resolver_404);

        let item_404_id = format!("queue-item-404-{}", uuid::Uuid::new_v4().as_simple());
        sqlx::query(
            "INSERT INTO outbound_queue (id, target_ds_did, target_endpoint, method, payload, convo_id, status, retry_count, max_retries, next_retry_at) \
             VALUES ($1, $2, $3, $4, $5, $6, 'pending', 0, 5, NOW() - INTERVAL '1 second')",
        )
        .bind(&item_404_id)
        .bind(&peer_did)
        .bind("https://status404.example.com")
        .bind("blue.catbird.mlsDS.deliverMessage")
        .bind(&payload)
        .bind("convo-test-404")
        .execute(&pool)
        .await
        .unwrap();

        let item_404 = QueueItem {
            id: item_404_id.clone(),
            target_ds_did: peer_did.clone(),
            target_endpoint: "https://status404.example.com".to_string(),
            method: "blue.catbird.mlsDS.deliverMessage".to_string(),
            payload: payload.clone(),
            convo_id: "convo-test-404".to_string(),
            retry_count: 0,
            max_retries: 5,
            payload_sha256: None,
            envelope_version: 1,
            claim_token: None,
        };
        queue_404
            .process_item(&item_404, &outbound, auth_sign.as_ref())
            .await;
        let (status_404, retry_count_404): (String, i32) =
            sqlx::query_as("SELECT status, retry_count FROM outbound_queue WHERE id = $1")
                .bind(&item_404_id)
                .fetch_one(&pool)
                .await
                .unwrap();

        assert_eq!(status_404, "failed", "404 must fail immediately");
        assert_eq!(retry_count_404, 0, "Retry count must remain 0 for 404");
    }
}

/// Shared pending caps enforcement helper using a connection/pool.
pub async fn enforce_pending_caps_with_pool(
    pool: &PgPool,
    target_ds_did: &str,
    convo_id: &str,
    policy: &peer_policy::PeerPolicy,
    per_peer_pending_cap: i64,
    per_convo_peer_pending_cap: i64,
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
    let adaptive_peer_cap = ((per_peer_pending_cap as f64) * cap_ratio).floor().max(1.0) as i64;
    let adaptive_convo_peer_cap = ((per_convo_peer_pending_cap as f64) * cap_ratio)
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
    .fetch_one(pool)
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
            configured_cap = per_peer_pending_cap,
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
            configured_cap = per_convo_peer_pending_cap,
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
