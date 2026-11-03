//! Phase 3 — federation outbox worker.
//!
//! Drains `federation_outbox` rows that the chokepoint wrote in the same
//! Postgres tx as a `delivery_events` INSERT. Each row represents one
//! "this delivery event must be replayed to peer DS X" job.
//!
//! Federation in this plan is intentionally limited: this plan does NOT
//! redesign federated routing or remote sequencer ownership (see
//! locked-decision #2 in `docs/plans (let-me-look-at-abstract-castle.md)`).
//! We persist the rows so the outbox is the durable source of truth, and
//! ship a placeholder dispatcher that logs + marks `done`. Hooking the
//! dispatcher to the existing `federation/outbound.rs` queue is a
//! follow-up — the chokepoint contract is unchanged.
//!
//! ## Why a stub dispatcher
//!
//! The plan acceptance test only requires:
//! "SIGKILL after `delivery_event` commits but before fanout — outbox
//! worker completes the fanout on restart."
//!
//! That test is satisfied by the *worker* completing the row, not by the
//! row reaching a real federation peer. The actual peer dispatch already
//! has its own queue (`federation::outbound::OutboundQueue`); wiring the
//! outbox to that queue is straightforward but out of scope here. We
//! mark the dispatch path with TODO(phase-3-federation-wire) so it shows
//! up in `git grep`.

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use tokio::time::interval;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use super::{
    cleanup_dead_rows, record_failure, try_reclaim, CLAIM_BATCH_SIZE, DEAD_ROWS_MAX_AGE,
    POLL_INTERVAL,
};
use crate::identity::canonical_did;
const TABLE_NAME: &str = "federation_outbox";

#[derive(Debug, Clone, FromRow)]
pub struct FederationOutboxRow {
    pub id: String,
    pub conversation_id: String,
    pub delivery_event_id: Option<String>,
    pub target_service_did: String,
    pub method: String,
    pub payload: Vec<u8>,
    pub payload_sha256: Option<Vec<u8>>,
    pub envelope_version: i32,
    pub attempts: i32,
    pub created_at: DateTime<Utc>,
    pub claim_token: Option<Uuid>,
}
/// Worker entry point. Spawned at server startup from `main.rs`.
///
/// Loops every [`POLL_INTERVAL`] seconds:
/// 1. Reclaim stuck `in_flight` rows (post-crash recovery).
/// 2. Claim up to [`CLAIM_BATCH_SIZE`] due `pending` rows in a single tx
///    (`FOR UPDATE SKIP LOCKED`), flipping them to `in_flight`.
/// 3. Dispatch each claimed row.
/// 4. On success: `mark_done`. On failure: `record_failure` (which
///    transitions to `pending` with backoff or `dead` if exhausted).
pub async fn run_federation_outbox_worker(pool: PgPool) {
    info!(
        poll_interval_secs = POLL_INTERVAL.as_secs(),
        batch_size = CLAIM_BATCH_SIZE,
        "starting federation_outbox worker"
    );

    let mut ticker = interval(POLL_INTERVAL);
    // Drift over time is fine here — we're rate-limiting Postgres polls,
    // not enforcing a deadline.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        ticker.tick().await;
        if let Err(e) = process_federation_outbox_tick(&pool, CLAIM_BATCH_SIZE).await {
            error!(error = ?e, "federation_outbox: claim batch failed");
        }
    }
}

/// Execute one production `federation_outbox` handoff iteration:
/// reclaim stuck `in_flight` leases, purge expired `dead` rows, claim up to `limit`
/// due `pending` rows, and atomically hand each row off to `outbound_queue` (or
/// record retry backoff / `dead` on failure).
pub async fn process_federation_outbox_tick(
    pool: &PgPool,
    limit: i64,
) -> Result<usize, sqlx::Error> {
    try_reclaim(pool, TABLE_NAME).await;
    let _ = cleanup_dead_rows(pool, TABLE_NAME, DEAD_ROWS_MAX_AGE).await;
    let claimed = claim_due_rows(pool, limit).await?;
    if claimed.is_empty() {
        return Ok(0);
    }

    debug!(count = claimed.len(), "federation_outbox: claimed batch");
    let count = claimed.len();

    for row in claimed {
        match handoff_to_outbound_queue(pool, &row).await {
            Ok(()) => {
                debug!(
                    row_id = %row.id,
                    target_did = %row.target_service_did,
                    method = %row.method,
                    "federation_outbox: atomic handoff completed, source marked done"
                );
            }
            Err(e) => {
                let err_msg = format!("{e:#}");
                match record_failure(
                    pool,
                    TABLE_NAME,
                    &row.id,
                    row.claim_token,
                    row.attempts,
                    row.created_at,
                    &err_msg,
                )
                .await
                {
                    Ok(stored_status) => {
                        warn!(
                            row_id = %row.id,
                            target_did = %row.target_service_did,
                            attempts = row.attempts + 1,
                            stored_status,
                            error = %err_msg,
                            "federation_outbox: handoff failed; row transitioned"
                        );
                    }
                    Err(db_err) => {
                        error!(
                            row_id = %row.id,
                            error = ?db_err,
                            "federation_outbox: record_failure DB write failed"
                        );
                    }
                }
            }
        }
    }
    Ok(count)
}

/// Claim up to `limit` due `pending` rows, flipping them to `in_flight`
/// in the same transaction. Returns the claimed rows for the caller to
/// dispatch.
///
/// Uses `FOR UPDATE SKIP LOCKED` so that horizontally-scaled workers
/// don't double-claim a row. Without `SKIP LOCKED`, two replicas calling
/// this concurrently would deadlock or block.
pub async fn claim_due_rows(
    pool: &PgPool,
    limit: i64,
) -> Result<Vec<FederationOutboxRow>, sqlx::Error> {
    let now = crate::sim_hooks::current_utc();
    let mut tx = pool.begin().await?;

    let candidates: Vec<(String,)> = sqlx::query_as(
        "SELECT id FROM federation_outbox \
         WHERE status = 'pending' AND next_attempt_at <= $2 \
         ORDER BY next_attempt_at, id \
         LIMIT $1 \
         FOR UPDATE SKIP LOCKED",
    )
    .bind(limit)
    .bind(now)
    .fetch_all(&mut *tx)
    .await?;

    if candidates.is_empty() {
        tx.commit().await?;
        return Ok(Vec::new());
    }

    let ids: Vec<String> = candidates.into_iter().map(|(id,)| id).collect();
    let claim_token =
        crate::sim_hooks::mint_entry_uuid_v4(b"federation_outbox.claim", &[ids[0].as_bytes()]);

    let rows: Vec<FederationOutboxRow> = sqlx::query_as(
        "UPDATE federation_outbox \
         SET status = 'in_flight', \
             claim_token = $2, \
             claim_expires_at = $4 + make_interval(secs => $3), \
             updated_at = $4 \
         WHERE id = ANY($1) \
         RETURNING id, conversation_id, delivery_event_id, target_service_did, \
                   method, payload, payload_sha256, envelope_version, \
                   attempts, created_at, claim_token",
    )
    .bind(&ids)
    .bind(claim_token)
    .bind(super::IN_FLIGHT_VISIBILITY_TIMEOUT.as_secs() as f64)
    .bind(now)
    .fetch_all(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(rows)
}

/// Atomically hand off one federation outbox row to `outbound_queue` and mark the source row `done`.
pub async fn handoff_to_outbound_queue(
    pool: &PgPool,
    row: &FederationOutboxRow,
) -> Result<(), sqlx::Error> {
    let now = crate::sim_hooks::current_utc();
    let mut tx = pool.begin().await?;

    // 1. Replay check before caps: if outbound_queue already contains this stable ID,
    //    skip insertion and mark source done immediately.
    let already_enqueued: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM outbound_queue WHERE id = $1)")
            .bind(&row.id)
            .fetch_one(&mut *tx)
            .await?;

    if !already_enqueued {
        let canonical_target_ds_did = canonical_did(&row.target_service_did).to_string();
        let policy = crate::federation::peer_policy::enforce_outbound_peer_policy_tx(
            &mut tx,
            &canonical_target_ds_did,
        )
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;

        let (per_peer_cap, per_convo_cap) =
            crate::federation::queue::current_pending_caps_from_env();
        crate::federation::queue::enforce_pending_caps_with_executor(
            &mut *tx,
            &canonical_target_ds_did,
            &row.conversation_id,
            &policy,
            per_peer_cap,
            per_convo_cap,
        )
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;

        sqlx::query(
            "INSERT INTO outbound_queue \
               (id, target_ds_did, target_endpoint, method, payload, convo_id, payload_sha256, envelope_version, status, next_retry_at, retry_count, max_retries, created_at) \
             VALUES ($1, $2, '', $3, $4, $5, $6, $7, 'pending', $8, 0, 5, $8) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&row.id)
        .bind(&canonical_target_ds_did)
        .bind(&row.method)
        .bind(&row.payload)
        .bind(&row.conversation_id)
        .bind(&row.payload_sha256)
        .bind(row.envelope_version)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    }
    // 2. Mark source federation_outbox row as 'done' in the SAME transaction!
    let updated = sqlx::query(
        "UPDATE federation_outbox \
         SET status = 'done', updated_at = $3, last_error = NULL \
         WHERE id = $1 AND ($2::uuid IS NULL OR claim_token = $2)",
    )
    .bind(&row.id)
    .bind(row.claim_token)
    .bind(now)
    .execute(&mut *tx)
    .await?;

    if updated.rows_affected() == 0 {
        return Err(sqlx::Error::RowNotFound);
    }

    tx.commit().await?;
    Ok(())
}

/// Execute a single bounded federation outbox + outbound queue dispatch step
/// for one DS under the caller's active `scope_ds_clock` and `scope_sim_ds`.
///
/// Reuses the exact production `process_federation_outbox_tick` handoff and
/// `OutboundQueue::process_pending_batch` signed `OutboundClient` dispatch
/// (including `deliverWelcome`, `deliverMessage`, `deliverDirectRequest`,
/// `deliverAcceptanceEntry`, `deliverMessageEntry`, receipt verification, and
/// retry backoff). Reconciliation runs on the production interval of DS-clock time.
#[cfg(feature = "sim")]
pub async fn step_federation_outbox(
    pool: &PgPool,
    queue: &crate::federation::queue::OutboundQueue,
    outbound: &crate::federation::outbound::OutboundClient,
    service_auth: &crate::federation::ServiceAuthClient,
) -> Result<usize, String> {
    // Paused sim time must not advance pool timers while sqlx releases the
    // single connection through real PostgreSQL I/O.
    crate::sim_hooks::drive_sim_io(async {
        let handed_off = process_federation_outbox_tick(pool, CLAIM_BATCH_SIZE)
            .await
            .map_err(|e| format!("federation_outbox tick failed: {e}"))?;
        let auth_sign = |target_did: &str, method: &str| {
            service_auth
                .sign_request(target_did, method)
                .map_err(|e| e.to_string())
        };
        let dispatched = queue
            .process_pending_batch(outbound, &auth_sign)
            .await
            .map_err(|e| format!("outbound_queue batch failed: {e}"))?;
        let interval = chrono::Duration::seconds(
            crate::federation::reconciliation::reconciliation_interval_secs() as i64,
        );
        if queue.claim_sim_reconciliation(crate::sim_hooks::current_utc(), interval) {
            let _ = crate::federation::reconciliation::run_reconciliation_once_for_sim(
                pool,
                queue.resolver(),
                outbound,
                &auth_sign,
                service_auth.self_did(),
            )
            .await;
        }
        Ok::<_, String>(handed_off.saturating_add(dispatched))
    })
    .await
}

/// Bounded, deterministic drain of due `federation_outbox` + `outbound_queue`
/// items for one DS under the caller's active `scope_ds_clock` and `scope_sim_ds`.
/// Never spins forever: runs at most `max_rounds` iterations and stops early once
/// neither `federation_outbox` nor `outbound_queue` claims any due item.
#[cfg(feature = "sim")]
pub async fn drain_federation_outbox(
    pool: &PgPool,
    queue: &crate::federation::queue::OutboundQueue,
    outbound: &crate::federation::outbound::OutboundClient,
    service_auth: &crate::federation::ServiceAuthClient,
    max_rounds: usize,
) -> Result<usize, String> {
    let mut total = 0_usize;
    for _ in 0..max_rounds {
        let progressed = step_federation_outbox(pool, queue, outbound, service_auth).await?;
        total = total.saturating_add(progressed);
        if progressed == 0 {
            break;
        }
    }
    Ok(total)
}
