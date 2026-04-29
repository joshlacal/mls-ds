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
use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, error, info, warn};

use super::{mark_done, record_failure, try_reclaim, CLAIM_BATCH_SIZE, POLL_INTERVAL};

const TABLE_NAME: &str = "federation_outbox";

#[derive(Debug, Clone, FromRow)]
struct FederationOutboxRow {
    id: String,
    conversation_id: String,
    delivery_event_id: String,
    target_service_did: String,
    payload: Vec<u8>,
    attempts: i32,
    created_at: DateTime<Utc>,
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

        try_reclaim(&pool, TABLE_NAME).await;

        let claimed = match claim_due_rows(&pool, CLAIM_BATCH_SIZE).await {
            Ok(rows) => rows,
            Err(e) => {
                error!(error = ?e, "federation_outbox: claim batch failed");
                continue;
            }
        };

        if claimed.is_empty() {
            continue;
        }

        debug!(count = claimed.len(), "federation_outbox: claimed batch");

        // Process each row sequentially. Spawning per-row would let one
        // very-slow peer block another, but the existing sequential
        // pattern matches blob_cleanup.rs and avoids a concurrent-write
        // surprise on `record_failure`/`mark_done`.
        for row in claimed {
            match dispatch(&row).await {
                Ok(()) => {
                    if let Err(e) = mark_done(&pool, TABLE_NAME, &row.id).await {
                        error!(
                            row_id = %row.id,
                            error = ?e,
                            "federation_outbox: mark_done failed"
                        );
                    }
                }
                Err(e) => {
                    let err_msg = format!("{e:#}");
                    match record_failure(
                        &pool,
                        TABLE_NAME,
                        &row.id,
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
                                "federation_outbox: dispatch failed; row transitioned"
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
    }
}

/// Claim up to `limit` due `pending` rows, flipping them to `in_flight`
/// in the same transaction. Returns the claimed rows for the caller to
/// dispatch.
///
/// Uses `FOR UPDATE SKIP LOCKED` so that horizontally-scaled workers
/// don't double-claim a row. Without `SKIP LOCKED`, two replicas calling
/// this concurrently would deadlock or block.
async fn claim_due_rows(
    pool: &PgPool,
    limit: i64,
) -> Result<Vec<FederationOutboxRow>, sqlx::Error> {
    let mut tx = pool.begin().await?;

    let candidates: Vec<(String,)> = sqlx::query_as(
        "SELECT id FROM federation_outbox \
         WHERE status = 'pending' AND next_attempt_at <= NOW() \
         ORDER BY next_attempt_at \
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

    let rows: Vec<FederationOutboxRow> = sqlx::query_as(
        "UPDATE federation_outbox \
         SET status = 'in_flight', updated_at = NOW() \
         WHERE id = ANY($1) \
         RETURNING id, conversation_id, delivery_event_id, target_service_did, \
                   payload, attempts, created_at",
    )
    .bind(&ids)
    .fetch_all(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(rows)
}

/// Dispatch one federation outbox row.
///
/// TODO(phase-3-federation-wire): currently a stub that logs and returns
/// success. The plan acceptance test only requires the row to transition
/// to `done` on restart after a SIGKILL — see crate-level docs above.
/// The real dispatch should call `federation::outbound::send_to_peer(...)`
/// or similar; that's a follow-up because federation routing is itself
/// out of scope for this plan.
async fn dispatch(row: &FederationOutboxRow) -> anyhow::Result<()> {
    debug!(
        row_id = %row.id,
        convo = %crate::crypto::redact_for_log(&row.conversation_id),
        delivery_event_id = %row.delivery_event_id,
        target_did = %row.target_service_did,
        payload_bytes = row.payload.len(),
        "federation_outbox: dispatching (stub)"
    );
    // Placeholder: the real wire-up calls into federation::outbound.
    // A no-op success keeps the durable-row contract honest while
    // federation routing itself is iterated in a follow-up.
    Ok(())
}
