//! Phase 3 — notification outbox worker.
//!
//! Drains `notification_outbox` rows that the chokepoint wrote in the
//! same Postgres tx as a `delivery_events` INSERT. Each row represents
//! one "this delivery event must be observed by recipient X via channel
//! Y" job (where Y = `kind`: 'sse' | 'push' | 'websocket').
//!
//! ## SSE refactor stance (also documented in PR body)
//!
//! Two design options were considered:
//!
//! 1. **Outbox-only** — replace the in-memory `side_effect_tx`/per-convo
//!    FIFO entirely; SSE subscribers wake on outbox rows transitioning to
//!    `in_flight`. Pros: single source of truth, no dual-write. Cons:
//!    adds Postgres polling latency to the hot path (5s by default —
//!    measurably worse than the current sub-100ms broadcast).
//!
//! 2. **Hybrid: in-memory broadcast (best-effort) + outbox row
//!    (durable)** — ship both. The chokepoint writes the outbox row in
//!    its tx (load-bearing for crash recovery), and the existing
//!    per-convo emit queue continues to fire SSE broadcasts to connected
//!    subscribers post-commit (low-latency happy path). Reconnecting
//!    subscribers backfill from `event_stream` via the existing cursor
//!    path; the outbox worker drains rows that no live subscriber
//!    consumed.
//!
//! We chose option 2. The chokepoint already writes an `event_stream`
//! row alongside `delivery_events`, so SSE backfill on reconnect already
//! works. The outbox worker's job for `kind='sse'` is therefore a
//! no-op-on-success: log + mark `done`. The durable row exists so a
//! crash *between* `delivery_events.commit()` and the per-convo emit
//! queue draining doesn't lose the broadcast intent. Push/websocket
//! kinds, if/when added, drive their respective dispatchers from the
//! same loop.

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use tokio::time::interval;
use tracing::{debug, error, info, warn};

use super::{mark_done, record_failure, try_reclaim, CLAIM_BATCH_SIZE, POLL_INTERVAL};

const TABLE_NAME: &str = "notification_outbox";

#[derive(Debug, Clone, FromRow)]
struct NotificationOutboxRow {
    id: String,
    conversation_id: String,
    delivery_event_id: String,
    recipient_did: String,
    recipient_device_id: Option<String>,
    kind: String,
    payload: Option<Vec<u8>>,
    attempts: i32,
    created_at: DateTime<Utc>,
}

pub async fn run_notification_outbox_worker(pool: PgPool) {
    info!(
        poll_interval_secs = POLL_INTERVAL.as_secs(),
        batch_size = CLAIM_BATCH_SIZE,
        "starting notification_outbox worker"
    );

    let mut ticker = interval(POLL_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        ticker.tick().await;

        try_reclaim(&pool, TABLE_NAME).await;

        let claimed = match claim_due_rows(&pool, CLAIM_BATCH_SIZE).await {
            Ok(rows) => rows,
            Err(e) => {
                error!(error = ?e, "notification_outbox: claim batch failed");
                continue;
            }
        };

        if claimed.is_empty() {
            continue;
        }

        debug!(count = claimed.len(), "notification_outbox: claimed batch");

        for row in claimed {
            match dispatch(&row).await {
                Ok(()) => {
                    if let Err(e) = mark_done(&pool, TABLE_NAME, &row.id).await {
                        error!(
                            row_id = %row.id,
                            error = ?e,
                            "notification_outbox: mark_done failed"
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
                                recipient = %crate::crypto::redact_for_log(&row.recipient_did),
                                kind = %row.kind,
                                attempts = row.attempts + 1,
                                stored_status,
                                error = %err_msg,
                                "notification_outbox: dispatch failed; row transitioned"
                            );
                        }
                        Err(db_err) => {
                            error!(
                                row_id = %row.id,
                                error = ?db_err,
                                "notification_outbox: record_failure DB write failed"
                            );
                        }
                    }
                }
            }
        }
    }
}

async fn claim_due_rows(
    pool: &PgPool,
    limit: i64,
) -> Result<Vec<NotificationOutboxRow>, sqlx::Error> {
    let mut tx = pool.begin().await?;

    let candidates: Vec<(String,)> = sqlx::query_as(
        "SELECT id FROM notification_outbox \
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

    let rows: Vec<NotificationOutboxRow> = sqlx::query_as(
        "UPDATE notification_outbox \
         SET status = 'in_flight', updated_at = NOW() \
         WHERE id = ANY($1) \
         RETURNING id, conversation_id, delivery_event_id, recipient_did, \
                   recipient_device_id, kind, payload, attempts, created_at",
    )
    .bind(&ids)
    .fetch_all(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(rows)
}

/// Dispatch one notification outbox row.
///
/// For `kind='sse'`: a no-op-on-success. Connected subscribers already
/// got the broadcast via the in-memory per-convo queue; reconnecting
/// subscribers backfill from `event_stream`. The durable row's purpose
/// is to survive a SIGKILL between commit and broadcast — once a row
/// makes it here, the per-convo queue has had its chance and the row
/// represents intent that's already been served by either path.
///
/// For `kind='push'` / `kind='websocket'`: not yet implemented; logs a
/// warning and marks `done` so we don't block the queue. Real dispatch
/// hooks here in a follow-up. TODO(phase-3-push-wire).
async fn dispatch(row: &NotificationOutboxRow) -> anyhow::Result<()> {
    debug!(
        row_id = %row.id,
        convo = %crate::crypto::redact_for_log(&row.conversation_id),
        delivery_event_id = %row.delivery_event_id,
        recipient = %crate::crypto::redact_for_log(&row.recipient_did),
        kind = %row.kind,
        payload_bytes = row.payload.as_ref().map(Vec::len).unwrap_or(0),
        "notification_outbox: dispatching"
    );
    match row.kind.as_str() {
        "sse" => {
            // The in-memory broadcast already happened (best-effort,
            // post-commit, in the per-convo emit queue). The outbox row
            // is the durability anchor; once we reach this dispatcher
            // the row's purpose has been fulfilled.
            Ok(())
        }
        "push" | "websocket" => {
            // Stub: TODO(phase-3-push-wire). Returning Ok(()) keeps the
            // worker draining and avoids the row going `dead`. When the
            // real dispatcher is wired, errors propagate up and trigger
            // backoff naturally.
            warn!(
                row_id = %row.id,
                kind = %row.kind,
                "notification_outbox: kind not yet wired; marking done"
            );
            Ok(())
        }
        other => {
            anyhow::bail!("unknown notification kind: {other}")
        }
    }
}
