//! Phase 3 — notification outbox worker.
//!
//! Drains `notification_outbox` rows that the chokepoint wrote in the
//! same Postgres tx as a `delivery_events` INSERT. Each row represents
//! one "this delivery event must be observed by recipient X via channel
//! Y" job (where Y = `kind`: 'sse' | 'push' | 'websocket').
//!
//! ## SSE durability contract (post codex P1 fix)
//!
//! The chokepoint
//! ([`crate::actors::reset_chokepoint::enqueue_outbox_for_event`])
//! writes THREE rows in the SAME Postgres tx as the originating
//! `delivery_events` INSERT:
//!
//!  1. one `notification_outbox` row per active member (this worker
//!     drains them — for `kind='sse'`, see below),
//!  2. zero or more `federation_outbox` rows for distinct peer DSes,
//!  3. **one `event_stream` row** carrying the full `StreamEvent` JSON
//!     and the canonical SSE cursor. This is the durability anchor for
//!     SSE clients: connected subscribers see it via the in-memory
//!     broadcast (cursor matches), reconnecting subscribers see it via
//!     cursor-replay through `subscribe_convo_events` /
//!     WebSocket backfill.
//!
//! Because (3) lands in the same tx as the `delivery_events` row, a
//! SIGKILL anywhere between commit and the live broadcast leaves the
//! `event_stream` row durable — reconnecting clients get the event via
//! cursor-replay. The `notification_outbox` row in (1) is now an
//! audit/observability artifact for the SSE channel; the worker's
//! `kind='sse'` dispatch is a true no-op-on-success because the
//! durability work happened in-tx upstream.
//!
//! ## Why we still write the `notification_outbox` row
//!
//! The row is the per-recipient observability artifact:
//!  - "did delivery event E reach recipient R via channel SSE?" is one
//!    row in the outbox, not a join through `event_stream`.
//!  - Future per-recipient retries (e.g. push, websocket) will share
//!    this surface; deleting the SSE row would force a schema split.
//!  - Ops queries tail the outbox to spot offline / lagging members
//!    without touching the noisier `event_stream` table.
//!
//! ## Push / websocket kinds
//!
//! Not wired in Phase 3 — the chokepoint never enqueues them. The
//! belt-and-suspenders guard below (`dispatch`) errs loudly if such a
//! row appears via legacy data or a future regression.

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
/// For `kind='sse'`: a no-op-on-success. The chokepoint
/// (`actors/reset_chokepoint.rs::enqueue_outbox_for_event`) wrote both
/// the `notification_outbox` row AND a matching `event_stream` row in
/// the SAME Postgres tx as the `delivery_events` INSERT. The
/// `event_stream` row is what reconnecting subscribers replay via
/// cursor (`subscribe_convo_events` / WS backfill), and live
/// subscribers see the same event via the in-memory broadcast emitted
/// post-commit using the SAME cursor. The `notification_outbox` row is
/// per-recipient observability — once we reach this dispatcher both
/// the durability anchor (event_stream) and any live broadcast have
/// already been served. Marking `done` is correct.
///
/// **Why this is not the bug Codex P1 flagged**: pre-fix, the
/// chokepoint only wrote the outbox row in-tx and the
/// `event_stream` write happened POST-commit alongside the live
/// broadcast. A SIGKILL between commit and post-commit work left the
/// outbox row claiming "pending"; this dispatcher then marked it
/// `done` without anything reaching `event_stream`, silently dropping
/// the message. The fix moved the `event_stream` write into the same
/// tx as the outbox row INSERT — see `enqueue_outbox_for_event` and
/// the `set_stream_event_cursor` path. Now this branch is a true
/// no-op-on-success because the durability work happened upstream.
///
/// For `kind='push'` / `kind='websocket'`: NOT supported. The chokepoint
/// (`actors/reset_chokepoint.rs::enqueue_outbox_for_event`) deliberately
/// only writes `kind='sse'` rows in Phase 3 — APNs/FCM and websocket
/// fanout are out of scope. This branch errs loudly to ensure that if
/// such a row appears via legacy data, manual INSERT, or a future
/// regression, the worker fails instead of silently marking it `done`.
/// Returning `Err` routes through `record_failure`, which logs a warning
/// per attempt and eventually transitions the row to `dead` — visible in
/// ops queries rather than a silent drop.
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
            // codex P1 fix: durability + live broadcast both happened
            // upstream in the chokepoint tx. This is a true no-op-on-
            // success — see fn doc-comment for the contract.
            Ok(())
        }
        "push" | "websocket" => {
            // Belt-and-suspenders: chokepoint never writes these in
            // Phase 3. If we see one, it's legacy/manual — fail loudly
            // rather than silently mark `done`. See chokepoint scope
            // comment for the rationale.
            anyhow::bail!(
                "notification kind '{}' is not wired (chokepoint should not be writing this); \
                 will not silently mark done — see actors/reset_chokepoint.rs \
                 enqueue_outbox_for_event scope comment",
                row.kind
            )
        }
        other => {
            anyhow::bail!("unknown notification kind: {other}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn fake_row(kind: &str) -> NotificationOutboxRow {
        NotificationOutboxRow {
            id: "row-1".to_string(),
            conversation_id: "convo-1".to_string(),
            delivery_event_id: "evt-1".to_string(),
            recipient_did: "did:plc:test".to_string(),
            recipient_device_id: None,
            kind: kind.to_string(),
            payload: Some(b"{}".to_vec()),
            attempts: 0,
            created_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn dispatch_sse_is_ok() {
        let row = fake_row("sse");
        let result = dispatch(&row).await;
        assert!(
            result.is_ok(),
            "sse kind should succeed (no-op-on-success): {result:?}"
        );
    }

    #[tokio::test]
    async fn dispatch_push_errors_loudly() {
        // Phase 3 contract: chokepoint never writes push rows; if one
        // appears (legacy data, manual INSERT), the worker MUST err
        // rather than silently mark `done`.
        let row = fake_row("push");
        let result = dispatch(&row).await;
        let err = result.expect_err("push kind must err — silent done is the bug we are fixing");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("not wired"),
            "error message should explain the kind isn't wired, got: {msg}"
        );
    }

    #[tokio::test]
    async fn dispatch_websocket_errors_loudly() {
        let row = fake_row("websocket");
        let result = dispatch(&row).await;
        let err =
            result.expect_err("websocket kind must err — silent done is the bug we are fixing");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("not wired"),
            "error message should explain the kind isn't wired, got: {msg}"
        );
    }

    #[tokio::test]
    async fn dispatch_unknown_kind_errors() {
        let row = fake_row("not-a-real-kind");
        let result = dispatch(&row).await;
        assert!(
            result.is_err(),
            "unknown kinds should err (forward-compat against schema drift)"
        );
    }
}
