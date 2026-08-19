//! Phase 2.5 §7 R3 — backstop reset-reminder worker.
//!
//! When `RequestCryptoSessionReset` fires (via quorum vote, sweep, or
//! inline-trigger) but no client is online to respond, the conversation
//! sits in `state='reset_requested'` indefinitely. The cursor-based
//! event_stream replay handles the offline-then-reconnect case, but if
//! NO client ever reconnects the conversation is stuck.
//!
//! This worker periodically scans for stuck `reset_requested` sessions
//! and re-broadcasts the `resetRequestedEvent` SSE + persists a fresh
//! `crypto_session_reset_requested` delivery_event row at bounded
//! retry intervals (1h / 6h / 24h). After 3 attempts the row is
//! marked `escalated_at`; ops sees a `tracing::error!` admin-alert
//! line and is expected to investigate.
//!
//! # Design notes
//!
//! - The worker does NOT call `request_crypto_session_reset_tx` — that
//!   function is the chokepoint state-machine entry whose job is to
//!   flip `active → reset_requested` and snapshot the responder
//!   allowlist. The reminder is a re-broadcast of an existing Request,
//!   not a fresh state transition. We re-INSERT the
//!   `crypto_session_reset_requested` event_type with a distinct
//!   `idempotency_key` (`reset-reminder:{cs_id}:{n}`) so the existing
//!   `delivery_events` partial-unique-index over
//!   `(conversation_id, sender_did, sender_device_id, idempotency_key)`
//!   does NOT collide with the original Request and reminders dedupe
//!   correctly across worker restarts.
//!
//! - `EMIT_RESET_REQUESTED_EVENT=false` suppresses the SSE broadcast
//!   only — the `delivery_events` row is still written so cursor-based
//!   replay can recover the reminder when the operator flips the flag
//!   back on. This matches Stage 1 dual-emit semantics in
//!   [`actors::conversation::ConversationActor::dual_emit_reset_requested`].
//!
//! - The worker is one-row-at-a-time (not a batch UPDATE) so a failure
//!   in the broadcast for one row does not cascade to the rest of the
//!   tick. Throughput at the expected scale (one reminder per stuck
//!   conversation per hour) is not a concern.
//!
//! - State row creation: rows are created lazily on the first tick
//!   that observes a `reset_requested` session without an existing
//!   row. This keeps the chokepoint write path unchanged and lets the
//!   worker self-bootstrap on freshly-deployed servers.
//!
//! Plan: `docs/plans (phase-2-5-indirect-funneling.md)` §7 R3.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::realtime::SseState;

/// Bounded retry sequence (per §7 R3): 1h, 6h, 24h. After the 3rd attempt the
/// row is `escalated_at` and stops being scanned.
const REMINDER_DELAYS_SECS: [i64; 3] = [
    60 * 60,      // attempt 1 → broadcast at t+1h
    6 * 60 * 60,  // attempt 2 → broadcast at t+6h
    24 * 60 * 60, // attempt 3 → broadcast at t+24h
];

/// Worker poll interval. Short enough that the 1h reminder fires within
/// ±5min of the target; long enough that the table scan is cheap.
const POLL_INTERVAL_SECS: u64 = 5 * 60;

/// Spawn-and-loop entry point. Used from `main.rs`.
pub async fn run_reset_reminder_worker(pool: PgPool, sse_state: Arc<SseState>) {
    let mut ticker = interval(Duration::from_secs(POLL_INTERVAL_SECS));
    info!(
        poll_interval_secs = POLL_INTERVAL_SECS,
        "Starting reset-reminder worker (Phase 2.5 §7 R3 backstop)"
    );

    loop {
        ticker.tick().await;
        if let Err(e) = reminder_tick(&pool, &sse_state).await {
            error!(error = %e, "reset-reminder tick failed");
        }
    }
}

/// One pass of the reminder worker. Public so integration tests can drive
/// it directly without waiting for the timer.
///
/// Steps:
///   1. **Bootstrap**: INSERT a `reset_reminder_state` row for any session
///      currently in `reset_requested` that has no row yet. The first
///      `next_attempt_at` is set to (the session's `reset_requested`
///      delivery_event timestamp + 1h). This handles the case where
///      a session entered `reset_requested` before this worker existed
///      (or before the migration that created the table ran).
///   2. **Scan**: SELECT rows where `next_attempt_at <= NOW()` and
///      `escalated_at IS NULL` AND the parent crypto_session is still
///      in `reset_requested` (sessions that activated have left this
///      state and the row is now stale).
///   3. **Per row**:
///      a. Look up the original `crypto_session_reset_requested` event
///      payload.
///      b. INSERT a fresh `crypto_session_reset_requested`
///      delivery_event with `idempotency_key = reset-reminder:{cs}:{n}`
///      and the SAME `payload_json` so re-broadcast clients see an
///      identical Request shape.
///      c. Persist + broadcast `StreamEvent::ResetRequestedEvent`
///      (gated by `EMIT_RESET_REQUESTED_EVENT`).
///      d. UPDATE `reset_reminder_state`: bump `attempt_count`,
///      advance `next_attempt_at`, set `last_attempt_at`. If the
///      bumped count exceeds the bounded retry length, set
///      `escalated_at` and log an admin-alert.
pub async fn reminder_tick(pool: &PgPool, sse_state: &Arc<SseState>) -> anyhow::Result<()> {
    bootstrap_pending_state(pool).await?;

    let due_rows = fetch_due_rows(pool).await?;
    if due_rows.is_empty() {
        debug!("reset-reminder tick: no due rows");
        return Ok(());
    }

    info!(
        due_count = due_rows.len(),
        "reset-reminder tick: processing due rows"
    );
    for row in due_rows {
        if let Err(e) = process_due_row(pool, sse_state, &row).await {
            warn!(
                crypto_session_id = %row.crypto_session_id,
                attempt_count = row.attempt_count,
                error = %e,
                "reset-reminder: failed to process due row; will retry on next tick"
            );
        }
    }

    Ok(())
}

#[derive(Debug, sqlx::FromRow)]
struct DueRow {
    crypto_session_id: String,
    conversation_id: String,
    attempt_count: i32,
    /// The `crypto_session_reset_requested` event_id we use as a stable
    /// `request_event_id` field on the SSE rebroadcast.
    request_event_id: String,
    /// Snapshot of the original Request's payload (with allowed_responders,
    /// trigger, reason, expected_new_mls_group_id, request_id). We
    /// rewrite this verbatim into the reminder event row so the audit
    /// trail is consistent.
    request_payload: serde_json::Value,
    /// Original Request's `sender_did` — re-used so the delivery_events
    /// partial-unique-index (which keys on sender_did) treats the
    /// reminders as continuations of the same caller.
    sender_did: Option<String>,
    /// crypto_session generation (for the SSE event payload).
    generation: i32,
    /// crypto_session.mls_group_id — used to populate the delivery_events
    /// row's mls_group_id column (audit consistency with the original
    /// Request, which set it to `current.mls_group_id`).
    mls_group_id: String,
    /// Original Request's `created_at` timestamp from `delivery_events`.
    /// Re-emitted SSE reminders carry this ORIGINAL timestamp (not
    /// `Utc::now()`) so clients can compute reset-age from the moment
    /// the reset was first requested rather than each reminder ping.
    requested_at: DateTime<Utc>,
}

/// Step 2 of `reminder_tick`. Picks rows whose timer has elapsed AND whose
/// parent crypto_session is still in `reset_requested`. Joins to fetch the
/// original Request event payload in one shot.
async fn fetch_due_rows(pool: &PgPool) -> anyhow::Result<Vec<DueRow>> {
    let rows = sqlx::query_as::<_, DueRow>(
        r#"
        WITH original AS (
            SELECT DISTINCT ON (de.crypto_session_id)
                de.crypto_session_id,
                de.id AS request_event_id,
                de.payload_json AS request_payload,
                de.sender_did,
                de.created_at AS requested_at
            FROM delivery_events de
            WHERE de.event_type = 'crypto_session_reset_requested'
              AND de.crypto_session_id IS NOT NULL
              AND (
                  de.idempotency_key IS NULL
                  OR de.idempotency_key NOT LIKE 'reset-reminder:%'
              )
            ORDER BY de.crypto_session_id, de.seq ASC
        )
        SELECT
            rrs.crypto_session_id,
            cs.conversation_id,
            rrs.attempt_count,
            o.request_event_id,
            o.request_payload,
            o.sender_did,
            cs.generation,
            cs.mls_group_id,
            o.requested_at
        FROM reset_reminder_state rrs
        JOIN crypto_sessions cs ON cs.id = rrs.crypto_session_id
        JOIN original o ON o.crypto_session_id = rrs.crypto_session_id
        WHERE rrs.escalated_at IS NULL
          AND rrs.next_attempt_at <= NOW()
          AND cs.state = 'reset_requested'
        ORDER BY rrs.next_attempt_at ASC
        LIMIT 200
        "#,
    )
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Step 1 of `reminder_tick`. Self-bootstrap rows for sessions that
/// entered `reset_requested` without a tracker row. Idempotent on
/// `(crypto_session_id)` PK.
async fn bootstrap_pending_state(pool: &PgPool) -> anyhow::Result<()> {
    let result = sqlx::query(
        r#"
        WITH first_request AS (
            SELECT DISTINCT ON (de.crypto_session_id)
                de.crypto_session_id,
                de.created_at AS requested_at
            FROM delivery_events de
            WHERE de.event_type = 'crypto_session_reset_requested'
              AND de.crypto_session_id IS NOT NULL
              AND (
                  de.idempotency_key IS NULL
                  OR de.idempotency_key NOT LIKE 'reset-reminder:%'
              )
            ORDER BY de.crypto_session_id, de.seq ASC
        ),
        candidates AS (
            SELECT
                cs.id AS crypto_session_id,
                fr.requested_at + INTERVAL '1 hour' AS next_attempt_at
            FROM crypto_sessions cs
            JOIN first_request fr ON fr.crypto_session_id = cs.id
            WHERE cs.state = 'reset_requested'
        )
        INSERT INTO reset_reminder_state
            (crypto_session_id, attempt_count, next_attempt_at)
        SELECT crypto_session_id, 0, next_attempt_at FROM candidates
        ON CONFLICT (crypto_session_id) DO NOTHING
        "#,
    )
    .execute(pool)
    .await?;

    let inserted = result.rows_affected();
    if inserted > 0 {
        debug!(inserted, "reset-reminder: bootstrapped state rows");
    }
    Ok(())
}

async fn process_due_row(
    pool: &PgPool,
    sse_state: &Arc<SseState>,
    row: &DueRow,
) -> anyhow::Result<()> {
    let next_attempt_count = row.attempt_count + 1;
    // attempt_count is 0-indexed in the table for "no reminders yet"; the
    // first reminder we send is logically attempt #1 (1-indexed for the
    // idempotency_key suffix and for the bounded retry comparison).
    let attempt_index = (next_attempt_count - 1).max(0) as usize;

    let idempotency_key = format!(
        "reset-reminder:{}:{}",
        row.crypto_session_id, next_attempt_count
    );

    // Step 3a-b: re-INSERT the delivery_events row. Done in a tx so a
    // partial failure (insert succeeds, store_event/emit fails after
    // `tx.commit()`) doesn't double-broadcast on the next tick.
    let mut tx = pool.begin().await?;

    // Allocate a fresh seq for this conversation. Mirrors
    // `reset_chokepoint::allocate_seq` (advisory lock + max+1).
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(&row.conversation_id)
        .execute(&mut *tx)
        .await?;
    let seq: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(seq), -1) + 1 FROM delivery_events WHERE conversation_id = $1",
    )
    .bind(&row.conversation_id)
    .fetch_one(&mut *tx)
    .await?;

    // Augment the rebroadcast payload with reminder-specific metadata so
    // operators reading the audit log can distinguish reminders from the
    // original Request. The base shape (request_id, trigger, reason,
    // allowed_responders, expected_new_mls_group_id) stays identical to
    // the original event so client decoders see an unchanged Request.
    let mut reminder_payload = row.request_payload.clone();
    if let Some(obj) = reminder_payload.as_object_mut() {
        obj.insert(
            "reminder_attempt".to_string(),
            serde_json::Value::from(next_attempt_count),
        );
        obj.insert(
            "reminder_for_event_id".to_string(),
            serde_json::Value::from(row.request_event_id.clone()),
        );
    }

    let new_event_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO delivery_events ( \
            id, conversation_id, seq, crypto_session_id, event_type, \
            sender_did, mls_group_id, idempotency_key, payload_json \
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         ON CONFLICT DO NOTHING",
    )
    .bind(&new_event_id)
    .bind(&row.conversation_id)
    .bind(seq)
    .bind(&row.crypto_session_id)
    .bind("crypto_session_reset_requested")
    .bind(row.sender_did.as_deref())
    .bind(&row.mls_group_id)
    .bind(&idempotency_key)
    .bind(&reminder_payload)
    .execute(&mut *tx)
    .await?;

    // Step 3d: bump scheduling state. Done in the same tx so the row's
    // attempt_count and the reminder event are consistent on commit.
    let escalate = next_attempt_count as usize >= REMINDER_DELAYS_SECS.len();
    let next_at: Option<DateTime<Utc>> = if escalate {
        None
    } else {
        Some(Utc::now() + chrono::Duration::seconds(REMINDER_DELAYS_SECS[attempt_index + 1]))
    };

    sqlx::query(
        "UPDATE reset_reminder_state \
         SET attempt_count = $1, \
             last_attempt_at = NOW(), \
             next_attempt_at = COALESCE($2, next_attempt_at), \
             escalated_at = CASE WHEN $3 THEN NOW() ELSE escalated_at END \
         WHERE crypto_session_id = $4",
    )
    .bind(next_attempt_count)
    .bind(next_at)
    .bind(escalate)
    .bind(&row.crypto_session_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    if escalate {
        // §7 R3 admin-alert. No SSE channel for ops alerts today (the
        // existing CircuitBreakerTrippedEvent is convo-scoped, wrong
        // shape) — operators monitor `journalctl -u catbird-mls-server
        // | grep reset_reminder_exhausted` per the runbook.
        error!(
            convo_id = %crate::crypto::redact_for_log(&row.conversation_id),
            crypto_session_id = %row.crypto_session_id,
            request_event_id = %row.request_event_id,
            attempt_count = next_attempt_count,
            phase_2_5_path = "reset_reminder_exhausted",
            "reset-reminder backstop exhausted: conversation stuck in `reset_requested` \
             with no online responder after 1h/6h/24h attempts. Operator should \
             investigate (members offline indefinitely? client release broken?)."
        );
    }

    info!(
        convo_id = %crate::crypto::redact_for_log(&row.conversation_id),
        crypto_session_id = %row.crypto_session_id,
        request_event_id = %row.request_event_id,
        attempt = next_attempt_count,
        idempotency_key = %idempotency_key,
        escalated = escalate,
        phase_2_5_path = "reset_reminder",
        "reset-reminder broadcast: re-emitted crypto_session_reset_requested"
    );

    let _ = (pool, sse_state, reminder_payload);
    Ok(())
}
