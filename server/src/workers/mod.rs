//! Phase 3 — durable outbox workers.
//!
//! These workers drain `federation_outbox` and `notification_outbox` rows
//! that were written in the SAME Postgres transaction as their originating
//! `delivery_events` INSERT (in
//! `actors/reset_chokepoint.rs::{request_crypto_session_reset_tx,
//! activate_crypto_session_tx}`). The chokepoint hands fanout off as
//! durable rows; the workers below are responsible for actually
//! dispatching them.
//!
//! Why durable rows: the prior in-memory `side_effect_tx` channel
//! (`actors/conversation.rs:405`) was lost on SIGKILL between commit and
//! broadcast send. Phase 3 §"Acceptance" spec: "SIGKILL after
//! `delivery_event` commits but before fanout — outbox worker completes
//! the fanout on restart."
//!
//! Worker behavior is identical across both kinds:
//!  - Poll every 5 seconds for `WHERE status='pending' AND next_attempt_at
//!    <= NOW()` ordered by `next_attempt_at`, with `LIMIT 100` and
//!    `FOR UPDATE SKIP LOCKED`.
//!  - Mark `status='in_flight'`, dispatch, transition to
//!    `done | failed | dead`.
//!  - Exponential backoff: `next_attempt_at = NOW() + 2^attempts *
//!    BASE_INTERVAL`, capped at 1h.
//!  - After 10 failures OR 24h elapsed since `created_at`: `status='dead'`.
//!
//! `FOR UPDATE SKIP LOCKED` lets multiple replicas run the same worker
//! pool without double-dispatch. The transactional claim flips
//! `status='in_flight'` before the row is released, so a crash mid-tick
//! leaves the row recoverable on restart (a follow-up tick that finds an
//! `in_flight` row older than the visibility timeout reverts it to
//! `pending` — see [`reclaim_stuck_in_flight`]).

pub mod federation_outbox;
pub mod notification_outbox;

pub use federation_outbox::run_federation_outbox_worker;
pub use notification_outbox::run_notification_outbox_worker;

use sqlx::PgPool;
use std::time::Duration;
use tracing::{error, info};
use uuid::Uuid;
/// Worker poll interval. Tuned for "low-latency notifications" — most rows
/// will be dispatched on the first tick because the chokepoint commits
/// ~immediately before the worker wakes. Increase if Postgres load is the
/// bottleneck (each tick costs 1 SELECT + N UPDATEs in worst case).
pub const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Base for exponential backoff. With `MAX_ATTEMPTS=10`, the curve is:
///  attempt 1: +5s
///  attempt 2: +10s
///  attempt 3: +20s
///  attempt 4: +40s
///  attempt 5: +80s
///  attempt 6: +160s
///  attempt 7: +320s
///  attempt 8: +640s
///  attempt 9: +1280s (capped to BACKOFF_CAP = 3600s)
///  attempt 10: +3600s
/// Total worst-case time-in-pending ≈ 6,755s ≈ 1h53m. After attempt 10,
/// status flips to `dead`.
pub const BACKOFF_BASE: Duration = Duration::from_secs(5);

/// Maximum backoff between retries. Caps the exponential growth.
pub const BACKOFF_CAP: Duration = Duration::from_secs(3600);

/// Maximum retry attempts before flipping to `status='dead'`.
pub const MAX_ATTEMPTS: i32 = 10;

/// Maximum age (since `created_at`) before flipping to `status='dead'`.
/// A row that has been pending+retrying for more than this is given up on
/// regardless of attempt count.
pub const MAX_LIFETIME: Duration = Duration::from_secs(86_400);
/// Maximum age for dead outbox rows before being purged during periodic cleanup.
/// Default: 7 days.
pub const DEAD_ROWS_MAX_AGE: Duration = Duration::from_secs(7 * 86_400);

/// Visibility timeout for `in_flight` rows: if a row has been `in_flight`
/// for longer than this, a follow-up tick reclaims it back to `pending`
/// (the worker that claimed it must have crashed). Long enough to
/// accommodate slow dispatches; short enough that a SIGKILL doesn't
/// strand the row for hours.
pub const IN_FLIGHT_VISIBILITY_TIMEOUT: Duration = Duration::from_secs(120);

/// Claim batch size per tick. 100 is enough for typical message rates
/// without monopolizing one worker's tx for long.
pub const CLAIM_BATCH_SIZE: i64 = 100;

/// Compute the backoff delay for the Nth attempt: `2^attempts * BACKOFF_BASE`,
/// capped at `BACKOFF_CAP`. Pure function for unit-testability.
///
/// **`attempts` is the pre-increment counter** — i.e. the value of
/// `outbox_row.attempts` BEFORE this failed attempt is recorded. So:
///
///   - First failure (row was at `attempts=0`): pass `0`, get `5s`
///     (2^0 * 5).
///   - Second failure (row was at `attempts=1`): pass `1`, get `10s`.
///   - Third failure (row was at `attempts=2`): pass `2`, get `20s`.
///   - …and so on through the schedule documented on `BACKOFF_BASE`.
///
/// codex P2 fix: prior to this doc-comment, `record_failure` passed
/// `new_attempts = attempts + 1` here, shifting the whole curve one
/// step later (first failure → 10s instead of 5s). Always pass the
/// pre-increment value.
pub fn compute_backoff(attempts: i32) -> Duration {
    let base = BACKOFF_BASE.as_secs();
    // 2^attempts saturates very quickly; bail out at 30 to avoid u64 overflow.
    let shift = attempts.clamp(0, 30) as u32;
    let secs = base.saturating_mul(1u64 << shift);
    let bounded = secs.min(BACKOFF_CAP.as_secs());
    Duration::from_secs(bounded)
}

/// Reclaim any rows that have been `in_flight` longer than the visibility
/// timeout. Called once per worker tick BEFORE the claim query. This is
/// the post-crash recovery path: a worker that flipped a row to
/// `in_flight` then died (SIGKILL) leaves the row in that state — we
/// flip it back to `pending` so it can be re-claimed.
///
/// Returns the number of rows reclaimed. A non-zero return is logged but
/// is not an error condition.
pub async fn reclaim_stuck_in_flight(pool: &PgPool, table: &str) -> Result<u64, sqlx::Error> {
    let timeout_secs = IN_FLIGHT_VISIBILITY_TIMEOUT.as_secs() as f64;
    let sql = match table {
        "notification_outbox" => {
            format!(
                "UPDATE {table} SET status = 'pending', updated_at = NOW() \
                 WHERE status = 'in_flight' \
                   AND updated_at < NOW() - make_interval(secs => $1)"
            )
        }
        _ => {
            format!(
                "UPDATE {table} SET status = 'pending', claim_token = NULL, claim_expires_at = NULL, updated_at = NOW() \
                 WHERE status = 'in_flight' \
                   AND (claim_expires_at <= NOW() OR (claim_expires_at IS NULL AND updated_at < NOW() - make_interval(secs => $1)))"
            )
        }
    };
    let result = sqlx::query(&sql).bind(timeout_secs).execute(pool).await?;
    Ok(result.rows_affected())
}

/// Mark a row as retryable (`pending` with backoff) or terminal
/// (`dead`) based on retry policy. Computes new `next_attempt_at` from
/// [`compute_backoff`].
///
/// Returns the **stored** status — `"dead"` if attempts exhausted or
/// lifetime exceeded, otherwise `"pending"` (the row is re-queued for
/// the next worker tick after `next_attempt_at`). The `attempts`
/// counter is incremented and `last_error` records the error message
/// even on the retry path, so the failure trail is preserved.
///
/// `pub` (rather than module-private) so the durable-outbox
/// integration test in `tests/durable_outbox_test.rs` can verify the
/// codex-P2 backoff regression directly without re-implementing the
/// retry SQL — see `record_failure_pre_increment_backoff_curve` in
/// that file.
pub async fn record_failure(
    pool: &PgPool,
    table: &str,
    row_id: &str,
    claim_token: Option<Uuid>,
    attempts: i32,
    created_at: chrono::DateTime<chrono::Utc>,
    error_msg: &str,
) -> Result<&'static str, sqlx::Error> {
    let lifetime_exceeded = chrono::Utc::now()
        .signed_duration_since(created_at)
        .to_std()
        .map(|d| d > MAX_LIFETIME)
        .unwrap_or(false);

    // codex P2 fix: pass the PRE-increment `attempts` to
    // compute_backoff. A row with `attempts=0` (first failure) MUST
    // get `2^0 * 5s = 5s`, not `2^1 * 5s = 10s`. Pre-fix, this passed
    // `new_attempts = attempts + 1`, which shifted the entire schedule
    // one step later (first failure 10s instead of 5s, second 20s
    // instead of 10s, etc.).
    let next_attempt_at = compute_backoff(attempts);
    let new_attempts = attempts + 1;
    let dead = new_attempts >= MAX_ATTEMPTS || lifetime_exceeded;
    let backoff_secs = next_attempt_at.as_secs() as i64;

    // Retry semantics: the claim query filters `status = 'pending'`,
    // so flipping a transient failure to 'pending' (with a backoff
    // `next_attempt_at`) is what actually re-queues it. 'failed' as a
    // distinct status was considered but would require a second
    // status in the claim filter and adds no value over the
    // (attempts > 0, last_error IS NOT NULL) projection.
    let stored_status = if dead { "dead" } else { "pending" };

    let rows_affected = match table {
        "federation_outbox" => {
            let sql = format!(
                "UPDATE {table} \
                 SET status = $1, \
                     attempts = $2, \
                     next_attempt_at = NOW() + make_interval(secs => $3), \
                     last_error = $4, \
                     claim_token = NULL, \
                     claim_expires_at = NULL, \
                     updated_at = NOW() \
                 WHERE id = $5 AND status = 'in_flight' AND ($6::uuid IS NULL OR claim_token = $6)"
            );
            let result = sqlx::query(&sql)
                .bind(stored_status)
                .bind(new_attempts)
                .bind(backoff_secs)
                .bind(error_msg)
                .bind(row_id)
                .bind(claim_token)
                .execute(pool)
                .await?;
            result.rows_affected()
        }
        "notification_outbox" => {
            let sql = format!(
                "UPDATE {table} \
                 SET status = $1, \
                     attempts = $2, \
                     next_attempt_at = NOW() + make_interval(secs => $3), \
                     last_error = $4, \
                     updated_at = NOW() \
                 WHERE id = $5"
            );
            let result = sqlx::query(&sql)
                .bind(stored_status)
                .bind(new_attempts)
                .bind(backoff_secs)
                .bind(error_msg)
                .bind(row_id)
                .execute(pool)
                .await?;
            result.rows_affected()
        }
        _ => {
            let sql = format!(
                "UPDATE {table} \
                 SET status = $1, \
                     attempts = $2, \
                     next_attempt_at = NOW() + make_interval(secs => $3), \
                     last_error = $4, \
                     claim_token = NULL, \
                     claim_expires_at = NULL, \
                     updated_at = NOW() \
                 WHERE id = $5 AND status = 'in_flight' AND ($6::uuid IS NULL OR claim_token = $6)"
            );
            let result = sqlx::query(&sql)
                .bind(stored_status)
                .bind(new_attempts)
                .bind(backoff_secs)
                .bind(error_msg)
                .bind(row_id)
                .bind(claim_token)
                .execute(pool)
                .await?;
            result.rows_affected()
        }
    };

    if rows_affected == 0 {
        return Ok("stale");
    }

    Ok(stored_status)
}

/// Mark a row as `done`. Idempotent — already-done rows match zero rows
/// and that's fine.
async fn mark_done(pool: &PgPool, table: &str, row_id: &str) -> Result<(), sqlx::Error> {
    let sql = format!("UPDATE {table} SET status = 'done', updated_at = NOW() WHERE id = $1");
    sqlx::query(&sql).bind(row_id).execute(pool).await?;
    Ok(())
}

/// Clean up dead rows older than `max_age` from outbox tables.
pub async fn cleanup_dead_rows(
    pool: &PgPool,
    table: &str,
    max_age: Duration,
) -> Result<u64, sqlx::Error> {
    let secs = max_age.as_secs() as f64;
    let sql = format!(
        "DELETE FROM {table} \
         WHERE status = 'dead' \
           AND (updated_at < NOW() - make_interval(secs => $1) OR (updated_at IS NULL AND created_at < NOW() - make_interval(secs => $1)))"
    );
    let result = sqlx::query(&sql).bind(secs).execute(pool).await?;
    Ok(result.rows_affected())
}

/// Convenience: log + ignore reclaim errors. The reclaim is a best-effort
/// recovery; a transient DB hiccup shouldn't kill the worker loop.
pub(crate) async fn try_reclaim(pool: &PgPool, table: &str) {
    match reclaim_stuck_in_flight(pool, table).await {
        Ok(0) => {} // common case, no log
        Ok(n) => {
            info!(
                table,
                reclaimed = n,
                "outbox: reclaimed stuck in_flight rows"
            );
        }
        Err(e) => {
            error!(table, error = ?e, "outbox: reclaim_stuck_in_flight failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_exponentially_until_cap() {
        // attempt 0 → 5s
        assert_eq!(compute_backoff(0), Duration::from_secs(5));
        // attempt 1 → 10s
        assert_eq!(compute_backoff(1), Duration::from_secs(10));
        // attempt 2 → 20s
        assert_eq!(compute_backoff(2), Duration::from_secs(20));
        // attempt 5 → 160s
        assert_eq!(compute_backoff(5), Duration::from_secs(160));
        // attempt 9 → 2560s capped to 3600s
        assert_eq!(compute_backoff(9), Duration::from_secs(2560));
        // attempt 10 → 5120s capped
        assert_eq!(compute_backoff(10), Duration::from_secs(3600));
        // huge attempt → still capped (no overflow)
        assert_eq!(compute_backoff(1_000), Duration::from_secs(3600));
        // negative (defensive) → minimum (5s)
        assert_eq!(compute_backoff(-1), Duration::from_secs(5));
    }
}
