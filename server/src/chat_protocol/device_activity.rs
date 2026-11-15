//! Day-granular device activity stamps.
//!
//! `chat.devices.last_active_at` and `chat.device_entry_acks.updated_at` exist for
//! one purpose: the dormancy sweep that stops an abandoned device from stalling
//! ACK-based ciphertext pruning. Neither needs to say *when* in a day a device was
//! online, and a wall-clock stamp on every request turns the table into a
//! per-device online log for anyone who later reads the database. Writers therefore
//! store the UTC day only.

use chrono::{DateTime, Duration, DurationRound, Utc};
use sqlx::{Executor, Postgres};

/// Truncate `instant` to the start of its UTC day.
///
/// Every writer of a device activity or ACK timestamp binds this value, never the
/// raw request instant.
pub fn coarse_activity_day(instant: DateTime<Utc>) -> DateTime<Utc> {
    instant.duration_trunc(Duration::days(1)).unwrap_or(instant)
}

fn pending_device_hold_hours() -> i64 {
    std::env::var("CHAT_PENDING_DEVICE_HOLD_HOURS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(72)
}

/// `D-2` / `B10`: Promote any `pending_approval` device on `user_did` whose
/// 72-hour elapsed-clock recovery hold has completed (`created_at <= now - 72h`)
/// without sibling revocation (`revoked_at IS NULL`).
pub async fn promote_matured_pending_devices_for_user<'e, E>(
    executor: E,
    user_did: &str,
    now: DateTime<Utc>,
) -> Result<u64, sqlx::Error>
where
    E: Executor<'e, Database = Postgres>,
{
    let cutoff = now - Duration::hours(pending_device_hold_hours());
    let result = sqlx::query(
        "UPDATE chat.devices \
            SET status = 'active', \
                updated_at = GREATEST(updated_at, $2) \
          WHERE user_did = $1 \
            AND status = 'pending_approval' \
            AND revoked_at IS NULL \
            AND created_at <= $3",
    )
    .bind(user_did)
    .bind(now)
    .bind(cutoff)
    .execute(executor)
    .await?;
    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::coarse_activity_day;
    use chrono::{TimeZone, Utc};

    #[test]
    fn truncates_to_the_utc_day_start() {
        let instant = Utc.with_ymd_and_hms(2026, 11, 9, 23, 59, 58).unwrap()
            + chrono::Duration::milliseconds(321);
        assert_eq!(
            coarse_activity_day(instant),
            Utc.with_ymd_and_hms(2026, 11, 9, 0, 0, 0).unwrap()
        );
    }

    #[test]
    fn is_idempotent_and_stable_within_one_day() {
        let morning = Utc.with_ymd_and_hms(2026, 11, 9, 0, 0, 1).unwrap();
        let evening = Utc.with_ymd_and_hms(2026, 11, 9, 22, 0, 0).unwrap();
        assert_eq!(coarse_activity_day(morning), coarse_activity_day(evening));
        assert_eq!(
            coarse_activity_day(coarse_activity_day(evening)),
            coarse_activity_day(evening)
        );
    }
}
