//! Day-granular device activity stamps.
//!
//! `chat.devices.last_active_at` and `chat.device_entry_acks.updated_at` exist for
//! one purpose: the dormancy sweep that stops an abandoned device from stalling
//! ACK-based ciphertext pruning. Neither needs to say *when* in a day a device was
//! online, and a wall-clock stamp on every request turns the table into a
//! per-device online log for anyone who later reads the database. Writers therefore
//! store the UTC day only.

use chrono::{DateTime, Duration, DurationRound, Utc};
use sqlx::PgConnection;
use uuid::Uuid;

/// Truncate `instant` to the start of its UTC day.
///
/// Every writer of a device activity or ACK timestamp binds this value, never the
/// raw request instant.
pub fn coarse_activity_day(instant: DateTime<Utc>) -> DateTime<Utc> {
    instant.duration_trunc(Duration::days(1)).unwrap_or(instant)
}

/// Recovery promotion requires a fresh, device-signed action after at least
/// 72 hours of sibling-visible pending status. Operators may extend the hold,
/// but cannot shorten the security floor.
pub fn pending_device_hold_hours() -> i64 {
    std::env::var("CHAT_PENDING_DEVICE_HOLD_HOURS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|v| *v >= 72)
        .unwrap_or(72)
}

/// A successfully device-signed Labyrinth request is activity even when the
/// device uses no chat endpoint. Wake only a still-active device, and retain the
/// same coarse UTC-day privacy bound as chat reads and ACKs. Callers must invoke
/// this only AFTER verifying the device signature.
pub async fn mark_authenticated_labyrinth_activity(
    conn: &mut PgConnection,
    did: &str,
    device_id: Uuid,
    at: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    let day = coarse_activity_day(at);
    sqlx::query(
        "UPDATE chat.devices \
            SET last_active_at = GREATEST(last_active_at, $3), dormant_at = NULL \
          WHERE user_did = $1 AND device_id = $2 \
            AND status = 'active' AND revoked_at IS NULL \
            AND (last_active_at < $3 OR dormant_at IS NOT NULL)",
    )
    .bind(did)
    .bind(device_id)
    .bind(day)
    .execute(conn)
    .await?;
    Ok(())
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
