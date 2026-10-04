//! Immutable, precharged slots for the bounded request lifecycle. Slot writers
//! never acquire the global budget after conversation locks.
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(super) const MAX_CONTROL_BLOB_BYTES: usize = 65_536;
pub(super) const ROW_BYTES: u64 = 16_384;
pub(super) const WELCOME_SLOT_BYTES: u64 = 524_288;

#[derive(Debug, thiserror::Error)]
pub(crate) enum RetentionError {
    #[error("request lifecycle retention capacity unavailable")]
    CapacityUnavailable,
    #[error("request lifecycle operation already terminal")]
    AlreadyConsumed,
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

pub(super) fn decision_reservation_bytes(
    snapshot_tree: u64,
    historical_audience: u64,
) -> Option<u64> {
    4_194_304u64
        .checked_add(snapshot_tree)?
        .checked_add(historical_audience.checked_mul(3)?.checked_mul(ROW_BYTES)?)
}
pub(super) fn lifecycle_reservation_bytes(
    snapshot_tree: u64,
    historical_audience: u64,
    deliveries: u64,
) -> Option<u64> {
    if deliveries > 39 {
        return None;
    }
    decision_reservation_bytes(snapshot_tree, historical_audience)?
        .checked_add(deliveries.checked_mul(WELCOME_SLOT_BYTES)?)
}
pub(super) async fn install_lifecycle_reserve(
    tx: &mut Transaction<'_, Postgres>,
    request_id: Uuid,
    decision_bytes: u64,
    deliveries: u64,
) -> Result<(), RetentionError> {
    if deliveries > 39 || decision_bytes < 4_194_304 {
        return Err(RetentionError::CapacityUnavailable);
    }
    sqlx::query("INSERT INTO chat.direct_request_lifecycle_reserves(request_id,decision_bytes,welcome_bytes_per_delivery,delivery_count) VALUES($1,$2,$3,$4)")
        .bind(request_id).bind(i64::try_from(decision_bytes).map_err(|_|RetentionError::CapacityUnavailable)?)
        .bind(WELCOME_SLOT_BYTES as i64).bind(deliveries as i64).execute(&mut **tx).await?;
    Ok(())
}

/// Each variable control blob is capped separately. Snapshot/tree bytes have
/// their own measured reservation and must never be passed as control blobs.
pub(super) fn logical_charge(
    blobs: &[&[u8]],
    snapshot_tree_bytes: u64,
    rows: u64,
) -> Result<u64, RetentionError> {
    let mut bytes = snapshot_tree_bytes
        .checked_add(
            rows.checked_mul(ROW_BYTES)
                .ok_or(RetentionError::CapacityUnavailable)?,
        )
        .ok_or(RetentionError::CapacityUnavailable)?;
    for blob in blobs {
        if blob.len() > MAX_CONTROL_BLOB_BYTES {
            return Err(RetentionError::CapacityUnavailable);
        }
        bytes = bytes
            .checked_add(blob.len() as u64)
            .ok_or(RetentionError::CapacityUnavailable)?;
    }
    Ok(bytes)
}
pub(super) async fn consume_decision(
    tx: &mut Transaction<'_, Postgres>,
    request: Uuid,
    operation: Uuid,
    kind: &str,
    bytes: u64,
) -> Result<(), RetentionError> {
    let available:Option<i64>=sqlx::query_scalar("SELECT decision_bytes FROM chat.direct_request_lifecycle_reserves WHERE request_id=$1 FOR UPDATE")
        .bind(request).fetch_optional(&mut **tx).await?;
    if available.is_none_or(|limit| bytes > limit as u64) {
        return Err(RetentionError::CapacityUnavailable);
    }
    let inserted=sqlx::query("INSERT INTO chat.direct_request_decision_slots(request_id,operation_id,decision_kind,charged_bytes) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING")
        .bind(request).bind(operation).bind(kind).bind(bytes as i64).execute(&mut **tx).await?;
    if inserted.rows_affected() != 1 {
        return Err(RetentionError::AlreadyConsumed);
    }
    Ok(())
}
pub(super) async fn consume_welcome(
    tx: &mut Transaction<'_, Postgres>,
    request: Uuid,
    did: &str,
    device: Uuid,
    operation: Uuid,
    request_digest: &[u8; 32],
    bytes: u64,
) -> Result<(), RetentionError> {
    let limit:Option<i64>=sqlx::query_scalar("SELECT r.welcome_bytes_per_delivery FROM chat.direct_request_lifecycle_reserves r JOIN chat.direct_request_device_deliveries d USING(request_id) WHERE r.request_id=$1 AND d.owner_did=$2 AND d.owner_device_id=$3 FOR UPDATE OF r")
        .bind(request).bind(did).bind(device).fetch_optional(&mut **tx).await?;
    if limit.is_none_or(|limit| bytes > limit as u64) {
        return Err(RetentionError::CapacityUnavailable);
    }
    let inserted=sqlx::query("INSERT INTO chat.direct_request_welcome_slots(request_id,recipient_did,recipient_device_id,operation_id,request_digest,charged_bytes) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING")
        .bind(request).bind(did).bind(device).bind(operation).bind(request_digest.as_slice()).bind(bytes as i64).execute(&mut **tx).await?;
    if inserted.rows_affected() != 1 {
        return Err(RetentionError::AlreadyConsumed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reservation_measures_full_history_and_delivery_slots() {
        assert_eq!(
            lifecycle_reservation_bytes(1000, 40, 39),
            Some(4_194_304 + 1000 + 3 * 40 * ROW_BYTES + 39 * WELCOME_SLOT_BYTES)
        );
        assert!(
            lifecycle_reservation_bytes(1000, 4000, 39).unwrap()
                > lifecycle_reservation_bytes(1000, 40, 39).unwrap()
        );
        assert!(lifecycle_reservation_bytes(0, 40, 40).is_none());
    }
    #[test]
    fn oversized_raw_controls_and_overflow_fail_closed() {
        assert!(logical_charge(&[&vec![b' '; MAX_CONTROL_BLOB_BYTES + 1]], 0, 1).is_err());
        assert!(logical_charge(&[b"ok"], 10_000_000, 1).is_ok());
        assert!(decision_reservation_bytes(u64::MAX, 1).is_none());
        assert!(decision_reservation_bytes(1, u64::MAX).is_none());
    }
}
