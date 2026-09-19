//! Logical retention charge for the immutable publication graph.
//!
//! Count each independently persisted blob, including repeated signed wrappers
//! and accepted entries. Scalar-row allowance covers bounded identity/hash
//! columns; this is a quota policy, not physical PostgreSQL/WAL/index sizing.

const ROW_ALLOWANCE: u64 = 16 * 1024;

/// Retention reserved at publication for the request's bounded remaining
/// lifecycle. Later writers must compare their actual persisted copies against
/// these slots before committing; the reservation is not a blob-size waiver.
pub(super) struct LifecycleReserve {
    pub decision: u64,
    pub per_delivery: u64,
    pub total: u64,
}

pub(super) fn lifecycle_reserve(
    snapshot_bytes: usize,
    tree_bytes: usize,
    historical_audience: u64,
    deliveries: u64,
) -> Option<LifecycleReserve> {
    if deliveries > 39 {
        return None;
    }
    // The first decision is acceptance OR a close before acceptance. The
    // snapshot/tree copy is separately charged because it can exceed the
    // 64 KiB limit imposed on later signed lifecycle blobs.
    let decision = (4u64 * 1024 * 1024)
        .checked_add(u64::try_from(snapshot_bytes).ok()?)?
        .checked_add(u64::try_from(tree_bytes).ok()?)?
        .checked_add(historical_audience.checked_mul(3)?.checked_mul(ROW_ALLOWANCE)?)?;
    let per_delivery: u64 = 512 * 1024;
    let total = decision.checked_add(deliveries.checked_mul(per_delivery)?)?;
    Some(LifecycleReserve { decision, per_delivery, total })
}

pub(super) struct PublicationArtifactLengths {
    pub signed_wrapper: usize,
    pub accepted_entry: usize,
    pub unsigned_body: usize,
    pub transcript: usize,
    pub signature: usize,
    pub remaining_blobs: u64,
    pub final_leaves: u64,
    pub deliveries: u64,
    pub predecessor_intervals: u64,
    pub legacy_successor: bool,
}

pub(super) fn charge(
    existing_attempt: u64,
    receipt: usize,
    parts: &PublicationArtifactLengths,
) -> Option<u64> {
    // Fresh: conversation, generation, state, transition, entry, metadata,
    // two participants, publication, event and two outbox rows. A successor
    // reuses the conversation/participants and adds one retirement state.
    let base_rows: u64 = if parts.legacy_successor { 10 } else { 12 };
    // Each final leaf adds membership, interval, entry and event audience rows.
    // The predecessor union can overlap, so charging all old audience rows is
    // deliberately conservative; the transaction never undercharges that union.
    let rows = base_rows
        .checked_add(parts.final_leaves.checked_mul(4)?)?
        .checked_add(parts.deliveries)?
        .checked_add(parts.predecessor_intervals.checked_mul(2)?)?;
    let mut total = existing_attempt
        .checked_add(u64::try_from(receipt).ok()?)?
        .checked_add(rows.checked_mul(ROW_ALLOWANCE)?)?
        .checked_add(parts.remaining_blobs)?;
    for (length, copies) in [
        (parts.signed_wrapper, 3), // transitions, entries, publications
        (parts.accepted_entry, 2), // entries, publications
        (parts.unsigned_body, 1),
        (parts.transcript, 1),
        (parts.signature, 2), // separately stored outside both wrappers
    ] {
        total = total.checked_add(u64::try_from(length).ok()?.checked_mul(copies)?)?;
    }
    Some(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> PublicationArtifactLengths {
        PublicationArtifactLengths {
            signed_wrapper: 4 * 1024 * 1024,
            accepted_entry: 4 * 1024 * 1024 + 256,
            unsigned_body: 4 * 1024 * 1024 - 128,
            transcript: 3 * 1024 * 1024,
            signature: 64,
            remaining_blobs: 2 * 1024 * 1024,
            final_leaves: 40,
            deliveries: 39,
            predecessor_intervals: 0,
            legacy_successor: false,
        }
    }

    #[test]
    fn legal_sized_bundle_cannot_hide_repeated_retained_copies() {
        let parts = fixture();
        // Its raw component bundle fits 8 MiB, but its independently retained
        // signed/control forms exceed the former blanket 8 MiB charge.
        let retained = charge(200_000, 2048, &parts).unwrap();
        assert!(retained > 24 * 1024 * 1024);
        assert!(retained < 64 * 1024 * 1024);
        let mut legacy = fixture();
        legacy.legacy_successor = true;
        legacy.predecessor_intervals = 20;
        legacy.remaining_blobs += 1024 * 1024;
        assert!(charge(200_000, 2048, &legacy).unwrap() > retained);
    }

    #[test]
    fn overflow_rejects_instead_of_wrapping_the_charge() {
        assert!(charge(u64::MAX, 1, &fixture()).is_none());
        let mut parts = fixture();
        parts.predecessor_intervals = u64::MAX;
        assert!(charge(0, 0, &parts).is_none());
    }

    #[test]
    fn lifecycle_reserve_counts_historical_audience_and_all_selected_deliveries() {
        let current = lifecycle_reserve(2_000_000, 500_000, 40, 39).unwrap();
        assert_eq!(current.decision, 4 * 1024 * 1024 + 2_500_000 + 40 * 3 * ROW_ALLOWANCE);
        assert_eq!(current.per_delivery, 512 * 1024);
        assert_eq!(current.total, current.decision + 39 * current.per_delivery);
        let historical = lifecycle_reserve(2_000_000, 500_000, 140, 39).unwrap();
        assert_eq!(historical.total - current.total, 100 * 3 * ROW_ALLOWANCE);
        assert!(lifecycle_reserve(0, 0, u64::MAX, 1).is_none());
        assert!(lifecycle_reserve(0, 0, 40, 40).is_none());
    }
}
