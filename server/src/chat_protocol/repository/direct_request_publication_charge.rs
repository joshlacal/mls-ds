//! Logical retention charge for the immutable publication graph.
//!
//! Count each independently persisted blob, including repeated signed wrappers
//! and accepted entries. Scalar-row allowance covers bounded identity/hash
//! columns; this is a quota policy, not physical PostgreSQL/WAL/index sizing.

const ROW_ALLOWANCE: u64 = 16 * 1024;

pub(crate) struct PublicationArtifactLengths {
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

pub(crate) fn charge(
    existing_attempt: u64,
    receipt: usize,
    parts: &PublicationArtifactLengths,
) -> Option<u64> {
    // Fresh: conversation, generation, state, transition, entry, metadata,
    // two participants, publication, event, two outbox rows, and the immutable
    // request-push event mapping. A successor reuses the
    // conversation/participants and adds one retirement state.
    let base_rows: u64 = if parts.legacy_successor { 11 } else { 13 };
    // Each final leaf adds membership, interval, entry and event audience rows.
    // The predecessor union can overlap, so charging all old audience rows is
    // deliberately conservative; the transaction never undercharges that union.
    let rows = base_rows
        .checked_add(parts.final_leaves.checked_mul(4)?)?
        // One delivery row and, conservatively, one request-push audience row
        // per selected delivery. Sender siblings are excluded from the actual
        // push audience, so this bound can overcharge but never undercharges.
        .checked_add(parts.deliveries.checked_mul(2)?)?
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
}
