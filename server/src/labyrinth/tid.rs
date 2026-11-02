//! Server-assigned record keys: atproto TIDs (53-bit microsecond timestamp,
//! 10-bit clock id, base32-sortable, 13 characters), strictly increasing
//! within a production process or an isolated simulation clock.

use std::sync::atomic::{AtomicU64, Ordering};

const ALPHABET: &[u8; 32] = b"234567abcdefghijklmnopqrstuvwxyz";

static LAST_MICROS: AtomicU64 = AtomicU64::new(0);

/// A new TID. Production keeps a process-monotone counter and random clock id;
/// deterministic workers use their own clock's resettable microsecond sequence.
pub fn next_tid() -> String {
    let (micros, clock_id) = match crate::sim_hooks::next_deterministic_tid_micros() {
        Some(micros) => (micros, 0),
        None => {
            let now = crate::sim_hooks::current_utc().timestamp_micros().max(0) as u64;
            let micros = LAST_MICROS
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |last| {
                    Some(now.max(last.saturating_add(1)))
                })
                .map(|last| now.max(last.saturating_add(1)))
                .expect("TID counter updates cannot fail");
            (micros, u64::from(rand::random::<u16>() & 0x3ff))
        }
    };
    encode(((micros & ((1 << 53) - 1)) << 10) | clock_id)
}

fn encode(mut value: u64) -> String {
    let mut out = [0u8; 13];
    for slot in out.iter_mut().rev() {
        *slot = ALPHABET[(value & 31) as usize];
        value >>= 5;
    }
    String::from_utf8(out.to_vec()).expect("alphabet is ASCII")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tids_are_13_chars_sortable_and_increasing() {
        let a = next_tid();
        let b = next_tid();
        assert_eq!(a.len(), 13);
        assert!(b > a, "{b} must sort after {a}");
        assert!(matches!(a.as_bytes()[0], b'2'..=b'7' | b'a'..=b'j'));
        assert_eq!(encode(0), "2222222222222");
    }

    #[test]
    fn deterministic_tid_sequences_are_clock_local_and_resettable() {
        use crate::sim_hooks::{with_ds_clock, ManualDsClock};
        use chrono::{DateTime, TimeDelta, Utc};
        use std::sync::Arc;

        let now = DateTime::<Utc>::from_timestamp(1_800_000_000, 0).unwrap();
        let first = Arc::new(ManualDsClock::new(now));
        let second = Arc::new(ManualDsClock::new(now));
        let a = with_ds_clock(first.clone(), next_tid);
        let b = with_ds_clock(first.clone(), next_tid);
        assert!(b > a);
        assert_eq!(with_ds_clock(second.clone(), next_tid), a);
        first.set_utc(now - TimeDelta::seconds(1));
        assert!(with_ds_clock(first.clone(), next_tid) > b);
        second.reset_counters();
        assert_eq!(with_ds_clock(second.clone(), next_tid), a);
        first.set_utc(now);
        first.reset_counters();
        assert_eq!(with_ds_clock(first, next_tid), a);
        assert_eq!(with_ds_clock(second, next_tid), b);
    }
}
