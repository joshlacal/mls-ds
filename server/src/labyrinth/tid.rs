//! Server-assigned record keys: atproto TIDs (53-bit microsecond timestamp,
//! 10-bit clock id, base32-sortable, 13 characters), strictly increasing
//! within this process.

use std::sync::atomic::{AtomicU64, Ordering};

const ALPHABET: &[u8; 32] = b"234567abcdefghijklmnopqrstuvwxyz";

static LAST_MICROS: AtomicU64 = AtomicU64::new(0);

/// A new TID. `clock_id` keeps concurrent processes apart; the per-process
/// counter keeps one process monotone even when the clock stalls.
pub fn next_tid() -> String {
    let now = chrono::Utc::now().timestamp_micros().max(0) as u64;
    let micros = LAST_MICROS
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |last| {
            Some(now.max(last + 1))
        })
        .map(|last| now.max(last + 1))
        .unwrap_or(now);
    let clock_id = u64::from(rand::random::<u16>() & 0x3ff);
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
}
