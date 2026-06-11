//! N26 (detection half, WS-1.1): key-package enumeration detection.
//!
//! `getKeyPackages` is rate-limited to ~30 req/min, but each request may name
//! up to 100 target DIDs, so a patient caller can still enumerate the
//! directory slowly. While `GATE_KEY_PACKAGES_MODE` defaults to `log_only`,
//! authorization denials are observable but not enforced — this tracker adds
//! an orthogonal signal: per-caller *unique target DID* cardinality over a
//! sliding window. A legitimate client touches the DIDs it actually chats
//! with; an enumerator touches many distinct DIDs exactly once.
//!
//! Detection only: callers above the threshold get a WARN log plus a
//! `key_package_enumeration_suspected_total` counter increment. Nothing is
//! blocked. The enforce flip (and any blocking response) is gated on
//! production log observation — see backlog N26.
//!
//! Tunables (read once at first use):
//! - `KEY_PACKAGE_ENUM_WINDOW_SECS` (default 600): sliding window length.
//! - `KEY_PACKAGE_ENUM_UNIQUE_TARGETS` (default 200): unique-target-DID
//!   cardinality above which a caller is flagged. Default rationale: a
//!   100-member group creation legitimately touches ~100 unique DIDs in one
//!   burst; two large creations inside ten minutes stay under 200. Sustained
//!   probing at the rate limit (30 req/min x 100 DIDs) crosses it in seconds.

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const WINDOW_SECS_ENV: &str = "KEY_PACKAGE_ENUM_WINDOW_SECS";
const WINDOW_SECS_DEFAULT: u64 = 600;
const UNIQUE_TARGETS_ENV: &str = "KEY_PACKAGE_ENUM_UNIQUE_TARGETS";
const UNIQUE_TARGETS_DEFAULT: usize = 200;

/// Drop state for callers idle longer than the window once the map grows
/// past this many callers (cheap inline GC; avoids unbounded growth from
/// one-shot callers).
const STALE_SWEEP_MIN_CALLERS: usize = 1024;

/// Per-caller sliding-window unique-target-DID cardinality tracker.
pub struct EnumerationDetector {
    window: Duration,
    threshold: usize,
    callers: Mutex<HashMap<String, CallerWindow>>,
}

#[derive(Default)]
struct CallerWindow {
    /// Target observations in arrival order, for window eviction.
    events: VecDeque<(Instant, String)>,
    /// Live multiset of targets inside the window; `len()` is the unique
    /// target cardinality.
    counts: HashMap<String, usize>,
}

impl CallerWindow {
    fn evict_older_than(&mut self, cutoff: Instant) {
        while let Some((seen_at, _)) = self.events.front() {
            if *seen_at >= cutoff {
                break;
            }
            let (_, did) = self.events.pop_front().expect("front checked above");
            if let Some(count) = self.counts.get_mut(&did) {
                *count -= 1;
                if *count == 0 {
                    self.counts.remove(&did);
                }
            }
        }
    }

    fn newest_event_at(&self) -> Option<Instant> {
        self.events.back().map(|(seen_at, _)| *seen_at)
    }
}

impl EnumerationDetector {
    pub fn new(window: Duration, threshold: usize) -> Self {
        Self {
            window,
            threshold,
            callers: Mutex::new(HashMap::new()),
        }
    }

    pub fn from_env() -> Self {
        let window_secs = std::env::var(WINDOW_SECS_ENV)
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(WINDOW_SECS_DEFAULT);
        let threshold = std::env::var(UNIQUE_TARGETS_ENV)
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(UNIQUE_TARGETS_DEFAULT);
        Self::new(Duration::from_secs(window_secs), threshold)
    }

    /// Process-wide detector, configured from env at first use.
    pub fn global() -> &'static Self {
        static DETECTOR: OnceLock<EnumerationDetector> = OnceLock::new();
        DETECTOR.get_or_init(Self::from_env)
    }

    pub fn window_secs(&self) -> u64 {
        self.window.as_secs()
    }

    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Record the targets of one `getKeyPackages` call for `caller`.
    ///
    /// Returns `Some(unique_target_count)` when the caller's unique-target
    /// cardinality inside the sliding window exceeds the threshold (emitted
    /// on every call while above threshold, so a sustained probe keeps the
    /// signal alive in logs/metrics).
    pub fn record<'a>(
        &self,
        caller: &str,
        targets: impl IntoIterator<Item = &'a str>,
    ) -> Option<usize> {
        self.record_at(caller, targets, Instant::now())
    }

    fn record_at<'a>(
        &self,
        caller: &str,
        targets: impl IntoIterator<Item = &'a str>,
        now: Instant,
    ) -> Option<usize> {
        let cutoff = now.checked_sub(self.window).unwrap_or(now);
        let mut callers = self.callers.lock().expect("enumeration tracker lock");

        if callers.len() > STALE_SWEEP_MIN_CALLERS {
            callers.retain(|_, window| window.newest_event_at().is_some_and(|at| at >= cutoff));
        }

        let window = callers.entry(caller.to_string()).or_default();
        window.evict_older_than(cutoff);
        for target in targets {
            // Self-lookups are always authorized and never enumeration signal.
            if target == caller {
                continue;
            }
            window.events.push_back((now, target.to_string()));
            *window.counts.entry(target.to_string()).or_insert(0) += 1;
        }

        let unique = window.counts.len();
        (unique > self.threshold).then_some(unique)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_dids(prefix: &str, n: usize) -> Vec<String> {
        (0..n).map(|i| format!("did:plc:{prefix}{i:05}")).collect()
    }

    /// Synthetic probe: a caller sweeping many distinct DIDs in small batches
    /// (mimicking the 30 req/min x bounded-batch rate-limit budget) must trip
    /// the detector inside one window.
    #[test]
    fn synthetic_probe_trips_threshold() {
        let detector = EnumerationDetector::new(Duration::from_secs(600), 200);
        let probe_targets = synthetic_dids("probe", 250);
        let start = Instant::now();

        let mut flagged = None;
        for (batch_idx, batch) in probe_targets.chunks(25).enumerate() {
            let at = start + Duration::from_secs(batch_idx as u64 * 2);
            let result =
                detector.record_at("did:plc:attacker", batch.iter().map(String::as_str), at);
            if let Some(unique) = result {
                flagged = Some((batch_idx, unique));
                break;
            }
        }

        let (batch_idx, unique) = flagged.expect("synthetic probe must be flagged");
        // 25 targets/batch: batch 8 lands at 225 unique > 200.
        assert_eq!(batch_idx, 8);
        assert_eq!(unique, 225);
    }

    #[test]
    fn legitimate_group_creation_stays_quiet() {
        let detector = EnumerationDetector::new(Duration::from_secs(600), 200);
        let members = synthetic_dids("member", 100);
        let start = Instant::now();

        // A 100-member createConvo burst, then repeated re-fetches of the
        // same membership (retries, device adds) — cardinality stays at 100.
        for i in 0..5 {
            let at = start + Duration::from_secs(i * 60);
            let result =
                detector.record_at("did:plc:creator", members.iter().map(String::as_str), at);
            assert_eq!(
                result, None,
                "repeat lookups of the same DIDs must not flag"
            );
        }
    }

    #[test]
    fn window_eviction_resets_cardinality() {
        let detector = EnumerationDetector::new(Duration::from_secs(600), 200);
        let first = synthetic_dids("first", 150);
        let second = synthetic_dids("second", 150);
        let start = Instant::now();

        assert_eq!(
            detector.record_at("did:plc:slow", first.iter().map(String::as_str), start),
            None
        );
        // Second batch lands after the first has aged out of the window:
        // 150 live uniques, not 300.
        let later = start + Duration::from_secs(601);
        assert_eq!(
            detector.record_at("did:plc:slow", second.iter().map(String::as_str), later),
            None
        );

        // Inside one window the same two batches do exceed the threshold.
        let detector = EnumerationDetector::new(Duration::from_secs(600), 200);
        assert_eq!(
            detector.record_at("did:plc:fast", first.iter().map(String::as_str), start),
            None
        );
        assert_eq!(
            detector.record_at(
                "did:plc:fast",
                second.iter().map(String::as_str),
                start + Duration::from_secs(30)
            ),
            Some(300)
        );
    }

    #[test]
    fn callers_are_tracked_independently_and_self_lookups_ignored() {
        let detector = EnumerationDetector::new(Duration::from_secs(600), 10);
        let targets = synthetic_dids("t", 11);
        let now = Instant::now();

        assert_eq!(
            detector.record_at("did:plc:alice", targets.iter().map(String::as_str), now),
            Some(11)
        );
        // Bob is unaffected by Alice's history.
        assert_eq!(
            detector.record_at("did:plc:bob", targets[..5].iter().map(String::as_str), now),
            None
        );
        // Self-lookups never count toward the caller's cardinality.
        assert_eq!(
            detector.record_at(
                "did:plc:carol",
                std::iter::repeat_n("did:plc:carol", 50),
                now
            ),
            None
        );
    }
}
