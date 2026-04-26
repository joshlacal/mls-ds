//! Runtime configuration loaded from environment variables.
//!
//! This module currently houses the Phase 2 auto-reset quorum knobs
//! introduced by ADR-008 D1 (`docs/superpowers/specs/2026-04-26-mls-auto-reset-phase2-design.md`).
//! Other parts of the server still read environment variables inline; this
//! module is intentionally narrow rather than trying to consolidate every
//! existing env read in one go.
//!
//! # Quorum Knobs
//!
//! The Path A "client-report quorum" detection path computes a per-conversation
//! `quorum_required` based on member count. For groups we use
//! `max(group_min, ceil(member_count * group_pct))`. For 1:1 conversations we
//! use the dedicated `dm` threshold (default 1 — a single Mode B report from
//! either side fires the reset).
//!
//! The `enforce_failure_mode_quorum` flag controls whether non-Mode B votes
//! (NULL or `local_state_loss`) count toward the quorum. With the flag on
//! (Phase 2 default), only `group_state_unrecoverable` votes count.
//!
//! See `docs/program/decisions/ADR-008-auto-reset-protocol-binding.md` §D1
//! and the spec referenced above for the rationale.

/// Quorum-related configuration for the Path A client-report reset detection.
///
/// Loaded from environment via [`QuorumConfig::from_env`]. Tests should
/// construct values directly to avoid clobbering process-global env state
/// across parallel test runs (cargo runs `#[test]`s on multiple threads).
#[derive(Clone, Debug, PartialEq)]
pub struct QuorumConfig {
    /// Fraction of group members whose Mode B reports trigger reset.
    /// Multiplied with `member_did_count` then ceil'd.
    pub group_pct: f64,
    /// Minimum reports required for a group regardless of `group_pct`.
    pub group_min: u32,
    /// Reports required for a 1:1 conversation (`member_did_count == 2`).
    pub dm: u32,
    /// Sliding window (seconds) within which votes count toward quorum.
    pub window_secs: u64,
    /// When true, only votes with `failure_mode = 'group_state_unrecoverable'`
    /// (Mode B) count toward quorum. When false, every recorded vote counts
    /// regardless of `failure_mode` (interim posture for clients that pre-date
    /// the field).
    pub enforce_failure_mode: bool,
}

impl Default for QuorumConfig {
    fn default() -> Self {
        Self {
            group_pct: 0.4,
            group_min: 2,
            dm: 1,
            window_secs: 600,
            enforce_failure_mode: true,
        }
    }
}

impl QuorumConfig {
    /// Read the quorum config from process environment, applying defaults for
    /// any missing/invalid value. Each variable matches the name in the spec.
    pub fn from_env() -> Self {
        let defaults = Self::default();
        Self {
            group_pct: parse_env_f64("QUORUM_THRESHOLD_GROUP_PCT", defaults.group_pct),
            group_min: parse_env_u32("QUORUM_THRESHOLD_GROUP_MIN", defaults.group_min),
            dm: parse_env_u32("QUORUM_THRESHOLD_DM", defaults.dm),
            window_secs: parse_env_u64("QUORUM_WINDOW_SECS", defaults.window_secs),
            enforce_failure_mode: parse_env_bool(
                "ENFORCE_FAILURE_MODE_QUORUM",
                defaults.enforce_failure_mode,
            ),
        }
    }

    /// Compute the number of votes required to fire an auto-reset for a
    /// conversation with `member_did_count` distinct active member identities.
    ///
    /// - `member_did_count <= 1`: returns `0` — caller treats this as
    ///   "no quorum possible" (we never reset a singleton convo).
    /// - `member_did_count == 2`: 1:1 case → returns `self.dm`.
    /// - `member_did_count >= 3`: group case → `max(group_min, ceil(n * group_pct))`.
    pub fn required_for(&self, member_did_count: i64) -> i64 {
        if member_did_count < 2 {
            return 0;
        }
        if member_did_count == 2 {
            return self.dm as i64;
        }
        let by_pct = ((member_did_count as f64) * self.group_pct).ceil() as i64;
        std::cmp::max(self.group_min as i64, by_pct)
    }
}

fn parse_env_f64(name: &str, default: f64) -> f64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|v| v.is_finite() && *v > 0.0 && *v <= 1.0)
        .unwrap_or(default)
}

fn parse_env_u32(name: &str, default: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
}

fn parse_env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
}

fn parse_env_bool(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quorum_config_defaults_match_spec() {
        let cfg = QuorumConfig::default();
        assert_eq!(cfg.group_pct, 0.4, "QUORUM_THRESHOLD_GROUP_PCT default");
        assert_eq!(cfg.group_min, 2, "QUORUM_THRESHOLD_GROUP_MIN default");
        assert_eq!(cfg.dm, 1, "QUORUM_THRESHOLD_DM default");
        assert_eq!(cfg.window_secs, 600, "QUORUM_WINDOW_SECS default");
        assert!(
            cfg.enforce_failure_mode,
            "ENFORCE_FAILURE_MODE_QUORUM default flipped to true for Phase 2"
        );
    }

    #[test]
    fn required_for_dm() {
        let cfg = QuorumConfig::default();
        assert_eq!(cfg.required_for(2), 1, "1:1 → dm threshold");
    }

    #[test]
    fn required_for_groups_uses_ceil_and_min() {
        let cfg = QuorumConfig::default();
        // 3 members × 0.4 = 1.2 → ceil 2; max(min=2, 2) = 2
        assert_eq!(cfg.required_for(3), 2, "3 members");
        // 5 × 0.4 = 2.0 → ceil 2; max(2, 2) = 2
        assert_eq!(cfg.required_for(5), 2, "5 members");
        // 6 × 0.4 = 2.4 → ceil 3; max(2, 3) = 3
        assert_eq!(cfg.required_for(6), 3, "6 members");
        // 10 × 0.4 = 4.0 → ceil 4; max(2, 4) = 4
        assert_eq!(cfg.required_for(10), 4, "10 members");
    }

    #[test]
    fn required_for_singleton_is_zero() {
        let cfg = QuorumConfig::default();
        assert_eq!(cfg.required_for(0), 0);
        assert_eq!(cfg.required_for(1), 0);
    }

    #[test]
    fn required_for_respects_group_min_bump() {
        let cfg = QuorumConfig {
            group_pct: 0.1,
            group_min: 3,
            ..QuorumConfig::default()
        };
        // 5 × 0.1 = 0.5 → ceil 1; max(3, 1) = 3
        assert_eq!(cfg.required_for(5), 3);
    }
}
