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

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
};

const DEFAULT_SERVER_HOST: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
const DEFAULT_SERVER_PORT: u16 = 8080;

/// Validated address on which the HTTP server listens.
///
/// `SERVER_HOST` deliberately accepts only an IP literal. This keeps startup
/// deterministic and prevents a hostname typo or DNS result from silently
/// widening the listener's network exposure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerBindConfig {
    host: IpAddr,
    port: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidServerHost;

impl fmt::Display for InvalidServerHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SERVER_HOST must be a valid IP address")
    }
}

impl std::error::Error for InvalidServerHost {}

impl ServerBindConfig {
    /// Load the bind address without falling back when `SERVER_HOST` is
    /// present but invalid. An absent host preserves the historical
    /// all-interfaces production default.
    pub fn from_env() -> Result<Self, InvalidServerHost> {
        Self::from_env_values(std::env::var("SERVER_HOST"), std::env::var("SERVER_PORT"))
    }

    fn from_env_values(
        host: Result<String, std::env::VarError>,
        port: Result<String, std::env::VarError>,
    ) -> Result<Self, InvalidServerHost> {
        let host = match host {
            Ok(host) => host.trim().parse().map_err(|_| InvalidServerHost)?,
            Err(std::env::VarError::NotPresent) => DEFAULT_SERVER_HOST,
            Err(std::env::VarError::NotUnicode(_)) => return Err(InvalidServerHost),
        };
        // Preserve the existing SERVER_PORT behavior: absent or malformed
        // values use 8080. This package only tightens host binding.
        let port = port
            .ok()
            .and_then(|port| port.trim().parse::<u16>().ok())
            .unwrap_or(DEFAULT_SERVER_PORT);

        Ok(Self { host, port })
    }

    pub fn socket_addr(self) -> SocketAddr {
        SocketAddr::new(self.host, self.port)
    }
}

/// Rollout posture for authenticated MLS devices.
///
/// This type only describes policy. Transition handlers remain unchanged
/// until the coordinator wires the shared enforcement gate in a later package.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceAuthMode {
    Observe,
    Enroll,
    Require,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidDeviceAuthMode;

impl fmt::Display for InvalidDeviceAuthMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DEVICE_AUTH_MODE must be observe, enroll, or require")
    }
}

impl std::error::Error for InvalidDeviceAuthMode {}

impl FromStr for DeviceAuthMode {
    type Err = InvalidDeviceAuthMode;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "observe" => Ok(Self::Observe),
            "enroll" => Ok(Self::Enroll),
            "require" => Ok(Self::Require),
            _ => Err(InvalidDeviceAuthMode),
        }
    }
}

impl DeviceAuthMode {
    /// Load the rollout mode without silently weakening an invalid value.
    pub fn from_env() -> Result<Self, InvalidDeviceAuthMode> {
        Self::from_env_result(std::env::var("DEVICE_AUTH_MODE"))
    }

    fn from_env_result(
        value: Result<String, std::env::VarError>,
    ) -> Result<Self, InvalidDeviceAuthMode> {
        match value {
            Ok(value) => value.parse(),
            Err(std::env::VarError::NotPresent) => Ok(Self::Observe),
            Err(std::env::VarError::NotUnicode(_)) => Err(InvalidDeviceAuthMode),
        }
    }

    pub const fn action_for(self, class: DeviceAuthEndpointClass) -> DeviceAuthPolicyAction {
        use DeviceAuthEndpointClass::{Bootstrap, Canary, Enrollment, Mutation, Read};
        use DeviceAuthPolicyAction::{Allow, EnforceEnrollment, ObserveWouldDeny, RequireBinding};

        match (self, class) {
            (_, Enrollment) => EnforceEnrollment,
            (_, Bootstrap | Read) => Allow,
            (Self::Observe, Canary | Mutation) => ObserveWouldDeny,
            (Self::Enroll, Canary) | (Self::Require, Canary | Mutation) => RequireBinding,
            (Self::Enroll, Mutation) => Allow,
        }
    }

    /// Classify an exact NSID and select its policy. Unknown endpoints return
    /// an error so callers cannot accidentally treat new mutations as reads.
    pub fn action_for_nsid(
        self,
        nsid: &str,
    ) -> Result<DeviceAuthPolicyAction, UnknownDeviceAuthEndpoint> {
        classify_device_auth_endpoint(nsid)
            .map(|class| self.action_for(class))
            .ok_or(UnknownDeviceAuthEndpoint)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceAuthEndpointClass {
    Enrollment,
    Bootstrap,
    Read,
    Canary,
    Mutation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceAuthPolicyAction {
    Allow,
    EnforceEnrollment,
    ObserveWouldDeny,
    RequireBinding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnknownDeviceAuthEndpoint;

impl fmt::Display for UnknownDeviceAuthEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("unknown device-auth endpoint")
    }
}

impl std::error::Error for UnknownDeviceAuthEndpoint {}

/// Closed, exact classifier for MLS-chat endpoints. Deliberately avoid
/// prefix/suffix matching: a newly added endpoint must receive an explicit
/// rollout class before it can pass the shared policy gate.
pub fn classify_device_auth_endpoint(nsid: &str) -> Option<DeviceAuthEndpointClass> {
    use DeviceAuthEndpointClass::{Bootstrap, Canary, Enrollment, Mutation, Read};

    Some(match nsid {
        // Enrollment
        "blue.catbird.chat.enrollDevice" => Enrollment,

        // Bootstrap
        "blue.catbird.chat.replenishKeyPackages" => Bootstrap,

        // Read
        "blue.catbird.chat.getBlob"
        | "blue.catbird.chat.getBlobUsage"
        | "blue.catbird.chat.getConversationState"
        | "blue.catbird.chat.getConversations"
        | "blue.catbird.chat.getDevices"
        | "blue.catbird.chat.getEntries"
        | "blue.catbird.chat.getLeafRecoveryInbox"
        | "blue.catbird.chat.getOwnDevices"
        | "blue.catbird.chat.getPendingWelcomes"
        | "blue.catbird.chat.getSubscriptionTicket"
        | "blue.catbird.chat.subscribeEvents" => Read,

        // Canary
        "blue.catbird.chat.publishTyping" => Canary,

        // Mutation
        "blue.catbird.chat.acceptConversation"
        | "blue.catbird.chat.acknowledgeWelcome"
        | "blue.catbird.chat.activateReset"
        | "blue.catbird.chat.cancelLeafRecovery"
        | "blue.catbird.chat.cancelLeave"
        | "blue.catbird.chat.closeConversation"
        | "blue.catbird.chat.createConversation"
        | "blue.catbird.chat.deleteBlob"
        | "blue.catbird.chat.prepareBlobUpload"
        | "blue.catbird.chat.rejectWelcome"
        | "blue.catbird.chat.reportRecoveryFailure"
        | "blue.catbird.chat.requestLeafRecovery"
        | "blue.catbird.chat.requestLeave"
        | "blue.catbird.chat.requestReset"
        | "blue.catbird.chat.revokeDevice"
        | "blue.catbird.chat.sendMessage"
        | "blue.catbird.chat.submitTransition"
        | "blue.catbird.chat.updatePushToken"
        | "blue.catbird.chat.uploadBlob" => Mutation,
        _ => return None,
    })
}

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

/// Phase 2 (Stage 4) — server-side sweep configuration.
///
/// Drives [`crate::jobs::auto_detect_failed_groups::run_failed_group_sweep`].
/// The sweep periodically scans `conversations` for groups whose commit-health
/// metrics indicate operational death (high recent 409 count, no successful
/// commit for an hour, large gap between current_epoch and group_info_epoch)
/// and dispatches `ConvoMessage::TriggerSystemReset` to the responsible
/// actor.
///
/// All values come from environment variables with the names documented on
/// each field; missing/invalid values fall back to the defaults set in
/// [`SweepConfig::default`], which match the spec § "Configuration & Thresholds".
#[derive(Clone, Debug, PartialEq)]
pub struct SweepConfig {
    /// `SWEEP_INTERVAL_SECS` — how often the sweep loop runs (default 300 = 5 min).
    pub sweep_interval_secs: u64,
    /// `MAX_ECOMMIT_STALENESS_EPOCHS` — minimum gap between
    /// `current_epoch` and `group_info_epoch` before a convo is considered
    /// stale (default 200).
    pub max_ecommit_staleness_epochs: i64,
    /// `MIN_QUIET_PERIOD_SECS` — minimum seconds since
    /// `last_successful_commit_at` (default 3600 = 1 h).
    pub min_quiet_period_secs: i64,
    /// `MIN_409_THRESHOLD` — minimum value of `recent_commit_409_count`
    /// (default 10).
    pub min_409_threshold: i32,
    /// `RECENT_409_WINDOW_SECS` — `last_commit_409_at` must be within this
    /// window for the failure to count as "current" (default 1800 = 30 min).
    pub recent_409_window_secs: i64,
    /// `MIN_RESET_GAP_SECS` — refuse to sweep-reset a convo whose
    /// `last_reset_at` is more recent than this (default 3600 = 1 h).
    pub min_reset_gap_secs: i64,
    /// `MODE_A_EXCLUSION_WINDOW_SECS` — if a Mode A (`local_state_loss`)
    /// reset_vote was recorded for the convo within this window, defer to
    /// the client-quorum path (default 300 = 5 min).
    pub mode_a_exclusion_window_secs: i64,
    /// Phase 2 B10: minimum value of `recent_groupinfo_404_count` (default
    /// 5). Used by the SECOND sweep predicate that catches the
    /// "GroupInfo missing" failure mode — convos broken in the way that
    /// keeps clients stuck at `getGroupInfo → 404`, never reaching
    /// `commitGroupChange → 409`. Without this trigger, such convos are
    /// invisible to the original 409-only sweep no matter how long they
    /// stay broken. Default tuned slightly higher than `min_409_threshold`
    /// because get_group_state is called more frequently per recovery
    /// attempt than commitGroupChange.
    pub min_groupinfo_404_threshold: i32,
    /// Phase 2 B10: window (seconds) within which `last_groupinfo_404_at`
    /// must fall for the GroupInfo-missing predicate to qualify a convo
    /// (default 1800 = 30 min). Same recency-check semantics as
    /// `recent_409_window_secs` — prevents the sweep from chasing
    /// historical lifetime accumulation on convos that recovered.
    pub recent_groupinfo_404_window_secs: i64,
}

impl Default for SweepConfig {
    fn default() -> Self {
        Self {
            sweep_interval_secs: 300,
            max_ecommit_staleness_epochs: 200,
            min_quiet_period_secs: 3600,
            min_409_threshold: 10,
            recent_409_window_secs: 1800,
            min_reset_gap_secs: 3600,
            mode_a_exclusion_window_secs: 300,
            min_groupinfo_404_threshold: 5,
            recent_groupinfo_404_window_secs: 1800,
        }
    }
}

impl SweepConfig {
    /// Read the sweep config from process environment, applying defaults for
    /// any missing/invalid value. Each variable matches the name documented
    /// on the corresponding field.
    pub fn from_env() -> Self {
        let defaults = Self::default();
        Self {
            sweep_interval_secs: parse_env_u64("SWEEP_INTERVAL_SECS", defaults.sweep_interval_secs),
            max_ecommit_staleness_epochs: parse_env_i64_positive(
                "MAX_ECOMMIT_STALENESS_EPOCHS",
                defaults.max_ecommit_staleness_epochs,
            ),
            min_quiet_period_secs: parse_env_i64_positive(
                "MIN_QUIET_PERIOD_SECS",
                defaults.min_quiet_period_secs,
            ),
            min_409_threshold: parse_env_i32_positive(
                "MIN_409_THRESHOLD",
                defaults.min_409_threshold,
            ),
            recent_409_window_secs: parse_env_i64_positive(
                "RECENT_409_WINDOW_SECS",
                defaults.recent_409_window_secs,
            ),
            min_reset_gap_secs: parse_env_i64_positive(
                "MIN_RESET_GAP_SECS",
                defaults.min_reset_gap_secs,
            ),
            mode_a_exclusion_window_secs: parse_env_i64_positive(
                "MODE_A_EXCLUSION_WINDOW_SECS",
                defaults.mode_a_exclusion_window_secs,
            ),
            min_groupinfo_404_threshold: parse_env_i32_positive(
                "MIN_GROUPINFO_404_THRESHOLD",
                defaults.min_groupinfo_404_threshold,
            ),
            recent_groupinfo_404_window_secs: parse_env_i64_positive(
                "RECENT_GROUPINFO_404_WINDOW_SECS",
                defaults.recent_groupinfo_404_window_secs,
            ),
        }
    }

    /// Test-only constructor returning the spec defaults verbatim. Lets test
    /// authors construct a `SweepConfig` without depending on env state.
    /// Not gated on `cfg(test)` so integration tests in `tests/` can call it.
    pub fn test_defaults() -> Self {
        Self::default()
    }
}

/// Phase 2 (B5) — event-driven inline trigger configuration.
///
/// Drives the post-409 fast path in
/// `crate::jobs::auto_detect_failed_groups::record_commit_409_with_inline_trigger`.
/// Detection latency from this path is ~one DB round-trip — independent of
/// `SweepConfig::sweep_interval_secs` — so the threshold can be tighter than
/// the sweep's `min_409_threshold` without inflating risk: the actor's own
/// cooldown gate (`last_reset_at < 1h`) and circuit breaker
/// (`auto_reset_disabled_at`) idempotently reject duplicate dispatches.
///
/// The sweep stays running as a safety net for convos that crossed the
/// inline threshold while the actor was unreachable, server was restarting,
/// or pre-existing rows that already crossed before this code shipped.
#[derive(Clone, Debug, PartialEq)]
pub struct InlineTriggerConfig {
    /// `INLINE_409_THRESHOLD` — minimum value of `recent_commit_409_count`
    /// after a single 409-bump that triggers an inline `TriggerSystemReset`
    /// dispatch (default 3). Tighter than `SweepConfig::min_409_threshold`
    /// because inline fires *during* a failure burst and we want sub-second
    /// detection. Idempotency guarantees in the actor handler make repeated
    /// dispatches safe.
    pub min_409_threshold: i32,
    /// `INLINE_TRIGGER_RESET_COOLDOWN_SECS` — refuse to inline-dispatch on a
    /// convo whose `last_reset_at` is more recent than this (default 3600 = 1
    /// h). Defense in depth — actor handler also enforces a 1h cooldown gate
    /// — but cuts wasted actor-mailbox traffic during a sustained 409 burst
    /// after a successful auto-reset.
    pub reset_cooldown_secs: i64,
    /// Phase 2 B10: `INLINE_GROUPINFO_404_THRESHOLD` — minimum value of
    /// `recent_groupinfo_404_count` after a single 404-bump that triggers
    /// an inline `TriggerSystemReset` dispatch (default 3). Mirrors
    /// `min_409_threshold` for the GroupInfo-missing failure mode that the
    /// 409-only inline path can't see (clients stuck at `getGroupInfo →
    /// 404` never reach `commitGroupChange`). Same actor-side idempotency
    /// (cooldown + circuit breaker) makes repeated dispatches safe.
    pub min_groupinfo_404_threshold: i32,
}

impl Default for InlineTriggerConfig {
    fn default() -> Self {
        Self {
            min_409_threshold: 3,
            reset_cooldown_secs: 3600,
            min_groupinfo_404_threshold: 3,
        }
    }
}

impl InlineTriggerConfig {
    /// Read the inline-trigger config from process environment, applying
    /// defaults for any missing/invalid value.
    pub fn from_env() -> Self {
        let defaults = Self::default();
        Self {
            min_409_threshold: parse_env_i32_positive(
                "INLINE_409_THRESHOLD",
                defaults.min_409_threshold,
            ),
            reset_cooldown_secs: parse_env_i64_positive(
                "INLINE_TRIGGER_RESET_COOLDOWN_SECS",
                defaults.reset_cooldown_secs,
            ),
            min_groupinfo_404_threshold: parse_env_i32_positive(
                "INLINE_GROUPINFO_404_THRESHOLD",
                defaults.min_groupinfo_404_threshold,
            ),
        }
    }

    /// Test-only constructor returning the spec defaults verbatim.
    pub fn test_defaults() -> Self {
        Self::default()
    }
}

fn parse_env_i64_positive(name: &str, default: i64) -> i64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
}

fn parse_env_i32_positive(name: &str, default: i32) -> i32 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<i32>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
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
    fn server_bind_defaults_to_all_interfaces_for_compatibility() {
        let config = ServerBindConfig::from_env_values(
            Err(std::env::VarError::NotPresent),
            Err(std::env::VarError::NotPresent),
        )
        .expect("missing SERVER_HOST must use the production-compatible default");

        assert_eq!(config.host, "0.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(config.port, 8080);
    }

    #[test]
    fn server_bind_accepts_explicit_loopback_ip() {
        let config =
            ServerBindConfig::from_env_values(Ok("127.0.0.1".to_owned()), Ok("3011".to_owned()))
                .expect("staging loopback address must parse");

        assert_eq!(config.host, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(config.port, 3011);
    }

    #[test]
    fn server_bind_trims_operator_whitespace() {
        let config = ServerBindConfig::from_env_values(
            Ok(" 127.0.0.1\n".to_owned()),
            Ok(" 3011\t".to_owned()),
        )
        .expect("operator whitespace must not change the configured bind address");

        assert_eq!(config.host, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(config.port, 3011);
    }

    #[test]
    fn server_bind_rejects_hostnames_instead_of_resolving_them() {
        let result = ServerBindConfig::from_env_values(
            Ok("localhost".to_owned()),
            Err(std::env::VarError::NotPresent),
        );

        assert_eq!(result, Err(InvalidServerHost));
    }

    #[cfg(unix)]
    #[test]
    fn server_bind_rejects_non_unicode_host() {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};

        let result = ServerBindConfig::from_env_values(
            Err(std::env::VarError::NotUnicode(OsString::from_vec(vec![
                0xff,
            ]))),
            Err(std::env::VarError::NotPresent),
        );

        assert_eq!(result, Err(InvalidServerHost));
    }

    #[cfg(unix)]
    #[test]
    fn non_unicode_device_auth_mode_is_rejected() {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};

        assert_eq!(
            DeviceAuthMode::from_env_result(Err(std::env::VarError::NotUnicode(
                OsString::from_vec(vec![0xff]),
            ))),
            Err(InvalidDeviceAuthMode)
        );
    }

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
