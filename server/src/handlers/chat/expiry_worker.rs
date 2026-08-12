//! Background expiry sweeper for the clean-chat protocol.
//!
//! Two clean-chat work families terminalize on a deterministic deadline that no
//! client request is guaranteed to reach:
//!
//!   * an OPEN `chat.leaf_recovery_requests` row past its `expires_at` (~5 min
//!     TTL) — it holds a `chat.key_package_reservations` row, and therefore a
//!     reserved key package, and blocks the owner's re-request through the
//!     partial unique index `leaf_recovery_requests_one_open_uq`; and
//!   * a PENDING `chat.welcome_deliveries` row past the `not_after` of the Add
//!     KeyPackage it consumed — it holds the recipient's reserved key package and
//!     never produces the `welcomeExpired` recovery-work item the recipient needs
//!     to be re-added.
//!
//! Both are cleared today only as a side effect of some other member's
//! coordinate-changing transition (or, for both, by the owner's own next signed
//! request, which self-heals via the `PendingDue` / `OpenDue` classifications).
//! On a quiet conversation neither happens. This worker is the missing
//! server-side driver.
//!
//! It is NOT a sweeper for leave or reset requests: no expiry authority exists
//! for those families at all (see the module comment in
//! `chat_protocol::repository::expiry_sweep`).
//!
//! ## Cutover gate
//!
//! The whole `blue.catbird.chat.*` surface must stay completely inert while
//! `CHAT_CUTOVER_ENABLED` is off — that property is the basis for deploying this
//! code dark. A background worker that touched `chat.*` unconditionally would
//! break it, so the gate is enforced twice:
//!
//!   1. `main.rs` only spawns this task when `ChatRuntime::cutover_enabled()` is
//!      true; when it is false the task is never created and no timer exists.
//!   2. [`run_chat_expiry_sweeper`] re-checks the same flag on the runtime it was
//!      handed and returns before constructing its interval or touching the pool,
//!      so even a caller that spawns it unconditionally performs zero `chat.*`
//!      access.
//!
//! Neither check reads the environment again: both consume the single
//! process-wide `ChatRuntime` value built once at startup.

use std::{sync::Arc, time::Duration};

use tokio::time::interval;

use super::runtime::ChatRuntime;
use crate::chat_protocol::repository::expiry_sweep::{
    due_leaf_recovery_targets, due_welcome_delivery_targets, sweep_one_welcome, WelcomeSweepOutcome,
};
use crate::handlers::chat::recovery_scheduler::{expire_one, RecoveryExpiryServiceOutcome};
use crate::storage::DbPool;

/// Default sweep period.
///
/// The shortest real TTL this worker can act on is the leaf-recovery request's
/// (~5 minutes), and a due recovery request pins a key package for its whole
/// overdue window. Key-package exhaustion is an observed live failure mode, so
/// the extra hold time the sweep adds is the quantity worth bounding: at 60s the
/// worst case is `TTL + 60s`, a 20% overshoot on the 5-minute family and
/// negligible on the Welcome family (whose `expires_at` is the consumed
/// KeyPackage `not_after`, at least 600s out and typically ~24h). The cost of the
/// period is two indexed reads per cycle when nothing is due, so a shorter period
/// would buy little and a longer one would leave the tightest family overdue for
/// a multiple of its own TTL.
const DEFAULT_SWEEP_INTERVAL_SECS: u64 = 60;

/// Default maximum rows attempted per family per cycle. Bounds one cycle's
/// transaction count; anything not reached is picked up next cycle in the same
/// deterministic `(expires_at, id)` order.
const DEFAULT_SWEEP_BATCH: i64 = 128;

/// Sweep cadence and batch size, read once at worker start.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChatExpirySweepConfig {
    pub interval_secs: u64,
    pub batch: i64,
}

impl Default for ChatExpirySweepConfig {
    fn default() -> Self {
        Self {
            interval_secs: DEFAULT_SWEEP_INTERVAL_SECS,
            batch: DEFAULT_SWEEP_BATCH,
        }
    }
}

impl ChatExpirySweepConfig {
    /// Read the cadence from the process environment, falling back to the
    /// documented default for any missing, unparseable, or non-positive value.
    pub fn from_env() -> Self {
        let defaults = Self::default();
        Self {
            interval_secs: std::env::var("CHAT_EXPIRY_SWEEP_INTERVAL_SECS")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|value| *value > 0)
                .unwrap_or(defaults.interval_secs),
            batch: std::env::var("CHAT_EXPIRY_SWEEP_BATCH")
                .ok()
                .and_then(|value| value.parse::<i64>().ok())
                .filter(|value| *value > 0)
                .unwrap_or(defaults.batch),
        }
    }
}

/// Per-cycle tallies, emitted as one structured log line per cycle.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct SweepCycleCounts {
    pub(crate) recovery_due: usize,
    pub(crate) recovery_expired: usize,
    pub(crate) recovery_retained: usize,
    pub(crate) recovery_errors: usize,
    pub(crate) welcome_due: usize,
    pub(crate) welcome_expired: usize,
    pub(crate) welcome_skipped: usize,
    pub(crate) welcome_errors: usize,
}

impl SweepCycleCounts {
    fn swept_anything(&self) -> bool {
        self.recovery_due > 0 || self.welcome_due > 0
    }

    fn had_errors(&self) -> bool {
        self.recovery_errors > 0 || self.welcome_errors > 0
    }
}

/// Run the clean-chat expiry sweeper until the process exits.
///
/// Returns immediately — before creating a timer and before any database access
/// — when the cutover gate is off. Every per-row failure is logged and counted;
/// no error path can end the loop, because an expiry worker that dies silently is
/// worse than none.
pub async fn run_chat_expiry_sweeper(pool: DbPool, runtime: Arc<ChatRuntime>) {
    if !runtime.cutover_enabled() {
        tracing::info!(
            "clean-chat expiry sweeper not running: CHAT_CUTOVER_ENABLED is off (no chat.* access)"
        );
        return;
    }
    let config = ChatExpirySweepConfig::from_env();
    tracing::info!(
        interval_secs = config.interval_secs,
        batch = config.batch,
        "clean-chat expiry sweeper started"
    );

    let mut timer = interval(Duration::from_secs(config.interval_secs));
    loop {
        timer.tick().await;
        let counts = run_sweep_cycle(&pool, config).await;
        if counts.had_errors() {
            tracing::warn!(
                recovery_due = counts.recovery_due,
                recovery_expired = counts.recovery_expired,
                recovery_retained = counts.recovery_retained,
                recovery_errors = counts.recovery_errors,
                welcome_due = counts.welcome_due,
                welcome_expired = counts.welcome_expired,
                welcome_skipped = counts.welcome_skipped,
                welcome_errors = counts.welcome_errors,
                "clean-chat expiry sweep cycle completed with errors"
            );
        } else if counts.swept_anything() {
            tracing::info!(
                recovery_due = counts.recovery_due,
                recovery_expired = counts.recovery_expired,
                recovery_retained = counts.recovery_retained,
                welcome_due = counts.welcome_due,
                welcome_expired = counts.welcome_expired,
                welcome_skipped = counts.welcome_skipped,
                "clean-chat expiry sweep cycle completed"
            );
        } else {
            tracing::debug!("clean-chat expiry sweep cycle found nothing due");
        }
    }
}

/// One sweep cycle: enumerate the due rows of both families, then terminalize
/// each in its own transaction. A failure on one row never aborts the cycle.
pub(crate) async fn run_sweep_cycle(
    pool: &DbPool,
    config: ChatExpirySweepConfig,
) -> SweepCycleCounts {
    let mut counts = SweepCycleCounts::default();

    match due_leaf_recovery_targets(pool, config.batch).await {
        Ok(due) => {
            counts.recovery_due = due.len();
            for request in due {
                match expire_one(pool, request.recovery_request_id).await {
                    Ok(RecoveryExpiryServiceOutcome::Applied) => {
                        counts.recovery_expired += 1;
                        tracing::info!(
                            recovery_request_id = %request.recovery_request_id,
                            conversation_id = %request.conversation_id,
                            expires_at = %request.expires_at,
                            "clean-chat expiry sweeper expired an overdue leaf-recovery request"
                        );
                    }
                    Ok(RecoveryExpiryServiceOutcome::RetainedTerminal) => {
                        counts.recovery_retained += 1;
                    }
                    Err(error) => {
                        counts.recovery_errors += 1;
                        tracing::warn!(
                            recovery_request_id = %request.recovery_request_id,
                            conversation_id = %request.conversation_id,
                            error = ?error,
                            "clean-chat expiry sweeper could not expire a leaf-recovery request"
                        );
                    }
                }
            }
        }
        Err(error) => {
            counts.recovery_errors += 1;
            tracing::warn!(
                error = ?error,
                "clean-chat expiry sweeper could not enumerate due leaf-recovery requests"
            );
        }
    }

    match due_welcome_delivery_targets(pool, config.batch).await {
        Ok(due) => {
            counts.welcome_due = due.len();
            for (conversation_id, welcome_id, expires_at) in due {
                match sweep_one_welcome(pool, conversation_id, welcome_id).await {
                    Ok(WelcomeSweepOutcome::Expired) => {
                        counts.welcome_expired += 1;
                        tracing::info!(
                            welcome_id = %welcome_id,
                            conversation_id = %conversation_id,
                            expires_at = %expires_at,
                            "clean-chat expiry sweeper expired an overdue Welcome delivery"
                        );
                    }
                    Ok(outcome) => {
                        counts.welcome_skipped += 1;
                        tracing::debug!(
                            welcome_id = %welcome_id,
                            conversation_id = %conversation_id,
                            outcome = ?outcome,
                            "clean-chat expiry sweeper skipped a Welcome delivery"
                        );
                    }
                    Err(error) => {
                        counts.welcome_errors += 1;
                        tracing::warn!(
                            welcome_id = %welcome_id,
                            conversation_id = %conversation_id,
                            error = ?error,
                            "clean-chat expiry sweeper could not expire a Welcome delivery"
                        );
                    }
                }
            }
        }
        Err(error) => {
            counts.welcome_errors += 1;
            tracing::warn!(
                error = ?error,
                "clean-chat expiry sweeper could not enumerate due Welcome deliveries"
            );
        }
    }

    counts
}
