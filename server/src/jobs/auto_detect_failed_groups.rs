//! Phase 2 (Stage 4) — Path B server-observed sweep.
//!
//! Periodically scans `conversations` for groups whose commit-health
//! metrics indicate operational death and dispatches
//! [`ConvoMessage::TriggerSystemReset`] to the responsible actor. This is
//! the "no client is online to vote" path; the "client-quorum" path lives
//! in `ConversationActor::handle_record_reset_vote`.
//!
//! See:
//!   - Spec: `docs/superpowers/specs/2026-04-26-mls-auto-reset-phase2-design.md`
//!     § "Detection Design → Path B: Server-observed sweep"
//!   - Plan: `docs/superpowers/plans/2026-04-26-mls-auto-reset-phase2.md`
//!     (Stage 4, Tasks 11–13)

use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tracing::{error, info, warn};

// Note: this module is dual-mounted (in `lib.rs` and in `main.rs`'s binary
// tree, mirroring `device_utils`). Both the library and the binary expose
// `actors`, `config`, and `crypto` at `crate::*` (the binary `use catbird_server::{...}`s
// them in main.rs to make `crate::actors` etc. resolve), so the imports
// below work identically in both compilation contexts.
use crate::actors::{ActorRegistry, ConvoMessage};
use crate::config::{InlineTriggerConfig, SweepConfig};
use crate::db::{self, CommitHealthSnapshot, DbPool};

/// One row emitted by the sweep query — the minimum fields the actor
/// dispatch needs for telemetry.
#[derive(Debug, sqlx::FromRow)]
struct StaleConvoRow {
    id: String,
    current_epoch: Option<i32>,
    group_info_epoch: Option<i32>,
    last_successful_commit_at: Option<chrono::DateTime<chrono::Utc>>,
    recent_commit_409_count: i32,
}

/// Spawn-and-loop entry point. Used from `main.rs`.
///
/// Runs forever; the inner [`sweep_once`] call performs a single tick.
/// Errors during a tick are logged but do not break the loop — the next
/// tick will retry on the next interval.
pub async fn run_failed_group_sweep(pool: PgPool, registry: Arc<ActorRegistry>, cfg: SweepConfig) {
    let mut ticker = interval(Duration::from_secs(cfg.sweep_interval_secs));
    info!(
        sweep_interval_secs = cfg.sweep_interval_secs,
        max_ecommit_staleness_epochs = cfg.max_ecommit_staleness_epochs,
        min_quiet_period_secs = cfg.min_quiet_period_secs,
        min_409_threshold = cfg.min_409_threshold,
        recent_409_window_secs = cfg.recent_409_window_secs,
        min_reset_gap_secs = cfg.min_reset_gap_secs,
        mode_a_exclusion_window_secs = cfg.mode_a_exclusion_window_secs,
        "Starting auto_detect_failed_groups sweep worker (Phase 2 Path B)"
    );

    loop {
        ticker.tick().await;
        match sweep_once(&pool, &registry, &cfg).await {
            Ok(0) => {
                // Nothing to do — common case, kept at debug to avoid log spam.
                tracing::debug!("sweep tick: no stale groups");
            }
            Ok(n) => {
                info!(dispatched = n, "sweep tick: dispatched system-resets");
            }
            Err(e) => {
                error!(error = %e, "sweep tick failed");
            }
        }
    }
}

/// Single sweep iteration. Returns the number of `TriggerSystemReset`
/// messages dispatched.
///
/// Exposed (non-`pub(crate)`) so integration tests can assert the precise
/// dispatch count without spinning up the full worker loop.
pub async fn sweep_once(
    pool: &PgPool,
    registry: &Arc<ActorRegistry>,
    cfg: &SweepConfig,
) -> anyhow::Result<usize> {
    // The 8 conditions of the spec's Path B query:
    //   1. auto_reset_disabled_at IS NULL          (circuit-breaker not tripped)
    //   2. last_successful_commit_at IS NULL OR quiet duration > min_quiet_period_secs
    //      (B3: NULL means we never saw a successful commit since the Phase 2
    //       schema landed — those convos are the most broken, not the
    //       least; predicate must INCLUDE them, not exclude them)
    //   3. ABS(epoch staleness) > max_ecommit_staleness_epochs
    //      (B4: catches both `current_epoch >> group_info_epoch` (clients ran
    //       ahead via External Commits) AND `group_info_epoch >> current_epoch`
    //       (fresh GroupInfo published but commits never landed) — both are
    //       genuinely-broken states worth resetting)
    //   4. recent_commit_409_count > min_409_threshold
    //   5. last_commit_409_at IS NOT NULL AND within recent_409_window_secs
    //   6. last_reset_at IS NULL OR older than min_reset_gap_secs
    //   7. NOT EXISTS recent Mode A reset_vote   (Mode A exclusion window)
    //
    // `LIMIT 50` keeps a single tick from monopolising the actor mailbox if a
    // mass-failure event lights up many convos at once.
    let rows: Vec<StaleConvoRow> = sqlx::query_as::<_, StaleConvoRow>(
        "SELECT c.id, c.current_epoch, c.group_info_epoch, \
                c.last_successful_commit_at, c.recent_commit_409_count \
         FROM conversations c \
         WHERE c.auto_reset_disabled_at IS NULL \
           AND ABS(c.current_epoch - COALESCE(c.group_info_epoch, 0)) > $1 \
           AND (c.last_successful_commit_at IS NULL \
                OR NOW() - c.last_successful_commit_at > make_interval(secs => $2)) \
           AND c.recent_commit_409_count > $3 \
           AND c.last_commit_409_at IS NOT NULL \
           AND NOW() - c.last_commit_409_at < make_interval(secs => $4) \
           AND (c.last_reset_at IS NULL \
                OR NOW() - c.last_reset_at > make_interval(secs => $5)) \
           AND NOT EXISTS ( \
                SELECT 1 FROM reset_votes rv \
                WHERE rv.convo_id = c.id \
                  AND rv.failure_mode = 'local_state_loss' \
                  AND rv.voted_at > NOW() - make_interval(secs => $6) \
           ) \
         LIMIT 50",
    )
    .bind(cfg.max_ecommit_staleness_epochs)
    .bind(cfg.min_quiet_period_secs as f64)
    .bind(cfg.min_409_threshold)
    .bind(cfg.recent_409_window_secs as f64)
    .bind(cfg.min_reset_gap_secs as f64)
    .bind(cfg.mode_a_exclusion_window_secs as f64)
    .fetch_all(pool)
    .await?;

    if rows.is_empty() {
        return Ok(0);
    }

    let now = chrono::Utc::now();
    let mut dispatched = 0usize;
    for row in rows {
        let staleness_epochs =
            (row.current_epoch.unwrap_or(0) as i64) - (row.group_info_epoch.unwrap_or(0) as i64);
        let quiet_duration_secs = row
            .last_successful_commit_at
            .map(|t| (now - t).num_seconds().max(0))
            .unwrap_or(0);

        let actor_ref = match registry.get_or_spawn(&row.id).await {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    convo_id = %crate::crypto::redact_for_log(&row.id),
                    error = %e,
                    "sweep: failed to spawn actor — skipping convo"
                );
                continue;
            }
        };

        info!(
            convo_id = %crate::crypto::redact_for_log(&row.id),
            staleness_epochs,
            quiet_duration_secs,
            count_409 = row.recent_commit_409_count,
            "sweep: dispatching TriggerSystemReset"
        );

        if let Err(e) = actor_ref.cast(ConvoMessage::TriggerSystemReset {
            reason: "server_sweep".to_string(),
            staleness_epochs,
            quiet_duration_secs,
        }) {
            warn!(
                convo_id = %crate::crypto::redact_for_log(&row.id),
                error = %e,
                "sweep: actor cast failed"
            );
            continue;
        }

        dispatched += 1;
    }

    Ok(dispatched)
}

// ──────────────────────────────────────────────────────────────────────
// Phase 2 (B5) — event-driven inline trigger.
// ──────────────────────────────────────────────────────────────────────

/// Decision returned by [`evaluate_inline_trigger`]. Surfacing the reason
/// (rather than a bare bool) lets the caller log *why* a snapshot did or
/// didn't dispatch — invaluable for prod debugging.
#[derive(Debug, PartialEq)]
pub enum InlineTriggerDecision {
    /// Cross the inline threshold AND none of the gates rejected → dispatch.
    Dispatch,
    /// `recent_commit_409_count` is below `min_409_threshold`.
    BelowThreshold { count: i32, threshold: i32 },
    /// `auto_reset_disabled_at` is set — circuit breaker tripped.
    CircuitBreakerTripped,
    /// `last_reset_at` is more recent than `reset_cooldown_secs`.
    ResetCooldownActive,
}

/// Pure predicate evaluator for the B5 inline trigger.
///
/// Decoupled from any DB or actor I/O so unit tests can exercise the
/// decision matrix without standing up sqlx or ractor. The caller composes:
///   1. Bump the counter via [`crate::db::record_commit_409`].
///   2. Pass the returned snapshot to this function.
///   3. If the result is [`InlineTriggerDecision::Dispatch`], cast
///      `ConvoMessage::TriggerSystemReset` to the convo's actor.
///
/// `now` is parameterised (rather than calling `Utc::now()` internally) so
/// tests can pin time without `tokio::time::pause` setup. Production
/// callers in [`record_commit_409_with_inline_trigger`] always pass
/// `chrono::Utc::now()`.
pub fn evaluate_inline_trigger(
    snapshot: &CommitHealthSnapshot,
    cfg: &InlineTriggerConfig,
    now: chrono::DateTime<chrono::Utc>,
) -> InlineTriggerDecision {
    if snapshot.auto_reset_disabled_at.is_some() {
        return InlineTriggerDecision::CircuitBreakerTripped;
    }
    if snapshot.recent_commit_409_count < cfg.min_409_threshold {
        return InlineTriggerDecision::BelowThreshold {
            count: snapshot.recent_commit_409_count,
            threshold: cfg.min_409_threshold,
        };
    }
    if let Some(last_reset) = snapshot.last_reset_at {
        let cooldown = chrono::Duration::seconds(cfg.reset_cooldown_secs);
        if now - last_reset < cooldown {
            return InlineTriggerDecision::ResetCooldownActive;
        }
    }
    InlineTriggerDecision::Dispatch
}

/// Bump the convo's 409 counter AND, on the same code path, evaluate the
/// inline-trigger predicate. If satisfied, immediately dispatch
/// `ConvoMessage::TriggerSystemReset { reason: "inline_409_threshold" }`
/// to the convo's actor — eliminating the up-to-`SWEEP_INTERVAL_SECS`
/// detection latency the periodic sweep would otherwise impose.
///
/// Failures of the underlying counter UPDATE propagate as `Err`. Failures
/// of the actor dispatch are logged but do NOT propagate — a missed inline
/// dispatch will be retried on the next 409, and the periodic sweep
/// remains as a safety net regardless. The 409 response to the client is
/// the contract; instrumentation must never mask it (callers should still
/// `let _ = ... .map_err(|e| warn!(...))` the returned `Result`).
///
/// Idempotency: the actor's `handle_trigger_system_reset` enforces both
/// the per-convo `last_reset_at < 1h` cooldown and the
/// `auto_reset_disabled_at` circuit breaker. Repeated dispatches during a
/// 409 burst are therefore safe — the actor short-circuits each one.
pub async fn record_commit_409_with_inline_trigger(
    pool: &DbPool,
    registry: &Arc<ActorRegistry>,
    convo_id: &str,
    cfg: &InlineTriggerConfig,
) -> anyhow::Result<()> {
    let snapshot = db::record_commit_409(pool, convo_id).await?;

    match evaluate_inline_trigger(&snapshot, cfg, chrono::Utc::now()) {
        InlineTriggerDecision::Dispatch => {
            info!(
                convo_id = %crate::crypto::redact_for_log(convo_id),
                count_409 = snapshot.recent_commit_409_count,
                threshold = cfg.min_409_threshold,
                "inline-trigger: dispatching TriggerSystemReset"
            );
            let actor_ref = match registry.get_or_spawn(convo_id).await {
                Ok(r) => r,
                Err(e) => {
                    warn!(
                        convo_id = %crate::crypto::redact_for_log(convo_id),
                        error = %e,
                        "inline-trigger: failed to spawn actor — skipping (sweep will catch on next tick)"
                    );
                    return Ok(());
                }
            };
            if let Err(e) = actor_ref.cast(ConvoMessage::TriggerSystemReset {
                reason: "inline_409_threshold".to_string(),
                staleness_epochs: 0,
                quiet_duration_secs: 0,
            }) {
                warn!(
                    convo_id = %crate::crypto::redact_for_log(convo_id),
                    error = %e,
                    "inline-trigger: actor cast failed — non-fatal, sweep will retry"
                );
            }
        }
        InlineTriggerDecision::BelowThreshold { count, threshold } => {
            tracing::debug!(
                convo_id = %crate::crypto::redact_for_log(convo_id),
                count,
                threshold,
                "inline-trigger: below threshold — counter bumped only"
            );
        }
        InlineTriggerDecision::CircuitBreakerTripped => {
            tracing::debug!(
                convo_id = %crate::crypto::redact_for_log(convo_id),
                "inline-trigger: auto_reset_disabled_at set — skipping"
            );
        }
        InlineTriggerDecision::ResetCooldownActive => {
            tracing::debug!(
                convo_id = %crate::crypto::redact_for_log(convo_id),
                "inline-trigger: recent reset cooldown active — skipping"
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod inline_trigger_tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn snap(
        count: i32,
        last_reset: Option<chrono::DateTime<chrono::Utc>>,
        disabled: bool,
    ) -> CommitHealthSnapshot {
        CommitHealthSnapshot {
            recent_commit_409_count: count,
            last_reset_at: last_reset,
            auto_reset_disabled_at: if disabled {
                Some(chrono::Utc::now())
            } else {
                None
            },
        }
    }

    fn cfg(threshold: i32, cooldown: i64) -> InlineTriggerConfig {
        InlineTriggerConfig {
            min_409_threshold: threshold,
            reset_cooldown_secs: cooldown,
        }
    }

    #[test]
    fn dispatches_when_threshold_crossed_and_no_gates() {
        let now = Utc.with_ymd_and_hms(2026, 4, 26, 18, 0, 0).unwrap();
        let s = snap(3, None, false);
        let c = cfg(3, 3600);
        assert_eq!(
            evaluate_inline_trigger(&s, &c, now),
            InlineTriggerDecision::Dispatch
        );
    }

    #[test]
    fn does_not_dispatch_below_threshold() {
        let now = Utc.with_ymd_and_hms(2026, 4, 26, 18, 0, 0).unwrap();
        let s = snap(2, None, false);
        let c = cfg(3, 3600);
        assert_eq!(
            evaluate_inline_trigger(&s, &c, now),
            InlineTriggerDecision::BelowThreshold {
                count: 2,
                threshold: 3
            }
        );
    }

    #[test]
    fn does_not_dispatch_when_circuit_breaker_tripped() {
        // Circuit breaker takes precedence over threshold check — even a
        // count of 1000 must not dispatch when the convo is disabled.
        let now = Utc.with_ymd_and_hms(2026, 4, 26, 18, 0, 0).unwrap();
        let s = snap(1000, None, true);
        let c = cfg(3, 3600);
        assert_eq!(
            evaluate_inline_trigger(&s, &c, now),
            InlineTriggerDecision::CircuitBreakerTripped
        );
    }

    #[test]
    fn does_not_dispatch_within_reset_cooldown() {
        // Reset 30 min ago, cooldown is 1h — must skip.
        let now = Utc.with_ymd_and_hms(2026, 4, 26, 18, 0, 0).unwrap();
        let last_reset = now - chrono::Duration::minutes(30);
        let s = snap(10, Some(last_reset), false);
        let c = cfg(3, 3600);
        assert_eq!(
            evaluate_inline_trigger(&s, &c, now),
            InlineTriggerDecision::ResetCooldownActive
        );
    }

    #[test]
    fn dispatches_when_reset_cooldown_expired() {
        // Reset 90 min ago, cooldown is 1h — eligible again.
        let now = Utc.with_ymd_and_hms(2026, 4, 26, 18, 0, 0).unwrap();
        let last_reset = now - chrono::Duration::minutes(90);
        let s = snap(10, Some(last_reset), false);
        let c = cfg(3, 3600);
        assert_eq!(
            evaluate_inline_trigger(&s, &c, now),
            InlineTriggerDecision::Dispatch
        );
    }

    #[test]
    fn dispatches_when_no_prior_reset_recorded() {
        // last_reset_at = NULL is the steady-state for never-reset convos.
        // Must not be conflated with "recently reset".
        let now = Utc.with_ymd_and_hms(2026, 4, 26, 18, 0, 0).unwrap();
        let s = snap(5, None, false);
        let c = cfg(3, 3600);
        assert_eq!(
            evaluate_inline_trigger(&s, &c, now),
            InlineTriggerDecision::Dispatch
        );
    }
}
