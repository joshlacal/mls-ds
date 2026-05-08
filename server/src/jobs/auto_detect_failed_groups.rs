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
use crate::db::{self, CommitHealthSnapshot, DbPool, GroupInfoHealthSnapshot};

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

/// Phase 2 B10: row emitted by the GroupInfo-missing sweep. Different
/// shape from `StaleConvoRow` because the failure signal here is
/// `recent_groupinfo_404_count` rather than 409 count, and the convo's
/// epoch fields are not necessarily diagnostic — what matters is that
/// `group_info` is NULL and clients are still trying.
#[derive(Debug, sqlx::FromRow)]
struct GroupInfoMissingRow {
    id: String,
    recent_groupinfo_404_count: i32,
    current_epoch: Option<i32>,
    group_info_epoch: Option<i32>,
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
        min_groupinfo_404_threshold = cfg.min_groupinfo_404_threshold,
        recent_groupinfo_404_window_secs = cfg.recent_groupinfo_404_window_secs,
        "Starting auto_detect_failed_groups sweep worker (Phase 2 Path B)"
    );

    loop {
        ticker.tick().await;
        // Run both sweep modes per tick. Idempotency in the actor's
        // handle_trigger_system_reset (cooldown + circuit breaker) keeps
        // the rare overlap case (a convo qualifying under BOTH 409 and
        // 404 predicates simultaneously) safe.
        let n_409 = match sweep_once(&pool, &registry, &cfg).await {
            Ok(n) => n,
            Err(e) => {
                error!(error = %e, "sweep tick failed (409 mode)");
                0
            }
        };
        let n_404 = match sweep_groupinfo_404_once(&pool, &registry, &cfg).await {
            Ok(n) => n,
            Err(e) => {
                error!(error = %e, "sweep tick failed (groupinfo-404 mode)");
                0
            }
        };
        match n_409 + n_404 {
            0 => tracing::debug!("sweep tick: no stale groups"),
            total => info!(
                dispatched_total = total,
                dispatched_409 = n_409,
                dispatched_groupinfo_404 = n_404,
                "sweep tick: dispatched system-resets"
            ),
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
// Phase 2 (B10) — second sweep mode for the GroupInfo-missing failure.
// ──────────────────────────────────────────────────────────────────────

/// Single sweep iteration for the "GroupInfo missing + clients trying"
/// failure mode. Returns the number of `TriggerSystemReset` messages
/// dispatched.
///
/// Mirrors [`sweep_once`] but keys off `recent_groupinfo_404_count` and
/// `last_groupinfo_404_at` instead of the 409 columns. Required because
/// the original 409-only sweep is blind to convos that get stuck at
/// `getGroupInfo → 404` in the External Commit pre-flight — clients
/// never reach `commitGroupChange`, so the 409 counter never moves and
/// the original sweep's `recent_commit_409_count > threshold` predicate
/// never fires.
///
/// Predicates:
///   1. `auto_reset_disabled_at IS NULL` — circuit breaker not tripped
///   2. `group_info IS NULL` — the actual failure signal (no GroupInfo
///      to serve clients). The partial index
///      `idx_conversations_groupinfo_404_sweep` is conditioned on this;
///      keeping it here ensures the planner uses the index.
///   3. `recent_groupinfo_404_count > min_groupinfo_404_threshold`
///   4. `last_groupinfo_404_at IS NOT NULL` AND within
///      `recent_groupinfo_404_window_secs`
///   5. `last_reset_at IS NULL OR > min_reset_gap_secs ago` — same gap
///      gate as the 409 sweep (don't pile resets on a recently-reset
///      convo that hasn't had time to bootstrap)
///   6. NOT EXISTS recent Mode A reset_vote — same Mode A exclusion as
///      the 409 sweep
pub async fn sweep_groupinfo_404_once(
    pool: &PgPool,
    registry: &Arc<ActorRegistry>,
    cfg: &SweepConfig,
) -> anyhow::Result<usize> {
    let rows: Vec<GroupInfoMissingRow> = sqlx::query_as::<_, GroupInfoMissingRow>(
        "SELECT c.id, c.recent_groupinfo_404_count, c.current_epoch, c.group_info_epoch \
         FROM conversations c \
         WHERE c.auto_reset_disabled_at IS NULL \
           AND c.group_info IS NULL \
           AND c.recent_groupinfo_404_count > $1 \
           AND c.last_groupinfo_404_at IS NOT NULL \
           AND NOW() - c.last_groupinfo_404_at < make_interval(secs => $2) \
           AND (c.last_reset_at IS NULL \
                OR NOW() - c.last_reset_at > make_interval(secs => $3)) \
           AND NOT EXISTS ( \
                SELECT 1 FROM reset_votes rv \
                WHERE rv.convo_id = c.id \
                  AND rv.failure_mode = 'local_state_loss' \
                  AND rv.voted_at > NOW() - make_interval(secs => $4) \
           ) \
         LIMIT 50",
    )
    .bind(cfg.min_groupinfo_404_threshold)
    .bind(cfg.recent_groupinfo_404_window_secs as f64)
    .bind(cfg.min_reset_gap_secs as f64)
    .bind(cfg.mode_a_exclusion_window_secs as f64)
    .fetch_all(pool)
    .await?;

    if rows.is_empty() {
        return Ok(0);
    }

    let mut dispatched = 0usize;
    for row in rows {
        let staleness_epochs =
            (row.current_epoch.unwrap_or(0) as i64) - (row.group_info_epoch.unwrap_or(0) as i64);

        let actor_ref = match registry.get_or_spawn(&row.id).await {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    convo_id = %crate::crypto::redact_for_log(&row.id),
                    error = %e,
                    "sweep(groupinfo-404): failed to spawn actor — skipping convo"
                );
                continue;
            }
        };

        info!(
            convo_id = %crate::crypto::redact_for_log(&row.id),
            staleness_epochs,
            count_404 = row.recent_groupinfo_404_count,
            "sweep(groupinfo-404): dispatching TriggerSystemReset"
        );

        if let Err(e) = actor_ref.cast(ConvoMessage::TriggerSystemReset {
            reason: "server_sweep_groupinfo_missing".to_string(),
            staleness_epochs,
            quiet_duration_secs: 0,
        }) {
            warn!(
                convo_id = %crate::crypto::redact_for_log(&row.id),
                error = %e,
                "sweep(groupinfo-404): actor cast failed"
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

/// Hardcoded cooldown for the cascading-recovery guard.
///
/// Independent of `InlineTriggerConfig::reset_cooldown_secs` (config-driven,
/// default 1h). This shorter window is deliberately defense-in-depth: it
/// gates on the *combination* of `group_info IS NULL` + a recent
/// `last_reset_at`, which together signal "a reset attempt fired, GroupInfo
/// was cleared, and a client has not yet bootstrapped a replacement". 15
/// minutes is empirically long enough for a healthy bootstrap roundtrip
/// (sub-second under normal conditions) and short enough not to delay
/// recovery if bootstrap genuinely failed and a fresh reset is warranted.
///
/// Production conversation `3153f1a2...` cascade root cause: after a
/// reset attempt, `group_info` goes NULL while bootstrap is awaited. The
/// 404 inline trigger then immediately fires again on the same NULL,
/// looping. This constant provides the localized hot-patch fix on top of
/// the existing `reset_cooldown_secs` config gate (which fires only on
/// resets that *successfully* updated `last_reset_at` — true today, but
/// the in-flight architectural redesign per #12 will produce a path
/// where reset attempts can update `last_reset_at` without immediately
/// republishing GroupInfo, making this gate the durable safety net).
const CASCADING_RECOVERY_COOLDOWN_SECS: i64 = 15 * 60;

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
    /// Cascading-recovery cooldown: `group_info IS NULL` AND
    /// `last_reset_at` is within [`CASCADING_RECOVERY_COOLDOWN_SECS`].
    /// Signals "a reset attempt is still mid-flight (awaiting client
    /// bootstrap)"; firing again here would restart the loop rather than
    /// progress recovery.
    CascadingRecoveryCooldown,
    /// Convo is still in its initial bootstrap window — `group_info` has
    /// NEVER been populated (`bootstrap_completed_at IS NULL`). The
    /// creator's first commit hasn't landed yet. Firing a system reset
    /// here would zombie the convo (state=active, group_info=NULL,
    /// recovery cooldown engaged with nothing to repair) — the failure
    /// mode reproduced on prod convo `3a610a64...` 2026-05-08. See
    /// migration `20260508110000_inline_404_bootstrap_gate.sql`.
    BootstrapWindow,
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
    // Bootstrap-window gate: skip the trigger entirely if the convo has
    // never had a non-NULL group_info. Brand-new convos can't be
    // auto-reset — they need their creator's first commit to land first.
    // Evaluated before threshold/cooldown so even a sustained 409 burst
    // during the create window can't trip a reset.
    if !snapshot.bootstrap_completed {
        return InlineTriggerDecision::BootstrapWindow;
    }
    if snapshot.recent_commit_409_count < cfg.min_409_threshold {
        return InlineTriggerDecision::BelowThreshold {
            count: snapshot.recent_commit_409_count,
            threshold: cfg.min_409_threshold,
        };
    }
    // Cascading-recovery guard: skip if a reset attempt is mid-flight
    // (group_info cleared, bootstrap not yet activated, last_reset_at
    // within the hardcoded 15m window). Defense-in-depth on top of the
    // config-driven `reset_cooldown_secs` gate below — fires earlier
    // and only on the cascading-loop signature, not all recent resets.
    if snapshot.group_info_is_null {
        if let Some(last_reset) = snapshot.last_reset_at {
            let cooldown = chrono::Duration::seconds(CASCADING_RECOVERY_COOLDOWN_SECS);
            if now - last_reset < cooldown {
                return InlineTriggerDecision::CascadingRecoveryCooldown;
            }
        }
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
        InlineTriggerDecision::CascadingRecoveryCooldown => {
            warn!(
                convo_id = %crate::crypto::redact_for_log(convo_id),
                count_409 = snapshot.recent_commit_409_count,
                cascading_cooldown_secs = CASCADING_RECOVERY_COOLDOWN_SECS,
                "inline-trigger: group_info NULL with recent reset — cascading-recovery cooldown active, skipping"
            );
        }
        InlineTriggerDecision::BootstrapWindow => {
            tracing::debug!(
                convo_id = %crate::crypto::redact_for_log(convo_id),
                count_409 = snapshot.recent_commit_409_count,
                "inline-trigger: convo still in bootstrap window (group_info never populated) — skipping"
            );
        }
    }

    Ok(())
}

// ──────────────────────────────────────────────────────────────────────
// Phase 2 (B10) — event-driven inline trigger for GroupInfo-404 path.
// ──────────────────────────────────────────────────────────────────────

/// Mirror of [`evaluate_inline_trigger`] for the GroupInfo-404 inline
/// path. Same gate matrix (circuit breaker → threshold → cooldown), but
/// keys off `recent_groupinfo_404_count` and the dedicated
/// `min_groupinfo_404_threshold` field on [`InlineTriggerConfig`].
///
/// Kept as a separate function (rather than a generic helper) so the
/// telemetry and prod debugging stay sharp — when something fires (or
/// doesn't) you know exactly which failure mode produced the decision.
pub fn evaluate_inline_groupinfo_404_trigger(
    snapshot: &GroupInfoHealthSnapshot,
    cfg: &InlineTriggerConfig,
    now: chrono::DateTime<chrono::Utc>,
) -> InlineTriggerDecision {
    if snapshot.auto_reset_disabled_at.is_some() {
        return InlineTriggerDecision::CircuitBreakerTripped;
    }
    // Bootstrap-window gate: skip if group_info has never been populated.
    // This is the primary motivator for the gate — the 2026-05-08
    // `3a610a64...` zombie convo was created by this exact path firing
    // 4s after createConvo, before the creator's first commit landed.
    // See migration `20260508110000_inline_404_bootstrap_gate.sql`.
    if !snapshot.bootstrap_completed {
        return InlineTriggerDecision::BootstrapWindow;
    }
    if snapshot.recent_groupinfo_404_count < cfg.min_groupinfo_404_threshold {
        return InlineTriggerDecision::BelowThreshold {
            count: snapshot.recent_groupinfo_404_count,
            threshold: cfg.min_groupinfo_404_threshold,
        };
    }
    // Cascading-recovery guard: see [`evaluate_inline_trigger`] for
    // rationale. For the 404 path this is the *primary* loop trap —
    // production conv `3153f1a2...` cascade was driven entirely by
    // 404-on-NULL re-firing this trigger.
    if snapshot.group_info_is_null {
        if let Some(last_reset) = snapshot.last_reset_at {
            let cooldown = chrono::Duration::seconds(CASCADING_RECOVERY_COOLDOWN_SECS);
            if now - last_reset < cooldown {
                return InlineTriggerDecision::CascadingRecoveryCooldown;
            }
        }
    }
    if let Some(last_reset) = snapshot.last_reset_at {
        let cooldown = chrono::Duration::seconds(cfg.reset_cooldown_secs);
        if now - last_reset < cooldown {
            return InlineTriggerDecision::ResetCooldownActive;
        }
    }
    InlineTriggerDecision::Dispatch
}

/// Bump the convo's GroupInfo-404 counter AND, on the same code path,
/// evaluate the inline-trigger predicate. Mirror of
/// [`record_commit_409_with_inline_trigger`] for the GroupInfo-missing
/// failure mode.
///
/// On `InlineTriggerDecision::Dispatch`, casts
/// `ConvoMessage::TriggerSystemReset { reason: "inline_groupinfo_404_threshold" }`.
/// All idempotency invariants from the 409 path apply — actor handler
/// re-checks cooldown + circuit breaker, so duplicate dispatches during
/// a sustained 404 burst are safe.
///
/// Counter-update failures propagate as `Err`; actor dispatch failures
/// are logged and swallowed (sweep will retry on next tick).
pub async fn record_groupinfo_404_with_inline_trigger(
    pool: &DbPool,
    registry: &Arc<ActorRegistry>,
    convo_id: &str,
    cfg: &InlineTriggerConfig,
) -> anyhow::Result<()> {
    let snapshot = db::record_groupinfo_404(pool, convo_id).await?;

    match evaluate_inline_groupinfo_404_trigger(&snapshot, cfg, chrono::Utc::now()) {
        InlineTriggerDecision::Dispatch => {
            info!(
                convo_id = %crate::crypto::redact_for_log(convo_id),
                count_404 = snapshot.recent_groupinfo_404_count,
                threshold = cfg.min_groupinfo_404_threshold,
                "inline-trigger(groupinfo-404): dispatching TriggerSystemReset"
            );
            let actor_ref = match registry.get_or_spawn(convo_id).await {
                Ok(r) => r,
                Err(e) => {
                    warn!(
                        convo_id = %crate::crypto::redact_for_log(convo_id),
                        error = %e,
                        "inline-trigger(groupinfo-404): failed to spawn actor — skipping (sweep will catch on next tick)"
                    );
                    return Ok(());
                }
            };
            if let Err(e) = actor_ref.cast(ConvoMessage::TriggerSystemReset {
                reason: "inline_groupinfo_404_threshold".to_string(),
                staleness_epochs: 0,
                quiet_duration_secs: 0,
            }) {
                warn!(
                    convo_id = %crate::crypto::redact_for_log(convo_id),
                    error = %e,
                    "inline-trigger(groupinfo-404): actor cast failed — non-fatal, sweep will retry"
                );
            }
        }
        InlineTriggerDecision::BelowThreshold { count, threshold } => {
            tracing::debug!(
                convo_id = %crate::crypto::redact_for_log(convo_id),
                count,
                threshold,
                "inline-trigger(groupinfo-404): below threshold — counter bumped only"
            );
        }
        InlineTriggerDecision::CircuitBreakerTripped => {
            tracing::debug!(
                convo_id = %crate::crypto::redact_for_log(convo_id),
                "inline-trigger(groupinfo-404): auto_reset_disabled_at set — skipping"
            );
        }
        InlineTriggerDecision::ResetCooldownActive => {
            tracing::debug!(
                convo_id = %crate::crypto::redact_for_log(convo_id),
                "inline-trigger(groupinfo-404): recent reset cooldown active — skipping"
            );
        }
        InlineTriggerDecision::CascadingRecoveryCooldown => {
            warn!(
                convo_id = %crate::crypto::redact_for_log(convo_id),
                count_404 = snapshot.recent_groupinfo_404_count,
                cascading_cooldown_secs = CASCADING_RECOVERY_COOLDOWN_SECS,
                "inline-trigger(groupinfo-404): group_info NULL with recent reset — cascading-recovery cooldown active, skipping"
            );
        }
        InlineTriggerDecision::BootstrapWindow => {
            tracing::debug!(
                convo_id = %crate::crypto::redact_for_log(convo_id),
                count_404 = snapshot.recent_groupinfo_404_count,
                "inline-trigger(groupinfo-404): convo still in bootstrap window (group_info never populated) — skipping"
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
        snap_with_groupinfo(count, last_reset, disabled, false)
    }

    /// Variant with explicit `group_info_is_null` for cascading-recovery
    /// guard tests. Default helper [`snap`] passes `false` so the
    /// pre-existing case matrix is unaffected.
    fn snap_with_groupinfo(
        count: i32,
        last_reset: Option<chrono::DateTime<chrono::Utc>>,
        disabled: bool,
        group_info_is_null: bool,
    ) -> CommitHealthSnapshot {
        // `bootstrap_completed: true` matches every prior test's implicit
        // assumption: the convo has been past its create→first-commit
        // window. Tests for the new bootstrap-gate use the dedicated
        // `snap_bootstrap_window` fixture below.
        CommitHealthSnapshot {
            recent_commit_409_count: count,
            last_reset_at: last_reset,
            auto_reset_disabled_at: if disabled {
                Some(chrono::Utc::now())
            } else {
                None
            },
            group_info_is_null,
            bootstrap_completed: true,
        }
    }

    /// Brand-new convo, group_info NEVER populated, no resets, no
    /// circuit breaker — exactly the prod state at 2026-05-08
    /// `3a610a64...` 4 seconds after createConvo. Inputs let us drive
    /// arbitrarily many 409s/404s through the trigger to assert the gate
    /// holds even under sustained pressure.
    fn snap_bootstrap_window_409(count: i32) -> CommitHealthSnapshot {
        CommitHealthSnapshot {
            recent_commit_409_count: count,
            last_reset_at: None,
            auto_reset_disabled_at: None,
            group_info_is_null: true,
            bootstrap_completed: false,
        }
    }

    fn snap_404(
        count: i32,
        last_reset: Option<chrono::DateTime<chrono::Utc>>,
        disabled: bool,
    ) -> GroupInfoHealthSnapshot {
        // 404 path's loop trap is on `group_info IS NULL` — default helper
        // matches the production failure mode. Tests that need the
        // bootstrapped (group_info NOT NULL) state set `group_info_is_null=false`.
        snap_404_with_groupinfo(count, last_reset, disabled, true)
    }

    fn snap_404_with_groupinfo(
        count: i32,
        last_reset: Option<chrono::DateTime<chrono::Utc>>,
        disabled: bool,
        group_info_is_null: bool,
    ) -> GroupInfoHealthSnapshot {
        // See `snap_with_groupinfo` for the `bootstrap_completed: true`
        // rationale.
        GroupInfoHealthSnapshot {
            recent_groupinfo_404_count: count,
            last_reset_at: last_reset,
            auto_reset_disabled_at: if disabled {
                Some(chrono::Utc::now())
            } else {
                None
            },
            group_info_is_null,
            bootstrap_completed: true,
        }
    }

    /// 404-side mirror of `snap_bootstrap_window_409`.
    fn snap_bootstrap_window_404(count: i32) -> GroupInfoHealthSnapshot {
        GroupInfoHealthSnapshot {
            recent_groupinfo_404_count: count,
            last_reset_at: None,
            auto_reset_disabled_at: None,
            group_info_is_null: true,
            bootstrap_completed: false,
        }
    }

    fn cfg(threshold: i32, cooldown: i64) -> InlineTriggerConfig {
        InlineTriggerConfig {
            min_409_threshold: threshold,
            reset_cooldown_secs: cooldown,
            min_groupinfo_404_threshold: threshold,
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

    // ──────────────────────────────────────────────────────────────────
    // Phase 2 (B10) — GroupInfo-404 inline trigger evaluator tests.
    // Same gate matrix as the 409 path; tests mirror the cases above.
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn groupinfo_404_dispatches_when_threshold_crossed_and_no_gates() {
        let now = Utc.with_ymd_and_hms(2026, 4, 26, 18, 0, 0).unwrap();
        let s = snap_404(3, None, false);
        let c = cfg(3, 3600);
        assert_eq!(
            evaluate_inline_groupinfo_404_trigger(&s, &c, now),
            InlineTriggerDecision::Dispatch
        );
    }

    #[test]
    fn groupinfo_404_does_not_dispatch_below_threshold() {
        let now = Utc.with_ymd_and_hms(2026, 4, 26, 18, 0, 0).unwrap();
        let s = snap_404(2, None, false);
        let c = cfg(3, 3600);
        assert_eq!(
            evaluate_inline_groupinfo_404_trigger(&s, &c, now),
            InlineTriggerDecision::BelowThreshold {
                count: 2,
                threshold: 3
            }
        );
    }

    #[test]
    fn groupinfo_404_does_not_dispatch_when_circuit_breaker_tripped() {
        let now = Utc.with_ymd_and_hms(2026, 4, 26, 18, 0, 0).unwrap();
        let s = snap_404(1000, None, true);
        let c = cfg(3, 3600);
        assert_eq!(
            evaluate_inline_groupinfo_404_trigger(&s, &c, now),
            InlineTriggerDecision::CircuitBreakerTripped
        );
    }

    #[test]
    fn groupinfo_404_does_not_dispatch_within_reset_cooldown() {
        let now = Utc.with_ymd_and_hms(2026, 4, 26, 18, 0, 0).unwrap();
        let last_reset = now - chrono::Duration::minutes(30);
        let s = snap_404(10, Some(last_reset), false);
        let c = cfg(3, 3600);
        assert_eq!(
            evaluate_inline_groupinfo_404_trigger(&s, &c, now),
            InlineTriggerDecision::ResetCooldownActive
        );
    }

    #[test]
    fn groupinfo_404_dispatches_when_reset_cooldown_expired() {
        let now = Utc.with_ymd_and_hms(2026, 4, 26, 18, 0, 0).unwrap();
        let last_reset = now - chrono::Duration::minutes(90);
        let s = snap_404(10, Some(last_reset), false);
        let c = cfg(3, 3600);
        assert_eq!(
            evaluate_inline_groupinfo_404_trigger(&s, &c, now),
            InlineTriggerDecision::Dispatch
        );
    }

    #[test]
    fn groupinfo_404_dispatches_when_no_prior_reset_recorded() {
        let now = Utc.with_ymd_and_hms(2026, 4, 26, 18, 0, 0).unwrap();
        let s = snap_404(5, None, false);
        let c = cfg(3, 3600);
        assert_eq!(
            evaluate_inline_groupinfo_404_trigger(&s, &c, now),
            InlineTriggerDecision::Dispatch
        );
    }

    // ──────────────────────────────────────────────────────────────────
    // Hotfix: cascading-recovery cooldown tests.
    //
    // Reproduces the prod conv `3153f1a2...` failure mode: after a reset
    // attempt, group_info goes NULL while bootstrap is awaited. The 404
    // (or 409) inline trigger then fires *again* on that NULL — looping.
    // Gate test: with group_info_is_null && last_reset<15m ago, decision
    // MUST be CascadingRecoveryCooldown, NOT Dispatch.
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn cascading_recovery_cooldown_blocks_409_dispatch_when_group_info_null_recently_reset() {
        let now = Utc.with_ymd_and_hms(2026, 4, 26, 18, 0, 0).unwrap();
        // Reset 5 min ago — well inside the 15m cascading cooldown but
        // well outside the 1h reset_cooldown_secs gate (so without the
        // new guard, ResetCooldownActive *would* still gate via the
        // legacy path; we'd see ResetCooldownActive, not Dispatch.
        // The point of the test is the *specific* decision variant: a
        // future change to lower `reset_cooldown_secs` to 0 must still
        // be guarded by this hotfix on the cascading signature.).
        let last_reset = now - chrono::Duration::minutes(5);
        let s = snap_with_groupinfo(10, Some(last_reset), false, true);
        let c = cfg(3, 0); // intentionally 0 — proves we don't depend on legacy
        assert_eq!(
            evaluate_inline_trigger(&s, &c, now),
            InlineTriggerDecision::CascadingRecoveryCooldown
        );
    }

    #[test]
    fn cascading_recovery_cooldown_does_not_block_when_group_info_present() {
        // Same recency, but group_info populated → cascading guard sees
        // a healthy bootstrap landed, hands off to legacy gates.
        let now = Utc.with_ymd_and_hms(2026, 4, 26, 18, 0, 0).unwrap();
        let last_reset = now - chrono::Duration::minutes(5);
        let s = snap_with_groupinfo(10, Some(last_reset), false, false);
        let c = cfg(3, 0);
        assert_eq!(
            evaluate_inline_trigger(&s, &c, now),
            InlineTriggerDecision::Dispatch
        );
    }

    #[test]
    fn cascading_recovery_cooldown_expires_after_15_minutes() {
        // 16 min after last_reset, cascading guard releases. Legacy
        // reset_cooldown_secs=0 means the path falls through to
        // Dispatch.
        let now = Utc.with_ymd_and_hms(2026, 4, 26, 18, 0, 0).unwrap();
        let last_reset = now - chrono::Duration::minutes(16);
        let s = snap_with_groupinfo(10, Some(last_reset), false, true);
        let c = cfg(3, 0);
        assert_eq!(
            evaluate_inline_trigger(&s, &c, now),
            InlineTriggerDecision::Dispatch
        );
    }

    #[test]
    fn groupinfo_404_cascading_recovery_cooldown_blocks_dispatch() {
        // Mirror of the 409 case for the GroupInfo-404 inline path.
        // Default snap_404 already sets group_info_is_null=true (the
        // production failure mode for this trigger).
        let now = Utc.with_ymd_and_hms(2026, 4, 26, 18, 0, 0).unwrap();
        let last_reset = now - chrono::Duration::minutes(5);
        let s = snap_404(10, Some(last_reset), false);
        let c = cfg(3, 0);
        assert_eq!(
            evaluate_inline_groupinfo_404_trigger(&s, &c, now),
            InlineTriggerDecision::CascadingRecoveryCooldown
        );
    }

    #[test]
    fn groupinfo_404_cascading_recovery_cooldown_releases_after_window() {
        let now = Utc.with_ymd_and_hms(2026, 4, 26, 18, 0, 0).unwrap();
        let last_reset = now - chrono::Duration::minutes(16);
        let s = snap_404(10, Some(last_reset), false);
        let c = cfg(3, 0);
        assert_eq!(
            evaluate_inline_groupinfo_404_trigger(&s, &c, now),
            InlineTriggerDecision::Dispatch
        );
    }

    #[test]
    fn groupinfo_404_cascading_recovery_cooldown_skips_when_group_info_present() {
        // After bootstrap lands, group_info_is_null=false → cascading guard
        // is a no-op even within the 15m window. This shouldn't happen on
        // the 404 path in practice (404 implies NULL), but the symmetric
        // logic guards against future schema/order-of-operations changes.
        let now = Utc.with_ymd_and_hms(2026, 4, 26, 18, 0, 0).unwrap();
        let last_reset = now - chrono::Duration::minutes(5);
        let s = snap_404_with_groupinfo(10, Some(last_reset), false, false);
        let c = cfg(3, 0);
        assert_eq!(
            evaluate_inline_groupinfo_404_trigger(&s, &c, now),
            InlineTriggerDecision::Dispatch
        );
    }

    // ---------------------------------------------------------------------
    // Bootstrap-window gate (2026-05-08 fix for the `3a610a64...` zombie).
    //
    // A brand-new convo (group_info NEVER populated, no resets, no circuit
    // breaker) must NEVER trip a system-triggered reset, no matter how
    // many 409s/404s land during the create→first-commit window. These
    // tests pin that contract for both inline trigger predicates so the
    // bug can't silently regress.
    // ---------------------------------------------------------------------

    #[test]
    fn bootstrap_window_gates_409_trigger_above_threshold() {
        let now = Utc.with_ymd_and_hms(2026, 5, 8, 13, 49, 31).unwrap();
        // Way over the 3-threshold; would dispatch on a bootstrapped convo.
        let s = snap_bootstrap_window_409(10);
        let c = cfg(3, 3600);
        assert_eq!(
            evaluate_inline_trigger(&s, &c, now),
            InlineTriggerDecision::BootstrapWindow,
            "still-bootstrapping convo MUST NOT trigger reset on 409 burst"
        );
    }

    #[test]
    fn bootstrap_window_gates_404_trigger_above_threshold() {
        // The exact prod failure mode: 3 consecutive getGroupInfo→404 on
        // a freshly-created convo, 4 seconds after createConvo, before
        // the creator's first commit lands. Pre-fix this dispatched a
        // reset; post-fix it MUST return BootstrapWindow.
        let now = Utc.with_ymd_and_hms(2026, 5, 8, 13, 49, 31).unwrap();
        let s = snap_bootstrap_window_404(3);
        let c = cfg(3, 3600);
        assert_eq!(
            evaluate_inline_groupinfo_404_trigger(&s, &c, now),
            InlineTriggerDecision::BootstrapWindow,
            "still-bootstrapping convo MUST NOT trigger reset on 404 burst — this is the 2026-05-08 prod regression"
        );
    }

    #[test]
    fn bootstrap_window_gate_takes_precedence_over_below_threshold() {
        // A convo can be both still-bootstrapping AND below threshold. The
        // bootstrap gate MUST return BootstrapWindow (the actionable
        // signal) rather than BelowThreshold — otherwise telemetry would
        // mask the bug.
        let now = Utc.with_ymd_and_hms(2026, 5, 8, 13, 49, 28).unwrap();
        let s_409 = snap_bootstrap_window_409(1);
        let s_404 = snap_bootstrap_window_404(1);
        let c = cfg(3, 3600);
        assert_eq!(
            evaluate_inline_trigger(&s_409, &c, now),
            InlineTriggerDecision::BootstrapWindow
        );
        assert_eq!(
            evaluate_inline_groupinfo_404_trigger(&s_404, &c, now),
            InlineTriggerDecision::BootstrapWindow
        );
    }

    #[test]
    fn bootstrap_window_gate_still_yields_to_circuit_breaker() {
        // Circuit breaker is the highest-priority signal: an operator
        // explicitly disabled auto-reset for this convo. The bootstrap
        // gate must come AFTER the circuit-breaker gate.
        let now = Utc.with_ymd_and_hms(2026, 5, 8, 13, 49, 31).unwrap();
        let s_409 = CommitHealthSnapshot {
            recent_commit_409_count: 10,
            last_reset_at: None,
            auto_reset_disabled_at: Some(now),
            group_info_is_null: true,
            bootstrap_completed: false,
        };
        let s_404 = GroupInfoHealthSnapshot {
            recent_groupinfo_404_count: 10,
            last_reset_at: None,
            auto_reset_disabled_at: Some(now),
            group_info_is_null: true,
            bootstrap_completed: false,
        };
        let c = cfg(3, 3600);
        assert_eq!(
            evaluate_inline_trigger(&s_409, &c, now),
            InlineTriggerDecision::CircuitBreakerTripped
        );
        assert_eq!(
            evaluate_inline_groupinfo_404_trigger(&s_404, &c, now),
            InlineTriggerDecision::CircuitBreakerTripped
        );
    }

    #[test]
    fn post_bootstrap_404_above_threshold_still_dispatches() {
        // Sanity: the gate ONLY suppresses the bootstrap-window case. A
        // genuine post-bootstrap 404 burst (group was once live, lost its
        // GroupInfo) must still dispatch the reset.
        let now = Utc.with_ymd_and_hms(2026, 5, 8, 14, 0, 0).unwrap();
        let s = snap_404_with_groupinfo(5, None, false, true);
        // Default `snap_404_with_groupinfo` sets bootstrap_completed=true.
        assert!(s.bootstrap_completed);
        let c = cfg(3, 3600);
        assert_eq!(
            evaluate_inline_groupinfo_404_trigger(&s, &c, now),
            InlineTriggerDecision::Dispatch
        );
    }
}
