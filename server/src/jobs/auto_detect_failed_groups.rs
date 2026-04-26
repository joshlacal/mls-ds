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
use crate::config::SweepConfig;

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
    // The 7 conditions of the spec's Path B query:
    //   1. auto_reset_disabled_at IS NULL          (circuit-breaker not tripped)
    //   2. last_successful_commit_at IS NOT NULL   (we've seen at least one commit)
    //   3. epoch staleness > max_ecommit_staleness_epochs
    //   4. quiet duration > min_quiet_period_secs
    //   5. recent_commit_409_count > min_409_threshold
    //   6. last_commit_409_at IS NOT NULL AND within recent_409_window_secs
    //   7. last_reset_at IS NULL OR older than min_reset_gap_secs
    //   8. NOT EXISTS recent Mode A reset_vote   (Mode A exclusion window)
    //
    // `LIMIT 50` keeps a single tick from monopolising the actor mailbox if a
    // mass-failure event lights up many convos at once.
    let rows: Vec<StaleConvoRow> = sqlx::query_as::<_, StaleConvoRow>(
        "SELECT c.id, c.current_epoch, c.group_info_epoch, \
                c.last_successful_commit_at, c.recent_commit_409_count \
         FROM conversations c \
         WHERE c.auto_reset_disabled_at IS NULL \
           AND c.last_successful_commit_at IS NOT NULL \
           AND (c.current_epoch - COALESCE(c.group_info_epoch, 0)) > $1 \
           AND NOW() - c.last_successful_commit_at > make_interval(secs => $2) \
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
