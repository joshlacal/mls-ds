//! Background expiry sweeper for the clean-chat protocol.
//!
//! Two clean-chat work families plus direct-request preparations/publications
//! terminalize on deterministic deadlines:
//!   * OPEN `chat.leaf_recovery_requests` past `expires_at` (~5 min TTL)
//!   * PENDING `chat.welcome_deliveries` past consumed KeyPackage `not_after`
//!   * C33 direct-request preparations and published requests (`30d` expiry)
//!   * sender-home outbound routes no pair coordinator answered (`1h`)

use std::{sync::Arc, time::Duration};

use tokio::time::interval;

use super::runtime::ChatRuntime;
use crate::chat_protocol::repository::expiry_sweep::{
    delete_expired_remote_lifecycle_state, delete_unanswered_outbound_routes,
    due_leaf_recovery_targets, due_welcome_delivery_targets, sweep_one_welcome,
    WelcomeSweepOutcome,
};
use crate::handlers::chat::recovery_scheduler::{expire_one, RecoveryExpiryServiceOutcome};
use crate::storage::DbPool;

const DEFAULT_SWEEP_INTERVAL_SECS: u64 = 60;
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
        if let Some(signer) = runtime.request_receipt_signer() {
            match crate::chat_protocol::repository::direct_request_preparation::expire_due_preparations(
                &pool,
                signer,
                config.batch,
            )
            .await
            {
                Ok(expired) if expired > 0 => {
                    tracing::info!(expired, "expired direct request preparations")
                }
                Ok(_) => {}
                Err(_) => tracing::warn!("direct request preparation expiry failed"),
            }
            match crate::chat_protocol::repository::expiry_sweep::expire_due_published_requests(
                &pool,
                signer,
                config.batch,
            )
            .await
            {
                Ok(expired) if expired > 0 => {
                    tracing::info!(expired, "expired published direct requests")
                }
                Ok(_) => {}
                Err(error) => tracing::warn!(%error, "published direct request expiry failed"),
            }
        }
        match crate::chat_protocol::repository::expiry_sweep::prune_terminal_request_artifacts(
            &pool,
            config.batch,
        )
        .await
        {
            Ok(pruned) if pruned > 0 => {
                tracing::info!(pruned, "pruned terminal direct request artifacts")
            }
            Ok(_) => {}
            Err(error) => tracing::warn!(%error, "terminal direct request artifact pruning failed"),
        }
        let now = crate::sim_hooks::current_utc();
        match crate::chat_protocol::repository::expiry_sweep::mark_inactive_devices(&pool, now)
            .await
        {
            Ok(marked) if marked > 0 => {
                tracing::info!(marked, "marked 60d inactive devices dormant")
            }
            Ok(_) => {}
            Err(error) => tracing::warn!(%error, "device dormancy sweep failed"),
        }
        match crate::chat_protocol::repository::expiry_sweep::prune_expired_application_payloads(
            &pool, now,
        )
        .await
        {
            Ok(pruned) if pruned > 0 => {
                tracing::info!(pruned, "pruned 30d expired application payloads")
            }
            Ok(_) => {}
            Err(error) => tracing::warn!(%error, "30d application payload pruning failed"),
        }
        let _ = runtime.sse_state().prune_idle_channels().await;
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

    let now = crate::sim_hooks::current_utc();
    match delete_unanswered_outbound_routes(pool, now, config.batch).await {
        Ok(deleted) if deleted > 0 => {
            tracing::info!(deleted, "deleted unanswered direct request routes")
        }
        Ok(_) => {}
        Err(error) => tracing::warn!(%error, "unanswered direct request route sweep failed"),
    }

    match delete_expired_remote_lifecycle_state(pool, now, config.batch).await {
        Ok(deleted) if deleted > 0 => {
            tracing::info!(deleted, "deleted expired remote lifecycle state")
        }
        Ok(_) => {}
        Err(error) => tracing::warn!(%error, "remote lifecycle expiry sweep failed"),
    }

    counts
}

#[cfg(all(test, feature = "test-support"))]
mod tests {
    use super::*;
    use crate::sim_hooks::{scope_ds_clock, ManualDsClock};
    use chrono::{DateTime, Utc};
    use uuid::Uuid;

    /// One cycle of the worker deletes a sender-home route no pair coordinator
    /// answered once it is an hour old, and keeps an answered route however old
    /// and an unanswered route younger than an hour.
    #[tokio::test]
    async fn one_cycle_deletes_only_routes_left_unanswered_for_an_hour() {
        let database =
            crate::common::fresh_db::fresh_fully_migrated_db("chat_expiry_worker_").await;
        let pool = database.connect(2).await;
        let now = DateTime::from_timestamp_millis(Utc::now().timestamp_millis()).unwrap();
        let hour = chrono::Duration::hours(1);
        // An unanswered route binds its pair until 600 s after its prepare was
        // signed, here when it was recorded; an answered one binds permanently.
        let binding = chrono::Duration::seconds(600);
        let (stale, answered, younger) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let young = now - hour + chrono::Duration::milliseconds(1);
        for (request_id, created_at, answered_at, binding_expires_at) in [
            (stale, now - hour, None, Some(now - hour + binding)),
            (answered, now - hour * 2, Some(now - hour * 2), None),
            (younger, young, None, Some(young + binding)),
        ] {
            sqlx::query(
                "INSERT INTO chat.direct_request_outbound_routes (request_id, actor_did, \
                     actor_device_id, recipient_did, coordinator_did, created_at, answered_at, \
                     binding_expires_at) \
                 VALUES ($1, 'did:web:sender.example.com', $2, 'did:web:recipient.example.com', \
                     'did:web:coordinator.example.com', $3, $4, $5)",
            )
            .bind(request_id)
            .bind(Uuid::new_v4())
            .bind(created_at)
            .bind(answered_at)
            .bind(binding_expires_at)
            .execute(&pool)
            .await
            .unwrap();
        }

        let clock = Arc::new(ManualDsClock::new(now));
        let config = ChatExpirySweepConfig::default();
        scope_ds_clock(clock, run_sweep_cycle(&pool, config)).await;

        let kept: Vec<Uuid> = sqlx::query_scalar(
            "SELECT request_id FROM chat.direct_request_outbound_routes ORDER BY created_at",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(kept, [answered, younger]);
    }
}
