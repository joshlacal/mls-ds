// Server-authored expiry sweep seams for the clean-chat protocol.
//
// Two prior-bound work families terminalize on a deterministic deadline that no
// client request is guaranteed to reach: an OPEN `chat.leaf_recovery_requests`
// row past its `expires_at`, and a PENDING `chat.welcome_deliveries` row past
// the `not_after` of the Add KeyPackage it consumed. Both hold scarce state
// while they sit due — the recovery request holds its
// `chat.key_package_reservations` row (and therefore a reserved key package),
// and the pending Welcome holds the same for its recipient — and both block the
// owner's re-request through a partial unique index
// (`leaf_recovery_requests_one_open_uq`). On a quiet conversation nothing else
// advances the coordinate, so nothing releases them.
//
// This module is the *scheduler-side input* for those two families. It owns no
// new authority and no new SQL writer:
//
//   1. `claim_due_leaf_recovery_requests` is a read-only enumeration of due OPEN
//      recovery requests. It takes no row lock: the terminalization itself
//      (`handlers::chat::recovery_scheduler::expire_one`) re-locks the exact
//      request under its own advisory lock in a fresh transaction and re-derives
//      every authoritative fact there, so a stale id from this read can only
//      produce a no-op, never a wrong write.
//
//   2. `expire_due_welcome_delivery` composes the ALREADY-BUILT welcome-expiry
//      route — `hydrate_locked_conversation_state` -> `lock_welcome_terminal` ->
//      `HydrationAuthority::plan_welcome_expiry_entry` ->
//      `prepare_welcome_terminal_execution` -> the sealed executor arm — in the
//      canonical lock order (exact recipient principal/device/key,
//      conversation aggregate, then the exact Welcome), which is exactly the order
//      `state_machine::plan_welcome_expiry_entry` documents for an expiry worker
//      and exactly the order the client acknowledge/reject facade uses. Nothing
//      here bypasses the CAS bindings, the head verify, or the plan seal: a due
//      classification is the *only* thing that produces a `PendingDue` guard, and
//      the guard is the only way into the planner.
//
// The observed instant is never caller-invented in production: `sweep_one_welcome`
// reads `date_trunc('milliseconds', transaction_timestamp())` inside its own
// transaction and rejects a non-whole-millisecond value, mirroring
// `recovery::prepare_recovery_expiry_authority`. `expire_due_welcome_delivery`
// takes the instant as a parameter for exactly the same reason the client facade
// does (the trusted instant is an input to aggregate hydration, not something the
// hydrator can invent), and the dueness gate downstream of it —
// `plan_welcome_expiry_entry`'s `observed_at < expires_at => WorkExpired` — is
// unchanged and unconditional.

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use super::{
    core::{
        hydrate_locked_conversation_state, lock_welcome_terminal, ConversationStateHydrationError,
        LockedWelcomeTerminal, WelcomeLockError,
    },
    execution_context::{
        apply_prepared_welcome_terminal_execution, prepare_welcome_terminal_execution,
        ExecutionContextHydrationError,
    },
};
use crate::chat_protocol::state_machine::{ExecutorError, HydrationAuthority, StateMachineError};

/// Failures the sweep seams can surface. Each stays typed so the worker's
/// retry/logging policy can distinguish "the database said no" from "this exact
/// row is not sweepable", and none is translated into an XRPC code here.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ExpirySweepError {
    #[error("clean-chat expiry sweep database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("clean-chat expiry sweep identity lock failed: {0}")]
    Prelude(#[from] super::prelude::PreludeError),
    #[error("clean-chat expiry sweep observed a non-whole-millisecond server instant")]
    TrustedInstantMismatch,
    #[error("clean-chat expiry sweep aggregate hydration failed: {0}")]
    Aggregate(#[from] ConversationStateHydrationError),
    #[error("clean-chat expiry sweep Welcome lock failed: {0}")]
    WelcomeLock(#[from] WelcomeLockError),
    #[error("clean-chat expiry sweep planning failed: {0}")]
    StateMachine(#[from] StateMachineError),
    #[error("clean-chat expiry sweep execution hydration failed: {0}")]
    ExecutionHydration(#[from] ExecutionContextHydrationError),
    #[error("clean-chat expiry sweep execution failed: {0:?}")]
    Execution(ExecutorError),
}

impl From<ExecutorError> for ExpirySweepError {
    fn from(value: ExecutorError) -> Self {
        Self::Execution(value)
    }
}

// ===========================================================================
// Part 1 — due OPEN leaf-recovery requests (the input for `expire_one`).
// ===========================================================================

/// One due OPEN leaf-recovery request, carrying only the advisory identity the
/// scheduler needs to re-lock it plus the conversation id for structured logs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, sqlx::FromRow)]
pub(crate) struct DueLeafRecoveryRequest {
    pub(crate) recovery_request_id: Uuid,
    pub(crate) conversation_id: Uuid,
    pub(crate) expires_at: DateTime<Utc>,
}

/// Enumerate up to `limit` OPEN leaf-recovery requests whose `expires_at` has
/// passed `observed_at`, in the deterministic global order
/// `(expires_at, recovery_request_id)`.
///
/// The read takes **no** row lock and performs no mutation. Locking here would be
/// actively wrong: `expire_one` opens its own transaction and takes the canonical
/// `pg_advisory_xact_lock` on the request's operation key, so a row lock held
/// across this read would either be released before that transaction starts (no
/// protection) or deadlock against it. Two schedulers racing on the same id
/// serialize on that advisory lock, and the loser observes a retained terminal
/// row and writes nothing.
pub(crate) async fn claim_due_leaf_recovery_requests(
    transaction: &mut Transaction<'_, Postgres>,
    observed_at: DateTime<Utc>,
    limit: i64,
) -> Result<Vec<DueLeafRecoveryRequest>, ExpirySweepError> {
    let rows = sqlx::query_as::<_, DueLeafRecoveryRequest>(
        r#"
        SELECT lrr.recovery_request_id,
               lrr.conversation_id,
               lrr.expires_at
          FROM chat.leaf_recovery_requests lrr
         WHERE lrr.status = 'open'
           AND lrr.expires_at <= $1
         ORDER BY lrr.expires_at, lrr.recovery_request_id
         LIMIT $2
        "#,
    )
    .bind(observed_at)
    .bind(limit)
    .fetch_all(&mut **transaction)
    .await?;
    Ok(rows)
}

// ===========================================================================
// Part 2 — server-authored Welcome expiry (composition, not new authority).
// ===========================================================================

/// Durable result of one Welcome sweep attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WelcomeSweepOutcome {
    /// The exact pending-due delivery was terminalized `expired` by the sealed
    /// executor arm, and its `welcomeExpired` recovery-work item was created.
    Expired,
    /// The delivery is still pending but not yet due at `observed_at`. Nothing
    /// was written.
    NotDue,
    /// The delivery is already in a retained terminal state (acknowledged,
    /// rejected, expired, or superseded). Nothing was written.
    RetainedTerminal,
    /// The delivery is absent from the locked conversation. Nothing was written.
    Missing,
}

/// Terminalize one exact due pending Welcome delivery inside the caller's
/// transaction, in the canonical lock order.
///
/// `observed_at` must be the caller's trusted whole-millisecond server instant;
/// it becomes the aggregate's `locked_at` and therefore the guard's, and the
/// planner rejects the plan outright when it is earlier than the delivery's
/// `expires_at`. The terminal instant written is the delivery's OWN `expires_at`
/// (immutable, DB-checked), never `observed_at`, so a sweep that runs late writes
/// exactly what a sweep that ran on time would have written.
pub(crate) async fn expire_due_welcome_delivery(
    transaction: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    welcome_id: Uuid,
    observed_at: DateTime<Utc>,
) -> Result<WelcomeSweepOutcome, ExpirySweepError> {
    if observed_at.timestamp_subsec_nanos() % 1_000_000 != 0 {
        return Err(ExpirySweepError::TrustedInstantMismatch);
    }
    // Discovery grants no authority. Lock the exact stored recipient before the
    // head, then retain the existing aggregate/Welcome CAS and dueness gates.
    let recipient: Option<(String, Uuid)> = sqlx::query_as(
        "SELECT wd.recipient_did,wd.recipient_device_id FROM chat.welcome_bundles wb JOIN chat.welcome_deliveries wd USING(welcome_id) WHERE wb.conversation_id=$1 AND wb.welcome_id=$2",
    ).bind(conversation_id).bind(welcome_id).fetch_optional(&mut **transaction).await?;
    let Some((did, device_id)) = recipient else {
        return Ok(WelcomeSweepOutcome::Missing);
    };
    let scope = super::prelude::CanonicalLockScope::new(
        vec![did.clone()],
        vec![super::prelude::CanonicalDeviceIdentity::new(did, device_id)],
    )?;
    let event_scope = super::prelude::lock_conversation_event_scope(transaction, &scope).await?;
    let aggregate =
        hydrate_locked_conversation_state(transaction, conversation_id, observed_at).await?;
    let welcome_guard = match lock_welcome_terminal(transaction, &aggregate, welcome_id).await {
        Ok(LockedWelcomeTerminal::PendingDue(guard)) => guard,
        Ok(LockedWelcomeTerminal::PendingNotDue(_)) => return Ok(WelcomeSweepOutcome::NotDue),
        Ok(_) => return Ok(WelcomeSweepOutcome::RetainedTerminal),
        Err(WelcomeLockError::Missing) => return Ok(WelcomeSweepOutcome::Missing),
        Err(error) => return Err(error.into()),
    };

    let hydration = HydrationAuthority::from_locked_conversation(&aggregate)?;
    let plan = hydration
        .plan_welcome_expiry_entry(&aggregate, welcome_guard)?
        .into_persistence_plan()?;
    let prepared = prepare_welcome_terminal_execution(transaction, &plan, &event_scope).await?;
    apply_prepared_welcome_terminal_execution(prepared).await?;
    Ok(WelcomeSweepOutcome::Expired)
}

/// The trusted server instant one sweep transaction observes: the transaction's
/// own start timestamp truncated to whole milliseconds. Read from the database,
/// never from the process clock, so it is the same instant every CAS in the
/// transaction is stamped against.
pub(crate) async fn trusted_sweep_instant(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<DateTime<Utc>, ExpirySweepError> {
    let instant: DateTime<Utc> =
        sqlx::query_scalar("SELECT date_trunc('milliseconds', transaction_timestamp())")
            .fetch_one(&mut **transaction)
            .await?;
    if instant.timestamp_subsec_nanos() % 1_000_000 != 0 {
        return Err(ExpirySweepError::TrustedInstantMismatch);
    }
    Ok(instant)
}

/// Enumerate the due pending Welcome deliveries a sweep cycle should attempt, in
/// a short read-only transaction of its own.
///
/// This wraps the already-built `welcome::claim_due_welcome_deliveries` claim and
/// deliberately drops its transaction (and therefore its `FOR UPDATE ... SKIP
/// LOCKED` row locks) before any terminalization runs: holding the delivery row
/// lock while `expire_due_welcome_delivery` then locks the conversation aggregate
/// would invert the canonical lock order that every client path takes
/// (conversation first, Welcome second) and risk a deadlock against live traffic.
/// Losing the claim's partitioning is harmless — a second sweeper that reaches the
/// same delivery finds it already terminal and writes nothing.
pub(crate) async fn due_welcome_delivery_targets(
    pool: &PgPool,
    limit: i64,
) -> Result<Vec<(Uuid, Uuid, DateTime<Utc>)>, ExpirySweepError> {
    let mut transaction = pool.begin().await?;
    let observed_at = trusted_sweep_instant(&mut transaction).await?;
    let due = super::welcome::claim_due_welcome_deliveries(&mut transaction, observed_at, limit)
        .await
        .map_err(|error| match error {
            super::welcome::WelcomeRepositoryError::Database(inner) => {
                ExpirySweepError::Database(inner)
            }
            _ => ExpirySweepError::TrustedInstantMismatch,
        })?;
    let targets = due
        .into_iter()
        .map(|delivery| {
            (
                delivery.conversation_id,
                delivery.welcome_id,
                delivery.expires_at,
            )
        })
        .collect();
    transaction.rollback().await?;
    Ok(targets)
}

/// Enumerate the due OPEN leaf-recovery requests a sweep cycle should attempt, in
/// a short read-only transaction of its own.
pub(crate) async fn due_leaf_recovery_targets(
    pool: &PgPool,
    limit: i64,
) -> Result<Vec<DueLeafRecoveryRequest>, ExpirySweepError> {
    let mut transaction = pool.begin().await?;
    let observed_at = trusted_sweep_instant(&mut transaction).await?;
    let due = claim_due_leaf_recovery_requests(&mut transaction, observed_at, limit).await?;
    transaction.rollback().await?;
    Ok(due)
}

/// Terminalize one exact due pending Welcome in a fresh, caller-free transaction.
/// The trusted instant is read from the database inside that transaction; no
/// caller supplies it.
pub(crate) async fn sweep_one_welcome(
    pool: &PgPool,
    conversation_id: Uuid,
    welcome_id: Uuid,
) -> Result<WelcomeSweepOutcome, ExpirySweepError> {
    let mut transaction = pool.begin().await?;
    let observed_at = trusted_sweep_instant(&mut transaction).await?;
    let outcome =
        expire_due_welcome_delivery(&mut transaction, conversation_id, welcome_id, observed_at)
            .await?;
    if matches!(outcome, WelcomeSweepOutcome::Expired) {
        transaction.commit().await?;
    } else {
        transaction.rollback().await?;
    }
    Ok(outcome)
}
