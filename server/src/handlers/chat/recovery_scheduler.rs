//! Callable Recovery expiry service.
//!
//! This is deliberately not an HTTP route and not a recurring process job. A
//! scheduler that already owns polling, leases, retries, and shutdown may call
//! [`expire_one`] for a specific request. Each invocation owns one fresh
//! transaction and uses only the scheduler authority path: there is no client
//! admission, business prelude, operation claim, idempotency completion, or
//! caller-provided event payload.

use uuid::Uuid;

use crate::{
    chat_protocol::repository::recovery::{
        plan_scheduler_recovery_expiry, prepare_recovery_expiry_authority, RecoveryRepositoryError,
        RecoverySchedulerExpiryRead,
    },
    storage::DbPool,
};

/// Durable result of one scheduler attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryExpiryServiceOutcome {
    /// The exact open-due request was terminalized by the sealed executor.
    Applied,
    /// The request was already in a retained terminal state; no business write
    /// or operation completion was attempted.
    RetainedTerminal,
}

/// Expire one known Recovery request in a fresh caller-owned transaction.
///
/// `ExpiryNotDue`, missing requests, corrupt rows, CAS drift, and storage
/// failures remain typed [`RecoveryRepositoryError`] values for the scheduler's
/// retry/logging policy. This function does not translate them into XRPC codes.
#[allow(dead_code)]
pub(crate) async fn expire_one(
    pool: &DbPool,
    request_id: Uuid,
) -> Result<RecoveryExpiryServiceOutcome, RecoveryRepositoryError> {
    let mut transaction = pool.begin().await?;
    let outcome = match prepare_recovery_expiry_authority(&mut transaction, request_id).await? {
        RecoverySchedulerExpiryRead::Authority(authority) => {
            let prepared = plan_scheduler_recovery_expiry(authority.into_plan_input())?;
            prepared.apply(&mut transaction).await?;
            RecoveryExpiryServiceOutcome::Applied
        }
        RecoverySchedulerExpiryRead::Retained(_) => RecoveryExpiryServiceOutcome::RetainedTerminal,
    };
    transaction.commit().await?;
    Ok(outcome)
}
