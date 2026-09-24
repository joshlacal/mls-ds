use sqlx::{Postgres, Transaction};
use uuid::Uuid;

/// Request-attempt lock precedes the global request budget and canonical
/// principal/device/key prefix. This mints lock evidence, never authentication.
pub(crate) struct DirectRequestOperationLock {
    transaction_id: String,
    request_id: Uuid,
}
impl DirectRequestOperationLock {
    pub(crate) fn transaction_id(&self) -> &str {
        &self.transaction_id
    }
    pub(crate) fn request_id(&self) -> Uuid {
        self.request_id
    }
}
pub(crate) async fn lock_direct_request_operation(
    transaction: &mut Transaction<'_, Postgres>,
    request_id: Uuid,
) -> Result<DirectRequestOperationLock, sqlx::Error> {
    lock_direct_request_operation_set(transaction, request_id, &[]).await
}

/// Acceptance locks its own immutable mutation ID and the original request
/// together, in UUID-byte order, before budget or identity state.
pub(crate) async fn lock_direct_request_operation_set(
    transaction: &mut Transaction<'_, Postgres>,
    request_id: Uuid,
    additional_ids: &[Uuid],
) -> Result<DirectRequestOperationLock, sqlx::Error> {
    let mut ids = additional_ids.to_vec();
    ids.push(request_id);
    ids.sort_unstable();
    ids.dedup();
    for id in ids {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!("chat-operation-id:{id}"))
            .execute(&mut **transaction)
            .await?;
    }
    sqlx::query("SELECT singleton FROM chat.direct_request_budget WHERE singleton FOR UPDATE")
        .fetch_one(&mut **transaction)
        .await?;
    let transaction_id = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await?;
    Ok(DirectRequestOperationLock {
        transaction_id,
        request_id,
    })
}

/// Try to lock the request operation non-blockingly. Returns None if any advisory
/// lock is held or if the budget row is locked.
pub(crate) async fn try_lock_direct_request_operation(
    transaction: &mut Transaction<'_, Postgres>,
    request_id: Uuid,
) -> Result<Option<DirectRequestOperationLock>, sqlx::Error> {
    try_lock_direct_request_operation_set(transaction, request_id, &[]).await
}

pub(crate) async fn try_lock_direct_request_operation_set(
    transaction: &mut Transaction<'_, Postgres>,
    request_id: Uuid,
    additional_ids: &[Uuid],
) -> Result<Option<DirectRequestOperationLock>, sqlx::Error> {
    let mut ids = additional_ids.to_vec();
    ids.push(request_id);
    ids.sort_unstable();
    ids.dedup();
    for id in ids {
        let acquired: bool =
            sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))")
                .bind(format!("chat-operation-id:{id}"))
                .fetch_one(&mut **transaction)
                .await?;
        if !acquired {
            return Ok(None);
        }
    }
    let budget = sqlx::query(
        "SELECT singleton FROM chat.direct_request_budget WHERE singleton FOR UPDATE NOWAIT",
    )
    .fetch_optional(&mut **transaction)
    .await;
    match &budget {
        Ok(Some(_)) => {}
        Ok(None) => return Ok(None),
        Err(sqlx::Error::Database(db_err)) if db_err.code().as_deref() == Some("55P03") => {
            return Ok(None);
        }
        Err(_) => {
            budget?;
        }
    }
    let transaction_id = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await?;
    Ok(Some(DirectRequestOperationLock {
        transaction_id,
        request_id,
    }))
}

/// Try to acquire the request operation advisory lock only, without touching the
/// budget singleton row. Used for background sweeps that do not mutate budget bytes.
pub(crate) async fn try_lock_direct_request_operation_only(
    transaction: &mut Transaction<'_, Postgres>,
    request_id: Uuid,
) -> Result<Option<DirectRequestOperationLock>, sqlx::Error> {
    let acquired: bool =
        sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!("chat-operation-id:{request_id}"))
            .fetch_one(&mut **transaction)
            .await?;
    if !acquired {
        return Ok(None);
    }
    let transaction_id = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await?;
    Ok(Some(DirectRequestOperationLock {
        transaction_id,
        request_id,
    }))
}

#[derive(sqlx::FromRow)]
pub(crate) struct DirectRequestLockedDevice {
    pub(crate) user_did: String,
    pub(crate) device_id: Uuid,
    pub(crate) status: String,
    pub(crate) auth_generation: i64,
    pub(crate) key_id: String,
    pub(crate) signing_public_key: Vec<u8>,
    pub(crate) revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Lock both accounts and their complete device/key set in canonical order.
/// Enrollment, replenishment and revocation use the same principal prefix, so
/// this read cannot miss an enrollment committed after the principal locks.
pub(crate) async fn lock_direct_request_identity_scope(
    transaction: &mut Transaction<'_, Postgres>,
    dids: &[String],
) -> Result<Vec<DirectRequestLockedDevice>, sqlx::Error> {
    sqlx::query("SELECT user_did FROM chat.principals WHERE user_did=ANY($1) ORDER BY convert_to(user_did,'UTF8') FOR UPDATE")
        .bind(dids).fetch_all(&mut **transaction).await?;
    sqlx::query("SELECT user_did,device_id FROM chat.devices WHERE user_did=ANY($1) ORDER BY convert_to(user_did,'UTF8'),uuid_send(device_id) FOR UPDATE")
        .bind(dids).fetch_all(&mut **transaction).await?;
    sqlx::query("SELECT user_did,device_id,key_id FROM chat.device_keys WHERE user_did=ANY($1) ORDER BY convert_to(user_did,'UTF8'),uuid_send(device_id),convert_to(key_id,'UTF8') FOR UPDATE")
        .bind(dids).fetch_all(&mut **transaction).await?;
    sqlx::query_as("SELECT d.user_did,d.device_id,d.status,d.auth_generation,k.key_id,k.signing_public_key,k.revoked_at FROM chat.devices d JOIN chat.device_keys k USING(user_did,device_id) WHERE d.user_did=ANY($1) ORDER BY convert_to(d.user_did,'UTF8'),uuid_send(d.device_id)")
        .bind(dids).fetch_all(&mut **transaction).await
}
