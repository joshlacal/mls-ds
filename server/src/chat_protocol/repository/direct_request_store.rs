// Durable request-attempt authority. No row here is a conversation or an event.
// This module deliberately has no HTTP route: admission, policy and signed
// receipts must be composed before the feature can be enabled.
use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, Postgres, Transaction};
use thiserror::Error;
use uuid::Uuid;

const PREPARATION_TTL_SECONDS: i64 = 300;
const MAX_BUNDLE_BYTES: i64 = 8_388_608;
const MAX_PENDING_ACCOUNT_BYTES: i64 = 67_108_864;
const MAX_PENDING_GLOBAL_BYTES: i64 = 1_073_741_824;
const MAX_RETAINED_GLOBAL_BYTES: i64 = 8_589_934_592;
const MIN_PACKAGE_HORIZON_SECONDS: i64 = 604_800 + 300 + PREPARATION_TTL_SECONDS;

#[derive(Debug, Error)]
pub(crate) enum DirectRequestStoreError {
    #[error("request authority does not match its immutable attempt")]
    IdentityConflict,
    #[error("invalid direct request signature")]
    InvalidSignature,
    #[error("request authority belongs to another transaction")]
    ForeignTransaction,
    #[error("request preparation has expired")]
    Expired,
    #[error("request resources are exhausted")]
    QuotaExceeded,
    #[error("direct request policy denied")]
    PolicyDenied,
    #[error("recipient request keys unavailable")]
    RecipientKeysUnavailable,
    #[error("included device authority changed")]
    IncludedAuthorityChanged,
    #[error("request receipt or snapshot is invalid")]
    InvalidReceipt,
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

/// Exact attempt identity. Construction is private to this repository module;
/// the forthcoming signed-admission compositor must construct this only from
/// the strict verified preparation/cancellation projection.
#[derive(Clone, Debug)]
struct AttemptIdentity {
    request_id: Uuid,
    actor_did: String,
    actor_device_id: Uuid,
    actor_key_id: String,
    actor_auth_generation: i64,
    recipient_did: String,
    prepare_digest: Vec<u8>,
}

#[derive(Debug, Clone, FromRow)]
struct AttemptRow {
    request_id: Uuid,
    actor_did: String,
    actor_device_id: Uuid,
    actor_key_id: String,
    actor_auth_generation: i64,
    recipient_did: String,
    prepare_digest: Vec<u8>,
    status: String,
    prepare_response: Option<Vec<u8>>,
    selected_digest: Option<Vec<u8>>,
    lease_expires_at: Option<DateTime<Utc>>,
    terminal_response: Option<Vec<u8>>,
    terminal_response_sha256: Option<Vec<u8>>,
    publication_digest: Option<Vec<u8>>,
    reserved_bytes: i64,
}
impl AttemptRow {
    fn matches(&self, identity: &AttemptIdentity) -> bool {
        self.request_id == identity.request_id
            && self.actor_did == identity.actor_did
            && self.actor_device_id == identity.actor_device_id
            && self.actor_key_id == identity.actor_key_id
            && self.actor_auth_generation == identity.actor_auth_generation
            && self.recipient_did == identity.recipient_did
            && self.prepare_digest == identity.prepare_digest
    }
    fn terminal_bytes(&self) -> Result<Option<&[u8]>, DirectRequestStoreError> {
        if self.status == "prepared" {
            return Ok(None);
        }
        let bytes = self
            .terminal_response
            .as_deref()
            .ok_or(DirectRequestStoreError::InvalidReceipt)?;
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        if self.terminal_response_sha256.as_deref() != Some(digest.as_slice()) {
            return Err(DirectRequestStoreError::InvalidReceipt);
        }
        Ok(Some(bytes))
    }
}

/// Transaction witness minted only after the prelude operation/budget lock.
/// No constructor is exposed to handlers or other repositories.
struct LockedAttempt {
    transaction_id: String,
    identity: AttemptIdentity,
    row: Option<AttemptRow>,
}

async fn transaction_id(tx: &mut Transaction<'_, Postgres>) -> Result<String, sqlx::Error> {
    sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **tx)
        .await
}

async fn require_transaction(
    tx: &mut Transaction<'_, Postgres>,
    lock: &LockedAttempt,
) -> Result<(), DirectRequestStoreError> {
    if transaction_id(tx).await? != lock.transaction_id {
        return Err(DirectRequestStoreError::ForeignTransaction);
    }
    Ok(())
}

// The prelude owns acquisition of the advisory request lock. A caller cannot
// insert an Unknown tombstone merely by possessing an untrusted UUID.
async fn load_locked_attempt(
    tx: &mut Transaction<'_, Postgres>,
    identity: AttemptIdentity,
    operation: &super::prelude::DirectRequestOperationLock,
) -> Result<LockedAttempt, DirectRequestStoreError> {
    let txid = transaction_id(tx).await?;
    if operation.transaction_id() != txid || operation.request_id() != identity.request_id {
        return Err(DirectRequestStoreError::ForeignTransaction);
    }
    let collision: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM chat.operation_claims WHERE operation_id=$1) OR EXISTS(SELECT 1 FROM chat.direct_request_key_publications WHERE operation_id=$1) OR EXISTS(SELECT 1 FROM chat.direct_request_acceptance_claims WHERE operation_id=$1)")
        .bind(identity.request_id).fetch_one(&mut **tx).await?;
    if collision {
        return Err(DirectRequestStoreError::IdentityConflict);
    }
    let row: Option<AttemptRow> = sqlx::query_as(
        "SELECT request_id,actor_did,actor_device_id,actor_key_id,actor_auth_generation,recipient_did,prepare_digest,status,prepare_response,selected_digest,lease_expires_at,terminal_response,terminal_response_sha256,publication_digest,reserved_bytes FROM chat.direct_request_attempts WHERE request_id=$1 FOR UPDATE")
        .bind(identity.request_id).fetch_optional(&mut **tx).await?;
    if row.as_ref().is_some_and(|r| !r.matches(&identity)) {
        return Err(DirectRequestStoreError::IdentityConflict);
    }
    Ok(LockedAttempt {
        transaction_id: txid,
        identity,
        row,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TerminalOutcome {
    Published,
    Cancelled,
    Expired,
    Rejected,
    ExistingDirect,
}
impl TerminalOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
            Self::ExistingDirect => "existing-direct",
        }
    }
}

/// Exact terminal replay precedes lease checks. The caller supplies a validated
/// signed receipt; storage preserves its bytes and can never synthesize success.
async fn finish_terminal(
    tx: &mut Transaction<'_, Postgres>,
    lock: LockedAttempt,
    outcome: TerminalOutcome,
    receipt: &[u8],
    publication_digest: Option<&[u8]>,
    now: DateTime<Utc>,
) -> Result<Vec<u8>, DirectRequestStoreError> {
    require_transaction(tx, &lock).await?;
    if let Some(row) = &lock.row {
        if let Some(bytes) = row.terminal_bytes()? {
            if outcome == TerminalOutcome::Published
                && row.status == "published"
                && row.publication_digest.as_deref() != publication_digest
            {
                return Err(DirectRequestStoreError::IdentityConflict);
            }
            return Ok(bytes.to_vec());
        }
    }
    if receipt.is_empty()
        || (outcome == TerminalOutcome::Published
            && publication_digest.map(<[u8]>::len) != Some(32))
    {
        return Err(DirectRequestStoreError::InvalidReceipt);
    }
    let digest = Sha256::digest(receipt).to_vec();
    if let Some(row) = &lock.row {
        if outcome == TerminalOutcome::Published
            && row.lease_expires_at.is_none_or(|expiry| expiry <= now)
        {
            return Err(DirectRequestStoreError::Expired);
        }
        sqlx::query("UPDATE chat.direct_request_attempts SET status=$2,terminal_at=$3,terminal_response=$4,terminal_response_sha256=$5,publication_digest=$6 WHERE request_id=$1 AND status='prepared'")
            .bind(lock.identity.request_id).bind(outcome.as_str()).bind(now).bind(receipt).bind(digest).bind(publication_digest).execute(&mut **tx).await?;
        // Cancelled/expired exposed one-time packages remain reserved forever
        // (until ordinary package expiry/revocation); never return to available.
        sqlx::query("UPDATE chat.direct_request_budget SET pending_bytes=pending_bytes-$1,retained_bytes=retained_bytes-$2 WHERE singleton")
            .bind(if outcome == TerminalOutcome::Published { 0 } else { row.reserved_bytes }).bind(if outcome == TerminalOutcome::Published { 0 } else { row.reserved_bytes })
            .execute(&mut **tx).await?;
    } else {
        if outcome == TerminalOutcome::Published {
            return Err(DirectRequestStoreError::InvalidReceipt);
        }
        let i = &lock.identity;
        sqlx::query("INSERT INTO chat.direct_request_attempts(request_id,actor_did,actor_device_id,actor_key_id,actor_auth_generation,recipient_did,prepare_digest,status,terminal_at,terminal_response,terminal_response_sha256,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$11,$8,$9,$10,$8)")
            .bind(i.request_id).bind(&i.actor_did).bind(i.actor_device_id).bind(&i.actor_key_id).bind(i.actor_auth_generation).bind(&i.recipient_did).bind(&i.prepare_digest).bind(now).bind(receipt).bind(digest).bind(outcome.as_str()).execute(&mut **tx).await?;
    }
    Ok(receipt.to_vec())
}

#[derive(Debug, Clone, FromRow)]
struct SelectedDevice {
    owner_did: String,
    owner_device_id: Uuid,
    owner_key_id: String,
    auth_generation: i64,
    grant_id: Uuid,
    grant_digest: Vec<u8>,
    capability_revision: i64,
    key_package_ref: Vec<u8>,
    wrapper_bytes: Vec<u8>,
    signed_grant: Vec<u8>,
    expires_at: DateTime<Utc>,
}

/// Called only after canonical principals/devices/keys are locked in prelude.
/// Replenishment and enrollment also lock those principals, so the snapshot
/// cannot change between this selection and reservation.
async fn select_devices(
    tx: &mut Transaction<'_, Postgres>,
    lock: &LockedAttempt,
    now: DateTime<Utc>,
) -> Result<Vec<SelectedDevice>, DirectRequestStoreError> {
    require_transaction(tx, lock).await?;
    let horizon = now + Duration::seconds(MIN_PACKAGE_HORIZON_SECONDS);
    let rows: Vec<SelectedDevice> = sqlx::query_as(r#"
        SELECT DISTINCT ON (p.owner_did,p.owner_device_id)
               p.owner_did,p.owner_device_id,p.owner_key_id,p.owner_auth_generation AS auth_generation,
               g.grant_id,g.grant_digest,g.capability_revision,p.key_package_ref,p.wrapper_bytes,
               g.signed_grant,LEAST(p.not_after,g.expires_at) AS expires_at
          FROM chat.key_packages p
          JOIN chat.devices d ON d.user_did=p.owner_did AND d.device_id=p.owner_device_id
          JOIN chat.device_keys k ON k.user_did=p.owner_did AND k.device_id=p.owner_device_id AND k.key_id=p.owner_key_id
          JOIN chat.direct_request_capabilities c ON c.owner_did=p.owner_did AND c.owner_device_id=p.owner_device_id
          JOIN chat.direct_request_grants g ON g.key_package_ref=p.key_package_ref
         WHERE p.owner_did IN ($1,$2) AND (p.owner_did,p.owner_device_id)<>($1,$3)
           AND d.status='active' AND k.revoked_at IS NULL AND p.owner_auth_generation=d.auth_generation
           AND c.enabled AND c.protocol_version='2' AND c.auth_generation=d.auth_generation AND c.owner_key_id=k.key_id
           AND g.revoked_at IS NULL AND g.auth_generation=d.auth_generation
           AND g.protocol_version='2' AND g.profile='encryptedIntroduction1' AND g.expires_at >= $4
           AND p.usage_scope='direct-request' AND p.status='available' AND p.not_before < $5 AND p.not_after >= $4
           AND NOT EXISTS(SELECT 1 FROM chat.direct_request_selected_devices s WHERE s.key_package_ref=p.key_package_ref)
         ORDER BY p.owner_did,p.owner_device_id,p.created_at,p.key_package_ref
    "#).bind(&lock.identity.actor_did).bind(&lock.identity.recipient_did).bind(lock.identity.actor_device_id).bind(horizon).bind(now)
        .fetch_all(&mut **tx).await?;
    if !rows
        .iter()
        .any(|r| r.owner_did == lock.identity.recipient_did)
    {
        return Err(DirectRequestStoreError::RecipientKeysUnavailable);
    }
    if rows.len() > 39 {
        return Err(DirectRequestStoreError::QuotaExceeded);
    }
    Ok(rows)
}

async fn reserve_preparation(
    tx: &mut Transaction<'_, Postgres>,
    lock: &LockedAttempt,
    selected: &[SelectedDevice],
    signed_response: &[u8],
    selection_digest: &[u8],
    now: DateTime<Utc>,
) -> Result<Vec<u8>, DirectRequestStoreError> {
    require_transaction(tx, &lock).await?;
    if let Some(row) = &lock.row {
        if let Some(bytes) = row.terminal_bytes()? {
            return Ok(bytes.to_vec());
        }
        return row
            .prepare_response
            .clone()
            .ok_or(DirectRequestStoreError::InvalidReceipt);
    }
    if signed_response.is_empty()
        || selection_digest.len() != 32
        || selected.is_empty()
        || selected.len() > 39
        || !selected
            .iter()
            .any(|r| r.owner_did == lock.identity.recipient_did)
    {
        return Err(DirectRequestStoreError::InvalidReceipt);
    }
    let i = &lock.identity;
    check_preparation_budget(tx, &lock.identity, now).await?;
    let updated=sqlx::query("UPDATE chat.direct_request_budget SET pending_bytes=pending_bytes+$1,retained_bytes=retained_bytes+$1 WHERE singleton AND (SELECT pending_bytes FROM chat.direct_request_effective_budget)+$1 <= $2 AND retained_bytes+$1 <= $3")
        .bind(MAX_BUNDLE_BYTES).bind(MAX_PENDING_GLOBAL_BYTES).bind(MAX_RETAINED_GLOBAL_BYTES).execute(&mut **tx).await?;
    if updated.rows_affected() != 1 {
        return Err(DirectRequestStoreError::QuotaExceeded);
    }
    sqlx::query("INSERT INTO chat.direct_request_attempts(request_id,actor_did,actor_device_id,actor_key_id,actor_auth_generation,recipient_did,prepare_digest,status,prepare_response,selected_digest,prepared_at,lease_expires_at,reserved_bytes,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,'prepared',$8,$9,$10,$11,$12,$10)")
        .bind(i.request_id).bind(&i.actor_did).bind(i.actor_device_id).bind(&i.actor_key_id).bind(i.actor_auth_generation).bind(&i.recipient_did).bind(&i.prepare_digest)
        .bind(signed_response).bind(selection_digest).bind(now).bind(now+Duration::seconds(PREPARATION_TTL_SECONDS)).bind(MAX_BUNDLE_BYTES).execute(&mut **tx).await?;
    let refs = selected
        .iter()
        .map(|d| d.key_package_ref.clone())
        .collect::<Vec<_>>();
    sqlx::query("SELECT key_package_ref FROM chat.key_packages WHERE key_package_ref=ANY($1) ORDER BY key_package_ref FOR UPDATE")
        .bind(&refs).fetch_all(&mut **tx).await?;
    for device in selected {
        let reserved=sqlx::query("UPDATE chat.key_packages SET status='reserved' WHERE key_package_ref=$1 AND status='available' AND usage_scope='direct-request'")
            .bind(&device.key_package_ref).execute(&mut **tx).await?;
        if reserved.rows_affected() != 1 {
            return Err(DirectRequestStoreError::IncludedAuthorityChanged);
        }
        sqlx::query("INSERT INTO chat.direct_request_selected_devices(request_id,owner_did,owner_device_id,owner_key_id,auth_generation,grant_id,grant_digest,capability_revision,key_package_ref) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)")
            .bind(i.request_id).bind(&device.owner_did).bind(device.owner_device_id).bind(&device.owner_key_id).bind(device.auth_generation).bind(device.grant_id)
            .bind(&device.grant_digest).bind(device.capability_revision).bind(&device.key_package_ref).execute(&mut **tx).await?;
    }
    Ok(signed_response.to_vec())
}

/// Snapshot invalidation is exact: unrelated enrollment and pool churn cannot
/// affect the result, while any included authority revocation/change does.
async fn validate_selected_authority(
    tx: &mut Transaction<'_, Postgres>,
    lock: &LockedAttempt,
    now: DateTime<Utc>,
) -> Result<(), DirectRequestStoreError> {
    require_transaction(tx, lock).await?;
    let invalid: bool=sqlx::query_scalar(r#"
        SELECT EXISTS(SELECT 1 FROM chat.direct_request_selected_devices s
          LEFT JOIN chat.devices d ON d.user_did=s.owner_did AND d.device_id=s.owner_device_id
          LEFT JOIN chat.device_keys k ON k.user_did=s.owner_did AND k.device_id=s.owner_device_id
          LEFT JOIN chat.direct_request_capabilities c ON c.owner_did=s.owner_did AND c.owner_device_id=s.owner_device_id
          LEFT JOIN chat.direct_request_grants g ON g.grant_id=s.grant_id
          LEFT JOIN chat.key_packages p ON p.key_package_ref=s.key_package_ref
         WHERE s.request_id=$1 AND (d.status IS DISTINCT FROM 'active' OR d.auth_generation IS DISTINCT FROM s.auth_generation
           OR k.key_id IS DISTINCT FROM s.owner_key_id OR k.revoked_at IS NOT NULL
           OR c.enabled IS DISTINCT FROM TRUE OR g.capability_revision IS DISTINCT FROM s.capability_revision
           OR c.auth_generation IS DISTINCT FROM s.auth_generation OR c.owner_key_id IS DISTINCT FROM s.owner_key_id
           OR g.grant_digest IS DISTINCT FROM s.grant_digest OR g.revoked_at IS NOT NULL OR g.expires_at<$2
           OR p.status IS DISTINCT FROM 'reserved' OR p.usage_scope IS DISTINCT FROM 'direct-request' OR p.not_after<$2))
    "#).bind(lock.identity.request_id).bind(now+Duration::seconds(604_800+300)).fetch_one(&mut **tx).await?;
    if invalid {
        return Err(DirectRequestStoreError::IncludedAuthorityChanged);
    }
    Ok(())
}

async fn check_preparation_budget(
    tx: &mut Transaction<'_, Postgres>,
    i: &AttemptIdentity,
    now: DateTime<Utc>,
) -> Result<(), DirectRequestStoreError> {
    let (sender_live,pair_live,recipient_live,hourly,account_bytes): (i64,i64,i64,i64,i64) = sqlx::query_as(r#"
        SELECT count(*) FILTER(WHERE status='prepared' AND actor_did=$1),
               count(*) FILTER(WHERE status='prepared' AND actor_did=$1 AND actor_device_id=$2 AND recipient_did=$3),
               count(*) FILTER(WHERE status='prepared' AND recipient_did=$3),
               count(*) FILTER(WHERE prepared_at IS NOT NULL AND actor_did=$1 AND prepared_at>$4-INTERVAL '1 hour'),
               GREATEST(COALESCE(sum(reserved_bytes) FILTER(WHERE status IN('prepared','published') AND NOT EXISTS(SELECT 1 FROM chat.direct_request_pending_releases r WHERE r.request_id=a.request_id) AND (actor_did=$1 OR recipient_did=$1)),0),COALESCE(sum(reserved_bytes) FILTER(WHERE status IN('prepared','published') AND NOT EXISTS(SELECT 1 FROM chat.direct_request_pending_releases r WHERE r.request_id=a.request_id) AND (actor_did=$3 OR recipient_did=$3)),0))::bigint
          FROM chat.direct_request_attempts a
    "#).bind(&i.actor_did).bind(i.actor_device_id).bind(&i.recipient_did).bind(now).fetch_one(&mut **tx).await?;
    if sender_live >= 2
        || pair_live >= 1
        || recipient_live >= 4
        || hourly >= 20
        || account_bytes + MAX_BUNDLE_BYTES > MAX_PENDING_ACCOUNT_BYTES
    {
        return Err(DirectRequestStoreError::QuotaExceeded);
    }
    let (pending, retained): (i64, i64) = sqlx::query_as(
        "SELECT pending_bytes,retained_bytes FROM chat.direct_request_effective_budget WHERE singleton",
    )
    .fetch_one(&mut **tx)
    .await?;
    if pending + MAX_BUNDLE_BYTES > MAX_PENDING_GLOBAL_BYTES
        || retained + MAX_BUNDLE_BYTES > MAX_RETAINED_GLOBAL_BYTES
    {
        return Err(DirectRequestStoreError::QuotaExceeded);
    }
    Ok(())
}
