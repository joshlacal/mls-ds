//! Erasable recovery-share rows and activity events.
//!
//! Every access is scoped to the authenticated caller's DID by the handler.
//! The external tombstone journal is checked on reads and synced before any
//! erasure SQL, so a failed transaction cannot make a deleted share readable.

use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgConnection};
use uuid::Uuid;

use crate::labyrinth::auth::Caller;
use crate::labyrinth::error::{LabyrinthError, LabyrinthResult};
use crate::labyrinth::recovery_crypto::RecoveryCrypto;
use crate::labyrinth::recovery_tombstones::RecoveryTombstones;

const MAX_LIVE_PER_DID: i64 = 16;
const MAX_NEW_PER_DEVICE_DAY: i64 = 8;

fn unavailable() -> LabyrinthError {
    LabyrinthError::not_found("RecoveryShareUnavailable")
}

fn conflict() -> LabyrinthError {
    LabyrinthError::new(
        StatusCode::CONFLICT,
        "RecoveryShareConflict",
        "a different share or fetch verifier already exists for this vdeviceId",
    )
}

fn limit_reached() -> LabyrinthError {
    LabyrinthError::new(
        StatusCode::TOO_MANY_REQUESTS,
        "RecoveryShareLimitReached",
        "recovery-share limit reached",
    )
}

fn journal_failure(error: String) -> LabyrinthError {
    tracing::error!(%error, "recovery tombstone journal failed");
    LabyrinthError::internal()
}

fn fixed<const N: usize>(bytes: Vec<u8>) -> LabyrinthResult<[u8; N]> {
    bytes.try_into().map_err(|_| LabyrinthError::internal())
}

fn constant_time_equal<const N: usize>(a: &[u8; N], b: &[u8; N]) -> bool {
    a.iter().zip(b).fold(0_u8, |difference, (left, right)| {
        difference | (left ^ right)
    }) == 0
}

/// Only an active, non-revoked chat device may manage shares. Request
/// admission has already verified its signed current chat key and locked the
/// device/key pair; this extra check covers the device's revocation timestamp.
pub async fn require_active_chat_device(
    conn: &mut PgConnection,
    caller: &Caller,
) -> LabyrinthResult<()> {
    let active: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat.devices \
           WHERE user_did=$1 AND device_id=$2 \
             AND status='active' AND revoked_at IS NULL)",
    )
    .bind(&caller.did)
    .bind(caller.device_id)
    .fetch_one(&mut *conn)
    .await?;
    if caller.status == "active" && active {
        Ok(())
    } else {
        Err(LabyrinthError::forbidden(
            "ChatDeviceNotActive",
            "the calling chat device is not active",
        ))
    }
}

#[derive(FromRow)]
struct RawShare {
    mechanism: String,
    encrypted_share: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
    kek_key_id: Option<String>,
    fetch_verifier: Option<Vec<u8>>,
    created_by_device_id: Uuid,
    created_at: DateTime<Utc>,
    last_fetched_at: Option<DateTime<Utc>>,
    fetch_count: i64,
    deleted_at: Option<DateTime<Utc>>,
}

impl RawShare {
    fn live(self) -> LabyrinthResult<Option<StoredShare>> {
        if self.deleted_at.is_some() {
            return Ok(None);
        }
        Ok(Some(StoredShare {
            mechanism: self.mechanism,
            encrypted_share: fixed(self.encrypted_share.ok_or_else(LabyrinthError::internal)?)?,
            nonce: fixed(self.nonce.ok_or_else(LabyrinthError::internal)?)?,
            kek_key_id: self.kek_key_id.ok_or_else(LabyrinthError::internal)?,
            fetch_verifier: fixed(self.fetch_verifier.ok_or_else(LabyrinthError::internal)?)?,
            created_by_device_id: self.created_by_device_id,
            created_at: self.created_at,
            last_fetched_at: self.last_fetched_at,
            fetch_count: self.fetch_count,
        }))
    }
}

pub struct StoredShare {
    pub mechanism: String,
    pub encrypted_share: [u8; 48],
    pub nonce: [u8; 12],
    pub kek_key_id: String,
    pub fetch_verifier: [u8; 32],
    pub created_by_device_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub last_fetched_at: Option<DateTime<Utc>>,
    pub fetch_count: i64,
}

/// Store a new share. A repeat of the exact plaintext/verifier/mechanism is
/// idempotent even though AES-GCM would choose a different nonce on retry.
pub async fn put(
    conn: &mut PgConnection,
    did: &str,
    vid: &[u8; 16],
    share: &[u8; 32],
    verifier: &[u8; 32],
    mechanism: &str,
    actor: Uuid,
    at: DateTime<Utc>,
    crypto: &RecoveryCrypto,
    journal: &RecoveryTombstones,
) -> LabyrinthResult<DateTime<Utc>> {
    if !matches!(mechanism, "code" | "passkey") {
        return Err(LabyrinthError::invalid("mechanism must be code or passkey"));
    }
    super::advisory_lock(conn, &format!("labyrinth.recovery_shares:{did}")).await?;
    if journal.contains(did, vid) {
        return Err(conflict());
    }
    let row: Option<RawShare> = sqlx::query_as(
        "SELECT mechanism,encrypted_share,nonce,kek_key_id,fetch_verifier, \
                created_by_device_id,created_at,last_fetched_at,fetch_count,deleted_at \
           FROM labyrinth.recovery_shares WHERE owner_did=$1 AND vdevice_id=$2 FOR UPDATE",
    )
    .bind(did)
    .bind(vid.as_slice())
    .fetch_optional(&mut *conn)
    .await?;
    if let Some(row) = row {
        let Some(existing) = row.live()? else {
            return Err(conflict());
        };
        let existing_share = crypto.decrypt_share(
            did,
            vid,
            &existing.kek_key_id,
            &existing.nonce,
            &existing.encrypted_share,
        )?;
        if existing.mechanism == mechanism
            && constant_time_equal(&existing.fetch_verifier, verifier)
            && constant_time_equal(existing_share.as_ref(), share)
        {
            return Ok(existing.created_at);
        }
        return Err(conflict());
    }
    let live: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM labyrinth.recovery_shares \
         WHERE owner_did=$1 AND deleted_at IS NULL",
    )
    .bind(did)
    .fetch_one(&mut *conn)
    .await?;
    let recent: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM labyrinth.recovery_share_events \
         WHERE owner_did=$1 AND actor_device_id=$2 AND kind='put' \
           AND at > $3 - INTERVAL '1 day'",
    )
    .bind(did)
    .bind(actor)
    .bind(at)
    .fetch_one(&mut *conn)
    .await?;
    if live >= MAX_LIVE_PER_DID || recent >= MAX_NEW_PER_DEVICE_DAY {
        return Err(limit_reached());
    }
    let (key_id, nonce, encrypted) = crypto.encrypt(did, vid, share)?;
    sqlx::query(
        "INSERT INTO labyrinth.recovery_shares \
         (owner_did,vdevice_id,mechanism,encrypted_share,nonce,kek_key_id, \
          fetch_verifier,created_by_device_id,created_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(did)
    .bind(vid.as_slice())
    .bind(mechanism)
    .bind(encrypted.as_slice())
    .bind(nonce.as_slice())
    .bind(key_id)
    .bind(verifier.as_slice())
    .bind(actor)
    .bind(at)
    .execute(&mut *conn)
    .await?;
    event(conn, did, vid, "put", Some(actor), at).await?;
    Ok(at)
}

/// Fetch a live row, checking the out-of-DB erasure journal on both sides of
/// the SQL read. Unknown, deleted, and journal-erased rows are indistinguishable.
pub async fn get(
    conn: &mut PgConnection,
    did: &str,
    vid: &[u8; 16],
    journal: &RecoveryTombstones,
) -> LabyrinthResult<Option<StoredShare>> {
    if journal.contains(did, vid) {
        return Ok(None);
    }
    let row: Option<RawShare> = sqlx::query_as(
        "SELECT mechanism,encrypted_share,nonce,kek_key_id,fetch_verifier, \
                created_by_device_id,created_at,last_fetched_at,fetch_count,deleted_at \
           FROM labyrinth.recovery_shares \
          WHERE owner_did=$1 AND vdevice_id=$2",
    )
    .bind(did)
    .bind(vid.as_slice())
    .fetch_optional(&mut *conn)
    .await?;
    if journal.contains(did, vid) {
        return Ok(None);
    }
    row.map(RawShare::live).transpose().map(Option::flatten)
}

async fn event(
    conn: &mut PgConnection,
    did: &str,
    vid: &[u8; 16],
    kind: &str,
    actor: Option<Uuid>,
    at: DateTime<Utc>,
) -> LabyrinthResult<()> {
    sqlx::query(
        "INSERT INTO labyrinth.recovery_share_events \
         (owner_did,vdevice_id,kind,actor_device_id,at) VALUES($1,$2,$3,$4,$5)",
    )
    .bind(did)
    .bind(vid.as_slice())
    .bind(kind)
    .bind(actor)
    .bind(at)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

pub async fn record_fetch(
    conn: &mut PgConnection,
    did: &str,
    vid: &[u8; 16],
    actor: Uuid,
    at: DateTime<Utc>,
    verify: bool,
    journal: &RecoveryTombstones,
) -> LabyrinthResult<()> {
    if journal.contains(did, vid) {
        return Err(unavailable());
    }
    // The creator gets exactly one uncounted read-back shortly after put.
    // A later `purpose=verify` is a restore fetch, so the original device
    // cannot hide repeated access by labeling it as verification forever.
    let first_verify = if verify {
        sqlx::query(
            "UPDATE labyrinth.recovery_shares SET verified_at=$3 \
             WHERE owner_did=$1 AND vdevice_id=$2 AND deleted_at IS NULL \
               AND created_by_device_id=$4 AND verified_at IS NULL \
               AND created_at <= $3 AND created_at >= $3 - INTERVAL '10 minutes'",
        )
        .bind(did)
        .bind(vid.as_slice())
        .bind(at)
        .bind(actor)
        .execute(&mut *conn)
        .await?
        .rows_affected()
            == 1
    } else {
        false
    };
    if !first_verify {
        let affected = sqlx::query(
            "UPDATE labyrinth.recovery_shares \
             SET fetch_count=fetch_count+1, \
                 last_fetched_at=GREATEST(created_at,last_fetched_at,$3) \
             WHERE owner_did=$1 AND vdevice_id=$2 AND deleted_at IS NULL",
        )
        .bind(did)
        .bind(vid.as_slice())
        .bind(at)
        .execute(&mut *conn)
        .await?
        .rows_affected();
        if affected != 1 || journal.contains(did, vid) {
            return Err(unavailable());
        }
    }
    event(
        conn,
        did,
        vid,
        if first_verify { "verify" } else { "fetch" },
        Some(actor),
        at,
    )
    .await
}

pub async fn record_denied(
    conn: &mut PgConnection,
    did: &str,
    vid: &[u8; 16],
    actor: Uuid,
    at: DateTime<Utc>,
) -> LabyrinthResult<()> {
    event(conn, did, vid, "fetchDenied", Some(actor), at).await
}

/// Erase one share after the journal has durably accepted its tombstone.
/// Repeated deletion returns its original deletion timestamp.
pub async fn delete(
    conn: &mut PgConnection,
    did: &str,
    vid: &[u8; 16],
    actor: Uuid,
    at: DateTime<Utc>,
    journal: &RecoveryTombstones,
) -> LabyrinthResult<Option<DateTime<Utc>>> {
    super::advisory_lock(conn, &format!("labyrinth.recovery_shares:{did}")).await?;
    let row: Option<(Option<DateTime<Utc>>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT deleted_at,created_at FROM labyrinth.recovery_shares \
         WHERE owner_did=$1 AND vdevice_id=$2 FOR UPDATE",
    )
    .bind(did)
    .bind(vid.as_slice())
    .fetch_optional(&mut *conn)
    .await?;
    let Some((deleted_at, created_at)) = row else {
        return Ok(None);
    };
    if let Some(deleted_at) = deleted_at {
        // Preserve an existing database tombstone in the out-of-DB journal
        // before answering an idempotent delete.
        journal
            .append_delete(did, vid, deleted_at)
            .map_err(journal_failure)?;
        return Ok(Some(deleted_at));
    }
    let at = at.max(created_at);
    journal
        .append_delete(did, vid, at)
        .map_err(journal_failure)?;
    let effective_at = journal.deleted_at(did, vid).unwrap_or(at);
    erase_row(conn, did, vid, effective_at).await?;
    event(conn, did, vid, "delete", Some(actor), effective_at).await?;
    Ok(Some(effective_at))
}

async fn erase_row(
    conn: &mut PgConnection,
    did: &str,
    vid: &[u8; 16],
    at: DateTime<Utc>,
) -> LabyrinthResult<()> {
    sqlx::query(
        "UPDATE labyrinth.recovery_shares \
         SET encrypted_share=NULL,nonce=NULL,kek_key_id=NULL,fetch_verifier=NULL,deleted_at=$3 \
         WHERE owner_did=$1 AND vdevice_id=$2 AND deleted_at IS NULL",
    )
    .bind(did)
    .bind(vid.as_slice())
    .bind(at)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

#[derive(Clone, Debug)]
pub struct ShareView {
    pub vdevice_id: [u8; 16],
    pub mechanism: String,
    pub created_at: DateTime<Utc>,
    pub created_by_device_id: Uuid,
    pub last_fetched_at: Option<DateTime<Utc>>,
    pub fetch_count: i64,
}

/// Cursor is the last lower-case vdeviceId hex, not a row offset.
pub async fn list(
    conn: &mut PgConnection,
    did: &str,
    cursor: Option<&str>,
    limit: i64,
    journal: &RecoveryTombstones,
) -> LabyrinthResult<(Vec<ShareView>, Option<String>)> {
    let after = cursor
        .map(|c| {
            if c.len() != 32 || c != c.to_ascii_lowercase() {
                return Err(LabyrinthError::invalid("cursor is invalid"));
            }
            let bytes = hex::decode(c).map_err(|_| LabyrinthError::invalid("cursor is invalid"))?;
            fixed::<16>(bytes)
        })
        .transpose()?;
    let rows: Vec<(
        Vec<u8>,
        String,
        DateTime<Utc>,
        Uuid,
        Option<DateTime<Utc>>,
        i64,
    )> = sqlx::query_as(
        "SELECT vdevice_id,mechanism,created_at,created_by_device_id, \
                    last_fetched_at,fetch_count \
               FROM labyrinth.recovery_shares \
              WHERE owner_did=$1 AND deleted_at IS NULL \
                AND ($2::bytea IS NULL OR vdevice_id>$2) \
              ORDER BY vdevice_id LIMIT $3",
    )
    .bind(did)
    .bind(after.map(|v| v.to_vec()))
    .bind(limit.clamp(1, 100) + 1)
    .fetch_all(&mut *conn)
    .await?;
    let has_more = rows.len() as i64 > limit.clamp(1, 100);
    let mut shares = Vec::new();
    let mut last = None;
    for (vid_bytes, mechanism, created_at, creator, last_fetched_at, fetch_count) in
        rows.into_iter().take(limit.clamp(1, 100) as usize)
    {
        let vid = fixed::<16>(vid_bytes)?;
        last = Some(hex::encode(vid));
        if !journal.contains(did, &vid) {
            shares.push(ShareView {
                vdevice_id: vid,
                mechanism,
                created_at,
                created_by_device_id: creator,
                last_fetched_at,
                fetch_count,
            });
        }
    }
    Ok((shares, has_more.then_some(last).flatten()))
}

#[derive(Clone, Debug)]
pub struct EventView {
    pub id: i64,
    pub vdevice_id: [u8; 16],
    pub kind: String,
    pub actor_device_id: Option<Uuid>,
    pub at: DateTime<Utc>,
}

pub async fn list_events(
    conn: &mut PgConnection,
    did: &str,
    cursor: Option<&str>,
    limit: i64,
) -> LabyrinthResult<(Vec<EventView>, Option<String>)> {
    let after = cursor
        .map(|c| {
            c.parse::<i64>()
                .ok()
                .filter(|id| *id >= 0 && id.to_string() == c)
                .ok_or_else(|| LabyrinthError::invalid("cursor is invalid"))
        })
        .transpose()?
        .unwrap_or(0);
    let rows: Vec<(i64, Vec<u8>, String, Option<Uuid>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT id,vdevice_id,kind,actor_device_id,at \
         FROM labyrinth.recovery_share_events \
         WHERE owner_did=$1 AND id>$2 ORDER BY id LIMIT $3",
    )
    .bind(did)
    .bind(after)
    .bind(limit.clamp(1, 100) + 1)
    .fetch_all(&mut *conn)
    .await?;
    let has_more = rows.len() as i64 > limit.clamp(1, 100);
    let mut events = Vec::new();
    for (id, vid, kind, actor, at) in rows.into_iter().take(limit.clamp(1, 100) as usize) {
        events.push(EventView {
            id,
            vdevice_id: fixed(vid)?,
            kind,
            actor_device_id: actor,
            at,
        });
    }
    let next = if has_more {
        events.last().map(|event| event.id.to_string())
    } else {
        None
    };
    Ok((events, next))
}

/// Purge all live shares of one DID, journaling and syncing each tombstone
/// before clearing any database secret. The caller must hold a transaction.
pub async fn purge(
    conn: &mut PgConnection,
    did: &str,
    at: DateTime<Utc>,
    journal: &RecoveryTombstones,
) -> LabyrinthResult<usize> {
    super::advisory_lock(conn, &format!("labyrinth.recovery_shares:{did}")).await?;
    let rows: Vec<(Vec<u8>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT vdevice_id,created_at FROM labyrinth.recovery_shares \
         WHERE owner_did=$1 AND deleted_at IS NULL ORDER BY vdevice_id FOR UPDATE",
    )
    .bind(did)
    .fetch_all(&mut *conn)
    .await?;
    for (vid, created_at) in &rows {
        let vid = fixed::<16>(vid.clone())?;
        journal
            .append_purge(did, &vid, at.max(*created_at))
            .map_err(journal_failure)?;
    }
    for (vid, _) in &rows {
        let vid = fixed::<16>(vid.clone())?;
        let effective_at = journal.deleted_at(did, &vid).unwrap_or(at);
        erase_row(conn, did, &vid, effective_at).await?;
        event(conn, did, &vid, "purge", None, effective_at).await?;
    }
    Ok(rows.len())
}
