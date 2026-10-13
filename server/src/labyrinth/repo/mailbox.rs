//! The personal mailbox (`MailboxStore`, design §2 "Mailbox"). Every call
//! reads or writes the caller DID's own mailbox; Labyrinth-level membership
//! is enforced cryptographically by epoch MACs (SPEC §5.4), not here.

use chrono::{DateTime, Utc};
use sqlx::PgConnection;

use super::{binding, directory, order, stored_json, PageReq, TimeRange};
use crate::labyrinth::auth::Caller;
use crate::labyrinth::error::{is_unique_violation, LabyrinthError, LabyrinthResult};
use crate::labyrinth::tid::next_tid;
use crate::labyrinth::wire::bytes::check_datetime;
use crate::labyrinth::wire::io::{Received, ServerOrder};
use crate::labyrinth::wire::records::{Device, Epoch, EpochMember, OwnerBatch, VirtualDevice};

/// What one write adds to the mailbox counters (design Y6 quotas).
#[derive(Default)]
struct Charge {
    bytes: i64,
    records: i64,
    epochs: i64,
    vdevices: i64,
}

/// Add to the owner's counters, creating the mailbox row on first use. A
/// quota CHECK violation surfaces as `QuotaExceeded`. Takes the owner's
/// mailbox lock ([`binding::lock_mailbox`]), so the row never appears under
/// a request that found none.
async fn charge(
    conn: &mut PgConnection,
    owner: &str,
    c: Charge,
    at: DateTime<Utc>,
) -> LabyrinthResult<()> {
    binding::lock_mailbox(conn, owner).await?;
    sqlx::query(
        "INSERT INTO labyrinth.mailboxes \
           (owner_did, bytes_used, record_count, epoch_count, vdevice_count, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         ON CONFLICT (owner_did) DO UPDATE SET \
           bytes_used = labyrinth.mailboxes.bytes_used + EXCLUDED.bytes_used, \
           record_count = labyrinth.mailboxes.record_count + EXCLUDED.record_count, \
           epoch_count = labyrinth.mailboxes.epoch_count + EXCLUDED.epoch_count, \
           vdevice_count = labyrinth.mailboxes.vdevice_count + EXCLUDED.vdevice_count",
    )
    .bind(owner)
    .bind(c.bytes)
    .bind(c.records)
    .bind(c.epochs)
    .bind(c.vdevices)
    .bind(at)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

pub async fn create_device(
    conn: &mut PgConnection,
    caller: &Caller,
    rec: &Received<Device>,
    at: DateTime<Utc>,
) -> LabyrinthResult<String> {
    rec.value.validate()?;
    binding::verify_chat_binding(caller, &rec.value)?;
    let owner = caller.did.as_str();
    let key = rec.value.device_key_pubkey.array::<32>("deviceKeyPubkey")?;
    // A physical device bootstraps (and binds) the calling chat device; a
    // virtual one binds nothing, so only a bound chat device may add it.
    // Otherwise any chat device could create the mailbox row of an account
    // whose mailbox lives in its PDS Space.
    let is_virtual = rec.value.r#virtual;
    if is_virtual {
        binding::require_bound(conn, caller, None).await?;
    }
    charge(
        conn,
        owner,
        Charge {
            bytes: rec.bytes.into(),
            records: 1,
            ..Charge::default()
        },
        at,
    )
    .await?;
    let inserted = sqlx::query(
        "INSERT INTO labyrinth.devices \
           (owner_did, device_key, record, record_bytes, is_virtual, revoked_at, created_at, \
            chat_device_id, chat_key_id) \
         VALUES ($1, $2, $3::jsonb, $4, $5, $6, $7, $8, $9) ON CONFLICT DO NOTHING",
    )
    .bind(owner)
    .bind(key.as_slice())
    .bind(&rec.text)
    .bind(rec.bytes)
    .bind(is_virtual)
    .bind(&rec.value.revoked_at)
    .bind(at)
    .bind(caller.device_id)
    .bind(&caller.key_id)
    .execute(&mut *conn)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(LabyrinthError::already_exists());
    }
    Ok(hex::encode(key))
}

/// Set `revokedAt` once (a no-op if already set) and delete the device's
/// ORF state in the same transaction.
pub async fn mark_device_revoked(
    conn: &mut PgConnection,
    caller: &Caller,
    key: &[u8; 32],
    revoked_at: &str,
) -> LabyrinthResult<()> {
    check_datetime("revokedAt", revoked_at)?;
    let owner = caller.did.as_str();
    binding::require_bound(conn, caller, None).await?;
    let exists: Option<Option<String>> = sqlx::query_scalar(
        "SELECT revoked_at FROM labyrinth.devices \
          WHERE owner_did = $1 AND device_key = $2 FOR UPDATE",
    )
    .bind(owner)
    .bind(key.as_slice())
    .fetch_optional(&mut *conn)
    .await?;
    match exists {
        None => return Err(LabyrinthError::not_found("DeviceNotFound")),
        Some(Some(_)) => {}
        Some(None) => {
            sqlx::query(
                "UPDATE labyrinth.devices SET revoked_at = $3 \
                  WHERE owner_did = $1 AND device_key = $2",
            )
            .bind(owner)
            .bind(key.as_slice())
            .bind(revoked_at)
            .execute(&mut *conn)
            .await?;
        }
    }
    super::orf::delete(conn, owner, key).await
}

const DEVICE_JSON: &str = "(CASE WHEN revoked_at IS NULL THEN record \
     ELSE jsonb_set(record, '{revokedAt}', to_jsonb(revoked_at)) END)::text";

pub async fn get_device(
    conn: &mut PgConnection,
    owner: &str,
    key: &[u8; 32],
) -> LabyrinthResult<Option<serde_json::Value>> {
    let text: Option<String> = sqlx::query_scalar(&format!(
        "SELECT {DEVICE_JSON} FROM labyrinth.devices WHERE owner_did = $1 AND device_key = $2"
    ))
    .bind(owner)
    .bind(key.as_slice())
    .fetch_optional(&mut *conn)
    .await?;
    text.as_deref().map(stored_json).transpose()
}

/// Devices ordered by key; the cursor is the last key in hex.
pub async fn list_devices(
    conn: &mut PgConnection,
    owner: &str,
    page: &PageReq,
) -> LabyrinthResult<(Vec<serde_json::Value>, Option<String>)> {
    let after = hex_cursor(page)?;
    let rows: Vec<(Vec<u8>, String)> = sqlx::query_as(&format!(
        "SELECT device_key, {DEVICE_JSON} FROM labyrinth.devices \
          WHERE owner_did = $1 AND device_key > $2 ORDER BY device_key LIMIT $3"
    ))
    .bind(owner)
    .bind(after)
    .bind(page.limit() + 1)
    .fetch_all(&mut *conn)
    .await?;
    keyed_page(rows, page.limit())
}

fn hex_cursor(page: &PageReq) -> LabyrinthResult<Vec<u8>> {
    match &page.cursor {
        None => Ok(Vec::new()),
        Some(c) => hex::decode(c).map_err(|_| LabyrinthError::invalid("cursor is not valid")),
    }
}

/// Split `limit + 1` byte-keyed rows into a page and its next cursor (the
/// last key in hex).
fn keyed_page(
    mut rows: Vec<(Vec<u8>, String)>,
    limit: i64,
) -> LabyrinthResult<(Vec<serde_json::Value>, Option<String>)> {
    let more = rows.len() as i64 > limit;
    rows.truncate(limit as usize);
    let cursor = if more {
        rows.last().map(|(k, _)| hex::encode(k))
    } else {
        None
    };
    let items = rows
        .iter()
        .map(|(_, text)| stored_json(text))
        .collect::<LabyrinthResult<_>>()?;
    Ok((items, cursor))
}

/// `createEpoch`: the epoch, its initial members and its directory head,
/// atomically. Returns the backend epochID ([CB-9]).
pub async fn create_epoch(
    conn: &mut PgConnection,
    caller: &Caller,
    epoch: &Received<Epoch>,
    members: &[Received<EpochMember>],
    at: DateTime<Utc>,
) -> LabyrinthResult<(i64, u64)> {
    epoch.value.validate()?;
    let owner = caller.did.as_str();
    if members.len() > 256 {
        return Err(LabyrinthError::invalid("at most 256 members"));
    }
    let n = epoch.value.public.epoch_number;
    for m in members {
        m.value.validate()?;
        if m.value.epoch_number != n {
            return Err(LabyrinthError::invalid(
                "member epochNumber differs from the epoch",
            ));
        }
    }
    // The mailbox lock before the head-directory lock (record_head), as in
    // publishEpochHead.
    binding::lock_mailbox(conn, owner).await?;
    binding::require_bound(conn, caller, Some(&epoch.value.opened_by.0)).await?;
    let member_keys: Vec<Vec<u8>> = members
        .iter()
        .map(|m| m.value.device_key_pubkey.0.clone())
        .collect();
    binding::require_registered(conn, owner, &member_keys).await?;
    // The head directory row (design §1a); a different head under a taken
    // number is the [CB-9] race and reads as RecordAlreadyExists here.
    directory::record_head(conn, caller, &epoch.value.public, at)
        .await
        .map_err(|e| {
            if e.name() == "EpochHeadConflict" {
                LabyrinthError::already_exists()
            } else {
                e
            }
        })?;
    let bytes: i64 =
        i64::from(epoch.bytes) + members.iter().map(|m| i64::from(m.bytes)).sum::<i64>();
    let records = 1 + members.len() as i64;
    charge(
        conn,
        owner,
        Charge {
            bytes,
            records,
            epochs: 1,
            vdevices: 0,
        },
        at,
    )
    .await?;
    let public = &epoch.value.public;
    let inserted: Result<i64, sqlx::Error> = sqlx::query_scalar(
        "INSERT INTO labyrinth.epochs \
           (owner_did, epoch_number, epoch_head, previous_epoch_head, opened_by, record, \
            record_bytes, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8) RETURNING epoch_id",
    )
    .bind(owner)
    .bind(n as i64)
    .bind(&public.epoch_head.0)
    .bind(public.previous_epoch_head.as_ref().map(|b| b.0.clone()))
    .bind(&epoch.value.opened_by.0)
    .bind(&epoch.text)
    .bind(epoch.bytes)
    .bind(at)
    .fetch_one(&mut *conn)
    .await;
    let epoch_id = match inserted {
        Ok(id) => id,
        Err(e) if is_unique_violation(&e) => return Err(LabyrinthError::already_exists()),
        Err(e) => return Err(e.into()),
    };
    for m in members {
        insert_member(conn, owner, m, at).await?;
    }
    Ok((epoch_id, n))
}

async fn insert_member(
    conn: &mut PgConnection,
    owner: &str,
    m: &Received<EpochMember>,
    at: DateTime<Utc>,
) -> LabyrinthResult<()> {
    let key = m.value.device_key_pubkey.array::<32>("deviceKeyPubkey")?;
    let inserted = sqlx::query(
        "INSERT INTO labyrinth.epoch_members \
           (owner_did, epoch_number, device_key, record, record_bytes, created_at) \
         VALUES ($1, $2, $3, $4::jsonb, $5, $6) ON CONFLICT DO NOTHING",
    )
    .bind(owner)
    .bind(m.value.epoch_number as i64)
    .bind(key.as_slice())
    .bind(&m.text)
    .bind(m.bytes)
    .bind(at)
    .execute(&mut *conn)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(LabyrinthError::already_exists());
    }
    Ok(())
}

async fn epoch_exists(conn: &mut PgConnection, owner: &str, n: u64) -> LabyrinthResult<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM labyrinth.epochs WHERE owner_did = $1 AND epoch_number = $2)",
    )
    .bind(owner)
    .bind(n as i64)
    .fetch_one(&mut *conn)
    .await?)
}

pub async fn create_epoch_member(
    conn: &mut PgConnection,
    caller: &Caller,
    m: &Received<EpochMember>,
    at: DateTime<Utc>,
) -> LabyrinthResult<()> {
    m.value.validate()?;
    let owner = caller.did.as_str();
    binding::require_bound(conn, caller, None).await?;
    binding::require_registered(conn, owner, &[m.value.device_key_pubkey.0.clone()]).await?;
    if !epoch_exists(conn, owner, m.value.epoch_number).await? {
        return Err(LabyrinthError::not_found("EpochNotFound"));
    }
    charge(
        conn,
        owner,
        Charge {
            bytes: m.bytes.into(),
            records: 1,
            ..Charge::default()
        },
        at,
    )
    .await?;
    insert_member(conn, owner, m, at).await
}

pub async fn get_epoch(
    conn: &mut PgConnection,
    owner: &str,
    n: u64,
) -> LabyrinthResult<Option<(String, serde_json::Value)>> {
    let row: Option<(i64, String)> = sqlx::query_as(
        "SELECT epoch_id, record::text FROM labyrinth.epochs \
          WHERE owner_did = $1 AND epoch_number = $2",
    )
    .bind(owner)
    .bind(n as i64)
    .fetch_optional(&mut *conn)
    .await?;
    row.map(|(id, text)| Ok((id.to_string(), stored_json(&text)?)))
        .transpose()
}

/// Epochs ascending by number; the cursor is the last number.
pub async fn list_epochs(
    conn: &mut PgConnection,
    owner: &str,
    page: &PageReq,
) -> LabyrinthResult<(Vec<(String, serde_json::Value)>, Option<String>)> {
    let after = match &page.cursor {
        None => -1,
        Some(_) => page.seq_cursor()?,
    };
    let mut rows: Vec<(i64, i64, String)> = sqlx::query_as(
        "SELECT epoch_number, epoch_id, record::text FROM labyrinth.epochs \
          WHERE owner_did = $1 AND epoch_number > $2 ORDER BY epoch_number LIMIT $3",
    )
    .bind(owner)
    .bind(after)
    .bind(page.limit() + 1)
    .fetch_all(&mut *conn)
    .await?;
    let more = rows.len() as i64 > page.limit();
    rows.truncate(page.limit() as usize);
    let cursor = more.then(|| rows.last().map(|r| r.0.to_string())).flatten();
    let items = rows
        .into_iter()
        .map(|(_, id, text)| Ok((id.to_string(), stored_json(&text)?)))
        .collect::<LabyrinthResult<_>>()?;
    Ok((items, cursor))
}

pub async fn list_epoch_members(
    conn: &mut PgConnection,
    owner: &str,
    n: u64,
    page: &PageReq,
) -> LabyrinthResult<(Vec<serde_json::Value>, Option<String>)> {
    if !epoch_exists(conn, owner, n).await? {
        return Err(LabyrinthError::not_found("EpochNotFound"));
    }
    let rows: Vec<(Vec<u8>, String)> = sqlx::query_as(
        "SELECT device_key, record::text FROM labyrinth.epoch_members \
          WHERE owner_did = $1 AND epoch_number = $2 AND device_key > $3 \
          ORDER BY device_key LIMIT $4",
    )
    .bind(owner)
    .bind(n as i64)
    .bind(hex_cursor(page)?)
    .bind(page.limit() + 1)
    .fetch_all(&mut *conn)
    .await?;
    keyed_page(rows, page.limit())
}

/// `createVirtualDevice`: the bundle, and optionally its epoch membership and
/// evolved ORF state, in one transaction.
pub async fn create_virtual_device(
    conn: &mut PgConnection,
    caller: &Caller,
    rec: &Received<VirtualDevice>,
    member: Option<&Received<EpochMember>>,
    orf_parent: Option<([u8; 32], [u8; 32])>,
    at: DateTime<Utc>,
) -> LabyrinthResult<()> {
    rec.value.validate()?;
    let owner = caller.did.as_str();
    binding::require_bound(conn, caller, None).await?;
    let id = rec.value.vdevice_id.array::<16>("vdeviceId")?;
    let key = rec.value.device_key_pubkey.array::<32>("deviceKeyPubkey")?;
    charge(
        conn,
        owner,
        Charge {
            bytes: rec.bytes.into(),
            records: 1,
            epochs: 0,
            vdevices: 1,
        },
        at,
    )
    .await?;
    let inserted = sqlx::query(
        "INSERT INTO labyrinth.virtual_devices \
           (owner_did, vdevice_id, device_key, record, record_bytes, created_at) \
         VALUES ($1, $2, $3, $4::jsonb, $5, $6) ON CONFLICT DO NOTHING",
    )
    .bind(owner)
    .bind(id.as_slice())
    .bind(key.as_slice())
    .bind(&rec.text)
    .bind(rec.bytes)
    .bind(at)
    .execute(&mut *conn)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(LabyrinthError::already_exists());
    }
    if let Some(m) = member {
        create_epoch_member(conn, caller, m, at).await?;
    }
    if let Some(parent) = orf_parent {
        super::orf::register(conn, owner, &key, Some(parent), at).await?;
    }
    Ok(())
}

/// A bundle's record with the server's `lastUsedAt` (J2) projected in.
const VDEVICE_JSON: &str = "(CASE WHEN last_used_at IS NULL THEN record \
     ELSE jsonb_set(record, '{lastUsedAt}', \
       to_jsonb(to_char(last_used_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'))) \
     END)::text";

/// `getVirtualDevice`; reading a bundle also records it as used (J2).
pub async fn get_virtual_device(
    conn: &mut PgConnection,
    owner: &str,
    id: &[u8; 16],
    at: DateTime<Utc>,
) -> LabyrinthResult<Option<serde_json::Value>> {
    sqlx::query(
        "UPDATE labyrinth.virtual_devices SET last_used_at = $3 \
          WHERE owner_did = $1 AND vdevice_id = $2",
    )
    .bind(owner)
    .bind(id.as_slice())
    .bind(at)
    .execute(&mut *conn)
    .await?;
    let text: Option<String> = sqlx::query_scalar(&format!(
        "SELECT {VDEVICE_JSON} FROM labyrinth.virtual_devices \
          WHERE owner_did = $1 AND vdevice_id = $2"
    ))
    .bind(owner)
    .bind(id.as_slice())
    .fetch_optional(&mut *conn)
    .await?;
    text.as_deref().map(stored_json).transpose()
}

pub async fn list_virtual_devices(
    conn: &mut PgConnection,
    owner: &str,
    page: &PageReq,
) -> LabyrinthResult<(Vec<serde_json::Value>, Option<String>)> {
    let rows: Vec<(Vec<u8>, String)> = sqlx::query_as(&format!(
        "SELECT vdevice_id, {VDEVICE_JSON} FROM labyrinth.virtual_devices \
              WHERE owner_did = $1 AND vdevice_id > $2 ORDER BY vdevice_id LIMIT $3"
    ))
    .bind(owner)
    .bind(hex_cursor(page)?)
    .bind(page.limit() + 1)
    .fetch_all(&mut *conn)
    .await?;
    keyed_page(rows, page.limit())
}

/// `appendOwnerBatch`: a server TID and the per-mailbox order stamp. Only a
/// bound chat device writes its account's archive.
pub async fn append_owner_batch(
    conn: &mut PgConnection,
    caller: &Caller,
    rec: &Received<OwnerBatch>,
    at: DateTime<Utc>,
) -> LabyrinthResult<(String, ServerOrder)> {
    rec.value.validate()?;
    let owner = caller.did.as_str();
    binding::require_bound(conn, caller, None).await?;
    charge(
        conn,
        owner,
        Charge {
            bytes: rec.bytes.into(),
            records: 1,
            ..Charge::default()
        },
        at,
    )
    .await?;
    let seq: i64 = sqlx::query_scalar(
        "UPDATE labyrinth.mailboxes SET next_owner_seq = next_owner_seq + 1 \
          WHERE owner_did = $1 RETURNING next_owner_seq - 1",
    )
    .bind(owner)
    .fetch_one(&mut *conn)
    .await?;
    let (min_ts, max_ts) = rec.value.ts_range();
    let rkey = next_tid();
    sqlx::query(
        "INSERT INTO labyrinth.owner_batches \
           (owner_did, rkey, thread_id, min_ts, max_ts, seq, record, record_bytes, received_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9)",
    )
    .bind(owner)
    .bind(&rkey)
    .bind(&rec.value.thread_id)
    .bind(min_ts as i64)
    .bind(max_ts as i64)
    .bind(seq)
    .bind(&rec.text)
    .bind(rec.bytes)
    .bind(at)
    .execute(&mut *conn)
    .await?;
    Ok((rkey, order(seq, None, at)))
}

/// One `listOwnerBatches` item.
pub struct OwnerBatchRow {
    pub rkey: String,
    pub record: serde_json::Value,
    pub order: ServerOrder,
}

/// Owner batches of a thread holding an item in `range`'s sender window and
/// received in its server window, in seq order (newest first when
/// `page.reverse`). The cursor is the last scanned seq, so a page may hold
/// fewer items than the limit while more remain.
pub async fn list_owner_batches(
    conn: &mut PgConnection,
    owner: &str,
    thread_id: &str,
    range: TimeRange,
    page: &PageReq,
) -> LabyrinthResult<(Vec<OwnerBatchRow>, Option<String>)> {
    let sql = format!(
        "SELECT seq, rkey, record::text, received_at FROM labyrinth.owner_batches o \
          WHERE owner_did = $1 AND thread_id = $2 AND seq {cmp} $3 \
            AND ($4::bigint IS NULL OR max_ts >= $4) \
            AND ($5::bigint IS NULL OR min_ts < $5) \
            AND {received} \
          ORDER BY seq {dir} LIMIT $6",
        cmp = page.seq_cmp(),
        dir = page.seq_dir(),
        received = super::thread::received_in("o", "$7", "$8"),
    );
    let mut rows: Vec<(i64, String, String, DateTime<Utc>)> = sqlx::query_as(&sql)
        .bind(owner)
        .bind(thread_id)
        .bind(page.seq_bound()?)
        .bind(range.from_ms)
        .bind(range.until_ms)
        .bind(page.limit() + 1)
        .bind(range.since)
        .bind(range.until)
        .fetch_all(&mut *conn)
        .await?;
    let more = rows.len() as i64 > page.limit();
    rows.truncate(page.limit() as usize);
    let cursor = more.then(|| rows.last().map(|r| r.0.to_string())).flatten();
    let mut items = Vec::with_capacity(rows.len());
    for (seq, rkey, text, received_at) in rows {
        let batch: OwnerBatch = serde_json::from_str(&text).map_err(|error| {
            tracing::error!(?error, "stored owner batch does not parse");
            LabyrinthError::internal()
        })?;
        if batch.items.iter().any(|i| range.contains(i.timestamp)) {
            items.push(OwnerBatchRow {
                rkey,
                record: stored_json(&text)?,
                order: order(seq, None, received_at),
            });
        }
    }
    Ok((items, cursor))
}
