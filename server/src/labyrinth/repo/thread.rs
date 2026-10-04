//! Per-conversation sender records (`ThreadStore`, design §1b, §2 "Thread",
//! §3).
//!
//! Writes: the author is the authenticated DID, the writing device holds an
//! active leaf in the conversation, every record is stamped with
//! `{seq, chatSeq, receivedAt}` under the conversation row lock
//! (`FOR SHARE`, against the chat append path's `FOR UPDATE`), and batches
//! are single-MEK (Y4). Reads are authorized per MEK: a caller sees MEKs it
//! wrote or was addressed in, and the batches sealed under them. Current
//! membership is not required, so a leaver keeps its addressed history and a
//! late joiner sees nothing sealed before it joined.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use sqlx::PgConnection;
use uuid::Uuid;

use super::{directory, order, stored_json, PageReq, TimeRange};
use crate::labyrinth::auth::Caller;
use crate::labyrinth::error::{LabyrinthError, LabyrinthResult};
use crate::labyrinth::heads::verify_epoch_public;
use crate::labyrinth::tid::next_tid;
use crate::labyrinth::wire::io::{Received, ServerOrder};
use crate::labyrinth::wire::records::{Batch, Mek, MekSender};

fn named(status: u16, name: &'static str, message: &str) -> LabyrinthError {
    LabyrinthError::new(
        axum::http::StatusCode::from_u16(status).expect("valid status"),
        name,
        message,
    )
}

fn not_participant() -> LabyrinthError {
    named(
        403,
        "NotParticipant",
        "the writing device has no active leaf in this conversation",
    )
}

/// `threadId` is a conversation id: a canonical lowercase UUID.
pub fn parse_thread_id(value: &str) -> LabyrinthResult<Uuid> {
    let id = Uuid::parse_str(value)
        .map_err(|_| LabyrinthError::invalid("threadId is not a conversation id"))?;
    if id.hyphenated().to_string() != value {
        return Err(LabyrinthError::invalid(
            "threadId must be a canonical lowercase UUID",
        ));
    }
    Ok(id)
}

/// Lock the conversation row `FOR SHARE` and return its last chat entry seq.
/// Remote conversations are sequenced elsewhere (design §3, Y3).
async fn lock_conversation(conn: &mut PgConnection, conversation_id: Uuid) -> LabyrinthResult<i64> {
    let row: Option<(i64, bool)> = sqlx::query_as(
        "SELECT next_entry_seq, is_remote FROM chat.conversations \
          WHERE conversation_id = $1 FOR SHARE",
    )
    .bind(conversation_id)
    .fetch_optional(&mut *conn)
    .await?;
    match row {
        None => Err(not_participant()),
        Some((_, true)) => Err(LabyrinthError::relay_not_implemented()),
        Some((next, false)) => Ok(next - 1),
    }
}

async fn require_active_leaf(
    conn: &mut PgConnection,
    conversation_id: Uuid,
    caller: &Caller,
) -> LabyrinthResult<()> {
    let active: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat.member_devices \
                        WHERE conversation_id = $1 AND user_did = $2 \
                          AND device_id = $3 AND active)",
    )
    .bind(conversation_id)
    .bind(&caller.did)
    .bind(caller.device_id)
    .fetch_one(&mut *conn)
    .await?;
    if active {
        Ok(())
    } else {
        Err(not_participant())
    }
}

/// The next per-conversation Labyrinth seq (from 1); the counter row lock
/// serializes stamping within a conversation until commit.
async fn next_seq(conn: &mut PgConnection, conversation_id: Uuid) -> LabyrinthResult<i64> {
    Ok(sqlx::query_scalar(
        "INSERT INTO labyrinth.thread_counters (conversation_id, next_seq) VALUES ($1, 2) \
         ON CONFLICT (conversation_id) DO UPDATE \
           SET next_seq = labyrinth.thread_counters.next_seq + 1 \
         RETURNING next_seq - 1",
    )
    .bind(conversation_id)
    .fetch_one(&mut *conn)
    .await?)
}

/// Charge the author's thread-record quota (design Y6: 1 GiB).
async fn charge_author(conn: &mut PgConnection, did: &str, bytes: i32) -> LabyrinthResult<()> {
    sqlx::query(
        "INSERT INTO labyrinth.author_usage (author_did, bytes_used) VALUES ($1, $2) \
         ON CONFLICT (author_did) DO UPDATE \
           SET bytes_used = labyrinth.author_usage.bytes_used + EXCLUDED.bytes_used",
    )
    .bind(did)
    .bind(i64::from(bytes))
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Every recipient DID must be a current participant.
async fn check_recipients(
    conn: &mut PgConnection,
    conversation_id: Uuid,
    dids: &BTreeSet<String>,
) -> LabyrinthResult<()> {
    let list: Vec<String> = dids.iter().cloned().collect();
    let found: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT user_did) FROM chat.participants \
          WHERE conversation_id = $1 AND current_membership AND user_did = ANY($2)",
    )
    .bind(conversation_id)
    .bind(&list)
    .fetch_one(&mut *conn)
    .await?;
    if found == list.len() as i64 {
        Ok(())
    } else {
        Err(named(
            400,
            "RecipientNotParticipant",
            "a recipient is not a participant",
        ))
    }
}

/// `createMek`. Returns `(rkey, order)`.
pub async fn create_mek(
    conn: &mut PgConnection,
    caller: &Caller,
    rec: &Received<Mek>,
    at: DateTime<Utc>,
) -> LabyrinthResult<(String, ServerOrder)> {
    let mek = &rec.value;
    mek.validate()?;
    let conversation_id = parse_thread_id(&mek.thread_id)?;
    let chat_seq = lock_conversation(conn, conversation_id).await?;
    require_active_leaf(conn, conversation_id, caller).await?;
    let (kind, attestation_key_id) = match &mek.sender {
        MekSender::Labyrinth(s) => {
            if s.did != caller.did {
                return Err(named(400, "SenderMismatch", "sender DID is not the caller"));
            }
            let parts = verify_epoch_public(&caller.did, &s.sender_epoch)?;
            let key_id = directory::current_chat_key_id(conn, &caller.did, &parts.attestation_key)
                .await?
                .ok_or_else(|| {
                    named(
                        400,
                        "AttestationNotCurrent",
                        "sender epoch attestation key is not current",
                    )
                })?;
            ("labyrinth", Some(key_id))
        }
        MekSender::Transport(s) => {
            if s.transport_pubkey.0 != caller.signing_key {
                return Err(named(
                    400,
                    "SenderMismatch",
                    "transportPubkey is not the writing device's chat key",
                ));
            }
            ("transport", None)
        }
    };
    let recipients: BTreeSet<String> = mek.recipients.iter().map(|r| r.did.clone()).collect();
    check_recipients(conn, conversation_id, &recipients).await?;
    charge_author(conn, &caller.did, rec.bytes).await?;
    let seq = next_seq(conn, conversation_id).await?;
    let inserted = sqlx::query(
        "INSERT INTO labyrinth.meks \
           (conversation_id, author_did, mek_id, sender_kind, attestation_key_id, \
            writer_device_id, record, record_bytes, seq, chat_seq, received_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10, $11) ON CONFLICT DO NOTHING",
    )
    .bind(conversation_id)
    .bind(&caller.did)
    .bind(&mek.mek_id.0)
    .bind(kind)
    .bind(attestation_key_id)
    .bind(caller.device_id)
    .bind(&rec.text)
    .bind(rec.bytes)
    .bind(seq)
    .bind(chat_seq)
    .bind(at)
    .execute(&mut *conn)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(LabyrinthError::already_exists());
    }
    for did in &recipients {
        sqlx::query(
            "INSERT INTO labyrinth.mek_recipients \
               (conversation_id, mek_id, author_did, recipient_did) VALUES ($1, $2, $3, $4)",
        )
        .bind(conversation_id)
        .bind(&mek.mek_id.0)
        .bind(&caller.did)
        .bind(did)
        .execute(&mut *conn)
        .await?;
    }
    Ok((hex::encode(&mek.mek_id.0), order(seq, Some(chat_seq), at)))
}

/// SQL predicate: MEK row `m` is readable by `$reader`.
const MEK_READABLE: &str = "(m.author_did = $READER OR EXISTS ( \
     SELECT 1 FROM labyrinth.mek_recipients r \
      WHERE r.conversation_id = m.conversation_id AND r.mek_id = m.mek_id \
        AND r.author_did = m.author_did AND r.recipient_did = $READER))";

fn mek_readable(param: &str) -> String {
    MEK_READABLE.replace("$READER", param)
}

/// One `findMeks` / `listBatches` item.
pub struct AuthoredRow {
    pub author: String,
    pub rkey: String,
    pub record: serde_json::Value,
    pub order: ServerOrder,
}

/// `findMeks`: the MEKs with this id the caller wrote or is addressed in.
pub async fn find_meks(
    conn: &mut PgConnection,
    reader: &str,
    conversation_id: Uuid,
    mek_id: &[u8; 12],
    page: &PageReq,
) -> LabyrinthResult<(Vec<AuthoredRow>, Option<String>)> {
    let sql = format!(
        "SELECT m.seq, m.author_did, m.record::text, m.chat_seq, m.received_at \
           FROM labyrinth.meks m \
          WHERE m.conversation_id = $1 AND m.mek_id = $2 AND m.seq > $4 AND {} \
          ORDER BY m.seq LIMIT $5",
        mek_readable("$3")
    );
    let mut rows: Vec<(i64, String, String, i64, DateTime<Utc>)> = sqlx::query_as(&sql)
        .bind(conversation_id)
        .bind(mek_id.as_slice())
        .bind(reader)
        .bind(page.seq_cursor()?)
        .bind(page.limit() + 1)
        .fetch_all(&mut *conn)
        .await?;
    let more = rows.len() as i64 > page.limit();
    rows.truncate(page.limit() as usize);
    let cursor = more.then(|| rows.last().map(|r| r.0.to_string())).flatten();
    let rkey = hex::encode(mek_id);
    let items = rows
        .into_iter()
        .map(|(seq, author, text, chat_seq, at)| {
            Ok(AuthoredRow {
                author,
                rkey: rkey.clone(),
                record: stored_json(&text)?,
                order: order(seq, Some(chat_seq), at),
            })
        })
        .collect::<LabyrinthResult<_>>()?;
    Ok((items, cursor))
}

/// `appendBatch`. Returns `(rkey, order)`.
pub async fn append_batch(
    conn: &mut PgConnection,
    caller: &Caller,
    rec: &Received<Batch>,
    at: DateTime<Utc>,
) -> LabyrinthResult<(String, ServerOrder)> {
    let batch = &rec.value;
    batch.validate()?;
    let conversation_id = parse_thread_id(&batch.thread_id)?;
    let chat_seq = lock_conversation(conn, conversation_id).await?;
    require_active_leaf(conn, conversation_id, caller).await?;
    let mek_id = &batch.items[0].mek_id;
    if batch.items.iter().any(|i| &i.mek_id != mek_id) {
        return Err(named(
            400,
            "MixedMekBatch",
            "a batch is sealed under one MEK",
        ));
    }
    if batch
        .items
        .iter()
        .any(|i| i.sender_transport_pubkey.0 != caller.signing_key)
    {
        return Err(named(
            400,
            "SenderKeyMismatch",
            "senderTransportPubkey is not the caller's",
        ));
    }
    let sql = format!(
        "SELECT count(*), count(*) FILTER (WHERE {}) \
           FROM labyrinth.meks m WHERE m.conversation_id = $1 AND m.mek_id = $2",
        mek_readable("$3")
    );
    let (known, usable): (i64, i64) = sqlx::query_as(&sql)
        .bind(conversation_id)
        .bind(&mek_id.0)
        .bind(&caller.did)
        .fetch_one(&mut *conn)
        .await?;
    if known == 0 {
        return Err(named(400, "UnknownMek", "no such MEK in the conversation"));
    }
    if usable == 0 {
        return Err(named(
            403,
            "NotRecipient",
            "the caller can neither author nor open this MEK",
        ));
    }
    charge_author(conn, &caller.did, rec.bytes).await?;
    let seq = next_seq(conn, conversation_id).await?;
    let (min_ts, max_ts) = batch.ts_range();
    let rkey = next_tid();
    sqlx::query(
        "INSERT INTO labyrinth.batches \
           (conversation_id, author_did, rkey, mek_id, writer_device_id, min_ts, max_ts, \
            record, record_bytes, seq, chat_seq, received_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10, $11, $12)",
    )
    .bind(conversation_id)
    .bind(&caller.did)
    .bind(&rkey)
    .bind(&mek_id.0)
    .bind(caller.device_id)
    .bind(min_ts as i64)
    .bind(max_ts as i64)
    .bind(&rec.text)
    .bind(rec.bytes)
    .bind(seq)
    .bind(chat_seq)
    .bind(at)
    .execute(&mut *conn)
    .await?;
    Ok((rkey, order(seq, Some(chat_seq), at)))
}

/// `listBatches`: batches the caller wrote or whose MEK it can read, in
/// `seq` order, optionally from one sender, holding an item in `range`. The
/// cursor is the last scanned seq.
pub async fn list_batches(
    conn: &mut PgConnection,
    reader: &str,
    conversation_id: Uuid,
    sender: Option<&str>,
    range: TimeRange,
    page: &PageReq,
) -> LabyrinthResult<(Vec<AuthoredRow>, Option<String>)> {
    let sql = format!(
        "SELECT b.seq, b.author_did, b.rkey, b.record::text, b.chat_seq, b.received_at \
           FROM labyrinth.batches b \
          WHERE b.conversation_id = $1 AND b.seq > $3 \
            AND ($4::text IS NULL OR b.author_did = $4) \
            AND ($5::bigint IS NULL OR b.max_ts >= $5) \
            AND ($6::bigint IS NULL OR b.min_ts < $6) \
            AND (b.author_did = $2 OR EXISTS ( \
                  SELECT 1 FROM labyrinth.meks m \
                   WHERE m.conversation_id = b.conversation_id AND m.mek_id = b.mek_id \
                     AND {})) \
          ORDER BY b.seq LIMIT $7",
        mek_readable("$2")
    );
    let mut rows: Vec<(i64, String, String, String, i64, DateTime<Utc>)> = sqlx::query_as(&sql)
        .bind(conversation_id)
        .bind(reader)
        .bind(page.seq_cursor()?)
        .bind(sender)
        .bind(range.from_ms)
        .bind(range.until_ms)
        .bind(page.limit() + 1)
        .fetch_all(&mut *conn)
        .await?;
    let more = rows.len() as i64 > page.limit();
    rows.truncate(page.limit() as usize);
    let cursor = more.then(|| rows.last().map(|r| r.0.to_string())).flatten();
    let mut items = Vec::with_capacity(rows.len());
    for (seq, author, rkey, text, chat_seq, at) in rows {
        let batch: Batch = serde_json::from_str(&text).map_err(|error| {
            tracing::error!(?error, "stored batch does not parse");
            LabyrinthError::internal()
        })?;
        if batch.items.iter().any(|i| range.contains(i.timestamp)) {
            items.push(AuthoredRow {
                author,
                rkey,
                record: stored_json(&text)?,
                order: order(seq, Some(chat_seq), at),
            });
        }
    }
    Ok((items, cursor))
}
