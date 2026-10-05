//! Attachment references (labyrinth SPEC §8, whitepaper v1.1 p.41-43; gap
//! audit G-P0-1, decision J4; migration `20261004100005`).
//!
//! * **Entitlement at put.** The blob must be a bound attachment of the
//!   named conversation whose application binding names exactly this
//!   message, and the calling chat device must hold the application interval
//!   covering that entry: the same arm chat's `authorize_blob_read` uses, minus
//!   its short unbound window, because Labyrinth is long-term history.
//! * **Unlinkability.** Only keyed digests of the owner and the message are
//!   stored (`crate::labyrinth::digest`); one message per blob.
//! * **Access at get.** ORF index and token MAC must match, the blob must
//!   still be bound to that message and not deleted or expired, and the
//!   message must still exist for the caller (p.42).

use chrono::{DateTime, Utc};
use sqlx::PgConnection;
use uuid::Uuid;

use super::ct_eq;
use super::liveness::{self, Liveness};
use super::orf::{orf_not_found, state};
use crate::labyrinth::auth::Caller;
use crate::labyrinth::digest;
use crate::labyrinth::error::{LabyrinthError, LabyrinthResult};
use crate::labyrinth::orf::{server_map, ATTACHMENT_INDEX_DOMAIN, ATTACHMENT_TOKEN_DOMAIN};
use crate::labyrinth::wire::bytes::check_str;

/// The ORF-blinded part of a reference request.
pub struct Blinded {
    pub device_key: [u8; 32],
    pub index: [u8; 32],
    pub token_salt: [u8; 32],
}

/// `putAttachmentRef` / `getAttachmentBlob` message coordinates.
pub struct MessageRef {
    pub thread_id: String,
    pub message_id: String,
}

impl MessageRef {
    pub fn conversation(&self) -> LabyrinthResult<Uuid> {
        super::thread::parse_thread_id(&self.thread_id)
    }

    fn check(&self) -> LabyrinthResult<()> {
        check_str("messageId", &self.message_id, 128)?;
        self.conversation().map(|_| ())
    }
}

fn not_entitled() -> LabyrinthError {
    LabyrinthError::forbidden(
        "AttachmentNotEntitled",
        "the blob is not an attachment of this message the calling device may read",
    )
}

fn not_found() -> LabyrinthError {
    LabyrinthError::not_found("NotFound")
}

pub(crate) fn parse_uuid(what: &str, value: &str) -> LabyrinthResult<Uuid> {
    let id = Uuid::parse_str(value)
        .map_err(|_| LabyrinthError::invalid(format!("{what} is not a UUID")))?;
    if id.hyphenated().to_string() != value {
        return Err(LabyrinthError::invalid(format!(
            "{what} must be a canonical lowercase UUID"
        )));
    }
    Ok(id)
}

/// SQL: the author (binding owner) of `blob` ($1) when it is a live, bound
/// attachment whose application binding is in conversation $2 for chat
/// message $3, outside any pending direct request.
const BOUND_TO_MESSAGE: &str = "SELECT bb.owner_did FROM chat.blobs b \
       JOIN chat.blob_bindings bb ON bb.blob_id = b.blob_id \
      WHERE b.blob_id = $1 AND b.purpose = 'attachment' AND b.status = 'bound' \
        AND b.object_store_key IS NOT NULL \
        AND bb.binding_kind = 'application' AND bb.conversation_id = $2 \
        AND bb.message_id = $3 \
        AND NOT EXISTS (SELECT 1 FROM chat.direct_request_publications p \
              LEFT JOIN chat.direct_request_lifecycle l USING (request_id) \
             WHERE p.conversation_id = bb.conversation_id \
               AND COALESCE(l.consent, 'pending') = 'pending') \
        AND {EXTRA}";

fn unsent() -> LabyrinthError {
    LabyrinthError::new(
        axum::http::StatusCode::GONE,
        "MessageRedacted",
        "the message was unsent; its attachments cannot be referenced",
    )
}

/// The caller's device holds an application interval covering the entry.
const DEVICE_INTERVAL: &str = "EXISTS (SELECT 1 FROM chat.application_intervals i \
      WHERE i.conversation_id = bb.conversation_id AND i.recipient_did = $4 \
        AND i.recipient_device_id = $5 AND bb.entry_seq >= i.start_seq \
        AND (i.terminal_seq IS NULL OR bb.entry_seq <= i.terminal_seq))";

/// `putAttachmentRef`.
pub async fn put(
    conn: &mut PgConnection,
    caller: &Caller,
    blinded: &Blinded,
    msg: &MessageRef,
    blob_id: &str,
    at: DateTime<Utc>,
) -> LabyrinthResult<()> {
    let key = digest::key()?;
    msg.check()?;
    let conversation = msg.conversation()?;
    let blob = parse_uuid("blobId", blob_id)?;
    let s = state(conn, &caller.did, &blinded.device_key)
        .await?
        .ok_or_else(orf_not_found)?;
    // Not a chat message id: no binding can name it.
    let chat_message = Uuid::parse_str(&msg.message_id).map_err(|_| not_entitled())?;
    // Lock the blob row so object GC (which claims FOR UPDATE) cannot reclaim
    // it between this check and the pin this reference creates.
    sqlx::query("SELECT 1 FROM chat.blobs WHERE blob_id = $1 FOR SHARE")
        .bind(blob)
        .fetch_optional(&mut *conn)
        .await?;
    let sql = BOUND_TO_MESSAGE.replace("{EXTRA}", DEVICE_INTERVAL);
    let author: String = sqlx::query_scalar(&sql)
        .bind(blob)
        .bind(conversation)
        .bind(chat_message)
        .bind(&caller.did)
        .bind(caller.device_id)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or_else(not_entitled)?;
    let message_digest = digest::message(&key, &msg.thread_id, &msg.message_id);
    // Finding 9: an unsent message's attachments stay revoked. The sender
    // copy is checked here when this DS sequences the conversation; the
    // sequencer's redaction announcements (`invalidateMessages`) cover the
    // rest.
    if is_redacted(conn, &key, &message_digest, &author, conversation, &msg.message_id).await? {
        return Err(unsent());
    }
    sqlx::query(
        "INSERT INTO labyrinth.attachment_blobs (blob_id, message_digest, created_at) \
         VALUES ($1, $2, $3) ON CONFLICT (blob_id) DO NOTHING",
    )
    .bind(blob)
    .bind(message_digest.as_slice())
    .bind(at)
    .execute(&mut *conn)
    .await?;
    let pinned: Vec<u8> = sqlx::query_scalar(
        "SELECT message_digest FROM labyrinth.attachment_blobs WHERE blob_id = $1",
    )
    .bind(blob)
    .fetch_one(&mut *conn)
    .await?;
    if !ct_eq(&pinned, &message_digest) {
        return Err(LabyrinthError::new(
            axum::http::StatusCode::CONFLICT,
            "AttachmentAlreadyReferenced",
            "this blob is already referenced by another message",
        ));
    }
    let index = server_map(s, ATTACHMENT_INDEX_DOMAIN, blinded.index)?;
    let salt = server_map(s, ATTACHMENT_TOKEN_DOMAIN, blinded.token_salt)?;
    let token_mac = digest::token_mac(&salt, &msg.thread_id, &msg.message_id);
    let inserted = sqlx::query(
        "INSERT INTO labyrinth.attachment_refs \
           (orf_index, owner_digest, message_digest, blob_id, token_mac, created_at, \
            state_digest) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING",
    )
    .bind(index.as_slice())
    .bind(digest::owner(&key, &caller.did).as_slice())
    .bind(message_digest.as_slice())
    .bind(blob)
    .bind(token_mac.as_slice())
    .bind(at)
    .bind(digest::orf_state(&key, &caller.did, &blinded.device_key).as_slice())
    .execute(&mut *conn)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(LabyrinthError::already_exists());
    }
    Ok(())
}

struct RefRow {
    message_digest: Vec<u8>,
    blob_id: Uuid,
    token_mac: Vec<u8>,
    created_at: DateTime<Utc>,
}

async fn find(
    conn: &mut PgConnection,
    caller: &Caller,
    device_key: &[u8; 32],
    blinded_index: [u8; 32],
) -> LabyrinthResult<([u8; 32], RefRow)> {
    let key = digest::key()?;
    let s = state(conn, &caller.did, device_key)
        .await?
        .ok_or_else(orf_not_found)?;
    let index = server_map(s, ATTACHMENT_INDEX_DOMAIN, blinded_index)?;
    let row: Option<(Vec<u8>, Uuid, Vec<u8>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT message_digest, blob_id, token_mac, created_at FROM labyrinth.attachment_refs \
          WHERE orf_index = $1 AND owner_digest = $2",
    )
    .bind(index.as_slice())
    .bind(digest::owner(&key, &caller.did).as_slice())
    .fetch_optional(&mut *conn)
    .await?;
    let (message_digest, blob_id, token_mac, created_at) = row.ok_or_else(not_found)?;
    Ok((
        s,
        RefRow {
            message_digest,
            blob_id,
            token_mac,
            created_at,
        },
    ))
}

/// `getAttachmentRef`: when the reference was stored.
pub async fn created_at(
    conn: &mut PgConnection,
    caller: &Caller,
    device_key: &[u8; 32],
    blinded_index: [u8; 32],
) -> LabyrinthResult<DateTime<Utc>> {
    Ok(find(conn, caller, device_key, blinded_index)
        .await?
        .1
        .created_at)
}

/// `deleteAttachmentRef`: idempotent.
pub async fn delete(
    conn: &mut PgConnection,
    caller: &Caller,
    device_key: &[u8; 32],
    blinded_index: [u8; 32],
) -> LabyrinthResult<()> {
    let key = digest::key()?;
    let s = state(conn, &caller.did, device_key)
        .await?
        .ok_or_else(orf_not_found)?;
    let index = server_map(s, ATTACHMENT_INDEX_DOMAIN, blinded_index)?;
    super::open_retention_scope(conn).await?;
    sqlx::query("DELETE FROM labyrinth.attachment_refs WHERE orf_index = $1 AND owner_digest = $2")
        .bind(index.as_slice())
        .bind(digest::owner(&key, &caller.did).as_slice())
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Where a token-authorized attachment's bytes live.
pub struct AttachmentObject {
    pub object_store_key: String,
    pub ciphertext_size: i64,
    pub ciphertext_sha256: Vec<u8>,
    /// The message's sender state still to be read from this sequencer.
    pub pending_remote: Option<RemoteCheck>,
}

/// A liveness question for a remote conversation's sequencer.
pub struct RemoteCheck {
    pub sequencer: String,
    pub author: String,
    /// The reader is the author and keeps its own archive copy.
    pub own_copy: bool,
}

/// `getAttachmentBlob` authorization. Every refusal reads as `NotFound`.
pub async fn authorize(
    conn: &mut PgConnection,
    caller: &Caller,
    blinded: &Blinded,
    msg: &MessageRef,
) -> LabyrinthResult<AttachmentObject> {
    msg.check()?;
    let key = digest::key()?;
    let (s, row) = find(conn, caller, &blinded.device_key, blinded.index).await?;
    let salt = server_map(s, ATTACHMENT_TOKEN_DOMAIN, blinded.token_salt)?;
    let mac = digest::token_mac(&salt, &msg.thread_id, &msg.message_id);
    let message_digest = digest::message(&key, &msg.thread_id, &msg.message_id);
    if !ct_eq(&mac, &row.token_mac) || !ct_eq(&message_digest, &row.message_digest) {
        return Err(not_found());
    }
    let conversation = msg.conversation()?;
    let chat_message = Uuid::parse_str(&msg.message_id).map_err(|_| not_found())?;
    let sql = BOUND_TO_MESSAGE.replace("{EXTRA}", "TRUE");
    let author: String = sqlx::query_scalar(&sql)
        .bind(row.blob_id)
        .bind(conversation)
        .bind(chat_message)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or_else(not_found)?;
    let pending_remote = match liveness::check(
        conn,
        &key,
        &caller.did,
        conversation,
        &msg.message_id,
        &author,
    )
    .await?
    {
        Liveness::Known(true) => None,
        Liveness::Known(false) => return Err(not_found()),
        Liveness::Remote(check) => Some(check),
    };
    let (object_store_key, ciphertext_size, ciphertext_sha256): (Option<String>, i64, Vec<u8>) =
        sqlx::query_as(
            "SELECT object_store_key, ciphertext_size, ciphertext_sha256 FROM chat.blobs \
              WHERE blob_id = $1",
        )
        .bind(row.blob_id)
        .fetch_one(&mut *conn)
        .await?;
    Ok(AttachmentObject {
        object_store_key: object_store_key.ok_or_else(not_found)?,
        ciphertext_size,
        ciphertext_sha256,
        pending_remote,
    })
}

/// Whether `author`'s message is redacted, per the local sender copy or a
/// recorded redaction announcement.
async fn is_redacted(
    conn: &mut PgConnection,
    key: &[u8; 32],
    message_digest: &[u8; 32],
    author: &str,
    conversation: Uuid,
    message_id: &str,
) -> LabyrinthResult<bool> {
    if liveness::announced_redacted(conn, key, message_digest, author).await? {
        return Ok(true);
    }
    let (_, redacted) = liveness::sender_state(conn, author, conversation, message_id, author).await?;
    Ok(redacted)
}

/// Revoke `author`'s messages of a conversation (unsend, account deletion,
/// or the sequencer's announcement of either): delete every reference to an
/// attachment `author` bound to one of them, and record the redaction so no
/// new reference can be put. Without a configured digest key no reference
/// can exist.
pub async fn invalidate_messages(
    conn: &mut PgConnection,
    thread_id: &str,
    author: &str,
    message_ids: &[String],
    at: DateTime<Utc>,
) -> LabyrinthResult<u64> {
    let Some(key) = digest::configured_key() else {
        return Ok(0);
    };
    let digests: Vec<Vec<u8>> = message_ids
        .iter()
        .map(|m| digest::message(&key, thread_id, m).to_vec())
        .collect();
    let author_digest = digest::owner(&key, author);
    sqlx::query(
        "INSERT INTO labyrinth.redacted_messages (message_digest, author_digest, created_at) \
         SELECT d, $2, $3 FROM unnest($1::bytea[]) AS d ON CONFLICT DO NOTHING",
    )
    .bind(&digests)
    .bind(author_digest.as_slice())
    .bind(at)
    .execute(&mut *conn)
    .await?;
    super::open_retention_scope(conn).await?;
    Ok(sqlx::query(
        "DELETE FROM labyrinth.attachment_refs r \
          WHERE r.message_digest = ANY($1) \
            AND EXISTS (SELECT 1 FROM chat.blob_bindings bb \
                         WHERE bb.blob_id = r.blob_id AND bb.owner_did = $2)",
    )
    .bind(&digests)
    .bind(author)
    .execute(&mut *conn)
    .await?
    .rows_affected())
}

/// Delete every reference `did` owns (mailbox purge).
pub async fn delete_owned(conn: &mut PgConnection, did: &str) -> LabyrinthResult<u64> {
    let Some(key) = digest::configured_key() else {
        tracing::warn!("no attachment digest key; owned references cannot be located");
        return Ok(0);
    };
    super::open_retention_scope(conn).await?;
    Ok(
        sqlx::query("DELETE FROM labyrinth.attachment_refs WHERE owner_digest = $1")
            .bind(digest::owner(&key, did).as_slice())
            .execute(&mut *conn)
            .await?
            .rows_affected(),
    )
}

/// Release the references created through deleted ORF states (finding 5):
/// drain up to `limit` tombstones. Returns the references removed.
pub async fn release_deleted_states(conn: &mut PgConnection, limit: i64) -> LabyrinthResult<u64> {
    let tombstones: Vec<(i64, String, Vec<u8>)> = sqlx::query_as(
        "SELECT tombstone_id, owner_did, device_key FROM labyrinth.orf_state_tombstones \
          ORDER BY tombstone_id LIMIT $1 FOR UPDATE SKIP LOCKED",
    )
    .bind(limit)
    .fetch_all(&mut *conn)
    .await?;
    let Some(key) = digest::configured_key() else {
        return Ok(0);
    };
    let mut removed = 0;
    super::open_retention_scope(conn).await?;
    for (id, owner, device_key) in tombstones {
        if let Ok(device_key) = <[u8; 32]>::try_from(device_key.as_slice()) {
            removed += sqlx::query("DELETE FROM labyrinth.attachment_refs WHERE state_digest = $1")
                .bind(digest::orf_state(&key, &owner, &device_key).as_slice())
                .execute(&mut *conn)
                .await?
                .rows_affected();
        }
        sqlx::query("DELETE FROM labyrinth.orf_state_tombstones WHERE tombstone_id = $1")
            .bind(id)
            .execute(&mut *conn)
            .await?;
    }
    Ok(removed)
}
