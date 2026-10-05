//! Retention (decisions J1, J2; migration `20261004100006`): unsend by
//! author redaction, mailbox and account purge, recovery-bundle lifecycle,
//! and GC of idempotency records. Records are otherwise kept until their
//! owner deletes them: Labyrinth is the long-term history archive.
//!
//! Every delete or record rewrite goes through a SQL function that opens the
//! transaction-bound retention scope the immutability triggers check.

use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use sqlx::PgConnection;
use uuid::Uuid;

use super::attachments;
use crate::labyrinth::auth::Caller;
use crate::labyrinth::error::{LabyrinthError, LabyrinthResult};
use crate::labyrinth::wire::bytes::{check_str, Bytes};
use crate::storage::DbPool;

/// Signature prefix of an author's redaction request ([CB-38]).
pub const REDACTION_PREFIX: &str = "catbird.labyrinth.redaction:";
/// Recovery bundles backed by keychain or passkey expire after this long
/// without use (J2).
pub const VIRTUAL_DEVICE_IDLE_DAYS: i64 = 180;
/// Idempotency records are kept this long.
pub const OPERATION_RETENTION_DAYS: i64 = 7;

/// `redactMessage.redaction`: the author's signed request.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionIn {
    pub transport_pubkey: Bytes,
    pub sig: Bytes,
}

fn invalid_redaction(message: &str) -> LabyrinthError {
    LabyrinthError::invalid_named("InvalidRedaction", message.to_owned())
}

/// The signed message: `prefix || "did=" || did || ";message_id=" || id ||
/// ";thread_id=" || hex(utf8(threadId))`.
pub fn redaction_message(did: &str, message_id: &str, thread_id: &str) -> Vec<u8> {
    format!(
        "{REDACTION_PREFIX}did={did};message_id={message_id};thread_id={}",
        hex::encode(thread_id.as_bytes())
    )
    .into_bytes()
}

/// `redactMessage`: the caller's own items with `message_id` in the
/// conversation. The request must be signed by the calling chat device.
pub async fn redact_message(
    conn: &mut PgConnection,
    caller: &Caller,
    thread_id: &str,
    message_id: &str,
    redaction: &RedactionIn,
    at: DateTime<Utc>,
) -> LabyrinthResult<i64> {
    check_str("messageId", message_id, 128)?;
    let conversation = super::thread::parse_thread_id(thread_id)?;
    super::thread::lock_local_conversation(conn, conversation).await?;
    let key: [u8; 32] = redaction
        .transport_pubkey
        .array("redaction.transportPubkey")?;
    if key != caller.signing_key {
        return Err(invalid_redaction(
            "redaction.transportPubkey is not the calling chat device's key",
        ));
    }
    let sig: [u8; 64] = redaction.sig.array("redaction.sig")?;
    VerifyingKey::from_bytes(&key)
        .map_err(|_| LabyrinthError::internal())?
        .verify_strict(
            &redaction_message(&caller.did, message_id, thread_id),
            &Signature::from_bytes(&sig),
        )
        .map_err(|_| invalid_redaction("redaction.sig does not verify"))?;
    let marker = serde_json::json!({
        "transportPubkey": redaction.transport_pubkey,
        "sig": redaction.sig,
    });
    let redacted = redact(
        conn,
        conversation,
        &caller.did,
        Some(&[message_id.to_owned()]),
        marker,
        at,
    )
    .await?;
    attachments::invalidate_messages(conn, thread_id, &[message_id.to_owned()]).await?;
    Ok(redacted)
}

async fn redact(
    conn: &mut PgConnection,
    conversation: Uuid,
    author: &str,
    messages: Option<&[String]>,
    marker: serde_json::Value,
    at: DateTime<Utc>,
) -> LabyrinthResult<i64> {
    let n: i32 = sqlx::query_scalar("SELECT labyrinth.redact_items($1, $2, $3, $4, $5)")
        .bind(conversation)
        .bind(author)
        .bind(messages)
        .bind(marker)
        .bind(at)
        .fetch_one(&mut *conn)
        .await?;
    Ok(i64::from(n))
}

/// Redact every item `author` wrote in conversations this DS sequences
/// (account deletion; the redaction carries no signature). With `home_ds`
/// (a relayed `purgeAuthor`), only conversations where that DS is the
/// author's home DS (its latest participant period's `ds_did`). Returns the
/// number of items redacted.
pub async fn redact_author(
    conn: &mut PgConnection,
    author: &str,
    home_ds: Option<&str>,
    at: DateTime<Utc>,
) -> LabyrinthResult<i64> {
    let threads: Vec<(Uuid, Vec<String>, Option<String>)> = sqlx::query_as(
        "SELECT bi.conversation_id, array_agg(DISTINCT bi.message_id), \
                (SELECT p.ds_did FROM chat.participants p \
                  WHERE p.conversation_id = bi.conversation_id AND p.user_did = $1 \
                  ORDER BY p.created_at DESC, p.participant_period_id DESC LIMIT 1) \
           FROM labyrinth.batch_items bi \
           JOIN chat.conversations c ON c.conversation_id = bi.conversation_id \
          WHERE bi.author_did = $1 AND bi.redacted_at IS NULL AND NOT c.is_remote \
          GROUP BY bi.conversation_id",
    )
    .bind(author)
    .fetch_all(&mut *conn)
    .await?;
    let mut total = 0;
    for (conversation, messages, ds_did) in threads {
        if let Some(home) = home_ds {
            if !ds_did.is_some_and(|d| crate::identity::dids_equivalent(&d, home)) {
                continue;
            }
        }
        total += redact(conn, conversation, author, None, serde_json::json!({}), at).await?;
        attachments::invalidate_messages(conn, &conversation.to_string(), &messages).await?;
    }
    Ok(total)
}

/// `purgeMailbox`: the caller's mailbox, ORF states, attachment references
/// and head-directory chain.
pub async fn purge_mailbox(conn: &mut PgConnection, did: &str) -> LabyrinthResult<()> {
    attachments::delete_owned(conn, did).await?;
    sqlx::query("SELECT labyrinth.purge_mailbox($1)")
        .bind(did)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// The local part of `deleteAccountData`: purge the mailbox, redact every
/// item the DID authored here, and drop its idempotency records.
pub async fn purge_account(
    conn: &mut PgConnection,
    did: &str,
    at: DateTime<Utc>,
) -> LabyrinthResult<i64> {
    purge_mailbox(conn, did).await?;
    let redacted = redact_author(conn, did, None, at).await?;
    sqlx::query("SELECT labyrinth.purge_operations($1)")
        .bind(did)
        .execute(&mut *conn)
        .await?;
    Ok(redacted)
}

/// `did`'s home DS in a conversation, per this DS's participant rows (its
/// latest participant period; NULL means this DS).
pub async fn home_ds(
    conn: &mut PgConnection,
    conversation: Uuid,
    did: &str,
) -> LabyrinthResult<Option<Option<String>>> {
    Ok(sqlx::query_scalar(
        "SELECT ds_did FROM chat.participants WHERE conversation_id = $1 AND user_did = $2 \
          ORDER BY created_at DESC, participant_period_id DESC LIMIT 1",
    )
    .bind(conversation)
    .bind(did)
    .fetch_optional(&mut *conn)
    .await?)
}

/// Remote sequencer DSes of conversations `did` takes or took part in.
pub async fn remote_sequencers(conn: &mut PgConnection, did: &str) -> LabyrinthResult<Vec<String>> {
    Ok(sqlx::query_scalar(
        "SELECT DISTINCT c.sequencer_ds FROM chat.participants p \
           JOIN chat.conversations c ON c.conversation_id = p.conversation_id \
          WHERE p.user_did = $1 AND c.is_remote AND c.sequencer_ds IS NOT NULL \
          ORDER BY 1",
    )
    .bind(did)
    .fetch_all(&mut *conn)
    .await?)
}

fn vd_not_found() -> LabyrinthError {
    LabyrinthError::not_found("VirtualDeviceNotFound")
}

/// `deleteVirtualDevice`.
pub async fn delete_virtual_device(
    conn: &mut PgConnection,
    owner: &str,
    id: &[u8; 16],
) -> LabyrinthResult<()> {
    let removed: bool = sqlx::query_scalar("SELECT labyrinth.drop_virtual_device($1, $2)")
        .bind(owner)
        .bind(id.as_slice())
        .fetch_one(&mut *conn)
        .await?;
    if removed {
        Ok(())
    } else {
        Err(vd_not_found())
    }
}

/// `touchVirtualDevice` (and every `getVirtualDevice`): stamp last use.
pub async fn touch_virtual_device(
    conn: &mut PgConnection,
    owner: &str,
    id: &[u8; 16],
    at: DateTime<Utc>,
) -> LabyrinthResult<()> {
    let touched = sqlx::query(
        "UPDATE labyrinth.virtual_devices SET last_used_at = $3 \
          WHERE owner_did = $1 AND vdevice_id = $2",
    )
    .bind(owner)
    .bind(id.as_slice())
    .bind(at)
    .execute(&mut *conn)
    .await?;
    if touched.rows_affected() == 1 {
        Ok(())
    } else {
        Err(vd_not_found())
    }
}

/// What one GC pass removed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct GcCounts {
    pub virtual_devices: i64,
    pub operations: i64,
}

/// One retention pass at `now`: expire idle keychain/passkey bundles and
/// old idempotency records, `batch` rows of each at most.
pub async fn run_gc(pool: &DbPool, now: DateTime<Utc>, batch: i32) -> LabyrinthResult<GcCounts> {
    let mut tx = pool.begin().await?;
    let virtual_devices: i32 =
        sqlx::query_scalar("SELECT labyrinth.expire_virtual_devices($1, $2)")
            .bind(now - Duration::days(VIRTUAL_DEVICE_IDLE_DAYS))
            .bind(batch)
            .fetch_one(&mut *tx)
            .await?;
    tx.commit().await?;
    let mut tx = pool.begin().await?;
    let operations: i32 = sqlx::query_scalar("SELECT labyrinth.gc_operations($1, $2)")
        .bind(now - Duration::days(OPERATION_RETENTION_DAYS))
        .bind(batch)
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(GcCounts {
        virtual_devices: i64::from(virtual_devices),
        operations: i64::from(operations),
    })
}

/// Run [`run_gc`] every `interval` for the life of the process.
pub async fn gc_worker(pool: DbPool, interval: std::time::Duration) {
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        match run_gc(&pool, Utc::now(), 500).await {
            Ok(counts) if counts != GcCounts::default() => {
                tracing::info!(?counts, "labyrinth retention pass");
            }
            Ok(_) => {}
            Err(error) => tracing::warn!(%error, "labyrinth retention pass failed"),
        }
    }
}
