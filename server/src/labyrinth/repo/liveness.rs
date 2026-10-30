//! Whether an attachment's message still exists for a reader (whitepaper
//! v1.1 p.42; second security review, findings 5 and 9).
//!
//! The rule, for message `m` authored by `author` (the attachment's chat
//! binding owner):
//!
//! 1. if any of `author`'s sender items for `m` is redacted, or a redaction
//!    of `m` by `author` was announced here, `m` is gone for everyone;
//! 2. otherwise `m` is live if an unredacted sender item of `author` for `m`
//!    is readable by the reader per MEK, or if the reader **is** the author
//!    and keeps `m` in its own owner archive.
//!
//! A reader's own archive copy never vouches for another author's message:
//! liveness of someone else's message comes from the sender records, which
//! for a remote conversation live on its sequencer (`labyrinthRelay
//! messageLive`).

use sqlx::PgConnection;
use uuid::Uuid;

use super::attachments::RemoteCheck;
use crate::labyrinth::digest;
use crate::labyrinth::error::LabyrinthResult;

/// The outcome of a local liveness check.
pub enum Liveness {
    Known(bool),
    /// The conversation's sender records live on another sequencer.
    Remote(RemoteCheck),
}

/// `(live, redacted)` of `author`'s sender items for `message_id`, for
/// `reader` (`labyrinth.sender_message_state`).
pub async fn sender_state(
    conn: &mut PgConnection,
    reader: &str,
    conversation: Uuid,
    message_id: &str,
    author: &str,
) -> LabyrinthResult<(bool, bool)> {
    super::space::require_not_deleted(conn, conversation).await?;
    Ok(
        sqlx::query_as("SELECT live, redacted FROM labyrinth.sender_message_state($1, $2, $3, $4)")
            .bind(reader)
            .bind(conversation)
            .bind(message_id)
            .bind(author)
            .fetch_one(&mut *conn)
            .await?,
    )
}

/// Whether a redaction of the message by `author` was recorded here.
pub async fn announced_redacted(
    conn: &mut PgConnection,
    key: &[u8; 32],
    message_digest: &[u8; 32],
    author: &str,
) -> LabyrinthResult<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM labyrinth.redacted_messages \
                        WHERE message_digest = $1 AND author_digest = $2)",
    )
    .bind(message_digest.as_slice())
    .bind(digest::owner(key, author).as_slice())
    .fetch_one(&mut *conn)
    .await?)
}

/// Whether `reader` keeps `message_id` of the thread in its owner archive.
async fn own_copy(
    conn: &mut PgConnection,
    reader: &str,
    conversation: Uuid,
    message_id: &str,
) -> LabyrinthResult<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM labyrinth.owner_batch_items \
                        WHERE owner_did = $1 AND thread_id = $2 AND message_id = $3)",
    )
    .bind(reader)
    .bind(conversation.to_string())
    .bind(message_id)
    .fetch_one(&mut *conn)
    .await?)
}

/// Combine a sender state with the author's own copy (rule 2).
pub fn decide(live: bool, redacted: bool, own_copy: bool) -> bool {
    !redacted && (live || own_copy)
}

/// Apply the rule on this DS; a remote conversation defers the sender part
/// to its sequencer.
pub async fn check(
    conn: &mut PgConnection,
    key: &[u8; 32],
    reader: &str,
    conversation: Uuid,
    message_id: &str,
    author: &str,
) -> LabyrinthResult<Liveness> {
    let thread_id = conversation.to_string();
    if announced_redacted(
        conn,
        key,
        &digest::message(key, &thread_id, message_id),
        author,
    )
    .await?
    {
        return Ok(Liveness::Known(false));
    }
    let own = reader == author && own_copy(conn, reader, conversation, message_id).await?;
    let remote: Option<Option<String>> = sqlx::query_scalar(
        "SELECT CASE WHEN is_remote THEN sequencer_ds END FROM chat.conversations \
          WHERE conversation_id = $1",
    )
    .bind(conversation)
    .fetch_optional(&mut *conn)
    .await?;
    if let Some(Some(sequencer)) = remote {
        return Ok(Liveness::Remote(RemoteCheck {
            sequencer,
            author: author.to_owned(),
            own_copy: own,
        }));
    }
    let (live, redacted) = sender_state(conn, reader, conversation, message_id, author).await?;
    Ok(Liveness::Known(decide(live, redacted, own)))
}
