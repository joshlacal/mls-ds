//! ORF states and attachment references (labyrinth SPEC §8, [CB-17]; design
//! §2 "ORF and attachments"). All rows belong to the caller DID.

use chrono::{DateTime, Utc};
use sqlx::PgConnection;
use uuid::Uuid;

use super::ct_eq;
use crate::labyrinth::error::{LabyrinthError, LabyrinthResult};
use crate::labyrinth::orf::{
    server_evolve, server_init, server_map, ATTACHMENT_INDEX_DOMAIN, ATTACHMENT_TOKEN_DOMAIN,
};
use crate::labyrinth::wire::bytes::check_str;

fn orf_not_found() -> LabyrinthError {
    LabyrinthError::not_found("OrfStateNotFound")
}

async fn state(
    conn: &mut PgConnection,
    owner: &str,
    device_key: &[u8; 32],
) -> LabyrinthResult<Option<[u8; 32]>> {
    let row: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT server_state FROM labyrinth.orf_states \
          WHERE owner_did = $1 AND device_key = $2 FOR SHARE",
    )
    .bind(owner)
    .bind(device_key.as_slice())
    .fetch_optional(&mut *conn)
    .await?;
    row.map(|s| {
        s.as_slice()
            .try_into()
            .map_err(|_| LabyrinthError::internal())
    })
    .transpose()
}

/// Register `device_key`'s state: fresh without a parent, else evolved from
/// the parent's state with the client's evolve token.
pub async fn register(
    conn: &mut PgConnection,
    owner: &str,
    device_key: &[u8; 32],
    parent: Option<([u8; 32], [u8; 32])>,
    at: DateTime<Utc>,
) -> LabyrinthResult<()> {
    if state(conn, owner, device_key).await?.is_some() {
        return Err(LabyrinthError::already_exists());
    }
    let new_state = match parent {
        None => server_init(),
        Some((parent_key, token)) => {
            let parent_state = state(conn, owner, &parent_key)
                .await?
                .ok_or_else(orf_not_found)?;
            server_evolve(parent_state, token)?
        }
    };
    let inserted = sqlx::query(
        "INSERT INTO labyrinth.orf_states (owner_did, device_key, server_state, created_at) \
         VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
    )
    .bind(owner)
    .bind(device_key.as_slice())
    .bind(new_state.as_slice())
    .bind(at)
    .execute(&mut *conn)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(LabyrinthError::already_exists());
    }
    Ok(())
}

/// Delete `device_key`'s state (revocation). Idempotent.
pub async fn delete(
    conn: &mut PgConnection,
    owner: &str,
    device_key: &[u8; 32],
) -> LabyrinthResult<()> {
    sqlx::query("DELETE FROM labyrinth.orf_states WHERE owner_did = $1 AND device_key = $2")
        .bind(owner)
        .bind(device_key.as_slice())
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// `putAttachmentRef` input after parsing.
pub struct NewAttachmentRef {
    pub device_key: [u8; 32],
    pub blinded_index: [u8; 32],
    pub blinded_token: [u8; 32],
    pub conversation_id: String,
    pub blob_id: String,
    pub message_id: String,
}

fn parse_uuid(what: &str, value: &str) -> LabyrinthResult<Uuid> {
    let id = Uuid::parse_str(value)
        .map_err(|_| LabyrinthError::invalid(format!("{what} is not a UUID")))?;
    if id.hyphenated().to_string() != value {
        return Err(LabyrinthError::invalid(format!(
            "{what} must be a canonical lowercase UUID"
        )));
    }
    Ok(id)
}

/// Store a reference under `server_map(state, index domain, blindedIndex)`
/// with `server_map(state, token domain, blindedToken)` as its access MAC.
/// The caller must be (or have been) a participant of the conversation and
/// the blob must be one of its attachments.
pub async fn put_attachment_ref(
    conn: &mut PgConnection,
    owner: &str,
    input: &NewAttachmentRef,
    at: DateTime<Utc>,
) -> LabyrinthResult<()> {
    check_str("messageId", &input.message_id, 256)?;
    let conversation_id = parse_uuid("conversationId", &input.conversation_id)?;
    let blob_id = parse_uuid("blobId", &input.blob_id)?;
    let s = state(conn, owner, &input.device_key)
        .await?
        .ok_or_else(orf_not_found)?;
    if !super::directory::ever_participant(conn, conversation_id, owner).await? {
        return Err(LabyrinthError::forbidden(
            "NotAuthorized",
            "the caller was never a participant of this conversation",
        ));
    }
    let blob_ok: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat.blobs WHERE blob_id = $1 AND purpose = 'attachment')",
    )
    .bind(blob_id)
    .fetch_one(&mut *conn)
    .await?;
    if !blob_ok {
        return Err(LabyrinthError::invalid("blobId names no attachment blob"));
    }
    let index = server_map(s, ATTACHMENT_INDEX_DOMAIN, input.blinded_index)?;
    let token_mac = server_map(s, ATTACHMENT_TOKEN_DOMAIN, input.blinded_token)?;
    let inserted = sqlx::query(
        "INSERT INTO labyrinth.attachment_refs \
           (owner_did, orf_index, conversation_id, blob_id, message_id, token_mac, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING",
    )
    .bind(owner)
    .bind(index.as_slice())
    .bind(conversation_id)
    .bind(blob_id)
    .bind(&input.message_id)
    .bind(token_mac.as_slice())
    .bind(at)
    .execute(&mut *conn)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(LabyrinthError::already_exists());
    }
    Ok(())
}

/// A stored attachment reference.
pub struct AttachmentRef {
    pub conversation_id: Uuid,
    pub blob_id: Uuid,
    pub message_id: String,
    pub token_mac: [u8; 32],
}

/// The reference at `server_map(state, index domain, blindedIndex)`.
pub async fn get_attachment_ref(
    conn: &mut PgConnection,
    owner: &str,
    device_key: &[u8; 32],
    blinded_index: [u8; 32],
) -> LabyrinthResult<AttachmentRef> {
    let s = state(conn, owner, device_key)
        .await?
        .ok_or_else(orf_not_found)?;
    let index = server_map(s, ATTACHMENT_INDEX_DOMAIN, blinded_index)?;
    let row: Option<(Uuid, Uuid, String, Vec<u8>)> = sqlx::query_as(
        "SELECT conversation_id, blob_id, message_id, token_mac FROM labyrinth.attachment_refs \
          WHERE owner_did = $1 AND orf_index = $2",
    )
    .bind(owner)
    .bind(index.as_slice())
    .fetch_optional(&mut *conn)
    .await?;
    let (conversation_id, blob_id, message_id, mac) =
        row.ok_or_else(|| LabyrinthError::not_found("NotFound"))?;
    Ok(AttachmentRef {
        conversation_id,
        blob_id,
        message_id,
        token_mac: mac
            .as_slice()
            .try_into()
            .map_err(|_| LabyrinthError::internal())?,
    })
}

/// Where a token-authorized attachment's bytes live.
pub struct AttachmentObject {
    pub object_store_key: String,
    pub ciphertext_size: i64,
    pub ciphertext_sha256: Vec<u8>,
}

/// Resolve the reference and check the blinded token against its MAC. A
/// wrong token, a missing reference and a blob without a live object all
/// read as `NotFound`.
pub async fn authorize_attachment_blob(
    conn: &mut PgConnection,
    owner: &str,
    device_key: &[u8; 32],
    blinded_index: [u8; 32],
    blinded_token: [u8; 32],
) -> LabyrinthResult<AttachmentObject> {
    let reference = get_attachment_ref(conn, owner, device_key, blinded_index).await?;
    let s = state(conn, owner, device_key)
        .await?
        .ok_or_else(orf_not_found)?;
    let mac = server_map(s, ATTACHMENT_TOKEN_DOMAIN, blinded_token)?;
    if !ct_eq(&mac, &reference.token_mac) {
        return Err(LabyrinthError::not_found("NotFound"));
    }
    let row: Option<(Option<String>, i64, Vec<u8>)> = sqlx::query_as(
        "SELECT object_store_key, ciphertext_size, ciphertext_sha256 FROM chat.blobs \
          WHERE blob_id = $1",
    )
    .bind(reference.blob_id)
    .fetch_optional(&mut *conn)
    .await?;
    match row {
        Some((Some(object_store_key), ciphertext_size, ciphertext_sha256)) => {
            Ok(AttachmentObject {
                object_store_key,
                ciphertext_size,
                ciphertext_sha256,
            })
        }
        _ => Err(LabyrinthError::not_found("NotFound")),
    }
}
