//! Immutable conversation placement and sender-owned Space record references.
//! Ciphertext is checked transiently for admission/CID, never retained here.
//! Existing batch metadata provides signed redaction and deletion propagation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgConnection;
use uuid::Uuid;

use super::{order, thread, PageReq, TimeRange};
use crate::labyrinth::{
    auth::Caller,
    error::{LabyrinthError, LabyrinthResult},
    wire::{
        bytes::check_did,
        io::ServerOrder,
        records::{Batch, Redaction},
    },
};

const CONVERSATION_TYPE: &str = "blue.catbird.labyrinth.conversation";

fn mismatch() -> LabyrinthError {
    LabyrinthError::invalid_named(
        "StorageGenerationMismatch",
        "conversation storage placement or generation does not match",
    )
}
fn unconfigured(message: &str) -> LabyrinthError {
    LabyrinthError::new(
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        "StorageNotConfigured",
        message,
    )
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Placement {
    pub placement: String,
    pub generation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space: Option<String>,
}

pub fn validate_placement(p: &Placement) -> LabyrinthResult<Uuid> {
    let generation = thread::parse_thread_id(&p.generation)?;
    match (p.placement.as_str(), p.space.as_deref()) {
        ("mlsds", None) => (),
        ("space", Some(uri)) => {
            let parts: Vec<_> = uri
                .strip_prefix("at://")
                .unwrap_or_default()
                .split('/')
                .collect();
            if parts.len() != 4
                || parts[1] != "space"
                || parts[2] != CONVERSATION_TYPE
                || parts[3] != p.generation
            {
                return Err(mismatch());
            }
            check_did("Space authority", parts[0])?;
        }
        _ => return Err(mismatch()),
    }
    Ok(generation)
}

/// Called in the conversation creation transaction, exactly once. The authority
/// must be a provisioned hosted account; this function does not provision it.
/// Configuration affects future conversations only; an invalid DID fails closed.
pub async fn initialize_from_environment(
    conn: &mut PgConnection,
    conversation: Uuid,
    remote: bool,
) -> Result<(), sqlx::Error> {
    let authority = if remote {
        None
    } else {
        std::env::var("LABYRINTH_CONVERSATION_SPACE_AUTHORITY_DID").ok()
    };
    let ready = std::env::var("LABYRINTH_CONVERSATION_SPACE_ISSUER_READY").as_deref() == Ok("true");
    require_issuer_ready(authority.as_deref(), ready)?;
    initialize(conn, conversation, authority.as_deref()).await
}

fn require_issuer_ready(authority: Option<&str>, ready: bool) -> Result<(), sqlx::Error> {
    if authority.is_some() && !ready {
        return Err(sqlx::Error::Protocol("conversation Space authority requires LABYRINTH_CONVERSATION_SPACE_ISSUER_READY=true after configuring the getSpaceMembership authority policy integration".into()));
    }
    Ok(())
}

pub async fn initialize(
    conn: &mut PgConnection,
    conversation: Uuid,
    authority: Option<&str>,
) -> Result<(), sqlx::Error> {
    let generation = Uuid::new_v4();
    if let Some(did) = authority {
        check_did("LABYRINTH_CONVERSATION_SPACE_AUTHORITY_DID", did)
            .map_err(|e| sqlx::Error::Protocol(e.message().to_owned()))?;
    }
    let space = authority.map(|did| format!("at://{did}/space/{CONVERSATION_TYPE}/{generation}"));
    sqlx::query("INSERT INTO labyrinth.thread_storage(conversation_id, placement, generation, space) VALUES ($1, $2, $3, $4)")
        .bind(conversation).bind(if space.is_some() { "space" } else { "mlsds" }).bind(generation).bind(space)
        .execute(conn).await?;
    Ok(())
}

async fn placement(conn: &mut PgConnection, conversation: Uuid) -> LabyrinthResult<Placement> {
    let row: Option<(String, Uuid, Option<String>, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT placement, generation, space, deleted_at FROM labyrinth.thread_storage WHERE conversation_id = $1 FOR SHARE")
        .bind(conversation).fetch_optional(conn).await?;
    let Some((placement, generation, space, deleted)) = row else {
        return Err(unconfigured("conversation storage was not initialized"));
    };
    if deleted.is_some() {
        return Err(LabyrinthError::new(
            axum::http::StatusCode::GONE,
            "SpaceDeleted",
            "this conversation Space generation was deleted",
        ));
    }
    let p = Placement {
        placement,
        generation: generation.to_string(),
        space,
    };
    validate_placement(&p)?;
    Ok(p)
}

/// No Space lifecycle/federation credential distribution has been certified.
/// Refuse mixed-host and pending-request conversations rather than bypassing
/// recipient consent or treating a replicated leaf as a Space credential.
async fn require_supported(conn: &mut PgConnection, conversation: Uuid) -> LabyrinthResult<()> {
    let unsupported: bool = sqlx::query_scalar("SELECT c.is_remote OR c.lifecycle <> 'active' OR EXISTS (SELECT 1 FROM chat.participants p WHERE p.conversation_id=c.conversation_id AND p.current_membership AND (p.status <> 'active' OR p.ds_did IS NOT NULL)) FROM chat.conversations c WHERE c.conversation_id=$1")
        .bind(conversation).fetch_one(conn).await?;
    if unsupported {
        return Err(unconfigured("Space history requires an active local conversation with accepted local participants; federation and pending-request Space authorization are unavailable"));
    }
    Ok(())
}

pub async fn get_storage(
    conn: &mut PgConnection,
    reader: &str,
    conversation: Uuid,
) -> LabyrinthResult<Placement> {
    thread::lock_local_conversation(conn, conversation).await?;
    let participant: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM chat.participants WHERE conversation_id=$1 AND user_did=$2 AND status='active')")
        .bind(conversation).bind(reader).fetch_one(&mut *conn).await?;
    if !participant {
        return Err(LabyrinthError::forbidden(
            "NotParticipant",
            "caller has no accepted conversation membership",
        ));
    }
    let p = placement(conn, conversation).await?;
    if p.placement == "space" {
        require_supported(conn, conversation).await?;
    }
    Ok(p)
}

pub async fn require_legacy(conn: &mut PgConnection, conversation: Uuid) -> LabyrinthResult<()> {
    let p = placement(conn, conversation).await?;
    if p.placement != "mlsds" {
        return Err(mismatch());
    }
    Ok(())
}

/// Validate the exact current leaf when issuing MEKs for a Space thread too.
/// Legacy conversations retain their existing admission behavior.
pub(crate) async fn validate_mek_writer(
    conn: &mut PgConnection,
    caller: &Caller,
    conversation: Uuid,
    chat_seq: i64,
) -> LabyrinthResult<()> {
    let p = placement(conn, conversation).await?;
    if p.placement == "space" {
        require_supported(conn, conversation).await?;
        exact_leaf(conn, caller, conversation, chat_seq).await?;
    }
    Ok(())
}

async fn exact_leaf(
    conn: &mut PgConnection,
    caller: &Caller,
    conversation: Uuid,
    chat_seq: i64,
) -> LabyrinthResult<(i64, i64)> {
    // The conversation row lock linearizes against MLS removal and reset.
    let leaf: Option<(i64, i64)> = sqlx::query_as("SELECT d.joined_seq, d.generation FROM chat.member_devices d JOIN chat.conversations c USING(conversation_id) JOIN chat.participants p USING(participant_period_id) WHERE d.conversation_id=$1 AND d.user_did=$2 AND d.device_id=$3 AND d.leaf_key_id=$4 AND d.leaf_signature_key=$5 AND d.active AND d.removed_seq IS NULL AND d.generation=c.current_generation AND d.joined_seq <= $6 AND p.current_membership AND p.status='active'")
        .bind(conversation).bind(&caller.did).bind(caller.device_id).bind(&caller.key_id).bind(caller.signing_key.as_slice()).bind(chat_seq).fetch_optional(&mut *conn).await?;
    leaf.ok_or_else(|| {
        LabyrinthError::forbidden(
            "NotParticipant",
            "caller has no exact current conversation leaf",
        )
    })
}

/// Explicit authority lifecycle callback; only the matching generation can be
/// marked terminal. There is deliberately no un-delete or rebind API.
pub async fn mark_deleted(
    conn: &mut PgConnection,
    conversation: Uuid,
    generation: Uuid,
    at: DateTime<Utc>,
) -> LabyrinthResult<()> {
    let matched = sqlx::query("UPDATE labyrinth.thread_storage SET deleted_at=$3 WHERE conversation_id=$1 AND generation=$2 AND placement='space' AND deleted_at IS NULL")
        .bind(conversation).bind(generation).bind(at).execute(&mut *conn).await?;
    if matched.rows_affected() == 0 {
        let deleted: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM labyrinth.thread_storage WHERE conversation_id=$1 AND generation=$2 AND placement='space' AND deleted_at IS NOT NULL)")
            .bind(conversation).bind(generation).fetch_one(conn).await?;
        if !deleted {
            return Err(mismatch());
        }
    }
    Ok(())
}

/// Canonical DRISL record CID. Bytes serialize as CBOR byte strings.
pub fn batch_cid(batch: &Batch) -> LabyrinthResult<String> {
    batch.validate()?;
    let encoded = serde_ipld_dagcbor::to_vec(batch)
        .map_err(|_| LabyrinthError::invalid("batch is not DRISL"))?;
    if encoded.len() > 1_048_576 {
        return Err(LabyrinthError::invalid("batch exceeds 1 MiB"));
    }
    let digest = cid::multihash::Multihash::<64>::wrap(0x12, &Sha256::digest(encoded))
        .map_err(|_| LabyrinthError::internal())?;
    Ok(cid::Cid::new_v1(0x71, digest).to_string())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppendSpaceBatch {
    pub record: Batch,
    pub generation: String,
    pub space: String,
    pub rkey: String,
    pub cid: String,
}

pub async fn append(
    conn: &mut PgConnection,
    caller: &Caller,
    input: &AppendSpaceBatch,
    at: DateTime<Utc>,
) -> LabyrinthResult<(String, ServerOrder)> {
    let batch = &input.record;
    let expected_cid = batch_cid(batch)?;
    let mut message_ids = std::collections::BTreeSet::new();
    if batch
        .items
        .iter()
        .any(|i| !message_ids.insert(&i.message_id))
    {
        return Err(LabyrinthError::invalid(
            "batch message IDs must be unique for exact redaction",
        ));
    }
    if input.cid != expected_cid
        || input.rkey.is_empty()
        || input.rkey.len() > 64
        || [".", ".."].contains(&input.rkey.as_str())
        || !input
            .rkey
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
    {
        return Err(LabyrinthError::invalid(
            "source CID or record key is invalid",
        ));
    }
    let conversation = thread::parse_thread_id(&batch.thread_id)?;
    let chat_seq = thread::lock_local_conversation(conn, conversation).await?;
    let p = placement(conn, conversation).await?;
    if p.placement != "space"
        || p.generation != input.generation
        || p.space.as_deref() != Some(&input.space)
    {
        return Err(mismatch());
    }
    require_supported(conn, conversation).await?;
    let (joined, chat_generation) = exact_leaf(conn, caller, conversation, chat_seq).await?;
    let mek_id = &batch.items[0].mek_id;
    if batch.items.iter().any(|i| &i.mek_id != mek_id) {
        return Err(LabyrinthError::invalid_named(
            "MixedMekBatch",
            "batch uses multiple MEKs",
        ));
    }
    if batch
        .items
        .iter()
        .any(|i| i.sender_transport_pubkey.0 != caller.signing_key)
    {
        return Err(LabyrinthError::invalid_named(
            "SenderKeyMismatch",
            "batch is not authored by the calling key",
        ));
    }
    let mek: Option<(String, i64, Option<i64>, bool)> = sqlx::query_as("SELECT m.author_did, m.chat_seq, m.chat_generation, (m.author_did=$3 OR EXISTS(SELECT 1 FROM labyrinth.mek_recipients r WHERE r.conversation_id=m.conversation_id AND r.mek_id=m.mek_id AND r.author_did=m.author_did AND r.recipient_did=$3)) FROM labyrinth.meks m WHERE m.conversation_id=$1 AND m.mek_id=$2")
        .bind(conversation).bind(&mek_id.0).bind(&caller.did).fetch_optional(&mut *conn).await?;
    let Some((mek_author, mek_seq, mek_generation, readable)) = mek else {
        return Err(LabyrinthError::invalid_named(
            "UnknownMek",
            "unknown conversation MEK",
        ));
    };
    if !readable {
        return Err(LabyrinthError::forbidden(
            "NotRecipient",
            "caller cannot open the MEK",
        ));
    }
    if mek_generation != Some(chat_generation) || mek_seq < joined || mek_seq > chat_seq {
        return Err(LabyrinthError::invalid_named(
            "UnknownMek",
            "MEK lies outside the current leaf generation and sequence bounds",
        ));
    }
    super::advisory_lock(
        conn,
        &format!("space-batch:{conversation}:{}:{}", caller.did, input.rkey),
    )
    .await?;
    let existing: Option<(String, i64, i64, DateTime<Utc>)> = sqlx::query_as("SELECT source_cid, seq, chat_seq, received_at FROM labyrinth.batches WHERE conversation_id=$1 AND author_did=$2 AND rkey=$3")
        .bind(conversation).bind(&caller.did).bind(&input.rkey).fetch_optional(&mut *conn).await?;
    if let Some((cid, seq, chat_seq, at)) = existing {
        if cid != input.cid {
            return Err(LabyrinthError::already_exists());
        }
        return Ok((input.rkey.clone(), order(seq, Some(chat_seq), at)));
    }
    let mut metadata = batch.clone();
    for item in &mut metadata.items {
        item.signed_enc_message.0.clear();
    }
    let metadata = serde_json::to_string(&metadata).map_err(|_| LabyrinthError::internal())?;
    let bytes =
        i32::try_from(metadata.len()).map_err(|_| LabyrinthError::invalid("metadata too large"))?;
    thread::charge_author(conn, &caller.did, bytes).await?;
    let seq = thread::next_seq(conn, conversation).await?;
    let (min_ts, max_ts) = batch.ts_range();
    sqlx::query("INSERT INTO labyrinth.batches(conversation_id, author_did, rkey, mek_id, writer_device_id, min_ts, max_ts, record, record_bytes, seq, chat_seq, received_at, mek_author_did, space_generation, space_ref, source_cid) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11,$12,$13,$14,$15,$16)")
        .bind(conversation).bind(&caller.did).bind(&input.rkey).bind(&mek_id.0).bind(caller.device_id).bind(min_ts as i64).bind(max_ts as i64).bind(metadata).bind(bytes).bind(seq).bind(chat_seq).bind(at).bind(mek_author).bind(thread::parse_thread_id(&input.generation)?).bind(&input.space).bind(&input.cid).execute(conn).await?;
    Ok((input.rkey.clone(), order(seq, Some(chat_seq), at)))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Tombstone {
    message_id: String,
    timestamp: u64,
    redaction: Redaction,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpaceBatchView {
    author: String,
    rkey: String,
    space: String,
    generation: String,
    cid: String,
    order: ServerOrder,
    redactions: Vec<Tombstone>,
    item_count: usize,
}

pub async fn list(
    conn: &mut PgConnection,
    reader: &str,
    conversation: Uuid,
    generation: &str,
    sender: Option<&str>,
    range: TimeRange,
    page: &PageReq,
) -> LabyrinthResult<(Vec<SpaceBatchView>, Option<String>)> {
    let p = get_storage(conn, reader, conversation).await?;
    if p.placement != "space" || p.generation != generation {
        return Err(mismatch());
    }
    let sql = format!("SELECT {}, b.source_cid FROM labyrinth.batches b WHERE b.conversation_id=$1 AND b.seq {} $3 AND ($4::text IS NULL OR b.author_did=$4) AND ($5::bigint IS NULL OR b.max_ts >= $5) AND ($6::bigint IS NULL OR b.min_ts < $6) AND {} AND {} ORDER BY b.seq {} LIMIT $7", thread::BATCH_COLUMNS, page.seq_cmp(), thread::received_in("b", "$8", "$9"), thread::batch_readable("$2"), page.seq_dir());
    let rows: Vec<(i64, String, String, String, i64, DateTime<Utc>, String)> = sqlx::query_as(&sql)
        .bind(conversation)
        .bind(reader)
        .bind(page.seq_bound()?)
        .bind(sender)
        .bind(range.from_ms)
        .bind(range.until_ms)
        .bind(page.limit() + 1)
        .bind(range.since)
        .bind(range.until)
        .fetch_all(conn)
        .await?;
    let (rows, cursor) = thread::page_of(rows, page, |r| r.0);
    let mut items = Vec::with_capacity(rows.len());
    for (seq, author, rkey, record, chat_seq, at, cid) in rows {
        let batch: Batch = serde_json::from_str(&record).map_err(|_| LabyrinthError::internal())?;
        if !batch.items.iter().any(|i| range.contains(i.timestamp)) {
            continue;
        }
        let item_count = batch.items.len();
        let redactions = batch
            .items
            .into_iter()
            .filter_map(|i| {
                i.redaction.map(|redaction| Tombstone {
                    message_id: i.message_id,
                    timestamp: i.timestamp,
                    redaction,
                })
            })
            .collect();
        items.push(SpaceBatchView {
            author,
            rkey,
            space: p.space.clone().ok_or_else(LabyrinthError::internal)?,
            generation: p.generation.clone(),
            cid,
            order: order(seq, Some(chat_seq), at),
            redactions,
            item_count,
        });
    }
    Ok((items, cursor))
}

/// Authority-only live read policy; canonical Space delegation stays between
/// the client and Swan. The service JWT identifies the authority, while `user`
/// is the DID Swan obtained from its verified delegation token.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpaceMembership {
    space: String,
    generation: String,
    user: String,
    chat_generation: i64,
    chat_seq: i64,
}

async fn authority_conversation(
    conn: &mut PgConnection,
    authority: &str,
    space: &str,
) -> LabyrinthResult<(Uuid, Uuid)> {
    // Validate authority before looking up a conversation, including canonical
    // exact namespace, so an unrelated authority cannot probe its membership.
    let pieces: Vec<_> = space
        .strip_prefix("at://")
        .unwrap_or_default()
        .split('/')
        .collect();
    if pieces.len() != 4
        || pieces[0] != authority
        || pieces[1] != "space"
        || pieces[2] != CONVERSATION_TYPE
    {
        return Err(LabyrinthError::forbidden(
            "NotAuthorized",
            "caller is not this Space authority",
        ));
    }
    let generation = thread::parse_thread_id(pieces[3])?;
    let conversation: Option<Uuid> = sqlx::query_scalar("SELECT conversation_id FROM labyrinth.thread_storage WHERE space=$1 AND generation=$2 AND placement='space'")
        .bind(space).bind(generation).fetch_optional(&mut *conn).await?;
    let Some(conversation) = conversation else {
        return Err(unconfigured("unknown conversation Space generation"));
    };
    Ok((conversation, generation))
}

pub async fn membership(
    conn: &mut PgConnection,
    authority: &str,
    space: &str,
    user: &str,
) -> LabyrinthResult<SpaceMembership> {
    check_did("user", user)?;
    let (conversation, _) = authority_conversation(conn, authority, space).await?;
    // Device revocation locks registered device/key rows before conversation
    // heads. Follow that order: pin one eligible identity, then lock the head
    // and revalidate that exact leaf. No identity locks may be taken after the
    // head lock, including when this candidate was removed or superseded.
    let candidate: Option<(Uuid, Uuid, String, Vec<u8>)> = sqlx::query_as(
        "SELECT d.leaf_period_id, d.device_id, d.leaf_key_id, d.leaf_signature_key \
           FROM chat.member_devices d \
           JOIN chat.participants p USING(participant_period_id) \
           JOIN chat.conversations c ON c.conversation_id=d.conversation_id \
           JOIN chat.devices device ON device.user_did=d.user_did AND device.device_id=d.device_id \
           JOIN chat.device_keys k ON k.user_did=d.user_did AND k.device_id=d.device_id \
             AND k.key_id=d.leaf_key_id AND k.signing_public_key=d.leaf_signature_key \
          WHERE d.conversation_id=$1 AND d.user_did=$2 AND d.active AND d.removed_seq IS NULL \
            AND d.generation=c.current_generation AND d.joined_seq < c.next_entry_seq \
            AND p.current_membership AND p.status='active' AND device.status='active' \
            AND k.revoked_at IS NULL \
          ORDER BY d.leaf_period_id LIMIT 1 FOR SHARE OF device, k",
    )
    .bind(conversation)
    .bind(user)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((leaf, device, key, signing_key)) = candidate else {
        return Err(LabyrinthError::forbidden(
            "NotParticipant",
            "user has no accepted current conversation leaf",
        ));
    };
    let chat_seq = thread::lock_local_conversation(conn, conversation).await?;
    let p = placement(conn, conversation).await?;
    require_supported(conn, conversation).await?;
    let live: Option<i64> = sqlx::query_scalar(
        "SELECT d.generation FROM chat.member_devices d \
           JOIN chat.participants p USING(participant_period_id) \
           JOIN chat.conversations c ON c.conversation_id=d.conversation_id \
          WHERE d.conversation_id=$1 AND d.user_did=$2 AND d.leaf_period_id=$3 \
            AND d.device_id=$4 AND d.leaf_key_id=$5 AND d.leaf_signature_key=$6 \
            AND d.active AND d.removed_seq IS NULL AND d.generation=c.current_generation \
            AND d.joined_seq <= $7 AND p.current_membership AND p.status='active'",
    )
    .bind(conversation)
    .bind(user)
    .bind(leaf)
    .bind(device)
    .bind(key)
    .bind(signing_key)
    .bind(chat_seq)
    .fetch_optional(conn)
    .await?;
    let Some(chat_generation) = live else {
        return Err(LabyrinthError::forbidden(
            "NotParticipant",
            "user has no accepted current conversation leaf",
        ));
    };
    Ok(SpaceMembership {
        space: space.into(),
        generation: p.generation,
        user: user.into(),
        chat_generation,
        chat_seq,
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeleteSpaceGeneration {
    pub space: String,
    pub generation: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpaceDeletion {
    space: String,
    generation: String,
    deleted: bool,
}

/// The authority has already persisted pending deletion and stopped issuance.
/// Commit the exact DS generation terminally before it acknowledges deletion or
/// fans out standard PDS notifications. Fresh-JWT retries are idempotent.
pub async fn delete_generation(
    conn: &mut PgConnection,
    authority: &str,
    input: &DeleteSpaceGeneration,
) -> LabyrinthResult<SpaceDeletion> {
    let requested = thread::parse_thread_id(&input.generation)?;
    let (conversation, generation) = authority_conversation(conn, authority, &input.space).await?;
    if requested != generation {
        return Err(mismatch());
    }
    // Use UPDATE locking so two simultaneous callbacks cannot deadlock while
    // upgrading a shared storage row lock. Normal admission holds SHARE here.
    sqlx::query(
        "SELECT conversation_id FROM chat.conversations WHERE conversation_id=$1 FOR UPDATE",
    )
    .bind(conversation)
    .execute(&mut *conn)
    .await?;
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *conn)
        .await?;
    mark_deleted(conn, conversation, generation, now).await?;
    Ok(SpaceDeletion {
        space: input.space.clone(),
        generation: input.generation.clone(),
        deleted: true,
    })
}

/// Existing attachment references cannot outlive a deleted conversation Space.
/// The shared row lock linearizes this read with the terminal transition.
pub(crate) async fn require_not_deleted(
    conn: &mut PgConnection,
    conversation: Uuid,
) -> LabyrinthResult<()> {
    let deleted: Option<bool> = sqlx::query_scalar("SELECT deleted_at IS NOT NULL FROM labyrinth.thread_storage WHERE conversation_id=$1 FOR SHARE")
        .bind(conversation).fetch_optional(conn).await?;
    if deleted == Some(true) {
        return Err(LabyrinthError::new(
            axum::http::StatusCode::GONE,
            "SpaceDeleted",
            "this conversation Space generation was deleted",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn configured_authority_requires_explicit_issuer_readiness() {
        assert!(require_issuer_ready(None, false).is_ok());
        assert!(require_issuer_ready(Some("did:web:authority.example.com"), false).is_err());
        assert!(require_issuer_ready(Some("did:web:authority.example.com"), true).is_ok());
    }
    #[test]
    fn placement_requires_exact_namespace_and_generation() {
        let generation = Uuid::new_v4().to_string();
        let mut p = Placement {
            placement: "space".into(),
            generation: generation.clone(),
            space: Some(format!(
                "at://did:web:authority.example.com/space/{CONVERSATION_TYPE}/{generation}"
            )),
        };
        assert!(validate_placement(&p).is_ok());
        p.space = Some(format!(
            "at://did:web:authority.example.com/space/blue.catbird.labyrinth.mailbox/{generation}"
        ));
        assert!(validate_placement(&p).is_err());
        p.space = Some(format!(
            "at://did:web:authority.example.com/space/{CONVERSATION_TYPE}/{}",
            Uuid::new_v4()
        ));
        assert!(validate_placement(&p).is_err());
    }
}
