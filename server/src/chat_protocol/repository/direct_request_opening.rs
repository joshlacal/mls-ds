//! O7 for the C33 opening. A published direct request carries its first
//! application ciphertext in `signedRequest.body.artifacts.initialCiphertext`.
//! Each home erases every copy of it once the opening's frozen audience
//! acknowledged its seq, once its sender's account is deleted, once the request
//! expires or no device can import it any more, and at the 30-day ceiling; a
//! close wipes every row. What stays is the signed evidence: every original
//! digest, the sender signature, the I13 `sequencerReceipt`, the
//! `publicationReceipt` and a redacted entry whose `initialCiphertext` is that
//! ciphertext's SHA-256, so every other signed field survives byte-for-byte.
//! Readers serve a pruned opening as `{…, payloadPruned: true}` without
//! `signedRequest`. Each prune is irreversible (migration 20261103000010), keeps
//! its publication's charged size for the terminal release (20261104000002) and
//! is skipped by the P8 `retain_application_ciphertext` plant.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use sqlx::{PgConnection, PgPool, Postgres, Transaction};
use uuid::Uuid;

pub(crate) const DIRECT_REQUEST_ENTRY_KIND: &str = "blue.catbird.chat.defs#directRequestEntry";
const PUBLICATION_BODY_KIND: &str = "blue.catbird.chat.defs#directRequestPublicationBody";

fn invalid(reason: &str) -> sqlx::Error {
    sqlx::Error::Protocol(format!("invalid direct request opening: {reason}"))
}

/// P8 plant: deliberately retain application ciphertext when pruning is due.
fn ciphertext_retained() -> bool {
    #[cfg(feature = "sim")]
    if crate::sim_hooks::active_sim_ds().is_some_and(|hooks| hooks.retain_application_ciphertext) {
        return true;
    }
    false
}

/// `entry`, a direct-request opening, with its opening ciphertext replaced by that
/// ciphertext's SHA-256 in the same presentation (`"…"` or `{"$bytes": "…"}`).
/// Nothing else changes.
pub(crate) fn redacted_opening_entry(entry: &Value) -> Result<Value, sqlx::Error> {
    let mut redacted = entry.clone();
    let slot = redacted
        .pointer_mut("/signedRequest/body/artifacts/initialCiphertext")
        .ok_or_else(|| invalid("opening ciphertext missing"))?;
    let (encoded, wrapped) = match &*slot {
        Value::String(text) => (text.clone(), false),
        Value::Object(map) if map.len() == 1 => match map.get("$bytes") {
            Some(Value::String(text)) => (text.clone(), true),
            _ => return Err(invalid("opening ciphertext presentation")),
        },
        _ => return Err(invalid("opening ciphertext presentation")),
    };
    let ciphertext = STANDARD
        .decode(encoded)
        .map_err(|_| invalid("opening ciphertext base64"))?;
    let digest = STANDARD.encode(Sha256::digest(&ciphertext));
    *slot = if wrapped {
        json!({ "$bytes": digest })
    } else {
        Value::String(digest)
    };
    Ok(redacted)
}

/// The served shape of a pruned opening: its retained fields verbatim, no
/// `signedRequest`, and `payloadPruned: true`.
pub(crate) fn pruned_opening_entry(entry: &Value) -> Value {
    let mut pruned = serde_json::Map::new();
    pruned.insert("$type".into(), DIRECT_REQUEST_ENTRY_KIND.into());
    for field in [
        "entryId",
        "conversationId",
        "seq",
        "receivedAt",
        "sequencerReceipt",
        "publicationReceipt",
    ] {
        if let Some(value) = entry.get(field) {
            pruned.insert(field.into(), value.clone());
        }
    }
    pruned.insert("payloadPruned".into(), true.into());
    Value::Object(pruned)
}

/// The evidence a transport copy of an opening freezes when stored: its request
/// id and pruned projection. `None` for every other entry.
pub(crate) fn transport_opening_evidence(
    entry: &Value,
) -> Result<Option<(Uuid, Vec<u8>)>, sqlx::Error> {
    let Some(body) = entry.pointer("/signedRequest/body") else {
        return Ok(None);
    };
    if body.get("$type").and_then(Value::as_str) != Some(PUBLICATION_BODY_KIND) {
        return Ok(None);
    }
    let request_id = body
        .get("requestId")
        .and_then(Value::as_str)
        .and_then(|id| Uuid::parse_str(id).ok())
        .ok_or_else(|| invalid("opening request id"))?;
    let pruned = serde_json::to_vec(&pruned_opening_entry(entry))
        .map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
    Ok(Some((request_id, pruned)))
}

/// Older acceptance manifests predate this migration: never name its columns there.
async fn opening_columns_exist(
    connection: &mut PgConnection,
    table: &str,
    column: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM pg_attribute \
          WHERE attrelid = to_regclass($1) AND attname = $2 AND NOT attisdropped)",
    )
    .bind(table)
    .bind(column)
    .fetch_one(connection)
    .await
}

/// Prune the coordinator's opening at `(conversation_id, seq)`: its entry, its
/// publication transition and its publication row lose every ciphertext-bearing
/// copy in `tx`, and a queued delivery of it is dropped, so the bytes never reach
/// the peer later. The entry keeps its redacted form; digests, signature and
/// receipts stay. Returns whether this call pruned it.
pub(crate) async fn prune_coordinator_opening(
    tx: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    seq: i64,
    at: DateTime<Utc>,
) -> Result<bool, sqlx::Error> {
    if ciphertext_retained()
        || !opening_columns_exist(&mut **tx, "chat.entries", "pruned_payload_bytes").await?
    {
        return Ok(false);
    }
    let opening: Option<(Uuid, Vec<u8>)> = sqlx::query_as(
        "SELECT transition_id, accepted_payload_bytes FROM chat.entries \
          WHERE conversation_id = $1 AND seq = $2 AND entry_kind = $3 \
            AND payload_pruned_at IS NULL \
          FOR UPDATE",
    )
    .bind(conversation_id)
    .bind(seq)
    .bind(DIRECT_REQUEST_ENTRY_KIND)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((request_id, entry_bytes)) = opening else {
        return Ok(false);
    };
    let entry: Value = serde_json::from_slice(&entry_bytes).map_err(|_| invalid("entry JSON"))?;
    let redacted = serde_json::to_vec(&redacted_opening_entry(&entry)?)
        .map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
    sqlx::query(
        "UPDATE chat.entries \
            SET accepted_payload_bytes = NULL, signed_request_bytes = NULL, \
                pruned_payload_bytes = $3, payload_pruned_at = $4 \
          WHERE conversation_id = $1 AND seq = $2 AND payload_pruned_at IS NULL",
    )
    .bind(conversation_id)
    .bind(seq)
    .bind(&redacted)
    .bind(at)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "UPDATE chat.transitions \
            SET signed_request_bytes = NULL, unsigned_projection_bytes = NULL, \
                signing_transcript_bytes = NULL, payload_pruned_at = $2 \
          WHERE transition_id = $1 AND kind = 'directRequestPublication' \
            AND payload_pruned_at IS NULL",
    )
    .bind(request_id)
    .bind(at)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "UPDATE chat.direct_request_publications \
            SET signed_publication = NULL, request_entry = NULL, initial_ciphertext = NULL, \
                opening_pruned_at = $2 \
          WHERE request_id = $1 AND opening_pruned_at IS NULL AND pruned_at IS NULL",
    )
    .bind(request_id)
    .bind(at)
    .execute(&mut **tx)
    .await?;
    sqlx::query("DELETE FROM outbound_queue WHERE id = $1")
        .bind(format!("direct-request-delivery-{request_id}"))
        .execute(&mut **tx)
        .await?;
    Ok(true)
}

/// Prune every opening `did` sent in a conversation this DS sequences.
pub(crate) async fn prune_coordinator_openings_sent_by(
    tx: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    did: &str,
    before_seq: i64,
    cutoff: DateTime<Utc>,
    at: DateTime<Utc>,
) -> Result<usize, sqlx::Error> {
    let seqs: Vec<i64> = sqlx::query_scalar(
        "SELECT e.seq FROM chat.entries e \
           JOIN chat.conversations c ON c.conversation_id = e.conversation_id \
          WHERE e.conversation_id = $1 AND NOT c.is_remote AND e.entry_kind = $2 \
            AND e.actor_did = $3 AND e.payload_pruned_at IS NULL AND e.seq < $4 AND e.received_at <= $5 \
          ORDER BY e.seq",
    )
    .bind(conversation_id)
    .bind(DIRECT_REQUEST_ENTRY_KIND)
    .bind(did)
    .bind(before_seq)
    .bind(cutoff)
    .fetch_all(&mut **tx)
    .await?;
    let mut pruned = 0;
    for seq in seqs {
        pruned += usize::from(prune_coordinator_opening(tx, conversation_id, seq, at).await?);
    }
    Ok(pruned)
}

/// The opening of `request_id` as this coordinator serves it, with whether it was
/// pruned: the stored entry, or its `payloadPruned` projection. `None` when it
/// was never published here.
pub(crate) async fn coordinator_opening_response(
    connection: &mut PgConnection,
    request_id: Uuid,
) -> Result<Option<(Value, bool)>, sqlx::Error> {
    let row: Option<(Option<Vec<u8>>, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT e.accepted_payload_bytes, \
                CASE WHEN e.accepted_payload_bytes IS NULL \
                     THEN (to_jsonb(e) ->> 'pruned_payload_bytes')::bytea END \
           FROM chat.entries e WHERE e.transition_id = $1 AND e.entry_kind = $2",
    )
    .bind(request_id)
    .bind(DIRECT_REQUEST_ENTRY_KIND)
    .fetch_optional(connection)
    .await?;
    match row {
        None => Ok(None),
        Some((Some(entry), _)) => Ok(Some((
            serde_json::from_slice(&entry).map_err(|_| invalid("entry JSON"))?,
            false,
        ))),
        Some((None, Some(redacted))) => {
            let redacted: Value =
                serde_json::from_slice(&redacted).map_err(|_| invalid("redacted entry JSON"))?;
            Ok(Some((pruned_opening_entry(&redacted), true)))
        }
        Some((None, None)) => Err(invalid("pruned opening lost its redacted entry")),
    }
}

/// Prune this transport-only home's copies of the opening `request_id`: its
/// transport entry becomes the pruned projection captured at insert and every
/// inbox row trades its request entry and signed publication for the redacted
/// entry. Returns whether this call pruned anything.
async fn prune_transport_opening(
    tx: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    request_id: Uuid,
    at: DateTime<Utc>,
) -> Result<bool, sqlx::Error> {
    let entry = sqlx::query(
        "UPDATE chat.direct_request_transport_entries \
            SET entry_bytes = pruned_entry_bytes, payload_pruned_at = $3 \
          WHERE conversation_id = $1 AND opening_request_id = $2 AND payload_pruned_at IS NULL",
    )
    .bind(conversation_id)
    .bind(request_id)
    .bind(at)
    .execute(&mut **tx)
    .await?;
    let inbox: Vec<(Uuid, Vec<u8>)> = sqlx::query_as(
        "SELECT delivery_id, request_entry FROM chat.direct_request_transport_inbox \
          WHERE conversation_id = $1 AND request_id = $2 AND opening_pruned_at IS NULL \
          ORDER BY delivery_id FOR UPDATE",
    )
    .bind(conversation_id)
    .bind(request_id)
    .fetch_all(&mut **tx)
    .await?;
    let mut redacted_any = false;
    for (delivery_id, request_entry) in &inbox {
        // A row that is not a well-formed opening cannot be redacted; it keeps its
        // bytes rather than failing the ack or deletion that reached it.
        let redacted = match serde_json::from_slice::<Value>(request_entry)
            .map_err(|_| invalid("inbox entry JSON"))
            .and_then(|entry| redacted_opening_entry(&entry))
        {
            Ok(redacted) => serde_json::to_vec(&redacted)
                .map_err(|error| sqlx::Error::Protocol(error.to_string()))?,
            Err(error) => {
                tracing::warn!(
                    conversation_id = %crate::crypto::redact_for_log(&conversation_id.hyphenated().to_string()),
                    %delivery_id,
                    %error,
                    "malformed transport opening left unpruned"
                );
                continue;
            }
        };
        sqlx::query(
            "UPDATE chat.direct_request_transport_inbox \
                SET request_entry = NULL, signed_publication = NULL, \
                    redacted_request_entry = $2, opening_pruned_at = $3 \
              WHERE delivery_id = $1 AND opening_pruned_at IS NULL",
        )
        .bind(delivery_id)
        .bind(&redacted)
        .bind(at)
        .execute(&mut **tx)
        .await?;
        redacted_any = true;
    }
    Ok(entry.rows_affected() > 0 || redacted_any)
}

async fn transport_opening_supported(connection: &mut PgConnection) -> Result<bool, sqlx::Error> {
    Ok(opening_columns_exist(
        &mut *connection,
        "chat.direct_request_transport_entries",
        "opening_request_id",
    )
    .await?
        && opening_columns_exist(
            connection,
            "chat.direct_request_transport_inbox",
            "redacted_request_entry",
        )
        .await?)
}

/// The transport-home audience rule for `e`, a transport entry row (`$1` is now):
/// at least one local active, non-dormant sender or recipient can still read the
/// opening, and none in that accepted/importable local inbox audience is behind
/// its seq. Expired or all-dormant local audiences are retained until the ceiling.
const TRANSPORT_OPENING_READY: &str = "e.opening_request_id IS NOT NULL \
    AND e.payload_pruned_at IS NULL \
    AND EXISTS ( \
        SELECT 1 \
          FROM (SELECT recipient_did AS user_did, recipient_device_id AS device_id \
                  FROM chat.direct_request_transport_inbox i \
                 WHERE i.conversation_id = e.conversation_id \
                   AND i.request_id = e.opening_request_id \
                   AND (i.status = 'accepted' OR (i.status = 'pending' AND i.import_until > $1)) \
                UNION \
                SELECT sender_did, sender_device_id \
                  FROM chat.direct_request_transport_inbox i \
                 WHERE i.conversation_id = e.conversation_id \
                   AND i.request_id = e.opening_request_id \
                   AND (i.status = 'accepted' OR (i.status = 'pending' AND i.import_until > $1))) audience \
          JOIN chat.devices d USING (user_did, device_id) \
         WHERE d.status = 'active' AND d.dormant_at IS NULL) \
    AND NOT EXISTS ( \
        SELECT 1 \
          FROM (SELECT recipient_did AS user_did, recipient_device_id AS device_id \
                  FROM chat.direct_request_transport_inbox i \
                 WHERE i.conversation_id = e.conversation_id \
                   AND i.request_id = e.opening_request_id \
                   AND (i.status = 'accepted' OR (i.status = 'pending' AND i.import_until > $1)) \
                UNION \
                SELECT sender_did, sender_device_id \
                  FROM chat.direct_request_transport_inbox i \
                 WHERE i.conversation_id = e.conversation_id \
                   AND i.request_id = e.opening_request_id \
                   AND (i.status = 'accepted' OR (i.status = 'pending' AND i.import_until > $1))) audience \
          JOIN chat.devices d USING (user_did, device_id) \
          LEFT JOIN chat.device_entry_acks ack \
            ON ack.conversation_id = e.conversation_id \
           AND ack.user_did = d.user_did AND ack.device_id = d.device_id \
         WHERE d.status = 'active' AND d.dormant_at IS NULL \
           AND COALESCE(ack.acked_through_seq, 0) < e.seq)";

/// A C33 transport-only home prunes its copies of each opening at or below
/// `acked_through_seq` that [`TRANSPORT_OPENING_READY`] allows. Returns the
/// pruned seqs.
pub(crate) async fn prune_acknowledged_transport_openings(
    tx: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    acked_through_seq: i64,
    at: DateTime<Utc>,
) -> Result<Vec<i64>, sqlx::Error> {
    if ciphertext_retained() || !transport_opening_supported(&mut **tx).await? {
        return Ok(Vec::new());
    }
    let ready: Vec<(i64, Uuid)> = sqlx::query_as(&format!(
        "SELECT e.seq, e.opening_request_id FROM chat.direct_request_transport_entries e \
          WHERE e.conversation_id = $2 AND e.seq <= $3 \
            AND e.created_at <= $4 AND {TRANSPORT_OPENING_READY} \
          ORDER BY e.seq"
    ))
    .bind(at)
    .bind(conversation_id)
    .bind(acked_through_seq)
    .bind(at - chrono::Duration::hours(72))
    .fetch_all(&mut **tx)
    .await?;
    let mut pruned = Vec::with_capacity(ready.len());
    for (seq, request_id) in ready {
        if prune_transport_opening(tx, conversation_id, request_id, at).await? {
            pruned.push(seq);
        }
    }
    Ok(pruned)
}

/// The periodic sweep of a transport-only home: every opening the ACK rule
/// ([`TRANSPORT_OPENING_READY`]) allows after the 72-hour minimum, and every
/// opening stored before `cutoff` (the 30-day ceiling), acknowledged or not.
/// Returns how many it pruned.
pub(crate) async fn prune_due_transport_openings(
    pool: &PgPool,
    cutoff: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<u64, sqlx::Error> {
    if ciphertext_retained() || !transport_opening_supported(&mut *pool.acquire().await?).await? {
        return Ok(0);
    }
    let due: Vec<(Uuid, Uuid)> = sqlx::query_as(&format!(
        "SELECT e.conversation_id, e.opening_request_id \
           FROM chat.direct_request_transport_entries e \
          WHERE (({TRANSPORT_OPENING_READY}) AND e.created_at <= $3) \
             OR (e.opening_request_id IS NOT NULL AND e.payload_pruned_at IS NULL \
                 AND e.created_at <= $2) \
          ORDER BY e.created_at, e.conversation_id, e.seq \
          LIMIT 256"
    ))
    .bind(now)
    .bind(cutoff)
    .bind(now - chrono::Duration::hours(72))
    .fetch_all(pool)
    .await?;
    let mut pruned = 0;
    for (conversation_id, request_id) in due {
        let mut tx = pool.begin().await?;
        pruned +=
            u64::from(prune_transport_opening(&mut tx, conversation_id, request_id, now).await?);
        tx.commit().await?;
    }
    Ok(pruned)
}

/// The 30-day ceiling for openings in this DS's own seq chains: each unpruned
/// opening received before `cutoff` loses its ciphertext, acknowledged or not.
/// Returns how many it pruned.
pub(crate) async fn prune_expired_coordinator_openings(
    pool: &PgPool,
    cutoff: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<u64, sqlx::Error> {
    if ciphertext_retained() {
        return Ok(0);
    }
    let due: Vec<(Uuid, i64)> = sqlx::query_as(
        "SELECT conversation_id, seq FROM chat.entries \
          WHERE entry_kind = $1 AND payload_pruned_at IS NULL AND received_at <= $2 \
          ORDER BY received_at, conversation_id, seq \
          LIMIT 256",
    )
    .bind(DIRECT_REQUEST_ENTRY_KIND)
    .bind(cutoff)
    .fetch_all(pool)
    .await?;
    let mut pruned = 0;
    for (conversation_id, seq) in due {
        let mut tx = pool.begin().await?;
        pruned += u64::from(prune_coordinator_opening(&mut tx, conversation_id, seq, now).await?);
        tx.commit().await?;
    }
    Ok(pruned)
}

/// Prune every opening `did` sent that this transport-only home holds for
/// `conversation_id`. Rows stored before their evidence existed record it first.
/// Returns how many openings it pruned.
pub(crate) async fn prune_transport_openings_sent_by(
    tx: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    did: &str,
    at: DateTime<Utc>,
) -> Result<usize, sqlx::Error> {
    prune_transport_openings(tx, conversation_id, did, None, at).await
}

pub(crate) async fn prune_transport_openings_sent_before(
    tx: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    did: &str,
    before_seq: i64,
    cutoff: DateTime<Utc>,
    at: DateTime<Utc>,
) -> Result<usize, sqlx::Error> {
    prune_transport_openings(tx, conversation_id, did, Some((before_seq, cutoff)), at).await
}

async fn prune_transport_openings(
    tx: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    did: &str,
    bounds: Option<(i64, DateTime<Utc>)>,
    at: DateTime<Utc>,
) -> Result<usize, sqlx::Error> {
    if ciphertext_retained() || !transport_opening_supported(&mut **tx).await? {
        return Ok(0);
    }
    let legacy: Vec<(i64, Vec<u8>)> = sqlx::query_as(
        "SELECT seq, entry_bytes FROM chat.direct_request_transport_entries \
          WHERE conversation_id = $1 AND evidence_pending ORDER BY seq",
    )
    .bind(conversation_id)
    .fetch_all(&mut **tx)
    .await?;
    for (seq, entry_bytes) in legacy {
        if let Err(error) = super::delivery::classify_legacy_transport_entry(
            &mut **tx,
            conversation_id,
            seq,
            &entry_bytes,
        )
        .await
        {
            // A malformed legacy row keeps its bytes rather than gaining false evidence.
            tracing::warn!(
                conversation_id = %crate::crypto::redact_for_log(&conversation_id.hyphenated().to_string()),
                seq,
                %error,
                "legacy transport entry left unclassified"
            );
        }
    }
    let requests: Vec<(Uuid, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT DISTINCT ON (request_id) request_id, CASE WHEN $3 THEN request_entry END
           FROM chat.direct_request_transport_inbox
          WHERE conversation_id = $1 AND sender_did = $2 AND opening_pruned_at IS NULL
          ORDER BY request_id, delivery_id",
    )
    .bind(conversation_id)
    .bind(did)
    .bind(bounds.is_some())
    .fetch_all(&mut **tx)
    .await?;
    let mut pruned = 0;
    for (request_id, entry) in requests {
        if let Some((before_seq, cutoff)) = bounds {
            // The authenticated opening is available even before its transport chain arrives.
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct OpeningScope {
                seq: i64,
                received_at: DateTime<Utc>,
            }
            let scope = entry
                .as_deref()
                .and_then(|bytes| serde_json::from_slice::<OpeningScope>(bytes).ok());
            if !scope.is_some_and(|scope| {
                scope.seq > 0 && scope.seq < before_seq && scope.received_at <= cutoff
            }) {
                continue;
            }
        }
        pruned += usize::from(prune_transport_opening(tx, conversation_id, request_id, at).await?);
    }
    Ok(pruned)
}

/// Prune the openings `did` sent through every C33 pair this DS holds only as a
/// transport-only home: the deleted account's own home learns of its deletion
/// locally, not from the pair's coordinator.
pub(crate) async fn prune_held_transport_openings_sent_by(
    tx: &mut Transaction<'_, Postgres>,
    did: &str,
    at: DateTime<Utc>,
) -> Result<usize, sqlx::Error> {
    if ciphertext_retained() || !transport_opening_supported(&mut **tx).await? {
        return Ok(0);
    }
    let conversations: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT i.conversation_id FROM chat.direct_request_transport_inbox i \
          WHERE i.sender_did = $1 AND i.opening_pruned_at IS NULL \
            AND NOT EXISTS (SELECT 1 FROM chat.conversations c \
                             WHERE c.conversation_id = i.conversation_id) \
          ORDER BY 1",
    )
    .bind(did)
    .fetch_all(&mut **tx)
    .await?;
    let mut pruned = 0;
    for conversation_id in conversations {
        pruned += prune_transport_openings_sent_by(tx, conversation_id, did, at).await?;
    }
    Ok(pruned)
}
