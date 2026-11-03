//! Retained terminal close evidence (`I14`, `O7`).
//!
//! A close wipes every operational row of the conversation in its own
//! transaction. The exact signed close entry survives only as an attachment to
//! the immutable `conversationClosed` event (keyed by `event_position`), so the
//! devices in that event's frozen audience still learn the authenticated close
//! through `getEntries` instead of observing a silently missing conversation.

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use super::delivery::{
    append_event, enqueue_outbox, insert_event_recipients, DeliveryRepositoryError,
    EventEntitlementKind, EventKind, EventRecipient, NewEvent, OutboxWorkKind,
};

const CLOSE_ENTRY_TYPE: &str = "blue.catbird.chat.defs#conversationCloseEntry";

fn encode(value: &Value) -> Result<Vec<u8>, DeliveryRepositoryError> {
    serde_json::to_vec(value).map_err(|error| {
        DeliveryRepositoryError::Database(sqlx::Error::Protocol(error.to_string()))
    })
}

async fn insert_attachment(
    transaction: &mut Transaction<'_, Postgres>,
    event_position: i64,
    source_ds_did: Option<&str>,
    source_authority_bytes: Option<&[u8]>,
    entry: &Value,
) -> Result<(), DeliveryRepositoryError> {
    let bytes = encode(entry)?;
    let statement = if source_ds_did.is_some() {
        "INSERT INTO chat.conversation_close_terminal_entries \
             (event_position, entry_bytes, entry_sha256, source_ds_did, source_authority_bytes) \
         VALUES ($1, $2, $3, $4, $5)"
    } else {
        "INSERT INTO chat.conversation_close_terminal_entries \
             (event_position, entry_bytes, entry_sha256) \
         VALUES ($1, $2, $3)"
    };
    let mut insert = sqlx::query(statement)
        .bind(event_position)
        .bind(&bytes)
        .bind(Sha256::digest(&bytes).to_vec());
    if let Some(source) = source_ds_did {
        insert = insert.bind(source).bind(source_authority_bytes);
    }
    insert.execute(&mut **transaction).await?;
    Ok(())
}

/// Lock the global direct-request budget that `conversation_id`'s wipe debits
/// (`chat.wipe_closed_conversation_operational_rows` releases the retained
/// charges of its publication and transport-inbox requests) where every
/// request operation takes it: after the operation lock and before the
/// principal/device/key prefix (`direct_request_lock.rs`). First taken at the
/// wipe, after the close's identity and head locks, it closes a cycle with an
/// `acceptConversation` that holds the budget and waits on those (40P01). Any
/// retained charge locks: a superset of the wipe's `gross_retained > 0`.
pub(crate) async fn lock_wipe_request_budget(
    transaction: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "SELECT budget.singleton FROM chat.direct_request_budget budget \
          WHERE budget.singleton AND EXISTS ( \
              SELECT 1 FROM chat.direct_request_retained_charges charge \
               WHERE charge.request_id IN ( \
                   SELECT request_id FROM chat.direct_request_publications \
                    WHERE conversation_id = $1 \
                   UNION ALL \
                   SELECT request_id FROM chat.direct_request_transport_inbox \
                    WHERE conversation_id = $1)) \
            FOR UPDATE OF budget",
    )
    .bind(conversation_id)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

/// Attach the signed close entry to the `conversationClosed` event this
/// transaction's close produced. `first_event_position` is the close
/// operation's first applied event; the close event is at or after it.
pub(crate) async fn attach_local_close_entry(
    transaction: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    first_event_position: i64,
    entry: &Value,
) -> Result<(), DeliveryRepositoryError> {
    let event_position: i64 = sqlx::query_scalar(
        "SELECT event_position FROM chat.events \
          WHERE event_position >= $1 \
            AND event_kind = 'conversationClosed' \
            AND convert_from(payload_bytes, 'UTF8')::jsonb->>'conversationId' = $2 \
          ORDER BY event_position ASC LIMIT 1",
    )
    .bind(first_event_position)
    .bind(conversation_id.hyphenated().to_string())
    .fetch_one(&mut **transaction)
    .await?;
    insert_attachment(transaction, event_position, None, None, entry).await
}

/// Append this home's `conversationClosed` event for a verified remote close,
/// addressed only to the caller-authenticated local audience, and retain the
/// signed entry plus its source sequencer/proof. An empty audience still needs
/// terminal evidence so the operational wipe can complete. `None` means only
/// that the same close entry was already recorded (a redelivered fan-out).
pub(crate) async fn append_remote_close_event(
    transaction: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    source_ds_did: &str,
    source_authority_bytes: Option<&[u8]>,
    conversation_kind: &str,
    terminal_seq: i64,
    recipient_devices: &[(String, Uuid)],
    entry: &Value,
    created_at: DateTime<Utc>,
) -> Result<Option<i64>, DeliveryRepositoryError> {
    // Transport-only homes have no conversation row to serialize duplicate
    // close deliveries. Keep their frozen terminal audience/event singular too.
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended( \
             'conversation-close-terminal:' || $1::uuid::text, 0))",
    )
    .bind(conversation_id)
    .execute(&mut **transaction)
    .await?;
    let entry_id = entry
        .get("entryId")
        .and_then(Value::as_str)
        .unwrap_or_default();
    // The signed entry carries a NUL-terminated signature domain that
    // PostgreSQL JSON rejects, so its entryId is compared here.
    let recorded: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT terminal.entry_bytes FROM chat.conversation_close_terminal_entries terminal \
           JOIN chat.events event USING (event_position) \
          WHERE convert_from(event.payload_bytes, 'UTF8')::jsonb->>'conversationId' = $1",
    )
    .bind(conversation_id.hyphenated().to_string())
    .fetch_all(&mut **transaction)
    .await?;
    let already_recorded = recorded.iter().any(|bytes| {
        serde_json::from_slice::<Value>(bytes)
            .is_ok_and(|recorded| recorded.get("entryId").and_then(Value::as_str) == Some(entry_id))
    });
    if already_recorded {
        return Ok(None);
    }
    let mut audience: Vec<(String, Uuid)> = Vec::with_capacity(recipient_devices.len());
    for (user_did, device_id) in recipient_devices {
        let registered: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM chat.devices WHERE user_did = $1 AND device_id = $2)",
        )
        .bind(user_did)
        .bind(device_id)
        .fetch_one(&mut **transaction)
        .await?;
        if registered {
            audience.push((user_did.clone(), *device_id));
        }
    }
    audience.sort_by(|left, right| {
        left.0
            .as_bytes()
            .cmp(right.0.as_bytes())
            .then_with(|| left.1.as_bytes().cmp(right.1.as_bytes()))
    });
    audience.dedup();

    let protocol_instance_id: Uuid = sqlx::query_scalar(
        "SELECT protocol_instance_id FROM chat.protocol_instances WHERE singleton FOR SHARE",
    )
    .fetch_one(&mut **transaction)
    .await?;
    let mut recipients = Vec::with_capacity(audience.len());
    for (user_did, device_id) in audience {
        sqlx::query("SELECT 1 FROM chat.devices WHERE user_did = $1 AND device_id = $2 FOR UPDATE")
            .bind(&user_did)
            .bind(device_id)
            .fetch_one(&mut **transaction)
            .await?;
        let predecessor: Option<i64> = sqlx::query_scalar(
            "SELECT max(event_position) FROM chat.event_recipients \
              WHERE user_did = $1 AND device_id = $2",
        )
        .bind(&user_did)
        .bind(device_id)
        .fetch_one(&mut **transaction)
        .await?;
        recipients.push(EventRecipient {
            user_did,
            device_id,
            entitlement_kind: EventEntitlementKind::HistoricalSchedule,
            audience_predecessor_position: predecessor,
        });
    }

    let payload_bytes = encode(&json!({
        "$type": "blue.catbird.chat.defs#conversationClosedEvent",
        "conversationId": conversation_id.hyphenated().to_string(),
        "conversationKind": conversation_kind,
        "terminalSeq": terminal_seq,
    }))?;
    let event_id = crate::sim_hooks::mint_entry_uuid_v4(
        b"federation.close.event",
        &[conversation_id.as_bytes(), entry_id.as_bytes()],
    );
    let event_position = append_event(
        transaction,
        &NewEvent {
            event_id,
            event_kind: EventKind::ConversationClosed,
            payload_bytes,
            created_at,
            protocol_instance_id,
        },
    )
    .await?;
    insert_event_recipients(transaction, event_position, &recipients).await?;
    enqueue_outbox(
        transaction,
        crate::sim_hooks::mint_entry_uuid_v4(
            b"federation.close.outbox",
            &[conversation_id.as_bytes(), event_id.as_bytes()],
        ),
        event_position,
        OutboxWorkKind::Stream,
        created_at,
    )
    .await?;
    insert_attachment(
        transaction,
        event_position,
        Some(source_ds_did),
        source_authority_bytes,
        entry,
    )
    .await?;
    Ok(Some(event_position))
}

/// The retained signed close entry for a device in the close event's frozen
/// audience, after the conversation's operational rows were wiped.
pub(crate) async fn retained_close_entry_for_device(
    transaction: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    user_did: &str,
    device_id: Uuid,
) -> Result<Option<Value>, DeliveryRepositoryError> {
    let table_exists: bool = sqlx::query_scalar(
        "SELECT to_regclass('chat.conversation_close_terminal_entries') IS NOT NULL",
    )
    .fetch_one(&mut **transaction)
    .await?;
    if !table_exists {
        return Ok(None);
    }
    let bytes: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT terminal.entry_bytes \
           FROM chat.event_recipients recipient \
           JOIN chat.events event USING (event_position) \
           JOIN chat.conversation_close_terminal_entries terminal USING (event_position) \
          WHERE recipient.user_did = $1 \
            AND recipient.device_id = $2 \
            AND event.event_kind = 'conversationClosed' \
            AND convert_from(event.payload_bytes, 'UTF8')::jsonb->>'conversationId' = $3 \
          ORDER BY event.event_position DESC LIMIT 1",
    )
    .bind(user_did)
    .bind(device_id)
    .bind(conversation_id.hyphenated().to_string())
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(bytes) = bytes else {
        return Ok(None);
    };
    let mut entry: Value = serde_json::from_slice(&bytes).map_err(|error| {
        DeliveryRepositoryError::Database(sqlx::Error::Protocol(error.to_string()))
    })?;
    if entry.get("$type").is_none() {
        entry["$type"] = json!(CLOSE_ENTRY_TYPE);
    }
    Ok(Some(entry))
}
