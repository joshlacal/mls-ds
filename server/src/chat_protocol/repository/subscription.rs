// Durable clean-chat subscription reads.
//
// `chat.events` is the only durable source. `chat.event_recipients` freezes
// entitlement for an exact device, so this reader never rediscovers a current
// conversation membership and cannot accidentally broaden a historical event.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use catbird_atproto::generated::blue_catbird::chat::{
    EventEnvelope, ProtocolEventPayload, SubscriptionMessage,
};
use chrono::{DateTime, Utc};
use jacquard_common::DefaultStr;
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};

use super::ticket::{
    insert_event_cursor_receipt, revalidate_consumed_ticket, ConsumedTicket, NewEventCursorReceipt,
    TicketRepositoryError,
};
use crate::{
    chat_protocol::{
        mint_capability_token, CursorSealer, OsSecureRandom, SealedCapability, SealerBinding,
    },
    sqlx_jacquard::chrono_to_datetime,
};

const MAX_BATCH: i64 = 256;

#[derive(Clone, Debug)]
pub(crate) struct VisibleEvent {
    pub(crate) event_position: i64,
    pub(crate) payload: ProtocolEventPayload<DefaultStr>,
    pub(crate) created_at: DateTime<Utc>,
}

/// Freeze the durable replay boundary after the ticket/device/protocol locks
/// have been acquired. Events appended after this value are reconciled by the
/// live polling phase using the same strict `event_position > last` predicate.
pub(crate) async fn replay_high_water(
    transaction: &mut Transaction<'_, Postgres>,
    ticket: &ConsumedTicket,
) -> Result<i64, TicketRepositoryError> {
    let (high_water, observed_at): (i64, DateTime<Utc>) = sqlx::query_as(
        "SELECT coalesce(max(event_position),0)::bigint, transaction_timestamp() FROM chat.events WHERE protocol_instance_id=$1",
    )
    .bind(ticket.protocol_instance_id)
    .fetch_one(&mut **transaction)
    .await?;
    revalidate_consumed_ticket(transaction, ticket, ticket.event_position, observed_at).await?;
    Ok(high_water.max(ticket.event_position))
}

/// Read one ordered, exact-device-visible batch. `through_position` is an
/// explicit replay/live fence; callers use a frozen high-water for replay and
/// a freshly sampled high-water for each live reconciliation pass.
pub(crate) async fn visible_events(
    transaction: &mut Transaction<'_, Postgres>,
    ticket: &ConsumedTicket,
    after_position: i64,
    through_position: i64,
    limit: i64,
) -> Result<Vec<VisibleEvent>, TicketRepositoryError> {
    if after_position < ticket.event_position
        || through_position < after_position
        || !(1..=MAX_BATCH).contains(&limit)
    {
        return Err(TicketRepositoryError::InvalidReceipt);
    }
    let observed_at: DateTime<Utc> = sqlx::query_scalar("SELECT transaction_timestamp()")
        .fetch_one(&mut **transaction)
        .await?;
    revalidate_consumed_ticket(transaction, ticket, after_position, observed_at).await?;
    let rows = sqlx::query(
        r#"SELECT event.event_position, event.payload_bytes,
                  event.payload_sha256, event.created_at
             FROM chat.event_recipients recipient
             JOIN chat.events event USING (event_position)
            WHERE recipient.user_did = $1
              AND recipient.device_id = $2
              AND event.protocol_instance_id = $3
              AND event.event_position > $4
              AND event.event_position <= $5
            ORDER BY event.event_position
            LIMIT $6"#,
    )
    .bind(&ticket.user_did)
    .bind(ticket.device_id)
    .bind(ticket.protocol_instance_id)
    .bind(after_position)
    .bind(through_position)
    .bind(limit)
    .fetch_all(&mut **transaction)
    .await?;

    rows.into_iter()
        .map(|row| {
            let bytes: Vec<u8> = row.try_get("payload_bytes")?;
            let stored_hash: Vec<u8> = row.try_get("payload_sha256")?;
            let payload_sha256: [u8; 32] = stored_hash
                .try_into()
                .map_err(|_| TicketRepositoryError::InvalidReceipt)?;
            if <[u8; 32]>::from(Sha256::digest(&bytes)) != payload_sha256 {
                return Err(TicketRepositoryError::InvalidReceipt);
            }
            let payload = serde_json::from_slice(&bytes)
                .map_err(|_| TicketRepositoryError::InvalidReceipt)?;
            Ok(VisibleEvent {
                event_position: row.try_get("event_position")?,
                payload,
                created_at: row.try_get("created_at")?,
            })
        })
        .collect()
}

/// Ensure the inventory snapshot cursor is the first durable receipt. Ticket
/// consumption locks the inventory session, making the read-before-insert safe
/// even when multiple separately minted tickets target the same session.
pub(crate) async fn ensure_initial_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    ticket: &ConsumedTicket,
) -> Result<(), TicketRepositoryError> {
    let existing: Option<(i64, Option<Vec<u8>>, Option<Vec<u8>>)> = sqlx::query_as(
        r#"SELECT event_position, predecessor_cursor_hash, canonical_envelope_sha256
             FROM chat.event_cursor_receipts
            WHERE cursor_hash=$1
            FOR UPDATE"#,
    )
    .bind(ticket.event_cursor_hash.as_slice())
    .fetch_optional(&mut **transaction)
    .await?;
    if let Some((position, predecessor, envelope_hash)) = existing {
        return if position == ticket.event_position
            && predecessor.is_none()
            && envelope_hash.is_none()
        {
            Ok(())
        } else {
            Err(TicketRepositoryError::InvalidReceipt)
        };
    }
    insert_event_cursor_receipt(
        transaction,
        &NewEventCursorReceipt {
            cursor_hash: ticket.event_cursor_hash,
            inventory_session_id: ticket.inventory_session_id,
            user_did: ticket.user_did.clone(),
            device_id: ticket.device_id,
            jkt: ticket.jkt.clone(),
            auth_generation: ticket.auth_generation,
            protocol_instance_id: ticket.protocol_instance_id,
            cursor_key_id: ticket.cursor_key_id.clone(),
            event_position: ticket.event_position,
            predecessor_cursor_hash: None,
            retained_floor_at_issue: ticket.snapshot_retained_floor,
            cursor_nonce: ticket.snapshot_cursor_nonce,
            cursor_ciphertext: ticket.snapshot_cursor_ciphertext.clone(),
            canonical_envelope_sha256: None,
            created_at: ticket.snapshot_created_at,
            expires_at: ticket.expires_at,
        },
    )
    .await
}

/// Materialize or replay the next cursor-bound generated envelope. The
/// receipt is committed before the caller writes the frame, so a dropped
/// response can be reconstructed byte-for-byte on a later ticket.
pub(crate) async fn materialize_envelope(
    transaction: &mut Transaction<'_, Postgres>,
    ticket: &ConsumedTicket,
    event: VisibleEvent,
    previous_cursor: &str,
    previous_cursor_hash: [u8; 32],
    sealer: &CursorSealer,
) -> Result<(SubscriptionMessage<DefaultStr>, String, [u8; 32]), TicketRepositoryError> {
    let existing = sqlx::query(
        r#"SELECT cursor_hash, predecessor_cursor_hash, retained_floor_at_issue,
                  cursor_nonce, cursor_ciphertext, canonical_envelope_sha256,
                  created_at, expires_at
             FROM chat.event_cursor_receipts
            WHERE inventory_session_id=$1 AND device_id=$2 AND event_position=$3
            FOR UPDATE"#,
    )
    .bind(ticket.inventory_session_id)
    .bind(ticket.device_id)
    .bind(event.event_position)
    .fetch_optional(&mut **transaction)
    .await?;

    let (cursor, cursor_hash, expected_envelope_hash) = if let Some(row) = existing {
        let cursor_hash: [u8; 32] = row
            .try_get::<Vec<u8>, _>("cursor_hash")?
            .try_into()
            .map_err(|_| TicketRepositoryError::InvalidReceipt)?;
        let predecessor: [u8; 32] = row
            .try_get::<Vec<u8>, _>("predecessor_cursor_hash")?
            .try_into()
            .map_err(|_| TicketRepositoryError::InvalidReceipt)?;
        let retained_floor: i64 = row.try_get("retained_floor_at_issue")?;
        let created_at: DateTime<Utc> = row.try_get("created_at")?;
        let expires_at: DateTime<Utc> = row.try_get("expires_at")?;
        if predecessor != previous_cursor_hash
            || retained_floor != ticket.snapshot_retained_floor
            || expires_at != ticket.expires_at
        {
            return Err(TicketRepositoryError::InvalidReceipt);
        }
        let binding = event_binding(
            ticket,
            event.event_position,
            Some(predecessor),
            created_at,
            expires_at,
        )?;
        let nonce: [u8; 12] = row
            .try_get::<Vec<u8>, _>("cursor_nonce")?
            .try_into()
            .map_err(|_| TicketRepositoryError::InvalidReceipt)?;
        let plaintext = sealer
            .verify_successor(
                &SealedCapability {
                    nonce,
                    ciphertext: row.try_get("cursor_ciphertext")?,
                },
                &binding,
            )
            .map_err(|_| TicketRepositoryError::InvalidReceipt)?;
        if <[u8; 32]>::from(Sha256::digest(plaintext.as_slice())) != cursor_hash {
            return Err(TicketRepositoryError::InvalidReceipt);
        }
        let expected_hash: [u8; 32] = row
            .try_get::<Vec<u8>, _>("canonical_envelope_sha256")?
            .try_into()
            .map_err(|_| TicketRepositoryError::InvalidReceipt)?;
        (
            URL_SAFE_NO_PAD.encode(plaintext.as_slice()),
            cursor_hash,
            expected_hash,
        )
    } else {
        let created_at: DateTime<Utc> = sqlx::query_scalar("SELECT transaction_timestamp()")
            .fetch_one(&mut **transaction)
            .await?;
        if created_at >= ticket.expires_at {
            return Err(TicketRepositoryError::TicketExpired);
        }
        let token = mint_capability_token(&mut OsSecureRandom::new())
            .map_err(|_| TicketRepositoryError::InvalidReceipt)?;
        let cursor = token.encode();
        let cursor_hash = token.lookup_hash();
        // The envelope hash is filled after constructing the generated union.
        (cursor, cursor_hash, [0; 32])
    };

    let message = SubscriptionMessage::EventEnvelope(Box::new(EventEnvelope {
        created_at: chrono_to_datetime(event.created_at),
        cursor: cursor.clone().into(),
        payload: event.payload,
        previous_cursor: previous_cursor.into(),
        extra_data: None,
    }));
    let canonical_bytes =
        serde_json::to_vec(&message).map_err(|_| TicketRepositoryError::InvalidReceipt)?;
    let envelope_hash: [u8; 32] = Sha256::digest(&canonical_bytes).into();

    if expected_envelope_hash != [0; 32] {
        if expected_envelope_hash != envelope_hash {
            return Err(TicketRepositoryError::InvalidReceipt);
        }
    } else {
        // Recreate the sealing inputs after envelope construction. This is
        // intentionally inside the transaction that persists the receipt.
        let created_at: DateTime<Utc> = sqlx::query_scalar("SELECT transaction_timestamp()")
            .fetch_one(&mut **transaction)
            .await?;
        let decoded = URL_SAFE_NO_PAD
            .decode(&cursor)
            .map_err(|_| TicketRepositoryError::InvalidReceipt)?;
        let binding = event_binding(
            ticket,
            event.event_position,
            Some(previous_cursor_hash),
            created_at,
            ticket.expires_at,
        )?;
        let sealed = sealer
            .seal_successor(&decoded, &binding, &mut OsSecureRandom::new())
            .map_err(|_| TicketRepositoryError::InvalidReceipt)?;
        insert_event_cursor_receipt(
            transaction,
            &NewEventCursorReceipt {
                cursor_hash,
                inventory_session_id: ticket.inventory_session_id,
                user_did: ticket.user_did.clone(),
                device_id: ticket.device_id,
                jkt: ticket.jkt.clone(),
                auth_generation: ticket.auth_generation,
                protocol_instance_id: ticket.protocol_instance_id,
                cursor_key_id: ticket.cursor_key_id.clone(),
                event_position: event.event_position,
                predecessor_cursor_hash: Some(previous_cursor_hash),
                retained_floor_at_issue: ticket.snapshot_retained_floor,
                cursor_nonce: sealed.nonce,
                cursor_ciphertext: sealed.ciphertext,
                canonical_envelope_sha256: Some(envelope_hash),
                created_at,
                expires_at: ticket.expires_at,
            },
        )
        .await?;
    }
    Ok((message, cursor, cursor_hash))
}

fn event_binding(
    ticket: &ConsumedTicket,
    event_position: i64,
    predecessor: Option<[u8; 32]>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> Result<SealerBinding, TicketRepositoryError> {
    SealerBinding::for_event_cursor_receipt(
        ticket.inventory_session_id,
        ticket.user_did.as_bytes(),
        ticket.device_id,
        ticket.jkt.as_deref().unwrap_or("").as_bytes(),
        u64::try_from(ticket.auth_generation).map_err(|_| TicketRepositoryError::InvalidReceipt)?,
        ticket.protocol_instance_id,
        ticket.cursor_key_id.as_bytes(),
        u64::try_from(event_position).map_err(|_| TicketRepositoryError::InvalidReceipt)?,
        predecessor,
        u64::try_from(ticket.snapshot_retained_floor)
            .map_err(|_| TicketRepositoryError::InvalidReceipt)?,
        u64::try_from(created_at.timestamp()).map_err(|_| TicketRepositoryError::InvalidReceipt)?,
        u64::try_from(expires_at.timestamp()).map_err(|_| TicketRepositoryError::InvalidReceipt)?,
    )
    .map_err(|_| TicketRepositoryError::InvalidReceipt)
}
