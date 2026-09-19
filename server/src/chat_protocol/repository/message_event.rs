//! Application event append parity with the deployed7ad source.
//! Source helper SHA256: b14506719c6ce7baa5d4f22911bfb562c6aed00bd4d737369788232e87bc5438
//! Preserve the existing device-row, foreign-key, and deferred-chain fences.
use super::delivery::{
    append_event, enqueue_outbox, insert_event_recipients, DeliveryRepositoryError,
    EventEntitlementKind, EventKind, EventRecipient, NewEvent, OutboxWorkKind,
};
use chrono::{DateTime, Utc};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(crate) async fn append_message_available_event(
    transaction: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    generation: i64,
    seq: u64,
    created_at: DateTime<Utc>,
) -> Result<i64, DeliveryRepositoryError> {
    let seq = i64::try_from(seq).map_err(|_| DeliveryRepositoryError::SequenceOverflow)?;
    let protocol_instance_id: Uuid = sqlx::query_scalar(
        "SELECT protocol_instance_id FROM chat.protocol_instances WHERE singleton FOR SHARE",
    )
    .fetch_one(&mut **transaction)
    .await?;
    let mut audience: Vec<(String, Uuid)> = sqlx::query_as(
        r#"
        SELECT recipient_did, recipient_device_id
          FROM chat.application_intervals
         WHERE conversation_id = $1
           AND generation = $2
           AND start_seq <= $3
           AND (terminal_seq IS NULL OR terminal_seq >= $3)
        "#,
    )
    .bind(conversation_id)
    .bind(generation)
    .bind(seq)
    .fetch_all(&mut **transaction)
    .await?;
    audience.sort_by(|left, right| {
        left.0
            .as_bytes()
            .cmp(right.0.as_bytes())
            .then_with(|| left.1.as_bytes().cmp(right.1.as_bytes()))
    });
    if audience.is_empty() {
        return Err(DeliveryRepositoryError::EmptyRecipients);
    }
    if audience.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(DeliveryRepositoryError::NonCanonicalRecipients);
    }

    let mut recipients = Vec::with_capacity(audience.len());
    for (user_did, device_id) in audience {
        sqlx::query("SELECT 1 FROM chat.devices WHERE user_did=$1 AND device_id=$2 FOR UPDATE")
            .bind(&user_did)
            .bind(device_id)
            .fetch_one(&mut **transaction)
            .await?;
        let predecessor = sqlx::query_scalar(
            "SELECT max(event_position) FROM chat.event_recipients \
             WHERE user_did=$1 AND device_id=$2",
        )
        .bind(&user_did)
        .bind(device_id)
        .fetch_one(&mut **transaction)
        .await?;
        recipients.push(EventRecipient {
            user_did,
            device_id,
            entitlement_kind: EventEntitlementKind::Leaf,
            audience_predecessor_position: predecessor,
        });
    }

    let payload_bytes = format!(
        r#"{{"$type":"blue.catbird.chat.defs#messageAvailableEvent","conversationId":"{}","seq":{seq}}}"#,
        conversation_id.hyphenated(),
    )
    .into_bytes();
    let event_position = append_event(
        transaction,
        &NewEvent {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::MessageAvailable,
            payload_bytes,
            created_at,
            protocol_instance_id,
        },
    )
    .await?;
    insert_event_recipients(transaction, event_position, &recipients).await?;
    enqueue_outbox(
        transaction,
        Uuid::new_v4(),
        event_position,
        OutboxWorkKind::Stream,
        created_at,
    )
    .await?;
    Ok(event_position)
}
