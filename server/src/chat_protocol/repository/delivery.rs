// Append-log delivery executor for the clean-chat protocol.
//
// This module owns the single narrow primitive that materializes accepted
// protocol history into `chat.entries`: allocation of the next append-log
// sequence number. Every entry kind -- application, control, transition,
// reset, close -- shares one conversation-global counter,
// `chat.conversations.next_entry_seq`, so allocation must be serialized by the
// conversation head row lock rather than by any application-level counter.
//
// The allocator therefore, in one caller-owned transaction:
//   1. locks the conversation head with `SELECT ... FOR UPDATE`;
//   2. uses the locked `next_entry_seq` as the new entry's `seq`;
//   3. inserts the entry at that `seq`;
//   4. advances `next_entry_seq` by one under the same lock.
//
// Concurrent appends block on the head lock and are thus assigned unique,
// contiguous seqs that never reset across generations. The database's own
// `(conversation_id, seq)` primary key and deferred contiguity invariant
// remain the ultimate authority; this executor's contract is to keep the
// counter and the append-log in lock-step.

use chrono::{DateTime, Utc};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

/// Failures the append-log allocator can surface to its caller.
#[derive(Debug)]
pub(crate) enum DeliveryRepositoryError {
    /// A database error escaped the transaction (including primary-key and
    /// deferred-invariant violations raised while inserting the entry).
    Database(sqlx::Error),
    /// No conversation head row exists for the target `conversation_id`, so no
    /// seq can be allocated. The allocator refuses to invent one.
    ConversationMissing,
    /// The locked `next_entry_seq` fell outside the protocol's safe-integer
    /// range and cannot be returned as a `u64` seq.
    SequenceOverflow,
}

impl From<sqlx::Error> for DeliveryRepositoryError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

/// One append-log entry to be allocated a globally-contiguous seq and inserted
/// into `chat.entries`. The `seq` is deliberately *not* a field: it is derived
/// from the locked conversation head so two concurrent appends can never carry
/// the same seq. Every other `chat.entries` column is carried verbatim, and the
/// database's `CHECK`/`FK`/deferred constraints remain the shape authority.
#[derive(Clone, Debug)]
pub(crate) struct AppendEntry {
    pub(crate) conversation_id: Uuid,
    pub(crate) entry_id: Uuid,
    pub(crate) entry_kind: String,
    pub(crate) accepted_payload_bytes: Vec<u8>,
    pub(crate) accepted_payload_sha256: Vec<u8>,
    pub(crate) signed_request_bytes: Vec<u8>,
    pub(crate) request_digest: Vec<u8>,
    pub(crate) signature: Vec<u8>,
    pub(crate) server_fields_bytes: Vec<u8>,
    pub(crate) outer_entry_fingerprint: Vec<u8>,
    pub(crate) actor_did: String,
    pub(crate) actor_device_id: Uuid,
    pub(crate) actor_key_id: String,
    pub(crate) actor_auth_generation: i64,
    pub(crate) generation: Option<i64>,
    pub(crate) state_version: Option<i64>,
    pub(crate) transition_id: Option<Uuid>,
    pub(crate) message_id: Option<Uuid>,
    pub(crate) received_at: DateTime<Utc>,
}

/// Allocate the next append-log seq for `entry.conversation_id` and insert the
/// entry at it, advancing the conversation-global counter — all inside the
/// caller-owned transaction. Returns the allocated seq.
///
/// The `SELECT ... FOR UPDATE` on the conversation head serializes concurrent
/// appenders on the same conversation, so the returned seqs are unique,
/// contiguous, and never reset by generation. The caller is responsible for
/// completing any coherent side rows (e.g. `chat.message_sends`) the entry's
/// kind requires before committing, so the deferred delivery invariants hold.
pub(crate) async fn append_entry(
    transaction: &mut Transaction<'_, Postgres>,
    entry: &AppendEntry,
) -> Result<u64, DeliveryRepositoryError> {
    // 1. Lock the conversation head. This is the serialization point: a
    //    concurrent appender blocks here until we commit or roll back, so it can
    //    never observe the same `next_entry_seq`.
    let locked_seq: Option<i64> = sqlx::query_scalar(
        r#"
        SELECT next_entry_seq
          FROM chat.conversations
         WHERE conversation_id = $1
         FOR UPDATE
        "#,
    )
    .bind(entry.conversation_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let seq = locked_seq.ok_or(DeliveryRepositoryError::ConversationMissing)?;

    // 2 + 3. Use the locked value as this entry's seq and insert the row.
    sqlx::query(
        r#"
        INSERT INTO chat.entries(
            conversation_id, seq, entry_id, entry_kind,
            accepted_payload_bytes, accepted_payload_sha256,
            signed_request_bytes, request_digest, signature,
            server_fields_bytes, outer_entry_fingerprint,
            actor_did, actor_device_id, actor_key_id, actor_auth_generation,
            generation, state_version, transition_id, message_id, received_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
            $11, $12, $13, $14, $15, $16, $17, $18, $19, $20
        )
        "#,
    )
    .bind(entry.conversation_id)
    .bind(seq)
    .bind(entry.entry_id)
    .bind(&entry.entry_kind)
    .bind(&entry.accepted_payload_bytes)
    .bind(&entry.accepted_payload_sha256)
    .bind(&entry.signed_request_bytes)
    .bind(&entry.request_digest)
    .bind(&entry.signature)
    .bind(&entry.server_fields_bytes)
    .bind(&entry.outer_entry_fingerprint)
    .bind(&entry.actor_did)
    .bind(entry.actor_device_id)
    .bind(&entry.actor_key_id)
    .bind(entry.actor_auth_generation)
    .bind(entry.generation)
    .bind(entry.state_version)
    .bind(entry.transition_id)
    .bind(entry.message_id)
    .bind(entry.received_at)
    .execute(&mut **transaction)
    .await?;

    // 4. Advance the append counter under the still-held head lock. The counter
    //    is conversation-global and monotonic, so it never resets by generation.
    sqlx::query(
        r#"
        UPDATE chat.conversations
           SET next_entry_seq = next_entry_seq + 1
         WHERE conversation_id = $1
        "#,
    )
    .bind(entry.conversation_id)
    .execute(&mut **transaction)
    .await?;

    u64::try_from(seq).map_err(|_| DeliveryRepositoryError::SequenceOverflow)
}
