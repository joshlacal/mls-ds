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
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

/// Failures the append-log allocator can surface to its caller.
#[derive(Debug)]
pub enum DeliveryRepositoryError {
    /// A database error escaped the transaction (including primary-key and
    /// deferred-invariant violations raised while inserting the entry).
    Database(sqlx::Error),
    /// No conversation head row exists for the target `conversation_id`, so no
    /// seq can be allocated. The allocator refuses to invent one.
    ConversationMissing,
    /// The locked `next_entry_seq` fell outside the protocol's safe-integer
    /// range and cannot be returned as a `u64` seq.
    SequenceOverflow,
    /// A frozen control-entry audience was requested with no recipients. A
    /// control entry that addresses no device is a caller bug, not an empty
    /// legal audience, so the allocator refuses to write zero rows.
    EmptyRecipients,
    /// A frozen audience was submitted out of the canonical
    /// `(user-DID UTF-8, device UUID raw bytes)` order, or with a duplicate
    /// tuple. The primitive enforces caller-supplied order rather than sorting
    /// or de-duplicating, so a non-canonical array is rejected outright.
    NonCanonicalRecipients,
    /// An outbox delivery CAS matched no row: the caller is not the current
    /// lease owner, or the row is no longer leased. The stale/non-owner caller
    /// changed nothing, which is an error rather than a silent no-op.
    OutboxLeaseMismatch,
    /// A compare-and-set matched no row: the stored row's compared columns did
    /// not equal the expected pre-state — drift, a wrong status, or an already
    /// terminalized period. The caller changed nothing, which is a conflict,
    /// not a silent success. Used by the migration-2 state-family terminalizers
    /// (interval close, Welcome delivery terminalize, recovery work terminalize)
    /// exactly as `transition::TransitionRepositoryError::CompareAndSetConflict`
    /// is used for the migration-1 families.
    CompareAndSetConflict,
    /// An application send reused an existing `(conversation_id, message_id)` with a
    /// DIFFERENT signed request (the stored `request_digest` disagrees). The
    /// message-id idempotency key binds one signed message; a second distinct
    /// message under the same id is rejected rather than overwriting the durable
    /// outcome. (An EXACT replay is idempotent and returns the stored outcome.)
    MessageSendConflict,
    /// A repository-issued terminal authority failed its seal, transaction,
    /// disposition, or immutable-row binding before the first write.
    InvalidTerminalAuthority,
    /// An application send carried no `message_id`. Every send is idempotency-keyed
    /// by `(conversation_id, message_id)`, so the id is mandatory.
    MissingMessageId,
    /// A projection was requested on the wrong entry kind: an application
    /// projection on a control row, or a control projection on an application
    /// row. The two closed projection shapes are disjoint, so a caller that asks
    /// for the wrong one is a bug, not an empty projection.
    EntryKindMismatch,
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
pub struct AppendEntry {
    pub conversation_id: Uuid,
    pub entry_id: Uuid,
    pub entry_kind: String,
    pub accepted_payload_bytes: Vec<u8>,
    pub accepted_payload_sha256: Vec<u8>,
    pub signed_request_bytes: Vec<u8>,
    pub request_digest: Vec<u8>,
    pub signature: Vec<u8>,
    pub server_fields_bytes: Vec<u8>,
    pub outer_entry_fingerprint: Vec<u8>,
    pub actor_did: String,
    pub actor_device_id: Uuid,
    pub actor_key_id: String,
    pub actor_auth_generation: i64,
    pub generation: Option<i64>,
    pub state_version: Option<i64>,
    pub transition_id: Option<Uuid>,
    pub message_id: Option<Uuid>,
    pub received_at: DateTime<Utc>,
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
pub async fn append_entry(
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

/// Insert one append-log entry at an **exact, pre-allocated** seq, without
/// touching `chat.conversations.next_entry_seq`.
///
/// This is the seq-seam partner of the transition executor's conversation-head
/// write. The executor's head write (INSERT for creation, compare-and-set UPDATE
/// for an existing conversation) is the single authority that advances
/// `next_entry_seq` from the planner's `allocated_seq` to
/// `successor_next_entry_seq`; the entry itself is then materialized here at that
/// exact `allocated_seq`. Unlike [`append_entry`], this primitive does **not**
/// `SELECT ... FOR UPDATE` the head or advance the counter — doing both here and
/// in the head write would double-advance it. The database's own
/// `(conversation_id, seq)` primary key and the deferred append-contiguity
/// invariant (`next_entry_seq == max(seq) + 1` at COMMIT) remain the arbiter: a
/// seq that disagrees with the head write's counter fails the deferred check at
/// COMMIT, and a duplicate seq fails the primary key immediately.
///
/// The caller must have already written the conversation head row in the same
/// transaction (the immediate `chat.entries` → `chat.conversations` foreign key
/// requires it).
pub(crate) async fn append_entry_at(
    transaction: &mut Transaction<'_, Postgres>,
    entry: &AppendEntry,
    seq: u64,
) -> Result<u64, DeliveryRepositoryError> {
    let seq_i64 = i64::try_from(seq).map_err(|_| DeliveryRepositoryError::SequenceOverflow)?;
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
    .bind(seq_i64)
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
    Ok(seq)
}

// ===========================================================================
// Application message send (Task E2b-7 arm 6).
//
// A message send is NOT a coordinate-changing transition: it appends one
// `applicationEntry` at a self-allocated seq (via `append_entry`) and advances
// only `next_entry_seq` — the crypto coordinate is untouched. It is
// idempotency-keyed by `(conversation_id, message_id)` in `chat.message_sends`.
// The audience of an application entry is INTERVAL-DERIVED (a reader sees it iff
// its application interval spans the seq), so this writes NO `entry_recipients`.
// ===========================================================================

/// One application send: the `applicationEntry` envelope (`entry`, whose
/// `message_id` is the idempotency key and whose `signed_request_bytes` /
/// `request_digest` / `signature` / `received_at` the durable `message_sends` row
/// must mirror exactly — `assert_message_send_mapping`), plus the
/// `signing_transcript_bytes` the digest covers and the server-authored
/// `outcome_bytes` returned to the sender.
#[derive(Clone, Debug)]
pub struct ApplicationSend {
    pub entry: AppendEntry,
    pub signing_transcript_bytes: Vec<u8>,
    pub outcome_bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationSendDisposition {
    Accept,
    Stale,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationSendOutcome {
    Accepted { seq: u64 },
    Stale,
}
/// Resolve an application send idempotently on `(conversation_id, message_id)`.
///
/// * FIRST resolution: apply `disposition` — `Accept` appends the
///   `applicationEntry` at a fresh seq (`append_entry`) and records an `accepted`
///   `message_sends` row bound to it; `Stale` records a `stale` tombstone row with
///   NO entry / NO seq (the explicitly-committed rejection path — it COMMITS even
///   though the business outcome is a refusal).
/// * REPLAY (a row already exists): return the STORED outcome, ignoring the
///   caller's disposition — an accepted send re-returns its original seq, a stale
///   send stays stale. A replay whose `request_digest` disagrees with the stored
///   one is a distinct message reusing the id → `MessageSendConflict`.
///
/// The two `chat.message_sends` ↔ `chat.entries` foreign keys are DEFERRED, so the
/// entry + accepted row (written here in the caller's transaction) are reconciled
/// by `assert_message_send_mapping` at COMMIT.
pub async fn resolve_application_send(
    transaction: &mut Transaction<'_, Postgres>,
    send: &ApplicationSend,
    disposition: ApplicationSendDisposition,
) -> Result<ApplicationSendOutcome, DeliveryRepositoryError> {
    let message_id = send
        .entry
        .message_id
        .ok_or(DeliveryRepositoryError::MissingMessageId)?;

    // Idempotency: a resolved send returns its durable outcome; a mismatching
    // digest under the same id is a conflict.
    let existing: Option<(String, Option<i64>, Vec<u8>)> = sqlx::query_as(
        r#"
        SELECT status, accepted_entry_seq, request_digest
          FROM chat.message_sends
         WHERE conversation_id = $1 AND message_id = $2
        "#,
    )
    .bind(send.entry.conversation_id)
    .bind(message_id)
    .fetch_optional(&mut **transaction)
    .await?;
    if let Some((status, accepted_entry_seq, request_digest)) = existing {
        if request_digest != send.entry.request_digest {
            return Err(DeliveryRepositoryError::MessageSendConflict);
        }
        return match status.as_str() {
            "accepted" => {
                let seq_i64 =
                    accepted_entry_seq.ok_or(DeliveryRepositoryError::CompareAndSetConflict)?;
                let seq = u64::try_from(seq_i64)
                    .map_err(|_| DeliveryRepositoryError::SequenceOverflow)?;
                Ok(ApplicationSendOutcome::Accepted { seq })
            }
            _ => Ok(ApplicationSendOutcome::Stale),
        };
    }

    match disposition {
        ApplicationSendDisposition::Accept => {
            let seq = append_entry(transaction, &send.entry).await?;
            insert_message_send_row(transaction, send, message_id, "accepted", Some(seq)).await?;
            Ok(ApplicationSendOutcome::Accepted { seq })
        }
        ApplicationSendDisposition::Stale => {
            insert_message_send_row(transaction, send, message_id, "stale", None).await?;
            Ok(ApplicationSendOutcome::Stale)
        }
    }
}

/// Insert the `chat.message_sends` row mirroring the send's signed envelope. Every
/// crypto column equals the `applicationEntry`'s so the deferred
/// `assert_message_send_mapping` invariant holds; `accepted_entry_seq` is the
/// allocated seq for an `accepted` row and `NULL` for a `stale` tombstone
/// (`message_sends_status_shape_check`).
async fn insert_message_send_row(
    transaction: &mut Transaction<'_, Postgres>,
    send: &ApplicationSend,
    message_id: Uuid,
    status: &str,
    accepted_entry_seq: Option<u64>,
) -> Result<(), DeliveryRepositoryError> {
    let accepted_seq_i64 = accepted_entry_seq
        .map(|seq| i64::try_from(seq).map_err(|_| DeliveryRepositoryError::SequenceOverflow))
        .transpose()?;
    sqlx::query(
        r#"
        INSERT INTO chat.message_sends(
            conversation_id, message_id, signed_request_bytes, signing_transcript_bytes,
            request_digest, signature, status, accepted_entry_seq, outcome_bytes,
            outcome_sha256, received_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        "#,
    )
    .bind(send.entry.conversation_id)
    .bind(message_id)
    .bind(&send.entry.signed_request_bytes)
    .bind(&send.signing_transcript_bytes)
    .bind(&send.entry.request_digest)
    .bind(&send.entry.signature)
    .bind(status)
    .bind(accepted_seq_i64)
    .bind(&send.outcome_bytes)
    .bind(Sha256::digest(&send.outcome_bytes).to_vec())
    .bind(send.entry.received_at)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

/// Insert one application send at an exact, expected sequence number and advance the conversation head via CAS.
pub(crate) async fn append_exact_application_entry(
    transaction: &mut Transaction<'_, Postgres>,
    send: &ApplicationSend,
    expected_seq: u64,
) -> Result<u64, DeliveryRepositoryError> {
    let message_id = send
        .entry
        .message_id
        .ok_or(DeliveryRepositoryError::MissingMessageId)?;
    let seq_i64 =
        i64::try_from(expected_seq).map_err(|_| DeliveryRepositoryError::SequenceOverflow)?;

    let head_row: Option<(Option<i64>, i64)> = sqlx::query_as(
        r#"
        SELECT current_entry_seq, next_entry_seq
          FROM chat.conversations
         WHERE conversation_id = $1
         FOR UPDATE
        "#,
    )
    .bind(send.entry.conversation_id)
    .fetch_optional(&mut **transaction)
    .await?;

    let (_current_seq, next_entry_seq) =
        head_row.ok_or(DeliveryRepositoryError::ConversationMissing)?;
    if next_entry_seq != seq_i64 {
        return Err(DeliveryRepositoryError::CompareAndSetConflict);
    }

    append_entry_at(transaction, &send.entry, expected_seq).await?;
    insert_message_send_row(transaction, send, message_id, "accepted", Some(expected_seq)).await?;

    let updated = sqlx::query(
        r#"
        UPDATE chat.conversations
           SET current_entry_seq = $1,
               next_entry_seq = $1 + 1
         WHERE conversation_id = $2
           AND next_entry_seq = $1
        "#,
    )
    .bind(seq_i64)
    .bind(send.entry.conversation_id)
    .execute(&mut **transaction)
    .await?;

    if updated.rows_affected() != 1 {
        return Err(DeliveryRepositoryError::CompareAndSetConflict);
    }

    Ok(expected_seq)
}

/// Exact compare of an existing application entry and message send row.
pub(crate) async fn compare_exact_application_entry(
    transaction: &mut Transaction<'_, Postgres>,
    send: &ApplicationSend,
    expected_seq: u64,
) -> Result<bool, DeliveryRepositoryError> {
    let message_id = send
        .entry
        .message_id
        .ok_or(DeliveryRepositoryError::MissingMessageId)?;
    let seq_i64 =
        i64::try_from(expected_seq).map_err(|_| DeliveryRepositoryError::SequenceOverflow)?;

    let entry_row: Option<(
        Uuid,
        String,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        String,
        Uuid,
        String,
        i64,
        Option<i64>,
        Option<i64>,
        Option<Uuid>,
        DateTime<Utc>,
    )> = sqlx::query_as(
        r#"
        SELECT entry_id, entry_kind, accepted_payload_bytes, accepted_payload_sha256,
               signed_request_bytes, request_digest, signature, outer_entry_fingerprint,
               actor_did, actor_device_id, actor_key_id, actor_auth_generation,
               generation, state_version, message_id, received_at
          FROM chat.entries
         WHERE conversation_id = $1 AND seq = $2
        "#,
    )
    .bind(send.entry.conversation_id)
    .bind(seq_i64)
    .fetch_optional(&mut **transaction)
    .await?;

    let Some((
        entry_id,
        entry_kind,
        accepted_payload_bytes,
        accepted_payload_sha256,
        signed_request_bytes,
        request_digest,
        signature,
        outer_entry_fingerprint,
        actor_did,
        actor_device_id,
        actor_key_id,
        actor_auth_generation,
        generation,
        state_version,
        stored_message_id,
        received_at,
    )) = entry_row
    else {
        return Ok(false);
    };

    if entry_id != send.entry.entry_id
        || entry_kind != send.entry.entry_kind
        || accepted_payload_bytes != send.entry.accepted_payload_bytes
        || accepted_payload_sha256 != send.entry.accepted_payload_sha256
        || signed_request_bytes != send.entry.signed_request_bytes
        || request_digest != send.entry.request_digest
        || signature != send.entry.signature
        || outer_entry_fingerprint != send.entry.outer_entry_fingerprint
        || actor_did != send.entry.actor_did
        || actor_device_id != send.entry.actor_device_id
        || actor_key_id != send.entry.actor_key_id
        || actor_auth_generation != send.entry.actor_auth_generation
        || generation != send.entry.generation
        || state_version != send.entry.state_version
        || stored_message_id != Some(message_id)
        || received_at != send.entry.received_at
    {
        return Ok(false);
    }

    let send_row: Option<(String, Option<i64>, Vec<u8>, Vec<u8>)> = sqlx::query_as(
        r#"
        SELECT status, accepted_entry_seq, signing_transcript_bytes, outcome_bytes
          FROM chat.message_sends
         WHERE conversation_id = $1 AND message_id = $2
        "#,
    )
    .bind(send.entry.conversation_id)
    .bind(message_id)
    .fetch_optional(&mut **transaction)
    .await?;

    let Some((status, accepted_entry_seq, signing_transcript_bytes, outcome_bytes)) = send_row
    else {
        return Ok(false);
    };

    if status != "accepted"
        || accepted_entry_seq != Some(seq_i64)
        || signing_transcript_bytes != send.signing_transcript_bytes
        || outcome_bytes != send.outcome_bytes
    {
        return Ok(false);
    }

    Ok(true)
}

// ===========================================================================
// Audience, event, and outbox write primitives.
//
// The transition executor (later tasks) composes these on top of `append_entry`
// inside one caller-owned transaction. Each primitive owns exactly one write
// shape; the sealed `chat.*` schema (kind CHECKs, primary keys, foreign keys,
// and the deferred audience/mapping/chain triggers) remains the ultimate
// authority. Timestamps are always the caller's trusted request instant `T`,
// never `NOW()`: an event's `created_at`, an outbox row's `next_attempt_at` /
// `created_at`, and a lease's expiry are all supplied by the caller.
// ===========================================================================

/// Entitlement arm for a frozen `chat.entry_recipients` control-audience row.
/// The closed set mirrors the schema's `entry_recipients_kind_check` exactly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EntryEntitlementKind {
    /// The device may fetch this signed control entry.
    Control,
    /// The device may fetch the signed closing control at an interval's
    /// `terminal_seq` after its application interval ended.
    IntervalClose,
    /// The device may fetch the signed `Terminal` control for a historical
    /// exact-device schedule when a `closeConversation` wins.
    ScheduleTerminal,
}

impl EntryEntitlementKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::IntervalClose => "intervalClose",
            Self::ScheduleTerminal => "scheduleTerminal",
        }
    }
}

/// Entitlement arm for a frozen `chat.event_recipients` row. The closed set
/// mirrors the schema's `event_recipients_kind_check` exactly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EventEntitlementKind {
    Participant,
    Leaf,
    Welcome,
    Recovery,
    HistoricalSchedule,
}

impl EventEntitlementKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Participant => "participant",
            Self::Leaf => "leaf",
            Self::Welcome => "welcome",
            Self::Recovery => "recovery",
            Self::HistoricalSchedule => "historicalSchedule",
        }
    }
}

/// Closed `chat.events.event_kind` domain. The ten variants map one-to-one to
/// the schema's `events_kind_check`; no other kind can be authored.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EventKind {
    ConversationChanged,
    ConversationClosed,
    MessageAvailable,
    WelcomeAvailable,
    WelcomeDisposition,
    ResetRequested,
    LeafRecovery,
    LeaveRequest,
    AccessEnded,
    Watermark,
}

impl EventKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::ConversationChanged => "conversationChanged",
            Self::ConversationClosed => "conversationClosed",
            Self::MessageAvailable => "messageAvailable",
            Self::WelcomeAvailable => "welcomeAvailable",
            Self::WelcomeDisposition => "welcomeDisposition",
            Self::ResetRequested => "resetRequested",
            Self::LeafRecovery => "leafRecovery",
            Self::LeaveRequest => "leaveRequest",
            Self::AccessEnded => "accessEnded",
            Self::Watermark => "watermark",
        }
    }
}

/// Closed `chat.outbox.work_kind` domain, mirroring `outbox_kind_check`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OutboxWorkKind {
    Stream,
    Notification,
    Recovery,
}

impl OutboxWorkKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Stream => "stream",
            Self::Notification => "notification",
            Self::Recovery => "recovery",
        }
    }
}

/// One frozen control-entry audience row: the exact device entitled to fetch a
/// specific control entry, and on which arm. The `(conversation, seq)` the row
/// addresses is supplied to `insert_entry_recipients`; each row repeats only
/// the recipient tuple and its arm.
#[derive(Clone, Debug)]
pub(crate) struct EntryRecipient {
    pub(crate) user_did: String,
    pub(crate) device_id: Uuid,
    pub(crate) entitlement_kind: EntryEntitlementKind,
}

/// One `chat.events` row to append. `event_position` is deliberately *not* a
/// field: it is the DB-allocated identity returned by `append_event`.
/// `payload_sha256` is likewise absent — it is computed in Rust from
/// `payload_bytes` and independently re-verified by the DB CHECK.
#[derive(Clone, Debug)]
pub(crate) struct NewEvent {
    pub(crate) event_id: Uuid,
    pub(crate) event_kind: EventKind,
    pub(crate) payload_bytes: Vec<u8>,
    /// Caller-supplied trusted instant `T`; never `NOW()`.
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) protocol_instance_id: Uuid,
}

/// One frozen `chat.event_recipients` row. `audience_predecessor_position`
/// chains a single device's audience rows across events: `None` for the
/// device's first event, otherwise the device's immediately preceding
/// `event_position`. The schema's deferred self-referential FK and chain
/// trigger validate the chain at commit.
#[derive(Clone, Debug)]
pub(crate) struct EventRecipient {
    pub(crate) user_did: String,
    pub(crate) device_id: Uuid,
    pub(crate) entitlement_kind: EventEntitlementKind,
    pub(crate) audience_predecessor_position: Option<i64>,
}

/// One row claimed by `claim_outbox_batch`. The worker uses the identity plus
/// its lease expiry to deliver the work and later terminalize it via
/// `mark_outbox_delivered`.
#[derive(Clone, Debug, sqlx::FromRow)]
pub(crate) struct ClaimedOutboxWork {
    pub(crate) outbox_id: Uuid,
    pub(crate) event_position: i64,
    pub(crate) work_kind: String,
    pub(crate) attempt_count: i64,
    pub(crate) lease_expires_at: DateTime<Utc>,
}

/// True when `rows` are strictly increasing by the canonical audience key
/// `(user-DID UTF-8 bytes, device UUID raw bytes)`. Equal or descending
/// adjacent keys (i.e. duplicates or out-of-order input) return false. An empty
/// or single-element input is trivially ordered.
fn recipients_are_canonically_ordered<'a, I>(rows: I) -> bool
where
    I: IntoIterator<Item = (&'a str, Uuid)>,
{
    let mut previous: Option<(&'a str, Uuid)> = None;
    for (user_did, device_id) in rows {
        if let Some((prev_did, prev_device)) = previous {
            let ordering = prev_did
                .as_bytes()
                .cmp(user_did.as_bytes())
                .then_with(|| prev_device.as_bytes().cmp(device_id.as_bytes()));
            if ordering != std::cmp::Ordering::Less {
                return false;
            }
        }
        previous = Some((user_did, device_id));
    }
    true
}

/// Freeze the immutable control-entry audience for the entry at
/// `(conversation_id, seq)`: one row per exact device entitled to fetch it.
///
/// Rows are frozen and immutable; the `(conversation_id, seq, user_did,
/// device_id)` primary key rejects duplicates and the non-deferred foreign keys
/// require the addressed entry and each device to already exist. The audience
/// must be non-empty (a control entry with no recipients is a caller bug) and
/// in canonical `(DID, device)` order with no duplicates — the primitive
/// enforces caller order rather than sorting. Semantic coherence of the
/// `intervalClose` / `scheduleTerminal` arms (their bound application interval
/// or terminal proof) is enforced by the schema's deferred
/// `entry_recipients_mapping_deferred` guard, which the caller satisfies by
/// composing those rows in the same transaction.
pub(crate) async fn insert_entry_recipients(
    transaction: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    seq: u64,
    recipients: &[EntryRecipient],
) -> Result<(), DeliveryRepositoryError> {
    if recipients.is_empty() {
        return Err(DeliveryRepositoryError::EmptyRecipients);
    }
    if !recipients_are_canonically_ordered(
        recipients
            .iter()
            .map(|recipient| (recipient.user_did.as_str(), recipient.device_id)),
    ) {
        return Err(DeliveryRepositoryError::NonCanonicalRecipients);
    }
    let seq = i64::try_from(seq).map_err(|_| DeliveryRepositoryError::SequenceOverflow)?;

    for recipient in recipients {
        sqlx::query(
            r#"
            INSERT INTO chat.entry_recipients(
                conversation_id, seq, user_did, device_id, entitlement_kind
            ) VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(conversation_id)
        .bind(seq)
        .bind(&recipient.user_did)
        .bind(recipient.device_id)
        .bind(recipient.entitlement_kind.as_str())
        .execute(&mut **transaction)
        .await?;
    }
    Ok(())
}

/// Append one `chat.events` row and return its DB-allocated `event_position`.
///
/// `event_position` is a `GENERATED ALWAYS AS IDENTITY` column, so the database
/// is the sole allocator and positions are globally increasing (gaps allowed).
/// `payload_sha256` is computed here from `payload_bytes`; the DB's
/// `events_payload_hash_check` re-derives it independently, so a hash that does
/// not match its payload is impossible through this primitive.
pub(crate) async fn append_event(
    transaction: &mut Transaction<'_, Postgres>,
    event: &NewEvent,
) -> Result<i64, DeliveryRepositoryError> {
    let payload_sha256 = Sha256::digest(&event.payload_bytes).to_vec();

    let event_position: i64 = sqlx::query_scalar(
        r#"
        INSERT INTO chat.events(
            event_id, event_kind, payload_bytes, payload_sha256,
            created_at, protocol_instance_id
        ) VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING event_position
        "#,
    )
    .bind(event.event_id)
    .bind(event.event_kind.as_str())
    .bind(&event.payload_bytes)
    .bind(&payload_sha256)
    .bind(event.created_at)
    .bind(event.protocol_instance_id)
    .fetch_one(&mut **transaction)
    .await?;

    Ok(event_position)
}

/// Freeze the immutable audience for the event at `event_position`: one row per
/// exact device, with its entitlement arm and predecessor link.
///
/// An empty audience is a no-op (an event may legitimately fan out to no
/// per-device recipient); a non-empty audience must be in canonical
/// `(DID, device)` order with no duplicates. Each row's
/// `audience_predecessor_position` chains the device's audience across events;
/// the schema's deferred self-FK and chain trigger verify the chain at commit,
/// while the immediate `< event_position` CHECK rejects a non-earlier
/// predecessor at insert.
pub(crate) async fn insert_event_recipients(
    transaction: &mut Transaction<'_, Postgres>,
    event_position: i64,
    recipients: &[EventRecipient],
) -> Result<(), DeliveryRepositoryError> {
    if recipients.is_empty() {
        return Ok(());
    }
    if !recipients_are_canonically_ordered(
        recipients
            .iter()
            .map(|recipient| (recipient.user_did.as_str(), recipient.device_id)),
    ) {
        return Err(DeliveryRepositoryError::NonCanonicalRecipients);
    }

    for recipient in recipients {
        sqlx::query(
            r#"
            INSERT INTO chat.event_recipients(
                event_position, user_did, device_id,
                entitlement_kind, audience_predecessor_position
            ) VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(event_position)
        .bind(&recipient.user_did)
        .bind(recipient.device_id)
        .bind(recipient.entitlement_kind.as_str())
        .bind(recipient.audience_predecessor_position)
        .execute(&mut **transaction)
        .await?;
    }
    Ok(())
}

/// Enqueue one durable `chat.outbox` work row for the event at
/// `event_position`, starting `pending` with zero attempts.
///
/// `at` is the caller's trusted instant `T`: it becomes both `next_attempt_at`
/// (when the row first becomes claimable) and `created_at`. The
/// `outbox_event_work_uq` uniqueness on `(event_position, work_kind)` prevents a
/// double enqueue for the same kind of work on the same event.
pub(crate) async fn enqueue_outbox(
    transaction: &mut Transaction<'_, Postgres>,
    outbox_id: Uuid,
    event_position: i64,
    work_kind: OutboxWorkKind,
    at: DateTime<Utc>,
) -> Result<(), DeliveryRepositoryError> {
    sqlx::query(
        r#"
        INSERT INTO chat.outbox(
            outbox_id, event_position, work_kind, status,
            attempt_count, next_attempt_at, created_at
        ) VALUES ($1, $2, $3, 'pending', 0, $4, $4)
        "#,
    )
    .bind(outbox_id)
    .bind(event_position)
    .bind(work_kind.as_str())
    .bind(at)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

/// Claim up to `limit` outbox rows for `lease_owner`, in global
/// `event_position` order, and lease them until `lease_expires_at`.
///
/// A row is claimable when it is `pending` and due (`next_attempt_at <= now`)
/// or `leased` with an expired lease (`lease_expires_at <= now`), where `now` is
/// the caller-supplied instant. `FOR UPDATE SKIP LOCKED` inside the ordering CTE
/// makes concurrent workers partition the queue: a row another worker is
/// claiming is skipped, never blocked on and never double-claimed. Claimed rows
/// are returned in ascending `event_position` order.
pub(crate) async fn claim_outbox_batch(
    transaction: &mut Transaction<'_, Postgres>,
    lease_owner: Uuid,
    now: DateTime<Utc>,
    lease_expires_at: DateTime<Utc>,
    limit: i64,
) -> Result<Vec<ClaimedOutboxWork>, DeliveryRepositoryError> {
    let mut claimed: Vec<ClaimedOutboxWork> = sqlx::query_as(
        r#"
        WITH claimable AS (
            SELECT outbox_id
              FROM chat.outbox
             WHERE (status = 'pending' AND next_attempt_at <= $2)
                OR (status = 'leased' AND lease_expires_at <= $2)
             ORDER BY event_position
             FOR UPDATE SKIP LOCKED
             LIMIT $4
        )
        UPDATE chat.outbox AS work
           SET status = 'leased',
               lease_owner = $1,
               lease_expires_at = $3
          FROM claimable
         WHERE work.outbox_id = claimable.outbox_id
        RETURNING work.outbox_id, work.event_position, work.work_kind,
                  work.attempt_count, work.lease_expires_at
        "#,
    )
    .bind(lease_owner)
    .bind(now)
    .bind(lease_expires_at)
    .bind(limit)
    .fetch_all(&mut **transaction)
    .await?;

    // The CTE claims in event_position order, but `UPDATE ... RETURNING` does
    // not preserve it; sort so callers observe the global queue order.
    claimed.sort_by_key(|work| work.event_position);
    Ok(claimed)
}

/// Terminalize a leased outbox row as `delivered`, but only for its exact
/// current lease owner.
///
/// This is an owner-scoped compare-and-set: the update matches only a row that
/// is still `leased` by `lease_owner`. A stale caller (the lease was reclaimed
/// by another worker, or the row already terminalized) matches zero rows and is
/// reported as `OutboxLeaseMismatch` rather than silently succeeding.
pub(crate) async fn mark_outbox_delivered(
    transaction: &mut Transaction<'_, Postgres>,
    outbox_id: Uuid,
    lease_owner: Uuid,
    delivered_at: DateTime<Utc>,
) -> Result<(), DeliveryRepositoryError> {
    let result = sqlx::query(
        r#"
        UPDATE chat.outbox
           SET status = 'delivered',
               delivered_at = $3
         WHERE outbox_id = $1
           AND status = 'leased'
           AND lease_owner = $2
        "#,
    )
    .bind(outbox_id)
    .bind(lease_owner)
    .bind(delivered_at)
    .execute(&mut **transaction)
    .await?;

    if result.rows_affected() != 1 {
        return Err(DeliveryRepositoryError::OutboxLeaseMismatch);
    }
    Ok(())
}

// ===========================================================================
// Migration-2 state-family row writers (delivery migration
// `20260722000002_chat_protocol_delivery.sql`).
//
// These are the dumb, exact SQL layer for the migration-2 side families the
// transition executor (task E2b, `state_machine.rs`) composes on top of
// `append_entry` + the audience/event/outbox primitives above, inside one
// caller-owned transaction. They mirror `repository::transition` exactly:
// param structs derived column-for-column from the sealed DDL, closed enums for
// the terminal / kind shapes the schema's CHECKs allow, and CAS via
// `rows_affected() == 1` (any other count is a typed `CompareAndSetConflict`,
// never a silent no-op or blind overwrite). Nothing here re-derives, validates,
// or "fixes up" a value: the caller hands down the exact bytes and the database's
// own CHECK / FK / UNIQUE / partial-index constraints and BEFORE-UPDATE
// immutability + lifecycle-monotonic triggers remain the ultimate authority.
//
// Every writer is transaction-scoped (`&mut Transaction`); it never commits and
// never opens its own transaction. The migration's DEFERRED cross-table
// coherence triggers (`assert_member_interval_mapping`,
// `assert_welcome_disposition_cas`, `assert_recovery_work_integrity`, the
// terminal-schedule guards, and the deferred provenance FKs into
// `chat.entries`/`chat.transitions`/`chat.generation_states`) fire only at
// COMMIT; building the fully coherent transition+entry+state graph they enforce
// is the composing executor's job, not these unit writers'.
// ===========================================================================

// ---------------------------------------------------------------------------
// Family A — chat.application_intervals (per-device exact-visibility periods).
// ---------------------------------------------------------------------------

/// Opening kind of an application interval. Mirrors
/// `application_intervals_opening_kind_check` exactly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IntervalOpeningKind {
    Creation,
    Add,
    Reset,
}

impl IntervalOpeningKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Creation => "creation",
            Self::Add => "add",
            Self::Reset => "reset",
        }
    }
}

/// Closing kind of a finite application interval. Mirrors
/// `application_intervals_close_kind_check` exactly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IntervalCloseKind {
    Remove,
    Replace,
    Reset,
    Terminal,
}

impl IntervalCloseKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Remove => "remove",
            Self::Replace => "replace",
            Self::Reset => "reset",
            Self::Terminal => "terminal",
        }
    }
}

/// One new **open** application interval, carried column-for-column. The insert
/// always writes the full five-field opening binding (`start_seq`, `opening_kind`,
/// `opening_transition_id`, 32-byte `opening_outer_entry_fingerprint`, and the
/// opening group-context coordinate) plus the recipient device + opening leaf,
/// and leaves every closing column NULL (an interval is never born finite). The
/// `membership_interval_id = opening_transition_id` identity, the 32-byte length
/// CHECKs, and the opening / leaf-opening unique indexes remain the DB's
/// authority; this helper writes exactly what the plan says.
#[derive(Clone, Debug)]
pub(crate) struct NewApplicationInterval {
    pub(crate) membership_interval_id: Uuid,
    pub(crate) conversation_id: Uuid,
    pub(crate) generation: i64,
    pub(crate) recipient_did: String,
    pub(crate) recipient_device_id: Uuid,
    pub(crate) start_seq: i64,
    pub(crate) opening_kind: IntervalOpeningKind,
    pub(crate) opening_transition_id: Uuid,
    pub(crate) opening_outer_entry_fingerprint: Vec<u8>,
    pub(crate) opening_state_version: i64,
    pub(crate) opening_group_id: Vec<u8>,
    pub(crate) opening_epoch: i64,
    pub(crate) opening_group_context_hash: Vec<u8>,
    pub(crate) opening_confirmation_tag: Vec<u8>,
    pub(crate) opening_leaf_period_id: Uuid,
    pub(crate) created_at: DateTime<Utc>,
}

/// Insert one new open application interval (all closing fields NULL).
///
/// The `application_intervals_opening_uq` / `_leaf_opening_uq` unique indexes and
/// the `membership_interval_id` primary key reject a re-opened duplicate; the
/// `application_intervals_close_shape_check` (open arm) and the opening-context
/// length CHECKs reject an illegal shape. Written verbatim.
pub(crate) async fn insert_application_interval(
    transaction: &mut Transaction<'_, Postgres>,
    interval: &NewApplicationInterval,
) -> Result<(), DeliveryRepositoryError> {
    sqlx::query(
        r#"
        INSERT INTO chat.application_intervals(
            membership_interval_id, conversation_id, generation, recipient_did,
            recipient_device_id, start_seq, opening_kind, opening_transition_id,
            opening_outer_entry_fingerprint, opening_state_version, opening_group_id,
            opening_epoch, opening_group_context_hash, opening_confirmation_tag,
            opening_leaf_period_id, terminal_seq, closing_state_version,
            closing_transition_id, closing_outer_entry_fingerprint, closing_kind,
            closing_leaf_period_id, removed_at, created_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
            NULL, NULL, NULL, NULL, NULL, NULL, NULL, $16
        )
        "#,
    )
    .bind(interval.membership_interval_id)
    .bind(interval.conversation_id)
    .bind(interval.generation)
    .bind(&interval.recipient_did)
    .bind(interval.recipient_device_id)
    .bind(interval.start_seq)
    .bind(interval.opening_kind.as_str())
    .bind(interval.opening_transition_id)
    .bind(&interval.opening_outer_entry_fingerprint)
    .bind(interval.opening_state_version)
    .bind(&interval.opening_group_id)
    .bind(interval.opening_epoch)
    .bind(&interval.opening_group_context_hash)
    .bind(&interval.opening_confirmation_tag)
    .bind(interval.opening_leaf_period_id)
    .bind(interval.created_at)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

/// The finite close applied to an open application interval. Every closing column
/// is present together (`application_intervals_close_shape_check` all-present arm);
/// there is no per-arm column variation, so the closing kind is a plain enum and
/// all other closing values are carried verbatim. The DB requires
/// `terminal_seq > start_seq` and a 32-byte `closing_outer_entry_fingerprint`.
#[derive(Clone, Debug)]
pub(crate) struct ApplicationIntervalClose {
    pub(crate) membership_interval_id: Uuid,
    pub(crate) terminal_seq: i64,
    pub(crate) closing_state_version: i64,
    pub(crate) closing_transition_id: Uuid,
    pub(crate) closing_outer_entry_fingerprint: Vec<u8>,
    pub(crate) closing_kind: IntervalCloseKind,
    pub(crate) closing_leaf_period_id: Uuid,
    pub(crate) removed_at: DateTime<Utc>,
}

/// Compare-and-set an open application interval to finite, writing all seven
/// closing columns at once. Matches only a still-open interval (`terminal_seq IS
/// NULL`); a second close, a wrong id, or a drifted (already-closed) row matches
/// nothing and is a typed conflict. A closed interval is terminal — the
/// `application_intervals_lifecycle_monotonic` trigger also rejects any rewrite of
/// a finite row, and the `application_intervals_identity_immutable` trigger allows
/// only these seven closing columns to change.
pub(crate) async fn close_application_interval(
    transaction: &mut Transaction<'_, Postgres>,
    close: &ApplicationIntervalClose,
) -> Result<(), DeliveryRepositoryError> {
    let result = sqlx::query(
        r#"
        UPDATE chat.application_intervals
           SET terminal_seq = $2,
               closing_state_version = $3,
               closing_transition_id = $4,
               closing_outer_entry_fingerprint = $5,
               closing_kind = $6,
               closing_leaf_period_id = $7,
               removed_at = $8
         WHERE membership_interval_id = $1
           AND terminal_seq IS NULL
        "#,
    )
    .bind(close.membership_interval_id)
    .bind(close.terminal_seq)
    .bind(close.closing_state_version)
    .bind(close.closing_transition_id)
    .bind(&close.closing_outer_entry_fingerprint)
    .bind(close.closing_kind.as_str())
    .bind(close.closing_leaf_period_id)
    .bind(close.removed_at)
    .execute(&mut **transaction)
    .await?;

    if result.rows_affected() != 1 {
        return Err(DeliveryRepositoryError::CompareAndSetConflict);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Family B — chat.application_schedule_terminal_proofs (immutable per-device
// historical-schedule terminal proofs).
// ---------------------------------------------------------------------------

/// One immutable schedule terminal proof, carried column-for-column. The
/// `(conversation_id, recipient_did, recipient_device_id)` primary key admits one
/// proof per exact device per conversation; a duplicate insert violates the PK and
/// propagates verbatim (mirroring the spine-PK convention in
/// `repository::transition`). The row is fully immutable once written.
#[derive(Clone, Debug)]
pub(crate) struct NewScheduleTerminalProof {
    pub(crate) conversation_id: Uuid,
    pub(crate) recipient_did: String,
    pub(crate) recipient_device_id: Uuid,
    pub(crate) terminal_seq: i64,
    pub(crate) transition_id: Uuid,
    pub(crate) outer_entry_fingerprint: Vec<u8>,
    pub(crate) received_at: DateTime<Utc>,
}

pub(crate) async fn insert_schedule_terminal_proof(
    transaction: &mut Transaction<'_, Postgres>,
    proof: &NewScheduleTerminalProof,
) -> Result<(), DeliveryRepositoryError> {
    sqlx::query(
        r#"
        INSERT INTO chat.application_schedule_terminal_proofs(
            conversation_id, recipient_did, recipient_device_id, terminal_seq,
            transition_id, outer_entry_fingerprint, received_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
    )
    .bind(proof.conversation_id)
    .bind(&proof.recipient_did)
    .bind(proof.recipient_device_id)
    .bind(proof.terminal_seq)
    .bind(proof.transition_id)
    .bind(&proof.outer_entry_fingerprint)
    .bind(proof.received_at)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Family C — chat.welcome_bundles (immutable per-Add-commit Welcome wrapper).
// ---------------------------------------------------------------------------

/// One immutable Welcome bundle, carried column-for-column: the wrapper bytes and
/// their hash, the producing Add transition + entry coordinate, and the bound
/// generation-state coordinate. The caller supplies `wrapper_sha256`; the DB's
/// `= digest(wrapper_bytes, 'sha256')` CHECK re-verifies it. `transition_id` is
/// UNIQUE (one bundle per Add commit). Written verbatim; the row is immutable.
#[derive(Clone, Debug)]
pub(crate) struct NewWelcomeBundle {
    pub(crate) welcome_id: Uuid,
    pub(crate) conversation_id: Uuid,
    pub(crate) transition_id: Uuid,
    pub(crate) entry_seq: i64,
    pub(crate) generation: i64,
    pub(crate) state_version: i64,
    pub(crate) group_id: Vec<u8>,
    pub(crate) epoch: i64,
    pub(crate) group_context_hash: Vec<u8>,
    pub(crate) confirmation_tag: Vec<u8>,
    pub(crate) wrapper_bytes: Vec<u8>,
    pub(crate) wrapper_sha256: Vec<u8>,
    pub(crate) created_at: DateTime<Utc>,
}

pub(crate) async fn insert_welcome_bundle(
    transaction: &mut Transaction<'_, Postgres>,
    bundle: &NewWelcomeBundle,
) -> Result<(), DeliveryRepositoryError> {
    sqlx::query(
        r#"
        INSERT INTO chat.welcome_bundles(
            welcome_id, conversation_id, transition_id, entry_seq, generation,
            state_version, group_id, epoch, group_context_hash, confirmation_tag,
            wrapper_bytes, wrapper_sha256, created_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
        )
        "#,
    )
    .bind(bundle.welcome_id)
    .bind(bundle.conversation_id)
    .bind(bundle.transition_id)
    .bind(bundle.entry_seq)
    .bind(bundle.generation)
    .bind(bundle.state_version)
    .bind(&bundle.group_id)
    .bind(bundle.epoch)
    .bind(&bundle.group_context_hash)
    .bind(&bundle.confirmation_tag)
    .bind(&bundle.wrapper_bytes)
    .bind(&bundle.wrapper_sha256)
    .bind(bundle.created_at)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Family D — chat.welcome_deliveries (the single pending recipient tuple per
// Welcome, keyed by welcome_id).
// ---------------------------------------------------------------------------

/// One new **pending** Welcome delivery, carried column-for-column: the canonical
/// Add-order recipient tuple, the open leaf-recovery request + reservation
/// provenance (`recovery_request_id`), the consumed package ref, and `expires_at`
/// (which the DB requires to equal the consumed KeyPackage's `not_after` via the
/// composite package-identity FK). The insert always writes `status = 'pending'`
/// with NULL `terminal_at`; the reservation-identity and package-identity FKs and
/// the `welcome_deliveries_terminal_shape_check` remain the DB's authority.
#[derive(Clone, Debug)]
pub(crate) struct NewWelcomeDelivery {
    pub(crate) welcome_id: Uuid,
    pub(crate) recipient_did: String,
    pub(crate) recipient_device_id: Uuid,
    pub(crate) recovery_request_id: Uuid,
    pub(crate) key_package_ref: Vec<u8>,
    pub(crate) expires_at: DateTime<Utc>,
}

pub(crate) async fn insert_welcome_delivery(
    transaction: &mut Transaction<'_, Postgres>,
    delivery: &NewWelcomeDelivery,
) -> Result<(), DeliveryRepositoryError> {
    sqlx::query(
        r#"
        INSERT INTO chat.welcome_deliveries(
            welcome_id, recipient_did, recipient_device_id, recovery_request_id,
            key_package_ref, expires_at, status, terminal_at
        ) VALUES ($1, $2, $3, $4, $5, $6, 'pending', NULL)
        "#,
    )
    .bind(delivery.welcome_id)
    .bind(&delivery.recipient_did)
    .bind(delivery.recipient_device_id)
    .bind(delivery.recovery_request_id)
    .bind(&delivery.key_package_ref)
    .bind(delivery.expires_at)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Family E — chat.welcome_dispositions + the delivery-status terminal race.
// ---------------------------------------------------------------------------

/// Closed rejection reason for a client-authored Welcome rejection. Mirrors
/// `welcome_dispositions_reason_check` exactly (present iff `winner_kind =
/// 'rejected'`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WelcomeRejectionReason {
    NoMatchingKeyPackage,
    InvalidWelcome,
    UnsupportedCipherSuite,
    CoordinateMismatch,
    LocalStateConflict,
}

impl WelcomeRejectionReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::NoMatchingKeyPackage => "noMatchingKeyPackage",
            Self::InvalidWelcome => "invalidWelcome",
            Self::UnsupportedCipherSuite => "unsupportedCipherSuite",
            Self::CoordinateMismatch => "coordinateMismatch",
            Self::LocalStateConflict => "localStateConflict",
        }
    }
}

/// The signed client authorization block a client-authored Welcome terminalization
/// carries (`acknowledged` / `rejected` arms of
/// `welcome_dispositions_signature_shape_check`). The DB requires
/// `request_digest = digest(signing_transcript_bytes, 'sha256')`, a 32-byte digest,
/// and a 64-byte signature; the caller supplies them verbatim.
#[derive(Clone, Debug)]
pub(crate) struct WelcomeClientAuthorization {
    pub(crate) signed_request_bytes: Vec<u8>,
    pub(crate) signing_transcript_bytes: Vec<u8>,
    pub(crate) request_digest: Vec<u8>,
    pub(crate) signature: Vec<u8>,
}

/// The exact terminal disposition a pending Welcome delivery takes. Each arm
/// determines BOTH the delivery successor status AND the disposition `winner_kind`
/// (they are required equal by the schema) AND the disposition columns that arm
/// carries, per `welcome_dispositions_signature_shape_check` /
/// `welcome_dispositions_reason_check`:
/// * `Acknowledged` / `Rejected` bind the client authorization block (and
///   `Rejected` also a closed rejection reason);
/// * `Expired` / both supersession arms are server-authored — no signature block,
///   no reason. Each supersession arm carries its exact durable terminal source.
#[derive(Clone, Debug)]
pub(crate) enum WelcomeDisposition {
    Acknowledged {
        authorization: WelcomeClientAuthorization,
    },
    Rejected {
        authorization: WelcomeClientAuthorization,
        reason: WelcomeRejectionReason,
    },
    Expired,
    SupersededByTransition {
        terminal_transition_id: Uuid,
    },
    SupersededByRevocation {
        terminal_revocation_id: Uuid,
    },
}

impl WelcomeDisposition {
    /// The winner kind, which is also the delivery's successor status. Mirrors
    /// `welcome_dispositions_winner_check` / `welcome_deliveries_status_check`.
    fn winner_kind(&self) -> &'static str {
        match self {
            Self::Acknowledged { .. } => "acknowledged",
            Self::Rejected { .. } => "rejected",
            Self::Expired => "expired",
            Self::SupersededByTransition { .. } | Self::SupersededByRevocation { .. } => {
                "superseded"
            }
        }
    }

    fn authorization(&self) -> Option<&WelcomeClientAuthorization> {
        match self {
            Self::Acknowledged { authorization } | Self::Rejected { authorization, .. } => {
                Some(authorization)
            }
            Self::Expired
            | Self::SupersededByTransition { .. }
            | Self::SupersededByRevocation { .. } => None,
        }
    }

    fn rejection_reason(&self) -> Option<&'static str> {
        match self {
            Self::Rejected { reason, .. } => Some(reason.as_str()),
            Self::Acknowledged { .. }
            | Self::Expired
            | Self::SupersededByTransition { .. }
            | Self::SupersededByRevocation { .. } => None,
        }
    }

    fn terminal_transition_id(&self) -> Option<Uuid> {
        match self {
            Self::SupersededByTransition {
                terminal_transition_id,
            } => Some(*terminal_transition_id),
            _ => None,
        }
    }

    fn terminal_revocation_id(&self) -> Option<Uuid> {
        match self {
            Self::SupersededByRevocation {
                terminal_revocation_id,
            } => Some(*terminal_revocation_id),
            _ => None,
        }
    }
}

/// Canonical server-owned payload for every Welcome terminal event. Callers
/// supply neither arbitrary bytes nor extra fields.
pub(crate) fn canonical_welcome_disposition_event_payload(
    welcome_id: Uuid,
    status: &str,
) -> Vec<u8> {
    // `status` is selected exclusively from `WelcomeDisposition::winner_kind`;
    // UUID's hyphenated lowercase display contains no JSON metacharacters.
    // Spell the repository-owned projection literally so its field order and
    // whitespace are protocol constants rather than incidental serde map order.
    format!(
        r#"{{"$type":"blue.catbird.chat.defs#welcomeDispositionEvent","status":"{status}","welcomeId":"{}"}}"#,
        welcome_id.hyphenated()
    )
    .into_bytes()
}

/// Canonical server-owned payload announcing a newly available Welcome.
pub(crate) fn canonical_welcome_available_event_payload(
    welcome_id: Uuid,
    conversation_id: Uuid,
) -> Vec<u8> {
    format!(
        r#"{{"$type":"blue.catbird.chat.defs#welcomeAvailableEvent","welcomeId":"{}","conversationId":"{}"}}"#,
        welcome_id.hyphenated(),
        conversation_id.hyphenated(),
    )
    .into_bytes()
}

/// Closed Recovery status vocabulary from
/// `blue.catbird.chat.defs#leafRecoveryStatus`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LeafRecoveryEventStatus {
    Open,
    Fulfilled,
    Cancelled,
    Expired,
    Superseded,
}

impl LeafRecoveryEventStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Fulfilled => "fulfilled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Superseded => "superseded",
        }
    }
}

/// Canonical server-owned payload for Recovery lifecycle events. `status` is
/// a closed lexicon value selected by the sealed state-machine edge.
pub(crate) fn canonical_leaf_recovery_event_payload(
    recovery_request_id: Uuid,
    conversation_id: Uuid,
    status: LeafRecoveryEventStatus,
) -> Vec<u8> {
    format!(
        r#"{{"$type":"blue.catbird.chat.defs#leafRecoveryEvent","recoveryRequestId":"{}","conversationId":"{}","status":"{}"}}"#,
        recovery_request_id.hyphenated(),
        conversation_id.hyphenated(),
        status.as_str(),
    )
    .into_bytes()
}

#[derive(sqlx::FromRow)]
struct PendingWelcomeTerminalPreflightRow {
    welcome_id: Uuid,
    conversation_id: Uuid,
    entry_seq: i64,
    generation: i64,
    state_version: i64,
    group_id: Vec<u8>,
    epoch: i64,
    group_context_hash: Vec<u8>,
    confirmation_tag: Vec<u8>,
    wrapper_bytes: Vec<u8>,
    wrapper_sha256: Vec<u8>,
    recipient_did: String,
    recipient_device_id: Uuid,
    recovery_request_id: Uuid,
    key_package_ref: Vec<u8>,
    expires_at: DateTime<Utc>,
    status: String,
}

/// Lock and reverify the exact pending Welcome row before any terminal graph
/// writer runs. The later `UPDATE ... WHERE status='pending'` remains the
/// definitive CAS; this preflight closes the earlier prefix window by ensuring
/// a stale/foreign/losing authority cannot append its event or outbox first.
pub(crate) async fn preflight_pending_welcome_terminal_cas(
    transaction: &mut Transaction<'_, Postgres>,
    binding: &crate::chat_protocol::state_machine::WelcomeCasBinding,
    disposition: &WelcomeDisposition,
    terminal_at: DateTime<Utc>,
) -> Result<(), DeliveryRepositoryError> {
    use crate::chat_protocol::snapshot::PublicGroupSnapshotLifecycle;
    use crate::chat_protocol::state_machine::WelcomeStatus;

    let winner_kind = disposition.winner_kind();
    let expected_successor = match winner_kind {
        "acknowledged" => WelcomeStatus::Acknowledged,
        "rejected" => WelcomeStatus::Rejected,
        "expired" => WelcomeStatus::Expired,
        _ => return Err(DeliveryRepositoryError::InvalidTerminalAuthority),
    };
    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await?;
    let recipient_did = std::str::from_utf8(binding.recipient().principal().as_bytes())
        .map_err(|_| DeliveryRepositoryError::InvalidTerminalAuthority)?;
    let expires_at = DateTime::<Utc>::from_timestamp_millis(binding.expires_at().unix_millis())
        .ok_or(DeliveryRepositoryError::InvalidTerminalAuthority)?;
    if !binding.verify_seal()
        || transaction_id != binding.transaction_id()
        || binding.expected_status() != WelcomeStatus::Pending
        || binding.successor_status() != expected_successor
        || binding.coordinate().lifecycle() != PublicGroupSnapshotLifecycle::Active
        || (winner_kind == "expired" && terminal_at != expires_at)
        || (winner_kind != "expired"
            && (terminal_at.timestamp_millis() != binding.locked_at().unix_millis()
                || terminal_at >= expires_at))
    {
        return Err(DeliveryRepositoryError::InvalidTerminalAuthority);
    }
    let transition_seq = i64::try_from(binding.transition_seq())
        .map_err(|_| DeliveryRepositoryError::InvalidTerminalAuthority)?;
    let generation = i64::try_from(binding.coordinate().generation())
        .map_err(|_| DeliveryRepositoryError::InvalidTerminalAuthority)?;
    let state_version = i64::try_from(binding.coordinate().state_version())
        .map_err(|_| DeliveryRepositoryError::InvalidTerminalAuthority)?;
    let epoch = i64::try_from(binding.coordinate().epoch())
        .map_err(|_| DeliveryRepositoryError::InvalidTerminalAuthority)?;
    let welcome_id = Uuid::from_bytes(*binding.welcome_id());

    let row: Option<PendingWelcomeTerminalPreflightRow> = sqlx::query_as(
        r#"
        SELECT
            bundle.welcome_id,
            bundle.conversation_id,
            bundle.entry_seq,
            bundle.generation,
            bundle.state_version,
            bundle.group_id,
            bundle.epoch,
            bundle.group_context_hash,
            bundle.confirmation_tag,
            bundle.wrapper_bytes,
            bundle.wrapper_sha256,
            delivery.recipient_did,
            delivery.recipient_device_id,
            delivery.recovery_request_id,
            delivery.key_package_ref,
            delivery.expires_at,
            delivery.status
          FROM chat.welcome_bundles AS bundle
          JOIN chat.welcome_deliveries AS delivery USING(welcome_id)
         WHERE bundle.welcome_id=$1
         FOR UPDATE OF delivery
        "#,
    )
    .bind(welcome_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(row) = row else {
        return Err(DeliveryRepositoryError::CompareAndSetConflict);
    };
    if row.status != "pending" {
        return Err(DeliveryRepositoryError::CompareAndSetConflict);
    }
    if row.welcome_id != welcome_id
        || row.conversation_id != Uuid::from_bytes(*binding.conversation_id())
        || row.entry_seq != transition_seq
        || row.generation != generation
        || row.state_version != state_version
        || row.group_id != binding.coordinate().group_id()
        || row.epoch != epoch
        || row.group_context_hash != binding.coordinate().group_context_hash()
        || row.confirmation_tag != binding.coordinate().confirmation_tag()
        || row.wrapper_sha256 != binding.opaque_welcome_sha256()
        || <[u8; 32]>::from(Sha256::digest(&row.wrapper_bytes)) != *binding.opaque_welcome_sha256()
        || row.recipient_did != recipient_did
        || row.recipient_device_id != Uuid::from_bytes(*binding.recipient().device_id())
        || row.recovery_request_id != Uuid::from_bytes(*binding.recovery_request_id())
        || row.key_package_ref != binding.key_package_ref()
        || row.expires_at != expires_at
    {
        return Err(DeliveryRepositoryError::InvalidTerminalAuthority);
    }
    Ok(())
}

/// Terminalize a pending Welcome delivery: the terminal race. In one call this
/// compare-and-sets the delivery's status `pending -> winner_kind` (the immutable
/// identity trigger allows only `status` + `terminal_at` to change, and the
/// lifecycle-monotonic trigger requires the row to be pending), AND — only if the
/// CAS wins — inserts the single immutable `chat.welcome_dispositions` row for the
/// same `welcome_id` (its `PRIMARY KEY (welcome_id)` enforces one disposition per
/// delivery). A loser CAS-misses and returns `CompareAndSetConflict` before any
/// disposition is written, so the disposition row count stays exactly one.
///
/// `terminal_at` is written to both the delivery and the disposition (the schema's
/// deferred `assert_welcome_disposition_cas` requires them equal at COMMIT), and
/// `event_position` binds the disposition to its `welcomeDisposition` event.
pub(crate) async fn terminalize_welcome_delivery(
    transaction: &mut Transaction<'_, Postgres>,
    binding: &crate::chat_protocol::state_machine::WelcomeCasBinding,
    disposition: &WelcomeDisposition,
    terminal_at: DateTime<Utc>,
    event_position: i64,
) -> Result<(), DeliveryRepositoryError> {
    use crate::chat_protocol::snapshot::PublicGroupSnapshotLifecycle;
    use crate::chat_protocol::state_machine::WelcomeStatus;

    let winner_kind = disposition.winner_kind();
    let welcome_id = Uuid::from_bytes(*binding.welcome_id());
    let expected_successor = match winner_kind {
        "acknowledged" => WelcomeStatus::Acknowledged,
        "rejected" => WelcomeStatus::Rejected,
        "expired" => WelcomeStatus::Expired,
        _ => return Err(DeliveryRepositoryError::InvalidTerminalAuthority),
    };
    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await?;
    let recipient_did = std::str::from_utf8(binding.recipient().principal().as_bytes())
        .map_err(|_| DeliveryRepositoryError::InvalidTerminalAuthority)?;
    if !binding.verify_seal()
        || transaction_id != binding.transaction_id()
        || binding.expected_status() != WelcomeStatus::Pending
        || binding.successor_status() != expected_successor
        || binding.coordinate().lifecycle() != PublicGroupSnapshotLifecycle::Active
        || (winner_kind == "expired"
            && terminal_at.timestamp_millis() != binding.expires_at().unix_millis())
        || (winner_kind != "expired"
            && terminal_at.timestamp_millis() != binding.locked_at().unix_millis())
    {
        return Err(DeliveryRepositoryError::InvalidTerminalAuthority);
    }
    let generation = i64::try_from(binding.coordinate().generation())
        .map_err(|_| DeliveryRepositoryError::InvalidTerminalAuthority)?;
    let state_version = i64::try_from(binding.coordinate().state_version())
        .map_err(|_| DeliveryRepositoryError::InvalidTerminalAuthority)?;
    let epoch = i64::try_from(binding.coordinate().epoch())
        .map_err(|_| DeliveryRepositoryError::InvalidTerminalAuthority)?;

    // Cross-check every immutable bundle/delivery authority column in the CAS.
    let result = sqlx::query(
        r#"
        UPDATE chat.welcome_deliveries AS delivery
           SET status = $2,
               terminal_at = $3
          FROM chat.welcome_bundles AS bundle
         WHERE delivery.welcome_id = $1
           AND delivery.status = 'pending'
           AND bundle.welcome_id = delivery.welcome_id
           AND bundle.conversation_id = $4
           AND bundle.entry_seq = $5
           AND bundle.generation = $6
           AND bundle.state_version = $7
           AND bundle.group_id = $8
           AND bundle.epoch = $9
           AND bundle.group_context_hash = $10
           AND bundle.confirmation_tag = $11
           AND bundle.wrapper_sha256 = $12
           AND delivery.recipient_did = $13
           AND delivery.recipient_device_id = $14
           AND delivery.recovery_request_id = $15
           AND delivery.key_package_ref = $16
           AND delivery.expires_at = $17
        "#,
    )
    .bind(welcome_id)
    .bind(winner_kind)
    .bind(terminal_at)
    .bind(Uuid::from_bytes(*binding.conversation_id()))
    .bind(
        i64::try_from(binding.transition_seq())
            .map_err(|_| DeliveryRepositoryError::InvalidTerminalAuthority)?,
    )
    .bind(generation)
    .bind(state_version)
    .bind(binding.coordinate().group_id().to_vec())
    .bind(epoch)
    .bind(binding.coordinate().group_context_hash().to_vec())
    .bind(binding.coordinate().confirmation_tag().to_vec())
    .bind(binding.opaque_welcome_sha256().to_vec())
    .bind(recipient_did)
    .bind(Uuid::from_bytes(*binding.recipient().device_id()))
    .bind(Uuid::from_bytes(*binding.recovery_request_id()))
    .bind(binding.key_package_ref().to_vec())
    .bind(
        DateTime::<Utc>::from_timestamp_millis(binding.expires_at().unix_millis())
            .ok_or(DeliveryRepositoryError::InvalidTerminalAuthority)?,
    )
    .execute(&mut **transaction)
    .await?;

    if result.rows_affected() != 1 {
        return Err(DeliveryRepositoryError::CompareAndSetConflict);
    }

    insert_welcome_disposition(
        transaction,
        welcome_id,
        disposition,
        terminal_at,
        event_position,
    )
    .await
}

/// Coordinate-changing supersession remains bound to its independently
/// reverified transition/revocation cause rather than a response/expiry guard.
pub(crate) async fn terminalize_welcome_delivery_for_supersession(
    transaction: &mut Transaction<'_, Postgres>,
    welcome_id: Uuid,
    disposition: &WelcomeDisposition,
    terminal_at: DateTime<Utc>,
    event_position: i64,
) -> Result<(), DeliveryRepositoryError> {
    if !matches!(
        disposition,
        WelcomeDisposition::SupersededByTransition { .. }
            | WelcomeDisposition::SupersededByRevocation { .. }
    ) {
        return Err(DeliveryRepositoryError::InvalidTerminalAuthority);
    }
    let result = sqlx::query(
        "UPDATE chat.welcome_deliveries SET status='superseded',terminal_at=$2 \
         WHERE welcome_id=$1 AND status='pending'",
    )
    .bind(welcome_id)
    .bind(terminal_at)
    .execute(&mut **transaction)
    .await?;
    if result.rows_affected() != 1 {
        return Err(DeliveryRepositoryError::CompareAndSetConflict);
    }
    insert_welcome_disposition(
        transaction,
        welcome_id,
        disposition,
        terminal_at,
        event_position,
    )
    .await
}

/// Expire a prior-coordinate Welcome as part of a later coordinate-changing
/// transition. The sealed plan carries every immutable bundle/delivery column,
/// so this uses the same complete CAS as standalone expiry without accepting a
/// caller-authored `WelcomeCasBinding`.
pub(crate) async fn terminalize_prior_bound_welcome_expiry(
    transaction: &mut Transaction<'_, Postgres>,
    binding: &crate::chat_protocol::state_machine::WelcomeWork,
    terminal_at: DateTime<Utc>,
    event_position: i64,
) -> Result<(), DeliveryRepositoryError> {
    use crate::chat_protocol::snapshot::PublicGroupSnapshotLifecycle;
    use crate::chat_protocol::state_machine::WelcomeStatus;

    if binding.status() != WelcomeStatus::Expired
        || binding.coordinate().lifecycle() != PublicGroupSnapshotLifecycle::Active
        || terminal_at.timestamp_millis() != binding.expires_at().unix_millis()
    {
        return Err(DeliveryRepositoryError::InvalidTerminalAuthority);
    }
    let recipient_did = std::str::from_utf8(binding.recipient().principal().as_bytes())
        .map_err(|_| DeliveryRepositoryError::InvalidTerminalAuthority)?;
    let generation = i64::try_from(binding.coordinate().generation())
        .map_err(|_| DeliveryRepositoryError::InvalidTerminalAuthority)?;
    let state_version = i64::try_from(binding.coordinate().state_version())
        .map_err(|_| DeliveryRepositoryError::InvalidTerminalAuthority)?;
    let epoch = i64::try_from(binding.coordinate().epoch())
        .map_err(|_| DeliveryRepositoryError::InvalidTerminalAuthority)?;
    let welcome_id = Uuid::from_bytes(*binding.welcome_id());
    let result = sqlx::query(
        r#"
        UPDATE chat.welcome_deliveries AS delivery
           SET status='expired', terminal_at=$2
          FROM chat.welcome_bundles AS bundle
         WHERE delivery.welcome_id=$1 AND delivery.status='pending'
           AND bundle.welcome_id=delivery.welcome_id
           AND bundle.conversation_id=$3 AND bundle.entry_seq=$4
           AND bundle.generation=$5 AND bundle.state_version=$6
           AND bundle.group_id=$7 AND bundle.epoch=$8
           AND bundle.group_context_hash=$9 AND bundle.confirmation_tag=$10
           AND bundle.wrapper_sha256=$11
           AND delivery.recipient_did=$12 AND delivery.recipient_device_id=$13
           AND delivery.recovery_request_id=$14 AND delivery.key_package_ref=$15
           AND delivery.expires_at=$2
        "#,
    )
    .bind(welcome_id)
    .bind(terminal_at)
    .bind(Uuid::from_bytes(*binding.coordinate().conversation_id()))
    .bind(
        i64::try_from(binding.transition_seq())
            .map_err(|_| DeliveryRepositoryError::InvalidTerminalAuthority)?,
    )
    .bind(generation)
    .bind(state_version)
    .bind(binding.coordinate().group_id().to_vec())
    .bind(epoch)
    .bind(binding.coordinate().group_context_hash().to_vec())
    .bind(binding.coordinate().confirmation_tag().to_vec())
    .bind(binding.sha256().to_vec())
    .bind(recipient_did)
    .bind(Uuid::from_bytes(*binding.recipient().device_id()))
    .bind(Uuid::from_bytes(*binding.recovery_request_id()))
    .bind(binding.key_package_ref().to_vec())
    .execute(&mut **transaction)
    .await?;
    if result.rows_affected() != 1 {
        return Err(DeliveryRepositoryError::CompareAndSetConflict);
    }
    insert_welcome_disposition(
        transaction,
        welcome_id,
        &WelcomeDisposition::Expired,
        terminal_at,
        event_position,
    )
    .await
}

async fn insert_welcome_disposition(
    transaction: &mut Transaction<'_, Postgres>,
    welcome_id: Uuid,
    disposition: &WelcomeDisposition,
    terminal_at: DateTime<Utc>,
    event_position: i64,
) -> Result<(), DeliveryRepositoryError> {
    let winner_kind = disposition.winner_kind();
    let (signed_request_bytes, signing_transcript_bytes, request_digest, signature) =
        match disposition.authorization() {
            Some(authorization) => (
                Some(authorization.signed_request_bytes.clone()),
                Some(authorization.signing_transcript_bytes.clone()),
                Some(authorization.request_digest.clone()),
                Some(authorization.signature.clone()),
            ),
            None => (None, None, None, None),
        };

    sqlx::query(
        r#"
        INSERT INTO chat.welcome_dispositions(
            welcome_id, winner_kind, signed_request_bytes, signing_transcript_bytes,
            request_digest, signature, rejection_reason, terminal_at, event_position,
            terminal_transition_id, terminal_revocation_id
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        "#,
    )
    .bind(welcome_id)
    .bind(winner_kind)
    .bind(signed_request_bytes)
    .bind(signing_transcript_bytes)
    .bind(request_digest)
    .bind(signature)
    .bind(disposition.rejection_reason())
    .bind(terminal_at)
    .bind(event_position)
    .bind(disposition.terminal_transition_id())
    .bind(disposition.terminal_revocation_id())
    .execute(&mut **transaction)
    .await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Family F — chat.recovery_work_items (deferred re-add work for expired/rejected
// Welcomes).
// ---------------------------------------------------------------------------

/// Source kind of a recovery work item. Mirrors
/// `recovery_work_items_source_kind_check` exactly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryWorkSourceKind {
    WelcomeExpired,
    WelcomeRejected,
}

impl RecoveryWorkSourceKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::WelcomeExpired => "welcomeExpired",
            Self::WelcomeRejected => "welcomeRejected",
        }
    }
}

/// One new **pending** recovery work item, carried column-for-column: the exact
/// recipient device, the retained source disposition id + kind, and the bound
/// source `(generation, state_version)` coordinate. The insert always writes
/// `status = 'pending'` with NULL terminal provenance; the `source_id` unique and
/// `recovery_work_items_terminal_shape_check` (pending arm) remain the DB's
/// authority.
#[derive(Clone, Debug)]
pub(crate) struct NewRecoveryWorkItem {
    pub(crate) recovery_work_id: Uuid,
    pub(crate) conversation_id: Uuid,
    pub(crate) recipient_did: String,
    pub(crate) recipient_device_id: Uuid,
    pub(crate) source_kind: RecoveryWorkSourceKind,
    pub(crate) source_id: Uuid,
    pub(crate) generation: i64,
    pub(crate) state_version: i64,
    pub(crate) created_at: DateTime<Utc>,
}

pub(crate) async fn insert_recovery_work_item(
    transaction: &mut Transaction<'_, Postgres>,
    item: &NewRecoveryWorkItem,
) -> Result<(), DeliveryRepositoryError> {
    sqlx::query(
        r#"
        INSERT INTO chat.recovery_work_items(
            recovery_work_id, conversation_id, recipient_did, recipient_device_id,
            source_kind, source_id, generation, state_version, status,
            terminal_transition_id, terminal_revocation_id, created_at, terminal_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, 'pending', NULL, NULL, $9, NULL
        )
        "#,
    )
    .bind(item.recovery_work_id)
    .bind(item.conversation_id)
    .bind(&item.recipient_did)
    .bind(item.recipient_device_id)
    .bind(item.source_kind.as_str())
    .bind(item.source_id)
    .bind(item.generation)
    .bind(item.state_version)
    .bind(item.created_at)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

/// The exact terminal edge a pending recovery work item takes, per
/// `recovery_work_items_terminal_shape_check`:
/// * `CompletedByTransition` — `completed`, binds the fulfilling leaf-recovery
///   transition + timestamp (revocation NULL);
/// * `SupersededByTransition` — `superseded`, binds a superseding transition +
///   timestamp;
/// * `SupersededByRevocation` — `superseded`, binds the recipient's device
///   revocation + timestamp.
/// Every arm requires `terminal_at >= created_at` (the DB's authority).
#[derive(Clone, Debug)]
pub(crate) enum RecoveryWorkTermination {
    CompletedByTransition {
        terminal_transition_id: Uuid,
        terminal_at: DateTime<Utc>,
    },
    SupersededByTransition {
        terminal_transition_id: Uuid,
        terminal_at: DateTime<Utc>,
    },
    SupersededByRevocation {
        terminal_revocation_id: Uuid,
        terminal_at: DateTime<Utc>,
    },
}

/// Terminalize a pending recovery work item. CAS on `status = 'pending'`, writing
/// exactly the `status` + terminal columns the target shape allows (the immutable
/// identity trigger allows only `status`, `terminal_transition_id`,
/// `terminal_revocation_id`, `terminal_at` to change; the lifecycle-monotonic
/// trigger requires the row to be pending). A repeat or wrong-state attempt
/// matches nothing and is a typed conflict.
pub(crate) async fn terminalize_recovery_work_item(
    transaction: &mut Transaction<'_, Postgres>,
    recovery_work_id: Uuid,
    termination: &RecoveryWorkTermination,
) -> Result<(), DeliveryRepositoryError> {
    let (status, terminal_transition_id, terminal_revocation_id, terminal_at) = match termination {
        RecoveryWorkTermination::CompletedByTransition {
            terminal_transition_id,
            terminal_at,
        } => (
            "completed",
            Some(*terminal_transition_id),
            None,
            *terminal_at,
        ),
        RecoveryWorkTermination::SupersededByTransition {
            terminal_transition_id,
            terminal_at,
        } => (
            "superseded",
            Some(*terminal_transition_id),
            None,
            *terminal_at,
        ),
        RecoveryWorkTermination::SupersededByRevocation {
            terminal_revocation_id,
            terminal_at,
        } => (
            "superseded",
            None,
            Some(*terminal_revocation_id),
            *terminal_at,
        ),
    };

    let result = sqlx::query(
        r#"
        UPDATE chat.recovery_work_items
           SET status = $2,
               terminal_transition_id = $3,
               terminal_revocation_id = $4,
               terminal_at = $5
         WHERE recovery_work_id = $1
           AND status = 'pending'
        "#,
    )
    .bind(recovery_work_id)
    .bind(status)
    .bind(terminal_transition_id)
    .bind(terminal_revocation_id)
    .bind(terminal_at)
    .execute(&mut **transaction)
    .await?;

    if result.rows_affected() != 1 {
        return Err(DeliveryRepositoryError::CompareAndSetConflict);
    }
    Ok(())
}

// ===========================================================================
// Delivery read path (Task 2 Slice 4a).
//
// These are the READ-side counterparts of the append-log + audience + interval
// writers above: they return exactly what the executor wrote, on the exact
// entitlement seams the writers froze, and never re-derive, filter-by-current-
// membership, or synthesize provenance. Each function is one snapshot-consistent
// SQL statement (or is composed by the caller inside one read-only
// repeatable-read transaction), all `chat.*` qualified.
//
// The entitlement rules are the schema's, restated verbatim in SQL:
//   * an APPLICATION entry is visible to a device ONLY through that exact
//     device's `chat.application_intervals` row spanning the entry's seq;
//   * a CONTROL entry is visible to a device ONLY through an exact
//     `chat.entry_recipients` row at that seq. A same-DID sibling that lacks
//     the interval/recipient row sees nothing through it.
//
// No production handler consumes these yet (the `getEntries` / inventory
// handlers land in a later slice), so the read surface carries the narrowest
// local `#[allow(dead_code)]` sanctioned by `src/lib.rs` rather than a blanket
// crate allow. The delivery writers above are already reachable through the
// unconditionally-compiled transition executor.
// ===========================================================================

/// The closed `blue.catbird.chat.defs#applicationEntry` type identifier. An
/// entry with this kind is application traffic; every other kind is a control
/// entry. Matches `chat.entries.entries_kind_check`'s application arm.
pub(crate) const APPLICATION_ENTRY_KIND: &str = "blue.catbird.chat.defs#applicationEntry";

/// One `chat.entries` row read back on the delivery seam. It carries ONLY the
/// columns the two public projections (`#applicationEntry` /
/// `#conversationEntry`) and their outer fingerprint need — never the derived
/// unsigned actor / coordinate / message-id index columns, which the brief
/// forbids from re-appearing as duplicated projection fields. The outer
/// fingerprint is carried alongside (not inside) the projection so a caller can
/// assert the recomputed projection fingerprint equals the frozen column.
#[derive(Clone, Debug, sqlx::FromRow)]
#[allow(dead_code)]
pub(crate) struct DeliveredEntryRow {
    pub(crate) conversation_id: Uuid,
    pub(crate) seq: i64,
    pub(crate) entry_id: Uuid,
    pub(crate) entry_kind: String,
    pub(crate) signed_request_bytes: Vec<u8>,
    pub(crate) request_digest: Vec<u8>,
    pub(crate) signature: Vec<u8>,
    pub(crate) server_fields_bytes: Vec<u8>,
    pub(crate) outer_entry_fingerprint: Vec<u8>,
    pub(crate) received_at: DateTime<Utc>,
}

/// The closed `#applicationEntry` projection: EXACTLY the five logical fields
/// `{entryId, conversationId, seq, signedRequest, receivedAt}`. The signed
/// request is carried as its exact stored bytes (`signed_request_bytes`); there
/// is no duplicated unsigned actor / device / coordinate / messageId /
/// applicationMessage / blobBindings field. The type itself is the closed shape.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct ApplicationEntryProjection {
    pub(crate) entry_id: Uuid,
    pub(crate) conversation_id: Uuid,
    pub(crate) seq: u64,
    pub(crate) signed_request_bytes: Vec<u8>,
    pub(crate) received_at: DateTime<Utc>,
}

/// The closed `#conversationEntry` control projection: EXACTLY
/// `{entryKind, entryId, conversationId, seq, requestDigest, signature,
/// serverFields, receivedAt}`. `server_fields_bytes` is the exact stored
/// canonical DAG-CBOR of the kind-appropriate `serverFields` (`{}`,
/// `{recovery}`, or `{tombstone}`); no unsigned surrogate is duplicated.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct ControlEntryProjection {
    pub(crate) entry_kind: String,
    pub(crate) entry_id: Uuid,
    pub(crate) conversation_id: Uuid,
    pub(crate) seq: u64,
    pub(crate) request_digest: Vec<u8>,
    pub(crate) signature: Vec<u8>,
    pub(crate) server_fields_bytes: Vec<u8>,
    pub(crate) received_at: DateTime<Utc>,
}

#[allow(dead_code)]
impl DeliveredEntryRow {
    /// True iff this row is application traffic (as opposed to a control entry).
    pub(crate) fn is_application(&self) -> bool {
        self.entry_kind == APPLICATION_ENTRY_KIND
    }

    /// The exact frozen 32-byte outer-entry fingerprint column.
    pub(crate) fn outer_entry_fingerprint(&self) -> &[u8] {
        &self.outer_entry_fingerprint
    }

    /// Project an application row to its closed five-field `#applicationEntry`.
    /// Returns an error for a control row (whose projection is the control shape).
    pub(crate) fn application_projection(
        &self,
    ) -> Result<ApplicationEntryProjection, DeliveryRepositoryError> {
        if !self.is_application() {
            return Err(DeliveryRepositoryError::EntryKindMismatch);
        }
        Ok(ApplicationEntryProjection {
            entry_id: self.entry_id,
            conversation_id: self.conversation_id,
            seq: u64::try_from(self.seq).map_err(|_| DeliveryRepositoryError::SequenceOverflow)?,
            signed_request_bytes: self.signed_request_bytes.clone(),
            received_at: self.received_at,
        })
    }

    /// Project a control row to its closed `#conversationEntry` control shape.
    /// Returns an error for an application row.
    pub(crate) fn control_projection(
        &self,
    ) -> Result<ControlEntryProjection, DeliveryRepositoryError> {
        if self.is_application() {
            return Err(DeliveryRepositoryError::EntryKindMismatch);
        }
        Ok(ControlEntryProjection {
            entry_kind: self.entry_kind.clone(),
            entry_id: self.entry_id,
            conversation_id: self.conversation_id,
            seq: u64::try_from(self.seq).map_err(|_| DeliveryRepositoryError::SequenceOverflow)?,
            request_digest: self.request_digest.clone(),
            signature: self.signature.clone(),
            server_fields_bytes: self.server_fields_bytes.clone(),
            received_at: self.received_at,
        })
    }
}

/// One gap-safe page of caller-visible entries, plus its continuation cursor.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(crate) struct EntriesPage {
    /// The caller-visible entries in this page, strictly ascending by seq, at
    /// most `limit` rows.
    pub(crate) entries: Vec<DeliveredEntryRow>,
    /// The next `afterSeq` cursor: `afterSeq` unchanged when the page is empty,
    /// otherwise the greatest seq returned in this page.
    pub(crate) next_after_seq: u64,
    /// True iff at least one later caller-visible entry exists beyond this page.
    pub(crate) has_more: bool,
}

/// `getEntries` gap-safe paging over the append log.
///
/// `after_seq` is a GLOBAL conversation scan position, never an entitlement-local
/// cursor: it may name a seq the caller cannot see. The single `visible` CTE
/// filters `seq > after_seq` by the exact entitlement seams — an application
/// entry qualifies ONLY through this device's `chat.application_intervals`
/// spanning its seq; a control entry ONLY through an exact `chat.entry_recipients`
/// row — so hidden rows are simply skipped, never surfaced and never used to
/// bound the page. The visible set is ordered by seq and `limit + 1` rows are
/// fetched: the extra row (if present) proves a later caller-visible entry exists
/// (`has_more`) and is dropped from the returned page. `next_after_seq` is
/// `after_seq` when the page is empty, else the greatest returned seq. The global
/// log is NEVER limited before entitlement filtering.
#[allow(dead_code)]
pub(crate) async fn get_entries(
    transaction: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    caller_did: &str,
    caller_device_id: Uuid,
    after_seq: u64,
    limit: i64,
) -> Result<EntriesPage, DeliveryRepositoryError> {
    let after_seq_i64 =
        i64::try_from(after_seq).map_err(|_| DeliveryRepositoryError::SequenceOverflow)?;
    let fetch = limit
        .checked_add(1)
        .ok_or(DeliveryRepositoryError::SequenceOverflow)?;

    let mut rows: Vec<DeliveredEntryRow> = sqlx::query_as(
        // DRIFT GUARD: the application-interval EXISTS predicate below
        // (`entry.seq >= interval.start_seq AND (interval.terminal_seq IS NULL OR
        // entry.seq <= interval.terminal_seq)`) is the canonical per-device
        // application-visibility rule. `repository/blobs.rs::read_application_attachment`
        // carries a byte-identical copy for blob custody and a matching
        // cross-reference comment; change both sites together so entry-log and
        // blob visibility never diverge.
        r#"
        WITH visible AS (
            SELECT entry.seq
              FROM chat.entries AS entry
             WHERE entry.conversation_id = $1
               AND entry.seq > $2
               AND (
                 (
                   entry.entry_kind = $5
                   AND EXISTS (
                     SELECT 1
                       FROM chat.application_intervals AS interval
                      WHERE interval.conversation_id = entry.conversation_id
                        AND interval.recipient_did = $3
                        AND interval.recipient_device_id = $4
                        AND entry.seq >= interval.start_seq
                        AND (interval.terminal_seq IS NULL
                             OR entry.seq <= interval.terminal_seq)
                   )
                 )
                 OR
                 (
                   entry.entry_kind <> $5
                   AND EXISTS (
                     SELECT 1
                       FROM chat.entry_recipients AS recipient
                      WHERE recipient.conversation_id = entry.conversation_id
                        AND recipient.seq = entry.seq
                        AND recipient.user_did = $3
                        AND recipient.device_id = $4
                   )
                 )
               )
             ORDER BY entry.seq
             LIMIT $6
        )
        SELECT entry.conversation_id, entry.seq, entry.entry_id, entry.entry_kind,
               entry.signed_request_bytes, entry.request_digest, entry.signature,
               entry.server_fields_bytes, entry.outer_entry_fingerprint,
               entry.received_at
          FROM chat.entries AS entry
          JOIN visible ON visible.seq = entry.seq
         WHERE entry.conversation_id = $1
         ORDER BY entry.seq
        "#,
    )
    .bind(conversation_id)
    .bind(after_seq_i64)
    .bind(caller_did)
    .bind(caller_device_id)
    .bind(APPLICATION_ENTRY_KIND)
    .bind(fetch)
    .fetch_all(&mut **transaction)
    .await?;

    let limit_usize =
        usize::try_from(limit).map_err(|_| DeliveryRepositoryError::SequenceOverflow)?;
    let has_more = rows.len() > limit_usize;
    if has_more {
        rows.truncate(limit_usize);
    }
    let next_after_seq = match rows.last() {
        Some(row) => {
            u64::try_from(row.seq).map_err(|_| DeliveryRepositoryError::SequenceOverflow)?
        }
        None => after_seq,
    };
    Ok(EntriesPage {
        entries: rows,
        next_after_seq,
        has_more,
    })
}

/// `conversationState.snapshotSeq`: the greatest seq that HAS BEEN allocated in
/// the conversation, i.e. `next_entry_seq - 1`, read from the conversation head.
///
/// This is a public-state datum, NOT an entry cursor or entitlement boundary: it
/// reflects the whole append log's high-water mark regardless of what the caller
/// can see, and must be read in the same snapshot as the caller's observed
/// public state (the caller composes both inside one read-only repeatable-read
/// transaction). Returns `None` when no conversation head exists.
#[allow(dead_code)]
pub(crate) async fn conversation_snapshot_seq(
    transaction: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
) -> Result<Option<u64>, DeliveryRepositoryError> {
    let next_entry_seq: Option<i64> = sqlx::query_scalar(
        r#"
        SELECT next_entry_seq
          FROM chat.conversations
         WHERE conversation_id = $1
        "#,
    )
    .bind(conversation_id)
    .fetch_optional(&mut **transaction)
    .await?;

    match next_entry_seq {
        Some(next) => {
            let snapshot = next
                .checked_sub(1)
                .ok_or(DeliveryRepositoryError::SequenceOverflow)?;
            Ok(Some(
                u64::try_from(snapshot).map_err(|_| DeliveryRepositoryError::SequenceOverflow)?,
            ))
        }
        None => Ok(None),
    }
}

/// One `chat.application_intervals` row read back for an exact device: the whole
/// immutable five-field opening binding, the exact verified opening context, and
/// the all-or-none finite close (every closing column present together, or all
/// NULL for an open interval). Columns are carried verbatim; the caller compares
/// the five opening fields and, for a finite interval, the exact
/// `{closingTransitionId, closingOuterEntryFingerprint, closingKind}` and
/// `terminalSeq`.
#[derive(Clone, Debug, sqlx::FromRow)]
#[allow(dead_code)]
pub(crate) struct ApplicationIntervalRow {
    pub(crate) membership_interval_id: Uuid,
    pub(crate) conversation_id: Uuid,
    pub(crate) generation: i64,
    pub(crate) recipient_did: String,
    pub(crate) recipient_device_id: Uuid,
    pub(crate) start_seq: i64,
    pub(crate) opening_kind: String,
    pub(crate) opening_transition_id: Uuid,
    pub(crate) opening_outer_entry_fingerprint: Vec<u8>,
    pub(crate) opening_state_version: i64,
    pub(crate) opening_group_id: Vec<u8>,
    pub(crate) opening_epoch: i64,
    pub(crate) opening_group_context_hash: Vec<u8>,
    pub(crate) opening_confirmation_tag: Vec<u8>,
    pub(crate) opening_leaf_period_id: Uuid,
    pub(crate) terminal_seq: Option<i64>,
    pub(crate) closing_state_version: Option<i64>,
    pub(crate) closing_transition_id: Option<Uuid>,
    pub(crate) closing_outer_entry_fingerprint: Option<Vec<u8>>,
    pub(crate) closing_kind: Option<String>,
    pub(crate) closing_leaf_period_id: Option<Uuid>,
    pub(crate) removed_at: Option<DateTime<Utc>>,
    pub(crate) created_at: DateTime<Utc>,
}

#[allow(dead_code)]
impl ApplicationIntervalRow {
    /// True iff the interval is finite (closed). A finite interval has ALL of
    /// `terminal_seq`, `closing_state_version`, `closing_transition_id`,
    /// `closing_outer_entry_fingerprint`, `closing_kind`, `closing_leaf_period_id`,
    /// and `removed_at` present; an open interval has all of them NULL. Anything
    /// else violates `application_intervals_close_shape_check` and the schema
    /// forbids it — this predicate keys on `terminal_seq` and the caller may
    /// assert the all-or-none coherence explicitly.
    pub(crate) fn is_finite(&self) -> bool {
        self.terminal_seq.is_some()
    }

    /// True iff the closing columns are internally coherent (all present or all
    /// absent) — the read-side echo of the schema's all-or-none close shape.
    pub(crate) fn close_columns_are_all_or_none(&self) -> bool {
        let present = [
            self.terminal_seq.is_some(),
            self.closing_state_version.is_some(),
            self.closing_transition_id.is_some(),
            self.closing_outer_entry_fingerprint.is_some(),
            self.closing_kind.is_some(),
            self.closing_leaf_period_id.is_some(),
            self.removed_at.is_some(),
        ];
        present.iter().all(|&present| present) || present.iter().all(|&present| !present)
    }
}

/// Read every `chat.application_intervals` row bound to one EXACT recipient
/// DID/device, ordered by opening seq.
///
/// One reducer interval set binds one exact `(recipient_did, recipient_device_id)`
/// tuple, and every row repeats it; a same-DID sibling is a DIFFERENT set and is
/// never returned here. This never routes another device's interval and never
/// synthesizes an opening or close.
#[allow(dead_code)]
pub(crate) async fn fetch_device_application_intervals(
    transaction: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    recipient_did: &str,
    recipient_device_id: Uuid,
) -> Result<Vec<ApplicationIntervalRow>, DeliveryRepositoryError> {
    let rows = sqlx::query_as(
        r#"
        SELECT membership_interval_id, conversation_id, generation, recipient_did,
               recipient_device_id, start_seq, opening_kind, opening_transition_id,
               opening_outer_entry_fingerprint, opening_state_version, opening_group_id,
               opening_epoch, opening_group_context_hash, opening_confirmation_tag,
               opening_leaf_period_id, terminal_seq, closing_state_version,
               closing_transition_id, closing_outer_entry_fingerprint, closing_kind,
               closing_leaf_period_id, removed_at, created_at
          FROM chat.application_intervals
         WHERE conversation_id = $1
           AND recipient_did = $2
           AND recipient_device_id = $3
         ORDER BY start_seq
        "#,
    )
    .bind(conversation_id)
    .bind(recipient_did)
    .bind(recipient_device_id)
    .fetch_all(&mut **transaction)
    .await?;
    Ok(rows)
}

/// One `chat.application_schedule_terminal_proofs` row read back for an exact
/// device: the exact Terminal entry reference and its 32-byte outer fingerprint.
#[derive(Clone, Debug, sqlx::FromRow)]
#[allow(dead_code)]
pub(crate) struct ScheduleTerminalProofRow {
    pub(crate) conversation_id: Uuid,
    pub(crate) recipient_did: String,
    pub(crate) recipient_device_id: Uuid,
    pub(crate) terminal_seq: i64,
    pub(crate) transition_id: Uuid,
    pub(crate) outer_entry_fingerprint: Vec<u8>,
    pub(crate) received_at: DateTime<Utc>,
}

/// Exact-device authenticated lookup of the schedule terminal proof: ZERO or ONE
/// proof per `(conversation, recipient_did, recipient_device_id)` (the primary
/// key). No cross-device proof listing exists; a same-DID sibling device with no
/// proof of its own returns `None`.
#[allow(dead_code)]
pub(crate) async fn fetch_schedule_terminal_proof(
    transaction: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    recipient_did: &str,
    recipient_device_id: Uuid,
) -> Result<Option<ScheduleTerminalProofRow>, DeliveryRepositoryError> {
    let row = sqlx::query_as(
        r#"
        SELECT conversation_id, recipient_did, recipient_device_id, terminal_seq,
               transition_id, outer_entry_fingerprint, received_at
          FROM chat.application_schedule_terminal_proofs
         WHERE conversation_id = $1
           AND recipient_did = $2
           AND recipient_device_id = $3
        "#,
    )
    .bind(conversation_id)
    .bind(recipient_did)
    .bind(recipient_device_id)
    .fetch_optional(&mut **transaction)
    .await?;
    Ok(row)
}

/// Fetch the signed control entry at an EXACT seq for an EXACT device, gated by a
/// `chat.entry_recipients` row for that device at that seq.
///
/// This is the read that keeps a former device entitled to its interval's signed
/// closing control at `terminal_seq`: when an interval ends, the writer retains an
/// exact `entry_recipients` row (`intervalClose` / `scheduleTerminal` arm) so the
/// former device can still fetch the closing/Terminal control here even though its
/// application interval no longer spans that seq. Application entries are never
/// returned (their audience is interval-derived, never `entry_recipients`).
/// Returns `None` when the device has no recipient row at that seq.
#[allow(dead_code)]
pub(crate) async fn fetch_control_entry_for_device(
    transaction: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    seq: u64,
    user_did: &str,
    device_id: Uuid,
) -> Result<Option<DeliveredEntryRow>, DeliveryRepositoryError> {
    let seq_i64 = i64::try_from(seq).map_err(|_| DeliveryRepositoryError::SequenceOverflow)?;
    let row = sqlx::query_as(
        r#"
        SELECT entry.conversation_id, entry.seq, entry.entry_id, entry.entry_kind,
               entry.signed_request_bytes, entry.request_digest, entry.signature,
               entry.server_fields_bytes, entry.outer_entry_fingerprint,
               entry.received_at
          FROM chat.entries AS entry
         WHERE entry.conversation_id = $1
           AND entry.seq = $2
           AND entry.entry_kind <> $5
           AND EXISTS (
             SELECT 1
               FROM chat.entry_recipients AS recipient
              WHERE recipient.conversation_id = entry.conversation_id
                AND recipient.seq = entry.seq
                AND recipient.user_did = $3
                AND recipient.device_id = $4
           )
        "#,
    )
    .bind(conversation_id)
    .bind(seq_i64)
    .bind(user_did)
    .bind(device_id)
    .bind(APPLICATION_ENTRY_KIND)
    .fetch_optional(&mut **transaction)
    .await?;
    Ok(row)
}
