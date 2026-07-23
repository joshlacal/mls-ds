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
