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
    /// A compare-and-set matched no row: the stored row's compared columns did
    /// not equal the expected pre-state — drift, a wrong status, or an already
    /// terminalized period. The caller changed nothing, which is a conflict,
    /// not a silent success. Used by the migration-2 state-family terminalizers
    /// (interval close, Welcome delivery terminalize, recovery work terminalize)
    /// exactly as `transition::TransitionRepositoryError::CompareAndSetConflict`
    /// is used for the migration-1 families.
    CompareAndSetConflict,
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
/// * `Expired` / `Superseded` are server-authored — no signature block, no reason.
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
    Superseded,
}

impl WelcomeDisposition {
    /// The winner kind, which is also the delivery's successor status. Mirrors
    /// `welcome_dispositions_winner_check` / `welcome_deliveries_status_check`.
    fn winner_kind(&self) -> &'static str {
        match self {
            Self::Acknowledged { .. } => "acknowledged",
            Self::Rejected { .. } => "rejected",
            Self::Expired => "expired",
            Self::Superseded => "superseded",
        }
    }

    fn authorization(&self) -> Option<&WelcomeClientAuthorization> {
        match self {
            Self::Acknowledged { authorization } | Self::Rejected { authorization, .. } => {
                Some(authorization)
            }
            Self::Expired | Self::Superseded => None,
        }
    }

    fn rejection_reason(&self) -> Option<&'static str> {
        match self {
            Self::Rejected { reason, .. } => Some(reason.as_str()),
            Self::Acknowledged { .. } | Self::Expired | Self::Superseded => None,
        }
    }
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
    welcome_id: Uuid,
    disposition: &WelcomeDisposition,
    terminal_at: DateTime<Utc>,
    event_position: i64,
) -> Result<(), DeliveryRepositoryError> {
    let winner_kind = disposition.winner_kind();

    // 1. CAS the pending delivery to its terminal status. The loser (a repeat or
    //    wrong-state call) matches nothing and returns before writing a
    //    disposition, so the delivery keeps exactly one disposition row.
    let result = sqlx::query(
        r#"
        UPDATE chat.welcome_deliveries
           SET status = $2,
               terminal_at = $3
         WHERE welcome_id = $1
           AND status = 'pending'
        "#,
    )
    .bind(welcome_id)
    .bind(winner_kind)
    .bind(terminal_at)
    .execute(&mut **transaction)
    .await?;

    if result.rows_affected() != 1 {
        return Err(DeliveryRepositoryError::CompareAndSetConflict);
    }

    // 2. Insert the one immutable disposition row for the winning terminalization.
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
            request_digest, signature, rejection_reason, terminal_at, event_position
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
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
