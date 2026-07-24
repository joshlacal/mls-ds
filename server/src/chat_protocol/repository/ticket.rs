// Subscription-ticket mint + one-use consume for the clean-chat protocol
// (Task 2, Slice 4c).
//
// A subscription ticket is the single-use bridge between a COMPLETED inventory
// session and the `subscribeEvents` WebSocket upgrade. This module owns the two
// closed transactions on `chat.subscription_tickets`:
//
//   1. **mint** — `getSubscriptionTicket(inventorySessionId, eventCursor)`
//      succeeds only after all three shared inventory domains (conversations,
//      pending Welcomes, recovery) are complete AND the presented event cursor
//      byte-equals the session's snapshot cursor. The minted ticket is bound to
//      the exact DID / device / JKT / auth generation / session / cursor /
//      subscription path; the database's deferred
//      `assert_subscription_ticket_binding` trigger re-verifies every one of
//      those bindings at COMMIT.
//   2. **consume** — `subscribeEvents` atomically consumes one matching
//      unexpired ticket (one-use, via a `consumed_at IS NULL` CAS) and requires
//      the presented cursor to byte-equal the ticket cursor BEFORE the caller
//      performs the WebSocket upgrade. A second consume of the same ticket, an
//      expired ticket, or a cursor mismatch changes nothing and is a typed
//      conflict.
//
// This is the NEW-table path. It is NOT the legacy `handlers::get_subscription_
// ticket` `ws_ticket_nonce` (30-second nonce) surface, which is untouched.

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

/// The exact subscription path a clean-chat ticket authorizes. Mirrors
/// `subscription_tickets_path_check`.
pub(crate) const SUBSCRIBE_EVENTS_PATH: &str = "/xrpc/blue.catbird.chat.subscribeEvents";

/// Failures the ticket mint / consume can surface.
#[derive(Debug)]
pub(crate) enum TicketRepositoryError {
    /// A raw database error escaped the transaction.
    Database(sqlx::Error),
    /// No inventory session exists for the requested `inventory_session_id`.
    SessionMissing,
    /// The inventory session exists but has not completed all three shared
    /// domains, so no ticket may be minted yet.
    SessionIncomplete,
    /// The presented event cursor does not byte-equal the session's snapshot
    /// cursor (mint) or the ticket's bound cursor (consume).
    CursorMismatch,
    /// The subscription path presented at consume did not match the ticket's
    /// bound path.
    PathMismatch,
    /// No unexpired, unconsumed ticket matched the consume CAS. The follow-up
    /// classification distinguishes the exact reason.
    TicketNotFound,
    /// The ticket exists but is already past its expiry.
    TicketExpired,
    /// The ticket exists and is unexpired but was already consumed (one-use).
    TicketAlreadyConsumed,
}

impl From<sqlx::Error> for TicketRepositoryError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

// ===========================================================================
// Mint.
// ===========================================================================

/// One subscription-ticket mint request. `ticket_hash` is the 32-byte hash of
/// the opaque ticket the caller will hand back to the client; the raw ticket is
/// never persisted. `event_cursor_bytes` is the cursor the caller presents — it
/// must byte-equal the session snapshot cursor, so the ticket cannot advance or
/// rewind the fence. `event_position` and `event_cursor_sha256` are NOT carried:
/// they are taken from the locked session so a caller can never desynchronize
/// them from the cursor bytes.
#[derive(Clone, Debug)]
pub(crate) struct MintSubscriptionTicket {
    pub(crate) ticket_hash: Vec<u8>,
    pub(crate) user_did: String,
    pub(crate) device_id: Uuid,
    pub(crate) jkt: String,
    pub(crate) auth_generation: i64,
    pub(crate) inventory_session_id: Uuid,
    pub(crate) event_cursor_bytes: Vec<u8>,
    pub(crate) subscription_path: String,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) expires_at: DateTime<Utc>,
}

/// The identity of a freshly minted ticket, echoing the fence it is bound to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MintedTicket {
    pub(crate) event_position: i64,
    pub(crate) event_cursor_bytes: Vec<u8>,
    pub(crate) expires_at: DateTime<Utc>,
}

/// Mint a subscription ticket against a completed inventory session. Locks the
/// session (`FOR UPDATE`), verifies all three shared domains are complete and
/// the presented cursor byte-equals the session snapshot cursor, then inserts
/// the ticket bound to the session's exact `(event_position, cursor bytes,
/// cursor sha256)`. The deferred `assert_subscription_ticket_binding` trigger
/// re-checks the DID/device/JKT/auth-generation/cursor/window binding and the
/// active-device requirement at COMMIT, so a caller cannot mint a ticket that
/// disagrees with its session.
pub(crate) async fn mint_subscription_ticket(
    transaction: &mut Transaction<'_, Postgres>,
    request: &MintSubscriptionTicket,
) -> Result<MintedTicket, TicketRepositoryError> {
    let session = sqlx::query(
        r#"
        SELECT conversations_complete,
               welcomes_complete,
               recovery_complete,
               snapshot_event_position,
               snapshot_event_cursor_bytes,
               snapshot_event_cursor_sha256
          FROM chat.inventory_sessions
         WHERE inventory_session_id = $1
           AND user_did = $2
           AND device_id = $3
           AND jkt = $4
           AND auth_generation = $5
         FOR UPDATE
        "#,
    )
    .bind(request.inventory_session_id)
    .bind(&request.user_did)
    .bind(request.device_id)
    .bind(&request.jkt)
    .bind(request.auth_generation)
    .fetch_optional(&mut **transaction)
    .await?;

    let session = session.ok_or(TicketRepositoryError::SessionMissing)?;

    let conversations_complete: bool = session.try_get("conversations_complete")?;
    let welcomes_complete: bool = session.try_get("welcomes_complete")?;
    let recovery_complete: bool = session.try_get("recovery_complete")?;
    if !(conversations_complete && welcomes_complete && recovery_complete) {
        return Err(TicketRepositoryError::SessionIncomplete);
    }

    let snapshot_event_position: i64 = session.try_get("snapshot_event_position")?;
    let snapshot_event_cursor_bytes: Vec<u8> = session.try_get("snapshot_event_cursor_bytes")?;
    let snapshot_event_cursor_sha256: Vec<u8> = session.try_get("snapshot_event_cursor_sha256")?;

    // Byte-equal cursor: the ticket cannot advance or rewind the session fence.
    if request.event_cursor_bytes != snapshot_event_cursor_bytes {
        return Err(TicketRepositoryError::CursorMismatch);
    }

    sqlx::query(
        r#"
        INSERT INTO chat.subscription_tickets(
            ticket_hash, user_did, device_id, jkt, auth_generation,
            inventory_session_id, event_position, event_cursor_bytes,
            event_cursor_sha256, subscription_path, created_at, expires_at, consumed_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NULL)
        "#,
    )
    .bind(&request.ticket_hash)
    .bind(&request.user_did)
    .bind(request.device_id)
    .bind(&request.jkt)
    .bind(request.auth_generation)
    .bind(request.inventory_session_id)
    .bind(snapshot_event_position)
    .bind(&snapshot_event_cursor_bytes)
    .bind(&snapshot_event_cursor_sha256)
    .bind(&request.subscription_path)
    .bind(request.created_at)
    .bind(request.expires_at)
    .execute(&mut **transaction)
    .await?;

    Ok(MintedTicket {
        event_position: snapshot_event_position,
        event_cursor_bytes: snapshot_event_cursor_bytes,
        expires_at: request.expires_at,
    })
}

// ===========================================================================
// Consume.
// ===========================================================================

/// The identity of a consumed ticket: the event position and cursor the durable
/// stream continues from. The caller performs the WebSocket upgrade only after a
/// successful consume.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ConsumedTicket {
    pub(crate) event_position: i64,
    pub(crate) event_cursor_bytes: Vec<u8>,
    pub(crate) inventory_session_id: Uuid,
    pub(crate) consumed_at: DateTime<Utc>,
}

/// Atomically consume one matching unexpired ticket. The CAS sets `consumed_at`
/// only from NULL (one-use), only while `observed_at` is before `expires_at`,
/// only when the presented cursor byte-equals the ticket cursor, and only for
/// the exact subscription path. A second consume, an expired ticket, or a cursor
/// mismatch matches no row and returns a typed conflict after a classification
/// read — the caller never upgrades a WebSocket on a losing consume.
pub(crate) async fn consume_subscription_ticket(
    transaction: &mut Transaction<'_, Postgres>,
    ticket_hash: &[u8],
    presented_cursor_bytes: &[u8],
    subscription_path: &str,
    observed_at: DateTime<Utc>,
) -> Result<ConsumedTicket, TicketRepositoryError> {
    let updated = sqlx::query(
        r#"
        UPDATE chat.subscription_tickets
           SET consumed_at = $4
         WHERE ticket_hash = $1
           AND consumed_at IS NULL
           AND $4 < expires_at
           AND event_cursor_bytes = $2
           AND subscription_path = $3
        RETURNING event_position, event_cursor_bytes, inventory_session_id, consumed_at
        "#,
    )
    .bind(ticket_hash)
    .bind(presented_cursor_bytes)
    .bind(subscription_path)
    .bind(observed_at)
    .fetch_optional(&mut **transaction)
    .await?;

    if let Some(row) = updated {
        let event_position: i64 = row.try_get("event_position")?;
        let event_cursor_bytes: Vec<u8> = row.try_get("event_cursor_bytes")?;
        let inventory_session_id: Uuid = row.try_get("inventory_session_id")?;
        let consumed_at: DateTime<Utc> = row.try_get("consumed_at")?;
        return Ok(ConsumedTicket {
            event_position,
            event_cursor_bytes,
            inventory_session_id,
            consumed_at,
        });
    }

    // Classify the miss for a precise typed error. The row is re-read in the same
    // transaction (still holding any locks) so the classification cannot race the
    // CAS it just lost.
    let existing = sqlx::query(
        r#"
        SELECT consumed_at, expires_at, event_cursor_bytes, subscription_path
          FROM chat.subscription_tickets
         WHERE ticket_hash = $1
        "#,
    )
    .bind(ticket_hash)
    .fetch_optional(&mut **transaction)
    .await?;

    let row = existing.ok_or(TicketRepositoryError::TicketNotFound)?;
    let consumed_at: Option<DateTime<Utc>> = row.try_get("consumed_at")?;
    let expires_at: DateTime<Utc> = row.try_get("expires_at")?;
    let bound_cursor: Vec<u8> = row.try_get("event_cursor_bytes")?;
    let bound_path: String = row.try_get("subscription_path")?;

    if consumed_at.is_some() {
        Err(TicketRepositoryError::TicketAlreadyConsumed)
    } else if observed_at >= expires_at {
        Err(TicketRepositoryError::TicketExpired)
    } else if bound_path != subscription_path {
        Err(TicketRepositoryError::PathMismatch)
    } else if bound_cursor != presented_cursor_bytes {
        Err(TicketRepositoryError::CursorMismatch)
    } else {
        // The row is unconsumed, unexpired, path- and cursor-matching, yet the
        // CAS matched nothing: this can only be a concurrent winner between the
        // UPDATE and this read, so it is an already-consumed conflict.
        Err(TicketRepositoryError::TicketAlreadyConsumed)
    }
}

/// The 32-byte hash under which an opaque ticket secret is stored. The raw
/// ticket bytes are never persisted; only this digest is.
pub(crate) fn ticket_hash(opaque_ticket: &[u8]) -> [u8; 32] {
    Sha256::digest(opaque_ticket).into()
}
