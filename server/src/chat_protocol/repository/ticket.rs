// Clean-chat subscription tickets and event-cursor receipts.
//
// G7 deliberately keeps capability plaintext out of PostgreSQL. Inventory
// and event capabilities are 32 random bytes presented as canonical
// base64url (43 ASCII characters); only their SHA-256 lookup hashes are
// persisted. The inventory snapshot capability itself is sealed by the
// inventory repository in `snapshot_event_cursor_nonce` and
// `snapshot_event_cursor_ciphertext`.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use std::fmt;
use uuid::Uuid;

#[cfg(any(not(test), feature = "subscription-production-proof"))]
use super::super::{
    dpop::VerifiedReadAdmission, read_authority, repository::inventory, OsSecureRandom,
    SecureRandom,
};

/// The exact subscription path a clean-chat ticket authorizes.
pub(crate) const SUBSCRIBE_EVENTS_PATH: &str = "/xrpc/blue.catbird.chat.subscribeEvents";
const CAPABILITY_ASCII_BYTES: usize = 43;
const HASH_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;
const MAX_SEALED_CIPHERTEXT_BYTES: usize = 512;

/// Failures exposed by the ticket/event repository boundary.
#[derive(Debug)]
pub(crate) enum TicketRepositoryError {
    Database(sqlx::Error),
    InvalidCapability,
    CapabilityMismatch,
    InvalidTicketHash,
    InvalidReceipt,
    SessionMissing,
    SessionBindingMismatch,
    DeviceBindingMismatch,
    SessionIncomplete,
    CursorMismatch,
    PathMismatch,
    TicketNotFound,
    TicketExpired,
    TicketAlreadyConsumed,
    CursorExpired,
}

impl From<sqlx::Error> for TicketRepositoryError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

/// One subscription-ticket mint request.
///
/// `inventory_session_id` and `event_cursor` are the two protocol spellings
/// of one G7 capability. They must decode to the same 32 random bytes. No
/// caller-supplied event position, cursor bytes, protocol, key, or retention
/// floor cross this boundary: all of those values come from the locked
/// inventory session row.
#[derive(Clone)]
pub(crate) struct MintSubscriptionTicket {
    pub(crate) ticket_hash: Vec<u8>,
    pub(crate) user_did: String,
    pub(crate) device_id: Uuid,
    pub(crate) jkt: Option<String>,
    pub(crate) auth_generation: i64,
    pub(crate) inventory_session_id: String,
    pub(crate) event_cursor: String,
    pub(crate) subscription_path: String,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) expires_at: DateTime<Utc>,
}

impl fmt::Debug for MintSubscriptionTicket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MintSubscriptionTicket")
            .field("ticket_hash", &"REDACTED")
            .field("user_did", &self.user_did)
            .field("device_id", &self.device_id)
            .field("jkt", &"REDACTED")
            .field("auth_generation", &self.auth_generation)
            .field("inventory_session_id", &"REDACTED")
            .field("event_cursor", &"REDACTED")
            .field("subscription_path", &self.subscription_path)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// The durable fence and lifetime returned after minting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MintedTicket {
    pub(crate) event_position: i64,
    pub(crate) event_cursor_hash: [u8; HASH_BYTES],
    pub(crate) inventory_session_id: Uuid,
    pub(crate) protocol_instance_id: Uuid,
    pub(crate) cursor_key_id: String,
    pub(crate) snapshot_retained_floor: i64,
    pub(crate) expires_at: DateTime<Utc>,
}

/// Atomically mint a ticket against a fully materialized and consumed G7
/// inventory session. The session is located by the opaque capability hash,
/// then locked before any ticket row is written. The deferred database
/// trigger remains the final authority for the composite identity and active
/// exact-device binding at commit.
pub(crate) async fn mint_subscription_ticket(
    transaction: &mut Transaction<'_, Postgres>,
    request: &MintSubscriptionTicket,
) -> Result<MintedTicket, TicketRepositoryError> {
    let ticket_hash = checked_hash(&request.ticket_hash)?;
    let inventory_hash = capability_hash(&request.inventory_session_id)?;
    let cursor_hash = capability_hash(&request.event_cursor)?;
    if inventory_hash != cursor_hash {
        return Err(TicketRepositoryError::CapabilityMismatch);
    }
    if request.subscription_path != SUBSCRIBE_EVENTS_PATH {
        return Err(TicketRepositoryError::PathMismatch);
    }
    if request.created_at >= request.expires_at {
        return Err(TicketRepositoryError::TicketExpired);
    }

    let session = sqlx::query(
        r#"
        SELECT inventory_session_id, token_hash, user_did, device_id, jkt,
               auth_generation, conversations_complete, welcomes_complete,
               recovery_complete, conversations_consumed, welcomes_consumed,
               recovery_consumed, snapshot_event_position,
               snapshot_event_cursor_sha256, protocol_instance_id, cursor_key_id,
               snapshot_retained_floor, legacy_cursor_invalidated_at,
               created_at, expires_at
          FROM chat.inventory_sessions
         WHERE token_hash = $1
           AND snapshot_event_cursor_sha256 = $1
         FOR UPDATE
        "#,
    )
    .bind(inventory_hash.as_slice())
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(TicketRepositoryError::SessionMissing)?;

    let session_id: Uuid = session.try_get("inventory_session_id")?;
    let durable_token_hash = fixed_hash(session.try_get("token_hash")?)?;
    let durable_cursor_hash = fixed_hash(session.try_get("snapshot_event_cursor_sha256")?)?;
    let user_did: String = session.try_get("user_did")?;
    let device_id: Uuid = session.try_get("device_id")?;
    let jkt: Option<String> = session.try_get("jkt")?;
    let auth_generation: i64 = session.try_get("auth_generation")?;
    if durable_token_hash != inventory_hash
        || durable_cursor_hash != inventory_hash
        || user_did != request.user_did
        || device_id != request.device_id
        || jkt != request.jkt
        || auth_generation != request.auth_generation
    {
        return Err(TicketRepositoryError::SessionBindingMismatch);
    }

    let complete: bool = session.try_get("conversations_complete")?
        && session.try_get("welcomes_complete")?
        && session.try_get("recovery_complete")?;
    let consumed: bool = session.try_get("conversations_consumed")?
        && session.try_get("welcomes_consumed")?
        && session.try_get("recovery_consumed")?;
    let legacy_cursor_invalidated_at: Option<DateTime<Utc>> =
        session.try_get("legacy_cursor_invalidated_at")?;
    if !complete || !consumed || legacy_cursor_invalidated_at.is_some() {
        return Err(TicketRepositoryError::SessionIncomplete);
    }

    let session_created_at: DateTime<Utc> = session.try_get("created_at")?;
    let session_expires_at: DateTime<Utc> = session.try_get("expires_at")?;
    if request.created_at < session_created_at
        || request.created_at >= session_expires_at
        || request.expires_at > session_expires_at
    {
        return Err(TicketRepositoryError::TicketExpired);
    }

    // The deferred trigger repeats this check at commit, closing the TOCTOU
    // window for callers composing this transaction.
    let active_device: Option<Uuid> = sqlx::query_scalar(
        r#"SELECT device_id
             FROM chat.devices
            WHERE user_did = $1
              AND device_id = $2
              AND status = 'active'
              AND dpop_jkt IS NOT DISTINCT FROM $3
              AND auth_generation = $4
              AND revoked_at IS NULL
              AND created_at <= $5
        "#,
    )
    .bind(&request.user_did)
    .bind(request.device_id)
    .bind(request.jkt.as_deref())
    .bind(request.auth_generation)
    .bind(request.created_at)
    .fetch_optional(&mut **transaction)
    .await?;
    if active_device != Some(request.device_id) {
        return Err(TicketRepositoryError::DeviceBindingMismatch);
    }

    let event_position: i64 = session.try_get("snapshot_event_position")?;
    let protocol_instance_id: Uuid = session.try_get("protocol_instance_id")?;
    let cursor_key_id: String = session.try_get("cursor_key_id")?;
    let snapshot_retained_floor: i64 = session.try_get("snapshot_retained_floor")?;
    sqlx::query(
        r#"
        INSERT INTO chat.subscription_tickets(
            ticket_hash, user_did, device_id, jkt, auth_generation,
            inventory_session_id, event_position, event_cursor_sha256,
            subscription_path, created_at, expires_at, consumed_at,
            protocol_instance_id, cursor_key_id, snapshot_retained_floor
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NULL,$12,$13,$14)
        "#,
    )
    .bind(ticket_hash.as_slice())
    .bind(&request.user_did)
    .bind(request.device_id)
    .bind(request.jkt.as_deref())
    .bind(request.auth_generation)
    .bind(session_id)
    .bind(event_position)
    .bind(cursor_hash.as_slice())
    .bind(&request.subscription_path)
    .bind(request.created_at)
    .bind(request.expires_at)
    .bind(protocol_instance_id)
    .bind(&cursor_key_id)
    .bind(snapshot_retained_floor)
    .execute(&mut **transaction)
    .await?;

    Ok(MintedTicket {
        event_position,
        event_cursor_hash: cursor_hash,
        inventory_session_id: session_id,
        protocol_instance_id,
        cursor_key_id,
        snapshot_retained_floor,
        expires_at: request.expires_at,
    })
}

/// The durable fence returned after one successful ticket consume. The
/// cursor itself is intentionally represented only by its hash.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ConsumedTicket {
    pub(crate) user_did: String,
    pub(crate) device_id: Uuid,
    pub(crate) jkt: Option<String>,
    pub(crate) auth_generation: i64,
    pub(crate) event_position: i64,
    pub(crate) event_cursor_hash: [u8; HASH_BYTES],
    pub(crate) inventory_session_id: Uuid,
    pub(crate) protocol_instance_id: Uuid,
    pub(crate) cursor_key_id: String,
    pub(crate) snapshot_retained_floor: i64,
    pub(crate) snapshot_cursor_nonce: [u8; NONCE_BYTES],
    pub(crate) snapshot_cursor_ciphertext: Vec<u8>,
    pub(crate) snapshot_created_at: DateTime<Utc>,
    pub(crate) expires_at: DateTime<Utc>,
    pub(crate) consumed_at: DateTime<Utc>,
}

/// Revalidate a live subscription's exact authority without consuming a new
/// ticket. Every idle/live loop calls this under fresh PostgreSQL locks before
/// forwarding durable or ephemeral data, so revocation and auth-generation
/// rebinds take effect even when the event high-water does not advance.
pub(crate) async fn revalidate_consumed_ticket(
    transaction: &mut Transaction<'_, Postgres>,
    ticket: &ConsumedTicket,
    cursor_position: i64,
    observed_at: DateTime<Utc>,
) -> Result<(), TicketRepositoryError> {
    if observed_at >= ticket.expires_at {
        return Err(TicketRepositoryError::TicketExpired);
    }
    let device_active: bool = sqlx::query_scalar(
        r#"SELECT EXISTS(
               SELECT 1 FROM chat.devices
                WHERE user_did=$1 AND device_id=$2
                  AND status='active' AND revoked_at IS NULL
                  AND dpop_jkt IS NOT DISTINCT FROM $3 AND auth_generation=$4
                FOR SHARE
           )"#,
    )
    .bind(&ticket.user_did)
    .bind(ticket.device_id)
    .bind(ticket.jkt.as_deref())
    .bind(ticket.auth_generation)
    .fetch_one(&mut **transaction)
    .await?;
    if !device_active {
        return Err(TicketRepositoryError::DeviceBindingMismatch);
    }
    let fence: Option<(Uuid, String, i64)> = sqlx::query_as(
        r#"SELECT protocol.protocol_instance_id, protocol.cursor_key_id,
                  retention.retained_floor
             FROM chat.protocol_instances protocol
             JOIN chat.event_retention retention USING(protocol_instance_id)
            WHERE protocol.singleton=TRUE
            FOR SHARE OF protocol, retention"#,
    )
    .fetch_optional(&mut **transaction)
    .await?;
    let Some((protocol_instance_id, cursor_key_id, retained_floor)) = fence else {
        return Err(TicketRepositoryError::SessionIncomplete);
    };
    if protocol_instance_id != ticket.protocol_instance_id || cursor_key_id != ticket.cursor_key_id
    {
        return Err(TicketRepositoryError::SessionIncomplete);
    }
    if cursor_position < retained_floor {
        return Err(TicketRepositoryError::CursorExpired);
    }
    Ok(())
}

/// Atomically consume one matching unexpired ticket. This is a strict CAS on
/// `(ticket_hash, event_cursor_sha256, path, consumed_at IS NULL, observed_at
/// < expires_at)`, so replay and exact-expiry attempts cannot authorize the
/// subscription compositor.
pub(crate) async fn consume_subscription_ticket(
    transaction: &mut Transaction<'_, Postgres>,
    ticket_hash: &[u8],
    presented_event_cursor: &str,
    subscription_path: &str,
    observed_at: DateTime<Utc>,
) -> Result<ConsumedTicket, TicketRepositoryError> {
    let ticket_hash = checked_hash(ticket_hash)?;
    let cursor_hash = capability_hash(presented_event_cursor)?;
    if subscription_path != SUBSCRIBE_EVENTS_PATH {
        return Err(TicketRepositoryError::PathMismatch);
    }

    // Serialize consumption with both the ticket row and its exact device
    // row. The device lock closes the revocation/auth-generation race between
    // the active-device check and the consumed_at CAS.
    if let Some(ticket) = sqlx::query(
        r#"SELECT user_did, device_id, jkt, auth_generation,
                  event_position, protocol_instance_id, cursor_key_id
             FROM chat.subscription_tickets
            WHERE ticket_hash = $1
            FOR UPDATE"#,
    )
    .bind(ticket_hash.as_slice())
    .fetch_optional(&mut **transaction)
    .await?
    {
        let user_did: String = ticket.try_get("user_did")?;
        let device_id: Uuid = ticket.try_get("device_id")?;
        let jkt: Option<String> = ticket.try_get("jkt")?;
        let auth_generation: i64 = ticket.try_get("auth_generation")?;
        let event_position: i64 = ticket.try_get("event_position")?;
        let protocol_instance_id: Uuid = ticket.try_get("protocol_instance_id")?;
        let cursor_key_id: String = ticket.try_get("cursor_key_id")?;
        let _device_lock = sqlx::query(
            r#"SELECT device_id
                 FROM chat.devices
                WHERE user_did = $1
                  AND device_id = $2
                  AND dpop_jkt IS NOT DISTINCT FROM $3
                  AND auth_generation = $4
                FOR UPDATE"#,
        )
        .bind(user_did)
        .bind(device_id)
        .bind(jkt.as_deref())
        .bind(auth_generation)
        .fetch_optional(&mut **transaction)
        .await?;

        // A ticket is minted against an inventory snapshot, but retention can
        // advance before the WebSocket upgrade. Lock the singleton protocol
        // fence and its live floor in this same consume transaction so the CAS
        // cannot authorize a cursor the server can no longer replay.
        let live_fence: Option<(Uuid, String, i64)> = sqlx::query_as(
            r#"SELECT protocol.protocol_instance_id, protocol.cursor_key_id,
                      retention.retained_floor
                 FROM chat.protocol_instances protocol
                 JOIN chat.event_retention retention
                   USING (protocol_instance_id)
                WHERE protocol.singleton = TRUE
                FOR SHARE OF protocol, retention"#,
        )
        .fetch_optional(&mut **transaction)
        .await?;
        let Some((live_protocol_id, live_cursor_key_id, live_retained_floor)) = live_fence else {
            return Err(TicketRepositoryError::SessionIncomplete);
        };
        if live_protocol_id != protocol_instance_id || live_cursor_key_id != cursor_key_id {
            return Err(TicketRepositoryError::SessionIncomplete);
        }
        if event_position < live_retained_floor {
            return Err(TicketRepositoryError::CursorExpired);
        }
    }

    let updated = sqlx::query(
        r#"
        UPDATE chat.subscription_tickets AS ticket
           SET consumed_at = $4
         WHERE ticket.ticket_hash = $1
           AND ticket.consumed_at IS NULL
           AND $4 < expires_at
           AND ticket.event_cursor_sha256 = $2
           AND ticket.subscription_path = $3
           AND ticket.protocol_instance_id IS NOT NULL
           AND ticket.cursor_key_id IS NOT NULL
           AND ticket.snapshot_retained_floor IS NOT NULL
           AND EXISTS (
                SELECT 1
                  FROM chat.devices device
                 WHERE device.user_did = ticket.user_did
                   AND device.device_id = ticket.device_id
                   AND device.status = 'active'
                   AND device.dpop_jkt IS NOT DISTINCT FROM ticket.jkt
                   AND device.auth_generation = ticket.auth_generation
                   AND device.revoked_at IS NULL
           )
        RETURNING ticket.user_did, ticket.device_id, ticket.jkt,
                  ticket.auth_generation, ticket.event_position, ticket.event_cursor_sha256,
                  ticket.inventory_session_id, ticket.protocol_instance_id,
                  ticket.cursor_key_id, ticket.snapshot_retained_floor,
                  ticket.expires_at, ticket.consumed_at
        "#,
    )
    .bind(ticket_hash.as_slice())
    .bind(cursor_hash.as_slice())
    .bind(subscription_path)
    .bind(observed_at)
    .fetch_optional(&mut **transaction)
    .await?;
    if let Some(row) = updated {
        let inventory = sqlx::query(
            r#"SELECT snapshot_event_cursor_nonce, snapshot_event_cursor_ciphertext,
                      created_at, expires_at
                 FROM chat.inventory_sessions
                WHERE inventory_session_id = $1
                  AND token_hash = $2
                  AND snapshot_event_cursor_sha256 = $2
                FOR UPDATE"#,
        )
        .bind(row.try_get::<Uuid, _>("inventory_session_id")?)
        .bind(cursor_hash.as_slice())
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or(TicketRepositoryError::SessionMissing)?;
        return Ok(ConsumedTicket {
            user_did: row.try_get("user_did")?,
            device_id: row.try_get("device_id")?,
            jkt: row.try_get("jkt")?,
            auth_generation: row.try_get("auth_generation")?,
            event_position: row.try_get("event_position")?,
            event_cursor_hash: fixed_hash(row.try_get("event_cursor_sha256")?)?,
            inventory_session_id: row.try_get("inventory_session_id")?,
            protocol_instance_id: row.try_get("protocol_instance_id")?,
            cursor_key_id: row.try_get("cursor_key_id")?,
            snapshot_retained_floor: row.try_get("snapshot_retained_floor")?,
            snapshot_cursor_nonce: inventory
                .try_get::<Vec<u8>, _>("snapshot_event_cursor_nonce")?
                .try_into()
                .map_err(|_| TicketRepositoryError::InvalidReceipt)?,
            snapshot_cursor_ciphertext: inventory.try_get("snapshot_event_cursor_ciphertext")?,
            snapshot_created_at: inventory.try_get("created_at")?,
            expires_at: inventory.try_get("expires_at")?,
            consumed_at: row.try_get("consumed_at")?,
        });
    }

    let existing = sqlx::query(
        r#"SELECT consumed_at, expires_at, event_cursor_sha256,
                  subscription_path, user_did, device_id, jkt,
                  auth_generation, protocol_instance_id, cursor_key_id,
                  snapshot_retained_floor
             FROM chat.subscription_tickets
            WHERE ticket_hash = $1
            FOR UPDATE"#,
    )
    .bind(ticket_hash.as_slice())
    .fetch_optional(&mut **transaction)
    .await?;
    let row = existing.ok_or(TicketRepositoryError::TicketNotFound)?;
    let consumed_at: Option<DateTime<Utc>> = row.try_get("consumed_at")?;
    let expires_at: DateTime<Utc> = row.try_get("expires_at")?;
    let bound_hash = fixed_hash(row.try_get("event_cursor_sha256")?)?;
    let bound_path: String = row.try_get("subscription_path")?;
    let bound_user_did: String = row.try_get("user_did")?;
    let bound_device_id: Uuid = row.try_get("device_id")?;
    let bound_jkt: Option<String> = row.try_get("jkt")?;
    let bound_auth_generation: i64 = row.try_get("auth_generation")?;
    let has_g7_binding: bool = row
        .try_get::<Option<Uuid>, _>("protocol_instance_id")?
        .is_some()
        && row.try_get::<Option<String>, _>("cursor_key_id")?.is_some()
        && row
            .try_get::<Option<i64>, _>("snapshot_retained_floor")?
            .is_some();
    if consumed_at.is_some() {
        Err(TicketRepositoryError::TicketAlreadyConsumed)
    } else if observed_at >= expires_at {
        Err(TicketRepositoryError::TicketExpired)
    } else if bound_path != subscription_path {
        Err(TicketRepositoryError::PathMismatch)
    } else if bound_hash != cursor_hash {
        Err(TicketRepositoryError::CursorMismatch)
    } else if !has_g7_binding {
        Err(TicketRepositoryError::SessionIncomplete)
    } else if !sqlx::query_scalar::<_, bool>(
        r#"SELECT EXISTS (
                 SELECT 1
                   FROM chat.devices
                  WHERE user_did = $1
                    AND device_id = $2
                    AND status = 'active'
                    AND dpop_jkt IS NOT DISTINCT FROM $3
                    AND auth_generation = $4
                    AND revoked_at IS NULL
             )"#,
    )
    .bind(bound_user_did)
    .bind(bound_device_id)
    .bind(bound_jkt.as_deref())
    .bind(bound_auth_generation)
    .fetch_one(&mut **transaction)
    .await?
    {
        Err(TicketRepositoryError::DeviceBindingMismatch)
    } else {
        Err(TicketRepositoryError::TicketAlreadyConsumed)
    }
}

/// One event cursor receipt. The ciphertext is the sealed capability payload;
/// this API never accepts or persists cursor plaintext.
#[derive(Clone, Debug)]
pub(crate) struct NewEventCursorReceipt {
    pub(crate) cursor_hash: [u8; HASH_BYTES],
    pub(crate) inventory_session_id: Uuid,
    pub(crate) user_did: String,
    pub(crate) device_id: Uuid,
    pub(crate) jkt: Option<String>,
    pub(crate) auth_generation: i64,
    pub(crate) protocol_instance_id: Uuid,
    pub(crate) cursor_key_id: String,
    pub(crate) event_position: i64,
    pub(crate) predecessor_cursor_hash: Option<[u8; HASH_BYTES]>,
    pub(crate) retained_floor_at_issue: i64,
    pub(crate) cursor_nonce: [u8; NONCE_BYTES],
    pub(crate) cursor_ciphertext: Vec<u8>,
    pub(crate) canonical_envelope_sha256: Option<[u8; HASH_BYTES]>,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) expires_at: DateTime<Utc>,
}

impl NewEventCursorReceipt {
    fn validate(&self) -> Result<(), TicketRepositoryError> {
        if self.cursor_hash == [0; HASH_BYTES]
            || self
                .predecessor_cursor_hash
                .is_some_and(|hash| hash == [0; HASH_BYTES])
            || self
                .canonical_envelope_sha256
                .is_some_and(|hash| hash == [0; HASH_BYTES])
            || self.cursor_nonce == [0; NONCE_BYTES]
            || self.cursor_ciphertext.len() < 17
            || self.cursor_ciphertext.len() > MAX_SEALED_CIPHERTEXT_BYTES
            || self.created_at >= self.expires_at
        {
            return Err(TicketRepositoryError::InvalidReceipt);
        }
        Ok(())
    }
}

/// Persist one sealed event-cursor receipt. Chain ordering, session binding,
/// and immutable-history rules remain enforced by the G7 database triggers.
pub(crate) async fn insert_event_cursor_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    receipt: &NewEventCursorReceipt,
) -> Result<(), TicketRepositoryError> {
    receipt.validate()?;

    sqlx::query(
        r#"
        INSERT INTO chat.event_cursor_receipts(
            cursor_hash, inventory_session_id, user_did, device_id, jkt,
            auth_generation, protocol_instance_id, cursor_key_id, event_position,
            predecessor_cursor_hash, retained_floor_at_issue, cursor_nonce,
            cursor_ciphertext, canonical_envelope_sha256, created_at, expires_at
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
        "#,
    )
    .bind(receipt.cursor_hash.as_slice())
    .bind(receipt.inventory_session_id)
    .bind(&receipt.user_did)
    .bind(receipt.device_id)
    .bind(receipt.jkt.as_deref())
    .bind(receipt.auth_generation)
    .bind(receipt.protocol_instance_id)
    .bind(&receipt.cursor_key_id)
    .bind(receipt.event_position)
    .bind(receipt.predecessor_cursor_hash.map(|hash| hash.to_vec()))
    .bind(receipt.retained_floor_at_issue)
    .bind(receipt.cursor_nonce.as_slice())
    .bind(&receipt.cursor_ciphertext)
    .bind(receipt.canonical_envelope_sha256.map(|hash| hash.to_vec()))
    .bind(receipt.created_at)
    .bind(receipt.expires_at)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

/// SHA-256 lookup hash for the opaque ticket secret. The raw ticket is never
/// persisted; callers may pass any secret bytes because the wire ticket format
/// is owned by the compositor.
pub(crate) fn ticket_hash(opaque_ticket: &[u8]) -> [u8; HASH_BYTES] {
    Sha256::digest(opaque_ticket).into()
}

/// Compose the clean-chat ticket endpoint from one POST read admission. The
/// session UUID is only a row handle; the repository recovers and verifies the
/// sealed snapshot capability before minting the one-use ticket. Both the
/// recovered capability and the caller's event cursor must match exactly.
#[cfg(any(not(test), feature = "subscription-production-proof"))]
pub(crate) async fn mint_subscription_ticket_for_admission(
    pool: &sqlx::PgPool,
    admission: VerifiedReadAdmission,
    inventory_session_capability: &str,
    event_cursor: &str,
    sealer: &crate::chat_protocol::CursorSealer,
) -> Result<(String, DateTime<Utc>), TicketRepositoryError> {
    let attempt = admission
        .into_single_read_attempt("blue.catbird.chat.getSubscriptionTicket", "POST")
        .map_err(|_| TicketRepositoryError::SessionBindingMismatch)?;
    let mut transaction = pool.begin().await?;
    let device = read_authority::lock_read_device_authority_once(&mut transaction, attempt)
        .await
        .map_err(|_| TicketRepositoryError::DeviceBindingMismatch)?;
    let inventory_session_id = inventory::derive_inventory_session_uuid(
        device.user_did(),
        device.device_id(),
        device.jkt(),
        device.auth_generation(),
    );
    let (capability, session_expires_at) = inventory::snapshot_capability_for_ticket(
        &mut transaction,
        &device,
        inventory_session_id,
        sealer,
    )
    .await
    .map_err(|error| match error {
        inventory::InventoryRepositoryError::SessionNotFound => {
            TicketRepositoryError::SessionMissing
        }
        inventory::InventoryRepositoryError::DeviceAuthorityMismatch => {
            TicketRepositoryError::DeviceBindingMismatch
        }
        _ => TicketRepositoryError::SessionBindingMismatch,
    })?;
    if event_cursor != capability || inventory_session_capability != capability {
        return Err(TicketRepositoryError::CursorMismatch);
    }
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT transaction_timestamp()")
        .fetch_one(&mut *transaction)
        .await?;
    let expires_at = (now + chrono::Duration::seconds(30)).min(session_expires_at);
    if now >= expires_at {
        return Err(TicketRepositoryError::TicketExpired);
    }
    let mut opaque = [0_u8; HASH_BYTES];
    let mut random = OsSecureRandom::new();
    random
        .fill(&mut opaque)
        .map_err(|_| TicketRepositoryError::InvalidTicketHash)?;
    let request = MintSubscriptionTicket {
        ticket_hash: ticket_hash(&opaque).to_vec(),
        user_did: device.user_did().to_owned(),
        device_id: device.device_id(),
        jkt: device.jkt().map(str::to_owned),
        auth_generation: i64::try_from(device.auth_generation())
            .map_err(|_| TicketRepositoryError::SessionBindingMismatch)?,
        // The durable ticket repository intentionally takes the opaque G7
        // capability in this field; the public UUID is validated above.
        inventory_session_id: capability.clone(),
        event_cursor: event_cursor.to_owned(),
        subscription_path: SUBSCRIBE_EVENTS_PATH.to_owned(),
        created_at: now,
        expires_at,
    };
    mint_subscription_ticket(&mut transaction, &request).await?;
    transaction.commit().await?;
    Ok((URL_SAFE_NO_PAD.encode(opaque), expires_at))
}

/// Hash a canonical 32-byte random capability. This helper is intentionally
/// private to the repository boundary so callers cannot accidentally persist
/// decoded capability bytes.
fn capability_hash(encoded: &str) -> Result<[u8; HASH_BYTES], TicketRepositoryError> {
    if encoded.len() != CAPABILITY_ASCII_BYTES {
        return Err(TicketRepositoryError::InvalidCapability);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| TicketRepositoryError::InvalidCapability)?;
    if decoded.len() != HASH_BYTES || URL_SAFE_NO_PAD.encode(&decoded) != encoded {
        return Err(TicketRepositoryError::InvalidCapability);
    }
    Ok(Sha256::digest(decoded).into())
}

fn checked_hash(value: &[u8]) -> Result<[u8; HASH_BYTES], TicketRepositoryError> {
    value
        .try_into()
        .map_err(|_| TicketRepositoryError::InvalidTicketHash)
}

fn fixed_hash(value: Vec<u8>) -> Result<[u8; HASH_BYTES], TicketRepositoryError> {
    value
        .try_into()
        .map_err(|_| TicketRepositoryError::InvalidReceipt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_hash_requires_the_canonical_43_character_encoding() {
        let capability = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert_eq!(
            capability_hash(capability).unwrap(),
            <[u8; 32]>::from(Sha256::digest([0u8; 32]))
        );
        assert!(capability_hash("not-a-capability").is_err());
        assert!(capability_hash("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").is_err());
    }

    #[test]
    fn source_contains_no_plaintext_cursor_columns() {
        let source = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/repository/ticket.rs"
        ));
        assert!(!source.contains(concat!("snapshot_event_cursor_", "bytes")));
        assert!(!source.contains(concat!("event_cursor_", "bytes")));
    }

    #[test]
    fn mint_request_debug_redacts_bearer_material() {
        let request = MintSubscriptionTicket {
            ticket_hash: vec![0xA5; 32],
            user_did: "did:plc:example".to_owned(),
            device_id: Uuid::nil(),
            jkt: Some("secret-jkt".to_owned()),
            auth_generation: 7,
            inventory_session_id: "session-capability-secret".to_owned(),
            event_cursor: "event-capability-secret".to_owned(),
            subscription_path: SUBSCRIBE_EVENTS_PATH.to_owned(),
            created_at: Utc::now(),
            expires_at: Utc::now(),
        };
        let debug = format!("{request:?}");
        assert!(!debug.contains("A5"));
        assert!(!debug.contains("secret-jkt"));
        assert!(!debug.contains("session-capability-secret"));
        assert!(!debug.contains("event-capability-secret"));
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn sealed_receipt_boundary_rejects_nonce_reuse_shapes() {
        let now = Utc::now();
        let mut receipt = NewEventCursorReceipt {
            cursor_hash: [1; 32],
            inventory_session_id: Uuid::new_v4(),
            user_did: "did:plc:example".to_owned(),
            device_id: Uuid::new_v4(),
            jkt: Some("jkt".to_owned()),
            auth_generation: 1,
            protocol_instance_id: Uuid::new_v4(),
            cursor_key_id: "key".to_owned(),
            event_position: 1,
            predecessor_cursor_hash: None,
            retained_floor_at_issue: 0,
            cursor_nonce: [1; 12],
            cursor_ciphertext: vec![2; 17],
            canonical_envelope_sha256: None,
            created_at: now,
            expires_at: now + chrono::Duration::minutes(1),
        };
        assert!(receipt.validate().is_ok());
        receipt.cursor_nonce = [0; 12];
        assert!(matches!(
            receipt.validate(),
            Err(TicketRepositoryError::InvalidReceipt)
        ));
        receipt.cursor_nonce = [1; 12];
        receipt.cursor_ciphertext = vec![2; 16];
        assert!(matches!(
            receipt.validate(),
            Err(TicketRepositoryError::InvalidReceipt)
        ));
    }
}
