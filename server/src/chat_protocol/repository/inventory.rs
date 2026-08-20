// Transaction-bound inventory continuation authority.
//
// A page cursor is authenticated twice: first as non-authorizing lookup
// material, then against the exact retained inventory session selected and
// locked by its token hash. No raw inventory-session token is persisted.

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, Postgres, Transaction};
use thiserror::Error;
use uuid::{Uuid, Variant, Version};

use super::super::{
    cursor::{
        inventory_item_key_hash, CursorCodec, CursorCodecError, EventCursor, InventoryPageBinding,
        InventoryPageDomain, InventoryPageLocator, InventorySessionBinding, InventorySessionToken,
        SealerError, SecureRandomError,
    },
    validation::{ed25519_key_id, BareDid, KeyThumbprint},
};

use super::super::cursor::{
    decode_capability_token, mint_capability_token, CapabilityToken, CursorSealer, OsSecureRandom,
    SealedCapability, SealerBinding, SecureRandom,
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jacquard_common::deps::smol_str::SmolStr;
use zeroize::Zeroizing;

const MAX_PROTOCOL_INTEGER: u64 = 9_007_199_254_740_991;
/// The exact inventory page limit ceiling (schema `page_limit BETWEEN 1 AND
/// 100` and the retained-item page ceiling).
///
/// Purpose-staged: used by the (still handler-less) D-2 page paths and by the
/// byte-identical `read_inventory_page` legacy surface, so the dead-code lint
/// is documented rather than papered over.
#[allow(dead_code)]
pub(crate) const MAX_INVENTORY_PAGE_ITEMS: u64 = 100;

#[derive(Debug, Error)]
pub(crate) enum InventoryRepositoryError {
    #[error("inventory session was not found")]
    SessionNotFound,
    #[error("inventory session durable row is invalid")]
    DurableRowInvalid,
    #[error("inventory session no longer has current device/key authority")]
    DeviceAuthorityMismatch,
    #[error("inventory session protocol/event fence mismatch")]
    ProtocolFenceMismatch,
    #[error("inventory session presentation does not match its durable hash")]
    SessionPresentationMismatch,
    #[error("inventory domain was already completed")]
    DomainAlreadyComplete,
    #[error("inventory cursor boundary item does not match retained materialization")]
    BoundaryItemMismatch,
    #[error("inventory authority belongs to a different PostgreSQL transaction")]
    TransactionMismatch,
    #[error("inventory completion lost its exact compare-and-set race or was reused")]
    RaceOrReuse,
    #[error("inventory page materialization is invalid")]
    InvalidMaterialization,
    #[error(
        "supplied conversation items do not match the repository's membership-guarded selection"
    )]
    InconsistentConversationSelection,
    #[error("supplied Welcome items do not match the repository's pending-delivery selection")]
    InconsistentWelcomeSelection,
    #[error(
        "supplied recovery items do not match the repository's open-request/pending-work selection"
    )]
    InconsistentRecoverySelection,
    #[error("inventory fence advanced during selection; retry the session create")]
    SnapshotConflict,
    #[error("device query names too many or zero DIDs")]
    RequestTooBroad,
    #[error(transparent)]
    Cursor(#[from] CursorCodecError),
    #[error("capability randomness source failed")]
    SecureRandom(#[from] SecureRandomError),
    #[error(transparent)]
    Sealer(#[from] SealerError),
    #[error("inventory snapshot creation exhausted its three-attempt retry ceiling")]
    RetryCeiling,
    #[cfg(not(test))]
    #[error(transparent)]
    Projection(#[from] crate::chat_protocol::read_projection::ProjectionError),
    #[cfg(not(test))]
    #[error("clean-chat inventory read authority failed")]
    ReadAuthority(super::super::read_authority::ReadAuthorityError),
    #[cfg(not(test))]
    #[error("clean-chat inventory read admission failed")]
    ReadAdmission(super::super::dpop::ReadAdmissionBindingError),
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

impl PartialEq for InventoryRepositoryError {
    fn eq(&self, other: &Self) -> bool {
        use InventoryRepositoryError::{
            BoundaryItemMismatch, Cursor, DeviceAuthorityMismatch, DomainAlreadyComplete,
            DurableRowInvalid, InconsistentConversationSelection, InconsistentRecoverySelection,
            InconsistentWelcomeSelection, InvalidMaterialization, ProtocolFenceMismatch,
            RaceOrReuse, RequestTooBroad, RetryCeiling, Sealer, SecureRandom, SessionNotFound,
            SessionPresentationMismatch, SnapshotConflict, TransactionMismatch,
        };
        match (self, other) {
            (SessionNotFound, SessionNotFound)
            | (DurableRowInvalid, DurableRowInvalid)
            | (DeviceAuthorityMismatch, DeviceAuthorityMismatch)
            | (ProtocolFenceMismatch, ProtocolFenceMismatch)
            | (SessionPresentationMismatch, SessionPresentationMismatch)
            | (DomainAlreadyComplete, DomainAlreadyComplete)
            | (BoundaryItemMismatch, BoundaryItemMismatch)
            | (TransactionMismatch, TransactionMismatch)
            | (RaceOrReuse, RaceOrReuse)
            | (RequestTooBroad, RequestTooBroad)
            | (InconsistentConversationSelection, InconsistentConversationSelection)
            | (InconsistentWelcomeSelection, InconsistentWelcomeSelection)
            | (InconsistentRecoverySelection, InconsistentRecoverySelection)
            | (SnapshotConflict, SnapshotConflict)
            | (RetryCeiling, RetryCeiling)
            | (InvalidMaterialization, InvalidMaterialization)
            | (SecureRandom(..), SecureRandom(..)) => true,
            (Cursor(left), Cursor(right)) => left == right,
            (Sealer(left), Sealer(right)) => left == right,
            _ => false,
        }
    }
}

impl Eq for InventoryRepositoryError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InventoryCompletionEvidence {
    complete: bool,
    item_count: Option<u64>,
    items_sha256: Option<[u8; 32]>,
}

impl InventoryCompletionEvidence {
    pub(crate) const fn incomplete() -> Self {
        Self {
            complete: false,
            item_count: None,
            items_sha256: None,
        }
    }

    pub(crate) fn complete(
        item_count: u64,
        items_sha256: [u8; 32],
    ) -> Result<Self, InventoryRepositoryError> {
        if item_count > MAX_PROTOCOL_INTEGER || items_sha256 == [0; 32] {
            return Err(InventoryRepositoryError::DurableRowInvalid);
        }
        Ok(Self {
            complete: true,
            item_count: Some(item_count),
            items_sha256: Some(items_sha256),
        })
    }

    fn from_database(
        complete: bool,
        item_count: Option<i64>,
        items_sha256: Option<Vec<u8>>,
    ) -> Result<Self, InventoryRepositoryError> {
        let item_count = item_count
            .map(database_protocol_integer)
            .transpose()
            .map_err(|_| InventoryRepositoryError::DurableRowInvalid)?;
        let items_sha256 = items_sha256
            .map(fixed_hash)
            .transpose()
            .map_err(|_| InventoryRepositoryError::DurableRowInvalid)?;
        let evidence = Self {
            complete,
            item_count,
            items_sha256,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    fn validate(self) -> Result<(), InventoryRepositoryError> {
        if (!self.complete && (self.item_count.is_some() || self.items_sha256.is_some()))
            || (self.complete
                && (self.item_count.is_none()
                    || self.items_sha256.is_none()
                    || self.items_sha256 == Some([0; 32])))
        {
            return Err(InventoryRepositoryError::DurableRowInvalid);
        }
        Ok(())
    }

    const fn is_complete(self) -> bool {
        self.complete
    }
}

/// Exact retained inventory-session row and all current lock witnesses.
///
/// The value is deliberately non-Clone. It is created only after the token
/// hash row, current active device/key, protocol singleton, retention floor,
/// and current event head have all been locked in one PostgreSQL transaction.
#[derive(Debug)]
pub(crate) struct LockedInventorySessionGuard {
    transaction_id: String,
    inventory_session_id: Uuid,
    token_hash: [u8; 32],
    user_did: String,
    device_id: Uuid,
    jkt: Option<String>,
    auth_generation: u64,
    snapshot_event_position: u64,
    snapshot_event_cursor_bytes: Vec<u8>,
    snapshot_event_cursor_sha256: [u8; 32],
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    conversations: InventoryCompletionEvidence,
    welcomes: InventoryCompletionEvidence,
    recovery: InventoryCompletionEvidence,
    active_key_id: String,
    active_signing_public_key_sha256: [u8; 32],
    key_enrollment_auth_generation: u64,
    protocol_instance_id: Uuid,
    cursor_key_id: String,
    retained_floor: u64,
    retention_updated_at: DateTime<Utc>,
    head_event_position: u64,
    head_event_id: Option<Uuid>,
    head_payload_sha256: Option<[u8; 32]>,
    head_created_at: Option<DateTime<Utc>>,
    locked_at: DateTime<Utc>,
    durable_row_digest: [u8; 32],
}

/// Opaque cursor material reconstructed from one locked durable row.
///
/// Its constructor is private to this repository module. The cursor codec can
/// consume it, but routes cannot assemble it from request fields.
#[derive(Debug)]
pub(crate) struct LockedInventoryCursorEvidence {
    session_binding: InventorySessionBinding,
    inventory_session: InventorySessionToken,
    snapshot_event_cursor: EventCursor,
    domain: InventoryPageDomain,
    canonical_filter: Vec<u8>,
    now: u64,
    retained_floor: u64,
    maximum_event_position: u64,
}

impl LockedInventoryCursorEvidence {
    /// Purpose-staged: consumed by the D-1 `CursorCodec` surface in cursor.rs
    /// (`verify_located_inventory_page_cursor`), which the D-2 rewiring left
    /// without production callers; the F-lane retires the codec surface and
    /// this helper together.
    #[allow(dead_code)]
    #[allow(clippy::type_complexity)]
    pub(crate) fn into_cursor_parts(
        self,
    ) -> (
        InventorySessionBinding,
        InventorySessionToken,
        EventCursor,
        InventoryPageDomain,
        Vec<u8>,
        u64,
        u64,
        u64,
    ) {
        (
            self.session_binding,
            self.inventory_session,
            self.snapshot_event_cursor,
            self.domain,
            self.canonical_filter,
            self.now,
            self.retained_floor,
            self.maximum_event_position,
        )
    }
}

#[derive(Debug)]
struct InventorySessionLockMaterial {
    transaction_id: String,
    inventory_session_id: Uuid,
    token_hash: [u8; 32],
    user_did: String,
    device_id: Uuid,
    jkt: Option<String>,
    auth_generation: u64,
    snapshot_event_position: u64,
    snapshot_event_cursor_bytes: Vec<u8>,
    snapshot_event_cursor_sha256: [u8; 32],
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    conversations: InventoryCompletionEvidence,
    welcomes: InventoryCompletionEvidence,
    recovery: InventoryCompletionEvidence,
    device_status: String,
    current_dpop_jkt: Option<String>,
    current_auth_generation: u64,
    device_revoked_at: Option<DateTime<Utc>>,
    key_id: String,
    signing_public_key: [u8; 32],
    key_enrollment_auth_generation: u64,
    key_revoked_at: Option<DateTime<Utc>>,
    protocol_instance_id: Uuid,
    cursor_key_id: String,
    retained_floor: u64,
    retention_updated_at: DateTime<Utc>,
    head_event_position: u64,
    head_event_id: Option<Uuid>,
    head_payload_sha256: Option<[u8; 32]>,
    head_created_at: Option<DateTime<Utc>>,
    locked_at: DateTime<Utc>,
}

impl LockedInventorySessionGuard {
    fn from_locked_material(
        codec: &CursorCodec,
        material: InventorySessionLockMaterial,
        expected_token_hash: Option<[u8; 32]>,
    ) -> Result<Self, InventoryRepositoryError> {
        let InventorySessionLockMaterial {
            transaction_id,
            inventory_session_id,
            token_hash,
            user_did,
            device_id,
            jkt,
            auth_generation,
            snapshot_event_position,
            snapshot_event_cursor_bytes,
            snapshot_event_cursor_sha256,
            created_at,
            expires_at,
            conversations,
            welcomes,
            recovery,
            device_status,
            current_dpop_jkt,
            current_auth_generation,
            device_revoked_at,
            key_id,
            signing_public_key,
            key_enrollment_auth_generation,
            key_revoked_at,
            protocol_instance_id,
            cursor_key_id,
            retained_floor,
            retention_updated_at,
            head_event_position,
            head_event_id,
            head_payload_sha256,
            head_created_at,
            locked_at,
        } = material;

        if !canonical_transaction_id(&transaction_id)
            || !uuid_is_canonical_v4(inventory_session_id)
            || token_hash == [0; 32]
            || expected_token_hash.is_some_and(|expected| expected != token_hash)
            || BareDid::parse(&user_did).is_err()
            || !uuid_is_canonical_v4(device_id)
            || jkt.as_deref().is_some_and(|value| KeyThumbprint::parse(value).is_err())
            || !(1..=MAX_PROTOCOL_INTEGER).contains(&auth_generation)
            || snapshot_event_position > MAX_PROTOCOL_INTEGER
            || snapshot_event_cursor_bytes.is_empty()
            || snapshot_event_cursor_bytes.len() > 512
            || <[u8; 32]>::from(Sha256::digest(&snapshot_event_cursor_bytes))
                != snapshot_event_cursor_sha256
            || unix_seconds(created_at).is_none()
            || unix_seconds(expires_at).is_none()
            || created_at >= expires_at
            || locked_at < created_at
            || locked_at >= expires_at
            || conversations.validate().is_err()
            || welcomes.validate().is_err()
            || recovery.validate().is_err()
        {
            return Err(InventoryRepositoryError::DurableRowInvalid);
        }

        if device_status != "active"
            || device_revoked_at.is_some()
            || key_revoked_at.is_some()
            || current_dpop_jkt != jkt
            || current_auth_generation != auth_generation
            || !(1..=auth_generation).contains(&key_enrollment_auth_generation)
            || KeyThumbprint::parse(&key_id).is_err()
            || !ed25519_key_id(&signing_public_key)
                .is_ok_and(|expected| expected.as_str() == key_id)
        {
            return Err(InventoryRepositoryError::DeviceAuthorityMismatch);
        }

        let head_shape_valid = if head_event_position == 0 {
            head_event_id.is_none() && head_payload_sha256.is_none() && head_created_at.is_none()
        } else {
            head_event_position <= MAX_PROTOCOL_INTEGER
                && head_event_id.is_some_and(uuid_is_canonical_v4)
                && head_payload_sha256.is_some_and(|digest| digest != [0; 32])
                && head_created_at.is_some_and(|created| created <= locked_at)
        };
        if !codec.matches_protocol_configuration(protocol_instance_id, &cursor_key_id)
            || retained_floor > MAX_PROTOCOL_INTEGER
            || retained_floor > head_event_position
            || snapshot_event_position < retained_floor
            || snapshot_event_position > head_event_position
            || retention_updated_at > locked_at
            || !head_shape_valid
        {
            return Err(InventoryRepositoryError::ProtocolFenceMismatch);
        }

        let active_signing_public_key_sha256 = Sha256::digest(signing_public_key).into();
        let durable_row_digest = locked_inventory_session_digest(
            &transaction_id,
            inventory_session_id,
            &token_hash,
            &user_did,
            device_id,
            jkt.as_deref(),
            auth_generation,
            snapshot_event_position,
            &snapshot_event_cursor_bytes,
            &snapshot_event_cursor_sha256,
            created_at,
            expires_at,
            conversations,
            welcomes,
            recovery,
            &key_id,
            &active_signing_public_key_sha256,
            key_enrollment_auth_generation,
            protocol_instance_id,
            &cursor_key_id,
            retained_floor,
            retention_updated_at,
            head_event_position,
            head_event_id,
            head_payload_sha256,
            head_created_at,
            locked_at,
        );

        Ok(Self {
            transaction_id,
            inventory_session_id,
            token_hash,
            user_did,
            device_id,
            jkt,
            auth_generation,
            snapshot_event_position,
            snapshot_event_cursor_bytes,
            snapshot_event_cursor_sha256,
            created_at,
            expires_at,
            conversations,
            welcomes,
            recovery,
            active_key_id: key_id,
            active_signing_public_key_sha256,
            key_enrollment_auth_generation,
            protocol_instance_id,
            cursor_key_id,
            retained_floor,
            retention_updated_at,
            head_event_position,
            head_event_id,
            head_payload_sha256,
            head_created_at,
            locked_at,
            durable_row_digest,
        })
    }

    fn completion(&self, domain: InventoryPageDomain) -> InventoryCompletionEvidence {
        match domain {
            InventoryPageDomain::Conversations => self.conversations,
            InventoryPageDomain::PendingWelcomes => self.welcomes,
            InventoryPageDomain::LeafRecovery => self.recovery,
        }
    }
}

#[derive(Debug)]
pub(crate) struct InventoryPageReadAuthority {
    session: LockedInventorySessionGuard,
    domain: InventoryPageDomain,
    verified_cursor_hash: [u8; 32],
    last_ordinal: u64,
    item_key_hash: [u8; 32],
    page_binding: InventoryPageBinding,
}

impl InventoryPageReadAuthority {
    pub(crate) fn inventory_session_id(&self) -> Uuid {
        self.session.inventory_session_id
    }

    pub(crate) fn domain(&self) -> InventoryPageDomain {
        self.domain
    }

    pub(crate) fn last_ordinal(&self) -> u64 {
        self.last_ordinal
    }

    fn validate_boundary_item(
        &self,
        transaction_id: &str,
        ordinal: u64,
        item_key: &[u8],
    ) -> Result<(), InventoryRepositoryError> {
        if transaction_id != self.session.transaction_id {
            return Err(InventoryRepositoryError::TransactionMismatch);
        }
        if ordinal != self.last_ordinal
            || !inventory_item_key_hash(self.domain, item_key)
                .is_ok_and(|digest| digest == self.item_key_hash)
        {
            return Err(InventoryRepositoryError::BoundaryItemMismatch);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn validate_boundary_item_for_test(
        &self,
        transaction_id: &str,
        ordinal: u64,
        item_key: &[u8],
    ) -> Result<(), InventoryRepositoryError> {
        self.validate_boundary_item(transaction_id, ordinal, item_key)
    }

    #[cfg(test)]
    pub(crate) fn seal_final_page_completion_for_test(
        self,
        transaction_id: &str,
        item_count: u64,
        items_sha256: [u8; 32],
    ) -> Result<InventoryPageCompletionAuthority, InventoryRepositoryError> {
        InventoryPageCompletionAuthority::new(self, transaction_id, item_count, items_sha256)
    }
}

#[derive(Debug)]
pub(crate) struct InventoryPageCompletionAuthority {
    session: LockedInventorySessionGuard,
    domain: InventoryPageDomain,
    verified_cursor_hash: [u8; 32],
    item_count: u64,
    items_sha256: [u8; 32],
}

impl InventoryPageCompletionAuthority {
    fn new(
        page: InventoryPageReadAuthority,
        transaction_id: &str,
        item_count: u64,
        items_sha256: [u8; 32],
    ) -> Result<Self, InventoryRepositoryError> {
        if transaction_id != page.session.transaction_id {
            return Err(InventoryRepositoryError::TransactionMismatch);
        }
        if item_count > MAX_PROTOCOL_INTEGER || items_sha256 == [0; 32] {
            return Err(InventoryRepositoryError::InvalidMaterialization);
        }
        if page.session.completion(page.domain).is_complete() {
            return Err(InventoryRepositoryError::DomainAlreadyComplete);
        }
        Ok(Self {
            session: page.session,
            domain: page.domain,
            verified_cursor_hash: page.verified_cursor_hash,
            item_count,
            items_sha256,
        })
    }

    #[cfg(test)]
    pub(crate) fn validate_transaction_for_test(
        &self,
        transaction_id: &str,
    ) -> Result<(), InventoryRepositoryError> {
        if transaction_id == self.session.transaction_id {
            Ok(())
        } else {
            Err(InventoryRepositoryError::TransactionMismatch)
        }
    }
}

#[derive(Debug, FromRow)]
struct InventorySessionRow {
    inventory_session_id: Uuid,
    token_hash: Vec<u8>,
    user_did: String,
    device_id: Uuid,
    jkt: Option<String>,
    auth_generation: i64,
    snapshot_event_position: i64,
    snapshot_event_cursor_bytes: Vec<u8>,
    snapshot_event_cursor_sha256: Vec<u8>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    conversations_complete: bool,
    welcomes_complete: bool,
    recovery_complete: bool,
    conversation_item_count: Option<i64>,
    conversation_items_sha256: Option<Vec<u8>>,
    welcome_item_count: Option<i64>,
    welcome_items_sha256: Option<Vec<u8>>,
    recovery_item_count: Option<i64>,
    recovery_items_sha256: Option<Vec<u8>>,
}

#[derive(Debug, FromRow)]
struct ActiveDeviceKeyRow {
    device_status: String,
    current_dpop_jkt: Option<String>,
    current_auth_generation: i64,
    device_revoked_at: Option<DateTime<Utc>>,
    key_id: String,
    signing_public_key: Vec<u8>,
    key_enrollment_auth_generation: i64,
    key_revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, FromRow)]
struct ProtocolInstanceRow {
    protocol_instance_id: Uuid,
    cursor_key_id: String,
}

#[derive(Debug, FromRow)]
struct EventRetentionRow {
    retained_floor: i64,
    retention_updated_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
struct HeadEventRow {
    head_event_position: i64,
    head_event_id: Uuid,
    head_payload_sha256: Vec<u8>,
    head_created_at: DateTime<Utc>,
}

/// Selects and locks the exact session identified by the authenticated locator,
/// then locks every current authority/fence row needed for phase-two checking.
pub(crate) async fn lock_inventory_session(
    transaction: &mut Transaction<'_, Postgres>,
    locator: &InventoryPageLocator,
    codec: &CursorCodec,
) -> Result<LockedInventorySessionGuard, InventoryRepositoryError> {
    let session: InventorySessionRow = sqlx::query_as(
        r#"
        SELECT inventory_session_id, token_hash, user_did, device_id, jkt,
               auth_generation, snapshot_event_position,
               snapshot_event_cursor_bytes, snapshot_event_cursor_sha256,
               created_at, expires_at, conversations_complete,
               welcomes_complete, recovery_complete, conversation_item_count,
               conversation_items_sha256, welcome_item_count,
               welcome_items_sha256, recovery_item_count,
               recovery_items_sha256
          FROM chat.inventory_sessions
         WHERE token_hash = $1
         FOR UPDATE
        "#,
    )
    .bind(locator.session_token_hash().as_slice())
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(InventoryRepositoryError::SessionNotFound)?;

    let (transaction_id, locked_at): (String, DateTime<Utc>) =
        sqlx::query_as("SELECT txid_current()::text, transaction_timestamp()")
            .fetch_one(&mut **transaction)
            .await?;

    let protocol: ProtocolInstanceRow = sqlx::query_as(
        r#"
        SELECT protocol_instance_id, cursor_key_id
          FROM chat.protocol_instances
         WHERE singleton = TRUE
         FOR UPDATE
        "#,
    )
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(InventoryRepositoryError::ProtocolFenceMismatch)?;

    let retention: EventRetentionRow = sqlx::query_as(
        r#"
        SELECT retained_floor, updated_at AS retention_updated_at
          FROM chat.event_retention
         WHERE protocol_instance_id = $1
         FOR UPDATE
        "#,
    )
    .bind(protocol.protocol_instance_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(InventoryRepositoryError::ProtocolFenceMismatch)?;

    let head: Option<HeadEventRow> = sqlx::query_as(
        r#"
        SELECT event_position AS head_event_position,
               event_id AS head_event_id,
               payload_sha256 AS head_payload_sha256,
               created_at AS head_created_at
          FROM chat.events
         WHERE protocol_instance_id = $1
         ORDER BY event_position DESC
         LIMIT 1
         FOR UPDATE
        "#,
    )
    .bind(protocol.protocol_instance_id)
    .fetch_optional(&mut **transaction)
    .await?;

    let device: ActiveDeviceKeyRow = sqlx::query_as(
        r#"
        SELECT device.status AS device_status,
               device.dpop_jkt AS current_dpop_jkt,
               device.auth_generation AS current_auth_generation,
               device.revoked_at AS device_revoked_at,
               device_key.key_id,
               device_key.signing_public_key,
               device_key.enrollment_auth_generation AS key_enrollment_auth_generation,
               device_key.revoked_at AS key_revoked_at
          FROM chat.devices AS device
          JOIN chat.device_keys AS device_key
            ON device_key.user_did = device.user_did
           AND device_key.device_id = device.device_id
         WHERE device.user_did = $1
           AND device.device_id = $2
         FOR UPDATE OF device, device_key
        "#,
    )
    .bind(&session.user_did)
    .bind(session.device_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(InventoryRepositoryError::DeviceAuthorityMismatch)?;

    let (head_event_position, head_event_id, head_payload_sha256, head_created_at) = match head {
        Some(head) => (
            database_protocol_integer(head.head_event_position)
                .map_err(|_| InventoryRepositoryError::ProtocolFenceMismatch)?,
            Some(head.head_event_id),
            Some(
                fixed_hash(head.head_payload_sha256)
                    .map_err(|_| InventoryRepositoryError::ProtocolFenceMismatch)?,
            ),
            Some(head.head_created_at),
        ),
        None => (0, None, None, None),
    };
    let material = InventorySessionLockMaterial {
        transaction_id,
        inventory_session_id: session.inventory_session_id,
        token_hash: fixed_hash(session.token_hash)
            .map_err(|_| InventoryRepositoryError::DurableRowInvalid)?,
        user_did: session.user_did,
        device_id: session.device_id,
        jkt: session.jkt,
        auth_generation: database_protocol_integer(session.auth_generation)
            .map_err(|_| InventoryRepositoryError::DurableRowInvalid)?,
        snapshot_event_position: database_protocol_integer(session.snapshot_event_position)
            .map_err(|_| InventoryRepositoryError::DurableRowInvalid)?,
        snapshot_event_cursor_bytes: session.snapshot_event_cursor_bytes,
        snapshot_event_cursor_sha256: fixed_hash(session.snapshot_event_cursor_sha256)
            .map_err(|_| InventoryRepositoryError::DurableRowInvalid)?,
        created_at: session.created_at,
        expires_at: session.expires_at,
        conversations: InventoryCompletionEvidence::from_database(
            session.conversations_complete,
            session.conversation_item_count,
            session.conversation_items_sha256,
        )?,
        welcomes: InventoryCompletionEvidence::from_database(
            session.welcomes_complete,
            session.welcome_item_count,
            session.welcome_items_sha256,
        )?,
        recovery: InventoryCompletionEvidence::from_database(
            session.recovery_complete,
            session.recovery_item_count,
            session.recovery_items_sha256,
        )?,
        device_status: device.device_status,
        current_dpop_jkt: device.current_dpop_jkt,
        current_auth_generation: database_protocol_integer(device.current_auth_generation)
            .map_err(|_| InventoryRepositoryError::DeviceAuthorityMismatch)?,
        device_revoked_at: device.device_revoked_at,
        key_id: device.key_id,
        signing_public_key: device
            .signing_public_key
            .try_into()
            .map_err(|_| InventoryRepositoryError::DeviceAuthorityMismatch)?,
        key_enrollment_auth_generation: database_protocol_integer(
            device.key_enrollment_auth_generation,
        )
        .map_err(|_| InventoryRepositoryError::DeviceAuthorityMismatch)?,
        key_revoked_at: device.key_revoked_at,
        protocol_instance_id: protocol.protocol_instance_id,
        cursor_key_id: protocol.cursor_key_id,
        retained_floor: database_protocol_integer(retention.retained_floor)
            .map_err(|_| InventoryRepositoryError::ProtocolFenceMismatch)?,
        retention_updated_at: retention.retention_updated_at,
        head_event_position,
        head_event_id,
        head_payload_sha256,
        head_created_at,
        locked_at,
    };
    LockedInventorySessionGuard::from_locked_material(
        codec,
        material,
        Some(locator.session_token_hash()),
    )
}

#[derive(Debug, FromRow)]
struct InventoryItemRow {
    ordinal: i64,
    item_key_bytes: Vec<u8>,
    payload_bytes: Vec<u8>,
    payload_sha256: Vec<u8>,
}

#[derive(Debug, FromRow)]
struct InventoryMaterializationDigestRow {
    item_count: i64,
    minimum_ordinal: Option<i64>,
    maximum_ordinal: Option<i64>,
    items_sha256: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct InventoryPageItem {
    ordinal: u64,
    item_key_bytes: Vec<u8>,
    payload_bytes: Vec<u8>,
    payload_sha256: [u8; 32],
}

impl InventoryPageItem {
    pub(crate) fn ordinal(&self) -> u64 {
        self.ordinal
    }

    pub(crate) fn item_key_bytes(&self) -> &[u8] {
        &self.item_key_bytes
    }

    pub(crate) fn payload_bytes(&self) -> &[u8] {
        &self.payload_bytes
    }

    pub(crate) fn payload_sha256(&self) -> &[u8; 32] {
        &self.payload_sha256
    }

    fn into_payload_bytes(self) -> Vec<u8> {
        self.payload_bytes
    }

    fn from_database(row: InventoryItemRow) -> Result<Self, InventoryRepositoryError> {
        let ordinal = database_protocol_integer(row.ordinal)
            .map_err(|_| InventoryRepositoryError::InvalidMaterialization)?;
        let payload_sha256 = fixed_hash(row.payload_sha256)
            .map_err(|_| InventoryRepositoryError::InvalidMaterialization)?;
        if row.item_key_bytes.is_empty()
            || row.item_key_bytes.len() > 512
            || row.payload_bytes.is_empty()
            || row.payload_bytes.len() > 16_777_216
            || <[u8; 32]>::from(Sha256::digest(&row.payload_bytes)) != payload_sha256
        {
            return Err(InventoryRepositoryError::InvalidMaterialization);
        }
        Ok(Self {
            ordinal,
            item_key_bytes: row.item_key_bytes,
            payload_bytes: row.payload_bytes,
            payload_sha256,
        })
    }
}

#[derive(Debug)]
pub(crate) struct InventoryPageContinuationAuthority {
    session: LockedInventorySessionGuard,
    page_binding: InventoryPageBinding,
    verified_cursor_hash: [u8; 32],
    last_ordinal: u64,
    item_key_bytes: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct InventoryPageBatch {
    items: Vec<InventoryPageItem>,
    continuation: Option<InventoryPageContinuationAuthority>,
    completion: Option<InventoryPageCompletionAuthority>,
}

impl InventoryPageBatch {
    pub(crate) fn items(&self) -> &[InventoryPageItem] {
        &self.items
    }

    pub(crate) fn has_more(&self) -> bool {
        self.continuation.is_some()
    }

    pub(crate) fn into_authorities(
        self,
    ) -> (
        Vec<InventoryPageItem>,
        Option<InventoryPageContinuationAuthority>,
        Option<InventoryPageCompletionAuthority>,
    ) {
        (self.items, self.continuation, self.completion)
    }
}

/// Consumes page-read authority in the same transaction that locked the
/// session. The cursor boundary is checked against the exact retained item
/// before any subsequent item is returned.
pub(crate) async fn read_inventory_page(
    transaction: &mut Transaction<'_, Postgres>,
    authority: InventoryPageReadAuthority,
    page_size: u64,
) -> Result<InventoryPageBatch, InventoryRepositoryError> {
    if !(1..=MAX_INVENTORY_PAGE_ITEMS).contains(&page_size) {
        return Err(InventoryRepositoryError::InvalidMaterialization);
    }
    let transaction_id = current_transaction_id(transaction).await?;
    if transaction_id != authority.session.transaction_id {
        return Err(InventoryRepositoryError::TransactionMismatch);
    }

    let boundary = fetch_boundary_item(
        transaction,
        authority.domain,
        authority.session.inventory_session_id,
        authority.last_ordinal,
    )
    .await?
    .ok_or(InventoryRepositoryError::BoundaryItemMismatch)?;
    authority.validate_boundary_item(
        &transaction_id,
        database_protocol_integer(boundary.ordinal)
            .map_err(|_| InventoryRepositoryError::BoundaryItemMismatch)?,
        &boundary.item_key_bytes,
    )?;

    let mut rows = fetch_inventory_items_after(
        transaction,
        authority.domain,
        authority.session.inventory_session_id,
        authority.last_ordinal,
        page_size + 1,
    )
    .await?;
    if rows.is_empty() || rows.len() > (page_size + 1) as usize {
        return Err(InventoryRepositoryError::InvalidMaterialization);
    }
    let expected_first = authority
        .last_ordinal
        .checked_add(1)
        .ok_or(InventoryRepositoryError::InvalidMaterialization)?;
    let mut items = Vec::with_capacity(rows.len());
    for (index, row) in rows.drain(..).enumerate() {
        let item = InventoryPageItem::from_database(row)?;
        if item.ordinal
            != expected_first
                .checked_add(index as u64)
                .ok_or(InventoryRepositoryError::InvalidMaterialization)?
        {
            return Err(InventoryRepositoryError::InvalidMaterialization);
        }
        items.push(item);
    }

    let has_more = items.len() > page_size as usize;
    if has_more {
        items.truncate(page_size as usize);
        let boundary = items
            .last()
            .ok_or(InventoryRepositoryError::InvalidMaterialization)?;
        let continuation = InventoryPageContinuationAuthority {
            session: authority.session,
            page_binding: authority.page_binding,
            verified_cursor_hash: authority.verified_cursor_hash,
            last_ordinal: boundary.ordinal,
            item_key_bytes: boundary.item_key_bytes.clone(),
        };
        Ok(InventoryPageBatch {
            items,
            continuation: Some(continuation),
            completion: None,
        })
    } else {
        let materialization = read_materialization_digest(
            transaction,
            authority.domain,
            authority.session.inventory_session_id,
        )
        .await?;
        let (item_count, items_sha256) = validate_materialization_digest(materialization)?;
        let completion = InventoryPageCompletionAuthority::new(
            authority,
            &transaction_id,
            item_count,
            items_sha256,
        )?;
        Ok(InventoryPageBatch {
            items,
            continuation: None,
            completion: Some(completion),
        })
    }
}

async fn current_transaction_id(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<String, InventoryRepositoryError> {
    Ok(sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await?)
}

async fn fetch_boundary_item(
    transaction: &mut Transaction<'_, Postgres>,
    domain: InventoryPageDomain,
    inventory_session_id: Uuid,
    ordinal: u64,
) -> Result<Option<InventoryItemRow>, InventoryRepositoryError> {
    let ordinal =
        i64::try_from(ordinal).map_err(|_| InventoryRepositoryError::BoundaryItemMismatch)?;
    let sql = match domain {
        InventoryPageDomain::Conversations => {
            "SELECT ordinal,item_key_bytes,payload_bytes,payload_sha256 FROM chat.inventory_conversation_items WHERE inventory_session_id = $1 AND ordinal = $2"
        }
        InventoryPageDomain::PendingWelcomes => {
            "SELECT ordinal,item_key_bytes,payload_bytes,payload_sha256 FROM chat.inventory_welcome_items WHERE inventory_session_id = $1 AND ordinal = $2"
        }
        InventoryPageDomain::LeafRecovery => {
            "SELECT ordinal,item_key_bytes,payload_bytes,payload_sha256 FROM chat.inventory_recovery_items WHERE inventory_session_id = $1 AND ordinal = $2"
        }
    };
    Ok(sqlx::query_as(sql)
        .bind(inventory_session_id)
        .bind(ordinal)
        .fetch_optional(&mut **transaction)
        .await?)
}

async fn fetch_inventory_items_after(
    transaction: &mut Transaction<'_, Postgres>,
    domain: InventoryPageDomain,
    inventory_session_id: Uuid,
    last_ordinal: u64,
    limit: u64,
) -> Result<Vec<InventoryItemRow>, InventoryRepositoryError> {
    let last_ordinal = i64::try_from(last_ordinal)
        .map_err(|_| InventoryRepositoryError::InvalidMaterialization)?;
    let limit =
        i64::try_from(limit).map_err(|_| InventoryRepositoryError::InvalidMaterialization)?;
    let sql = match domain {
        InventoryPageDomain::Conversations => {
            "SELECT ordinal,item_key_bytes,payload_bytes,payload_sha256 FROM chat.inventory_conversation_items WHERE inventory_session_id = $1 AND ordinal > $2 ORDER BY ordinal LIMIT $3"
        }
        InventoryPageDomain::PendingWelcomes => {
            "SELECT ordinal,item_key_bytes,payload_bytes,payload_sha256 FROM chat.inventory_welcome_items WHERE inventory_session_id = $1 AND ordinal > $2 ORDER BY ordinal LIMIT $3"
        }
        InventoryPageDomain::LeafRecovery => {
            "SELECT ordinal,item_key_bytes,payload_bytes,payload_sha256 FROM chat.inventory_recovery_items WHERE inventory_session_id = $1 AND ordinal > $2 ORDER BY ordinal LIMIT $3"
        }
    };
    Ok(sqlx::query_as(sql)
        .bind(inventory_session_id)
        .bind(last_ordinal)
        .bind(limit)
        .fetch_all(&mut **transaction)
        .await?)
}

async fn read_materialization_digest(
    transaction: &mut Transaction<'_, Postgres>,
    domain: InventoryPageDomain,
    inventory_session_id: Uuid,
) -> Result<InventoryMaterializationDigestRow, InventoryRepositoryError> {
    let sql = match domain {
        InventoryPageDomain::Conversations => {
            r#"
            SELECT count(*) AS item_count, min(ordinal) AS minimum_ordinal,
                   max(ordinal) AS maximum_ordinal,
                   digest(COALESCE(string_agg(
                       int8send(ordinal) || uuid_send(conversation_id)
                       || item_key_bytes || payload_sha256,
                       decode('', 'hex') ORDER BY ordinal
                   ), decode('', 'hex')), 'sha256') AS items_sha256
              FROM chat.inventory_conversation_items
             WHERE inventory_session_id = $1
            "#
        }
        InventoryPageDomain::PendingWelcomes => {
            r#"
            SELECT count(*) AS item_count, min(ordinal) AS minimum_ordinal,
                   max(ordinal) AS maximum_ordinal,
                   digest(COALESCE(string_agg(
                       int8send(ordinal) || uuid_send(welcome_id)
                       || item_key_bytes || payload_sha256,
                       decode('', 'hex') ORDER BY ordinal
                   ), decode('', 'hex')), 'sha256') AS items_sha256
              FROM chat.inventory_welcome_items
             WHERE inventory_session_id = $1
            "#
        }
        InventoryPageDomain::LeafRecovery => {
            r#"
            SELECT count(*) AS item_count, min(ordinal) AS minimum_ordinal,
                   max(ordinal) AS maximum_ordinal,
                   digest(COALESCE(string_agg(
                       int8send(ordinal) || item_key_bytes || payload_sha256,
                       decode('', 'hex') ORDER BY ordinal
                   ), decode('', 'hex')), 'sha256') AS items_sha256
              FROM chat.inventory_recovery_items
             WHERE inventory_session_id = $1
            "#
        }
    };
    Ok(sqlx::query_as(sql)
        .bind(inventory_session_id)
        .fetch_one(&mut **transaction)
        .await?)
}

fn validate_materialization_digest(
    row: InventoryMaterializationDigestRow,
) -> Result<(u64, [u8; 32]), InventoryRepositoryError> {
    let item_count = database_protocol_integer(row.item_count)
        .map_err(|_| InventoryRepositoryError::InvalidMaterialization)?;
    let items_sha256 = fixed_hash(row.items_sha256)
        .map_err(|_| InventoryRepositoryError::InvalidMaterialization)?;
    let shape_valid = if item_count == 0 {
        row.minimum_ordinal.is_none() && row.maximum_ordinal.is_none()
    } else {
        row.minimum_ordinal == Some(0)
            && row.maximum_ordinal
                == Some(
                    i64::try_from(item_count - 1)
                        .map_err(|_| InventoryRepositoryError::InvalidMaterialization)?,
                )
    };
    if !shape_valid || items_sha256 == [0; 32] {
        return Err(InventoryRepositoryError::InvalidMaterialization);
    }
    Ok((item_count, items_sha256))
}

#[cfg(test)]
#[derive(Debug)]
pub(crate) struct InventorySessionLockFixture {
    pub(crate) transaction_id: String,
    pub(crate) inventory_session_id: Uuid,
    pub(crate) token_hash: [u8; 32],
    pub(crate) user_did: String,
    pub(crate) device_id: Uuid,
    pub(crate) jkt: Option<String>,
    pub(crate) auth_generation: u64,
    pub(crate) snapshot_event_position: u64,
    pub(crate) snapshot_event_cursor_bytes: Vec<u8>,
    pub(crate) snapshot_event_cursor_sha256: [u8; 32],
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) expires_at: DateTime<Utc>,
    pub(crate) conversations: InventoryCompletionEvidence,
    pub(crate) welcomes: InventoryCompletionEvidence,
    pub(crate) recovery: InventoryCompletionEvidence,
    pub(crate) device_status: String,
    pub(crate) current_dpop_jkt: Option<String>,
    pub(crate) current_auth_generation: u64,
    pub(crate) device_revoked_at: Option<DateTime<Utc>>,
    pub(crate) key_id: String,
    pub(crate) signing_public_key: [u8; 32],
    pub(crate) key_enrollment_auth_generation: u64,
    pub(crate) key_revoked_at: Option<DateTime<Utc>>,
    pub(crate) protocol_instance_id: Uuid,
    pub(crate) cursor_key_id: String,
    pub(crate) retained_floor: u64,
    pub(crate) retention_updated_at: DateTime<Utc>,
    pub(crate) head_event_position: u64,
    pub(crate) head_event_id: Option<Uuid>,
    pub(crate) head_payload_sha256: Option<[u8; 32]>,
    pub(crate) head_created_at: Option<DateTime<Utc>>,
    pub(crate) locked_at: DateTime<Utc>,
}

#[cfg(test)]
pub(crate) fn lock_inventory_session_for_test(
    codec: &CursorCodec,
    fixture: InventorySessionLockFixture,
) -> Result<LockedInventorySessionGuard, InventoryRepositoryError> {
    LockedInventorySessionGuard::from_locked_material(
        codec,
        InventorySessionLockMaterial {
            transaction_id: fixture.transaction_id,
            inventory_session_id: fixture.inventory_session_id,
            token_hash: fixture.token_hash,
            user_did: fixture.user_did,
            device_id: fixture.device_id,
            jkt: fixture.jkt,
            auth_generation: fixture.auth_generation,
            snapshot_event_position: fixture.snapshot_event_position,
            snapshot_event_cursor_bytes: fixture.snapshot_event_cursor_bytes,
            snapshot_event_cursor_sha256: fixture.snapshot_event_cursor_sha256,
            created_at: fixture.created_at,
            expires_at: fixture.expires_at,
            conversations: fixture.conversations,
            welcomes: fixture.welcomes,
            recovery: fixture.recovery,
            device_status: fixture.device_status,
            current_dpop_jkt: fixture.current_dpop_jkt,
            current_auth_generation: fixture.current_auth_generation,
            device_revoked_at: fixture.device_revoked_at,
            key_id: fixture.key_id,
            signing_public_key: fixture.signing_public_key,
            key_enrollment_auth_generation: fixture.key_enrollment_auth_generation,
            key_revoked_at: fixture.key_revoked_at,
            protocol_instance_id: fixture.protocol_instance_id,
            cursor_key_id: fixture.cursor_key_id,
            retained_floor: fixture.retained_floor,
            retention_updated_at: fixture.retention_updated_at,
            head_event_position: fixture.head_event_position,
            head_event_id: fixture.head_event_id,
            head_payload_sha256: fixture.head_payload_sha256,
            head_created_at: fixture.head_created_at,
            locked_at: fixture.locked_at,
        },
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn locked_inventory_session_digest(
    transaction_id: &str,
    inventory_session_id: Uuid,
    token_hash: &[u8; 32],
    user_did: &str,
    device_id: Uuid,
    jkt: Option<&str>,
    auth_generation: u64,
    snapshot_event_position: u64,
    snapshot_event_cursor_bytes: &[u8],
    snapshot_event_cursor_sha256: &[u8; 32],
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    conversations: InventoryCompletionEvidence,
    welcomes: InventoryCompletionEvidence,
    recovery: InventoryCompletionEvidence,
    active_key_id: &str,
    active_signing_public_key_sha256: &[u8; 32],
    key_enrollment_auth_generation: u64,
    protocol_instance_id: Uuid,
    cursor_key_id: &str,
    retained_floor: u64,
    retention_updated_at: DateTime<Utc>,
    head_event_position: u64,
    head_event_id: Option<Uuid>,
    head_payload_sha256: Option<[u8; 32]>,
    head_created_at: Option<DateTime<Utc>>,
    locked_at: DateTime<Utc>,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-LOCKED-INVENTORY-SESSION\0");
    update_text(&mut digest, transaction_id);
    digest.update(inventory_session_id.as_bytes());
    digest.update(token_hash);
    update_text(&mut digest, user_did);
    digest.update(device_id.as_bytes());
    update_text(&mut digest, jkt.unwrap_or_default());
    digest.update(auth_generation.to_be_bytes());
    digest.update(snapshot_event_position.to_be_bytes());
    update_bytes(&mut digest, snapshot_event_cursor_bytes);
    digest.update(snapshot_event_cursor_sha256);
    update_datetime(&mut digest, created_at);
    update_datetime(&mut digest, expires_at);
    update_completion(&mut digest, conversations);
    update_completion(&mut digest, welcomes);
    update_completion(&mut digest, recovery);
    update_text(&mut digest, active_key_id);
    digest.update(active_signing_public_key_sha256);
    digest.update(key_enrollment_auth_generation.to_be_bytes());
    digest.update(protocol_instance_id.as_bytes());
    update_text(&mut digest, cursor_key_id);
    digest.update(retained_floor.to_be_bytes());
    update_datetime(&mut digest, retention_updated_at);
    digest.update(head_event_position.to_be_bytes());
    update_optional_uuid(&mut digest, head_event_id);
    update_optional_hash(&mut digest, head_payload_sha256);
    update_optional_datetime(&mut digest, head_created_at);
    update_datetime(&mut digest, locked_at);
    digest.finalize().into()
}

fn update_text(digest: &mut Sha256, value: &str) {
    update_bytes(digest, value.as_bytes());
}

fn update_bytes(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

fn update_datetime(digest: &mut Sha256, value: DateTime<Utc>) {
    digest.update(value.timestamp_micros().to_be_bytes());
}

fn update_completion(digest: &mut Sha256, evidence: InventoryCompletionEvidence) {
    digest.update([u8::from(evidence.complete)]);
    match evidence.item_count {
        Some(count) => {
            digest.update([1]);
            digest.update(count.to_be_bytes());
        }
        None => digest.update([0]),
    }
    update_optional_hash(digest, evidence.items_sha256);
}

fn update_optional_uuid(digest: &mut Sha256, value: Option<Uuid>) {
    match value {
        Some(value) => {
            digest.update([1]);
            digest.update(value.as_bytes());
        }
        None => digest.update([0]),
    }
}

fn update_optional_hash(digest: &mut Sha256, value: Option<[u8; 32]>) {
    match value {
        Some(value) => {
            digest.update([1]);
            digest.update(value);
        }
        None => digest.update([0]),
    }
}

fn update_optional_datetime(digest: &mut Sha256, value: Option<DateTime<Utc>>) {
    match value {
        Some(value) => {
            digest.update([1]);
            update_datetime(digest, value);
        }
        None => digest.update([0]),
    }
}

fn database_protocol_integer(value: i64) -> Result<u64, ()> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value <= MAX_PROTOCOL_INTEGER)
        .ok_or(())
}

fn fixed_hash(value: Vec<u8>) -> Result<[u8; 32], ()> {
    value.try_into().map_err(|_| ())
}

fn unix_seconds(value: DateTime<Utc>) -> Option<u64> {
    if value.timestamp_subsec_nanos() != 0 {
        return None;
    }
    u64::try_from(value.timestamp())
        .ok()
        .filter(|value| *value <= MAX_PROTOCOL_INTEGER)
}

fn canonical_transaction_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 20
        && value.as_bytes()[0] != b'0'
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<u64>().is_ok_and(|value| value > 0)
}

fn uuid_is_canonical_v4(value: Uuid) -> bool {
    value.get_variant() == Variant::RFC4122 && value.get_version() == Some(Version::Random)
}

// ===========================================================================
// getDevices — the bounded, fenceless multi-DID active-device query (Slice 4b).
//
// This is the ordinary directory read (`getDevices`), NOT `getOwnDevices` (which
// uses the separate `device_inventory_*` as-of fence). It is deliberately
// bounded structurally: at most `MAX_GET_DEVICES_DIDS` requested DIDs, at most
// `MAX_DEVICES_PER_DID` active devices returned per DID, and therefore at most
// `MAX_GET_DEVICES_TOTAL` rows in one response. The per-DID cap is applied in SQL
// by a `ROW_NUMBER()` window so a DID that (transiently) exceeds the schema's
// 20-active-device ceiling still returns a bounded page rather than an unbounded
// scan.
// ===========================================================================

/// The maximum number of DIDs one `getDevices` call may name.
pub(crate) const MAX_GET_DEVICES_DIDS: usize = 5;
/// The maximum active devices returned for any one DID.
pub(crate) const MAX_DEVICES_PER_DID: i64 = 20;
/// The maximum total devices in one bounded `getDevices` response
/// (`MAX_GET_DEVICES_DIDS * MAX_DEVICES_PER_DID`).
pub(crate) const MAX_GET_DEVICES_TOTAL: usize = 100;

/// One active device as returned by `getDevices`. Carries the addressable device
/// identity columns; the wire `deviceView` shaping (and any capability
/// projection) is a later adapter concern.
#[derive(Clone, Debug, sqlx::FromRow)]
pub(crate) struct DeviceView {
    pub(crate) user_did: String,
    pub(crate) device_id: Uuid,
    pub(crate) device_name: String,
    pub(crate) status: String,
    pub(crate) dpop_jkt: Option<String>,
    pub(crate) auth_generation: i64,
    pub(crate) created_at: DateTime<Utc>,
}

/// Return every ACTIVE, non-revoked device for the requested DIDs, bounded to at
/// most `MAX_DEVICES_PER_DID` per DID and `MAX_GET_DEVICES_TOTAL` overall. The
/// caller must name between one and `MAX_GET_DEVICES_DIDS` DIDs (a duplicate DID
/// counts once against the bound after de-duplication is the caller's concern;
/// this read rejects a request that names too many or zero DIDs). Ordering is
/// canonical `(user_did, created_at, device_id)` so the bounded page is
/// deterministic.
pub(crate) async fn get_devices(
    transaction: &mut Transaction<'_, Postgres>,
    dids: &[String],
) -> Result<Vec<DeviceView>, InventoryRepositoryError> {
    if dids.is_empty() || dids.len() > MAX_GET_DEVICES_DIDS {
        return Err(InventoryRepositoryError::RequestTooBroad);
    }

    let rows = sqlx::query_as::<_, DeviceView>(
        r#"
        SELECT user_did, device_id, device_name, status, dpop_jkt, auth_generation, created_at
          FROM (
            SELECT device.user_did,
                   device.device_id,
                   device.device_name,
                   device.status,
                   device.dpop_jkt,
                   device.auth_generation,
                   device.created_at,
                   ROW_NUMBER() OVER (
                       PARTITION BY device.user_did
                       ORDER BY device.created_at, device.device_id
                   ) AS rn
              FROM chat.devices device
             WHERE device.user_did = ANY($1)
               AND device.status = 'active'
               AND device.revoked_at IS NULL
          ) bounded
         WHERE bounded.rn <= $2
         ORDER BY bounded.user_did, bounded.created_at, bounded.device_id
        "#,
    )
    .bind(dids)
    .bind(MAX_DEVICES_PER_DID)
    .fetch_all(&mut **transaction)
    .await?;

    // The `<= MAX_GET_DEVICES_DIDS` DID bound and the per-DID `ROW_NUMBER()` cap of
    // `MAX_DEVICES_PER_DID` structurally bound the response to `MAX_GET_DEVICES_TOTAL`
    // rows. Assert that invariant defensively: an over-count could only come from a
    // schema/window regression, and a directory read must never return an unbounded
    // page.
    if rows.len() > MAX_GET_DEVICES_TOTAL {
        return Err(InventoryRepositoryError::RequestTooBroad);
    }

    Ok(rows)
}

// ===========================================================================
// getConversations session CREATE + materialize (D-2: opaque capability core).
//
// The first `getConversations` call creates ONE retained inventory session under
// ONE captured event fence (the `chat.protocol_instances` singleton position, the
// current `chat.events` head, and the `chat.event_retention` floor) and
// materializes the three shared audience domains (conversations, pending
// Welcomes, recovery) into their per-session item tables with canonical ordinals
// `0..count-1`, then records per-domain completion evidence (count + digest +
// payload bytes exactly as the deferred `assert_inventory_materialization`
// trigger recomputes). Page reads and ticket mint consume the session this
// function produces.
//
// The caller supplies NO payload bytes, NO echoed ids, and NO raw identity: the
// verified `LockedReadDeviceAuthority` from the B-read guard is the identity,
// the C1 typed loaders derive every durable source row under the captured
// fence, the C1 projections build the generated DTOs, and the canonical v1
// encoder produces the retained payload bytes exactly once per item. The
// session capability is a single 32-byte random capability (43-character
// base64url) that is BOTH the presented `inventory_session_id` and the
// presented snapshot event cursor; only its SHA-256 is persisted (`token_hash`
// and `snapshot_event_cursor_sha256`), and the plaintext is sealed at rest as a
// 12-byte nonce + ciphertext pair under the active database-pinned cursor key.
// ===========================================================================

/// The durable identity of a freshly created inventory session, echoing the
/// captured fence and the capability stack. `inventory_session_token` is the
/// 43-character base64url session/event-cursor capability the client re-presents
/// on every page and to the ticket mint; `snapshot_event_cursor_bytes` is the
/// same capability's raw 32 bytes. Neither is persisted (only the SHA-256
/// lookup hash and the sealed nonce/ciphertext pair live at rest).
#[cfg(not(test))]
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct CreatedInventorySession {
    pub(crate) inventory_session_id: Uuid,
    pub(crate) inventory_session_token: String,
    pub(crate) snapshot_event_position: u64,
    pub(crate) snapshot_event_cursor_bytes: Vec<u8>,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) expires_at: DateTime<Utc>,
    pub(crate) conversation_item_count: u64,
    pub(crate) welcome_item_count: u64,
    pub(crate) recovery_item_count: u64,
}

/// Redacted `Debug`: the capability plaintext (`inventory_session_token` and
/// `snapshot_event_cursor_bytes`) never appears in `Debug` output.
#[cfg(not(test))]
impl std::fmt::Debug for CreatedInventorySession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CreatedInventorySession")
            .field("inventory_session_id", &self.inventory_session_id)
            .field("inventory_session_token", &"REDACTED")
            .field("snapshot_event_position", &self.snapshot_event_position)
            .field("snapshot_event_cursor_bytes", &"REDACTED")
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("conversation_item_count", &self.conversation_item_count)
            .field("welcome_item_count", &self.welcome_item_count)
            .field("recovery_item_count", &self.recovery_item_count)
            .finish()
    }
}

/// The creation-time request: the deterministic session identity (the facade
/// derives it from the verified device coordinates) plus the repository-owned
/// whole-second lifetime window. No caller identity, generation, or payload
/// bytes cross this boundary.
#[cfg(not(test))]
#[derive(Clone, Debug)]
pub(crate) struct CreateInventorySessionRequest {
    pub(crate) inventory_session_id: Uuid,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) expires_at: DateTime<Utc>,
}

/// Create one retained inventory session under one captured event fence and
/// materialize + complete its three shared domains in the same transaction.
///
/// The event fence is snapshotted at the current `chat.events` head (an empty log
/// snapshots at position 0). The session capability is a single random 32-byte
/// capability minted here and sealed at rest (12-byte nonce + ciphertext) with
/// `SealerBinding::for_event_cursor_receipt` under the active database-pinned
/// cursor key; only its SHA-256 is persisted (`token_hash` and
/// `snapshot_event_cursor_sha256`). `legacy_cursor_invalidated_at` stays NULL,
/// all three materialization `*_complete` proofs are proven true, and all three
/// client `*_consumed` proofs start false. After inserting the item rows with
/// canonical ordinals `0..count-1` and recording each domain's completion
/// evidence, the deferred `assert_inventory_materialization` and
/// `assert_inventory_session_identity` triggers are forced IMMEDIATE so a
/// malformed materialization or a stale device authority fails here rather than
/// at COMMIT.
///
/// The identity comes from the consumed `LockedReadDeviceAuthority` (the B-read
/// guard), never from caller bytes; the materialization is selected by the
/// loader seam -> `verify_inventory_fence` -> `inventory_authorities` chain and
/// produced by the C1 typed loaders -> projections -> canonical encoder.
///
/// Retry contract: the device-scoped domain selections run through
/// `inventory_authorities` (conversation heads locked in ascending UUID order,
/// final protocol/key/head/floor revalidation inside the authorities), and the
/// captured event fence is re-validated immediately before the materialization
/// inserts. A fence that advanced returns the retryable `SnapshotConflict` with
/// zero durable residue (only the still-incomplete session row was written; it
/// rolls back). A caller that receives `SnapshotConflict` re-runs the whole
/// call.
///
/// Note (r12 minor #4): `SET CONSTRAINTS … IMMEDIATE` changes the named deferred
/// constraints to immediate for the REMAINDER of the enclosing transaction, not
/// just for the statements this function issues. That is correct for the
/// terminal create path (it is the last mutation in its transaction), but any
/// future caller that composes further deferred work after
/// `create_inventory_session` in the same transaction must account for the
/// constraints already being immediate (or re-defer them explicitly).
#[cfg(not(test))]
pub(crate) async fn create_inventory_session(
    transaction: &mut Transaction<'_, Postgres>,
    device: super::super::read_authority::LockedReadDeviceAuthority,
    request: CreateInventorySessionRequest,
    sealer: &CursorSealer,
    random: &mut (dyn SecureRandom + Send),
) -> Result<CreatedInventorySession, InventoryRepositoryError> {
    let created_at = request.created_at;
    let expires_at = request.expires_at;
    if unix_seconds(created_at).is_none()
        || unix_seconds(expires_at).is_none()
        || created_at >= expires_at
        || !uuid_is_canonical_v4(request.inventory_session_id)
    {
        return Err(InventoryRepositoryError::DurableRowInvalid);
    }
    // The verified device coordinates are the identity; copy them out before the
    // device is consumed by the fence verification below.
    let user_did = device.user_did().to_owned();
    let device_id = device.device_id();
    let jkt = device.jkt().map(str::to_owned);
    let auth_generation = device.auth_generation();

    // 1. Capture + lock the event fence: the protocol singleton, the retention
    //    floor, and the current events head. Snapshot the session at the head.
    let protocol: ProtocolInstanceRow = sqlx::query_as(
        r#"
        SELECT protocol_instance_id, cursor_key_id
          FROM chat.protocol_instances
         WHERE singleton = TRUE
         FOR UPDATE
        "#,
    )
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(InventoryRepositoryError::ProtocolFenceMismatch)?;

    let retention: EventRetentionRow = sqlx::query_as(
        r#"
        SELECT retained_floor, updated_at AS retention_updated_at
          FROM chat.event_retention
         WHERE protocol_instance_id = $1
         FOR UPDATE
        "#,
    )
    .bind(protocol.protocol_instance_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(InventoryRepositoryError::ProtocolFenceMismatch)?;

    let head: Option<HeadEventRow> = sqlx::query_as(
        r#"
        SELECT event_position AS head_event_position,
               event_id AS head_event_id,
               payload_sha256 AS head_payload_sha256,
               created_at AS head_created_at
          FROM chat.events
         WHERE protocol_instance_id = $1
         ORDER BY event_position DESC
         LIMIT 1
         FOR UPDATE
        "#,
    )
    .bind(protocol.protocol_instance_id)
    .fetch_optional(&mut **transaction)
    .await?;

    let retained_floor = database_protocol_integer(retention.retained_floor)
        .map_err(|_| InventoryRepositoryError::ProtocolFenceMismatch)?;
    let head_event_position = match head {
        Some(head) => database_protocol_integer(head.head_event_position)
            .map_err(|_| InventoryRepositoryError::ProtocolFenceMismatch)?,
        None => 0,
    };
    if retained_floor > head_event_position {
        return Err(InventoryRepositoryError::ProtocolFenceMismatch);
    }
    let snapshot_event_position = head_event_position;

    // 2. Mint the random session/event-cursor capability and seal it at rest.
    //    The plaintext exists only in this stack frame; the durable lookup hash
    //    is its SHA-256 and the durable seal is the nonce/ciphertext pair. The
    //    binding is the event-cursor-receipt shape (no predecessor, no envelope
    //    hash) derived from the session row's own columns.
    let capability =
        mint_capability_token(random).map_err(InventoryRepositoryError::SecureRandom)?;
    let capability_hash = capability.lookup_hash();
    let event_cursor_binding = SealerBinding::for_event_cursor_receipt(
        request.inventory_session_id,
        user_did.as_bytes(),
        device_id,
        jkt.as_deref().unwrap_or("").as_bytes(),
        auth_generation,
        protocol.protocol_instance_id,
        protocol.cursor_key_id.as_bytes(),
        snapshot_event_position,
        None,
        retained_floor,
        unix_seconds(created_at).ok_or(InventoryRepositoryError::DurableRowInvalid)?,
        unix_seconds(expires_at).ok_or(InventoryRepositoryError::DurableRowInvalid)?,
    )
    .map_err(InventoryRepositoryError::Sealer)?;
    let sealed_cursor = sealer
        .seal_successor(capability.as_bytes(), &event_cursor_binding, random)
        .map_err(InventoryRepositoryError::Sealer)?;

    // 3. Insert the session with all domains INCOMPLETE and all *_consumed
    //    FALSE first, so every item FK (including the recipient composite FK on
    //    the owner identity) resolves before completion evidence is recorded.
    //    `legacy_cursor_invalidated_at` stays NULL: the G7 binding check
    //    requires the sealed-cursor arm for a live session.
    sqlx::query(
        r#"
        INSERT INTO chat.inventory_sessions(
            inventory_session_id, token_hash, user_did, device_id, jkt,
            auth_generation, snapshot_event_position, snapshot_event_cursor_sha256,
            created_at, expires_at, protocol_instance_id, cursor_key_id,
            cursor_format_version, snapshot_retained_floor,
            snapshot_event_cursor_nonce, snapshot_event_cursor_ciphertext,
            conversations_complete, welcomes_complete, recovery_complete,
            conversations_consumed, welcomes_consumed, recovery_consumed
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,1,$13,$14,$15,
                  FALSE,FALSE,FALSE,FALSE,FALSE,FALSE)
        "#,
    )
    .bind(request.inventory_session_id)
    .bind(capability_hash.as_slice())
    .bind(&user_did)
    .bind(device_id)
    .bind(jkt.as_deref())
    .bind(i64::try_from(auth_generation).map_err(|_| InventoryRepositoryError::DurableRowInvalid)?)
    .bind(
        i64::try_from(snapshot_event_position)
            .map_err(|_| InventoryRepositoryError::DurableRowInvalid)?,
    )
    .bind(capability_hash.as_slice())
    .bind(created_at)
    .bind(expires_at)
    .bind(protocol.protocol_instance_id)
    .bind(&protocol.cursor_key_id)
    .bind(i64::try_from(retained_floor).map_err(|_| InventoryRepositoryError::DurableRowInvalid)?)
    .bind(&sealed_cursor.nonce)
    .bind(&sealed_cursor.ciphertext)
    .execute(&mut **transaction)
    .await?;

    // 4. The durable-row loader seam over the just-inserted row, then the fence
    //    verification (which consumes the device) and the conversation
    //    authorities that select the materialization.
    let locked_row = lock_inventory_session_row(transaction, request.inventory_session_id)
        .await?
        .ok_or(InventoryRepositoryError::DurableRowInvalid)?;
    let fence = verify_locked_inventory_fence(transaction, device, &locked_row).await?;
    let authorities = super::super::read_authority::inventory_authorities(transaction, fence)
        .await
        .map_err(InventoryRepositoryError::ReadAuthority)?;

    // 5. Optimistic fence re-validation (ratified 2026-07-24 locking ruling),
    //    extended to run ONCE after the authorities derivation and immediately
    //    before the materialization inserts. If the head moved, a
    //    selection-affecting mutation may have interleaved, so fail with the
    //    retryable `SnapshotConflict` (the transaction has written only the
    //    still-incomplete session row, which rolls back with zero residue — the
    //    caller re-runs the whole create).
    let revalidated_head: Option<i64> = sqlx::query_scalar(
        r#"
        SELECT max(event_position)
          FROM chat.events
         WHERE protocol_instance_id = $1
        "#,
    )
    .bind(protocol.protocol_instance_id)
    .fetch_one(&mut **transaction)
    .await?;
    let revalidated_head = match revalidated_head {
        Some(position) => database_protocol_integer(position)
            .map_err(|_| InventoryRepositoryError::ProtocolFenceMismatch)?,
        None => 0,
    };
    if revalidated_head != snapshot_event_position {
        return Err(InventoryRepositoryError::SnapshotConflict);
    }

    // 6. Materialize each domain from the C1 typed loaders -> projections ->
    //    canonical encoder, encoding every item EXACTLY ONCE and retaining the
    //    canonical bytes as the item payloads.
    //
    // 6a. Conversation domain: one item per authority, in ascending
    //     conversation_id order, with the exact arm-provenance columns the
    //     source-precedence trigger and the materialization digest transcript
    //     require.
    let mut conversation_ordinal: i64 = 0;
    for authority in authorities.iter() {
        let source =
            conversation_projection_source(transaction, authority, &user_did, device_id).await?;
        let dto = super::super::read_projection::conversation_inventory_item(&source)
            .map_err(InventoryRepositoryError::Projection)?;
        let canonical = super::super::read_projection::encode_canonical_generated_chat_json_v1(
            &dto,
            "blue.catbird.chat.defs#conversationInventoryItem",
        )
        .map_err(InventoryRepositoryError::Projection)?;
        let payload_sha256 = canonical.sha256();
        let arm_columns =
            conversation_arm_columns(transaction, authority, &user_did, device_id).await?;
        sqlx::query(
            r#"
            INSERT INTO chat.inventory_conversation_items(
                inventory_session_id, ordinal, conversation_id, recipient_did,
                recipient_device_id, item_kind, participant_period_id,
                membership_interval_id, interval_terminal_seq,
                interval_closing_transition_id,
                interval_closing_outer_entry_fingerprint, interval_removed_at,
                schedule_terminal_seq, schedule_terminal_transition_id,
                schedule_terminal_outer_entry_fingerprint,
                item_key_bytes, payload_bytes, payload_sha256
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,
                      uuid_send($3),$16,$17)
            "#,
        )
        .bind(request.inventory_session_id)
        .bind(conversation_ordinal)
        .bind(authority.conversation_id())
        .bind(&user_did)
        .bind(device_id)
        .bind(arm_columns.item_kind)
        .bind(arm_columns.participant_period_id)
        .bind(arm_columns.membership_interval_id)
        .bind(arm_columns.interval_terminal_seq)
        .bind(arm_columns.interval_closing_transition_id)
        .bind(arm_columns.interval_closing_outer_entry_fingerprint)
        .bind(arm_columns.interval_removed_at)
        .bind(arm_columns.schedule_terminal_seq)
        .bind(arm_columns.schedule_terminal_transition_id)
        .bind(arm_columns.schedule_terminal_outer_entry_fingerprint)
        .bind(canonical.bytes())
        .bind(payload_sha256.as_slice())
        .execute(&mut **transaction)
        .await?;
        conversation_ordinal += 1;
    }

    // 6b. Welcome domain — the exact device's `status='pending'` deliveries,
    //     payload server-derived from `welcome_bundles.wrapper_bytes`. Ordinals
    //     ascend by `welcome_id`.
    let welcome_sources = retained_welcome_sources(transaction, &user_did, device_id).await?;
    for (ordinal, (welcome_id, source)) in welcome_sources.iter().enumerate() {
        let ordinal =
            i64::try_from(ordinal).map_err(|_| InventoryRepositoryError::InvalidMaterialization)?;
        let dto = super::super::read_projection::welcome_view(source)
            .map_err(InventoryRepositoryError::Projection)?;
        let canonical = super::super::read_projection::encode_canonical_generated_chat_json_v1(
            &dto,
            "blue.catbird.chat.defs#welcomeView",
        )
        .map_err(InventoryRepositoryError::Projection)?;
        let payload_sha256 = canonical.sha256();
        sqlx::query(
            r#"
            INSERT INTO chat.inventory_welcome_items(
                inventory_session_id, ordinal, welcome_id, recipient_did,
                recipient_device_id, item_key_bytes, payload_bytes, payload_sha256
            ) VALUES ($1,$2,$3,$4,$5,uuid_send($3),$6,$7)
            "#,
        )
        .bind(request.inventory_session_id)
        .bind(ordinal)
        .bind(*welcome_id)
        .bind(&user_did)
        .bind(device_id)
        .bind(canonical.bytes())
        .bind(payload_sha256.as_slice())
        .execute(&mut **transaction)
        .await?;
    }

    // 6c. Recovery domain — every retained leaf-recovery request (all five
    //     statuses) then every retained recovery-work item (all three statuses),
    //     one canonical ordinal sequence with 0x00/0x01-prefixed item keys.
    let recovery_entries =
        retained_recovery_inbox_entries(transaction, &user_did, device_id).await?;
    let mut recovery_ordinal: i64 = 0;
    for entry in recovery_entries {
        let dto = super::super::read_projection::leaf_recovery_inbox_item(entry.input)
            .map_err(InventoryRepositoryError::Projection)?;
        let canonical = super::super::read_projection::encode_canonical_generated_chat_json_v1(
            &dto,
            "blue.catbird.chat.defs#leafRecoveryInboxItem",
        )
        .map_err(InventoryRepositoryError::Projection)?;
        let payload_sha256 = canonical.sha256();
        sqlx::query(
            r#"
            INSERT INTO chat.inventory_recovery_items(
                inventory_session_id, ordinal, item_kind, leaf_recovery_request_id,
                recovery_work_id, recipient_did, recipient_device_id,
                item_key_bytes, payload_bytes, payload_sha256
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
            "#,
        )
        .bind(request.inventory_session_id)
        .bind(recovery_ordinal)
        .bind(entry.item_kind)
        .bind(entry.leaf_recovery_request_id)
        .bind(entry.recovery_work_id)
        .bind(&user_did)
        .bind(device_id)
        .bind(&entry.item_key_bytes)
        .bind(canonical.bytes())
        .bind(payload_sha256.as_slice())
        .execute(&mut **transaction)
        .await?;
        recovery_ordinal += 1;
    }

    // 7. Record per-domain completion evidence from the exact projection the
    //    materialization trigger recomputes (the G7 aggregate transcript
    //    including item kind, arm provenance, and payload byte length), then
    //    mark each domain complete. A single-transaction full snapshot completes
    //    every domain here.
    let (conversation_item_count, conversation_hash, conversation_payload_bytes) =
        read_g7_materialization_digest(
            transaction,
            InventoryPageDomain::Conversations,
            request.inventory_session_id,
        )
        .await?;
    let (welcome_item_count, welcome_hash, welcome_payload_bytes) = read_g7_materialization_digest(
        transaction,
        InventoryPageDomain::PendingWelcomes,
        request.inventory_session_id,
    )
    .await?;
    let (recovery_item_count, recovery_hash, recovery_payload_bytes) =
        read_g7_materialization_digest(
            transaction,
            InventoryPageDomain::LeafRecovery,
            request.inventory_session_id,
        )
        .await?;

    sqlx::query(
        r#"
        UPDATE chat.inventory_sessions
           SET conversations_complete = TRUE,
               conversation_item_count = $2, conversation_items_sha256 = $3,
               conversation_payload_bytes = $4,
               welcomes_complete = TRUE,
               welcome_item_count = $5, welcome_items_sha256 = $6,
               welcome_payload_bytes = $7,
               recovery_complete = TRUE,
               recovery_item_count = $8, recovery_items_sha256 = $9,
               recovery_payload_bytes = $10
         WHERE inventory_session_id = $1
        "#,
    )
    .bind(request.inventory_session_id)
    .bind(
        i64::try_from(conversation_item_count)
            .map_err(|_| InventoryRepositoryError::InvalidMaterialization)?,
    )
    .bind(conversation_hash.as_slice())
    .bind(
        i64::try_from(conversation_payload_bytes)
            .map_err(|_| InventoryRepositoryError::InvalidMaterialization)?,
    )
    .bind(
        i64::try_from(welcome_item_count)
            .map_err(|_| InventoryRepositoryError::InvalidMaterialization)?,
    )
    .bind(welcome_hash.as_slice())
    .bind(
        i64::try_from(welcome_payload_bytes)
            .map_err(|_| InventoryRepositoryError::InvalidMaterialization)?,
    )
    .bind(
        i64::try_from(recovery_item_count)
            .map_err(|_| InventoryRepositoryError::InvalidMaterialization)?,
    )
    .bind(recovery_hash.as_slice())
    .bind(
        i64::try_from(recovery_payload_bytes)
            .map_err(|_| InventoryRepositoryError::InvalidMaterialization)?,
    )
    .execute(&mut **transaction)
    .await?;

    // 8. Force the deferred session-level triggers IMMEDIATE so a materialization
    //    or authentication-identity mismatch surfaces as this call's error, not a
    //    detached COMMIT failure. (Item-level deferred source FKs still resolve at
    //    COMMIT; the materialization trigger already re-checks recipient + proof
    //    binding here.)
    sqlx::query(
        "SET CONSTRAINTS chat.inventory_sessions_materialization_deferred, \
         chat.inventory_sessions_auth_identity_deferred IMMEDIATE",
    )
    .execute(&mut **transaction)
    .await?;

    Ok(CreatedInventorySession {
        inventory_session_id: request.inventory_session_id,
        inventory_session_token: capability.encode(),
        snapshot_event_position,
        snapshot_event_cursor_bytes: capability.as_bytes().to_vec(),
        created_at,
        expires_at,
        conversation_item_count,
        welcome_item_count,
        recovery_item_count,
    })
}

// ===========================================================================
// getOwnDevices session CREATE + materialize (the SEPARATE device fence).
//
// `getOwnDevices` is a distinct retained fence over `chat.device_inventory_
// sessions` / `chat.device_inventory_items`: it snapshots the authenticated
// principal's OWN device directory as of a `fence_revision`, and it NEVER
// substitutes for the shared conversation/Welcome/recovery inventory session.
// Unlike that session it carries no event cursor and no HMAC token — the session
// UUID is its own identity — so this CREATE is the closed transaction that inserts
// the fence row, materializes one item per described subject device (each item's
// recipient is the requester principal's own subject device, per the table's
// principal-binding CHECK), records the completion evidence the deferred
// `assert_device_inventory_materialization` trigger recomputes, and forces that
// trigger + the principal-boundary trigger IMMEDIATE. The `fence_revision` and the
// selection/encoding of the subject rows are the Task 4 handler's inputs; the
// subject devices must already exist and belong to the requester's principal.
// ===========================================================================

/// One own-device snapshot item: a subject device of the requester's principal
/// and its caller-encoded canonical view.
#[derive(Clone, Debug)]
pub(crate) struct DeviceInventorySubject {
    pub(crate) subject_device_id: Uuid,
    pub(crate) payload_bytes: Vec<u8>,
}

/// The authenticated identity + device fence + materialized own-device contents
/// for a `create_device_inventory_session` call.
#[derive(Clone, Debug)]
pub(crate) struct CreateDeviceInventorySessionRequest<'a> {
    pub(crate) device_inventory_session_id: Uuid,
    pub(crate) user_did: &'a str,
    pub(crate) device_id: Uuid,
    pub(crate) jkt: Option<&'a str>,
    pub(crate) auth_generation: u64,
    pub(crate) fence_revision: u64,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) expires_at: DateTime<Utc>,
    pub(crate) subjects: Vec<DeviceInventorySubject>,
}

/// The identity of a freshly created own-device inventory session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CreatedDeviceInventorySession {
    pub(crate) device_inventory_session_id: Uuid,
    pub(crate) fence_revision: u64,
    pub(crate) item_count: u64,
}

/// Create one retained own-device inventory session at `fence_revision` and
/// materialize + complete its subject-device items in the same transaction. The
/// requester device authority is validated up-front and re-checked by the
/// deferred principal/materialization triggers forced IMMEDIATE at the end.
pub(crate) async fn create_device_inventory_session(
    transaction: &mut Transaction<'_, Postgres>,
    request: CreateDeviceInventorySessionRequest<'_>,
) -> Result<CreatedDeviceInventorySession, InventoryRepositoryError> {
    let issued_at =
        unix_seconds(request.created_at).ok_or(InventoryRepositoryError::DurableRowInvalid)?;
    let expires_at =
        unix_seconds(request.expires_at).ok_or(InventoryRepositoryError::DurableRowInvalid)?;
    if issued_at >= expires_at
        || !(1..=MAX_PROTOCOL_INTEGER).contains(&request.auth_generation)
        || request.fence_revision > MAX_PROTOCOL_INTEGER
        || !uuid_is_canonical_v4(request.device_inventory_session_id)
        || !uuid_is_canonical_v4(request.device_id)
    {
        return Err(InventoryRepositoryError::DurableRowInvalid);
    }

    // Lock + validate the requester device authority (mirrors the shared session
    // create; the deferred triggers re-check it at completion).
    let device: ActiveDeviceKeyRow = sqlx::query_as(
        r#"
        SELECT device.status AS device_status,
               device.dpop_jkt AS current_dpop_jkt,
               device.auth_generation AS current_auth_generation,
               device.revoked_at AS device_revoked_at,
               device_key.key_id,
               device_key.signing_public_key,
               device_key.enrollment_auth_generation AS key_enrollment_auth_generation,
               device_key.revoked_at AS key_revoked_at
          FROM chat.devices AS device
          JOIN chat.device_keys AS device_key
            ON device_key.user_did = device.user_did
           AND device_key.device_id = device.device_id
         WHERE device.user_did = $1
           AND device.device_id = $2
         FOR UPDATE OF device, device_key
        "#,
    )
    .bind(request.user_did)
    .bind(request.device_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(InventoryRepositoryError::DeviceAuthorityMismatch)?;

    if device.device_status != "active"
        || device.device_revoked_at.is_some()
        || device.key_revoked_at.is_some()
        || device.current_dpop_jkt.as_deref() != request.jkt
        || database_protocol_integer(device.current_auth_generation)
            .map_err(|_| InventoryRepositoryError::DeviceAuthorityMismatch)?
            != request.auth_generation
    {
        return Err(InventoryRepositoryError::DeviceAuthorityMismatch);
    }

    sqlx::query(
        r#"
        INSERT INTO chat.device_inventory_sessions(
            device_inventory_session_id, user_did, device_id, jkt, auth_generation,
            fence_revision, created_at, expires_at, complete
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,FALSE)
        "#,
    )
    .bind(request.device_inventory_session_id)
    .bind(request.user_did)
    .bind(request.device_id)
    .bind(request.jkt)
    .bind(
        i64::try_from(request.auth_generation)
            .map_err(|_| InventoryRepositoryError::DurableRowInvalid)?,
    )
    .bind(
        i64::try_from(request.fence_revision)
            .map_err(|_| InventoryRepositoryError::DurableRowInvalid)?,
    )
    .bind(request.created_at)
    .bind(request.expires_at)
    .execute(&mut **transaction)
    .await?;

    for (ordinal, subject) in request.subjects.iter().enumerate() {
        let ordinal =
            i64::try_from(ordinal).map_err(|_| InventoryRepositoryError::InvalidMaterialization)?;
        let payload_sha256: [u8; 32] = Sha256::digest(&subject.payload_bytes).into();
        sqlx::query(
            r#"
            INSERT INTO chat.device_inventory_items(
                device_inventory_session_id, ordinal, subject_device_id,
                requester_did, requester_device_id, recipient_did, recipient_device_id,
                payload_bytes, payload_sha256
            ) VALUES ($1,$2,$3,$4,$5,$4,$3,$6,$7)
            "#,
        )
        .bind(request.device_inventory_session_id)
        .bind(ordinal)
        .bind(subject.subject_device_id)
        .bind(request.user_did)
        .bind(request.device_id)
        .bind(&subject.payload_bytes)
        .bind(payload_sha256.as_slice())
        .execute(&mut **transaction)
        .await?;
    }

    // Completion evidence from the exact projection the device-materialization
    // trigger recomputes: int8send(ordinal) || uuid_send(subject_device_id) ||
    // payload_sha256, ordered by ordinal.
    let digest_row: InventoryMaterializationDigestRow = sqlx::query_as(
        r#"
        SELECT count(*) AS item_count, min(ordinal) AS minimum_ordinal,
               max(ordinal) AS maximum_ordinal,
               digest(COALESCE(string_agg(
                   int8send(ordinal) || uuid_send(subject_device_id) || payload_sha256,
                   decode('', 'hex') ORDER BY ordinal
               ), decode('', 'hex')), 'sha256') AS items_sha256
          FROM chat.device_inventory_items
         WHERE device_inventory_session_id = $1
        "#,
    )
    .bind(request.device_inventory_session_id)
    .fetch_one(&mut **transaction)
    .await?;
    let (item_count, items_sha256) = validate_materialization_digest(digest_row)?;

    sqlx::query(
        r#"
        UPDATE chat.device_inventory_sessions
           SET complete = TRUE, item_count = $2, items_sha256 = $3
         WHERE device_inventory_session_id = $1
        "#,
    )
    .bind(request.device_inventory_session_id)
    .bind(i64::try_from(item_count).map_err(|_| InventoryRepositoryError::InvalidMaterialization)?)
    .bind(items_sha256.to_vec())
    .execute(&mut **transaction)
    .await?;

    sqlx::query(
        "SET CONSTRAINTS chat.device_inventory_sessions_materialization_deferred, \
         chat.device_inventory_items_principal_deferred IMMEDIATE",
    )
    .execute(&mut **transaction)
    .await?;

    Ok(CreatedDeviceInventorySession {
        device_inventory_session_id: request.device_inventory_session_id,
        fence_revision: request.fence_revision,
        item_count,
    })
}

// ===========================================================================
// terminalSeq wake/navigation hint DTOs (brief 115, 325).
//
// A `terminalSeq` carried in a tombstone, event, inventory-summary, or
// interval-summary hint is wake/navigation data ONLY. Each of these DTOs exposes
// exactly its `terminal_seq` (and its addressing key) and deliberately carries NO
// outer-entry fingerprint: a hint never duplicates the outer-entry fingerprint,
// and a hint alone can neither close an interval nor schedule-terminalize one.
// The exact signed close row and the exact schedule-terminal proof remain
// fetchable only to the historical device at that seq (the retained inventory
// materialization above), never through a hint. These are pure carrier structs;
// they hold no authority and reference no proof.
// ===========================================================================

/// Tombstone hint: the terminal seq at which a conversation the device is being
/// woken about was closed. Carries no close proof and no outer fingerprint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TombstoneTerminalHint {
    pub(crate) conversation_id: Uuid,
    pub(crate) terminal_seq: u64,
}

/// Event hint: a navigation pointer to the terminal seq an event references.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EventTerminalHint {
    pub(crate) conversation_id: Uuid,
    pub(crate) terminal_seq: u64,
}

/// Inventory-summary hint: the terminal seq for a conversation summarized in an
/// inventory page. Wake/navigation only — the exact proof stays in the retained
/// per-device materialization, not this summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct InventorySummaryTerminalHint {
    pub(crate) conversation_id: Uuid,
    pub(crate) terminal_seq: u64,
}

/// Interval-summary hint: the terminal seq that closed (or already-closed) an
/// application interval a summary refers to. Carries no outer fingerprint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IntervalSummaryTerminalHint {
    pub(crate) conversation_id: Uuid,
    pub(crate) terminal_seq: u64,
}

// ===========================================================================
// B-auth: the two repository-owned existing-device READ facades.
//
// `getDevices` and `getOwnDevices` are the only two ordinary-unsigned read
// endpoints that spend a sealed `VerifiedReadAdmission`. Everything between the
// opaque admission and the canonical response bytes lives here: the ordered
// requester locks, the single production `from_repository_lock` callsite, the
// consuming attempt verification, the generated-DTO projection, the durable
// item serialization, and the sanitized facade error vocabulary. The two
// handlers are reduced to admission -> facade -> `context::json_ok`.
//
// WHY THIS WHOLE SECTION IS `#[cfg(not(test))]`
// ---------------------------------------------
// `inventory.rs` is `include!`d as a module by TEN integration test crates.
// Three of them provide NO `chat_protocol::dpop` module at all:
//
//     tests/chat_protocol_inventory.rs
//     tests/chat_protocol_cursor.rs
//     tests/chat_protocol_inventory_repository.rs
//
// (two of the three additionally provide no `device_directory`). An
// unconditional `use super::super::dpop::…` here therefore fails to resolve in
// those crates and breaks them. None of the three is owned by Stage T or by
// either B-auth implementer — they sit outside every owner set, so the break
// would be unfixable from inside this lane.
//
// The gate is the same mechanism `repository/mod.rs` already uses for `core`,
// `execution_context`, `relationship`, `reset`, `revocation`,
// `submit_transition`, and `welcome_terminal`: `cfg(test)` is set for an
// integration test crate (it is compiled with `--test`), but NOT for the
// library those crates link, so the facade is present in the real `catbird_server`
// lib and absent from every path-included copy. That is precisely the split the
// checklist's "exactly once IN PRODUCTION" requires.
//
// DO NOT "tidy" this gate away. Removing it breaks three unowned crates.
//
// Cost, recorded honestly: this section is invisible to `cargo test --lib` and
// `--all-targets`. Tests over it must go through the REAL library — the
// `chat_router` built from `catbird_server::handlers::chat` — or over the source
// text via `include_str!`, never through the path-included `mod inventory`.
// ===========================================================================

/// Retained own-device snapshot lifetime.
///
/// Relocated verbatim from the pre-B-auth `handlers/chat/get_own_devices.rs`
/// (`SESSION_TTL_MINUTES`), where the handler owned this derivation before the
/// authority moved the durable-session request inside the facade. The value is
/// preserved, not chosen: `chat.device_inventory_sessions_expiry_check` bounds
/// any session to `expires_at <= created_at + INTERVAL '15 minutes'`, so ten
/// minutes is the existing sealed policy well inside the schema ceiling.
///
/// The bound is repository-owned by construction: the admission seam hands the
/// facade only a base instant and accepts no caller TTL, expiry, or duration,
/// so no caller can manufacture a snapshot lifetime.
#[cfg(not(test))]
const OWN_DEVICE_SNAPSHOT_TTL_MINUTES: i64 = 10;

/// Sanitized facade failure. Every variant is a unit variant, so no `Debug`
/// rendering can carry requester DID, device, JKT, generation, key material,
/// replay identity, or transaction identity. Authority drift never appears as a
/// distinct variant: it collapses into `Invariant` exactly like every other
/// terminal condition, so the wire cannot distinguish "wrong JKT" from "wrong
/// generation" from "internal projection fault".
#[derive(Debug)]
pub(crate) enum ExistingDeviceReadFacadeError {
    /// A database fault. Carries no protocol vocabulary.
    Storage,
    /// Any terminal internal condition, including EVERY authority drift.
    Invariant,
    /// The caller named too many or zero DIDs (`getDevices` only).
    RequestTooBroad,
    /// The fixed three-attempt ceiling was reached (`getOwnDevices` only).
    /// The handler renders HTTP 503 + `Retry-After: 1`.
    RetryCeiling,
}

/// Consuming canonical `getDevices` response bytes. Private field, no item
/// getter, no cursor, no authority/admission/attempt/row/transaction handle, no
/// requester marker, and no mutable bytes reference: a handler can only move the
/// bytes into `context::json_ok`.
#[cfg(not(test))]
pub(crate) struct CanonicalGetDevicesResponse {
    response_bytes: Vec<u8>,
}

#[cfg(not(test))]
impl CanonicalGetDevicesResponse {
    pub(crate) fn into_response_bytes(self) -> Vec<u8> {
        self.response_bytes
    }
}

/// Consuming canonical `getOwnDevices` response bytes. Constructible only after
/// the durable session commit succeeds, so its mere existence is proof that no
/// bytes escaped before commit.
#[cfg(not(test))]
pub(crate) struct CommittedOwnDeviceSnapshot {
    response_bytes: Vec<u8>,
}

#[cfg(not(test))]
impl CommittedOwnDeviceSnapshot {
    pub(crate) fn into_response_bytes(self) -> Vec<u8> {
        self.response_bytes
    }
}

/// Lock the EXACT requester `chat.devices` row. Deliberately a single-table
/// statement: the device barrier must complete before the key statement is even
/// issued, and a joined `FOR UPDATE OF device, device_key` is not proof of that
/// order.
#[cfg(not(test))]
const LOCK_READ_REQUESTER_DEVICE_SQL: &str = r#"
    SELECT device.user_did,
           device.device_id,
           device.status,
           device.dpop_jkt,
           device.auth_generation
      FROM chat.devices AS device
     WHERE device.user_did = $1
       AND device.device_id = $2
     FOR UPDATE
"#;

/// Lock the EXACT requester `chat.device_keys` row, in a SEPARATE statement
/// issued only after the device lock above has already returned.
#[cfg(not(test))]
const LOCK_READ_REQUESTER_DEVICE_KEY_SQL: &str = r#"
    SELECT device_key.key_id,
           device_key.signing_public_key,
           device_key.revoked_at
      FROM chat.device_keys AS device_key
     WHERE device_key.user_did = $1
       AND device_key.device_id = $2
     FOR UPDATE
"#;

#[cfg(not(test))]
#[derive(FromRow)]
struct LockedReadRequesterDeviceRow {
    user_did: String,
    device_id: Uuid,
    status: String,
    dpop_jkt: Option<String>,
    auth_generation: i64,
}

#[cfg(not(test))]
#[derive(FromRow)]
struct LockedReadRequesterKeyRow {
    key_id: String,
    signing_public_key: Vec<u8>,
    revoked_at: Option<DateTime<Utc>>,
}

/// The verified requester lock for one attempt.
///
/// `verified` is the private same-transaction proof; it is never returned past
/// the facade. The remaining fields are ORDINARY SQL ROW VALUES read back from
/// the two locked rows and kept as facade locals. They are permitted to be bound
/// into an internal durable write after hidden verification succeeds, and they
/// are never returned to a handler or placed in a response.
#[cfg(not(test))]
struct VerifiedRequesterLock {
    transaction_id: String,
    verified: super::super::dpop::VerifiedExistingDeviceReadRow,
    row_user_did: String,
    row_device_id: Uuid,
    row_dpop_jkt: Option<String>,
    row_auth_generation: i64,
}

/// Begin one attempt: two ORDERED single-table `FOR UPDATE` statements, then the
/// single production `LockedReadDatabaseRow::from_repository_lock` callsite, then
/// the consuming attempt verification.
///
/// Ordering is structural, not documentary: the device lock is `await`ed and
/// matched before the key statement is constructed, and the constructor call is
/// unreachable unless BOTH `Some(..)` arms bind. A missing device row or a
/// missing key row returns BEFORE construction.
///
/// Every failure is terminal. Authority drift — inactive device, revoked key,
/// drifted JKT/generation/key — surfaces from `consume_verify_locked_row` and is
/// mapped to `Invariant`, never to a retryable outcome. A failed or foreign
/// transaction retains no authority: the attempt was consumed by value.
#[cfg(not(test))]
async fn lock_and_verify_read_requester(
    transaction: &mut Transaction<'_, Postgres>,
    attempt: super::super::dpop::ReadAdmissionAttempt,
) -> Result<VerifiedRequesterLock, ExistingDeviceReadFacadeError> {
    // The borrow of `attempt` is authority-bearing, not merely a lifetime
    // convenience: the carrier cannot outlive the attempt, so the lock
    // coordinates cannot escape this operation. Copy the two values out and drop
    // the borrow immediately so the attempt can still be consumed below.
    let (lock_did, lock_device_id) = {
        let coordinates = attempt.lock_coordinates();
        (coordinates.did.to_owned(), coordinates.device_id)
    };

    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await
        .map_err(|_| ExistingDeviceReadFacadeError::Storage)?;

    // BARRIER 1 — the exact requester device row.
    let device: Option<LockedReadRequesterDeviceRow> =
        sqlx::query_as(LOCK_READ_REQUESTER_DEVICE_SQL)
            .bind(&lock_did)
            .bind(lock_device_id)
            .fetch_optional(&mut **transaction)
            .await
            .map_err(|_| ExistingDeviceReadFacadeError::Storage)?;
    let Some(device) = device else {
        // Missing device row: return before construction.
        return Err(ExistingDeviceReadFacadeError::Invariant);
    };

    // BARRIER 2 — a SEPARATE statement for the exact requester key row, issued
    // only now that barrier 1 has completed.
    let key: Option<LockedReadRequesterKeyRow> = sqlx::query_as(LOCK_READ_REQUESTER_DEVICE_KEY_SQL)
        .bind(&lock_did)
        .bind(lock_device_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| ExistingDeviceReadFacadeError::Storage)?;
    let Some(key) = key else {
        // Missing key row: return before construction.
        return Err(ExistingDeviceReadFacadeError::Invariant);
    };

    let signing_public_key_sha256: [u8; 32] = Sha256::digest(&key.signing_public_key).into();

    // THE single production `from_repository_lock` callsite. Reachable only
    // after BOTH ordered locks succeeded, and it carries the row's OWN
    // `user_did`/`device_id` rather than the coordinates that addressed it.
    let locked_row = super::super::dpop::LockedReadDatabaseRow::from_repository_lock(
        transaction_id.clone().into_boxed_str(),
        device.user_did.clone().into_boxed_str(),
        device.device_id,
        device.status.clone().into_boxed_str(),
        device.dpop_jkt.clone().map(String::into_boxed_str),
        device.auth_generation,
        key.key_id.into_boxed_str(),
        signing_public_key_sha256,
        key.revoked_at,
    )
    .map_err(|_| ExistingDeviceReadFacadeError::Invariant)?;

    // Constructing the row proved nothing. Only this consuming verification
    // mints authority, and it spends the attempt.
    let verified = attempt
        .consume_verify_locked_row(locked_row)
        .map_err(|_| ExistingDeviceReadFacadeError::Invariant)?;

    Ok(VerifiedRequesterLock {
        transaction_id,
        verified,
        row_user_did: device.user_did,
        row_device_id: device.device_id,
        row_dpop_jkt: device.dpop_jkt,
        row_auth_generation: device.auth_generation,
    })
}

/// Check the private same-transaction token before a protected query. Every
/// protected audience/directory/item/session query in this section calls this
/// immediately before issuing SQL.
#[cfg(not(test))]
fn guard_protected_query(
    lock: &VerifiedRequesterLock,
) -> Result<(), ExistingDeviceReadFacadeError> {
    lock.verified
        .verify_same_transaction(&lock.transaction_id)
        .map_err(|_| ExistingDeviceReadFacadeError::Invariant)
}

/// Map an inventory repository failure into the sanitized facade vocabulary.
/// Only the device-fence `SnapshotConflict` is retryable, and it is handled by
/// the caller's own outcome type rather than by an error variant.
#[cfg(not(test))]
fn facade_error_from_inventory(error: InventoryRepositoryError) -> ExistingDeviceReadFacadeError {
    match error {
        InventoryRepositoryError::RequestTooBroad => ExistingDeviceReadFacadeError::RequestTooBroad,
        InventoryRepositoryError::Database(_) => ExistingDeviceReadFacadeError::Storage,
        _ => ExistingDeviceReadFacadeError::Invariant,
    }
}

/// Build the exact generated `deviceView` for one durable directory row.
///
/// This mirrors the read-only `handlers/chat/device_views.rs` shaping field for
/// field. It is duplicated rather than called because that helper is
/// `pub(in crate::handlers::chat)` and the authority places the complete
/// generated-DTO projection inside this repository module.
#[cfg(not(test))]
fn read_facade_device_view(
    view: &super::device_directory::DeviceDirectoryView,
) -> catbird_atproto::generated::blue_catbird::chat::DeviceView<jacquard_common::DefaultStr> {
    use jacquard_common::deps::{bytes::Bytes, smol_str::SmolStr};

    catbird_atproto::generated::blue_catbird::chat::DeviceView {
        auth_generation: view.auth_generation,
        available_package_count: view.available_package_count,
        created_at: crate::sqlx_jacquard::chrono_to_datetime(view.created_at),
        device_id: SmolStr::from(view.device_id.to_string()),
        key_id: SmolStr::from(view.key_id.as_str()),
        reserved_package_count: view.reserved_package_count,
        signature_public_key: Bytes::from(view.signing_public_key.clone()),
        status: SmolStr::from(view.status.as_str()),
        updated_at: crate::sqlx_jacquard::chrono_to_datetime(view.updated_at),
        extra_data: None,
    }
}

/// Build the exact generated `addressableDevice` for one enriched directory row.
///
/// It contains ONLY the endpoint's declared wire fields: audience DID, device
/// ID, key ID, decoded pinned capability, live available-package count, and the
/// generated empty `extra_data`. It deliberately carries no authentication
/// generation, JKT, signing key, status, timestamp, reserved count, requester
/// coordinate, or row object.
#[cfg(not(test))]
fn read_facade_addressable_device(
    view: &super::device_directory::DeviceDirectoryView,
    user_did: &str,
) -> Result<
    catbird_atproto::generated::blue_catbird::chat::AddressableDevice<jacquard_common::DefaultStr>,
    ExistingDeviceReadFacadeError,
> {
    use jacquard_common::deps::smol_str::SmolStr;

    let capability = serde_json::from_str::<
        catbird_atproto::generated::blue_catbird::chat::DeviceCapability<
            jacquard_common::DefaultStr,
        >,
    >(&view.capabilities_json)
    .map_err(|_| ExistingDeviceReadFacadeError::Invariant)?;
    let user_did = jacquard_common::types::string::Did::new_owned(user_did)
        .map_err(|_| ExistingDeviceReadFacadeError::Invariant)?;
    Ok(
        catbird_atproto::generated::blue_catbird::chat::AddressableDevice {
            available_package_count: view.available_package_count,
            capability,
            device_id: SmolStr::from(view.device_id.to_string()),
            key_id: SmolStr::from(view.key_id.as_str()),
            user_did,
            extra_data: None,
        },
    )
}

/// `blue.catbird.chat.getDevices` — the complete repository-owned facade.
///
/// Consumes the opaque admission into the closed one-attempt budget BEFORE any
/// SQL, opens one fresh `READ COMMITTED` transaction, spends the single attempt
/// against the two ordered requester locks, holds those locks through the
/// bounded audience/directory read, and ends the read-only transaction before
/// returning consuming canonical JSON bytes.
#[cfg(not(test))]
pub(crate) async fn read_addressable_devices_for_admission(
    pool: &sqlx::PgPool,
    admission: super::super::dpop::VerifiedReadAdmission,
    dids: &[String],
) -> Result<CanonicalGetDevicesResponse, ExistingDeviceReadFacadeError> {
    // Convert the admission BEFORE SQL. An endpoint or method mismatch fails
    // here, with no transaction ever opened.
    let attempt = admission
        .into_get_devices_read_admission()
        .map_err(|_| ExistingDeviceReadFacadeError::Invariant)?
        .into_attempt();

    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| ExistingDeviceReadFacadeError::Storage)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *transaction)
        .await
        .map_err(|_| ExistingDeviceReadFacadeError::Storage)?;

    let outcome = read_addressable_devices_in_transaction(&mut transaction, attempt, dids).await;

    // Read-only: the requester locks are held until exactly here, and releasing
    // the transaction discards nothing durable.
    let _ = transaction.rollback().await;
    outcome
}

#[cfg(not(test))]
async fn read_addressable_devices_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    attempt: super::super::dpop::ReadAdmissionAttempt,
    dids: &[String],
) -> Result<CanonicalGetDevicesResponse, ExistingDeviceReadFacadeError> {
    let lock = lock_and_verify_read_requester(transaction, attempt).await?;

    // PROTECTED QUERY — bounded audience read.
    guard_protected_query(&lock)?;
    let rows = get_devices(transaction, dids)
        .await
        .map_err(facade_error_from_inventory)?;

    let mut devices = Vec::with_capacity(rows.len());
    for row in &rows {
        // PROTECTED QUERY — per-row directory enrichment.
        guard_protected_query(&lock)?;
        // The audience read returns only active devices; a row that vanishes
        // between the two reads is skipped rather than surfaced as a phantom.
        let Some(view) =
            super::device_directory::read_device_view(transaction, &row.user_did, row.device_id)
                .await
                .map_err(|_| ExistingDeviceReadFacadeError::Storage)?
        else {
            continue;
        };
        devices.push(read_facade_addressable_device(&view, &row.user_did)?);
    }

    let output = catbird_atproto::generated::blue_catbird::chat::get_devices::GetDevicesOutput::<
        jacquard_common::DefaultStr,
    > {
        devices,
        extra_data: None,
    };
    let response_bytes =
        serde_json::to_vec(&output).map_err(|_| ExistingDeviceReadFacadeError::Invariant)?;
    Ok(CanonicalGetDevicesResponse { response_bytes })
}

/// One attempt's terminal disposition inside the fixed three-attempt loop.
#[cfg(not(test))]
enum OwnDeviceSnapshotOutcome {
    /// The device fence lost its race. Roll back, drop this attempt's proof, and
    /// use the next fixed array element.
    Retry,
    /// Materialization succeeded. The generated output is complete but NOT yet
    /// serialized: bytes are produced only after the commit below.
    Materialized(
        catbird_atproto::generated::blue_catbird::chat::get_own_devices::GetOwnDevicesOutput<
            jacquard_common::DefaultStr,
        >,
    ),
}

/// `blue.catbird.chat.getOwnDevices` — the complete repository-owned facade.
///
/// Owns the fixed three-attempt boundary end to end. No handler drives retries:
/// the loop is over the fixed `[ReadAdmissionAttempt; 3]` array, a fourth
/// iteration is unrepresentable, and every retry rolls back the prior
/// transaction and drops the prior row proof before taking the next element.
#[cfg(not(test))]
pub(crate) async fn create_own_device_snapshot_for_admission(
    pool: &sqlx::PgPool,
    admission: super::super::dpop::VerifiedReadAdmission,
) -> Result<CommittedOwnDeviceSnapshot, ExistingDeviceReadFacadeError> {
    // Convert the admission BEFORE SQL.
    let attempts = admission
        .into_get_own_devices_read_admission()
        .map_err(|_| ExistingDeviceReadFacadeError::Invariant)?
        .into_attempts();

    for attempt in attempts {
        // Each attempt starts a FRESH transaction.
        let mut transaction = pool
            .begin()
            .await
            .map_err(|_| ExistingDeviceReadFacadeError::Storage)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
            .execute(&mut *transaction)
            .await
            .map_err(|_| ExistingDeviceReadFacadeError::Storage)?;

        match materialize_own_device_snapshot(&mut transaction, attempt).await {
            Ok(OwnDeviceSnapshotOutcome::Materialized(output)) => {
                // A successful commit is the deferred-constraint proof.
                transaction
                    .commit()
                    .await
                    .map_err(|_| ExistingDeviceReadFacadeError::Storage)?;
                // Only NOW may bytes exist.
                let response_bytes = serde_json::to_vec(&output)
                    .map_err(|_| ExistingDeviceReadFacadeError::Invariant)?;
                return Ok(CommittedOwnDeviceSnapshot { response_bytes });
            }
            Ok(OwnDeviceSnapshotOutcome::Retry) => {
                // Drop this attempt's transaction and row proof before the next
                // fixed array element is used.
                let _ = transaction.rollback().await;
                continue;
            }
            Err(error) => {
                let _ = transaction.rollback().await;
                return Err(error);
            }
        }
    }

    // The fixed ceiling. The handler renders HTTP 503 + `Retry-After: 1`; no
    // protocol vocabulary is invented.
    Err(ExistingDeviceReadFacadeError::RetryCeiling)
}

#[cfg(not(test))]
async fn materialize_own_device_snapshot(
    transaction: &mut Transaction<'_, Postgres>,
    attempt: super::super::dpop::ReadAdmissionAttempt,
) -> Result<OwnDeviceSnapshotOutcome, ExistingDeviceReadFacadeError> {
    let lock = lock_and_verify_read_requester(transaction, attempt).await?;

    // PROTECTED QUERY — own-device directory read.
    guard_protected_query(&lock)?;
    let views = super::device_directory::list_own_device_views(transaction, &lock.row_user_did)
        .await
        .map_err(|_| ExistingDeviceReadFacadeError::Storage)?;

    // Construct each generated `ownDeviceView` EXACTLY ONCE. The value that is
    // serialized to durable `payload_bytes` is the SAME value that is appended
    // to the response item list — it is moved, never rebuilt.
    let mut items = Vec::with_capacity(views.len());
    let mut subjects = Vec::with_capacity(views.len());
    for view in &views {
        let own = catbird_atproto::generated::blue_catbird::chat::OwnDeviceView {
            device: read_facade_device_view(view),
            extra_data: None,
        };
        let payload_bytes =
            serde_json::to_vec(&own).map_err(|_| ExistingDeviceReadFacadeError::Invariant)?;
        subjects.push(DeviceInventorySubject {
            subject_device_id: view.device_id,
            payload_bytes,
        });
        items.push(own);
    }

    // Payload/value divergence FAILS BEFORE COMMIT. Single construction already
    // makes divergence structurally impossible; this proves it rather than
    // assuming it, and costs one re-serialization over a set the own-device
    // directory bounds.
    if subjects.len() != items.len() {
        return Err(ExistingDeviceReadFacadeError::Invariant);
    }
    for (subject, item) in subjects.iter().zip(items.iter()) {
        let reserialized =
            serde_json::to_vec(item).map_err(|_| ExistingDeviceReadFacadeError::Invariant)?;
        if reserialized != subject.payload_bytes {
            return Err(ExistingDeviceReadFacadeError::Invariant);
        }
    }

    // The repository-owned bounded window. `created_at` is a derivation on the
    // same-transaction proof — the retained trusted instant never leaves that
    // type, and it arrives already truncated to a whole second because
    // `unix_seconds` rejects sub-second precision. The TTL is this module's
    // constant; the seam accepts none.
    let created_at = lock
        .verified
        .bounded_snapshot_created_at()
        .map_err(|_| ExistingDeviceReadFacadeError::Invariant)?;
    let expires_at = created_at + chrono::Duration::minutes(OWN_DEVICE_SNAPSHOT_TTL_MINUTES);

    // The session's internal requester columns come from the ALREADY VERIFIED
    // locked database row, not from the hidden admission. They never cross the
    // facade interface.
    let auth_generation = u64::try_from(lock.row_auth_generation)
        .map_err(|_| ExistingDeviceReadFacadeError::Invariant)?;
    let request = CreateDeviceInventorySessionRequest {
        device_inventory_session_id: Uuid::new_v4(),
        user_did: &lock.row_user_did,
        device_id: lock.row_device_id,
        jkt: lock.row_dpop_jkt.as_deref(),
        auth_generation,
        fence_revision: 0,
        created_at,
        expires_at,
        subjects,
    };

    // PROTECTED QUERY — the durable session write.
    guard_protected_query(&lock)?;
    match create_device_inventory_session(transaction, request).await {
        Ok(_) => {}
        // The ONLY retryable outcome. Authority drift never reaches here: it is
        // terminal inside `lock_and_verify_read_requester`.
        Err(InventoryRepositoryError::SnapshotConflict) => {
            return Ok(OwnDeviceSnapshotOutcome::Retry)
        }
        Err(error) => return Err(facade_error_from_inventory(error)),
    }

    // Single page: the whole own-device set materializes at once, so there is no
    // further page and no continuation cursor.
    let output =
        catbird_atproto::generated::blue_catbird::chat::get_own_devices::GetOwnDevicesOutput::<
            jacquard_common::DefaultStr,
        > {
            has_more: false,
            items,
            next_page_cursor: None,
            snapshot_expires_at: crate::sqlx_jacquard::chrono_to_datetime(expires_at),
            extra_data: None,
        };
    Ok(OwnDeviceSnapshotOutcome::Materialized(output))
}
// ===========================================================================
// D-2: the production inventory facade, typed loaders, and receipt wiring.
//
// `create_inventory_snapshot_and_first_page` is the ONE production facade for
// the clean-chat inventory endpoints (blue.catbird.chat.getConversations /
// getPendingWelcomes / getLeafRecoveryInbox). It owns exactly three whole-call
// READ COMMITTED attempts, uses a fresh B-read guard per attempt, and serves
// the first page of the requested domain from a retained session.
//
// Session identity is DETERMINISTIC per verified device: the v4-masked SHA-256
// over (user_did, device_id, jkt, auth_generation) is the retained row key, so
// a repeated call — a lost-response retry, a no-cursor Welcome/recovery read,
// or a concurrent second initial creator — deterministically selects the SAME
// session and its initial receipts. The session CAPABILITY is a single random
// 32-byte capability (43-character base64url) that is BOTH the presented
// `inventorySessionId` and the presented `snapshotEventCursor`; only its
// SHA-256 is persisted (token_hash + snapshot_event_cursor_sha256) and the
// plaintext is sealed at rest (12-byte nonce + ciphertext) under the active
// database-pinned cursor key, so every replay decrypts the IDENTICAL
// capability and the complete response bytes match the stored SHA-256
// byte-for-byte. Page successor capabilities are likewise random, sealed in
// the served receipt, and decrypted identically on replay.
//
// Receipts are hash-located: the continuation/final paths select by
// `request_cursor_hash` (the SHA-256 of the presented successor plaintext) and
// never decode authority fields from the public cursor. Materialization
// `*_complete` is proven at creation and never mutated by a page call; the
// first-final-page `*_consumed` compare-and-set is separate and monotonic.
// ===========================================================================

/// The three clean-chat inventory domains served by the facade and the receipt
/// layer. Each maps to one closed endpoint NSID, one receipt `domain` text,
/// and one per-session item table.
///
/// Purpose-staged: constructed by the G/H handler lanes (and the D-3 tests);
/// in the library the variants and derived helpers are not yet exercised, so
/// the dead-code lint is documented rather than papered over.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InventoryDomain {
    Conversations,
    Welcomes,
    Recovery,
}

/// Purpose-staged (see the enum): the derived helpers are exercised by the
/// G/H handler lanes and the D-3 tests.
#[allow(dead_code)]
impl InventoryDomain {
    /// The receipt `domain` column value for this domain.
    pub(crate) const fn receipt_domain_text(self) -> &'static str {
        match self {
            Self::Conversations => "conversations",
            Self::Welcomes => "welcomes",
            Self::Recovery => "recovery",
        }
    }

    /// The closed endpoint NSID bound to this domain.
    pub(crate) const fn endpoint_nsid(self) -> &'static str {
        match self {
            Self::Conversations => INVENTORY_CONVERSATIONS_NSID,
            Self::Welcomes => INVENTORY_WELCOMES_NSID,
            Self::Recovery => INVENTORY_RECOVERY_NSID,
        }
    }

    /// The per-session item table for this domain.
    pub(crate) const fn item_table(self) -> &'static str {
        match self {
            Self::Conversations => "chat.inventory_conversation_items",
            Self::Welcomes => "chat.inventory_welcome_items",
            Self::Recovery => "chat.inventory_recovery_items",
        }
    }

    /// The corresponding cursor-codec page domain (receipt/item-table domain).
    pub(crate) const fn page_domain(self) -> InventoryPageDomain {
        match self {
            Self::Conversations => InventoryPageDomain::Conversations,
            Self::Welcomes => InventoryPageDomain::PendingWelcomes,
            Self::Recovery => InventoryPageDomain::LeafRecovery,
        }
    }
}

/// `blue.catbird.chat.getConversations`
pub(crate) const INVENTORY_CONVERSATIONS_NSID: &str = "blue.catbird.chat.getConversations";
/// `blue.catbird.chat.getPendingWelcomes`
pub(crate) const INVENTORY_WELCOMES_NSID: &str = "blue.catbird.chat.getPendingWelcomes";
/// `blue.catbird.chat.getLeafRecoveryInbox`
pub(crate) const INVENTORY_RECOVERY_NSID: &str = "blue.catbird.chat.getLeafRecoveryInbox";

/// The frozen internal inventory request fields: endpoint NSID, cursor format
/// version (exactly 1), domain, exact public limit (1..=100), and the canonical
/// filter SHA-256 (the SHA-256 of the canonical `[]` when the endpoint has no
/// public filter). It never carries raw caller identity, generation, or payload
/// bytes — the identity comes from the admission's B-read guard.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct InventoryPublicRequestBinding {
    endpoint_nsid: &'static str,
    cursor_format_version: u16,
    domain: InventoryDomain,
    limit: u16,
    canonical_filter_sha256: [u8; 32],
}

/// Purpose-staged: the validating constructor is exercised by the G/H handler
/// lanes and the D-3 tests; the library only receives already-built bindings.
#[allow(dead_code)]
impl InventoryPublicRequestBinding {
    /// Validating constructor: the format version must be exactly 1, the limit
    /// must be within 1..=100, the filter digest must be nonzero, and the
    /// endpoint NSID must be the closed NSID of the domain.
    pub(crate) fn new(
        endpoint_nsid: &'static str,
        cursor_format_version: u16,
        domain: InventoryDomain,
        limit: u16,
        canonical_filter_sha256: [u8; 32],
    ) -> Result<Self, InventoryRepositoryError> {
        if cursor_format_version != 1
            || !(1..=MAX_INVENTORY_PAGE_ITEMS).contains(&u64::from(limit))
            || canonical_filter_sha256 == [0; 32]
            || endpoint_nsid != domain.endpoint_nsid()
        {
            return Err(InventoryRepositoryError::InvalidMaterialization);
        }
        Ok(Self {
            endpoint_nsid,
            cursor_format_version,
            domain,
            limit,
            canonical_filter_sha256,
        })
    }

    pub(crate) fn endpoint_nsid(&self) -> &'static str {
        self.endpoint_nsid
    }

    pub(crate) const fn cursor_format_version(&self) -> u16 {
        self.cursor_format_version
    }

    pub(crate) const fn domain(&self) -> InventoryDomain {
        self.domain
    }

    pub(crate) const fn limit(&self) -> u16 {
        self.limit
    }

    pub(crate) const fn canonical_filter_sha256(&self) -> [u8; 32] {
        self.canonical_filter_sha256
    }
}

/// Consuming canonical inventory page response: the checked canonical bytes
/// plus their SHA-256. Both fields are private; consumers receive them through
/// accessors only.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct CanonicalInventoryResponse {
    bytes: Vec<u8>,
    sha256: [u8; 32],
}

/// Redacted `Debug`: the response bytes embed the session capability text
/// (`inventorySessionId`, `snapshotEventCursor`) and, when present, the
/// successor capability (`nextPageCursor`), so no `Debug` rendering may carry
/// them (binding constraint: capability plaintexts never appear in `Debug`
/// output). Only the non-secret response SHA-256 is printed.
impl std::fmt::Debug for CanonicalInventoryResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CanonicalInventoryResponse")
            .field("bytes", &"REDACTED")
            .field("sha256", &self.sha256)
            .finish()
    }
}

/// Purpose-staged: the accessors are exercised by the G/H handler lanes and
/// the D-3 tests; the library only moves the response out of the facade.
#[allow(dead_code)]
impl CanonicalInventoryResponse {
    /// Validating constructor: the SHA-256 must be the digest of the bytes and
    /// the bytes must respect the 16 MiB + 64 KiB response ceiling.
    pub(crate) fn checked(
        bytes: Vec<u8>,
        sha256: [u8; 32],
    ) -> Result<Self, InventoryRepositoryError> {
        if bytes.len() > MAX_RESPONSE_BYTES || <[u8; 32]>::from(Sha256::digest(&bytes)) != sha256 {
            return Err(InventoryRepositoryError::InvalidMaterialization);
        }
        Ok(Self { bytes, sha256 })
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn sha256(&self) -> [u8; 32] {
        self.sha256
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// The 16 MiB + 64 KiB response ceiling (read-semantics plan line 24). Shared
/// by the unconditional validating response constructor and the page
/// accumulation, so it is unconditional.
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024 + 64 * 1024;
/// Envelope headroom reserved for the response wrapper (hasMore,
/// inventorySessionId, nextPageCursor, snapshotEventCursor, snapshotExpiresAt)
/// while the page accumulation respects the 16 MiB + 64 KiB response ceiling.
const PAGE_ENVELOPE_HEADROOM: usize = 1024;

/// The only production source of the retained session identity: the v4-masked
/// SHA-256 over the verified (DID, device, JKT, auth generation) coordinates.
/// The schema's `chat.is_uuid_v4` check validates only the variant/version
/// nibbles, so the deterministic identity is masked to the v4 shape. The value
/// is a row handle, never a bearer: every page call still requires the DPoP
/// admission for the exact device, and the bearer is the random sealed
/// capability.
pub(crate) fn derive_inventory_session_uuid(
    user_did: &str,
    device_id: Uuid,
    jkt: Option<&str>,
    auth_generation: u64,
) -> Uuid {
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-INVENTORY-SESSION-IDENTITY\0");
    digest.update((user_did.len() as u64).to_be_bytes());
    digest.update(user_did.as_bytes());
    digest.update(device_id.as_bytes());
    let jkt_str = jkt.unwrap_or_default();
    digest.update((jkt_str.len() as u64).to_be_bytes());
    digest.update(jkt_str.as_bytes());
    digest.update(auth_generation.to_be_bytes());
    let bytes: [u8; 32] = digest.finalize().into();
    let mut uuid_bytes = [0u8; 16];
    uuid_bytes.copy_from_slice(&bytes[..16]);
    uuid_bytes[6] = (uuid_bytes[6] & 0x0F) | 0x40;
    uuid_bytes[8] = (uuid_bytes[8] & 0x3F) | 0x80;
    Uuid::from_bytes(uuid_bytes)
}

/// The repository-owned whole-second base instant for a session/receipt:
/// `transaction_timestamp()` truncated to a whole second by the database. This
/// is the ONLY clock the D-2 facade uses; it never samples a wall clock in
/// process.
async fn current_whole_second(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<DateTime<Utc>, InventoryRepositoryError> {
    Ok(
        sqlx::query_scalar("SELECT date_trunc('second', transaction_timestamp())")
            .fetch_one(&mut **transaction)
            .await?,
    )
}

/// The checked canonical UTC text (`YYYY-MM-DDTHH:MM:SS.sssZ`) the C1 checked
/// sources and the canonical response require.
fn canonical_datetime(value: DateTime<Utc>) -> String {
    value.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// The checked cipher-suite constant of the sealed protocol (single value).

const INVENTORY_CIPHER_SUITE_V1: &str = "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519";
/// The generated key-package artifact framing/content-type constants (single
/// value; no durable columns carry them).
#[cfg(not(test))]
const INVENTORY_KEY_PACKAGE_FRAMING: &str = "mlsMessage";
#[cfg(not(test))]
const INVENTORY_KEY_PACKAGE_CONTENT_TYPE: &str = "keyPackage";

/// The locked durable session row consumed by the loader seam. Everything the
/// page serve, the receipts, and the fence verification need comes from this
/// row; no plaintext capability column exists (only the seal + lookup hash).
#[derive(Debug, FromRow)]
struct InventorySessionFenceLockRow {
    inventory_session_id: Uuid,
    user_did: String,
    device_id: Uuid,
    jkt: Option<String>,
    auth_generation: i64,
    snapshot_event_position: i64,
    snapshot_event_cursor_sha256: Vec<u8>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    protocol_instance_id: Uuid,
    cursor_key_id: String,
    cursor_format_version: i16,
    snapshot_retained_floor: i64,
    snapshot_event_cursor_nonce: Vec<u8>,
    snapshot_event_cursor_ciphertext: Vec<u8>,
    legacy_cursor_invalidated_at: Option<DateTime<Utc>>,
}

/// The loader seam: the unchanged `SELECT ... FOR UPDATE` contract over the
/// retained session row, keyed by the deterministic session identity.
async fn lock_inventory_session_row(
    transaction: &mut Transaction<'_, Postgres>,
    inventory_session_id: Uuid,
) -> Result<Option<InventorySessionFenceLockRow>, InventoryRepositoryError> {
    Ok(sqlx::query_as(
        r#"
        SELECT inventory_session_id, user_did, device_id, jkt, auth_generation,
               snapshot_event_position, snapshot_event_cursor_sha256,
               created_at, expires_at, protocol_instance_id, cursor_key_id,
               cursor_format_version, snapshot_retained_floor,
               snapshot_event_cursor_nonce, snapshot_event_cursor_ciphertext,
               legacy_cursor_invalidated_at
          FROM chat.inventory_sessions
         WHERE inventory_session_id = $1
         FOR UPDATE
        "#,
    )
    .bind(inventory_session_id)
    .fetch_optional(&mut **transaction)
    .await?)
}

/// The sole production caller of
/// `LockedInventoryFenceRecord::from_lock_material` and
/// `from_locked_inventory_fence_record` (BREAD-03 seam): extract the six
/// durable fence material fields from the locked row and verify the fence
/// against the live protocol instance, active cursor key, retention floor, and
/// temporal bounds. The row must belong to the presenting device.
#[cfg(not(test))]
async fn verify_locked_inventory_fence(
    transaction: &mut Transaction<'_, Postgres>,
    device: super::super::read_authority::LockedReadDeviceAuthority,
    row: &InventorySessionFenceLockRow,
) -> Result<super::super::read_authority::VerifiedInventoryFence, InventoryRepositoryError> {
    if row.user_did != device.user_did()
        || row.device_id != device.device_id()
        || row.jkt.as_deref() != device.jkt()
        || row.auth_generation
            != i64::try_from(device.auth_generation())
                .map_err(|_| InventoryRepositoryError::DurableRowInvalid)?
        || row.legacy_cursor_invalidated_at.is_some()
        || row.cursor_format_version != 1
    {
        return Err(InventoryRepositoryError::DeviceAuthorityMismatch);
    }
    let event_position = database_protocol_integer(row.snapshot_event_position)
        .map_err(|_| InventoryRepositoryError::DurableRowInvalid)?;
    let event_cursor_sha256 = fixed_hash(row.snapshot_event_cursor_sha256.clone())
        .map_err(|_| InventoryRepositoryError::DurableRowInvalid)?;
    let retained_floor = database_protocol_integer(row.snapshot_retained_floor)
        .map_err(|_| InventoryRepositoryError::DurableRowInvalid)?;
    let record = super::super::read_authority::LockedInventoryFenceRecord::from_lock_material(
        row.protocol_instance_id,
        row.cursor_key_id.clone(),
        event_position,
        event_cursor_sha256,
        retained_floor,
        row.created_at,
    )
    .map_err(InventoryRepositoryError::ReadAuthority)?;
    let durable_row = super::super::read_authority::from_locked_inventory_fence_record(record);
    super::super::read_authority::verify_inventory_fence(transaction, device, durable_row)
        .await
        .map_err(InventoryRepositoryError::ReadAuthority)
}

/// The consuming device-authority type of the paging entrypoints
/// (`serve_initial_inventory_page`, `issue_next_inventory_page_cursor`,
/// `complete_inventory_page`).
///
/// In the production library (`cfg(not(test))`) this IS the B-read
/// `LockedReadDeviceAuthority`, so the paging entrypoints keep their exact
/// device-consuming signatures. Under `cfg(test)` — i.e. inside the ten
/// path-include test harnesses, most of which mount no `read_authority`
/// module — it is a harness-only identity record. This split is the
/// final-review fix mandate: the production serve/replay/continuation bodies
/// must stay compiled and executable in the test harnesses (no test-local
/// replicas), while nothing referencing `read_authority` may leak into the
/// partial include trees. The REAL B-read fence chain is driven separately by
/// the DB suite through its admission bridge.
#[cfg(not(test))]
pub(crate) type PagingDeviceAuthority = super::super::read_authority::LockedReadDeviceAuthority;

/// Harness-only device identity for the paging entrypoints (see
/// `PagingDeviceAuthority`). Carries exactly the identity tuple the fence
/// binds; it grants nothing on its own.
#[cfg(test)]
pub(crate) struct PagingDeviceAuthority {
    pub(crate) user_did: String,
    pub(crate) device_id: Uuid,
    pub(crate) jkt: Option<String>,
    pub(crate) auth_generation: i64,
}

/// The paging entrypoints' device fence. In production this is the full
/// consuming B-read fence (`verify_locked_inventory_fence`); under
/// `cfg(test)` it is the identity/format half of the same check, so a
/// harness caller can never serve another device's session (the
/// temporal/protocol half is `revalidate_session_fence`, which runs
/// unconditionally on every serve, plus the DB suite's real fence-chain
/// tests through the admission bridge).
#[cfg(not(test))]
async fn verify_paging_device_fence(
    transaction: &mut Transaction<'_, Postgres>,
    device: PagingDeviceAuthority,
    row: &InventorySessionFenceLockRow,
) -> Result<(), InventoryRepositoryError> {
    verify_locked_inventory_fence(transaction, device, row)
        .await
        .map(|_| ())
}

#[cfg(test)]
async fn verify_paging_device_fence(
    transaction: &mut Transaction<'_, Postgres>,
    device: PagingDeviceAuthority,
    row: &InventorySessionFenceLockRow,
) -> Result<(), InventoryRepositoryError> {
    let _ = transaction;
    if row.user_did != device.user_did
        || row.device_id != device.device_id
        || row.jkt.as_deref() != device.jkt.as_deref()
        || row.auth_generation != device.auth_generation
        || row.legacy_cursor_invalidated_at.is_some()
        || row.cursor_format_version != 1
    {
        return Err(InventoryRepositoryError::DeviceAuthorityMismatch);
    }
    Ok(())
}

/// The G6-compatible final fence/source revalidation, run immediately before
/// the page sealing: the live protocol instance must still own the active
/// cursor key, the live retention floor must never sit above the snapshot
/// event position, and the snapshot position must never sit beyond the current
/// maximum event position. The `FOR UPDATE` protocol re-read is the
/// deterministic barrier that makes concurrent key drift fail closed.
async fn revalidate_session_fence(
    transaction: &mut Transaction<'_, Postgres>,
    row: &InventorySessionFenceLockRow,
) -> Result<(), InventoryRepositoryError> {
    let live: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT protocol_instance_id, cursor_key_id FROM chat.protocol_instances \
         WHERE protocol_instance_id=$1 FOR UPDATE",
    )
    .bind(row.protocol_instance_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some((_, live_cursor_key)) = live else {
        return Err(InventoryRepositoryError::ProtocolFenceMismatch);
    };
    if live_cursor_key != row.cursor_key_id {
        return Err(InventoryRepositoryError::ProtocolFenceMismatch);
    }
    let live_floor: Option<i64> = sqlx::query_scalar(
        "SELECT retained_floor FROM chat.event_retention \
         WHERE protocol_instance_id=$1 FOR UPDATE",
    )
    .bind(row.protocol_instance_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let snapshot_event_position = u64::try_from(row.snapshot_event_position)
        .map_err(|_| InventoryRepositoryError::ProtocolFenceMismatch)?;
    if let Some(floor) = live_floor {
        if u64::try_from(floor).map_err(|_| InventoryRepositoryError::ProtocolFenceMismatch)?
            > snapshot_event_position
        {
            return Err(InventoryRepositoryError::ProtocolFenceMismatch);
        }
    }
    let maximum_event_position: i64 =
        sqlx::query_scalar("SELECT coalesce(max(event_position),0)::bigint FROM chat.events")
            .fetch_one(&mut **transaction)
            .await?;
    if snapshot_event_position
        > u64::try_from(maximum_event_position)
            .map_err(|_| InventoryRepositoryError::ProtocolFenceMismatch)?
    {
        return Err(InventoryRepositoryError::ProtocolFenceMismatch);
    }
    Ok(())
}

/// Recover the session's opaque capability (the presented `inventorySessionId`
/// AND `snapshotEventCursor`) by decrypting the sealed snapshot event cursor.
/// Every replay decrypts the identical plaintext.
fn verify_successor_capability(
    sealer: &CursorSealer,
    row: &InventorySessionFenceLockRow,
) -> Result<Zeroizing<Vec<u8>>, InventoryRepositoryError> {
    let binding = SealerBinding::for_event_cursor_receipt(
        row.inventory_session_id,
        row.user_did.as_bytes(),
        row.device_id,
        row.jkt.as_deref().unwrap_or("").as_bytes(),
        u64::try_from(row.auth_generation)
            .map_err(|_| InventoryRepositoryError::DurableRowInvalid)?,
        row.protocol_instance_id,
        row.cursor_key_id.as_bytes(),
        u64::try_from(row.snapshot_event_position)
            .map_err(|_| InventoryRepositoryError::DurableRowInvalid)?,
        None,
        u64::try_from(row.snapshot_retained_floor)
            .map_err(|_| InventoryRepositoryError::DurableRowInvalid)?,
        unix_seconds(row.created_at).ok_or(InventoryRepositoryError::DurableRowInvalid)?,
        unix_seconds(row.expires_at).ok_or(InventoryRepositoryError::DurableRowInvalid)?,
    )
    .map_err(InventoryRepositoryError::Sealer)?;
    let nonce: [u8; 12] = row
        .snapshot_event_cursor_nonce
        .as_slice()
        .try_into()
        .map_err(|_| InventoryRepositoryError::DurableRowInvalid)?;
    let sealed = SealedCapability {
        nonce,
        ciphertext: row.snapshot_event_cursor_ciphertext.clone(),
    };
    sealer
        .verify_successor(&sealed, &binding)
        .map_err(InventoryRepositoryError::Sealer)
}

/// Resolve the one opaque snapshot capability needed by the subscription
/// ticket compositor. The UUID session handle is not a bearer: this helper
/// locks the exact session, verifies the exact device identity and live fence,
/// then decrypts the sealed capability under the session's binding. The raw
/// capability is returned only to the caller's transaction frame.
#[cfg(any(not(test), feature = "subscription-production-proof"))]
pub(crate) async fn snapshot_capability_for_ticket(
    transaction: &mut Transaction<'_, Postgres>,
    device: &super::super::read_authority::LockedReadDeviceAuthority,
    inventory_session_id: Uuid,
    sealer: &CursorSealer,
) -> Result<(String, DateTime<Utc>), InventoryRepositoryError> {
    let row = lock_inventory_session_row(transaction, inventory_session_id)
        .await?
        .ok_or(InventoryRepositoryError::SessionNotFound)?;
    if row.user_did != device.user_did()
        || row.device_id != device.device_id()
        || row.jkt.as_deref() != device.jkt()
        || row.auth_generation
            != i64::try_from(device.auth_generation())
                .map_err(|_| InventoryRepositoryError::DeviceAuthorityMismatch)?
    {
        return Err(InventoryRepositoryError::DeviceAuthorityMismatch);
    }
    revalidate_session_fence(transaction, &row).await?;
    let plaintext = verify_successor_capability(sealer, &row)?;
    if plaintext.len() != 32 {
        return Err(InventoryRepositoryError::DurableRowInvalid);
    }
    let capability = URL_SAFE_NO_PAD.encode(&plaintext);
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT transaction_timestamp()")
        .fetch_one(&mut **transaction)
        .await?;
    if now >= row.expires_at {
        return Err(InventoryRepositoryError::DurableRowInvalid);
    }
    Ok((capability, row.expires_at))
}

/// The `SealerBinding` for one served page receipt, derived from the receipt
/// row's own columns (the session row + the request + the receipt's own
/// created/expires instants).
fn page_receipt_binding(
    request: &InventoryPublicRequestBinding,
    row: &InventorySessionFenceLockRow,
    receipt_created_at: u64,
    receipt_expires_at: u64,
    after_ordinal: Option<u64>,
    successor_cursor_hash: Option<[u8; 32]>,
) -> Result<SealerBinding, SealerError> {
    SealerBinding::for_page_receipt(
        request.domain().receipt_domain_text().as_bytes(),
        request.endpoint_nsid().as_bytes(),
        request.cursor_format_version(),
        row.inventory_session_id,
        row.user_did.as_bytes(),
        row.device_id,
        row.jkt.as_deref().unwrap_or("").as_bytes(),
        u64::try_from(row.auth_generation).map_err(|_| SealerError::InvalidField)?,
        row.protocol_instance_id,
        row.cursor_key_id.as_bytes(),
        u64::try_from(row.snapshot_event_position).map_err(|_| SealerError::InvalidField)?,
        fixed_hash(row.snapshot_event_cursor_sha256.clone())
            .map_err(|_| SealerError::InvalidField)?,
        u64::try_from(row.snapshot_retained_floor).map_err(|_| SealerError::InvalidField)?,
        request.canonical_filter_sha256(),
        request.limit(),
        after_ordinal,
        successor_cursor_hash,
        receipt_created_at,
        receipt_expires_at,
    )
}

/// Deterministic response assembly: the generated `*Output` wrapper shape
/// (`hasMore`, `inventorySessionId`, `items`, optional `nextPageCursor`,
/// `snapshotEventCursor`, `snapshotExpiresAt`) with the retained canonical item
/// bytes spliced verbatim. The field order matches the generated serializer and
/// coincides with the JCS-sorted order; every value is ASCII-safe and the item
/// bytes are already canonical, so the bytes are fully deterministic and the
/// stored SHA-256 is reproducible on every replay.
fn assemble_inventory_page_response(
    has_more: bool,
    capability_text: &str,
    items: &[Vec<u8>],
    next_page_cursor: Option<&str>,
    expires_at: DateTime<Utc>,
) -> Result<Vec<u8>, InventoryRepositoryError> {
    let mut out = Vec::with_capacity(
        256 + items.iter().map(Vec::len).sum::<usize>() + 2 * capability_text.len(),
    );
    out.extend_from_slice(b"{\"hasMore\":");
    out.extend_from_slice(if has_more { b"true" } else { b"false" });
    out.extend_from_slice(b",\"inventorySessionId\":\"");
    append_json_string(&mut out, capability_text);
    out.extend_from_slice(b"\",\"items\":[");
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        out.extend_from_slice(item);
    }
    out.extend_from_slice(b"]");
    if let Some(cursor) = next_page_cursor {
        out.extend_from_slice(b",\"nextPageCursor\":\"");
        append_json_string(&mut out, cursor);
        out.push(b'"');
    }
    out.extend_from_slice(b",\"snapshotEventCursor\":\"");
    append_json_string(&mut out, capability_text);
    out.extend_from_slice(b"\",\"snapshotExpiresAt\":\"");
    append_json_string(&mut out, &canonical_datetime(expires_at));
    out.extend_from_slice(b"\"}");
    if out.len() > MAX_RESPONSE_BYTES {
        return Err(InventoryRepositoryError::InvalidMaterialization);
    }
    Ok(out)
}

fn append_json_string(out: &mut Vec<u8>, value: &str) {
    for byte in value.bytes() {
        match byte {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x09 => out.extend_from_slice(b"\\t"),
            0x0A => out.extend_from_slice(b"\\n"),
            0x0C => out.extend_from_slice(b"\\f"),
            0x0D => out.extend_from_slice(b"\\r"),
            0x00..=0x1F => {
                out.extend_from_slice(format!("\\u{byte:04x}").as_bytes());
            }
            _ => out.push(byte),
        }
    }
}

fn capability_hash(encoded: &str) -> Result<[u8; 32], InventoryRepositoryError> {
    if encoded.len() != 43 {
        return Err(InventoryRepositoryError::SessionPresentationMismatch);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| InventoryRepositoryError::SessionPresentationMismatch)?;
    if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(&decoded) != encoded {
        return Err(InventoryRepositoryError::SessionPresentationMismatch);
    }
    Ok(Sha256::digest(decoded).into())
}

/// One page of retained canonical item bytes, bounded by the exact limit and
/// the 16 MiB + 64 KiB response ceiling, plus the has-more verdict.
struct RetainedPage {
    items: Vec<Vec<u8>>,
    first_ordinal: Option<i64>,
    item_count: i64,
    items_sha256: [u8; 32],
    has_more: bool,
}

/// Read the page of retained items after `after_ordinal` (the initial page
/// uses -1), probing one row past the limit and accumulating at most
/// `limit` items while respecting the response ceiling.
async fn read_retained_page(
    transaction: &mut Transaction<'_, Postgres>,
    row: &InventorySessionFenceLockRow,
    request: &InventoryPublicRequestBinding,
    after_ordinal: i64,
) -> Result<RetainedPage, InventoryRepositoryError> {
    let limit = i64::from(request.limit());
    let rows = fetch_page_items(
        transaction,
        request.domain().page_domain(),
        row.inventory_session_id,
        after_ordinal,
        limit + 1,
    )
    .await?;
    let total_rows = rows.len();
    let mut items = Vec::with_capacity(total_rows.min(limit as usize));
    let mut accumulated = 0usize;
    for item_row in rows {
        if items.len() as i64 >= limit {
            break;
        }
        let item_size = item_row.payload_bytes.len();
        if accumulated + item_size > MAX_RESPONSE_BYTES - PAGE_ENVELOPE_HEADROOM {
            break;
        }
        // Every served item passes the checked per-item constructor (the
        // 16 MiB per-item ceiling + the stored payload SHA-256 verification),
        // the same validation the legacy read path applies.
        let checked = InventoryPageItem::from_database(item_row)?;
        accumulated += item_size;
        items.push(checked.into_payload_bytes());
    }
    let has_more = total_rows > items.len();
    let item_count =
        i64::try_from(items.len()).map_err(|_| InventoryRepositoryError::InvalidMaterialization)?;
    let first_ordinal = if item_count == 0 {
        None
    } else {
        Some(
            after_ordinal
                .checked_add(1)
                .ok_or(InventoryRepositoryError::InvalidMaterialization)?,
        )
    };
    let items_sha256 = page_items_digest(
        transaction,
        request.domain().page_domain(),
        row.inventory_session_id,
        first_ordinal,
        item_count,
    )
    .await?;
    Ok(RetainedPage {
        items,
        first_ordinal,
        item_count,
        items_sha256,
        has_more,
    })
}

async fn fetch_page_items(
    transaction: &mut Transaction<'_, Postgres>,
    domain: InventoryPageDomain,
    inventory_session_id: Uuid,
    after_ordinal: i64,
    limit: i64,
) -> Result<Vec<InventoryItemRow>, InventoryRepositoryError> {
    let sql = match domain {
        InventoryPageDomain::Conversations => {
            "SELECT ordinal,item_key_bytes,payload_bytes,payload_sha256 FROM chat.inventory_conversation_items WHERE inventory_session_id = $1 AND ordinal > $2 ORDER BY ordinal LIMIT $3"
        }
        InventoryPageDomain::PendingWelcomes => {
            "SELECT ordinal,item_key_bytes,payload_bytes,payload_sha256 FROM chat.inventory_welcome_items WHERE inventory_session_id = $1 AND ordinal > $2 ORDER BY ordinal LIMIT $3"
        }
        InventoryPageDomain::LeafRecovery => {
            "SELECT ordinal,item_key_bytes,payload_bytes,payload_sha256 FROM chat.inventory_recovery_items WHERE inventory_session_id = $1 AND ordinal > $2 ORDER BY ordinal LIMIT $3"
        }
    };
    Ok(sqlx::query_as(sql)
        .bind(inventory_session_id)
        .bind(after_ordinal)
        .bind(limit)
        .fetch_all(&mut **transaction)
        .await?)
}

/// The page-level digest recorded on the served receipt, mirroring the legacy
/// per-domain materialization transcripts over the page's ordinal window.
async fn page_items_digest(
    transaction: &mut Transaction<'_, Postgres>,
    domain: InventoryPageDomain,
    inventory_session_id: Uuid,
    first_ordinal: Option<i64>,
    item_count: i64,
) -> Result<[u8; 32], InventoryRepositoryError> {
    let sql = match domain {
        InventoryPageDomain::Conversations => {
            r#"
            SELECT digest(COALESCE(string_agg(
                int8send(ordinal) || uuid_send(conversation_id)
                || item_key_bytes || payload_sha256,
                decode('', 'hex') ORDER BY ordinal
            ), decode('', 'hex')), 'sha256')
              FROM chat.inventory_conversation_items
             WHERE inventory_session_id = $1
               AND ordinal >= $2 AND ordinal < $2 + $3
            "#
        }
        InventoryPageDomain::PendingWelcomes => {
            r#"
            SELECT digest(COALESCE(string_agg(
                int8send(ordinal) || uuid_send(welcome_id)
                || item_key_bytes || payload_sha256,
                decode('', 'hex') ORDER BY ordinal
            ), decode('', 'hex')), 'sha256')
              FROM chat.inventory_welcome_items
             WHERE inventory_session_id = $1
               AND ordinal >= $2 AND ordinal < $2 + $3
            "#
        }
        InventoryPageDomain::LeafRecovery => {
            r#"
            SELECT digest(COALESCE(string_agg(
                int8send(ordinal) || item_key_bytes || payload_sha256,
                decode('', 'hex') ORDER BY ordinal
            ), decode('', 'hex')), 'sha256')
              FROM chat.inventory_recovery_items
             WHERE inventory_session_id = $1
               AND ordinal >= $2 AND ordinal < $2 + $3
            "#
        }
    };
    let digest: Vec<u8> = sqlx::query_scalar(sql)
        .bind(inventory_session_id)
        .bind(first_ordinal.unwrap_or(0))
        .bind(item_count)
        .fetch_one(&mut **transaction)
        .await?;
    fixed_hash(digest).map_err(|_| InventoryRepositoryError::InvalidMaterialization)
}

/// The served page receipt row (all columns), used by the boundary lookups and
/// the deterministic replay path.
#[derive(Debug, FromRow)]
struct ServedPageReceiptRow {
    page_receipt_id: Uuid,
    request_cursor_hash: Option<Vec<u8>>,
    inventory_session_id: Uuid,
    domain: String,
    endpoint_nsid: String,
    cursor_format_version: i16,
    page_limit: i16,
    canonical_filter_sha256: Vec<u8>,
    user_did: String,
    device_id: Uuid,
    jkt: Option<String>,
    auth_generation: i64,
    protocol_instance_id: Uuid,
    cursor_key_id: String,
    snapshot_event_position: i64,
    snapshot_event_cursor_sha256: Vec<u8>,
    snapshot_retained_floor: i64,
    after_ordinal: Option<i64>,
    first_ordinal: Option<i64>,
    item_count: Option<i64>,
    items_sha256: Option<Vec<u8>>,
    has_more: Option<bool>,
    successor_cursor_hash: Option<Vec<u8>>,
    successor_cursor_nonce: Option<Vec<u8>>,
    successor_cursor_ciphertext: Option<Vec<u8>>,
    canonical_response_sha256: Option<Vec<u8>>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    served_at: Option<DateTime<Utc>>,
}

/// The initial-receipt arm: `request_cursor_hash IS NULL`, one deterministic
/// unserved-then-served receipt per `(session, domain, limit, filter)`.
async fn select_initial_page_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    row: &InventorySessionFenceLockRow,
    request: &InventoryPublicRequestBinding,
) -> Result<Option<ServedPageReceiptRow>, InventoryRepositoryError> {
    let sql = format!(
        "{SERVED_PAGE_RECEIPT_COLUMNS} WHERE inventory_session_id = $1 AND domain = $2 \
         AND page_limit = $3 AND canonical_filter_sha256 = $4 AND request_cursor_hash IS NULL"
    );
    Ok(sqlx::query_as(&sql)
        .bind(row.inventory_session_id)
        .bind(request.domain().receipt_domain_text())
        .bind(
            i16::try_from(request.limit())
                .map_err(|_| InventoryRepositoryError::InvalidMaterialization)?,
        )
        .bind(request.canonical_filter_sha256().as_slice())
        .fetch_optional(&mut **transaction)
        .await?)
}

/// The replay arm: the receipt a presented capability was ALREADY redeemed
/// for, keyed by `request_cursor_hash` — the SHA-256 of the presented
/// successor capability. Such a receipt exists only after the continuation
/// was first served; locating the PREDECESSOR is the other direction
/// (`select_predecessor_receipt_by_successor_hash`). Authority fields are
/// never decoded from the public cursor.
async fn select_page_receipt_by_request_hash(
    transaction: &mut Transaction<'_, Postgres>,
    request_cursor_hash: [u8; 32],
) -> Result<Option<ServedPageReceiptRow>, InventoryRepositoryError> {
    let sql = format!("{SERVED_PAGE_RECEIPT_COLUMNS} WHERE request_cursor_hash = $1");
    Ok(sqlx::query_as(&sql)
        .bind(request_cursor_hash.as_slice())
        .fetch_optional(&mut **transaction)
        .await?)
}

/// The predecessor arm of the hash-located boundary: the sealed boundary
/// trigger (`chat.validate_inventory_page_receipt_boundary`) defines the
/// predecessor as the served receipt whose MINTED successor is the presented
/// capability — `WHERE receipt.successor_cursor_hash =
/// <SHA-256 of the presented capability>`. Authority fields are never decoded
/// from the public cursor.
async fn select_predecessor_receipt_by_successor_hash(
    transaction: &mut Transaction<'_, Postgres>,
    successor_cursor_hash: [u8; 32],
) -> Result<Option<ServedPageReceiptRow>, InventoryRepositoryError> {
    let sql = format!("{SERVED_PAGE_RECEIPT_COLUMNS} WHERE successor_cursor_hash = $1");
    Ok(sqlx::query_as(&sql)
        .bind(successor_cursor_hash.as_slice())
        .fetch_optional(&mut **transaction)
        .await?)
}

/// The last served ordinal of a page beginning at `first_ordinal` with
/// `item_count` items: `first_ordinal + item_count - 1` — equivalently
/// `after_ordinal + item_count`, since a page always starts one past its
/// pre-page boundary (the NULL/initial arm starts at `first_ordinal`
/// directly). This is the sealed boundary trigger's `NEW.after_ordinal`
/// requirement for the successor page and the replay integrity boundary for
/// the served page itself. `None` for an empty or invalid shape (a negative
/// ordinal, a non-positive count, or overflow) — callers fail closed.
pub(crate) fn page_last_ordinal(first_ordinal: i64, item_count: i64) -> Option<i64> {
    if first_ordinal < 0 || item_count < 1 {
        return None;
    }
    first_ordinal.checked_add(item_count - 1)
}

/// The `after_ordinal` forwarded to the page served against a located
/// predecessor: the predecessor's LAST SERVED ordinal (the sealed boundary
/// trigger requires `NEW.after_ordinal = predecessor.first_ordinal +
/// predecessor.item_count - 1`). The predecessor is verified served and
/// nonfinal before this runs, so an incoherent shape is durable-row
/// corruption, not a presentation problem.
fn predecessor_forward_after_ordinal(
    predecessor: &ServedPageReceiptRow,
) -> Result<i64, InventoryRepositoryError> {
    let first = predecessor
        .first_ordinal
        .ok_or(InventoryRepositoryError::DurableRowInvalid)?;
    let count = predecessor
        .item_count
        .ok_or(InventoryRepositoryError::DurableRowInvalid)?;
    if let Some(after) = predecessor.after_ordinal {
        if after.checked_add(1) != Some(first) {
            return Err(InventoryRepositoryError::DurableRowInvalid);
        }
    }
    page_last_ordinal(first, count).ok_or(InventoryRepositoryError::DurableRowInvalid)
}

const SERVED_PAGE_RECEIPT_COLUMNS: &str = r#"
    SELECT page_receipt_id, request_cursor_hash, inventory_session_id, domain,
           endpoint_nsid, cursor_format_version, page_limit,
           canonical_filter_sha256, user_did, device_id, jkt, auth_generation,
           protocol_instance_id, cursor_key_id, snapshot_event_position,
           snapshot_event_cursor_sha256, snapshot_retained_floor, after_ordinal,
           first_ordinal, item_count, items_sha256, has_more,
           successor_cursor_hash, successor_cursor_nonce,
           successor_cursor_ciphertext, canonical_response_sha256, created_at,
           expires_at, served_at
      FROM chat.inventory_page_receipts
"#;

/// Insert the unserved receipt (all response columns NULL). The boundary
/// trigger validates the continuation arm; the partial unique index on
/// `(inventory_session_id, domain, page_limit, canonical_filter_sha256) WHERE
/// request_cursor_hash IS NULL` (and the unique request hash) is the
/// deterministic one-winner barrier.
#[allow(clippy::too_many_arguments)]
async fn insert_page_receipt_unserved(
    transaction: &mut Transaction<'_, Postgres>,
    row: &InventorySessionFenceLockRow,
    request: &InventoryPublicRequestBinding,
    request_cursor_hash: Option<[u8; 32]>,
    after_ordinal: Option<i64>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> Result<Uuid, InventoryRepositoryError> {
    let receipt_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO chat.inventory_page_receipts(
            page_receipt_id, request_cursor_hash, inventory_session_id, domain,
            endpoint_nsid, cursor_format_version, page_limit,
            canonical_filter_sha256, user_did, device_id, jkt, auth_generation,
            protocol_instance_id, cursor_key_id, snapshot_event_position,
            snapshot_event_cursor_sha256, snapshot_retained_floor, after_ordinal,
            created_at, expires_at
        ) VALUES ($1,$2,$3,$4,$5,1,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
        "#,
    )
    .bind(receipt_id)
    .bind(request_cursor_hash.map(|hash| hash.to_vec()))
    .bind(row.inventory_session_id)
    .bind(request.domain().receipt_domain_text())
    .bind(request.endpoint_nsid())
    .bind(
        i16::try_from(request.limit())
            .map_err(|_| InventoryRepositoryError::InvalidMaterialization)?,
    )
    .bind(request.canonical_filter_sha256().as_slice())
    .bind(&row.user_did)
    .bind(row.device_id)
    .bind(row.jkt.as_deref())
    .bind(row.auth_generation)
    .bind(row.protocol_instance_id)
    .bind(&row.cursor_key_id)
    .bind(row.snapshot_event_position)
    .bind(row.snapshot_event_cursor_sha256.as_slice())
    .bind(row.snapshot_retained_floor)
    .bind(after_ordinal)
    .bind(created_at)
    .bind(expires_at)
    .execute(&mut **transaction)
    .await?;
    Ok(receipt_id)
}

/// Mark the unserved receipt served with the exact page evidence and the
/// successor seal (only when `has_more`). The lifecycle trigger permits exactly
/// the unserved -> served transition.
#[allow(clippy::too_many_arguments)]
async fn serve_page_receipt_row(
    transaction: &mut Transaction<'_, Postgres>,
    receipt_id: Uuid,
    served_at: DateTime<Utc>,
    page: &RetainedPage,
    successor: Option<&SealedSuccessor>,
    canonical_response_sha256: [u8; 32],
) -> Result<(), InventoryRepositoryError> {
    sqlx::query(
        r#"
        UPDATE chat.inventory_page_receipts
           SET served_at = $2, first_ordinal = $3, item_count = $4,
               items_sha256 = $5, has_more = $6,
               successor_cursor_hash = $7, successor_cursor_nonce = $8,
               successor_cursor_ciphertext = $9, canonical_response_sha256 = $10
         WHERE page_receipt_id = $1
        "#,
    )
    .bind(receipt_id)
    .bind(served_at)
    .bind(page.first_ordinal)
    .bind(page.item_count)
    .bind(page.items_sha256.as_slice())
    .bind(page.has_more)
    .bind(successor.map(|successor| successor.hash.as_slice()))
    .bind(successor.map(|successor| successor.sealed.nonce.as_slice()))
    .bind(successor.map(|successor| successor.sealed.ciphertext.as_slice()))
    .bind(canonical_response_sha256.as_slice())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

/// One minted + sealed successor page capability (only for `has_more=true`).
struct SealedSuccessor {
    hash: [u8; 32],
    sealed: SealedCapability,
    text: String,
}

/// Mint and seal the next page capability under the page-receipt binding. The
/// binding carries the RECEIPT's own created/expires instants (for a
/// continuation receipt these differ from the session's creation instant).
fn mint_and_seal_successor(
    sealer: &CursorSealer,
    random: &mut (dyn SecureRandom + Send),
    request: &InventoryPublicRequestBinding,
    row: &InventorySessionFenceLockRow,
    receipt_created_at: u64,
    receipt_expires_at: u64,
    after_ordinal: Option<i64>,
) -> Result<SealedSuccessor, InventoryRepositoryError> {
    let token = mint_capability_token(random).map_err(InventoryRepositoryError::SecureRandom)?;
    let hash = token.lookup_hash();
    let after_ordinal = after_ordinal
        .map(|ordinal| u64::try_from(ordinal))
        .transpose()
        .map_err(|_| InventoryRepositoryError::InvalidMaterialization)?;
    let binding = page_receipt_binding(
        request,
        row,
        receipt_created_at,
        receipt_expires_at,
        after_ordinal,
        Some(hash),
    )
    .map_err(InventoryRepositoryError::Sealer)?;
    let sealed = sealer
        .seal_successor(token.as_bytes(), &binding, random)
        .map_err(InventoryRepositoryError::Sealer)?;
    Ok(SealedSuccessor {
        hash,
        sealed,
        text: token.encode(),
    })
}

/// Verify a presented successor capability against a served receipt's sealed
/// value and binding; the decrypted plaintext must hash to the request hash.
fn verify_presented_successor(
    sealer: &CursorSealer,
    presented: &CapabilityToken,
    receipt: &ServedPageReceiptRow,
    request: &InventoryPublicRequestBinding,
    row: &InventorySessionFenceLockRow,
) -> Result<(), InventoryRepositoryError> {
    let (nonce, ciphertext, successor_hash) = match (
        &receipt.successor_cursor_nonce,
        &receipt.successor_cursor_ciphertext,
        &receipt.successor_cursor_hash,
    ) {
        (Some(nonce), Some(ciphertext), Some(hash)) => (nonce, ciphertext, hash),
        _ => return Err(InventoryRepositoryError::SessionPresentationMismatch),
    };
    let nonce: [u8; 12] = nonce
        .as_slice()
        .try_into()
        .map_err(|_| InventoryRepositoryError::DurableRowInvalid)?;
    let successor_hash: [u8; 32] = successor_hash
        .as_slice()
        .try_into()
        .map_err(|_| InventoryRepositoryError::DurableRowInvalid)?;
    let binding = page_receipt_binding(
        request,
        row,
        unix_seconds(receipt.created_at).ok_or(SealerError::InvalidField)?,
        unix_seconds(receipt.expires_at).ok_or(SealerError::InvalidField)?,
        receipt
            .after_ordinal
            .map(|ordinal| u64::try_from(ordinal).ok())
            .flatten(),
        Some(successor_hash),
    )
    .map_err(InventoryRepositoryError::Sealer)?;
    let sealed = SealedCapability {
        nonce,
        ciphertext: ciphertext.clone(),
    };
    let plaintext = sealer
        .verify_successor(&sealed, &binding)
        .map_err(InventoryRepositoryError::Sealer)?;
    if <[u8; 32]>::from(Sha256::digest(plaintext.as_slice())) != presented.lookup_hash() {
        return Err(InventoryRepositoryError::SessionPresentationMismatch);
    }
    Ok(())
}

/// One fresh serve vs. deterministic replay outcome, with the served page's
/// has-more verdict (the final-page CAS depends on it).
enum ServedPageOutcome {
    Fresh {
        response: CanonicalInventoryResponse,
        has_more: bool,
    },
    Replayed {
        response: CanonicalInventoryResponse,
        has_more: bool,
    },
}

impl ServedPageOutcome {
    fn into_response(self) -> CanonicalInventoryResponse {
        match self {
            Self::Fresh { response, .. } | Self::Replayed { response, .. } => response,
        }
    }

    fn is_fresh(&self) -> bool {
        matches!(self, Self::Fresh { .. })
    }

    fn has_more(&self) -> bool {
        match self {
            Self::Fresh { has_more, .. } | Self::Replayed { has_more, .. } => *has_more,
        }
    }
}

/// Serve one page receipt for the exact `(session, domain, limit, filter)`
/// binding: unserved-then-served in one transaction, with the deterministic
/// one-winner barrier on the receipt identity and byte-for-byte replay for the
/// loser (including the identical decrypted successor).
async fn serve_page_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    row: &InventorySessionFenceLockRow,
    request: &InventoryPublicRequestBinding,
    request_cursor_hash: Option<[u8; 32]>,
    after_ordinal: Option<i64>,
    sealer: &CursorSealer,
    random: &mut (dyn SecureRandom + Send),
) -> Result<ServedPageOutcome, InventoryRepositoryError> {
    let page = read_retained_page(transaction, row, request, after_ordinal.unwrap_or(-1)).await?;
    // The receipt's OWN created/expires instants: the whole-second serve
    // instant (>= the predecessor's served_at for the continuation arm) and
    // the session's expiry ceiling.
    let served_at = current_whole_second(transaction).await?;
    let receipt_created_at = served_at;
    let receipt_expires_at = row.expires_at;
    // The one-winner barrier is a UNIQUE VIOLATION on the receipt identity —
    // and on PostgreSQL any statement error ABORTS the enclosing transaction
    // (every later statement fails 25P02). The replay arm must therefore run
    // on a transaction restored to a savepoint taken BEFORE the contended
    // INSERT; the savepoint keeps the whole attempt inside ONE transaction
    // (fresh B-read guard + fence + serve share it) as the read-semantics
    // contract requires. Rolling back to the savepoint discards the failed
    // insert's effects and its queued trigger events; the loser's replay
    // reads then see the winner's committed receipt under READ COMMITTED.
    sqlx::query("SAVEPOINT serve_page_receipt_insert")
        .execute(&mut **transaction)
        .await?;
    let receipt_id = insert_page_receipt_unserved(
        transaction,
        row,
        request,
        request_cursor_hash,
        after_ordinal,
        receipt_created_at,
        receipt_expires_at,
    )
    .await;

    match receipt_id {
        Ok(receipt_id) => {
            sqlx::query("RELEASE SAVEPOINT serve_page_receipt_insert")
                .execute(&mut **transaction)
                .await?;
            let successor = if page.has_more {
                Some(mint_and_seal_successor(
                    sealer,
                    random,
                    request,
                    row,
                    unix_seconds(receipt_created_at)
                        .ok_or(InventoryRepositoryError::DurableRowInvalid)?,
                    unix_seconds(receipt_expires_at)
                        .ok_or(InventoryRepositoryError::DurableRowInvalid)?,
                    after_ordinal,
                )?)
            } else {
                None
            };
            let capability_plaintext = verify_successor_capability(sealer, row)?;
            let capability_text = URL_SAFE_NO_PAD.encode(capability_plaintext.as_slice());
            let response_bytes = assemble_inventory_page_response(
                page.has_more,
                &capability_text,
                &page.items,
                successor.as_ref().map(|successor| successor.text.as_str()),
                row.expires_at,
            )?;
            let response_sha256: [u8; 32] = Sha256::digest(&response_bytes).into();
            serve_page_receipt_row(
                transaction,
                receipt_id,
                served_at,
                &page,
                successor.as_ref(),
                response_sha256,
            )
            .await?;
            let response = CanonicalInventoryResponse::checked(response_bytes, response_sha256)?;
            Ok(ServedPageOutcome::Fresh {
                response,
                has_more: page.has_more,
            })
        }
        Err(InventoryRepositoryError::Database(ref error)) if is_unique_violation(error) => {
            // Un-abort the transaction before the replay reads (25P02
            // otherwise), then deterministic replay: the winner's served
            // receipt is re-read by the SAME boundary key (initial arm or
            // request hash), the identical decrypted successor is recovered
            // from ITS seal, and the response is reassembled from the
            // retained bytes and verified against the stored canonical
            // response SHA-256.
            sqlx::query("ROLLBACK TO SAVEPOINT serve_page_receipt_insert")
                .execute(&mut **transaction)
                .await?;
            let receipt = match request_cursor_hash {
                Some(request_cursor_hash) => {
                    select_page_receipt_by_request_hash(transaction, request_cursor_hash).await?
                }
                None => select_initial_page_receipt(transaction, row, request).await?,
            }
            .ok_or(InventoryRepositoryError::RaceOrReuse)?;
            replay_served_receipt(transaction, row, request, &receipt, sealer).await
        }
        Err(error) => Err(error),
    }
}

/// Reassemble and verify one already-served receipt's canonical response
/// byte-for-byte.
async fn replay_served_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    row: &InventorySessionFenceLockRow,
    request: &InventoryPublicRequestBinding,
    receipt: &ServedPageReceiptRow,
    sealer: &CursorSealer,
) -> Result<ServedPageOutcome, InventoryRepositoryError> {
    let served_at = receipt
        .served_at
        .ok_or(InventoryRepositoryError::RaceOrReuse)?;
    let has_more = receipt
        .has_more
        .ok_or(InventoryRepositoryError::RaceOrReuse)?;
    let item_count = receipt
        .item_count
        .ok_or(InventoryRepositoryError::RaceOrReuse)?;
    let first_ordinal = receipt.first_ordinal;
    let canonical_response_sha256 = fixed_hash(
        receipt
            .canonical_response_sha256
            .clone()
            .ok_or(InventoryRepositoryError::RaceOrReuse)?,
    )
    .map_err(|_| InventoryRepositoryError::RaceOrReuse)?;
    // The fetch boundary BEFORE the page: the stored `after_ordinal` (NULL on
    // the initial arm, where the page starts at `first_ordinal` directly).
    let fetch_after = match (receipt.after_ordinal, first_ordinal) {
        (Some(after), _) => after,
        (None, Some(first)) => first
            .checked_sub(1)
            .ok_or(InventoryRepositoryError::RaceOrReuse)?,
        (None, None) => -1,
    };
    let rows = fetch_page_items(
        transaction,
        request.domain().page_domain(),
        row.inventory_session_id,
        fetch_after,
        item_count + 1,
    )
    .await?;
    if rows.len() < item_count as usize {
        return Err(InventoryRepositoryError::RaceOrReuse);
    }
    if item_count == 0 {
        if !rows.is_empty() {
            return Err(InventoryRepositoryError::RaceOrReuse);
        }
    } else {
        let first = first_ordinal.ok_or(InventoryRepositoryError::RaceOrReuse)?;
        // A page always begins one past its pre-page boundary.
        if let Some(after) = receipt.after_ordinal {
            if after.checked_add(1) != Some(first) {
                return Err(InventoryRepositoryError::RaceOrReuse);
            }
        }
        // The page's LAST item ordinal is `first_ordinal + item_count - 1`
        // (equivalently `after_ordinal + item_count`) — never the pre-page
        // boundary itself.
        let expected_last =
            page_last_ordinal(first, item_count).ok_or(InventoryRepositoryError::RaceOrReuse)?;
        if rows.first().map(|item| item.ordinal) != Some(first)
            || rows.get(item_count as usize - 1).map(|item| item.ordinal) != Some(expected_last)
        {
            return Err(InventoryRepositoryError::RaceOrReuse);
        }
    }
    // Replayed items pass the same checked per-item constructor as a fresh
    // serve (16 MiB per-item ceiling + stored payload SHA-256 verification).
    let mut items: Vec<Vec<u8>> = Vec::with_capacity(item_count as usize);
    for item_row in rows.into_iter().take(item_count as usize) {
        items.push(InventoryPageItem::from_database(item_row)?.into_payload_bytes());
    }
    if items.len() as i64 != item_count {
        return Err(InventoryRepositoryError::RaceOrReuse);
    }
    let successor_text = match (
        &receipt.successor_cursor_hash,
        &receipt.successor_cursor_nonce,
        &receipt.successor_cursor_ciphertext,
    ) {
        (Some(hash), Some(nonce), Some(ciphertext)) => {
            let nonce: [u8; 12] = nonce
                .as_slice()
                .try_into()
                .map_err(|_| InventoryRepositoryError::DurableRowInvalid)?;
            let successor_hash: [u8; 32] = hash
                .as_slice()
                .try_into()
                .map_err(|_| InventoryRepositoryError::DurableRowInvalid)?;
            let binding = page_receipt_binding(
                request,
                row,
                unix_seconds(receipt.created_at).ok_or(SealerError::InvalidField)?,
                unix_seconds(receipt.expires_at).ok_or(SealerError::InvalidField)?,
                receipt
                    .after_ordinal
                    .map(|ordinal| u64::try_from(ordinal).ok())
                    .flatten(),
                Some(successor_hash),
            )
            .map_err(InventoryRepositoryError::Sealer)?;
            let sealed = SealedCapability {
                nonce,
                ciphertext: ciphertext.clone(),
            };
            let plaintext = sealer
                .verify_successor(&sealed, &binding)
                .map_err(InventoryRepositoryError::Sealer)?;
            Some(URL_SAFE_NO_PAD.encode(plaintext.as_slice()))
        }
        (None, None, None) => None,
        _ => return Err(InventoryRepositoryError::DurableRowInvalid),
    };
    let capability_plaintext = verify_successor_capability(sealer, row)?;
    let capability_text = URL_SAFE_NO_PAD.encode(capability_plaintext.as_slice());
    let response_bytes = assemble_inventory_page_response(
        has_more,
        &capability_text,
        &items,
        successor_text.as_deref(),
        row.expires_at,
    )?;
    let response_sha256: [u8; 32] = Sha256::digest(&response_bytes).into();
    if response_sha256 != canonical_response_sha256 {
        return Err(InventoryRepositoryError::RaceOrReuse);
    }
    let _ = served_at;
    let response = CanonicalInventoryResponse::checked(response_bytes, response_sha256)?;
    Ok(ServedPageOutcome::Replayed { response, has_more })
}

/// The initial-page arm of the facade: serve the deterministic initial receipt
/// for `(session, domain, limit, filter)`. `pub(crate)` so the DB harness can
/// drive the production initial serve/replay/CAS body directly (the facade's
/// create path owns the `None`-device replay arm).
pub(crate) async fn serve_initial_inventory_page(
    transaction: &mut Transaction<'_, Postgres>,
    device: Option<PagingDeviceAuthority>,
    inventory_session_id: Uuid,
    request: &InventoryPublicRequestBinding,
    sealer: &CursorSealer,
    random: &mut (dyn SecureRandom + Send),
) -> Result<CanonicalInventoryResponse, InventoryRepositoryError> {
    let row = lock_inventory_session_row(transaction, inventory_session_id)
        .await?
        .ok_or(InventoryRepositoryError::SessionNotFound)?;
    if let Some(device) = device {
        verify_paging_device_fence(transaction, device, &row).await?;
    }
    revalidate_session_fence(transaction, &row).await?;
    let outcome =
        serve_page_receipt(transaction, &row, request, None, None, sealer, random).await?;
    // A single-page domain's initial receipt IS the final receipt: the
    // first-final-page `*_consumed` compare-and-set fires here (a replay never
    // repeats it). Multi-page domains reach the CAS through
    // `complete_inventory_page`.
    if outcome.is_fresh() && !outcome.has_more() {
        let served_at = current_whole_second(transaction).await?;
        consume_final_page(transaction, &row, served_at, request.domain().page_domain()).await?;
    }
    Ok(outcome.into_response())
}

/// One per-attempt create-or-lock + first-page flow.
#[cfg(not(test))]
async fn create_inventory_snapshot_attempt(
    transaction: &mut Transaction<'_, Postgres>,
    attempt: super::super::dpop::ReadAdmissionAttempt,
    request: &InventoryPublicRequestBinding,
    expected_inventory_session_capability: Option<&str>,
    sealer: &CursorSealer,
    random: &mut (dyn SecureRandom + Send),
) -> Result<CanonicalInventoryResponse, InventoryRepositoryError> {
    // Fresh B-read guard per attempt: two ordered FOR UPDATE statements, the
    // single locked-row constructor callsite, and the consuming verification.
    let device =
        super::super::read_authority::lock_read_device_authority_once(transaction, attempt)
            .await
            .map_err(InventoryRepositoryError::ReadAuthority)?;

    // Deterministic session identity: one retained session per verified
    // (DID, device, JKT, auth generation), so repeated calls and the no-cursor
    // Welcomes/recovery reads deterministically select the same session and
    // its initial receipts.
    let inventory_session_id = derive_inventory_session_uuid(
        device.user_did(),
        device.device_id(),
        device.jkt(),
        device.auth_generation(),
    );
    // Create-or-lock. On first sight the session row is created and fully
    // materialized; a concurrent winner's committed row (unique violation on
    // the session identity) and every later call take the replay path over the
    // retained bytes. The device is consumed by the create path's fence
    // verification; the replay path consumes it in the serve verification.
    let existing = lock_inventory_session_row(transaction, inventory_session_id).await?;
    if let Some(expected_cap) = expected_inventory_session_capability {
        let expected_hash = capability_hash(expected_cap)?;
        let Some(existing_row) = &existing else {
            return Err(InventoryRepositoryError::SessionNotFound);
        };
        if existing_row.snapshot_event_cursor_sha256 != expected_hash.as_slice() {
            return Err(InventoryRepositoryError::SessionPresentationMismatch);
        }
    }
    let device = if existing.is_none() {
        let created_at = current_whole_second(transaction).await?;
        let expires_at = created_at + chrono::Duration::minutes(15);
        // The concurrent-create loser is detected by a UNIQUE VIOLATION on
        // the session identity — which aborts the PostgreSQL transaction
        // (25P02 for every later statement). The create arm therefore runs
        // under a savepoint so the replay serve below can proceed on the
        // SAME attempt transaction, as the read-semantics contract requires.
        sqlx::query("SAVEPOINT create_inventory_session_arm")
            .execute(&mut **transaction)
            .await?;
        match create_inventory_session(
            transaction,
            device,
            CreateInventorySessionRequest {
                inventory_session_id,
                created_at,
                expires_at,
            },
            sealer,
            random,
        )
        .await
        {
            Ok(_) => {
                sqlx::query("RELEASE SAVEPOINT create_inventory_session_arm")
                    .execute(&mut **transaction)
                    .await?;
                None
            }
            Err(InventoryRepositoryError::Database(ref error)) if is_unique_violation(error) => {
                // The concurrent winner committed (the create consumed this
                // attempt's device). Un-abort the transaction, then the
                // deterministic session identity means the replay serve locks
                // the winner's row by construction; the final fence re-read
                // covers any concurrent drift.
                sqlx::query("ROLLBACK TO SAVEPOINT create_inventory_session_arm")
                    .execute(&mut **transaction)
                    .await?;
                None
            }
            Err(error) => return Err(error),
        }
    } else {
        Some(device)
    };

    serve_initial_inventory_page(
        transaction,
        device,
        inventory_session_id,
        request,
        sealer,
        random,
    )
    .await
}

/// `blue.catbird.chat.getConversations` (and the no-cursor Welcomes/recovery
/// reads) — the ONE production inventory facade.
///
/// Owns exactly three whole-call READ COMMITTED attempts with a fresh B-read
/// guard per attempt; no handler retry exists. The composition is: admission ->
/// fresh guard -> loader seam -> `verify_inventory_fence` ->
/// `inventory_authorities` -> C1 typed loaders -> C1 projections ->
/// `encode_canonical_generated_chat_json_v1` exactly once per item -> retain
/// the canonical bytes + response SHA-256 -> page read (exact limit) ->
/// initial receipt (one deterministic unserved-then-served receipt per
/// `(session, domain, limit, filter)`) -> `CanonicalInventoryResponse`.
///
/// Purpose-staged: the G/H handler lanes wire this facade to the three
/// endpoints; until then it has no production caller and the dead-code lint
/// is documented rather than papered over.
#[cfg(not(test))]
#[allow(dead_code)]
pub(crate) async fn create_inventory_snapshot_and_first_page(
    pool: &sqlx::PgPool,
    admission: super::super::dpop::VerifiedReadAdmission,
    request: InventoryPublicRequestBinding,
    expected_inventory_session_capability: Option<&str>,
    sealer: &CursorSealer,
    random: &mut (dyn SecureRandom + Send),
) -> Result<CanonicalInventoryResponse, InventoryRepositoryError> {
    let attempts = admission
        .into_inventory_read_attempts(request.endpoint_nsid(), "GET")
        .map_err(InventoryRepositoryError::ReadAdmission)?;
    for attempt in attempts {
        let mut transaction = pool
            .begin()
            .await
            .map_err(InventoryRepositoryError::Database)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
            .execute(&mut *transaction)
            .await
            .map_err(InventoryRepositoryError::Database)?;
        match create_inventory_snapshot_attempt(
            &mut transaction,
            attempt,
            &request,
            expected_inventory_session_capability,
            sealer,
            random,
        )
        .await
        {
            Ok(response) => {
                transaction
                    .commit()
                    .await
                    .map_err(InventoryRepositoryError::Database)?;
                return Ok(response);
            }
            Err(InventoryRepositoryError::SnapshotConflict) => {
                let _ = transaction.rollback().await;
                continue;
            }
            Err(error) => {
                let _ = transaction.rollback().await;
                return Err(error);
            }
        }
    }
    Err(InventoryRepositoryError::RetryCeiling)
}

/// Serve a continuation page after authenticating the exact device for each
/// bounded inventory attempt.  The cursor itself is only a sealed capability;
/// this facade never decodes authority fields from it or accepts a caller
/// selected device identity.  Final-page consumption is owned by
/// `complete_inventory_page`, which performs the one-way compare-and-set in
/// the same transaction as the page receipt.
#[cfg(not(test))]
pub(crate) async fn continue_inventory_page_for_admission(
    pool: &sqlx::PgPool,
    admission: super::super::dpop::VerifiedReadAdmission,
    presented_page_cursor: &str,
    request: InventoryPublicRequestBinding,
    expected_inventory_session_capability: Option<&str>,
    sealer: &CursorSealer,
) -> Result<CanonicalInventoryResponse, InventoryRepositoryError> {
    let attempts = admission
        .into_inventory_read_attempts(request.endpoint_nsid(), "GET")
        .map_err(InventoryRepositoryError::ReadAdmission)?;
    for attempt in attempts {
        let mut transaction = pool
            .begin()
            .await
            .map_err(InventoryRepositoryError::Database)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
            .execute(&mut *transaction)
            .await
            .map_err(InventoryRepositoryError::Database)?;
        let device = super::super::read_authority::lock_read_device_authority_once(
            &mut transaction,
            attempt,
        )
        .await
        .map_err(InventoryRepositoryError::ReadAuthority)?;
        match complete_inventory_page(
            &mut transaction,
            device,
            presented_page_cursor,
            &request,
            expected_inventory_session_capability,
            sealer,
        )
        .await
        {
            Ok(response) => {
                transaction
                    .commit()
                    .await
                    .map_err(InventoryRepositoryError::Database)?;
                return Ok(response);
            }
            Err(InventoryRepositoryError::SnapshotConflict) => {
                let _ = transaction.rollback().await;
            }
            Err(error) => {
                let _ = transaction.rollback().await;
                return Err(error);
            }
        }
    }
    Err(InventoryRepositoryError::RetryCeiling)
}

/// One continuation or final page serve, given the already-verified session
/// row and the hash-located predecessor receipt.
async fn serve_continuation_page(
    transaction: &mut Transaction<'_, Postgres>,
    row: &InventorySessionFenceLockRow,
    request: &InventoryPublicRequestBinding,
    request_cursor_hash: [u8; 32],
    after_ordinal: i64,
    sealer: &CursorSealer,
    random: &mut (dyn SecureRandom + Send),
) -> Result<ServedPageOutcome, InventoryRepositoryError> {
    revalidate_session_fence(transaction, row).await?;
    serve_page_receipt(
        transaction,
        row,
        request,
        Some(request_cursor_hash),
        Some(after_ordinal),
        sealer,
        random,
    )
    .await
}

/// The hash-located boundary continuation: `issue_next_inventory_page_cursor`
/// locates the PREDECESSOR receipt by `successor_cursor_hash` (the SHA-256 of
/// the presented successor capability — the sealed boundary trigger's
/// direction), never decoding authority fields from the public cursor. It
/// locks the session, revalidates every binding, verifies the presented
/// capability against the predecessor's own seal, forwards the predecessor's
/// LAST SERVED ordinal as the next page boundary, and serves the next page
/// receipt (sealing the next successor under
/// `SealerBinding::for_page_receipt`). An already-served continuation replays
/// byte-for-byte through the `request_cursor_hash` replay arm after the
/// one-winner unique violation.
///
/// Purpose-staged: the G/H continuation handlers wire this (and the D DB
/// suite drives this exact production body through the include harness);
/// until then it has no production caller and the dead-code lint is
/// documented rather than papered over.
#[allow(dead_code)]
pub(crate) async fn issue_next_inventory_page_cursor(
    transaction: &mut Transaction<'_, Postgres>,
    device: PagingDeviceAuthority,
    presented_page_cursor: &str,
    request: &InventoryPublicRequestBinding,
    sealer: &CursorSealer,
    random: &mut (dyn SecureRandom + Send),
) -> Result<CanonicalInventoryResponse, InventoryRepositoryError> {
    let presented = decode_capability_token(presented_page_cursor)?;
    let request_cursor_hash = presented.lookup_hash();
    let predecessor =
        select_predecessor_receipt_by_successor_hash(transaction, request_cursor_hash)
            .await?
            .ok_or(InventoryRepositoryError::SessionPresentationMismatch)?;
    let row = lock_inventory_session_row(transaction, predecessor.inventory_session_id)
        .await?
        .ok_or(InventoryRepositoryError::SessionNotFound)?;
    verify_paging_device_fence(transaction, device, &row).await?;
    verify_continuation_binding(request, &predecessor, &row)?;
    verify_presented_successor(sealer, &presented, &predecessor, request, &row)?;
    let after_ordinal = predecessor_forward_after_ordinal(&predecessor)?;
    let outcome = serve_continuation_page(
        transaction,
        &row,
        request,
        request_cursor_hash,
        after_ordinal,
        sealer,
        random,
    )
    .await?;
    Ok(outcome.into_response())
}

/// The first-final-page `*_consumed` compare-and-set. The final receipt is
/// served first (the consumption trigger requires it), then the CAS flips this
/// domain's `*_consumed` false -> true exactly once; a later replay skips the
/// CAS. Materialization `*_complete` is never mutated here.
///
/// Purpose-staged: the G/H continuation handlers wire this (and the D DB
/// suite drives this exact production body through the include harness);
/// until then it has no production caller and the dead-code lint is
/// documented rather than papered over.
#[allow(dead_code)]
pub(crate) async fn complete_inventory_page(
    transaction: &mut Transaction<'_, Postgres>,
    device: PagingDeviceAuthority,
    presented_page_cursor: &str,
    request: &InventoryPublicRequestBinding,
    expected_inventory_session_capability: Option<&str>,
    sealer: &CursorSealer,
) -> Result<CanonicalInventoryResponse, InventoryRepositoryError> {
    let presented = decode_capability_token(presented_page_cursor)?;
    let request_cursor_hash = presented.lookup_hash();
    let predecessor =
        select_predecessor_receipt_by_successor_hash(transaction, request_cursor_hash)
            .await?
            .ok_or(InventoryRepositoryError::SessionPresentationMismatch)?;
    let row = lock_inventory_session_row(transaction, predecessor.inventory_session_id)
        .await?
        .ok_or(InventoryRepositoryError::SessionNotFound)?;
    if let Some(expected_cap) = expected_inventory_session_capability {
        let expected_hash = capability_hash(expected_cap)?;
        if row.snapshot_event_cursor_sha256 != expected_hash.as_slice() {
            return Err(InventoryRepositoryError::SessionPresentationMismatch);
        }
    }
    verify_paging_device_fence(transaction, device, &row).await?;
    verify_continuation_binding(request, &predecessor, &row)?;
    verify_presented_successor(sealer, &presented, &predecessor, request, &row)?;
    let after_ordinal = predecessor_forward_after_ordinal(&predecessor)?;
    let outcome = serve_continuation_page(
        transaction,
        &row,
        request,
        request_cursor_hash,
        after_ordinal,
        sealer,
        &mut OsSecureRandom::new(),
    )
    .await?;
    // The first-final-page CAS runs only when THIS transaction served the
    // final receipt (has_more = false); a replay never repeats the CAS.
    if outcome.is_fresh() && !outcome.has_more() {
        // The final receipt was served by THIS transaction: perform the exact
        // one-way consumption CAS (a second consumer or a changed durable
        // session field affects zero rows and replays instead).
        let served_at = current_whole_second(transaction).await?;
        consume_final_page(transaction, &row, served_at, request.domain().page_domain()).await?;
    }
    Ok(outcome.into_response())
}

fn verify_continuation_binding(
    request: &InventoryPublicRequestBinding,
    predecessor: &ServedPageReceiptRow,
    row: &InventorySessionFenceLockRow,
) -> Result<(), InventoryRepositoryError> {
    if predecessor.domain != request.domain().receipt_domain_text()
        || predecessor.endpoint_nsid != request.endpoint_nsid()
        || predecessor.cursor_format_version != 1
        || predecessor.page_limit
            != i16::try_from(request.limit())
                .map_err(|_| InventoryRepositoryError::InvalidMaterialization)?
        || predecessor.canonical_filter_sha256 != request.canonical_filter_sha256().to_vec()
        || predecessor.inventory_session_id != row.inventory_session_id
        || predecessor.user_did != row.user_did
        || predecessor.device_id != row.device_id
        || predecessor.jkt != row.jkt
        || predecessor.auth_generation != row.auth_generation
        || predecessor.protocol_instance_id != row.protocol_instance_id
        || predecessor.cursor_key_id != row.cursor_key_id
        || predecessor.snapshot_event_position != row.snapshot_event_position
        || predecessor.snapshot_event_cursor_sha256 != row.snapshot_event_cursor_sha256
        || predecessor.snapshot_retained_floor != row.snapshot_retained_floor
        || predecessor.expires_at != row.expires_at
        || predecessor.has_more != Some(true)
        || predecessor.served_at.is_none()
    {
        return Err(InventoryRepositoryError::SessionPresentationMismatch);
    }
    Ok(())
}

/// The exact one-way `*_consumed` compare-and-set for the served final page.
async fn consume_final_page(
    transaction: &mut Transaction<'_, Postgres>,
    row: &InventorySessionFenceLockRow,
    served_at: DateTime<Utc>,
    domain: InventoryPageDomain,
) -> Result<(), InventoryRepositoryError> {
    let (consumed_column, consumed_at_column) = match domain {
        InventoryPageDomain::Conversations => {
            ("conversations_consumed", "conversations_consumed_at")
        }
        InventoryPageDomain::PendingWelcomes => ("welcomes_consumed", "welcomes_consumed_at"),
        InventoryPageDomain::LeafRecovery => ("recovery_consumed", "recovery_consumed_at"),
    };
    let sql = format!(
        "UPDATE chat.inventory_sessions SET {consumed_column} = TRUE, \
         {consumed_at_column} = $2 WHERE inventory_session_id = $1 \
         AND {consumed_column} = FALSE"
    );
    let result = sqlx::query(&sql)
        .bind(row.inventory_session_id)
        .bind(served_at)
        .execute(&mut **transaction)
        .await?;
    if result.rows_affected() != 1 {
        return Err(InventoryRepositoryError::RaceOrReuse);
    }
    Ok(())
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    matches!(
        error,
        sqlx::Error::Database(database) if database.code().as_deref() == Some("23505")
    )
}

// ===========================================================================
// D-2 typed loaders: durable rows -> C1 checked projection sources.
//
// These loaders are the ONLY path from the durable source rows to the C1
// checked source types. The C1 checked field structs are the definitive field
// checklist: an unknown `$type`, a missing/extra field, or a wrong terminal
// shape fails before any DTO is materialized. The conversation domain covers
// every authority arm (state/removal/close), the Welcome domain the complete
// pending-delivery source, and the recovery domain every retained
// leaf-recovery status and every recovery-work terminal variant.
// ===========================================================================

/// The per-arm provenance columns a conversation item row carries (the exact
/// columns the arm-shape check, the source-precedence trigger, and the
/// materialization digest transcript require).
#[cfg(not(test))]
struct ConversationArmColumns {
    item_kind: &'static str,
    participant_period_id: Option<Uuid>,
    membership_interval_id: Option<Uuid>,
    interval_terminal_seq: Option<i64>,
    interval_closing_transition_id: Option<Uuid>,
    interval_closing_outer_entry_fingerprint: Option<Vec<u8>>,
    interval_removed_at: Option<DateTime<Utc>>,
    schedule_terminal_seq: Option<i64>,
    schedule_terminal_transition_id: Option<Uuid>,
    schedule_terminal_outer_entry_fingerprint: Option<Vec<u8>>,
}

/// One typed loader per `ConversationInventoryAuthority` arm.
#[cfg(not(test))]
async fn conversation_projection_source(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &super::super::read_authority::ConversationInventoryAuthority,
    user_did: &str,
    device_id: Uuid,
) -> Result<super::super::read_projection::ConversationProjectionSource, InventoryRepositoryError> {
    use super::super::read_projection::ConversationProjectionSource;
    let conversation_id = authority.conversation_id();
    match authority.arm() {
        super::super::read_authority::ConversationInventoryArm::State { .. } => {
            load_conversation_state_source(transaction, conversation_id).await
        }
        super::super::read_authority::ConversationInventoryArm::Removal {
            membership_interval_id,
            terminal_seq,
            removed_at,
            ..
        } => ConversationProjectionSource::removal(
            &conversation_id.to_string(),
            user_did,
            &device_id.to_string(),
            &membership_interval_id.to_string(),
            &canonical_datetime(*removed_at),
            i64::try_from(*terminal_seq)
                .map_err(|_| InventoryRepositoryError::DurableRowInvalid)?,
        )
        .map_err(InventoryRepositoryError::Projection),
        super::super::read_authority::ConversationInventoryArm::Close {
            terminal_seq,
            closing_transition_id,
            closing_outer_entry_fingerprint,
        } => {
            let row = load_conversation_close_source(transaction, conversation_id).await?;
            ConversationProjectionSource::close(
                &canonical_datetime(row.closed_at),
                &row.closed_by_did,
                &row.closed_by_device_id.to_string(),
                &conversation_id.to_string(),
                &row.kind,
                super::super::read_projection::CheckedConversationCoordinates::new(
                    &conversation_id.to_string(),
                    row.close_generation,
                    row.close_state_version,
                    &row.close_group_id,
                    row.close_epoch,
                    &row.close_group_context_hash,
                    &row.close_confirmation_tag,
                    &row.lifecycle,
                )
                .map_err(InventoryRepositoryError::Projection)?,
                row.close_seq,
            )
            .map_err(InventoryRepositoryError::Projection)
            .and_then(|source| {
                // The schedule-terminal proof must match the arm's terminal
                // coordinates exactly; a mismatch is a spliced close.
                if row.close_seq
                    != i64::try_from(*terminal_seq)
                        .map_err(|_| InventoryRepositoryError::DurableRowInvalid)?
                    || row.close_transition_id != *closing_transition_id
                    || row.close_outer_entry_fingerprint != *closing_outer_entry_fingerprint
                {
                    return Err(InventoryRepositoryError::DurableRowInvalid);
                }
                Ok(source)
            })
        }
    }
}

/// The item-row provenance columns for one authority.
#[cfg(not(test))]
async fn conversation_arm_columns(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &super::super::read_authority::ConversationInventoryAuthority,
    user_did: &str,
    device_id: Uuid,
) -> Result<ConversationArmColumns, InventoryRepositoryError> {
    let arm = authority.arm();
    Ok(match arm {
        super::super::read_authority::ConversationInventoryArm::State {
            participant_period_id,
        } => ConversationArmColumns {
            item_kind: "blue.catbird.chat.defs#conversationInventoryState",
            participant_period_id: Some(*participant_period_id),
            membership_interval_id: None,
            interval_terminal_seq: None,
            interval_closing_transition_id: None,
            interval_closing_outer_entry_fingerprint: None,
            interval_removed_at: None,
            schedule_terminal_seq: None,
            schedule_terminal_transition_id: None,
            schedule_terminal_outer_entry_fingerprint: None,
        },
        super::super::read_authority::ConversationInventoryArm::Removal {
            membership_interval_id,
            terminal_seq,
            closing_transition_id,
            closing_outer_entry_fingerprint,
            removed_at,
        } => ConversationArmColumns {
            item_kind: "blue.catbird.chat.defs#conversationRemovalTombstone",
            participant_period_id: None,
            membership_interval_id: Some(*membership_interval_id),
            interval_terminal_seq: Some(
                i64::try_from(*terminal_seq)
                    .map_err(|_| InventoryRepositoryError::DurableRowInvalid)?,
            ),
            interval_closing_transition_id: Some(*closing_transition_id),
            interval_closing_outer_entry_fingerprint: Some(closing_outer_entry_fingerprint.clone()),
            interval_removed_at: Some(*removed_at),
            schedule_terminal_seq: None,
            schedule_terminal_transition_id: None,
            schedule_terminal_outer_entry_fingerprint: None,
        },
        super::super::read_authority::ConversationInventoryArm::Close {
            terminal_seq,
            closing_transition_id,
            closing_outer_entry_fingerprint,
        } => {
            let proof = load_schedule_terminal_proof(
                transaction,
                authority.conversation_id(),
                user_did,
                device_id,
            )
            .await?
            .ok_or(InventoryRepositoryError::DurableRowInvalid)?;
            if proof.terminal_seq
                != i64::try_from(*terminal_seq)
                    .map_err(|_| InventoryRepositoryError::DurableRowInvalid)?
                || proof.transition_id != *closing_transition_id
                || proof.outer_entry_fingerprint != *closing_outer_entry_fingerprint
            {
                return Err(InventoryRepositoryError::DurableRowInvalid);
            }
            ConversationArmColumns {
                item_kind: "blue.catbird.chat.defs#conversationCloseTombstone",
                participant_period_id: None,
                membership_interval_id: None,
                interval_terminal_seq: None,
                interval_closing_transition_id: None,
                interval_closing_outer_entry_fingerprint: None,
                interval_removed_at: None,
                schedule_terminal_seq: Some(proof.terminal_seq),
                schedule_terminal_transition_id: Some(proof.transition_id),
                schedule_terminal_outer_entry_fingerprint: Some(proof.outer_entry_fingerprint),
            }
        }
    })
}

/// The full checked conversation-state source: conversations row, current
/// generation state + producing transition seq, current participants, active
/// leaves, and the current metadata snapshot. Any missing/extra field or a
/// state without its metadata snapshot fails before materialization.

#[cfg(not(test))]
pub(crate) async fn load_conversation_state_source(
    transaction: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
) -> Result<crate::chat_protocol::read_projection::ConversationProjectionSource, InventoryRepositoryError> {
    use crate::chat_protocol::read_projection::{
        CheckedConversationCoordinates, CheckedDeviceLeafView, CheckedInvitationProvenance,
        CheckedMetadataAuthorProof, CheckedMetadataAvatarBinding, CheckedMetadataCryptoContext,
        CheckedMetadataSnapshot, CheckedParticipantView, ConversationProjectionSource,
    };
    let state: ConversationStateSourceRow = sqlx::query_as(
        r#"
        SELECT conversation.kind, conversation.lifecycle,
               conversation.current_generation, conversation.current_state_version,
               state.group_id AS state_group_id, state.epoch AS state_epoch,
               state.group_context_hash AS state_group_context_hash,
               state.confirmation_tag AS state_confirmation_tag,
               state.producing_transition_id, transition.entry_seq AS snapshot_seq
          FROM chat.conversations AS conversation
          JOIN chat.generation_states AS state
            ON state.conversation_id = conversation.conversation_id
           AND state.generation = conversation.current_generation
           AND state.state_version = conversation.current_state_version
          JOIN chat.transitions AS transition
            ON transition.transition_id = state.producing_transition_id
         WHERE conversation.conversation_id = $1
        "#,
    )
    .bind(conversation_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(InventoryRepositoryError::DurableRowInvalid)?;

    let coordinates = CheckedConversationCoordinates::new(
        &conversation_id.to_string(),
        state.current_generation,
        state.current_state_version,
        &state.state_group_id,
        state.state_epoch,
        &state.state_group_context_hash,
        &state.state_confirmation_tag,
        &state.lifecycle,
    )
    .map_err(InventoryRepositoryError::Projection)?;

    let participant_rows: Vec<ConversationParticipantRow> = sqlx::query_as(
        r#"
        SELECT participant.user_did, participant.status, participant.role,
               (SELECT count(*) FROM chat.member_devices leaf
                 WHERE leaf.participant_period_id = participant.participant_period_id
                   AND leaf.active) AS leaf_count,
               participant.invitation_transition_id,
               participant.created_by_did, participant.created_by_device_id
          FROM chat.participants AS participant
         WHERE participant.conversation_id = $1
           AND participant.current_membership
         ORDER BY participant.user_did
        "#,
    )
    .bind(conversation_id)
    .fetch_all(&mut **transaction)
    .await?;
    let mut participants = Vec::with_capacity(participant_rows.len());
    for row in participant_rows {
        let invitation_provenance = match row.invitation_transition_id {
            Some(transition_id) => Some(
                CheckedInvitationProvenance::new(
                    &transition_id.to_string(),
                    &row.created_by_did,
                    &row.created_by_device_id.to_string(),
                )
                .map_err(InventoryRepositoryError::Projection)?,
            ),
            None => None,
        };
        participants.push(
            CheckedParticipantView::new(
                &row.user_did,
                &row.role,
                &row.status,
                row.leaf_count,
                invitation_provenance,
            )
            .map_err(InventoryRepositoryError::Projection)?,
        );
    }

    let leaf_rows: Vec<ConversationLeafRow> = sqlx::query_as(
        r#"
        SELECT leaf.user_did, leaf.device_id, leaf.origin, leaf.leaf_key_id,
               device.status AS device_status, leaf.join_key_package_ref
          FROM chat.member_devices AS leaf
          JOIN chat.devices AS device
            ON device.user_did = leaf.user_did
           AND device.device_id = leaf.device_id
         WHERE leaf.conversation_id = $1
           AND leaf.active
         ORDER BY leaf.user_did, leaf.device_id
        "#,
    )
    .bind(conversation_id)
    .fetch_all(&mut **transaction)
    .await?;
    let mut leaves = Vec::with_capacity(leaf_rows.len());
    for row in leaf_rows {
        leaves.push(
            CheckedDeviceLeafView::new(
                &row.user_did,
                &row.device_id.to_string(),
                &row.origin,
                &row.leaf_key_id,
                &row.device_status,
                row.join_key_package_ref.as_deref(),
            )
            .map_err(InventoryRepositoryError::Projection)?,
        );
    }

    let metadata: ConversationMetadataRow = sqlx::query_as(
        r#"
        SELECT origin_transition_id, metadata_version, nonce, ciphertext,
               ciphertext_sha256, ciphertext_size, avatar_blob_id,
               avatar_ciphertext_sha256, avatar_ciphertext_size,
               author_did, author_device_id, author_key_id, author_public_key,
               author_auth_generation, author_origin_seq, author_role,
               author_device_status
          FROM chat.metadata_snapshots
         WHERE conversation_id = $1 AND generation = $2 AND state_version = $3
        "#,
    )
    .bind(conversation_id)
    .bind(state.current_generation)
    .bind(state.current_state_version)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(InventoryRepositoryError::DurableRowInvalid)?;

    let metadata_coordinate = CheckedMetadataCryptoContext::new(
        conversation_id.as_bytes(),
        state.current_generation,
        &state.state_group_id,
        state.state_epoch,
        &state.state_group_context_hash,
        &state.state_confirmation_tag,
    )
    .map_err(InventoryRepositoryError::Projection)?;
    let author_proof = CheckedMetadataAuthorProof::new(
        &metadata.author_did,
        &metadata.author_device_id.to_string(),
        &metadata.author_key_id,
        &metadata.author_public_key,
        metadata.author_auth_generation,
        &metadata.origin_transition_id.to_string(),
        metadata.author_origin_seq,
        &metadata.author_role,
        &metadata.author_device_status,
    )
    .map_err(InventoryRepositoryError::Projection)?;
    let avatar_binding = match (
        &metadata.avatar_blob_id,
        &metadata.avatar_ciphertext_sha256,
        metadata.avatar_ciphertext_size,
    ) {
        (Some(blob_id), Some(sha256), Some(size)) => Some(
            CheckedMetadataAvatarBinding::new(&blob_id.to_string(), sha256, size, "metadata")
                .map_err(InventoryRepositoryError::Projection)?,
        ),
        (None, None, None) => None,
        _ => return Err(InventoryRepositoryError::DurableRowInvalid),
    };
    let metadata_snapshot = CheckedMetadataSnapshot::new(
        metadata_coordinate,
        &metadata.origin_transition_id.to_string(),
        metadata.metadata_version,
        &metadata.nonce,
        &metadata.ciphertext,
        &metadata.ciphertext_sha256,
        metadata.ciphertext_size,
        author_proof,
        avatar_binding,
    )
    .map_err(InventoryRepositoryError::Projection)?;

    ConversationProjectionSource::state(
        INVENTORY_CIPHER_SUITE_V1,
        &state.kind,
        coordinates,
        leaves,
        metadata_snapshot,
        participants,
        state.snapshot_seq,
    )
    .map_err(InventoryRepositoryError::Projection)
}


#[derive(Debug, FromRow)]
struct ConversationStateSourceRow {
    kind: String,
    lifecycle: String,
    current_generation: i64,
    current_state_version: i64,
    state_group_id: Vec<u8>,
    state_epoch: i64,
    state_group_context_hash: Vec<u8>,
    state_confirmation_tag: Vec<u8>,
    producing_transition_id: Uuid,
    snapshot_seq: i64,
}


#[derive(Debug, FromRow)]
struct ConversationParticipantRow {
    user_did: String,
    status: String,
    role: String,
    leaf_count: i64,
    invitation_transition_id: Option<Uuid>,
    created_by_did: String,
    created_by_device_id: Uuid,
}


#[derive(Debug, FromRow)]
struct ConversationLeafRow {
    user_did: String,
    device_id: Uuid,
    origin: String,
    leaf_key_id: String,
    device_status: String,
    join_key_package_ref: Option<Vec<u8>>,
}


#[derive(Debug, FromRow)]
struct ConversationMetadataRow {
    origin_transition_id: Uuid,
    metadata_version: i64,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    ciphertext_sha256: Vec<u8>,
    ciphertext_size: i64,
    avatar_blob_id: Option<Uuid>,
    avatar_ciphertext_sha256: Option<Vec<u8>>,
    avatar_ciphertext_size: Option<i64>,
    author_did: String,
    author_device_id: Uuid,
    author_key_id: String,
    author_public_key: Vec<u8>,
    author_auth_generation: i64,
    author_origin_seq: i64,
    author_role: String,
    author_device_status: String,
}

/// The close-arm source: the conversation's close coordinate, the closing
/// transition actor, and the retired state's crypto coordinate.
#[cfg(not(test))]
async fn load_conversation_close_source(
    transaction: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
) -> Result<ConversationCloseSourceRow, InventoryRepositoryError> {
    sqlx::query_as(
        r#"
        SELECT conversation.kind, conversation.lifecycle, conversation.closed_at,
               conversation.close_transition_id, conversation.close_generation,
               conversation.close_state_version, conversation.close_seq,
               transition.actor_did AS closed_by_did,
               transition.actor_device_id AS closed_by_device_id,
               entry.outer_entry_fingerprint AS close_outer_entry_fingerprint,
               state.group_id AS close_group_id, state.epoch AS close_epoch,
               state.group_context_hash AS close_group_context_hash,
               state.confirmation_tag AS close_confirmation_tag
          FROM chat.conversations AS conversation
          JOIN chat.transitions AS transition
            ON transition.transition_id = conversation.close_transition_id
          JOIN chat.entries AS entry
            ON entry.conversation_id = conversation.conversation_id
           AND entry.seq = conversation.close_seq
          JOIN chat.generation_states AS state
            ON state.conversation_id = conversation.conversation_id
           AND state.generation = conversation.close_generation
           AND state.state_version = conversation.close_state_version
         WHERE conversation.conversation_id = $1
        "#,
    )
    .bind(conversation_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(InventoryRepositoryError::DurableRowInvalid)
}

#[cfg(not(test))]
#[derive(Debug, FromRow)]
struct ConversationCloseSourceRow {
    kind: String,
    lifecycle: String,
    closed_at: DateTime<Utc>,
    close_transition_id: Uuid,
    close_generation: i64,
    close_state_version: i64,
    close_seq: i64,
    closed_by_did: String,
    closed_by_device_id: Uuid,
    close_outer_entry_fingerprint: Vec<u8>,
    close_group_id: Vec<u8>,
    close_epoch: i64,
    close_group_context_hash: Vec<u8>,
    close_confirmation_tag: Vec<u8>,
}

/// The exact schedule-terminal proof row for one recipient/conversation.
#[cfg(not(test))]
async fn load_schedule_terminal_proof(
    transaction: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    user_did: &str,
    device_id: Uuid,
) -> Result<Option<ScheduleTerminalProofRow>, InventoryRepositoryError> {
    Ok(sqlx::query_as(
        r#"
        SELECT terminal_seq, transition_id, outer_entry_fingerprint
          FROM chat.application_schedule_terminal_proofs
         WHERE conversation_id = $1 AND recipient_did = $2 AND recipient_device_id = $3
        "#,
    )
    .bind(conversation_id)
    .bind(user_did)
    .bind(device_id)
    .fetch_optional(&mut **transaction)
    .await?)
}

#[cfg(not(test))]
#[derive(Debug, FromRow)]
struct ScheduleTerminalProofRow {
    terminal_seq: i64,
    transition_id: Uuid,
    outer_entry_fingerprint: Vec<u8>,
}

/// The complete retained Welcome source for the exact device's pending
/// deliveries: every checked field of `RetainedWelcomeProjectionSource`,
/// derived from the delivery, bundle, and conversation rows.
#[cfg(not(test))]
async fn retained_welcome_sources(
    transaction: &mut Transaction<'_, Postgres>,
    user_did: &str,
    device_id: Uuid,
) -> Result<
    Vec<(
        Uuid,
        super::super::read_projection::RetainedWelcomeProjectionSource,
    )>,
    InventoryRepositoryError,
> {
    use super::super::read_projection::{
        CheckedConversationCoordinates, CheckedWelcomeProvenance, RetainedWelcomeProjectionSource,
    };
    let rows: Vec<WelcomeSourceRow> = sqlx::query_as(
        r#"
        SELECT wd.welcome_id, wb.conversation_id, wb.entry_seq, wb.generation,
               wb.state_version, wb.group_id, wb.epoch, wb.group_context_hash,
               wb.confirmation_tag, conversation.lifecycle, wd.status,
               wb.wrapper_bytes, wb.wrapper_sha256,
               wd.recipient_did, wd.recipient_device_id,
               wd.recovery_request_id, wd.key_package_ref, wd.expires_at
          FROM chat.welcome_deliveries AS wd
          JOIN chat.welcome_bundles AS wb ON wb.welcome_id = wd.welcome_id
          JOIN chat.conversations AS conversation
            ON conversation.conversation_id = wb.conversation_id
         WHERE wd.recipient_did = $1
           AND wd.recipient_device_id = $2
           AND wd.status = 'pending'
         ORDER BY wd.welcome_id
        "#,
    )
    .bind(user_did)
    .bind(device_id)
    .fetch_all(&mut **transaction)
    .await?;
    let mut sources = Vec::with_capacity(rows.len());
    for row in rows {
        let coordinates = CheckedConversationCoordinates::new(
            &row.conversation_id.to_string(),
            row.generation,
            row.state_version,
            &row.group_id,
            row.epoch,
            &row.group_context_hash,
            &row.confirmation_tag,
            &row.lifecycle,
        )
        .map_err(InventoryRepositoryError::Projection)?;
        let provenance = CheckedWelcomeProvenance::new(
            &row.recovery_request_id.to_string(),
            &row.key_package_ref,
        )
        .map_err(InventoryRepositoryError::Projection)?;
        let source = RetainedWelcomeProjectionSource::new(
            &row.welcome_id.to_string(),
            &row.conversation_id.to_string(),
            row.entry_seq,
            coordinates,
            &row.status,
            &row.wrapper_bytes,
            &row.wrapper_sha256,
            &row.recipient_did,
            &row.recipient_device_id.to_string(),
            provenance,
            &canonical_datetime(row.expires_at),
        )
        .map_err(InventoryRepositoryError::Projection)?;
        sources.push((row.welcome_id, source));
    }
    Ok(sources)
}

#[cfg(not(test))]
#[derive(Debug, FromRow)]
struct WelcomeSourceRow {
    welcome_id: Uuid,
    conversation_id: Uuid,
    entry_seq: i64,
    generation: i64,
    state_version: i64,
    group_id: Vec<u8>,
    epoch: i64,
    group_context_hash: Vec<u8>,
    confirmation_tag: Vec<u8>,
    lifecycle: String,
    status: String,
    wrapper_bytes: Vec<u8>,
    wrapper_sha256: Vec<u8>,
    recipient_did: String,
    recipient_device_id: Uuid,
    recovery_request_id: Uuid,
    key_package_ref: Vec<u8>,
    expires_at: DateTime<Utc>,
}

/// One retained recovery inbox entry: the closed `LeafRecoveryInboxInput`
/// plus the durable item identity the materialization row needs.
#[cfg(not(test))]
struct RetainedRecoveryInboxEntry {
    item_kind: &'static str,
    leaf_recovery_request_id: Option<Uuid>,
    recovery_work_id: Option<Uuid>,
    item_key_bytes: Vec<u8>,
    input: super::super::read_projection::LeafRecoveryInboxInput,
}

/// Every retained leaf-recovery request (all five statuses) and every retained
/// recovery-work item (all three statuses) for the exact device, in the
/// canonical 0x00-requests-then-0x01-work ordinal order.
#[cfg(not(test))]
async fn retained_recovery_inbox_entries(
    transaction: &mut Transaction<'_, Postgres>,
    user_did: &str,
    device_id: Uuid,
) -> Result<Vec<RetainedRecoveryInboxEntry>, InventoryRepositoryError> {
    use super::super::read_projection::{
        CheckedConversationCoordinates, CheckedKeyPackageArtifact, CheckedLeafRecoveryReservation,
        LeafRecoveryInboxInput, RetainedLeafRecoveryProjectionSource,
        RetainedRecoveryWorkProjectionSource, RetainedRecoveryWorkTerminal,
    };
    let mut entries = Vec::new();

    let request_rows: Vec<LeafRecoverySourceRow> = sqlx::query_as(
        r#"
        SELECT request.recovery_request_id, request.conversation_id,
               request.generation, request.requester_did,
               request.requester_device_id, request.requester_key_id,
               request.requester_auth_generation, request.recovery_kind,
               request.bound_state_version, request.bound_group_id,
               request.bound_epoch, request.bound_group_context_hash,
               request.bound_confirmation_tag, request.status,
               request.requested_at, request.expires_at,
               conversation.lifecycle AS conversation_lifecycle,
               reservation.conversation_id AS reservation_conversation_id,
               reservation.generation AS reservation_generation,
               reservation.requester_did AS reservation_requester_did,
               reservation.requester_device_id AS reservation_requester_device_id,
               reservation.requester_key_id AS reservation_requester_key_id,
               reservation.requester_auth_generation
                   AS reservation_requester_auth_generation,
               reservation.key_package_ref AS reservation_key_package_ref,
               reservation.bound_state_version AS reservation_bound_state_version,
               reservation.bound_group_id AS reservation_bound_group_id,
               reservation.bound_epoch AS reservation_bound_epoch,
               reservation.bound_group_context_hash
                   AS reservation_bound_group_context_hash,
               reservation.bound_confirmation_tag AS reservation_bound_confirmation_tag,
               reservation.status AS reservation_status,
               reservation.expires_at AS reservation_expires_at,
               package.wrapper_bytes AS package_wrapper_bytes,
               package.wrapper_sha256 AS package_wrapper_sha256
          FROM chat.leaf_recovery_requests AS request
          JOIN chat.key_package_reservations AS reservation
            ON reservation.recovery_request_id = request.recovery_request_id
          JOIN chat.key_packages AS package
            ON package.key_package_ref = reservation.key_package_ref
          JOIN chat.conversations AS conversation
            ON conversation.conversation_id = request.conversation_id
         WHERE request.requester_did = $1
           AND request.requester_device_id = $2
         ORDER BY request.recovery_request_id
        "#,
    )
    .bind(user_did)
    .bind(device_id)
    .fetch_all(&mut **transaction)
    .await?;
    for row in request_rows {
        // The reservation's coordinate, identity, and status come from the
        // RESERVATION row's OWN columns; the view's coordinate comes from the
        // REQUEST row's own bound columns. The C1 checked constructors then
        // cross-check the two durable sources (request row vs reservation
        // row), so a durable drift fails closed instead of being normalized
        // into canonical bytes.
        let reservation_bound_coordinate = CheckedConversationCoordinates::new(
            &row.reservation_conversation_id.to_string(),
            row.reservation_generation,
            row.reservation_bound_state_version,
            &row.reservation_bound_group_id,
            row.reservation_bound_epoch,
            &row.reservation_bound_group_context_hash,
            &row.reservation_bound_confirmation_tag,
            &row.conversation_lifecycle,
        )
        .map_err(InventoryRepositoryError::Projection)?;
        let key_package = CheckedKeyPackageArtifact::new(
            INVENTORY_KEY_PACKAGE_FRAMING,
            INVENTORY_KEY_PACKAGE_CONTENT_TYPE,
            &row.package_wrapper_bytes,
            &row.package_wrapper_sha256,
            &row.reservation_key_package_ref,
        )
        .map_err(InventoryRepositoryError::Projection)?;
        let reservation = CheckedLeafRecoveryReservation::new(
            &row.recovery_request_id.to_string(),
            &row.reservation_conversation_id.to_string(),
            reservation_bound_coordinate,
            &row.reservation_requester_did,
            &row.reservation_requester_device_id.to_string(),
            &row.reservation_requester_key_id,
            row.reservation_requester_auth_generation,
            &row.reservation_key_package_ref,
            INVENTORY_CIPHER_SUITE_V1,
            "leafRecovery",
            &row.reservation_status,
            &canonical_datetime(row.reservation_expires_at),
            key_package,
        )
        .map_err(InventoryRepositoryError::Projection)?;
        // The view's bound coordinate is re-derived from the REQUEST row; the
        // C1 constructor cross-checks the reservation's coordinate against it
        // and fails closed on any divergence.
        let bound_coordinate = CheckedConversationCoordinates::new(
            &row.conversation_id.to_string(),
            row.generation,
            row.bound_state_version,
            &row.bound_group_id,
            row.bound_epoch,
            &row.bound_group_context_hash,
            &row.bound_confirmation_tag,
            &row.conversation_lifecycle,
        )
        .map_err(InventoryRepositoryError::Projection)?;
        let source = RetainedLeafRecoveryProjectionSource::new(
            &row.recovery_request_id.to_string(),
            &row.conversation_id.to_string(),
            &row.requester_did,
            &row.requester_device_id.to_string(),
            &row.recovery_kind,
            bound_coordinate,
            &row.status,
            &canonical_datetime(row.requested_at),
            &canonical_datetime(row.expires_at),
            reservation,
        )
        .map_err(InventoryRepositoryError::Projection)?;
        let input = LeafRecoveryInboxInput::leaf_recovery(source);
        let mut item_key_bytes = vec![0x00u8];
        item_key_bytes.extend_from_slice(row.recovery_request_id.as_bytes());
        entries.push(RetainedRecoveryInboxEntry {
            item_kind: "leafRecoveryRequest",
            leaf_recovery_request_id: Some(row.recovery_request_id),
            recovery_work_id: None,
            item_key_bytes,
            input,
        });
    }

    let work_rows: Vec<RecoveryWorkSourceRow> = sqlx::query_as(
        r#"
        SELECT work.recovery_work_id, work.conversation_id,
               work.recipient_did, work.recipient_device_id,
               work.source_kind, work.source_id, work.status,
               work.terminal_transition_id, work.terminal_revocation_id,
               work.created_at, work.terminal_at,
               conversation.lifecycle AS conversation_lifecycle,
               state.group_id AS state_group_id, state.epoch AS state_epoch,
               state.group_context_hash AS state_group_context_hash,
               state.confirmation_tag AS state_confirmation_tag
          FROM chat.recovery_work_items AS work
          JOIN chat.conversations AS conversation
            ON conversation.conversation_id = work.conversation_id
          JOIN chat.generation_states AS state
            ON state.conversation_id = work.conversation_id
           AND state.generation = work.generation
           AND state.state_version = work.state_version
         WHERE work.recipient_did = $1
           AND work.recipient_device_id = $2
         ORDER BY work.recovery_work_id
        "#,
    )
    .bind(user_did)
    .bind(device_id)
    .fetch_all(&mut **transaction)
    .await?;
    for row in work_rows {
        let source_coordinate = CheckedConversationCoordinates::new(
            &row.conversation_id.to_string(),
            row.generation,
            row.state_version,
            &row.state_group_id,
            row.state_epoch,
            &row.state_group_context_hash,
            &row.state_confirmation_tag,
            &row.conversation_lifecycle,
        )
        .map_err(InventoryRepositoryError::Projection)?;
        let terminal = match row.status.as_str() {
            "pending" => RetainedRecoveryWorkTerminal::Pending,
            "completed" => {
                let terminal_transition_id = row
                    .terminal_transition_id
                    .ok_or(InventoryRepositoryError::DurableRowInvalid)?;
                let terminal_at = row
                    .terminal_at
                    .ok_or(InventoryRepositoryError::DurableRowInvalid)?;
                RetainedRecoveryWorkTerminal::CompletedByTransition {
                    terminal_transition_id: SmolStr::from(terminal_transition_id.to_string()),
                    terminal_at: SmolStr::from(canonical_datetime(terminal_at)),
                }
            }
            "superseded" => {
                let terminal_at = row
                    .terminal_at
                    .ok_or(InventoryRepositoryError::DurableRowInvalid)?;
                match row.terminal_revocation_id {
                    Some(terminal_revocation_id) => {
                        RetainedRecoveryWorkTerminal::SupersededByRevocation {
                            terminal_revocation_id: SmolStr::from(
                                terminal_revocation_id.to_string(),
                            ),
                            terminal_at: SmolStr::from(canonical_datetime(terminal_at)),
                        }
                    }
                    None => RetainedRecoveryWorkTerminal::SupersededByTransition {
                        terminal_transition_id: SmolStr::from(
                            row.terminal_transition_id
                                .ok_or(InventoryRepositoryError::DurableRowInvalid)?
                                .to_string(),
                        ),
                        terminal_at: SmolStr::from(canonical_datetime(terminal_at)),
                    },
                }
            }
            _ => return Err(InventoryRepositoryError::DurableRowInvalid),
        };
        let source = RetainedRecoveryWorkProjectionSource::new(
            &row.recovery_work_id.to_string(),
            &row.conversation_id.to_string(),
            &row.recipient_did,
            &row.recipient_device_id.to_string(),
            &row.source_kind,
            &row.source_id.to_string(),
            source_coordinate,
            &canonical_datetime(row.created_at),
            terminal,
        )
        .map_err(InventoryRepositoryError::Projection)?;
        // The closed terminal-shape constructors fail on a wrong arm.
        let input = match row.status.as_str() {
            "pending" => LeafRecoveryInboxInput::recovery_work_pending(source),
            "completed" => LeafRecoveryInboxInput::recovery_work_completed_by_transition(source),
            "superseded" if row.terminal_revocation_id.is_some() => {
                LeafRecoveryInboxInput::recovery_work_superseded_by_revocation(source)
            }
            "superseded" => LeafRecoveryInboxInput::recovery_work_superseded_by_transition(source),
            _ => return Err(InventoryRepositoryError::DurableRowInvalid),
        }
        .map_err(InventoryRepositoryError::Projection)?;
        let mut item_key_bytes = vec![0x01u8];
        item_key_bytes.extend_from_slice(row.recovery_work_id.as_bytes());
        entries.push(RetainedRecoveryInboxEntry {
            item_kind: "recoveryWork",
            leaf_recovery_request_id: None,
            recovery_work_id: Some(row.recovery_work_id),
            item_key_bytes,
            input,
        });
    }
    Ok(entries)
}

#[cfg(not(test))]
#[derive(Debug, FromRow)]
struct LeafRecoverySourceRow {
    recovery_request_id: Uuid,
    conversation_id: Uuid,
    generation: i64,
    requester_did: String,
    requester_device_id: Uuid,
    requester_key_id: String,
    requester_auth_generation: i64,
    recovery_kind: String,
    bound_state_version: i64,
    bound_group_id: Vec<u8>,
    bound_epoch: i64,
    bound_group_context_hash: Vec<u8>,
    bound_confirmation_tag: Vec<u8>,
    status: String,
    requested_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    conversation_lifecycle: String,
    reservation_conversation_id: Uuid,
    reservation_generation: i64,
    reservation_requester_did: String,
    reservation_requester_device_id: Uuid,
    reservation_requester_key_id: String,
    reservation_requester_auth_generation: i64,
    reservation_key_package_ref: Vec<u8>,
    reservation_bound_state_version: i64,
    reservation_bound_group_id: Vec<u8>,
    reservation_bound_epoch: i64,
    reservation_bound_group_context_hash: Vec<u8>,
    reservation_bound_confirmation_tag: Vec<u8>,
    reservation_status: String,
    reservation_expires_at: DateTime<Utc>,
    package_wrapper_bytes: Vec<u8>,
    package_wrapper_sha256: Vec<u8>,
}

#[cfg(not(test))]
#[derive(Debug, FromRow)]
struct RecoveryWorkSourceRow {
    recovery_work_id: Uuid,
    conversation_id: Uuid,
    generation: i64,
    state_version: i64,
    recipient_did: String,
    recipient_device_id: Uuid,
    source_kind: String,
    source_id: Uuid,
    status: String,
    terminal_transition_id: Option<Uuid>,
    terminal_revocation_id: Option<Uuid>,
    created_at: DateTime<Utc>,
    terminal_at: Option<DateTime<Utc>>,
    conversation_lifecycle: String,
    state_group_id: Vec<u8>,
    state_epoch: i64,
    state_group_context_hash: Vec<u8>,
    state_confirmation_tag: Vec<u8>,
}

/// The G7 materialization aggregate transcript reader: count, min/max ordinal,
/// payload-byte sum, and the digest EXACTLY as
/// `chat.assert_inventory_materialization` recomputes it (item kind + tagged
/// arm provenance + payload length included for the conversation domain).
#[cfg(not(test))]
async fn read_g7_materialization_digest(
    transaction: &mut Transaction<'_, Postgres>,
    domain: InventoryPageDomain,
    inventory_session_id: Uuid,
) -> Result<(u64, [u8; 32], u64), InventoryRepositoryError> {
    let sql = match domain {
        InventoryPageDomain::Conversations => {
            r#"
            SELECT count(*) AS item_count, min(ordinal) AS minimum_ordinal,
                   max(ordinal) AS maximum_ordinal,
                   COALESCE(sum(octet_length(payload_bytes))::BIGINT, 0) AS payload_bytes,
                   digest(COALESCE(string_agg(
                       int8send(ordinal)
                       || item_key_bytes
                       || int4send(octet_length(convert_to(item_kind, 'UTF8')))
                       || convert_to(item_kind, 'UTF8')
                       || CASE WHEN participant_period_id IS NULL
                               THEN decode('00', 'hex')
                               ELSE decode('01', 'hex') || uuid_send(participant_period_id) END
                       || CASE WHEN membership_interval_id IS NULL
                               THEN decode('00', 'hex')
                               ELSE decode('01', 'hex') || uuid_send(membership_interval_id) END
                       || CASE WHEN interval_terminal_seq IS NULL
                               THEN decode('00', 'hex')
                               ELSE decode('01', 'hex') || int8send(interval_terminal_seq) END
                       || CASE WHEN interval_closing_transition_id IS NULL
                               THEN decode('00', 'hex')
                               ELSE decode('01', 'hex') || uuid_send(interval_closing_transition_id) END
                       || CASE WHEN interval_closing_outer_entry_fingerprint IS NULL
                               THEN decode('00', 'hex')
                               ELSE decode('01', 'hex')
                                    || interval_closing_outer_entry_fingerprint END
                       || CASE WHEN interval_removed_at IS NULL
                               THEN decode('00', 'hex')
                               ELSE decode('01', 'hex') || timestamptz_send(interval_removed_at) END
                       || CASE WHEN schedule_terminal_seq IS NULL
                               THEN decode('00', 'hex')
                               ELSE decode('01', 'hex') || int8send(schedule_terminal_seq) END
                       || CASE WHEN schedule_terminal_transition_id IS NULL
                               THEN decode('00', 'hex')
                               ELSE decode('01', 'hex')
                                    || uuid_send(schedule_terminal_transition_id) END
                       || CASE WHEN schedule_terminal_outer_entry_fingerprint IS NULL
                               THEN decode('00', 'hex')
                               ELSE decode('01', 'hex')
                                    || schedule_terminal_outer_entry_fingerprint END
                       || payload_sha256
                       || int8send(octet_length(payload_bytes)::BIGINT),
                       decode('', 'hex') ORDER BY ordinal
                   ), decode('', 'hex')), 'sha256') AS items_sha256
              FROM chat.inventory_conversation_items
             WHERE inventory_session_id = $1
            "#
        }
        InventoryPageDomain::PendingWelcomes => {
            r#"
            SELECT count(*) AS item_count, min(ordinal) AS minimum_ordinal,
                   max(ordinal) AS maximum_ordinal,
                   COALESCE(sum(octet_length(payload_bytes))::BIGINT, 0) AS payload_bytes,
                   digest(COALESCE(string_agg(
                       int8send(ordinal)
                       || item_key_bytes
                       || payload_sha256
                       || int8send(octet_length(payload_bytes)::BIGINT),
                       decode('', 'hex') ORDER BY ordinal
                   ), decode('', 'hex')), 'sha256') AS items_sha256
              FROM chat.inventory_welcome_items
             WHERE inventory_session_id = $1
            "#
        }
        InventoryPageDomain::LeafRecovery => {
            r#"
            SELECT count(*) AS item_count, min(ordinal) AS minimum_ordinal,
                   max(ordinal) AS maximum_ordinal,
                   COALESCE(sum(octet_length(payload_bytes))::BIGINT, 0) AS payload_bytes,
                   digest(COALESCE(string_agg(
                       int8send(ordinal)
                       || item_key_bytes
                       || payload_sha256
                       || int8send(octet_length(payload_bytes)::BIGINT),
                       decode('', 'hex') ORDER BY ordinal
                   ), decode('', 'hex')), 'sha256') AS items_sha256
              FROM chat.inventory_recovery_items
             WHERE inventory_session_id = $1
            "#
        }
    };
    let row: G7MaterializationDigestRow = sqlx::query_as(sql)
        .bind(inventory_session_id)
        .fetch_one(&mut **transaction)
        .await?;
    let item_count = database_protocol_integer(row.item_count)
        .map_err(|_| InventoryRepositoryError::InvalidMaterialization)?;
    let items_sha256 = fixed_hash(row.items_sha256)
        .map_err(|_| InventoryRepositoryError::InvalidMaterialization)?;
    let payload_bytes = database_protocol_integer(row.payload_bytes)
        .map_err(|_| InventoryRepositoryError::InvalidMaterialization)?;
    let shape_valid = if item_count == 0 {
        row.minimum_ordinal.is_none() && row.maximum_ordinal.is_none()
    } else {
        row.minimum_ordinal == Some(0)
            && row.maximum_ordinal
                == Some(
                    i64::try_from(item_count - 1)
                        .map_err(|_| InventoryRepositoryError::InvalidMaterialization)?,
                )
    };
    if !shape_valid || items_sha256 == [0; 32] {
        return Err(InventoryRepositoryError::InvalidMaterialization);
    }
    Ok((item_count, items_sha256, payload_bytes))
}

#[cfg(not(test))]
#[derive(Debug, FromRow)]
struct G7MaterializationDigestRow {
    item_count: i64,
    minimum_ordinal: Option<i64>,
    maximum_ordinal: Option<i64>,
    payload_bytes: i64,
    items_sha256: Vec<u8>,
}
