// Transaction-bound inventory continuation authority.
//
// A page cursor is authenticated twice: first as non-authorizing lookup
// material, then against the exact retained inventory session selected and
// locked by its token hash. No raw inventory-session token is persisted.

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, Postgres, QueryBuilder, Transaction};
use thiserror::Error;
use uuid::{Uuid, Variant, Version};

use super::super::{
    cursor::{
        inventory_item_key_hash, opaque_binding_hash, CursorCodec, CursorCodecError,
        DeviceCursorBinding, EventCursor, InventoryPageBinding, InventoryPageCursor,
        InventoryPageDomain, InventoryPageLocator, InventorySessionBinding, InventorySessionToken,
        LockedInventoryPageVerification,
    },
    validation::{ed25519_key_id, BareDid, KeyThumbprint},
};

const MAX_PROTOCOL_INTEGER: u64 = 9_007_199_254_740_991;
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
    #[error(transparent)]
    Cursor(#[from] CursorCodecError),
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

impl PartialEq for InventoryRepositoryError {
    fn eq(&self, other: &Self) -> bool {
        use InventoryRepositoryError::{
            BoundaryItemMismatch, Cursor, DeviceAuthorityMismatch, DomainAlreadyComplete,
            DurableRowInvalid, InvalidMaterialization, ProtocolFenceMismatch, RaceOrReuse,
            SessionNotFound, SessionPresentationMismatch, TransactionMismatch,
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
            | (InvalidMaterialization, InvalidMaterialization) => true,
            (Cursor(left), Cursor(right)) => left == right,
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
    jkt: String,
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
    jkt: String,
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
    current_dpop_jkt: String,
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
            || KeyThumbprint::parse(&jkt).is_err()
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
            &jkt,
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

    fn cursor_evidence(
        &self,
        codec: &CursorCodec,
        domain: InventoryPageDomain,
        raw_inventory_session: Option<&str>,
        canonical_filter: &[u8],
    ) -> Result<LockedInventoryCursorEvidence, InventoryRepositoryError> {
        let did = BareDid::parse(&self.user_did)
            .map_err(|_| InventoryRepositoryError::DurableRowInvalid)?;
        let jkt = KeyThumbprint::parse(&self.jkt)
            .map_err(|_| InventoryRepositoryError::DurableRowInvalid)?;
        let device = DeviceCursorBinding::new(&did, self.device_id, self.auth_generation, &jkt)?;
        let now =
            unix_seconds(self.locked_at).ok_or(InventoryRepositoryError::DurableRowInvalid)?;
        let expires_at =
            unix_seconds(self.expires_at).ok_or(InventoryRepositoryError::DurableRowInvalid)?;
        let created_at =
            unix_seconds(self.created_at).ok_or(InventoryRepositoryError::DurableRowInvalid)?;
        let event_cursor = codec.hydrate_event_cursor(
            &self.snapshot_event_cursor_bytes,
            self.snapshot_event_cursor_sha256,
            &device,
            self.snapshot_event_position,
            expires_at,
            now,
            self.retained_floor,
            self.head_event_position,
        )?;
        let session_binding = codec.bind_inventory_session(
            device,
            self.inventory_session_id,
            &event_cursor,
            self.snapshot_event_position,
            expires_at,
            now,
            self.retained_floor,
            self.head_event_position,
        )?;
        let inventory_session = if let Some(encoded) = raw_inventory_session {
            if !opaque_binding_hash(encoded.as_bytes())
                .is_ok_and(|presented| presented == self.token_hash)
            {
                return Err(InventoryRepositoryError::SessionPresentationMismatch);
            }
            codec
                .hydrate_inventory_session_token(
                    encoded.as_bytes(),
                    self.token_hash,
                    &session_binding,
                    now,
                    self.retained_floor,
                    self.head_event_position,
                )
                .map_err(|_| InventoryRepositoryError::SessionPresentationMismatch)?
        } else {
            let reconstructed = codec.issue_inventory_session_id(
                &session_binding,
                created_at,
                self.retained_floor,
                self.head_event_position,
            )?;
            if reconstructed.binding_hash() != self.token_hash {
                return Err(InventoryRepositoryError::SessionPresentationMismatch);
            }
            reconstructed
        };

        Ok(LockedInventoryCursorEvidence {
            session_binding,
            inventory_session,
            snapshot_event_cursor: event_cursor,
            domain,
            canonical_filter: canonical_filter.to_vec(),
            now,
            retained_floor: self.retained_floor,
            maximum_event_position: self.head_event_position,
        })
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

pub(crate) fn seal_conversation_inventory_page(
    codec: &CursorCodec,
    encoded: &str,
    locator: InventoryPageLocator,
    guard: LockedInventorySessionGuard,
    canonical_filter: &[u8],
) -> Result<InventoryPageReadAuthority, InventoryRepositoryError> {
    seal_inventory_page(
        codec,
        encoded,
        locator,
        guard,
        InventoryPageDomain::Conversations,
        None,
        canonical_filter,
    )
}

pub(crate) fn seal_pending_welcome_inventory_page(
    codec: &CursorCodec,
    encoded: &str,
    locator: InventoryPageLocator,
    guard: LockedInventorySessionGuard,
    raw_inventory_session_id: &str,
    canonical_filter: &[u8],
) -> Result<InventoryPageReadAuthority, InventoryRepositoryError> {
    seal_inventory_page(
        codec,
        encoded,
        locator,
        guard,
        InventoryPageDomain::PendingWelcomes,
        Some(raw_inventory_session_id),
        canonical_filter,
    )
}

pub(crate) fn seal_recovery_inventory_page(
    codec: &CursorCodec,
    encoded: &str,
    locator: InventoryPageLocator,
    guard: LockedInventorySessionGuard,
    raw_inventory_session_id: &str,
    canonical_filter: &[u8],
) -> Result<InventoryPageReadAuthority, InventoryRepositoryError> {
    seal_inventory_page(
        codec,
        encoded,
        locator,
        guard,
        InventoryPageDomain::LeafRecovery,
        Some(raw_inventory_session_id),
        canonical_filter,
    )
}

#[allow(clippy::too_many_arguments)]
fn seal_inventory_page(
    codec: &CursorCodec,
    encoded: &str,
    locator: InventoryPageLocator,
    guard: LockedInventorySessionGuard,
    domain: InventoryPageDomain,
    raw_inventory_session_id: Option<&str>,
    canonical_filter: &[u8],
) -> Result<InventoryPageReadAuthority, InventoryRepositoryError> {
    if guard.completion(domain).is_complete() {
        return Err(InventoryRepositoryError::DomainAlreadyComplete);
    }
    let evidence =
        guard.cursor_evidence(codec, domain, raw_inventory_session_id, canonical_filter)?;
    let LockedInventoryPageVerification {
        verified,
        binding: page_binding,
    } = codec.verify_located_inventory_page_cursor(encoded, locator, evidence)?;
    let verified_cursor_hash = opaque_binding_hash(encoded.as_bytes())?;
    Ok(InventoryPageReadAuthority {
        session: guard,
        domain: verified.domain(),
        verified_cursor_hash,
        last_ordinal: verified.last_ordinal(),
        item_key_hash: verified.item_key_hash(),
        page_binding,
    })
}

#[derive(Debug, FromRow)]
struct InventorySessionRow {
    inventory_session_id: Uuid,
    token_hash: Vec<u8>,
    user_did: String,
    device_id: Uuid,
    jkt: String,
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
    current_dpop_jkt: String,
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

/// Issues the next page cursor only while the transaction that read the page
/// still owns the exact session/fence guard.
pub(crate) async fn issue_next_inventory_page_cursor(
    transaction: &mut Transaction<'_, Postgres>,
    codec: &CursorCodec,
    authority: InventoryPageContinuationAuthority,
) -> Result<InventoryPageCursor, InventoryRepositoryError> {
    let transaction_id = current_transaction_id(transaction).await?;
    if transaction_id != authority.session.transaction_id {
        return Err(InventoryRepositoryError::TransactionMismatch);
    }
    let issued_at = unix_seconds(authority.session.locked_at)
        .ok_or(InventoryRepositoryError::DurableRowInvalid)?;
    let cursor = codec.issue_inventory_page_cursor(
        &authority.page_binding,
        authority.last_ordinal,
        &authority.item_key_bytes,
        issued_at,
        authority.session.retained_floor,
        authority.session.head_event_position,
    )?;
    let _consumed_prior_cursor_hash = authority.verified_cursor_hash;
    Ok(cursor)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InventoryCompletionReceipt {
    inventory_session_id: Uuid,
    domain: InventoryPageDomain,
    item_count: u64,
    items_sha256: [u8; 32],
}

impl InventoryCompletionReceipt {
    pub(crate) fn inventory_session_id(self) -> Uuid {
        self.inventory_session_id
    }

    pub(crate) fn domain(self) -> InventoryPageDomain {
        self.domain
    }

    pub(crate) fn item_count(self) -> u64 {
        self.item_count
    }

    pub(crate) fn items_sha256(self) -> [u8; 32] {
        self.items_sha256
    }
}

/// Performs the exact one-way completion CAS. A second consumer, a detached
/// transaction, or any changed durable session field affects zero rows.
pub(crate) async fn complete_inventory_page(
    transaction: &mut Transaction<'_, Postgres>,
    authority: InventoryPageCompletionAuthority,
) -> Result<InventoryCompletionReceipt, InventoryRepositoryError> {
    let transaction_id = current_transaction_id(transaction).await?;
    if transaction_id != authority.session.transaction_id {
        return Err(InventoryRepositoryError::TransactionMismatch);
    }
    if authority.session.completion(authority.domain).is_complete() {
        return Err(InventoryRepositoryError::DomainAlreadyComplete);
    }

    let mut query = QueryBuilder::<Postgres>::new(match authority.domain {
        InventoryPageDomain::Conversations => {
            "UPDATE chat.inventory_sessions SET conversations_complete = TRUE, conversation_item_count = "
        }
        InventoryPageDomain::PendingWelcomes => {
            "UPDATE chat.inventory_sessions SET welcomes_complete = TRUE, welcome_item_count = "
        }
        InventoryPageDomain::LeafRecovery => {
            "UPDATE chat.inventory_sessions SET recovery_complete = TRUE, recovery_item_count = "
        }
    });
    query
        .push_bind(
            i64::try_from(authority.item_count)
                .map_err(|_| InventoryRepositoryError::InvalidMaterialization)?,
        )
        .push(match authority.domain {
            InventoryPageDomain::Conversations => ", conversation_items_sha256 = ",
            InventoryPageDomain::PendingWelcomes => ", welcome_items_sha256 = ",
            InventoryPageDomain::LeafRecovery => ", recovery_items_sha256 = ",
        })
        .push_bind(authority.items_sha256.to_vec())
        .push(" WHERE inventory_session_id = ")
        .push_bind(authority.session.inventory_session_id)
        .push(" AND token_hash = ")
        .push_bind(authority.session.token_hash.to_vec())
        .push(" AND user_did = ")
        .push_bind(&authority.session.user_did)
        .push(" AND device_id = ")
        .push_bind(authority.session.device_id)
        .push(" AND jkt = ")
        .push_bind(&authority.session.jkt)
        .push(" AND auth_generation = ")
        .push_bind(
            i64::try_from(authority.session.auth_generation)
                .map_err(|_| InventoryRepositoryError::DurableRowInvalid)?,
        )
        .push(" AND snapshot_event_position = ")
        .push_bind(
            i64::try_from(authority.session.snapshot_event_position)
                .map_err(|_| InventoryRepositoryError::DurableRowInvalid)?,
        )
        .push(" AND snapshot_event_cursor_bytes = ")
        .push_bind(&authority.session.snapshot_event_cursor_bytes)
        .push(" AND snapshot_event_cursor_sha256 = ")
        .push_bind(authority.session.snapshot_event_cursor_sha256.to_vec())
        .push(" AND created_at = ")
        .push_bind(authority.session.created_at)
        .push(" AND expires_at = ")
        .push_bind(authority.session.expires_at);
    push_completion_predicate(
        &mut query,
        "conversations_complete",
        "conversation_item_count",
        "conversation_items_sha256",
        authority.session.conversations,
    );
    push_completion_predicate(
        &mut query,
        "welcomes_complete",
        "welcome_item_count",
        "welcome_items_sha256",
        authority.session.welcomes,
    );
    push_completion_predicate(
        &mut query,
        "recovery_complete",
        "recovery_item_count",
        "recovery_items_sha256",
        authority.session.recovery,
    );

    let result = query.build().execute(&mut **transaction).await?;
    if result.rows_affected() != 1 {
        return Err(InventoryRepositoryError::RaceOrReuse);
    }
    sqlx::query("SET CONSTRAINTS chat.inventory_sessions_materialization_deferred IMMEDIATE")
        .execute(&mut **transaction)
        .await?;

    let _consumed_cursor_hash = authority.verified_cursor_hash;
    Ok(InventoryCompletionReceipt {
        inventory_session_id: authority.session.inventory_session_id,
        domain: authority.domain,
        item_count: authority.item_count,
        items_sha256: authority.items_sha256,
    })
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

fn push_completion_predicate(
    query: &mut QueryBuilder<'_, Postgres>,
    complete_column: &'static str,
    count_column: &'static str,
    digest_column: &'static str,
    evidence: InventoryCompletionEvidence,
) {
    if evidence.complete {
        query
            .push(" AND ")
            .push(complete_column)
            .push(" = TRUE AND ")
            .push(count_column)
            .push(" = ")
            .push_bind(
                i64::try_from(evidence.item_count.expect("validated complete evidence"))
                    .expect("protocol integer fits i64"),
            )
            .push(" AND ")
            .push(digest_column)
            .push(" = ")
            .push_bind(
                evidence
                    .items_sha256
                    .expect("validated complete evidence")
                    .to_vec(),
            );
    } else {
        query
            .push(" AND ")
            .push(complete_column)
            .push(" = FALSE AND ")
            .push(count_column)
            .push(" IS NULL AND ")
            .push(digest_column)
            .push(" IS NULL");
    }
}

#[cfg(test)]
#[derive(Debug)]
pub(crate) struct InventorySessionLockFixture {
    pub(crate) transaction_id: String,
    pub(crate) inventory_session_id: Uuid,
    pub(crate) token_hash: [u8; 32],
    pub(crate) user_did: String,
    pub(crate) device_id: Uuid,
    pub(crate) jkt: String,
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
    pub(crate) current_dpop_jkt: String,
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
    jkt: &str,
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
    update_text(&mut digest, jkt);
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
