// Row-level + closed-transaction writers for clean-chat ciphertext-blob custody.
//
// This module is the migration-3 (`20260722000003_chat_protocol_blobs.sql`)
// authority. It has two layers, mirroring how the sibling Slice-4 repository
// modules (`inventory.rs`, `welcome.rs`, `ticket.rs`) consolidate their dumb SQL
// and their closed transaction/query semantics into a single self-contained
// repository module:
//
//   * DUMB WRITERS (`insert_prepared_blob`, `apply_usage_delta`,
//     `insert_upload_ticket`, `cas_*`, `insert_blob_binding`, the read helpers) —
//     one write/read shape each, param structs derived column-for-column from the
//     sealed DDL, no re-derivation. The database's CHECK / FK / UNIQUE / partial-
//     index / deferred-trigger constraints remain the ultimate authority.
//
//   * CLOSED TRANSACTION SEMANTICS (`prepare_blob`, `complete_upload`,
//     `bind_application_blob`, `delete_blob`, `expire_due_blobs`) — compose the
//     dumb writers inside ONE caller-owned transaction, validate the purpose /
//     media / size predicates the DDL closes, and keep the maintained
//     `chat.blob_usage` counters exactly reconcilable with the authoritative
//     `chat.blobs` history (see the delta table on each function). They NEVER
//     bypass the conversation state machine: an application binding is inserted
//     as part of the send transaction the executor owns, and this module only
//     supplies the blob-side CAS + binding row.
//
// The ciphertext-blind boundary is structural: this module stores every
// descriptor, AAD, and hash as opaque `BYTEA` and NEVER parses the encrypted
// inner application fields (blurhash, reaction, atprotoRecord, externalLink).
// Those grammars are the shared-Rust client authority (catbird-mls), not the
// delivery service.
//
// Every function is transaction-scoped (`&mut Transaction`); it never commits and
// never opens its own transaction. Caller-supplied timestamps only — never
// `NOW()`.

use std::{
    fmt,
    sync::atomic::{AtomicBool, Ordering},
};

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

/// Ciphertext including the 16-byte AEAD tag is at most 10 MiB.
pub(crate) const MAX_CIPHERTEXT_BYTES: i64 = 10 * 1024 * 1024;
/// Audio ciphertext including the tag is at most 8 MiB.
pub(crate) const MAX_AUDIO_CIPHERTEXT_BYTES: i64 = 8 * 1024 * 1024;
/// The AEAD tag width: `ciphertextSize == plaintextSize + 16` for every blob.
pub(crate) const AEAD_TAG_BYTES: i64 = 16;
/// Capability lifetime after authorization commits. Storage consumption must
/// happen immediately; this is a second fence against queued/stale tokens.
pub(crate) const AUTHORIZED_FETCH_TTL: chrono::Duration = chrono::Duration::seconds(30);

/// Failures the blob writers surface to the composing caller.
#[derive(Debug, thiserror::Error)]
pub(crate) enum BlobRepositoryError {
    /// A database error escaped the transaction (including CHECK / FK / UNIQUE
    /// violations the caller did not specifically expect). The row-shape
    /// authority is the schema; an unexpected violation propagates verbatim.
    #[error("database error: {0}")]
    Database(sqlx::Error),
    /// A compare-and-set matched no row: the stored row's compared columns did
    /// not equal the expected pre-state (a wrong status, a wrong owner, an
    /// already-terminalized blob, or a consumed ticket). Changing nothing is a
    /// conflict, not a silent success.
    #[error("blob compare-and-set conflict")]
    CompareAndSetConflict,
    /// `chat.blobs` primary key collision — the caller reused a blob id.
    #[error("blob already exists")]
    BlobAlreadyExists,
    /// `chat.blob_upload_tickets` collision — a duplicate ticket hash or a second
    /// ticket for one blob.
    #[error("upload ticket conflict")]
    TicketConflict,
    /// A second binding raced for the same blob or the same application entry and
    /// lost the `chat.blob_bindings` PK / `_application_entry_uq` unique index.
    #[error("blob binding conflict")]
    BindingConflict,
    /// The owner's maintained `chat.blob_usage` would exceed the 500 MiB / 100
    /// live-unbound ceilings (`blob_usage_caps_check`).
    #[error("blob quota exceeded")]
    QuotaExceeded,
    /// A single device exceeded its active-blob ceiling
    /// (`assert_blob_device_active_cap`).
    #[error("device active blob cap exceeded")]
    DeviceActiveCapExceeded,
    /// The requested media type is not permitted for the requested purpose
    /// (`blobs_media_type_check`): audio and `image/gif` are attachment-only, and
    /// the metadata-avatar contract is never widened.
    #[error("media type not allowed for purpose")]
    MediaTypeNotAllowedForPurpose,
    /// `ciphertextSize != plaintextSize + 16` — the fixed AEAD-tag relation the
    /// delivery service enforces without decrypting.
    #[error("ciphertext/plaintext size relation invalid")]
    CiphertextSizeRelation,
    /// Ciphertext exceeds the 10 MiB (or 8 MiB audio) ceiling.
    #[error("ciphertext too large")]
    CiphertextTooLarge,
    /// Plaintext size is below the `>= 1` floor.
    #[error("plaintext size invalid")]
    PlaintextSizeInvalid,
    /// The signed binding fragment/purpose does not match its kind: an
    /// application send accepts only `#applicationAttachmentBinding`
    /// (purpose=attachment) and a metadata snapshot only
    /// `#metadataAvatarBinding` (purpose=metadata).
    #[error("blob purpose/binding mismatch")]
    PurposeBindingMismatch,
    /// A bound blob reachable through an application binding had a NULL
    /// `object_store_key`. The `blobs_status_shape_check` guarantees a `bound`
    /// blob carries its object key, so a NULL here is a storage-invariant
    /// violation (corruption), never a "missing optional" — it is surfaced as a
    /// hard error rather than silently coerced to an empty key.
    #[error("object-store identity missing")]
    ObjectStoreKeyMissing,
    #[error("object-store key is not the deterministic blob CID")]
    ObjectStoreIdentityMismatch,
    /// The caller's exact device/auth-generation is not an active device.
    #[error("blob read not authorized")]
    NotAuthorized,
    /// A bound blob is outside its live unbound window or has terminalized.
    #[error("blob expired")]
    BlobExpired,
    /// A post-commit capability was presented to a different transaction.
    #[error("authorization transaction binding mismatch")]
    TransactionBindingMismatch,
    /// A post-commit capability was consumed more than once.
    #[error("authorized fetch already consumed")]
    FetchAlreadyConsumed,
    /// Commit failed after an authorization snapshot was prepared.
    #[error("authorization commit failed: {0}")]
    Commit(sqlx::Error),
}

impl From<sqlx::Error> for BlobRepositoryError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

/// Request material for the repository-owned blob-read authorization.
/// `auth_generation` is deliberately supplied by the verified request and is
/// matched against the live device row inside the same transaction.
#[derive(Clone, Debug)]
pub(crate) struct AuthorizeBlobReadRequest {
    pub(crate) blob_id: Uuid,
    pub(crate) caller_did: String,
    pub(crate) caller_device_id: Uuid,
    pub(crate) auth_generation: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BlobMembershipFence {
    conversation_id: Uuid,
    interval_start_seq: Option<i64>,
    interval_terminal_seq: Option<i64>,
    entry_seq: Option<i64>,
}

/// Physical identity sealed into an authorized read. Fields are private so a
/// handler cannot extract an object-store key and bypass `BlobStore`.
#[derive(Clone)]
pub(crate) struct BlobStorageRequest {
    object_store_key: String,
    derived_cid: String,
    expected_size: i64,
    expected_sha256: [u8; 32],
    media_type: String,
}

impl fmt::Debug for BlobStorageRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BlobStorageRequest")
            .field("expected_size", &self.expected_size)
            .field("media_type", &self.media_type)
            .finish_non_exhaustive()
    }
}

impl BlobStorageRequest {
    pub(crate) fn object_store_key(&self) -> &str {
        &self.object_store_key
    }

    pub(crate) fn derived_cid(&self) -> &str {
        &self.derived_cid
    }

    pub(crate) fn expected_size(&self) -> i64 {
        self.expected_size
    }

    pub(crate) fn expected_sha256(&self) -> &[u8; 32] {
        &self.expected_sha256
    }

    pub(crate) fn media_type(&self) -> &str {
        &self.media_type
    }
}

/// The only value that may cross from authorization into a handler. It is
/// intentionally not `Clone`: an authorized fetch must be moved to storage.
/// The atomic guard additionally makes accidental borrowed re-use fail closed.
#[must_use = "an authorized blob fetch must be consumed by BlobStore"]
pub(crate) struct AuthorizedBlobFetch {
    storage: BlobStorageRequest,
    consumed: AtomicBool,
    // Retain the binding digest and exact auth fence in the capability. They
    // are not exposed to handlers, but make the capability's identity explicit
    // and keep future storage adapters from weakening the binding.
    binding_digest: [u8; 32],
    blob_id: Uuid,
    caller_did: String,
    caller_device_id: Uuid,
    auth_generation: i64,
    revocation_id: Option<Uuid>,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    membership_fence: BlobMembershipFence,
}

impl std::fmt::Debug for AuthorizedBlobFetch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorizedBlobFetch")
            .field("caller_device_id", &self.caller_device_id)
            .field("auth_generation", &self.auth_generation)
            .finish_non_exhaustive()
    }
}

impl AuthorizedBlobFetch {
    /// Revalidate and atomically consume the one-use capability immediately
    /// before a storage adapter is allowed to read. The repository obtains
    /// trusted database time and locks the exact device, binding, interval, or
    /// membership rows; callers cannot substitute a timestamp or fence.
    pub(crate) async fn consume_for_storage(
        &self,
        pool: &PgPool,
    ) -> Result<BlobStorageRequest, BlobRepositoryError> {
        consume_authorized_blob_fetch(pool, self).await
    }

    fn claim_once(&self) -> Result<(), BlobRepositoryError> {
        self.consumed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| BlobRepositoryError::FetchAlreadyConsumed)
    }

    pub(crate) fn binding_digest(&self) -> [u8; 32] {
        self.binding_digest
    }
}

/// Capability material held while the caller-owned SQL transaction is still
/// open. It cannot be turned into an `AuthorizedBlobFetch` until the exact
/// transaction commits successfully.
#[must_use = "publicize the pending capability only after committing its transaction"]
pub(crate) struct PendingAuthorizedBlobFetch<'pool> {
    transaction: BlobAuthorizationTransaction<'pool>,
    storage: BlobStorageRequest,
    binding_digest: [u8; 32],
    blob_id: Uuid,
    caller_did: String,
    caller_device_id: Uuid,
    auth_generation: i64,
    revocation_id: Option<Uuid>,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    membership_fence: BlobMembershipFence,
}

impl std::fmt::Debug for PendingAuthorizedBlobFetch<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingAuthorizedBlobFetch")
            .field("issued_at", &self.issued_at)
            .field("caller_device_id", &self.caller_device_id)
            .field("auth_generation", &self.auth_generation)
            .finish_non_exhaustive()
    }
}

impl PendingAuthorizedBlobFetch<'_> {
    /// Consume the pending repository capability and commit its owning
    /// transaction. This method is the only legal transition to a post-commit
    /// `AuthorizedBlobFetch`.
    pub(crate) async fn publicize(self) -> Result<AuthorizedBlobFetch, BlobRepositoryError> {
        publicize_authorized_blob_fetch(self).await
    }
}

/// G7 storage identity authority. Upload completion happens before a binding
/// row exists, so the physical key is derived from the immutable blob id and
/// ciphertext hash (the schema's blob identity columns), not a later mutable
/// authorization snapshot. Every upload, completion CAS, authorization query,
/// object metadata check, and test uses this same derivation.
pub(crate) fn derive_blob_cid(blob_id: Uuid, ciphertext_sha256: &[u8; 32]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-G7-BLOB-CID-V1\0");
    digest.update(blob_id.as_bytes());
    digest.update(ciphertext_sha256);
    hex::encode(digest.finalize())
}

fn object_store_key_matches(blob_id: Uuid, ciphertext_sha256: &[u8; 32], key: &str) -> bool {
    key == derive_blob_cid(blob_id, ciphertext_sha256)
}

/// The only constructor for a blob authorization transaction. It begins from
/// a pool directly, so a nested SQLx savepoint/transaction cannot be passed to
/// the authority API by type. Callers must use the returned top-level owner.
pub(crate) struct BlobAuthorizationTransaction<'pool> {
    transaction: Option<Transaction<'pool, Postgres>>,
}

impl<'pool> BlobAuthorizationTransaction<'pool> {
    pub(crate) async fn begin(pool: &'pool PgPool) -> Result<Self, BlobRepositoryError> {
        Ok(Self {
            transaction: Some(pool.begin().await?),
        })
    }

    fn transaction_mut(
        &mut self,
    ) -> Result<&mut Transaction<'pool, Postgres>, BlobRepositoryError> {
        self.transaction
            .as_mut()
            .ok_or(BlobRepositoryError::TransactionBindingMismatch)
    }

    async fn rollback(mut self) {
        if let Some(transaction) = self.transaction.take() {
            let _ = transaction.rollback().await;
        }
    }

    async fn commit(mut self) -> Result<(), BlobRepositoryError> {
        self.transaction
            .take()
            .ok_or(BlobRepositoryError::TransactionBindingMismatch)?
            .commit()
            .await
            .map_err(BlobRepositoryError::Commit)
    }
}

fn binding_digest(
    descriptor_sha256: &[u8],
    aad_sha256: &[u8],
    ciphertext_sha256: &[u8],
) -> Result<[u8; 32], BlobRepositoryError> {
    if descriptor_sha256.len() != 32 || aad_sha256.len() != 32 || ciphertext_sha256.len() != 32 {
        return Err(BlobRepositoryError::Database(sqlx::Error::Protocol(
            "invalid blob binding digest length".to_owned(),
        )));
    }
    let mut digest = Sha256::new();
    digest.update(descriptor_sha256);
    digest.update(aad_sha256);
    digest.update(ciphertext_sha256);
    Ok(digest.finalize().into())
}

/// True when `error` is a unique-violation (SQLSTATE 23505) raised by the named
/// constraint. Maps an expected uniqueness collision to a typed variant while
/// letting every other database error propagate unchanged.
fn is_unique_violation(error: &sqlx::Error, constraint: &str) -> bool {
    error
        .as_database_error()
        .filter(|db| db.code().as_deref() == Some("23505"))
        .and_then(|db| db.constraint())
        == Some(constraint)
}

/// True when `error` is a check-violation (SQLSTATE 23514) raised by the named
/// constraint. Used to surface the maintained-counter ceiling as a typed
/// `QuotaExceeded` rather than an opaque check-violation.
fn is_check_violation(error: &sqlx::Error, constraint: &str) -> bool {
    error
        .as_database_error()
        .filter(|db| db.code().as_deref() == Some("23514"))
        .and_then(|db| db.constraint())
        == Some(constraint)
}

// ===========================================================================
// Closed domain enums — each mirrors a sealed DDL CHECK exactly.
// ===========================================================================

/// Blob purpose. Mirrors `blobs_purpose_check` and the two distinct signed
/// binding fragments: an application attachment vs. a metadata avatar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BlobPurpose {
    Attachment,
    Metadata,
}

impl BlobPurpose {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Attachment => "attachment",
            Self::Metadata => "metadata",
        }
    }
}

/// Blob status. Mirrors `blobs_status_check` exactly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BlobStatus {
    Prepared,
    CompletedUnbound,
    Bound,
    Deleted,
    Expired,
}

impl BlobStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::CompletedUnbound => "completedUnbound",
            Self::Bound => "bound",
            Self::Deleted => "deleted",
            Self::Expired => "expired",
        }
    }
}

/// The exact closed media-type enum. `blobs_media_type_check` accepts the five
/// encrypted-image MIMEs plus four audio MIMEs for an attachment, but only the
/// four still-image MIMEs (no GIF, no audio) for a metadata avatar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BlobMediaType {
    ImageHeic,
    ImageJpeg,
    ImagePng,
    ImageWebp,
    ImageGif,
    AudioAac,
    AudioMp4,
    AudioOgg,
    AudioOpus,
}

impl BlobMediaType {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ImageHeic => "image/heic",
            Self::ImageJpeg => "image/jpeg",
            Self::ImagePng => "image/png",
            Self::ImageWebp => "image/webp",
            Self::ImageGif => "image/gif",
            Self::AudioAac => "audio/aac",
            Self::AudioMp4 => "audio/mp4",
            Self::AudioOgg => "audio/ogg",
            Self::AudioOpus => "audio/opus",
        }
    }

    /// Audio ciphertext is bounded tighter (8 MiB) than image ciphertext.
    pub(crate) fn is_audio(self) -> bool {
        matches!(
            self,
            Self::AudioAac | Self::AudioMp4 | Self::AudioOgg | Self::AudioOpus
        )
    }

    /// The exact media set a purpose admits. Attachment: five images (incl. GIF)
    /// + four audio. Metadata avatar: four still images only — GIF and audio
    /// reject WITHOUT widening the metadata contract.
    pub(crate) fn is_allowed_for(self, purpose: BlobPurpose) -> bool {
        match purpose {
            BlobPurpose::Attachment => true,
            BlobPurpose::Metadata => matches!(
                self,
                Self::ImageHeic | Self::ImageJpeg | Self::ImagePng | Self::ImageWebp
            ),
        }
    }
}

/// Binding kind. Mirrors `blob_bindings_kind_check` exactly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BindingKind {
    Application,
    MetadataAvatar,
}

impl BindingKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Application => "application",
            Self::MetadataAvatar => "metadataAvatar",
        }
    }
}

// ===========================================================================
// Dumb writer 1 — INSERT chat.blobs (status='prepared').
// ===========================================================================

/// A freshly-prepared blob row, column-for-column from the `prepared` arm of
/// `blobs_status_shape_check`. `object_store_key`/`uploaded_at`/`unbound_expires_
/// at`/`bound_at`/`deleted_at`/`expired_at` are all absent for a prepared blob;
/// `upload_expires_at` MUST equal `prepared_at + 5 minutes`.
#[derive(Clone, Debug)]
pub(crate) struct NewPreparedBlob {
    pub(crate) blob_id: Uuid,
    pub(crate) owner_did: String,
    pub(crate) owner_device_id: Uuid,
    pub(crate) owner_key_id: String,
    pub(crate) owner_auth_generation: i64,
    pub(crate) purpose: BlobPurpose,
    pub(crate) media_type: BlobMediaType,
    pub(crate) plaintext_size: i64,
    pub(crate) ciphertext_size: i64,
    pub(crate) ciphertext_sha256: Vec<u8>,
    pub(crate) prepared_at: DateTime<Utc>,
}

/// INSERT one prepared blob. `upload_expires_at` is derived in SQL as
/// `prepared_at + INTERVAL '5 minutes'` so it satisfies `blobs_upload_expiry_
/// check` by construction. A reused `blob_id` is `BlobAlreadyExists`.
pub(crate) async fn insert_prepared_blob(
    transaction: &mut Transaction<'_, Postgres>,
    blob: &NewPreparedBlob,
) -> Result<(), BlobRepositoryError> {
    sqlx::query(
        r#"
        INSERT INTO chat.blobs(
            blob_id, owner_did, owner_device_id, owner_key_id, owner_auth_generation,
            purpose, media_type, plaintext_size, ciphertext_size, ciphertext_sha256,
            object_store_key, status, prepared_at, upload_expires_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
            NULL, 'prepared', $11, $11 + INTERVAL '5 minutes'
        )
        "#,
    )
    .bind(blob.blob_id)
    .bind(&blob.owner_did)
    .bind(blob.owner_device_id)
    .bind(&blob.owner_key_id)
    .bind(blob.owner_auth_generation)
    .bind(blob.purpose.as_str())
    .bind(blob.media_type.as_str())
    .bind(blob.plaintext_size)
    .bind(blob.ciphertext_size)
    .bind(&blob.ciphertext_sha256)
    .bind(blob.prepared_at)
    .execute(&mut **transaction)
    .await
    .map_err(|error| {
        if is_unique_violation(&error, "blobs_pkey") {
            BlobRepositoryError::BlobAlreadyExists
        } else {
            BlobRepositoryError::Database(error)
        }
    })?;
    Ok(())
}

// ===========================================================================
// Dumb writer 2 — chat.apply_blob_usage_delta (maintained O(1) counters).
// ===========================================================================

/// Apply one signed delta to the owner's maintained `chat.blob_usage` counters
/// under the principal anchor. The 500 MiB / 100 live-unbound ceilings
/// (`blob_usage_caps_check`) fire IMMEDIATELY on the underlying UPDATE, so an
/// over-cap delta surfaces synchronously as `QuotaExceeded`.
pub(crate) async fn apply_usage_delta(
    transaction: &mut Transaction<'_, Postgres>,
    owner_did: &str,
    used_delta: i64,
    reserved_delta: i64,
    unbound_delta: i64,
    count_delta: i64,
) -> Result<(), BlobRepositoryError> {
    sqlx::query("SELECT chat.apply_blob_usage_delta($1, $2, $3, $4, $5)")
        .bind(owner_did)
        .bind(used_delta)
        .bind(reserved_delta)
        .bind(unbound_delta)
        .bind(count_delta)
        .execute(&mut **transaction)
        .await
        .map_err(|error| {
            if is_check_violation(&error, "blob_usage_caps_check") {
                BlobRepositoryError::QuotaExceeded
            } else {
                BlobRepositoryError::Database(error)
            }
        })?;
    Ok(())
}

// ===========================================================================
// Dumb writer 3 — INSERT chat.blob_upload_tickets.
// ===========================================================================

/// A single-use upload ticket, 1:1 with a prepared blob. `created_at` /
/// `expires_at` MUST equal the blob's `prepared_at` / `upload_expires_at`
/// (`blob_upload_tickets_blob_lifetime_fk` and `assert_blob_ticket_lifecycle`).
#[derive(Clone, Debug)]
pub(crate) struct NewUploadTicket {
    pub(crate) ticket_hash: Vec<u8>,
    pub(crate) blob_id: Uuid,
    pub(crate) owner_did: String,
    pub(crate) owner_device_id: Uuid,
    pub(crate) created_at: DateTime<Utc>,
}

/// INSERT one upload ticket. `expires_at` is derived as `created_at + INTERVAL
/// '5 minutes'` to satisfy `blob_upload_tickets_expiry_check` by construction. A
/// duplicate ticket hash or a second ticket for one blob is `TicketConflict`.
pub(crate) async fn insert_upload_ticket(
    transaction: &mut Transaction<'_, Postgres>,
    ticket: &NewUploadTicket,
) -> Result<(), BlobRepositoryError> {
    sqlx::query(
        r#"
        INSERT INTO chat.blob_upload_tickets(
            ticket_hash, blob_id, owner_did, owner_device_id, created_at, expires_at
        ) VALUES ($1, $2, $3, $4, $5, $5 + INTERVAL '5 minutes')
        "#,
    )
    .bind(&ticket.ticket_hash)
    .bind(ticket.blob_id)
    .bind(&ticket.owner_did)
    .bind(ticket.owner_device_id)
    .bind(ticket.created_at)
    .execute(&mut **transaction)
    .await
    .map_err(|error| {
        if is_unique_violation(&error, "blob_upload_tickets_pkey")
            || is_unique_violation(&error, "blob_upload_tickets_blob_id_key")
        {
            BlobRepositoryError::TicketConflict
        } else {
            BlobRepositoryError::Database(error)
        }
    })?;
    Ok(())
}

/// CAS a ticket to consumed. Matches only an unconsumed ticket; a second consume
/// (single-use) or an absent hash matches no row and is `CompareAndSetConflict`.
/// `consumed_at` must lie in `[created_at, expires_at)` per
/// `blob_upload_tickets_consumption_check` — an expired ticket rejects.
pub(crate) async fn cas_consume_upload_ticket(
    transaction: &mut Transaction<'_, Postgres>,
    ticket_hash: &[u8],
    consumed_at: DateTime<Utc>,
) -> Result<(), BlobRepositoryError> {
    let result = sqlx::query(
        r#"
        UPDATE chat.blob_upload_tickets
           SET consumed_at = $2
         WHERE ticket_hash = $1
           AND consumed_at IS NULL
        "#,
    )
    .bind(ticket_hash)
    .bind(consumed_at)
    .execute(&mut **transaction)
    .await?;
    if result.rows_affected() == 1 {
        Ok(())
    } else {
        Err(BlobRepositoryError::CompareAndSetConflict)
    }
}

// ===========================================================================
// Dumb writer 4 — chat.blobs status CAS transitions.
// ===========================================================================

/// CAS a prepared blob to `completedUnbound`, stamping the upload. Matches only a
/// `prepared` blob owned by the exact device; `unbound_expires_at` is derived as
/// `uploaded_at + INTERVAL '1 hour'` (`blobs_status_shape_check`). Any drift
/// (wrong owner, wrong status, already-uploaded) is `CompareAndSetConflict`.
pub(crate) async fn cas_complete_upload(
    transaction: &mut Transaction<'_, Postgres>,
    blob_id: Uuid,
    owner_did: &str,
    owner_device_id: Uuid,
    uploaded_at: DateTime<Utc>,
    object_store_key: &str,
) -> Result<(), BlobRepositoryError> {
    let ciphertext_sha256: Vec<u8> = sqlx::query_scalar(
        "SELECT ciphertext_sha256 FROM chat.blobs WHERE blob_id = $1 AND owner_did = $2 AND owner_device_id = $3 AND status = 'prepared' FOR UPDATE",
    )
    .bind(blob_id)
    .bind(owner_did)
    .bind(owner_device_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(BlobRepositoryError::CompareAndSetConflict)?;
    let ciphertext_sha256: [u8; 32] = ciphertext_sha256.as_slice().try_into().map_err(|_| {
        BlobRepositoryError::Database(sqlx::Error::Protocol(
            "invalid ciphertext hash length".to_owned(),
        ))
    })?;
    if !object_store_key_matches(blob_id, &ciphertext_sha256, object_store_key) {
        return Err(BlobRepositoryError::ObjectStoreIdentityMismatch);
    }
    let result = sqlx::query(
        r#"
        UPDATE chat.blobs
           SET status = 'completedUnbound',
               uploaded_at = $4,
               unbound_expires_at = $4 + INTERVAL '1 hour',
               object_store_key = $5
         WHERE blob_id = $1
           AND owner_did = $2
           AND owner_device_id = $3
           AND status = 'prepared'
        "#,
    )
    .bind(blob_id)
    .bind(owner_did)
    .bind(owner_device_id)
    .bind(uploaded_at)
    .bind(object_store_key)
    .execute(&mut **transaction)
    .await?;
    if result.rows_affected() == 1 {
        Ok(())
    } else {
        Err(BlobRepositoryError::CompareAndSetConflict)
    }
}

/// CAS a completed-unbound blob to `bound`. This is the two-senders bind race:
/// exactly one concurrent sender moves `completedUnbound -> bound`; the loser
/// matches no row and is `CompareAndSetConflict`. `bound_at` must lie in
/// `[uploaded_at, unbound_expires_at)` (`blobs_bound_at_window_check`).
pub(crate) async fn cas_bind_blob(
    transaction: &mut Transaction<'_, Postgres>,
    blob_id: Uuid,
    owner_did: &str,
    owner_device_id: Uuid,
    bound_at: DateTime<Utc>,
) -> Result<(), BlobRepositoryError> {
    let result = sqlx::query(
        r#"
        UPDATE chat.blobs
           SET status = 'bound', bound_at = $4
         WHERE blob_id = $1
           AND owner_did = $2
           AND owner_device_id = $3
           AND status = 'completedUnbound'
        "#,
    )
    .bind(blob_id)
    .bind(owner_did)
    .bind(owner_device_id)
    .bind(bound_at)
    .execute(&mut **transaction)
    .await?;
    if result.rows_affected() == 1 {
        Ok(())
    } else {
        Err(BlobRepositoryError::CompareAndSetConflict)
    }
}

/// CAS a completed-unbound blob to `deleted`. Only the signing owner may delete a
/// completed unbound blob; removal from a conversation does not remove that
/// right and does not appear here. A bound / already-terminal / wrong-owner blob
/// matches no row and is `CompareAndSetConflict`.
pub(crate) async fn cas_delete_blob(
    transaction: &mut Transaction<'_, Postgres>,
    blob_id: Uuid,
    owner_did: &str,
    owner_device_id: Uuid,
    deleted_at: DateTime<Utc>,
) -> Result<(), BlobRepositoryError> {
    let result = sqlx::query(
        r#"
        UPDATE chat.blobs
           SET status = 'deleted', deleted_at = $4
         WHERE blob_id = $1
           AND owner_did = $2
           AND owner_device_id = $3
           AND status = 'completedUnbound'
        "#,
    )
    .bind(blob_id)
    .bind(owner_did)
    .bind(owner_device_id)
    .bind(deleted_at)
    .execute(&mut **transaction)
    .await?;
    if result.rows_affected() == 1 {
        Ok(())
    } else {
        Err(BlobRepositoryError::CompareAndSetConflict)
    }
}

// ===========================================================================
// Dumb writer 5 — INSERT chat.blob_bindings.
// ===========================================================================

/// One immutable blob binding, column-for-column from `blob_bindings_context_
/// shape_check`. An `Application` binding sets `entry_seq`/`message_id` (purpose
/// attachment); a `MetadataAvatar` binding sets `metadata_origin_transition_id`/
/// `metadata_version` (purpose metadata). The window columns are pinned to the
/// exact blob by `blob_bindings_blob_window_fk`.
#[derive(Clone, Debug)]
pub(crate) struct NewBlobBinding {
    pub(crate) blob_id: Uuid,
    pub(crate) binding_kind: BindingKind,
    pub(crate) conversation_id: Uuid,
    pub(crate) entry_seq: Option<i64>,
    pub(crate) message_id: Option<Uuid>,
    pub(crate) metadata_origin_transition_id: Option<Uuid>,
    pub(crate) metadata_version: Option<i64>,
    pub(crate) owner_did: String,
    pub(crate) owner_device_id: Uuid,
    pub(crate) descriptor_bytes: Vec<u8>,
    pub(crate) descriptor_sha256: Vec<u8>,
    pub(crate) aad_bytes: Vec<u8>,
    pub(crate) aad_sha256: Vec<u8>,
    pub(crate) ciphertext_sha256: Vec<u8>,
    pub(crate) plaintext_size: i64,
    pub(crate) ciphertext_size: i64,
    pub(crate) purpose: BlobPurpose,
    pub(crate) bound_at: DateTime<Utc>,
    pub(crate) uploaded_at: DateTime<Utc>,
    pub(crate) unbound_expires_at: DateTime<Utc>,
}

/// INSERT one blob binding. A second binding for the same blob (`blob_bindings_
/// pkey`) or the same application entry (`blob_bindings_application_entry_uq`)
/// is the losing side of a bind race → `BindingConflict`.
pub(crate) async fn insert_blob_binding(
    transaction: &mut Transaction<'_, Postgres>,
    binding: &NewBlobBinding,
) -> Result<(), BlobRepositoryError> {
    sqlx::query(
        r#"
        INSERT INTO chat.blob_bindings(
            blob_id, binding_kind, conversation_id, entry_seq, message_id,
            metadata_origin_transition_id, metadata_version, owner_did, owner_device_id,
            descriptor_bytes, descriptor_sha256, aad_bytes, aad_sha256, ciphertext_sha256,
            plaintext_size, ciphertext_size, purpose, bound_at, uploaded_at, unbound_expires_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
            $11, $12, $13, $14, $15, $16, $17, $18, $19, $20
        )
        "#,
    )
    .bind(binding.blob_id)
    .bind(binding.binding_kind.as_str())
    .bind(binding.conversation_id)
    .bind(binding.entry_seq)
    .bind(binding.message_id)
    .bind(binding.metadata_origin_transition_id)
    .bind(binding.metadata_version)
    .bind(&binding.owner_did)
    .bind(binding.owner_device_id)
    .bind(&binding.descriptor_bytes)
    .bind(&binding.descriptor_sha256)
    .bind(&binding.aad_bytes)
    .bind(&binding.aad_sha256)
    .bind(&binding.ciphertext_sha256)
    .bind(binding.plaintext_size)
    .bind(binding.ciphertext_size)
    .bind(binding.purpose.as_str())
    .bind(binding.bound_at)
    .bind(binding.uploaded_at)
    .bind(binding.unbound_expires_at)
    .execute(&mut **transaction)
    .await
    .map_err(|error| {
        if is_unique_violation(&error, "blob_bindings_pkey")
            || is_unique_violation(&error, "blob_bindings_application_entry_uq")
        {
            BlobRepositoryError::BindingConflict
        } else {
            BlobRepositoryError::Database(error)
        }
    })?;
    Ok(())
}

// ===========================================================================
// Dumb reader — application-attachment visibility against device intervals.
// ===========================================================================

/// The opaque custody view returned by an authorized attachment read: the
/// physical object key plus the sealed sizes/hashes. The delivery service never
/// exposes or parses the encrypted descriptor's inner fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AttachmentBlobView {
    pub(crate) blob_id: Uuid,
    object_store_key: String,
    pub(crate) ciphertext_size: i64,
    pub(crate) plaintext_size: i64,
    pub(crate) ciphertext_sha256: Vec<u8>,
    pub(crate) descriptor_bytes: Vec<u8>,
    pub(crate) aad_bytes: Vec<u8>,
    pub(crate) entry_seq: i64,
}

/// Read one application-attachment blob for an EXACT caller device. The binding
/// qualifies ONLY through this device's `chat.application_intervals` spanning the
/// binding's `entry_seq`. A same-DID sibling with no interval at that seq, a
/// pre-join device, a gap device, and a re-Added device without history backfill
/// all fail the interval join and read `None` — the DID matching is never
/// sufficient. Returns `None` when not visible.
///
/// DRIFT GUARD: the `EXISTS (... application_intervals ...)` interval-spanning
/// predicate below is SEMANTICALLY IDENTICAL — the same inclusive
/// `[start_seq, terminal_seq]` bounds — to the delivery read predicate in
/// `repository/delivery.rs` (`getEntries` visible-CTE, the
/// `entry.seq >= interval.start_seq AND (interval.terminal_seq IS NULL OR
/// entry.seq <= interval.terminal_seq)` clause). It is NOT a byte-for-byte
/// copy: the probed seq is this binding's `entry_seq` here versus the log
/// row's `entry.seq` there — the operand names differ while the bound
/// semantics must not. Both sites carry a matching
/// cross-reference comment; if you change the inclusive `[start_seq, terminal_seq]`
/// semantics here, change it there too (and vice versa) so per-device application
/// visibility never diverges between the entry log and blob custody.
pub(crate) async fn read_application_attachment(
    transaction: &mut Transaction<'_, Postgres>,
    blob_id: Uuid,
    caller_did: &str,
    caller_device_id: Uuid,
) -> Result<Option<AttachmentBlobView>, BlobRepositoryError> {
    let row: Option<(
        Uuid,
        Option<String>,
        i64,
        i64,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        i64,
    )> = sqlx::query_as(
        r#"
            SELECT b.blob_id, b.object_store_key, binding.ciphertext_size,
                   binding.plaintext_size, binding.ciphertext_sha256,
                   binding.descriptor_bytes, binding.aad_bytes, binding.entry_seq
              FROM chat.blob_bindings AS binding
              JOIN chat.blobs AS b ON b.blob_id = binding.blob_id
             WHERE binding.blob_id = $1
               AND binding.binding_kind = 'application'
               AND EXISTS (
                     SELECT 1
                       FROM chat.application_intervals AS interval
                      WHERE interval.conversation_id = binding.conversation_id
                        AND interval.recipient_did = $2
                        AND interval.recipient_device_id = $3
                        AND binding.entry_seq >= interval.start_seq
                        AND (interval.terminal_seq IS NULL
                             OR binding.entry_seq <= interval.terminal_seq)
                   )
            "#,
    )
    .bind(blob_id)
    .bind(caller_did)
    .bind(caller_device_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some((
        blob_id,
        object_store_key,
        ciphertext_size,
        plaintext_size,
        ciphertext_sha256,
        descriptor_bytes,
        aad_bytes,
        entry_seq,
    )) = row
    else {
        return Ok(None);
    };
    // A bound blob (the only kind an application binding can point to) always
    // carries its object key per `blobs_status_shape_check`; a NULL is a storage
    // invariant violation, not an absent optional, so it is a hard error.
    let object_store_key = object_store_key.ok_or(BlobRepositoryError::ObjectStoreKeyMissing)?;
    Ok(Some(AttachmentBlobView {
        blob_id,
        object_store_key,
        ciphertext_size,
        plaintext_size,
        ciphertext_sha256,
        descriptor_bytes,
        aad_bytes,
        entry_seq,
    }))
}

/// Authorize one private blob read from the live, locked database snapshot.
///
/// The query deliberately has two closed authorization arms:
/// * application attachments require the caller's exact device interval to
///   span the entry sequence; and
/// * metadata avatars require an active membership row, allowing an immutable
///   metadata snapshot to be reused without re-authorizing its producer.
///
/// In both arms the caller's DID alone is insufficient: `devices` must be
/// active at the exact presented auth generation. Bound blobs also remain
/// inside their live unbound window, so a stale/revoked/sibling/expired read
/// produces `NotAuthorized` without returning any storage identity.
pub(crate) async fn authorize_blob_read<'pool>(
    mut transaction: BlobAuthorizationTransaction<'pool>,
    request: &AuthorizeBlobReadRequest,
) -> Result<PendingAuthorizedBlobFetch<'pool>, BlobRepositoryError> {
    let issued_at: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()::timestamptz")
        .fetch_one(&mut **transaction.transaction_mut()?)
        .await?;

    let row: Option<(
        Uuid,
        Option<String>,
        String,
        i64,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        String,
        DateTime<Utc>,
        Option<Uuid>,
        Uuid,
        Option<i64>,
        Option<i64>,
        Option<i64>,
    )> = sqlx::query_as(
        r#"
        SELECT b.blob_id, b.object_store_key, b.media_type,
               b.ciphertext_size, b.ciphertext_sha256,
               binding.descriptor_sha256, binding.aad_sha256,
               binding.binding_kind, b.unbound_expires_at,
               device.revocation_id,
               binding.conversation_id, interval.start_seq,
               interval.terminal_seq, binding.entry_seq
          FROM chat.blobs AS b
          JOIN chat.blob_bindings AS binding ON binding.blob_id = b.blob_id
          JOIN chat.devices AS device
            ON device.user_did = $2 AND device.device_id = $3
          LEFT JOIN LATERAL (
                SELECT candidate.start_seq, candidate.terminal_seq
                  FROM chat.application_intervals AS candidate
                 WHERE candidate.conversation_id = binding.conversation_id
                   AND candidate.recipient_did = $2
                   AND candidate.recipient_device_id = $3
                   AND binding.entry_seq >= candidate.start_seq
                   AND (candidate.terminal_seq IS NULL
                        OR binding.entry_seq <= candidate.terminal_seq)
                 ORDER BY candidate.start_seq DESC
                 LIMIT 1
                 FOR SHARE
          ) AS interval ON binding.binding_kind = 'application'
         WHERE b.blob_id = $1
           AND b.status = 'bound'
           AND b.object_store_key IS NOT NULL
           AND b.unbound_expires_at IS NOT NULL
           AND $5 < b.unbound_expires_at
           AND device.status = 'active'
           AND device.auth_generation = $4
           AND (
                (binding.binding_kind = 'application'
                 AND interval.start_seq IS NOT NULL)
                OR
                (binding.binding_kind = 'metadataAvatar'
                 AND EXISTS (
                     SELECT 1
                       FROM chat.member_devices AS member
                      WHERE member.conversation_id = binding.conversation_id
                         AND member.user_did = $2
                         AND member.device_id = $3
                         AND member.active
                         FOR SHARE
                 ))
           )
        FOR SHARE OF b, binding, device
        "#,
    )
    .bind(request.blob_id)
    .bind(&request.caller_did)
    .bind(request.caller_device_id)
    .bind(request.auth_generation)
    .bind(issued_at)
    .fetch_optional(&mut **transaction.transaction_mut()?)
    .await?;

    let Some((
        blob_id,
        object_store_key,
        media_type,
        expected_size,
        ciphertext_sha256,
        descriptor_sha256,
        aad_sha256,
        _binding_kind,
        _unbound_expires_at,
        revocation_id,
        conversation_id,
        interval_start_seq,
        interval_terminal_seq,
        entry_seq,
    )) = row
    else {
        // Do not distinguish sibling, revoked, missing, or expired rows at the
        // handler boundary. All are a denial with no storage oracle.
        return Err(BlobRepositoryError::NotAuthorized);
    };
    let object_store_key = object_store_key.ok_or(BlobRepositoryError::ObjectStoreKeyMissing)?;
    let expected_sha256: [u8; 32] = ciphertext_sha256.as_slice().try_into().map_err(|_| {
        BlobRepositoryError::Database(sqlx::Error::Protocol(
            "invalid ciphertext hash length".to_owned(),
        ))
    })?;
    let binding_digest = binding_digest(&descriptor_sha256, &aad_sha256, &ciphertext_sha256)?;
    let derived_cid = derive_blob_cid(blob_id, &expected_sha256);
    if object_store_key != derived_cid {
        return Err(BlobRepositoryError::ObjectStoreIdentityMismatch);
    }
    let expires_at = issued_at
        .checked_add_signed(AUTHORIZED_FETCH_TTL)
        .ok_or(BlobRepositoryError::BlobExpired)?;

    Ok(PendingAuthorizedBlobFetch {
        transaction,
        storage: BlobStorageRequest {
            object_store_key,
            derived_cid,
            expected_size,
            expected_sha256,
            media_type,
        },
        binding_digest,
        blob_id,
        caller_did: request.caller_did.clone(),
        caller_device_id: request.caller_device_id,
        auth_generation: request.auth_generation,
        revocation_id,
        issued_at,
        expires_at,
        membership_fence: BlobMembershipFence {
            conversation_id,
            interval_start_seq,
            interval_terminal_seq,
            entry_seq,
        },
    })
}

/// Commit the top-level authority transaction and only then mint the opaque
/// fetch capability. The transaction wrapper is the authority proof; there is
/// deliberately no transaction-id assertion because a transaction id does
/// not prove top-level commit across savepoints.
pub(crate) async fn publicize_authorized_blob_fetch(
    pending: PendingAuthorizedBlobFetch<'_>,
) -> Result<AuthorizedBlobFetch, BlobRepositoryError> {
    pending.transaction.commit().await?;
    Ok(AuthorizedBlobFetch {
        storage: pending.storage,
        consumed: AtomicBool::new(false),
        binding_digest: pending.binding_digest,
        blob_id: pending.blob_id,
        caller_did: pending.caller_did,
        caller_device_id: pending.caller_device_id,
        auth_generation: pending.auth_generation,
        revocation_id: pending.revocation_id,
        issued_at: pending.issued_at,
        expires_at: pending.expires_at,
        membership_fence: pending.membership_fence,
    })
}

/// Revalidate one opaque capability against a fresh, trusted database snapshot
/// immediately before storage access. The query locks the immutable blob and
/// binding plus the exact device and matching interval/member row; revocation,
/// generation, membership, interval, object identity, and live-window drift
/// therefore deny before any object-store request is made.
pub(crate) async fn consume_authorized_blob_fetch(
    pool: &PgPool,
    authorization: &AuthorizedBlobFetch,
) -> Result<BlobStorageRequest, BlobRepositoryError> {
    let mut transaction = BlobAuthorizationTransaction::begin(pool).await?;
    let now: DateTime<Utc> = match sqlx::query_scalar("SELECT clock_timestamp()::timestamptz")
        .fetch_one(&mut **transaction.transaction_mut()?)
        .await
    {
        Ok(now) => now,
        Err(error) => {
            transaction.rollback().await;
            return Err(BlobRepositoryError::Database(error));
        }
    };
    if now < authorization.issued_at || now >= authorization.expires_at {
        transaction.rollback().await;
        return Err(BlobRepositoryError::BlobExpired);
    }

    let row: Option<(
        Option<String>,
        String,
        i64,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        String,
        Option<Uuid>,
        Uuid,
        Option<i64>,
        Option<i64>,
        Option<i64>,
    )> = match sqlx::query_as(
        r#"
        SELECT b.object_store_key, b.media_type, b.ciphertext_size,
               b.ciphertext_sha256, binding.descriptor_sha256,
               binding.aad_sha256, binding.binding_kind, device.revocation_id,
               binding.conversation_id, interval.start_seq,
               interval.terminal_seq, binding.entry_seq
          FROM chat.blobs AS b
          JOIN chat.blob_bindings AS binding ON binding.blob_id = b.blob_id
          JOIN chat.devices AS device
            ON device.user_did = $7 AND device.device_id = $8
          LEFT JOIN LATERAL (
                SELECT candidate.start_seq, candidate.terminal_seq
                  FROM chat.application_intervals AS candidate
                 WHERE candidate.conversation_id = binding.conversation_id
                   AND candidate.recipient_did = $7
                   AND candidate.recipient_device_id = $8
                   AND binding.entry_seq >= candidate.start_seq
                   AND (candidate.terminal_seq IS NULL
                        OR binding.entry_seq <= candidate.terminal_seq)
                 ORDER BY candidate.start_seq DESC
                 LIMIT 1
                 FOR SHARE
          ) AS interval ON binding.binding_kind = 'application'
         WHERE b.blob_id = $1
           AND b.status = 'bound'
           AND b.object_store_key = $2
           AND b.media_type = $3
           AND b.ciphertext_size = $4
           AND b.ciphertext_sha256 = $5
           AND b.unbound_expires_at > $6
           AND device.status = 'active'
           AND device.auth_generation = $9
           AND device.revocation_id IS NOT DISTINCT FROM $10
           AND binding.conversation_id = $14
           AND (
                (binding.binding_kind = 'application'
                 AND interval.start_seq IS NOT DISTINCT FROM $11
                 AND interval.terminal_seq IS NOT DISTINCT FROM $12
                 AND binding.entry_seq IS NOT DISTINCT FROM $13)
                OR
                (binding.binding_kind = 'metadataAvatar'
                 AND EXISTS (
                     SELECT 1
                       FROM chat.member_devices AS member
                      WHERE member.conversation_id = binding.conversation_id
                        AND member.user_did = $7
                        AND member.device_id = $8
                        AND member.active
                        FOR SHARE
                 ))
           )
        FOR SHARE OF b, binding, device
        "#,
    )
    .bind(authorization.blob_id)
    .bind(authorization.storage.object_store_key())
    .bind(authorization.storage.media_type())
    .bind(authorization.storage.expected_size())
    .bind(authorization.storage.expected_sha256().as_slice())
    .bind(now)
    .bind(&authorization.caller_did)
    .bind(authorization.caller_device_id)
    .bind(authorization.auth_generation)
    .bind(authorization.revocation_id)
    .bind(authorization.membership_fence.interval_start_seq)
    .bind(authorization.membership_fence.interval_terminal_seq)
    .bind(authorization.membership_fence.entry_seq)
    .bind(authorization.membership_fence.conversation_id)
    .fetch_optional(&mut **transaction.transaction_mut()?)
    .await
    {
        Ok(row) => row,
        Err(error) => {
            transaction.rollback().await;
            return Err(BlobRepositoryError::Database(error));
        }
    };

    let Some((
        object_store_key,
        media_type,
        expected_size,
        ciphertext_sha256,
        descriptor_sha256,
        aad_sha256,
        _binding_kind,
        revocation_id,
        conversation_id,
        interval_start_seq,
        interval_terminal_seq,
        entry_seq,
    )) = row
    else {
        transaction.rollback().await;
        return Err(BlobRepositoryError::NotAuthorized);
    };
    let object_store_key = object_store_key.ok_or(BlobRepositoryError::ObjectStoreKeyMissing)?;
    let expected_sha256: [u8; 32] = ciphertext_sha256.as_slice().try_into().map_err(|_| {
        BlobRepositoryError::Database(sqlx::Error::Protocol(
            "invalid ciphertext hash length".to_owned(),
        ))
    })?;
    let current_binding_digest =
        binding_digest(&descriptor_sha256, &aad_sha256, &ciphertext_sha256)?;
    let current_fence = BlobMembershipFence {
        conversation_id,
        interval_start_seq,
        interval_terminal_seq,
        entry_seq,
    };
    let derived_cid = derive_blob_cid(authorization.blob_id, &expected_sha256);
    if object_store_key != derived_cid
        || object_store_key != authorization.storage.object_store_key()
        || media_type != authorization.storage.media_type()
        || expected_size != authorization.storage.expected_size()
        || expected_sha256 != *authorization.storage.expected_sha256()
        || current_binding_digest != authorization.binding_digest
        || revocation_id != authorization.revocation_id
        || current_fence != authorization.membership_fence
    {
        transaction.rollback().await;
        return Err(BlobRepositoryError::NotAuthorized);
    }

    // Mark the process-local capability consumed before releasing the locked
    // snapshot. A commit failure burns the capability and fails closed; no
    // storage adapter can observe a pre-commit authorization.
    if let Err(error) = authorization.claim_once() {
        transaction.rollback().await;
        return Err(error);
    }
    transaction.commit().await?;
    Ok(authorization.storage.clone())
}

// ===========================================================================
// Closed transaction semantics — compose the dumb writers under one tx and keep
// chat.blob_usage reconcilable with the authoritative chat.blobs history.
// ===========================================================================

/// The exact validated prepare request. `plaintext_size`/`ciphertext_size` are
/// the sealed sizes; the AEAD-tag relation and the per-media ceilings are checked
/// before any write.
#[derive(Clone, Debug)]
pub(crate) struct PrepareBlobRequest {
    pub(crate) blob_id: Uuid,
    pub(crate) owner_did: String,
    pub(crate) owner_device_id: Uuid,
    pub(crate) owner_key_id: String,
    pub(crate) owner_auth_generation: i64,
    pub(crate) purpose: BlobPurpose,
    pub(crate) media_type: BlobMediaType,
    pub(crate) plaintext_size: i64,
    pub(crate) ciphertext_size: i64,
    pub(crate) ciphertext_sha256: Vec<u8>,
    pub(crate) ticket_hash: Vec<u8>,
    pub(crate) prepared_at: DateTime<Utc>,
}

/// Validate the visible outer blob predicates the delivery service owns WITHOUT
/// decrypting: media-per-purpose, `ciphertextSize == plaintextSize + 16`, the
/// `>= 1` plaintext floor, and the 10 MiB / 8 MiB-audio ceilings. These are the
/// fail-closed checks the ciphertext-blind server performs on both encrypted
/// image and encrypted audio.
pub(crate) fn validate_blob_dimensions(
    purpose: BlobPurpose,
    media_type: BlobMediaType,
    plaintext_size: i64,
    ciphertext_size: i64,
) -> Result<(), BlobRepositoryError> {
    if !media_type.is_allowed_for(purpose) {
        return Err(BlobRepositoryError::MediaTypeNotAllowedForPurpose);
    }
    if plaintext_size < 1 {
        return Err(BlobRepositoryError::PlaintextSizeInvalid);
    }
    if ciphertext_size != plaintext_size + AEAD_TAG_BYTES {
        return Err(BlobRepositoryError::CiphertextSizeRelation);
    }
    if ciphertext_size > MAX_CIPHERTEXT_BYTES {
        return Err(BlobRepositoryError::CiphertextTooLarge);
    }
    if media_type.is_audio() && ciphertext_size > MAX_AUDIO_CIPHERTEXT_BYTES {
        return Err(BlobRepositoryError::CiphertextTooLarge);
    }
    Ok(())
}

/// Prepare a blob: validate the visible dimensions, insert the prepared blob and
/// its 1:1 upload ticket, and RESERVE quota. Usage delta:
///   used += 0, reserved += ciphertext_size, live_unbound += 1, blob_count += 1.
/// A over-cap owner surfaces `QuotaExceeded` from the reserve.
pub(crate) async fn prepare_blob(
    transaction: &mut Transaction<'_, Postgres>,
    request: &PrepareBlobRequest,
) -> Result<(), BlobRepositoryError> {
    validate_blob_dimensions(
        request.purpose,
        request.media_type,
        request.plaintext_size,
        request.ciphertext_size,
    )?;
    insert_prepared_blob(
        transaction,
        &NewPreparedBlob {
            blob_id: request.blob_id,
            owner_did: request.owner_did.clone(),
            owner_device_id: request.owner_device_id,
            owner_key_id: request.owner_key_id.clone(),
            owner_auth_generation: request.owner_auth_generation,
            purpose: request.purpose,
            media_type: request.media_type,
            plaintext_size: request.plaintext_size,
            ciphertext_size: request.ciphertext_size,
            ciphertext_sha256: request.ciphertext_sha256.clone(),
            prepared_at: request.prepared_at,
        },
    )
    .await?;
    insert_upload_ticket(
        transaction,
        &NewUploadTicket {
            ticket_hash: request.ticket_hash.clone(),
            blob_id: request.blob_id,
            owner_did: request.owner_did.clone(),
            owner_device_id: request.owner_device_id,
            created_at: request.prepared_at,
        },
    )
    .await?;
    apply_usage_delta(
        transaction,
        &request.owner_did,
        0,
        request.ciphertext_size,
        1,
        1,
    )
    .await?;
    Ok(())
}

/// Complete an upload: consume the single-use ticket and CAS the prepared blob to
/// `completedUnbound`, then move quota from reserved to used. Usage delta:
///   used += ciphertext_size, reserved -= ciphertext_size, live_unbound += 0,
///   blob_count += 0 (a prepared and a completedUnbound blob both count).
pub(crate) async fn complete_upload(
    transaction: &mut Transaction<'_, Postgres>,
    blob_id: Uuid,
    owner_did: &str,
    owner_device_id: Uuid,
    ciphertext_size: i64,
    ticket_hash: &[u8],
    uploaded_at: DateTime<Utc>,
    object_store_key: &str,
) -> Result<(), BlobRepositoryError> {
    cas_consume_upload_ticket(transaction, ticket_hash, uploaded_at).await?;
    cas_complete_upload(
        transaction,
        blob_id,
        owner_did,
        owner_device_id,
        uploaded_at,
        object_store_key,
    )
    .await?;
    apply_usage_delta(
        transaction,
        owner_did,
        ciphertext_size,
        -ciphertext_size,
        0,
        0,
    )
    .await?;
    Ok(())
}

/// Bind one completed-unbound application blob inside the send transaction: CAS
/// the blob to `bound` (the two-senders race resolves here) and insert the
/// immutable application binding. The binding's `purpose` MUST be `attachment`.
/// Usage delta:
///   used += 0 (completedUnbound and bound both count as used),
///   reserved += 0, live_unbound -= 1 (bound leaves the live-unbound set),
///   blob_count += 0.
pub(crate) async fn bind_application_blob(
    transaction: &mut Transaction<'_, Postgres>,
    binding: &NewBlobBinding,
) -> Result<(), BlobRepositoryError> {
    if binding.binding_kind != BindingKind::Application
        || binding.purpose != BlobPurpose::Attachment
    {
        return Err(BlobRepositoryError::PurposeBindingMismatch);
    }
    cas_bind_blob(
        transaction,
        binding.blob_id,
        &binding.owner_did,
        binding.owner_device_id,
        binding.bound_at,
    )
    .await?;
    insert_blob_binding(transaction, binding).await?;
    apply_usage_delta(transaction, &binding.owner_did, 0, 0, -1, 0).await?;
    Ok(())
}

/// Bind one repository-locked completed-unbound metadata avatar. The immutable
/// binding carries the signed descriptor plus the canonical avatar-blob AAD
/// derived during execution-context hydration. It is deliberately separate
/// from application attachment binding so neither purpose can inhabit the
/// other's persistence path.
pub(crate) async fn bind_metadata_avatar_blob(
    transaction: &mut Transaction<'_, Postgres>,
    binding: &NewBlobBinding,
) -> Result<(), BlobRepositoryError> {
    if binding.binding_kind != BindingKind::MetadataAvatar
        || binding.purpose != BlobPurpose::Metadata
        || binding.entry_seq.is_some()
        || binding.message_id.is_some()
        || binding.metadata_origin_transition_id.is_none()
        || binding.metadata_version.is_none()
    {
        return Err(BlobRepositoryError::PurposeBindingMismatch);
    }
    cas_bind_blob(
        transaction,
        binding.blob_id,
        &binding.owner_did,
        binding.owner_device_id,
        binding.bound_at,
    )
    .await?;
    insert_blob_binding(transaction, binding).await?;
    apply_usage_delta(transaction, &binding.owner_did, 0, 0, -1, 0).await?;
    Ok(())
}

/// Delete a completed-unbound blob by its signing owner. Usage delta:
///   used -= ciphertext_size (deleted leaves the used set),
///   reserved += 0, live_unbound -= 1, blob_count -= 1.
pub(crate) async fn delete_blob(
    transaction: &mut Transaction<'_, Postgres>,
    blob_id: Uuid,
    owner_did: &str,
    owner_device_id: Uuid,
    ciphertext_size: i64,
    deleted_at: DateTime<Utc>,
) -> Result<(), BlobRepositoryError> {
    cas_delete_blob(transaction, blob_id, owner_did, owner_device_id, deleted_at).await?;
    apply_usage_delta(transaction, owner_did, -ciphertext_size, 0, -1, -1).await?;
    Ok(())
}

/// One blob claimed by the unbound-expiry sweep, with the usage delta already
/// applied. Returned so a caller can observe/collect the reclaimed physical
/// objects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExpiredBlob {
    pub(crate) blob_id: Uuid,
    pub(crate) owner_did: String,
    pub(crate) prior_status: BlobStatus,
    pub(crate) ciphertext_size: i64,
}

/// Sweep due blobs to `expired` in bounded SKIP LOCKED batches (mirrors the
/// welcome-expiry / object-GC claim convention). Two shapes expire:
///   * a `prepared` blob past `upload_expires_at` (never uploaded): its
///     `expired_at = upload_expires_at`, usage delta reserved -= size,
///     live_unbound -= 1, blob_count -= 1;
///   * a `completedUnbound` blob past `unbound_expires_at` (uploaded, one hour
///     unbound): its `expired_at = unbound_expires_at`, usage delta used -= size,
///     live_unbound -= 1, blob_count -= 1.
/// Each row's usage delta is applied under the principal anchor in the same
/// transaction. Returns the claimed rows.
pub(crate) async fn expire_due_blobs(
    transaction: &mut Transaction<'_, Postgres>,
    now: DateTime<Utc>,
    batch_limit: i64,
) -> Result<Vec<ExpiredBlob>, BlobRepositoryError> {
    // `uploaded_at` is NOT mutated by the expiry UPDATE, so the prior shape
    // (`completedUnbound` iff uploaded) is returned directly in the RETURNING
    // clause — no per-row follow-up probe. This is the single set-based claim.
    let claimed: Vec<(Uuid, String, bool, i64)> = sqlx::query_as(
        r#"
        WITH due AS (
            SELECT c.blob_id
              FROM chat.blobs c
             WHERE (c.status = 'prepared' AND c.upload_expires_at <= $1)
                OR (c.status = 'completedUnbound' AND c.unbound_expires_at <= $1)
             ORDER BY c.blob_id
             FOR UPDATE SKIP LOCKED
             LIMIT $2
        )
        UPDATE chat.blobs b
           SET status = 'expired',
               expired_at = CASE
                   WHEN b.status = 'prepared' THEN b.upload_expires_at
                   ELSE b.unbound_expires_at
               END
          FROM due
         WHERE b.blob_id = due.blob_id
        RETURNING b.blob_id, b.owner_did, (b.uploaded_at IS NOT NULL), b.ciphertext_size
        "#,
    )
    .bind(now)
    .bind(batch_limit)
    .fetch_all(&mut **transaction)
    .await?;

    let mut expired = Vec::with_capacity(claimed.len());
    for (blob_id, owner_did, prior_completed, ciphertext_size) in claimed {
        // A completedUnbound blob counted toward `used`; a never-uploaded prepared
        // blob counted toward `reserved`. Both leave the live set on expiry.
        let (used_delta, reserved_delta) = if prior_completed {
            (-ciphertext_size, 0)
        } else {
            (0, -ciphertext_size)
        };
        apply_usage_delta(transaction, &owner_did, used_delta, reserved_delta, -1, -1).await?;
        expired.push(ExpiredBlob {
            blob_id,
            owner_did,
            prior_status: if prior_completed {
                BlobStatus::CompletedUnbound
            } else {
                BlobStatus::Prepared
            },
            ciphertext_size,
        });
    }
    Ok(expired)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat_protocol::repository::delivery::{
        close_application_interval, ApplicationIntervalClose, IntervalCloseKind,
    };
    use crate::chat_protocol::repository::transition::{
        cas_registration_revoke, close_leaf_period, insert_device_revocation, LeafClose,
        NewDeviceRevocation, RegistrationRevoke,
    };

    fn test_fetch() -> AuthorizedBlobFetch {
        let issued_at = Utc::now();
        AuthorizedBlobFetch {
            storage: BlobStorageRequest {
                object_store_key: "opaque-object".to_owned(),
                derived_cid: "derived-cid".to_owned(),
                expected_size: 3,
                expected_sha256: Sha256::digest(b"abc").into(),
                media_type: "image/png".to_owned(),
            },
            consumed: AtomicBool::new(false),
            binding_digest: [0x11; 32],
            blob_id: Uuid::from_bytes([0x22; 16]),
            caller_did: "did:plc:test".to_owned(),
            caller_device_id: Uuid::new_v4(),
            auth_generation: 7,
            revocation_id: None,
            issued_at,
            expires_at: issued_at + AUTHORIZED_FETCH_TTL,
            membership_fence: BlobMembershipFence {
                conversation_id: Uuid::new_v4(),
                interval_start_seq: Some(1),
                interval_terminal_seq: None,
                entry_seq: Some(1),
            },
        }
    }

    #[test]
    fn authorization_capability_is_atomic_one_use() {
        let fetch = test_fetch();
        assert!(fetch.claim_once().is_ok());
        assert!(matches!(
            fetch.claim_once(),
            Err(BlobRepositoryError::FetchAlreadyConsumed)
        ));
    }

    #[test]
    fn authorization_capability_uses_trusted_issue_window() {
        let fetch = test_fetch();
        assert!(fetch.issued_at < fetch.expires_at);
        assert_eq!(fetch.expires_at - fetch.issued_at, AUTHORIZED_FETCH_TTL);
    }

    #[test]
    fn deterministic_cid_rejects_object_swap() {
        let blob_id = Uuid::from_bytes([0x42; 16]);
        let hash = [0x11; 32];
        let cid = derive_blob_cid(blob_id, &hash);
        assert!(object_store_key_matches(blob_id, &hash, &cid));
        assert!(!object_store_key_matches(blob_id, &hash, "attacker-object"));
    }

    #[test]
    fn storage_request_debug_redacts_physical_identity() {
        let request = BlobStorageRequest {
            object_store_key: "secret-object-key".to_owned(),
            derived_cid: "secret-derived-cid".to_owned(),
            expected_size: 3,
            expected_sha256: [0x77; 32],
            media_type: "image/png".to_owned(),
        };
        let rendered = format!("{request:?}");
        assert!(!rendered.contains("secret-object-key"));
        assert!(!rendered.contains("secret-derived-cid"));
        assert!(!rendered.contains("77"));
    }

    #[test]
    fn one_use_race_has_exactly_one_winner() {
        use std::sync::Arc;

        let fetch = Arc::new(test_fetch());
        let first = {
            let fetch = Arc::clone(&fetch);
            std::thread::spawn(move || fetch.claim_once().is_ok())
        };
        let second = {
            let fetch = Arc::clone(&fetch);
            std::thread::spawn(move || fetch.claim_once().is_ok())
        };
        assert_eq!(
            first.join().unwrap() as u8 + second.join().unwrap() as u8,
            1
        );
    }

    #[test]
    fn cid_is_bound_to_blob_and_ciphertext_hash() {
        let blob_id = Uuid::from_bytes([1; 16]);
        let first = derive_blob_cid(blob_id, &[2; 32]);
        let second = derive_blob_cid(blob_id, &[3; 32]);
        assert_ne!(first, second);
        assert_eq!(first.len(), 64);
    }

    #[test]
    fn authorization_sql_is_row_locked_and_fenced() {
        let source = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/repository/blobs.rs"
        ));
        for required in [
            "b.status = 'bound'",
            "device.status = 'active'",
            "device.auth_generation = $4",
            "device.revocation_id",
            "member.active",
            "binding.entry_seq >= candidate.start_seq",
            "candidate.terminal_seq",
            "$5 < b.unbound_expires_at",
            "clock_timestamp()::timestamptz",
            "FOR SHARE",
            "pool.begin().await",
            "transaction: BlobAuthorizationTransaction",
        ] {
            assert!(
                source.contains(required),
                "missing SQL/API fence: {required}"
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL; run explicitly with cargo test -- --ignored"]
    async fn top_level_authority_rolls_back_on_explicit_abort() {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL is required for this ignored integration test");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&database_url)
            .await
            .expect("TEST_DATABASE_URL must name a reachable Postgres instance");
        let authority = BlobAuthorizationTransaction::begin(&pool)
            .await
            .expect("pool.begin must create the authority transaction");
        authority.rollback().await;
        sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&pool)
            .await
            .expect("rollback must return the pool connection usable");
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL and TEST_BLOB_* seeded fixture; run explicitly with cargo test -- --ignored"]
    async fn authorize_commit_consume_is_one_fresh_repository_flow() {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL is required for this ignored integration test");
        let blob_id = std::env::var("TEST_BLOB_ID")
            .expect("TEST_BLOB_ID is required for this ignored integration test");
        let caller_did = std::env::var("TEST_BLOB_CALLER_DID")
            .expect("TEST_BLOB_CALLER_DID is required for this ignored integration test");
        let caller_device_id = std::env::var("TEST_BLOB_CALLER_DEVICE_ID")
            .expect("TEST_BLOB_CALLER_DEVICE_ID is required for this ignored integration test");
        let auth_generation = std::env::var("TEST_BLOB_AUTH_GENERATION")
            .expect("TEST_BLOB_AUTH_GENERATION is required for this ignored integration test");
        let blob_id: Uuid = blob_id.parse().expect("TEST_BLOB_ID must be a UUID");
        let caller_device_id: Uuid = caller_device_id
            .parse()
            .expect("TEST_BLOB_CALLER_DEVICE_ID must be a UUID");
        let auth_generation: i64 = auth_generation
            .parse()
            .expect("TEST_BLOB_AUTH_GENERATION must be an integer");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&database_url)
            .await
            .expect("TEST_DATABASE_URL must name a reachable Postgres instance");
        let authority = BlobAuthorizationTransaction::begin(&pool)
            .await
            .expect("begin top-level authority transaction");
        let pending = authorize_blob_read(
            authority,
            &AuthorizeBlobReadRequest {
                blob_id,
                caller_did,
                caller_device_id,
                auth_generation,
            },
        )
        .await
        .expect("seeded fixture must authorize");
        let authorization = pending
            .publicize()
            .await
            .expect("authorization must be minted only after commit");
        authorization
            .consume_for_storage(&pool)
            .await
            .expect("fresh device/membership/interval fence must allow consume");
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL, TEST_BLOB_* seeded application fixture, and TEST_BLOB_CLOSE_* canonical interval proof; run explicitly with cargo test -- --ignored"]
    async fn seeded_post_authorization_interval_closure_denies_consumption() {
        for variable in [
            "TEST_DATABASE_URL",
            "TEST_BLOB_ID",
            "TEST_BLOB_CALLER_DID",
            "TEST_BLOB_CALLER_DEVICE_ID",
            "TEST_BLOB_AUTH_GENERATION",
            "TEST_BLOB_CLOSE_INTERVAL_ID",
            "TEST_BLOB_CLOSE_TERMINAL_SEQ",
            "TEST_BLOB_CLOSE_STATE_VERSION",
            "TEST_BLOB_CLOSE_TRANSITION_ID",
            "TEST_BLOB_CLOSE_FINGERPRINT_HEX",
            "TEST_BLOB_CLOSE_LEAF_PERIOD_ID",
        ] {
            assert!(
                std::env::var(variable).is_ok(),
                "{variable} is required for this ignored seeded interval-drift test"
            );
        }
        let database_url = std::env::var("TEST_DATABASE_URL").unwrap();
        let blob_id: Uuid = std::env::var("TEST_BLOB_ID")
            .unwrap()
            .parse()
            .expect("TEST_BLOB_ID must be a UUID");
        let caller_did = std::env::var("TEST_BLOB_CALLER_DID").unwrap();
        let caller_device_id: Uuid = std::env::var("TEST_BLOB_CALLER_DEVICE_ID")
            .unwrap()
            .parse()
            .expect("TEST_BLOB_CALLER_DEVICE_ID must be a UUID");
        let auth_generation: i64 = std::env::var("TEST_BLOB_AUTH_GENERATION")
            .unwrap()
            .parse()
            .expect("TEST_BLOB_AUTH_GENERATION must be an integer");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&database_url)
            .await
            .expect("TEST_DATABASE_URL must name a reachable Postgres instance");

        let authority = BlobAuthorizationTransaction::begin(&pool)
            .await
            .expect("begin top-level authority transaction");
        let authorization = authorize_blob_read(
            authority,
            &AuthorizeBlobReadRequest {
                blob_id,
                caller_did,
                caller_device_id,
                auth_generation,
            },
        )
        .await
        .expect("seeded application fixture must authorize before drift")
        .publicize()
        .await
        .expect("authorization must be minted only after commit");

        // Close through the repository's canonical interval CAS, carrying the
        // exact signed close proof from the seeded fixture. This is the real
        // member-removal/application-interval lifecycle edge; direct UPDATEs
        // are intentionally not accepted by the production schema triggers.
        let mut transaction = pool.begin().await.expect("begin interval close");
        let removed_at: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()::timestamptz")
            .fetch_one(&mut *transaction)
            .await
            .expect("database clock for canonical interval close");
        close_application_interval(
            &mut transaction,
            &ApplicationIntervalClose {
                membership_interval_id: std::env::var("TEST_BLOB_CLOSE_INTERVAL_ID")
                    .unwrap()
                    .parse()
                    .expect("TEST_BLOB_CLOSE_INTERVAL_ID must be a UUID"),
                terminal_seq: std::env::var("TEST_BLOB_CLOSE_TERMINAL_SEQ")
                    .unwrap()
                    .parse()
                    .expect("TEST_BLOB_CLOSE_TERMINAL_SEQ must be an integer"),
                closing_state_version: std::env::var("TEST_BLOB_CLOSE_STATE_VERSION")
                    .unwrap()
                    .parse()
                    .expect("TEST_BLOB_CLOSE_STATE_VERSION must be an integer"),
                closing_transition_id: std::env::var("TEST_BLOB_CLOSE_TRANSITION_ID")
                    .unwrap()
                    .parse()
                    .expect("TEST_BLOB_CLOSE_TRANSITION_ID must be a UUID"),
                closing_outer_entry_fingerprint: hex::decode(
                    std::env::var("TEST_BLOB_CLOSE_FINGERPRINT_HEX").unwrap(),
                )
                .expect("TEST_BLOB_CLOSE_FINGERPRINT_HEX must be hex"),
                closing_kind: IntervalCloseKind::Remove,
                closing_leaf_period_id: std::env::var("TEST_BLOB_CLOSE_LEAF_PERIOD_ID")
                    .unwrap()
                    .parse()
                    .expect("TEST_BLOB_CLOSE_LEAF_PERIOD_ID must be a UUID"),
                removed_at,
            },
        )
        .await
        .expect("seeded canonical interval close must commit");
        close_leaf_period(
            &mut transaction,
            &LeafClose {
                leaf_period_id: std::env::var("TEST_BLOB_CLOSE_LEAF_PERIOD_ID")
                    .unwrap()
                    .parse()
                    .expect("TEST_BLOB_CLOSE_LEAF_PERIOD_ID must be a UUID"),
                removed_state_version: std::env::var("TEST_BLOB_CLOSE_STATE_VERSION")
                    .unwrap()
                    .parse()
                    .expect("TEST_BLOB_CLOSE_STATE_VERSION must be an integer"),
                removed_transition_id: std::env::var("TEST_BLOB_CLOSE_TRANSITION_ID")
                    .unwrap()
                    .parse()
                    .expect("TEST_BLOB_CLOSE_TRANSITION_ID must be a UUID"),
                removed_seq: std::env::var("TEST_BLOB_CLOSE_TERMINAL_SEQ")
                    .unwrap()
                    .parse()
                    .expect("TEST_BLOB_CLOSE_TERMINAL_SEQ must be an integer"),
                removed_at,
            },
        )
        .await
        .expect("seeded canonical member removal must apply");
        transaction
            .commit()
            .await
            .expect("interval closure must commit before consumption");

        assert!(matches!(
            authorization.consume_for_storage(&pool).await,
            Err(BlobRepositoryError::NotAuthorized)
        ));
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL, TEST_BLOB_* seeded fixture, and TEST_BLOB_REVOCATION_ACTOR_DEVICE_ID; run explicitly with cargo test -- --ignored"]
    async fn seeded_post_authorization_device_revocation_denies_consumption() {
        for variable in [
            "TEST_DATABASE_URL",
            "TEST_BLOB_ID",
            "TEST_BLOB_CALLER_DID",
            "TEST_BLOB_CALLER_DEVICE_ID",
            "TEST_BLOB_AUTH_GENERATION",
            "TEST_BLOB_REVOCATION_ACTOR_DEVICE_ID",
        ] {
            assert!(
                std::env::var(variable).is_ok(),
                "{variable} is required for this ignored seeded revocation-drift test"
            );
        }
        let database_url = std::env::var("TEST_DATABASE_URL").unwrap();
        let blob_id: Uuid = std::env::var("TEST_BLOB_ID")
            .unwrap()
            .parse()
            .expect("TEST_BLOB_ID must be a UUID");
        let caller_did = std::env::var("TEST_BLOB_CALLER_DID").unwrap();
        let caller_device_id: Uuid = std::env::var("TEST_BLOB_CALLER_DEVICE_ID")
            .unwrap()
            .parse()
            .expect("TEST_BLOB_CALLER_DEVICE_ID must be a UUID");
        let auth_generation: i64 = std::env::var("TEST_BLOB_AUTH_GENERATION")
            .unwrap()
            .parse()
            .expect("TEST_BLOB_AUTH_GENERATION must be an integer");
        let actor_device_id: Uuid = std::env::var("TEST_BLOB_REVOCATION_ACTOR_DEVICE_ID")
            .unwrap()
            .parse()
            .expect("TEST_BLOB_REVOCATION_ACTOR_DEVICE_ID must be a UUID");
        assert_ne!(
            actor_device_id, caller_device_id,
            "revocation actor must be a distinct active sibling device"
        );
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&database_url)
            .await
            .expect("TEST_DATABASE_URL must name a reachable Postgres instance");

        let authority = BlobAuthorizationTransaction::begin(&pool)
            .await
            .expect("begin top-level authority transaction");
        let authorization = authorize_blob_read(
            authority,
            &AuthorizeBlobReadRequest {
                blob_id,
                caller_did: caller_did.clone(),
                caller_device_id,
                auth_generation,
            },
        )
        .await
        .expect("seeded fixture must authorize before revocation")
        .publicize()
        .await
        .expect("authorization must be minted only after commit");

        let (actor_key_id, actor_auth_generation, historical_jkt): (String, i64, String) =
            sqlx::query_as(
                "SELECT key.key_id, device.auth_generation, device.dpop_jkt
                   FROM chat.devices AS device
                   JOIN chat.device_keys AS key
                     ON key.user_did = device.user_did AND key.device_id = device.device_id
                  WHERE device.user_did = $1 AND device.device_id = $2",
            )
            .bind(&caller_did)
            .bind(actor_device_id)
            .fetch_one(&pool)
            .await
            .expect("revocation actor device must be seeded");
        let accepted_at: DateTime<Utc> =
            sqlx::query_scalar("SELECT clock_timestamp()::timestamptz")
                .fetch_one(&pool)
                .await
                .expect("database clock for revocation");
        let revocation_id = Uuid::new_v4();
        let accepted_request_bytes = vec![0x01];
        let signing_transcript_bytes = vec![0x02];
        let request_digest: [u8; 32] = Sha256::digest(&signing_transcript_bytes).into();
        let signature = vec![0x03; 64];
        let response_bytes = vec![0x04];
        let response_sha256: [u8; 32] = Sha256::digest(&response_bytes).into();
        let mut transaction = pool.begin().await.expect("begin revocation");
        insert_device_revocation(
            &mut transaction,
            &NewDeviceRevocation {
                revocation_id,
                actor_did: caller_did.clone(),
                actor_device_id,
                actor_key_id: actor_key_id.clone(),
                actor_auth_generation,
                target_did: caller_did.clone(),
                target_device_id: caller_device_id,
                target_auth_generation: auth_generation,
                accepted_request_bytes: accepted_request_bytes.clone(),
                signing_transcript_bytes: signing_transcript_bytes.clone(),
                request_digest: request_digest.to_vec(),
                signature: signature.clone(),
                signed_at: accepted_at,
                accepted_at,
            },
        )
        .await
        .expect("insert canonical revocation row");
        cas_registration_revoke(
            &mut transaction,
            &RegistrationRevoke {
                target_did: caller_did.clone(),
                target_device_id: caller_device_id,
                expected_auth_generation: auth_generation,
                revocation_id,
                revoked_at: accepted_at,
            },
        )
        .await
        .expect("revoke device and key through canonical CAS");
        sqlx::query(
            "INSERT INTO chat.idempotency_records (
                principal_did, endpoint_nsid, operation_id, request_digest,
                accepted_request_bytes, signing_transcript_bytes, signature,
                completed_status, response_bytes, response_sha256, event_position,
                historical_jkt, current_jkt, completed_at
             ) VALUES ($1, 'blue.catbird.chat.revokeDevice', $2, $3, $4, $5, $6,
                       200, $7, $8, NULL, $9, NULL, $10)",
        )
        .bind(&caller_did)
        .bind(revocation_id)
        .bind(request_digest.as_slice())
        .bind(&accepted_request_bytes)
        .bind(&signing_transcript_bytes)
        .bind(&signature)
        .bind(&response_bytes)
        .bind(response_sha256.as_slice())
        .bind(historical_jkt)
        .bind(accepted_at)
        .execute(&mut *transaction)
        .await
        .expect("canonical revocation completion receipt");
        transaction
            .commit()
            .await
            .expect("revocation must commit before consumption");

        assert!(matches!(
            authorization.consume_for_storage(&pool).await,
            Err(BlobRepositoryError::NotAuthorized)
        ));
    }
}
