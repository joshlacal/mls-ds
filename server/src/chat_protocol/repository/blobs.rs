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

use chrono::{DateTime, Utc};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

/// Ciphertext including the 16-byte AEAD tag is at most 10 MiB.
pub(crate) const MAX_CIPHERTEXT_BYTES: i64 = 10 * 1024 * 1024;
/// Audio ciphertext including the tag is at most 8 MiB.
pub(crate) const MAX_AUDIO_CIPHERTEXT_BYTES: i64 = 8 * 1024 * 1024;
/// The AEAD tag width: `ciphertextSize == plaintextSize + 16` for every blob.
pub(crate) const AEAD_TAG_BYTES: i64 = 16;

/// Failures the blob writers surface to the composing caller.
#[derive(Debug)]
pub(crate) enum BlobRepositoryError {
    /// A database error escaped the transaction (including CHECK / FK / UNIQUE
    /// violations the caller did not specifically expect). The row-shape
    /// authority is the schema; an unexpected violation propagates verbatim.
    Database(sqlx::Error),
    /// A compare-and-set matched no row: the stored row's compared columns did
    /// not equal the expected pre-state (a wrong status, a wrong owner, an
    /// already-terminalized blob, or a consumed ticket). Changing nothing is a
    /// conflict, not a silent success.
    CompareAndSetConflict,
    /// `chat.blobs` primary key collision — the caller reused a blob id.
    BlobAlreadyExists,
    /// `chat.blob_upload_tickets` collision — a duplicate ticket hash or a second
    /// ticket for one blob.
    TicketConflict,
    /// A second binding raced for the same blob or the same application entry and
    /// lost the `chat.blob_bindings` PK / `_application_entry_uq` unique index.
    BindingConflict,
    /// The owner's maintained `chat.blob_usage` would exceed the 500 MiB / 100
    /// live-unbound ceilings (`blob_usage_caps_check`).
    QuotaExceeded,
    /// A single device exceeded its active-blob ceiling
    /// (`assert_blob_device_active_cap`).
    DeviceActiveCapExceeded,
    /// The requested media type is not permitted for the requested purpose
    /// (`blobs_media_type_check`): audio and `image/gif` are attachment-only, and
    /// the metadata-avatar contract is never widened.
    MediaTypeNotAllowedForPurpose,
    /// `ciphertextSize != plaintextSize + 16` — the fixed AEAD-tag relation the
    /// delivery service enforces without decrypting.
    CiphertextSizeRelation,
    /// Ciphertext exceeds the 10 MiB (or 8 MiB audio) ceiling.
    CiphertextTooLarge,
    /// Plaintext size is below the `>= 1` floor.
    PlaintextSizeInvalid,
    /// The signed binding fragment/purpose does not match its kind: an
    /// application send accepts only `#applicationAttachmentBinding`
    /// (purpose=attachment) and a metadata snapshot only
    /// `#metadataAvatarBinding` (purpose=metadata).
    PurposeBindingMismatch,
}

impl From<sqlx::Error> for BlobRepositoryError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
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
    pub(crate) object_store_key: String,
    pub(crate) ciphertext_size: i64,
    pub(crate) plaintext_size: i64,
    pub(crate) ciphertext_sha256: Vec<u8>,
    pub(crate) descriptor_bytes: Vec<u8>,
    pub(crate) aad_bytes: Vec<u8>,
    pub(crate) entry_seq: i64,
}

/// Read one application-attachment blob for an EXACT caller device. The binding
/// qualifies ONLY through this device's `chat.application_intervals` spanning the
/// binding's `entry_seq` (inclusive `[start_seq, terminal_seq]`, mirroring the
/// delivery read predicate). A same-DID sibling with no interval at that seq, a
/// pre-join device, a gap device, and a re-Added device without history backfill
/// all fail the interval join and read `None` — the DID matching is never
/// sufficient. Returns `None` when not visible.
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
    Ok(row.map(
        |(
            blob_id,
            object_store_key,
            ciphertext_size,
            plaintext_size,
            ciphertext_sha256,
            descriptor_bytes,
            aad_bytes,
            entry_seq,
        )| AttachmentBlobView {
            blob_id,
            object_store_key: object_store_key.unwrap_or_default(),
            ciphertext_size,
            plaintext_size,
            ciphertext_sha256,
            descriptor_bytes,
            aad_bytes,
            entry_seq,
        },
    ))
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
    let claimed: Vec<(Uuid, String, String, i64)> = sqlx::query_as(
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
        RETURNING b.blob_id, b.owner_did, b.status, b.ciphertext_size
        "#,
    )
    .bind(now)
    .bind(batch_limit)
    .fetch_all(&mut **transaction)
    .await?;

    // The RETURNING status is the NEW ('expired') status; recover the prior
    // status from whether the row carried an object (uploaded => completedUnbound).
    // Re-read prior status precisely from expired_at == unbound vs upload window.
    let mut expired = Vec::with_capacity(claimed.len());
    for (blob_id, owner_did, _new_status, ciphertext_size) in claimed {
        // Determine which shape expired by inspecting the stamped columns.
        let prior_completed: bool =
            sqlx::query_scalar("SELECT uploaded_at IS NOT NULL FROM chat.blobs WHERE blob_id = $1")
                .bind(blob_id)
                .fetch_one(&mut **transaction)
                .await?;
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
