// Row-level state-family writers for the clean-chat transition executor.
//
// This module is the dumb, exact SQL layer for the migration-1
// (`20260722000001_chat_protocol_core.sql`) state families. Each function owns
// exactly one write shape against one `chat.*` table and carries a param struct
// derived column-for-column from the sealed DDL. Nothing here re-derives,
// validates, or "fixes up" a value: the caller (the transition executor that
// composes these inside one caller-owned transaction, task E2b — which lives in
// `state_machine.rs` where the private plan-evidence types are readable) hands
// down the exact bytes, and the database's own CHECK / FK / UNIQUE / partial-
// index constraints remain the ultimate authority. The row-lock-serialized head
// CAS, entry append, audience, and event writes are owned elsewhere
// (`repository/delivery.rs`); this module owns only the migration-1 side-row
// deltas the planner emits.
//
// CAS discipline: every update that terminalizes or advances a row's status is a
// compare-and-set. The `UPDATE ... WHERE <expected pre-state>` matches exactly
// the row in the expected state; `rows_affected() == 1` is required, and any
// other count (a drifted row, a wrong status, an already-terminalized row) is a
// typed `CompareAndSetConflict`, never a silent no-op or blind overwrite. Insert
// helpers write append-only rows and rely on the DDL primary keys / partial
// unique indexes to reject a duplicate current period.
//
// Every applier is transaction-scoped (`&mut Transaction`); it never commits and
// never opens its own transaction. Change lists apply in caller order.

use chrono::{DateTime, Utc};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

/// Failures the state-family row writers can surface to the composing executor.
#[derive(Debug)]
pub(crate) enum TransitionRepositoryError {
    /// A database error escaped the transaction (including CHECK / FK / UNIQUE
    /// violations the caller did not specifically expect). The row shape
    /// authority is the schema; an unexpected violation propagates verbatim.
    Database(sqlx::Error),
    /// A compare-and-set matched no row: the stored row's compared columns did
    /// not equal the expected pre-state — drift, a wrong status, or an already
    /// terminalized period. The caller changed nothing, which is a conflict,
    /// not a silent success.
    CompareAndSetConflict,
    /// A metadata snapshot reused a `(conversation_id, generation, epoch, nonce)`
    /// tuple (unique `metadata_snapshots_nonce_uq`). Reusing an AEAD nonce under
    /// one epoch is a crypto-safety violation, surfaced as its own typed
    /// variant rather than an opaque unique-violation.
    MetadataNonceReuse,
}

impl From<sqlx::Error> for TransitionRepositoryError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

/// True when `error` is a unique-violation (SQLSTATE 23505) raised by the named
/// constraint. Used to map an expected uniqueness collision to a typed variant
/// while letting every other database error propagate unchanged.
fn is_unique_violation(error: &sqlx::Error, constraint: &str) -> bool {
    error
        .as_database_error()
        .filter(|db| db.code().as_deref() == Some("23505"))
        .and_then(|db| db.constraint())
        == Some(constraint)
}

// ===========================================================================
// Family 1 — chat.participants periods.
// ===========================================================================

/// Participant lifecycle status for a newly inserted period. Mirrors the
/// `participants_status_check` domain exactly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ParticipantStatus {
    Pending,
    Active,
}

impl ParticipantStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
        }
    }
}

/// Participant role. Mirrors the `participants_role_check` domain exactly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ParticipantRole {
    Member,
    Admin,
}

impl ParticipantRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::Member => "member",
            Self::Admin => "admin",
        }
    }
}

/// Immutable invitation provenance for a pending or accepted participant period.
/// Present iff the participant joined by invitation (a genesis admin has none).
#[derive(Clone, Debug)]
pub(crate) struct ParticipantInvitation {
    pub(crate) invitation_transition_id: Uuid,
    pub(crate) invitation_entry_id: Uuid,
    pub(crate) invited_at: DateTime<Utc>,
}

/// Immutable acceptance provenance recorded when a pending period becomes active.
#[derive(Clone, Debug)]
pub(crate) struct ParticipantAcceptance {
    pub(crate) acceptance_transition_id: Uuid,
    pub(crate) acceptance_entry_id: Uuid,
    pub(crate) accepted_at: DateTime<Utc>,
}

/// One new **current** participant period. Every column is carried verbatim; the
/// insert always writes `current_membership = true` with NULL removal provenance
/// (a new period is never born terminalized). The optional invitation /
/// acceptance provenance select the legal shape enforced by
/// `participants_membership_provenance_check`.
#[derive(Clone, Debug)]
pub(crate) struct NewParticipantPeriod {
    pub(crate) participant_period_id: Uuid,
    pub(crate) conversation_id: Uuid,
    pub(crate) user_did: String,
    pub(crate) status: ParticipantStatus,
    pub(crate) role: ParticipantRole,
    pub(crate) role_transition_id: Uuid,
    pub(crate) role_changed_at: DateTime<Utc>,
    pub(crate) created_by_did: String,
    pub(crate) created_by_device_id: Uuid,
    pub(crate) invitation: Option<ParticipantInvitation>,
    pub(crate) acceptance: Option<ParticipantAcceptance>,
    pub(crate) created_at: DateTime<Utc>,
}

/// Insert one new current participant period.
///
/// The `participants_one_current_uq` partial unique index rejects a second
/// current period for the same `(conversation_id, user_did)`; the membership /
/// invitation / acceptance shape checks reject an illegal provenance
/// combination. This helper writes exactly what the plan says and leaves those
/// guards to the database.
pub(crate) async fn insert_participant_period(
    transaction: &mut Transaction<'_, Postgres>,
    period: &NewParticipantPeriod,
) -> Result<(), TransitionRepositoryError> {
    let (invitation_transition_id, invitation_entry_id, invited_at) = match &period.invitation {
        Some(invitation) => (
            Some(invitation.invitation_transition_id),
            Some(invitation.invitation_entry_id),
            Some(invitation.invited_at),
        ),
        None => (None, None, None),
    };
    let (acceptance_transition_id, acceptance_entry_id, accepted_at) = match &period.acceptance {
        Some(acceptance) => (
            Some(acceptance.acceptance_transition_id),
            Some(acceptance.acceptance_entry_id),
            Some(acceptance.accepted_at),
        ),
        None => (None, None, None),
    };

    sqlx::query(
        r#"
        INSERT INTO chat.participants(
            participant_period_id, conversation_id, user_did, status, role,
            role_transition_id, role_changed_at, created_by_did, created_by_device_id,
            invitation_transition_id, invitation_entry_id, invited_at,
            acceptance_transition_id, acceptance_entry_id, accepted_at,
            removing_transition_id, removing_seq, removed_at,
            current_membership, created_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9,
            $10, $11, $12, $13, $14, $15,
            NULL, NULL, NULL, TRUE, $16
        )
        "#,
    )
    .bind(period.participant_period_id)
    .bind(period.conversation_id)
    .bind(&period.user_did)
    .bind(period.status.as_str())
    .bind(period.role.as_str())
    .bind(period.role_transition_id)
    .bind(period.role_changed_at)
    .bind(&period.created_by_did)
    .bind(period.created_by_device_id)
    .bind(invitation_transition_id)
    .bind(invitation_entry_id)
    .bind(invited_at)
    .bind(acceptance_transition_id)
    .bind(acceptance_entry_id)
    .bind(accepted_at)
    .bind(period.created_at)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

/// Compare-and-set that promotes a pending participant period to active with its
/// acceptance provenance. Matches only a row that is still exactly
/// `pending`, current, invited, and un-accepted; a drifted row (already active,
/// terminalized, or never pending) matches nothing and is a typed conflict.
#[derive(Clone, Debug)]
pub(crate) struct ParticipantAcceptanceCas {
    pub(crate) participant_period_id: Uuid,
    pub(crate) conversation_id: Uuid,
    pub(crate) user_did: String,
    pub(crate) acceptance: ParticipantAcceptance,
}

pub(crate) async fn cas_participant_pending_to_active(
    transaction: &mut Transaction<'_, Postgres>,
    cas: &ParticipantAcceptanceCas,
) -> Result<(), TransitionRepositoryError> {
    let result = sqlx::query(
        r#"
        UPDATE chat.participants
           SET status = 'active',
               acceptance_transition_id = $4,
               acceptance_entry_id = $5,
               accepted_at = $6
         WHERE participant_period_id = $1
           AND conversation_id = $2
           AND user_did = $3
           AND status = 'pending'
           AND current_membership = TRUE
           AND invitation_transition_id IS NOT NULL
           AND acceptance_transition_id IS NULL
        "#,
    )
    .bind(cas.participant_period_id)
    .bind(cas.conversation_id)
    .bind(&cas.user_did)
    .bind(cas.acceptance.acceptance_transition_id)
    .bind(cas.acceptance.acceptance_entry_id)
    .bind(cas.acceptance.accepted_at)
    .execute(&mut **transaction)
    .await?;

    if result.rows_affected() != 1 {
        return Err(TransitionRepositoryError::CompareAndSetConflict);
    }
    Ok(())
}

/// Terminalize the current participant period: clear the current flag and record
/// the removing transition / seq / timestamp. Matches only a still-current,
/// un-removed period; a repeat attempt matches nothing (typed conflict).
#[derive(Clone, Debug)]
pub(crate) struct ParticipantTerminalization {
    pub(crate) participant_period_id: Uuid,
    pub(crate) removing_transition_id: Uuid,
    pub(crate) removing_seq: i64,
    pub(crate) removed_at: DateTime<Utc>,
}

pub(crate) async fn terminalize_participant_period(
    transaction: &mut Transaction<'_, Postgres>,
    termination: &ParticipantTerminalization,
) -> Result<(), TransitionRepositoryError> {
    let result = sqlx::query(
        r#"
        UPDATE chat.participants
           SET current_membership = FALSE,
               removing_transition_id = $2,
               removing_seq = $3,
               removed_at = $4
         WHERE participant_period_id = $1
           AND current_membership = TRUE
           AND removing_transition_id IS NULL
        "#,
    )
    .bind(termination.participant_period_id)
    .bind(termination.removing_transition_id)
    .bind(termination.removing_seq)
    .bind(termination.removed_at)
    .execute(&mut **transaction)
    .await?;

    if result.rows_affected() != 1 {
        return Err(TransitionRepositoryError::CompareAndSetConflict);
    }
    Ok(())
}

// ===========================================================================
// Family 2 — chat.member_devices leaf periods.
// ===========================================================================

/// Leaf origin, carrying the join KeyPackage ref for the `keyPackage` arm.
/// Mirrors `member_devices_origin_shape_check`: a `genesis` leaf has no join
/// package; a `keyPackage` leaf binds the 32-byte ref it consumed.
#[derive(Clone, Debug)]
pub(crate) enum LeafOrigin {
    Genesis,
    KeyPackage { key_package_ref: Vec<u8> },
}

impl LeafOrigin {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Genesis => "genesis",
            Self::KeyPackage { .. } => "keyPackage",
        }
    }

    fn key_package_ref(&self) -> Option<&[u8]> {
        match self {
            Self::Genesis => None,
            Self::KeyPackage { key_package_ref } => Some(key_package_ref),
        }
    }
}

/// One new **active** member-device leaf period with its full join provenance.
/// The insert always writes `active = true` with NULL removal provenance.
#[derive(Clone, Debug)]
pub(crate) struct NewLeafPeriod {
    pub(crate) leaf_period_id: Uuid,
    pub(crate) participant_period_id: Uuid,
    pub(crate) conversation_id: Uuid,
    pub(crate) generation: i64,
    pub(crate) user_did: String,
    pub(crate) device_id: Uuid,
    pub(crate) leaf_index: i64,
    pub(crate) basic_credential: Vec<u8>,
    pub(crate) leaf_signature_key: Vec<u8>,
    pub(crate) leaf_key_id: String,
    pub(crate) leaf_auth_generation: i64,
    pub(crate) origin: LeafOrigin,
    pub(crate) joined_state_version: i64,
    pub(crate) joined_transition_id: Uuid,
    pub(crate) joined_seq: i64,
    pub(crate) created_at: DateTime<Utc>,
}

/// Insert one new active leaf period.
///
/// The `member_devices_current_device_uq` / `_current_credential_uq` /
/// `_current_leaf_index_uq` partial unique indexes reject a duplicate active
/// device, credential, or leaf index; the origin shape and credential-format
/// checks reject an illegal join. Written verbatim.
pub(crate) async fn insert_leaf_period(
    transaction: &mut Transaction<'_, Postgres>,
    leaf: &NewLeafPeriod,
) -> Result<(), TransitionRepositoryError> {
    sqlx::query(
        r#"
        INSERT INTO chat.member_devices(
            leaf_period_id, participant_period_id, conversation_id, generation,
            user_did, device_id, leaf_index, basic_credential, leaf_signature_key,
            leaf_key_id, leaf_auth_generation, origin, join_key_package_ref,
            joined_state_version, joined_transition_id, joined_seq,
            removed_state_version, removed_transition_id, removed_seq, removed_at,
            active, created_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
            $14, $15, $16, NULL, NULL, NULL, NULL, TRUE, $17
        )
        "#,
    )
    .bind(leaf.leaf_period_id)
    .bind(leaf.participant_period_id)
    .bind(leaf.conversation_id)
    .bind(leaf.generation)
    .bind(&leaf.user_did)
    .bind(leaf.device_id)
    .bind(leaf.leaf_index)
    .bind(&leaf.basic_credential)
    .bind(&leaf.leaf_signature_key)
    .bind(&leaf.leaf_key_id)
    .bind(leaf.leaf_auth_generation)
    .bind(leaf.origin.as_str())
    .bind(leaf.origin.key_package_ref())
    .bind(leaf.joined_state_version)
    .bind(leaf.joined_transition_id)
    .bind(leaf.joined_seq)
    .bind(leaf.created_at)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

/// Close (deactivate) a leaf period, recording the removing state version /
/// transition / seq / timestamp. Matches only a still-active, un-removed period.
#[derive(Clone, Debug)]
pub(crate) struct LeafClose {
    pub(crate) leaf_period_id: Uuid,
    pub(crate) removed_state_version: i64,
    pub(crate) removed_transition_id: Uuid,
    pub(crate) removed_seq: i64,
    pub(crate) removed_at: DateTime<Utc>,
}

pub(crate) async fn close_leaf_period(
    transaction: &mut Transaction<'_, Postgres>,
    close: &LeafClose,
) -> Result<(), TransitionRepositoryError> {
    let result = sqlx::query(
        r#"
        UPDATE chat.member_devices
           SET active = FALSE,
               removed_state_version = $2,
               removed_transition_id = $3,
               removed_seq = $4,
               removed_at = $5
         WHERE leaf_period_id = $1
           AND active = TRUE
           AND removed_transition_id IS NULL
        "#,
    )
    .bind(close.leaf_period_id)
    .bind(close.removed_state_version)
    .bind(close.removed_transition_id)
    .bind(close.removed_seq)
    .bind(close.removed_at)
    .execute(&mut **transaction)
    .await?;

    if result.rows_affected() != 1 {
        return Err(TransitionRepositoryError::CompareAndSetConflict);
    }
    Ok(())
}

// ===========================================================================
// Family 3 — chat.metadata_snapshots (append-only, nonce-unique).
// ===========================================================================

/// Optional avatar binding block. All avatar columns are present together or
/// absent together (`metadata_snapshots_avatar_shape_check`); `avatar_purpose`
/// is always `'metadata'` for a present binding, written verbatim below.
#[derive(Clone, Debug)]
pub(crate) struct MetadataAvatarBinding {
    pub(crate) avatar_blob_id: Uuid,
    pub(crate) avatar_ciphertext_sha256: Vec<u8>,
    pub(crate) avatar_ciphertext_size: i64,
    pub(crate) avatar_binding_origin_transition_id: Uuid,
    pub(crate) avatar_binding_metadata_version: i64,
    pub(crate) avatar_binding_owner_did: String,
    pub(crate) avatar_binding_owner_device_id: Uuid,
}

/// One append-only encrypted metadata snapshot, carried column-for-column. The
/// caller supplies `ciphertext_sha256` / `ciphertext_size` and every digest; the
/// database's `= digest(...)` and `octet_length(...)` CHECKs re-verify them.
#[derive(Clone, Debug)]
pub(crate) struct NewMetadataSnapshot {
    pub(crate) metadata_snapshot_id: Uuid,
    pub(crate) conversation_id: Uuid,
    pub(crate) generation: i64,
    pub(crate) state_version: i64,
    pub(crate) group_id: Vec<u8>,
    pub(crate) epoch: i64,
    pub(crate) group_context_hash: Vec<u8>,
    pub(crate) confirmation_tag: Vec<u8>,
    pub(crate) producing_transition_id: Uuid,
    pub(crate) origin_transition_id: Uuid,
    pub(crate) metadata_version: i64,
    pub(crate) nonce: Vec<u8>,
    pub(crate) ciphertext: Vec<u8>,
    pub(crate) ciphertext_sha256: Vec<u8>,
    pub(crate) ciphertext_size: i64,
    pub(crate) avatar: Option<MetadataAvatarBinding>,
    pub(crate) author_did: String,
    pub(crate) author_device_id: Uuid,
    pub(crate) author_key_id: String,
    pub(crate) author_public_key: Vec<u8>,
    pub(crate) author_auth_generation: i64,
    pub(crate) author_origin_seq: i64,
    pub(crate) author_role: String,
    pub(crate) author_device_status: String,
    pub(crate) created_at: DateTime<Utc>,
}

/// Insert one metadata snapshot. A `(conversation_id, generation, epoch, nonce)`
/// collision (unique `metadata_snapshots_nonce_uq`) maps to the typed
/// `MetadataNonceReuse`; every other constraint violation propagates verbatim.
pub(crate) async fn insert_metadata_snapshot(
    transaction: &mut Transaction<'_, Postgres>,
    snapshot: &NewMetadataSnapshot,
) -> Result<(), TransitionRepositoryError> {
    let (
        avatar_blob_id,
        avatar_ciphertext_sha256,
        avatar_ciphertext_size,
        avatar_purpose,
        avatar_binding_origin_transition_id,
        avatar_binding_metadata_version,
        avatar_binding_owner_did,
        avatar_binding_owner_device_id,
    ) = match &snapshot.avatar {
        Some(avatar) => (
            Some(avatar.avatar_blob_id),
            Some(avatar.avatar_ciphertext_sha256.clone()),
            Some(avatar.avatar_ciphertext_size),
            Some("metadata"),
            Some(avatar.avatar_binding_origin_transition_id),
            Some(avatar.avatar_binding_metadata_version),
            Some(avatar.avatar_binding_owner_did.clone()),
            Some(avatar.avatar_binding_owner_device_id),
        ),
        None => (None, None, None, None, None, None, None, None),
    };

    let result = sqlx::query(
        r#"
        INSERT INTO chat.metadata_snapshots(
            metadata_snapshot_id, conversation_id, generation, state_version,
            group_id, epoch, group_context_hash, confirmation_tag,
            producing_transition_id, origin_transition_id, metadata_version,
            nonce, ciphertext, ciphertext_sha256, ciphertext_size,
            avatar_blob_id, avatar_ciphertext_sha256, avatar_ciphertext_size,
            avatar_purpose, avatar_binding_origin_transition_id,
            avatar_binding_metadata_version, avatar_binding_owner_did,
            avatar_binding_owner_device_id,
            author_did, author_device_id, author_key_id, author_public_key,
            author_auth_generation, author_origin_seq, author_role,
            author_device_status, created_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
            $16, $17, $18, $19, $20, $21, $22, $23,
            $24, $25, $26, $27, $28, $29, $30, $31, $32
        )
        "#,
    )
    .bind(snapshot.metadata_snapshot_id)
    .bind(snapshot.conversation_id)
    .bind(snapshot.generation)
    .bind(snapshot.state_version)
    .bind(&snapshot.group_id)
    .bind(snapshot.epoch)
    .bind(&snapshot.group_context_hash)
    .bind(&snapshot.confirmation_tag)
    .bind(snapshot.producing_transition_id)
    .bind(snapshot.origin_transition_id)
    .bind(snapshot.metadata_version)
    .bind(&snapshot.nonce)
    .bind(&snapshot.ciphertext)
    .bind(&snapshot.ciphertext_sha256)
    .bind(snapshot.ciphertext_size)
    .bind(avatar_blob_id)
    .bind(avatar_ciphertext_sha256)
    .bind(avatar_ciphertext_size)
    .bind(avatar_purpose)
    .bind(avatar_binding_origin_transition_id)
    .bind(avatar_binding_metadata_version)
    .bind(avatar_binding_owner_did)
    .bind(avatar_binding_owner_device_id)
    .bind(&snapshot.author_did)
    .bind(snapshot.author_device_id)
    .bind(&snapshot.author_key_id)
    .bind(&snapshot.author_public_key)
    .bind(snapshot.author_auth_generation)
    .bind(snapshot.author_origin_seq)
    .bind(&snapshot.author_role)
    .bind(&snapshot.author_device_status)
    .bind(snapshot.created_at)
    .execute(&mut **transaction)
    .await;

    match result {
        Ok(_) => Ok(()),
        Err(error) if is_unique_violation(&error, "metadata_snapshots_nonce_uq") => {
            Err(TransitionRepositoryError::MetadataNonceReuse)
        }
        Err(error) => Err(TransitionRepositoryError::Database(error)),
    }
}

// ===========================================================================
// Family 4a — chat.reset_requests.
// ===========================================================================

/// Reason a reset was requested. Mirrors `reset_requests_reason_check`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResetReason {
    LocalStateLost,
    PoisonedState,
    EpochDivergence,
    ManualRecovery,
}

impl ResetReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::LocalStateLost => "localStateLost",
            Self::PoisonedState => "poisonedState",
            Self::EpochDivergence => "epochDivergence",
            Self::ManualRecovery => "manualRecovery",
        }
    }
}

/// One signed, pending reset request, carried column-for-column. `expires_at`
/// must equal `received_at + 24h` (DB CHECK); `request_digest` must equal
/// `digest(signing_transcript_bytes)` (DB CHECK). Written verbatim.
#[derive(Clone, Debug)]
pub(crate) struct NewResetRequest {
    pub(crate) reset_request_id: Uuid,
    pub(crate) conversation_id: Uuid,
    pub(crate) requester_did: String,
    pub(crate) requester_device_id: Uuid,
    pub(crate) requester_key_id: String,
    pub(crate) requester_auth_generation: i64,
    pub(crate) prior_generation: i64,
    pub(crate) prior_state_version: i64,
    pub(crate) prior_group_id: Vec<u8>,
    pub(crate) prior_epoch: i64,
    pub(crate) prior_group_context_hash: Vec<u8>,
    pub(crate) prior_confirmation_tag: Vec<u8>,
    pub(crate) reason: ResetReason,
    pub(crate) signed_request_bytes: Vec<u8>,
    pub(crate) signing_transcript_bytes: Vec<u8>,
    pub(crate) request_digest: Vec<u8>,
    pub(crate) signature: Vec<u8>,
    pub(crate) received_at: DateTime<Utc>,
    pub(crate) expires_at: DateTime<Utc>,
}

pub(crate) async fn insert_reset_request(
    transaction: &mut Transaction<'_, Postgres>,
    request: &NewResetRequest,
) -> Result<(), TransitionRepositoryError> {
    sqlx::query(
        r#"
        INSERT INTO chat.reset_requests(
            reset_request_id, conversation_id, requester_did, requester_device_id,
            requester_key_id, requester_auth_generation, prior_generation,
            prior_state_version, prior_group_id, prior_epoch,
            prior_group_context_hash, prior_confirmation_tag, reason, status,
            signed_request_bytes, signing_transcript_bytes, request_digest,
            signature, received_at, expires_at, terminal_transition_id, terminal_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 'pending',
            $14, $15, $16, $17, $18, $19, NULL, NULL
        )
        "#,
    )
    .bind(request.reset_request_id)
    .bind(request.conversation_id)
    .bind(&request.requester_did)
    .bind(request.requester_device_id)
    .bind(&request.requester_key_id)
    .bind(request.requester_auth_generation)
    .bind(request.prior_generation)
    .bind(request.prior_state_version)
    .bind(&request.prior_group_id)
    .bind(request.prior_epoch)
    .bind(&request.prior_group_context_hash)
    .bind(&request.prior_confirmation_tag)
    .bind(request.reason.as_str())
    .bind(&request.signed_request_bytes)
    .bind(&request.signing_transcript_bytes)
    .bind(&request.request_digest)
    .bind(&request.signature)
    .bind(request.received_at)
    .bind(request.expires_at)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

/// The exact terminal edge a pending reset request takes. Each arm carries only
/// the provenance columns its `reset_requests_terminal_shape_check` arm allows:
/// `stale`/`consumed` bind a terminal transition + timestamp; `expired` records
/// only the timestamp (which the DB requires to equal `expires_at`).
#[derive(Clone, Debug)]
pub(crate) enum ResetRequestTermination {
    Stale {
        terminal_transition_id: Uuid,
        terminal_at: DateTime<Utc>,
    },
    Consumed {
        terminal_transition_id: Uuid,
        terminal_at: DateTime<Utc>,
    },
    Expired {
        terminal_at: DateTime<Utc>,
    },
}

/// Terminalize a pending reset request. CAS on `status = 'pending'`; a repeat or
/// wrong-state attempt matches nothing (typed conflict).
pub(crate) async fn terminalize_reset_request(
    transaction: &mut Transaction<'_, Postgres>,
    reset_request_id: Uuid,
    termination: &ResetRequestTermination,
) -> Result<(), TransitionRepositoryError> {
    let (status, terminal_transition_id, terminal_at) = match termination {
        ResetRequestTermination::Stale {
            terminal_transition_id,
            terminal_at,
        } => ("stale", Some(*terminal_transition_id), *terminal_at),
        ResetRequestTermination::Consumed {
            terminal_transition_id,
            terminal_at,
        } => ("consumed", Some(*terminal_transition_id), *terminal_at),
        ResetRequestTermination::Expired { terminal_at } => ("expired", None, *terminal_at),
    };

    let result = sqlx::query(
        r#"
        UPDATE chat.reset_requests
           SET status = $2,
               terminal_transition_id = $3,
               terminal_at = $4
         WHERE reset_request_id = $1
           AND status = 'pending'
        "#,
    )
    .bind(reset_request_id)
    .bind(status)
    .bind(terminal_transition_id)
    .bind(terminal_at)
    .execute(&mut **transaction)
    .await?;

    if result.rows_affected() != 1 {
        return Err(TransitionRepositoryError::CompareAndSetConflict);
    }
    Ok(())
}

// ===========================================================================
// Family 4b — chat.leave_requests.
// ===========================================================================

/// One signed, pending leave request, carried column-for-column.
#[derive(Clone, Debug)]
pub(crate) struct NewLeaveRequest {
    pub(crate) leave_request_id: Uuid,
    pub(crate) conversation_id: Uuid,
    pub(crate) requester_did: String,
    pub(crate) requester_device_id: Uuid,
    pub(crate) requester_key_id: String,
    pub(crate) requester_auth_generation: i64,
    pub(crate) prior_generation: i64,
    pub(crate) prior_state_version: i64,
    pub(crate) prior_group_id: Vec<u8>,
    pub(crate) prior_epoch: i64,
    pub(crate) prior_group_context_hash: Vec<u8>,
    pub(crate) prior_confirmation_tag: Vec<u8>,
    pub(crate) signed_request_bytes: Vec<u8>,
    pub(crate) signing_transcript_bytes: Vec<u8>,
    pub(crate) request_digest: Vec<u8>,
    pub(crate) signature: Vec<u8>,
    pub(crate) received_at: DateTime<Utc>,
    pub(crate) expires_at: DateTime<Utc>,
}

pub(crate) async fn insert_leave_request(
    transaction: &mut Transaction<'_, Postgres>,
    request: &NewLeaveRequest,
) -> Result<(), TransitionRepositoryError> {
    sqlx::query(
        r#"
        INSERT INTO chat.leave_requests(
            leave_request_id, conversation_id, requester_did, requester_device_id,
            requester_key_id, requester_auth_generation, prior_generation,
            prior_state_version, prior_group_id, prior_epoch,
            prior_group_context_hash, prior_confirmation_tag, status,
            signed_request_bytes, signing_transcript_bytes, request_digest,
            signature, terminal_request_digest, terminal_transition_id,
            received_at, expires_at, terminal_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'pending',
            $13, $14, $15, $16, NULL, NULL, $17, $18, NULL
        )
        "#,
    )
    .bind(request.leave_request_id)
    .bind(request.conversation_id)
    .bind(&request.requester_did)
    .bind(request.requester_device_id)
    .bind(&request.requester_key_id)
    .bind(request.requester_auth_generation)
    .bind(request.prior_generation)
    .bind(request.prior_state_version)
    .bind(&request.prior_group_id)
    .bind(request.prior_epoch)
    .bind(&request.prior_group_context_hash)
    .bind(&request.prior_confirmation_tag)
    .bind(&request.signed_request_bytes)
    .bind(&request.signing_transcript_bytes)
    .bind(&request.request_digest)
    .bind(&request.signature)
    .bind(request.received_at)
    .bind(request.expires_at)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

/// The exact terminal edge a pending leave request takes, per
/// `leave_requests_terminal_shape_check`: `fulfilled`/`stale` bind a terminal
/// request digest + transition + timestamp; `cancelled` binds a terminal request
/// digest + timestamp (no transition); `expired` records only the timestamp
/// (which the DB requires to equal `expires_at`).
#[derive(Clone, Debug)]
pub(crate) enum LeaveRequestTermination {
    Fulfilled {
        terminal_request_digest: Vec<u8>,
        terminal_transition_id: Uuid,
        terminal_at: DateTime<Utc>,
    },
    Stale {
        terminal_request_digest: Vec<u8>,
        terminal_transition_id: Uuid,
        terminal_at: DateTime<Utc>,
    },
    Cancelled {
        terminal_request_digest: Vec<u8>,
        terminal_at: DateTime<Utc>,
    },
    Expired {
        terminal_at: DateTime<Utc>,
    },
}

pub(crate) async fn terminalize_leave_request(
    transaction: &mut Transaction<'_, Postgres>,
    leave_request_id: Uuid,
    termination: &LeaveRequestTermination,
) -> Result<(), TransitionRepositoryError> {
    let (status, terminal_request_digest, terminal_transition_id, terminal_at) = match termination {
        LeaveRequestTermination::Fulfilled {
            terminal_request_digest,
            terminal_transition_id,
            terminal_at,
        } => (
            "fulfilled",
            Some(terminal_request_digest.clone()),
            Some(*terminal_transition_id),
            *terminal_at,
        ),
        LeaveRequestTermination::Stale {
            terminal_request_digest,
            terminal_transition_id,
            terminal_at,
        } => (
            "stale",
            Some(terminal_request_digest.clone()),
            Some(*terminal_transition_id),
            *terminal_at,
        ),
        LeaveRequestTermination::Cancelled {
            terminal_request_digest,
            terminal_at,
        } => (
            "cancelled",
            Some(terminal_request_digest.clone()),
            None,
            *terminal_at,
        ),
        LeaveRequestTermination::Expired { terminal_at } => ("expired", None, None, *terminal_at),
    };

    let result = sqlx::query(
        r#"
        UPDATE chat.leave_requests
           SET status = $2,
               terminal_request_digest = $3,
               terminal_transition_id = $4,
               terminal_at = $5
         WHERE leave_request_id = $1
           AND status = 'pending'
        "#,
    )
    .bind(leave_request_id)
    .bind(status)
    .bind(terminal_request_digest)
    .bind(terminal_transition_id)
    .bind(terminal_at)
    .execute(&mut **transaction)
    .await?;

    if result.rows_affected() != 1 {
        return Err(TransitionRepositoryError::CompareAndSetConflict);
    }
    Ok(())
}

// ===========================================================================
// Family 4c — chat.leaf_recovery_requests.
// ===========================================================================

/// Recovery kind, carrying the replaced leaf period for the `replace` arm
/// (`leaf_recovery_requests_kind_shape_check`).
#[derive(Clone, Debug)]
pub(crate) enum LeafRecoveryKind {
    Add,
    Replace { replaced_leaf_period_id: Uuid },
}

impl LeafRecoveryKind {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Replace { .. } => "replace",
        }
    }

    fn replaced_leaf_period_id(&self) -> Option<Uuid> {
        match self {
            Self::Add => None,
            Self::Replace {
                replaced_leaf_period_id,
            } => Some(*replaced_leaf_period_id),
        }
    }
}

/// Origin of a leaf-recovery request. Mirrors `leaf_recovery_requests_source_check`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LeafRecoverySource {
    RequestLeafRecovery,
    AcceptConversation,
}

impl LeafRecoverySource {
    fn as_str(self) -> &'static str {
        match self {
            Self::RequestLeafRecovery => "requestLeafRecovery",
            Self::AcceptConversation => "acceptConversation",
        }
    }
}

/// One signed, open leaf-recovery request, carried column-for-column.
/// `reservation_request_id` must equal `recovery_request_id` (DB CHECK), and the
/// paired `chat.key_package_reservations` row must be inserted in the same
/// transaction (both directions are `DEFERRABLE INITIALLY DEFERRED`).
#[derive(Clone, Debug)]
pub(crate) struct NewLeafRecoveryRequest {
    pub(crate) recovery_request_id: Uuid,
    pub(crate) conversation_id: Uuid,
    pub(crate) generation: i64,
    pub(crate) requester_did: String,
    pub(crate) requester_device_id: Uuid,
    pub(crate) requester_key_id: String,
    pub(crate) requester_auth_generation: i64,
    pub(crate) recovery_kind: LeafRecoveryKind,
    pub(crate) source: LeafRecoverySource,
    pub(crate) bound_state_version: i64,
    pub(crate) bound_group_id: Vec<u8>,
    pub(crate) bound_epoch: i64,
    pub(crate) bound_group_context_hash: Vec<u8>,
    pub(crate) bound_confirmation_tag: Vec<u8>,
    pub(crate) reservation_request_id: Uuid,
    pub(crate) signed_request_bytes: Vec<u8>,
    pub(crate) signing_transcript_bytes: Vec<u8>,
    pub(crate) request_digest: Vec<u8>,
    pub(crate) signature: Vec<u8>,
    pub(crate) requested_at: DateTime<Utc>,
    pub(crate) expires_at: DateTime<Utc>,
}

pub(crate) async fn insert_leaf_recovery_request(
    transaction: &mut Transaction<'_, Postgres>,
    request: &NewLeafRecoveryRequest,
) -> Result<(), TransitionRepositoryError> {
    sqlx::query(
        r#"
        INSERT INTO chat.leaf_recovery_requests(
            recovery_request_id, conversation_id, generation, requester_did,
            requester_device_id, requester_key_id, requester_auth_generation,
            recovery_kind, source, bound_state_version, bound_group_id,
            bound_epoch, bound_group_context_hash, bound_confirmation_tag,
            reservation_request_id, replaced_leaf_period_id, status,
            signed_request_bytes, signing_transcript_bytes, request_digest,
            signature, requested_at, expires_at, fulfilling_transition_id,
            terminal_transition_id, terminal_revocation_id,
            terminal_signed_request_bytes, terminal_signing_transcript_bytes,
            terminal_request_digest, terminal_signature, terminal_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
            $16, 'open', $17, $18, $19, $20, $21, $22,
            NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
        )
        "#,
    )
    .bind(request.recovery_request_id)
    .bind(request.conversation_id)
    .bind(request.generation)
    .bind(&request.requester_did)
    .bind(request.requester_device_id)
    .bind(&request.requester_key_id)
    .bind(request.requester_auth_generation)
    .bind(request.recovery_kind.as_str())
    .bind(request.source.as_str())
    .bind(request.bound_state_version)
    .bind(&request.bound_group_id)
    .bind(request.bound_epoch)
    .bind(&request.bound_group_context_hash)
    .bind(&request.bound_confirmation_tag)
    .bind(request.reservation_request_id)
    .bind(request.recovery_kind.replaced_leaf_period_id())
    .bind(&request.signed_request_bytes)
    .bind(&request.signing_transcript_bytes)
    .bind(&request.request_digest)
    .bind(&request.signature)
    .bind(request.requested_at)
    .bind(request.expires_at)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

/// The exact terminal edge an open leaf-recovery request takes, per
/// `leaf_recovery_requests_terminal_shape_check`:
/// * `fulfilled` binds the fulfilling transition + timestamp;
/// * `cancelled` binds a full terminal signed request (bytes, transcript,
///   digest, signature) + timestamp;
/// * `expired` records only the timestamp (DB requires it to equal `expires_at`);
/// * `superseded` binds exactly one of a terminal transition **or** a terminal
///   revocation + timestamp.
#[derive(Clone, Debug)]
pub(crate) enum LeafRecoveryTermination {
    Fulfilled {
        fulfilling_transition_id: Uuid,
        terminal_at: DateTime<Utc>,
    },
    Cancelled {
        terminal_signed_request_bytes: Vec<u8>,
        terminal_signing_transcript_bytes: Vec<u8>,
        terminal_request_digest: Vec<u8>,
        terminal_signature: Vec<u8>,
        terminal_at: DateTime<Utc>,
    },
    Expired {
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

pub(crate) async fn terminalize_leaf_recovery_request(
    transaction: &mut Transaction<'_, Postgres>,
    recovery_request_id: Uuid,
    termination: &LeafRecoveryTermination,
) -> Result<(), TransitionRepositoryError> {
    // (status, fulfilling_transition_id, terminal_transition_id,
    //  terminal_revocation_id, terminal_signed_request_bytes,
    //  terminal_signing_transcript_bytes, terminal_request_digest,
    //  terminal_signature, terminal_at)
    let (
        status,
        fulfilling_transition_id,
        terminal_transition_id,
        terminal_revocation_id,
        terminal_signed_request_bytes,
        terminal_signing_transcript_bytes,
        terminal_request_digest,
        terminal_signature,
        terminal_at,
    ) = match termination {
        LeafRecoveryTermination::Fulfilled {
            fulfilling_transition_id,
            terminal_at,
        } => (
            "fulfilled",
            Some(*fulfilling_transition_id),
            None,
            None,
            None,
            None,
            None,
            None,
            *terminal_at,
        ),
        LeafRecoveryTermination::Cancelled {
            terminal_signed_request_bytes,
            terminal_signing_transcript_bytes,
            terminal_request_digest,
            terminal_signature,
            terminal_at,
        } => (
            "cancelled",
            None,
            None,
            None,
            Some(terminal_signed_request_bytes.clone()),
            Some(terminal_signing_transcript_bytes.clone()),
            Some(terminal_request_digest.clone()),
            Some(terminal_signature.clone()),
            *terminal_at,
        ),
        LeafRecoveryTermination::Expired { terminal_at } => (
            "expired",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            *terminal_at,
        ),
        LeafRecoveryTermination::SupersededByTransition {
            terminal_transition_id,
            terminal_at,
        } => (
            "superseded",
            None,
            Some(*terminal_transition_id),
            None,
            None,
            None,
            None,
            None,
            *terminal_at,
        ),
        LeafRecoveryTermination::SupersededByRevocation {
            terminal_revocation_id,
            terminal_at,
        } => (
            "superseded",
            None,
            None,
            Some(*terminal_revocation_id),
            None,
            None,
            None,
            None,
            *terminal_at,
        ),
    };

    let result = sqlx::query(
        r#"
        UPDATE chat.leaf_recovery_requests
           SET status = $2,
               fulfilling_transition_id = $3,
               terminal_transition_id = $4,
               terminal_revocation_id = $5,
               terminal_signed_request_bytes = $6,
               terminal_signing_transcript_bytes = $7,
               terminal_request_digest = $8,
               terminal_signature = $9,
               terminal_at = $10
         WHERE recovery_request_id = $1
           AND status = 'open'
        "#,
    )
    .bind(recovery_request_id)
    .bind(status)
    .bind(fulfilling_transition_id)
    .bind(terminal_transition_id)
    .bind(terminal_revocation_id)
    .bind(terminal_signed_request_bytes)
    .bind(terminal_signing_transcript_bytes)
    .bind(terminal_request_digest)
    .bind(terminal_signature)
    .bind(terminal_at)
    .execute(&mut **transaction)
    .await?;

    if result.rows_affected() != 1 {
        return Err(TransitionRepositoryError::CompareAndSetConflict);
    }
    Ok(())
}

// ===========================================================================
// Family 5 — chat.key_package_reservations.
// ===========================================================================

/// One active KeyPackage reservation, carried column-for-column. `purpose` is
/// always `'leafRecovery'` (written verbatim). The requester and recipient are
/// the same device (`key_package_reservations_request_recipient_check`); the
/// caller supplies both explicitly rather than the layer deriving one.
#[derive(Clone, Debug)]
pub(crate) struct NewReservation {
    pub(crate) recovery_request_id: Uuid,
    pub(crate) key_package_ref: Vec<u8>,
    pub(crate) conversation_id: Uuid,
    pub(crate) generation: i64,
    pub(crate) requester_did: String,
    pub(crate) requester_device_id: Uuid,
    pub(crate) requester_key_id: String,
    pub(crate) requester_auth_generation: i64,
    pub(crate) recipient_did: String,
    pub(crate) recipient_device_id: Uuid,
    pub(crate) bound_state_version: i64,
    pub(crate) bound_group_id: Vec<u8>,
    pub(crate) bound_epoch: i64,
    pub(crate) bound_group_context_hash: Vec<u8>,
    pub(crate) bound_confirmation_tag: Vec<u8>,
    pub(crate) expires_at: DateTime<Utc>,
    pub(crate) created_at: DateTime<Utc>,
}

pub(crate) async fn insert_reservation(
    transaction: &mut Transaction<'_, Postgres>,
    reservation: &NewReservation,
) -> Result<(), TransitionRepositoryError> {
    sqlx::query(
        r#"
        INSERT INTO chat.key_package_reservations(
            recovery_request_id, key_package_ref, conversation_id, generation,
            requester_did, requester_device_id, requester_key_id,
            requester_auth_generation, recipient_did, recipient_device_id,
            bound_state_version, bound_group_id, bound_epoch,
            bound_group_context_hash, bound_confirmation_tag, purpose, expires_at,
            status, consumed_transition_id, terminal_transition_id,
            terminal_revocation_id, terminal_request_digest, terminal_at, created_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
            'leafRecovery', $16, 'active', NULL, NULL, NULL, NULL, NULL, $17
        )
        "#,
    )
    .bind(reservation.recovery_request_id)
    .bind(&reservation.key_package_ref)
    .bind(reservation.conversation_id)
    .bind(reservation.generation)
    .bind(&reservation.requester_did)
    .bind(reservation.requester_device_id)
    .bind(&reservation.requester_key_id)
    .bind(reservation.requester_auth_generation)
    .bind(&reservation.recipient_did)
    .bind(reservation.recipient_device_id)
    .bind(reservation.bound_state_version)
    .bind(&reservation.bound_group_id)
    .bind(reservation.bound_epoch)
    .bind(&reservation.bound_group_context_hash)
    .bind(&reservation.bound_confirmation_tag)
    .bind(reservation.expires_at)
    .bind(reservation.created_at)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

/// The exact terminal edge an active reservation takes, per
/// `key_package_reservations_terminal_shape_check`:
/// * `consumed` binds the consuming transition + timestamp;
/// * `expired` records only the timestamp (DB requires it to equal `expires_at`);
/// * `released` binds exactly one of a terminal transition, revocation, **or**
///   request digest + timestamp.
#[derive(Clone, Debug)]
pub(crate) enum ReservationTermination {
    Consumed {
        consumed_transition_id: Uuid,
        terminal_at: DateTime<Utc>,
    },
    Expired {
        terminal_at: DateTime<Utc>,
    },
    ReleasedByTransition {
        terminal_transition_id: Uuid,
        terminal_at: DateTime<Utc>,
    },
    ReleasedByRevocation {
        terminal_revocation_id: Uuid,
        terminal_at: DateTime<Utc>,
    },
    ReleasedByRequestDigest {
        terminal_request_digest: Vec<u8>,
        terminal_at: DateTime<Utc>,
    },
}

pub(crate) async fn terminalize_reservation(
    transaction: &mut Transaction<'_, Postgres>,
    recovery_request_id: Uuid,
    termination: &ReservationTermination,
) -> Result<(), TransitionRepositoryError> {
    // (status, consumed_transition_id, terminal_transition_id,
    //  terminal_revocation_id, terminal_request_digest, terminal_at)
    let (
        status,
        consumed_transition_id,
        terminal_transition_id,
        terminal_revocation_id,
        terminal_request_digest,
        terminal_at,
    ) = match termination {
        ReservationTermination::Consumed {
            consumed_transition_id,
            terminal_at,
        } => (
            "consumed",
            Some(*consumed_transition_id),
            None,
            None,
            None,
            *terminal_at,
        ),
        ReservationTermination::Expired { terminal_at } => {
            ("expired", None, None, None, None, *terminal_at)
        }
        ReservationTermination::ReleasedByTransition {
            terminal_transition_id,
            terminal_at,
        } => (
            "released",
            None,
            Some(*terminal_transition_id),
            None,
            None,
            *terminal_at,
        ),
        ReservationTermination::ReleasedByRevocation {
            terminal_revocation_id,
            terminal_at,
        } => (
            "released",
            None,
            None,
            Some(*terminal_revocation_id),
            None,
            *terminal_at,
        ),
        ReservationTermination::ReleasedByRequestDigest {
            terminal_request_digest,
            terminal_at,
        } => (
            "released",
            None,
            None,
            None,
            Some(terminal_request_digest.clone()),
            *terminal_at,
        ),
    };

    let result = sqlx::query(
        r#"
        UPDATE chat.key_package_reservations
           SET status = $2,
               consumed_transition_id = $3,
               terminal_transition_id = $4,
               terminal_revocation_id = $5,
               terminal_request_digest = $6,
               terminal_at = $7
         WHERE recovery_request_id = $1
           AND status = 'active'
        "#,
    )
    .bind(recovery_request_id)
    .bind(status)
    .bind(consumed_transition_id)
    .bind(terminal_transition_id)
    .bind(terminal_revocation_id)
    .bind(terminal_request_digest)
    .bind(terminal_at)
    .execute(&mut **transaction)
    .await?;

    if result.rows_affected() != 1 {
        return Err(TransitionRepositoryError::CompareAndSetConflict);
    }
    Ok(())
}

// ===========================================================================
// Family 6 — chat.key_packages status compare-and-set.
// ===========================================================================

/// Live KeyPackage status for the CAS `from` guard. Mirrors
/// `key_packages_status_check`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PackageStatus {
    Available,
    Reserved,
    Consumed,
    Expired,
    Revoked,
}

impl PackageStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

/// The exact successor edge a KeyPackage status CAS applies, carrying only the
/// terminal provenance the target `key_packages_terminal_shape_check` arm
/// allows:
/// * `Reserve` — `available` → `reserved`, no terminal columns;
/// * `Consume` — → `consumed`, binds the consuming transition + timestamp;
/// * `Expire` — → `expired`, records only the timestamp (DB requires it to
///   equal `not_after`);
/// * `Revoke` — → `revoked`, binds the revocation id + timestamp.
#[derive(Clone, Debug)]
pub(crate) enum PackageSuccessor {
    Reserve,
    Consume {
        terminal_transition_id: Uuid,
        terminal_at: DateTime<Utc>,
    },
    Expire {
        terminal_at: DateTime<Utc>,
    },
    Revoke {
        terminal_revocation_id: Uuid,
        terminal_at: DateTime<Utc>,
    },
}

/// Compare-and-set one KeyPackage's status from `expected_status` to the
/// successor edge, writing exactly the terminal provenance that edge carries.
/// Matches only a row whose `status = expected_status`; a wrong-`from` status
/// (already reserved / consumed / revoked / expired) matches nothing and is a
/// typed conflict.
pub(crate) async fn cas_key_package_status(
    transaction: &mut Transaction<'_, Postgres>,
    key_package_ref: &[u8],
    expected_status: PackageStatus,
    successor: &PackageSuccessor,
) -> Result<(), TransitionRepositoryError> {
    let (successor_status, terminal_transition_id, terminal_revocation_id, terminal_at) =
        match successor {
            PackageSuccessor::Reserve => (PackageStatus::Reserved, None, None, None),
            PackageSuccessor::Consume {
                terminal_transition_id,
                terminal_at,
            } => (
                PackageStatus::Consumed,
                Some(*terminal_transition_id),
                None,
                Some(*terminal_at),
            ),
            PackageSuccessor::Expire { terminal_at } => {
                (PackageStatus::Expired, None, None, Some(*terminal_at))
            }
            PackageSuccessor::Revoke {
                terminal_revocation_id,
                terminal_at,
            } => (
                PackageStatus::Revoked,
                None,
                Some(*terminal_revocation_id),
                Some(*terminal_at),
            ),
        };

    let result = sqlx::query(
        r#"
        UPDATE chat.key_packages
           SET status = $3,
               terminal_transition_id = $4,
               terminal_revocation_id = $5,
               terminal_at = $6
         WHERE key_package_ref = $1
           AND status = $2
        "#,
    )
    .bind(key_package_ref)
    .bind(expected_status.as_str())
    .bind(successor_status.as_str())
    .bind(terminal_transition_id)
    .bind(terminal_revocation_id)
    .bind(terminal_at)
    .execute(&mut **transaction)
    .await?;

    if result.rows_affected() != 1 {
        return Err(TransitionRepositoryError::CompareAndSetConflict);
    }
    Ok(())
}

// ===========================================================================
// Family 7 — append-only coordinate-spine rows the executor needs:
// chat.generation_states and chat.transitions.
// ===========================================================================

/// Generation-state lifecycle. Mirrors `generation_states_lifecycle_check`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GenerationStateLifecycle {
    Active,
    Superseded,
}

impl GenerationStateLifecycle {
    fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Superseded => "superseded",
        }
    }
}

/// The producing state kind. Mirrors `generation_states_kind_check` exactly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GenerationStateKind {
    Creation,
    Commit,
    Policy,
    AcceptConversation,
    Metadata,
    LeavePolicy,
    ResetRetirement,
    ResetSuccessor,
    CloseConversation,
}

impl GenerationStateKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Creation => "creation",
            Self::Commit => "commit",
            Self::Policy => "policy",
            Self::AcceptConversation => "acceptConversation",
            Self::Metadata => "metadata",
            Self::LeavePolicy => "leavePolicy",
            Self::ResetRetirement => "resetRetirement",
            Self::ResetSuccessor => "resetSuccessor",
            Self::CloseConversation => "closeConversation",
        }
    }
}

/// One append-only `chat.generation_states` row (the public coordinate spine),
/// carried column-for-column. The caller supplies the snapshot / tree bytes and
/// their digests; the DB's `= digest(...)` CHECKs re-verify them.
#[derive(Clone, Debug)]
pub(crate) struct NewGenerationState {
    pub(crate) conversation_id: Uuid,
    pub(crate) generation: i64,
    pub(crate) state_version: i64,
    pub(crate) group_id: Vec<u8>,
    pub(crate) epoch: i64,
    pub(crate) group_context_hash: Vec<u8>,
    pub(crate) confirmation_tag: Vec<u8>,
    pub(crate) lifecycle: GenerationStateLifecycle,
    pub(crate) state_kind: GenerationStateKind,
    pub(crate) producing_transition_id: Uuid,
    pub(crate) public_snapshot_bytes: Vec<u8>,
    pub(crate) snapshot_sha256: Vec<u8>,
    pub(crate) tree_summary_bytes: Vec<u8>,
    pub(crate) tree_summary_sha256: Vec<u8>,
    pub(crate) leaf_count: i64,
    pub(crate) created_at: DateTime<Utc>,
}

pub(crate) async fn insert_generation_state_row(
    transaction: &mut Transaction<'_, Postgres>,
    state: &NewGenerationState,
) -> Result<(), TransitionRepositoryError> {
    sqlx::query(
        r#"
        INSERT INTO chat.generation_states(
            conversation_id, generation, state_version, group_id, epoch,
            group_context_hash, confirmation_tag, lifecycle, state_kind,
            producing_transition_id, public_snapshot_bytes, snapshot_sha256,
            tree_summary_bytes, tree_summary_sha256, leaf_count, created_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
        )
        "#,
    )
    .bind(state.conversation_id)
    .bind(state.generation)
    .bind(state.state_version)
    .bind(&state.group_id)
    .bind(state.epoch)
    .bind(&state.group_context_hash)
    .bind(&state.confirmation_tag)
    .bind(state.lifecycle.as_str())
    .bind(state.state_kind.as_str())
    .bind(state.producing_transition_id)
    .bind(&state.public_snapshot_bytes)
    .bind(&state.snapshot_sha256)
    .bind(&state.tree_summary_bytes)
    .bind(&state.tree_summary_sha256)
    .bind(state.leaf_count)
    .bind(state.created_at)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

/// Transition kind. Mirrors `transitions_kind_check` exactly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TransitionKind {
    Creation,
    Commit,
    Policy,
    AcceptConversation,
    Metadata,
    LeafRecovery,
    LeaveCommit,
    LeavePolicy,
    CloseConversation,
    ResetActivation,
}

impl TransitionKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Creation => "creation",
            Self::Commit => "commit",
            Self::Policy => "policy",
            Self::AcceptConversation => "acceptConversation",
            Self::Metadata => "metadata",
            Self::LeafRecovery => "leafRecovery",
            Self::LeaveCommit => "leaveCommit",
            Self::LeavePolicy => "leavePolicy",
            Self::CloseConversation => "closeConversation",
            Self::ResetActivation => "resetActivation",
        }
    }
}

/// Actor role recorded on a transition. Mirrors the `member`/`admin` arm of
/// `transitions_actor_authority_check`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TransitionActorRole {
    Member,
    Admin,
}

impl TransitionActorRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::Member => "member",
            Self::Admin => "admin",
        }
    }
}

/// The four optional `(generation, state_version)` coordinate pairs a transition
/// may carry, grouped so a generation is never present without its state version
/// (`transitions_coordinate_pairs_check`).
#[derive(Clone, Copy, Debug)]
pub(crate) struct TransitionCoordinates {
    pub(crate) prior: Option<(i64, i64)>,
    pub(crate) next: Option<(i64, i64)>,
    pub(crate) retired: Option<(i64, i64)>,
    pub(crate) successor: Option<(i64, i64)>,
}

/// One append-only accepted `chat.transitions` row, carried column-for-column.
/// The caller supplies the coordinate pairs, optional reset / close / metadata
/// ids, and the signed request material verbatim; the DB's kind-coordinate
/// shape, signature, and identity constraints remain the authority.
#[derive(Clone, Debug)]
pub(crate) struct NewTransition {
    pub(crate) transition_id: Uuid,
    pub(crate) conversation_id: Uuid,
    pub(crate) kind: TransitionKind,
    pub(crate) actor_did: String,
    pub(crate) actor_device_id: Uuid,
    pub(crate) actor_key_id: String,
    pub(crate) actor_auth_generation: i64,
    pub(crate) actor_role: TransitionActorRole,
    pub(crate) actor_device_status: String,
    pub(crate) signed_request_bytes: Vec<u8>,
    pub(crate) unsigned_projection_bytes: Vec<u8>,
    pub(crate) signing_transcript_bytes: Vec<u8>,
    pub(crate) request_digest: Vec<u8>,
    pub(crate) signature: Vec<u8>,
    pub(crate) coordinates: TransitionCoordinates,
    pub(crate) reset_request_id: Option<Uuid>,
    pub(crate) close_transition_id: Option<Uuid>,
    pub(crate) metadata_snapshot_id: Option<Uuid>,
    pub(crate) entry_seq: i64,
    pub(crate) accepted_at: DateTime<Utc>,
}

pub(crate) async fn insert_transition_row(
    transaction: &mut Transaction<'_, Postgres>,
    transition: &NewTransition,
) -> Result<(), TransitionRepositoryError> {
    let (prior_generation, prior_state_version) = split_coordinate(transition.coordinates.prior);
    let (next_generation, next_state_version) = split_coordinate(transition.coordinates.next);
    let (retired_generation, retired_state_version) =
        split_coordinate(transition.coordinates.retired);
    let (successor_generation, successor_state_version) =
        split_coordinate(transition.coordinates.successor);

    sqlx::query(
        r#"
        INSERT INTO chat.transitions(
            transition_id, conversation_id, kind, actor_did, actor_device_id,
            actor_key_id, actor_auth_generation, actor_role, actor_device_status,
            signed_request_bytes, unsigned_projection_bytes,
            signing_transcript_bytes, request_digest, signature,
            prior_generation, prior_state_version, next_generation,
            next_state_version, retired_generation, retired_state_version,
            successor_generation, successor_state_version, reset_request_id,
            close_transition_id, metadata_snapshot_id, entry_seq, accepted_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
            $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27
        )
        "#,
    )
    .bind(transition.transition_id)
    .bind(transition.conversation_id)
    .bind(transition.kind.as_str())
    .bind(&transition.actor_did)
    .bind(transition.actor_device_id)
    .bind(&transition.actor_key_id)
    .bind(transition.actor_auth_generation)
    .bind(transition.actor_role.as_str())
    .bind(&transition.actor_device_status)
    .bind(&transition.signed_request_bytes)
    .bind(&transition.unsigned_projection_bytes)
    .bind(&transition.signing_transcript_bytes)
    .bind(&transition.request_digest)
    .bind(&transition.signature)
    .bind(prior_generation)
    .bind(prior_state_version)
    .bind(next_generation)
    .bind(next_state_version)
    .bind(retired_generation)
    .bind(retired_state_version)
    .bind(successor_generation)
    .bind(successor_state_version)
    .bind(transition.reset_request_id)
    .bind(transition.close_transition_id)
    .bind(transition.metadata_snapshot_id)
    .bind(transition.entry_seq)
    .bind(transition.accepted_at)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

/// Split an optional `(generation, state_version)` coordinate pair into two
/// separately-bound `Option<i64>` columns, keeping the "both present or both
/// absent" invariant the DDL's `transitions_coordinate_pairs_check` enforces.
fn split_coordinate(pair: Option<(i64, i64)>) -> (Option<i64>, Option<i64>) {
    match pair {
        Some((generation, state_version)) => (Some(generation), Some(state_version)),
        None => (None, None),
    }
}

// ===========================================================================
// Family 8 — the conversation-head and generation spine the executor owns.
//
// No writer previously existed for `chat.conversations` (the head) or
// `chat.generations`; the transition executor (task E2b) is their first
// in-crate consumer. They are added here in the same dumb-SQL / closed-enum
// E2a style: the head write is the single authority that advances
// `next_entry_seq` (the seq seam), and the generation writers own the
// per-generation lifecycle spine the deferred pointer-agreement triggers check.
// ===========================================================================

/// Conversation kind for a freshly created head row. Mirrors
/// `conversations_kind_check` / `conversations_kind_shape_check`: a `direct`
/// head carries the canonical unordered DID pair; a `group` head carries none.
#[derive(Clone, Debug)]
pub(crate) enum ConversationHeadKind {
    Direct {
        direct_did_low: String,
        direct_did_high: String,
    },
    Group,
}

impl ConversationHeadKind {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Direct { .. } => "direct",
            Self::Group => "group",
        }
    }

    fn direct_pair(&self) -> (Option<&str>, Option<&str>) {
        match self {
            Self::Direct {
                direct_did_low,
                direct_did_high,
            } => (Some(direct_did_low), Some(direct_did_high)),
            Self::Group => (None, None),
        }
    }
}

/// One freshly created `chat.conversations` head row. The insert always writes
/// `lifecycle = 'active'` with NULL close provenance and the caller-chosen
/// `next_entry_seq` (which the executor sets to the plan's
/// `successor_next_entry_seq`, since the genesis entry consumes the allocated
/// seq). The deferred `conversations_current_state_fk` and the pointer-agreement
/// triggers remain the DB's authority.
#[derive(Clone, Debug)]
pub(crate) struct NewConversationHead {
    pub(crate) conversation_id: Uuid,
    pub(crate) kind: ConversationHeadKind,
    pub(crate) current_generation: i64,
    pub(crate) current_state_version: i64,
    pub(crate) next_entry_seq: i64,
    pub(crate) created_at: DateTime<Utc>,
}

pub(crate) async fn insert_conversation_head(
    transaction: &mut Transaction<'_, Postgres>,
    head: &NewConversationHead,
) -> Result<(), TransitionRepositoryError> {
    let (direct_did_low, direct_did_high) = head.kind.direct_pair();
    sqlx::query(
        r#"
        INSERT INTO chat.conversations(
            conversation_id, kind, lifecycle, current_generation,
            current_state_version, next_entry_seq, direct_did_low, direct_did_high,
            created_at, close_transition_id, close_generation, close_state_version,
            close_seq, closed_at
        ) VALUES (
            $1, $2, 'active', $3, $4, $5, $6, $7, $8, NULL, NULL, NULL, NULL, NULL
        )
        "#,
    )
    .bind(head.conversation_id)
    .bind(head.kind.as_str())
    .bind(head.current_generation)
    .bind(head.current_state_version)
    .bind(head.next_entry_seq)
    .bind(direct_did_low)
    .bind(direct_did_high)
    .bind(head.created_at)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

/// The optional terminal close block a head compare-and-set may carry. Present
/// only for `closeConversation`, which flips the head to `superseded` and
/// records the exact close coordinate (`conversations_close_shape_check`).
#[derive(Clone, Debug)]
pub(crate) struct ConversationHeadClose {
    pub(crate) close_transition_id: Uuid,
    pub(crate) close_generation: i64,
    pub(crate) close_state_version: i64,
    pub(crate) close_seq: i64,
    pub(crate) closed_at: DateTime<Utc>,
}

/// Compare-and-set the conversation head across one legal coordinate edge.
///
/// Matches only a head whose `(current_generation, current_state_version,
/// next_entry_seq, lifecycle)` all equal the expected prior; a stale or drifted
/// head (a concurrent edge already advanced it, or it was already closed)
/// matches nothing and is a typed `CompareAndSetConflict`. This is the seq
/// seam's single counter authority for an existing conversation: it advances
/// `next_entry_seq` from `expected_next_entry_seq` (= the plan's `allocated_seq`)
/// to `successor_next_entry_seq`. The `close` block, when present, additionally
/// flips `lifecycle` to `superseded` and records the close coordinate.
#[derive(Clone, Debug)]
pub(crate) struct ConversationHeadCas {
    pub(crate) conversation_id: Uuid,
    pub(crate) expected_generation: i64,
    pub(crate) expected_state_version: i64,
    pub(crate) expected_next_entry_seq: i64,
    pub(crate) successor_generation: i64,
    pub(crate) successor_state_version: i64,
    pub(crate) successor_next_entry_seq: i64,
    pub(crate) close: Option<ConversationHeadClose>,
}

pub(crate) async fn cas_conversation_head(
    transaction: &mut Transaction<'_, Postgres>,
    cas: &ConversationHeadCas,
) -> Result<(), TransitionRepositoryError> {
    let (
        successor_lifecycle,
        close_transition_id,
        close_generation,
        close_state_version,
        close_seq,
        closed_at,
    ) = match &cas.close {
        Some(close) => (
            "superseded",
            Some(close.close_transition_id),
            Some(close.close_generation),
            Some(close.close_state_version),
            Some(close.close_seq),
            Some(close.closed_at),
        ),
        None => ("active", None, None, None, None, None),
    };

    let result = sqlx::query(
        r#"
        UPDATE chat.conversations
           SET current_generation = $5,
               current_state_version = $6,
               next_entry_seq = $7,
               lifecycle = $8,
               close_transition_id = $9,
               close_generation = $10,
               close_state_version = $11,
               close_seq = $12,
               closed_at = $13
         WHERE conversation_id = $1
           AND current_generation = $2
           AND current_state_version = $3
           AND next_entry_seq = $4
           AND lifecycle = 'active'
        "#,
    )
    .bind(cas.conversation_id)
    .bind(cas.expected_generation)
    .bind(cas.expected_state_version)
    .bind(cas.expected_next_entry_seq)
    .bind(cas.successor_generation)
    .bind(cas.successor_state_version)
    .bind(cas.successor_next_entry_seq)
    .bind(successor_lifecycle)
    .bind(close_transition_id)
    .bind(close_generation)
    .bind(close_state_version)
    .bind(close_seq)
    .bind(closed_at)
    .execute(&mut **transaction)
    .await?;

    if result.rows_affected() != 1 {
        return Err(TransitionRepositoryError::CompareAndSetConflict);
    }
    Ok(())
}

/// One freshly activated `chat.generations` row (creation or reset successor).
/// The insert always writes `lifecycle = 'active'` with NULL supersede
/// provenance; `activated_seq` equals the producing transition's entry seq and
/// `activated_at` equals its accepted instant (both checked by the deferred
/// state-output trigger). `current_state_version` starts at the successor's
/// state version (0 for a fresh generation).
#[derive(Clone, Debug)]
pub(crate) struct NewGeneration {
    pub(crate) conversation_id: Uuid,
    pub(crate) generation: i64,
    pub(crate) group_id: Vec<u8>,
    pub(crate) genesis_group_info_bytes: Vec<u8>,
    pub(crate) genesis_group_info_sha256: Vec<u8>,
    pub(crate) current_state_version: i64,
    pub(crate) activated_seq: i64,
    pub(crate) activated_at: DateTime<Utc>,
}

pub(crate) async fn insert_generation(
    transaction: &mut Transaction<'_, Postgres>,
    generation: &NewGeneration,
) -> Result<(), TransitionRepositoryError> {
    sqlx::query(
        r#"
        INSERT INTO chat.generations(
            conversation_id, generation, group_id, lifecycle,
            genesis_group_info_bytes, genesis_group_info_sha256,
            current_state_version, activated_seq, activated_at,
            superseded_seq, superseded_at
        ) VALUES (
            $1, $2, $3, 'active', $4, $5, $6, $7, $8, NULL, NULL
        )
        "#,
    )
    .bind(generation.conversation_id)
    .bind(generation.generation)
    .bind(&generation.group_id)
    .bind(&generation.genesis_group_info_bytes)
    .bind(&generation.genesis_group_info_sha256)
    .bind(generation.current_state_version)
    .bind(generation.activated_seq)
    .bind(generation.activated_at)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

/// Advance an active generation's `current_state_version` pointer within the
/// same generation (policy / acceptConversation / metadata / leavePolicy — every
/// same-generation `stateVersion+1` edge). Matches only a still-active
/// generation whose `current_state_version` equals the expected prior; a drifted
/// pointer matches nothing and is a typed conflict. The deferred
/// generation-pointer-agreement trigger requires the new pointer to equal the
/// max produced state version and to point at an active state row.
#[derive(Clone, Debug)]
pub(crate) struct GenerationStateVersionCas {
    pub(crate) conversation_id: Uuid,
    pub(crate) generation: i64,
    pub(crate) expected_state_version: i64,
    pub(crate) successor_state_version: i64,
}

pub(crate) async fn cas_generation_state_version(
    transaction: &mut Transaction<'_, Postgres>,
    cas: &GenerationStateVersionCas,
) -> Result<(), TransitionRepositoryError> {
    let result = sqlx::query(
        r#"
        UPDATE chat.generations
           SET current_state_version = $4
         WHERE conversation_id = $1
           AND generation = $2
           AND current_state_version = $3
           AND lifecycle = 'active'
        "#,
    )
    .bind(cas.conversation_id)
    .bind(cas.generation)
    .bind(cas.expected_state_version)
    .bind(cas.successor_state_version)
    .execute(&mut **transaction)
    .await?;

    if result.rows_affected() != 1 {
        return Err(TransitionRepositoryError::CompareAndSetConflict);
    }
    Ok(())
}

/// Supersede an active generation, recording the superseding seq/instant and its
/// final `current_state_version` pointer. Used by `closeConversation` (the
/// generation goes terminal with the conversation) and by reset retirement (the
/// old generation is superseded as its successor activates). Matches only a
/// still-active generation whose `current_state_version` equals the expected
/// prior; a drifted or already-superseded generation is a typed conflict.
#[derive(Clone, Debug)]
pub(crate) struct GenerationSupersede {
    pub(crate) conversation_id: Uuid,
    pub(crate) generation: i64,
    pub(crate) expected_state_version: i64,
    pub(crate) successor_state_version: i64,
    pub(crate) superseded_seq: i64,
    pub(crate) superseded_at: DateTime<Utc>,
}

pub(crate) async fn supersede_generation(
    transaction: &mut Transaction<'_, Postgres>,
    supersede: &GenerationSupersede,
) -> Result<(), TransitionRepositoryError> {
    let result = sqlx::query(
        r#"
        UPDATE chat.generations
           SET lifecycle = 'superseded',
               current_state_version = $4,
               superseded_seq = $5,
               superseded_at = $6
         WHERE conversation_id = $1
           AND generation = $2
           AND current_state_version = $3
           AND lifecycle = 'active'
        "#,
    )
    .bind(supersede.conversation_id)
    .bind(supersede.generation)
    .bind(supersede.expected_state_version)
    .bind(supersede.successor_state_version)
    .bind(supersede.superseded_seq)
    .bind(supersede.superseded_at)
    .execute(&mut **transaction)
    .await?;

    if result.rows_affected() != 1 {
        return Err(TransitionRepositoryError::CompareAndSetConflict);
    }
    Ok(())
}
