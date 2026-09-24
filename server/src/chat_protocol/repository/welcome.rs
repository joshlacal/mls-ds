// Welcome-expiry worker and recovery-inbox read authority for the clean-chat
// protocol (Task 2, Slice 4b).
//
// This module owns two closed query/transaction seams that sit *beside* the
// `repository::delivery` writers rather than duplicating them:
//
//   1. The **welcome-expiry worker claim**: a `FOR UPDATE SKIP LOCKED` select
//      over pending `chat.welcome_deliveries` in global `(expires_at, welcome_id)`
//      order, returning exactly the due rows a worker will terminalize. It is the
//      missing *input* half of the expiry lifecycle — the terminal CAS itself is
//      the already-built `delivery::terminalize_welcome_delivery`
//      (`WelcomeDisposition::Expired`) plus `delivery::insert_recovery_work_item`.
//      The claim never CASes, never mutates, and never advances a conversation
//      coordinate; it only claims work so two workers cannot double-process one
//      row and a delayed ACK/reject that arrives after the claim CAS-misses.
//
//   2. The **recovery-inbox reads**: the `recoveryWorkView` closed four-variant
//      projection and the flat `getLeafRecoveryInbox` union. Both are strictly
//      device-scoped, so a same-DID sibling device enumerates nothing through
//      them, and the four recovery-work variants are reconstructed by a checked
//      mapping that rejects every malformed status/terminal-field combination.
//
// The module CALLS the `delivery` writers; it never relocates them and never
// bypasses the state machine for a conversation mutation (welcome expiry keeps
// the coordinate fixed and is server-authored advisory work only).
//
// No production handler consumes this read/claim surface yet (the worker and the
// `getLeafRecoveryInbox` handler land in a later slice), so the module is marked
// `#[allow(dead_code)]` at its `mod` declaration (`repository/mod.rs`), mirroring
// the sibling `delivery` read path's narrow local allow rather than a crate-wide
// one.

use chrono::{DateTime, Utc};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use super::delivery::RecoveryWorkSourceKind;

/// Failures the welcome-expiry / recovery-inbox reads can surface. Mirrors the
/// sibling `delivery::DeliveryRepositoryError` conventions: a raw database error
/// is wrapped, and each structural rejection is its own typed variant so a
/// caller (and a test) can distinguish "the database said no" from "the stored
/// row shape is not a legal closed-union member".
#[derive(Debug)]
pub(crate) enum WelcomeRepositoryError {
    /// A database error escaped the transaction/query.
    Database(sqlx::Error),
    /// A claimed or read row carried a negative `generation`, `state_version`, or
    /// `transition_seq`. Those columns are schema-checked safe integers, so a
    /// negative value can only mean corruption; the row is rejected rather than
    /// surfaced as a nonsensical coordinate.
    SafeIntegerOverflow,
    /// A `chat.recovery_work_items` row could not be mapped to exactly one closed
    /// `recoveryWorkView` variant: its `(status, terminal_transition_id,
    /// terminal_revocation_id, terminal_at)` tuple was not a legal member of the
    /// four-variant union (missing terminal fields, both terminal ids set, a
    /// wrong/unknown status, or a terminal field present on a pending row). The
    /// projection is closed, so a malformed row is rejected rather than coerced.
    MalformedRecoveryWorkVariant,
    /// A stored `source_kind` was not one of the closed
    /// `welcomeExpired | welcomeRejected` values.
    MalformedRecoveryWorkSourceKind,
}

impl From<sqlx::Error> for WelcomeRepositoryError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

// ===========================================================================
// Part 1 — welcome-expiry worker claim (the input for the expiry lifecycle).
// ===========================================================================

/// One due pending Welcome delivery, claimed under the worker's row lock. It
/// carries exactly what the expiry terminalization needs: the delivery identity
/// and immutable recipient/reservation/package bytes (from
/// `chat.welcome_deliveries`) plus the bound coordinate and opening transition
/// seq (from the delivery's `chat.welcome_bundles` row). `expires_at` is the
/// consumed Add KeyPackage `not_after`, copied verbatim, and is also the exact
/// terminal instant a successful expiry writes (`terminal_at = expires_at`).
///
/// The row is claimed with `FOR UPDATE ... SKIP LOCKED`, so holding this value
/// means the caller's open transaction owns the exclusive lock on that delivery
/// row: no concurrent worker can claim it, and a delayed ACK/reject that reaches
/// `terminalize_welcome_delivery` after the worker's CAS finds the row no longer
/// `pending` and loses.
#[derive(Clone, Debug)]
pub(crate) struct DueWelcomeDelivery {
    pub(crate) welcome_id: Uuid,
    pub(crate) conversation_id: Uuid,
    pub(crate) recipient_did: String,
    pub(crate) recipient_device_id: Uuid,
    pub(crate) recovery_request_id: Uuid,
    pub(crate) key_package_ref: Vec<u8>,
    pub(crate) expires_at: DateTime<Utc>,
    pub(crate) generation: i64,
    pub(crate) state_version: i64,
    pub(crate) transition_seq: i64,
}

/// Claim up to `limit` **due** pending Welcome deliveries for expiry processing,
/// locking them in the same global order the pending-expiry index materializes:
/// `(expires_at, welcome_id)`. A row is due only when its `expires_at <=
/// observed_at`; the caller supplies `observed_at` from its trusted server
/// instant.
///
/// The select locks only the `chat.welcome_deliveries` rows (`FOR UPDATE OF wd`)
/// and `SKIP LOCKED`s any a concurrent worker already holds, so two workers
/// running this claim in parallel partition the due set and never double-claim a
/// single delivery. The join to `chat.welcome_bundles` supplies the bound
/// coordinate/seq and is not itself locked.
///
/// This function performs no CAS and no mutation: it only claims work. The
/// caller terminalizes each returned row with the existing
/// `delivery::terminalize_welcome_delivery` (`WelcomeDisposition::Expired`,
/// `terminal_at = expires_at`) and `delivery::insert_recovery_work_item`
/// (`welcomeExpired`) inside the same transaction.
pub(crate) async fn claim_due_welcome_deliveries(
    transaction: &mut Transaction<'_, Postgres>,
    observed_at: DateTime<Utc>,
    limit: i64,
) -> Result<Vec<DueWelcomeDelivery>, WelcomeRepositoryError> {
    let rows = sqlx::query_as::<_, DueWelcomeDeliveryRow>(
        r#"
        SELECT wd.welcome_id,
               wb.conversation_id,
               wd.recipient_did,
               wd.recipient_device_id,
               wd.recovery_request_id,
               wd.key_package_ref,
               wd.expires_at,
               wb.generation,
               wb.state_version,
               wb.entry_seq AS transition_seq
          FROM chat.welcome_deliveries wd
          JOIN chat.welcome_bundles wb ON wb.welcome_id = wd.welcome_id
         WHERE wd.status = 'pending'
           AND wd.expires_at <= $1
         ORDER BY wd.expires_at, wd.welcome_id
         FOR UPDATE OF wd SKIP LOCKED
         LIMIT $2
        "#,
    )
    .bind(observed_at)
    .bind(limit)
    .fetch_all(&mut **transaction)
    .await?;

    rows.into_iter().map(DueWelcomeDelivery::try_from).collect()
}

#[derive(sqlx::FromRow)]
struct DueWelcomeDeliveryRow {
    welcome_id: Uuid,
    conversation_id: Uuid,
    recipient_did: String,
    recipient_device_id: Uuid,
    recovery_request_id: Uuid,
    key_package_ref: Vec<u8>,
    expires_at: DateTime<Utc>,
    generation: i64,
    state_version: i64,
    transition_seq: i64,
}

impl TryFrom<DueWelcomeDeliveryRow> for DueWelcomeDelivery {
    type Error = WelcomeRepositoryError;

    fn try_from(row: DueWelcomeDeliveryRow) -> Result<Self, Self::Error> {
        // The bound coordinate integers are schema-checked safe integers, but the
        // seq/generation/state_version are read back as `i64`; a negative value
        // could only appear through corruption, so reject it rather than surface a
        // nonsense coordinate.
        if row.generation < 0 || row.state_version < 0 || row.transition_seq < 0 {
            return Err(WelcomeRepositoryError::SafeIntegerOverflow);
        }
        Ok(Self {
            welcome_id: row.welcome_id,
            conversation_id: row.conversation_id,
            recipient_did: row.recipient_did,
            recipient_device_id: row.recipient_device_id,
            recovery_request_id: row.recovery_request_id,
            key_package_ref: row.key_package_ref,
            expires_at: row.expires_at,
            generation: row.generation,
            state_version: row.state_version,
            transition_seq: row.transition_seq,
        })
    }
}

// ===========================================================================
// Part 2 — recoveryWorkView: the closed four-variant projection.
// ===========================================================================

/// The immutable historical coordinate a recovery-work item is bound to: the
/// exact `(conversation_id, generation, state_version)` of the superseded
/// Welcome's producing transition. It keys into `chat.generation_states` and is
/// carried verbatim; hydrating the full public coordinate (group id, epoch,
/// context hash) is a later adapter concern, not this device-advisory read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RecoveryWorkCoordinate {
    pub(crate) conversation_id: Uuid,
    pub(crate) generation: i64,
    pub(crate) state_version: i64,
}

/// The nine fields every `recoveryWorkView` variant repeats verbatim (per the
/// lexicon: `recoveryWorkId, conversationId, recipientDid, recipientDeviceId,
/// sourceKind, sourceId, sourceCoordinate, status, createdAt`). `status` is not
/// carried here because it is the closed discriminant of the enum below.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RecoveryWorkCommon {
    pub(crate) recovery_work_id: Uuid,
    pub(crate) conversation_id: Uuid,
    pub(crate) recipient_did: String,
    pub(crate) recipient_device_id: Uuid,
    pub(crate) source_kind: RecoveryWorkSourceKind,
    pub(crate) source_id: Uuid,
    pub(crate) source_coordinate: RecoveryWorkCoordinate,
    pub(crate) created_at: DateTime<Utc>,
}

/// The named closed union `recoveryWorkView`: exactly four concrete variants,
/// each with a fixed `status` const and exactly the terminal fields that status
/// allows. `pending` carries none; the two `superseded`/`completed`-by-transition
/// variants carry `terminalTransitionId + terminalAt`; the revocation variant
/// carries `terminalRevocationId + terminalAt`. Any other combination is not a
/// member of this union and cannot be constructed (see `map_row`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryWorkView {
    Pending {
        common: RecoveryWorkCommon,
    },
    CompletedByTransition {
        common: RecoveryWorkCommon,
        terminal_transition_id: Uuid,
        terminal_at: DateTime<Utc>,
    },
    SupersededByTransition {
        common: RecoveryWorkCommon,
        terminal_transition_id: Uuid,
        terminal_at: DateTime<Utc>,
    },
    SupersededByRevocation {
        common: RecoveryWorkCommon,
        terminal_revocation_id: Uuid,
        terminal_at: DateTime<Utc>,
    },
}

impl RecoveryWorkView {
    /// The closed-union `$type`-equivalent variant name, for structural tests
    /// and later wire adaptation.
    pub(crate) fn variant_name(&self) -> &'static str {
        match self {
            Self::Pending { .. } => "recoveryWorkPendingView",
            Self::CompletedByTransition { .. } => "recoveryWorkCompletedByTransitionView",
            Self::SupersededByTransition { .. } => "recoveryWorkSupersededByTransitionView",
            Self::SupersededByRevocation { .. } => "recoveryWorkSupersededByRevocationView",
        }
    }

    pub(crate) fn common(&self) -> &RecoveryWorkCommon {
        match self {
            Self::Pending { common }
            | Self::CompletedByTransition { common, .. }
            | Self::SupersededByTransition { common, .. }
            | Self::SupersededByRevocation { common, .. } => common,
        }
    }
}

/// One `chat.recovery_work_items` row as read back. The terminal columns are all
/// nullable because their presence is exactly what selects the variant; the
/// checked `map_row` mapping — not this struct — is the union authority.
#[derive(Clone, Debug, sqlx::FromRow)]
pub(crate) struct RecoveryWorkRow {
    pub(crate) recovery_work_id: Uuid,
    pub(crate) conversation_id: Uuid,
    pub(crate) recipient_did: String,
    pub(crate) recipient_device_id: Uuid,
    pub(crate) source_kind: String,
    pub(crate) source_id: Uuid,
    pub(crate) generation: i64,
    pub(crate) state_version: i64,
    pub(crate) status: String,
    pub(crate) terminal_transition_id: Option<Uuid>,
    pub(crate) terminal_revocation_id: Option<Uuid>,
    pub(crate) terminal_at: Option<DateTime<Utc>>,
    pub(crate) created_at: DateTime<Utc>,
}

fn parse_source_kind(value: &str) -> Result<RecoveryWorkSourceKind, WelcomeRepositoryError> {
    match value {
        "welcomeExpired" => Ok(RecoveryWorkSourceKind::WelcomeExpired),
        "welcomeRejected" => Ok(RecoveryWorkSourceKind::WelcomeRejected),
        _ => Err(WelcomeRepositoryError::MalformedRecoveryWorkSourceKind),
    }
}

/// Map one stored row to exactly one closed `recoveryWorkView` variant, or reject
/// it. This is the structural union gate the brief requires: every
/// missing/extra/cross-kind/both-terminal/wrong-status combination rejects.
///
/// The database's `recovery_work_items_terminal_shape_check` already forbids the
/// illegal shapes at write time, but this mapping is the read-side authority so
/// a caller (and the accept/reject test matrix) can rely on the projection being
/// closed independently of trusting the row's provenance.
pub(crate) fn map_row(row: &RecoveryWorkRow) -> Result<RecoveryWorkView, WelcomeRepositoryError> {
    if row.generation < 0 || row.state_version < 0 {
        return Err(WelcomeRepositoryError::SafeIntegerOverflow);
    }
    let common = RecoveryWorkCommon {
        recovery_work_id: row.recovery_work_id,
        conversation_id: row.conversation_id,
        recipient_did: row.recipient_did.clone(),
        recipient_device_id: row.recipient_device_id,
        source_kind: parse_source_kind(&row.source_kind)?,
        source_id: row.source_id,
        source_coordinate: RecoveryWorkCoordinate {
            conversation_id: row.conversation_id,
            generation: row.generation,
            state_version: row.state_version,
        },
        created_at: row.created_at,
    };

    match (
        row.status.as_str(),
        row.terminal_transition_id,
        row.terminal_revocation_id,
        row.terminal_at,
    ) {
        // pending: no terminal field of any kind.
        ("pending", None, None, None) => Ok(RecoveryWorkView::Pending { common }),
        // completed: transition + instant, no revocation.
        ("completed", Some(transition), None, Some(at)) => {
            Ok(RecoveryWorkView::CompletedByTransition {
                common,
                terminal_transition_id: transition,
                terminal_at: at,
            })
        }
        // superseded by a coordinate-advancing transition.
        ("superseded", Some(transition), None, Some(at)) => {
            Ok(RecoveryWorkView::SupersededByTransition {
                common,
                terminal_transition_id: transition,
                terminal_at: at,
            })
        }
        // superseded by the recipient device's own revocation.
        ("superseded", None, Some(revocation), Some(at)) => {
            Ok(RecoveryWorkView::SupersededByRevocation {
                common,
                terminal_revocation_id: revocation,
                terminal_at: at,
            })
        }
        // Everything else — missing terminal fields, both terminal ids set, a
        // terminal field on a pending row, an unknown status — is not a legal
        // member of the closed union.
        _ => Err(WelcomeRepositoryError::MalformedRecoveryWorkVariant),
    }
}

/// Read the `recoveryWorkView` list for exactly one recipient device. The select
/// is scoped to `(recipient_did, recipient_device_id)`, so a same-DID sibling
/// device — which owns different rows or none — enumerates nothing through it.
///
/// The revocation-terminal variant is additionally guarded at the SQL level: the
/// row's `terminal_revocation_id` must resolve to a `chat.device_revocations`
/// row whose `(target_did, target_device_id)` byte-equals this row's
/// `(recipient_did, recipient_device_id)`. The write-time foreign key already
/// enforces this exact binding, so the guard is a defensive read-side assertion
/// that a superseded-by-revocation item can never surface a sibling's revocation.
pub(crate) async fn read_recovery_work_view(
    transaction: &mut Transaction<'_, Postgres>,
    recipient_did: &str,
    recipient_device_id: Uuid,
) -> Result<Vec<RecoveryWorkView>, WelcomeRepositoryError> {
    let rows = sqlx::query_as::<_, RecoveryWorkRow>(
        r#"
        SELECT rwi.recovery_work_id,
               rwi.conversation_id,
               rwi.recipient_did,
               rwi.recipient_device_id,
               rwi.source_kind,
               rwi.source_id,
               rwi.generation,
               rwi.state_version,
               rwi.status,
               rwi.terminal_transition_id,
               rwi.terminal_revocation_id,
               rwi.terminal_at,
               rwi.created_at
          FROM chat.recovery_work_items rwi
         WHERE rwi.recipient_did = $1
           AND rwi.recipient_device_id = $2
           AND (
                rwi.terminal_revocation_id IS NULL
                OR EXISTS (
                    SELECT 1
                      FROM chat.device_revocations dr
                     WHERE dr.revocation_id = rwi.terminal_revocation_id
                       AND dr.target_did = rwi.recipient_did
                       AND dr.target_device_id = rwi.recipient_device_id
                )
           )
         ORDER BY rwi.created_at, rwi.recovery_work_id
        "#,
    )
    .bind(recipient_did)
    .bind(recipient_device_id)
    .fetch_all(&mut **transaction)
    .await?;

    rows.iter().map(map_row).collect()
}

// ===========================================================================
// Part 3 — getLeafRecoveryInbox: the flat closed union.
// ===========================================================================

/// The `leafRecoveryView` arm of the inbox union: one open, target-device-signed
/// leaf-recovery request paired with its active internal reservation. It carries
/// the request/reservation columns verbatim; the union references this view
/// unchanged (it is *not* redefined here), so the inbox never introduces a
/// second nested union.
#[derive(Clone, Debug)]
pub(crate) struct LeafRecoveryView {
    pub(crate) recovery_request_id: Uuid,
    pub(crate) conversation_id: Uuid,
    pub(crate) generation: i64,
    pub(crate) requester_did: String,
    pub(crate) requester_device_id: Uuid,
    pub(crate) requester_key_id: String,
    pub(crate) requester_auth_generation: i64,
    pub(crate) recovery_kind: String,
    pub(crate) source: String,
    pub(crate) bound_state_version: i64,
    pub(crate) bound_group_id: Vec<u8>,
    pub(crate) bound_epoch: i64,
    pub(crate) bound_group_context_hash: Vec<u8>,
    pub(crate) bound_confirmation_tag: Vec<u8>,
    pub(crate) signed_request_bytes: Vec<u8>,
    pub(crate) request_digest: Vec<u8>,
    pub(crate) signature: Vec<u8>,
    pub(crate) requested_at: DateTime<Utc>,
    pub(crate) expires_at: DateTime<Utc>,
    /// The paired active reservation (keyed by the same `recovery_request_id`).
    pub(crate) reservation_key_package_ref: Vec<u8>,
    pub(crate) reservation_expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, sqlx::FromRow)]
struct LeafRecoveryViewRow {
    recovery_request_id: Uuid,
    conversation_id: Uuid,
    generation: i64,
    requester_did: String,
    requester_device_id: Uuid,
    requester_key_id: String,
    requester_auth_generation: i64,
    recovery_kind: String,
    source: String,
    bound_state_version: i64,
    bound_group_id: Vec<u8>,
    bound_epoch: i64,
    bound_group_context_hash: Vec<u8>,
    bound_confirmation_tag: Vec<u8>,
    signed_request_bytes: Vec<u8>,
    request_digest: Vec<u8>,
    signature: Vec<u8>,
    requested_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    reservation_key_package_ref: Vec<u8>,
    reservation_expires_at: DateTime<Utc>,
}

/// The flat closed union `leafRecoveryInboxItem`: unchanged `leafRecoveryView`
/// plus the same four concrete recovery-work objects. Neither arm references
/// another union — the recovery-work objects are the concrete variants, not the
/// `recoveryWorkView` union value.
#[derive(Clone, Debug)]
pub(crate) enum LeafRecoveryInboxItem {
    LeafRecovery(LeafRecoveryView),
    RecoveryWork(RecoveryWorkView),
}

impl LeafRecoveryInboxItem {
    pub(crate) fn variant_name(&self) -> &'static str {
        match self {
            Self::LeafRecovery(_) => "leafRecoveryView",
            Self::RecoveryWork(view) => view.variant_name(),
        }
    }
}

/// Read the full `getLeafRecoveryInbox` for exactly one device: every OPEN
/// leaf-recovery request the device signed (as requester), each paired with its
/// active reservation, followed by every recovery-work item addressed to the
/// device. Both halves are scoped to the exact `(did, device_id)`, so a sibling
/// enumerates nothing. The recovery-work half reuses the same closed-union
/// mapping and revocation-target guard as `read_recovery_work_view`.
pub(crate) async fn read_leaf_recovery_inbox(
    transaction: &mut Transaction<'_, Postgres>,
    device_did: &str,
    device_id: Uuid,
) -> Result<Vec<LeafRecoveryInboxItem>, WelcomeRepositoryError> {
    let request_rows = sqlx::query_as::<_, LeafRecoveryViewRow>(
        r#"
        SELECT lrr.recovery_request_id,
               lrr.conversation_id,
               lrr.generation,
               lrr.requester_did,
               lrr.requester_device_id,
               lrr.requester_key_id,
               lrr.requester_auth_generation,
               lrr.recovery_kind,
               lrr.source,
               lrr.bound_state_version,
               lrr.bound_group_id,
               lrr.bound_epoch,
               lrr.bound_group_context_hash,
               lrr.bound_confirmation_tag,
               lrr.signed_request_bytes,
               lrr.request_digest,
               lrr.signature,
               lrr.requested_at,
               lrr.expires_at,
               kpr.key_package_ref AS reservation_key_package_ref,
               kpr.expires_at      AS reservation_expires_at
          FROM chat.leaf_recovery_requests lrr
          JOIN chat.key_package_reservations kpr
            ON kpr.recovery_request_id = lrr.recovery_request_id
         WHERE lrr.requester_did = $1
           AND lrr.requester_device_id = $2
           AND lrr.status = 'open'
           AND kpr.status = 'active'
         ORDER BY lrr.requested_at, lrr.recovery_request_id
        "#,
    )
    .bind(device_did)
    .bind(device_id)
    .fetch_all(&mut **transaction)
    .await?;

    let mut items: Vec<LeafRecoveryInboxItem> = request_rows
        .into_iter()
        .map(|row| {
            LeafRecoveryInboxItem::LeafRecovery(LeafRecoveryView {
                recovery_request_id: row.recovery_request_id,
                conversation_id: row.conversation_id,
                generation: row.generation,
                requester_did: row.requester_did,
                requester_device_id: row.requester_device_id,
                requester_key_id: row.requester_key_id,
                requester_auth_generation: row.requester_auth_generation,
                recovery_kind: row.recovery_kind,
                source: row.source,
                bound_state_version: row.bound_state_version,
                bound_group_id: row.bound_group_id,
                bound_epoch: row.bound_epoch,
                bound_group_context_hash: row.bound_group_context_hash,
                bound_confirmation_tag: row.bound_confirmation_tag,
                signed_request_bytes: row.signed_request_bytes,
                request_digest: row.request_digest,
                signature: row.signature,
                requested_at: row.requested_at,
                expires_at: row.expires_at,
                reservation_key_package_ref: row.reservation_key_package_ref,
                reservation_expires_at: row.reservation_expires_at,
            })
        })
        .collect();

    for view in read_recovery_work_view(transaction, device_did, device_id).await? {
        items.push(LeafRecoveryInboxItem::RecoveryWork(view));
    }

    Ok(items)
}
