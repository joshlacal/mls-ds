// Repository-owned `getConversationState` read.
//
// The handler supplies only a sealed read admission and the public
// conversation UUID.  This facade spends the one ordinary-read attempt,
// locks and authorizes the exact requester device, and keeps that transaction
// open while projecting the state and pending control-plane requests.

#[path = "conversation/recovery.rs"]
mod recovery;

use chrono::{DateTime, SecondsFormat, Utc};
use petrel_core::Did;
use sqlx::{FromRow, Postgres, Transaction};
use thiserror::Error;
use uuid::Uuid;

use super::super::{
    dpop::VerifiedReadAdmission,
    read_authority::{
        authorize_conversation_state, into_single_read_admission, lock_read_device_authority_once,
        CurrentConversationRelationshipWitness, OrdinaryReadEndpoint, ReadAuthorityError,
    },
    read_projection::{
        conversation_coordinates_dto, conversation_state_view,
        encode_canonical_petrel_chat_json_v1, CheckedConversationCoordinates,
    },
};

#[derive(Debug, Error)]
pub(crate) enum ConversationStateReadError {
    #[error("conversation not found")]
    ConversationNotFound,
    #[error("client must opt into paginated deletion inventory")]
    PaginationRequired,
    #[error("not entitled")]
    NotEntitled,
    #[error("outside membership interval")]
    AccessOutsideMembershipInterval,
    #[error("device revoked")]
    DeviceRevoked,
    #[error("storage failure")]
    Storage,
    #[error("internal invariant")]
    Invariant,
}

pub(crate) struct CanonicalConversationStateResponse {
    bytes: Vec<u8>,
}

impl CanonicalConversationStateResponse {
    pub(crate) fn into_response_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Read one conversation state with the exact-device B-read authority.
pub(crate) async fn read_conversation_state_for_admission(
    pool: &sqlx::PgPool,
    admission: VerifiedReadAdmission,
    conversation_id: Uuid,
) -> Result<CanonicalConversationStateResponse, ConversationStateReadError> {
    read_conversation_state_page_for_admission(pool, admission, conversation_id, None).await
}

pub(crate) async fn read_conversation_state_page_for_admission(
    pool: &sqlx::PgPool,
    admission: VerifiedReadAdmission,
    conversation_id: Uuid,
    deletions_after: Option<i64>,
) -> Result<CanonicalConversationStateResponse, ConversationStateReadError> {
    let attempt = into_single_read_admission(admission, OrdinaryReadEndpoint::GetConversationState)
        .map_err(|_| ConversationStateReadError::Invariant)?
        .into_attempt();

    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| ConversationStateReadError::Storage)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *transaction)
        .await
        .map_err(|_| ConversationStateReadError::Storage)?;

    let result = read_conversation_state_in_transaction(
        &mut transaction,
        attempt,
        conversation_id,
        deletions_after,
    )
    .await;
    let _ = transaction.rollback().await;
    result
}

async fn read_conversation_state_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    attempt: super::super::dpop::ReadAdmissionAttempt,
    conversation_id: Uuid,
    deletions_after: Option<i64>,
) -> Result<CanonicalConversationStateResponse, ConversationStateReadError> {
    let device = lock_read_device_authority_once(transaction, attempt)
        .await
        .map_err(map_authority_error)?;
    let requester_did = device.user_did().to_owned();
    let requester_device_id = device.device_id();

    let local_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat.conversations WHERE conversation_id = $1)",
    )
    .bind(conversation_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| ConversationStateReadError::Storage)?;

    if local_exists {
        // Keep the checked relationship witness through projection: a pending
        // invitee receives the conversation state it must sign acceptance over,
        // but never the established members' pending control-plane requests.
        let authority = authorize_conversation_state(transaction, device, conversation_id)
            .await
            .map_err(map_authority_error)?;

        let source = super::inventory::load_conversation_state_source(
            transaction,
            conversation_id,
            &requester_did,
        )
        .await
        .map_err(map_inventory_error)?;
        let mut state = conversation_state_view(&source).map_err(|error| {
            tracing::error!(class = ?error.kind(), "conversation state projection failed");
            ConversationStateReadError::Invariant
        })?;
        attach_labyrinth_heads(transaction, &mut state.participants)
            .await
            .map_err(|_| ConversationStateReadError::Storage)?;
        let established = includes_pending_requests(authority.relationship());
        let (pending_leave_requests, pending_reset_requests) = if established {
            load_pending_requests(transaction, conversation_id).await?
        } else {
            (Vec::new(), Vec::new())
        };
        let pending_leaf_recovery_requests =
            recovery::load_pending_leaf_recoveries(transaction, &authority).await?;
        // Deletion evidence is current-member material, leaf or not: a fresh device of a
        // member DID needs it to hide restored history it can never read entries for.
        let (account_deletions, deletions_cursor) = if established {
            load_account_deletion_page(transaction, conversation_id, deletions_after).await?
        } else {
            (Vec::new(), None)
        };

        return conversation_state_response(
            catbird_server::blue_catbird::chat::get_conversation_state::Output {
                account_deletions,
                deletions_cursor,
                pending_leave_requests,
                pending_leaf_recovery_requests: Some(pending_leaf_recovery_requests),
                pending_reset_requests,
                state,
            },
        );
    }

    let Some((row_device_id, member)) = transport_home_reader(
        transaction,
        conversation_id,
        &requester_did,
        requester_device_id,
    )
    .await
    .map_err(|_| ConversationStateReadError::Storage)?
    else {
        return Err(ConversationStateReadError::ConversationNotFound);
    };

    let (_delivery_id, source) = super::inventory::load_remote_transport_conversation_source(
        transaction,
        conversation_id,
        &requester_did,
        row_device_id,
    )
    .await
    .map_err(map_inventory_error)?;

    let mut state = conversation_state_view(&source).map_err(|error| {
        tracing::error!(class = ?error.kind(), "remote conversation state projection failed");
        ConversationStateReadError::Invariant
    })?;
    // The heads come from this DS's own directory, as on the local path and
    // in getEpochHead, whichever DS sequences the conversation.
    attach_labyrinth_heads(transaction, &mut state.participants)
        .await
        .map_err(|_| ConversationStateReadError::Storage)?;

    let (account_deletions, deletions_cursor) = if member {
        load_account_deletion_page(transaction, conversation_id, deletions_after).await?
    } else {
        (Vec::new(), None)
    };

    conversation_state_response(
        catbird_server::blue_catbird::chat::get_conversation_state::Output {
            account_deletions,
            deletions_cursor,
            pending_leave_requests: Vec::new(),
            pending_leaf_recovery_requests: Some(Vec::new()),
            pending_reset_requests: Vec::new(),
            state,
        },
    )
}

/// At a C33 transport home, the recipient inbox row whose state `did`'s `device_id` reads,
/// and whether `did` is a current member. The home holds one row per recipient device:
/// the exact device reads its own row, never whichever row PostgreSQL returns first, and
/// any other active device of the recipient DID of an accepted pair (a fresh recovery
/// device with no row) reads that pair's row with no leaf of its own. Only an accepted
/// pair's recipient is a current member. `None`: no relationship, nothing is served.
pub(crate) async fn transport_home_reader(
    transaction: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    did: &str,
    device_id: Uuid,
) -> Result<Option<(Uuid, bool)>, sqlx::Error> {
    let (exact, accepted): (Option<Uuid>, Option<Uuid>) = sqlx::query_as(
        "SELECT (SELECT recipient_device_id FROM chat.direct_request_transport_inbox \
                  WHERE conversation_id = $1 AND recipient_did = $2 \
                    AND recipient_device_id = $3), \
                (SELECT recipient_device_id FROM chat.direct_request_transport_inbox \
                  WHERE conversation_id = $1 AND recipient_did = $2 AND status = 'accepted' \
                  ORDER BY delivery_id LIMIT 1)",
    )
    .bind(conversation_id)
    .bind(did)
    .bind(device_id)
    .fetch_one(&mut **transaction)
    .await?;
    Ok(exact.or(accepted).map(|row| (row, accepted.is_some())))
}

const ACCOUNT_DELETED_ENTRY_KIND: &str = "blue.catbird.chat.defs#accountDeletedEntry";

/// Every `accountDeletedEntry` of `conversation_id` this DS holds, ascending seq, exactly
/// as its sequencer signed it: sequenced here, or replicated to this group mirror or C33
/// transport home. A plain `#accountDeletedEntry` ref carries no `$type`.
pub(crate) async fn load_account_deletions(
    transaction: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
) -> Result<Vec<catbird_server::blue_catbird::chat::AccountDeletedEntry>, ConversationStateReadError>
{
    Ok(
        load_account_deletion_page(transaction, conversation_id, None)
            .await?
            .0,
    )
}

pub(crate) async fn load_account_deletion_page(
    transaction: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    after: Option<i64>,
) -> Result<
    (
        Vec<catbird_server::blue_catbird::chat::AccountDeletedEntry>,
        Option<i64>,
    ),
    ConversationStateReadError,
> {
    const PAGE_SIZE: usize = 100;
    let sequenced: Vec<(i64, Uuid, DateTime<Utc>, Vec<u8>)> = sqlx::query_as(
        "SELECT seq, entry_id, received_at, server_fields_bytes FROM chat.entries \
          WHERE conversation_id = $1 AND entry_kind = $2 AND seq > $3 ORDER BY seq LIMIT 101",
    )
    .bind(conversation_id)
    .bind(ACCOUNT_DELETED_ENTRY_KIND)
    .bind(after.unwrap_or(0))
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| ConversationStateReadError::Storage)?;
    // Application rows carry their message id, and a replicated deletion is never
    // longer than its entry bound: every other row is skipped by those stored
    // columns alone, without detoasting its bytes.
    let replicated: Vec<(i64, Vec<u8>)> = sqlx::query_as(
        "SELECT seq, entry_bytes FROM chat.direct_request_transport_entries
          WHERE conversation_id = $1 AND application_message_id IS NULL AND seq > $4
            AND CASE WHEN octet_length(entry_bytes) <= $3 AND position($2::bytea IN entry_bytes) > 0
                     THEN convert_from(entry_bytes, 'UTF8')::jsonb ->> '$type' = $5
                     ELSE false END
          ORDER BY seq LIMIT 101",
    )
    .bind(conversation_id)
    .bind(format!("\"{ACCOUNT_DELETED_ENTRY_KIND}\"").into_bytes())
    .bind(crate::federation::receipt::ACCOUNT_DELETED_ENTRY_MAX_BYTES as i32)
    .bind(after.unwrap_or(0))
    .bind(ACCOUNT_DELETED_ENTRY_KIND)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| ConversationStateReadError::Storage)?;

    let mut by_seq = std::collections::BTreeMap::new();
    for (seq, entry_id, received_at, server_fields) in sequenced {
        let fields: super::entry_read::AccountDeletedServerFields =
            serde_ipld_dagcbor::from_slice(&server_fields)
                .map_err(|_| ConversationStateReadError::Invariant)?;
        by_seq.insert(
            seq,
            fields.entry(conversation_id, seq, entry_id, received_at),
        );
    }
    for (seq, bytes) in replicated {
        let entry: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| ConversationStateReadError::Invariant)?;
        // Its home verified the authority before storing it; it must still be exact.
        let (deletion, _) = crate::federation::receipt::AccountDeletion::from_entry(&entry)
            .map_err(|_| ConversationStateReadError::Invariant)?;
        if deletion.conversation_id != conversation_id || deletion.seq != seq {
            return Err(ConversationStateReadError::Invariant);
        }
        if by_seq.get(&seq).is_some_and(|existing| existing != &entry) {
            return Err(ConversationStateReadError::Invariant);
        }
        by_seq.insert(seq, entry);
    }
    let next = if by_seq.len() > PAGE_SIZE {
        if after.is_none() {
            return Err(ConversationStateReadError::PaginationRequired);
        }
        by_seq.keys().nth(PAGE_SIZE - 1).copied()
    } else {
        None
    };
    let page = by_seq
        .into_values()
        .take(PAGE_SIZE)
        .map(|mut entry| {
            if let Some(object) = entry.as_object_mut() {
                object.remove("$type");
            }
            serde_json::from_value(entry).map_err(|_| ConversationStateReadError::Invariant)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((page, next))
}

/// Present one `getConversationState` output.
///
/// Ordinary conversations use main's canonical JCS encoder. A conversation
/// carrying a `directRequest` uses the encrypted-requests presentation bridge,
/// which re-projects the generated view and proves no signed request material
/// changed before emitting `{"$bytes"}` presentation.
fn conversation_state_response(
    output: catbird_server::blue_catbird::chat::get_conversation_state::Output,
) -> Result<CanonicalConversationStateResponse, ConversationStateReadError> {
    let Some(request) = &output.state.direct_request else {
        return Ok(CanonicalConversationStateResponse {
            bytes: canonical_conversation_state_response_page(
                &output.account_deletions,
                output.deletions_cursor,
                &output.state,
                output
                    .pending_leaf_recovery_requests
                    .as_deref()
                    .unwrap_or_default(),
                &output.pending_leave_requests,
                &output.pending_reset_requests,
            )?,
        });
    };
    let mut wire = catbird_server::atproto_conv::wire_json_value(&output)
        .map_err(|_| ConversationStateReadError::Invariant)?;
    wire["state"]["directRequest"] =
        crate::chat_protocol::transcript::direct_request_generated_view_wire(
            request,
            "directRequestState",
            false,
        )
        .map_err(|_| ConversationStateReadError::Invariant)?;
    Ok(CanonicalConversationStateResponse {
        bytes: crate::chat_protocol::direct_request_transcript::present_endpoint_output(
            "blue.catbird.chat.getConversationState",
            serde_json::to_vec(&wire).map_err(|_| ConversationStateReadError::Invariant)?,
        )
        .map_err(|_| ConversationStateReadError::Invariant)?,
    })
}

fn append_canonical_array<T: serde::Serialize + serde::de::DeserializeOwned + PartialEq>(
    bytes: &mut Vec<u8>,
    values: &[T],
    definition_id: &'static str,
) -> Result<(), ConversationStateReadError> {
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            bytes.push(b',');
        }
        let canonical = encode_canonical_petrel_chat_json_v1(value, definition_id)
            .map_err(|_| ConversationStateReadError::Invariant)?;
        bytes.extend_from_slice(canonical.bytes());
    }
    Ok(())
}

fn canonical_conversation_state_response(
    account_deletions: &[catbird_server::blue_catbird::chat::AccountDeletedEntry],
    state: &catbird_server::blue_catbird::chat::ConversationState,
    pending_leaf_recovery_requests: &[catbird_server::blue_catbird::chat::LeafRecoveryView],
    pending_leave_requests: &[catbird_server::blue_catbird::chat::LeaveRequestView],
    pending_reset_requests: &[catbird_server::blue_catbird::chat::ResetRequestView],
) -> Result<Vec<u8>, ConversationStateReadError> {
    canonical_conversation_state_response_page(
        account_deletions,
        None,
        state,
        pending_leaf_recovery_requests,
        pending_leave_requests,
        pending_reset_requests,
    )
}

fn canonical_conversation_state_response_page(
    account_deletions: &[catbird_server::blue_catbird::chat::AccountDeletedEntry],
    deletions_cursor: Option<i64>,
    state: &catbird_server::blue_catbird::chat::ConversationState,
    pending_leaf_recovery_requests: &[catbird_server::blue_catbird::chat::LeafRecoveryView],
    pending_leave_requests: &[catbird_server::blue_catbird::chat::LeaveRequestView],
    pending_reset_requests: &[catbird_server::blue_catbird::chat::ResetRequestView],
) -> Result<Vec<u8>, ConversationStateReadError> {
    let canonical_state =
        encode_canonical_petrel_chat_json_v1(state, "blue.catbird.chat.defs#conversationState")
            .map_err(|_| ConversationStateReadError::Invariant)?;
    let mut bytes = Vec::with_capacity(canonical_state.bytes().len() + 64);
    bytes.extend_from_slice(br#"{"accountDeletions":["#);
    append_canonical_array(
        &mut bytes,
        account_deletions,
        "blue.catbird.chat.defs#accountDeletedEntry",
    )?;
    bytes.push(b']');
    if let Some(cursor) = deletions_cursor {
        bytes.extend_from_slice(br#","deletionsCursor":"#);
        bytes.extend_from_slice(cursor.to_string().as_bytes());
    }
    bytes.extend_from_slice(br#","pendingLeafRecoveryRequests":["#);
    append_canonical_array(
        &mut bytes,
        pending_leaf_recovery_requests,
        "blue.catbird.chat.defs#leafRecoveryView",
    )?;
    bytes.extend_from_slice(br#"],"pendingLeaveRequests":["#);
    append_canonical_array(
        &mut bytes,
        pending_leave_requests,
        "blue.catbird.chat.defs#leaveRequestView",
    )?;
    bytes.extend_from_slice(br#"],"pendingResetRequests":["#);
    append_canonical_array(
        &mut bytes,
        pending_reset_requests,
        "blue.catbird.chat.defs#resetRequestView",
    )?;
    bytes.extend_from_slice(br#"],"state":"#);
    bytes.extend_from_slice(canonical_state.bytes());
    bytes.push(b'}');
    Ok(bytes)
}

/// Pending leave/reset requests are established-member material: only a
/// current open leaf or an active participant receives them. A pending invitee
/// receives the state alone, and any future witness arm must opt in here
/// explicitly rather than inherit the requests by default.
fn includes_pending_requests(relationship: &CurrentConversationRelationshipWitness) -> bool {
    matches!(
        relationship,
        CurrentConversationRelationshipWitness::CurrentOpenLeaf { .. }
            | CurrentConversationRelationshipWitness::CurrentActiveParticipant { .. }
    )
}

fn map_authority_error(error: ReadAuthorityError) -> ConversationStateReadError {
    match error {
        ReadAuthorityError::ConversationNotFound => {
            ConversationStateReadError::ConversationNotFound
        }
        ReadAuthorityError::NotEntitled => ConversationStateReadError::NotEntitled,
        ReadAuthorityError::AccessOutsideMembershipInterval => {
            ConversationStateReadError::AccessOutsideMembershipInterval
        }
        ReadAuthorityError::DeviceRevoked => ConversationStateReadError::DeviceRevoked,
        ReadAuthorityError::Storage => ConversationStateReadError::Storage,
        ReadAuthorityError::Invariant => ConversationStateReadError::Invariant,
    }
}

fn map_inventory_error(
    error: super::inventory::InventoryRepositoryError,
) -> ConversationStateReadError {
    tracing::error!(class = ?std::mem::discriminant(&error), "conversation state source failed");
    if let super::inventory::InventoryRepositoryError::Projection(projection) = &error {
        tracing::error!(class = ?projection.kind(), "conversation state source projection failed");
    }
    match error {
        super::inventory::InventoryRepositoryError::Database(_) => {
            ConversationStateReadError::Storage
        }
        _ => ConversationStateReadError::Invariant,
    }
}

#[derive(Debug, FromRow)]
struct PendingResetRow {
    reset_request_id: Uuid,
    requester_did: String,
    requester_device_id: Uuid,
    prior_generation: i64,
    prior_state_version: i64,
    prior_group_id: Vec<u8>,
    prior_epoch: i64,
    prior_group_context_hash: Vec<u8>,
    prior_confirmation_tag: Vec<u8>,
    reason: String,
    received_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
struct PendingLeaveRow {
    leave_request_id: Uuid,
    requester_did: String,
    requester_device_id: Uuid,
    prior_generation: i64,
    prior_state_version: i64,
    prior_group_id: Vec<u8>,
    prior_epoch: i64,
    prior_group_context_hash: Vec<u8>,
    prior_confirmation_tag: Vec<u8>,
    received_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

async fn load_pending_requests(
    transaction: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
) -> Result<
    (
        Vec<catbird_server::blue_catbird::chat::LeaveRequestView>,
        Vec<catbird_server::blue_catbird::chat::ResetRequestView>,
    ),
    ConversationStateReadError,
> {
    let resets: Vec<PendingResetRow> = sqlx::query_as(
        r#"
        SELECT reset_request_id, requester_did, requester_device_id, prior_generation,
               prior_state_version, prior_group_id, prior_epoch, prior_group_context_hash,
               prior_confirmation_tag, reason, received_at, expires_at
          FROM chat.reset_requests
         WHERE conversation_id = $1 AND status = 'pending'
         ORDER BY reset_request_id
        "#,
    )
    .bind(conversation_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| ConversationStateReadError::Storage)?;

    let leaves: Vec<PendingLeaveRow> = sqlx::query_as(
        r#"
        SELECT leave_request_id, requester_did, requester_device_id, prior_generation,
               prior_state_version, prior_group_id, prior_epoch, prior_group_context_hash,
               prior_confirmation_tag, received_at, expires_at
          FROM chat.leave_requests
         WHERE conversation_id = $1 AND status = 'pending'
         ORDER BY leave_request_id
        "#,
    )
    .bind(conversation_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| ConversationStateReadError::Storage)?;

    let pending_reset_requests = resets
        .into_iter()
        .map(|row| reset_view(row, conversation_id))
        .collect::<Result<Vec<_>, _>>()?;
    let pending_leave_requests = leaves
        .into_iter()
        .map(|row| leave_view(row, conversation_id))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((pending_leave_requests, pending_reset_requests))
}

fn checked_prior(
    conversation_id: Uuid,
    generation: i64,
    state_version: i64,
    group_id: &[u8],
    epoch: i64,
    group_context_hash: &[u8],
    confirmation_tag: &[u8],
) -> Result<catbird_server::blue_catbird::chat::ConversationCoordinates, ConversationStateReadError>
{
    let checked = CheckedConversationCoordinates::new(
        &conversation_id.to_string(),
        generation,
        state_version,
        group_id,
        epoch,
        group_context_hash,
        confirmation_tag,
        "active",
    )
    .map_err(|_| ConversationStateReadError::Invariant)?;
    Ok(conversation_coordinates_dto(&checked))
}

fn canonical_datetime(
    value: DateTime<Utc>,
) -> catbird_server::blue_catbird::chat::CanonicalDatetime {
    catbird_server::blue_catbird::chat::CanonicalDatetime::parse(
        value.to_rfc3339_opts(SecondsFormat::Millis, true),
    )
    .expect("canonical millis UTC is a valid AT Protocol datetime")
}

fn requester_did(value: &str) -> Result<Did, ConversationStateReadError> {
    Did::parse(String::from(value)).map_err(|_| ConversationStateReadError::Invariant)
}

fn reset_view(
    row: PendingResetRow,
    conversation_id: Uuid,
) -> Result<catbird_server::blue_catbird::chat::ResetRequestView, ConversationStateReadError> {
    Ok(catbird_server::blue_catbird::chat::ResetRequestView {
        conversation_id: String::from(conversation_id.to_string()),
        expires_at: canonical_datetime(row.expires_at),
        prior: checked_prior(
            conversation_id,
            row.prior_generation,
            row.prior_state_version,
            &row.prior_group_id,
            row.prior_epoch,
            &row.prior_group_context_hash,
            &row.prior_confirmation_tag,
        )?,
        reason: catbird_server::atproto_conv::open_enum(row.reason),
        requested_at: canonical_datetime(row.received_at),
        requester_device_id: String::from(row.requester_device_id.to_string()),
        requester_did: requester_did(&row.requester_did)?,
        reset_request_id: String::from(row.reset_request_id.to_string()),
        status: catbird_server::blue_catbird::chat::ResetRequestViewStatus::Pending,
        extra_data: None,
    })
}

fn leave_view(
    row: PendingLeaveRow,
    conversation_id: Uuid,
) -> Result<catbird_server::blue_catbird::chat::LeaveRequestView, ConversationStateReadError> {
    Ok(catbird_server::blue_catbird::chat::LeaveRequestView {
        conversation_id: String::from(conversation_id.to_string()),
        expires_at: canonical_datetime(row.expires_at),
        leave_request_id: String::from(row.leave_request_id.to_string()),
        prior: checked_prior(
            conversation_id,
            row.prior_generation,
            row.prior_state_version,
            &row.prior_group_id,
            row.prior_epoch,
            &row.prior_group_context_hash,
            &row.prior_confirmation_tag,
        )?,
        requested_at: canonical_datetime(row.received_at),
        requester_device_id: String::from(row.requester_device_id.to_string()),
        requester_did: requester_did(&row.requester_did)?,
        status: catbird_server::atproto_conv::open_enum("pending"),
        extra_data: None,
    })
}

/// `participantView.labyrinthHead` (labyrinth design §1a, Y5): each
/// participant's latest head in the mls-ds Labyrinth directory
/// (`labyrinth.epoch_heads`, migration 20261004100001). A database without
/// the `labyrinth` schema (the frozen clean-chat test ledger, or a
/// deployment without the Labyrinth migrations) projects no heads instead of
/// failing the chat read. Kept here, not in `crate::labyrinth`, because the
/// test harnesses `include!` this file into their own crates.
async fn attach_labyrinth_heads(
    transaction: &mut Transaction<'_, Postgres>,
    participants: &mut [catbird_server::blue_catbird::chat::ParticipantView],
) -> Result<(), sqlx::Error> {
    if participants.is_empty() {
        return Ok(());
    }
    let installed: bool =
        sqlx::query_scalar("SELECT to_regclass('labyrinth.epoch_heads') IS NOT NULL")
            .fetch_one(&mut **transaction)
            .await?;
    if !installed {
        return Ok(());
    }
    let dids: Vec<String> = participants
        .iter()
        .map(|participant| participant.user_did.as_str().to_owned())
        .collect();
    let heads: Vec<(String, i64, Vec<u8>, String)> = sqlx::query_as(
        "SELECT DISTINCT ON (did) did, epoch_number, epoch_head, attestation_key_id \
           FROM labyrinth.epoch_heads WHERE did = ANY($1) \
          ORDER BY did, epoch_number DESC",
    )
    .bind(&dids)
    .fetch_all(&mut **transaction)
    .await?;
    for participant in participants.iter_mut() {
        if let Some((_, epoch_number, head, key_id)) = heads
            .iter()
            .find(|(did, ..)| did == participant.user_did.as_str())
        {
            participant.labyrinth_head = Some(catbird_server::blue_catbird::chat::LabyrinthHead {
                attestation_key_id: String::from(key_id.as_str()),
                epoch_head: petrel_core::Bytes(<[u8]>::to_vec(head)),
                epoch_number: *epoch_number,
                extra_data: None,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    mod fresh_db {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/test_support/fresh_db.rs"
        ));
    }

    use super::*;

    #[test]
    fn pending_participant_cannot_read_pending_control_requests() {
        let relationship = CurrentConversationRelationshipWitness::CurrentPendingParticipant {
            participant_period_id: Uuid::new_v4(),
        };

        assert!(!includes_pending_requests(&relationship));
    }

    #[test]
    fn established_member_can_read_pending_control_requests() {
        let relationship = CurrentConversationRelationshipWitness::CurrentActiveParticipant {
            participant_period_id: Uuid::new_v4(),
        };

        assert!(includes_pending_requests(&relationship));
    }

    #[tokio::test]
    async fn pending_request_queries_accept_empty_catalog() {
        let (pool, _db) = fresh_db::fresh_full_catalog_pool("actor_convo_", 1).await;
        let mut transaction = pool.begin().await.expect("begin transaction");

        let (leaves, resets) = load_pending_requests(&mut transaction, Uuid::new_v4())
            .await
            .expect("load pending requests");

        assert!(leaves.is_empty());
        assert!(resets.is_empty());
    }

    #[test]
    fn conversation_state_response_uses_lexicon_bytes_objects() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/chat_protocol_g7_canonical_json_v1.json"
        ))
        .expect("parse fixture");
        let state: catbird_server::blue_catbird::chat::ConversationState =
            catbird_server::chat_protocol::retained_json::decode_definition(
                "conversationState",
                fixture["vectors"][0]["value"].clone(),
            )
            .expect("decode fixture state");
        let conversation_id = Uuid::new_v4();
        let pending_leave_requests = (0..2)
            .map(|_| {
                leave_view(
                    PendingLeaveRow {
                        leave_request_id: Uuid::new_v4(),
                        requester_did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
                        requester_device_id: Uuid::new_v4(),
                        prior_generation: 0,
                        prior_state_version: 1,
                        prior_group_id: vec![1; 32],
                        prior_epoch: 0,
                        prior_group_context_hash: vec![2; 32],
                        prior_confirmation_tag: vec![3; 32],
                        received_at: Utc::now(),
                        expires_at: Utc::now(),
                    },
                    conversation_id,
                )
                .expect("build leave view")
            })
            .collect::<Vec<_>>();
        let pending_reset_requests = (0..2)
            .map(|_| {
                reset_view(
                    PendingResetRow {
                        reset_request_id: Uuid::new_v4(),
                        requester_did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
                        requester_device_id: Uuid::new_v4(),
                        prior_generation: 0,
                        prior_state_version: 1,
                        prior_group_id: vec![1; 32],
                        prior_epoch: 0,
                        prior_group_context_hash: vec![2; 32],
                        prior_confirmation_tag: vec![3; 32],
                        reason: "manualRecovery".to_owned(),
                        received_at: Utc::now(),
                        expires_at: Utc::now(),
                    },
                    conversation_id,
                )
                .expect("build reset view")
            })
            .collect::<Vec<_>>();
        let response: serde_json::Value = serde_json::from_slice(
            &canonical_conversation_state_response(
                &[],
                &state,
                &[],
                &pending_leave_requests,
                &pending_reset_requests,
            )
            .expect("encode canonical response"),
        )
        .expect("decode response");

        assert_eq!(
            response["pendingLeafRecoveryRequests"],
            serde_json::json!([])
        );

        for path in [
            "/state/metadataSnapshot/coordinate/conversationId/$bytes",
            "/pendingLeaveRequests/0/prior/groupId/$bytes",
            "/pendingResetRequests/0/prior/confirmationTag/$bytes",
        ] {
            assert!(
                response
                    .pointer(path)
                    .and_then(serde_json::Value::as_str)
                    .is_some(),
                "{path} must use the ATProto $bytes wire object"
            );
        }
        assert_eq!(
            response["pendingLeaveRequests"]
                .as_array()
                .expect("leave request array")
                .len(),
            2
        );
        assert_eq!(
            response["pendingResetRequests"]
                .as_array()
                .expect("reset request array")
                .len(),
            2
        );
    }

    #[test]
    fn conversation_state_response_carries_participant_labyrinth_head() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/chat_protocol_g7_canonical_json_v1.json"
        ))
        .expect("parse fixture");
        let mut state: catbird_server::blue_catbird::chat::ConversationState =
            catbird_server::chat_protocol::retained_json::decode_definition(
                "conversationState",
                fixture["vectors"][0]["value"].clone(),
            )
            .expect("decode fixture state");
        let without: serde_json::Value = serde_json::from_slice(
            &canonical_conversation_state_response(&[], &state, &[], &[], &[])
                .expect("encode without head"),
        )
        .expect("decode");
        assert!(without
            .pointer("/state/participants/0/labyrinthHead")
            .is_none());
        state.participants[0].labyrinth_head =
            Some(catbird_server::blue_catbird::chat::LabyrinthHead {
                attestation_key_id: String::from("key-id"),
                epoch_head: petrel_core::Bytes(<[u8]>::to_vec(&[7; 32])),
                epoch_number: 3,
                extra_data: None,
            });
        let with: serde_json::Value = serde_json::from_slice(
            &canonical_conversation_state_response(&[], &state, &[], &[], &[])
                .expect("encode with head"),
        )
        .expect("decode");
        let head = with
            .pointer("/state/participants/0/labyrinthHead")
            .expect("labyrinthHead projected");
        assert_eq!(head["epochNumber"], 3);
        assert_eq!(head["attestationKeyId"], "key-id");
        assert!(head
            .pointer("/epochHead/$bytes")
            .and_then(serde_json::Value::as_str)
            .is_some());
    }
}
