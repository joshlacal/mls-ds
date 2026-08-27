// Repository-owned `getConversationState` read.
//
// The handler supplies only a sealed read admission and the public
// conversation UUID.  This facade spends the one ordinary-read attempt,
// locks and authorizes the exact requester device, and keeps that transaction
// open while projecting the state and pending control-plane requests.

use chrono::{DateTime, SecondsFormat, Utc};
use jacquard_common::{deps::smol_str::SmolStr, types::string::Did};
use sqlx::{FromRow, Postgres, Transaction};
use thiserror::Error;
use uuid::Uuid;

use super::super::{
    dpop::VerifiedReadAdmission,
    read_authority::{
        authorize_conversation_state, into_single_read_admission, lock_read_device_authority_once,
        OrdinaryReadEndpoint, ReadAuthorityError,
    },
    read_projection::{
        conversation_coordinates_dto, conversation_state_view, CheckedConversationCoordinates,
    },
};

#[derive(Debug, Error)]
pub(crate) enum ConversationStateReadError {
    #[error("conversation not found")]
    ConversationNotFound,
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

    let result =
        read_conversation_state_in_transaction(&mut transaction, attempt, conversation_id).await;
    let _ = transaction.rollback().await;
    result
}

async fn read_conversation_state_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    attempt: super::super::dpop::ReadAdmissionAttempt,
    conversation_id: Uuid,
) -> Result<CanonicalConversationStateResponse, ConversationStateReadError> {
    let device = lock_read_device_authority_once(transaction, attempt)
        .await
        .map_err(map_authority_error)?;
    // This call holds the locked conversation head and the exact requester
    // proof through all source and pending-request reads below.
    authorize_conversation_state(transaction, device, conversation_id)
        .await
        .map_err(map_authority_error)?;

    let source = super::inventory::load_conversation_state_source(transaction, conversation_id)
        .await
        .map_err(map_inventory_error)?;
    let state =
        conversation_state_view(&source).map_err(|_| ConversationStateReadError::Invariant)?;
    let (pending_leave_requests, pending_reset_requests) =
        load_pending_requests(transaction, conversation_id).await?;

    let output = catbird_atproto::generated::blue_catbird::chat::get_conversation_state::
        GetConversationStateOutput {
            pending_leave_requests,
            pending_reset_requests,
            state,
            extra_data: None,
        };
    Ok(CanonicalConversationStateResponse {
        bytes: serde_json::to_vec(&output).map_err(|_| ConversationStateReadError::Invariant)?,
    })
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
        Vec<catbird_atproto::generated::blue_catbird::chat::LeaveRequestView>,
        Vec<catbird_atproto::generated::blue_catbird::chat::ResetRequestView>,
    ),
    ConversationStateReadError,
> {
    let resets: Vec<PendingResetRow> = sqlx::query_as(
        "SELECT reset_request_id, requester_did, requester_device_id, prior_generation,\
                prior_state_version, prior_group_id, prior_epoch, prior_group_context_hash,\
                prior_confirmation_tag, reason, received_at, expires_at\
           FROM chat.reset_requests\
          WHERE conversation_id = $1 AND status = 'pending'\
          ORDER BY reset_request_id",
    )
    .bind(conversation_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| ConversationStateReadError::Storage)?;

    let leaves: Vec<PendingLeaveRow> = sqlx::query_as(
        "SELECT leave_request_id, requester_did, requester_device_id, prior_generation,\
                prior_state_version, prior_group_id, prior_epoch, prior_group_context_hash,\
                prior_confirmation_tag, received_at, expires_at\
           FROM chat.leave_requests\
          WHERE conversation_id = $1 AND status = 'pending'\
          ORDER BY leave_request_id",
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
) -> Result<
    catbird_atproto::generated::blue_catbird::chat::ConversationCoordinates,
    ConversationStateReadError,
> {
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
) -> catbird_atproto::generated::blue_catbird::chat::CanonicalDatetime {
    catbird_atproto::generated::blue_catbird::chat::CanonicalDatetime::raw_str(
        value.to_rfc3339_opts(SecondsFormat::Millis, true),
    )
}

fn requester_did(value: &str) -> Result<Did<SmolStr>, ConversationStateReadError> {
    Did::new(SmolStr::from(value)).map_err(|_| ConversationStateReadError::Invariant)
}

fn reset_view(
    row: PendingResetRow,
    conversation_id: Uuid,
) -> Result<
    catbird_atproto::generated::blue_catbird::chat::ResetRequestView,
    ConversationStateReadError,
> {
    Ok(
        catbird_atproto::generated::blue_catbird::chat::ResetRequestView {
            conversation_id: SmolStr::from(conversation_id.to_string()),
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
            reason: SmolStr::from(row.reason),
            requested_at: canonical_datetime(row.received_at),
            requester_device_id: SmolStr::from(row.requester_device_id.to_string()),
            requester_did: requester_did(&row.requester_did)?,
            reset_request_id: SmolStr::from(row.reset_request_id.to_string()),
            status: SmolStr::from("pending"),
            extra_data: None,
        },
    )
}

fn leave_view(
    row: PendingLeaveRow,
    conversation_id: Uuid,
) -> Result<
    catbird_atproto::generated::blue_catbird::chat::LeaveRequestView,
    ConversationStateReadError,
> {
    Ok(
        catbird_atproto::generated::blue_catbird::chat::LeaveRequestView {
            conversation_id: SmolStr::from(conversation_id.to_string()),
            expires_at: canonical_datetime(row.expires_at),
            leave_request_id: SmolStr::from(row.leave_request_id.to_string()),
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
            requester_device_id: SmolStr::from(row.requester_device_id.to_string()),
            requester_did: requester_did(&row.requester_did)?,
            status: SmolStr::from("pending"),
            extra_data: None,
        },
    )
}
