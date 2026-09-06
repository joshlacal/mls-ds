// Repository-owned `getConversationState` read.
//
// The handler supplies only a sealed read admission and the public
// conversation UUID.  This facade spends the one ordinary-read attempt,
// locks and authorizes the exact requester device, and keeps that transaction
// open while projecting the state and pending control-plane requests.

mod recovery;

use chrono::{DateTime, SecondsFormat, Utc};
use jacquard_common::{deps::smol_str::SmolStr, types::string::Did};
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
        encode_canonical_generated_chat_json_v1, CheckedConversationCoordinates,
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
    let output = result?;
    Ok(CanonicalConversationStateResponse {
        bytes: canonical_conversation_state_response(
            &output.state,
            output
                .pending_leaf_recovery_requests
                .as_deref()
                .unwrap_or_default(),
            &output.pending_leave_requests,
            &output.pending_reset_requests,
        )?,
    })
}

async fn read_conversation_state_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    attempt: super::super::dpop::ReadAdmissionAttempt,
    conversation_id: Uuid,
) -> Result<
    catbird_atproto::generated::blue_catbird::chat::get_conversation_state::
        GetConversationStateOutput,
    ConversationStateReadError,
>{
    let device = lock_read_device_authority_once(transaction, attempt)
        .await
        .map_err(map_authority_error)?;
    // Keep the checked relationship witness through projection: a pending
    // invitee receives the conversation state it must sign acceptance over,
    // but never the established members' pending control-plane requests.
    let authority = authorize_conversation_state(transaction, device, conversation_id)
        .await
        .map_err(map_authority_error)?;

    let source = super::inventory::load_conversation_state_source(transaction, conversation_id)
        .await
        .map_err(map_inventory_error)?;
    let state =
        conversation_state_view(&source).map_err(|_| ConversationStateReadError::Invariant)?;
    let (pending_leave_requests, pending_reset_requests) =
        if includes_pending_requests(authority.relationship()) {
            load_pending_requests(transaction, conversation_id).await?
        } else {
            (Vec::new(), Vec::new())
        };

    let pending_leaf_recovery_requests =
        recovery::load_pending_leaf_recoveries(transaction, &authority).await?;

    Ok(
        catbird_atproto::generated::blue_catbird::chat::get_conversation_state::
            GetConversationStateOutput {
                pending_leave_requests,
                pending_leaf_recovery_requests: Some(pending_leaf_recovery_requests),
                pending_reset_requests,
                state,
                extra_data: None,
            },
    )
}

fn append_canonical_array<T: serde::Serialize>(
    bytes: &mut Vec<u8>,
    values: &[T],
    definition_id: &'static str,
) -> Result<(), ConversationStateReadError> {
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            bytes.push(b',');
        }
        let canonical = encode_canonical_generated_chat_json_v1(value, definition_id)
            .map_err(|_| ConversationStateReadError::Invariant)?;
        bytes.extend_from_slice(canonical.bytes());
    }
    Ok(())
}

fn canonical_conversation_state_response(
    state: &catbird_atproto::generated::blue_catbird::chat::ConversationState,
    pending_leaf_recovery_requests: &[catbird_atproto::generated::blue_catbird::chat::LeafRecoveryView],
    pending_leave_requests: &[catbird_atproto::generated::blue_catbird::chat::LeaveRequestView],
    pending_reset_requests: &[catbird_atproto::generated::blue_catbird::chat::ResetRequestView],
) -> Result<Vec<u8>, ConversationStateReadError> {
    let canonical_state =
        encode_canonical_generated_chat_json_v1(state, "blue.catbird.chat.defs#conversationState")
            .map_err(|_| ConversationStateReadError::Invariant)?;
    let mut bytes = Vec::with_capacity(canonical_state.bytes().len() + 64);
    bytes.extend_from_slice(br#"{"pendingLeafRecoveryRequests":["#);
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
            status: catbird_atproto::generated::blue_catbird::chat::ResetRequestViewStatus::Pending,
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
        let state: catbird_atproto::generated::blue_catbird::chat::ConversationState<
            jacquard_common::DefaultStr,
        > = serde_json::from_value(fixture["vectors"][0]["value"].clone())
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
}
