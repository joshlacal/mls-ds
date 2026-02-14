use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use tracing::error;

use crate::{
    auth::AuthUser, federation::FederationConfig, identity::canonical_did, storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.getDeliveryStatus";

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetDeliveryStatusParams {
    pub convo_id: String,
    /// Comma-separated message IDs (up to 50).
    pub message_ids: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliveryStatusOutput {
    pub statuses: Vec<MessageDeliveryStatus>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageDeliveryStatus {
    pub message_id: String,
    pub status: String,
    pub acked_by: Vec<String>,
    pub total_remote_ds: i32,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// GET /xrpc/blue.catbird.mlsChat.getDeliveryStatus
///
/// Query delivery acknowledgment status for one or more messages in a
/// conversation. Returns per-message status indicating how many remote
/// delivery services have acknowledged receipt.
#[tracing::instrument(skip(pool, fed_config, auth_user))]
pub async fn get_delivery_status(
    State(pool): State<DbPool>,
    State(fed_config): State<FederationConfig>,
    auth_user: AuthUser,
    axum::extract::Query(params): axum::extract::Query<GetDeliveryStatusParams>,
) -> Result<Json<DeliveryStatusOutput>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        error!("❌ [getDeliveryStatus] Unauthorized");
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Verify caller is a member of the conversation
    crate::auth::verify_is_member(&pool, &params.convo_id, &auth_user.did).await?;

    // Parse comma-separated message IDs (cap at 50)
    let message_ids: Vec<&str> = params
        .message_ids
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .take(50)
        .collect();

    if message_ids.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Count distinct remote DSes in this conversation
    let self_did = &fed_config.self_did;
    let all_ds_dids: Vec<Option<String>> = sqlx::query_scalar(
        "SELECT DISTINCT COALESCE(split_part(ds_did, '#', 1), $2) \
         FROM members WHERE convo_id = $1 AND left_at IS NULL",
    )
    .bind(&params.convo_id)
    .bind(self_did)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!("Failed to query DS DIDs: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let total_remote_ds = all_ds_dids
        .iter()
        .flatten()
        .filter(|did| canonical_did(did) != canonical_did(self_did))
        .count() as i32;

    // Batch-fetch all ACKs in a single query
    let all_acks = crate::db::get_delivery_acks_for_messages(&pool, &params.convo_id, &message_ids)
        .await
        .map_err(|e| {
            error!("Failed to batch-fetch delivery acks: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Group by message_id
    let mut acks_by_message: std::collections::HashMap<&str, Vec<&str>> =
        std::collections::HashMap::new();
    for ack in &all_acks {
        acks_by_message
            .entry(&ack.message_id)
            .or_default()
            .push(&ack.receiver_ds_did);
    }

    // Build status for each requested message
    let mut statuses = Vec::with_capacity(message_ids.len());
    for msg_id in &message_ids {
        let acked_by: Vec<String> = acks_by_message
            .get(msg_id)
            .map(|ds_dids| ds_dids.iter().map(|s| s.to_string()).collect())
            .unwrap_or_default();

        let ack_count = acked_by.len() as i32;
        let status = if total_remote_ds == 0 {
            "local_only"
        } else if ack_count >= total_remote_ds {
            "delivered_to_all"
        } else if ack_count > 0 {
            "partial"
        } else {
            "pending"
        };

        statuses.push(MessageDeliveryStatus {
            message_id: msg_id.to_string(),
            status: status.to_string(),
            acked_by,
            total_remote_ds,
        });
    }

    Ok(Json(DeliveryStatusOutput { statuses }))
}
