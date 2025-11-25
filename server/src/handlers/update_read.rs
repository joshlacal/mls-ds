use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use tracing::{error, info};

use crate::{auth::AuthUser, storage::DbPool};

#[derive(Debug, Deserialize)]
pub struct UpdateReadInput {
    #[serde(rename = "convoId")]
    pub convo_id: String,
    #[serde(rename = "messageId")]
    pub message_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UpdateReadOutput {
    #[serde(rename = "readAt")]
    pub read_at: String,
}

/// Mark messages as read in an MLS conversation
/// POST /xrpc/blue.catbird.mls.updateRead
#[tracing::instrument(skip(pool, auth_user))]
pub async fn update_read(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Json(input): Json<UpdateReadInput>,
) -> Result<Json<UpdateReadOutput>, StatusCode> {
    info!(
        user = %crate::crypto::redact_for_log(&auth_user.did),
        convo = %crate::crypto::redact_for_log(&input.convo_id),
        has_message_id = input.message_id.is_some(),
        "Marking messages as read"
    );

    // Enforce authorization
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, "blue.catbird.mls.updateRead") {
        error!("❌ [update_read] Unauthorized - failed auth check");
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Check if user is a member of the conversation
    let is_member = crate::storage::is_member(&pool, &auth_user.did, &input.convo_id)
        .await
        .map_err(|e| {
            error!("❌ [update_read] Failed to check membership: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if !is_member {
        error!(
            "❌ [update_read] User {} is not a member of conversation {}",
            auth_user.did, input.convo_id
        );
        return Err(StatusCode::FORBIDDEN);
    }

    // If messageId is provided, validate it exists in this conversation
    if let Some(ref msg_id) = input.message_id {
        let message_exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM messages WHERE id = $1 AND convo_id = $2)"
        )
        .bind(msg_id)
        .bind(&input.convo_id)
        .fetch_one(&pool)
        .await
        .map_err(|e| {
            error!("❌ [update_read] Failed to check message existence: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        if !message_exists {
            error!("❌ [update_read] Message {} not found in conversation {}", msg_id, input.convo_id);
            return Err(StatusCode::NOT_FOUND);
        }
    }

    // Insert or update read receipt
    // Use ON CONFLICT to handle duplicate updates gracefully
    let read_at = sqlx::query_scalar::<_, chrono::DateTime<chrono::Utc>>(
        r#"
        INSERT INTO read_receipts (convo_id, member_did, message_id, read_at)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (convo_id, member_did, message_id)
        DO UPDATE SET read_at = NOW()
        RETURNING read_at
        "#
    )
    .bind(&input.convo_id)
    .bind(&auth_user.did)
    .bind(&input.message_id)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("❌ [update_read] Failed to insert/update read receipt: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // If marking all messages as read (messageId is None), reset unread count
    if input.message_id.is_none() {
        sqlx::query(
            "UPDATE members SET unread_count = 0, last_read_at = NOW() WHERE convo_id = $1 AND member_did = $2"
        )
        .bind(&input.convo_id)
        .bind(&auth_user.did)
        .execute(&pool)
        .await
        .map_err(|e| {
            error!("❌ [update_read] Failed to reset unread count: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    }

    info!(
        "✅ [update_read] Messages marked as read for user {} in conversation {}",
        auth_user.did, input.convo_id
    );

    Ok(Json(UpdateReadOutput {
        read_at: crate::sqlx_atrium::chrono_to_datetime(read_at),
    }))
}
