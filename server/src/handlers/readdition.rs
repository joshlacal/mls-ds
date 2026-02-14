use axum::{extract::State, http::StatusCode, Json};
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::{
    auth::AuthUser,
    device_utils::parse_device_did,
    generated::blue_catbird::mls::readdition::{Readdition, ReadditionOutput},
    realtime::{SseState, StreamEvent},
    storage::DbPool,
};

/// Request re-addition to a conversation when both Welcome and External Commit have failed.
/// POST /xrpc/blue.catbird.mls.readdition
///
/// Used when a member cannot rejoin a conversation through normal means.
/// This emits a ReadditionRequested SSE event to active members who can then
/// re-add the user with fresh KeyPackages.
pub async fn readdition(
    State(pool): State<DbPool>,
    State(sse_state): State<Arc<SseState>>,
    auth_user: AuthUser,
    body: String,
) -> Result<Json<ReadditionOutput<'static>>, StatusCode> {
    let input = crate::jacquard_json::from_json_body::<Readdition>(&body)?;
    // Enforce authentication
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, "blue.catbird.mls.readdition")
    {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let device_did = &auth_user.did;
    let convo_id = &input.convo_id;

    // Extract user DID from device DID
    let (user_did, _device_id) = parse_device_did(device_did).map_err(|e| {
        error!("Invalid device DID format: {}", e);
        StatusCode::BAD_REQUEST
    })?;

    info!(
        convo = %crate::crypto::redact_for_log(convo_id),
        user = %crate::crypto::redact_for_log(&user_did),
        "Processing re-addition request"
    );

    // 1. Check if conversation exists
    let convo_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM conversations WHERE id = $1)")
            .bind(convo_id.as_str())
            .fetch_one(&pool)
            .await
            .map_err(|e| {
                error!("Failed to check conversation existence: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

    if !convo_exists {
        warn!(
            convo = %crate::crypto::redact_for_log(convo_id),
            "Conversation not found"
        );
        return Err(StatusCode::NOT_FOUND);
    }

    // 2. Check if requester is/was a member (allows members who need rejoin or were soft-deleted)
    let is_member: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM members WHERE convo_id = $1 AND user_did = $2)",
    )
    .bind(convo_id.as_str())
    .bind(&user_did)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("Failed to check membership: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if !is_member {
        warn!(
            convo = %crate::crypto::redact_for_log(convo_id),
            user = %crate::crypto::redact_for_log(&user_did),
            "User is not a member"
        );
        return Err(StatusCode::FORBIDDEN);
    }

    // 3. Mark member as needs_rejoin and record the request
    sqlx::query(
        r#"
        UPDATE members
        SET needs_rejoin = true,
            rejoin_requested_at = NOW(),
            rejoin_attempts = COALESCE(rejoin_attempts, 0) + 1
        WHERE convo_id = $1 AND user_did = $2
        "#,
    )
    .bind(convo_id.as_str())
    .bind(&user_did)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("Failed to update member rejoin status: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // 4. Count active members (not left, not needing rejoin, not the requester)
    let active_members: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(DISTINCT user_did)
        FROM members
        WHERE convo_id = $1
          AND left_at IS NULL
          AND needs_rejoin = false
          AND user_did != $2
        "#,
    )
    .bind(convo_id.as_str())
    .bind(&user_did)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("Failed to count active members: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if active_members == 0 {
        warn!(
            convo = %crate::crypto::redact_for_log(convo_id),
            "No active members to process re-addition"
        );
        // Still return success - no one to notify but request was valid
        return Ok(Json(ReadditionOutput {
            requested: false,
            active_members: Some(0),
            extra_data: None,
        }));
    }

    // 5. Emit ReadditionRequested SSE event
    let cursor = sse_state
        .cursor_gen
        .next(convo_id, "readditionRequested")
        .await;
    let event = StreamEvent::ReadditionRequested {
        cursor,
        convo_id: convo_id.to_string(),
        user_did: user_did.clone(),
        requested_at: chrono::Utc::now().to_rfc3339(),
    };

    if let Err(e) = sse_state.emit(convo_id.as_str(), event).await {
        warn!(
            convo = %crate::crypto::redact_for_log(convo_id),
            error = %e,
            "Failed to emit ReadditionRequested event"
        );
        // Don't fail the request - emission failure is non-critical
    } else {
        info!(
            convo = %crate::crypto::redact_for_log(convo_id),
            active_members = active_members,
            "Emitted ReadditionRequested event"
        );
    }

    Ok(Json(ReadditionOutput {
        requested: true,
        active_members: Some(active_members as i64),
        extra_data: None,
    }))
}
