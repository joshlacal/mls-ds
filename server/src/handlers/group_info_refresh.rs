use axum::{extract::State, http::StatusCode, Json};
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::{
    auth::AuthUser,
    device_utils::parse_device_did,
    generated::blue::catbird::mls::group_info_refresh::{Input, Output, OutputData},
    realtime::{SseState, StreamEvent},
    storage::DbPool,
};

/// Request active members to publish fresh GroupInfo for a conversation.
/// POST /xrpc/blue.catbird.mls.groupInfoRefresh
///
/// Used when a member encounters stale GroupInfo during external commit rejoin.
/// Emits a GroupInfoRefreshRequested SSE event to all active members so one of
/// them can publish fresh GroupInfo.
pub async fn group_info_refresh(
    State(pool): State<DbPool>,
    State(sse_state): State<Arc<SseState>>,
    auth_user: AuthUser,
    Json(input): Json<Input>,
) -> Result<Json<Output>, StatusCode> {
    // Enforce authentication
    if let Err(_e) = crate::auth::enforce_standard(
        &auth_user.claims,
        "blue.catbird.mls.groupInfoRefresh",
    ) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let device_did = &auth_user.did;
    let convo_id = &input.data.convo_id;

    // Extract user DID from device DID
    let (user_did, _device_id) = parse_device_did(device_did).map_err(|e| {
        error!("Invalid device DID format: {}", e);
        StatusCode::BAD_REQUEST
    })?;

    info!(
        convo = %crate::crypto::redact_for_log(convo_id),
        user = %crate::crypto::redact_for_log(&user_did),
        "Processing GroupInfo refresh request"
    );

    // 1. Check if conversation exists
    let convo_exists =
        sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM conversations WHERE id = $1)")
            .bind(convo_id)
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

    // 2. Check if requester is/was a member (allows members who need rejoin)
    let is_member = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM members WHERE convo_id = $1 AND user_did = $2)",
    )
    .bind(convo_id)
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

    // 3. Count active members (not left, not needing rejoin)
    let active_members = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(DISTINCT user_did)
        FROM members
        WHERE convo_id = $1
          AND left_at IS NULL
          AND needs_rejoin = false
        "#,
    )
    .bind(convo_id)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("Failed to count active members: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if active_members == 0 {
        warn!(
            convo = %crate::crypto::redact_for_log(convo_id),
            "No active members to notify"
        );
        // Still return success - no one to notify but request was valid
        return Ok(Json(Output::from(OutputData {
            requested: false,
            active_members: Some(0),
        })));
    }

    // 4. Emit GroupInfoRefreshRequested SSE event
    let cursor = sse_state
        .cursor_gen
        .next(convo_id, "groupInfoRefreshRequested")
        .await;
    let event = StreamEvent::GroupInfoRefreshRequested {
        cursor,
        convo_id: convo_id.clone(),
        requested_by: user_did.clone(),
        requested_at: chrono::Utc::now().to_rfc3339(),
    };

    if let Err(e) = sse_state.emit(convo_id, event).await {
        warn!(
            convo = %crate::crypto::redact_for_log(convo_id),
            error = %e,
            "Failed to emit GroupInfoRefreshRequested event"
        );
        // Don't fail the request - emission failure is non-critical
        // The SSE channel might just not have any subscribers yet
    } else {
        info!(
            convo = %crate::crypto::redact_for_log(convo_id),
            active_members = active_members,
            "Emitted GroupInfoRefreshRequested event"
        );
    }

    Ok(Json(Output::from(OutputData {
        requested: true,
        active_members: Some(active_members),
    })))
}
