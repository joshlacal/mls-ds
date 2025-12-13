use axum::{extract::State, http::StatusCode, Json};
use chrono::Utc;
use std::sync::Arc;
use tracing::{error, info};

use crate::{
    auth::AuthUser,
    generated::blue::catbird::mls::add_reaction::{Input, Output, OutputData, NSID},
    realtime::{SseState, StreamEvent},
    db,
    storage::DbPool,
    sqlx_atrium::chrono_to_datetime,
};

/// Add a reaction to a message
/// POST /xrpc/blue.catbird.mls.addReaction
#[tracing::instrument(skip(pool, sse_state, auth_user))]
pub async fn add_reaction(
    State(pool): State<DbPool>,
    State(sse_state): State<Arc<SseState>>,
    auth_user: AuthUser,
    Json(input): Json<Input>,
) -> Result<Json<Output>, StatusCode> {
    let user_did = auth_user.did.clone();
    
    info!(
        "add_reaction: user={}, convo={}, message={}, reaction={}",
        crate::crypto::redact_for_log(&user_did),
        crate::crypto::redact_for_log(&input.convo_id),
        crate::crypto::redact_for_log(&input.message_id),
        &input.reaction
    );

    // Enforce authorization
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        error!("❌ [add_reaction] Unauthorized - failed auth check");
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Check membership
    let is_member = db::is_member(&pool, &user_did, &input.convo_id)
        .await
        .map_err(|e| {
            error!("Failed to check membership: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if !is_member {
        error!("User is not a member of the conversation");
        return Err(StatusCode::FORBIDDEN);
    }

    // Check message exists
    let message_exists = db::message_exists(&pool, &input.convo_id, &input.message_id)
        .await
        .map_err(|e| {
            error!("Failed to check message existence: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if !message_exists {
        error!("Message not found");
        return Err(StatusCode::NOT_FOUND);
    }

    // Validate reaction (max 16 chars, must be non-empty)
    if input.reaction.is_empty() || input.reaction.len() > 16 {
        error!("Invalid reaction length");
        return Err(StatusCode::BAD_REQUEST);
    }

    let now = Utc::now();

    // Insert reaction into database
    let inserted = db::add_reaction(
        &pool,
        &input.convo_id,
        &input.message_id,
        &user_did,
        &input.reaction,
        now,
    )
    .await
    .map_err(|e| {
        // Check if it's a duplicate
        if e.to_string().contains("UNIQUE constraint") || e.to_string().contains("duplicate") {
            error!("Reaction already exists");
            return StatusCode::CONFLICT;
        }
        error!("Failed to add reaction: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if !inserted {
        // Already reacted
        return Err(StatusCode::CONFLICT);
    }

    // Emit SSE event to all conversation members
    let cursor = sse_state.cursor_gen.next(&input.convo_id, "reactionEvent").await;
    let event = StreamEvent::ReactionEvent {
        cursor: cursor.clone(),
        convo_id: input.convo_id.clone(),
        message_id: input.message_id.clone(),
        did: user_did.clone(),
        reaction: input.reaction.clone(),
        action: "add".to_string(),
    };

    // Store event for cursor-based replay
    if let Err(e) = crate::db::store_event(
        &pool,
        &cursor,
        &input.convo_id,
        "reactionEvent",
        Some(&input.message_id),
    )
    .await
    {
        error!("Failed to store reaction event: {:?}", e);
    }

    if let Err(e) = sse_state.emit(&input.convo_id, event).await {
        error!("Failed to emit reaction event: {}", e);
        // Don't fail the request, reaction was still saved
    }

    info!("Reaction added successfully");

    Ok(Json(Output::from(OutputData {
        success: true,
        reacted_at: Some(chrono_to_datetime(now)),
    })))
}
