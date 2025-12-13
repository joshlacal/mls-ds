use axum::{extract::State, http::StatusCode, Json};
use std::sync::Arc;
use tracing::{error, info};

use crate::{
    auth::AuthUser,
    db,
    generated::blue::catbird::mls::remove_reaction::{Input, Output, OutputData, NSID},
    realtime::{SseState, StreamEvent},
    storage::DbPool,
};

/// Remove a reaction from a message
/// POST /xrpc/blue.catbird.mls.removeReaction
#[tracing::instrument(skip(pool, sse_state, auth_user))]
pub async fn remove_reaction(
    State(pool): State<DbPool>,
    State(sse_state): State<Arc<SseState>>,
    auth_user: AuthUser,
    Json(input): Json<Input>,
) -> Result<Json<Output>, StatusCode> {
    let user_did = auth_user.did.clone();

    info!(
        "remove_reaction: user={}, convo={}, message={}, reaction={}",
        crate::crypto::redact_for_log(&user_did),
        crate::crypto::redact_for_log(&input.convo_id),
        crate::crypto::redact_for_log(&input.message_id),
        &input.reaction
    );

    // Enforce authorization
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        error!("❌ [remove_reaction] Unauthorized - failed auth check");
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

    // Delete reaction from database
    let deleted = db::remove_reaction(
        &pool,
        &input.convo_id,
        &input.message_id,
        &user_did,
        &input.reaction,
    )
    .await
    .map_err(|e| {
        error!("Failed to remove reaction: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if !deleted {
        // Reaction didn't exist
        error!("Reaction not found");
        return Err(StatusCode::NOT_FOUND);
    }

    // Emit SSE event to all conversation members
    let cursor = sse_state
        .cursor_gen
        .next(&input.convo_id, "reactionEvent")
        .await;
    let event = StreamEvent::ReactionEvent {
        cursor: cursor.clone(),
        convo_id: input.convo_id.clone(),
        message_id: input.message_id.clone(),
        did: user_did.clone(),
        reaction: input.reaction.clone(),
        action: "remove".to_string(),
    };

    if let Err(e) = sse_state.emit(&input.convo_id, event).await {
        error!("Failed to emit reaction event: {}", e);
        // Don't fail the request, reaction was still removed
    }

    info!("Reaction removed successfully");

    Ok(Json(Output::from(OutputData { success: true })))
}
