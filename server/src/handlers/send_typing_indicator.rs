// DEPRECATED: Prefer E2EE ephemeral messages via v2.sendEphemeral.
// This handler creates plaintext typing events visible to the server.
// Kept for backward compatibility with clients that don't support E2EE signals.

use axum::{extract::State, http::StatusCode, Json};
use std::sync::Arc;
use tracing::{error, info};

use crate::{
    auth::AuthUser,
    db,
    realtime::{SseState, StreamEvent},
    storage::DbPool,
};

/// Local types for sendTypingIndicator (no generated lexicon module)
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendTypingIndicatorInput {
    convo_id: String,
    is_typing: bool,
}

#[derive(Debug, serde::Serialize)]
pub struct SendTypingIndicatorOutput {
    success: bool,
}

const NSID: &str = "blue.catbird.mls.sendTypingIndicator";

/// Send a typing indicator to a conversation
/// POST /xrpc/blue.catbird.mls.sendTypingIndicator
#[tracing::instrument(skip(pool, sse_state, auth_user))]
pub async fn send_typing_indicator(
    State(pool): State<DbPool>,
    State(sse_state): State<Arc<SseState>>,
    auth_user: AuthUser,
    Json(input): Json<SendTypingIndicatorInput>,
) -> Result<Json<SendTypingIndicatorOutput>, StatusCode> {
    let user_did = auth_user.did.clone();

    info!(
        "send_typing_indicator: user={}, convo={}, isTyping={}",
        crate::crypto::redact_for_log(&user_did),
        crate::crypto::redact_for_log(&input.convo_id),
        input.is_typing
    );

    // Enforce authorization
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        error!("❌ [send_typing_indicator] Unauthorized - failed auth check");
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

    // Emit SSE event to all conversation members
    // Note: Typing indicators are ephemeral - we don't persist them to the database
    let cursor = sse_state
        .cursor_gen
        .next(&input.convo_id, "typingEvent")
        .await;
    let event = StreamEvent::TypingEvent {
        cursor: cursor.clone(),
        convo_id: input.convo_id.clone(),
        did: user_did.clone(),
        is_typing: input.is_typing,
    };

    if let Err(e) = sse_state.emit(&input.convo_id, event).await {
        error!("Failed to emit typing event: {}", e);
        // Don't fail the request - typing indicators are best-effort
    }

    info!("Typing indicator sent successfully");

    Ok(Json(SendTypingIndicatorOutput { success: true }))
}
