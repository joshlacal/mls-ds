use axum::{extract::State, http::StatusCode, Json};
use std::sync::Arc;
use tracing::error;

use jacquard_axum::ExtractXrpc;

use crate::{
    auth::AuthUser,
    generated::blue_catbird::mlsChat::update_cursor::{UpdateCursorOutput, UpdateCursorRequest},
    handlers::update_cursor::UpdateCursorInput,
    handlers::update_read::UpdateReadInput,
    realtime::SseState,
    sqlx_jacquard::chrono_to_datetime,
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.updateCursor";

/// Consolidated cursor and read-state endpoint.
///
/// POST /xrpc/blue.catbird.mlsChat.updateCursor
///
/// Delegates to both `update_cursor` and `update_read` as needed:
/// - If `cursor` is provided → calls `update_cursor`
/// - If `messageId` is provided or `markRead` is true → calls `update_read`
/// - Both can fire in the same request.
#[tracing::instrument(skip(pool, sse_state, auth_user, input))]
pub async fn update_cursor(
    State(pool): State<DbPool>,
    State(sse_state): State<Arc<SseState>>,
    auth_user: AuthUser,
    ExtractXrpc(input): ExtractXrpc<UpdateCursorRequest>,
) -> Result<Json<UpdateCursorOutput<'static>>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        error!("❌ [v2.updateCursor] Unauthorized");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let mut read_at: Option<jacquard_common::types::string::Datetime> = None;

    // 1. Update SSE cursor if provided
    if let Some(ref cursor) = input.cursor {
        let cursor_input = UpdateCursorInput {
            convo_id: input.convo_id.to_string(),
            cursor: cursor.to_string(),
        };

        let cursor_result = crate::handlers::update_cursor(
            State(pool.clone()),
            auth_user.clone(),
            Json(cursor_input),
        )
        .await?;

        // Use the cursor update time
        let _ = cursor_result.0.success;
    }

    // 2. Update read state if requested
    let mark_read = input.mark_read.unwrap_or(false);
    if mark_read || input.message_id.is_some() {
        let read_input = UpdateReadInput {
            convo_id: input.convo_id.to_string(),
            // mark_read with no message_id marks all as read
            message_id: if mark_read && input.message_id.is_none() {
                None
            } else {
                input.message_id.as_ref().map(|m| m.to_string())
            },
        };

        let read_result = crate::handlers::update_read(
            State(pool),
            State(sse_state),
            auth_user,
            Json(read_input),
        )
        .await?;

        if let Ok(dt) = read_result
            .0
            .read_at
            .parse::<chrono::DateTime<chrono::Utc>>()
        {
            read_at = Some(chrono_to_datetime(dt));
        }
    }

    Ok(Json(UpdateCursorOutput {
        updated_at: chrono_to_datetime(chrono::Utc::now()),
        read_at,
        extra_data: Default::default(),
    }))
}
