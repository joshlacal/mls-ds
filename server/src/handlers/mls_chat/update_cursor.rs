use axum::{extract::State, http::StatusCode, Json};
use std::sync::Arc;
use tracing::{error, info};

use jacquard_axum::ExtractXrpc;

use crate::{
    auth::AuthUser,
    generated::blue_catbird::mlsChat::update_cursor::{UpdateCursorOutput, UpdateCursorRequest},
    realtime::{SseState, StreamEvent},
    sqlx_jacquard::chrono_to_datetime,
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.updateCursor";

/// Consolidated cursor and read-state endpoint.
///
/// POST /xrpc/blue.catbird.mlsChat.updateCursor
///
/// - If `cursor` is provided → updates cursor
/// - If `messageId` is provided or `markRead` is true → updates read receipt
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

    let convo_id = input.convo_id.to_string();
    let caller_did = &auth_user.did;

    // Check membership
    let is_member: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM members
            WHERE convo_id = $1 AND (user_did = $2 OR member_did = $2) AND left_at IS NULL
        )
        "#,
    )
    .bind(&convo_id)
    .bind(caller_did)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("Failed to check membership: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if !is_member {
        return Err(StatusCode::FORBIDDEN);
    }

    let mut read_at: Option<jacquard_common::types::string::Datetime> = None;

    // 1. Update cursor if provided
    if let Some(ref cursor) = input.cursor {
        let cursor_str = cursor.to_string();

        // Validate cursor format
        crate::realtime::cursor::CursorGenerator::validate(&cursor_str)
            .map_err(|_| StatusCode::BAD_REQUEST)?;

        info!(
            user = %crate::crypto::redact_for_log(caller_did),
            convo = %crate::crypto::redact_for_log(&convo_id),
            "Updating cursor"
        );

        sqlx::query(
            r#"
            INSERT INTO cursors (user_did, convo_id, last_seen_cursor, updated_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (user_did, convo_id)
            DO UPDATE SET last_seen_cursor = $3, updated_at = NOW()
            "#,
        )
        .bind(caller_did)
        .bind(&convo_id)
        .bind(&cursor_str)
        .execute(&pool)
        .await
        .map_err(|e| {
            error!("Failed to update cursor: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    }

    // 2. Update read state if requested
    let mark_read = input.mark_read.unwrap_or(false);
    if mark_read || input.message_id.is_some() {
        let message_id = if mark_read && input.message_id.is_none() {
            None
        } else {
            input.message_id.as_ref().map(|m| m.to_string())
        };

        // If messageId is provided, validate it exists
        if let Some(ref msg_id) = message_id {
            let message_exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM messages WHERE id = $1 AND convo_id = $2)",
            )
            .bind(msg_id)
            .bind(&convo_id)
            .fetch_one(&pool)
            .await
            .map_err(|e| {
                error!("Failed to check message existence: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            if !message_exists {
                return Err(StatusCode::NOT_FOUND);
            }
        }

        // Insert or update read receipt
        let dt = sqlx::query_scalar::<_, chrono::DateTime<chrono::Utc>>(
            r#"
            INSERT INTO read_receipts (convo_id, member_did, message_id, read_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (convo_id, member_did, message_id)
            DO UPDATE SET read_at = NOW()
            RETURNING read_at
            "#,
        )
        .bind(&convo_id)
        .bind(caller_did)
        .bind(&message_id)
        .fetch_one(&pool)
        .await
        .map_err(|e| {
            error!("Failed to insert/update read receipt: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        // If marking all as read (no messageId), reset unread count
        if message_id.is_none() {
            sqlx::query(
                "UPDATE members SET unread_count = 0, last_read_at = NOW() WHERE convo_id = $1 AND (user_did = $2 OR member_did = $2) AND left_at IS NULL",
            )
            .bind(&convo_id)
            .bind(caller_did)
            .execute(&pool)
            .await
            .map_err(|e| {
                error!("Failed to reset unread count: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
        }

        // Emit SSE read event
        let cursor = sse_state
            .cursor_gen
            .next(&convo_id, "readEvent")
            .await;
        let event = StreamEvent::ReadEvent {
            cursor,
            convo_id: convo_id.clone(),
            did: caller_did.clone(),
            message_id: message_id.clone(),
            read_at: dt.to_rfc3339(),
        };

        if let Err(e) = sse_state.emit(&convo_id, event).await {
            error!("Failed to emit read event via SSE: {}", e);
        }

        read_at = Some(chrono_to_datetime(dt));
    }

    Ok(Json(UpdateCursorOutput {
        updated_at: chrono_to_datetime(chrono::Utc::now()),
        read_at,
        extra_data: Default::default(),
    }))
}
