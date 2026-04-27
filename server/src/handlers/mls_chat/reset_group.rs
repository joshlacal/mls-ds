use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::{
    auth::AuthUser,
    realtime::{sse::StreamEvent, SseState},
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.resetGroup";

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResetGroupRequest {
    pub convo_id: String,
    pub new_group_id: String,
    pub cipher_suite: String,
    pub group_info: Option<String>,
    pub reason: Option<String>,
    /// When true, clears the circuit breaker and resets the counter to 0,
    /// re-enabling automatic recovery for this conversation.
    #[serde(default)]
    pub clear_circuit_breaker: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResetGroupOutput {
    pub success: bool,
    pub new_group_id: String,
    pub reset_generation: i32,
    pub new_epoch: i64,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Reset an MLS group by replacing its group_id and clearing ephemeral state.
///
/// POST /xrpc/blue.catbird.mlsChat.resetGroup
///
/// Only admins may reset a group. This increments `reset_count`, swaps the
/// `group_id`, resets `current_epoch` to 0, and deletes welcome messages and
/// pending device additions for the conversation.
#[tracing::instrument(skip(pool, sse_state, auth_user, input))]
pub async fn reset_group(
    State(pool): State<DbPool>,
    State(sse_state): State<Arc<SseState>>,
    auth_user: AuthUser,
    Json(input): Json<ResetGroupRequest>,
) -> Result<Response, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        error!("[resetGroup] Unauthorized");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let caller_did = &auth_user.did;
    let convo_id = &input.convo_id;
    let new_group_id = &input.new_group_id;

    info!(
        convo = %crate::crypto::redact_for_log(convo_id),
        caller = %crate::crypto::redact_for_log(caller_did),
        "[resetGroup] start"
    );

    // --- Verify caller is admin ---
    let is_admin: bool = sqlx::query_scalar(
        "SELECT COALESCE(is_admin, false) FROM members WHERE convo_id = $1 AND (user_did = $2 OR member_did = $2) AND left_at IS NULL LIMIT 1",
    )
    .bind(convo_id)
    .bind(caller_did)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!("[resetGroup] admin check failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .unwrap_or(false);

    if !is_admin {
        warn!("[resetGroup] caller is not admin");
        return Err(StatusCode::FORBIDDEN);
    }

    // --- Validate newGroupId not already in use ---
    // Return the owning convoId alongside the error so clients can distinguish
    // "my own retry" from "genuinely conflicting group id".
    let conflicting_convo_id: Option<String> =
        sqlx::query_scalar("SELECT id FROM conversations WHERE group_id = $1 LIMIT 1")
            .bind(new_group_id)
            .fetch_optional(&pool)
            .await
            .map_err(|e| {
                error!("[resetGroup] group_id uniqueness check failed: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

    if let Some(existing_convo_id) = conflicting_convo_id {
        warn!("[resetGroup] newGroupId already in use");
        return Ok((
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "GroupIdAlreadyExists",
                "message": "The new group ID is already in use by another conversation",
                "conflictingGroupId": new_group_id,
                "conflictingConvoId": existing_convo_id
            })),
        )
            .into_response());
    }

    // --- Decode optional group_info ---
    let group_info_bytes: Option<Vec<u8>> = if let Some(ref gi_b64) = input.group_info {
        use base64::Engine;
        Some(
            base64::engine::general_purpose::STANDARD
                .decode(gi_b64)
                .map_err(|e| {
                    warn!("[resetGroup] invalid base64 groupInfo: {}", e);
                    StatusCode::BAD_REQUEST
                })?,
        )
    } else {
        None
    };

    // --- Begin transaction ---
    let mut tx = pool.begin().await.map_err(|e| {
        error!("[resetGroup] begin tx: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Update conversation
    // When clearCircuitBreaker is true: reset_count = 0, auto_reset_disabled_at = NULL
    // Otherwise: increment reset_count normally
    let reset_count: Option<i32> = sqlx::query_scalar(
        r#"UPDATE conversations SET
            group_id = $1, current_epoch = 0,
            group_info = $2, group_info_epoch = CASE WHEN $2 IS NOT NULL THEN 0 ELSE NULL END,
            group_info_updated_at = CASE WHEN $2 IS NOT NULL THEN NOW() ELSE NULL END,
            confirmation_tag = NULL, cipher_suite = $3,
            reset_count = CASE WHEN $6 THEN 0 ELSE reset_count + 1 END,
            auto_reset_disabled_at = CASE WHEN $6 THEN NULL ELSE auto_reset_disabled_at END,
            last_reset_at = NOW(), last_reset_by = $4,
            updated_at = NOW()
        WHERE id = $5
        RETURNING reset_count"#,
    )
    .bind(new_group_id)
    .bind(&group_info_bytes)
    .bind(&input.cipher_suite)
    .bind(caller_did)
    .bind(convo_id)
    .bind(input.clear_circuit_breaker)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        error!("[resetGroup] update conversations: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let reset_count = match reset_count {
        Some(rc) => rc,
        None => {
            tx.rollback().await.ok();
            warn!(
                "[resetGroup] conversation not found: {}",
                crate::crypto::redact_for_log(convo_id)
            );
            return Err(StatusCode::NOT_FOUND);
        }
    };

    // Delete old welcome messages
    sqlx::query("DELETE FROM welcome_messages WHERE convo_id = $1")
        .bind(convo_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            error!("[resetGroup] delete welcome_messages: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Delete pending device additions
    sqlx::query("DELETE FROM pending_device_additions WHERE convo_id = $1")
        .bind(convo_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            error!("[resetGroup] delete pending_device_additions: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Commit transaction
    tx.commit().await.map_err(|e| {
        error!("[resetGroup] commit tx: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if input.clear_circuit_breaker {
        info!(
            convo = %crate::crypto::redact_for_log(convo_id),
            "[resetGroup] circuit breaker cleared, reset_count zeroed"
        );
    }

    info!(
        convo = %crate::crypto::redact_for_log(convo_id),
        new_group_id = %crate::crypto::redact_for_log(new_group_id),
        reset_count = reset_count,
        "[resetGroup] complete"
    );

    // --- Emit SSE GroupResetEvent ---
    let cursor = sse_state.cursor_gen.next(convo_id, "groupResetEvent").await;

    let event = StreamEvent::GroupResetEvent {
        cursor: cursor.clone(),
        convo_id: convo_id.clone(),
        new_group_id: new_group_id.clone(),
        reset_generation: reset_count,
        reset_by: caller_did.clone(),
        cipher_suite: input.cipher_suite.clone(),
        reason: input.reason.clone(),
    };

    // Store event for cursor-based replay
    if let Err(e) = crate::db::store_event(&pool, convo_id, &event).await {
        error!("[resetGroup] store event: {:?}", e);
    }

    if let Err(e) = sse_state.emit(convo_id, event).await {
        error!("[resetGroup] SSE emit: {}", e);
    }

    // --- Return response ---
    Ok(Json(ResetGroupOutput {
        success: true,
        new_group_id: new_group_id.clone(),
        reset_generation: reset_count,
        new_epoch: 0,
    })
    .into_response())
}
