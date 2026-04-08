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

const NSID: &str = "blue.catbird.mlsChat.reportRecoveryFailure";

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportRecoveryFailureRequest {
    pub convo_id: String,
    pub failure_type: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportRecoveryFailureOutput {
    pub recorded: bool,
    pub auto_reset_triggered: bool,
    pub failure_count: i64,
    pub member_count: i64,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum auto-resets before circuit breaker trips.
const CIRCUIT_BREAKER_MAX_RESETS: i32 = 3;

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Report that recovery has been exhausted for a conversation.
///
/// POST /xrpc/blue.catbird.mlsChat.reportRecoveryFailure
///
/// Any member may report. When >=50% of active members have reported
/// (within a 1-hour expiry window), the server auto-resets the group.
#[tracing::instrument(skip(pool, sse_state, auth_user, input))]
pub async fn report_recovery_failure(
    State(pool): State<DbPool>,
    State(sse_state): State<Arc<SseState>>,
    auth_user: AuthUser,
    Json(input): Json<ReportRecoveryFailureRequest>,
) -> Result<Response, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        error!("[reportRecoveryFailure] Unauthorized");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let caller_did = &auth_user.did;
    let convo_id = &input.convo_id;
    let failure_type = input
        .failure_type
        .as_deref()
        .unwrap_or("external_commit_exhausted");

    info!(
        convo = %crate::crypto::redact_for_log(convo_id),
        caller = %crate::crypto::redact_for_log(caller_did),
        failure_type,
        "[reportRecoveryFailure] start"
    );

    // --- Verify caller is a member ---
    let is_member: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM members WHERE convo_id = $1 AND (user_did = $2 OR member_did = $2) AND left_at IS NULL)",
    )
    .bind(convo_id)
    .bind(caller_did)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("[reportRecoveryFailure] membership check failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if !is_member {
        warn!("[reportRecoveryFailure] caller is not a member");
        return Err(StatusCode::FORBIDDEN);
    }

    // --- Upsert failure report ---
    sqlx::query(
        r#"INSERT INTO recovery_failures (convo_id, member_did, reported_at, failure_type)
           VALUES ($1, $2, NOW(), $3)
           ON CONFLICT (convo_id, member_did) DO UPDATE
           SET reported_at = NOW(), failure_type = $3"#,
    )
    .bind(convo_id)
    .bind(caller_did)
    .bind(failure_type)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("[reportRecoveryFailure] upsert failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // --- Count recent failures vs total members ---
    let failure_count: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM recovery_failures
           WHERE convo_id = $1
           AND reported_at > NOW() - INTERVAL '1 hour'"#,
    )
    .bind(convo_id)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("[reportRecoveryFailure] count failures: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let member_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM members WHERE convo_id = $1 AND left_at IS NULL")
            .bind(convo_id)
            .fetch_one(&pool)
            .await
            .map_err(|e| {
                error!("[reportRecoveryFailure] count members: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

    info!(
        convo = %crate::crypto::redact_for_log(convo_id),
        failure_count,
        member_count,
        "[reportRecoveryFailure] quorum check"
    );

    let not_triggered = Json(ReportRecoveryFailureOutput {
        recorded: true,
        auto_reset_triggered: false,
        failure_count,
        member_count,
    })
    .into_response();

    // --- Evaluate auto-reset policy: >=50% of members reported ---
    if member_count == 0 || failure_count * 2 < member_count {
        return Ok(not_triggered);
    }

    // --- Check cooldown: no auto-reset within 30 minutes ---
    let recent_reset: bool = sqlx::query_scalar(
        r#"SELECT EXISTS(
            SELECT 1 FROM conversations
            WHERE id = $1
            AND last_reset_at IS NOT NULL
            AND last_reset_at > NOW() - INTERVAL '30 minutes'
        )"#,
    )
    .bind(convo_id)
    .fetch_one(&pool)
    .await
    .unwrap_or(false);

    if recent_reset {
        info!("[reportRecoveryFailure] cooldown active, skipping auto-reset");
        return Ok(not_triggered);
    }

    // --- Check circuit breaker: auto_reset_disabled_at ---
    let disabled: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM conversations WHERE id = $1 AND auto_reset_disabled_at IS NOT NULL)",
    )
    .bind(convo_id)
    .fetch_one(&pool)
    .await
    .unwrap_or(false);

    if disabled {
        warn!("[reportRecoveryFailure] circuit breaker active for conversation");
        return Ok(not_triggered);
    }

    // --- Execute auto-reset ---
    info!(
        convo = %crate::crypto::redact_for_log(convo_id),
        "[reportRecoveryFailure] threshold met, executing auto-reset"
    );

    let new_group_id = format!("{:032x}", uuid::Uuid::new_v4().as_u128());

    let mut tx = pool.begin().await.map_err(|e| {
        error!("[reportRecoveryFailure] begin tx: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Reset the conversation
    let reset_count: Option<i32> = sqlx::query_scalar(
        r#"UPDATE conversations SET
            group_id = $1, current_epoch = 0,
            group_info = NULL, group_info_epoch = NULL,
            group_info_updated_at = NULL,
            confirmation_tag = NULL,
            reset_count = reset_count + 1, last_reset_at = NOW(),
            last_reset_by = 'system:auto_recovery',
            updated_at = NOW()
        WHERE id = $2
        RETURNING reset_count"#,
    )
    .bind(&new_group_id)
    .bind(convo_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        error!("[reportRecoveryFailure] update conversations: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let reset_count = match reset_count {
        Some(rc) => rc,
        None => {
            tx.rollback().await.ok();
            return Err(StatusCode::NOT_FOUND);
        }
    };

    // Trip circuit breaker if we've hit the limit
    if reset_count >= CIRCUIT_BREAKER_MAX_RESETS {
        sqlx::query("UPDATE conversations SET auto_reset_disabled_at = NOW() WHERE id = $1")
            .bind(convo_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                error!("[reportRecoveryFailure] trip circuit breaker: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
        warn!(
            convo = %crate::crypto::redact_for_log(convo_id),
            reset_count,
            "[reportRecoveryFailure] circuit breaker tripped"
        );

        // Emit CircuitBreakerTrippedEvent via SSE
        let tripped_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let cb_cursor = sse_state
            .cursor_gen
            .next(convo_id, "circuitBreakerTrippedEvent")
            .await;
        let cb_event = StreamEvent::CircuitBreakerTrippedEvent {
            cursor: cb_cursor.clone(),
            convo_id: convo_id.clone(),
            reset_count,
            tripped_at,
        };
        if let Err(e) = crate::db::store_event(
            &pool,
            &cb_cursor,
            convo_id,
            "circuitBreakerTrippedEvent",
            None,
        )
        .await
        {
            error!(
                "[reportRecoveryFailure] store circuit breaker event: {:?}",
                e
            );
        }
        if let Err(e) = sse_state.emit(convo_id, cb_event).await {
            error!("[reportRecoveryFailure] SSE emit circuit breaker: {}", e);
        }
    }

    // Delete welcome messages
    sqlx::query("DELETE FROM welcome_messages WHERE convo_id = $1")
        .bind(convo_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            error!("[reportRecoveryFailure] delete welcome_messages: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Delete pending device additions
    sqlx::query("DELETE FROM pending_device_additions WHERE convo_id = $1")
        .bind(convo_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            error!(
                "[reportRecoveryFailure] delete pending_device_additions: {}",
                e
            );
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Clear recovery failures for this conversation
    sqlx::query("DELETE FROM recovery_failures WHERE convo_id = $1")
        .bind(convo_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            error!("[reportRecoveryFailure] clear recovery_failures: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    tx.commit().await.map_err(|e| {
        error!("[reportRecoveryFailure] commit tx: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!(
        convo = %crate::crypto::redact_for_log(convo_id),
        new_group_id = %crate::crypto::redact_for_log(&new_group_id),
        reset_count,
        "[reportRecoveryFailure] auto-reset complete"
    );

    // --- Emit SSE GroupResetEvent ---
    let cursor = sse_state.cursor_gen.next(convo_id, "groupResetEvent").await;

    let event = StreamEvent::GroupResetEvent {
        cursor: cursor.clone(),
        convo_id: convo_id.clone(),
        new_group_id: new_group_id.clone(),
        reset_generation: reset_count,
        reset_by: "system:auto_recovery".to_string(),
        cipher_suite: String::new(),
        reason: Some(
            "Automatic recovery: quorum of members reported unrecoverable failure".to_string(),
        ),
    };

    if let Err(e) = crate::db::store_event(&pool, &cursor, convo_id, "groupResetEvent", None).await
    {
        error!("[reportRecoveryFailure] store event: {:?}", e);
    }

    if let Err(e) = sse_state.emit(convo_id, event).await {
        error!("[reportRecoveryFailure] SSE emit: {}", e);
    }

    Ok(Json(ReportRecoveryFailureOutput {
        recorded: true,
        auto_reset_triggered: true,
        failure_count,
        member_count,
    })
    .into_response())
}
