use axum::{extract::State, http::StatusCode, Json};
use std::sync::Arc;
use tracing::{error, info};

use crate::{
    auth::{enforce_standard, AuthUser},
    block_sync::BlockSyncService,
    generated::blue::catbird::mls::handle_block_change::{
        AffectedConvo, AffectedConvoData, Input, Output, OutputData, NSID,
    },
    sqlx_atrium::chrono_to_datetime,
    storage::DbPool,
};

/// Handle a block change notification from the client.
///
/// This is called when a user blocks/unblocks someone on Bluesky.
/// We update our local cache and find affected conversations.
#[tracing::instrument(skip(pool, block_sync, auth_user))]
pub async fn handle_block_change(
    State(pool): State<DbPool>,
    State(block_sync): State<Arc<BlockSyncService>>,
    auth_user: AuthUser,
    Json(input): Json<Input>,
) -> Result<Json<Output>, StatusCode> {
    let input = input.data;

    enforce_standard(&auth_user.claims, NSID).map_err(|_| StatusCode::UNAUTHORIZED)?;

    let blocker_str = input.blocker_did.to_string();
    let blocked_str = input.blocked_did.to_string();

    // Invalidate the cache for this user so we fetch fresh data on next check
    block_sync.invalidate_cache(&blocker_str).await;

    if input.action == "created" {
        // Insert block
        let now = chrono::Utc::now();
        sqlx::query(
            "INSERT INTO bsky_blocks (user_did, target_did, source, synced_at)
             VALUES ($1, $2, 'client', $3)
             ON CONFLICT (user_did, target_did) DO UPDATE SET synced_at = $3",
        )
        .bind(&blocker_str)
        .bind(&blocked_str)
        .bind(&now)
        .execute(&pool)
        .await
        .map_err(|e| {
            error!("Failed to insert block: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        info!(
            "Block created: {} blocked {}",
            crate::crypto::redact_for_log(&blocker_str),
            crate::crypto::redact_for_log(&blocked_str)
        );
    } else {
        // Remove block
        sqlx::query("DELETE FROM bsky_blocks WHERE user_did = $1 AND target_did = $2")
            .bind(&blocker_str)
            .bind(&blocked_str)
            .execute(&pool)
            .await
            .map_err(|e| {
                error!("Failed to delete block: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        info!(
            "Block removed: {} unblocked {}",
            crate::crypto::redact_for_log(&blocker_str),
            crate::crypto::redact_for_log(&blocked_str)
        );
    }

    // Find affected conversations where both users are members
    let affected_convo_ids: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT m1.convo_id
         FROM members m1
         JOIN members m2 ON m1.convo_id = m2.convo_id
         WHERE m1.member_did = $1 AND m2.member_did = $2
         AND m1.left_at IS NULL AND m2.left_at IS NULL",
    )
    .bind(&blocker_str)
    .bind(&blocked_str)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!("Failed to query affected conversations: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Convert to AffectedConvo objects
    let now = chrono::Utc::now();
    let affected_convos: Vec<AffectedConvo> = affected_convo_ids
        .into_iter()
        .map(|convo_id| {
            let action = if input.action == "created" {
                "block_detected"
            } else {
                "block_removed"
            };

            AffectedConvo::from(AffectedConvoData {
                convo_id,
                action: action.to_string(),
                admin_notified: false,
                notification_sent_at: Some(chrono_to_datetime(now)),
            })
        })
        .collect();

    info!(
        "Block change ({}) affected {} conversations",
        input.action,
        affected_convos.len()
    );

    Ok(Json(Output::from(OutputData { affected_convos })))
}
