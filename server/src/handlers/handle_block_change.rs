use axum::{extract::State, http::StatusCode, Json};
use tracing::{info, error};

use crate::{
    auth::{AuthUser, enforce_standard},
    generated::blue::catbird::mls::handle_block_change::{Input, Output, OutputData, AffectedConvo, AffectedConvoData, NSID},
    sqlx_atrium::chrono_to_datetime,
    storage::DbPool,
};

#[tracing::instrument(skip(pool, auth_user))]
pub async fn handle_block_change(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Json(input): Json<Input>,
) -> Result<Json<Output>, StatusCode> {
    let input = input.data;

    enforce_standard(&auth_user.claims, NSID).map_err(|_| StatusCode::UNAUTHORIZED)?;

    let blocker_str = input.blocker_did.to_string();
    let blocked_str = input.blocked_did.to_string();

    if input.action == "created" {
        // Insert block
        let now = chrono::Utc::now();
        sqlx::query(
            "INSERT INTO bsky_blocks (user_did, target_did, source, synced_at)
             VALUES ($1, $2, 'bsky', $3)
             ON CONFLICT (user_did, target_did) DO UPDATE SET synced_at = $3"
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

        info!("Block created: {} blocked {}", blocker_str, blocked_str);
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

        info!("Block removed: {} unblocked {}", blocker_str, blocked_str);
    }

    // Find affected conversations
    let affected_convo_ids: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT m1.convo_id
         FROM members m1
         JOIN members m2 ON m1.convo_id = m2.convo_id
         WHERE m1.user_did = $1 AND m2.user_did = $2
         AND m1.left_at IS NULL AND m2.left_at IS NULL"
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

    Ok(Json(Output::from(OutputData {
        affected_convos,
    })))
}
