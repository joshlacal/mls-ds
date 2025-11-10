use axum::{extract::{Query, State}, http::StatusCode, Json};
use tracing::{info, error};

use crate::{
    auth::{AuthUser, enforce_standard},
    generated::blue::catbird::mls::get_block_status::{Parameters, Output, OutputData, NSID},
    generated::blue::catbird::mls::check_blocks::{BlockRelationship, BlockRelationshipData},
    sqlx_atrium::{chrono_to_datetime, string_to_did},
    storage::DbPool,
};

#[tracing::instrument(skip(pool, auth_user))]
pub async fn get_block_status(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Query(params): Query<Parameters>,
) -> Result<Json<Output>, StatusCode> {
    let params = params.data;

    enforce_standard(&auth_user.claims, NSID).map_err(|_| StatusCode::UNAUTHORIZED)?;

    let convo_id = &params.convo_id;

    // Get all members
    let member_dids: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT user_did FROM members WHERE convo_id = $1 AND left_at IS NULL"
    )
    .bind(convo_id)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!("Failed to query members: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if member_dids.is_empty() {
        info!("Conversation has no members");
        return Ok(Json(Output::from(OutputData {
            convo_id: convo_id.clone(),
            has_conflicts: false,
            member_count: Some(0),
            blocks: Vec::new(),
            checked_at: chrono_to_datetime(chrono::Utc::now()),
        })));
    }

    // Check for any blocks among members
    let rows: Vec<(String, String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        "SELECT user_did, target_did, synced_at
         FROM bsky_blocks
         WHERE user_did = ANY($1) AND target_did = ANY($1)"
    )
    .bind(&member_dids)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!("Failed to query blocks: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let mut blocks = Vec::new();
    for (blocker_str, blocked_str, synced_at) in rows {
        let blocker_did = string_to_did(&blocker_str).map_err(|e| {
            error!("Invalid blocker DID: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        let blocked_did = string_to_did(&blocked_str).map_err(|e| {
            error!("Invalid blocked DID: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        blocks.push(BlockRelationship::from(BlockRelationshipData {
            blocker_did,
            blocked_did,
            block_uri: None,
            created_at: chrono_to_datetime(synced_at),
        }));
    }

    let has_conflicts = !blocks.is_empty();

    info!(
        "Conversation {} has {} members, {} block conflicts",
        convo_id, member_dids.len(), blocks.len()
    );

    Ok(Json(Output::from(OutputData {
        convo_id: convo_id.clone(),
        has_conflicts,
        member_count: Some(member_dids.len()),
        blocks,
        checked_at: chrono_to_datetime(chrono::Utc::now()),
    })))
}
