use axum::{extract::{Query, State}, http::StatusCode, Json};
use tracing::{info, error};

use crate::{
    auth::{AuthUser, enforce_standard},
    generated::blue::catbird::mls::check_blocks::{Parameters, Output, OutputData, BlockRelationship, BlockRelationshipData, NSID},
    sqlx_atrium::{chrono_to_datetime, string_to_did},
    storage::DbPool,
};

#[tracing::instrument(skip(pool, auth_user))]
pub async fn check_blocks(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Query(params): Query<Parameters>,
) -> Result<Json<Output>, StatusCode> {
    let params = params.data;

    enforce_standard(&auth_user.claims, NSID).map_err(|_| StatusCode::UNAUTHORIZED)?;

    // Validate DID count (2-100)
    if params.dids.len() < 2 || params.dids.len() > 100 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let now = chrono::Utc::now();
    let mut blocks = Vec::new();

    // Query blocks table for all pairs
    let did_strs: Vec<String> = params.dids.iter().map(|d| d.to_string()).collect();

    let rows: Vec<(String, String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        "SELECT user_did, target_did, synced_at
         FROM bsky_blocks
         WHERE user_did = ANY($1) AND target_did = ANY($1)"
    )
    .bind(&did_strs)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!("Failed to query blocks: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

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
            block_uri: None, // Optional - would need to store in DB
            created_at: chrono_to_datetime(synced_at),
        }));
    }

    info!("Found {} block relationships among {} DIDs", blocks.len(), params.dids.len());

    Ok(Json(Output::from(OutputData {
        blocks,
        checked_at: chrono_to_datetime(now),
    })))
}
