use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::{
    auth::{enforce_standard, AuthUser},
    block_sync::BlockSyncService,
    generated::blue::catbird::mls::check_blocks::{
        BlockRelationship, BlockRelationshipData, Output, OutputData, Parameters, NSID,
    },
    sqlx_atrium::{chrono_to_datetime, string_to_did},
    storage::DbPool,
};

/// Check blocks between users by querying their PDSes directly
///
/// This handler:
/// 1. First queries PDSes for fresh block data (via BlockSyncService)
/// 2. Syncs the blocks to local DB for caching
/// 3. Returns any block conflicts found
#[tracing::instrument(skip(pool, block_sync, auth_user))]
pub async fn check_blocks(
    State(pool): State<DbPool>,
    State(block_sync): State<Arc<BlockSyncService>>,
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
    let did_strs: Vec<String> = params.dids.iter().map(|d| d.to_string()).collect();

    // Query each user's PDS for their block records
    // This is the authoritative source, not our cached DB
    info!(
        "Checking blocks for {} DIDs via PDS queries",
        did_strs.len()
    );

    match block_sync.check_block_conflicts(&did_strs).await {
        Ok(conflicts) => {
            for (blocker_str, blocked_str) in conflicts {
                // Also sync to DB for caching
                if let Err(e) = block_sync.sync_blocks_to_db(&pool, &blocker_str).await {
                    warn!(
                        "Failed to sync blocks to DB for {}: {}",
                        crate::crypto::redact_for_log(&blocker_str),
                        e
                    );
                }

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
                    created_at: chrono_to_datetime(now),
                }));
            }
        }
        Err(e) => {
            // Fall back to local DB if PDS queries fail
            warn!("PDS block check failed, falling back to local DB: {}", e);

            let rows: Vec<(String, String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
                "SELECT user_did, target_did, synced_at
                 FROM bsky_blocks
                 WHERE user_did = ANY($1) AND target_did = ANY($1)",
            )
            .bind(&did_strs)
            .fetch_all(&pool)
            .await
            .map_err(|e| {
                error!("Failed to query blocks from DB: {}", e);
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
                    block_uri: None,
                    created_at: chrono_to_datetime(synced_at),
                }));
            }
        }
    }

    info!(
        "Found {} block relationships among {} DIDs",
        blocks.len(),
        did_strs.len()
    );

    Ok(Json(Output::from(OutputData {
        blocks,
        checked_at: chrono_to_datetime(now),
    })))
}
