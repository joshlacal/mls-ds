use axum::{extract::State, http::StatusCode, Json};
use std::sync::Arc;
use tracing::{error, info, warn};

use jacquard_axum::ExtractXrpc;

use crate::{
    auth::{enforce_standard, AuthUser},
    block_sync::BlockSyncService,
    generated::blue_catbird::mlsChat::check_blocks::{
        BlockRelationship, CheckBlocksOutput, CheckBlocksRequest,
    },
    sqlx_jacquard::chrono_to_datetime,
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.checkBlocks";

/// Check for mutual block relationships among a provided set of DIDs.
///
/// POST /xrpc/blue.catbird.mlsChat.checkBlocks
///
/// Queries the Bluesky PDSes of each DID via `BlockSyncService` to find any
/// block edges between pairs in the input set. On PDS failure, falls back to
/// the locally synced `bsky_blocks` table.
#[tracing::instrument(skip(pool, block_sync, auth_user, input))]
pub async fn check_blocks_post(
    State(pool): State<DbPool>,
    State(block_sync): State<Arc<BlockSyncService>>,
    auth_user: AuthUser,
    ExtractXrpc(input): ExtractXrpc<CheckBlocksRequest>,
) -> Result<Json<CheckBlocksOutput<'static>>, StatusCode> {
    if let Err(_e) = enforce_standard(&auth_user.claims, NSID) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let did_strs: Vec<String> = input.dids.iter().map(|d| d.to_string()).collect();

    if did_strs.len() < 2 {
        warn!("checkBlocks called with <2 dids");
        return Err(StatusCode::BAD_REQUEST);
    }
    if did_strs.len() > 100 {
        warn!("checkBlocks called with >100 dids ({})", did_strs.len());
        return Err(StatusCode::BAD_REQUEST);
    }

    let now = chrono::Utc::now();
    let mut blocks: Vec<BlockRelationship<'static>> = Vec::new();

    match block_sync.check_block_conflicts(&did_strs).await {
        Ok(conflicts) => {
            for (blocker_str, blocked_str) in conflicts {
                if let Err(e) = block_sync.sync_blocks_to_db(&pool, &blocker_str).await {
                    warn!(
                        "Failed to sync blocks to DB for {}: {}",
                        crate::crypto::redact_for_log(&blocker_str),
                        e
                    );
                }

                blocks.push(BlockRelationship {
                    blocker_did: blocker_str.into(),
                    blocked_did: blocked_str.into(),
                    created_at: chrono_to_datetime(now),
                    block_uri: None,
                    extra_data: Default::default(),
                });
            }
        }
        Err(e) => {
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
                blocks.push(BlockRelationship {
                    blocker_did: blocker_str.into(),
                    blocked_did: blocked_str.into(),
                    created_at: chrono_to_datetime(synced_at),
                    block_uri: None,
                    extra_data: Default::default(),
                });
            }
        }
    }

    info!(
        "checkBlocks: found {} block relationships among {} DIDs",
        blocks.len(),
        did_strs.len()
    );

    let blocked = !blocks.is_empty();

    Ok(Json(CheckBlocksOutput {
        blocked,
        blocks,
        checked_at: chrono_to_datetime(now),
        extra_data: Default::default(),
    }))
}
