use axum::{extract::State, http::StatusCode, Json};
use std::sync::Arc;
use tracing::{error, info, warn};

use jacquard_axum::ExtractXrpc;

use crate::{
    auth::{enforce_standard, AuthUser},
    block_sync::BlockSyncService,
    generated::blue_catbird::mlsChat::get_block_status::{
        BlockRelationship, ConversationBlockStatus, GetBlockStatusOutput, GetBlockStatusRequest,
    },
    sqlx_jacquard::chrono_to_datetime,
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.getBlockStatus";

/// Report block relationships among the members of a conversation.
///
/// POST /xrpc/blue.catbird.mlsChat.getBlockStatus
///
/// Verifies the caller is an active member of the conversation, then fetches
/// all active member DIDs and probes `BlockSyncService::check_block_conflicts`
/// for any block edges among them.
#[tracing::instrument(skip(pool, block_sync, auth_user, input))]
pub async fn get_block_status_post(
    State(pool): State<DbPool>,
    State(block_sync): State<Arc<BlockSyncService>>,
    auth_user: AuthUser,
    ExtractXrpc(input): ExtractXrpc<GetBlockStatusRequest>,
) -> Result<Json<GetBlockStatusOutput<'static>>, StatusCode> {
    if let Err(_e) = enforce_standard(&auth_user.claims, NSID) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let convo_id = input.convo_id.as_ref();
    let caller_did = &auth_user.did;

    // Verify caller is an active member of this conversation
    let is_member: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM members WHERE convo_id = $1 AND (user_did = $2 OR member_did = $2) AND left_at IS NULL)",
    )
    .bind(convo_id)
    .bind(caller_did)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("getBlockStatus: membership check failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if !is_member {
        warn!(
            "getBlockStatus: caller {} is not a member of convo {}",
            crate::crypto::redact_for_log(caller_did),
            crate::crypto::redact_for_log(convo_id),
        );
        return Err(StatusCode::FORBIDDEN);
    }

    // Fetch distinct active member DIDs for this conversation
    let member_dids: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT COALESCE(user_did, member_did) FROM members WHERE convo_id = $1 AND left_at IS NULL",
    )
    .bind(convo_id)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!("getBlockStatus: failed to query members: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let now = chrono::Utc::now();
    let member_count = member_dids.len() as i64;

    let mut blocks: Vec<BlockRelationship<'static>> = Vec::new();

    if member_dids.len() >= 2 {
        match block_sync.check_block_conflicts(&member_dids).await {
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
                .bind(&member_dids)
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
    }

    let has_conflicts = !blocks.is_empty();

    info!(
        "getBlockStatus: convo {} has {} members, {} block conflicts",
        crate::crypto::redact_for_log(convo_id),
        member_count,
        blocks.len()
    );

    Ok(Json(GetBlockStatusOutput {
        blocks,
        checked_at: chrono_to_datetime(now),
        status: ConversationBlockStatus {
            convo_id: convo_id.to_string().into(),
            has_conflicts,
            member_count,
            extra_data: Default::default(),
        },
        extra_data: Default::default(),
    }))
}
