use axum::{extract::State, http::StatusCode, Json};
use std::sync::Arc;
use tracing::{error, info, warn};

use jacquard_axum::ExtractXrpc;

use crate::{
    auth::{enforce_standard, AuthUser},
    block_sync::BlockSyncService,
    generated::blue_catbird::mlsChat::blocks::{
        BlockChangeResult, BlockRelationship, BlocksOutput, BlocksRequest, ConversationBlockStatus,
    },
    sqlx_jacquard::chrono_to_datetime,
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.blocks";

/// Consolidated blocks handler (POST)
/// POST /xrpc/blue.catbird.mlsChat.blocks
///
/// Action-based dispatch:
///   - "check": check pairwise blocks among provided DIDs
///   - "getStatus": check all members of a conversation
///   - "handleChange": process block create/delete from client
#[tracing::instrument(skip(pool, block_sync, auth_user, input))]
pub async fn blocks_post(
    State(pool): State<DbPool>,
    State(block_sync): State<Arc<BlockSyncService>>,
    auth_user: AuthUser,
    ExtractXrpc(input): ExtractXrpc<BlocksRequest>,
) -> Result<Json<BlocksOutput<'static>>, StatusCode> {
    if let Err(_e) = enforce_standard(&auth_user.claims, NSID) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let now = chrono::Utc::now();

    match input.action.as_ref() {
        "getStatus" => {
            let convo_id = input.convo_id.as_deref().unwrap_or_default();

            let member_dids: Vec<String> = sqlx::query_scalar(
                "SELECT DISTINCT member_did FROM members WHERE convo_id = $1 AND left_at IS NULL",
            )
            .bind(convo_id)
            .fetch_all(&pool)
            .await
            .map_err(|e| {
                error!("Failed to query members: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            if member_dids.is_empty() {
                return Ok(Json(BlocksOutput {
                    has_conflicts: Some(false),
                    blocks: Some(vec![]),
                    checked_at: Some(chrono_to_datetime(now)),
                    status: Some(ConversationBlockStatus {
                        convo_id: convo_id.to_string().into(),
                        has_conflicts: false,
                        member_count: 0,
                        checked_at: Some(chrono_to_datetime(now)),
                        extra_data: Default::default(),
                    }),
                    ..Default::default()
                }));
            }

            let blocks = fetch_block_conflicts(&pool, &block_sync, &member_dids).await?;
            let has_conflicts = !blocks.is_empty();

            info!(
                "Conversation {} has {} members, {} block conflicts",
                crate::crypto::redact_for_log(convo_id),
                member_dids.len(),
                blocks.len()
            );

            Ok(Json(BlocksOutput {
                has_conflicts: Some(has_conflicts),
                blocks: Some(blocks),
                checked_at: Some(chrono_to_datetime(now)),
                status: Some(ConversationBlockStatus {
                    convo_id: convo_id.to_string().into(),
                    has_conflicts,
                    member_count: member_dids.len() as i64,
                    checked_at: Some(chrono_to_datetime(now)),
                    extra_data: Default::default(),
                }),
                ..Default::default()
            }))
        }

        "check" => {
            let did_strs: Vec<String> = input
                .dids
                .as_ref()
                .map(|dids| dids.iter().map(|d| d.to_string()).collect())
                .unwrap_or_default();

            if did_strs.len() < 2 || did_strs.len() > 100 {
                return Err(StatusCode::BAD_REQUEST);
            }

            let blocks = fetch_block_conflicts(&pool, &block_sync, &did_strs).await?;

            info!(
                "Found {} block relationships among {} DIDs",
                blocks.len(),
                did_strs.len()
            );

            Ok(Json(BlocksOutput {
                blocks: Some(blocks),
                checked_at: Some(chrono_to_datetime(now)),
                ..Default::default()
            }))
        }

        "handleChange" => {
            let block_record = input.block_record.as_ref().ok_or_else(|| {
                warn!("Missing blockRecord for handleChange action");
                StatusCode::BAD_REQUEST
            })?;

            let blocker_str = block_record.blocker_did.to_string();
            let blocked_str = block_record.blocked_did.to_string();
            let record_action = block_record.action.as_ref();

            // Invalidate cache for this user
            block_sync.invalidate_cache(&blocker_str).await;

            if record_action == "created" {
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

            let action_label = if record_action == "created" {
                "block_detected"
            } else {
                "block_removed"
            };

            let changes: Vec<BlockChangeResult<'static>> = affected_convo_ids
                .into_iter()
                .map(|convo_id| BlockChangeResult {
                    convo_id: convo_id.into(),
                    action: action_label.into(),
                    removed_did: None,
                    extra_data: Default::default(),
                })
                .collect();

            info!(
                "Block change ({}) affected {} conversations",
                record_action,
                changes.len()
            );

            Ok(Json(BlocksOutput {
                changes: Some(changes),
                ..Default::default()
            }))
        }

        other => {
            warn!("Unknown blocks action: {}", other);
            Err(StatusCode::BAD_REQUEST)
        }
    }
}

/// Shared helper: fetch block conflicts via BlockSyncService with DB fallback
async fn fetch_block_conflicts(
    pool: &DbPool,
    block_sync: &BlockSyncService,
    did_strs: &[String],
) -> Result<Vec<BlockRelationship<'static>>, StatusCode> {
    let now = chrono::Utc::now();
    let mut blocks = Vec::new();

    match block_sync.check_block_conflicts(did_strs).await {
        Ok(conflicts) => {
            for (blocker_str, blocked_str) in conflicts {
                if let Err(e) = block_sync.sync_blocks_to_db(pool, &blocker_str).await {
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
            .bind(did_strs)
            .fetch_all(pool)
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

    Ok(blocks)
}
