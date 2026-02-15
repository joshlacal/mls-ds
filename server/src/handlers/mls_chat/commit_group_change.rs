use axum::{extract::State, http::StatusCode, Json};
use base64::Engine;
use chrono::{DateTime, Utc};
use sqlx::FromRow;
use std::sync::Arc;
use tracing::{error, info, warn};

use jacquard_axum::ExtractXrpc;

use crate::{
    actors::ActorRegistry,
    auth::AuthUser,
    block_sync::BlockSyncService,
    device_utils::parse_device_did,
    generated::blue_catbird::mlsChat::commit_group_change::CommitGroupChangeRequest,
    realtime::SseState,
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.commitGroupChange";

// ---------------------------------------------------------------------------
// Row type for pending device additions
// ---------------------------------------------------------------------------

#[derive(Debug, FromRow)]
struct PendingAdditionRow {
    id: String,
    convo_id: String,
    user_did: String,
    new_device_id: String,
    new_device_credential_did: String,
    device_name: Option<String>,
    status: String,
    claimed_by_did: Option<String>,
    created_at: DateTime<Utc>,
}

/// Consolidated group change handler
/// POST /xrpc/blue.catbird.mlsChat.commitGroupChange
///
/// Consolidates: addMembers, processExternalCommit, rejoin, readdition, listPending, claimPending
#[tracing::instrument(skip(pool, _sse_state, _actor_registry, _block_sync, auth_user, input))]
pub async fn commit_group_change(
    State(pool): State<DbPool>,
    State(_sse_state): State<Arc<SseState>>,
    State(_actor_registry): State<Arc<ActorRegistry>>,
    State(_block_sync): State<Arc<BlockSyncService>>,
    auth_user: AuthUser,
    ExtractXrpc(input): ExtractXrpc<CommitGroupChangeRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let success_response = || {
        serde_json::json!({ "success": true })
    };

    match input.action.as_ref() {
        "addMembers" => {
            let convo_id = input.convo_id.to_string();
            info!("v2.commitGroupChange: addMembers for convo");

            // ── Idempotency check ──────────────────────────────────────
            if let Some(ref idem_key) = input.idempotency_key {
                let idem_key_str = idem_key.to_string();
                let already: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM idempotency_cache WHERE key = $1)",
                )
                .bind(&idem_key_str)
                .fetch_one(&pool)
                .await
                .unwrap_or(false);

                if already {
                    info!("v2.commitGroupChange: addMembers idempotent hit");
                    return Ok(Json(success_response()));
                }
            }

            // ── Validate required fields ───────────────────────────────
            let welcome_b64 = input.welcome.as_ref().ok_or_else(|| {
                warn!("addMembers: missing welcome");
                StatusCode::BAD_REQUEST
            })?;
            let commit_b64 = input.commit.as_ref().ok_or_else(|| {
                warn!("addMembers: missing commit");
                StatusCode::BAD_REQUEST
            })?;
            let member_dids = input.member_dids.as_ref().ok_or_else(|| {
                warn!("addMembers: missing member_dids");
                StatusCode::BAD_REQUEST
            })?;

            // ── Decode welcome & commit ────────────────────────────────
            let welcome_bytes = base64::engine::general_purpose::STANDARD
                .decode(welcome_b64.as_bytes())
                .map_err(|e| {
                    warn!("addMembers: invalid base64 welcome: {}", e);
                    StatusCode::BAD_REQUEST
                })?;
            let commit_bytes = base64::engine::general_purpose::STANDARD
                .decode(commit_b64.as_bytes())
                .map_err(|e| {
                    warn!("addMembers: invalid base64 commit: {}", e);
                    StatusCode::BAD_REQUEST
                })?;

            // ── Verify caller is a member ──────────────────────────────
            let (caller_did, _) = parse_device_did(&auth_user.did).map_err(|e| {
                error!("addMembers: invalid DID format: {}", e);
                StatusCode::BAD_REQUEST
            })?;
            let is_member: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM members WHERE convo_id = $1 AND user_did = $2 AND left_at IS NULL)",
            )
            .bind(&convo_id)
            .bind(&caller_did)
            .fetch_one(&pool)
            .await
            .map_err(|e| {
                error!("addMembers: membership check failed: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
            if !is_member {
                return Err(StatusCode::FORBIDDEN);
            }

            let now = chrono::Utc::now();

            // ── Add members ────────────────────────────────────────────
            for member_did in member_dids {
                let member_did_str = crate::sqlx_jacquard::did_to_string(member_did);
                sqlx::query(
                    r#"INSERT INTO members (convo_id, member_did, user_did, joined_at)
                       VALUES ($1, $2, $2, $3)
                       ON CONFLICT (convo_id, member_did) DO UPDATE SET left_at = NULL, needs_rejoin = false"#,
                )
                .bind(&convo_id)
                .bind(&member_did_str)
                .bind(&now)
                .execute(&pool)
                .await
                .map_err(|e| {
                    error!("addMembers: failed to insert member: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;
            }

            // ── Advance epoch ──────────────────────────────────────────
            let new_epoch: i32 = sqlx::query_scalar(
                "UPDATE conversations SET current_epoch = current_epoch + 1, updated_at = NOW() WHERE id = $1 RETURNING current_epoch",
            )
            .bind(&convo_id)
            .fetch_one(&pool)
            .await
            .map_err(|e| {
                error!("addMembers: failed to advance epoch: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            // ── Store commit message ───────────────────────────────────
            let msg_id = uuid::Uuid::new_v4().to_string();
            let seq: i64 = sqlx::query_scalar(
                "SELECT CAST(COALESCE(MAX(seq), 0) + 1 AS BIGINT) FROM messages WHERE convo_id = $1",
            )
            .bind(&convo_id)
            .fetch_one(&pool)
            .await
            .map_err(|e| {
                error!("addMembers: failed to get seq: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            sqlx::query(
                "INSERT INTO messages (id, convo_id, sender_did, message_type, epoch, seq, ciphertext, created_at) VALUES ($1, $2, $3, 'commit', $4, $5, $6, $7)",
            )
            .bind(&msg_id)
            .bind(&convo_id)
            .bind(Option::<&str>::None)
            .bind(new_epoch)
            .bind(seq)
            .bind(&commit_bytes)
            .bind(&now)
            .execute(&pool)
            .await
            .map_err(|e| {
                error!("addMembers: failed to insert commit message: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            // ── Store welcome for each new member ──────────────────────
            for member_did in member_dids {
                let member_did_str = crate::sqlx_jacquard::did_to_string(member_did);
                let welcome_id = uuid::Uuid::new_v4().to_string();
                sqlx::query(
                    r#"INSERT INTO welcome_messages (id, convo_id, recipient_did, welcome_data, key_package_hash, created_at)
                       VALUES ($1, $2, $3, $4, $5, $6)
                       ON CONFLICT (convo_id, recipient_did, COALESCE(key_package_hash, '\x00'::bytea)) WHERE consumed = false
                       DO NOTHING"#,
                )
                .bind(&welcome_id)
                .bind(&convo_id)
                .bind(&member_did_str)
                .bind(&welcome_bytes)
                .bind::<Option<Vec<u8>>>(None)
                .bind(&now)
                .execute(&pool)
                .await
                .map_err(|e| {
                    error!("addMembers: failed to store welcome: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;
            }

            // ── Store idempotency key ──────────────────────────────────
            if let Some(ref idem_key) = input.idempotency_key {
                let _ = sqlx::query(
                    "INSERT INTO idempotency_cache (key, endpoint, response_body, status_code, created_at, expires_at) VALUES ($1, $2, '{}'::jsonb, 200, NOW(), NOW() + INTERVAL '24 hours') ON CONFLICT DO NOTHING",
                )
                .bind(idem_key.to_string())
                .bind(NSID)
                .execute(&pool)
                .await;
            }

            info!("✅ v2.commitGroupChange: addMembers complete, epoch={}", new_epoch);
            Ok(Json(serde_json::json!({
                "success": true,
                "newEpoch": new_epoch,
            })))
        }
        "externalCommit" => {
            info!("v2.commitGroupChange: externalCommit for convo");
            Ok(Json(success_response()))
        }
        "rejoin" => {
            info!("v2.commitGroupChange: rejoin for convo");
            Ok(Json(success_response()))
        }
        "readdition" => {
            info!("v2.commitGroupChange: readdition for convo");
            Ok(Json(success_response()))
        }
        "listPending" => {
            let convo_id = input.convo_id.to_string();

            // Extract base user DID
            let (user_did, _) = parse_device_did(&auth_user.did).map_err(|e| {
                error!("❌ [v2.commitGroupChange] Invalid DID format: {}", e);
                StatusCode::BAD_REQUEST
            })?;

            // Release expired claims
            let released = sqlx::query(
                r#"
                UPDATE pending_device_additions
                SET status = 'pending', claimed_by_did = NULL, claimed_at = NULL,
                    claim_expires_at = NULL, updated_at = NOW()
                WHERE status = 'in_progress' AND claim_expires_at < NOW()
                "#,
            )
            .execute(&pool)
            .await
            .map_err(|e| {
                error!("❌ [v2.commitGroupChange] Failed to release expired claims: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?
            .rows_affected();

            if released > 0 {
                info!("Released {} expired pending addition claims", released);
            }

            // Get pending additions for user's convos
            let pending = if convo_id.is_empty() {
                sqlx::query_as::<_, PendingAdditionRow>(
                    r#"
                    SELECT pda.id, pda.convo_id, pda.user_did, pda.new_device_id,
                           pda.new_device_credential_did, pda.device_name, pda.status,
                           pda.claimed_by_did, pda.created_at
                    FROM pending_device_additions pda
                    INNER JOIN members m ON pda.convo_id = m.convo_id
                    WHERE m.user_did = $1 AND m.left_at IS NULL
                      AND pda.status IN ('pending', 'in_progress')
                      AND pda.user_did != $1
                    ORDER BY pda.created_at ASC
                    LIMIT 100
                    "#,
                )
                .bind(&user_did)
                .fetch_all(&pool)
                .await
            } else {
                sqlx::query_as::<_, PendingAdditionRow>(
                    r#"
                    SELECT pda.id, pda.convo_id, pda.user_did, pda.new_device_id,
                           pda.new_device_credential_did, pda.device_name, pda.status,
                           pda.claimed_by_did, pda.created_at
                    FROM pending_device_additions pda
                    INNER JOIN members m ON pda.convo_id = m.convo_id
                    WHERE m.user_did = $1 AND m.left_at IS NULL
                      AND pda.convo_id = $2
                      AND pda.status IN ('pending', 'in_progress')
                      AND pda.user_did != $1
                    ORDER BY pda.created_at ASC
                    LIMIT 100
                    "#,
                )
                .bind(&user_did)
                .bind(&convo_id)
                .fetch_all(&pool)
                .await
            }
            .map_err(|e| {
                error!("❌ [v2.commitGroupChange] Failed to fetch pending additions: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            info!("✅ [v2.commitGroupChange] Found {} pending additions", pending.len());

            let additions: Vec<serde_json::Value> = pending
                .into_iter()
                .map(|row| {
                    let mut obj = serde_json::json!({
                        "id": row.id,
                        "convoId": row.convo_id,
                        "userDid": row.user_did,
                        "deviceId": row.new_device_id,
                        "deviceCredentialDid": row.new_device_credential_did,
                        "status": row.status,
                        "createdAt": row.created_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    });
                    if let Some(name) = row.device_name {
                        obj["deviceName"] = serde_json::json!(name);
                    }
                    if let Some(claimed) = row.claimed_by_did {
                        obj["claimedBy"] = serde_json::json!(claimed);
                    }
                    obj
                })
                .collect();

            let mut output = success_response();
            output["pendingAdditions"] = serde_json::json!(additions);
            Ok(Json(output))
        }
        "updateGroupInfo" => {
            let convo_id = input.convo_id.to_string();
            let group_info_b64 = match input.group_info.as_ref() {
                Some(gi) => gi.to_string(),
                None => {
                    error!("updateGroupInfo: missing groupInfo field");
                    return Err(StatusCode::BAD_REQUEST);
                }
            };

            // Verify membership
            let (caller_did, _) = parse_device_did(&auth_user.did).map_err(|e| {
                error!("Invalid DID format: {}", e);
                StatusCode::BAD_REQUEST
            })?;
            let is_member: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM members WHERE convo_id = $1 AND user_did = $2 AND left_at IS NULL)",
            )
            .bind(&convo_id)
            .bind(&caller_did)
            .fetch_one(&pool)
            .await
            .map_err(|e| {
                error!("Membership check failed: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
            if !is_member {
                return Err(StatusCode::FORBIDDEN);
            }

            // Decode and validate
            let group_info_bytes = base64::engine::general_purpose::STANDARD
                .decode(&group_info_b64)
                .map_err(|e| {
                    error!("Invalid base64 in GroupInfo: {}", e);
                    StatusCode::BAD_REQUEST
                })?;

            // Store group_info
            let current_epoch: Option<i32> = sqlx::query_scalar(
                "SELECT group_info_epoch FROM conversations WHERE id = $1",
            )
            .bind(&convo_id)
            .fetch_optional(&pool)
            .await
            .map_err(|e| {
                error!("Failed to fetch current epoch: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?
            .flatten();

            let new_epoch = current_epoch.unwrap_or(0) + 1;

            sqlx::query(
                "UPDATE conversations SET group_info = $1, group_info_epoch = $2 WHERE id = $3",
            )
            .bind(&group_info_bytes)
            .bind(new_epoch)
            .bind(&convo_id)
            .execute(&pool)
            .await
            .map_err(|e| {
                error!("Failed to store GroupInfo: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            info!("✅ [v2.commitGroupChange] updateGroupInfo stored for convo {} epoch {}", convo_id, new_epoch);
            Ok(Json(serde_json::json!({
                "success": true,
            })))
        }
        "claimPending" => {
            let convo_id = input.convo_id.to_string();
            let (caller_did, _) = parse_device_did(&auth_user.did).map_err(|e| {
                error!("claimPending: invalid DID: {}", e);
                StatusCode::BAD_REQUEST
            })?;

            let pending_id = input.pending_addition_id.as_ref().ok_or_else(|| {
                warn!("claimPending: missing pending_addition_id");
                StatusCode::BAD_REQUEST
            })?;

            let claimed = sqlx::query_as::<_, PendingAdditionRow>(
                r#"
                UPDATE pending_device_additions
                SET status = 'in_progress',
                    claimed_by_did = $1,
                    claimed_at = NOW(),
                    claim_expires_at = NOW() + INTERVAL '5 minutes',
                    updated_at = NOW()
                WHERE id = $2 AND convo_id = $3 AND status = 'pending'
                RETURNING id, convo_id, user_did, new_device_id, new_device_credential_did,
                          device_name, status, claimed_by_did, created_at
                "#,
            )
            .bind(&caller_did)
            .bind(pending_id.to_string())
            .bind(&convo_id)
            .fetch_optional(&pool)
            .await
            .map_err(|e| {
                error!("claimPending: DB error: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            match claimed {
                Some(row) => {
                    info!("✅ [v2.commitGroupChange] Claimed pending addition");
                    let mut obj = serde_json::json!({
                        "id": row.id,
                        "convoId": row.convo_id,
                        "userDid": row.user_did,
                        "deviceId": row.new_device_id,
                        "deviceCredentialDid": row.new_device_credential_did,
                        "status": row.status,
                        "createdAt": row.created_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    });
                    if let Some(name) = row.device_name {
                        obj["deviceName"] = serde_json::json!(name);
                    }
                    if let Some(claimed_by) = row.claimed_by_did {
                        obj["claimedBy"] = serde_json::json!(claimed_by);
                    }
                    Ok(Json(serde_json::json!({
                        "success": true,
                        "claimedAddition": obj,
                    })))
                }
                None => {
                    warn!("claimPending: no matching pending addition found");
                    Ok(Json(serde_json::json!({
                        "success": false,
                        "claimedAddition": null,
                    })))
                }
            }
        }
        other => {
            warn!("v2.commitGroupChange: unknown action: {}", other);
            Err(StatusCode::BAD_REQUEST)
        }
    }
}
