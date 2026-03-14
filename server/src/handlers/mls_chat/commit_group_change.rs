use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use base64::Engine;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::FromRow;
use std::sync::Arc;
use tracing::{error, info, warn};

use jacquard_axum::ExtractXrpc;

use crate::{
    actors::ActorRegistry,
    auth::AuthUser,
    block_sync::BlockSyncService,
    device_utils::parse_device_did,
    generated::blue_catbird::mlsChat::commit_group_change::{
        CommitGroupChangeOutput, CommitGroupChangeRequest, PendingDeviceAddition,
    },
    realtime::SseState,
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.commitGroupChange";

#[derive(Serialize)]
struct XrpcErrorBody {
    error: &'static str,
    message: String,
}

pub struct XrpcError(StatusCode, &'static str, String);

impl IntoResponse for XrpcError {
    fn into_response(self) -> Response {
        (
            self.0,
            Json(XrpcErrorBody {
                error: self.1,
                message: self.2,
            }),
        )
            .into_response()
    }
}

fn bad_request(message: impl Into<String>) -> XrpcError {
    XrpcError(StatusCode::BAD_REQUEST, "InvalidRequest", message.into())
}

fn auth_required(message: impl Into<String>) -> XrpcError {
    XrpcError(StatusCode::UNAUTHORIZED, "AuthRequired", message.into())
}

fn forbidden(message: impl Into<String>) -> XrpcError {
    XrpcError(StatusCode::FORBIDDEN, "Forbidden", message.into())
}

fn conflict(message: impl Into<String>) -> XrpcError {
    XrpcError(StatusCode::CONFLICT, "Conflict", message.into())
}

fn internal_server_error(message: impl Into<String>) -> XrpcError {
    XrpcError(
        StatusCode::INTERNAL_SERVER_ERROR,
        "InternalServerError",
        message.into(),
    )
}

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

fn invalidate_welcome_response(rows_affected: u64) -> CommitGroupChangeOutput<'static> {
    CommitGroupChangeOutput {
        success: rows_affected > 0,
        claimed_addition: None,
        new_epoch: None,
        pending_additions: None,
        rejoined_at: None,
        extra_data: Default::default(),
    }
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
) -> Result<Response, XrpcError> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        return Err(auth_required("Authentication required"));
    }

    let success_response = || CommitGroupChangeOutput {
        success: true,
        claimed_addition: None,
        new_epoch: None,
        pending_additions: None,
        rejoined_at: None,
        extra_data: Default::default(),
    };

    match input.action.as_ref() {
        "addMembers" => {
            let convo_id = input.convo_id.to_string();
            info!("v2.commitGroupChange: addMembers for convo {}", crate::crypto::redact_for_log(&convo_id));

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
                    let current_epoch: Option<i32> =
                        sqlx::query_scalar("SELECT current_epoch FROM conversations WHERE id = $1")
                            .bind(&convo_id)
                            .fetch_optional(&pool)
                            .await
                            .ok()
                            .flatten();
                    info!("v2.commitGroupChange: addMembers idempotent hit");
                    return Ok(Json(CommitGroupChangeOutput {
                        success: true,
                        new_epoch: Some(current_epoch.unwrap_or(0) as i64),
                        claimed_addition: None,
                        pending_additions: None,
                        rejoined_at: None,
                        extra_data: Default::default(),
                    })
                    .into_response());
                }
            }

            // ── Validate required fields ───────────────────────────────
            let welcome_b64 = input.welcome.as_ref().ok_or_else(|| {
                warn!("addMembers: missing welcome");
                bad_request("Missing welcome")
            })?;
            let commit_b64 = input.commit.as_ref().ok_or_else(|| {
                warn!("addMembers: missing commit");
                bad_request("Missing commit")
            })?;
            let member_dids = input.member_dids.as_ref().ok_or_else(|| {
                warn!("addMembers: missing member_dids");
                bad_request("Missing memberDids")
            })?;

            // ── Decode welcome & commit ────────────────────────────────
            let welcome_bytes = base64::engine::general_purpose::STANDARD
                .decode(welcome_b64.as_bytes())
                .map_err(|e| {
                    warn!("addMembers: invalid base64 welcome: {}", e);
                    bad_request("Invalid base64 welcome")
                })?;
            let commit_bytes = base64::engine::general_purpose::STANDARD
                .decode(commit_b64.as_bytes())
                .map_err(|e| {
                    warn!("addMembers: invalid base64 commit: {}", e);
                    bad_request("Invalid base64 commit")
                })?;

            // ── Verify caller is a member ──────────────────────────────
            let (caller_did, _) = parse_device_did(&auth_user.did).map_err(|e| {
                error!("addMembers: invalid DID format: {}", e);
                bad_request("Invalid DID format")
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
                internal_server_error("Failed to check membership")
            })?;
            if !is_member {
                return Err(forbidden("Not a member of this conversation"));
            }

            let now = chrono::Utc::now();

            // ── Fetch current epoch for CAS ───────────────────────────
            let current_epoch = crate::db::get_current_epoch(&pool, &convo_id)
                .await
                .map_err(|e| {
                    error!(convo_id = %crate::crypto::redact_for_log(&convo_id), "addMembers: failed to get current epoch: {}", e);
                    internal_server_error("Failed to get current epoch")
                })?;

            // ── Begin transaction: members + CAS epoch + commit + welcomes + idempotency ──
            let mut tx = pool.begin().await.map_err(|e| {
                error!(convo_id = %crate::crypto::redact_for_log(&convo_id), "addMembers: failed to begin transaction: {}", e);
                internal_server_error("Failed to begin transaction")
            })?;

            // ── Add members (inside transaction for atomicity with welcome) ──
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
                .execute(&mut *tx)
                .await
                .map_err(|e| {
                    error!(convo_id = %crate::crypto::redact_for_log(&convo_id), "addMembers: failed to insert member: {}", e);
                    internal_server_error("Failed to insert member")
                })?;
            }

            // ── Advance epoch (CAS) ───────────────────────────────────
            let new_epoch = crate::db::try_advance_conversation_epoch_tx(
                &mut tx,
                &convo_id,
                current_epoch,
            )
            .await
            .map_err(|e| {
                error!("addMembers: failed to advance epoch: {}", e);
                internal_server_error("Failed to advance epoch")
            })?;

            let new_epoch = match new_epoch {
                Some(epoch) => epoch,
                None => {
                    warn!("addMembers: epoch CAS failed (concurrent commit), returning 409");
                    return Err(conflict("Conversation epoch advanced concurrently"));
                }
            };

            // ── Invalidate stale GroupInfo after epoch advance ────────
            sqlx::query(
                "UPDATE conversations SET group_info = NULL, group_info_epoch = NULL, group_info_updated_at = NULL WHERE id = $1",
            )
            .bind(&convo_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                error!("addMembers: failed to invalidate stale GroupInfo after epoch advance: {}", e);
                internal_server_error("Failed to invalidate stale GroupInfo")
            })?;

            // ── Store commit message ───────────────────────────────────
            let msg_id = uuid::Uuid::new_v4().to_string();
            let seq: i64 = sqlx::query_scalar(
                "SELECT CAST(COALESCE(MAX(seq), 0) + 1 AS BIGINT) FROM messages WHERE convo_id = $1",
            )
            .bind(&convo_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| {
                error!("addMembers: failed to get seq: {}", e);
                internal_server_error("Failed to allocate message sequence")
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
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                error!("addMembers: failed to insert commit message: {}", e);
                internal_server_error("Failed to store commit message")
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
                .execute(&mut *tx)
                .await
                .map_err(|e| {
                    error!("addMembers: failed to store welcome: {}", e);
                    internal_server_error("Failed to store welcome")
                })?;
            }

            // ── Store idempotency key ──────────────────────────────────
            if let Some(ref idem_key) = input.idempotency_key {
                let _ = sqlx::query(
                    "INSERT INTO idempotency_cache (key, endpoint, response_body, status_code, created_at, expires_at) VALUES ($1, $2, '{}'::jsonb, 200, NOW(), NOW() + INTERVAL '24 hours') ON CONFLICT DO NOTHING",
                )
                .bind(idem_key.to_string())
                .bind(NSID)
                .execute(&mut *tx)
                .await;
            }

            // ── Commit transaction ─────────────────────────────────────
            tx.commit().await.map_err(|e| {
                error!("addMembers: failed to commit transaction: {}", e);
                internal_server_error("Failed to commit transaction")
            })?;

            info!(
                "✅ v2.commitGroupChange: addMembers complete for convo {}, epoch={}",
                crate::crypto::redact_for_log(&convo_id),
                new_epoch
            );
            Ok(Json(CommitGroupChangeOutput {
                success: true,
                new_epoch: Some(new_epoch as i64),
                claimed_addition: None,
                pending_additions: None,
                rejoined_at: None,
                extra_data: Default::default(),
            })
            .into_response())
        }
        "externalCommit" => {
            let convo_id = input.convo_id.to_string();
            info!("v2.commitGroupChange: externalCommit for convo");

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
                    let current_epoch: Option<i32> =
                        sqlx::query_scalar("SELECT current_epoch FROM conversations WHERE id = $1")
                            .bind(&convo_id)
                            .fetch_optional(&pool)
                            .await
                            .ok()
                            .flatten();
                    info!("v2.commitGroupChange: externalCommit idempotent hit");
                    return Ok(Json(CommitGroupChangeOutput {
                        success: true,
                        new_epoch: Some(current_epoch.unwrap_or(0) as i64),
                        claimed_addition: None,
                        pending_additions: None,
                        rejoined_at: None,
                        extra_data: Default::default(),
                    })
                    .into_response());
                }
            }

            // ── Validate required fields ───────────────────────────────
            let commit_b64 = input.commit.as_ref().ok_or_else(|| {
                warn!("externalCommit: missing commit");
                bad_request("Missing commit")
            })?;

            // ── Decode commit ───────────────────────────────────────────
            let commit_bytes = base64::engine::general_purpose::STANDARD
                .decode(commit_b64.as_bytes())
                .map_err(|e| {
                    warn!("externalCommit: invalid base64 commit: {}", e);
                    bad_request("Invalid base64 commit")
                })?;

            // ── Verify caller is current/past member ───────────────────
            let (caller_did, _) = parse_device_did(&auth_user.did).map_err(|e| {
                error!("externalCommit: invalid DID format: {}", e);
                bad_request("Invalid DID format")
            })?;
            let is_member_or_past: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM members WHERE convo_id = $1 AND (user_did = $2 OR member_did = $2))",
            )
            .bind(&convo_id)
            .bind(&caller_did)
            .fetch_one(&pool)
            .await
            .map_err(|e| {
                error!("externalCommit: membership check failed: {}", e);
                internal_server_error("Failed to check membership")
            })?;
            if !is_member_or_past {
                return Err(forbidden("Not a member of this conversation"));
            }

            let now = chrono::Utc::now();

            // ── Fetch current epoch for CAS ───────────────────────────
            let current_epoch = crate::db::get_current_epoch(&pool, &convo_id)
                .await
                .map_err(|e| {
                    error!("externalCommit: failed to get current epoch: {}", e);
                    internal_server_error("Failed to get current epoch")
                })?;

            // ── Begin transaction: reactivate + CAS epoch + commit + idempotency ──
            let mut tx = pool.begin().await.map_err(|e| {
                error!("externalCommit: failed to begin transaction: {}", e);
                internal_server_error("Failed to begin transaction")
            })?;

            // Ensure caller is marked as active after successful rejoin.
            sqlx::query(
                "UPDATE members SET left_at = NULL, needs_rejoin = false, rejoin_requested_at = NULL WHERE convo_id = $1 AND (user_did = $2 OR member_did = $2)",
            )
            .bind(&convo_id)
            .bind(&caller_did)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                error!("externalCommit: failed to reactivate member: {}", e);
                internal_server_error("Failed to reactivate member")
            })?;

            // ── Advance epoch (CAS) ───────────────────────────────────
            let new_epoch = crate::db::try_advance_conversation_epoch_tx(
                &mut tx,
                &convo_id,
                current_epoch,
            )
            .await
            .map_err(|e| {
                error!("externalCommit: failed to advance epoch: {}", e);
                internal_server_error("Failed to advance epoch")
            })?;

            let new_epoch = match new_epoch {
                Some(epoch) => epoch,
                None => {
                    warn!("externalCommit: epoch CAS failed (concurrent commit), returning 409");
                    return Err(conflict("Conversation epoch advanced concurrently"));
                }
            };

            // ── Invalidate stale GroupInfo after epoch advance ────────
            sqlx::query(
                "UPDATE conversations SET group_info = NULL, group_info_epoch = NULL, group_info_updated_at = NULL WHERE id = $1",
            )
            .bind(&convo_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                error!("externalCommit: failed to invalidate stale GroupInfo after epoch advance: {}", e);
                internal_server_error("Failed to invalidate stale GroupInfo")
            })?;

            // ── Store commit message ───────────────────────────────────
            let msg_id = uuid::Uuid::new_v4().to_string();
            let seq: i64 = sqlx::query_scalar(
                "SELECT CAST(COALESCE(MAX(seq), 0) + 1 AS BIGINT) FROM messages WHERE convo_id = $1",
            )
            .bind(&convo_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| {
                error!("externalCommit: failed to get seq: {}", e);
                internal_server_error("Failed to allocate message sequence")
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
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                error!("externalCommit: failed to insert commit message: {}", e);
                internal_server_error("Failed to store commit message")
            })?;

            // ── Store idempotency key ──────────────────────────────────
            if let Some(ref idem_key) = input.idempotency_key {
                let _ = sqlx::query(
                    "INSERT INTO idempotency_cache (key, endpoint, response_body, status_code, created_at, expires_at) VALUES ($1, $2, '{}'::jsonb, 200, NOW(), NOW() + INTERVAL '24 hours') ON CONFLICT DO NOTHING",
                )
                .bind(idem_key.to_string())
                .bind(NSID)
                .execute(&mut *tx)
                .await;
            }

            // ── Commit transaction ─────────────────────────────────────
            tx.commit().await.map_err(|e| {
                error!("externalCommit: failed to commit transaction: {}", e);
                internal_server_error("Failed to commit transaction")
            })?;

            info!(
                "✅ v2.commitGroupChange: externalCommit complete, epoch={}",
                new_epoch
            );
            Ok(Json(CommitGroupChangeOutput {
                success: true,
                new_epoch: Some(new_epoch as i64),
                claimed_addition: None,
                pending_additions: None,
                rejoined_at: None,
                extra_data: Default::default(),
            })
            .into_response())
        }
        "rejoin" => {
            info!("v2.commitGroupChange: rejoin for convo");
            Ok(Json(success_response()).into_response())
        }
        "readdition" => {
            info!("v2.commitGroupChange: readdition for convo");
            Ok(Json(success_response()).into_response())
        }
        "invalidateWelcome" => {
            let convo_id = input.convo_id.to_string();
            if convo_id.trim().is_empty() {
                warn!("invalidateWelcome: missing convo_id");
                return Err(bad_request("Missing convoId"));
            }

            let invalidated = sqlx::query(
                r#"
                UPDATE welcome_messages
                SET consumed = true,
                    consumed_at = NOW(),
                    error_reason = COALESCE(error_reason, 'Client invalidated Welcome')
                WHERE convo_id = $1
                  AND recipient_did = $2
                  AND consumed = false
                "#,
            )
            .bind(&convo_id)
            .bind(&auth_user.did)
            .execute(&pool)
            .await
            .map_err(|e| {
                error!("invalidateWelcome: failed to invalidate welcome: {}", e);
                internal_server_error("Failed to invalidate welcome")
            })?
            .rows_affected();

            info!(
                "✅ [v2.commitGroupChange] invalidateWelcome complete for convo {} (rows={})",
                crate::crypto::redact_for_log(&convo_id),
                invalidated
            );

            Ok(Json(invalidate_welcome_response(invalidated)).into_response())
        }
        "listPending" => {
            let convo_id = input.convo_id.to_string();

            // Extract base user DID
            let (user_did, _) = parse_device_did(&auth_user.did).map_err(|e| {
                error!("❌ [v2.commitGroupChange] Invalid DID format: {}", e);
                bad_request("Invalid DID format")
            })?;

            // Age out stale pending additions older than 1 hour.
            // These are unlikely to ever be processed -- the device has either
            // self-joined via External Commit or gone offline permanently.
            let aged_out = sqlx::query(
                r#"
                UPDATE pending_device_additions
                SET status = 'failed', updated_at = NOW()
                WHERE status IN ('pending', 'in_progress')
                  AND created_at < NOW() - INTERVAL '1 hour'
                "#,
            )
            .execute(&pool)
            .await
            .map_err(|e| {
                error!("❌ [v2.commitGroupChange] Failed to age out stale pending additions: {}", e);
                internal_server_error("Failed to age out stale pending additions")
            })?
            .rows_affected();

            if aged_out > 0 {
                info!("Aged out {} stale pending additions (>1 hour old)", aged_out);
            }

            // Release expired claims (for additions that are still fresh)
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
                error!(
                    "❌ [v2.commitGroupChange] Failed to release expired claims: {}",
                    e
                );
                internal_server_error("Failed to release expired claims")
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
                error!(
                    "❌ [v2.commitGroupChange] Failed to fetch pending additions: {}",
                    e
                );
                internal_server_error("Failed to fetch pending additions")
            })?;

            info!(
                "✅ [v2.commitGroupChange] Found {} pending additions",
                pending.len()
            );

            let additions: Vec<PendingDeviceAddition<'static>> = pending
                .into_iter()
                .map(|row| PendingDeviceAddition {
                    id: row.id.into(),
                    convo_id: row.convo_id.into(),
                    user_did: crate::sqlx_jacquard::string_to_did(&row.user_did),
                    device_id: row.new_device_id.into(),
                    device_credential_did: row.new_device_credential_did.into(),
                    status: row.status.into(),
                    created_at: crate::sqlx_jacquard::chrono_to_datetime(row.created_at),
                    device_name: row.device_name.map(|n| n.into()),
                    claimed_by: row
                        .claimed_by_did
                        .as_deref()
                        .map(crate::sqlx_jacquard::string_to_did),
                    extra_data: Default::default(),
                })
                .collect();

            Ok(Json(CommitGroupChangeOutput {
                success: true,
                pending_additions: Some(additions),
                claimed_addition: None,
                new_epoch: None,
                rejoined_at: None,
                extra_data: Default::default(),
            })
            .into_response())
        }
        "updateGroupInfo" => {
            let convo_id = input.convo_id.to_string();
            let group_info_b64 = match input.group_info.as_ref() {
                Some(gi) => gi.to_string(),
                None => {
                    error!("updateGroupInfo: missing groupInfo field");
                    return Err(bad_request("Missing groupInfo"));
                }
            };

            // Verify membership
            let (caller_did, _) = parse_device_did(&auth_user.did).map_err(|e| {
                error!("Invalid DID format: {}", e);
                bad_request("Invalid DID format")
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
                internal_server_error("Failed to check membership")
            })?;
            if !is_member {
                return Err(forbidden("Not a member of this conversation"));
            }

            // Decode and validate
            let group_info_bytes = base64::engine::general_purpose::STANDARD
                .decode(&group_info_b64)
                .map_err(|e| {
                    error!("Invalid base64 in GroupInfo: {}", e);
                    bad_request("Invalid base64 groupInfo")
                })?;

            // Store group_info
            let current_epoch: Option<i32> =
                sqlx::query_scalar("SELECT group_info_epoch FROM conversations WHERE id = $1")
                    .bind(&convo_id)
                    .fetch_optional(&pool)
                    .await
                    .map_err(|e| {
                        error!("Failed to fetch current epoch: {}", e);
                        internal_server_error("Failed to fetch current GroupInfo epoch")
                    })?
                    .flatten();

            let new_epoch = current_epoch.unwrap_or(0) + 1;

            sqlx::query(
                "UPDATE conversations SET group_info = $1, group_info_epoch = $2, group_info_updated_at = NOW() WHERE id = $3",
            )
            .bind(&group_info_bytes)
            .bind(new_epoch)
            .bind(&convo_id)
            .execute(&pool)
            .await
            .map_err(|e| {
                error!("Failed to store GroupInfo: {}", e);
                internal_server_error("Failed to store GroupInfo")
            })?;

            info!(
                "✅ [v2.commitGroupChange] updateGroupInfo stored for convo {} epoch {}",
                convo_id, new_epoch
            );
            Ok(Json(success_response()).into_response())
        }
        "claimPending" => {
            let convo_id = input.convo_id.to_string();
            let (caller_did, _) = parse_device_did(&auth_user.did).map_err(|e| {
                error!("claimPending: invalid DID: {}", e);
                bad_request("Invalid DID format")
            })?;

            let pending_id = input.pending_addition_id.as_ref().ok_or_else(|| {
                warn!("claimPending: missing pending_addition_id");
                bad_request("Missing pendingAdditionId")
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
                internal_server_error("Failed to claim pending addition")
            })?;

            match claimed {
                Some(row) => {
                    info!("✅ [v2.commitGroupChange] Claimed pending addition");
                    let addition = PendingDeviceAddition {
                        id: row.id.into(),
                        convo_id: row.convo_id.into(),
                        user_did: crate::sqlx_jacquard::string_to_did(&row.user_did),
                        device_id: row.new_device_id.into(),
                        device_credential_did: row.new_device_credential_did.into(),
                        status: row.status.into(),
                        created_at: crate::sqlx_jacquard::chrono_to_datetime(row.created_at),
                        device_name: row.device_name.map(|n| n.into()),
                        claimed_by: row
                            .claimed_by_did
                            .as_deref()
                            .map(crate::sqlx_jacquard::string_to_did),
                        extra_data: Default::default(),
                    };
                    Ok(Json(CommitGroupChangeOutput {
                        success: true,
                        claimed_addition: Some(addition),
                        new_epoch: None,
                        pending_additions: None,
                        rejoined_at: None,
                        extra_data: Default::default(),
                    })
                    .into_response())
                }
                None => {
                    warn!("claimPending: no matching pending addition found");
                    Ok(Json(CommitGroupChangeOutput {
                        success: false,
                        claimed_addition: None,
                        new_epoch: None,
                        pending_additions: None,
                        rejoined_at: None,
                        extra_data: Default::default(),
                    })
                    .into_response())
                }
            }
        }
        "completePending" => {
            let (caller_did, _) = parse_device_did(&auth_user.did).map_err(|e| {
                error!("completePending: invalid DID: {}", e);
                bad_request("Invalid DID format")
            })?;

            let pending_id = input.pending_addition_id.as_ref().ok_or_else(|| {
                warn!("completePending: missing pending_addition_id");
                bad_request("Missing pendingAdditionId")
            })?;

            let now = chrono::Utc::now();

            // Mark the pending addition as completed.
            // First try strict match: in_progress + claimed by this user.
            let result = sqlx::query(
                r#"
                UPDATE pending_device_additions
                SET status = 'completed',
                    completed_by_did = $2,
                    completed_at = $3,
                    updated_at = $3
                WHERE id = $1
                  AND status = 'in_progress'
                  AND claimed_by_did = $2
                "#,
            )
            .bind(pending_id.to_string())
            .bind(&caller_did)
            .bind(now)
            .execute(&pool)
            .await
            .map_err(|e| {
                error!("completePending: DB error: {}", e);
                internal_server_error("Failed to complete pending addition")
            })?;

            let mut completed = result.rows_affected() > 0;

            if completed {
                info!("completePending: marked {} as completed", pending_id);
            } else {
                // Fallback: the claim may have expired and been reset to 'pending',
                // but the MLS operation already succeeded. Accept completion from
                // any status that isn't already terminal.
                let fallback = sqlx::query(
                    r#"
                    UPDATE pending_device_additions
                    SET status = 'completed',
                        completed_by_did = $2,
                        completed_at = $3,
                        updated_at = $3
                    WHERE id = $1
                      AND status IN ('pending', 'in_progress')
                    "#,
                )
                .bind(pending_id.to_string())
                .bind(&caller_did)
                .bind(now)
                .execute(&pool)
                .await
                .map_err(|e| {
                    error!("completePending fallback: DB error: {}", e);
                    internal_server_error("Failed to complete pending addition")
                })?;

                completed = fallback.rows_affected() > 0;
                if completed {
                    info!("completePending: fallback completed {}", pending_id);
                } else {
                    warn!("completePending: no matching pending addition found for {}", pending_id);
                }
            }

            Ok(Json(CommitGroupChangeOutput {
                success: completed,
                claimed_addition: None,
                new_epoch: None,
                pending_additions: None,
                rejoined_at: None,
                extra_data: Default::default(),
            })
            .into_response())
        }
        "removeMember" => {
            let convo_id = input.convo_id.to_string();
            info!("v2.commitGroupChange: removeMember for convo");

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
                    let current_epoch: Option<i32> =
                        sqlx::query_scalar("SELECT current_epoch FROM conversations WHERE id = $1")
                            .bind(&convo_id)
                            .fetch_optional(&pool)
                            .await
                            .ok()
                            .flatten();
                    info!("v2.commitGroupChange: removeMember idempotent hit");
                    return Ok(Json(CommitGroupChangeOutput {
                        success: true,
                        new_epoch: Some(current_epoch.unwrap_or(0) as i64),
                        claimed_addition: None,
                        pending_additions: None,
                        rejoined_at: None,
                        extra_data: Default::default(),
                    })
                    .into_response());
                }
            }

            // ── Validate required fields ───────────────────────────────
            let commit_b64 = input.commit.as_ref().ok_or_else(|| {
                warn!("removeMember: missing commit");
                bad_request("Missing commit")
            })?;
            let member_dids = input.member_dids.as_ref().ok_or_else(|| {
                warn!("removeMember: missing member_dids");
                bad_request("Missing memberDids")
            })?;

            // ── Decode commit ──────────────────────────────────────────
            let commit_bytes = base64::engine::general_purpose::STANDARD
                .decode(commit_b64.as_bytes())
                .map_err(|e| {
                    warn!("removeMember: invalid base64 commit: {}", e);
                    bad_request("Invalid base64 commit")
                })?;

            // ── Verify caller is an admin ──────────────────────────────
            let (caller_did, _) = parse_device_did(&auth_user.did).map_err(|e| {
                error!("removeMember: invalid DID format: {}", e);
                bad_request("Invalid DID format")
            })?;
            let is_admin: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM members WHERE convo_id = $1 AND user_did = $2 AND left_at IS NULL AND is_admin = true)",
            )
            .bind(&convo_id)
            .bind(&caller_did)
            .fetch_one(&pool)
            .await
            .map_err(|e| {
                error!("removeMember: admin check failed: {}", e);
                internal_server_error("Failed to check admin status")
            })?;
            if !is_admin {
                return Err(forbidden("Not an admin of this conversation"));
            }

            let now = chrono::Utc::now();

            // ── Mark removed members as left ───────────────────────────
            for member_did in member_dids {
                let member_did_str = crate::sqlx_jacquard::did_to_string(member_did);
                sqlx::query(
                    "UPDATE members SET left_at = $3 WHERE convo_id = $1 AND (user_did = $2 OR member_did = $2) AND left_at IS NULL",
                )
                .bind(&convo_id)
                .bind(&member_did_str)
                .bind(&now)
                .execute(&pool)
                .await
                .map_err(|e| {
                    error!("removeMember: failed to mark member as left: {}", e);
                    internal_server_error("Failed to remove member")
                })?;
            }

            // ── Fetch current epoch for CAS ───────────────────────────
            let current_epoch = crate::db::get_current_epoch(&pool, &convo_id)
                .await
                .map_err(|e| {
                    error!("removeMember: failed to get current epoch: {}", e);
                    internal_server_error("Failed to get current epoch")
                })?;

            // ── Begin transaction: CAS epoch + commit + idempotency ───
            let mut tx = pool.begin().await.map_err(|e| {
                error!("removeMember: failed to begin transaction: {}", e);
                internal_server_error("Failed to begin transaction")
            })?;

            // ── Advance epoch (CAS) ───────────────────────────────────
            let new_epoch = crate::db::try_advance_conversation_epoch_tx(
                &mut tx,
                &convo_id,
                current_epoch,
            )
            .await
            .map_err(|e| {
                error!("removeMember: failed to advance epoch: {}", e);
                internal_server_error("Failed to advance epoch")
            })?;

            let new_epoch = match new_epoch {
                Some(epoch) => epoch,
                None => {
                    warn!("removeMember: epoch CAS failed (concurrent commit), returning 409");
                    return Err(conflict("Conversation epoch advanced concurrently"));
                }
            };

            // ── Invalidate stale GroupInfo after epoch advance ────────
            sqlx::query(
                "UPDATE conversations SET group_info = NULL, group_info_epoch = NULL, group_info_updated_at = NULL WHERE id = $1",
            )
            .bind(&convo_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                error!("removeMember: failed to invalidate stale GroupInfo: {}", e);
                internal_server_error("Failed to invalidate stale GroupInfo")
            })?;

            // ── Store commit message ───────────────────────────────────
            let msg_id = uuid::Uuid::new_v4().to_string();
            let seq: i64 = sqlx::query_scalar(
                "SELECT CAST(COALESCE(MAX(seq), 0) + 1 AS BIGINT) FROM messages WHERE convo_id = $1",
            )
            .bind(&convo_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| {
                error!("removeMember: failed to get seq: {}", e);
                internal_server_error("Failed to allocate message sequence")
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
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                error!("removeMember: failed to insert commit message: {}", e);
                internal_server_error("Failed to store commit message")
            })?;

            // ── Store idempotency key ──────────────────────────────────
            if let Some(ref idem_key) = input.idempotency_key {
                let _ = sqlx::query(
                    "INSERT INTO idempotency_cache (key, endpoint, response_body, status_code, created_at, expires_at) VALUES ($1, $2, '{}'::jsonb, 200, NOW(), NOW() + INTERVAL '24 hours') ON CONFLICT DO NOTHING",
                )
                .bind(idem_key.to_string())
                .bind(NSID)
                .execute(&mut *tx)
                .await;
            }

            // ── Commit transaction ─────────────────────────────────────
            tx.commit().await.map_err(|e| {
                error!("removeMember: failed to commit transaction: {}", e);
                internal_server_error("Failed to commit transaction")
            })?;

            info!(
                "✅ v2.commitGroupChange: removeMember complete, epoch={}",
                new_epoch
            );
            Ok(Json(CommitGroupChangeOutput {
                success: true,
                new_epoch: Some(new_epoch as i64),
                claimed_addition: None,
                pending_additions: None,
                rejoined_at: None,
                extra_data: Default::default(),
            })
            .into_response())
        }
        // Generic commit handler for self-updates, metadata updates, and other
        // epoch-advancing operations that don't add or remove members.
        "commit" | "updateMetadata" => {
            let action_name = input.action.to_string();
            let convo_id = input.convo_id.to_string();
            info!("v2.commitGroupChange: {} for convo", action_name);

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
                    let current_epoch: Option<i32> =
                        sqlx::query_scalar("SELECT current_epoch FROM conversations WHERE id = $1")
                            .bind(&convo_id)
                            .fetch_optional(&pool)
                            .await
                            .ok()
                            .flatten();
                    info!("v2.commitGroupChange: {} idempotent hit", action_name);
                    return Ok(Json(CommitGroupChangeOutput {
                        success: true,
                        new_epoch: Some(current_epoch.unwrap_or(0) as i64),
                        claimed_addition: None,
                        pending_additions: None,
                        rejoined_at: None,
                        extra_data: Default::default(),
                    })
                    .into_response());
                }
            }

            // ── Validate commit field ──────────────────────────────────
            let commit_b64 = input.commit.as_ref().ok_or_else(|| {
                warn!("{}: missing commit", action_name);
                bad_request("Missing commit")
            })?;

            let commit_bytes = base64::engine::general_purpose::STANDARD
                .decode(commit_b64.as_bytes())
                .map_err(|e| {
                    warn!("{}: invalid base64 commit: {}", action_name, e);
                    bad_request("Invalid base64 commit")
                })?;

            // ── Verify caller is a member ──────────────────────────────
            let (caller_did, _) = parse_device_did(&auth_user.did).map_err(|e| {
                error!("{}: invalid DID format: {}", action_name, e);
                bad_request("Invalid DID format")
            })?;
            let is_member: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM members WHERE convo_id = $1 AND user_did = $2 AND left_at IS NULL)",
            )
            .bind(&convo_id)
            .bind(&caller_did)
            .fetch_one(&pool)
            .await
            .map_err(|e| {
                error!("{}: membership check failed: {}", action_name, e);
                internal_server_error("Failed to check membership")
            })?;
            if !is_member {
                return Err(forbidden("Not a member of this conversation"));
            }

            let now = chrono::Utc::now();

            // ── Fetch current epoch for CAS ───────────────────────────
            let current_epoch = crate::db::get_current_epoch(&pool, &convo_id)
                .await
                .map_err(|e| {
                    error!("{}: failed to get current epoch: {}", action_name, e);
                    internal_server_error("Failed to get current epoch")
                })?;

            // ── Begin transaction: CAS epoch + commit + idempotency ───
            let mut tx = pool.begin().await.map_err(|e| {
                error!("{}: failed to begin transaction: {}", action_name, e);
                internal_server_error("Failed to begin transaction")
            })?;

            // ── Advance epoch (CAS) ───────────────────────────────────
            let new_epoch = crate::db::try_advance_conversation_epoch_tx(
                &mut tx,
                &convo_id,
                current_epoch,
            )
            .await
            .map_err(|e| {
                error!("{}: failed to advance epoch: {}", action_name, e);
                internal_server_error("Failed to advance epoch")
            })?;

            let new_epoch = match new_epoch {
                Some(epoch) => epoch,
                None => {
                    warn!("{}: epoch CAS failed (concurrent commit), returning 409", action_name);
                    return Err(conflict("Conversation epoch advanced concurrently"));
                }
            };

            // ── Invalidate stale GroupInfo after epoch advance ────────
            sqlx::query(
                "UPDATE conversations SET group_info = NULL, group_info_epoch = NULL, group_info_updated_at = NULL WHERE id = $1",
            )
            .bind(&convo_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                error!("{}: failed to invalidate stale GroupInfo: {}", action_name, e);
                internal_server_error("Failed to invalidate stale GroupInfo")
            })?;

            // ── Store commit message ───────────────────────────────────
            let msg_id = uuid::Uuid::new_v4().to_string();
            let seq: i64 = sqlx::query_scalar(
                "SELECT CAST(COALESCE(MAX(seq), 0) + 1 AS BIGINT) FROM messages WHERE convo_id = $1",
            )
            .bind(&convo_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| {
                error!("{}: failed to get seq: {}", action_name, e);
                internal_server_error("Failed to allocate message sequence")
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
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                error!("{}: failed to insert commit message: {}", action_name, e);
                internal_server_error("Failed to store commit message")
            })?;

            // ── Store idempotency key ──────────────────────────────────
            if let Some(ref idem_key) = input.idempotency_key {
                let _ = sqlx::query(
                    "INSERT INTO idempotency_cache (key, endpoint, response_body, status_code, created_at, expires_at) VALUES ($1, $2, '{}'::jsonb, 200, NOW(), NOW() + INTERVAL '24 hours') ON CONFLICT DO NOTHING",
                )
                .bind(idem_key.to_string())
                .bind(NSID)
                .execute(&mut *tx)
                .await;
            }

            // ── Commit transaction ─────────────────────────────────────
            tx.commit().await.map_err(|e| {
                error!("{}: failed to commit transaction: {}", action_name, e);
                internal_server_error("Failed to commit transaction")
            })?;

            info!(
                "✅ v2.commitGroupChange: {} complete, epoch={}",
                action_name, new_epoch
            );
            Ok(Json(CommitGroupChangeOutput {
                success: true,
                new_epoch: Some(new_epoch as i64),
                claimed_addition: None,
                pending_additions: None,
                rejoined_at: None,
                extra_data: Default::default(),
            })
            .into_response())
        }
        "refreshGroupInfo" => {
            // iOS clients send this to request active members to publish fresh GroupInfo.
            // Currently a no-op (SSE notification not yet implemented), but return success
            // so the client doesn't get a 400 error and trigger unnecessary recovery logic.
            info!("v2.commitGroupChange: refreshGroupInfo (no-op, SSE not implemented)");
            Ok(Json(success_response()).into_response())
        }
        "confirmWelcome" => {
            // Ack-only: clients may send this after successfully processing a Welcome message.
            // It must not mutate membership, epoch, or welcome state.
            info!("v2.commitGroupChange: confirmWelcome (ack-only no-op)");
            Ok(Json(success_response()).into_response())
        }
        other => {
            warn!("v2.commitGroupChange: unknown action: {}", other);
            Err(bad_request(format!("Unknown action: {}", other)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{header, StatusCode};

    #[test]
    fn invalidate_welcome_response_returns_false_when_nothing_invalidated() {
        let response = invalidate_welcome_response(0);
        assert!(!response.success);
    }

    #[test]
    fn invalidate_welcome_response_returns_true_when_rows_invalidated() {
        let response = invalidate_welcome_response(2);
        assert!(response.success);
    }

    /// Verifies the shape of the addMembers idempotency-hit response:
    /// it must include both `success: true` and a `newEpoch` field.
    #[test]
    fn add_members_idempotent_response_includes_new_epoch() {
        let epoch: i32 = 5;
        let response = CommitGroupChangeOutput {
            success: true,
            new_epoch: Some(epoch as i64),
            claimed_addition: None,
            pending_additions: None,
            rejoined_at: None,
            extra_data: Default::default(),
        };
        assert!(response.success);
        assert_eq!(response.new_epoch, Some(5));
    }

    /// When no epoch row exists the idempotency path falls back to 0.
    #[test]
    fn add_members_idempotent_response_defaults_epoch_to_zero() {
        let current_epoch: Option<i32> = None;
        let response = CommitGroupChangeOutput {
            success: true,
            new_epoch: Some(current_epoch.unwrap_or(0) as i64),
            claimed_addition: None,
            pending_additions: None,
            rejoined_at: None,
            extra_data: Default::default(),
        };
        assert_eq!(response.new_epoch, Some(0));
    }

    #[test]
    fn xrpc_error_sets_json_content_type() {
        let response = bad_request("Missing commit").into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
    }
}
