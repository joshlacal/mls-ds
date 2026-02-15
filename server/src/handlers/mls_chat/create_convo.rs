use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use base64::Engine;
use chrono::{DateTime, Utc};
use jacquard_axum::ExtractXrpc;
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::{
    admin_system::verify_is_admin,
    auth::AuthUser,
    block_sync::BlockSyncService,
    generated::blue_catbird::mlsChat::create_convo::CreateConvoRequest,
    sqlx_jacquard::{chrono_to_datetime, did_to_string},
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.createConvo";

// ---------------------------------------------------------------------------
// Handler (v2 – inline SQL, no v1 delegation)
// ---------------------------------------------------------------------------

/// Consolidated conversation creation and invite management endpoint.
///
/// POST /xrpc/blue.catbird.mlsChat.createConvo
///
/// The generated CreateConvo type is used for direct creation. Invite management
/// actions are dispatched via the optional `invite.action` field.
#[tracing::instrument(skip(pool, block_sync, auth_user, input))]
pub async fn create_convo(
    State(pool): State<DbPool>,
    State(block_sync): State<Arc<BlockSyncService>>,
    auth_user: AuthUser,
    ExtractXrpc(input): ExtractXrpc<CreateConvoRequest>,
) -> Response {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        error!("❌ [v2.createConvo] Unauthorized");
        return StatusCode::UNAUTHORIZED.into_response();
    }

    // ── Invite revocation branch ─────────────────────────────────────────
    if let Some(ref invite) = input.invite {
        if invite.action.as_ref() == "revoke" {
            return handle_revoke_invite(&pool, &auth_user, invite).await;
        }
        // "create" or unknown action – fall through to create convo flow
    }

    // ── Standard conversation creation ───────────────────────────────────
    match handle_create_convo(pool, block_sync, auth_user, &input).await {
        Ok(json) => Json(json).into_response(),
        Err(resp) => resp,
    }
}

// ---------------------------------------------------------------------------
// Revoke invite (inline – replaces v1 revoke_invite delegation)
// ---------------------------------------------------------------------------

async fn handle_revoke_invite(
    pool: &DbPool,
    auth_user: &AuthUser,
    invite: &crate::generated::blue_catbird::mlsChat::create_convo::InviteAction<'_>,
) -> Response {
    let invite_id = invite.code.as_deref().unwrap_or_default().to_string();
    let caller_did = &auth_user.did;

    info!(invite_id = %invite_id, caller = %caller_did, "v2.createConvo: revoking invite");

    // Get conversation ID from invite
    let convo_id: Option<String> =
        sqlx::query_scalar("SELECT convo_id FROM invites WHERE id = $1")
            .bind(&invite_id)
            .fetch_optional(pool)
            .await
            .unwrap_or(None);

    let convo_id = match convo_id {
        Some(cid) => cid,
        None => {
            warn!("Invite not found: {}", invite_id);
            return (StatusCode::NOT_FOUND, "Invite not found").into_response();
        }
    };

    // Verify caller is admin
    if let Err(e) = verify_is_admin(pool, &convo_id, caller_did).await {
        error!("Admin verification failed: {:?}", e);
        return (StatusCode::FORBIDDEN, "Not an admin").into_response();
    }

    // Revoke the invite
    let rows_affected = match sqlx::query(
        r#"UPDATE invites
           SET revoked = true, revoked_at = NOW(), revoked_by_did = $1
           WHERE id = $2 AND revoked = false"#,
    )
    .bind(caller_did)
    .bind(&invite_id)
    .execute(pool)
    .await
    {
        Ok(r) => r.rows_affected(),
        Err(e) => {
            error!("Database error revoking invite: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    if rows_affected == 0 {
        warn!("Invite already revoked or not found: {}", invite_id);
        return (StatusCode::NOT_FOUND, "Invite already revoked or not found").into_response();
    }

    info!(invite_id = %invite_id, convo_id = %convo_id, "Invite revoked successfully");
    Json(serde_json::json!({"success": true})).into_response()
}

// ---------------------------------------------------------------------------
// Create conversation (inline – replaces v1 create_convo delegation)
// ---------------------------------------------------------------------------

async fn handle_create_convo(
    pool: DbPool,
    block_sync: Arc<BlockSyncService>,
    auth_user: AuthUser,
    input: &crate::generated::blue_catbird::mlsChat::create_convo::CreateConvo<'_>,
) -> Result<serde_json::Value, Response> {
    tracing::debug!("🔷 [v2.createConvo] incoming create request");

    info!(
        creator = %crate::crypto::redact_for_log(&auth_user.did),
        group = %crate::crypto::redact_for_log(&input.group_id),
        initial_members = input.initial_members.as_ref().map(|m| m.len()).unwrap_or(0),
        has_welcome = input.welcome_message.is_some(),
        "[v2.createConvo] start"
    );

    // Parse creator DID
    let creator_did: String = auth_user.did.clone();

    // Validate cipher suite
    let valid_suites = [
        "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        "MLS_128_DHKEMP256_AES128GCM_SHA256_P256",
        "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
    ];
    if !valid_suites.contains(&input.cipher_suite.as_str()) {
        warn!("❌ [v2.createConvo] Invalid cipher suite: {}", input.cipher_suite);
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "InvalidCipherSuite",
                "message": format!("Cipher suite '{}' is not supported", input.cipher_suite)
            })),
        )
            .into_response());
    }

    // Validate initial members count
    if let Some(ref members) = input.initial_members {
        let total_member_count = members.len() + 1;
        let max_members = 1000;
        if total_member_count > max_members {
            warn!("❌ [v2.createConvo] Too many members: {}", total_member_count);
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "TooManyMembers",
                    "message": format!("Cannot add more than {} initial members (got {} including creator)", max_members, total_member_count)
                })),
            )
                .into_response());
        }
    }

    // ── Block detection ──────────────────────────────────────────────────
    let mut all_member_dids_for_block_check = vec![auth_user.did.clone()];
    if let Some(ref members) = input.initial_members {
        for member_did in members.iter() {
            let member_did_str = did_to_string(member_did);
            if member_did_str != auth_user.did {
                all_member_dids_for_block_check.push(member_did_str);
            }
        }
    }

    if all_member_dids_for_block_check.len() > 1 {
        match block_sync
            .check_block_conflicts(&all_member_dids_for_block_check)
            .await
        {
            Ok(conflicts) => {
                if !conflicts.is_empty() {
                    for (blocker, _blocked) in &conflicts {
                        if let Err(e) = block_sync.sync_blocks_to_db(&pool, blocker).await {
                            warn!("Failed to sync blocks to DB: {}", e);
                        }
                    }
                    warn!(
                        "❌ [v2.createConvo] Block detected: {} blocks found via PDS",
                        conflicts.len()
                    );
                    return Err((
                        StatusCode::FORBIDDEN,
                        Json(serde_json::json!({
                            "error": "MutualBlockDetected",
                            "message": "Cannot create conversation: one or more members have blocked each other"
                        })),
                    )
                        .into_response());
                }
            }
            Err(e) => {
                // Fallback to local DB
                warn!("PDS block check failed, falling back to local DB: {}", e);
                let blocks: Vec<(String, String)> = sqlx::query_as(
                    "SELECT user_did, target_did FROM bsky_blocks WHERE user_did = ANY($1) AND target_did = ANY($1)",
                )
                .bind(&all_member_dids_for_block_check)
                .fetch_all(&pool)
                .await
                .map_err(|e| {
                    error!("❌ [v2.createConvo] Failed to check blocks: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                })?;

                if !blocks.is_empty() {
                    warn!("❌ [v2.createConvo] Block detected: {} blocks (DB cache)", blocks.len());
                    return Err((
                        StatusCode::FORBIDDEN,
                        Json(serde_json::json!({
                            "error": "MutualBlockDetected",
                            "message": "Cannot create conversation: one or more members have blocked each other"
                        })),
                    )
                        .into_response());
                }
            }
        }
    }

    // ── Conversation ID and metadata ─────────────────────────────────────
    let convo_id = input.group_id.to_string();
    let now = Utc::now();

    let (name, description) = if let Some(ref meta) = input.metadata {
        (
            meta.name.as_deref().map(String::from),
            meta.description.as_deref().map(String::from),
        )
    } else {
        (None, None)
    };

    // ── Idempotency check (group_id is the primary key) ──────────────────
    // Check if conversation already exists with this group_id
    let existing: Option<String> =
        sqlx::query_scalar("SELECT id FROM conversations WHERE id = $1")
            .bind(&convo_id)
            .fetch_optional(&pool)
            .await
            .map_err(|e| {
                error!("❌ [v2.createConvo] idempotency check: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            })?;

    if existing.is_some() {
        tracing::debug!("📍 [v2.createConvo] Idempotency: returning existing conversation");

        // Fetch existing members
        let existing_members: Vec<(String, String, Option<String>, Option<String>, DateTime<Utc>, bool, Option<i32>)> = sqlx::query_as(
            "SELECT member_did, user_did, device_id, device_name, joined_at, is_admin, leaf_index
             FROM members WHERE convo_id = $1 AND left_at IS NULL ORDER BY joined_at",
        )
        .bind(&convo_id)
        .fetch_all(&pool)
        .await
        .map_err(|e| {
            error!("❌ [v2.createConvo] fetch existing members: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?;

        let members_json: Vec<serde_json::Value> = existing_members
            .into_iter()
            .map(|(member_did, user_did, device_id, device_name, joined_at, is_admin, leaf_index)| {
                serde_json::json!({
                    "did": member_did,
                    "userDid": user_did,
                    "deviceId": device_id,
                    "deviceName": device_name,
                    "joinedAt": chrono_to_datetime(joined_at).to_string(),
                    "isAdmin": is_admin,
                    "leafIndex": leaf_index,
                    "isModerator": false,
                })
            })
            .collect();

        let mut convo_json = serde_json::json!({
            "convo": {
                "groupId": convo_id,
                "creator": creator_did,
                "members": members_json,
                "epoch": 0,
                "cipherSuite": input.cipher_suite.as_ref(),
                "createdAt": chrono_to_datetime(now).to_string(),
            }
        });

        if name.is_some() || description.is_some() {
            convo_json["convo"]["metadata"] = serde_json::json!({
                "name": name,
                "description": description,
            });
        }

        return Ok(convo_json);
    }

    // ── Create conversation ──────────────────────────────────────────────
    tracing::debug!("📍 [v2.createConvo] creating conversation in database");

    sqlx::query(
        "INSERT INTO conversations (id, creator_did, current_epoch, created_at, updated_at, name, cipher_suite, sequencer_ds, is_remote)
         VALUES ($1, $2, 0, $3, $3, $4, $5, NULL, false)",
    )
    .bind(&convo_id)
    .bind(&auth_user.did)
    .bind(&now)
    .bind(&name)
    .bind(input.cipher_suite.as_ref())
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("❌ [v2.createConvo] Failed to create conversation: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;

    // ── Add creator as admin member ──────────────────────────────────────
    tracing::debug!("📍 [v2.createConvo] adding creator membership");
    sqlx::query(
        "INSERT INTO members (convo_id, member_did, user_did, joined_at, is_admin) VALUES ($1, $2, $3, $4, true)",
    )
    .bind(&convo_id)
    .bind(&auth_user.did)
    .bind(&auth_user.did)
    .bind(&now)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("❌ [v2.createConvo] Failed to add creator membership: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;

    let mut members_json = vec![serde_json::json!({
        "did": creator_did,
        "userDid": creator_did,
        "joinedAt": chrono_to_datetime(now).to_string(),
        "isAdmin": true,
        "isModerator": false,
        "leafIndex": 0,
    })];

    // ── Add initial members ──────────────────────────────────────────────
    if let Some(ref initial_members) = input.initial_members {
        tracing::debug!("📍 [v2.createConvo] adding initial members");
        for (idx, member_did) in initial_members.iter().enumerate() {
            let member_did_str = did_to_string(member_did);

            if member_did_str == auth_user.did {
                continue;
            }

            info!("📍 [v2.createConvo] Adding member {}", idx + 1);
            sqlx::query(
                "INSERT INTO members (convo_id, member_did, user_did, joined_at, is_admin) VALUES ($1, $2, $3, $4, false)",
            )
            .bind(&convo_id)
            .bind(&member_did_str)
            .bind(&member_did_str)
            .bind(&now)
            .execute(&pool)
            .await
            .map_err(|e| {
                error!("❌ [v2.createConvo] Failed to add member: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            })?;

            members_json.push(serde_json::json!({
                "did": member_did_str,
                "userDid": member_did_str,
                "joinedAt": chrono_to_datetime(now).to_string(),
                "isAdmin": false,
                "isModerator": false,
                "leafIndex": idx + 1,
            }));
        }
    }

    // ── Store Welcome message ────────────────────────────────────────────
    if let Some(ref welcome_b64) = input.welcome_message {
        info!("📍 [v2.createConvo] Processing Welcome message...");

        let welcome_data = base64::engine::general_purpose::STANDARD
            .decode(&**welcome_b64)
            .map_err(|e| {
                warn!("❌ [v2.createConvo] Invalid base64 welcome: {}", e);
                StatusCode::BAD_REQUEST.into_response()
            })?;

        info!(
            "📨 [v2.createConvo] Welcome message for convo {}: {} bytes",
            input.group_id,
            welcome_data.len()
        );

        // Validate key packages
        if let Some(ref kp_hashes) = input.key_package_hashes {
            info!(
                "📍 [v2.createConvo] Validating {} key packages...",
                kp_hashes.len()
            );
            for entry in kp_hashes {
                let member_did_str = did_to_string(&entry.did);
                let hash_hex: &str = &entry.hash;

                let available: bool = sqlx::query_scalar(
                    r#"SELECT EXISTS(
                        SELECT 1 FROM key_packages
                        WHERE owner_did = $1
                          AND key_package_hash = $2
                          AND consumed_at IS NULL
                          AND (reserved_at IS NULL OR reserved_at < NOW() - INTERVAL '5 minutes')
                    )"#,
                )
                .bind(&member_did_str)
                .bind(hash_hex)
                .fetch_one(&pool)
                .await
                .map_err(|e| {
                    error!("❌ [v2.createConvo] key package check: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                })?;

                if !available {
                    let available_count: i64 = sqlx::query_scalar(
                        r#"SELECT COUNT(*) FROM key_packages
                           WHERE owner_did = $1
                             AND consumed_at IS NULL
                             AND (reserved_at IS NULL OR reserved_at < NOW() - INTERVAL '5 minutes')"#,
                    )
                    .bind(&member_did_str)
                    .fetch_one(&pool)
                    .await
                    .unwrap_or(0);

                    warn!(
                        "❌ [v2.createConvo] Key package not available for {}: available={}",
                        crate::crypto::redact_for_log(&member_did_str),
                        available_count
                    );
                    return Err((
                        StatusCode::CONFLICT,
                        Json(serde_json::json!({
                            "error": "KeyPackageNotFound",
                            "message": format!(
                                "Key package not available for {}: hash={}. Server has {} available.",
                                member_did_str, hash_hex, available_count
                            )
                        })),
                    )
                        .into_response());
                }
            }
            info!("✅ [v2.createConvo] All {} key packages available", kp_hashes.len());
        }

        // Collect all member DIDs (creator + initial_members)
        let mut all_member_dids = vec![auth_user.did.clone()];
        if let Some(ref member_list) = input.initial_members {
            for member_did in member_list.iter() {
                let member_did_str = did_to_string(member_did);
                if member_did_str != auth_user.did {
                    all_member_dids.push(member_did_str);
                }
            }
        }

        info!(
            "📍 [v2.createConvo] Storing Welcome for {} total members",
            all_member_dids.len()
        );

        for member_did_str in all_member_dids.iter() {
            let member_hashes: Vec<Vec<u8>> = input
                .key_package_hashes
                .as_ref()
                .map(|hashes| {
                    hashes
                        .iter()
                        .filter(|entry| did_to_string(&entry.did) == *member_did_str)
                        .filter_map(|entry| hex::decode(&*entry.hash).ok())
                        .collect()
                })
                .unwrap_or_default();

            if member_hashes.is_empty() {
                let welcome_id = uuid::Uuid::new_v4().to_string();
                sqlx::query(
                    "INSERT INTO welcome_messages (id, convo_id, recipient_did, welcome_data, key_package_hash, created_at)
                     VALUES ($1, $2, $3, $4, $5, $6)
                     ON CONFLICT (convo_id, recipient_did, COALESCE(key_package_hash, '\\x00'::bytea)) WHERE consumed = false
                     DO NOTHING",
                )
                .bind(&welcome_id)
                .bind(&convo_id)
                .bind(member_did_str)
                .bind(&welcome_data)
                .bind::<Option<Vec<u8>>>(None)
                .bind(&now)
                .execute(&pool)
                .await
                .map_err(|e| {
                    error!("❌ [v2.createConvo] store welcome for {}: {}", crate::crypto::redact_for_log(member_did_str), e);
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                })?;
            } else {
                for hash in member_hashes {
                    let welcome_id = uuid::Uuid::new_v4().to_string();
                    sqlx::query(
                        "INSERT INTO welcome_messages (id, convo_id, recipient_did, welcome_data, key_package_hash, created_at)
                         VALUES ($1, $2, $3, $4, $5, $6)
                         ON CONFLICT (convo_id, recipient_did, COALESCE(key_package_hash, '\\x00'::bytea)) WHERE consumed = false
                         DO NOTHING",
                    )
                    .bind(&welcome_id)
                    .bind(&convo_id)
                    .bind(member_did_str)
                    .bind(&welcome_data)
                    .bind(Some(hash))
                    .bind(&now)
                    .execute(&pool)
                    .await
                    .map_err(|e| {
                        error!("❌ [v2.createConvo] store welcome for {}: {}", crate::crypto::redact_for_log(member_did_str), e);
                        StatusCode::INTERNAL_SERVER_ERROR.into_response()
                    })?;
                }
            }
        }

        // Mark key packages as consumed
        if let Some(ref kp_hashes) = input.key_package_hashes {
            for entry in kp_hashes {
                let member_did_str = did_to_string(&entry.did);
                let hash_hex: &str = &entry.hash;

                match crate::db::mark_key_package_consumed(&pool, &member_did_str, hash_hex).await {
                    Ok(consumed) => {
                        if consumed {
                            tracing::debug!(
                                "✅ [v2.createConvo] key package consumed for {}",
                                crate::crypto::redact_for_log(&member_did_str)
                            );
                        } else {
                            tracing::warn!(
                                "⚠️ [v2.createConvo] key package not found/already consumed for {}",
                                crate::crypto::redact_for_log(&member_did_str)
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!("⚠️ [v2.createConvo] mark key package consumed: {}", e);
                    }
                }
            }
        }
    }

    info!(
        convo = %crate::crypto::redact_for_log(&convo_id),
        member_count = members_json.len(),
        epoch = 0,
        "✅ [v2.createConvo] complete"
    );

    // ── Build response ───────────────────────────────────────────────────
    let mut convo_json = serde_json::json!({
        "convo": {
            "groupId": convo_id,
            "creator": creator_did,
            "members": members_json,
            "epoch": 0,
            "cipherSuite": input.cipher_suite.as_ref(),
            "createdAt": chrono_to_datetime(now).to_string(),
        }
    });

    if name.is_some() || description.is_some() {
        convo_json["convo"]["metadata"] = serde_json::json!({
            "name": name,
            "description": description,
        });
    }

    Ok(convo_json)
}
