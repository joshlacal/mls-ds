use base64::Engine;

use axum::{extract::State, http::StatusCode, Json};
use std::sync::Arc;
use tokio::sync::oneshot;
use tracing::{info, warn, error};

use crate::{
    actors::{ActorRegistry, ConvoMessage, KeyPackageHashEntry},
    auth::AuthUser,
    error_responses::AddMembersError,
    generated::blue::catbird::mls::add_members::{Input as AddMembersInput, Output as AddMembersOutput, OutputData, Error},
    storage::{get_current_epoch, is_member, DbPool},
};

/// Add members to an existing conversation
/// POST /xrpc/chat.bsky.convo.addMembers
#[tracing::instrument(skip(pool, actor_registry))]
pub async fn add_members(
    State(pool): State<DbPool>,
    State(actor_registry): State<Arc<ActorRegistry>>,
    auth_user: AuthUser,
    Json(input): Json<AddMembersInput>,
) -> Result<Json<AddMembersOutput>, AddMembersError> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, "blue.catbird.mls.addMembers") {
        return Err(StatusCode::UNAUTHORIZED.into());
    }
    let did = &auth_user.did;
    // Validate input
    if input.did_list.is_empty() {
        warn!("Empty did_list provided");
        return Err(StatusCode::BAD_REQUEST.into());
    }

    for d in &input.did_list {
        let did_str = d.as_str();
        if !did_str.starts_with("did:") {
            warn!("Invalid DID format: {}", did_str);
            return Err(StatusCode::BAD_REQUEST.into());
        }
    }

    // Check if requester is a member
    if !is_member(&pool, did, &input.convo_id)
        .await
        .map_err(|e| {
            error!("Failed to check membership: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
    {
        warn!("User is not a member of conversation");
        return Err(StatusCode::FORBIDDEN.into());
    }

    // Note: Reduced logging per security hardening - no convo IDs at info level
    tracing::debug!("Adding {} members to convo {}", input.did_list.len(), crate::crypto::redact_for_log(&input.convo_id));

    // Enforce idempotency key for write endpoints unless explicitly disabled
    let require_idem = std::env::var("REQUIRE_IDEMPOTENCY")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes"))
        .unwrap_or(true);
    if require_idem && input.idempotency_key.is_none() {
        warn!("❌ [add_members] Missing idempotencyKey");
        return Err(StatusCode::BAD_REQUEST.into());
    }

    // If idempotency key is provided, check if this operation was already completed
    if let Some(ref _idem_key) = input.idempotency_key {
        // Check if all members are already added - if so, this is a duplicate request
        let mut all_exist = true;
        for target_did in &input.did_list {
            let target_did_str = target_did.as_str();
            let exists = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM members WHERE convo_id = $1 AND member_did = $2 AND left_at IS NULL)"
            )
            .bind(&input.convo_id)
            .bind(target_did_str)
            .fetch_one(&pool)
            .await
            .unwrap_or(false);

            if !exists {
                all_exist = false;
                break;
            }
        }

        if all_exist {
            info!("📍 [add_members] Idempotency: All members already exist, returning success");
            let current_epoch = get_current_epoch(&pool, &input.convo_id)
                .await
                .map_err(|e| {
                    error!("Failed to get current epoch: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;

            return Ok(Json(AddMembersOutput::from(OutputData {
                success: true,
                new_epoch: current_epoch as usize,
            })));
        }
    }

    // Check if actor system is enabled
    let use_actors = std::env::var("ENABLE_ACTOR_SYSTEM")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    let new_epoch = if use_actors {
        tracing::debug!("Using actor system for add_members");

        // Decode commit if provided
        let commit_bytes = if let Some(ref commit) = input.commit {
            Some(base64::engine::general_purpose::STANDARD.decode(commit)
                .map_err(|e| {
                    warn!("Invalid base64 commit: {}", e);
                    StatusCode::BAD_REQUEST
                })?)
        } else {
            None
        };

        // Convert key_package_hashes to actor message format
        let key_package_hashes = input.key_package_hashes.as_ref().map(|hashes| {
            hashes.iter().map(|entry| KeyPackageHashEntry {
                did: entry.data.did.to_string(),
                hash: entry.data.hash.clone(),
            }).collect()
        });

        // Get or spawn conversation actor
        let actor_ref = actor_registry.get_or_spawn(&input.convo_id).await
            .map_err(|e| {
                error!("Failed to get conversation actor: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        // Send AddMembers message
        let (tx, rx) = oneshot::channel();
        actor_ref.send_message(ConvoMessage::AddMembers {
            did_list: input.did_list.iter().map(|d| d.to_string()).collect(),
            commit: commit_bytes,
            welcome_message: input.welcome_message.clone(),
            key_package_hashes,
            reply: tx,
        }).map_err(|_| {
            error!("Failed to send message to actor");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        // Await response
        rx.await
            .map_err(|_| {
                error!("Actor channel closed unexpectedly");
                StatusCode::INTERNAL_SERVER_ERROR
            })?
            .map_err(|e| {
                error!("Actor failed to add members: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?
    } else {
        tracing::debug!("Using legacy database approach for add_members");

        let current_epoch = get_current_epoch(&pool, &input.convo_id)
            .await
            .map_err(|e| {
                error!("Failed to get current epoch: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        let new_epoch = current_epoch + 1;
        let now = chrono::Utc::now();

        // Process commit if provided
        if let Some(ref commit) = input.commit {
            let commit_bytes = base64::engine::general_purpose::STANDARD.decode(commit)
                .map_err(|e| {
                    warn!("Invalid base64 commit: {}", e);
                    StatusCode::BAD_REQUEST
                })?;

            let msg_id = uuid::Uuid::new_v4().to_string();

            sqlx::query(
                "INSERT INTO messages (id, convo_id, sender_did, message_type, epoch, ciphertext, created_at) VALUES ($1, $2, $3, 'commit', $4, $5, $6)"
            )
            .bind(&msg_id)
            .bind(&input.convo_id)
            .bind(did)
            .bind(new_epoch)
            .bind(&commit_bytes)
            .bind(&now)
            .execute(&pool)
            .await
            .map_err(|e| {
                error!("Failed to insert commit message: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            sqlx::query("UPDATE conversations SET current_epoch = $1 WHERE id = $2")
                .bind(new_epoch)
                .bind(&input.convo_id)
                .execute(&pool)
                .await
                .map_err(|e| {
                    error!("Failed to update conversation epoch: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;
        }

        // Add new members (multi-device: add ALL devices for each user)
        for target_did in &input.did_list {
            let target_did_str = target_did.as_str();
            tracing::debug!("📍 [add_members] processing member");

            // Query user's devices from user_devices table
            let devices: Vec<(String, String, Option<String>)> = sqlx::query_as(
                "SELECT device_id, device_mls_did, device_name
                 FROM user_devices
                 WHERE user_did = $1
                 ORDER BY registered_at"
            )
            .bind(target_did_str)
            .fetch_all(&pool)
            .await
            .map_err(|e| {
                error!("Failed to query devices for {}: {}", target_did_str, e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            if devices.is_empty() {
                // Fallback to single-device mode (backward compatibility)
                tracing::debug!("📍 [add_members] no devices found, using single-device mode");

                // Check if already a member
                let is_existing = sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM members WHERE convo_id = $1 AND member_did = $2"
                )
                .bind(&input.convo_id)
                .bind(target_did_str)
                .fetch_one(&pool)
                .await
                .map_err(|e| {
                    error!("Failed to check existing membership: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;

                if is_existing > 0 {
                    tracing::debug!("Member already exists, skipping");
                    continue;
                }

                sqlx::query(
                    "INSERT INTO members (convo_id, member_did, user_did, joined_at, is_admin)
                     VALUES ($1, $2, $3, $4, false)"
                )
                .bind(&input.convo_id)
                .bind(target_did_str)
                .bind(target_did_str)
                .bind(&now)
                .execute(&pool)
                .await
                .map_err(|e| {
                    error!("Failed to add member: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;

                tracing::debug!("✅ [add_members] added single-device member");
            } else {
                // Multi-device mode: add each device
                tracing::debug!("📍 [add_members] found devices for user");

                for (device_id, device_mls_did, device_name) in devices {
                    // Check if device already a member
                    let is_existing = sqlx::query_scalar::<_, i64>(
                        "SELECT COUNT(*) FROM members WHERE convo_id = $1 AND member_did = $2"
                    )
                    .bind(&input.convo_id)
                    .bind(&device_mls_did)
                    .fetch_one(&pool)
                    .await
                    .map_err(|e| {
                        error!("Failed to check existing device membership: {}", e);
                        StatusCode::INTERNAL_SERVER_ERROR
                    })?;

                    if is_existing > 0 {
                        tracing::debug!("Device already exists, skipping");
                        continue;
                    }

                    sqlx::query(
                        "INSERT INTO members (convo_id, member_did, user_did, device_id, device_name, joined_at, is_admin)
                         VALUES ($1, $2, $3, $4, $5, $6, false)"
                    )
                    .bind(&input.convo_id)
                    .bind(&device_mls_did)
                    .bind(target_did_str)
                    .bind(&device_id)
                    .bind(&device_name)
                    .bind(&now)
                    .execute(&pool)
                    .await
                    .map_err(|e| {
                        error!("Failed to add device for user: {}", e);
                        StatusCode::INTERNAL_SERVER_ERROR
                    })?;

                    tracing::debug!("✅ [add_members] added device for user");
                }
            }
        }

        // Store Welcome message for new members
        // MLS generates ONE Welcome message containing encrypted secrets for ALL members
        if let Some(ref welcome_b64) = input.welcome_message {
            tracing::debug!("📍 [add_members] processing welcome message");

            // Decode base64 Welcome message
            let welcome_data = base64::engine::general_purpose::STANDARD
                .decode(welcome_b64)
                .map_err(|e| {
                    warn!("❌ [add_members] Invalid base64 welcome message: {}", e);
                    StatusCode::BAD_REQUEST
                })?;

            info!("📍 [add_members] Single Welcome message ({} bytes) for {} new members",
                  welcome_data.len(), input.did_list.len());

            // Validate all key packages are available BEFORE storing anything
            if let Some(ref kp_hashes) = input.key_package_hashes {
                info!("📍 [add_members] Validating {} key packages are available...", kp_hashes.len());

                for entry in kp_hashes {
                    let member_did_str = entry.did.as_str();
                    let hash_hex = &entry.hash;

                    // Check if key package exists and is available (not consumed/reserved)
                    let available = sqlx::query_scalar::<_, bool>(
                        r#"
                        SELECT EXISTS(
                            SELECT 1 FROM key_packages
                            WHERE owner_did = $1
                              AND key_package_hash = $2
                              AND consumed_at IS NULL
                              AND (reserved_at IS NULL OR reserved_at < NOW() - INTERVAL '5 minutes')
                        )
                        "#
                    )
                    .bind(member_did_str)
                    .bind(hash_hex)
                    .fetch_one(&pool)
                    .await
                    .map_err(|e| {
                        error!("❌ [add_members] Failed to check key package availability: {}", e);
                        StatusCode::INTERNAL_SERVER_ERROR
                    })?;

                    if !available {
                        warn!(
                            "❌ [add_members] Key package not available for {}: hash={}",
                            member_did_str, hash_hex
                        );
                        return Err(Error::KeyPackageNotFound(Some(format!(
                            "Key package not available for {}: hash={}",
                            member_did_str, hash_hex
                        ))).into());
                    }
                }
                info!("✅ [add_members] All {} key packages are available", kp_hashes.len());
            }

            // Store the SAME Welcome for each new member
            for target_did in &input.did_list {
                let target_did_str = target_did.as_str();
                let welcome_id = uuid::Uuid::new_v4().to_string();

                // Get the key_package_hash for this member from the input
                let key_package_hash = input.key_package_hashes.as_ref()
                    .and_then(|hashes| {
                        hashes.iter()
                            .find(|entry| entry.did.as_str() == target_did_str)
                            .map(|entry| hex::decode(&entry.hash).ok())
                            .flatten()
                    });

                sqlx::query(
                    "INSERT INTO welcome_messages (id, convo_id, recipient_did, welcome_data, key_package_hash, created_at)
                     VALUES ($1, $2, $3, $4, $5, $6)
                     ON CONFLICT (convo_id, recipient_did, COALESCE(key_package_hash, '\\x00'::bytea)) WHERE consumed = false
                     DO NOTHING"
                )
                .bind(&welcome_id)
                .bind(&input.convo_id)
                .bind(target_did_str)
                .bind(&welcome_data)
                .bind::<Option<Vec<u8>>>(key_package_hash) // key_package_hash from client
                .bind(&now)
                .execute(&pool)
                .await
                .map_err(|e| {
                    error!("❌ [add_members] Failed to store welcome message for {}: {}", target_did_str, e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;

                info!("✅ [add_members] Welcome stored for member");
            }
            info!("📍 [add_members] Stored Welcome for {} members", input.did_list.len());

            // Mark key packages as consumed
            if let Some(ref kp_hashes) = input.key_package_hashes {
                for entry in kp_hashes {
                    let member_did_str = entry.did.as_str();
                    let hash_hex = &entry.hash;

                    match crate::db::mark_key_package_consumed(&pool, member_did_str, hash_hex).await {
                        Ok(consumed) => {
                            if consumed {
                                tracing::debug!("✅ [add_members] marked key package as consumed for {}", member_did_str);
                            } else {
                                tracing::warn!("⚠️ [add_members] key package not found or already consumed for {}", member_did_str);
                            }
                        }
                        Err(e) => {
                            tracing::warn!("⚠️ [add_members] failed to mark key package as consumed: {}", e);
                        }
                    }
                }
                tracing::debug!("📍 [add_members] marked {} key packages as consumed", kp_hashes.len());

                // Check inventory and send notification if low
                for entry in kp_hashes {
                    let member_did_str = entry.did.as_str();

                    // Count remaining available packages for this user
                    match crate::db::count_available_key_packages(&pool, member_did_str).await {
                        Ok(available) => {
                            tracing::debug!(
                                "User {} has {} available key packages remaining",
                                member_did_str,
                                available
                            );

                            // Notify if below threshold (5 packages)
                            if available < 5 {
                                // Check if we should send notification (throttling)
                                match crate::db::should_send_low_inventory_notification(&pool, member_did_str).await {
                                    Ok(should_send) => {
                                        if should_send {
                                            tracing::info!(
                                                "⚠️ User {} has low key package inventory: {} available",
                                                member_did_str,
                                                available
                                            );

                                            // TODO: Send notification via notification service
                                            // When NotificationService is integrated into AppState:
                                            // if let Some(notification_service) = state.notification_service.as_ref() {
                                            //     notification_service
                                            //         .notify_low_key_packages(member_did_str, available, 10)
                                            //         .await
                                            //         .ok(); // Don't fail the request if notification fails
                                            // }

                                            // Record that we sent the notification
                                            crate::db::record_low_inventory_notification(&pool, member_did_str)
                                                .await
                                                .ok(); // Log but don't fail
                                        } else {
                                            tracing::debug!(
                                                "Skipping notification for {} (already notified within 24h)",
                                                member_did_str
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            "Failed to check notification throttling for {}: {}",
                                            member_did_str,
                                            e
                                        );
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Failed to count available key packages for {}: {}",
                                member_did_str,
                                e
                            );
                        }
                    }
                }
            }
        } else {
            info!("📍 [add_members] No welcome message provided");
        }

        new_epoch as u32
    };

    info!("Successfully added members to conversation, new epoch: {}", new_epoch);

    Ok(Json(AddMembersOutput::from(OutputData {
        success: true,
        new_epoch: new_epoch as usize,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::init_db;

    async fn setup_test_convo(pool: &DbPool, creator: &str, convo_id: &str) {
        let now = chrono::Utc::now();
        sqlx::query("INSERT INTO conversations (id, creator_did, current_epoch, created_at, updated_at) VALUES ($1, $2, 0, $3, $3)")
            .bind(convo_id)
            .bind(creator)
            .bind(&now)
            .execute(pool)
            .await
            .unwrap();
        
        sqlx::query("INSERT INTO members (convo_id, member_did, joined_at) VALUES ($1, $2, $3)")
            .bind(convo_id)
            .bind(creator)
            .bind(&now)
            .execute(pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_add_members_success() {
        // Use TEST_DATABASE_URL for Postgres-backed tests; skip if unset
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else { return; };
        let pool = crate::db::init_db(crate::db::DbConfig { database_url: db_url, max_connections: 5, min_connections: 1, acquire_timeout: std::time::Duration::from_secs(5), idle_timeout: std::time::Duration::from_secs(30) }).await.unwrap();
        let convo_id = "test-convo-1";
        let creator = "did:plc:creator";
        
        setup_test_convo(&pool, creator, convo_id).await;

        let did = AuthUser { did: creator.to_string(), claims: crate::auth::AtProtoClaims { iss: creator.to_string(), aud: "test".to_string(), exp: 9999999999, iat: None, sub: None, jti: Some("test-jti".to_string()), lxm: None } };
        let input = AddMembersInput {
            convo_id: convo_id.to_string(),
            did_list: vec!["did:plc:member1".to_string()],
            commit: None,
            welcome: None,
        };

        let result = add_members(State(pool), did, Json(input)).await;
        assert!(result.is_ok());
        
        let output = result.unwrap().0;
        assert!(output.success);
        assert_eq!(output.new_epoch, 1);
    }

    #[tokio::test]
    async fn test_add_members_not_member() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else { return; };
        let pool = crate::db::init_db(crate::db::DbConfig { database_url: db_url, max_connections: 5, min_connections: 1, acquire_timeout: std::time::Duration::from_secs(5), idle_timeout: std::time::Duration::from_secs(30) }).await.unwrap();
        let convo_id = "test-convo-2";
        let creator = "did:plc:creator";
        
        setup_test_convo(&pool, creator, convo_id).await;

        let did = AuthUser { did: "did:plc:outsider".to_string(), claims: crate::auth::AtProtoClaims { iss: "did:plc:outsider".to_string(), aud: "test".to_string(), exp: 9999999999, iat: None, sub: None, jti: Some("test-jti".to_string()), lxm: None } };
        let input = AddMembersInput {
            convo_id: convo_id.to_string(),
            did_list: vec!["did:plc:member1".to_string()],
            commit: None,
            welcome: None,
        };

        let result = add_members(State(pool), did, Json(input)).await;
        assert_eq!(result.unwrap_err(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_add_members_empty_list() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else { return; };
        let pool = crate::db::init_db(crate::db::DbConfig { database_url: db_url, max_connections: 5, min_connections: 1, acquire_timeout: std::time::Duration::from_secs(5), idle_timeout: std::time::Duration::from_secs(30) }).await.unwrap();
        let convo_id = "test-convo-3";
        let creator = "did:plc:creator";
        
        setup_test_convo(&pool, creator, convo_id).await;

        let did = AuthUser { did: creator.to_string(), claims: crate::auth::AtProtoClaims { iss: creator.to_string(), aud: "test".to_string(), exp: 9999999999, iat: None, sub: None, jti: Some("test-jti".to_string()), lxm: None } };
        let input = AddMembersInput {
            convo_id: convo_id.to_string(),
            did_list: vec![],
            commit: None,
            welcome: None,
        };

        let result = add_members(State(pool), did, Json(input)).await;
        assert_eq!(result.unwrap_err(), StatusCode::BAD_REQUEST);
    }
}
