use axum::{extract::State, http::StatusCode, Json};
use base64::Engine;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::{
    auth::AuthUser,
    block_sync::BlockSyncService,
    error_responses::CreateConvoError,
    generated::blue_catbird::mls::create_convo::{
        CreateConvo, CreateConvoError as LexCreateConvoError,
    },
    generated::blue_catbird::mls::{ConvoMetadata, ConvoView, MemberView},
    sqlx_jacquard::{chrono_to_datetime, did_to_string},
    storage::DbPool,
};

/// Create a new conversation
/// POST /xrpc/blue.catbird.mls.createConvo
#[tracing::instrument(skip(pool, block_sync, auth_user))]
pub async fn create_convo(
    State(pool): State<DbPool>,
    State(block_sync): State<Arc<BlockSyncService>>,
    auth_user: AuthUser,
    body: String,
) -> Result<Json<ConvoView<'static>>, CreateConvoError> {
    let input = crate::jacquard_json::from_json_body::<CreateConvo>(&body)?;

    tracing::debug!("🔷 [create_convo] incoming create request");

    info!(
        creator = %crate::crypto::redact_for_log(&auth_user.did),
        group = %crate::crypto::redact_for_log(&input.group_id),
        initial_members = input.initial_members.as_ref().map(|m| m.len()).unwrap_or(0),
        has_welcome = input.welcome_message.is_some(),
        "[create_convo] start"
    );

    if let Err(_e) =
        crate::auth::enforce_standard(&auth_user.claims, "blue.catbird.mls.createConvo")
    {
        error!("❌ [create_convo] Unauthorized");
        return Err(StatusCode::UNAUTHORIZED.into());
    }

    // Parse creator DID safely
    let creator_did = auth_user.did.parse().map_err(|e| {
        error!(
            "Invalid creator DID '{}': {}",
            crate::crypto::redact_for_log(&auth_user.did),
            e
        );
        StatusCode::BAD_REQUEST
    })?;

    tracing::debug!("📍 [create_convo] Validating cipher suite");
    // Validate cipher suite
    let valid_suites = [
        "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        "MLS_128_DHKEMP256_AES128GCM_SHA256_P256",
        "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
    ];
    if !valid_suites.contains(&input.cipher_suite.as_str()) {
        warn!(
            "❌ [create_convo] Invalid cipher suite: {}",
            input.cipher_suite
        );
        return Err(LexCreateConvoError::InvalidCipherSuite(Some(
            format!("Cipher suite '{}' is not supported", input.cipher_suite).into(),
        ))
        .into());
    }

    // Validate initial members count
    // Default max_members is 1000, but can be configured per-conversation policy
    // Note: Policy doesn't exist yet at creation time, so we use a default limit here
    // The actual policy.max_members will be set when the policy is created (via trigger)
    if let Some(ref members) = input.initial_members {
        tracing::debug!("📍 [create_convo] validating initial members");
        // Total count includes creator + initial members
        let total_member_count = members.len() + 1;

        // Use default max of 1000 for creation (policy doesn't exist yet)
        // This can be lowered later via updatePolicy, but not during creation
        let max_members = 1000;

        if total_member_count > max_members {
            warn!(
                "❌ [create_convo] Too many initial members: {} (max {})",
                total_member_count, max_members
            );
            return Err(LexCreateConvoError::TooManyMembers(Some(
                format!(
                    "Cannot add more than {} initial members (got {} including creator)",
                    max_members, total_member_count
                )
                .into(),
            ))
            .into());
        }
    }

    // Check for blocks between creator and initial members by querying PDSes
    tracing::debug!("📍 [create_convo] checking for blocks between members via PDS");
    let mut all_member_dids_for_block_check = vec![auth_user.did.clone()];
    if let Some(ref members) = input.initial_members {
        for member_did in members.iter() {
            let member_did_str = did_to_string(member_did);
            if member_did_str != auth_user.did {
                all_member_dids_for_block_check.push(member_did_str);
            }
        }
    }

    // Only check if there are multiple members (more than just the creator)
    if all_member_dids_for_block_check.len() > 1 {
        // Query PDSes for authoritative block data
        match block_sync
            .check_block_conflicts(&all_member_dids_for_block_check)
            .await
        {
            Ok(conflicts) => {
                if !conflicts.is_empty() {
                    // Sync blocks to DB for future reference
                    for (blocker, _blocked) in &conflicts {
                        if let Err(e) = block_sync.sync_blocks_to_db(&pool, blocker).await {
                            warn!("Failed to sync blocks to DB: {}", e);
                        }
                    }

                    warn!(
                        "❌ [create_convo] Block detected between members: {} blocks found via PDS",
                        conflicts.len()
                    );
                    return Err(LexCreateConvoError::MutualBlockDetected(Some(
                        format!(
                        "Cannot create conversation: one or more members have blocked each other"
                    )
                        .into(),
                    ))
                    .into());
                }
                tracing::debug!(
                    "✅ [create_convo] No blocks detected between members (PDS verified)"
                );
            }
            Err(e) => {
                // Fall back to local DB if PDS queries fail
                warn!("PDS block check failed, falling back to local DB: {}", e);

                let blocks: Vec<(String, String)> = sqlx::query_as(
                    "SELECT user_did, target_did FROM bsky_blocks
                     WHERE user_did = ANY($1) AND target_did = ANY($1)",
                )
                .bind(&all_member_dids_for_block_check)
                .fetch_all(&pool)
                .await
                .map_err(|e| {
                    error!("❌ [create_convo] Failed to check blocks: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;

                if !blocks.is_empty() {
                    warn!(
                        "❌ [create_convo] Block detected between members: {} blocks found (from DB cache)",
                        blocks.len()
                    );
                    return Err(LexCreateConvoError::MutualBlockDetected(Some(
                        format!(
                        "Cannot create conversation: one or more members have blocked each other"
                    )
                        .into(),
                    ))
                    .into());
                }
                tracing::debug!(
                    "✅ [create_convo] No blocks detected between members (DB fallback)"
                );
            }
        }
    }

    // Use client-provided group_id as the canonical conversation ID
    let convo_id = input.group_id.to_string();
    let now = chrono::Utc::now();

    let (name, description) = if let Some(ref meta) = input.metadata {
        (
            meta.name.as_deref().map(String::from),
            meta.description.as_deref().map(String::from),
        )
    } else {
        (None, None)
    };

    tracing::debug!("📍 [create_convo] creating conversation in database");

    // Enforce idempotency key for production (can be disabled via REQUIRE_IDEMPOTENCY=false)
    let require_idem = std::env::var("REQUIRE_IDEMPOTENCY")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes"))
        .unwrap_or(true);
    if require_idem && input.idempotency_key.is_none() {
        warn!("❌ [create_convo] Missing idempotencyKey");
        return Err(StatusCode::BAD_REQUEST.into());
    }

    // If idempotency key is provided, check for existing conversation
    if let Some(ref idem_key) = input.idempotency_key {
        if let Ok(Some(existing_convo_id)) = sqlx::query_scalar::<_, String>(
            "SELECT id FROM conversations WHERE idempotency_key = $1",
        )
        .bind(idem_key.as_ref())
        .fetch_optional(&pool)
        .await
        {
            tracing::debug!("📍 [create_convo] Idempotency: returning existing conversation");

            // Fetch existing conversation details
            let existing_members: Vec<(String, String, Option<String>, Option<String>, DateTime<Utc>, bool, Option<i32>)> = sqlx::query_as(
                "SELECT member_did, user_did, device_id, device_name, joined_at, is_admin, leaf_index
                 FROM members WHERE convo_id = $1 AND left_at IS NULL ORDER BY joined_at"
            )
            .bind(&existing_convo_id)
            .fetch_all(&pool)
            .await
            .map_err(|e| {
                error!("❌ [create_convo] Failed to fetch existing members: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            let members: Vec<MemberView> = existing_members
                .into_iter()
                .map(
                    |(
                        member_did,
                        user_did,
                        device_id,
                        device_name,
                        joined_at,
                        is_admin,
                        leaf_index,
                    )| {
                        let did = member_did.parse().map_err(|e| {
                            error!(
                                "Invalid member DID '{}': {}",
                                crate::crypto::redact_for_log(&member_did),
                                e
                            );
                            StatusCode::INTERNAL_SERVER_ERROR
                        })?;

                        let user_did_parsed = user_did.parse().map_err(|e| {
                            error!(
                                "Invalid user DID '{}': {}",
                                crate::crypto::redact_for_log(&user_did),
                                e
                            );
                            StatusCode::INTERNAL_SERVER_ERROR
                        })?;

                        Ok(MemberView {
                            did,
                            user_did: user_did_parsed,
                            device_id: device_id.map(Into::into),
                            device_name: device_name.map(Into::into),
                            joined_at: chrono_to_datetime(joined_at),
                            is_admin,
                            leaf_index: leaf_index.map(|i| i as i64),
                            credential: None,
                            promoted_at: None,
                            promoted_by: None,
                            is_moderator: Some(false),
                            extra_data: Default::default(),
                        })
                    },
                )
                .collect::<Result<Vec<_>, StatusCode>>()?;

            let metadata = if name.is_some() || description.is_some() {
                Some(ConvoMetadata {
                    name: name.clone().map(Into::into),
                    description: description.clone().map(Into::into),
                    extra_data: Default::default(),
                })
            } else {
                None
            };

            return Ok(Json(ConvoView {
                group_id: existing_convo_id.into(), // existing_convo_id is the group_id
                creator: creator_did,
                members,
                epoch: 0,
                cipher_suite: input.cipher_suite.clone(),
                created_at: chrono_to_datetime(now),
                last_message_at: None,
                metadata,
                extra_data: Default::default(),
            }));
        }
    }

    // Create conversation - id is the client-provided group_id
    // Federation: sequencer_ds is NULL for locally-created conversations (NULL means "this DS is the sequencer").
    // is_remote defaults to false. When federation is enabled, remote participants' DSes will
    // see sequencer_ds set to the creating DS's DID.
    sqlx::query(
        "INSERT INTO conversations (id, creator_did, current_epoch, created_at, updated_at, name, cipher_suite, idempotency_key, sequencer_ds, is_remote)
         VALUES ($1, $2, 0, $3, $3, $4, $5, $6, NULL, false)"
    )
    .bind(&convo_id)  // convo_id is now String from input.group_id
    .bind(&auth_user.did)
    .bind(&now)
    .bind(&name)
    .bind(&*input.cipher_suite)
    .bind(input.idempotency_key.as_deref())
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("❌ [create_convo] Failed to create conversation: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tracing::debug!("📍 [create_convo] adding creator membership");
    // Add creator as first member
    sqlx::query(
        "INSERT INTO members (convo_id, member_did, user_did, joined_at, is_admin) VALUES ($1, $2, $3, $4, true)"
    )
    .bind(&convo_id)
    .bind(&auth_user.did)
    .bind(&auth_user.did) // For single-device: user_did = member_did
    .bind(&now)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("❌ [create_convo] Failed to add creator membership: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let mut members = vec![MemberView {
        did: creator_did.clone(),
        user_did: creator_did.clone(), // For single-device: same as did
        device_id: None,
        device_name: None,
        joined_at: chrono_to_datetime(now),
        is_admin: true,
        is_moderator: Some(false),
        leaf_index: Some(0),
        credential: None,
        promoted_at: None,
        promoted_by: None,
        extra_data: Default::default(),
    }];

    // Add initial members if specified
    if let Some(ref initial_members) = input.initial_members {
        tracing::debug!("📍 [create_convo] adding initial members");
        for (idx, member_did) in initial_members.iter().enumerate() {
            let member_did_str = did_to_string(member_did);

            // Skip if member is the creator (already added above)
            if member_did_str == auth_user.did {
                continue;
            }

            info!("📍 [create_convo] Adding member {}", idx + 1);
            sqlx::query(
                "INSERT INTO members (convo_id, member_did, user_did, joined_at, is_admin) VALUES ($1, $2, $3, $4, false)"
            )
            .bind(&convo_id)
            .bind(&member_did_str)
            .bind(&member_did_str) // For single-device: user_did = member_did
            .bind(&now)
            .execute(&pool)
            .await
            .map_err(|e| {
                error!("❌ [create_convo] Failed to add member: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            members.push(MemberView {
                did: member_did.clone(),
                user_did: member_did.clone(), // For single-device: same as did
                device_id: None,
                device_name: None,
                joined_at: chrono_to_datetime(now),
                is_admin: false,
                is_moderator: Some(false),
                leaf_index: Some((idx + 1) as i64),
                credential: None,
                promoted_at: None,
                promoted_by: None,
                extra_data: Default::default(),
            });
        }
    }

    // Store Welcome message for initial members
    // MLS generates ONE Welcome message containing encrypted secrets for ALL members
    // Each member can decrypt only their portion from the same Welcome
    if let Some(ref welcome_b64) = input.welcome_message {
        info!("📍 [create_convo] Processing Welcome message...");

        // Decode base64 Welcome message
        let welcome_data = base64::engine::general_purpose::STANDARD
            .decode(&**welcome_b64)
            .map_err(|e| {
                warn!("❌ [create_convo] Invalid base64 welcome message: {}", e);
                StatusCode::BAD_REQUEST
            })?;

        info!(
            "📍 [create_convo] Single Welcome message ({} bytes) for all members/devices",
            welcome_data.len()
        );

        info!("📨 [CREATE_CONVO] Stored Welcome message for convo {}: {} bytes", input.group_id, welcome_data.len());

        // Validate all key packages are available BEFORE storing anything
        if let Some(ref kp_hashes) = input.key_package_hashes {
            info!(
                "📍 [create_convo] Validating {} key packages are available...",
                kp_hashes.len()
            );

            for entry in kp_hashes {
                let member_did_str = did_to_string(&entry.did);
                let hash_hex: &str = &entry.hash;

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
                    "#,
                )
                .bind(&member_did_str)
                .bind(hash_hex)
                .fetch_one(&pool)
                .await
                .map_err(|e| {
                    error!(
                        "❌ [create_convo] Failed to check key package availability: {}",
                        e
                    );
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;

                if !available {
                    // Enhanced logging: show what hashes ARE available for this user
                    let available_hashes: Vec<String> = sqlx::query_scalar(
                        r#"
                        SELECT key_package_hash FROM key_packages
                        WHERE owner_did = $1
                          AND consumed_at IS NULL
                          AND (reserved_at IS NULL OR reserved_at < NOW() - INTERVAL '5 minutes')
                        ORDER BY created_at DESC
                        LIMIT 10
                        "#,
                    )
                    .bind(&member_did_str)
                    .fetch_all(&pool)
                    .await
                    .unwrap_or_default();

                    warn!(
                        "❌ [create_convo] Key package not available for {}: available_hashes_count={}",
                        crate::crypto::redact_for_log(&member_did_str), available_hashes.len()
                    );
                    return Err(LexCreateConvoError::KeyPackageNotFound(Some(format!(
                        "Key package not available for {}: hash={}. Server has {} available key packages.",
                        member_did_str, hash_hex, available_hashes.len()
                    ).into())).into());
                }
            }
            info!(
                "✅ [create_convo] All {} key packages are available",
                kp_hashes.len()
            );
        }

        // Store the SAME Welcome for ALL members (creator + initial members)
        // In MLS, the Welcome message contains encrypted secrets for all members,
        // and each member (including the creator) must process it to initialize their group state

        // Collect all member DIDs (creator + initial_members)
        let mut all_member_dids = vec![auth_user.did.clone()];
        if let Some(ref member_list) = input.initial_members {
            for member_did in member_list.iter() {
                let member_did_str = did_to_string(member_did);
                // Avoid duplicates (in case creator is also in initial_members)
                if member_did_str != auth_user.did {
                    all_member_dids.push(member_did_str);
                }
            }
        }

        info!(
            "📍 [create_convo] Storing Welcome message for {} total members (including creator)",
            all_member_dids.len()
        );

        for member_did_str in all_member_dids.iter() {
            // Get ALL key_package_hashes for this member
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
                // Legacy/Fallback: Store one welcome with NULL hash
                sqlx::query(
                    "INSERT INTO welcome_messages (id, convo_id, recipient_did, welcome_data, key_package_hash, created_at)
                     VALUES ($1, $2, $3, $4, $5, $6)
                     ON CONFLICT (convo_id, recipient_did, COALESCE(key_package_hash, '\\x00'::bytea)) WHERE consumed = false
                     DO NOTHING"
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
                    error!("❌ [create_convo] Failed to store welcome message for {}: {}", crate::crypto::redact_for_log(member_did_str), e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;

                tracing::debug!(
                    "✅ [create_convo] welcome stored for member (legacy): {}",
                    crate::crypto::redact_for_log(member_did_str)
                );
            } else {
                // Multi-device: Store welcome for EACH hash
                for hash in member_hashes {
                    let welcome_id = uuid::Uuid::new_v4().to_string();
                    sqlx::query(
                        "INSERT INTO welcome_messages (id, convo_id, recipient_did, welcome_data, key_package_hash, created_at)
                         VALUES ($1, $2, $3, $4, $5, $6)
                         ON CONFLICT (convo_id, recipient_did, COALESCE(key_package_hash, '\\x00'::bytea)) WHERE consumed = false
                         DO NOTHING"
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
                        error!("❌ [create_convo] Failed to store welcome message for {}: {}", crate::crypto::redact_for_log(member_did_str), e);
                        StatusCode::INTERNAL_SERVER_ERROR
                    })?;
                }
                tracing::debug!(
                    "✅ [create_convo] welcome stored for member (multi-device): {}",
                    crate::crypto::redact_for_log(member_did_str)
                );
            }
        }
        tracing::debug!(
            "📍 [create_convo] stored welcome for {} members",
            all_member_dids.len()
        );

        // Mark key packages as consumed
        if let Some(ref kp_hashes) = input.key_package_hashes {
            for entry in kp_hashes {
                let member_did_str = did_to_string(&entry.did);
                let hash_hex: &str = &entry.hash;

                match crate::db::mark_key_package_consumed(&pool, &member_did_str, hash_hex).await {
                    Ok(consumed) => {
                        if consumed {
                            tracing::debug!(
                                "✅ [create_convo] marked key package as consumed for {}",
                                crate::crypto::redact_for_log(&member_did_str)
                            );
                        } else {
                            tracing::warn!("⚠️ [create_convo] key package not found or already consumed for {}", crate::crypto::redact_for_log(&member_did_str));
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            "⚠️ [create_convo] failed to mark key package as consumed: {}",
                            e
                        );
                    }
                }
            }
            tracing::debug!(
                "📍 [create_convo] marked {} key packages as consumed",
                kp_hashes.len()
            );
        }
    } else {
        tracing::debug!("📍 [create_convo] no welcome message provided");
    }

    info!(
        convo = %crate::crypto::redact_for_log(&convo_id),
        member_count = members.len(),
        epoch = 0,
        "✅ [create_convo] complete"
    );

    // Build metadata view if metadata exists
    let metadata = if name.is_some() || description.is_some() {
        Some(ConvoMetadata {
            name: name.map(Into::into),
            description: description.map(Into::into),
            extra_data: Default::default(),
        })
    } else {
        None
    };

    Ok(Json(ConvoView {
        group_id: convo_id.into(), // convo_id is String, convert to CowStr
        creator: creator_did,
        members,
        epoch: 0,
        cipher_suite: input.cipher_suite,
        created_at: chrono_to_datetime(now),
        last_message_at: None,
        metadata,
        extra_data: Default::default(),
    }))
}
