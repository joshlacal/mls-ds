use axum::{extract::State, http::StatusCode, Json};
use base64::Engine;
use chrono::{DateTime, Utc};
use tracing::{info, warn, error};

use crate::{
    auth::AuthUser,
    error_responses::CreateConvoError,
    generated::blue::catbird::mls::create_convo::{Input, NSID, Error},
    generated::blue::catbird::mls::defs::{ConvoView, ConvoViewData, ConvoMetadata, ConvoMetadataData, MemberView, MemberViewData},
    sqlx_atrium::{chrono_to_datetime, did_to_string},
    storage::DbPool,
};

/// Create a new conversation
/// POST /xrpc/blue.catbird.mls.createConvo
#[tracing::instrument(skip(pool, auth_user))]
pub async fn create_convo(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Json(input): Json<Input>,
) -> Result<Json<ConvoView>, CreateConvoError> {
    let input = input.data;

    tracing::debug!("🔷 [create_convo] incoming create request");

    info!(
        creator = %crate::crypto::redact_for_log(&auth_user.did),
        group = %crate::crypto::redact_for_log(&input.group_id),
        initial_members = input.initial_members.as_ref().map(|m| m.len()).unwrap_or(0),
        has_welcome = input.welcome_message.is_some(),
        "[create_convo] start"
    );

    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        error!("❌ [create_convo] Unauthorized");
        return Err(StatusCode::UNAUTHORIZED.into());
    }

    // Parse creator DID safely
    let creator_did = auth_user.did.parse().map_err(|e| {
        error!("Invalid creator DID '{}': {}", auth_user.did, e);
        StatusCode::BAD_REQUEST
    })?;

    tracing::debug!("📍 [create_convo] Validating cipher suite");
    // Validate cipher suite
    let valid_suites = ["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
                        "MLS_128_DHKEMP256_AES128GCM_SHA256_P256"];
    if !valid_suites.contains(&input.cipher_suite.as_str()) {
        warn!("❌ [create_convo] Invalid cipher suite: {}", input.cipher_suite);
        return Err(Error::InvalidCipherSuite(Some(format!(
            "Cipher suite '{}' is not supported",
            input.cipher_suite
        ))).into());
    }

    // Validate initial members
    if let Some(ref members) = input.initial_members {
    tracing::debug!("📍 [create_convo] validating initial members");
        if members.len() > 100 {
            warn!("❌ [create_convo] Too many initial members: {}", members.len());
            return Err(Error::TooManyMembers(Some(format!(
                "Cannot add more than 100 initial members (got {})",
                members.len()
            ))).into());
        }
    }

    // Use client-provided group_id as the canonical conversation ID
    let convo_id = input.group_id.clone();
    let now = chrono::Utc::now();

    let (name, description) = if let Some(ref meta) = input.metadata {
        let meta_data = &meta.data;
        (meta_data.name.clone(), meta_data.description.clone())
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
            "SELECT id FROM conversations WHERE idempotency_key = $1"
        )
        .bind(idem_key)
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
                .map(|(member_did, user_did, device_id, device_name, joined_at, is_admin, leaf_index)| {
                    let did = member_did.parse().map_err(|e| {
                        error!("Invalid member DID '{}': {}", member_did, e);
                        StatusCode::INTERNAL_SERVER_ERROR
                    })?;

                    let user_did_parsed = user_did.parse().map_err(|e| {
                        error!("Invalid user DID '{}': {}", user_did, e);
                        StatusCode::INTERNAL_SERVER_ERROR
                    })?;

                    Ok(MemberView::from(MemberViewData {
                        did,
                        user_did: user_did_parsed,
                        device_id,
                        device_name,
                        joined_at: chrono_to_datetime(joined_at),
                        is_admin,
                        leaf_index: leaf_index.map(|i| i as usize),
                        credential: None,
                        promoted_at: None,
                        promoted_by: None,
                    }))
                })
                .collect::<Result<Vec<_>, StatusCode>>()?;

            let metadata = if name.is_some() || description.is_some() {
                Some(ConvoMetadata::from(ConvoMetadataData {
                    name: name.clone(),
                    description: description.clone(),
                }))
            } else {
                None
            };

            return Ok(Json(ConvoView::from(ConvoViewData {
                group_id: existing_convo_id,  // existing_convo_id is the group_id
                creator: creator_did,
                members,
                epoch: 0,
                cipher_suite: input.cipher_suite.clone(),
                created_at: chrono_to_datetime(now),
                last_message_at: None,
                metadata,
            })));
        }
    }

    // Create conversation - id is the client-provided group_id
    sqlx::query(
        "INSERT INTO conversations (id, creator_did, current_epoch, created_at, updated_at, name, cipher_suite, idempotency_key)
         VALUES ($1, $2, 0, $3, $3, $4, $5, $6)"
    )
    .bind(&convo_id)  // convo_id is now input.group_id
    .bind(&auth_user.did)
    .bind(&now)
    .bind(&name)
    .bind(&input.cipher_suite)
    .bind(&input.idempotency_key)
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

    let mut members = vec![MemberView::from(MemberViewData {
        did: creator_did.clone(),
        user_did: creator_did.clone(), // For single-device: same as did
        device_id: None,
        device_name: None,
        joined_at: chrono_to_datetime(now),
        is_admin: true,
        leaf_index: Some(0),
        credential: None,
        promoted_at: None,
        promoted_by: None,
    })];

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

            members.push(MemberView::from(MemberViewData {
                did: member_did.clone(),
                user_did: member_did.clone(), // For single-device: same as did
                device_id: None,
                device_name: None,
                joined_at: chrono_to_datetime(now),
                is_admin: false,
                leaf_index: Some((idx + 1) as usize),
                credential: None,
                promoted_at: None,
                promoted_by: None,
            }));
        }
    }

    // Store Welcome message for initial members
    // MLS generates ONE Welcome message containing encrypted secrets for ALL members
    // Each member can decrypt only their portion from the same Welcome
    if let Some(ref welcome_b64) = input.welcome_message {
        info!("📍 [create_convo] Processing Welcome message...");

        // Decode base64 Welcome message
        let welcome_data = base64::engine::general_purpose::STANDARD
            .decode(welcome_b64)
            .map_err(|e| {
                warn!("❌ [create_convo] Invalid base64 welcome message: {}", e);
                StatusCode::BAD_REQUEST
            })?;

        info!("📍 [create_convo] Single Welcome message ({} bytes) for all members/devices", welcome_data.len());

        // Validate all key packages are available BEFORE storing anything
        if let Some(ref kp_hashes) = input.key_package_hashes {
            info!("📍 [create_convo] Validating {} key packages are available...", kp_hashes.len());

            for entry in kp_hashes {
                let member_did_str = did_to_string(&entry.data.did);
                let hash_hex = &entry.data.hash;

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
                .bind(&member_did_str)
                .bind(hash_hex)
                .fetch_one(&pool)
                .await
                .map_err(|e| {
                    error!("❌ [create_convo] Failed to check key package availability: {}", e);
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
                        "#
                    )
                    .bind(&member_did_str)
                    .fetch_all(&pool)
                    .await
                    .unwrap_or_default();

                    warn!(
                        "❌ [create_convo] Key package not available for {}: requested_hash={}, available_hashes_count={}, available_hashes={:?}",
                        member_did_str, hash_hex, available_hashes.len(), available_hashes
                    );
                    return Err(Error::KeyPackageNotFound(Some(format!(
                        "Key package not available for {}: hash={}. Server has {} available key packages.",
                        member_did_str, hash_hex, available_hashes.len()
                    ))).into());
                }
            }
            info!("✅ [create_convo] All {} key packages are available", kp_hashes.len());
        }

        // Store the SAME Welcome for each initial member (excluding creator)
        if let Some(ref member_list) = input.initial_members {
            let non_creator_members: Vec<_> = member_list.iter()
                .filter(|d| did_to_string(d) != auth_user.did)
                .collect();

            for member_did in &non_creator_members {
                let welcome_id = uuid::Uuid::new_v4().to_string();
                let member_did_str = did_to_string(member_did);

                // Get the key_package_hash for this member from the input
                let key_package_hash = input.key_package_hashes.as_ref()
                    .and_then(|hashes| {
                        hashes.iter()
                            .find(|entry| did_to_string(&entry.data.did) == member_did_str)
                            .map(|entry| hex::decode(&entry.data.hash).ok())
                            .flatten()
                    });

                sqlx::query(
                    "INSERT INTO welcome_messages (id, convo_id, recipient_did, welcome_data, key_package_hash, created_at)
                     VALUES ($1, $2, $3, $4, $5, $6)
                     ON CONFLICT (convo_id, recipient_did, COALESCE(key_package_hash, '\\x00'::bytea)) WHERE consumed = false
                     DO NOTHING"
                )
                .bind(&welcome_id)
                .bind(&convo_id)
                .bind(&member_did_str)
                .bind(&welcome_data)
                .bind::<Option<Vec<u8>>>(key_package_hash) // key_package_hash from client
                .bind(&now)
                .execute(&pool)
                .await
                .map_err(|e| {
                    error!("❌ [create_convo] Failed to store welcome message: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;

                tracing::debug!("✅ [create_convo] welcome stored for member");
            }
            tracing::debug!("📍 [create_convo] stored welcome for initial members");

            // Mark key packages as consumed
            if let Some(ref kp_hashes) = input.key_package_hashes {
                for entry in kp_hashes {
                    let member_did_str = did_to_string(&entry.data.did);
                    let hash_hex = &entry.data.hash;

                    match crate::db::mark_key_package_consumed(&pool, &member_did_str, hash_hex).await {
                        Ok(consumed) => {
                            if consumed {
                                tracing::debug!("✅ [create_convo] marked key package as consumed for {}", member_did_str);
                            } else {
                                tracing::warn!("⚠️ [create_convo] key package not found or already consumed for {}", member_did_str);
                            }
                        }
                        Err(e) => {
                            tracing::warn!("⚠️ [create_convo] failed to mark key package as consumed: {}", e);
                        }
                    }
                }
                tracing::debug!("📍 [create_convo] marked {} key packages as consumed", kp_hashes.len());
            }
        } else {
            tracing::debug!("📍 [create_convo] no initial_members list - skipping welcome storage");
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
        Some(ConvoMetadata::from(ConvoMetadataData {
            name,
            description,
        }))
    } else {
        None
    };

    Ok(Json(ConvoView::from(ConvoViewData {
        group_id: convo_id,  // convo_id is the group_id
        creator: creator_did,
        members,
        epoch: 0,
        cipher_suite: input.cipher_suite,
        created_at: chrono_to_datetime(now),
        last_message_at: None,
        metadata,
    })))
}
