use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use chrono::{Duration, Utc};
use jacquard_axum::ExtractXrpc;
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::{
    auth::AuthUser,
    device_utils::parse_device_did,
    generated::blue_catbird::mlsChat::register_device::{
        RegisterDeviceOutput, RegisterDeviceRequest,
    },
    realtime::{SseState, StreamEvent},
    storage::DbPool,
};

// NSID for auth enforcement
const NSID: &str = "blue.catbird.mlsChat.registerDevice";

#[cfg(test)]
async fn cleanup_re_registered_device_key_packages(
    pool: &DbPool,
    user_did: &str,
    old_device_id: &str,
) -> Result<u64, StatusCode> {
    let mut tx = pool.begin().await.map_err(|e| {
        error!("Failed to begin re-registration cleanup transaction: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let deleted =
        cleanup_re_registered_device_key_packages_in_tx(&mut tx, user_did, old_device_id).await?;
    tx.commit().await.map_err(|e| {
        error!(
            "Failed to commit re-registration cleanup transaction: {}",
            e
        );
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(deleted)
}

async fn cleanup_re_registered_device_key_packages_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_did: &str,
    old_device_id: &str,
) -> Result<u64, StatusCode> {
    sqlx::query("DELETE FROM key_packages WHERE owner_did = $1 AND device_id = $2")
        .bind(user_did)
        .bind(old_device_id)
        .execute(&mut **tx)
        .await
        .map_err(|e| {
            error!("Failed to delete old key packages: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })
        .map(|result| result.rows_affected())
}

// ─── POST handler ───

/// Consolidated device management endpoint (POST)
/// POST /xrpc/blue.catbird.mlsChat.registerDevice
///
/// All actions are handled inline with direct SQL queries.
///
/// Actions:
///   - register: Register a new device (or re-register existing)
///   - updateToken: Register/update a push notification token
///   - removeToken: Remove a push notification token
///   - delete: Delete a device and its key packages
///   - claimPendingAddition: Claim a pending device addition for processing
///   - completePendingAddition: Mark a claimed pending addition as completed
#[tracing::instrument(skip(pool, sse_state, auth_user, input))]
pub async fn register_device_post(
    State(pool): State<DbPool>,
    State(sse_state): State<Arc<SseState>>,
    auth_user: AuthUser,
    ExtractXrpc(input): ExtractXrpc<RegisterDeviceRequest>,
) -> Result<Response, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Determine action: explicit field, or infer from payload shape
    let raw: serde_json::Value = serde_json::to_value(&input).unwrap_or_default();
    let explicit_action = raw.get("action").and_then(|v| v.as_str());

    let action = if let Some(a) = explicit_action {
        a.to_string()
    } else {
        // Infer action from payload: empty keyPackages + pushToken = token update
        let key_packages_empty = input.key_packages.is_empty();
        let has_push_token = input.push_token.is_some();
        if key_packages_empty && has_push_token {
            info!("Inferred updateToken action (empty keyPackages + pushToken present)");
            "updateToken".to_string()
        } else {
            "register".to_string()
        }
    };

    match action.as_str() {
        "register" => Ok(handle_register(&pool, &sse_state, &auth_user, &input)
            .await?
            .into_response()),
        "updateToken" => Ok(handle_update_token(&pool, &auth_user, &input)
            .await?
            .into_response()),
        "removeToken" => Ok(handle_remove_token(&pool, &auth_user, &raw)
            .await?
            .into_response()),
        "delete" => Ok(handle_delete(&pool, &auth_user, &raw)
            .await?
            .into_response()),
        "claimPendingAddition" => Ok(handle_claim_pending_addition(&pool, &auth_user, &raw)
            .await?
            .into_response()),
        "completePendingAddition" => Ok(handle_complete_pending_addition(&pool, &auth_user, &raw)
            .await?
            .into_response()),
        unknown => {
            warn!("Unknown action for v2 registerDevice POST: {}", unknown);
            Err(StatusCode::BAD_REQUEST)
        }
    }
}

// ─── Action: register ───

async fn handle_register(
    pool: &DbPool,
    sse_state: &Arc<SseState>,
    auth_user: &AuthUser,
    input: &crate::generated::blue_catbird::mlsChat::register_device::RegisterDevice<'_>,
) -> Result<Json<RegisterDeviceOutput<'static>>, StatusCode> {
    let (user_did, _) = parse_device_did(&auth_user.did).map_err(|e| {
        error!("Invalid device DID format: {}", e);
        StatusCode::BAD_REQUEST
    })?;

    // Sanitize device name
    let sanitized_device_name: String = input
        .device_name
        .as_ref()
        .chars()
        .filter(|c| !c.is_control() && *c != '\u{FEFF}' && *c != '\u{200B}')
        .take(100)
        .collect();

    if sanitized_device_name.trim().is_empty() {
        warn!("Empty device name provided after sanitization");
        return Err(StatusCode::BAD_REQUEST);
    }
    let device_name = sanitized_device_name;

    // Validate signature public key (Ed25519 = 32 bytes)
    if input.signature_public_key.len() != 32 {
        warn!(
            "Invalid signature public key length: {} (expected 32 bytes)",
            input.signature_public_key.len()
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    // Validate key packages
    if input.key_packages.is_empty() {
        warn!("No key packages provided");
        return Err(StatusCode::BAD_REQUEST);
    }
    if input.key_packages.len() > 200 {
        warn!(
            "Too many key packages: {} (max 200)",
            input.key_packages.len()
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    for (idx, kp) in input.key_packages.iter().enumerate() {
        let key_data = kp.key_package.to_vec();
        if key_data.is_empty() {
            warn!("Empty key package at index {}", idx);
            return Err(StatusCode::BAD_REQUEST);
        }
        if *kp.expires.as_ref() <= Utc::now().fixed_offset() {
            warn!("Key package {} has past expiration", idx);
            return Err(StatusCode::BAD_REQUEST);
        }

        if let Err(e) = crate::db::validate_declared_key_package_binding(
            &user_did,
            kp.cipher_suite.as_ref(),
            &key_data,
            Some(&input.signature_public_key),
        )
        .await
        {
            warn!(
                "Rejected key package {} during pre-registration validation: {:#}",
                idx, e
            );
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    let sig_key_hex = hex::encode(&input.signature_public_key);
    let mut device_id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let mut tx = pool.begin().await.map_err(|e| {
        error!("Failed to begin device registration transaction: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let mut matched_by_uuid = false;
    let mut candidate: Option<(String, String)> = None;
    if let Some(ref device_uuid) = input.device_uuid {
        candidate = sqlx::query_as(
            "SELECT id, device_id FROM devices \
             WHERE user_did = $1 AND device_uuid = $2",
        )
        .bind(&user_did)
        .bind(device_uuid.as_ref())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| {
            error!("Failed to find existing device by UUID: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        matched_by_uuid = candidate.is_some();
    }
    if candidate.is_none() {
        candidate = sqlx::query_as(
            "SELECT id, device_id FROM devices \
             WHERE user_did = $1 AND signature_public_key = $2",
        )
        .bind(&user_did)
        .bind(&sig_key_hex)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| {
            error!("Failed to find existing device by signature key: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    }

    // Federation claims lock a KeyPackage before taking a shared device lock. Keep that
    // global order here: lock every package for the candidate device first, then lock and
    // revalidate the device row. The preliminary lookup is never trusted for authorization.
    let mut existing: Option<(String, String, bool)> = None;
    if let Some((candidate_id, candidate_device_id)) = candidate {
        sqlx::query(
            "SELECT id FROM key_packages \
             WHERE owner_did = $1 AND device_id = $2 \
             ORDER BY id FOR UPDATE",
        )
        .bind(&user_did)
        .bind(&candidate_device_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| {
            error!("Failed to lock existing device KeyPackages: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        existing = if matched_by_uuid {
            sqlx::query_as(
                "SELECT id, device_id, active FROM devices \
                 WHERE id = $1 AND user_did = $2 AND device_uuid = $3 FOR UPDATE",
            )
            .bind(&candidate_id)
            .bind(&user_did)
            .bind(input.device_uuid.as_ref().map(|value| value.as_ref()))
            .fetch_optional(&mut *tx)
            .await
        } else {
            sqlx::query_as(
                "SELECT id, device_id, active FROM devices \
                 WHERE id = $1 AND user_did = $2 AND signature_public_key = $3 FOR UPDATE",
            )
            .bind(&candidate_id)
            .bind(&user_did)
            .bind(&sig_key_hex)
            .fetch_optional(&mut *tx)
            .await
        }
        .map_err(|e| {
            error!("Failed to lock and revalidate existing device: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        if existing.is_none() {
            warn!(
                "Rejected re-registration after concurrent device identity change for user h:{}",
                crate::crypto::hash_for_log(&user_did)
            );
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    if matches!(existing, Some((_, _, false))) {
        warn!(
            "Rejected re-registration of inactive device for user h:{}",
            crate::crypto::hash_for_log(&user_did)
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    // Upsert user
    sqlx::query(
        r#"INSERT INTO users (did, created_at, last_seen_at)
           VALUES ($1, NOW(), NOW())
           ON CONFLICT (did) DO UPDATE SET last_seen_at = NOW()"#,
    )
    .bind(&user_did)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        error!("Failed to ensure user exists: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let is_reregistration = existing.is_some();
    if let Some((db_id, old_device_id, _active)) = existing {
        device_id = old_device_id.clone();
        info!(
            "Device re-registration detected for user h:{}: reusing device_id={}",
            crate::crypto::hash_for_log(&user_did),
            device_id
        );
        let deleted_count =
            cleanup_re_registered_device_key_packages_in_tx(&mut tx, &user_did, &old_device_id)
                .await?;
        info!(
            "Deleted {} old key packages for re-registered device {}",
            deleted_count, old_device_id
        );

        let rereg_mls_did = format!("{}#{}", user_did, device_id);
        let update_result = if matched_by_uuid {
            sqlx::query(
                r#"UPDATE devices
                   SET device_name = $1, credential_did = $2,
                       signature_public_key = $3, registered_at = NOW(), last_seen_at = NOW()
                   WHERE id = $4 AND active = TRUE"#,
            )
            .bind(&device_name)
            .bind(&rereg_mls_did)
            .bind(&sig_key_hex)
            .bind(&db_id)
            .execute(&mut *tx)
            .await
        } else {
            sqlx::query(
                r#"UPDATE devices
                   SET device_name = $1, credential_did = $2,
                       device_uuid = $3, registered_at = NOW(), last_seen_at = NOW()
                   WHERE id = $4 AND active = TRUE"#,
            )
            .bind(&device_name)
            .bind(&rereg_mls_did)
            .bind(input.device_uuid.as_ref().map(|s| s.as_ref()))
            .bind(&db_id)
            .execute(&mut *tx)
            .await
        };
        update_result.map_err(|e| {
            error!("Failed to update re-registered device: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    }

    // Compute mls_did after device_id is finalized (may be reused from existing device)
    let mls_did = format!("{}#{}", user_did, device_id);

    info!(
        "Registering device for user h:{}: {} ({}) [re-registration: {}]",
        crate::crypto::hash_for_log(&user_did),
        device_id,
        device_name,
        is_reregistration
    );

    // Insert new device if not re-registration
    if !is_reregistration {
        let device_count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM devices WHERE user_did = $1")
                .bind(&user_did)
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| {
                    error!("Failed to count user devices: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;

        if device_count.0 >= 20 {
            warn!(
                "User h:{} has reached device limit: {}",
                crate::crypto::hash_for_log(&user_did),
                device_count.0
            );
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }

        let db_device_id = Uuid::new_v4().to_string();
        sqlx::query(
            r#"INSERT INTO devices (id, user_did, device_id, device_name, credential_did, signature_public_key, device_uuid, registered_at, last_seen_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())"#,
        )
        .bind(&db_device_id)
        .bind(&user_did)
        .bind(&device_id)
        .bind(&device_name)
        .bind(&mls_did)
        .bind(&sig_key_hex)
        .bind(input.device_uuid.as_ref().map(|s| s.as_ref()))
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            error!("Failed to insert device: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    }

    // Store key packages via the shared db helper (handles OpenMLS parsing, hash computation, credential validation)
    let mut stored_count = 0u64;
    for (idx, kp) in input.key_packages.iter().enumerate() {
        let key_data = kp.key_package.to_vec();
        if key_data.is_empty() {
            warn!("Empty key package at index {}", idx);
            continue;
        }
        if *kp.expires.as_ref() <= now.fixed_offset() {
            warn!("Key package {} has past expiration", idx);
            continue;
        }

        match crate::db::store_key_package_with_device_bound_to_signature_in_tx(
            &mut tx,
            &user_did,
            kp.cipher_suite.as_ref(),
            key_data,
            kp.expires.as_ref().with_timezone(&Utc),
            Some(device_id.clone()),
            Some(&input.signature_public_key),
            false,
        )
        .await
        {
            Ok(_) => stored_count += 1,
            Err(e) => {
                warn!(
                    "Rejected key package {} during device registration: {:#}",
                    idx, e
                );
                return Err(StatusCode::BAD_REQUEST);
            }
        }
    }
    info!(
        "Stored {} key packages for device {}",
        stored_count, device_id
    );

    // Update push token atomically if provided during registration
    if let Some(ref push_token) = input.push_token {
        sqlx::query(
            r#"UPDATE devices
               SET push_token = $3, push_token_updated_at = NOW(), last_seen_at = NOW()
               WHERE user_did = $1 AND device_id = $2"#,
        )
        .bind(&user_did)
        .bind(&device_id)
        .bind(push_token.as_ref())
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            warn!("Failed to store push token during registration: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        info!("Push token stored during device registration");
    }

    tx.commit().await.map_err(|e| {
        error!("Failed to commit device registration transaction: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Find active conversations for auto-join
    let convos: Vec<(String,)> = sqlx::query_as(
        "SELECT DISTINCT convo_id FROM members WHERE user_did = $1 AND left_at IS NULL",
    )
    .bind(&user_did)
    .fetch_all(pool)
    .await
    .map_err(|e| {
        error!("Failed to fetch user conversations: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let auto_joined_convos: Vec<String> = convos.iter().map(|(id,)| id.clone()).collect();
    info!(
        "Device {} can auto-join {} conversations",
        device_id,
        auto_joined_convos.len()
    );

    // Create pending device additions for each conversation
    for convo_id in &auto_joined_convos {
        let pending_id = Uuid::new_v4().to_string();

        let insert_result = sqlx::query_as::<_, (String,)>(
            r#"INSERT INTO pending_device_additions
                   (id, convo_id, user_did, new_device_id, new_device_credential_did, device_name, status, created_at)
               VALUES ($1, $2, $3, $4, $5, $6, 'pending', NOW())
               ON CONFLICT (convo_id, new_device_credential_did) DO UPDATE
                   SET new_device_id = EXCLUDED.new_device_id,
                       device_name = EXCLUDED.device_name,
                       status = 'pending',
                       claimed_by_did = NULL,
                       claimed_at = NULL,
                       claim_expires_at = NULL,
                       updated_at = NOW()
                   WHERE pending_device_additions.status != 'completed'
               RETURNING id"#,
        )
        .bind(&pending_id)
        .bind(convo_id)
        .bind(&user_did)
        .bind(&device_id)
        .bind(&mls_did)
        .bind(&device_name)
        .fetch_optional(pool)
        .await;

        match insert_result {
            Ok(Some(_)) => {
                let cursor = sse_state.cursor_gen.next(convo_id, "newDeviceEvent").await;
                let event = StreamEvent::NewDeviceEvent {
                    cursor,
                    convo_id: convo_id.clone(),
                    user_did: user_did.to_string(),
                    device_id: device_id.clone(),
                    device_name: Some(device_name.clone()),
                    device_credential_did: mls_did.clone(),
                    pending_addition_id: pending_id.clone(),
                };
                if let Err(e) = sse_state.emit(convo_id, event).await {
                    warn!(
                        "Failed to emit NewDeviceEvent for convo {}: {}",
                        crate::crypto::redact_for_log(convo_id),
                        e
                    );
                }
            }
            Ok(None) => {
                info!(
                    "Pending addition already exists for device {} in convo {}",
                    device_id,
                    crate::crypto::redact_for_log(convo_id)
                );
            }
            Err(e) => {
                warn!(
                    "Failed to create pending addition for convo {}: {}",
                    crate::crypto::redact_for_log(convo_id),
                    e
                );
            }
        }
    }

    Ok(Json(RegisterDeviceOutput {
        device_id: device_id.into(),
        mls_did: mls_did.into(),
        auto_joined_convos: auto_joined_convos.into_iter().map(|s| s.into()).collect(),
        welcome_messages: None,
        extra_data: Default::default(),
    }))
}

// ─── Action: updateToken ───

async fn handle_update_token(
    pool: &DbPool,
    auth_user: &AuthUser,
    input: &crate::generated::blue_catbird::mlsChat::register_device::RegisterDevice<'_>,
) -> Result<Json<RegisterDeviceOutput<'static>>, StatusCode> {
    let push_token = input
        .push_token
        .as_ref()
        .map(|s| s.as_ref().to_string())
        .ok_or_else(|| {
            warn!("updateToken action requires pushToken field");
            StatusCode::BAD_REQUEST
        })?;

    let device_name = input.device_name.as_ref().to_string();
    let device_uuid = input.device_uuid.as_ref().map(|s| s.as_ref().to_string());

    // Find device — prefer deviceUUID, fall back to most recent
    let device: Option<(String, String)> = if let Some(ref uuid) = device_uuid {
        sqlx::query_as(
            "SELECT device_id, user_did FROM devices WHERE user_did = $1 AND device_uuid = $2",
        )
        .bind(&auth_user.did)
        .bind(uuid)
        .fetch_optional(pool)
        .await
        .map_err(|e| {
            warn!("Failed to query device by UUID: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
    } else {
        sqlx::query_as(
            "SELECT device_id, user_did FROM devices WHERE user_did = $1 ORDER BY registered_at DESC LIMIT 1",
        )
        .bind(&auth_user.did)
        .fetch_optional(pool)
        .await
        .map_err(|e| {
            warn!("Failed to query device: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
    };

    let (device_id, _) = device.ok_or_else(|| {
        warn!(
            "No device found for user h:{} - must register first",
            crate::crypto::hash_for_log(&auth_user.did)
        );
        StatusCode::NOT_FOUND
    })?;

    sqlx::query(
        r#"UPDATE devices
           SET push_token = $3,
               push_token_updated_at = NOW(),
               device_name = COALESCE(NULLIF($4, ''), device_name),
               last_seen_at = NOW()
           WHERE user_did = $1 AND device_id = $2"#,
    )
    .bind(&auth_user.did)
    .bind(&device_id)
    .bind(&push_token)
    .bind(&device_name)
    .execute(pool)
    .await
    .map_err(|e| {
        warn!("Failed to update push token: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let mls_did = format!("{}#{}", auth_user.did, device_id);
    info!(device_id = %device_id, "Push token updated");

    Ok(Json(RegisterDeviceOutput {
        device_id: device_id.into(),
        mls_did: mls_did.into(),
        auto_joined_convos: vec![],
        welcome_messages: None,
        extra_data: Default::default(),
    }))
}

// ─── Action: removeToken ───

async fn handle_remove_token(
    pool: &DbPool,
    auth_user: &AuthUser,
    raw: &serde_json::Value,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let device_id = raw
        .get("deviceId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            warn!("removeToken action requires deviceId field");
            StatusCode::BAD_REQUEST
        })?;

    sqlx::query(
        "UPDATE devices SET push_token = NULL, push_token_updated_at = NULL WHERE user_did = $1 AND device_id = $2",
    )
    .bind(&auth_user.did)
    .bind(device_id)
    .execute(pool)
    .await
    .map_err(|e| {
        warn!("Failed to unregister push token: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!(device_id = %device_id, "Push token removed");

    // TODO: Replace json! with generated output type once lexicon defines removeToken output
    Ok(Json(serde_json::json!({ "success": true })))
}

// ─── Action: delete ───

async fn handle_delete(
    pool: &DbPool,
    auth_user: &AuthUser,
    raw: &serde_json::Value,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let device_id = raw
        .get("deviceId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            warn!("delete action requires deviceId field");
            StatusCode::BAD_REQUEST
        })?;

    let user_did = &auth_user.did;

    // Verify device exists and is owned by caller
    let device_info: Option<(String, String)> =
        sqlx::query_as("SELECT user_did, credential_did FROM devices WHERE device_id = $1")
            .bind(device_id)
            .fetch_optional(pool)
            .await
            .map_err(|e| {
                error!("Failed to query device: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

    let (owner_did, credential_did) = match device_info {
        Some(info) => info,
        None => {
            warn!("Device not found: {} (treating as success)", device_id);
            // TODO: Replace json! with generated output type once lexicon defines delete output
            return Ok(Json(serde_json::json!({
                "deleted": false,
                "keyPackagesDeleted": 0,
                "conversationsLeft": 0,
            })));
        }
    };

    if owner_did != *user_did {
        warn!(
            "User h:{} attempted to delete device {} owned by another user",
            crate::crypto::hash_for_log(user_did),
            device_id
        );
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Mark device as left in all conversations
    let members_removed =
        sqlx::query("UPDATE members SET left_at = NOW() WHERE device_id = $1 AND left_at IS NULL")
            .bind(device_id)
            .execute(pool)
            .await
            .map_err(|e| {
                error!("Failed to remove device from conversations: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?
            .rows_affected();

    // Clean up pending welcome messages (non-critical)
    sqlx::query(
        "DELETE FROM welcome_messages \
         WHERE consumed = false \
           AND (recipient_did = $1 OR (recipient_did = $2 AND recipient_device_id = $3))",
    )
    .bind(&credential_did)
    .bind(user_did)
    .bind(device_id)
    .execute(pool)
    .await
    .ok();

    // Delete key packages
    let key_packages_deleted = sqlx::query("DELETE FROM key_packages WHERE device_id = $1")
        .bind(device_id)
        .execute(pool)
        .await
        .map_err(|e| {
            error!("Failed to delete key packages: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .rows_affected();

    // Delete device record
    let devices_deleted = sqlx::query("DELETE FROM devices WHERE device_id = $1")
        .bind(device_id)
        .execute(pool)
        .await
        .map_err(|e| {
            error!("Failed to delete device: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .rows_affected();

    if devices_deleted == 0 {
        error!("Device deletion failed - device not found: {}", device_id);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    info!(
        "Successfully deleted device {} and {} key packages",
        device_id, key_packages_deleted
    );

    // TODO: Replace json! with generated output type once lexicon defines delete output
    Ok(Json(serde_json::json!({
        "deleted": true,
        "keyPackagesDeleted": key_packages_deleted,
        "conversationsLeft": members_removed,
    })))
}

// ─── Action: claimPendingAddition ───

// TODO: Replace all json! responses below with generated output type once lexicon defines claimPendingAddition output
async fn handle_claim_pending_addition(
    pool: &DbPool,
    auth_user: &AuthUser,
    raw: &serde_json::Value,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let pending_addition_id = raw
        .get("pendingAdditionId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            warn!("claimPendingAddition requires pendingAdditionId field");
            StatusCode::BAD_REQUEST
        })?;

    let (user_did, _) = parse_device_did(&auth_user.did).map_err(|e| {
        error!("Invalid DID format: {}", e);
        StatusCode::BAD_REQUEST
    })?;

    let now = Utc::now();
    let claim_expires = now + Duration::seconds(60);

    info!(
        user = %crate::crypto::redact_for_log(&user_did),
        pending_id = %crate::crypto::redact_for_log(pending_addition_id),
        "Attempting to claim pending device addition"
    );

    // Release expired claims
    let released = sqlx::query(
        r#"UPDATE pending_device_additions
           SET status = 'pending', claimed_by_did = NULL, claimed_at = NULL,
               claim_expires_at = NULL, updated_at = NOW()
           WHERE status = 'in_progress' AND claim_expires_at < $1"#,
    )
    .bind(now)
    .execute(pool)
    .await
    .map_err(|e| {
        error!("Failed to release expired claims: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .rows_affected();

    if released > 0 {
        info!("Released {} expired pending addition claims", released);
    }

    // Fetch pending addition
    let pending: Option<(
        String,         // id
        String,         // convo_id
        String,         // user_did
        String,         // new_device_id
        String,         // new_device_credential_did
        Option<String>, // device_name
        String,         // status
        Option<String>, // claimed_by_did
    )> = sqlx::query_as(
        r#"SELECT id, convo_id, user_did, new_device_id, new_device_credential_did,
                  device_name, status, claimed_by_did
           FROM pending_device_additions WHERE id = $1"#,
    )
    .bind(pending_addition_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        error!("Failed to fetch pending addition: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let (
        _p_id,
        p_convo_id,
        p_user_did,
        p_new_device_id,
        p_new_device_credential_did,
        _p_device_name,
        p_status,
        p_claimed_by_did,
    ) = match pending {
        Some(p) => p,
        None => {
            warn!("Pending addition not found: {}", pending_addition_id);
            return Ok(Json(serde_json::json!({
                "claimed": false,
            })));
        }
    };

    // Check terminal state
    if p_status != "pending" && p_status != "in_progress" {
        warn!(
            "Pending addition {} already in terminal state: {}",
            pending_addition_id, p_status
        );
        return Ok(Json(serde_json::json!({
            "claimed": false,
            "convoId": p_convo_id,
            "deviceCredentialDid": p_new_device_credential_did,
            "claimedBy": p_claimed_by_did,
        })));
    }

    // Verify membership
    let is_member: Option<(i32,)> = sqlx::query_as(
        "SELECT 1 FROM members WHERE convo_id = $1 AND user_did = $2 AND left_at IS NULL",
    )
    .bind(&p_convo_id)
    .bind(&user_did)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        error!("Failed to check membership: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if is_member.is_none() {
        warn!(
            "User h:{} is not a member of conversation {}",
            crate::crypto::hash_for_log(&user_did),
            p_convo_id
        );
        return Err(StatusCode::FORBIDDEN);
    }

    // Prevent self-claim
    if p_user_did == user_did {
        info!(
            "User h:{} attempted to claim their own device addition - returning not claimed",
            crate::crypto::hash_for_log(&user_did)
        );
        return Ok(Json(serde_json::json!({
            "claimed": false,
            "convoId": p_convo_id,
            "deviceCredentialDid": p_new_device_credential_did,
        })));
    }

    // Atomically claim
    let claim_result: Option<(String,)> = sqlx::query_as(
        r#"UPDATE pending_device_additions
           SET status = 'in_progress', claimed_by_did = $2, claimed_at = $3,
               claim_expires_at = $4, updated_at = $3
           WHERE id = $1 AND (status = 'pending' OR (status = 'in_progress' AND claim_expires_at < $3))
           RETURNING id"#,
    )
    .bind(pending_addition_id)
    .bind(&user_did)
    .bind(now)
    .bind(claim_expires)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        error!("Failed to claim pending addition: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if claim_result.is_none() {
        info!("Pending addition {} already claimed", pending_addition_id,);
        return Ok(Json(serde_json::json!({
            "claimed": false,
            "convoId": p_convo_id,
            "deviceCredentialDid": p_new_device_credential_did,
            "claimedBy": p_claimed_by_did,
        })));
    }

    info!(
        "Successfully claimed pending addition {} for conversation {}",
        crate::crypto::redact_for_log(pending_addition_id),
        crate::crypto::redact_for_log(&p_convo_id)
    );

    // Fetch key package for new device
    let key_package: Option<(String, Option<String>, Option<String>, String)> = sqlx::query_as(
        r#"SELECT kp.owner_did, replace(encode(kp.key_package, 'base64'), chr(10), ''), kp.key_package_hash, kp.cipher_suite
           FROM key_packages kp
           WHERE kp.owner_did = $1 AND kp.device_id = $2
             AND kp.consumed_at IS NULL AND kp.expires_at > $3
             AND (kp.reserved_at IS NULL OR kp.reserved_at < $4)
           ORDER BY kp.created_at ASC LIMIT 1"#,
    )
    .bind(&p_user_did)
    .bind(&p_new_device_id)
    .bind(now)
    .bind(now - Duration::minutes(5))
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        error!("Failed to fetch key package: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let key_package_json = key_package.map(|(did, kp_data, kp_hash, cipher_suite)| {
        serde_json::json!({
            "did": did,
            "keyPackage": kp_data.unwrap_or_default(),
            "keyPackageHash": kp_hash,
            "cipherSuite": cipher_suite,
        })
    });

    if key_package_json.is_none() {
        warn!(
            "No available key package for device {} (user h:{})",
            p_new_device_id,
            crate::crypto::hash_for_log(&p_user_did)
        );
    }

    Ok(Json(serde_json::json!({
        "claimed": true,
        "convoId": p_convo_id,
        "deviceCredentialDid": p_new_device_credential_did,
        "keyPackage": key_package_json,
        "claimedBy": user_did,
    })))
}

// ─── Action: completePendingAddition ───

// TODO: Replace all json! responses below with generated output type once lexicon defines completePendingAddition output
async fn handle_complete_pending_addition(
    pool: &DbPool,
    auth_user: &AuthUser,
    raw: &serde_json::Value,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let pending_addition_id = raw
        .get("pendingAdditionId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            warn!("completePendingAddition requires pendingAdditionId field");
            StatusCode::BAD_REQUEST
        })?;

    let new_epoch = raw
        .get("newEpoch")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| {
            warn!("completePendingAddition requires newEpoch field");
            StatusCode::BAD_REQUEST
        })?;

    let (user_did, _) = parse_device_did(&auth_user.did).map_err(|e| {
        error!("Invalid DID format: {}", e);
        StatusCode::BAD_REQUEST
    })?;

    let now = Utc::now();

    info!(
        user = %crate::crypto::redact_for_log(&user_did),
        pending_id = %crate::crypto::redact_for_log(pending_addition_id),
        new_epoch = new_epoch,
        "Completing pending device addition"
    );

    let result: Option<(String,)> = sqlx::query_as(
        r#"UPDATE pending_device_additions
           SET status = 'completed', completed_by_did = $2, completed_at = $3,
               new_epoch = $4, updated_at = $3
           WHERE id = $1 AND status = 'in_progress' AND claimed_by_did = $2
           RETURNING id"#,
    )
    .bind(pending_addition_id)
    .bind(&user_did)
    .bind(now)
    .bind(new_epoch as i32)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        error!("Failed to complete pending addition: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if result.is_none() {
        // Diagnose failure
        let pending: Option<(String, Option<String>)> = sqlx::query_as(
            "SELECT status, claimed_by_did FROM pending_device_additions WHERE id = $1",
        )
        .bind(pending_addition_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| {
            error!("Failed to fetch pending addition status: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        match pending {
            None => {
                warn!("Pending addition not found: {}", pending_addition_id);
                return Ok(Json(serde_json::json!({
                    "success": false,
                    "error": "PendingAdditionNotFound",
                })));
            }
            Some((status, claimed_by)) => {
                if status != "in_progress" {
                    warn!(
                        "Pending addition {} is not in_progress (status: {})",
                        pending_addition_id, status
                    );
                    return Ok(Json(serde_json::json!({
                        "success": false,
                        "error": format!("InvalidStatus:{}", status),
                    })));
                }
                if claimed_by.as_deref() != Some(&user_did) {
                    warn!(
                        "Pending addition {} claimed by {}, not {}",
                        crate::crypto::redact_for_log(pending_addition_id),
                        claimed_by
                            .as_deref()
                            .map(crate::crypto::redact_for_log)
                            .unwrap_or_else(|| "unknown".to_string()),
                        crate::crypto::redact_for_log(&user_did)
                    );
                    return Err(StatusCode::FORBIDDEN);
                }
            }
        }
    }

    info!(
        "Successfully completed pending addition {} at epoch {}",
        pending_addition_id, new_epoch
    );

    Ok(Json(serde_json::json!({
        "success": true,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AtProtoClaims;
    use crate::db::{init_db, DbConfig};
    use crate::generated::blue_catbird::mlsChat::register_device::{
        KeyPackageItem, RegisterDevice,
    };
    use sqlx::Row;
    use std::time::Duration as StdDuration;

    async fn setup_test_db() -> DbPool {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://localhost/catbird_test".to_string());

        init_db(DbConfig {
            database_url,
            max_connections: 4,
            min_connections: 1,
            acquire_timeout: StdDuration::from_secs(30),
            idle_timeout: StdDuration::from_secs(600),
        })
        .await
        .expect("initialize test database")
    }

    fn generate_key_package(identity: &str) -> (Vec<u8>, Vec<u8>) {
        use openmls::prelude::{tls_codec::Serialize as TlsSerialize, *};
        use openmls_basic_credential::SignatureKeyPair;
        use openmls_traits::OpenMlsProvider;

        let provider = openmls_libcrux_crypto::Provider::new().expect("libcrux provider");
        let ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
        let credential = BasicCredential::new(identity.as_bytes().to_vec());
        let signature_keys =
            SignatureKeyPair::new(ciphersuite.signature_algorithm()).expect("signature keypair");
        signature_keys
            .store(provider.storage())
            .expect("store signature keys");
        let signature_public_key = signature_keys.to_public_vec();
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signature_public_key.clone().into(),
        };
        let bundle = KeyPackage::builder()
            .build(ciphersuite, &provider, &signature_keys, credential_with_key)
            .expect("build key package");

        (
            bundle
                .key_package()
                .tls_serialize_detached()
                .expect("serialize key package"),
            signature_public_key,
        )
    }

    fn mismatched_registration_input<'a>(
        device_uuid: &'a str,
        key_package: Vec<u8>,
        signature_public_key: Vec<u8>,
    ) -> RegisterDevice<'a> {
        registration_input(
            Some(device_uuid),
            "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            key_package,
            signature_public_key,
        )
    }

    fn registration_input<'a>(
        device_uuid: Option<&'a str>,
        declared_cipher_suite: &'a str,
        key_package: Vec<u8>,
        signature_public_key: Vec<u8>,
    ) -> RegisterDevice<'a> {
        let key_package = KeyPackageItem::new()
            .cipher_suite(declared_cipher_suite)
            .expires((Utc::now() + Duration::days(1)).fixed_offset())
            .key_package(key_package)
            .build();

        RegisterDevice::new()
            .device_name("Regression device")
            .maybe_device_uuid(device_uuid.map(Into::into))
            .key_packages(vec![key_package])
            .signature_public_key(signature_public_key)
            .build()
    }

    fn auth_user(did: &str) -> AuthUser {
        AuthUser {
            did: did.to_string(),
            claims: AtProtoClaims {
                iss: did.to_string(),
                aud: "did:web:example.invalid".to_string(),
                exp: Utc::now().timestamp() + 300,
                iat: Some(Utc::now().timestamp()),
                sub: None,
                lxm: Some(NSID.to_string()),
                jti: None,
            },
        }
    }

    async fn cleanup_registration_fixture(pool: &DbPool, user_did: &str) {
        sqlx::query("DELETE FROM key_packages WHERE owner_did = $1")
            .bind(user_did)
            .execute(pool)
            .await
            .expect("cleanup key packages");
        sqlx::query("DELETE FROM devices WHERE user_did = $1")
            .bind(user_did)
            .execute(pool)
            .await
            .expect("cleanup devices");
        sqlx::query("DELETE FROM users WHERE did = $1")
            .bind(user_did)
            .execute(pool)
            .await
            .expect("cleanup user");
    }

    async fn registration_state_snapshot(
        pool: &DbPool,
        user_did: &str,
    ) -> (String, String, bool, i64, String) {
        let user: String =
            sqlx::query_scalar("SELECT row_to_json(u)::text FROM users u WHERE u.did = $1")
                .bind(user_did)
                .fetch_one(pool)
                .await
                .expect("snapshot user");
        let (device, active, auth_generation): (String, bool, i64) = sqlx::query_as(
            "SELECT (to_jsonb(d) - 'active' - 'auth_generation')::text, \
                    active, auth_generation \
             FROM devices d WHERE d.user_did = $1",
        )
        .bind(user_did)
        .fetch_one(pool)
        .await
        .expect("snapshot device");
        let key_packages: String = sqlx::query_scalar(
            "SELECT COALESCE(jsonb_agg(to_jsonb(kp) ORDER BY kp.id)::text, '[]') \
             FROM key_packages kp WHERE kp.owner_did = $1",
        )
        .bind(user_did)
        .fetch_one(pool)
        .await
        .expect("snapshot key packages");
        (user, device, active, auth_generation, key_packages)
    }

    async fn seed_registration_state(
        pool: &DbPool,
        user_did: &str,
        device_id: &str,
        device_uuid: &str,
        signature_hex: &str,
        suffix: &str,
        active: bool,
    ) {
        cleanup_registration_fixture(pool, user_did).await;
        sqlx::query(
            "INSERT INTO users (did, created_at, last_seen_at) \
             VALUES ($1, '2020-01-01T00:00:00Z', '2020-01-02T00:00:00Z')",
        )
        .bind(user_did)
        .execute(pool)
        .await
        .expect("seed registration user");
        sqlx::query(
            "INSERT INTO devices \
             (id, user_did, device_id, device_name, credential_did, signature_public_key, \
              device_uuid, registered_at, last_seen_at, active) \
             VALUES ($1, $2, $3, 'Inactive original', $4, $5, $6, \
                     '2020-01-03T00:00:00Z', '2020-01-04T00:00:00Z', $7)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(user_did)
        .bind(device_id)
        .bind(format!("{user_did}#{device_id}"))
        .bind(signature_hex)
        .bind(device_uuid)
        .bind(active)
        .execute(pool)
        .await
        .expect("seed registration device");
        sqlx::query(
            "INSERT INTO key_packages \
             (id, owner_did, device_id, credential_did, cipher_suite, key_package, \
              key_package_hash, created_at, expires_at, state) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, \
                     '2020-01-05T00:00:00Z', NOW() + INTERVAL '30 days', 'available')",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(user_did)
        .bind(device_id)
        .bind(format!("{user_did}#{device_id}"))
        .bind("MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519")
        .bind(vec![0xA5_u8, 0x5A])
        .bind(format!("registration-{suffix}"))
        .execute(pool)
        .await
        .expect("seed registration key package");
    }

    #[tokio::test]
    #[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
    async fn inactive_reregistration_by_uuid_or_signature_is_rejected_without_mutation() {
        let pool = setup_test_db().await;

        for match_by_uuid in [true, false] {
            let suffix = Uuid::new_v4().simple().to_string();
            let user_did = format!("did:plc:inactivereg{}", &suffix[..12]);
            let device_id = format!("device-{suffix}");
            let stored_uuid = format!("stored-{suffix}");
            let (key_package, signature_public_key) = generate_key_package(&user_did);
            let signature_hex = hex::encode(&signature_public_key);
            seed_registration_state(
                &pool,
                &user_did,
                &device_id,
                &stored_uuid,
                &signature_hex,
                &suffix,
                false,
            )
            .await;

            let before = registration_state_snapshot(&pool, &user_did).await;
            let requested_uuid = match_by_uuid.then_some(stored_uuid.as_str());
            let input = registration_input(
                requested_uuid,
                "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
                key_package,
                signature_public_key,
            );

            let result = handle_register(
                &pool,
                &Arc::new(SseState::new(16)),
                &auth_user(&user_did),
                &input,
            )
            .await;

            assert_eq!(
                result.expect_err("inactive re-registration must fail closed"),
                StatusCode::BAD_REQUEST
            );
            let after = registration_state_snapshot(&pool, &user_did).await;
            assert_eq!(
                after, before,
                "inactive registration state must be unchanged"
            );
            cleanup_registration_fixture(&pool, &user_did).await;
        }
    }

    #[tokio::test]
    #[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
    async fn concurrent_deactivation_fences_uuid_and_signature_reregistration() {
        let pool = setup_test_db().await;

        for match_by_uuid in [true, false] {
            let suffix = Uuid::new_v4().simple().to_string();
            let user_did = format!("did:plc:racinginactive{}", &suffix[..12]);
            let device_id = format!("device-{suffix}");
            let stored_uuid = format!("stored-{suffix}");
            let (key_package, signature_public_key) = generate_key_package(&user_did);
            let signature_hex = hex::encode(&signature_public_key);
            seed_registration_state(
                &pool,
                &user_did,
                &device_id,
                &stored_uuid,
                &signature_hex,
                &suffix,
                true,
            )
            .await;
            let before = registration_state_snapshot(&pool, &user_did).await;
            assert!(before.2, "race fixture must begin active");

            let mut deactivation = pool.begin().await.expect("begin deactivation");
            sqlx::query(
                "UPDATE devices SET active = FALSE \
                 WHERE user_did = $1 AND device_id = $2",
            )
            .bind(&user_did)
            .bind(&device_id)
            .execute(&mut *deactivation)
            .await
            .expect("stage deactivation");

            let requested_uuid = match_by_uuid.then_some(stored_uuid.as_str());
            let input = registration_input(
                requested_uuid,
                "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
                key_package,
                signature_public_key,
            );
            let sse_state = Arc::new(SseState::new(16));
            let auth_user = auth_user(&user_did);
            let mut registration = Box::pin(handle_register(&pool, &sse_state, &auth_user, &input));

            assert!(
                tokio::time::timeout(StdDuration::from_millis(100), &mut registration)
                    .await
                    .is_err(),
                "registration must wait for the contested device-row lock"
            );
            deactivation.commit().await.expect("commit deactivation");
            let result = tokio::time::timeout(StdDuration::from_secs(5), registration)
                .await
                .expect("registration resumes after deactivation");
            assert_eq!(
                result.expect_err("deactivation winner must reject registration"),
                StatusCode::BAD_REQUEST
            );

            let after = registration_state_snapshot(&pool, &user_did).await;
            assert_eq!(after.0, before.0, "user row must remain unchanged");
            assert_eq!(after.1, before.1, "device metadata must remain unchanged");
            assert!(!after.2, "deactivation must be the only device change");
            assert_eq!(
                after.3,
                before.3 + 1,
                "deactivation must be the only auth-generation change"
            );
            assert_eq!(after.4, before.4, "KeyPackages must remain unchanged");
            cleanup_registration_fixture(&pool, &user_did).await;
        }
    }

    #[tokio::test]
    #[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
    async fn reregistration_obeys_key_package_then_device_lock_order() {
        let pool = setup_test_db().await;

        for match_by_uuid in [true, false] {
            let suffix = Uuid::new_v4().simple().to_string();
            let user_did = format!("did:plc:lockorder{}", &suffix[..12]);
            let device_id = format!("device-{suffix}");
            let stored_uuid = format!("stored-{suffix}");
            let (key_package, signature_public_key) = generate_key_package(&user_did);
            let signature_hex = hex::encode(&signature_public_key);
            seed_registration_state(
                &pool,
                &user_did,
                &device_id,
                &stored_uuid,
                &signature_hex,
                &suffix,
                true,
            )
            .await;

            // Stage the first lock taken by federation KeyPackage claiming. A registration
            // following the global order must wait here without holding the device row.
            let mut federation_claim = pool.begin().await.expect("begin federation claim");
            sqlx::query(
                "SELECT id FROM key_packages \
                 WHERE owner_did = $1 AND device_id = $2 \
                 ORDER BY id FOR UPDATE",
            )
            .bind(&user_did)
            .bind(&device_id)
            .fetch_all(&mut *federation_claim)
            .await
            .expect("lock candidate KeyPackages");

            let requested_uuid = match_by_uuid.then_some(stored_uuid.as_str());
            let input = registration_input(
                requested_uuid,
                "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
                key_package,
                signature_public_key,
            );
            let sse_state = Arc::new(SseState::new(16));
            let auth_user = auth_user(&user_did);
            let mut registration = Box::pin(handle_register(&pool, &sse_state, &auth_user, &input));

            assert!(
                tokio::time::timeout(StdDuration::from_millis(100), &mut registration)
                    .await
                    .is_err(),
                "registration must wait for the federation KeyPackage lock"
            );

            // Federation takes the device lock only after its KeyPackage lock. This must not
            // wait on registration, otherwise the two paths have inverted their lock order.
            let device_lock = tokio::time::timeout(
                StdDuration::from_secs(1),
                sqlx::query(
                    "SELECT active FROM devices \
                     WHERE user_did = $1 AND device_id = $2 FOR SHARE",
                )
                .bind(&user_did)
                .bind(&device_id)
                .fetch_one(&mut *federation_claim),
            )
            .await;
            assert!(
                device_lock.is_ok(),
                "registration must not hold the device lock while waiting on KeyPackages"
            );
            device_lock
                .expect("device lock completed")
                .expect("lock active device");

            federation_claim
                .commit()
                .await
                .expect("commit federation claim");
            let output = tokio::time::timeout(StdDuration::from_secs(5), registration)
                .await
                .expect("registration resumes after federation claim")
                .expect("registration succeeds");
            assert_eq!(output.0.device_id.as_ref(), device_id);

            let active: bool = sqlx::query_scalar(
                "SELECT active FROM devices WHERE user_did = $1 AND device_id = $2",
            )
            .bind(&user_did)
            .bind(&device_id)
            .fetch_one(&pool)
            .await
            .expect("fetch re-registered device");
            assert!(active, "re-registered device remains active");
            cleanup_registration_fixture(&pool, &user_did).await;
        }
    }

    #[tokio::test]
    #[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
    async fn reregistration_and_last_resort_publish_share_key_package_then_device_order() {
        let pool = setup_test_db().await;
        let suffix = Uuid::new_v4().simple().to_string();
        let user_did = format!("did:plc:lastresortlock{}", &suffix[..12]);
        let device_id = format!("device-{suffix}");
        let stored_uuid = format!("stored-{suffix}");
        let (key_package, signature_public_key) = generate_key_package(&user_did);
        let signature_hex = hex::encode(&signature_public_key);
        seed_registration_state(
            &pool,
            &user_did,
            &device_id,
            &stored_uuid,
            &signature_hex,
            &suffix,
            true,
        )
        .await;
        sqlx::query(
            "UPDATE key_packages SET is_last_resort = TRUE \
             WHERE owner_did = $1 AND device_id = $2",
        )
        .bind(&user_did)
        .bind(&device_id)
        .execute(&pool)
        .await
        .expect("mark existing package as last resort");

        // Stage the first lock taken by re-registration. The actual shared publication
        // helper must wait here before it acquires a shared device lock.
        let mut registration = pool.begin().await.expect("begin registration");
        sqlx::query(
            "SELECT id FROM key_packages \
             WHERE owner_did = $1 AND device_id = $2 \
             ORDER BY id FOR UPDATE",
        )
        .bind(&user_did)
        .bind(&device_id)
        .fetch_all(&mut *registration)
        .await
        .expect("lock re-registration KeyPackages");

        let mut publication = pool.begin().await.expect("begin last-resort publication");
        let publisher_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *publication)
            .await
            .expect("fetch publisher backend pid");
        let publish_did = user_did.clone();
        let publish_device_id = device_id.clone();
        let publish_signature_key = signature_public_key.clone();
        let publisher = tokio::spawn(async move {
            let result = crate::db::store_key_package_with_device_bound_to_signature_in_tx(
                &mut publication,
                &publish_did,
                "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
                key_package,
                Utc::now() + Duration::days(1),
                Some(publish_device_id),
                Some(&publish_signature_key),
                true,
            )
            .await;
            (publication, result)
        });

        let mut publisher_waiting_on_key_package = false;
        for _ in 0..100 {
            publisher_waiting_on_key_package = sqlx::query_scalar(
                "SELECT EXISTS( \
                   SELECT 1 FROM pg_stat_activity \
                   WHERE pid = $1 AND wait_event_type = 'Lock' \
                     AND query LIKE '%UPDATE key_packages%' \
                 )",
            )
            .bind(publisher_pid)
            .fetch_one(&pool)
            .await
            .expect("inspect publisher wait state");
            if publisher_waiting_on_key_package {
                break;
            }
            tokio::time::sleep(StdDuration::from_millis(10)).await;
        }
        assert!(
            publisher_waiting_on_key_package,
            "last-resort publication must reach the contested KeyPackage lock"
        );

        let device_lock = tokio::time::timeout(
            StdDuration::from_secs(1),
            sqlx::query(
                "SELECT active FROM devices \
                 WHERE user_did = $1 AND device_id = $2 FOR UPDATE",
            )
            .bind(&user_did)
            .bind(&device_id)
            .fetch_one(&mut *registration),
        )
        .await;
        assert!(
            device_lock.is_ok(),
            "last-resort publication must not hold the device lock while waiting on KeyPackages"
        );
        device_lock
            .expect("device lock completed")
            .expect("lock registration device");

        registration
            .commit()
            .await
            .expect("commit registration lock stage");
        let (publication, published) = tokio::time::timeout(StdDuration::from_secs(5), publisher)
            .await
            .expect("publication resumes after registration")
            .expect("publisher task completes");
        published.expect("last-resort publication succeeds");
        publication.commit().await.expect("commit publication");

        let available_last_resort: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM key_packages \
             WHERE owner_did = $1 AND device_id = $2 \
               AND is_last_resort = TRUE AND state = 'available' AND dead_at IS NULL",
        )
        .bind(&user_did)
        .bind(&device_id)
        .fetch_one(&pool)
        .await
        .expect("count available last-resort packages");
        assert_eq!(
            available_last_resort, 1,
            "last-resort replacement semantics must be preserved"
        );
        cleanup_registration_fixture(&pool, &user_did).await;
    }

    #[tokio::test]
    #[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
    async fn declared_ciphersuite_mismatch_does_not_mutate_new_registration() {
        let pool = setup_test_db().await;
        let suffix = Uuid::new_v4().simple().to_string();
        let user_did = format!("did:plc:newmismatch{}", &suffix[..12]);
        let device_uuid = format!("new-mismatch-{suffix}");
        cleanup_registration_fixture(&pool, &user_did).await;
        let (key_package, signature_public_key) = generate_key_package(&user_did);
        let input = mismatched_registration_input(&device_uuid, key_package, signature_public_key);

        let result = handle_register(
            &pool,
            &Arc::new(SseState::new(16)),
            &auth_user(&user_did),
            &input,
        )
        .await;

        assert_eq!(
            result.expect_err("mismatch must fail"),
            StatusCode::BAD_REQUEST
        );
        let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE did = $1")
            .bind(&user_did)
            .fetch_one(&pool)
            .await
            .expect("count users");
        let devices: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM devices WHERE user_did = $1")
            .bind(&user_did)
            .fetch_one(&pool)
            .await
            .expect("count devices");
        let key_packages: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM key_packages WHERE owner_did = $1")
                .bind(&user_did)
                .fetch_one(&pool)
                .await
                .expect("count key packages");
        assert_eq!((users, devices, key_packages), (0, 0, 0));
    }

    #[tokio::test]
    #[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
    async fn declared_ciphersuite_mismatch_does_not_mutate_reregistration() {
        let pool = setup_test_db().await;
        let suffix = Uuid::new_v4().simple().to_string();
        let user_did = format!("did:plc:reregmismatch{}", &suffix[..12]);
        let device_id = format!("device-{suffix}");
        let device_uuid = format!("uuid-{suffix}");
        let old_signature_hex = hex::encode([0x41_u8; 32]);
        cleanup_registration_fixture(&pool, &user_did).await;
        sqlx::query("INSERT INTO users (did) VALUES ($1)")
            .bind(&user_did)
            .execute(&pool)
            .await
            .expect("seed user");
        sqlx::query(
            "INSERT INTO devices \
             (id, user_did, device_id, device_name, credential_did, signature_public_key, device_uuid) \
             VALUES ($1, $2, $3, 'Original device', $4, $5, $6)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&user_did)
        .bind(&device_id)
        .bind(format!("{user_did}#{device_id}"))
        .bind(&old_signature_hex)
        .bind(&device_uuid)
        .execute(&pool)
        .await
        .expect("seed device");
        sqlx::query(
            "INSERT INTO key_packages \
             (id, owner_did, device_id, cipher_suite, key_package, key_package_hash) \
             VALUES ($1, $2, $3, 'legacy-suite', $4, $5)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&user_did)
        .bind(&device_id)
        .bind(vec![0xA5_u8])
        .bind(format!("legacy-{suffix}"))
        .execute(&pool)
        .await
        .expect("seed key package");
        let (key_package, signature_public_key) = generate_key_package(&user_did);
        let input = mismatched_registration_input(&device_uuid, key_package, signature_public_key);

        let result = handle_register(
            &pool,
            &Arc::new(SseState::new(16)),
            &auth_user(&user_did),
            &input,
        )
        .await;

        assert_eq!(
            result.expect_err("mismatch must fail"),
            StatusCode::BAD_REQUEST
        );
        let device: (String, String) = sqlx::query_as(
            "SELECT device_name, signature_public_key FROM devices \
             WHERE user_did = $1 AND device_uuid = $2",
        )
        .bind(&user_did)
        .bind(&device_uuid)
        .fetch_one(&pool)
        .await
        .expect("fetch unchanged device");
        let key_packages: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM key_packages WHERE owner_did = $1 AND device_id = $2",
        )
        .bind(&user_did)
        .bind(&device_id)
        .fetch_one(&pool)
        .await
        .expect("count unchanged key packages");
        assert_eq!(device, ("Original device".to_string(), old_signature_hex));
        assert_eq!(key_packages, 1);
        cleanup_registration_fixture(&pool, &user_did).await;
    }

    #[tokio::test]
    #[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
    async fn reregistration_cleanup_preserves_unconsumed_welcomes_for_same_device() {
        let pool = setup_test_db().await;
        let suffix = Uuid::new_v4().simple().to_string();
        let user_did = format!("did:plc:rereg{}", &suffix[..16]);
        let device_id = Uuid::new_v4().to_string();
        let credential_did = format!("{user_did}#{device_id}");
        let convo_id = format!("rereg-preserve-{suffix}");

        sqlx::query("INSERT INTO users (did) VALUES ($1) ON CONFLICT DO NOTHING")
            .bind(&user_did)
            .execute(&pool)
            .await
            .expect("seed user");

        sqlx::query(
            r#"INSERT INTO conversations
               (id, creator_did, current_epoch, cipher_suite, is_remote, group_id)
               VALUES ($1, $2, 1, 'MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519', false, $1)"#,
        )
        .bind(&convo_id)
        .bind(&user_did)
        .execute(&pool)
        .await
        .expect("seed conversation");

        sqlx::query(
            r#"INSERT INTO key_packages
               (id, owner_did, device_id, credential_did, cipher_suite, key_package, key_package_hash)
               VALUES ($1, $2, $3, $4, 'MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519', $5, $6)"#,
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&user_did)
        .bind(&device_id)
        .bind(&credential_did)
        .bind(vec![0x42_u8])
        .bind(format!("hash-{suffix}"))
        .execute(&pool)
        .await
        .expect("seed key package");

        sqlx::query(
            r#"INSERT INTO welcome_messages
               (id, convo_id, recipient_did, recipient_device_id, welcome_data, key_package_hash, consumed)
               VALUES ($1, $2, $3, $4, $5, $6, false)"#,
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&convo_id)
        .bind(&user_did)
        .bind(&device_id)
        .bind(vec![0xAA_u8, 0xBB])
        .bind(vec![0xDE_u8, 0xAD])
        .execute(&pool)
        .await
        .expect("seed welcome");

        let deleted = cleanup_re_registered_device_key_packages(&pool, &user_did, &device_id)
            .await
            .expect("cleanup succeeds");

        assert_eq!(deleted, 1, "old key packages should still be removed");

        let rows = sqlx::query(
            "SELECT consumed FROM welcome_messages WHERE convo_id = $1 AND recipient_device_id = $2",
        )
        .bind(&convo_id)
        .bind(&device_id)
        .fetch_all(&pool)
        .await
        .expect("fetch welcomes");

        assert_eq!(rows.len(), 1);
        let consumed: bool = rows[0].get("consumed");
        assert!(
            !consumed,
            "pending Welcome must remain available for the receiver to consume"
        );

        sqlx::query("DELETE FROM conversations WHERE id = $1")
            .bind(&convo_id)
            .execute(&pool)
            .await
            .expect("cleanup conversation");
        sqlx::query("DELETE FROM users WHERE did = $1")
            .bind(&user_did)
            .execute(&pool)
            .await
            .expect("cleanup user");
    }
}
