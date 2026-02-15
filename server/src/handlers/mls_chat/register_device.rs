use axum::{extract::State, http::StatusCode, Json};
use base64::Engine;
use chrono::{Duration, Utc};
use jacquard_axum::ExtractXrpc;
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::{
    auth::AuthUser,
    device_utils::parse_device_did,
    generated::blue_catbird::mlsChat::register_device::RegisterDeviceRequest,
    realtime::{SseState, StreamEvent},
    storage::DbPool,
};

// NSID for auth enforcement
const NSID: &str = "blue.catbird.mlsChat.registerDevice";

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
) -> Result<Json<serde_json::Value>, StatusCode> {
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
        "register" => handle_register(&pool, &sse_state, &auth_user, &input).await,
        "updateToken" => handle_update_token(&pool, &auth_user, &input).await,
        "removeToken" => handle_remove_token(&pool, &auth_user, &raw).await,
        "delete" => handle_delete(&pool, &auth_user, &raw).await,
        "claimPendingAddition" => handle_claim_pending_addition(&pool, &auth_user, &raw).await,
        "completePendingAddition" => {
            handle_complete_pending_addition(&pool, &auth_user, &raw).await
        }
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
) -> Result<Json<serde_json::Value>, StatusCode> {
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

    let device_id = Uuid::new_v4().to_string();
    let mls_did = format!("{}#{}", &user_did, device_id);
    let now = Utc::now();
    let sig_key_hex = hex::encode(&input.signature_public_key);

    // Upsert user
    sqlx::query(
        r#"INSERT INTO users (did, created_at, last_seen_at)
           VALUES ($1, NOW(), NOW())
           ON CONFLICT (did) DO UPDATE SET last_seen_at = NOW()"#,
    )
    .bind(&user_did)
    .execute(pool)
    .await
    .map_err(|e| {
        error!("Failed to ensure user exists: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Check for re-registration by device_uuid
    let mut is_reregistration = if let Some(ref device_uuid) = input.device_uuid {
        let existing: Option<(String, String, String)> = sqlx::query_as(
            "SELECT id, device_id, credential_did FROM devices WHERE user_did = $1 AND device_uuid = $2",
        )
        .bind(&user_did)
        .bind(device_uuid.as_ref())
        .fetch_optional(pool)
        .await
        .map_err(|e| {
            error!("Failed to check existing device by UUID: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        if let Some((db_id, old_device_id, _old_credential_did)) = existing {
            info!(
                "Device re-registration detected for user {}: device_uuid={}, old_device_id={}",
                user_did,
                device_uuid.as_ref(),
                old_device_id
            );

            // Clean up old key packages
            let deleted_count = sqlx::query("DELETE FROM key_packages WHERE owner_did = $1 AND device_id = $2")
                .bind(&user_did)
                .bind(&old_device_id)
                .execute(pool)
                .await
                .map_err(|e| {
                    error!("Failed to delete old key packages: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?
                .rows_affected();
            info!("Deleted {} old key packages for re-registered device {}", deleted_count, old_device_id);

            // Invalidate pending welcomes
            let invalidated = sqlx::query(
                r#"UPDATE welcome_messages
                   SET consumed = true, consumed_at = NOW(), error_reason = 'Device re-registered with fresh key packages'
                   WHERE recipient_did = $1 AND consumed = false"#,
            )
            .bind(&user_did)
            .execute(pool)
            .await
            .map_err(|e| {
                error!("Failed to invalidate old Welcome messages: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?
            .rows_affected();

            if invalidated > 0 {
                info!("Invalidated {} stale Welcome messages for re-registered user {}", invalidated, user_did);
            }

            // Update existing device record
            sqlx::query(
                r#"UPDATE devices
                   SET device_id = $1, device_name = $2, credential_did = $3,
                       signature_public_key = $4, registered_at = NOW(), last_seen_at = NOW()
                   WHERE id = $5"#,
            )
            .bind(&device_id)
            .bind(&device_name)
            .bind(&mls_did)
            .bind(&sig_key_hex)
            .bind(&db_id)
            .execute(pool)
            .await
            .map_err(|e| {
                error!("Failed to update re-registered device: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            true
        } else {
            false
        }
    } else {
        false
    };

    // Check re-registration by signature_public_key
    if !is_reregistration {
        let existing: Option<(String, String, String)> = sqlx::query_as(
            "SELECT id, device_id, credential_did FROM devices WHERE user_did = $1 AND signature_public_key = $2",
        )
        .bind(&user_did)
        .bind(&sig_key_hex)
        .fetch_optional(pool)
        .await
        .map_err(|e| {
            error!("Failed to check existing device by signature key: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        if let Some((db_id, old_device_id, _old_credential_did)) = existing {
            info!(
                "Device re-registration detected by signature key for user {}: old_device_id={}",
                user_did, old_device_id
            );

            let deleted_count = sqlx::query("DELETE FROM key_packages WHERE owner_did = $1 AND device_id = $2")
                .bind(&user_did)
                .bind(&old_device_id)
                .execute(pool)
                .await
                .map_err(|e| {
                    error!("Failed to delete old key packages: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?
                .rows_affected();
            info!("Deleted {} old key packages for re-registered device {} (signature key match)", deleted_count, old_device_id);

            let invalidated = sqlx::query(
                r#"UPDATE welcome_messages
                   SET consumed = true, consumed_at = NOW(), error_reason = 'Device re-registered with fresh key packages (sig key match)'
                   WHERE recipient_did = $1 AND consumed = false"#,
            )
            .bind(&user_did)
            .execute(pool)
            .await
            .map_err(|e| {
                error!("Failed to invalidate old Welcome messages: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?
            .rows_affected();

            if invalidated > 0 {
                info!("Invalidated {} stale Welcome messages for re-registered user {} (sig key match)", invalidated, user_did);
            }

            sqlx::query(
                r#"UPDATE devices
                   SET device_id = $1, device_name = $2, credential_did = $3,
                       device_uuid = $4, registered_at = NOW(), last_seen_at = NOW()
                   WHERE id = $5"#,
            )
            .bind(&device_id)
            .bind(&device_name)
            .bind(&mls_did)
            .bind(input.device_uuid.as_ref().map(|s| s.as_ref()))
            .bind(&db_id)
            .execute(pool)
            .await
            .map_err(|e| {
                error!("Failed to update re-registered device: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            is_reregistration = true;
        }
    }

    info!(
        "Registering device for user {}: {} ({}) [re-registration: {}]",
        user_did, device_id, device_name, is_reregistration
    );

    // Insert new device if not re-registration
    if !is_reregistration {
        let device_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM devices WHERE user_did = $1")
            .bind(&user_did)
            .fetch_one(pool)
            .await
            .map_err(|e| {
                error!("Failed to count user devices: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        if device_count.0 >= 10 {
            warn!("User {} has reached device limit: {}", user_did, device_count.0);
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
        .execute(pool)
        .await
        .map_err(|e| {
            error!("Failed to insert device: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    }

    // Store key packages via the shared db helper (handles OpenMLS parsing, hash computation, credential validation)
    let mut stored_count = 0u64;
    for (idx, kp) in input.key_packages.iter().enumerate() {
        let key_data =
            match base64::engine::general_purpose::STANDARD.decode(kp.key_package.as_ref()) {
                Ok(data) => data,
                Err(e) => {
                    warn!("Invalid base64 in key package {}: {}", idx, e);
                    continue;
                }
            };
        if key_data.is_empty() {
            warn!("Empty key package at index {}", idx);
            continue;
        }
        if *kp.expires.as_ref() <= now.fixed_offset() {
            warn!("Key package {} has past expiration", idx);
            continue;
        }

        match crate::db::store_key_package_with_device(
            pool,
            &user_did,
            kp.cipher_suite.as_ref(),
            key_data,
            kp.expires.as_ref().with_timezone(&Utc),
            Some(device_id.clone()),
            None,
        )
        .await
        {
            Ok(_) => stored_count += 1,
            Err(e) => error!("Failed to store key package {}: {}", idx, e),
        }
    }
    info!("Stored {} key packages for device {}", stored_count, device_id);

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
        .execute(pool)
        .await
        .map_err(|e| {
            warn!("Failed to store push token during registration: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        info!("Push token stored during device registration");
    }

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
                    warn!("Failed to emit NewDeviceEvent for convo {}: {}", convo_id, e);
                }
            }
            Ok(None) => {
                info!("Pending addition already exists for device {} in convo {}", device_id, convo_id);
            }
            Err(e) => {
                warn!("Failed to create pending addition for convo {}: {}", convo_id, e);
            }
        }
    }

    Ok(Json(serde_json::json!({
        "deviceId": device_id,
        "mlsDid": mls_did,
        "autoJoinedConvos": auto_joined_convos,
    })))
}

// ─── Action: updateToken ───

async fn handle_update_token(
    pool: &DbPool,
    auth_user: &AuthUser,
    input: &crate::generated::blue_catbird::mlsChat::register_device::RegisterDevice<'_>,
) -> Result<Json<serde_json::Value>, StatusCode> {
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
            "No device found for user {} - must register first",
            auth_user.did
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
    info!(user_did = %auth_user.did, device_id = %device_id, "Push token updated");

    Ok(Json(serde_json::json!({
        "deviceId": device_id,
        "mlsDid": mls_did,
        "autoJoinedConvos": [],
    })))
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

    info!(user_did = %auth_user.did, device_id = %device_id, "Push token removed");

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
    let device_info: Option<(String, String)> = sqlx::query_as(
        "SELECT user_did, credential_did FROM devices WHERE device_id = $1",
    )
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
            return Ok(Json(serde_json::json!({
                "deleted": false,
                "keyPackagesDeleted": 0,
                "conversationsLeft": 0,
            })));
        }
    };

    if owner_did != *user_did {
        warn!(
            "User {} attempted to delete device {} owned by {}",
            user_did, device_id, owner_did
        );
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Mark device as left in all conversations
    let members_removed = sqlx::query("UPDATE members SET left_at = NOW() WHERE device_id = $1 AND left_at IS NULL")
        .bind(device_id)
        .execute(pool)
        .await
        .map_err(|e| {
            error!("Failed to remove device from conversations: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .rows_affected();

    // Clean up pending welcome messages (non-critical)
    sqlx::query("DELETE FROM welcome_messages WHERE recipient_did = $1 AND consumed = false")
        .bind(&credential_did)
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

    Ok(Json(serde_json::json!({
        "deleted": true,
        "keyPackagesDeleted": key_packages_deleted,
        "conversationsLeft": members_removed,
    })))
}

// ─── Action: claimPendingAddition ───

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
        warn!("Pending addition {} already in terminal state: {}", pending_addition_id, p_status);
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
        warn!("User {} is not a member of conversation {}", user_did, p_convo_id);
        return Err(StatusCode::FORBIDDEN);
    }

    // Prevent self-claim
    if p_user_did == user_did {
        info!("User {} attempted to claim their own device addition - returning not claimed", crate::crypto::redact_for_log(&user_did));
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
        info!(
            "Pending addition {} already claimed by {}",
            pending_addition_id,
            p_claimed_by_did.as_deref().unwrap_or("unknown")
        );
        return Ok(Json(serde_json::json!({
            "claimed": false,
            "convoId": p_convo_id,
            "deviceCredentialDid": p_new_device_credential_did,
            "claimedBy": p_claimed_by_did,
        })));
    }

    info!("Successfully claimed pending addition {} for conversation {}", pending_addition_id, p_convo_id);

    // Fetch key package for new device
    let key_package: Option<(String, Option<String>, Option<String>, String)> = sqlx::query_as(
        r#"SELECT kp.owner_did, encode(kp.key_package, 'base64'), kp.key_package_hash, kp.cipher_suite
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
        warn!("No available key package for device {} (user {})", p_new_device_id, p_user_did);
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
                    warn!("Pending addition {} is not in_progress (status: {})", pending_addition_id, status);
                    return Ok(Json(serde_json::json!({
                        "success": false,
                        "error": format!("InvalidStatus:{}", status),
                    })));
                }
                if claimed_by.as_deref() != Some(&user_did) {
                    warn!(
                        "Pending addition {} claimed by {}, not {}",
                        pending_addition_id,
                        claimed_by.as_deref().unwrap_or("unknown"),
                        user_did
                    );
                    return Err(StatusCode::FORBIDDEN);
                }
            }
        }
    }

    info!("Successfully completed pending addition {} at epoch {}", pending_addition_id, new_epoch);

    Ok(Json(serde_json::json!({
        "success": true,
    })))
}
