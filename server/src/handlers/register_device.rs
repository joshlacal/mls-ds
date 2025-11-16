use axum::{extract::State, http::StatusCode, Json};
use base64::Engine;
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{
    auth::AuthUser,
    device_utils::parse_device_did,
    storage::DbPool,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyPackageItem {
    #[serde(rename = "keyPackage")]
    pub key_package: String,
    #[serde(rename = "cipherSuite")]
    pub cipher_suite: String,
    pub expires: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterDeviceInput {
    device_name: String,
    #[serde(default)]
    device_uuid: Option<String>,
    key_packages: Vec<KeyPackageItem>,
    #[serde(with = "crate::atproto_bytes")]
    signature_public_key: Vec<u8>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WelcomeMessage {
    convo_id: String,
    welcome: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterDeviceOutput {
    device_id: String,
    mls_did: String,
    auto_joined_convos: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    welcome_messages: Option<Vec<WelcomeMessage>>,
}

/// Register a device for multi-device MLS support
/// POST /xrpc/blue.catbird.mls.registerDevice
#[tracing::instrument(skip(pool, input))]
pub async fn register_device(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Json(input): Json<RegisterDeviceInput>,
) -> Result<Json<RegisterDeviceOutput>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, "blue.catbird.mls.registerDevice") {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Extract user DID from device DID (handles both single and multi-device mode)
    // During initial registration, auth_user.did is the user DID
    // During re-registration, it might be a device DID
    let (user_did, _device_id_from_auth) = parse_device_did(&auth_user.did)
        .map_err(|e| {
            error!("Invalid device DID format: {}", e);
            StatusCode::BAD_REQUEST
        })?;

    // Validate device name
    if input.device_name.trim().is_empty() {
        warn!("Empty device name provided");
        return Err(StatusCode::BAD_REQUEST);
    }

    if input.device_name.len() > 100 {
        warn!("Device name too long: {} characters", input.device_name.len());
        return Err(StatusCode::BAD_REQUEST);
    }

    // Validate signature public key
    if input.signature_public_key.len() != 32 {
        warn!("Invalid signature public key length: {} (expected 32 bytes)", input.signature_public_key.len());
        return Err(StatusCode::BAD_REQUEST);
    }

    // Validate key packages
    if input.key_packages.is_empty() {
        warn!("No key packages provided");
        return Err(StatusCode::BAD_REQUEST);
    }

    if input.key_packages.len() > 200 {
        warn!("Too many key packages: {} (max 200)", input.key_packages.len());
        return Err(StatusCode::BAD_REQUEST);
    }

    // Generate device ID
    let device_id = Uuid::new_v4().to_string();

    // Construct MLS DID: did:plc:user#device-uuid
    let mls_did = format!("{}#{}", &user_did, device_id);

    let now = Utc::now();
    let sig_key_hex = hex::encode(&input.signature_public_key);

    // Check for device re-registration by device_uuid
    let mut is_reregistration = if let Some(ref device_uuid) = input.device_uuid {
        let existing_by_uuid: Option<(String, String, String)> = sqlx::query_as(
            r#"
            SELECT id, device_id, credential_did
            FROM devices
            WHERE user_did = $1 AND device_uuid = $2
            "#,
        )
        .bind(&user_did)
        .bind(device_uuid)
        .fetch_optional(&pool)
        .await
        .map_err(|e| {
            error!("Failed to check existing device by UUID: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        if let Some((db_id, old_device_id, old_credential_did)) = existing_by_uuid {
            info!("Device re-registration detected for user {}: device_uuid={}, old_device_id={}",
                user_did, device_uuid, old_device_id);

            // Delete all old key packages for this device
            let deleted_count = sqlx::query!(
                r#"
                DELETE FROM key_packages
                WHERE owner_did = $1 AND device_id = $2
                "#,
                user_did,
                old_device_id
            )
            .execute(&pool)
            .await
            .map_err(|e| {
                error!("Failed to delete old key packages: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?
            .rows_affected();

            info!("Deleted {} old key packages for re-registered device {}", deleted_count, old_device_id);

            // Update existing device record with new signature key and timestamps
            // Note: We keep device_uuid the same (it's the persistent identifier)
            sqlx::query!(
                r#"
                UPDATE devices
                SET device_id = $1,
                    device_name = $2,
                    credential_did = $3,
                    signature_public_key = $4,
                    registered_at = $5,
                    last_seen_at = $6
                WHERE id = $7
                "#,
                device_id,
                input.device_name,
                mls_did,
                sig_key_hex,
                now,
                now,
                db_id
            )
            .execute(&pool)
            .await
            .map_err(|e| {
                error!("Failed to update re-registered device: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            info!("Updated device record for re-registration: {}", device_id);
            true
        } else {
            false
        }
    } else {
        false
    };

    // If not a re-registration by device_uuid, check if we can re-register by signature key
    if !is_reregistration {
        let existing_device: Option<(String, String, String)> = sqlx::query_as(
            r#"
            SELECT id, device_id, credential_did
            FROM devices
            WHERE user_did = $1 AND signature_public_key = $2
            "#,
        )
        .bind(&user_did)
        .bind(&sig_key_hex)
        .fetch_optional(&pool)
        .await
        .map_err(|e| {
            error!("Failed to check existing device by signature key: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        if let Some((db_id, old_device_id, _old_credential_did)) = existing_device {
            info!("Device re-registration detected by signature key for user {}: old_device_id={}",
                user_did, old_device_id);

            // Delete all old key packages for this device
            let deleted_count = sqlx::query!(
                r#"
                DELETE FROM key_packages
                WHERE owner_did = $1 AND device_id = $2
                "#,
                user_did,
                old_device_id
            )
            .execute(&pool)
            .await
            .map_err(|e| {
                error!("Failed to delete old key packages: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?
            .rows_affected();

            info!("Deleted {} old key packages for re-registered device {} (signature key match)", deleted_count, old_device_id);

            // Update existing device record with new device_id and timestamps
            sqlx::query!(
                r#"
                UPDATE devices
                SET device_id = $1,
                    device_name = $2,
                    credential_did = $3,
                    device_uuid = $4,
                    registered_at = $5,
                    last_seen_at = $6
                WHERE id = $7
                "#,
                device_id,
                input.device_name,
                mls_did,
                input.device_uuid.as_deref(),
                now,
                now,
                db_id
            )
            .execute(&pool)
            .await
            .map_err(|e| {
                error!("Failed to update re-registered device: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            info!("Updated device record for re-registration by signature key: {}", device_id);
            is_reregistration = true;
        }
    }

    info!("Registering device for user {}: {} ({}) [re-registration: {}]",
        user_did, device_id, input.device_name, is_reregistration);

    // Only insert new device if this is NOT a re-registration
    if !is_reregistration {
        // Check device limit (max 10 devices per user)
        let device_count: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*)
            FROM devices
            WHERE user_did = $1
            "#,
        )
        .bind(&user_did)
        .fetch_one(&pool)
        .await
        .map_err(|e| {
            error!("Failed to count user devices: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        if device_count.0 >= 10 {
            warn!("User {} has reached device limit: {}", user_did, device_count.0);
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }

        // Insert new device
        let db_device_id = Uuid::new_v4().to_string();
        sqlx::query!(
            r#"
            INSERT INTO devices (id, user_did, device_id, device_name, credential_did, signature_public_key, device_uuid, registered_at, last_seen_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
            db_device_id,
            user_did,
            device_id,
            input.device_name,
            mls_did,
            sig_key_hex,
            input.device_uuid.as_deref(),
            now,
            now
        )
        .execute(&pool)
        .await
        .map_err(|e| {
            error!("Failed to insert device: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        info!("Device {} registered successfully", device_id);
    } else {
        info!("Device {} re-registered successfully", device_id);
    }

    // Store key packages for this device
    let mut stored_count = 0;
    for (idx, kp) in input.key_packages.iter().enumerate() {
        // Validate base64 encoding
        let key_data = match base64::engine::general_purpose::STANDARD.decode(&kp.key_package) {
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

        // Validate expiration
        if kp.expires <= now {
            warn!("Key package {} has past expiration", idx);
            continue;
        }

        // Store key package with user DID as owner (not device DID)
        // The server will parse the KeyPackage and extract the verified credential identity
        // NOTE: We pass device_id for tracking, but credential_did is now extracted from the KeyPackage
        match crate::db::store_key_package_with_device(
            &pool,
            &user_did,
            &kp.cipher_suite,
            key_data,
            kp.expires,
            Some(device_id.clone()),
            None,  // credential_did is now extracted from KeyPackage and validated
        ).await {
            Ok(_) => {
                stored_count += 1;
            }
            Err(e) => {
                error!("Failed to store key package {}: {}", idx, e);
            }
        }
    }

    info!("Stored {} key packages for device {}", stored_count, device_id);

    // Find all conversations this user is a member of (for auto-rejoin)
    let convos: Vec<(String,)> = sqlx::query_as(
        r#"
        SELECT DISTINCT convo_id
        FROM members
        WHERE user_did = $1 AND left_at IS NULL
        "#,
    )
    .bind(user_did)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!("Failed to fetch user conversations: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let auto_joined_convos: Vec<String> = convos.iter().map(|(id,)| id.clone()).collect();

    info!("Device {} can auto-join {} conversations", device_id, auto_joined_convos.len());

    // For now, we don't generate welcome messages during registration
    // The device will need to request rejoin via blue.catbird.mls.requestRejoin
    Ok(Json(RegisterDeviceOutput {
        device_id,
        mls_did,
        auto_joined_convos,
        welcome_messages: None,
    }))
}
