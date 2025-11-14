use axum::{extract::State, http::StatusCode, Json};
use base64::Engine;
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{
    auth::AuthUser,
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

    let user_did = &auth_user.did;

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
    let mls_did = format!("{}#{}", user_did, device_id);

    info!("Registering new device for user {}: {} ({})", user_did, device_id, input.device_name);

    let now = Utc::now();

    // Check if a device with this signature key already exists
    let sig_key_hex = hex::encode(&input.signature_public_key);
    let existing_device: Option<(String,)> = sqlx::query_as(
        r#"
        SELECT device_id
        FROM devices
        WHERE user_did = $1 AND signature_public_key = $2
        "#,
    )
    .bind(user_did)
    .bind(&sig_key_hex)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!("Failed to check existing device by signature key: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if let Some((existing_id,)) = existing_device {
        warn!("Device with this signature key already exists: {}", existing_id);
        return Err(StatusCode::CONFLICT);
    }

    // Check device limit (max 10 devices per user)
    let device_count: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*)
        FROM devices
        WHERE user_did = $1
        "#,
    )
    .bind(user_did)
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
        INSERT INTO devices (id, user_did, device_id, device_name, credential_did, signature_public_key, registered_at, last_seen_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
        db_device_id,
        user_did,
        device_id,
        input.device_name,
        mls_did,
        sig_key_hex,
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

        // Store key package
        match crate::db::store_key_package_with_device(
            &pool,
            user_did,
            &kp.cipher_suite,
            key_data,
            kp.expires,
            Some(device_id.clone()),
            Some(mls_did.clone()),
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
