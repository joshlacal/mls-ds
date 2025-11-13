use axum::{extract::State, http::StatusCode, Json};
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
pub struct RegisterDeviceInput {
    device_id: String,
    device_name: String,
    platform: Option<String>,
    app_version: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterDeviceOutput {
    device_id: String,
    credential_did: String,
    user_did: String,
    registered_at: DateTime<Utc>,
    is_new_device: bool,
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

    // Validate device ID is a valid UUID
    if Uuid::parse_str(&input.device_id).is_err() {
        warn!("Invalid device ID format: {}", input.device_id);
        return Err(StatusCode::BAD_REQUEST);
    }

    // Validate device name
    if input.device_name.trim().is_empty() {
        warn!("Empty device name provided");
        return Err(StatusCode::BAD_REQUEST);
    }

    if input.device_name.len() > 100 {
        warn!("Device name too long: {} characters", input.device_name.len());
        return Err(StatusCode::BAD_REQUEST);
    }

    // Validate platform if provided
    if let Some(ref platform) = input.platform {
        if !["ios", "android", "web", "desktop"].contains(&platform.as_str()) {
            warn!("Invalid platform: {}", platform);
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    // Construct credential DID: did:plc:user#device-uuid
    let credential_did = format!("{}#{}", user_did, input.device_id);

    info!("Registering device {} for user {}", input.device_id, user_did);

    let now = Utc::now();

    // Check if device already exists
    let existing = sqlx::query!(
        r#"
        SELECT id, registered_at
        FROM devices
        WHERE user_did = $1 AND device_id = $2
        "#,
        user_did,
        input.device_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!("Failed to check existing device: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let (is_new_device, registered_at) = if let Some(row) = existing {
        // Update existing device
        sqlx::query!(
            r#"
            UPDATE devices
            SET device_name = $1,
                last_seen_at = $2,
                platform = $3,
                app_version = $4
            WHERE user_did = $5 AND device_id = $6
            "#,
            input.device_name,
            now,
            input.platform,
            input.app_version,
            user_did,
            input.device_id
        )
        .execute(&pool)
        .await
        .map_err(|e| {
            error!("Failed to update device: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        info!("Updated existing device {} for user {}", input.device_id, user_did);
        (false, row.registered_at)
    } else {
        // Insert new device
        let device_id = uuid::Uuid::new_v4().to_string();
        sqlx::query!(
            r#"
            INSERT INTO devices (id, user_did, device_id, device_name, credential_did, registered_at, last_seen_at, platform, app_version)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
            device_id,
            user_did,
            input.device_id,
            input.device_name,
            credential_did,
            now,
            now,
            input.platform,
            input.app_version
        )
        .execute(&pool)
        .await
        .map_err(|e| {
            error!("Failed to insert device: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        info!("Registered new device {} for user {}", input.device_id, user_did);
        (true, now)
    };

    Ok(Json(RegisterDeviceOutput {
        device_id: input.device_id,
        credential_did,
        user_did: user_did.clone(),
        registered_at,
        is_new_device,
    }))
}
