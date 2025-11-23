use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use tracing::{error, info};

use crate::{
    auth::AuthUser,
    storage::DbPool,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterDeviceTokenInput {
    pub device_id: String,
    pub push_token: String,
    pub device_name: Option<String>,
    pub platform: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegisterDeviceTokenOutput {
    pub success: bool,
}

/// Register or update a device push token
/// POST /xrpc/blue.catbird.mls.registerDeviceToken
#[tracing::instrument(skip(pool, auth_user))]
pub async fn register_device_token(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Json(input): Json<RegisterDeviceTokenInput>,
) -> Result<Json<RegisterDeviceTokenOutput>, StatusCode> {
    info!(
        user_did = %auth_user.did,
        device_id = %input.device_id,
        "Registering device push token"
    );

    // Update or insert device with push token
    let result = sqlx::query(
        r#"
        INSERT INTO devices (user_did, device_id, push_token, push_token_updated_at, device_name, platform, last_seen_at)
        VALUES ($1, $2, $3, NOW(), $4, $5, NOW())
        ON CONFLICT (user_did, device_id)
        DO UPDATE SET
            push_token = EXCLUDED.push_token,
            push_token_updated_at = NOW(),
            device_name = COALESCE(EXCLUDED.device_name, devices.device_name),
            platform = COALESCE(EXCLUDED.platform, devices.platform),
            last_seen_at = NOW()
        "#,
    )
    .bind(&auth_user.did)
    .bind(&input.device_id)
    .bind(&input.push_token)
    .bind(input.device_name.as_deref())
    .bind(input.platform.as_deref())
    .execute(&pool)
    .await;

    match result {
        Ok(_) => {
            info!(
                user_did = %auth_user.did,
                device_id = %input.device_id,
                "Device push token registered successfully"
            );
            Ok(Json(RegisterDeviceTokenOutput { success: true }))
        }
        Err(e) => {
            error!(
                user_did = %auth_user.did,
                device_id = %input.device_id,
                error = %e,
                "Failed to register device push token"
            );
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnregisterDeviceTokenInput {
    pub device_id: String,
}

#[derive(Debug, Serialize)]
pub struct UnregisterDeviceTokenOutput {
    pub success: bool,
}

/// Unregister a device push token
/// POST /xrpc/blue.catbird.mls.unregisterDeviceToken
#[tracing::instrument(skip(pool, auth_user))]
pub async fn unregister_device_token(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Json(input): Json<UnregisterDeviceTokenInput>,
) -> Result<Json<UnregisterDeviceTokenOutput>, StatusCode> {
    info!(
        user_did = %auth_user.did,
        device_id = %input.device_id,
        "Unregistering device push token"
    );

    let result = sqlx::query(
        r#"
        UPDATE devices
        SET push_token = NULL,
            push_token_updated_at = NULL
        WHERE user_did = $1 AND device_id = $2
        "#,
    )
    .bind(&auth_user.did)
    .bind(&input.device_id)
    .execute(&pool)
    .await;

    match result {
        Ok(_) => {
            info!(
                user_did = %auth_user.did,
                device_id = %input.device_id,
                "Device push token unregistered successfully"
            );
            Ok(Json(UnregisterDeviceTokenOutput { success: true }))
        }
        Err(e) => {
            error!(
                user_did = %auth_user.did,
                device_id = %input.device_id,
                error = %e,
                "Failed to unregister device push token"
            );
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
