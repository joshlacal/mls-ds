use axum::{
    extract::{rejection::JsonRejection, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::{error, info};

use crate::{auth::AuthUser, storage::DbPool};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterDeviceTokenInput {
    pub device_id: String,
    pub push_token: String,
    pub device_name: Option<String>,
    pub platform: String, // Required per lexicon
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
    input: Result<Json<RegisterDeviceTokenInput>, JsonRejection>,
) -> Result<Json<RegisterDeviceTokenOutput>, StatusCode> {
    let Json(input) = input.map_err(|rejection| {
        error!(
            "❌ [register_device_token] Failed to deserialize request body: {}",
            rejection
        );
        StatusCode::BAD_REQUEST
    })?;

    info!(
        user_did = %auth_user.did,
        device_id = %input.device_id,
        platform = %input.platform,
        "Registering device push token"
    );

    // Update existing device with push token
    // Note: Device must already exist (created via registerDevice)
    let result = sqlx::query(
        r#"
        UPDATE devices
        SET push_token = $3,
            push_token_updated_at = NOW(),
            device_name = COALESCE($4, device_name),
            platform = $5,
            last_seen_at = NOW()
        WHERE user_did = $1 AND device_id = $2
        "#,
    )
    .bind(&auth_user.did)
    .bind(&input.device_id)
    .bind(&input.push_token)
    .bind(input.device_name.as_deref())
    .bind(&input.platform)
    .execute(&pool)
    .await;

    match result {
        Ok(result) => {
            if result.rows_affected() == 0 {
                error!(
                    user_did = %auth_user.did,
                    device_id = %input.device_id,
                    "Device not found - must register device first via registerDevice"
                );
                return Err(StatusCode::NOT_FOUND);
            }

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
