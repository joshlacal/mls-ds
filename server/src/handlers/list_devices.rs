use axum::{extract::State, http::StatusCode, Json};
use chrono::{DateTime, Utc};
use serde::Serialize;
use tracing::{error, info};

use crate::{auth::AuthUser, storage::DbPool};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceInfo {
    device_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_uuid: Option<String>,
    credential_did: String,
    last_seen_at: DateTime<Utc>,
    registered_at: DateTime<Utc>,
    key_package_count: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListDevicesOutput {
    devices: Vec<DeviceInfo>,
}

/// List all registered devices for the authenticated user
/// GET /xrpc/blue.catbird.mls.listDevices
#[tracing::instrument(skip(pool))]
pub async fn list_devices(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
) -> Result<Json<ListDevicesOutput>, StatusCode> {
    if let Err(_e) =
        crate::auth::enforce_standard(&auth_user.claims, "blue.catbird.mls.listDevices")
    {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let user_did = &auth_user.did;

    info!("Listing devices for user {}", user_did);

    // Query devices with key package counts
    let devices: Vec<DeviceInfo> = sqlx::query_as!(
        DeviceInfo,
        r#"
        SELECT
            d.device_id,
            d.device_name,
            d.device_uuid,
            d.credential_did,
            d.last_seen_at,
            d.registered_at,
            COUNT(kp.id) FILTER (WHERE kp.consumed_at IS NULL AND kp.expires_at > NOW()) as "key_package_count!"
        FROM devices d
        LEFT JOIN key_packages kp ON d.device_id = kp.device_id
        WHERE d.user_did = $1
        GROUP BY d.id, d.device_id, d.device_name, d.device_uuid, d.credential_did, d.last_seen_at, d.registered_at
        ORDER BY d.last_seen_at DESC
        "#,
        user_did
    )
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!("Failed to list devices: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!("Found {} devices for user {}", devices.len(), user_did);

    Ok(Json(ListDevicesOutput { devices }))
}
