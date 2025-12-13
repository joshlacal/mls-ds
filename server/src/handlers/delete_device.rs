use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::{auth::AuthUser, storage::DbPool};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteDeviceInput {
    device_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteDeviceOutput {
    deleted: bool,
    key_packages_deleted: i64,
    conversations_left: i64,
}

/// Delete a registered device and all its associated key packages
/// POST /xrpc/blue.catbird.mls.deleteDevice
#[tracing::instrument(skip(pool, input))]
pub async fn delete_device(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Json(input): Json<DeleteDeviceInput>,
) -> Result<Json<DeleteDeviceOutput>, StatusCode> {
    if let Err(_e) =
        crate::auth::enforce_standard(&auth_user.claims, "blue.catbird.mls.deleteDevice")
    {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let user_did = &auth_user.did;

    info!("Deleting device {} for user {}", input.device_id, user_did);

    // Verify the device exists and is owned by the authenticated user
    let device_info: Option<(String, String)> = sqlx::query_as(
        r#"
        SELECT user_did, credential_did
        FROM devices
        WHERE device_id = $1
        "#,
    )
    .bind(&input.device_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!("Failed to query device: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let (owner_did, credential_did) = device_info.ok_or_else(|| {
        warn!("Device not found: {}", input.device_id);
        StatusCode::NOT_FOUND
    })?;

    // Verify ownership
    if owner_did != *user_did {
        warn!(
            "User {} attempted to delete device {} owned by {}",
            user_did, input.device_id, owner_did
        );
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Mark device as left in all conversations
    let members_removed = sqlx::query(
        r#"
        UPDATE members
        SET left_at = NOW()
        WHERE device_id = $1 AND left_at IS NULL
        "#,
    )
    .bind(&input.device_id)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("Failed to remove device from conversations: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .rows_affected();

    info!(
        "Removed device {} from {} conversations",
        input.device_id, members_removed
    );

    // Clean up pending welcome messages for this device
    sqlx::query(
        r#"
        DELETE FROM welcome_messages
        WHERE recipient_did = $1
        AND consumed = false
        "#,
    )
    .bind(&credential_did)
    .execute(&pool)
    .await
    .ok(); // Non-critical, don't fail if this errors

    // Delete all key packages associated with this device
    let key_packages_deleted = sqlx::query!(
        r#"
        DELETE FROM key_packages
        WHERE device_id = $1
        "#,
        input.device_id
    )
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("Failed to delete key packages: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .rows_affected();

    info!(
        "Deleted {} key packages for device {}",
        key_packages_deleted, input.device_id
    );

    // Delete the device record
    let devices_deleted = sqlx::query!(
        r#"
        DELETE FROM devices
        WHERE device_id = $1
        "#,
        input.device_id
    )
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("Failed to delete device: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .rows_affected();

    if devices_deleted == 0 {
        error!(
            "Device deletion failed - device not found: {}",
            input.device_id
        );
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    info!(
        "Successfully deleted device {} and {} key packages",
        input.device_id, key_packages_deleted
    );

    Ok(Json(DeleteDeviceOutput {
        deleted: true,
        key_packages_deleted: key_packages_deleted as i64,
        conversations_left: members_removed as i64,
    }))
}
