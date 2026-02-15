use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;
use tracing::{error, info, warn};

use crate::{
    auth::AuthUser, generated::blue_catbird::mls::delete_device::DeleteDevice, storage::DbPool,
};

/// Type alias preserving the old name for v2 handler compatibility.
pub type DeleteDeviceInput = DeleteDevice<'static>;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteDeviceOutput {
    deleted: bool,
    key_packages_deleted: i64,
    conversations_left: i64,
}

/// Delete a registered device and all its associated key packages
/// POST /xrpc/blue.catbird.mls.deleteDevice
#[tracing::instrument(skip(pool, body))]
pub async fn delete_device(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    body: String,
) -> Result<Json<DeleteDeviceOutput>, StatusCode> {
    let input = crate::jacquard_json::from_json_body::<DeleteDevice>(&body)?;
    // Auth already enforced by AuthUser extractor (lxm/jti checked against URI path).
    // Skipping v1 NSID check here to allow v2 (mlsChat) delegation.

    let user_did = &auth_user.did;
    let device_id: String = input.device_id.into();

    info!(
        "Deleting device {} for user {}",
        device_id,
        crate::crypto::redact_for_log(user_did)
    );

    // Verify the device exists and is owned by the authenticated user
    let device_info: Option<(String, String)> = sqlx::query_as(
        r#"
        SELECT user_did, credential_did
        FROM devices
        WHERE device_id = $1
        "#,
    )
    .bind(&device_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!("Failed to query device: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let (owner_did, credential_did) = match device_info {
        Some(info) => info,
        None => {
            warn!("Device not found: {} (treating as success)", device_id);
            return Ok(Json(DeleteDeviceOutput {
                deleted: false,
                key_packages_deleted: 0,
                conversations_left: 0,
            }));
        }
    };

    // Verify ownership
    if owner_did != *user_did {
        warn!(
            "User {} attempted to delete device {} owned by {}",
            user_did, device_id, owner_did
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
    .bind(&device_id)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("Failed to remove device from conversations: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .rows_affected();

    info!(
        "Removed device {} from {} conversations",
        device_id, members_removed
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
        device_id
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
        key_packages_deleted, device_id
    );

    // Delete the device record
    let devices_deleted = sqlx::query!(
        r#"
        DELETE FROM devices
        WHERE device_id = $1
        "#,
        device_id
    )
    .execute(&pool)
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

    Ok(Json(DeleteDeviceOutput {
        deleted: true,
        key_packages_deleted: key_packages_deleted as i64,
        conversations_left: members_removed as i64,
    }))
}
