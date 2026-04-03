use axum::{extract::State, http::StatusCode, Json};
use jacquard_axum::ExtractXrpc;
use tracing::{error, info, warn};

use crate::{
    auth::AuthUser,
    generated::blue_catbird::mlsChat::remove_device::{
        RemoveDeviceOutput, RemoveDeviceRequest,
    },
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.removeDevice";

/// Remove a specific device belonging to the authenticated user.
/// POST /xrpc/blue.catbird.mlsChat.removeDevice
///
/// Soft-deletes the device from all conversations, cleans up welcome messages
/// and key packages, then deletes the device record.
#[tracing::instrument(skip(pool, auth_user, input))]
pub async fn remove_device(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    ExtractXrpc(input): ExtractXrpc<RemoveDeviceRequest>,
) -> Result<Json<RemoveDeviceOutput<'static>>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let device_id = input.device_id.to_string();
    let user_did = &auth_user.did;

    if device_id.is_empty() {
        warn!("Empty deviceId provided");
        return Err(StatusCode::BAD_REQUEST);
    }

    // Verify device exists and is owned by caller
    let device_info: Option<(String, String)> =
        sqlx::query_as("SELECT user_did, credential_did FROM devices WHERE device_id = $1")
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
            return Ok(Json(RemoveDeviceOutput {
                deleted: false,
                key_packages_deleted: Some(0),
                conversations_left: Some(0),
                extra_data: Default::default(),
            }));
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
            .bind(&device_id)
            .execute(&pool)
            .await
            .map_err(|e| {
                error!("Failed to remove device from conversations: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?
            .rows_affected();

    // Clean up pending welcome messages (non-critical)
    sqlx::query("DELETE FROM welcome_messages WHERE recipient_did = $1 AND consumed = false")
        .bind(&credential_did)
        .execute(&pool)
        .await
        .ok();

    // Delete key packages
    let key_packages_deleted = sqlx::query("DELETE FROM key_packages WHERE device_id = $1")
        .bind(&device_id)
        .execute(&pool)
        .await
        .map_err(|e| {
            error!("Failed to delete key packages: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .rows_affected();

    // Delete device record
    let devices_deleted = sqlx::query("DELETE FROM devices WHERE device_id = $1")
        .bind(&device_id)
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

    Ok(Json(RemoveDeviceOutput {
        deleted: true,
        key_packages_deleted: Some(key_packages_deleted as i64),
        conversations_left: Some(members_removed as i64),
        extra_data: Default::default(),
    }))
}
