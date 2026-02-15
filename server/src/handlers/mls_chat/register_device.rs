use axum::{extract::State, http::StatusCode, Json};
use jacquard_axum::ExtractXrpc;
use std::sync::Arc;
use tracing::{info, warn};

use crate::{
    auth::AuthUser, generated::blue_catbird::mlsChat::register_device::RegisterDeviceRequest,
    realtime::SseState, storage::DbPool,
};

// NSID for auth enforcement
const NSID: &str = "blue.catbird.mlsChat.registerDevice";

// ─── POST handler ───

/// Consolidated device management endpoint (POST)
/// POST /xrpc/blue.catbird.mlsChat.registerDevice
///
/// Dispatches based on `action` field to the appropriate v1 handler.
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

    // Serialize parsed input back to body string for v1 delegation
    let body = serde_json::to_string(&input).unwrap_or_default();

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
        "register" => {
            // Delegate to v1 register_device handler using the body string
            let v1_input: crate::generated::blue_catbird::mls::register_device::RegisterDevice<
                'static,
            > = {
                use jacquard_common::IntoStatic;
                let parsed: crate::generated::blue_catbird::mls::register_device::RegisterDevice =
                    serde_json::from_str(&body).map_err(|e| {
                        warn!("Failed to parse register action body: {}", e);
                        StatusCode::BAD_REQUEST
                    })?;
                parsed.into_static()
            };
            let result = crate::handlers::register_device::register_device(
                State(pool),
                State(sse_state),
                auth_user,
                serde_json::to_string(&v1_input).unwrap(),
            )
            .await?;
            Ok(Json(serde_json::to_value(result.0).unwrap_or_default()))
        }

        "updateToken" => {
            // Handle push token update using RegisterDevice input fields.
            // iOS sends: { deviceName, pushToken, keyPackages: [], signaturePublicKey: "" }
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

            // Find the device to update — prefer deviceUUID, fall back to most recent device
            let device: Option<(String, String)> = if let Some(ref uuid) = device_uuid {
                sqlx::query_as(
                    "SELECT device_id, user_did FROM devices WHERE user_did = $1 AND device_uuid = $2",
                )
                .bind(&auth_user.did)
                .bind(uuid)
                .fetch_optional(&pool)
                .await
                .map_err(|e| {
                    warn!("Failed to query device by UUID: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?
            } else {
                sqlx::query_as(
                    "SELECT device_id, user_did FROM devices WHERE user_did = $1 ORDER BY created_at DESC LIMIT 1",
                )
                .bind(&auth_user.did)
                .fetch_optional(&pool)
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

            // Update push token
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
            .execute(&pool)
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

        "removeToken" => {
            let input: crate::handlers::register_device_token::UnregisterDeviceTokenInput =
                serde_json::from_str(&body).map_err(|e| {
                    warn!("Failed to parse removeToken action body: {}", e);
                    StatusCode::BAD_REQUEST
                })?;
            let result = crate::handlers::register_device_token::unregister_device_token(
                State(pool),
                auth_user,
                Json(input),
            )
            .await?;
            Ok(Json(serde_json::to_value(result.0).unwrap_or_default()))
        }

        "delete" => {
            let v1_input: crate::generated::blue_catbird::mls::delete_device::DeleteDevice<
                'static,
            > = {
                use jacquard_common::IntoStatic;
                let parsed: crate::generated::blue_catbird::mls::delete_device::DeleteDevice =
                    serde_json::from_str(&body).map_err(|e| {
                        warn!("Failed to parse delete action body: {}", e);
                        StatusCode::BAD_REQUEST
                    })?;
                parsed.into_static()
            };
            let result = crate::handlers::delete_device::delete_device(
                State(pool),
                auth_user,
                serde_json::to_string(&v1_input).unwrap(),
            )
            .await?;
            Ok(Json(serde_json::to_value(result.0).unwrap_or_default()))
        }

        "claimPendingAddition" => {
            let input: crate::handlers::claim_pending_device_addition::ClaimPendingDeviceAdditionInput =
                serde_json::from_str(&body).map_err(|e| {
                    warn!("Failed to parse claimPendingAddition action body: {}", e);
                    StatusCode::BAD_REQUEST
                })?;
            let result =
                crate::handlers::claim_pending_device_addition::claim_pending_device_addition(
                    State(pool),
                    auth_user,
                    Json(input),
                )
                .await?;
            Ok(Json(serde_json::to_value(result.0).unwrap_or_default()))
        }

        "completePendingAddition" => {
            let input: crate::handlers::complete_pending_device_addition::CompletePendingDeviceAdditionInput =
                serde_json::from_str(&body).map_err(|e| {
                    warn!("Failed to parse completePendingAddition action body: {}", e);
                    StatusCode::BAD_REQUEST
                })?;
            let result =
                crate::handlers::complete_pending_device_addition::complete_pending_device_addition(
                    State(pool),
                    auth_user,
                    Json(input),
                )
                .await?;
            Ok(Json(serde_json::to_value(result.0).unwrap_or_default()))
        }

        unknown => {
            warn!("Unknown action for v2 registerDevice POST: {}", unknown);
            Err(StatusCode::BAD_REQUEST)
        }
    }
}
