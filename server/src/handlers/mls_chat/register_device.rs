use axum::{extract::State, http::StatusCode, Json};
use jacquard_axum::ExtractXrpc;
use std::sync::Arc;
use tracing::warn;

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

    // RegisterDevice doesn't model the action field — defaults to "register"
    let raw: serde_json::Value = serde_json::to_value(&input).unwrap_or_default();
    let action = raw
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("register");

    match action {
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
            let input: crate::handlers::register_device_token::RegisterDeviceTokenInput =
                serde_json::from_str(&body).map_err(|e| {
                    warn!("Failed to parse updateToken action body: {}", e);
                    StatusCode::BAD_REQUEST
                })?;
            let result = crate::handlers::register_device_token::register_device_token(
                State(pool),
                auth_user,
                Ok(Json(input)),
            )
            .await?;
            Ok(Json(serde_json::to_value(result.0).unwrap_or_default()))
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
