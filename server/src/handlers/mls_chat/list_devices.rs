use axum::{extract::State, http::StatusCode, Json};
use jacquard_axum::ExtractXrpc;

use crate::{
    auth::AuthUser, generated::blue_catbird::mlsChat::list_devices::ListDevicesRequest,
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.listDevices";

/// List registered devices for the authenticated user.
/// GET /xrpc/blue.catbird.mlsChat.listDevices
#[tracing::instrument(skip(pool, auth_user))]
pub async fn list_devices(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    ExtractXrpc(_input): ExtractXrpc<ListDevicesRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let result = crate::handlers::list_devices::list_devices(State(pool), auth_user).await?;
    Ok(Json(serde_json::to_value(result.0).unwrap_or_default()))
}
