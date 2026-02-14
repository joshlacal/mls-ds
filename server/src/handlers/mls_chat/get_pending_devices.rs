use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use jacquard_axum::ExtractXrpc;
use tracing::warn;

use crate::{
    auth::AuthUser,
    generated::blue_catbird::mlsChat::get_pending_devices::GetPendingDevicesRequest,
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.getPendingDevices";

/// Get pending device additions for conversations.
/// GET /xrpc/blue.catbird.mlsChat.getPendingDevices
#[tracing::instrument(skip(pool, auth_user))]
pub async fn get_pending_devices(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    ExtractXrpc(input): ExtractXrpc<GetPendingDevicesRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let limit = input.limit.unwrap_or(50).clamp(1, 100);

    // Build a JSON object and deserialize into the v1 Query type
    let mut query_json = serde_json::Map::new();
    if let Some(ref ids) = input.convo_ids {
        let ids_vec: Vec<String> = ids.iter().map(|s| s.to_string()).collect();
        query_json.insert(
            "convoIds".to_string(),
            serde_json::to_value(ids_vec).unwrap_or_default(),
        );
    }
    query_json.insert("limit".to_string(), serde_json::json!(limit));

    let v1_input: crate::handlers::get_pending_device_additions::GetPendingDeviceAdditionsInput =
        serde_json::from_value(serde_json::Value::Object(query_json)).map_err(|e| {
            warn!("Failed to construct pending additions query: {}", e);
            StatusCode::BAD_REQUEST
        })?;

    let result = crate::handlers::get_pending_device_additions::get_pending_device_additions(
        State(pool),
        auth_user,
        Query(v1_input),
    )
    .await?;
    Ok(Json(serde_json::to_value(result.0).unwrap_or_default()))
}
