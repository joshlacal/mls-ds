use axum::{extract::State, http::StatusCode, Json};
use jacquard_axum::ExtractXrpc;
use sqlx::Row;
use tracing::{error, info};

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

    let user_did = &auth_user.did;
    info!("Listing devices for user {}", crate::crypto::redact_for_log(user_did));

    let rows = sqlx::query(
        r#"
        SELECT
            d.device_id,
            d.device_name,
            d.device_uuid,
            d.credential_did,
            d.last_seen_at,
            d.registered_at,
            d.platform,
            d.push_token,
            COUNT(kp.id) FILTER (WHERE kp.consumed_at IS NULL AND kp.expires_at > NOW()) as key_package_count
        FROM devices d
        LEFT JOIN key_packages kp ON d.device_id = kp.device_id AND d.user_did = kp.owner_did
        WHERE d.user_did = $1
        GROUP BY d.id, d.device_id, d.device_name, d.device_uuid, d.credential_did,
                 d.last_seen_at, d.registered_at, d.platform, d.push_token
        ORDER BY d.last_seen_at DESC
        "#,
    )
    .bind(user_did)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!("Failed to list devices: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!("Found {} devices for user {}", rows.len(), crate::crypto::redact_for_log(user_did));

    let devices_json: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            let mut obj = serde_json::json!({
                "deviceId": r.get::<String, _>("device_id"),
                "credentialDid": r.get::<String, _>("credential_did"),
                "lastSeenAt": r.get::<chrono::DateTime<chrono::Utc>, _>("last_seen_at").to_rfc3339(),
                "registeredAt": r.get::<chrono::DateTime<chrono::Utc>, _>("registered_at").to_rfc3339(),
                "keyPackageCount": r.get::<i64, _>("key_package_count"),
            });
            if let Some(name) = r.get::<Option<String>, _>("device_name") {
                obj["deviceName"] = serde_json::json!(name);
            }
            if let Some(uuid) = r.get::<Option<String>, _>("device_uuid") {
                obj["deviceUuid"] = serde_json::json!(uuid);
            }
            if let Some(platform) = r.get::<Option<String>, _>("platform") {
                obj["platform"] = serde_json::json!(platform);
            }
            if let Some(push_token) = r.get::<Option<String>, _>("push_token") {
                obj["pushToken"] = serde_json::json!(push_token);
            }
            obj
        })
        .collect();

    Ok(Json(serde_json::json!({ "devices": devices_json })))
}
