use axum::{extract::State, http::StatusCode, Json};
use jacquard_axum::ExtractXrpc;
use sqlx::Row;
use tracing::{error, info};

use crate::{
    auth::AuthUser,
    generated::blue_catbird::mlsChat::list_devices::{
        DeviceInfo, ListDevicesOutput, ListDevicesRequest,
    },
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
) -> Result<Json<ListDevicesOutput>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let user_did = &auth_user.did;
    info!(
        "Listing devices for user {}",
        crate::crypto::redact_for_log(user_did)
    );

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

    info!(
        "Found {} devices for user {}",
        rows.len(),
        crate::crypto::redact_for_log(user_did)
    );

    let devices: Vec<DeviceInfo> = rows
        .into_iter()
        .map(|r| DeviceInfo {
            device_id: r.get::<String, _>("device_id").into(),
            credential_did: r.get::<String, _>("credential_did").into(),
            device_name: r
                .get::<Option<String>, _>("device_name")
                .unwrap_or_default()
                .into(),
            device_uuid: r.get::<Option<String>, _>("device_uuid").map(Into::into),
            key_package_count: r.get::<i64, _>("key_package_count"),
            last_seen_at: crate::sqlx_jacquard::chrono_to_datetime(
                r.get::<chrono::DateTime<chrono::Utc>, _>("last_seen_at"),
            ),
            registered_at: crate::sqlx_jacquard::chrono_to_datetime(
                r.get::<chrono::DateTime<chrono::Utc>, _>("registered_at"),
            ),
            push_token_registered: Some(r.get::<Option<String>, _>("push_token").is_some()),
            extra_data: Default::default(),
        })
        .collect();

    Ok(Json(ListDevicesOutput {
        devices,
        extra_data: Default::default(),
    }))
}
