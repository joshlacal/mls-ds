//! Compat shim for the legacy `blue.catbird.mlsChat.registerDeviceToken`
//! endpoint. The lexicon was retired and folded into
//! `blue.catbird.mlsChat.registerDevice` (action=`updateToken`), but iOS
//! clients running older Petrel-generated code still hit the dead route
//! and 404 on every push-token registration. The 404 storm lights up
//! NotificationManager retry logic and breaks push delivery for
//! pre-update users.
//!
//! This shim accepts the legacy payload `{deviceId, pushToken,
//! deviceName?, platform?}`, performs an idempotent UPDATE on the
//! `devices` row, and returns `{success: true}` so old clients see a
//! clean 200. New clients should target `registerDevice` directly.
//!
//! TODO: retire this route once telemetry confirms iOS releases below
//! the registerDevice-consolidation cutoff have aged out of the active
//! population. Look for `register_device_token_compat_total` going to
//! zero in metrics.
use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::{auth::AuthUser, storage::DbPool};

const NSID: &str = "blue.catbird.mlsChat.registerDeviceToken";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterDeviceTokenInput {
    pub device_id: String,
    pub push_token: String,
    #[serde(default)]
    pub device_name: Option<String>,
    #[serde(default)]
    pub platform: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegisterDeviceTokenOutput {
    pub success: bool,
}

pub async fn register_device_token(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Json(input): Json<RegisterDeviceTokenInput>,
) -> Result<Json<RegisterDeviceTokenOutput>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    if input.device_id.trim().is_empty() {
        warn!("registerDeviceToken (compat): empty deviceId");
        return Err(StatusCode::BAD_REQUEST);
    }
    if input.push_token.trim().is_empty() {
        warn!("registerDeviceToken (compat): empty pushToken");
        return Err(StatusCode::BAD_REQUEST);
    }
    if input.push_token.len() > 512 {
        warn!(
            "registerDeviceToken (compat): pushToken exceeds 512 bytes ({})",
            input.push_token.len()
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    let rows_affected = sqlx::query(
        r#"UPDATE devices
           SET push_token = $3,
               push_token_updated_at = NOW(),
               last_seen_at = NOW()
           WHERE user_did = $1 AND device_id = $2"#,
    )
    .bind(&auth_user.did)
    .bind(&input.device_id)
    .bind(&input.push_token)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("registerDeviceToken (compat): UPDATE failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .rows_affected();

    metrics::counter!("register_device_token_compat_total", 1);

    if rows_affected == 0 {
        warn!(
            target: "register_device_token_compat",
            user_did = %crate::crypto::hash_for_log(&auth_user.did),
            device_id = %input.device_id,
            outcome = "device_not_found",
            "registerDeviceToken (compat): no matching device row — client is calling the retired endpoint without first registering via registerDevice"
        );
        return Err(StatusCode::NOT_FOUND);
    }

    info!(
        target: "register_device_token_compat",
        user_did = %crate::crypto::hash_for_log(&auth_user.did),
        device_id = %input.device_id,
        platform = %input.platform.as_deref().unwrap_or("unspecified"),
        outcome = "success",
        "registerDeviceToken (compat): push_token updated for legacy client"
    );

    Ok(Json(RegisterDeviceTokenOutput { success: true }))
}
