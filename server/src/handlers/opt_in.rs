use axum::{extract::State, http::StatusCode, Json};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error};

use crate::{
    auth::AuthUser,
    storage::DbPool,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OptInInput {
    #[serde(skip_serializing_if = "Option::is_none")]
    device_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OptInOutput {
    opted_in: bool,
    opted_in_at: DateTime<Utc>,
}

/// Opt in to MLS chat
/// POST /xrpc/blue.catbird.mls.optIn
#[tracing::instrument(skip(pool, input))]
pub async fn opt_in(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Json(input): Json<OptInInput>,
) -> Result<Json<OptInOutput>, StatusCode> {
    // Enforce authentication
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, "blue.catbird.mls.optIn") {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let user_did = &auth_user.did;

    // Ensure user exists in users table (for FK constraint)
    let user_exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM users WHERE did = $1)"
    )
    .bind(user_did)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("Failed to check if user exists: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if !user_exists {
        // Insert user record if it doesn't exist
        sqlx::query(
            "INSERT INTO users (did, created_at, last_seen_at)
             VALUES ($1, NOW(), NOW())
             ON CONFLICT (did) DO NOTHING"
        )
        .bind(user_did)
        .execute(&pool)
        .await
        .map_err(|e| {
            error!("Failed to create user record: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    }

    // Insert or update opt-in record
    let result = sqlx::query_as::<_, (DateTime<Utc>,)>(
        "INSERT INTO opt_in (did, device_id, opted_in_at)
         VALUES ($1, $2, NOW())
         ON CONFLICT (did)
         DO UPDATE SET
            device_id = EXCLUDED.device_id,
            opted_in_at = NOW()
         RETURNING opted_in_at"
    )
    .bind(user_did)
    .bind(&input.device_id)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("Failed to insert/update opt-in record: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!(did = %user_did, device_id = ?input.device_id, "User opted in to MLS chat");

    Ok(Json(OptInOutput {
        opted_in: true,
        opted_in_at: result.0,
    }))
}
