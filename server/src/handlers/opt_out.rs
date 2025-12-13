use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;
use tracing::{error, info};

use crate::{auth::AuthUser, storage::DbPool};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OptOutOutput {
    success: bool,
}

/// Opt out of MLS chat
/// POST /xrpc/blue.catbird.mls.optOut
#[tracing::instrument(skip(pool))]
pub async fn opt_out(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
) -> Result<Json<OptOutOutput>, StatusCode> {
    // Enforce authentication
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, "blue.catbird.mls.optOut") {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let user_did = &auth_user.did;

    // Delete opt-in record
    let result = sqlx::query("DELETE FROM opt_in WHERE did = $1")
        .bind(user_did)
        .execute(&pool)
        .await
        .map_err(|e| {
            error!("Failed to delete opt-in record: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let success = result.rows_affected() > 0;

    info!(did = %user_did, success = success, "User opted out of MLS chat");

    Ok(Json(OptOutOutput { success }))
}
