use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;
use tracing::error;

use crate::{auth::AuthUser, storage::DbPool};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRequestCountOutput {
    pub count: i64,
}

/// Get the count of pending chat requests for the authenticated user
/// GET /xrpc/blue.catbird.mls.getRequestCount
#[tracing::instrument(skip(pool))]
pub async fn get_request_count(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
) -> Result<Json<GetRequestCountOutput>, StatusCode> {
    let recipient_did = &auth_user.did;

    let count: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM chat_requests
        WHERE recipient_did = $1
          AND status = 'pending'
        "#,
    )
    .bind(recipient_did)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("Failed to count chat requests: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(GetRequestCountOutput { count }))
}
