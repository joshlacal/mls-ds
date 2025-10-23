use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{auth::AuthUser, db::DbPool};

#[derive(Debug, Deserialize)]
pub struct UpdateCursorInput {
    #[serde(rename = "convoId")]
    pub convo_id: String,
    pub cursor: String,
}

#[derive(Debug, Serialize)]
pub struct UpdateCursorOutput {
    pub success: bool,
}

/// Update user's last seen cursor for a conversation
pub async fn update_cursor(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Json(input): Json<UpdateCursorInput>,
) -> Result<Json<UpdateCursorOutput>, StatusCode> {
    info!(
        user_did = %auth_user.did,
        convo_id = %input.convo_id,
        cursor = %input.cursor,
        "Updating cursor"
    );

    // Validate membership
    let is_member = crate::db::is_member(&pool, &auth_user.did, &input.convo_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if !is_member {
        return Err(StatusCode::FORBIDDEN);
    }

    // Validate cursor format
    crate::realtime::cursor::CursorGenerator::validate(&input.cursor)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // Update cursor in database
    crate::db::update_last_seen_cursor(&pool, &auth_user.did, &input.convo_id, &input.cursor)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(UpdateCursorOutput { success: true }))
}
