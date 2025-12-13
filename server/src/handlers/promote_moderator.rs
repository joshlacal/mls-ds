use axum::{extract::State, http::StatusCode, Json};
use tracing::{error, info};

use crate::{
    auth::{verify_is_admin, verify_is_member, AuthUser},
    storage::DbPool,
};

/// NSID for this endpoint
pub const NSID: &str = "blue.catbird.mls.promoteModerator";

/// Input for promoteModerator
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct InputData {
    pub convo_id: String,
    pub target_did: String,
}

/// Wrapper for input
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct Input {
    #[serde(flatten)]
    pub data: InputData,
}

/// Output for promoteModerator
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct OutputData {
    pub ok: bool,
    pub promoted_at: String,
}

/// Wrapper for output
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct Output {
    #[serde(flatten)]
    pub data: OutputData,
}

impl From<OutputData> for Output {
    fn from(data: OutputData) -> Self {
        Output { data }
    }
}

/// Promote a member to moderator status
/// POST /xrpc/blue.catbird.mls.promoteModerator
#[tracing::instrument(skip(pool, auth_user))]
pub async fn promote_moderator(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Json(input): Json<Input>,
) -> Result<Json<Output>, StatusCode> {
    let input = input.data;

    info!(
        "📍 [promote_moderator] START - actor: {}, convo: {}, target: {}",
        auth_user.did, input.convo_id, input.target_did
    );

    // Enforce standard auth
    if let Err(_) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        error!("❌ [promote_moderator] Unauthorized");
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Verify actor is an admin
    verify_is_admin(&pool, &input.convo_id, &auth_user.did).await?;

    // Verify target is a member
    verify_is_member(&pool, &input.convo_id, &input.target_did).await?;

    // Check if target is already an admin (admins have moderator privileges)
    let is_admin: bool = sqlx::query_scalar(
        "SELECT COALESCE(is_admin, false) FROM members
         WHERE convo_id = $1 AND user_did = $2 AND left_at IS NULL
         LIMIT 1",
    )
    .bind(&input.convo_id)
    .bind(&input.target_did)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("❌ [promote_moderator] Database query failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if is_admin {
        error!("❌ [promote_moderator] Target is already an admin (has moderator privileges)");
        return Err(StatusCode::BAD_REQUEST);
    }

    // Check if target is already a moderator
    let is_already_moderator: bool = sqlx::query_scalar(
        "SELECT COALESCE(is_moderator, false) FROM members
         WHERE convo_id = $1 AND user_did = $2 AND left_at IS NULL
         LIMIT 1",
    )
    .bind(&input.convo_id)
    .bind(&input.target_did)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("❌ [promote_moderator] Database query failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if is_already_moderator {
        error!("❌ [promote_moderator] Target is already a moderator");
        return Err(StatusCode::BAD_REQUEST);
    }

    let now = chrono::Utc::now();

    // Promote member to moderator (updates ALL devices of this user)
    sqlx::query(
        "UPDATE members
         SET is_moderator = true, moderator_promoted_at = $3, moderator_promoted_by_did = $4
         WHERE convo_id = $1 AND user_did = $2 AND left_at IS NULL",
    )
    .bind(&input.convo_id)
    .bind(&input.target_did)
    .bind(&now)
    .bind(&auth_user.did)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("❌ [promote_moderator] Failed to promote: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Log admin action for audit trail
    let action_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO admin_actions (id, convo_id, actor_did, action, target_did, created_at)
         VALUES ($1, $2, $3, 'promote_moderator', $4, $5)",
    )
    .bind(&action_id)
    .bind(&input.convo_id)
    .bind(&auth_user.did)
    .bind(&input.target_did)
    .bind(&now)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("❌ [promote_moderator] Failed to log action: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!("✅ [promote_moderator] SUCCESS - user promoted to moderator");

    Ok(Json(Output::from(OutputData {
        ok: true,
        promoted_at: now.to_rfc3339(),
    })))
}
