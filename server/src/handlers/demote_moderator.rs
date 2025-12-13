use axum::{extract::State, http::StatusCode, Json};
use tracing::{error, info};

use crate::{
    auth::{verify_is_admin, verify_is_member, AuthUser},
    storage::DbPool,
};

/// NSID for this endpoint
pub const NSID: &str = "blue.catbird.mls.demoteModerator";

/// Input for demoteModerator
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

/// Output for demoteModerator
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct OutputData {
    pub ok: bool,
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

/// Demote a moderator to regular member
/// POST /xrpc/blue.catbird.mls.demoteModerator
#[tracing::instrument(skip(pool, auth_user))]
pub async fn demote_moderator(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Json(input): Json<Input>,
) -> Result<Json<Output>, StatusCode> {
    let input = input.data;

    info!(
        "📍 [demote_moderator] START - actor: {}, convo: {}, target: {}",
        auth_user.did, input.convo_id, input.target_did
    );

    // Enforce standard auth
    if let Err(_) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        error!("❌ [demote_moderator] Unauthorized");
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Verify actor is an admin (or is self-demoting)
    if auth_user.did != input.target_did {
        verify_is_admin(&pool, &input.convo_id, &auth_user.did).await?;
    } else {
        // Self-demotion: just verify actor is a member
        verify_is_member(&pool, &input.convo_id, &auth_user.did).await?;
    }

    // Verify target is a member
    verify_is_member(&pool, &input.convo_id, &input.target_did).await?;

    // Check if target is currently a moderator
    let is_moderator: bool = sqlx::query_scalar(
        "SELECT COALESCE(is_moderator, false) FROM members
         WHERE convo_id = $1 AND user_did = $2 AND left_at IS NULL
         LIMIT 1",
    )
    .bind(&input.convo_id)
    .bind(&input.target_did)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("❌ [demote_moderator] Database query failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if !is_moderator {
        error!("❌ [demote_moderator] Target is not a moderator");
        return Err(StatusCode::BAD_REQUEST);
    }

    let now = chrono::Utc::now();

    // Demote moderator to regular member (updates ALL devices of this user)
    sqlx::query(
        "UPDATE members
         SET is_moderator = false, moderator_promoted_at = NULL, moderator_promoted_by_did = NULL
         WHERE convo_id = $1 AND user_did = $2 AND left_at IS NULL",
    )
    .bind(&input.convo_id)
    .bind(&input.target_did)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("❌ [demote_moderator] Failed to demote: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Log admin action for audit trail
    let action_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO admin_actions (id, convo_id, actor_did, action, target_did, created_at)
         VALUES ($1, $2, $3, 'demote_moderator', $4, $5)",
    )
    .bind(&action_id)
    .bind(&input.convo_id)
    .bind(&auth_user.did)
    .bind(&input.target_did)
    .bind(&now)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("❌ [demote_moderator] Failed to log action: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!("✅ [demote_moderator] SUCCESS - moderator demoted");

    Ok(Json(Output::from(OutputData { ok: true })))
}
