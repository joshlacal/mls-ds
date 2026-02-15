use axum::{extract::State, http::StatusCode, Json};
use tracing::{error, info};

use crate::{
    auth::{verify_is_admin, verify_is_member, AuthUser},
    generated::blue_catbird::mls::promote_admin::{PromoteAdmin, PromoteAdminOutput},
    sqlx_jacquard::chrono_to_datetime,
    storage::DbPool,
};

/// Promote a member to admin status
/// POST /xrpc/blue.catbird.mls.promoteAdmin
#[tracing::instrument(skip(pool, auth_user))]
pub async fn promote_admin(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    body: String,
) -> Result<Json<PromoteAdminOutput<'static>>, StatusCode> {
    let input = crate::jacquard_json::from_json_body::<PromoteAdmin>(&body)?;
    info!(
        "📍 [promote_admin] START - actor: {}, convo: {}, target: {}",
        auth_user.did,
        input.convo_id,
        input.target_did.as_str()
    );

    // Enforce standard auth
    // Verify actor is an admin
    verify_is_admin(&pool, &input.convo_id, &auth_user.did).await?;

    // Verify target is a member
    verify_is_member(&pool, &input.convo_id, input.target_did.as_str()).await?;

    // Check if target is already an admin (check any of their devices)
    // In multi-device mode, all devices of a user share the same admin status
    let is_already_admin: bool = sqlx::query_scalar(
        "SELECT is_admin FROM members
         WHERE convo_id = $1 AND user_did = $2 AND left_at IS NULL
         LIMIT 1",
    )
    .bind(input.convo_id.as_str())
    .bind(input.target_did.as_str())
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("❌ [promote_admin] Database query failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if is_already_admin {
        error!("❌ [promote_admin] Target is already an admin");
        return Err(StatusCode::BAD_REQUEST);
    }

    let now = chrono::Utc::now();

    // Promote member to admin (updates ALL devices of this user)
    // In multi-device mode, admin status applies to the user, not individual devices
    sqlx::query(
        "UPDATE members
         SET is_admin = true, promoted_at = $3, promoted_by_did = $4
         WHERE convo_id = $1 AND user_did = $2 AND left_at IS NULL",
    )
    .bind(input.convo_id.as_str())
    .bind(input.target_did.as_str())
    .bind(&now)
    .bind(&auth_user.did)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("❌ [promote_admin] Failed to promote: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Log admin action for audit trail
    let action_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO admin_actions (id, convo_id, actor_did, action, target_did, created_at)
         VALUES ($1, $2, $3, 'promote', $4, $5)",
    )
    .bind(&action_id)
    .bind(input.convo_id.as_str())
    .bind(&auth_user.did)
    .bind(input.target_did.as_str())
    .bind(&now)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("❌ [promote_admin] Failed to log action: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!("✅ [promote_admin] SUCCESS - user promoted to admin");

    Ok(Json(PromoteAdminOutput {
        ok: true,
        promoted_at: chrono_to_datetime(now),
        extra_data: Default::default(),
    }))
}
