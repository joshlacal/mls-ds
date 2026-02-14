use axum::{extract::State, http::StatusCode, Json};
use tracing::{error, info};

use crate::{
    auth::{count_admins, verify_is_admin, verify_is_member, AuthUser},
    generated::blue_catbird::mls::demote_admin::{DemoteAdmin, DemoteAdminOutput},
    storage::DbPool,
};

/// Demote an admin to regular member
/// POST /xrpc/blue.catbird.mls.demoteAdmin
#[tracing::instrument(skip(pool, auth_user))]
pub async fn demote_admin(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    body: String,
) -> Result<Json<DemoteAdminOutput<'static>>, StatusCode> {
    let input = crate::jacquard_json::from_json_body::<DemoteAdmin>(&body)?;
    info!(
        "📍 [demote_admin] START - actor: {}, convo: {}, target: {}",
        auth_user.did,
        input.convo_id,
        input.target_did.as_str()
    );

    // Enforce standard auth
    if let Err(_) = crate::auth::enforce_standard(&auth_user.claims, "blue.catbird.mls.demoteAdmin")
    {
        error!("❌ [demote_admin] Unauthorized");
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Verify actor is an admin (or is self-demoting)
    if auth_user.did != input.target_did.as_str() {
        verify_is_admin(&pool, &input.convo_id, &auth_user.did).await?;
    } else {
        // Self-demotion: just verify actor is a member
        verify_is_member(&pool, &input.convo_id, &auth_user.did).await?;
    }

    // Verify target is a member
    verify_is_member(&pool, &input.convo_id, input.target_did.as_str()).await?;

    // Check if target is currently an admin (check any of their devices)
    // In multi-device mode, all devices of a user share the same admin status
    let is_admin: bool = sqlx::query_scalar(
        "SELECT is_admin FROM members
         WHERE convo_id = $1 AND user_did = $2 AND left_at IS NULL
         LIMIT 1",
    )
    .bind(input.convo_id.as_str())
    .bind(input.target_did.as_str())
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("❌ [demote_admin] Database query failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if !is_admin {
        error!("❌ [demote_admin] Target is not an admin");
        return Err(StatusCode::BAD_REQUEST);
    }

    // Prevent demoting the last admin
    let admin_count = count_admins(&pool, &input.convo_id).await?;
    if admin_count <= 1 {
        error!("❌ [demote_admin] Cannot demote last admin");
        return Err(StatusCode::BAD_REQUEST);
    }

    let now = chrono::Utc::now();

    // Demote admin to regular member (updates ALL devices of this user)
    // In multi-device mode, admin status applies to the user, not individual devices
    sqlx::query(
        "UPDATE members
         SET is_admin = false
         WHERE convo_id = $1 AND user_did = $2 AND left_at IS NULL",
    )
    .bind(input.convo_id.as_str())
    .bind(input.target_did.as_str())
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("❌ [demote_admin] Failed to demote: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Log admin action for audit trail
    let action_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO admin_actions (id, convo_id, actor_did, action, target_did, created_at)
         VALUES ($1, $2, $3, 'demote', $4, $5)",
    )
    .bind(&action_id)
    .bind(input.convo_id.as_str())
    .bind(&auth_user.did)
    .bind(input.target_did.as_str())
    .bind(&now)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("❌ [demote_admin] Failed to log action: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!("✅ [demote_admin] SUCCESS - admin demoted");

    Ok(Json(DemoteAdminOutput {
        ok: true,
        extra_data: Default::default(),
    }))
}
