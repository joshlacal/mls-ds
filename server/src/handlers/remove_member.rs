use axum::{extract::State, http::StatusCode, Json};
use tracing::{info, error};

use crate::{
    auth::{AuthUser, verify_is_admin, verify_is_member, enforce_standard},
    generated::blue::catbird::mls::remove_member::{Input, Output, OutputData, NSID},
    storage::DbPool,
};

/// Remove a member from conversation (admin-only)
/// POST /xrpc/blue.catbird.mls.removeMember
#[tracing::instrument(skip(pool, auth_user))]
pub async fn remove_member(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Json(input): Json<Input>,
) -> Result<Json<Output>, StatusCode> {
    let input = input.data;

    info!("📍 [remove_member] START - actor: {}, convo: {}, target: {}",
          auth_user.did, input.convo_id, input.target_did.as_str());

    // Enforce standard auth
    if let Err(_) = enforce_standard(&auth_user.claims, NSID) {
        error!("❌ [remove_member] Unauthorized");
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Verify actor is an admin
    verify_is_admin(&pool, &input.convo_id, &auth_user.did).await?;

    // Cannot remove self
    if auth_user.did == input.target_did.as_str() {
        error!("❌ [remove_member] Cannot remove self - use leaveConvo");
        return Err(StatusCode::BAD_REQUEST);
    }

    // Verify target is member
    verify_is_member(&pool, &input.convo_id, input.target_did.as_str()).await?;

    let now = chrono::Utc::now();

    // Soft delete member (set left_at for ALL devices of this user)
    // In multi-device mode, this removes all devices belonging to the target user
    let affected_rows = sqlx::query(
        "UPDATE members SET left_at = $3
         WHERE convo_id = $1 AND user_did = $2 AND left_at IS NULL"
    )
    .bind(&input.convo_id)
    .bind(input.target_did.as_str())
    .bind(&now)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("❌ [remove_member] Database update failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .rows_affected();

    if affected_rows == 0 {
        error!("❌ [remove_member] Member already removed or not found");
        return Err(StatusCode::NOT_FOUND);
    }

    // Log admin action
    let action_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO admin_actions (id, convo_id, actor_did, action, target_did, reason, created_at)
         VALUES ($1, $2, $3, 'remove', $4, $5, $6)"
    )
    .bind(&action_id)
    .bind(&input.convo_id)
    .bind(&auth_user.did)
    .bind(input.target_did.as_str())
    .bind(&input.reason)
    .bind(&now)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("❌ [remove_member] Failed to log action: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Get current epoch hint
    let epoch_hint: Option<i32> = sqlx::query_scalar(
        "SELECT current_epoch FROM conversations WHERE id = $1"
    )
    .bind(&input.convo_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!("❌ [remove_member] Failed to fetch epoch: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let epoch_hint = epoch_hint.ok_or_else(|| {
        error!("❌ [remove_member] Conversation not found");
        StatusCode::NOT_FOUND
    })? as usize;

    info!("✅ [remove_member] SUCCESS - {} removed by {}, epoch: {}",
          input.target_did.as_str(), auth_user.did, epoch_hint);

    Ok(Json(Output::from(OutputData {
        ok: true,
        epoch_hint,
    })))
}
