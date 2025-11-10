use axum::{extract::State, http::StatusCode, Json};
use tracing::{info, error};

use crate::{
    auth::{AuthUser, verify_is_admin, enforce_standard},
    generated::blue::catbird::mls::resolve_report::{Input, Output, OutputData, NSID},
    storage::DbPool,
};

/// Resolve a report with an action (admin-only)
/// POST /xrpc/blue.catbird.mls.resolveReport
#[tracing::instrument(skip(pool, auth_user))]
pub async fn resolve_report(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Json(input): Json<Input>,
) -> Result<Json<Output>, StatusCode> {
    let input = input.data;

    info!("📍 [resolve_report] START - actor: {}, report: {}, action: {}",
          auth_user.did, input.report_id, input.action);

    // Enforce standard auth
    if let Err(_) = enforce_standard(&auth_user.claims, NSID) {
        error!("❌ [resolve_report] Unauthorized");
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Validate action enum
    let valid_actions = ["removed_member", "dismissed", "no_action"];
    if !valid_actions.contains(&input.action.as_str()) {
        error!("❌ [resolve_report] Invalid action: {}", input.action);
        return Err(StatusCode::BAD_REQUEST);
    }

    // Validate notes length (max 1000 chars)
    if let Some(ref notes) = input.notes {
        if notes.len() > 1000 {
            error!("❌ [resolve_report] Notes exceed 1000 characters");
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    // Fetch report to get convo_id and verify it exists
    let (convo_id, current_status): (String, String) = sqlx::query_as(
        "SELECT convo_id, status FROM reports WHERE id = $1"
    )
    .bind(&input.report_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!("❌ [resolve_report] Database query failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .ok_or_else(|| {
        error!("❌ [resolve_report] Report not found");
        StatusCode::NOT_FOUND
    })?;

    // Verify admin status for this conversation
    verify_is_admin(&pool, &convo_id, &auth_user.did).await?;

    // Check if already resolved
    if current_status != "pending" {
        error!("❌ [resolve_report] Report already resolved (status: {})", current_status);
        return Err(StatusCode::BAD_REQUEST);
    }

    let now = chrono::Utc::now();

    // Update report
    let affected_rows = sqlx::query(
        "UPDATE reports
         SET status = 'resolved', resolved_by_did = $2, resolved_at = $3,
             resolution_action = $4, resolution_notes = $5
         WHERE id = $1"
    )
    .bind(&input.report_id)
    .bind(&auth_user.did)
    .bind(&now)
    .bind(&input.action)
    .bind(&input.notes)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("❌ [resolve_report] Database update failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .rows_affected();

    if affected_rows == 0 {
        error!("❌ [resolve_report] Failed to update report (concurrent modification?)");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    info!("✅ [resolve_report] SUCCESS - report {} resolved with action '{}'",
          input.report_id, input.action);

    Ok(Json(Output::from(OutputData { ok: true })))
}
