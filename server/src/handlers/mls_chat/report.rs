use axum::{extract::State, http::StatusCode, Json};
use jacquard_axum::ExtractXrpc;
use tracing::{error, info};

use crate::{
    auth::{enforce_standard, verify_is_admin, verify_is_member, AuthUser},
    generated::blue_catbird::mlsChat::report::{ReportOutput, ReportRequest},
    sqlx_jacquard::chrono_to_datetime,
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.report";

/// Consolidated report/moderation handler (POST)
/// POST /xrpc/blue.catbird.mlsChat.report
///
/// Consolidates: reportMember, resolveReport, warnMember
#[tracing::instrument(skip(pool, auth_user, input))]
pub async fn report_post(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    ExtractXrpc(input): ExtractXrpc<ReportRequest>,
) -> Result<Json<ReportOutput<'static>>, StatusCode> {
    if let Err(_e) = enforce_standard(&auth_user.claims, NSID) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    match input.action.as_ref() {
        "report" => {
            let convo_id = input.convo_id.as_ref();
            let reported_did = input.target_did.as_deref().unwrap_or_default();
            let category = input.reason.as_deref().unwrap_or_default();
            let encrypted_content = input
                .details
                .as_ref()
                .map(|b| b.to_vec())
                .unwrap_or_default();
            let message_ids: Option<Vec<String>> = input
                .message_ids
                .as_ref()
                .map(|ids| ids.iter().map(|s| s.to_string()).collect());

            info!(
                "v2.report: reportMember {} in {}",
                crate::crypto::redact_for_log(reported_did),
                crate::crypto::redact_for_log(convo_id)
            );

            // Verify reporter is member
            verify_is_member(&pool, convo_id, &auth_user.did).await?;

            // Verify target is member
            verify_is_member(&pool, convo_id, reported_did).await?;

            // Cannot report self
            if auth_user.did == reported_did {
                error!("Cannot report self");
                return Err(StatusCode::BAD_REQUEST);
            }

            // Validate encrypted content size (50KB max)
            if encrypted_content.len() > 50 * 1024 {
                error!("Encrypted content exceeds 50KB");
                return Err(StatusCode::BAD_REQUEST);
            }

            // Validate messageIds array size (max 20)
            if let Some(ref msg_ids) = message_ids {
                if msg_ids.len() > 20 {
                    error!("Too many message IDs (max 20)");
                    return Err(StatusCode::BAD_REQUEST);
                }
            }

            // Validate category
            let valid_categories = [
                "harassment",
                "spam",
                "hate_speech",
                "violence",
                "sexual_content",
                "impersonation",
                "privacy_violation",
                "other",
            ];
            if !valid_categories.contains(&category) {
                error!("Invalid category: {}", category);
                return Err(StatusCode::BAD_REQUEST);
            }

            let now = chrono::Utc::now();
            let report_id = uuid::Uuid::new_v4().to_string();

            sqlx::query(
                "INSERT INTO reports (
                    id, convo_id, reporter_did, reported_did, category,
                    encrypted_content, message_ids, created_at, status
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending')",
            )
            .bind(&report_id)
            .bind(convo_id)
            .bind(&auth_user.did)
            .bind(reported_did)
            .bind(category)
            .bind(&encrypted_content)
            .bind(&message_ids)
            .bind(&now)
            .execute(&pool)
            .await
            .map_err(|e| {
                error!("Database insert failed: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            info!("Report {} created", report_id);

            Ok(Json(ReportOutput {
                report_id: Some(report_id.into()),
                submitted_at: Some(chrono_to_datetime(now)),
                success: Some(true),
                reports: None,
                extra_data: Default::default(),
            }))
        }
        "resolve" => {
            let report_id = input.report_id.as_deref().unwrap_or_default();
            let resolve_action = input.reason.as_deref().unwrap_or_default();
            let notes = input.reason.as_deref();

            info!("v2.report: resolveReport {}", report_id);

            // Validate action enum
            let valid_actions = ["removed_member", "dismissed", "no_action"];
            if !valid_actions.contains(&resolve_action) {
                error!("Invalid action: {}", resolve_action);
                return Err(StatusCode::BAD_REQUEST);
            }

            // Validate notes length (max 1000 chars)
            if let Some(ref notes) = notes {
                if notes.len() > 1000 {
                    error!("Notes exceed 1000 characters");
                    return Err(StatusCode::BAD_REQUEST);
                }
            }

            // Fetch report to get convo_id and verify it exists
            let (convo_id, current_status): (String, String) =
                sqlx::query_as("SELECT convo_id, status FROM reports WHERE id = $1")
                    .bind(report_id)
                    .fetch_optional(&pool)
                    .await
                    .map_err(|e| {
                        error!("Database query failed: {}", e);
                        StatusCode::INTERNAL_SERVER_ERROR
                    })?
                    .ok_or_else(|| {
                        error!("Report not found");
                        StatusCode::NOT_FOUND
                    })?;

            // Verify admin status
            verify_is_admin(&pool, &convo_id, &auth_user.did).await?;

            // Check if already resolved
            if current_status != "pending" {
                error!("Report already resolved (status: {})", current_status);
                return Err(StatusCode::BAD_REQUEST);
            }

            let now = chrono::Utc::now();

            sqlx::query(
                "UPDATE reports
                 SET status = 'resolved', resolved_by_did = $2, resolved_at = $3,
                     resolution_action = $4, resolution_notes = $5
                 WHERE id = $1",
            )
            .bind(report_id)
            .bind(&auth_user.did)
            .bind(&now)
            .bind(resolve_action)
            .bind(notes)
            .execute(&pool)
            .await
            .map_err(|e| {
                error!("Database update failed: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            info!(
                "Report {} resolved with action '{}'",
                report_id, resolve_action
            );

            Ok(Json(ReportOutput {
                success: Some(true),
                report_id: None,
                reports: None,
                submitted_at: None,
                extra_data: Default::default(),
            }))
        }
        "warn" => {
            let convo_id = input.convo_id.as_ref();
            let member_did = input.target_did.as_deref().unwrap_or_default();
            let reason = input.reason.as_deref().unwrap_or_default();

            info!(
                "v2.report: warnMember {} in {}",
                crate::crypto::redact_for_log(member_did),
                crate::crypto::redact_for_log(convo_id)
            );

            // Verify actor is admin
            verify_is_admin(&pool, convo_id, &auth_user.did).await?;

            // Cannot warn self
            if auth_user.did == member_did {
                error!("Cannot warn self");
                return Err(StatusCode::BAD_REQUEST);
            }

            // Verify target is member
            verify_is_member(&pool, convo_id, member_did).await?;

            // Validate reason length (max 500 chars)
            if reason.len() > 500 {
                error!("Reason exceeds 500 characters");
                return Err(StatusCode::BAD_REQUEST);
            }

            // Check if target is an admin (cannot warn admins)
            let target_is_admin: Option<bool> = sqlx::query_scalar(
                "SELECT is_admin FROM members
                 WHERE convo_id = $1 AND (member_did = $2 OR user_did = $2) AND left_at IS NULL
                 LIMIT 1",
            )
            .bind(convo_id)
            .bind(member_did)
            .fetch_optional(&pool)
            .await
            .map_err(|e| {
                error!("Database query failed: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            if target_is_admin.unwrap_or(false) {
                error!("Cannot warn admins");
                return Err(StatusCode::FORBIDDEN);
            }

            let now = chrono::Utc::now();
            let warning_id = uuid::Uuid::new_v4().to_string();

            sqlx::query(
                "INSERT INTO admin_actions (id, convo_id, actor_did, action, target_did, reason, created_at)
                 VALUES ($1, $2, $3, 'warn', $4, $5, $6)",
            )
            .bind(&warning_id)
            .bind(convo_id)
            .bind(&auth_user.did)
            .bind(member_did)
            .bind(reason)
            .bind(&now)
            .execute(&pool)
            .await
            .map_err(|e| {
                error!("Failed to create warning record: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            info!(
                "Warning {} issued to {}",
                warning_id,
                crate::crypto::redact_for_log(member_did)
            );

            Ok(Json(ReportOutput {
                success: Some(true),
                report_id: Some(warning_id.into()),
                reports: None,
                submitted_at: Some(chrono_to_datetime(now)),
                extra_data: Default::default(),
            }))
        }
        other => {
            error!("Unknown report action: {}", other);
            Err(StatusCode::BAD_REQUEST)
        }
    }
}
