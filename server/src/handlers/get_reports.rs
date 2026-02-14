use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use base64::Engine;
use chrono::{DateTime, Utc};
use tracing::{error, info};

use crate::{
    auth::{enforce_standard, verify_is_admin, AuthUser},
    generated::blue_catbird::mls::get_reports::{GetReports, GetReportsOutput, ReportView},
    sqlx_jacquard::{chrono_to_datetime, try_string_to_did},
    storage::DbPool,
};

/// Get reports for a conversation (admin-only)
/// GET /xrpc/blue.catbird.mls.getReports
#[tracing::instrument(skip(pool, auth_user))]
pub async fn get_reports(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    raw_query: axum::extract::RawQuery,
) -> Result<Json<GetReportsOutput<'static>>, StatusCode> {
    let params = crate::jacquard_json::from_query_string::<GetReports>(
        raw_query.0.as_deref().unwrap_or(""),
    )?;
    info!(
        "📍 [get_reports] START - actor: {}, convo: {}, status: {:?}, limit: {:?}",
        auth_user.did, params.convo_id, params.status, params.limit
    );

    // Enforce standard auth
    if let Err(_) = enforce_standard(&auth_user.claims, "blue.catbird.mls.getReports") {
        error!("❌ [get_reports] Unauthorized");
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Verify admin status
    verify_is_admin(&pool, &params.convo_id, &auth_user.did).await?;

    // Get limit (default 50, max 100)
    let limit = params.limit.unwrap_or(50).min(100);

    // Build query with optional status filter
    let rows: Vec<(
        String,
        String,
        String,
        Vec<u8>,
        DateTime<Utc>,
        String,
        Option<String>,
        Option<DateTime<Utc>>,
    )> = if let Some(ref status) = params.status {
        sqlx::query_as(
            "SELECT id, reporter_did, reported_did, encrypted_content, created_at, status,
                    resolved_by_did, resolved_at
             FROM reports
             WHERE convo_id = $1 AND status = $2
             ORDER BY created_at DESC
             LIMIT $3",
        )
        .bind(params.convo_id.as_str())
        .bind(status.as_str())
        .bind(limit)
        .fetch_all(&pool)
        .await
        .map_err(|e| {
            error!("❌ [get_reports] Database query failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
    } else {
        sqlx::query_as(
            "SELECT id, reporter_did, reported_did, encrypted_content, created_at, status,
                    resolved_by_did, resolved_at
             FROM reports
             WHERE convo_id = $1
             ORDER BY created_at DESC
             LIMIT $2",
        )
        .bind(params.convo_id.as_str())
        .bind(limit)
        .fetch_all(&pool)
        .await
        .map_err(|e| {
            error!("❌ [get_reports] Database query failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
    };

    // Convert to ReportView
    let reports: Result<Vec<ReportView>, StatusCode> = rows
        .into_iter()
        .map(
            |(
                id,
                reporter_did,
                reported_did,
                encrypted_content,
                created_at,
                status,
                resolved_by_did,
                resolved_at,
            )| {
                let reporter_did = try_string_to_did(&reporter_did).map_err(|e| {
                    error!("❌ [get_reports] Invalid reporter DID: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;

                let reported_did = try_string_to_did(&reported_did).map_err(|e| {
                    error!("❌ [get_reports] Invalid reported DID: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;

                let resolved_by = resolved_by_did
                    .as_ref()
                    .map(|d| try_string_to_did(d))
                    .transpose()
                    .map_err(|e| {
                        error!("❌ [get_reports] Invalid resolved_by DID: {}", e);
                        StatusCode::INTERNAL_SERVER_ERROR
                    })?;

                Ok(ReportView {
                    id: id.into(),
                    reporter_did,
                    reported_did,
                    encrypted_content: base64::engine::general_purpose::STANDARD
                        .encode(encrypted_content)
                        .into(),
                    created_at: chrono_to_datetime(created_at),
                    status: status.into(),
                    resolved_by,
                    resolved_at: resolved_at.map(chrono_to_datetime),
                    extra_data: None,
                })
            },
        )
        .collect();

    let reports = reports?;

    info!(
        "✅ [get_reports] SUCCESS - returned {} reports",
        reports.len()
    );

    Ok(Json(GetReportsOutput {
        reports,
        extra_data: None,
    }))
}
