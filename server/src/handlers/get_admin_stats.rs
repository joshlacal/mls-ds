use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use std::collections::HashMap;
use tracing::{error, info};

use crate::{
    auth::{enforce_standard, verify_is_admin, AuthUser},
    generated::blue::catbird::mls::get_admin_stats::{
        ModerationStats, ModerationStatsData, Output, OutputData, Parameters, ReportCategoryCounts,
        ReportCategoryCountsData, NSID,
    },
    sqlx_atrium::chrono_to_datetime,
    storage::DbPool,
};

/// Get moderation statistics (admin-only)
/// GET /xrpc/blue.catbird.mls.getAdminStats
#[tracing::instrument(skip(pool, auth_user))]
pub async fn get_admin_stats(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Query(params): Query<Parameters>,
) -> Result<Json<Output>, StatusCode> {
    let params = params.data;

    info!(
        "📍 [get_admin_stats] START - actor: {}, convo: {:?}, since: {:?}",
        auth_user.did, params.convo_id, params.since
    );

    // Enforce standard auth
    if let Err(_) = enforce_standard(&auth_user.claims, NSID) {
        error!("❌ [get_admin_stats] Unauthorized");
        return Err(StatusCode::UNAUTHORIZED);
    }

    // If convoId provided, verify admin
    if let Some(ref convo_id) = params.convo_id {
        verify_is_admin(&pool, convo_id, &auth_user.did).await?;
    }

    // Build time filter clause
    let time_filter = if let Some(ref since) = params.since {
        format!("AND created_at >= '{}'", since.as_str())
    } else {
        String::new()
    };

    // Query report statistics
    let (total_reports, pending_reports, resolved_reports): (i64, i64, i64) =
        sqlx::query_as(&format!(
            "SELECT
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE status = 'pending') as pending,
                COUNT(*) FILTER (WHERE status = 'resolved') as resolved
             FROM reports
             WHERE ($1::TEXT IS NULL OR convo_id = $1) {}",
            time_filter
        ))
        .bind(&params.convo_id)
        .fetch_one(&pool)
        .await
        .map_err(|e| {
            error!("❌ [get_admin_stats] Failed to query report stats: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Query removal count
    let total_removals: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM admin_actions
             WHERE action = 'remove' AND ($1::TEXT IS NULL OR convo_id = $1) {}",
        time_filter
    ))
    .bind(&params.convo_id)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("❌ [get_admin_stats] Failed to query removal count: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Query reports by category
    let category_rows: Vec<(String, i64)> = sqlx::query_as(&format!(
        "SELECT category, COUNT(*) FROM reports
             WHERE ($1::TEXT IS NULL OR convo_id = $1) {}
             GROUP BY category",
        time_filter
    ))
    .bind(&params.convo_id)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!(
            "❌ [get_admin_stats] Failed to query category counts: {}",
            e
        );
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Convert to HashMap for easier access
    let category_map: HashMap<String, i64> = category_rows.into_iter().collect();

    // Build ReportCategoryCounts
    let reports_by_category = ReportCategoryCounts::from(ReportCategoryCountsData {
        harassment: category_map.get("harassment").map(|&c| c as usize),
        spam: category_map.get("spam").map(|&c| c as usize),
        hate_speech: category_map.get("hate_speech").map(|&c| c as usize),
        violence: category_map.get("violence").map(|&c| c as usize),
        sexual_content: category_map.get("sexual_content").map(|&c| c as usize),
        impersonation: category_map.get("impersonation").map(|&c| c as usize),
        privacy_violation: category_map.get("privacy_violation").map(|&c| c as usize),
        other_category: category_map.get("other").map(|&c| c as usize),
    });

    // Calculate average resolution time in hours
    let avg_resolution_hours: Option<f64> = sqlx::query_scalar(&format!(
        "SELECT AVG(EXTRACT(EPOCH FROM (resolved_at - created_at)) / 3600)
             FROM reports
             WHERE status = 'resolved' AND ($1::TEXT IS NULL OR convo_id = $1) {}",
        time_filter
    ))
    .bind(&params.convo_id)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!(
            "❌ [get_admin_stats] Failed to query avg resolution time: {}",
            e
        );
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Convert to usize if present
    let average_resolution_time_hours = avg_resolution_hours.map(|h| h.round() as usize);

    let stats = ModerationStats::from(ModerationStatsData {
        total_reports: total_reports as usize,
        pending_reports: pending_reports as usize,
        resolved_reports: resolved_reports as usize,
        total_removals: total_removals as usize,
        block_conflicts_resolved: 0, // Will be populated in Phase 5
        reports_by_category: Some(reports_by_category),
        average_resolution_time_hours,
    });

    let generated_at = chrono_to_datetime(chrono::Utc::now());

    info!(
        "✅ [get_admin_stats] SUCCESS - total_reports: {}, pending: {}, resolved: {}",
        total_reports, pending_reports, resolved_reports
    );

    Ok(Json(Output::from(OutputData {
        stats,
        generated_at,
        convo_id: params.convo_id,
    })))
}
