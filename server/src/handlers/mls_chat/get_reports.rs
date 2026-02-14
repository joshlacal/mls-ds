use axum::{extract::State, http::StatusCode, Json};
use jacquard_axum::ExtractXrpc;
use tracing::{error, info};

use crate::{
    auth::{enforce_standard, verify_is_admin, AuthUser},
    generated::blue_catbird::mlsChat::get_reports::{
        GetReportsOutput, GetReportsRequest, ReportView,
    },
    sqlx_jacquard::chrono_to_datetime,
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.getReports";

/// Query reports for a conversation.
/// GET /xrpc/blue.catbird.mlsChat.getReports
#[tracing::instrument(skip(pool, auth_user))]
pub async fn get_reports(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    ExtractXrpc(input): ExtractXrpc<GetReportsRequest>,
) -> Result<Json<GetReportsOutput<'static>>, StatusCode> {
    if let Err(_e) = enforce_standard(&auth_user.claims, NSID) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let convo_id = input.convo_id.as_ref();

    // Verify admin status
    verify_is_admin(&pool, convo_id, &auth_user.did).await?;

    let limit = input.limit.unwrap_or(50).min(100);

    let rows: Vec<(
        String,
        String,
        String,
        String,
        chrono::DateTime<chrono::Utc>,
        String,
        Option<String>,
        Option<chrono::DateTime<chrono::Utc>>,
    )> = if let Some(ref status) = input.status {
        sqlx::query_as(
            "SELECT id, reporter_did, reported_did, category, created_at, status,
                    resolved_by_did, resolved_at
             FROM reports
             WHERE convo_id = $1 AND status = $2
             ORDER BY created_at DESC
             LIMIT $3",
        )
        .bind(convo_id)
        .bind(status.as_ref())
        .bind(limit)
        .fetch_all(&pool)
        .await
        .map_err(|e| {
            error!("Database query failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
    } else {
        sqlx::query_as(
            "SELECT id, reporter_did, reported_did, category, created_at, status,
                    resolved_by_did, resolved_at
             FROM reports
             WHERE convo_id = $1
             ORDER BY created_at DESC
             LIMIT $2",
        )
        .bind(convo_id)
        .bind(limit)
        .fetch_all(&pool)
        .await
        .map_err(|e| {
            error!("Database query failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
    };

    let mut reports: Vec<ReportView<'static>> = Vec::with_capacity(rows.len());

    for (
        id,
        reporter_did,
        reported_did,
        category,
        created_at,
        status,
        resolved_by_did,
        resolved_at,
    ) in rows
    {
        let reporter_did = reporter_did.parse().map_err(|e| {
            error!("Failed to parse reporter DID '{}': {}", reporter_did, e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        let reported_did = reported_did.parse().map_err(|e| {
            error!("Failed to parse reported DID '{}': {}", reported_did, e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        let resolved_by_did = match resolved_by_did {
            Some(d) => {
                let parsed = d.parse().map_err(|e| {
                    error!("Failed to parse resolved_by DID '{}': {}", d, e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;
                Some(parsed)
            }
            None => None,
        };

        reports.push(ReportView {
            id: id.into(),
            category: category.into(),
            reporter_did,
            reported_did,
            status: status.into(),
            created_at: chrono_to_datetime(created_at),
            resolved_by_did,
            resolved_at: resolved_at.map(chrono_to_datetime),
            extra_data: Default::default(),
        });
    }
    info!(
        "Returned {} reports for convo {}",
        reports.len(),
        crate::crypto::redact_for_log(convo_id)
    );

    Ok(Json(GetReportsOutput {
        reports,
        cursor: None,
        extra_data: Default::default(),
    }))
}
