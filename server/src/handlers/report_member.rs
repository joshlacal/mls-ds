use axum::{extract::State, http::StatusCode, Json};
use tracing::{error, info};

use crate::{
    auth::{enforce_standard, verify_is_member, AuthUser},
    generated::blue_catbird::mls::report_member::{ReportMember, ReportMemberOutput},
    sqlx_jacquard::chrono_to_datetime,
    storage::DbPool,
};

/// Report a member for moderation (E2EE)
/// POST /xrpc/blue.catbird.mls.reportMember
#[tracing::instrument(skip(pool, auth_user))]
pub async fn report_member(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    body: String,
) -> Result<Json<ReportMemberOutput<'static>>, StatusCode> {
    let input = crate::jacquard_json::from_json_body::<ReportMember>(&body)?;
    info!(
        "📍 [report_member] START - reporter: {}, convo: {}, reported: {}, category: {}",
        auth_user.did,
        input.convo_id,
        input.reported_did.as_str(),
        input.category
    );

    // Enforce standard auth
    if let Err(_) = enforce_standard(&auth_user.claims, "blue.catbird.mls.reportMember") {
        error!("❌ [report_member] Unauthorized");
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Verify reporter is member
    verify_is_member(&pool, &input.convo_id, &auth_user.did).await?;

    // Verify target is member
    verify_is_member(&pool, &input.convo_id, input.reported_did.as_str()).await?;

    // Cannot report self
    if auth_user.did == input.reported_did.as_str() {
        error!("❌ [report_member] Cannot report self");
        return Err(StatusCode::BAD_REQUEST);
    }

    // Validate encrypted content size (50KB max)
    if input.encrypted_content.len() > 50 * 1024 {
        error!("❌ [report_member] Encrypted content exceeds 50KB");
        return Err(StatusCode::BAD_REQUEST);
    }

    // Validate messageIds array size (max 20)
    if let Some(ref msg_ids) = input.message_ids {
        if msg_ids.len() > 20 {
            error!("❌ [report_member] Too many message IDs (max 20)");
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    // Validate category (valid enum values)
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
    if !valid_categories.contains(&input.category.as_str()) {
        error!("❌ [report_member] Invalid category: {}", input.category);
        return Err(StatusCode::BAD_REQUEST);
    }

    let now = chrono::Utc::now();
    let report_id = uuid::Uuid::new_v4().to_string();
    let message_ids_owned: Option<Vec<String>> = input
        .message_ids
        .as_ref()
        .map(|ids| ids.iter().map(|s| s.to_string()).collect());

    // Insert report
    sqlx::query(
        "INSERT INTO reports (
            id, convo_id, reporter_did, reported_did, category,
            encrypted_content, message_ids, created_at, status
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending')",
    )
    .bind(&report_id)
    .bind(input.convo_id.as_str())
    .bind(&auth_user.did)
    .bind(input.reported_did.as_str())
    .bind(input.category.as_str())
    .bind(input.encrypted_content.as_ref())
    .bind(&message_ids_owned)
    .bind(&now)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("❌ [report_member] Database insert failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!("✅ [report_member] SUCCESS - report {} created", report_id);

    Ok(Json(ReportMemberOutput {
        report_id: report_id.into(),
        submitted_at: chrono_to_datetime(now),
        extra_data: None,
    }))
}
