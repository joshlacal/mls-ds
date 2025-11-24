// =============================================================================
// Admin System for MLS E2EE Group Chat
// =============================================================================
// ⚠️ DEPRECATED: Most handler functions have been moved to handlers/ directory
// ⚠️ This module is kept only for the verify_is_admin() utility function
// ⚠️ All route handlers now use handlers/promote_admin.rs, handlers/demote_admin.rs, etc.
// =============================================================================
// Server enforces admin permissions but does NOT see admin roster
// Admin roster is distributed encrypted via MLS control messages
//
// Server only knows:
// - Who is admin (is_admin column in members table)
// - When they were promoted (promoted_at, promoted_by_did)
//
// Server does NOT store:
// - Admin roster ciphertext (too large, changes frequently)
// - Admin capabilities (clients decrypt and enforce)
//
// Admin Actions:
// 1. Promote member to admin
// 2. Demote admin to member
// 3. Remove member from conversation
// 4. View E2EE reports (encrypted content)
// 5. Resolve reports (mark as resolved/dismissed)
//
// ❌ Admins CANNOT delete messages (E2EE fundamental limitation)
// =============================================================================

use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{error, info};
use crate::auth::AuthUser;

// =============================================================================
// Request/Response Models
// =============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PromoteAdminInput {
    /// Conversation ID
    pub convo_id: String,
    /// DID of member to promote
    pub member_did: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PromoteAdminOutput {
    /// Success confirmation
    pub success: bool,
    /// Updated member view
    pub member: MemberView,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DemoteAdminInput {
    /// Conversation ID
    pub convo_id: String,
    /// DID of admin to demote
    pub admin_did: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DemoteAdminOutput {
    /// Success confirmation
    pub success: bool,
    /// Updated member view
    pub member: MemberView,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveMemberInput {
    /// Conversation ID
    pub convo_id: String,
    /// DID of member to remove
    pub member_did: String,
    /// MLS Commit message (group state update)
    pub commit: Vec<u8>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveMemberOutput {
    /// Success confirmation
    pub success: bool,
    /// New epoch after removal
    pub new_epoch: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportMemberInput {
    /// Conversation ID
    pub convo_id: String,
    /// DID of member being reported
    pub reported_did: String,
    /// Encrypted report content (reason, evidence)
    /// Encrypted with MLS group key - only admins can decrypt
    pub encrypted_content: Vec<u8>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportMemberOutput {
    /// Created report ID
    pub report_id: String,
    /// Success confirmation
    pub success: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetReportsInput {
    /// Conversation ID
    pub convo_id: String,
    /// Filter by status (optional)
    pub status: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetReportsOutput {
    /// List of reports
    pub reports: Vec<ReportView>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolveReportInput {
    /// Report ID
    pub report_id: String,
    /// Resolution action taken
    pub action: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolveReportOutput {
    /// Success confirmation
    pub success: bool,
}

// =============================================================================
// View Models
// =============================================================================

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct MemberView {
    pub did: String,
    pub joined_at: chrono::DateTime<chrono::Utc>,
    pub is_admin: bool,
    pub promoted_at: Option<chrono::DateTime<chrono::Utc>>,
    pub promoted_by: Option<String>,
    pub leaf_index: Option<i32>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct ReportView {
    pub id: String,
    pub convo_id: String,
    pub reporter_did: String,
    pub reported_did: String,
    pub encrypted_content: Vec<u8>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub status: String,
    pub resolved_by_did: Option<String>,
    pub resolved_at: Option<chrono::DateTime<chrono::Utc>>,
    pub resolution_action: Option<String>,
}

// =============================================================================
// Handler: Promote Member to Admin
// =============================================================================

/// Promote a member to admin status
///
/// Authorization: Caller must be an admin in the conversation
/// Server updates DB but does NOT distribute admin roster (done via MLS)
pub async fn promote_admin(
    State(pool): State<PgPool>,
    auth_user: AuthUser,
    Json(input): Json<PromoteAdminInput>,
) -> Result<Json<PromoteAdminOutput>, StatusCode> {
    let caller_did = &auth_user.did;

    info!(
        convo_id = %input.convo_id,
        caller = %caller_did,
        target = %input.member_did,
        "Admin promoting member"
    );

    // 1. Verify caller is an admin
    verify_is_admin(&pool, &input.convo_id, caller_did).await?;

    // 2. Verify target is an active member
    let is_member = sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM members
            WHERE convo_id = $1 AND member_did = $2 AND left_at IS NULL
        )
        "#,
    )
    .bind(&input.convo_id)
    .bind(&input.member_did)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("Database error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if !is_member {
        return Err(StatusCode::FORBIDDEN);
    }

    // 3. Promote member to admin
    sqlx::query(
        r#"
        UPDATE members
        SET is_admin = true,
            promoted_at = NOW(),
            promoted_by_did = $1
        WHERE convo_id = $2 AND member_did = $3
        "#,
    )
    .bind(caller_did)
    .bind(&input.convo_id)
    .bind(&input.member_did)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("Database error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // 4. Fetch updated member view
    let member = sqlx::query_as::<_, MemberView>(
        r#"
        SELECT
            member_did as did,
            joined_at,
            is_admin,
            promoted_at,
            promoted_by_did as promoted_by,
            leaf_index
        FROM members
        WHERE convo_id = $1 AND member_did = $2
        "#,
    )
    .bind(&input.convo_id)
    .bind(&input.member_did)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("Database error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(PromoteAdminOutput {
        success: true,
        member,
    }))
}

// =============================================================================
// Handler: Demote Admin to Member
// =============================================================================

/// Demote an admin to regular member status
///
/// Authorization: Caller must be an admin in the conversation
/// Note: Cannot demote the conversation creator
pub async fn demote_admin(
    State(pool): State<PgPool>,
    auth_user: AuthUser,
    Json(input): Json<DemoteAdminInput>,
) -> Result<Json<DemoteAdminOutput>, StatusCode> {
    let caller_did = &auth_user.did;

    info!(
        convo_id = %input.convo_id,
        caller = %caller_did,
        target = %input.admin_did,
        "Admin demoting member"
    );

    // 1. Verify caller is an admin
    verify_is_admin(&pool, &input.convo_id, caller_did).await?;

    // 2. Verify target is not the creator (creator cannot be demoted)
    let creator_did = sqlx::query_scalar::<_, String>(
        "SELECT creator_did FROM conversations WHERE id = $1"
    )
    .bind(&input.convo_id)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("Database error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if input.admin_did == creator_did {
        error!("Cannot demote conversation creator");
        return Err(StatusCode::BAD_REQUEST);
    }

    // 3. Demote admin to member
    sqlx::query(
        r#"
        UPDATE members
        SET is_admin = false,
            promoted_at = NULL,
            promoted_by_did = NULL
        WHERE convo_id = $1 AND member_did = $2
        "#,
    )
    .bind(&input.convo_id)
    .bind(&input.admin_did)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("Database error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // 4. Fetch updated member view
    let member = sqlx::query_as::<_, MemberView>(
        r#"
        SELECT
            member_did as did,
            joined_at,
            is_admin,
            promoted_at,
            promoted_by_did as promoted_by,
            leaf_index
        FROM members
        WHERE convo_id = $1 AND member_did = $2
        "#,
    )
    .bind(&input.convo_id)
    .bind(&input.admin_did)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("Database error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(DemoteAdminOutput {
        success: true,
        member,
    }))
}

// =============================================================================
// Handler: Remove Member from Conversation
// =============================================================================

/// Remove a member from the conversation (admin action)
///
/// Authorization: Caller must be an admin
/// Note: Cannot remove the creator, cannot remove self
pub async fn remove_member(
    State(pool): State<PgPool>,
    auth_user: AuthUser,
    Json(input): Json<RemoveMemberInput>,
) -> Result<Json<RemoveMemberOutput>, StatusCode> {
    let caller_did = &auth_user.did;

    info!(
        convo_id = %input.convo_id,
        caller = %caller_did,
        target = %input.member_did,
        "Admin removing member"
    );

    // 1. Verify caller is an admin
    verify_is_admin(&pool, &input.convo_id, caller_did).await?;

    // 2. Verify not removing self
    if caller_did == &input.member_did {
        error!("Cannot remove yourself (use leaveConvo instead)");
        return Err(StatusCode::BAD_REQUEST);
    }

    // 3. Verify target is not the creator
    let creator_did = sqlx::query_scalar::<_, String>(
        "SELECT creator_did FROM conversations WHERE id = $1"
    )
    .bind(&input.convo_id)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("Database error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if input.member_did == creator_did {
        error!("Cannot remove conversation creator");
        return Err(StatusCode::BAD_REQUEST);
    }

    // 4. Mark member as left
    sqlx::query(
        r#"
        UPDATE members
        SET left_at = NOW()
        WHERE convo_id = $1 AND member_did = $2
        "#,
    )
    .bind(&input.convo_id)
    .bind(&input.member_did)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("Database error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // 5. Increment epoch (MLS group state changed)
    let new_epoch = sqlx::query_scalar::<_, i64>(
        r#"
        UPDATE conversations
        SET current_epoch = current_epoch + 1,
            updated_at = NOW()
        WHERE id = $1
        RETURNING current_epoch
        "#,
    )
    .bind(&input.convo_id)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("Database error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // 6. Store Commit message
    let commit_id = generate_id();
    sqlx::query(
        r#"
        INSERT INTO messages (
            id, convo_id, sender_did, message_type,
            epoch, seq, ciphertext, created_at
        )
        VALUES ($1, $2, $3, 'commit', $4, 0, $5, NOW())
        "#,
    )
    .bind(&commit_id)
    .bind(&input.convo_id)
    .bind(caller_did)
    .bind(new_epoch)
    .bind(&input.commit)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("Database error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(RemoveMemberOutput {
        success: true,
        new_epoch,
    }))
}

// =============================================================================
// Handler: Report Member (E2EE)
// =============================================================================

/// Report a member to conversation admins
/// Report content is E2EE - encrypted with MLS group key, only admins decrypt
///
/// Authorization: Caller must be a member
pub async fn report_member(
    State(pool): State<PgPool>,
    auth_user: AuthUser,
    Json(input): Json<ReportMemberInput>,
) -> Result<Json<ReportMemberOutput>, StatusCode> {
    let reporter_did = &auth_user.did;

    info!(
        convo_id = %input.convo_id,
        reporter = %reporter_did,
        reported = %input.reported_did,
        "Member submitting E2EE report"
    );

    // 1. Verify reporter is a member
    verify_is_member(&pool, &input.convo_id, reporter_did).await?;

    // 2. Verify reported user is a member
    verify_is_member(&pool, &input.convo_id, &input.reported_did).await?;

    // 3. Create report
    let report_id = generate_id();

    sqlx::query(
        r#"
        INSERT INTO reports (
            id, convo_id, reporter_did, reported_did,
            encrypted_content, created_at, status
        )
        VALUES ($1, $2, $3, $4, $5, NOW(), 'pending')
        "#,
    )
    .bind(&report_id)
    .bind(&input.convo_id)
    .bind(reporter_did)
    .bind(&input.reported_did)
    .bind(&input.encrypted_content)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("Database error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(ReportMemberOutput {
        report_id,
        success: true,
    }))
}

// =============================================================================
// Handler: Get Reports (Admin Only)
// =============================================================================

/// Get reports for a conversation (admin only)
/// Reports contain encrypted content - admins decrypt client-side
///
/// Authorization: Caller must be an admin
pub async fn get_reports(
    State(pool): State<PgPool>,
    auth_user: AuthUser,
    Json(input): Json<GetReportsInput>,
) -> Result<Json<GetReportsOutput>, StatusCode> {
    let caller_did = &auth_user.did;

    // 1. Verify caller is an admin
    verify_is_admin(&pool, &input.convo_id, caller_did).await?;

    // 2. Fetch reports (optionally filtered by status)
    let reports = if let Some(status) = &input.status {
        sqlx::query_as::<_, ReportView>(
            r#"
            SELECT *
            FROM reports
            WHERE convo_id = $1 AND status = $2
            ORDER BY created_at DESC
            "#,
        )
        .bind(&input.convo_id)
        .bind(status)
        .fetch_all(&pool)
        .await
        .map_err(|e| {
            error!("Database error: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
    } else {
        sqlx::query_as::<_, ReportView>(
            r#"
            SELECT *
            FROM reports
            WHERE convo_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(&input.convo_id)
        .fetch_all(&pool)
        .await
        .map_err(|e| {
            error!("Database error: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
    };

    Ok(Json(GetReportsOutput { reports }))
}

// =============================================================================
// Handler: Resolve Report (Admin Only)
// =============================================================================

/// Resolve a report (mark as resolved or dismissed)
///
/// Authorization: Caller must be an admin
pub async fn resolve_report(
    State(pool): State<PgPool>,
    auth_user: AuthUser,
    Json(input): Json<ResolveReportInput>,
) -> Result<Json<ResolveReportOutput>, StatusCode> {
    let caller_did = &auth_user.did;

    info!(
        report_id = %input.report_id,
        resolver = %caller_did,
        action = %input.action,
        "Admin resolving report"
    );

    // 1. Get convo_id from report
    let convo_id = sqlx::query_scalar::<_, String>(
        "SELECT convo_id FROM reports WHERE id = $1"
    )
    .bind(&input.report_id)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("Database error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // 2. Verify caller is an admin
    verify_is_admin(&pool, &convo_id, caller_did).await?;

    // 3. Update report status
    sqlx::query(
        r#"
        UPDATE reports
        SET status = 'resolved',
            resolved_by_did = $1,
            resolved_at = NOW(),
            resolution_action = $2
        WHERE id = $3
        "#,
    )
    .bind(caller_did)
    .bind(&input.action)
    .bind(&input.report_id)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("Database error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(ResolveReportOutput { success: true }))
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Verify user is an admin in the conversation
pub async fn verify_is_admin(
    pool: &PgPool,
    convo_id: &str,
    did: &str,
) -> Result<(), StatusCode> {
    let is_admin = sqlx::query_scalar::<_, bool>(
        r#"
        SELECT is_admin
        FROM members
        WHERE convo_id = $1 AND member_did = $2 AND left_at IS NULL
        "#,
    )
    .bind(convo_id)
    .bind(did)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        error!("Database error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .unwrap_or(false);

    if !is_admin {
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(())
}

/// Verify user is a member in the conversation
async fn verify_is_member(
    pool: &PgPool,
    convo_id: &str,
    did: &str,
) -> Result<(), StatusCode> {
    let is_member = sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM members
            WHERE convo_id = $1 AND member_did = $2 AND left_at IS NULL
        )
        "#,
    )
    .bind(convo_id)
    .bind(did)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        error!("Database error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if !is_member {
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(())
}

/// Generate a unique ID (placeholder - use proper ID generation)
fn generate_id() -> String {
    use uuid::Uuid;
    Uuid::new_v4().to_string()
}
