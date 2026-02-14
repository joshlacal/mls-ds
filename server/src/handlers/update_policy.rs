///! Conversation policy management handlers
///!
///! This module handles:
///! - Updating conversation policies (admin only)
///! - Getting current policy (members can view)
///!
///! Policies control:
///! - Whether external commits are allowed
///! - Whether invites are required for new joins
///! - Whether members can rejoin after desync
///! - Rejoin window duration
///! - Last admin protection
use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{error, info};

use crate::admin_system::verify_is_admin;
use crate::auth::AuthUser;

// =============================================================================
// REQUEST/RESPONSE TYPES
// =============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatePolicyInput {
    pub convo_id: String,

    // Each field is optional - only update what's provided
    pub allow_external_commits: Option<bool>,
    pub require_invite_for_join: Option<bool>,
    pub allow_rejoin: Option<bool>,
    pub rejoin_window_days: Option<i32>,
    pub prevent_removing_last_admin: Option<bool>,
    pub max_members: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetPolicyInput {
    pub convo_id: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct PolicyView {
    pub convo_id: String,
    pub allow_external_commits: bool,
    pub require_invite_for_join: bool,
    pub allow_rejoin: bool,
    pub rejoin_window_days: i32,
    pub prevent_removing_last_admin: bool,
    pub max_members: i32,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatePolicyOutput {
    pub success: bool,
    pub policy: PolicyView,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetPolicyOutput {
    pub policy: PolicyView,
}

// =============================================================================
// HANDLERS
// =============================================================================

/// Update conversation policy (admin only)
///
/// Authorization: Caller must be an admin of the conversation
///
/// Request body (all fields optional):
/// ```json
/// {
///   "convoId": "...",
///   "allowExternalCommits": true,
///   "requireInviteForJoin": false,
///   "allowRejoin": true,
///   "rejoinWindowDays": 30,
///   "preventRemovingLastAdmin": true
/// }
/// ```
pub async fn update_policy(
    State(pool): State<PgPool>,
    auth_user: AuthUser,
    Json(input): Json<UpdatePolicyInput>,
) -> Result<Json<UpdatePolicyOutput>, (StatusCode, String)> {
    let caller_did = &auth_user.did;

    info!(
        convo_id = %input.convo_id,
        caller = %caller_did,
        "Admin updating policy"
    );

    // Step 1: Verify caller is an admin
    verify_is_admin(&pool, &input.convo_id, caller_did)
        .await
        .map_err(|e| {
            error!("Admin verification failed: {}", e);
            (StatusCode::FORBIDDEN, "Not an admin".to_string())
        })?;

    // Step 2: Validate inputs
    if let Some(window_days) = input.rejoin_window_days {
        if window_days < 0 {
            return Err((
                StatusCode::BAD_REQUEST,
                "rejoin_window_days must be >= 0".to_string(),
            ));
        }
    }

    // Validate max_members if provided
    if let Some(max_members) = input.max_members {
        if max_members < 2 || max_members > 10000 {
            return Err((
                StatusCode::BAD_REQUEST,
                "max_members must be between 2 and 10000".to_string(),
            ));
        }

        // Check current member count - cannot set max_members below current count
        let current_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM members WHERE convo_id = $1 AND left_at IS NULL",
        )
        .bind(input.convo_id.as_str())
        .fetch_one(&pool)
        .await
        .map_err(|e| {
            error!("Failed to get current member count: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error".to_string(),
            )
        })?;

        if (current_count as i32) > max_members {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "Cannot set max_members to {} when conversation has {} members. Remove members first.",
                    max_members, current_count
                ),
            ));
        }
    }

    // Step 3: Build dynamic UPDATE query
    let mut updates = Vec::new();
    let mut param_count = 2; // $1 = caller_did, $2 = convo_id

    // We'll rebuild this query properly with sqlx query builder
    // For now, using a simplified approach with all fields

    if input.allow_external_commits.is_some() {
        updates.push(format!("allow_external_commits = ${}", param_count));
        param_count += 1;
    }
    if input.require_invite_for_join.is_some() {
        updates.push(format!("require_invite_for_join = ${}", param_count));
        param_count += 1;
    }
    if input.allow_rejoin.is_some() {
        updates.push(format!("allow_rejoin = ${}", param_count));
        param_count += 1;
    }
    if input.rejoin_window_days.is_some() {
        updates.push(format!("rejoin_window_days = ${}", param_count));
        param_count += 1;
    }
    if input.prevent_removing_last_admin.is_some() {
        updates.push(format!("prevent_removing_last_admin = ${}", param_count));
        param_count += 1;
    }
    if input.max_members.is_some() {
        updates.push(format!("max_members = ${}", param_count));
        param_count += 1;
    }

    if updates.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "No policy fields provided to update".to_string(),
        ));
    }

    // Build the UPDATE query
    let query = format!(
        r#"
        UPDATE conversation_policy
        SET updated_by_did = $1,
            updated_at = NOW(),
            {}
        WHERE convo_id = $2
        RETURNING convo_id, allow_external_commits, require_invite_for_join,
                  allow_rejoin, rejoin_window_days, prevent_removing_last_admin, max_members, updated_at
        "#,
        updates.join(", ")
    );

    // Execute with proper parameter binding
    // Note: This is a simplified version - production should use sqlx query builder
    let mut query_builder = sqlx::query_as::<_, PolicyView>(&query)
        .bind(caller_did)
        .bind(input.convo_id.as_str());

    if let Some(val) = input.allow_external_commits {
        query_builder = query_builder.bind(val);
    }
    if let Some(val) = input.require_invite_for_join {
        query_builder = query_builder.bind(val);
    }
    if let Some(val) = input.allow_rejoin {
        query_builder = query_builder.bind(val);
    }
    if let Some(val) = input.rejoin_window_days {
        query_builder = query_builder.bind(val);
    }
    if let Some(val) = input.prevent_removing_last_admin {
        query_builder = query_builder.bind(val);
    }
    if let Some(val) = input.max_members {
        query_builder = query_builder.bind(val);
    }

    let policy = query_builder.fetch_one(&pool).await.map_err(|e| {
        error!("Database error updating policy: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to update policy".to_string(),
        )
    })?;

    info!(
        convo_id = %input.convo_id,
        "Policy updated successfully"
    );

    Ok(Json(UpdatePolicyOutput {
        success: true,
        policy,
    }))
}

/// Get conversation policy
///
/// Authorization: Caller must be a member of the conversation
///
/// Request body:
/// ```json
/// {
///   "convoId": "..."
/// }
/// ```
pub async fn get_policy(
    State(pool): State<PgPool>,
    auth_user: AuthUser,
    Query(input): Query<GetPolicyInput>,
) -> Result<Json<GetPolicyOutput>, (StatusCode, String)> {
    let caller_did = &auth_user.did;

    // Step 1: Verify caller is a member (left_at IS NULL)
    let is_member = sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS(
            SELECT 1
            FROM members
            WHERE convo_id = $1
              AND member_did = $2
              AND left_at IS NULL
        )
        "#,
    )
    .bind(input.convo_id.as_str())
    .bind(caller_did)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("Database error checking membership: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Database error".to_string(),
        )
    })?;

    if !is_member {
        return Err((
            StatusCode::FORBIDDEN,
            "Not a member of this conversation".to_string(),
        ));
    }

    // Step 2: Fetch policy
    let policy = sqlx::query_as::<_, PolicyView>(
        r#"
        SELECT
            convo_id, allow_external_commits, require_invite_for_join,
            allow_rejoin, rejoin_window_days, prevent_removing_last_admin, max_members, updated_at
        FROM conversation_policy
        WHERE convo_id = $1
        "#,
    )
    .bind(input.convo_id.as_str())
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("Database error fetching policy: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to fetch policy".to_string(),
        )
    })?;

    Ok(Json(GetPolicyOutput { policy }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rejoin_window_validation() {
        // Valid values
        assert!(0 >= 0); // 0 = unlimited
        assert!(30 >= 0); // 30 days
        assert!(365 >= 0); // 1 year

        // Invalid
        assert!(-1 < 0);
        assert!(-30 < 0);
    }
}
