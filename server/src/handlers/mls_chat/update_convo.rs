use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use base64::Engine;
use jacquard_axum::ExtractXrpc;
use openmls::messages::group_info::VerifiableGroupInfo;
use openmls::prelude::MlsMessageIn;
use std::sync::Arc;
use tls_codec::Deserialize as TlsDeserialize;
use tracing::{error, info, warn};

use crate::{
    auth::{verify_is_admin, verify_is_member, count_admins, AuthUser},
    device_utils::parse_device_did,
    generated::blue_catbird::mlsChat::update_convo::{UpdateConvo, UpdateConvoRequest},
    group_info::{get_group_info, store_group_info, MAX_GROUP_INFO_SIZE, MIN_GROUP_INFO_SIZE},
    realtime::{SseState, StreamEvent},
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.updateConvo";

/// Consolidated conversation update handler (POST)
/// POST /xrpc/blue.catbird.mlsChat.updateConvo
///
/// Consolidates: updatePolicy, promoteAdmin, demoteAdmin, promoteModerator,
/// demoteModerator, updateGroupInfo, groupInfoRefresh
#[tracing::instrument(skip(pool, sse_state, auth_user, input))]
pub async fn update_convo(
    State(pool): State<DbPool>,
    State(sse_state): State<Arc<SseState>>,
    auth_user: AuthUser,
    ExtractXrpc(input): ExtractXrpc<UpdateConvoRequest>,
) -> Response {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let convo_id = input.convo_id.to_string();
    let caller_did = &auth_user.did;

    match input.action.as_ref() {
        "promoteAdmin" => handle_promote_admin(&pool, caller_did, &convo_id, &input).await,
        "demoteAdmin" => handle_demote_admin(&pool, caller_did, &convo_id, &input).await,
        "promoteModerator" => handle_promote_moderator(&pool, caller_did, &convo_id, &input).await,
        "demoteModerator" => handle_demote_moderator(&pool, caller_did, &convo_id, &input).await,
        "updatePolicy" => handle_update_policy(&pool, caller_did, &convo_id, &input).await,
        "updateGroupInfo" => handle_update_group_info(&pool, caller_did, &convo_id, &input).await,
        "refreshGroupInfo" => {
            handle_refresh_group_info(&pool, &sse_state, caller_did, &convo_id).await
        }
        other => {
            warn!("v2.updateConvo: unknown action '{}'", other);
            StatusCode::BAD_REQUEST.into_response()
        }
    }
}

async fn handle_promote_admin(
    pool: &DbPool,
    caller_did: &str,
    convo_id: &str,
    input: &UpdateConvo<'_>,
) -> Response {
    let target_did = match input.target_did.as_ref() {
        Some(did) => did.to_string(),
        None => return StatusCode::BAD_REQUEST.into_response(),
    };

    info!(
        "v2.updateConvo: promoteAdmin {} in {}",
        crate::crypto::redact_for_log(&target_did),
        crate::crypto::redact_for_log(convo_id)
    );

    // Verify caller is admin
    if let Err(s) = verify_is_admin(pool, convo_id, caller_did).await {
        return s.into_response();
    }
    // Verify target is a member
    if let Err(s) = verify_is_member(pool, convo_id, &target_did).await {
        return s.into_response();
    }

    // Check if already admin
    let already_admin: Option<bool> = sqlx::query_scalar(
        "SELECT is_admin FROM members WHERE convo_id = $1 AND user_did = $2 AND left_at IS NULL LIMIT 1",
    )
    .bind(convo_id)
    .bind(&target_did)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    if already_admin == Some(true) {
        return (StatusCode::CONFLICT, "Already an admin").into_response();
    }

    let now = chrono::Utc::now();

    // Promote
    sqlx::query(
        "UPDATE members SET is_admin = true, promoted_at = $3, promoted_by_did = $4 WHERE convo_id = $1 AND user_did = $2 AND left_at IS NULL",
    )
    .bind(convo_id)
    .bind(&target_did)
    .bind(now)
    .bind(caller_did)
    .execute(pool)
    .await
    .map_err(|e| {
        error!("Failed to promote admin: {}", e);
    })
    .ok();

    // Audit log
    let action_id = uuid::Uuid::new_v4().to_string();
    let _ = sqlx::query(
        "INSERT INTO admin_actions (id, convo_id, actor_did, action, target_did, created_at) VALUES ($1, $2, $3, 'promote', $4, $5)",
    )
    .bind(&action_id)
    .bind(convo_id)
    .bind(caller_did)
    .bind(&target_did)
    .bind(now)
    .execute(pool)
    .await;

    Json(serde_json::json!({
        "action": "promoteAdmin",
        "ok": true,
        "promotedAt": now.to_rfc3339(),
    }))
    .into_response()
}

async fn handle_demote_admin(
    pool: &DbPool,
    caller_did: &str,
    convo_id: &str,
    input: &UpdateConvo<'_>,
) -> Response {
    let target_did = match input.target_did.as_ref() {
        Some(did) => did.to_string(),
        None => return StatusCode::BAD_REQUEST.into_response(),
    };

    info!(
        "v2.updateConvo: demoteAdmin {} in {}",
        crate::crypto::redact_for_log(&target_did),
        crate::crypto::redact_for_log(convo_id)
    );

    let is_self = caller_did == target_did;
    if is_self {
        if let Err(s) = verify_is_member(pool, convo_id, caller_did).await {
            return s.into_response();
        }
    } else if let Err(s) = verify_is_admin(pool, convo_id, caller_did).await {
        return s.into_response();
    }
    if let Err(s) = verify_is_member(pool, convo_id, &target_did).await {
        return s.into_response();
    }

    // Check target is actually admin
    let is_admin: Option<bool> = sqlx::query_scalar(
        "SELECT is_admin FROM members WHERE convo_id = $1 AND user_did = $2 AND left_at IS NULL LIMIT 1",
    )
    .bind(convo_id)
    .bind(&target_did)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    if is_admin != Some(true) {
        return (StatusCode::BAD_REQUEST, "Not an admin").into_response();
    }

    // Prevent demoting last admin
    let admin_count = match count_admins(pool, convo_id).await {
        Ok(c) => c,
        Err(s) => return s.into_response(),
    };
    if admin_count <= 1 {
        return (StatusCode::CONFLICT, "Cannot demote the last admin").into_response();
    }

    let now = chrono::Utc::now();

    sqlx::query(
        "UPDATE members SET is_admin = false WHERE convo_id = $1 AND user_did = $2 AND left_at IS NULL",
    )
    .bind(convo_id)
    .bind(&target_did)
    .execute(pool)
    .await
    .map_err(|e| {
        error!("Failed to demote admin: {}", e);
    })
    .ok();

    let action_id = uuid::Uuid::new_v4().to_string();
    let _ = sqlx::query(
        "INSERT INTO admin_actions (id, convo_id, actor_did, action, target_did, created_at) VALUES ($1, $2, $3, 'demote', $4, $5)",
    )
    .bind(&action_id)
    .bind(convo_id)
    .bind(caller_did)
    .bind(&target_did)
    .bind(now)
    .execute(pool)
    .await;

    Json(serde_json::json!({
        "action": "demoteAdmin",
        "ok": true,
    }))
    .into_response()
}

async fn handle_promote_moderator(
    pool: &DbPool,
    caller_did: &str,
    convo_id: &str,
    input: &UpdateConvo<'_>,
) -> Response {
    let target_did = match input.target_did.as_ref() {
        Some(did) => did.to_string(),
        None => return StatusCode::BAD_REQUEST.into_response(),
    };

    info!(
        "v2.updateConvo: promoteModerator {} in {}",
        crate::crypto::redact_for_log(&target_did),
        crate::crypto::redact_for_log(convo_id)
    );

    if let Err(s) = verify_is_admin(pool, convo_id, caller_did).await {
        return s.into_response();
    }
    if let Err(s) = verify_is_member(pool, convo_id, &target_did).await {
        return s.into_response();
    }

    // Check if already admin (admins don't need moderator)
    let is_admin: Option<bool> = sqlx::query_scalar(
        "SELECT COALESCE(is_admin, false) FROM members WHERE convo_id = $1 AND user_did = $2 AND left_at IS NULL LIMIT 1",
    )
    .bind(convo_id)
    .bind(&target_did)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    if is_admin == Some(true) {
        return (StatusCode::CONFLICT, "Target is already an admin").into_response();
    }

    // Check if already moderator
    let is_mod: Option<bool> = sqlx::query_scalar(
        "SELECT COALESCE(is_moderator, false) FROM members WHERE convo_id = $1 AND user_did = $2 AND left_at IS NULL LIMIT 1",
    )
    .bind(convo_id)
    .bind(&target_did)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    if is_mod == Some(true) {
        return (StatusCode::CONFLICT, "Already a moderator").into_response();
    }

    let now = chrono::Utc::now();

    sqlx::query(
        "UPDATE members SET is_moderator = true, moderator_promoted_at = $3, moderator_promoted_by_did = $4 WHERE convo_id = $1 AND user_did = $2 AND left_at IS NULL",
    )
    .bind(convo_id)
    .bind(&target_did)
    .bind(now)
    .bind(caller_did)
    .execute(pool)
    .await
    .map_err(|e| {
        error!("Failed to promote moderator: {}", e);
    })
    .ok();

    let action_id = uuid::Uuid::new_v4().to_string();
    let _ = sqlx::query(
        "INSERT INTO admin_actions (id, convo_id, actor_did, action, target_did, created_at) VALUES ($1, $2, $3, 'promote_moderator', $4, $5)",
    )
    .bind(&action_id)
    .bind(convo_id)
    .bind(caller_did)
    .bind(&target_did)
    .bind(now)
    .execute(pool)
    .await;

    Json(serde_json::json!({
        "action": "promoteModerator",
        "ok": true,
        "promotedAt": now.to_rfc3339(),
    }))
    .into_response()
}

async fn handle_demote_moderator(
    pool: &DbPool,
    caller_did: &str,
    convo_id: &str,
    input: &UpdateConvo<'_>,
) -> Response {
    let target_did = match input.target_did.as_ref() {
        Some(did) => did.to_string(),
        None => return StatusCode::BAD_REQUEST.into_response(),
    };

    info!(
        "v2.updateConvo: demoteModerator {} in {}",
        crate::crypto::redact_for_log(&target_did),
        crate::crypto::redact_for_log(convo_id)
    );

    let is_self = caller_did == target_did;
    if is_self {
        if let Err(s) = verify_is_member(pool, convo_id, caller_did).await {
            return s.into_response();
        }
    } else if let Err(s) = verify_is_admin(pool, convo_id, caller_did).await {
        return s.into_response();
    }
    if let Err(s) = verify_is_member(pool, convo_id, &target_did).await {
        return s.into_response();
    }

    // Check if actually a moderator
    let is_mod: Option<bool> = sqlx::query_scalar(
        "SELECT COALESCE(is_moderator, false) FROM members WHERE convo_id = $1 AND user_did = $2 AND left_at IS NULL LIMIT 1",
    )
    .bind(convo_id)
    .bind(&target_did)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    if is_mod != Some(true) {
        return (StatusCode::BAD_REQUEST, "Not a moderator").into_response();
    }

    let now = chrono::Utc::now();

    sqlx::query(
        "UPDATE members SET is_moderator = false, moderator_promoted_at = NULL, moderator_promoted_by_did = NULL WHERE convo_id = $1 AND user_did = $2 AND left_at IS NULL",
    )
    .bind(convo_id)
    .bind(&target_did)
    .execute(pool)
    .await
    .map_err(|e| {
        error!("Failed to demote moderator: {}", e);
    })
    .ok();

    let action_id = uuid::Uuid::new_v4().to_string();
    let _ = sqlx::query(
        "INSERT INTO admin_actions (id, convo_id, actor_did, action, target_did, created_at) VALUES ($1, $2, $3, 'demote_moderator', $4, $5)",
    )
    .bind(&action_id)
    .bind(convo_id)
    .bind(caller_did)
    .bind(&target_did)
    .bind(now)
    .execute(pool)
    .await;

    Json(serde_json::json!({
        "action": "demoteModerator",
        "ok": true,
    }))
    .into_response()
}

async fn handle_update_policy(
    pool: &DbPool,
    caller_did: &str,
    convo_id: &str,
    input: &UpdateConvo<'_>,
) -> Response {
    info!(
        "v2.updateConvo: updatePolicy for {}",
        crate::crypto::redact_for_log(convo_id)
    );

    // Must be admin
    if let Err(s) = verify_is_admin(pool, convo_id, caller_did).await {
        return s.into_response();
    }

    let policy_json = input
        .policy
        .as_ref()
        .map(|p| serde_json::to_value(p).unwrap_or_default())
        .unwrap_or_default();

    let allow_external_commits = policy_json.get("allowExternalCommits").and_then(|v| v.as_bool());
    let require_invite_for_join = policy_json.get("requireInviteForJoin").and_then(|v| v.as_bool());
    let allow_rejoin = policy_json.get("allowRejoin").and_then(|v| v.as_bool());
    let rejoin_window_days = policy_json
        .get("rejoinWindowDays")
        .and_then(|v| v.as_i64())
        .map(|v| v as i32);
    let prevent_removing_last_admin = policy_json
        .get("preventRemovingLastAdmin")
        .and_then(|v| v.as_bool());
    let max_members = policy_json
        .get("maxMembers")
        .and_then(|v| v.as_i64())
        .map(|v| v as i32);

    // Build dynamic UPDATE query
    let mut updates = Vec::new();
    let mut param_count = 3; // $1 = caller_did, $2 = convo_id, start dynamic at $3

    if allow_external_commits.is_some() {
        updates.push(format!("allow_external_commits = ${}", param_count));
        param_count += 1;
    }
    if require_invite_for_join.is_some() {
        updates.push(format!("require_invite_for_join = ${}", param_count));
        param_count += 1;
    }
    if allow_rejoin.is_some() {
        updates.push(format!("allow_rejoin = ${}", param_count));
        param_count += 1;
    }
    if rejoin_window_days.is_some() {
        updates.push(format!("rejoin_window_days = ${}", param_count));
        param_count += 1;
    }
    if prevent_removing_last_admin.is_some() {
        updates.push(format!("prevent_removing_last_admin = ${}", param_count));
        param_count += 1;
    }
    if max_members.is_some() {
        updates.push(format!("max_members = ${}", param_count));
        // param_count += 1; // not needed after last
    }

    if updates.is_empty() {
        return (StatusCode::BAD_REQUEST, "No policy fields to update").into_response();
    }

    let query_str = format!(
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

    let mut query_builder = sqlx::query(&query_str).bind(caller_did).bind(convo_id);

    if let Some(val) = allow_external_commits {
        query_builder = query_builder.bind(val);
    }
    if let Some(val) = require_invite_for_join {
        query_builder = query_builder.bind(val);
    }
    if let Some(val) = allow_rejoin {
        query_builder = query_builder.bind(val);
    }
    if let Some(val) = rejoin_window_days {
        query_builder = query_builder.bind(val);
    }
    if let Some(val) = prevent_removing_last_admin {
        query_builder = query_builder.bind(val);
    }
    if let Some(val) = max_members {
        query_builder = query_builder.bind(val);
    }

    let row = match query_builder.fetch_one(pool).await {
        Ok(row) => row,
        Err(e) => {
            error!("Failed to update policy: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    use sqlx::Row;
    Json(serde_json::json!({
        "action": "updatePolicy",
        "success": true,
        "policy": {
            "convoId": row.get::<String, _>("convo_id"),
            "allowExternalCommits": row.get::<bool, _>("allow_external_commits"),
            "requireInviteForJoin": row.get::<bool, _>("require_invite_for_join"),
            "allowRejoin": row.get::<bool, _>("allow_rejoin"),
            "rejoinWindowDays": row.get::<i32, _>("rejoin_window_days"),
            "preventRemovingLastAdmin": row.get::<bool, _>("prevent_removing_last_admin"),
            "maxMembers": row.get::<i32, _>("max_members"),
            "updatedAt": row.get::<chrono::DateTime<chrono::Utc>, _>("updated_at").to_rfc3339(),
        }
    }))
    .into_response()
}

async fn handle_update_group_info(
    pool: &DbPool,
    caller_did: &str,
    convo_id: &str,
    input: &UpdateConvo<'_>,
) -> Response {
    info!(
        "v2.updateConvo: updateGroupInfo for {}",
        crate::crypto::redact_for_log(convo_id)
    );

    let group_info_b64 = match input.group_info.as_ref() {
        Some(gi) => gi.to_string(),
        None => return (StatusCode::BAD_REQUEST, "Missing groupInfo").into_response(),
    };
    let epoch = match input.epoch {
        Some(e) => e,
        None => return (StatusCode::BAD_REQUEST, "Missing epoch").into_response(),
    };

    // Must be a member
    if let Err(s) = verify_is_member(pool, convo_id, caller_did).await {
        return s.into_response();
    }

    // Decode base64
    let group_info_bytes = match base64::engine::general_purpose::STANDARD.decode(&group_info_b64) {
        Ok(bytes) => bytes,
        Err(e) => {
            error!(convo_id = %convo_id, error = %e, "Invalid base64 in GroupInfo");
            return (StatusCode::BAD_REQUEST, "Invalid base64 encoding").into_response();
        }
    };

    // Validate size bounds
    if group_info_bytes.len() < MIN_GROUP_INFO_SIZE {
        error!(size = group_info_bytes.len(), "GroupInfo too small");
        return (StatusCode::BAD_REQUEST, "GroupInfo too small").into_response();
    }
    if group_info_bytes.len() > MAX_GROUP_INFO_SIZE {
        error!(size = group_info_bytes.len(), "GroupInfo too large");
        return (StatusCode::BAD_REQUEST, "GroupInfo too large").into_response();
    }

    // Validate MLS structure
    let valid = MlsMessageIn::tls_deserialize(&mut group_info_bytes.as_slice()).is_ok()
        || VerifiableGroupInfo::tls_deserialize(&mut group_info_bytes.as_slice()).is_ok();

    if !valid {
        error!(convo_id = %convo_id, "Invalid MLS GroupInfo structure");
        return (StatusCode::BAD_REQUEST, "Invalid MLS GroupInfo structure").into_response();
    }

    // Epoch check: must strictly increase
    if let Ok(Some((_, existing_epoch, _))) = get_group_info(pool, convo_id).await {
        if epoch as i32 <= existing_epoch {
            warn!(
                convo_id = %convo_id,
                new_epoch = epoch,
                existing_epoch = existing_epoch,
                "Rejecting GroupInfo with non-increasing epoch"
            );
            return (StatusCode::CONFLICT, "Epoch must be greater than current epoch")
                .into_response();
        }
    }

    // Store
    if let Err(e) = store_group_info(pool, convo_id, &group_info_bytes, epoch as i32).await {
        error!(convo_id = %convo_id, error = %e, "Failed to store GroupInfo");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    Json(serde_json::json!({
        "action": "updateGroupInfo",
        "updated": true,
    }))
    .into_response()
}

async fn handle_refresh_group_info(
    pool: &DbPool,
    sse_state: &Arc<SseState>,
    caller_did: &str,
    convo_id: &str,
) -> Response {
    info!(
        "v2.updateConvo: refreshGroupInfo for {}",
        crate::crypto::redact_for_log(convo_id)
    );

    let (user_did, _) = match parse_device_did(caller_did) {
        Ok(r) => r,
        Err(e) => {
            error!("Invalid device DID format: {}", e);
            return StatusCode::BAD_REQUEST.into_response();
        }
    };

    // Check conversation exists
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM conversations WHERE id = $1)")
            .bind(convo_id)
            .fetch_one(pool)
            .await
            .unwrap_or(false);

    if !exists {
        return StatusCode::NOT_FOUND.into_response();
    }

    // Check requester is/was a member (allows former members needing rejoin)
    let is_member: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM members WHERE convo_id = $1 AND user_did = $2)",
    )
    .bind(convo_id)
    .bind(&user_did)
    .fetch_one(pool)
    .await
    .unwrap_or(false);

    if !is_member {
        return StatusCode::FORBIDDEN.into_response();
    }

    // Count active members
    let active_members: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(DISTINCT user_did) FROM members
        WHERE convo_id = $1 AND left_at IS NULL AND needs_rejoin = false
        "#,
    )
    .bind(convo_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    if active_members == 0 {
        return Json(serde_json::json!({
            "action": "refreshGroupInfo",
            "requested": false,
            "activeMembers": 0,
        }))
        .into_response();
    }

    // Emit SSE event
    let cursor = sse_state
        .cursor_gen
        .next(convo_id, "groupInfoRefreshRequested")
        .await;
    let event = StreamEvent::GroupInfoRefreshRequested {
        cursor,
        convo_id: convo_id.to_string(),
        requested_by: user_did.clone(),
        requested_at: chrono::Utc::now().to_rfc3339(),
    };

    if let Err(e) = sse_state.emit(convo_id, event).await {
        warn!(error = %e, "Failed to emit GroupInfoRefreshRequested event");
    }

    Json(serde_json::json!({
        "action": "refreshGroupInfo",
        "requested": true,
        "activeMembers": active_members,
    }))
    .into_response()
}
