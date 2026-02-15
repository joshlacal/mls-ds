use axum::{extract::State, http::StatusCode, Json};
use jacquard_axum::ExtractXrpc;
use tracing::error;

use crate::{
    auth::AuthUser, generated::blue_catbird::mlsChat::get_convo_settings::GetConvoSettingsRequest,
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.getConvoSettings";

/// Get conversation settings/policy.
/// GET /xrpc/blue.catbird.mlsChat.getConvoSettings
#[tracing::instrument(skip(pool, auth_user))]
pub async fn get_convo_settings(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    ExtractXrpc(input): ExtractXrpc<GetConvoSettingsRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let convo_id = input.convo_id.as_ref();
    let caller_did = &auth_user.did;

    // Check membership
    let is_member: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM members
            WHERE convo_id = $1 AND (user_did = $2 OR member_did = $2) AND left_at IS NULL
        )
        "#,
    )
    .bind(convo_id)
    .bind(caller_did)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("Database error checking membership: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if !is_member {
        return Err(StatusCode::FORBIDDEN);
    }

    // Get policy
    let row = sqlx::query(
        r#"
        SELECT
            convo_id,
            allow_external_commits,
            require_invite_for_join,
            allow_rejoin,
            rejoin_window_days,
            prevent_removing_last_admin,
            max_members,
            updated_at
        FROM conversation_policy
        WHERE convo_id = $1
        "#,
    )
    .bind(convo_id)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("Database error fetching policy: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    use sqlx::Row;
    Ok(Json(serde_json::json!({
        "convoId": row.get::<String, _>("convo_id"),
        "policy": {
            "allowExternalCommits": row.get::<bool, _>("allow_external_commits"),
            "requireInviteForJoin": row.get::<bool, _>("require_invite_for_join"),
            "allowRejoin": row.get::<bool, _>("allow_rejoin"),
            "rejoinWindowDays": row.get::<i32, _>("rejoin_window_days"),
            "preventRemovingLastAdmin": row.get::<bool, _>("prevent_removing_last_admin"),
            "maxMembers": row.get::<i32, _>("max_members"),
            "updatedAt": row.get::<chrono::DateTime<chrono::Utc>, _>("updated_at").to_rfc3339(),
        }
    })))
}
