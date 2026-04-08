use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::{auth::AuthUser, storage::DbPool};

const NSID: &str = "blue.catbird.mlsChat.getGroupHealth";

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetGroupHealthQuery {
    pub convo_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetGroupHealthOutput {
    pub convo_id: String,
    pub reset_count: i32,
    pub circuit_breaker_tripped: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub circuit_breaker_tripped_at: Option<String>,
    pub recovery_failure_count: i64,
    pub member_count: i64,
    pub quorum_reached: bool,
    pub cooldown_active: bool,
    pub admin_intervention_required: bool,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Get health status for a conversation's MLS group.
///
/// GET /xrpc/blue.catbird.mlsChat.getGroupHealth?convoId=xxx
///
/// Any active member may call this endpoint.
#[tracing::instrument(skip(pool, auth_user))]
pub async fn get_group_health(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    axum::extract::Query(params): axum::extract::Query<GetGroupHealthQuery>,
) -> Result<Response, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        error!("[getGroupHealth] Unauthorized");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let convo_id = &params.convo_id;
    let caller_did = &auth_user.did;

    // --- Verify caller is an active member ---
    let is_member: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM members WHERE convo_id = $1 AND (user_did = $2 OR member_did = $2) AND left_at IS NULL)",
    )
    .bind(convo_id)
    .bind(caller_did)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("[getGroupHealth] membership check failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if !is_member {
        warn!("[getGroupHealth] caller is not a member");
        return Err(StatusCode::FORBIDDEN);
    }

    // --- Fetch conversation health data ---
    let row: Option<(
        String,                                // c.id
        i32,                                   // c.reset_count
        Option<chrono::DateTime<chrono::Utc>>, // c.auto_reset_disabled_at
        Option<chrono::DateTime<chrono::Utc>>, // c.last_reset_at
    )> = sqlx::query_as(
        r#"SELECT
            c.id,
            COALESCE(c.reset_count, 0)::INT,
            c.auto_reset_disabled_at,
            c.last_reset_at
        FROM conversations c
        WHERE c.id = $1"#,
    )
    .bind(convo_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!("[getGroupHealth] conversation query failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let (id, reset_count, auto_reset_disabled_at, last_reset_at) = match row {
        Some(r) => r,
        None => {
            warn!("[getGroupHealth] conversation not found");
            return Err(StatusCode::NOT_FOUND);
        }
    };

    // --- Count recent recovery failures ---
    let failure_count: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM recovery_failures
           WHERE convo_id = $1
           AND reported_at > NOW() - INTERVAL '1 hour'"#,
    )
    .bind(convo_id)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("[getGroupHealth] count failures: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // --- Count active members ---
    let member_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM members WHERE convo_id = $1 AND left_at IS NULL")
            .bind(convo_id)
            .fetch_one(&pool)
            .await
            .map_err(|e| {
                error!("[getGroupHealth] count members: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

    // --- Derive boolean fields ---
    let circuit_breaker_tripped = auto_reset_disabled_at.is_some();
    let quorum_reached = member_count > 0 && failure_count * 2 >= member_count;
    let cooldown_active = last_reset_at
        .map(|t| chrono::Utc::now() - t < chrono::Duration::minutes(30))
        .unwrap_or(false);
    let admin_intervention_required = circuit_breaker_tripped;

    let circuit_breaker_tripped_at =
        auto_reset_disabled_at.map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true));

    info!(
        convo = %crate::crypto::redact_for_log(convo_id),
        reset_count,
        circuit_breaker_tripped,
        failure_count,
        member_count,
        "[getGroupHealth] returning health status"
    );

    Ok(Json(GetGroupHealthOutput {
        convo_id: id,
        reset_count,
        circuit_breaker_tripped,
        circuit_breaker_tripped_at,
        recovery_failure_count: failure_count,
        member_count,
        quorum_reached,
        cooldown_active,
        admin_intervention_required,
    })
    .into_response())
}
