use axum::{Json, extract::State, http::StatusCode};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, warn};
use uuid::Uuid;

use crate::{
    auth::AuthUser,
    device_utils::parse_device_did,
    realtime::{SseState, StreamEvent},
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.reissueWelcome";
const MAX_REISSUE_REQUESTS_PER_HOUR: i64 = 3;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReissueWelcomeRequest {
    pub convo_id: String,
    pub recipient_device_did: String,
    pub reason: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReissueWelcomeOutput {
    pub welcome_requested: bool,
    pub request_id: String,
    pub requested_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inviter_device: Option<String>,
}

fn recipient_belongs_to_auth_user(auth_did: &str, recipient_device_did: &str) -> bool {
    let Ok((auth_owner_did, _)) = parse_device_did(auth_did) else {
        return false;
    };
    parse_device_did(recipient_device_did)
        .map(|(owner_did, _)| owner_did == auth_owner_did)
        .unwrap_or(false)
}

#[tracing::instrument(skip(pool, sse_state, auth_user, input))]
pub async fn reissue_welcome(
    State(pool): State<DbPool>,
    State(sse_state): State<Arc<SseState>>,
    auth_user: AuthUser,
    Json(input): Json<ReissueWelcomeRequest>,
) -> Result<Json<ReissueWelcomeOutput>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    if !recipient_belongs_to_auth_user(&auth_user.did, &input.recipient_device_did) {
        warn!("reissueWelcome: caller tried to request for another recipient device");
        return Err(StatusCode::FORBIDDEN);
    }

    let requester_is_member: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS(
            SELECT 1
            FROM members
            WHERE convo_id = $1
              AND (member_did = $2 OR user_did = $2)
              AND left_at IS NULL
        )
        "#,
    )
    .bind(&input.convo_id)
    .bind(&auth_user.did)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("reissueWelcome: membership check failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    if !requester_is_member {
        return Err(StatusCode::FORBIDDEN);
    }

    let recent_count: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM reissue_requests
        WHERE convo_id = $1
          AND recipient_device_did = $2
          AND requested_at > NOW() - INTERVAL '1 hour'
        "#,
    )
    .bind(&input.convo_id)
    .bind(&input.recipient_device_did)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("reissueWelcome: rate-limit check failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    if recent_count >= MAX_REISSUE_REQUESTS_PER_HOUR {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let inviter_device: Option<String> = sqlx::query_scalar(
        r#"
        SELECT member_did
        FROM members
        WHERE convo_id = $1
          AND left_at IS NULL
          AND COALESCE(is_admin, false) = true
          AND member_did <> $2
        ORDER BY joined_at ASC
        LIMIT 1
        "#,
    )
    .bind(&input.convo_id)
    .bind(&input.recipient_device_did)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!("reissueWelcome: admin lookup failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let Some(inviter_device) = inviter_device else {
        warn!("reissueWelcome: no admin available to reissue Welcome");
        return Err(StatusCode::GONE);
    };

    let request_id = Uuid::new_v4().to_string();
    let requested_at = Utc::now();
    sqlx::query(
        r#"
        INSERT INTO reissue_requests
            (id, convo_id, recipient_device_did, requested_at, attempts, last_attempt_at)
        VALUES ($1, $2, $3, $4, 1, $4)
        "#,
    )
    .bind(&request_id)
    .bind(&input.convo_id)
    .bind(&input.recipient_device_did)
    .bind(requested_at)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("reissueWelcome: insert failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let event = StreamEvent::WelcomeReissueRequestedEvent {
        cursor: sse_state
            .cursor_gen
            .next(&input.convo_id, "welcomeReissueRequestedEvent")
            .await,
        convo_id: input.convo_id.clone(),
        recipient_device_did: input.recipient_device_did.clone(),
        requested_at: requested_at.to_rfc3339(),
        request_id: request_id.clone(),
    };
    if let Err(e) = sse_state.emit(&input.convo_id, event).await {
        warn!("reissueWelcome: best-effort SSE emit failed: {}", e);
    }

    Ok(Json(ReissueWelcomeOutput {
        welcome_requested: true,
        request_id,
        requested_at,
        inviter_device: Some(inviter_device),
    }))
}
