use axum::{extract::State, http::StatusCode, Json};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::{
    auth::AuthUser,
    device_utils::parse_device_did,
    realtime::{SseState, StreamEvent},
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.reissueWelcome";
const MAX_REISSUE_REQUESTS_PER_HOUR: i64 = 3;

#[derive(Debug)]
struct ReissueRequestRecord {
    request_id: String,
    requested_at: DateTime<Utc>,
    attempts: i32,
    reused_existing: bool,
}

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

fn should_reject_reissue_request(open_request_exists: bool, recent_count: i64) -> bool {
    !open_request_exists && recent_count >= MAX_REISSUE_REQUESTS_PER_HOUR
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

    let mut tx = pool.begin().await.map_err(|e| {
        error!("reissueWelcome: tx begin failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

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
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        error!("reissueWelcome: membership check failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    if !requester_is_member {
        return Err(StatusCode::FORBIDDEN);
    }

    let open_request_exists: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS(
            SELECT 1
            FROM reissue_requests
            WHERE convo_id = $1
              AND recipient_device_did = $2
              AND responded_at IS NULL
        )
        "#,
    )
    .bind(&input.convo_id)
    .bind(&input.recipient_device_did)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        error!("reissueWelcome: open request check failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

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
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        error!("reissueWelcome: rate-limit check failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    if should_reject_reissue_request(open_request_exists, recent_count) {
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
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        error!("reissueWelcome: admin lookup failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let Some(inviter_device) = inviter_device else {
        warn!("reissueWelcome: no admin available to reissue Welcome");
        return Err(StatusCode::GONE);
    };

    let proposed_request_id = Uuid::new_v4().to_string();
    let attempt_at = Utc::now();
    let (request_id, requested_at, attempts, reused_existing): (String, DateTime<Utc>, i32, bool) =
        sqlx::query_as(
            r#"
            INSERT INTO reissue_requests
                (id, convo_id, recipient_device_did, requested_at, attempts, last_attempt_at)
            VALUES ($1, $2, $3, $4, 1, $4)
            ON CONFLICT (convo_id, recipient_device_did)
                WHERE responded_at IS NULL
            DO UPDATE SET
                attempts = reissue_requests.attempts + 1,
                last_attempt_at = EXCLUDED.last_attempt_at
            RETURNING id, requested_at, attempts, id <> $1 AS reused_existing
            "#,
        )
        .bind(&proposed_request_id)
        .bind(&input.convo_id)
        .bind(&input.recipient_device_did)
        .bind(attempt_at)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| {
            error!("reissueWelcome: upsert failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let request = ReissueRequestRecord {
        request_id,
        requested_at,
        attempts,
        reused_existing,
    };

    tx.commit().await.map_err(|e| {
        error!("reissueWelcome: tx commit failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!(
        convo_id = %crate::crypto::redact_for_log(&input.convo_id),
        recipient_device_did = %crate::crypto::redact_for_log(&input.recipient_device_did),
        request_id = %crate::crypto::redact_for_log(&request.request_id),
        inviter_device_did = %crate::crypto::redact_for_log(&inviter_device),
        recent_request_count = recent_count,
        request_attempts = request.attempts,
        reused_existing = request.reused_existing,
        requester_is_member,
        has_reason = !input.reason.trim().is_empty(),
        "reissueWelcome: request upserted"
    );

    let event = StreamEvent::WelcomeReissueRequestedEvent {
        cursor: sse_state
            .cursor_gen
            .next(&input.convo_id, "welcomeReissueRequestedEvent")
            .await,
        convo_id: input.convo_id.clone(),
        recipient_device_did: input.recipient_device_did.clone(),
        requested_at: request.requested_at.to_rfc3339(),
        request_id: request.request_id.clone(),
    };
    sse_state.enqueue_with_store(&input.convo_id, pool.clone(), event);
    info!(
        convo_id = %crate::crypto::redact_for_log(&input.convo_id),
        recipient_device_did = %crate::crypto::redact_for_log(&input.recipient_device_did),
        request_id = %crate::crypto::redact_for_log(&request.request_id),
        "reissueWelcome: requested event enqueued with event_stream persistence"
    );

    Ok(Json(ReissueWelcomeOutput {
        welcome_requested: true,
        request_id: request.request_id,
        requested_at: request.requested_at,
        inviter_device: Some(inviter_device),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_reissue_request_bypasses_creation_rate_limit() {
        assert!(
            !should_reject_reissue_request(
                true,
                MAX_REISSUE_REQUESTS_PER_HOUR
            ),
            "retries for an existing open request should return/re-emit that request instead of 429"
        );
    }

    #[test]
    fn new_reissue_request_is_rate_limited_after_hourly_limit() {
        assert!(
            should_reject_reissue_request(false, MAX_REISSUE_REQUESTS_PER_HOUR),
            "new open requests should still honor the hourly creation limit"
        );
    }
}
