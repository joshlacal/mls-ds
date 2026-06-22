use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{error, warn};

use crate::{auth::AuthUser, storage::DbPool};

const NSID: &str = "blue.catbird.mlsChat.getWelcomeReissueStatus";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetWelcomeReissueStatusQuery {
    pub request_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetWelcomeReissueStatusOutput {
    pub request_id: String,
    pub convo_id: String,
    pub recipient_device_did: String,
    pub status: String,
    pub requested_at: DateTime<Utc>,
    pub attempts: i32,
    pub last_attempt_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivered_to_inviter_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub responded_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumed_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expired_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub welcome_blob_id: Option<String>,
}

#[derive(Debug)]
struct ReissueStatusRow {
    request_id: String,
    convo_id: String,
    recipient_device_did: String,
    status: String,
    requested_at: DateTime<Utc>,
    delivered_to_inviter_at: Option<DateTime<Utc>>,
    responded_at: Option<DateTime<Utc>>,
    consumed_at: Option<DateTime<Utc>>,
    expired_at: Option<DateTime<Utc>>,
    welcome_blob_id: Option<String>,
    attempts: i32,
    last_attempt_at: DateTime<Utc>,
}

#[tracing::instrument(skip(pool, auth_user))]
pub async fn get_welcome_reissue_status(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Query(query): Query<GetWelcomeReissueStatusQuery>,
) -> Result<Json<GetWelcomeReissueStatusOutput>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    if query.request_id.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    if let Err(e) = sqlx::query(
        r#"
        UPDATE reissue_requests
        SET status = 'expired',
            expired_at = COALESCE(expired_at, NOW())
        WHERE id = $1
          AND responded_at IS NULL
          AND status IN ('requested', 'delivered_to_inviter')
          AND requested_at < NOW() - INTERVAL '24 hours'
        "#,
    )
    .bind(&query.request_id)
    .execute(&pool)
    .await
    {
        warn!(
            request_id = %crate::crypto::redact_for_log(&query.request_id),
            error = %e,
            "getWelcomeReissueStatus: lazy expiry update failed"
        );
    }

    let row = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            String,
            DateTime<Utc>,
            Option<DateTime<Utc>>,
            Option<DateTime<Utc>>,
            Option<DateTime<Utc>>,
            Option<DateTime<Utc>>,
            Option<String>,
            i32,
            DateTime<Utc>,
        ),
    >(
        r#"
        SELECT
            id,
            convo_id,
            recipient_device_did,
            status,
            requested_at,
            delivered_to_inviter_at,
            responded_at,
            consumed_at,
            expired_at,
            welcome_blob_id,
            attempts,
            last_attempt_at
        FROM reissue_requests
        WHERE id = $1
        "#,
    )
    .bind(&query.request_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!(
            request_id = %crate::crypto::redact_for_log(&query.request_id),
            error = %e,
            "getWelcomeReissueStatus: request lookup failed"
        );
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let Some((
        request_id,
        convo_id,
        recipient_device_did,
        status,
        requested_at,
        delivered_to_inviter_at,
        responded_at,
        consumed_at,
        expired_at,
        welcome_blob_id,
        attempts,
        last_attempt_at,
    )) = row
    else {
        return Err(StatusCode::NOT_FOUND);
    };
    let row = ReissueStatusRow {
        request_id,
        convo_id,
        recipient_device_did,
        status,
        requested_at,
        delivered_to_inviter_at,
        responded_at,
        consumed_at,
        expired_at,
        welcome_blob_id,
        attempts,
        last_attempt_at,
    };

    let requester_is_member: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS(
            SELECT 1
            FROM members
            WHERE convo_id = $1
              AND (member_did = $2 OR user_did = $2)
        )
        "#,
    )
    .bind(&row.convo_id)
    .bind(&auth_user.did)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!(
            convo_id = %crate::crypto::redact_for_log(&row.convo_id),
            did = %crate::crypto::redact_for_log(&auth_user.did),
            error = %e,
            "getWelcomeReissueStatus: membership check failed"
        );
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    if !requester_is_member {
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(Json(GetWelcomeReissueStatusOutput {
        request_id: row.request_id,
        convo_id: row.convo_id,
        recipient_device_did: row.recipient_device_did,
        status: row.status,
        requested_at: row.requested_at,
        attempts: row.attempts,
        last_attempt_at: row.last_attempt_at,
        delivered_to_inviter_at: row.delivered_to_inviter_at,
        responded_at: row.responded_at,
        consumed_at: row.consumed_at,
        expired_at: row.expired_at,
        welcome_blob_id: row.welcome_blob_id,
    }))
}
