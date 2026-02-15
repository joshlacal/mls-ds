use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use tracing::{error, info, warn};

use crate::{auth::AuthUser, storage::DbPool};

#[derive(Debug, Deserialize)]
pub struct ListChatRequestsParams {
    pub cursor: Option<String>,
    pub limit: Option<i64>,
    pub status: Option<String>,
}

#[derive(Debug, FromRow)]
struct ChatRequestRow {
    id: String,
    sender_did: String,
    status: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    is_group_invite: bool,
    group_id: Option<String>,
    message_count: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatRequestView {
    pub id: String,
    pub sender_did: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_count: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_group_invite: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListChatRequestsOutput {
    pub requests: Vec<ChatRequestView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// List pending chat requests received by the authenticated user
/// GET /xrpc/blue.catbird.mls.listChatRequests
#[tracing::instrument(skip(pool))]
pub async fn list_chat_requests(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Query(params): Query<ListChatRequestsParams>,
) -> Result<Json<ListChatRequestsOutput>, StatusCode> {
    let recipient_did = &auth_user.did;
    let limit = params.limit.unwrap_or(50).max(1).min(100);

    let status = params.status.unwrap_or_else(|| "pending".to_string());
    match status.as_str() {
        "pending" | "accepted" | "declined" | "blocked" | "expired" => {}
        other => {
            warn!(status = other, "Invalid chat request status filter");
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    info!(limit, status = %status, "Listing chat requests");

    // Cursor is a request ID; we paginate in descending (created_at, id) order.
    let (cursor_created_at, cursor_id) = if let Some(ref cursor) = params.cursor {
        let row = sqlx::query_as::<_, (DateTime<Utc>, String)>(
            "SELECT created_at, id FROM chat_requests WHERE recipient_did = $1 AND id = $2",
        )
        .bind(recipient_did)
        .bind(cursor)
        .fetch_optional(&pool)
        .await
        .map_err(|e| {
            error!("Failed to validate cursor: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        match row {
            Some((created_at, id)) => (Some(created_at), Some(id)),
            None => return Err(StatusCode::BAD_REQUEST),
        }
    } else {
        (None, None)
    };

    let rows: Vec<ChatRequestRow> = if let (Some(created_at), Some(id)) =
        (cursor_created_at, cursor_id)
    {
        sqlx::query_as::<_, ChatRequestRow>(
            r#"
            SELECT
                cr.id,
                cr.sender_did,
                cr.status::TEXT as status,
                cr.created_at,
                cr.expires_at,
                cr.is_group_invite,
                cr.group_id,
                COALESCE((SELECT COUNT(*) FROM held_messages hm WHERE hm.request_id = cr.id), 0) as message_count
            FROM chat_requests cr
            WHERE cr.recipient_did = $1
              AND cr.status::TEXT = $2
              AND (cr.created_at, cr.id) < ($3, $4)
            ORDER BY cr.created_at DESC, cr.id DESC
            LIMIT $5
            "#,
        )
        .bind(recipient_did)
        .bind(&status)
        .bind(created_at)
        .bind(id)
        .bind(limit)
        .fetch_all(&pool)
        .await
        .map_err(|e| {
            error!("Failed to list chat requests: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
    } else {
        sqlx::query_as::<_, ChatRequestRow>(
            r#"
            SELECT
                cr.id,
                cr.sender_did,
                cr.status::TEXT as status,
                cr.created_at,
                cr.expires_at,
                cr.is_group_invite,
                cr.group_id,
                COALESCE((SELECT COUNT(*) FROM held_messages hm WHERE hm.request_id = cr.id), 0) as message_count
            FROM chat_requests cr
            WHERE cr.recipient_did = $1
              AND cr.status::TEXT = $2
            ORDER BY cr.created_at DESC, cr.id DESC
            LIMIT $3
            "#,
        )
        .bind(recipient_did)
        .bind(&status)
        .bind(limit)
        .fetch_all(&pool)
        .await
        .map_err(|e| {
            error!("Failed to list chat requests: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
    };

    let next_cursor = rows
        .last()
        .map(|r| r.id.clone())
        .filter(|_| rows.len() as i64 == limit);

    let requests = rows
        .into_iter()
        .map(|r| ChatRequestView {
            id: r.id,
            sender_did: r.sender_did,
            status: r.status,
            created_at: r.created_at,
            expires_at: r.expires_at,
            preview_text: None,
            message_count: Some(r.message_count),
            is_group_invite: Some(r.is_group_invite),
            group_id: r.group_id,
        })
        .collect();

    Ok(Json(ListChatRequestsOutput {
        requests,
        cursor: next_cursor,
    }))
}
