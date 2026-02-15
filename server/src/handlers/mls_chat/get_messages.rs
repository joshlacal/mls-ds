use axum::{
    extract::{RawQuery, State},
    http::StatusCode,
    Json,
};
use base64::Engine;
use chrono::{DateTime, Utc};
use jacquard_axum::ExtractXrpc;
use sqlx::FromRow;
use tracing::{error, info, warn};

use crate::{
    auth::AuthUser,
    generated::blue_catbird::mlsChat::get_messages::GetMessagesRequest,
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.getMessages";

// ---------------------------------------------------------------------------
// Row types for inline SQL
// ---------------------------------------------------------------------------

#[derive(Debug, FromRow)]
struct MessageRow {
    id: String,
    convo_id: String,
    message_type: String,
    epoch: i64,
    seq: i64,
    ciphertext: Vec<u8>,
    created_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
struct CommitRow {
    id: String,
    epoch: i64,
    ciphertext: Vec<u8>,
    created_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Consolidated message retrieval endpoint.
///
/// GET /xrpc/blue.catbird.mlsChat.getMessages
///
/// Query parameter `type` selects behavior:
/// - `"all"` (default) → returns both app messages and commits
/// - `"app"`           → app messages only
/// - `"commit"`        → commit messages only
#[tracing::instrument(skip(pool, auth_user))]
pub async fn get_messages(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    RawQuery(extra_query): RawQuery,
    ExtractXrpc(params): ExtractXrpc<GetMessagesRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let extra_query_str = extra_query.as_deref().unwrap_or("");

    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        error!("❌ [v2.getMessages] Unauthorized");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let did = &auth_user.did;
    let message_type = params.r#type.as_deref().unwrap_or("all");
    let convo_id = params.convo_id.to_string();
    let limit = params.limit.unwrap_or(50).max(1).min(100);
    let since_seq = params.since_seq;

    if convo_id.is_empty() {
        warn!("❌ [v2.getMessages] Empty convo_id");
        return Err(StatusCode::BAD_REQUEST);
    }

    // Parse additional query params for commits
    let mut from_epoch: i64 = 0;
    let mut to_epoch: Option<i64> = None;
    for pair in extra_query_str.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            match key {
                "fromEpoch" => from_epoch = value.parse().unwrap_or(0),
                "toEpoch" => to_epoch = value.parse().ok(),
                _ => {}
            }
        }
    }

    match message_type {
        "app" => {
            let messages = fetch_app_messages(&pool, did, &convo_id, since_seq, limit).await?;
            Ok(Json(messages))
        }

        "commit" => {
            let commits =
                fetch_commits(&pool, did, &convo_id, from_epoch, to_epoch).await?;
            Ok(Json(commits))
        }

        "all" => {
            let messages =
                fetch_app_messages(&pool, did, &convo_id, since_seq, limit).await?;
            let commits =
                fetch_commits(&pool, did, &convo_id, from_epoch, to_epoch).await?;

            let mut response = messages;
            if let Some(commit_list) = commits.get("commits") {
                response["commits"] = commit_list.clone();
            }

            Ok(Json(response))
        }

        other => {
            warn!("❌ [v2.getMessages] Unknown type filter: {}", other);
            Err(StatusCode::BAD_REQUEST)
        }
    }
}

// ---------------------------------------------------------------------------
// type="app" — inline of v1 get_messages
// ---------------------------------------------------------------------------

async fn fetch_app_messages(
    pool: &DbPool,
    did: &str,
    convo_id: &str,
    since_seq: Option<i64>,
    limit: i64,
) -> Result<serde_json::Value, StatusCode> {
    // Check membership
    let is_member: Option<(i32,)> = sqlx::query_as(
        "SELECT 1 as v FROM members WHERE convo_id = $1 AND (user_did = $2 OR member_did = $2) AND left_at IS NULL LIMIT 1",
    )
    .bind(convo_id)
    .bind(did)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        error!("❌ [v2.getMessages] Failed to check membership: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if is_member.is_none() {
        warn!("❌ [v2.getMessages] User is not a member");
        return Err(StatusCode::FORBIDDEN);
    }

    // Fetch messages
    let messages: Vec<MessageRow> = if let Some(since) = since_seq {
        sqlx::query_as::<_, MessageRow>(
            r#"
            SELECT id, convo_id, message_type,
                   CAST(epoch AS BIGINT) as epoch, CAST(seq AS BIGINT) as seq,
                   ciphertext, created_at
            FROM messages
            WHERE convo_id = $1 AND seq > $2 AND (expires_at IS NULL OR expires_at > NOW())
            ORDER BY epoch ASC, seq ASC
            LIMIT $3
            "#,
        )
        .bind(convo_id)
        .bind(since)
        .bind(limit)
        .fetch_all(pool)
        .await
        .map_err(|e| {
            error!("❌ [v2.getMessages] Failed to fetch messages since seq: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
    } else {
        sqlx::query_as::<_, MessageRow>(
            r#"
            SELECT id, convo_id, message_type,
                   CAST(epoch AS BIGINT) as epoch, CAST(seq AS BIGINT) as seq,
                   ciphertext, created_at
            FROM messages
            WHERE convo_id = $1 AND (expires_at IS NULL OR expires_at > NOW())
            ORDER BY seq DESC
            LIMIT $2
            "#,
        )
        .bind(convo_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .map_err(|e| {
            error!("❌ [v2.getMessages] Failed to list messages: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
    };

    // Reset unread count
    sqlx::query(
        "UPDATE members SET unread_count = 0 WHERE convo_id = $1 AND user_did = $2 AND left_at IS NULL",
    )
    .bind(convo_id)
    .bind(did)
    .execute(pool)
    .await
    .map_err(|e| {
        error!("❌ [v2.getMessages] Failed to reset unread count: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let last_seq = messages.last().map(|m| m.seq);

    let message_views: Vec<serde_json::Value> = messages
        .into_iter()
        .map(|m| {
            let ciphertext_b64 =
                base64::engine::general_purpose::STANDARD.encode(&m.ciphertext);
            serde_json::json!({
                "id": m.id,
                "convoId": m.convo_id,
                "ciphertext": { "$bytes": ciphertext_b64 },
                "epoch": m.epoch,
                "seq": m.seq,
                "createdAt": m.created_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                "messageType": m.message_type,
            })
        })
        .collect();

    info!("✅ [v2.getMessages] Fetched {} app messages", message_views.len());

    let mut response = serde_json::json!({
        "messages": message_views,
    });
    if let Some(seq) = last_seq {
        response["lastSeq"] = serde_json::json!(seq);
    }

    Ok(response)
}

// ---------------------------------------------------------------------------
// type="commit" — inline of v1 get_commits
// ---------------------------------------------------------------------------

async fn fetch_commits(
    pool: &DbPool,
    did: &str,
    convo_id: &str,
    from_epoch: i64,
    to_epoch: Option<i64>,
) -> Result<serde_json::Value, StatusCode> {
    if from_epoch < 0 {
        warn!("❌ [v2.getMessages] Invalid from_epoch: {}", from_epoch);
        return Err(StatusCode::BAD_REQUEST);
    }

    // Check membership
    let is_member: Option<(i32,)> = sqlx::query_as(
        "SELECT 1 as v FROM members WHERE convo_id = $1 AND (user_did = $2 OR member_did = $2) AND left_at IS NULL LIMIT 1",
    )
    .bind(convo_id)
    .bind(did)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        error!("❌ [v2.getMessages] Failed to check membership: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if is_member.is_none() {
        warn!("❌ [v2.getMessages] User is not a member");
        return Err(StatusCode::FORBIDDEN);
    }

    // Determine end epoch
    let to_epoch = if let Some(to) = to_epoch {
        to
    } else {
        let current_epoch: i32 =
            sqlx::query_scalar("SELECT current_epoch FROM conversations WHERE id = $1")
                .bind(convo_id)
                .fetch_one(pool)
                .await
                .map_err(|e| {
                    error!("❌ [v2.getMessages] Failed to fetch current epoch: {}", e);
                    match e {
                        sqlx::Error::RowNotFound => StatusCode::NOT_FOUND,
                        _ => StatusCode::INTERNAL_SERVER_ERROR,
                    }
                })?;
        current_epoch as i64
    };

    if from_epoch > to_epoch {
        warn!(
            "❌ [v2.getMessages] Invalid epoch range: {} to {}",
            from_epoch, to_epoch
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    let commits = sqlx::query_as::<_, CommitRow>(
        r#"
        SELECT id, epoch, ciphertext, created_at
        FROM messages
        WHERE convo_id = $1 AND message_type = 'commit' AND epoch >= $2 AND epoch <= $3
        ORDER BY epoch ASC, created_at ASC
        "#,
    )
    .bind(convo_id)
    .bind(from_epoch)
    .bind(to_epoch)
    .fetch_all(pool)
    .await
    .map_err(|e| {
        error!("❌ [v2.getMessages] Failed to fetch commits: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!("✅ [v2.getMessages] Fetched {} commits", commits.len());

    let commit_views: Vec<serde_json::Value> = commits
        .into_iter()
        .map(|c| {
            let commit_data_b64 =
                base64::engine::general_purpose::STANDARD.encode(&c.ciphertext);
            serde_json::json!({
                "id": c.id,
                "epoch": c.epoch,
                "commitData": { "$bytes": commit_data_b64 },
                "sender": serde_json::Value::Null,
                "createdAt": c.created_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            })
        })
        .collect();

    Ok(serde_json::json!({
        "convoId": convo_id,
        "commits": commit_views,
    }))
}
