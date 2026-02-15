use axum::{
    extract::{RawQuery, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Utc};
use jacquard_axum::ExtractXrpc;
use sqlx::FromRow;
use tracing::{error, info, warn};

use crate::{
    auth::AuthUser,
    generated::blue_catbird::mlsChat::get_convos::GetConvosRequest,
    models::{Conversation, Membership},
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.getConvos";

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Consolidated conversation listing endpoint.
///
/// GET /xrpc/blue.catbird.mlsChat.getConvos
///
/// Query parameter `filter` selects behavior:
/// - `"all"` (default) → active conversations with members
/// - `"pending"`        → pending chat requests + count
/// - `"expected"`       → conversations user should be in
#[tracing::instrument(skip(pool, auth_user))]
pub async fn get_convos(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    RawQuery(extra_query): RawQuery,
    ExtractXrpc(params): ExtractXrpc<GetConvosRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let extra_query_str = extra_query.as_deref().unwrap_or("");

    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        error!("❌ [v2.getConvos] Unauthorized");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let did = &auth_user.did;
    let filter = params.filter.as_deref().unwrap_or("all");

    // Parse extra query params not in the generated type
    let mut device_id: Option<String> = None;
    let mut status: Option<String> = None;
    for pair in extra_query_str.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            let decoded = match urlencoding::decode(value) {
                Ok(v) => v.to_string(),
                Err(e) => {
                    error!("❌ [v2.getConvos] Failed to decode query parameter '{}': {}", key, e);
                    return Err(StatusCode::BAD_REQUEST);
                }
            };
            match key {
                "deviceId" => device_id = Some(decoded),
                "status" => status = Some(decoded),
                _ => {}
            }
        }
    }

    match filter {
        "all" => handle_all(&pool, did).await,
        "pending" => {
            let cursor = params.cursor.map(|c| c.to_string());
            let limit = params.limit;
            let status = status.unwrap_or_else(|| "pending".to_string());
            handle_pending(&pool, did, cursor, limit, &status).await
        }
        "expected" => handle_expected(&pool, did, device_id).await,
        other => {
            error!("❌ [v2.getConvos] Unknown filter: {}", other);
            Err(StatusCode::BAD_REQUEST)
        }
    }
}

// ---------------------------------------------------------------------------
// filter="all" — inline of v1 get_convos
// ---------------------------------------------------------------------------

async fn handle_all(pool: &DbPool, did: &str) -> Result<Json<serde_json::Value>, StatusCode> {
    // Get all active memberships (matches user_did, member_did, or device-suffixed member_did)
    let memberships = sqlx::query_as::<_, Membership>(
        r#"
        SELECT convo_id, member_did, user_did, device_id, device_name, joined_at, left_at,
               unread_count, last_read_at, is_admin, promoted_at, promoted_by_did,
               COALESCE(is_moderator, false) as is_moderator, leaf_index,
               needs_rejoin, rejoin_requested_at, rejoin_key_package_hash
        FROM members
        WHERE (user_did = $1 OR member_did = $1 OR member_did LIKE ($1 || '#%'))
          AND left_at IS NULL
        ORDER BY joined_at DESC
        "#,
    )
    .bind(did)
    .fetch_all(pool)
    .await
    .map_err(|e| {
        error!("❌ [v2.getConvos] Failed to fetch memberships: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let mut convos = Vec::new();

    for membership in memberships {
        let convo: Option<Conversation> = sqlx::query_as(
            "SELECT id, creator_did, current_epoch, created_at, updated_at, name, cipher_suite, sequencer_ds, is_remote FROM conversations WHERE id = $1",
        )
        .bind(&membership.convo_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| {
            error!("❌ [v2.getConvos] Failed to fetch conversation: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        if let Some(c) = convo {
            if c.id.is_empty() {
                continue;
            }

            let member_rows: Vec<Membership> = sqlx::query_as(
                r#"
                SELECT convo_id, member_did, user_did, device_id, device_name, joined_at, left_at,
                       unread_count, last_read_at, is_admin, promoted_at, promoted_by_did,
                       COALESCE(is_moderator, false) as is_moderator, leaf_index,
                       needs_rejoin, rejoin_requested_at, rejoin_key_package_hash
                FROM members WHERE convo_id = $1 AND left_at IS NULL ORDER BY user_did, joined_at
                "#,
            )
            .bind(&membership.convo_id)
            .fetch_all(pool)
            .await
            .map_err(|e| {
                error!("❌ [v2.getConvos] Failed to fetch members: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            let members: Vec<crate::models::MemberView<'static>> = member_rows
                .into_iter()
                .map(|m| {
                    m.to_member_view().map_err(|e| {
                        error!("❌ [v2.getConvos] Failed to convert member view: {}", e);
                        StatusCode::INTERNAL_SERVER_ERROR
                    })
                })
                .collect::<Result<Vec<_>, StatusCode>>()?;

            let convo_view = c.to_convo_view(members).map_err(|e| {
                error!("❌ [v2.getConvos] Failed to convert convo view: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            convos.push(convo_view);
        }
    }

    info!("✅ [v2.getConvos] Found {} conversations", convos.len());

    let output = crate::generated::blue_catbird::mls::get_convos::GetConvosOutput {
        conversations: convos,
        cursor: None,
        extra_data: Default::default(),
    };
    Ok(Json(serde_json::to_value(output).unwrap()))
}

// ---------------------------------------------------------------------------
// filter="pending" — inline of v1 list_chat_requests + get_request_count
// ---------------------------------------------------------------------------

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

async fn handle_pending(
    pool: &DbPool,
    recipient_did: &str,
    cursor: Option<String>,
    limit: Option<i64>,
    status: &str,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let limit = limit.unwrap_or(50).max(1).min(100);

    match status {
        "pending" | "accepted" | "declined" | "blocked" | "expired" => {}
        other => {
            warn!("❌ [v2.getConvos] Invalid chat request status: {}", other);
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    // Get pending count
    let pending_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM chat_requests WHERE recipient_did = $1 AND status = 'pending'",
    )
    .bind(recipient_did)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        error!("❌ [v2.getConvos] Failed to count requests: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Cursor-based pagination (cursor is a request ID)
    let (cursor_created_at, cursor_id) = if let Some(ref cursor_val) = cursor {
        let row = sqlx::query_as::<_, (DateTime<Utc>, String)>(
            "SELECT created_at, id FROM chat_requests WHERE recipient_did = $1 AND id = $2",
        )
        .bind(recipient_did)
        .bind(cursor_val)
        .fetch_optional(pool)
        .await
        .map_err(|e| {
            error!("❌ [v2.getConvos] Failed to validate cursor: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        match row {
            Some((created_at, id)) => (Some(created_at), Some(id)),
            None => return Err(StatusCode::BAD_REQUEST),
        }
    } else {
        (None, None)
    };

    let rows: Vec<ChatRequestRow> =
        if let (Some(created_at), Some(id)) = (cursor_created_at, cursor_id) {
            sqlx::query_as::<_, ChatRequestRow>(
                r#"
                SELECT cr.id, cr.sender_did, cr.status::TEXT as status, cr.created_at, cr.expires_at,
                       cr.is_group_invite, cr.group_id,
                       COALESCE((SELECT COUNT(*) FROM held_messages hm WHERE hm.request_id = cr.id), 0) as message_count
                FROM chat_requests cr
                WHERE cr.recipient_did = $1 AND cr.status::TEXT = $2
                  AND (cr.created_at, cr.id) < ($3, $4)
                ORDER BY cr.created_at DESC, cr.id DESC
                LIMIT $5
                "#,
            )
            .bind(recipient_did)
            .bind(status)
            .bind(created_at)
            .bind(id)
            .bind(limit)
            .fetch_all(pool)
            .await
            .map_err(|e| {
                error!("❌ [v2.getConvos] Failed to list chat requests: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?
        } else {
            sqlx::query_as::<_, ChatRequestRow>(
                r#"
                SELECT cr.id, cr.sender_did, cr.status::TEXT as status, cr.created_at, cr.expires_at,
                       cr.is_group_invite, cr.group_id,
                       COALESCE((SELECT COUNT(*) FROM held_messages hm WHERE hm.request_id = cr.id), 0) as message_count
                FROM chat_requests cr
                WHERE cr.recipient_did = $1 AND cr.status::TEXT = $2
                ORDER BY cr.created_at DESC, cr.id DESC
                LIMIT $3
                "#,
            )
            .bind(recipient_did)
            .bind(status)
            .bind(limit)
            .fetch_all(pool)
            .await
            .map_err(|e| {
                error!("❌ [v2.getConvos] Failed to list chat requests: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?
        };

    let next_cursor = rows
        .last()
        .map(|r| r.id.clone())
        .filter(|_| rows.len() as i64 == limit);

    let requests: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            let mut obj = serde_json::json!({
                "id": r.id,
                "senderDid": r.sender_did,
                "status": r.status,
                "createdAt": r.created_at,
                "expiresAt": r.expires_at,
                "messageCount": r.message_count,
            });
            if r.is_group_invite {
                obj["isGroupInvite"] = serde_json::json!(true);
            }
            if let Some(gid) = r.group_id {
                obj["groupId"] = serde_json::json!(gid);
            }
            obj
        })
        .collect();

    let mut response = serde_json::json!({
        "requests": requests,
        "pendingCount": pending_count,
    });
    if let Some(c) = next_cursor {
        response["cursor"] = serde_json::json!(c);
    }

    Ok(Json(response))
}

// ---------------------------------------------------------------------------
// filter="expected" — inline of v1 get_expected_conversations
// ---------------------------------------------------------------------------

async fn handle_expected(
    pool: &DbPool,
    user_did: &str,
    device_id_param: Option<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let device_id = device_id_param.or_else(|| {
        if user_did.contains('#') {
            user_did.split('#').nth(1).map(|s| s.to_string())
        } else {
            None
        }
    });

    let base_user_did = if user_did.contains('#') {
        user_did.split('#').next().unwrap_or(user_did)
    } else {
        user_did
    };

    let conversations = sqlx::query_as::<_, (
        String,                                 // convo_id
        String,                                 // name
        i64,                                    // member_count
        Option<DateTime<Utc>>,                  // last_activity
        bool,                                   // needs_rejoin
        Option<String>,                         // device_id from members
    )>(
        r#"
        SELECT DISTINCT ON (c.id)
            c.id as convo_id,
            COALESCE(c.name, 'Unnamed Conversation') as name,
            (SELECT COUNT(*) FROM members m2 WHERE m2.convo_id = c.id AND m2.left_at IS NULL) as member_count,
            (SELECT MAX(created_at) FROM messages WHERE convo_id = c.id) as last_activity,
            m.needs_rejoin,
            m.device_id
        FROM conversations c
        INNER JOIN members m ON c.id = m.convo_id
        WHERE m.user_did = $1 AND m.left_at IS NULL
        ORDER BY c.id,
                 CASE WHEN $2::text IS NOT NULL AND m.device_id = $2 THEN 0 ELSE 1 END,
                 m.device_id NULLS LAST,
                 c.updated_at DESC
        "#,
    )
    .bind(base_user_did)
    .bind(&device_id)
    .fetch_all(pool)
    .await
    .map_err(|e| {
        error!("❌ [v2.getConvos] Failed to fetch expected conversations: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let result: Vec<serde_json::Value> = conversations
        .into_iter()
        .map(|(convo_id, name, member_count, last_activity, needs_rejoin, member_device_id)| {
            let device_in_group = if let Some(target_device) = &device_id {
                member_device_id.as_ref() == Some(target_device)
            } else {
                member_device_id.is_some()
            };
            let should_be_in_group = !device_in_group && !needs_rejoin;

            serde_json::json!({
                "convoId": convo_id,
                "name": name,
                "memberCount": member_count,
                "shouldBeInGroup": should_be_in_group,
                "lastActivity": last_activity.map(|dt| dt.to_rfc3339()),
                "needsRejoin": needs_rejoin,
                "deviceInGroup": device_in_group,
            })
        })
        .collect();

    info!(
        "✅ [v2.getConvos] Expected: {} convos, {} missing",
        result.len(),
        result.iter().filter(|c| c["shouldBeInGroup"] == true).count()
    );

    Ok(Json(serde_json::json!({ "conversations": result })))
}
