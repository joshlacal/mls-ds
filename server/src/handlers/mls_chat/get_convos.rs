use axum::{
    extract::{RawQuery, State},
    http::StatusCode,
    response::IntoResponse,
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
) -> Result<axum::response::Response, StatusCode> {
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
                    error!(
                        "❌ [v2.getConvos] Failed to decode query parameter '{}': {}",
                        key, e
                    );
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
        "all" => Ok(handle_all(&pool, did).await?.into_response()),
        "pending" => {
            let cursor = params.cursor.map(|c| c.to_string());
            let limit = params.limit;
            let status = status.unwrap_or_else(|| "pending".to_string());
            Ok(handle_pending(&pool, did, cursor, limit, &status)
                .await?
                .into_response())
        }
        "expected" => Ok(handle_expected(&pool, did, device_id)
            .await?
            .into_response()),
        other => {
            error!("❌ [v2.getConvos] Unknown filter: {}", other);
            Err(StatusCode::BAD_REQUEST)
        }
    }
}

// ---------------------------------------------------------------------------
// filter="all" — inline of v1 get_convos
// ---------------------------------------------------------------------------

async fn handle_all(
    pool: &DbPool,
    did: &str,
) -> Result<
    Json<crate::generated::blue_catbird::mlsChat::get_convos::GetConvosOutput<'static>>,
    StatusCode,
> {
    // Get all active memberships (matches user_did, member_did, or device-suffixed member_did)
    let memberships = sqlx::query_as::<_, Membership>(
        r#"
        SELECT convo_id, member_did, user_did, device_id, device_name, joined_at, left_at,
               unread_count, last_read_at, is_admin, promoted_at, promoted_by_did,
               COALESCE(is_moderator, false) as is_moderator, leaf_index,
               needs_rejoin, rejoin_requested_at, rejoin_key_package_hash
        FROM members
        WHERE (user_did = $1 OR member_did = $1 OR split_part(member_did, '#', 1) = $1)
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
            "SELECT id, creator_did, current_epoch, created_at, updated_at, cipher_suite, confirmation_tag, sequencer_ds, is_remote, group_id, reset_count FROM conversations WHERE id = $1",
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

            let last_message_at = fetch_last_message_at(pool, &membership.convo_id).await?;

            let convo_view = c
                .to_convo_view_with_last_message_at(
                    members,
                    crate::identity::service_did_base_opt().as_deref(),
                    last_message_at,
                )
                .map_err(|e| {
                    error!("❌ [v2.getConvos] Failed to convert convo view: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;

            convos.push(convo_view);
        }
    }

    info!("✅ [v2.getConvos] Found {} conversations", convos.len());

    Ok(Json(
        crate::generated::blue_catbird::mlsChat::get_convos::GetConvosOutput {
            conversations: convos,
            cursor: None,
            pending_count: None,
            request_count: None,
            extra_data: Default::default(),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::{postgres::PgPoolOptions, PgPool};
    use std::collections::BTreeSet;
    use std::time::Duration;

    async fn setup_test_db() -> PgPool {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://localhost/catbird_test".to_string());

        PgPoolOptions::new()
            .max_connections(4)
            .min_connections(1)
            .acquire_timeout(Duration::from_secs(30))
            .idle_timeout(Duration::from_secs(600))
            .connect(&database_url)
            .await
            .expect("Failed to connect to test database")
    }

    async fn cleanup_test_convo(pool: &PgPool, convo_id: &str) {
        let _ = sqlx::query("DELETE FROM messages WHERE convo_id = $1")
            .bind(convo_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM members WHERE convo_id = $1")
            .bind(convo_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM conversations WHERE id = $1")
            .bind(convo_id)
            .execute(pool)
            .await;
    }

    async fn insert_test_membership(
        pool: &PgPool,
        convo_id: &str,
        member_did: &str,
        user_did: &str,
        left_at: Option<DateTime<Utc>>,
    ) {
        let created_at = Utc::now();

        cleanup_test_convo(pool, convo_id).await;

        sqlx::query(
            "INSERT INTO conversations (id, creator_did, current_epoch, created_at, updated_at, cipher_suite, is_remote, group_id)
             VALUES ($1, $2, 1, $3, $3, $4, false, $1)",
        )
        .bind(convo_id)
        .bind(user_did)
        .bind(created_at)
        .bind("MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519")
        .execute(pool)
        .await
        .expect("insert conversation");

        sqlx::query(
            "INSERT INTO members (convo_id, member_did, user_did, joined_at, left_at, is_admin)
             VALUES ($1, $2, $3, $4, $5, false)",
        )
        .bind(convo_id)
        .bind(member_did)
        .bind(user_did)
        .bind(created_at)
        .bind(left_at)
        .execute(pool)
        .await
        .expect("insert member");
    }

    async fn listed_test_conversation_ids(
        pool: &PgPool,
        did: &str,
        prefix: &str,
    ) -> BTreeSet<String> {
        handle_all(pool, did)
            .await
            .expect("handle_all response")
            .0
            .conversations
            .into_iter()
            .map(|convo| convo.conversation_id.as_ref().to_string())
            .filter(|convo_id| convo_id.starts_with(prefix))
            .collect()
    }

    #[tokio::test]
    #[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
    async fn handle_all_treats_principal_did_characters_literally() {
        let pool = setup_test_db().await;
        let prefix = format!("get-convos-literal-did-{}-", uuid::Uuid::new_v4());
        let underscore_did = "did:plc:literal_";
        let percent_did = "did:plc:literal%25";

        let cases = [
            (
                "underscore-near-match",
                "did:plc:literalx#device-attacker",
                "did:plc:literalx",
                None,
            ),
            (
                "percent-near-match",
                "did:plc:literal-other25#device-attacker",
                "did:plc:literal-other25",
                None,
            ),
            (
                "exact-user-did",
                "did:plc:other#device-user",
                underscore_did,
                None,
            ),
            (
                "exact-member-did",
                percent_did,
                "did:plc:other-member",
                None,
            ),
            (
                "legacy-device-member",
                "did:plc:literal_#device-legacy",
                "did:plc:legacy-device-owner",
                None,
            ),
            (
                "inactive-device-member",
                "did:plc:literal_#device-inactive",
                "did:plc:literal_",
                Some(Utc::now()),
            ),
        ];

        for (suffix, member_did, user_did, left_at) in cases {
            insert_test_membership(
                &pool,
                &format!("{prefix}{suffix}"),
                member_did,
                user_did,
                left_at,
            )
            .await;
        }

        let observed = (
            listed_test_conversation_ids(&pool, underscore_did, &prefix).await,
            listed_test_conversation_ids(&pool, percent_did, &prefix).await,
        );
        let expected = (
            BTreeSet::from([
                format!("{prefix}exact-user-did"),
                format!("{prefix}legacy-device-member"),
            ]),
            BTreeSet::from([format!("{prefix}exact-member-did")]),
        );
        assert_eq!(observed, expected);

        for (suffix, _, _, _) in cases {
            cleanup_test_convo(&pool, &format!("{prefix}{suffix}")).await;
        }
    }

    #[tokio::test]
    #[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
    async fn handle_all_projects_last_message_at_from_messages_table() {
        let pool = setup_test_db().await;
        let convo_id = format!("get-convos-last-message-at-{}", uuid::Uuid::new_v4());
        let did = "did:plc:lastmessageattest";
        let created_at = chrono::DateTime::parse_from_rfc3339("2026-06-14T10:00:00Z")
            .expect("valid created_at")
            .with_timezone(&Utc);
        let older_message_at = chrono::DateTime::parse_from_rfc3339("2026-06-14T10:05:00Z")
            .expect("valid older message time")
            .with_timezone(&Utc);
        let latest_message_at = chrono::DateTime::parse_from_rfc3339("2026-06-14T10:07:00Z")
            .expect("valid latest message time")
            .with_timezone(&Utc);

        cleanup_test_convo(&pool, &convo_id).await;

        sqlx::query(
            "INSERT INTO conversations (id, creator_did, current_epoch, created_at, updated_at, cipher_suite, is_remote, group_id)
             VALUES ($1, $2, 1, $3, $3, $4, false, $1)",
        )
        .bind(&convo_id)
        .bind(did)
        .bind(created_at)
        .bind("MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519")
        .execute(&pool)
        .await
        .expect("insert conversation");

        sqlx::query(
            "INSERT INTO members (convo_id, member_did, user_did, joined_at, is_admin)
             VALUES ($1, $2, $2, $3, true)",
        )
        .bind(&convo_id)
        .bind(did)
        .bind(created_at)
        .execute(&pool)
        .await
        .expect("insert member");

        for (seq, id, created_at) in [
            (1_i64, "older-message", older_message_at),
            (2_i64, "latest-message", latest_message_at),
        ] {
            sqlx::query(
                "INSERT INTO messages (id, convo_id, sender_did, message_type, epoch, wire_epoch, seq, ciphertext, msg_id, padded_size, created_at)
                 VALUES ($1, $2, NULL, 'app', 1, 1, $3, $4, $5, 512, $6)",
            )
            .bind(format!("{convo_id}-{id}"))
            .bind(&convo_id)
            .bind(seq)
            .bind(Vec::<u8>::from([0xCA, 0x7B, 0x1D]))
            .bind(format!("{convo_id}-{id}-msg"))
            .bind(created_at)
            .execute(&pool)
            .await
            .expect("insert message");
        }

        let response = handle_all(&pool, did).await.expect("handle_all response");
        let convo = response
            .0
            .conversations
            .iter()
            .find(|convo| convo.conversation_id.as_ref() == convo_id)
            .expect("test conversation in getConvos response");

        assert_eq!(
            convo.last_message_at.as_ref().map(|dt| dt.as_str()),
            Some("2026-06-14T10:07:00.000000Z")
        );

        cleanup_test_convo(&pool, &convo_id).await;
    }
}

async fn fetch_last_message_at(
    pool: &DbPool,
    convo_id: &str,
) -> Result<Option<DateTime<Utc>>, StatusCode> {
    sqlx::query_scalar("SELECT MAX(created_at) FROM messages WHERE convo_id = $1")
        .bind(convo_id)
        .fetch_one(pool)
        .await
        .map_err(|e| {
            error!("❌ [v2.getConvos] Failed to fetch last_message_at: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })
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
    let limit = limit.unwrap_or(50).clamp(1, 100);

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

    let rows: Vec<ChatRequestRow> = if let (Some(created_at), Some(id)) =
        (cursor_created_at, cursor_id)
    {
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

    // TODO: Replace json! with generated output type — fields don't match GetConvosOutput
    // (pending filter returns "requests" array of chat request objects, not ConvoView conversations)
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
) -> Result<
    Json<crate::generated::blue_catbird::mlsChat::get_convos::GetConvosOutput<'static>>,
    StatusCode,
> {
    let _device_id = device_id_param.or_else(|| {
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

    // Fetch full conversation + membership data so we can build proper ConvoView objects
    let memberships = sqlx::query_as::<_, Membership>(
        r#"
        SELECT convo_id, member_did, user_did, device_id, device_name, joined_at, left_at,
               unread_count, last_read_at, is_admin, promoted_at, promoted_by_did,
               COALESCE(is_moderator, false) as is_moderator, leaf_index,
               needs_rejoin, rejoin_requested_at, rejoin_key_package_hash
        FROM members
        WHERE user_did = $1 AND left_at IS NULL
        ORDER BY joined_at DESC
        "#,
    )
    .bind(base_user_did)
    .fetch_all(pool)
    .await
    .map_err(|e| {
        error!(
            "❌ [v2.getConvos] Failed to fetch expected memberships: {}",
            e
        );
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let mut convos = Vec::new();

    for membership in memberships {
        let convo: Option<Conversation> = sqlx::query_as(
            "SELECT id, creator_did, current_epoch, created_at, updated_at, cipher_suite, confirmation_tag, sequencer_ds, is_remote, group_id, reset_count FROM conversations WHERE id = $1",
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

            let last_message_at = fetch_last_message_at(pool, &membership.convo_id).await?;

            let convo_view = c
                .to_convo_view_with_last_message_at(
                    members,
                    crate::identity::service_did_base_opt().as_deref(),
                    last_message_at,
                )
                .map_err(|e| {
                    error!("❌ [v2.getConvos] Failed to convert convo view: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;

            convos.push(convo_view);
        }
    }

    info!("✅ [v2.getConvos] Expected: {} convos", convos.len(),);

    Ok(Json(
        crate::generated::blue_catbird::mlsChat::get_convos::GetConvosOutput {
            conversations: convos,
            cursor: None,
            pending_count: None,
            request_count: None,
            extra_data: Default::default(),
        },
    ))
}
