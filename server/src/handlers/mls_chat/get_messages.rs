use axum::{
    extract::{RawQuery, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Utc};
use jacquard_axum::ExtractXrpc;
use sqlx::FromRow;
use tracing::{debug, error, info, warn};

use crate::{
    auth::AuthUser,
    generated::blue_catbird::mlsChat::{
        get_messages::{GetMessagesOutput, GetMessagesRequest},
        MessageView,
    },
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
    #[sqlx(default)]
    reset_generation: i32,
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
) -> Result<Json<GetMessagesOutput<'static>>, StatusCode> {
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
            let (messages, last_seq) =
                fetch_app_messages(&pool, did, &convo_id, since_seq, limit).await?;
            Ok(Json(GetMessagesOutput {
                messages,
                last_seq,
                gap_info: None,
                extra_data: Default::default(),
            }))
        }

        "commit" | "commits" => {
            let messages = fetch_commits(&pool, did, &convo_id, from_epoch, to_epoch).await?;
            Ok(Json(GetMessagesOutput {
                messages,
                last_seq: None,
                gap_info: None,
                extra_data: Default::default(),
            }))
        }

        "all" => {
            let (mut messages, last_seq) =
                fetch_app_messages(&pool, did, &convo_id, since_seq, limit).await?;
            let commits = fetch_commits(&pool, did, &convo_id, from_epoch, to_epoch).await?;
            messages.extend(commits);
            messages.sort_by(|a, b| a.epoch.cmp(&b.epoch).then(a.seq.cmp(&b.seq)));
            Ok(Json(GetMessagesOutput {
                messages,
                last_seq,
                gap_info: None,
                extra_data: Default::default(),
            }))
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
) -> Result<(Vec<MessageView<'static>>, Option<i64>), StatusCode> {
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
                   ciphertext, created_at, COALESCE(reset_generation, 0) as reset_generation
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
            error!(
                "❌ [v2.getMessages] Failed to fetch messages since seq: {}",
                e
            );
            StatusCode::INTERNAL_SERVER_ERROR
        })?
    } else {
        sqlx::query_as::<_, MessageRow>(
            r#"
            SELECT id, convo_id, message_type,
                   CAST(epoch AS BIGINT) as epoch, CAST(seq AS BIGINT) as seq,
                   ciphertext, created_at, COALESCE(reset_generation, 0) as reset_generation
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

    let message_views: Vec<MessageView<'static>> = messages
        .into_iter()
        .map(|m| {
            let mut extra = std::collections::BTreeMap::new();
            extra.insert(
                jacquard_common::smol_str::SmolStr::new("resetGeneration"),
                jacquard_common::types::value::Data::Integer(m.reset_generation as i64),
            );
            // Same legacy-row migration as fetch_commits below.
            let ct = crate::group_info::decode_legacy_if_needed(
                m.ciphertext,
                &format!("message-ciphertext[{}]", m.id),
            );
            MessageView {
                id: m.id.into(),
                convo_id: m.convo_id.into(),
                ciphertext: bytes::Bytes::from(ct),
                epoch: m.epoch,
                seq: m.seq,
                created_at: crate::sqlx_jacquard::chrono_to_datetime(m.created_at),
                message_type: Some(m.message_type.into()),
                extra_data: Some(extra),
            }
        })
        .collect();

    info!(
        "✅ [v2.getMessages] Fetched {} app messages",
        message_views.len()
    );

    Ok((message_views, last_seq))
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
) -> Result<Vec<MessageView<'static>>, StatusCode> {
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

    // `from_epoch == to_epoch + 1` (or higher) is the legitimate "caught up"
    // state — clients request `fromEpoch = localEpoch + 1` and hit this case
    // whenever they're already synced. Returning 400 forces every caught-up
    // client into a pointless error-backoff loop. Short-circuit with an
    // empty list instead; the CAS-authoritative `current_epoch` comes from
    // `conversations.current_epoch` above, so no race.
    if from_epoch > to_epoch {
        debug!(
            "[v2.getMessages] Client caught up (from={} > to={}), returning empty",
            from_epoch, to_epoch
        );
        return Ok(Vec::new());
    }
    // Keep the 400 path only for genuinely pathological requests where the
    // caller supplied an explicit `toEpoch` below `fromEpoch`.
    if to_epoch < 0 {
        warn!(
            "❌ [v2.getMessages] Invalid epoch range: {} to {}",
            from_epoch, to_epoch
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    // Cap commit fetches to prevent massive payloads.
    // Clients that are very far behind should rejoin via External Commit instead.
    const MAX_COMMITS: i64 = 50;

    let commits = sqlx::query_as::<_, MessageRow>(
        r#"
        SELECT id, convo_id, 'commit' as message_type,
               CAST(epoch AS BIGINT) as epoch, CAST(seq AS BIGINT) as seq,
               ciphertext, created_at, COALESCE(reset_generation, 0) as reset_generation
        FROM messages
        WHERE convo_id = $1 AND message_type = 'commit' AND epoch >= $2 AND epoch <= $3
        ORDER BY epoch ASC, seq ASC
        LIMIT $4
        "#,
    )
    .bind(convo_id)
    .bind(from_epoch)
    .bind(to_epoch)
    .bind(MAX_COMMITS)
    .fetch_all(pool)
    .await
    .map_err(|e| {
        error!("❌ [v2.getMessages] Failed to fetch commits: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!("✅ [v2.getMessages] Fetched {} commits", commits.len());

    let commit_views: Vec<MessageView<'static>> = commits
        .into_iter()
        .map(|c| {
            let mut extra = std::collections::BTreeMap::new();
            extra.insert(
                jacquard_common::smol_str::SmolStr::new("resetGeneration"),
                jacquard_common::types::value::Data::Integer(c.reset_generation as i64),
            );
            // Legacy-row migration: some pre-regen commits were stored as
            // base64 text (UTF-8 of the base64 alphabet) in the bytea column.
            // Detect and decode before emitting so clients see raw MLS wire.
            let ct = crate::group_info::decode_legacy_if_needed(
                c.ciphertext,
                &format!("commit-ciphertext[{}]", c.id),
            );
            MessageView {
                id: c.id.into(),
                convo_id: c.convo_id.into(),
                ciphertext: bytes::Bytes::from(ct),
                epoch: c.epoch,
                seq: c.seq,
                created_at: crate::sqlx_jacquard::chrono_to_datetime(c.created_at),
                message_type: Some(c.message_type.into()),
                extra_data: Some(extra),
            }
        })
        .collect();

    Ok(commit_views)
}
