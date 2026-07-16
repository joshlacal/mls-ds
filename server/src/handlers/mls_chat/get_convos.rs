use axum::{
    body::Body,
    extract::{RawQuery, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::Engine;
use chrono::{DateTime, SecondsFormat, Utc};
use futures::TryStreamExt;
use jacquard_axum::ExtractXrpc;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgConnection};
use std::{
    collections::HashMap,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use tracing::{error, info, warn};

use crate::{
    auth::AuthUser,
    generated::blue_catbird::mlsChat::get_convos::GetConvosRequest,
    models::{Conversation, Membership},
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.getConvos";
const MIB: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListingFilter {
    All,
    Expected,
}

impl ListingFilter {
    fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Expected => "expected",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct PagePolicy {
    max_cursor_bytes: usize,
    max_members: usize,
    max_raw_bytes: usize,
    max_json_bytes: usize,
    deadline: Duration,
}

impl Default for PagePolicy {
    fn default() -> Self {
        Self {
            max_cursor_bytes: 4 * 1024,
            max_members: 10_000,
            max_raw_bytes: 24 * MIB,
            max_json_bytes: 32 * MIB,
            deadline: Duration::from_secs(20),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListingError {
    BadRequest,
    PayloadTooLarge,
    Internal,
}

impl ListingError {
    fn status(self) -> StatusCode {
        match self {
            Self::BadRequest => StatusCode::BAD_REQUEST,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CursorPosition {
    joined_at: DateTime<Utc>,
    convo_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CursorWire {
    v: u8,
    f: String,
    j: String,
    c: String,
}

fn encode_cursor(filter: ListingFilter, position: &CursorPosition) -> Result<String, ListingError> {
    let wire = CursorWire {
        v: 1,
        f: filter.as_str().to_string(),
        j: position
            .joined_at
            .to_rfc3339_opts(SecondsFormat::Micros, true),
        c: position.convo_id.clone(),
    };
    let bytes = serde_json::to_vec(&wire).map_err(|_| ListingError::Internal)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

fn validate_generated_cursor(
    cursor: String,
    max_cursor_bytes: usize,
) -> Result<String, ListingError> {
    if cursor.len() > max_cursor_bytes {
        return Err(ListingError::PayloadTooLarge);
    }
    Ok(cursor)
}

fn decode_cursor(
    filter: ListingFilter,
    token: Option<&str>,
    max_cursor_bytes: usize,
) -> Result<Option<CursorPosition>, ListingError> {
    let Some(token) = token else {
        return Ok(None);
    };
    if token.len() > max_cursor_bytes {
        return Err(ListingError::BadRequest);
    }

    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| ListingError::BadRequest)?;
    let wire: CursorWire =
        serde_json::from_slice(&decoded).map_err(|_| ListingError::BadRequest)?;
    let canonical = serde_json::to_vec(&wire).map_err(|_| ListingError::BadRequest)?;
    if canonical != decoded || wire.v != 1 || wire.f != filter.as_str() || wire.c.is_empty() {
        return Err(ListingError::BadRequest);
    }

    let joined_at = DateTime::parse_from_rfc3339(&wire.j)
        .map_err(|_| ListingError::BadRequest)?
        .with_timezone(&Utc);
    if joined_at.to_rfc3339_opts(SecondsFormat::Micros, true) != wire.j {
        return Err(ListingError::BadRequest);
    }

    Ok(Some(CursorPosition {
        joined_at,
        convo_id: wire.c,
    }))
}

fn bounded_limit(limit: Option<i64>) -> usize {
    limit.unwrap_or(50).clamp(1, 100) as usize
}

#[derive(Debug, Clone, FromRow)]
struct ListingKey {
    convo_id: String,
    joined_at: DateTime<Utc>,
    last_message_at: Option<DateTime<Utc>>,
    member_count: i64,
    raw_bytes: i64,
}

impl ListingKey {
    fn position(&self) -> CursorPosition {
        CursorPosition {
            joined_at: self.joined_at,
            convo_id: self.convo_id.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PrefixSelection {
    count: usize,
    shortened: bool,
}

fn select_preflight_prefix(
    keys: &[ListingKey],
    page_limit: usize,
    policy: &PagePolicy,
) -> Result<PrefixSelection, ListingError> {
    let candidate_count = keys.len().min(page_limit);
    let mut selected = 0_usize;
    let mut members = 0_usize;
    let mut raw_bytes = 0_usize;

    for key in &keys[..candidate_count] {
        let key_members =
            usize::try_from(key.member_count).map_err(|_| ListingError::PayloadTooLarge)?;
        let key_raw = usize::try_from(key.raw_bytes).map_err(|_| ListingError::PayloadTooLarge)?;
        let next_members = members
            .checked_add(key_members)
            .ok_or(ListingError::PayloadTooLarge)?;
        let next_raw = raw_bytes
            .checked_add(key_raw)
            .ok_or(ListingError::PayloadTooLarge)?;

        if key_members > policy.max_members
            || key_raw > policy.max_raw_bytes
            || next_members > policy.max_members
            || next_raw > policy.max_raw_bytes
        {
            if selected == 0 {
                return Err(ListingError::PayloadTooLarge);
            }
            return Ok(PrefixSelection {
                count: selected,
                shortened: true,
            });
        }

        members = next_members;
        raw_bytes = next_raw;
        selected += 1;
    }

    Ok(PrefixSelection {
        count: selected,
        shortened: keys.len() > selected,
    })
}

#[derive(Debug)]
struct RenderedPage {
    body: Vec<u8>,
    emitted: usize,
    cursor: Option<String>,
}

fn render_json_page(
    conversations: &[Vec<u8>],
    keys: &[ListingKey],
    has_more: bool,
    filter: ListingFilter,
    max_cursor_bytes: usize,
    max_json_bytes: usize,
) -> Result<RenderedPage, ListingError> {
    if conversations.len() != keys.len() {
        return Err(ListingError::Internal);
    }
    if conversations.is_empty() {
        let body = br#"{"conversations":[]}"#.to_vec();
        if body.len() > max_json_bytes {
            return Err(ListingError::PayloadTooLarge);
        }
        return Ok(RenderedPage {
            body,
            emitted: 0,
            cursor: None,
        });
    }

    for emitted in (1..=conversations.len()).rev() {
        let more = has_more || emitted < conversations.len();
        let cursor = if more {
            let generated = validate_generated_cursor(
                encode_cursor(filter, &keys[emitted - 1].position())?,
                max_cursor_bytes,
            );
            match generated {
                Ok(cursor) => Some(cursor),
                Err(ListingError::PayloadTooLarge) => continue,
                Err(error) => return Err(error),
            }
        } else {
            None
        };
        let mut body = Vec::new();
        body.extend_from_slice(br#"{"conversations":["#);
        for (index, conversation) in conversations[..emitted].iter().enumerate() {
            if index > 0 {
                body.push(b',');
            }
            body.extend_from_slice(conversation);
        }
        body.push(b']');
        if let Some(ref cursor) = cursor {
            body.extend_from_slice(br#", "cursor":"#);
            serde_json::to_writer(&mut body, cursor).map_err(|_| ListingError::Internal)?;
        }
        body.push(b'}');

        if body.len() <= max_json_bytes {
            return Ok(RenderedPage {
                body,
                emitted,
                cursor,
            });
        }
    }

    Err(ListingError::PayloadTooLarge)
}

#[cfg(test)]
#[derive(Default)]
struct PreflightHook {
    reached: tokio::sync::Notify,
    resume: tokio::sync::Notify,
}

#[derive(Clone, Copy, Default)]
struct QueryTracker<'a> {
    counter: Option<&'a AtomicUsize>,
    #[cfg(test)]
    preflight_hook: Option<&'a PreflightHook>,
}

impl QueryTracker<'_> {
    fn record(self) {
        if let Some(counter) = self.counter {
            counter.fetch_add(1, Ordering::SeqCst);
        }
    }

    async fn after_preflight(self) {
        #[cfg(test)]
        if let Some(hook) = self.preflight_hook {
            hook.reached.notify_one();
            hook.resume.notified().await;
        }
    }
}

#[derive(Debug, FromRow)]
struct ConversationProjection {
    id: String,
    creator_did: String,
    current_epoch: i32,
    cipher_suite: Option<String>,
    created_at: DateTime<Utc>,
    confirmation_tag: Option<Vec<u8>>,
    sequencer_ds: Option<String>,
    group_id: Option<String>,
    reset_count: Option<i32>,
}

impl ConversationProjection {
    fn into_model(self) -> Conversation {
        Conversation {
            id: self.id,
            creator_did: self.creator_did,
            current_epoch: self.current_epoch,
            cipher_suite: self.cipher_suite,
            created_at: self.created_at,
            updated_at: self.created_at,
            confirmation_tag: self.confirmation_tag,
            sequencer_ds: self.sequencer_ds,
            is_remote: false,
            group_id: self.group_id,
            reset_count: self.reset_count,
            auto_reset_disabled_at: None,
        }
    }
}

#[derive(Debug, FromRow)]
struct RosterProjection {
    convo_id: String,
    member_did: String,
    user_did: Option<String>,
    device_id: Option<String>,
    device_name: Option<String>,
    joined_at: DateTime<Utc>,
    is_admin: bool,
    is_moderator: bool,
    leaf_index: Option<i32>,
    promoted_at: Option<DateTime<Utc>>,
    promoted_by_did: Option<String>,
}

impl RosterProjection {
    fn into_model(self) -> Membership {
        Membership {
            convo_id: self.convo_id,
            member_did: self.member_did,
            joined_at: self.joined_at,
            left_at: None,
            leaf_index: self.leaf_index,
            is_admin: self.is_admin,
            promoted_at: self.promoted_at,
            promoted_by_did: self.promoted_by_did,
            is_moderator: self.is_moderator,
            needs_rejoin: false,
            rejoin_requested_at: None,
            rejoin_key_package_hash: None,
            unread_count: 0,
            last_read_at: None,
            user_did: self.user_did,
            device_id: self.device_id,
            device_name: self.device_name,
            ds_did: None,
        }
    }
}

fn listing_keys_sql(filter: ListingFilter) -> &'static str {
    const ALL_SQL: &str = r#"
        WITH principal AS (
            SELECT m.convo_id, MAX(m.joined_at) AS joined_at
            FROM members m
            WHERE (m.user_did = $1 OR m.member_did = $1 OR split_part(m.member_did, '#', 1) = $1)
              AND m.left_at IS NULL
            GROUP BY m.convo_id
        ),
        candidate AS MATERIALIZED (
            SELECT c.id AS convo_id, p.joined_at
            FROM principal p
            JOIN conversations c ON c.id = p.convo_id
            WHERE c.id <> ''
              AND ($2::timestamptz IS NULL OR (p.joined_at, c.id) < ($2, $3))
            ORDER BY p.joined_at DESC, c.id DESC
            LIMIT $4
        )
        SELECT c.id AS convo_id, candidate.joined_at, activity.last_message_at,
               roster.member_count,
               (
                   octet_length(c.id)::bigint
                   + octet_length(c.creator_did)::bigint
                   + 4 + 8
                   + COALESCE(octet_length(c.cipher_suite), 0)::bigint
                   + COALESCE(octet_length(c.confirmation_tag), 0)::bigint
                   + COALESCE(octet_length(c.sequencer_ds), 0)::bigint
                   + COALESCE(octet_length(c.group_id), 0)::bigint
                   + CASE WHEN c.reset_count IS NULL THEN 0 ELSE 4 END
                   + CASE WHEN activity.last_message_at IS NULL THEN 0 ELSE 8 END
                   + roster.member_bytes
               )::bigint AS raw_bytes
        FROM candidate
        JOIN conversations c ON c.id = candidate.convo_id
        LEFT JOIN LATERAL (
            SELECT MAX(msg.created_at) AS last_message_at
            FROM messages msg
            WHERE msg.convo_id = c.id
        ) activity ON true
        JOIN LATERAL (
            SELECT COUNT(*)::bigint AS member_count,
                   COALESCE(SUM(
                       octet_length(rm.convo_id)::bigint
                       + octet_length(rm.member_did)::bigint
                       + COALESCE(octet_length(rm.user_did), 0)::bigint
                       + COALESCE(octet_length(rm.device_id), 0)::bigint
                       + COALESCE(octet_length(rm.device_name), 0)::bigint
                       + 8 + 1 + 1
                       + CASE WHEN rm.leaf_index IS NULL THEN 0 ELSE 4 END
                       + CASE WHEN rm.promoted_at IS NULL THEN 0 ELSE 8 END
                       + COALESCE(octet_length(rm.promoted_by_did), 0)::bigint
                   ), 0)::bigint AS member_bytes
            FROM (
                SELECT m2.convo_id, m2.member_did, m2.user_did, m2.device_id,
                       m2.device_name, m2.joined_at, m2.is_admin,
                       COALESCE(m2.is_moderator, false) AS is_moderator,
                       m2.leaf_index, m2.promoted_at, m2.promoted_by_did
                FROM members m2
                WHERE m2.convo_id = c.id AND m2.left_at IS NULL
                LIMIT 10001
            ) rm
        ) roster ON true
        ORDER BY candidate.joined_at DESC, c.id DESC
    "#;
    const EXPECTED_SQL: &str = r#"
        WITH principal AS (
            SELECT m.convo_id, MAX(m.joined_at) AS joined_at
            FROM members m
            WHERE m.user_did = $1 AND m.left_at IS NULL
            GROUP BY m.convo_id
        ),
        candidate AS MATERIALIZED (
            SELECT c.id AS convo_id, p.joined_at
            FROM principal p
            JOIN conversations c ON c.id = p.convo_id
            WHERE c.id <> ''
              AND ($2::timestamptz IS NULL OR (p.joined_at, c.id) < ($2, $3))
            ORDER BY p.joined_at DESC, c.id DESC
            LIMIT $4
        )
        SELECT c.id AS convo_id, candidate.joined_at, activity.last_message_at,
               roster.member_count,
               (
                   octet_length(c.id)::bigint
                   + octet_length(c.creator_did)::bigint
                   + 4 + 8
                   + COALESCE(octet_length(c.cipher_suite), 0)::bigint
                   + COALESCE(octet_length(c.confirmation_tag), 0)::bigint
                   + COALESCE(octet_length(c.sequencer_ds), 0)::bigint
                   + COALESCE(octet_length(c.group_id), 0)::bigint
                   + CASE WHEN c.reset_count IS NULL THEN 0 ELSE 4 END
                   + CASE WHEN activity.last_message_at IS NULL THEN 0 ELSE 8 END
                   + roster.member_bytes
               )::bigint AS raw_bytes
        FROM candidate
        JOIN conversations c ON c.id = candidate.convo_id
        LEFT JOIN LATERAL (
            SELECT MAX(msg.created_at) AS last_message_at
            FROM messages msg
            WHERE msg.convo_id = c.id
        ) activity ON true
        JOIN LATERAL (
            SELECT COUNT(*)::bigint AS member_count,
                   COALESCE(SUM(
                       octet_length(rm.convo_id)::bigint
                       + octet_length(rm.member_did)::bigint
                       + COALESCE(octet_length(rm.user_did), 0)::bigint
                       + COALESCE(octet_length(rm.device_id), 0)::bigint
                       + COALESCE(octet_length(rm.device_name), 0)::bigint
                       + 8 + 1 + 1
                       + CASE WHEN rm.leaf_index IS NULL THEN 0 ELSE 4 END
                       + CASE WHEN rm.promoted_at IS NULL THEN 0 ELSE 8 END
                       + COALESCE(octet_length(rm.promoted_by_did), 0)::bigint
                   ), 0)::bigint AS member_bytes
            FROM (
                SELECT m2.convo_id, m2.member_did, m2.user_did, m2.device_id,
                       m2.device_name, m2.joined_at, m2.is_admin,
                       COALESCE(m2.is_moderator, false) AS is_moderator,
                       m2.leaf_index, m2.promoted_at, m2.promoted_by_did
                FROM members m2
                WHERE m2.convo_id = c.id AND m2.left_at IS NULL
                LIMIT 10001
            ) rm
        ) roster ON true
        ORDER BY candidate.joined_at DESC, c.id DESC
    "#;

    match filter {
        ListingFilter::All => ALL_SQL,
        ListingFilter::Expected => EXPECTED_SQL,
    }
}

async fn fetch_listing_keys(
    connection: &mut PgConnection,
    principal_did: &str,
    filter: ListingFilter,
    cursor: Option<&CursorPosition>,
    fetch_limit: usize,
    tracker: QueryTracker<'_>,
) -> Result<Vec<ListingKey>, ListingError> {
    tracker.record();
    let cursor_time = cursor.map(|value| value.joined_at);
    let cursor_id = cursor.map(|value| value.convo_id.as_str());
    sqlx::query_as::<_, ListingKey>(listing_keys_sql(filter))
        .bind(principal_did)
        .bind(cursor_time)
        .bind(cursor_id)
        .bind(i64::try_from(fetch_limit).map_err(|_| ListingError::Internal)?)
        .fetch_all(&mut *connection)
        .await
        .map_err(|e| {
            error!("❌ [v2.getConvos] bounded key query failed: {}", e);
            ListingError::Internal
        })
}

async fn fetch_conversation_projections(
    connection: &mut PgConnection,
    ids: &[String],
    tracker: QueryTracker<'_>,
) -> Result<Vec<ConversationProjection>, ListingError> {
    tracker.record();
    sqlx::query_as::<_, ConversationProjection>(
        r#"
        SELECT c.id, c.creator_did, c.current_epoch, c.cipher_suite, c.created_at,
               c.confirmation_tag, c.sequencer_ds, c.group_id, c.reset_count
        FROM conversations c
        WHERE c.id = ANY($1::text[])
        ORDER BY array_position($1::text[], c.id)
        "#,
    )
    .bind(ids)
    .fetch_all(&mut *connection)
    .await
    .map_err(|e| {
        error!("❌ [v2.getConvos] bounded conversation query failed: {}", e);
        ListingError::Internal
    })
}

async fn fetch_roster_projections(
    connection: &mut PgConnection,
    ids: &[String],
    initial_raw_bytes: usize,
    max_members: usize,
    max_raw_bytes: usize,
    tracker: QueryTracker<'_>,
) -> Result<Vec<RosterProjection>, ListingError> {
    tracker.record();
    let mut rows = sqlx::query_as::<_, RosterProjection>(
        r#"
        SELECT m.convo_id, m.member_did, m.user_did, m.device_id, m.device_name,
               m.joined_at, m.is_admin,
               COALESCE(m.is_moderator, false) AS is_moderator,
               m.leaf_index, m.promoted_at, m.promoted_by_did
        FROM members m
        WHERE m.convo_id = ANY($1::text[]) AND m.left_at IS NULL
        ORDER BY array_position($1::text[], m.convo_id), m.user_did, m.joined_at, m.member_did
        "#,
    )
    .bind(ids)
    .fetch(&mut *connection);
    let mut retained = Vec::new();
    let mut retained_raw_bytes = initial_raw_bytes;
    while let Some(row) = rows.try_next().await.map_err(|e| {
        error!("❌ [v2.getConvos] bounded roster query failed: {}", e);
        ListingError::Internal
    })? {
        let next_raw_bytes = retained_raw_bytes
            .checked_add(roster_projection_bytes(&row))
            .ok_or(ListingError::PayloadTooLarge)?;
        if retained.len() >= max_members || next_raw_bytes > max_raw_bytes {
            return Err(ListingError::PayloadTooLarge);
        }
        retained_raw_bytes = next_raw_bytes;
        retained.push(row);
    }
    Ok(retained)
}

fn conversation_projection_bytes(value: &ConversationProjection) -> usize {
    value.id.len()
        + value.creator_did.len()
        + 4
        + 8
        + value.cipher_suite.as_ref().map_or(0, String::len)
        + value.confirmation_tag.as_ref().map_or(0, Vec::len)
        + value.sequencer_ds.as_ref().map_or(0, String::len)
        + value.group_id.as_ref().map_or(0, String::len)
        + value.reset_count.map_or(0, |_| 4)
}

fn take_projection_activity<T>(
    projections: &mut HashMap<String, T>,
    key: &ListingKey,
) -> Result<(T, Option<DateTime<Utc>>), ListingError> {
    let projection = projections
        .remove(&key.convo_id)
        .ok_or(ListingError::Internal)?;
    Ok((projection, key.last_message_at))
}

fn roster_projection_bytes(value: &RosterProjection) -> usize {
    value.convo_id.len()
        + value.member_did.len()
        + value.user_did.as_ref().map_or(0, String::len)
        + value.device_id.as_ref().map_or(0, String::len)
        + value.device_name.as_ref().map_or(0, String::len)
        + 8
        + 1
        + 1
        + value.leaf_index.map_or(0, |_| 4)
        + value.promoted_at.map_or(0, |_| 8)
        + value.promoted_by_did.as_ref().map_or(0, String::len)
}

async fn load_bounded_listing(
    pool: &DbPool,
    principal_did: &str,
    filter: ListingFilter,
    cursor: Option<&CursorPosition>,
    limit: usize,
    policy: &PagePolicy,
    tracker: QueryTracker<'_>,
) -> Result<Response, ListingError> {
    let mut transaction = pool.begin().await.map_err(|e| {
        error!("❌ [v2.getConvos] failed to begin bounded read transaction: {e}");
        ListingError::Internal
    })?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await
        .map_err(|e| {
            error!("❌ [v2.getConvos] failed to configure bounded read transaction: {e}");
            ListingError::Internal
        })?;
    let keys = fetch_listing_keys(
        &mut transaction,
        principal_did,
        filter,
        cursor,
        limit.saturating_add(1).min(101),
        tracker,
    )
    .await?;

    if keys.is_empty() {
        let rendered = render_json_page(
            &[],
            &[],
            false,
            filter,
            policy.max_cursor_bytes,
            policy.max_json_bytes,
        )?;
        transaction.commit().await.map_err(|e| {
            error!("❌ [v2.getConvos] failed to commit empty bounded read: {e}");
            ListingError::Internal
        })?;
        return response_from_rendered(rendered);
    }

    tracker.after_preflight().await;

    let selection = select_preflight_prefix(&keys, limit, policy)?;
    let selected_keys = &keys[..selection.count];
    let ids: Vec<String> = selected_keys
        .iter()
        .map(|key| key.convo_id.clone())
        .collect();
    let conversations = fetch_conversation_projections(&mut transaction, &ids, tracker).await?;
    let conversation_raw_bytes = conversations
        .iter()
        .try_fold(0usize, |total, conversation| {
            total
                .checked_add(conversation_projection_bytes(conversation))
                .ok_or(ListingError::PayloadTooLarge)
        })?
        .checked_add(
            selected_keys
                .iter()
                .filter(|key| key.last_message_at.is_some())
                .count()
                .checked_mul(8)
                .ok_or(ListingError::PayloadTooLarge)?,
        )
        .ok_or(ListingError::PayloadTooLarge)?;
    if conversation_raw_bytes > policy.max_raw_bytes {
        return Err(ListingError::PayloadTooLarge);
    }
    let rosters = fetch_roster_projections(
        &mut transaction,
        &ids,
        conversation_raw_bytes,
        policy.max_members,
        policy.max_raw_bytes,
        tracker,
    )
    .await?;

    let mut conversations_by_id: HashMap<String, ConversationProjection> = conversations
        .into_iter()
        .map(|conversation| (conversation.id.clone(), conversation))
        .collect();
    let mut rosters_by_id: HashMap<String, Vec<RosterProjection>> = HashMap::new();
    for roster in rosters {
        rosters_by_id
            .entry(roster.convo_id.clone())
            .or_default()
            .push(roster);
    }

    let mut serialized_conversations = Vec::with_capacity(selected_keys.len());
    let local_ds_did = crate::identity::service_did_base_opt();
    for key in selected_keys {
        let (projection, last_message_at) =
            take_projection_activity(&mut conversations_by_id, key)?;
        let roster = rosters_by_id.remove(&key.convo_id).unwrap_or_default();
        if i64::try_from(roster.len()).map_err(|_| ListingError::Internal)? != key.member_count {
            return Err(ListingError::Internal);
        }
        let actual_raw = conversation_projection_bytes(&projection)
            .checked_add(last_message_at.map_or(0, |_| 8))
            .ok_or(ListingError::PayloadTooLarge)?
            .checked_add(roster.iter().map(roster_projection_bytes).sum::<usize>())
            .ok_or(ListingError::PayloadTooLarge)?;
        if i64::try_from(actual_raw).map_err(|_| ListingError::PayloadTooLarge)? != key.raw_bytes {
            return Err(ListingError::Internal);
        }

        let members = roster
            .into_iter()
            .map(|member| {
                member
                    .into_model()
                    .to_member_view()
                    .map_err(|_| ListingError::Internal)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let view = projection
            .into_model()
            .to_convo_view_with_last_message_at(members, local_ds_did.as_deref(), last_message_at)
            .map_err(|_| ListingError::Internal)?;
        serialized_conversations
            .push(serde_json::to_vec(&view).map_err(|_| ListingError::Internal)?);
    }

    if !conversations_by_id.is_empty() || !rosters_by_id.is_empty() {
        return Err(ListingError::Internal);
    }

    let rendered = render_json_page(
        &serialized_conversations,
        selected_keys,
        selection.shortened,
        filter,
        policy.max_cursor_bytes,
        policy.max_json_bytes,
    )?;
    transaction.commit().await.map_err(|e| {
        error!("❌ [v2.getConvos] failed to commit bounded read: {e}");
        ListingError::Internal
    })?;
    response_from_rendered(rendered)
}

fn response_from_rendered(rendered: RenderedPage) -> Result<Response, ListingError> {
    let RenderedPage {
        body,
        emitted,
        cursor,
    } = rendered;
    info!(
        emitted,
        has_cursor = cursor.is_some(),
        "✅ [v2.getConvos] bounded conversation page"
    );
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .map_err(|_| ListingError::Internal)
}

async fn bounded_listing_response(
    pool: &DbPool,
    principal_did: &str,
    filter: ListingFilter,
    cursor_token: Option<&str>,
    limit: Option<i64>,
    policy: PagePolicy,
    tracker: QueryTracker<'_>,
) -> Result<Response, StatusCode> {
    match tokio::time::timeout(policy.deadline, async {
        let cursor = decode_cursor(filter, cursor_token, policy.max_cursor_bytes)?;
        load_bounded_listing(
            pool,
            principal_did,
            filter,
            cursor.as_ref(),
            bounded_limit(limit),
            &policy,
            tracker,
        )
        .await
    })
    .await
    {
        Ok(Ok(response)) => Ok(response),
        Ok(Err(error)) => Err(error.status()),
        Err(_) => Err(StatusCode::GATEWAY_TIMEOUT),
    }
}

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

    let cursor = params.cursor.map(|value| value.to_string());
    let limit = params.limit;

    match filter {
        "all" => {
            bounded_listing_response(
                &pool,
                did,
                ListingFilter::All,
                cursor.as_deref(),
                limit,
                PagePolicy::default(),
                QueryTracker::default(),
            )
            .await
        }
        "pending" => {
            let status = status.unwrap_or_else(|| "pending".to_string());
            Ok(handle_pending(&pool, did, cursor, limit, &status)
                .await?
                .into_response())
        }
        "expected" => {
            let _device_id =
                device_id.or_else(|| did.split_once('#').map(|(_, value)| value.into()));
            let base_did = did.split('#').next().unwrap_or(did);
            bounded_listing_response(
                &pool,
                base_did,
                ListingFilter::Expected,
                cursor.as_deref(),
                limit,
                PagePolicy::default(),
                QueryTracker::default(),
            )
            .await
        }
        other => {
            error!("❌ [v2.getConvos] Unknown filter: {}", other);
            Err(StatusCode::BAD_REQUEST)
        }
    }
}

// ---------------------------------------------------------------------------
// filter="all" — inline of v1 get_convos
// ---------------------------------------------------------------------------

#[cfg(test)]
async fn handle_all(
    pool: &DbPool,
    did: &str,
) -> Result<
    Json<crate::generated::blue_catbird::mlsChat::get_convos::GetConvosOutput<'static>>,
    StatusCode,
> {
    let response = bounded_listing_response(
        pool,
        did,
        ListingFilter::All,
        None,
        Some(100),
        PagePolicy::default(),
        QueryTracker::default(),
    )
    .await?;
    let body = axum::body::to_bytes(response.into_body(), 32 * MIB)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let output: crate::generated::blue_catbird::mlsChat::get_convos::GetConvosOutput<'_> =
        serde_json::from_slice(&body).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(jacquard_common::IntoStatic::into_static(output)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use sqlx::{postgres::PgPoolOptions, PgPool};
    use std::collections::BTreeSet;
    use std::time::Duration;

    fn listing_key(
        convo_id: &str,
        joined_at: DateTime<Utc>,
        member_count: i64,
        raw_bytes: i64,
    ) -> ListingKey {
        ListingKey {
            convo_id: convo_id.to_string(),
            joined_at,
            last_message_at: None,
            member_count,
            raw_bytes,
        }
    }

    #[test]
    fn bounded_cursor_round_trips_and_binds_filter_time_and_version() {
        let joined_at = DateTime::parse_from_rfc3339("2026-07-15T12:34:56.123456Z")
            .unwrap()
            .with_timezone(&Utc);
        let position = CursorPosition {
            joined_at,
            convo_id: "convo-z".to_string(),
        };

        for filter in [ListingFilter::All, ListingFilter::Expected] {
            let token = encode_cursor(filter, &position).unwrap();
            assert!(!token.contains('='));
            assert_eq!(
                decode_cursor(filter, Some(&token), 4096).unwrap(),
                Some(position.clone())
            );
        }

        let all_token = encode_cursor(ListingFilter::All, &position).unwrap();
        assert!(matches!(
            decode_cursor(ListingFilter::Expected, Some(&all_token), 4096),
            Err(ListingError::BadRequest)
        ));
    }

    #[test]
    fn selected_key_activity_is_bound_by_conversation_id_not_projection_order() {
        let joined_at = Utc::now();
        let activity_a = joined_at + chrono::Duration::minutes(1);
        let activity_b = joined_at + chrono::Duration::minutes(2);
        let key_a = ListingKey {
            convo_id: "a".to_string(),
            joined_at,
            member_count: 1,
            raw_bytes: 1,
            last_message_at: Some(activity_a),
        };
        let key_b = ListingKey {
            convo_id: "b".to_string(),
            joined_at,
            member_count: 1,
            raw_bytes: 1,
            last_message_at: Some(activity_b),
        };
        let mut projections = HashMap::from([
            ("b".to_string(), "projection-b"),
            ("a".to_string(), "projection-a"),
        ]);

        assert_eq!(
            take_projection_activity(&mut projections, &key_a).unwrap(),
            ("projection-a", Some(activity_a))
        );
        assert_eq!(
            take_projection_activity(&mut projections, &key_b).unwrap(),
            ("projection-b", Some(activity_b))
        );
        assert!(projections.is_empty());
    }

    #[test]
    fn bounded_cursor_rejects_malformed_oversized_noncanonical_and_invalid_fields() {
        fn token(json: &str) -> String {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json)
        }

        let invalid = [
            "not-base64!".to_string(),
            token(r#"{"v":2,"f":"all","j":"2026-07-15T12:34:56.123456Z","c":"c"}"#),
            token(r#"{"v":1,"f":"all","j":"2026-07-15T12:34:56Z","c":"c"}"#),
            token(r#"{"v":1,"f":"all","j":"2026-07-15T12:34:56.123456+00:00","c":"c"}"#),
            token(r#"{"v":1,"f":"all","j":"invalid","c":"c"}"#),
            token(r#"{"v":1,"f":"all","j":"2026-07-15T12:34:56.123456Z","c":""}"#),
            token(r#"{"v":1,"f":"all","j":"2026-07-15T12:34:56.123456Z","c":"c","x":1}"#),
            token(r#" {"v":1,"f":"all","j":"2026-07-15T12:34:56.123456Z","c":"c"}"#),
            token(r#"{"v":1,"f":"all","j":"2026-07-15T12:34:56.123456Z","c":"c"} "#),
            token(r#"{"v":1,"f":"all","j":"2026-07-15T12:34:56.123456Z","c":"c"}{}"#),
            "a".repeat(4097),
        ];

        for value in invalid {
            assert!(matches!(
                decode_cursor(ListingFilter::All, Some(&value), 4096),
                Err(ListingError::BadRequest)
            ));
        }
    }

    #[test]
    fn generated_cursor_enforces_exact_wire_ceiling() {
        assert_eq!(
            validate_generated_cursor("x".repeat(4096), 4096)
                .unwrap()
                .len(),
            4096
        );
        assert!(matches!(
            validate_generated_cursor("x".repeat(4097), 4096),
            Err(ListingError::PayloadTooLarge)
        ));

        let joined_at = DateTime::parse_from_rfc3339("2026-07-15T12:34:56.123456Z")
            .unwrap()
            .with_timezone(&Utc);
        let key_for_cursor_len = |mut wanted: std::ops::RangeInclusive<usize>| {
            wanted
                .find_map(|convo_id_len| {
                    let key = listing_key(&"c".repeat(convo_id_len), joined_at, 1, 1);
                    let len = encode_cursor(ListingFilter::All, &key.position())
                        .unwrap()
                        .len();
                    (len >= 4096).then_some((key, len))
                })
                .unwrap()
        };
        let (exact_key, exact_len) = key_for_cursor_len(1..=4096);
        assert_eq!(exact_len, 4096);
        let exact = render_json_page(
            &[br#"{\"conversationId\":\"a\"}"#.to_vec()],
            &[exact_key],
            true,
            ListingFilter::All,
            4096,
            usize::MAX,
        )
        .unwrap();
        assert_eq!(exact.cursor.unwrap().len(), 4096);

        let oversized_key = listing_key(&"c".repeat(4096), joined_at, 1, 1);
        assert!(matches!(
            render_json_page(
                &[br#"{\"conversationId\":\"a\"}"#.to_vec()],
                &[oversized_key],
                true,
                ListingFilter::All,
                4096,
                usize::MAX,
            ),
            Err(ListingError::PayloadTooLarge)
        ));

        let earlier_key = listing_key("a", joined_at, 1, 1);
        let shortened = render_json_page(
            &[
                br#"{\"conversationId\":\"a\"}"#.to_vec(),
                br#"{\"conversationId\":\"oversized\"}"#.to_vec(),
            ],
            &[earlier_key, listing_key(&"c".repeat(4096), joined_at, 1, 1)],
            true,
            ListingFilter::All,
            4096,
            usize::MAX,
        )
        .unwrap();
        assert_eq!(shortened.emitted, 1);
        assert!(shortened.cursor.unwrap().len() <= 4096);
    }

    #[test]
    fn page_limit_and_preflight_budgets_use_complete_conversation_prefixes() {
        assert_eq!(bounded_limit(None), 50);
        assert_eq!(bounded_limit(Some(-5)), 1);
        assert_eq!(bounded_limit(Some(500)), 100);

        let joined_at = Utc::now();
        let policy = PagePolicy::default();
        let exact_members = vec![listing_key("a", joined_at, 10_000, 1)];
        assert_eq!(
            select_preflight_prefix(&exact_members, 100, &policy).unwrap(),
            PrefixSelection {
                count: 1,
                shortened: false
            }
        );

        let next_member_deferred = vec![
            listing_key("a", joined_at, 10_000, 1),
            listing_key("b", joined_at, 1, 1),
        ];
        assert_eq!(
            select_preflight_prefix(&next_member_deferred, 100, &policy).unwrap(),
            PrefixSelection {
                count: 1,
                shortened: true
            }
        );
        assert!(matches!(
            select_preflight_prefix(&[listing_key("a", joined_at, 10_001, 1)], 100, &policy),
            Err(ListingError::PayloadTooLarge)
        ));

        let exact_raw = vec![listing_key("a", joined_at, 1, policy.max_raw_bytes as i64)];
        assert_eq!(
            select_preflight_prefix(&exact_raw, 100, &policy)
                .unwrap()
                .count,
            1
        );
        assert!(matches!(
            select_preflight_prefix(
                &[listing_key(
                    "a",
                    joined_at,
                    1,
                    policy.max_raw_bytes as i64 + 1
                )],
                100,
                &policy
            ),
            Err(ListingError::PayloadTooLarge)
        ));
        let next_raw_deferred = vec![
            listing_key("a", joined_at, 1, policy.max_raw_bytes as i64),
            listing_key("b", joined_at, 1, 1),
        ];
        assert_eq!(
            select_preflight_prefix(&next_raw_deferred, 100, &policy).unwrap(),
            PrefixSelection {
                count: 1,
                shortened: true
            }
        );
    }

    #[test]
    fn direct_json_renderer_enforces_exact_serialized_boundary_without_truncation() {
        let joined_at = DateTime::parse_from_rfc3339("2026-07-15T12:34:56.123456Z")
            .unwrap()
            .with_timezone(&Utc);
        let key = listing_key("a", joined_at, 1, 1);
        let envelope_bytes = br#"{"conversations":[]}"#.len();
        let object_overhead = br#"{"x":""}"#.len();
        let payload_len = (32 * 1024 * 1024) - envelope_bytes - object_overhead;
        let conversation = format!(r#"{{"x":"{}"}}"#, "x".repeat(payload_len)).into_bytes();

        let exact = render_json_page(
            std::slice::from_ref(&conversation),
            std::slice::from_ref(&key),
            false,
            ListingFilter::All,
            4096,
            32 * 1024 * 1024,
        )
        .unwrap();
        assert_eq!(exact.body.len(), 32 * 1024 * 1024);
        assert_eq!(exact.emitted, 1);
        assert!(exact.cursor.is_none());

        assert!(matches!(
            render_json_page(
                &[conversation],
                &[key],
                false,
                ListingFilter::All,
                4096,
                (32 * 1024 * 1024) - 1,
            ),
            Err(ListingError::PayloadTooLarge)
        ));

        let small_keys = vec![
            listing_key("a", joined_at, 1, 1),
            listing_key("b", joined_at - chrono::Duration::microseconds(1), 1, 1),
        ];
        let small_conversations = vec![
            format!(r#"{{"id":"a","padding":"{}"}}"#, "a".repeat(256)).into_bytes(),
            format!(r#"{{"id":"b","padding":"{}"}}"#, "b".repeat(256)).into_bytes(),
        ];
        let full = render_json_page(
            &small_conversations,
            &small_keys,
            false,
            ListingFilter::All,
            4096,
            usize::MAX,
        )
        .unwrap();
        let shortened = render_json_page(
            &small_conversations,
            &small_keys,
            false,
            ListingFilter::All,
            4096,
            full.body.len() - 1,
        )
        .unwrap();
        assert_eq!(shortened.emitted, 1);
        assert!(shortened.cursor.is_some());
        let parsed: serde_json::Value = serde_json::from_slice(&shortened.body).unwrap();
        assert_eq!(parsed["conversations"].as_array().unwrap().len(), 1);
    }

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

    async fn cleanup_test_prefix(pool: &PgPool, prefix: &str) {
        let pattern = format!("{prefix}%");
        let _ = sqlx::query("DELETE FROM messages WHERE convo_id LIKE $1")
            .bind(&pattern)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM members WHERE convo_id LIKE $1")
            .bind(&pattern)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM conversations WHERE id LIKE $1")
            .bind(&pattern)
            .execute(pool)
            .await;
    }

    fn relation_actual_loops(plan: &serde_json::Value, relation: &str, loops: &mut Vec<u64>) {
        if plan["Relation Name"].as_str() == Some(relation) {
            loops.push(
                plan["Actual Loops"]
                    .as_u64()
                    .expect("EXPLAIN ANALYZE relation node has Actual Loops"),
            );
        }
        if let Some(children) = plan["Plans"].as_array() {
            for child in children {
                relation_actual_loops(child, relation, loops);
            }
        }
    }

    #[tokio::test]
    #[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
    async fn key_query_bounds_lateral_roster_and_message_work_to_candidate_page() {
        let pool = setup_test_db().await;
        let prefix = format!("get-convos-plan-{}-", uuid::Uuid::new_v4());
        let did = format!("did:plc:getconvosplan{}", uuid::Uuid::new_v4().simple());
        let joined_at = Utc::now();
        let conversation_count = 40_i32;
        let page_limit = 1_i64;
        let fetch_limit = page_limit + 1;
        assert!(i64::from(conversation_count) > fetch_limit);
        cleanup_test_prefix(&pool, &prefix).await;

        sqlx::query(
            r#"
            INSERT INTO conversations
                (id, creator_did, current_epoch, created_at, updated_at, cipher_suite,
                 is_remote, group_id)
            SELECT $1 || lpad(gs::text, 3, '0'), $2, 1,
                   $3 - make_interval(secs => gs),
                   $3 - make_interval(secs => gs), $4, false,
                   $1 || lpad(gs::text, 3, '0')
            FROM generate_series(1, $5) gs
            "#,
        )
        .bind(&prefix)
        .bind(&did)
        .bind(joined_at)
        .bind("MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519")
        .bind(conversation_count)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            r#"
            INSERT INTO members
                (convo_id, member_did, user_did, joined_at, is_admin)
            SELECT id, $2 || '#principal', $2, created_at, true
            FROM conversations WHERE id LIKE $1
            UNION ALL
            SELECT id, $3 || id, $3 || id, created_at, false
            FROM conversations WHERE id LIKE $1
            "#,
        )
        .bind(format!("{prefix}%"))
        .bind(&did)
        .bind("did:plc:roster-")
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            r#"
            INSERT INTO messages
                (id, convo_id, sender_did, message_type, epoch, wire_epoch, seq,
                 ciphertext, msg_id, padded_size, created_at)
            SELECT id || '-message', id, NULL, 'app', 1, 1, 1,
                   decode('ca7b1d', 'hex'), id || '-msg', 512, created_at
            FROM conversations WHERE id LIKE $1
            "#,
        )
        .bind(format!("{prefix}%"))
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("ANALYZE conversations, members, messages")
            .execute(&pool)
            .await
            .unwrap();

        for filter in [ListingFilter::All, ListingFilter::Expected] {
            let explain = format!(
                "EXPLAIN (ANALYZE, FORMAT JSON) {}",
                listing_keys_sql(filter)
            );
            let document: serde_json::Value = sqlx::query_scalar(&explain)
                .bind(&did)
                .bind(Option::<DateTime<Utc>>::None)
                .bind(Option::<String>::None)
                .bind(fetch_limit)
                .fetch_one(&pool)
                .await
                .unwrap();
            let plan = &document[0]["Plan"];
            let mut roster_loops = Vec::new();
            let mut message_loops = Vec::new();
            relation_actual_loops(plan, "members", &mut roster_loops);
            relation_actual_loops(plan, "messages", &mut message_loops);

            assert!(
                !roster_loops.is_empty(),
                "members plan node missing: {plan}"
            );
            assert!(
                !message_loops.is_empty(),
                "messages plan node missing: {plan}"
            );
            assert!(
                roster_loops.iter().copied().max().unwrap() <= fetch_limit as u64,
                "{filter:?} roster work exceeded bounded candidate page: {roster_loops:?}"
            );
            assert!(
                message_loops.iter().copied().max().unwrap() <= fetch_limit as u64,
                "{filter:?} message work exceeded bounded candidate page: {message_loops:?}"
            );
        }

        cleanup_test_prefix(&pool, &prefix).await;
    }

    async fn listing_json(
        pool: &PgPool,
        did: &str,
        filter: ListingFilter,
        cursor: Option<&str>,
        limit: Option<i64>,
        policy: PagePolicy,
        counter: Option<&AtomicUsize>,
    ) -> Result<serde_json::Value, StatusCode> {
        let response = bounded_listing_response(
            pool,
            did,
            filter,
            cursor,
            limit,
            policy,
            QueryTracker {
                counter,
                ..QueryTracker::default()
            },
        )
        .await?;
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        let body = axum::body::to_bytes(response.into_body(), 32 * MIB)
            .await
            .expect("bounded body");
        serde_json::from_slice(&body).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    }

    fn conversation_ids(value: &serde_json::Value) -> Vec<String> {
        value["conversations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|conversation| conversation["conversationId"].as_str().unwrap().to_string())
            .collect()
    }

    #[tokio::test]
    #[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
    async fn bounded_all_and_expected_paginate_101_unique_equal_timestamp_conversations() {
        let pool = setup_test_db().await;
        let prefix = format!("get-convos-page-{}-", uuid::Uuid::new_v4());
        let did = "did:plc:getconvospagination";
        let joined_at = DateTime::parse_from_rfc3339("2026-07-15T10:00:00.123456Z")
            .unwrap()
            .with_timezone(&Utc);
        cleanup_test_prefix(&pool, &prefix).await;

        sqlx::query(
            r#"
            INSERT INTO conversations
                (id, creator_did, current_epoch, created_at, updated_at, cipher_suite,
                 is_remote, group_id)
            SELECT $1 || lpad(gs::text, 3, '0'), $2, 1, $3, $3, $4, false,
                   $1 || lpad(gs::text, 3, '0')
            FROM generate_series(0, 100) gs
            "#,
        )
        .bind(&prefix)
        .bind(did)
        .bind(joined_at)
        .bind("MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519")
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            r#"
            INSERT INTO members (convo_id, member_did, user_did, joined_at, is_admin)
            SELECT id, $2, $2, $3, true FROM conversations WHERE id LIKE $1
            "#,
        )
        .bind(format!("{prefix}%"))
        .bind(did)
        .bind(joined_at)
        .execute(&pool)
        .await
        .unwrap();

        for filter in [ListingFilter::All, ListingFilter::Expected] {
            let first_counter = AtomicUsize::new(0);
            let first = listing_json(
                &pool,
                did,
                filter,
                None,
                Some(100),
                PagePolicy::default(),
                Some(&first_counter),
            )
            .await
            .unwrap();
            assert_eq!(first_counter.load(Ordering::SeqCst), 3);
            let first_ids = conversation_ids(&first);
            assert_eq!(first_ids.len(), 100);
            assert_eq!(first_ids[0], format!("{prefix}100"));
            assert_eq!(first_ids[99], format!("{prefix}001"));
            let cursor = first["cursor"].as_str().expect("first page cursor");

            let second_counter = AtomicUsize::new(0);
            let second = listing_json(
                &pool,
                did,
                filter,
                Some(cursor),
                Some(100),
                PagePolicy::default(),
                Some(&second_counter),
            )
            .await
            .unwrap();
            assert_eq!(second_counter.load(Ordering::SeqCst), 3);
            assert!(second.get("cursor").is_none());
            let second_ids = conversation_ids(&second);
            assert_eq!(second_ids, vec![format!("{prefix}000")]);

            let first_set: BTreeSet<_> = first_ids.into_iter().collect();
            let second_set: BTreeSet<_> = second_ids.into_iter().collect();
            assert!(first_set.is_disjoint(&second_set));
            assert_eq!(first_set.union(&second_set).count(), 101);
        }

        cleanup_test_prefix(&pool, &prefix).await;
    }

    #[tokio::test]
    #[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
    async fn bounded_pipeline_deduplicates_devices_and_has_constant_query_count() {
        let pool = setup_test_db().await;
        let prefix = format!("get-convos-devices-{}-", uuid::Uuid::new_v4());
        let convo_id = format!("{prefix}one");
        let did = "did:plc:getconvosdevices";
        let joined_at = Utc::now();
        cleanup_test_prefix(&pool, &prefix).await;

        sqlx::query(
            "INSERT INTO conversations (id, creator_did, current_epoch, created_at, updated_at, cipher_suite, is_remote, group_id) VALUES ($1, $2, 1, $3, $3, $4, false, $1)",
        )
        .bind(&convo_id)
        .bind(did)
        .bind(joined_at)
        .bind("MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519")
        .execute(&pool)
        .await
        .unwrap();
        for index in 0..3 {
            sqlx::query(
                "INSERT INTO members (convo_id, member_did, user_did, device_id, joined_at, is_admin) VALUES ($1, $2, $3, $4, $5, false)",
            )
            .bind(&convo_id)
            .bind(format!("{did}#device-{index}"))
            .bind(did)
            .bind(format!("device-{index}"))
            .bind(joined_at + chrono::Duration::microseconds(index))
            .execute(&pool)
            .await
            .unwrap();
        }

        let counter = AtomicUsize::new(0);
        let page = listing_json(
            &pool,
            did,
            ListingFilter::All,
            None,
            Some(100),
            PagePolicy::default(),
            Some(&counter),
        )
        .await
        .unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 3);
        assert_eq!(page["conversations"].as_array().unwrap().len(), 1);
        assert_eq!(
            page["conversations"][0]["members"]
                .as_array()
                .unwrap()
                .len(),
            3
        );

        let empty_counter = AtomicUsize::new(0);
        let empty = listing_json(
            &pool,
            "did:plc:no-such-listing-principal",
            ListingFilter::All,
            None,
            Some(100),
            PagePolicy::default(),
            Some(&empty_counter),
        )
        .await
        .unwrap();
        assert!(conversation_ids(&empty).is_empty());
        assert_eq!(empty_counter.load(Ordering::SeqCst), 1);

        let invalid_counter = AtomicUsize::new(0);
        let invalid = listing_json(
            &pool,
            did,
            ListingFilter::All,
            Some("invalid!"),
            Some(100),
            PagePolicy::default(),
            Some(&invalid_counter),
        )
        .await;
        assert_eq!(invalid.unwrap_err(), StatusCode::BAD_REQUEST);
        assert_eq!(invalid_counter.load(Ordering::SeqCst), 0);

        cleanup_test_prefix(&pool, &prefix).await;
    }

    #[tokio::test]
    #[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
    async fn complete_roster_member_ceiling_accepts_10000_and_rejects_10001() {
        let pool = setup_test_db().await;
        let prefix = format!("get-convos-members-{}-", uuid::Uuid::new_v4());
        let convo_id = format!("{prefix}one");
        let did = "did:plc:getconvosmemberlimit";
        let joined_at = Utc::now();
        cleanup_test_prefix(&pool, &prefix).await;
        sqlx::query(
            "INSERT INTO conversations (id, creator_did, current_epoch, created_at, updated_at, cipher_suite, is_remote, group_id) VALUES ($1, $2, 1, $3, $3, $4, false, $1)",
        )
        .bind(&convo_id)
        .bind(did)
        .bind(joined_at)
        .bind("MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519")
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            r#"
            INSERT INTO members (convo_id, member_did, user_did, joined_at, is_admin)
            SELECT $1, 'did:plc:member' || gs::text, $2, $3, false
            FROM generate_series(1, 10000) gs
            "#,
        )
        .bind(&convo_id)
        .bind(did)
        .bind(joined_at)
        .execute(&pool)
        .await
        .unwrap();

        let exact = listing_json(
            &pool,
            did,
            ListingFilter::All,
            None,
            Some(1),
            PagePolicy::default(),
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            exact["conversations"][0]["members"]
                .as_array()
                .unwrap()
                .len(),
            10_000
        );

        sqlx::query(
            "INSERT INTO members (convo_id, member_did, user_did, joined_at, is_admin) VALUES ($1, 'did:plc:member10001', $2, $3, false)",
        )
        .bind(&convo_id)
        .bind(did)
        .bind(joined_at)
        .execute(&pool)
        .await
        .unwrap();
        let counter = AtomicUsize::new(0);
        let oversized = listing_json(
            &pool,
            did,
            ListingFilter::All,
            None,
            Some(1),
            PagePolicy::default(),
            Some(&counter),
        )
        .await;
        assert_eq!(oversized.unwrap_err(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        cleanup_test_prefix(&pool, &prefix).await;
    }

    #[tokio::test]
    #[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
    async fn real_sql_and_streaming_enforce_exact_raw_payload_boundary() {
        let pool = setup_test_db().await;
        let prefix = format!("get-convos-raw-{}-", uuid::Uuid::new_v4());
        let convo_id = format!("{prefix}one");
        let did = "did:plc:getconvosrawlimit";
        let member_did = format!("{did}#device");
        let joined_at = Utc::now();
        cleanup_test_prefix(&pool, &prefix).await;
        sqlx::query(
            "INSERT INTO conversations (id, creator_did, current_epoch, created_at, updated_at, cipher_suite, is_remote, group_id) VALUES ($1, $2, 1, $3, $3, $4, false, $1)",
        )
        .bind(&convo_id)
        .bind(did)
        .bind(joined_at)
        .bind("MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519")
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO members (convo_id, member_did, user_did, device_name, joined_at, is_admin) VALUES ($1, $2, $3, '', $4, false)",
        )
        .bind(&convo_id)
        .bind(&member_did)
        .bind(did)
        .bind(joined_at)
        .execute(&pool)
        .await
        .unwrap();

        let mut baseline_connection = pool.acquire().await.unwrap();
        let baseline = fetch_listing_keys(
            &mut baseline_connection,
            did,
            ListingFilter::All,
            None,
            1,
            QueryTracker::default(),
        )
        .await
        .unwrap();
        drop(baseline_connection);
        let baseline_raw = usize::try_from(baseline[0].raw_bytes).unwrap();
        let exact_padding = "x".repeat(PagePolicy::default().max_raw_bytes - baseline_raw);
        sqlx::query("UPDATE members SET device_name = $1 WHERE convo_id = $2")
            .bind(&exact_padding)
            .bind(&convo_id)
            .execute(&pool)
            .await
            .unwrap();

        let exact = listing_json(
            &pool,
            did,
            ListingFilter::All,
            None,
            Some(1),
            PagePolicy::default(),
            None,
        )
        .await
        .unwrap();
        assert_eq!(conversation_ids(&exact), vec![convo_id.clone()]);

        sqlx::query("UPDATE members SET device_name = device_name || 'x' WHERE convo_id = $1")
            .bind(&convo_id)
            .execute(&pool)
            .await
            .unwrap();
        let oversized = listing_json(
            &pool,
            did,
            ListingFilter::All,
            None,
            Some(1),
            PagePolicy::default(),
            None,
        )
        .await;
        assert_eq!(oversized.unwrap_err(), StatusCode::PAYLOAD_TOO_LARGE);

        cleanup_test_prefix(&pool, &prefix).await;
    }

    #[tokio::test]
    #[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
    async fn concurrent_roster_growth_is_excluded_by_stable_read_snapshot() {
        let pool = setup_test_db().await;
        let prefix = format!("get-convos-race-{}-", uuid::Uuid::new_v4());
        let convo_id = format!("{prefix}one");
        let did = "did:plc:getconvosrosterdrift";
        let joined_at = Utc::now();
        cleanup_test_prefix(&pool, &prefix).await;
        sqlx::query(
            "INSERT INTO conversations (id, creator_did, current_epoch, created_at, updated_at, cipher_suite, is_remote, group_id) VALUES ($1, $2, 1, $3, $3, $4, false, $1)",
        )
        .bind(&convo_id)
        .bind(did)
        .bind(joined_at)
        .bind("MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519")
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO members (convo_id, member_did, user_did, joined_at, is_admin) VALUES ($1, $2, $2, $3, true)",
        )
        .bind(&convo_id)
        .bind(did)
        .bind(joined_at)
        .execute(&pool)
        .await
        .unwrap();

        let hook = PreflightHook::default();
        let counter = AtomicUsize::new(0);
        let listing = bounded_listing_response(
            &pool,
            did,
            ListingFilter::All,
            None,
            Some(1),
            PagePolicy::default(),
            QueryTracker {
                counter: Some(&counter),
                preflight_hook: Some(&hook),
            },
        );
        let mutation = async {
            hook.reached.notified().await;
            sqlx::query(
                r#"
                INSERT INTO members (convo_id, member_did, user_did, joined_at, is_admin)
                SELECT $1, 'did:plc:late-member-' || gs::text, $2, $3, false
                FROM generate_series(1, 10000) gs
                "#,
            )
            .bind(&convo_id)
            .bind(did)
            .bind(joined_at)
            .execute(&pool)
            .await
            .unwrap();
            hook.resume.notify_one();
        };
        let (result, ()) = tokio::join!(listing, mutation);
        let response = result.unwrap();
        let body = axum::body::to_bytes(response.into_body(), 32 * MIB)
            .await
            .unwrap();
        let page: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            page["conversations"][0]["members"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(counter.load(Ordering::SeqCst), 3);

        cleanup_test_prefix(&pool, &prefix).await;
    }

    #[tokio::test]
    #[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
    async fn stalled_key_query_returns_sanitized_504_and_runs_no_later_query() {
        let pool = setup_test_db().await;
        let mut lock = pool.begin().await.unwrap();
        sqlx::query("LOCK TABLE members IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *lock)
            .await
            .unwrap();

        let counter = AtomicUsize::new(0);
        let policy = PagePolicy {
            deadline: Duration::from_millis(50),
            ..PagePolicy::default()
        };
        let started = std::time::Instant::now();
        let result = listing_json(
            &pool,
            "did:plc:getconvostimeout",
            ListingFilter::All,
            None,
            Some(100),
            policy,
            Some(&counter),
        )
        .await;
        assert_eq!(result.unwrap_err(), StatusCode::GATEWAY_TIMEOUT);
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        lock.rollback().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
    async fn pending_filter_keeps_request_id_cursor_contract() {
        let pool = setup_test_db().await;
        let suffix = uuid::Uuid::new_v4();
        let sender = format!("did:plc:pending-sender-{suffix}");
        let recipient = format!("did:plc:pending-recipient-{suffix}");
        let newer_id = format!("pending-newer-{suffix}");
        let older_id = format!("pending-older-{suffix}");
        for did in [&sender, &recipient] {
            sqlx::query("INSERT INTO users (did) VALUES ($1) ON CONFLICT DO NOTHING")
                .bind(did)
                .execute(&pool)
                .await
                .unwrap();
        }
        for (id, created_at) in [
            (&older_id, Utc::now() - chrono::Duration::minutes(2)),
            (&newer_id, Utc::now() - chrono::Duration::minutes(1)),
        ] {
            sqlx::query(
                "INSERT INTO chat_requests (id, sender_did, recipient_did, status, created_at) VALUES ($1, $2, $3, 'pending', $4)",
            )
            .bind(id)
            .bind(&sender)
            .bind(&recipient)
            .bind(created_at)
            .execute(&pool)
            .await
            .unwrap();
        }

        let response = handle_pending(
            &pool,
            &recipient,
            Some(newer_id.clone()),
            Some(1),
            "pending",
        )
        .await
        .unwrap();
        assert_eq!(response.0["requests"][0]["id"], older_id);
        assert_eq!(response.0["cursor"], older_id);

        sqlx::query("DELETE FROM chat_requests WHERE recipient_did = $1")
            .bind(&recipient)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE did = ANY($1::text[])")
            .bind(vec![sender, recipient])
            .execute(&pool)
            .await
            .unwrap();
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
