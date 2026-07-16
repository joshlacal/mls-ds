use axum::{
    extract::{RawQuery, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Utc};
use jacquard_axum::ExtractXrpc;
use sqlx::FromRow;
use std::{io, time::Duration};

#[cfg(test)]
use std::future::Future;
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
const MAX_RAW_RESPONSE_BYTES: i64 = 46 * 1024 * 1024;
const MAX_SERIALIZED_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
const GET_MESSAGES_DEADLINE: Duration = Duration::from_secs(20);

fn is_commit_filter(value: &str) -> bool {
    matches!(value, "commit" | "commits")
}

// ---------------------------------------------------------------------------
// Row types for inline SQL
// ---------------------------------------------------------------------------

#[derive(Debug, FromRow)]
struct MessageRow {
    id: String,
    convo_id: String,
    message_type: String,
    epoch: i64,
    #[sqlx(default)]
    wire_epoch: Option<i64>,
    seq: i64,
    ciphertext: Vec<u8>,
    created_at: DateTime<Utc>,
    #[sqlx(default)]
    reset_generation: i32,
    raw_size: i64,
    candidate_count: i64,
}

const APP_NO_SINCE_QUERY: &str = r#"
    WITH candidates AS MATERIALIZED (
      SELECT id, convo_id, message_type, CAST(epoch AS BIGINT) epoch,
             NULL::BIGINT wire_epoch, CAST(seq AS BIGINT) seq, ciphertext,
             created_at, COALESCE(reset_generation, 0) reset_generation,
             OCTET_LENGTH(ciphertext)::BIGINT raw_size
      FROM messages WHERE convo_id=$1 AND message_type='app'
        AND ($3::BIGINT IS NULL OR epoch >= $3)
        AND (expires_at IS NULL OR expires_at > NOW())
      ORDER BY seq DESC
      LIMIT $2
    ), eligible AS (
      SELECT *,
             SUM(raw_size) OVER (ORDER BY seq DESC)::BIGINT cumulative_raw,
             COUNT(*) OVER ()::BIGINT candidate_count
      FROM candidates
    )
    SELECT id, convo_id, message_type, epoch, wire_epoch, seq, ciphertext,
           created_at, reset_generation, raw_size, candidate_count FROM eligible
    WHERE cumulative_raw <= $4
    ORDER BY seq ASC
    "#;

#[cfg(test)]
#[derive(Clone)]
struct SnapshotTestHook {
    reached: std::sync::Arc<tokio::sync::Barrier>,
    proceed: std::sync::Arc<tokio::sync::Barrier>,
}

#[cfg(test)]
#[derive(Clone)]
struct KeyedSnapshotTestHook {
    convo_id: String,
    hook: SnapshotTestHook,
}

#[cfg(test)]
static SNAPSHOT_TEST_HOOK: std::sync::OnceLock<std::sync::Mutex<Option<KeyedSnapshotTestHook>>> =
    std::sync::OnceLock::new();
#[cfg(test)]
static COMBINED_SNAPSHOT_TEST_HOOK: std::sync::OnceLock<
    std::sync::Mutex<Option<KeyedSnapshotTestHook>>,
> = std::sync::OnceLock::new();
#[cfg(test)]
static INTERLEAVED_SNAPSHOT_TEST_HOOK: std::sync::OnceLock<
    std::sync::Mutex<Option<KeyedSnapshotTestHook>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
async fn run_snapshot_test_hook(convo_id: &str) {
    let hook = SNAPSHOT_TEST_HOOK
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .expect("snapshot hook lock")
        .clone();
    if let Some(keyed) = hook.filter(|keyed| keyed.convo_id == convo_id) {
        keyed.hook.reached.wait().await;
        keyed.hook.proceed.wait().await;
    }
}

#[cfg(test)]
async fn run_combined_snapshot_test_hook(convo_id: &str) {
    let hook = COMBINED_SNAPSHOT_TEST_HOOK
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .expect("combined snapshot hook lock")
        .clone();
    if let Some(keyed) = hook.filter(|keyed| keyed.convo_id == convo_id) {
        keyed.hook.reached.wait().await;
        keyed.hook.proceed.wait().await;
    }
}

#[cfg(test)]
async fn run_interleaved_snapshot_test_hook(convo_id: &str) {
    let hook = INTERLEAVED_SNAPSHOT_TEST_HOOK
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .expect("interleaved snapshot hook lock")
        .clone();
    if let Some(keyed) = hook.filter(|keyed| keyed.convo_id == convo_id) {
        keyed.hook.reached.wait().await;
        keyed.hook.proceed.wait().await;
    }
}

#[derive(Debug, PartialEq, Eq)]
enum SerializedSizeError {
    LimitExceeded,
    Serialization,
}

#[cfg(test)]
std::thread_local! {
    static SERIALIZATION_ATTEMPTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

struct BoundedCounter {
    written: usize,
    limit: usize,
    exceeded: bool,
}

impl io::Write for BoundedCounter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let Some(next) = self.written.checked_add(buf.len()) else {
            self.exceeded = true;
            return Err(io::Error::other("serialized response size overflow"));
        };
        if next > self.limit {
            self.exceeded = true;
            return Err(io::Error::other("serialized response exceeds limit"));
        }
        self.written = next;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn serialized_size_bounded<T: serde::Serialize>(
    value: &T,
    limit: usize,
) -> Result<usize, SerializedSizeError> {
    #[cfg(test)]
    SERIALIZATION_ATTEMPTS.with(|attempts| attempts.set(attempts.get() + 1));
    let mut counter = BoundedCounter {
        written: 0,
        limit,
        exceeded: false,
    };
    match serde_json::to_writer(&mut counter, value) {
        Ok(()) => Ok(counter.written),
        Err(_) if counter.exceeded => Err(SerializedSizeError::LimitExceeded),
        Err(_) => Err(SerializedSizeError::Serialization),
    }
}

#[cfg(test)]
async fn with_retrieval_deadline<F, T>(future: F) -> Result<T, StatusCode>
where
    F: Future<Output = Result<T, StatusCode>>,
{
    with_retrieval_deadline_for(GET_MESSAGES_DEADLINE, future).await
}

#[cfg(test)]
async fn with_retrieval_deadline_for<F, T>(duration: Duration, future: F) -> Result<T, StatusCode>
where
    F: Future<Output = Result<T, StatusCode>>,
{
    tokio::time::timeout(duration, future)
        .await
        .map_err(|_| StatusCode::REQUEST_TIMEOUT)?
}

fn enforce_serialized_budget(
    mut output: GetMessagesOutput,
    had_eligible: bool,
    final_sequence_sort: bool,
) -> Result<GetMessagesOutput, StatusCode> {
    if final_sequence_sort
        && output
            .messages
            .iter()
            .any(|message| message.message_type.as_deref() == Some("commit"))
    {
        let (commits, others): (Vec<_>, Vec<_>) = output
            .messages
            .into_iter()
            .partition(|message| message.message_type.as_deref() == Some("commit"));
        output.messages = commits.into_iter().chain(others).collect();
    }
    let full_len = output.messages.len();
    let mut low = 0_usize;
    let mut high = full_len;
    while low < high {
        let mid = low + (high - low).div_ceil(2);
        let mut candidate = output.clone();
        candidate.messages.truncate(mid);
        candidate.last_seq = candidate
            .messages
            .iter()
            .filter(|message| message.message_type.as_deref() == Some("app"))
            .map(|message| message.seq)
            .max();
        match serialized_size_bounded(&candidate, MAX_SERIALIZED_RESPONSE_BYTES) {
            Ok(_) => low = mid,
            Err(SerializedSizeError::LimitExceeded) => high = mid - 1,
            Err(SerializedSizeError::Serialization) => {
                return Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    }
    output.messages.truncate(low);
    if low == 0 && had_eligible {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    if final_sequence_sort {
        output.messages.sort_by_key(|message| message.seq);
    }
    output.last_seq = output
        .messages
        .iter()
        .filter(|message| message.message_type.as_deref() == Some("app"))
        .map(|message| message.seq)
        .max();
    match serialized_size_bounded(&output, MAX_SERIALIZED_RESPONSE_BYTES) {
        Ok(_) => Ok(output),
        Err(SerializedSizeError::LimitExceeded) => Err(StatusCode::PAYLOAD_TOO_LARGE),
        Err(SerializedSizeError::Serialization) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
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
) -> Result<Json<GetMessagesOutput>, StatusCode> {
    let extra_query_str = extra_query.as_deref().unwrap_or("");

    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        error!("❌ [v2.getMessages] Unauthorized");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let did = &auth_user.did;
    let message_type = params.r#type.as_deref().unwrap_or("all");
    let convo_id = params.convo_id.to_string();
    let limit = params.limit.unwrap_or(50).clamp(1, 100);
    let since_seq = params.since_seq;
    let join_epoch = params.join_epoch;

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

    let request_deadline = tokio::time::Instant::now() + GET_MESSAGES_DEADLINE;
    let retrieval = async {
        let (output, had_eligible, final_sequence_sort) = match message_type {
            "app" => {
                let (mut messages, last_seq, suppressed_before_join, _, deferred, _) =
                    fetch_app_messages(
                        &pool,
                        did,
                        &convo_id,
                        since_seq,
                        limit,
                        join_epoch,
                        MAX_RAW_RESPONSE_BYTES,
                    )
                    .await?;
                if since_seq.is_none() {
                    messages.reverse();
                }
                Ok((
                    GetMessagesOutput {
                        messages,
                        last_seq,
                        gap_info: None,
                        suppressed_before_join,
                        extra_data: Default::default(),
                    },
                    deferred,
                    true,
                ))
            }

            value if is_commit_filter(value) => {
                let (messages, _, deferred, _) = fetch_commits(
                    &pool,
                    did,
                    &convo_id,
                    from_epoch,
                    to_epoch,
                    MAX_RAW_RESPONSE_BYTES,
                )
                .await?;
                Ok((
                    GetMessagesOutput {
                        messages,
                        last_seq: None,
                        gap_info: None,
                        suppressed_before_join: None,
                        extra_data: Default::default(),
                    },
                    deferred,
                    false,
                ))
            }

            "all" => {
                let (messages, last_seq, suppressed_before_join, app_deferred, commit_deferred, _) =
                    fetch_all_messages(
                        &pool,
                        did,
                        &convo_id,
                        since_seq,
                        limit,
                        join_epoch,
                        (from_epoch, to_epoch),
                    )
                    .await?;
                Ok((
                    GetMessagesOutput {
                        messages,
                        last_seq,
                        gap_info: None,
                        suppressed_before_join,
                        extra_data: Default::default(),
                    },
                    app_deferred || commit_deferred,
                    true,
                ))
            }

            other => {
                warn!("❌ [v2.getMessages] Unknown type filter: {}", other);
                Err(StatusCode::BAD_REQUEST)
            }
        }?;
        let admitted_commit_count = output
            .messages
            .iter()
            .filter(|message| message.message_type.as_deref() == Some("commit"))
            .count();
        let output = enforce_serialized_budget(output, had_eligible, final_sequence_sort)?;
        if message_type == "all"
            && output
                .messages
                .iter()
                .filter(|message| message.message_type.as_deref() == Some("commit"))
                .count()
                < admitted_commit_count
        {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        // Reads intentionally never mutate unread_count. There is currently no
        // universal per-conversation serialization point shared by every app
        // message writer, so clearing here could mark a post-snapshot delivery
        // as read. A future shared-writer generation protocol must own that UX.
        Ok::<_, StatusCode>(output)
    };

    let output = tokio::time::timeout_at(request_deadline, retrieval)
        .await
        .map_err(|_| StatusCode::REQUEST_TIMEOUT)??;
    Ok(Json(output))
}

// ---------------------------------------------------------------------------
// type="app" — inline of v1 get_messages
// ---------------------------------------------------------------------------

type AppFetchResult = (Vec<MessageView>, Option<i64>, Option<i64>, i64, bool, bool);

async fn begin_read_snapshot(
    pool: &DbPool,
) -> Result<sqlx::Transaction<'_, sqlx::Postgres>, StatusCode> {
    let mut tx = pool.begin().await.map_err(|e| {
        error!("❌ [v2.getMessages] Failed to begin snapshot: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            error!("❌ [v2.getMessages] Failed to configure snapshot: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    Ok(tx)
}

async fn fetch_app_messages(
    pool: &DbPool,
    did: &str,
    convo_id: &str,
    since_seq: Option<i64>,
    limit: i64,
    join_epoch: Option<i64>,
    raw_budget: i64,
) -> Result<AppFetchResult, StatusCode> {
    let mut tx = begin_read_snapshot(pool).await?;
    let result = fetch_app_messages_in_snapshot(
        &mut tx, did, convo_id, since_seq, limit, join_epoch, raw_budget,
    )
    .await?;
    tx.commit().await.map_err(|e| {
        error!("❌ [v2.getMessages] Failed to close app snapshot: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(result)
}

async fn fetch_app_messages_in_snapshot(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    did: &str,
    convo_id: &str,
    since_seq: Option<i64>,
    limit: i64,
    join_epoch: Option<i64>,
    raw_budget: i64,
) -> Result<AppFetchResult, StatusCode> {
    // Check membership
    let is_member: Option<(i32,)> = sqlx::query_as(
        "SELECT 1 as v FROM members WHERE convo_id = $1 AND (user_did = $2 OR member_did = $2) AND left_at IS NULL LIMIT 1",
    )
    .bind(convo_id)
    .bind(did)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| {
        error!("❌ [v2.getMessages] Failed to check membership: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if is_member.is_none() {
        warn!("❌ [v2.getMessages] User is not a member");
        return Err(StatusCode::FORBIDDEN);
    }

    let first_raw_size = if let Some(since) = since_seq {
        sqlx::query_scalar::<_, i64>(
            "SELECT OCTET_LENGTH(ciphertext)::BIGINT FROM messages WHERE convo_id=$1 AND message_type='app' AND seq>$2 AND ($3::BIGINT IS NULL OR epoch >= $3) AND (expires_at IS NULL OR expires_at > NOW()) ORDER BY seq ASC LIMIT 1"
        ).bind(convo_id).bind(since).bind(join_epoch).fetch_optional(&mut **tx).await
    } else {
        sqlx::query_scalar::<_, i64>(
            "SELECT OCTET_LENGTH(ciphertext)::BIGINT FROM messages WHERE convo_id=$1 AND message_type='app' AND ($2::BIGINT IS NULL OR epoch >= $2) AND (expires_at IS NULL OR expires_at > NOW()) ORDER BY seq DESC LIMIT 1"
        ).bind(convo_id).bind(join_epoch).fetch_optional(&mut **tx).await
    }.map_err(|e| {
        error!("❌ [v2.getMessages] Failed to inspect first message: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    #[cfg(test)]
    run_snapshot_test_hook(convo_id).await;
    #[cfg(test)]
    run_interleaved_snapshot_test_hook(convo_id).await;

    // The cumulative predicate runs in PostgreSQL, so ciphertext beyond the
    // shared budget never crosses the database/server boundary.
    let messages: Vec<MessageRow> = if let Some(since) = since_seq {
        sqlx::query_as::<_, MessageRow>(
            r#"
            WITH candidates AS MATERIALIZED (
              SELECT id, convo_id, message_type, CAST(epoch AS BIGINT) epoch,
                     NULL::BIGINT wire_epoch, CAST(seq AS BIGINT) seq, ciphertext,
                     created_at, COALESCE(reset_generation, 0) reset_generation,
                     OCTET_LENGTH(ciphertext)::BIGINT raw_size
              FROM messages WHERE convo_id=$1 AND message_type='app' AND seq>$2
                AND ($4::BIGINT IS NULL OR epoch >= $4)
                AND (expires_at IS NULL OR expires_at > NOW())
              ORDER BY seq ASC
              LIMIT $3
            ), eligible AS (
              SELECT *,
                     SUM(raw_size) OVER (ORDER BY seq ASC)::BIGINT cumulative_raw,
                     COUNT(*) OVER ()::BIGINT candidate_count
              FROM candidates
            )
            SELECT id, convo_id, message_type, epoch, wire_epoch, seq, ciphertext,
                   created_at, reset_generation, raw_size, candidate_count FROM eligible
            WHERE cumulative_raw <= $5
            ORDER BY seq ASC
            "#,
        )
        .bind(convo_id)
        .bind(since)
        .bind(limit)
        .bind(join_epoch)
        .bind(raw_budget)
        .fetch_all(&mut **tx)
        .await
        .map_err(|e| {
            error!(
                "❌ [v2.getMessages] Failed to fetch messages since seq: {}",
                e
            );
            StatusCode::INTERNAL_SERVER_ERROR
        })?
    } else {
        sqlx::query_as::<_, MessageRow>(APP_NO_SINCE_QUERY)
            .bind(convo_id)
            .bind(limit)
            .bind(join_epoch)
            .bind(raw_budget)
            .fetch_all(&mut **tx)
            .await
            .map_err(|e| {
                error!("❌ [v2.getMessages] Failed to list messages: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?
    };

    let raw_truncated = messages
        .first()
        .map(|message| (messages.len() as i64) < message.candidate_count)
        .unwrap_or(first_raw_size.is_some());
    let raw_used = messages.iter().map(|message| message.raw_size).sum();
    let deferred = first_raw_size.is_some();
    let last_seq = messages.last().map(|m| m.seq);
    let suppressed_before_join =
        count_suppressed_before_join(tx, convo_id, since_seq, join_epoch).await?;

    let message_views: Vec<MessageView> = messages
        .into_iter()
        .map(|m| {
            let mut extra = std::collections::BTreeMap::new();
            extra.insert(
                jacquard_common::SmolStr::new("resetGeneration"),
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

    Ok((
        message_views,
        last_seq,
        suppressed_before_join,
        raw_used,
        deferred,
        raw_truncated,
    ))
}

async fn count_suppressed_before_join(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    convo_id: &str,
    since_seq: Option<i64>,
    join_epoch: Option<i64>,
) -> Result<Option<i64>, StatusCode> {
    let Some(join_epoch) = join_epoch else {
        return Ok(None);
    };

    let suppressed = if let Some(since) = since_seq {
        sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*)::BIGINT
            FROM messages
            WHERE convo_id = $1
              AND message_type = 'app'
              AND seq > $2
              AND epoch < $3
              AND (expires_at IS NULL OR expires_at > NOW())
            "#,
        )
        .bind(convo_id)
        .bind(since)
        .bind(join_epoch)
        .fetch_one(&mut **tx)
        .await
    } else {
        sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*)::BIGINT
            FROM messages
            WHERE convo_id = $1
              AND message_type = 'app'
              AND epoch < $2
              AND (expires_at IS NULL OR expires_at > NOW())
            "#,
        )
        .bind(convo_id)
        .bind(join_epoch)
        .fetch_one(&mut **tx)
        .await
    }
    .map_err(|e| {
        error!(
            "❌ [v2.getMessages] Failed to count pre-join messages: {}",
            e
        );
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Some(suppressed))
}

// ---------------------------------------------------------------------------
// type="commit" — inline of v1 get_commits
// ---------------------------------------------------------------------------

type CommitFetchResult = (Vec<MessageView>, i64, bool, bool);

async fn fetch_commits(
    pool: &DbPool,
    did: &str,
    convo_id: &str,
    from_epoch: i64,
    to_epoch: Option<i64>,
    raw_budget: i64,
) -> Result<CommitFetchResult, StatusCode> {
    let mut tx = begin_read_snapshot(pool).await?;
    let result =
        fetch_commits_in_snapshot(&mut tx, did, convo_id, from_epoch, to_epoch, raw_budget).await?;
    tx.commit().await.map_err(|e| {
        error!("❌ [v2.getMessages] Failed to close commit snapshot: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(result)
}

async fn fetch_commits_in_snapshot(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    did: &str,
    convo_id: &str,
    from_epoch: i64,
    to_epoch: Option<i64>,
    raw_budget: i64,
) -> Result<CommitFetchResult, StatusCode> {
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
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| {
        error!("❌ [v2.getMessages] Failed to check membership: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if is_member.is_none() {
        warn!("❌ [v2.getMessages] User is not a member");
        return Err(StatusCode::FORBIDDEN);
    }

    // Determine end epoch.
    //
    // TODO(phase 4): switch back to `crypto_session.last_observed_epoch`
    // once `try_advance_conversation_epoch_tx` (db.rs) advances both
    // `conversations.current_epoch` AND
    // `crypto_sessions.last_observed_epoch` in the same tx. Until then
    // `last_observed_epoch` is stale after every accepted commit
    // (merged_bug_001 from ultrareview).
    let to_epoch = if let Some(to) = to_epoch {
        to
    } else {
        let current_epoch: i32 =
            sqlx::query_scalar("SELECT current_epoch FROM conversations WHERE id = $1")
                .bind(convo_id)
                .fetch_optional(&mut **tx)
                .await
                .map_err(|e| {
                    error!("❌ [v2.getMessages] Failed to fetch current epoch: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?
                .ok_or_else(|| {
                    error!("❌ [v2.getMessages] Conversation not found");
                    StatusCode::NOT_FOUND
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
        return Ok((Vec::new(), 0, false, false));
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
    // API callers still use post-advance epoch bounds (`localEpoch + 1`).
    // MLS commit ciphertext is authored at the pre-advance wire epoch, so shift
    // the bounds down while preserving the public response epoch for clients.
    let wire_from_epoch = from_epoch.saturating_sub(1);
    let wire_to_epoch = to_epoch.saturating_sub(1);

    let first_raw_size = sqlx::query_scalar::<_, i64>(
        r#"SELECT OCTET_LENGTH(ciphertext)::BIGINT FROM messages
           WHERE convo_id=$1 AND message_type='commit'
             AND COALESCE(wire_epoch, GREATEST(epoch - 1, 0)) >= $2
             AND COALESCE(wire_epoch, GREATEST(epoch - 1, 0)) <= $3
           ORDER BY COALESCE(wire_epoch, GREATEST(epoch - 1, 0)) ASC, seq ASC LIMIT 1"#,
    )
    .bind(convo_id)
    .bind(wire_from_epoch)
    .bind(wire_to_epoch)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| {
        error!("❌ [v2.getMessages] Failed to inspect first commit: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    #[cfg(test)]
    run_snapshot_test_hook(convo_id).await;

    let commits = sqlx::query_as::<_, MessageRow>(
        r#"
        WITH candidates AS MATERIALIZED (
          SELECT id, convo_id, 'commit'::TEXT message_type, CAST(epoch AS BIGINT) epoch,
                 CAST(COALESCE(wire_epoch, GREATEST(epoch-1,0)) AS BIGINT) wire_epoch,
                 CAST(seq AS BIGINT) seq, ciphertext, created_at,
                 COALESCE(reset_generation,0) reset_generation,
                 OCTET_LENGTH(ciphertext)::BIGINT raw_size
          FROM messages WHERE convo_id=$1 AND message_type='commit'
            AND COALESCE(wire_epoch, GREATEST(epoch-1,0)) >= $2
            AND COALESCE(wire_epoch, GREATEST(epoch-1,0)) <= $3
          ORDER BY COALESCE(wire_epoch, GREATEST(epoch-1,0)) ASC, seq ASC
          LIMIT $4
        ), eligible AS (
          SELECT *,
                 SUM(raw_size) OVER (ORDER BY wire_epoch ASC, seq ASC)::BIGINT cumulative_raw,
                 COUNT(*) OVER ()::BIGINT candidate_count
          FROM candidates
        )
        SELECT id, convo_id, message_type, epoch, wire_epoch, seq, ciphertext,
               created_at, reset_generation, raw_size, candidate_count FROM eligible
        WHERE cumulative_raw <= $5
        ORDER BY wire_epoch ASC, seq ASC
        "#,
    )
    .bind(convo_id)
    .bind(wire_from_epoch)
    .bind(wire_to_epoch)
    .bind(MAX_COMMITS)
    .bind(raw_budget)
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| {
        error!("❌ [v2.getMessages] Failed to fetch commits: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!("✅ [v2.getMessages] Fetched {} commits", commits.len());

    let raw_truncated = commits
        .first()
        .map(|commit| (commits.len() as i64) < commit.candidate_count)
        .unwrap_or(first_raw_size.is_some());
    let raw_used = commits.iter().map(|commit| commit.raw_size).sum();
    let commit_views: Vec<MessageView> = commits
        .into_iter()
        .map(|c| {
            let mut extra = std::collections::BTreeMap::new();
            extra.insert(
                jacquard_common::SmolStr::new("resetGeneration"),
                jacquard_common::types::value::Data::Integer(c.reset_generation as i64),
            );
            if let Some(wire_epoch) = c.wire_epoch {
                extra.insert(
                    jacquard_common::SmolStr::new("wireEpoch"),
                    jacquard_common::types::value::Data::Integer(wire_epoch),
                );
            }
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

    Ok((
        commit_views,
        raw_used,
        first_raw_size.is_some(),
        raw_truncated,
    ))
}

async fn fetch_all_messages(
    pool: &DbPool,
    did: &str,
    convo_id: &str,
    since_seq: Option<i64>,
    limit: i64,
    join_epoch: Option<i64>,
    epoch_range: (i64, Option<i64>),
) -> Result<(Vec<MessageView>, Option<i64>, Option<i64>, bool, bool, bool), StatusCode> {
    let mut tx = begin_read_snapshot(pool).await?;
    // Commits are required to advance MLS state and decrypt later app
    // messages, so they receive first admission to the shared raw budget.
    let (commits, commit_bytes, commit_eligible, commit_raw_truncated) = fetch_commits_in_snapshot(
        &mut tx,
        did,
        convo_id,
        epoch_range.0,
        epoch_range.1,
        MAX_RAW_RESPONSE_BYTES,
    )
    .await?;
    if commit_raw_truncated {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    #[cfg(test)]
    run_combined_snapshot_test_hook(convo_id).await;
    let (mut messages, last_seq, suppressed, _, app_eligible, app_raw_truncated) =
        fetch_app_messages_in_snapshot(
            &mut tx,
            did,
            convo_id,
            since_seq,
            limit,
            join_epoch,
            MAX_RAW_RESPONSE_BYTES - commit_bytes,
        )
        .await?;
    tx.commit().await.map_err(|e| {
        error!(
            "❌ [v2.getMessages] Failed to close combined snapshot: {}",
            e
        );
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    if since_seq.is_none() {
        messages.reverse();
    }
    messages.extend(commits);
    Ok((
        messages,
        last_seq,
        suppressed,
        app_eligible,
        commit_eligible,
        app_raw_truncated,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message_view(seq: i64, id_len: usize) -> MessageView {
        MessageView {
            id: "x".repeat(id_len).into(),
            convo_id: "convo".into(),
            ciphertext: bytes::Bytes::from_static(b"x"),
            epoch: 1,
            seq,
            created_at: crate::sqlx_jacquard::chrono_to_datetime(Utc::now()),
            message_type: Some("app".into()),
            extra_data: None,
        }
    }

    fn commit_view(seq: i64, id_len: usize) -> MessageView {
        let mut message = message_view(seq, id_len);
        message.message_type = Some("commit".into());
        message
    }

    #[test]
    fn serialized_counter_rejects_a_value_over_the_wire_budget_without_buffering() {
        let oversized = vec![0_u8; MAX_SERIALIZED_RESPONSE_BYTES + 1];
        assert_eq!(
            serialized_size_bounded(&oversized, MAX_SERIALIZED_RESPONSE_BYTES),
            Err(SerializedSizeError::LimitExceeded)
        );
    }

    #[test]
    fn commit_filter_aliases_remain_compatible() {
        assert!(is_commit_filter("commit"));
        assert!(is_commit_filter("commits"));
        assert!(!is_commit_filter("all"));
    }

    #[test]
    fn eligible_single_row_that_cannot_be_admitted_is_413() {
        let output = GetMessagesOutput {
            messages: Vec::new(),
            last_seq: None,
            gap_info: None,
            suppressed_before_join: None,
            extra_data: Default::default(),
        };
        assert_eq!(
            enforce_serialized_budget(output, true, true).unwrap_err(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    #[test]
    fn exact_wire_trimming_preserves_recent_newest_first_admission() {
        SERIALIZATION_ATTEMPTS.with(|attempts| attempts.set(0));
        let output = GetMessagesOutput {
            // Admission order is newest then older; final output is ascending.
            messages: vec![
                message_view(2, 33 * 1024 * 1024),
                message_view(1, 33 * 1024 * 1024),
            ],
            last_seq: Some(2),
            gap_info: None,
            suppressed_before_join: None,
            extra_data: Default::default(),
        };
        let bounded = enforce_serialized_budget(output, true, true).expect("bounded response");
        assert_eq!(
            bounded
                .messages
                .iter()
                .map(|message| message.seq)
                .collect::<Vec<_>>(),
            vec![2]
        );
        assert_eq!(bounded.last_seq, Some(2));
        assert_eq!(
            SERIALIZATION_ATTEMPTS.with(std::cell::Cell::get),
            3,
            "two-row admission requires two binary-search probes plus one final cap check"
        );
    }

    #[test]
    fn exact_wire_trimming_prioritizes_commits_over_apps() {
        let output = GetMessagesOutput {
            messages: vec![
                message_view(1, 33 * 1024 * 1024),
                commit_view(2, 33 * 1024 * 1024),
            ],
            last_seq: Some(1),
            gap_info: None,
            suppressed_before_join: None,
            extra_data: Default::default(),
        };
        let bounded = enforce_serialized_budget(output, true, true).expect("bounded response");
        assert_eq!(bounded.messages.len(), 1);
        assert_eq!(bounded.messages[0].message_type.as_deref(), Some("commit"));
        assert_eq!(bounded.last_seq, None);
    }

    #[test]
    fn exact_cap_attempts_are_logarithmic_at_combined_count_limit() {
        SERIALIZATION_ATTEMPTS.with(|attempts| attempts.set(0));
        let output = GetMessagesOutput {
            messages: (1..=150).map(|seq| message_view(seq, 8)).collect(),
            last_seq: Some(150),
            gap_info: None,
            suppressed_before_join: None,
            extra_data: Default::default(),
        };
        let bounded = enforce_serialized_budget(output, true, true).expect("bounded");
        assert_eq!(bounded.messages.len(), 150);
        assert!(SERIALIZATION_ATTEMPTS.with(std::cell::Cell::get) <= 9);
    }

    #[tokio::test]
    async fn retrieval_deadline_returns_request_timeout() {
        let stalled = async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            Ok::<_, StatusCode>(())
        };
        assert_eq!(
            with_retrieval_deadline_for(Duration::from_millis(5), stalled)
                .await
                .unwrap_err(),
            StatusCode::REQUEST_TIMEOUT
        );
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn interleaved_message_only_delivery_does_not_change_unread() {
        let database_url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL");
        let pool = sqlx::PgPool::connect(&database_url).await.expect("connect");
        let suffix = ulid::Ulid::new().to_string();
        let convo_id = format!("w3-unread-snapshot-{suffix}");
        let did = format!("did:plc:{suffix}");
        sqlx::query("INSERT INTO conversations (id, creator_did, group_id) VALUES ($1,$2,$3)")
            .bind(&convo_id)
            .bind(&did)
            .bind(format!("group-{suffix}"))
            .execute(&pool)
            .await
            .expect("conversation");
        sqlx::query("INSERT INTO members (convo_id, member_did, user_did, unread_count) VALUES ($1,$2,$2,5)")
            .bind(&convo_id)
            .bind(&did)
            .execute(&pool)
            .await
            .expect("member");
        sqlx::query("INSERT INTO messages (id,convo_id,message_type,epoch,seq,ciphertext) VALUES ($1,$2,'app',1,1,$3)")
            .bind(format!("snapshot-old-{suffix}"))
            .bind(&convo_id)
            .bind(vec![1_u8])
            .execute(&pool)
            .await
            .expect("old message");

        let reached = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        let proceed = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        *INTERLEAVED_SNAPSHOT_TEST_HOOK
            .get_or_init(|| std::sync::Mutex::new(None))
            .lock()
            .expect("interleaved snapshot hook") = Some(KeyedSnapshotTestHook {
            convo_id: convo_id.clone(),
            hook: SnapshotTestHook {
                reached: reached.clone(),
                proceed: proceed.clone(),
            },
        });
        let fetch_pool = pool.clone();
        let fetch_did = did.clone();
        let fetch_convo = convo_id.clone();
        let fetch = tokio::spawn(async move {
            fetch_app_messages(
                &fetch_pool,
                &fetch_did,
                &fetch_convo,
                Some(0),
                100,
                None,
                MAX_RAW_RESPONSE_BYTES,
            )
            .await
        });
        reached.wait().await;

        // Production federation paths may commit a message without touching
        // the member row. The read must remain observational in this race.
        sqlx::query("INSERT INTO messages (id,convo_id,message_type,epoch,seq,ciphertext) VALUES ($1,$2,'app',1,2,$3)")
            .bind(format!("snapshot-new-{suffix}"))
            .bind(&convo_id)
            .bind(vec![2_u8])
            .execute(&pool)
            .await
            .expect("new message");
        proceed.wait().await;
        let (response, _, _, _, _, _) = fetch
            .await
            .expect("snapshot task")
            .expect("snapshot response");
        *INTERLEAVED_SNAPSHOT_TEST_HOOK
            .get()
            .expect("interleaved snapshot hook state")
            .lock()
            .expect("interleaved snapshot hook") = None;
        assert_eq!(
            response
                .iter()
                .map(|message| message.seq)
                .collect::<Vec<_>>(),
            vec![1],
            "repeatable-read response must omit the interleaved delivery"
        );
        let unread: i32 = sqlx::query_scalar(
            "SELECT unread_count FROM members WHERE convo_id=$1 AND user_did=$2",
        )
        .bind(&convo_id)
        .bind(&did)
        .fetch_one(&pool)
        .await
        .expect("unread after interleaved read");
        assert_eq!(unread, 5, "getMessages must never mutate unread state");

        sqlx::query("DELETE FROM conversations WHERE id=$1")
            .bind(&convo_id)
            .execute(&pool)
            .await
            .expect("cleanup");
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn postgres_app_query_enforces_shared_raw_budget_and_ordering() {
        let database_url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL");
        let pool = sqlx::PgPool::connect(&database_url).await.expect("connect");
        let suffix = ulid::Ulid::new().to_string();
        let convo_id = format!("w3-budget-{suffix}");
        let did = format!("did:plc:{suffix}");
        sqlx::query("INSERT INTO conversations (id, creator_did, group_id) VALUES ($1,$2,$3)")
            .bind(&convo_id)
            .bind(&did)
            .bind(format!("group-{suffix}"))
            .execute(&pool)
            .await
            .expect("conversation");
        sqlx::query("INSERT INTO members (convo_id, member_did, user_did) VALUES ($1,$2,$2)")
            .bind(&convo_id)
            .bind(&did)
            .execute(&pool)
            .await
            .expect("member");
        sqlx::query("UPDATE members SET unread_count=21 WHERE convo_id=$1 AND user_did=$2")
            .bind(&convo_id)
            .bind(&did)
            .execute(&pool)
            .await
            .expect("initial unread");
        for seq in 1_i64..=7 {
            sqlx::query("INSERT INTO messages (id, convo_id, message_type, epoch, seq, ciphertext) VALUES ($1,$2,'app',1,$3,$4)")
                .bind(format!("m-{suffix}-{seq}"))
                .bind(&convo_id)
                .bind(seq)
                .bind(vec![seq as u8; 10 * 1024 * 1024])
                .execute(&pool).await.expect("message");
        }

        let (newest, last_seq, _, raw_used, _, _) = fetch_app_messages(
            &pool,
            &did,
            &convo_id,
            None,
            100,
            None,
            MAX_RAW_RESPONSE_BYTES,
        )
        .await
        .expect("bounded newest query");
        assert_eq!(
            newest.iter().map(|message| message.seq).collect::<Vec<_>>(),
            vec![4, 5, 6, 7]
        );
        assert_eq!(last_seq, Some(7));
        assert_eq!(raw_used, 40 * 1024 * 1024);
        let unread_after_truncated_read: i32 = sqlx::query_scalar(
            "SELECT unread_count FROM members WHERE convo_id=$1 AND user_did=$2",
        )
        .bind(&convo_id)
        .bind(&did)
        .fetch_one(&pool)
        .await
        .expect("unread after truncated read");
        assert_eq!(unread_after_truncated_read, 21);

        let (after_cursor, _, _, _, _, _) = fetch_app_messages(
            &pool,
            &did,
            &convo_id,
            Some(0),
            100,
            None,
            MAX_RAW_RESPONSE_BYTES,
        )
        .await
        .expect("bounded cursor query");
        assert_eq!(
            after_cursor
                .iter()
                .map(|message| message.seq)
                .collect::<Vec<_>>(),
            vec![1, 2, 3, 4]
        );

        let (follow_up, follow_last, _, _, _, _) = fetch_app_messages(
            &pool,
            &did,
            &convo_id,
            Some(4),
            100,
            None,
            MAX_RAW_RESPONSE_BYTES,
        )
        .await
        .expect("cursor progress");
        assert_eq!(
            follow_up
                .iter()
                .map(|message| message.seq)
                .collect::<Vec<_>>(),
            vec![5, 6, 7]
        );
        assert_eq!(follow_last, Some(7));
        let (joined, _, suppressed, _, _, _) = fetch_app_messages(
            &pool,
            &did,
            &convo_id,
            Some(0),
            100,
            Some(2),
            MAX_RAW_RESPONSE_BYTES,
        )
        .await
        .expect("join suppression");
        assert!(joined.is_empty());
        assert_eq!(suppressed, Some(7));
        sqlx::query("INSERT INTO messages (id,convo_id,message_type,epoch,seq,ciphertext) VALUES ($1,$2,'app',1,8,$3)")
            .bind(format!("legacy-{suffix}")).bind(&convo_id).bind(b"AAECAw==".to_vec())
            .execute(&pool).await.expect("legacy row");
        let (legacy, legacy_last, _, _, _, _) = fetch_app_messages(
            &pool,
            &did,
            &convo_id,
            Some(7),
            100,
            None,
            MAX_RAW_RESPONSE_BYTES,
        )
        .await
        .expect("legacy fetch");
        assert_eq!(legacy_last, Some(8));
        assert_eq!(legacy[0].ciphertext.as_ref(), &[0, 1, 2, 3]);
        assert!(serde_json::to_value(&legacy[0]).expect("legacy json")["createdAt"].is_string());
        sqlx::query("DELETE FROM messages WHERE convo_id=$1 AND seq=8")
            .bind(&convo_id)
            .execute(&pool)
            .await
            .expect("clear legacy");

        for wire_epoch in 0_i64..7 {
            let seq = wire_epoch + 100;
            sqlx::query("INSERT INTO messages (id, convo_id, message_type, epoch, wire_epoch, seq, ciphertext) VALUES ($1,$2,'commit',$3,$4,$5,$6)")
                .bind(format!("c-{suffix}-{seq}"))
                .bind(&convo_id)
                .bind(wire_epoch + 1)
                .bind(wire_epoch)
                .bind(seq)
                .bind(vec![seq as u8; 8 * 1024 * 1024])
                .execute(&pool).await.expect("commit");
        }
        sqlx::query("UPDATE conversations SET current_epoch=7 WHERE id=$1")
            .bind(&convo_id)
            .execute(&pool)
            .await
            .expect("epoch");
        let (commits, commit_bytes, _, _) =
            fetch_commits(&pool, &did, &convo_id, 1, Some(7), MAX_RAW_RESPONSE_BYTES)
                .await
                .expect("bounded commits");
        assert_eq!(
            commits
                .iter()
                .map(|message| message.seq)
                .collect::<Vec<_>>(),
            vec![100, 101, 102, 103, 104]
        );
        assert_eq!(commit_bytes, 40 * 1024 * 1024);
        let first_commit_json = serde_json::to_value(&commits[0]).expect("commit json");
        assert_eq!(first_commit_json["wireEpoch"], 0);
        assert_eq!(first_commit_json["resetGeneration"], 0);
        assert!(first_commit_json["createdAt"].is_string());
        let (caught_up, _, _, _) =
            fetch_commits(&pool, &did, &convo_id, 8, Some(7), MAX_RAW_RESPONSE_BYTES)
                .await
                .expect("caught up");
        assert!(caught_up.is_empty());
        assert_eq!(
            fetch_all_messages(&pool, &did, &convo_id, None, 100, None, (1, Some(7)))
                .await
                .unwrap_err(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "combined retrieval must fail closed rather than omit required commits"
        );

        // Combined retrieval reserves the shared raw budget for commits first.
        // Two 23 MiB apps would otherwise consume all 46 MiB and silently omit
        // this required 2 MiB commit. The commit is retained, only the newest
        // app prefix is admitted, while unread remains observational state.
        sqlx::query("DELETE FROM messages WHERE convo_id=$1")
            .bind(&convo_id)
            .execute(&pool)
            .await
            .expect("clear for combined priority");
        for seq in 1_i64..=2 {
            sqlx::query("INSERT INTO messages (id,convo_id,message_type,epoch,seq,ciphertext) VALUES ($1,$2,'app',1,$3,$4)")
                .bind(format!("priority-app-{suffix}-{seq}"))
                .bind(&convo_id)
                .bind(seq)
                .bind(vec![seq as u8; 23 * 1024 * 1024])
                .execute(&pool).await.expect("priority app");
        }
        sqlx::query("INSERT INTO messages (id,convo_id,message_type,epoch,wire_epoch,seq,ciphertext) VALUES ($1,$2,'commit',1,0,100,$3)")
            .bind(format!("priority-commit-{suffix}"))
            .bind(&convo_id)
            .bind(vec![9_u8; 2 * 1024 * 1024])
            .execute(&pool).await.expect("priority commit");
        sqlx::query("UPDATE conversations SET current_epoch=1 WHERE id=$1")
            .bind(&convo_id)
            .execute(&pool)
            .await
            .expect("priority epoch");
        sqlx::query("UPDATE members SET unread_count=17 WHERE convo_id=$1 AND user_did=$2")
            .bind(&convo_id)
            .bind(&did)
            .execute(&pool)
            .await
            .expect("priority unread");
        let (priority, _, _, _, _, app_incomplete) =
            fetch_all_messages(&pool, &did, &convo_id, None, 100, None, (1, Some(1)))
                .await
                .expect("commit-prioritized all response");
        assert_eq!(
            priority
                .iter()
                .map(|message| (message.seq, message.message_type.as_deref()))
                .collect::<Vec<_>>(),
            vec![(2, Some("app")), (100, Some("commit"))]
        );
        assert!(app_incomplete);
        let unread: i32 = sqlx::query_scalar(
            "SELECT unread_count FROM members WHERE convo_id=$1 AND user_did=$2",
        )
        .bind(&convo_id)
        .bind(&did)
        .fetch_one(&pool)
        .await
        .expect("priority unread preserved");
        assert_eq!(unread, 17);

        // Stable-snapshot regression: deleting an oversized first row between
        // eligibility and payload admission must not change the 413 decision.
        sqlx::query("DELETE FROM messages WHERE convo_id=$1")
            .bind(&convo_id)
            .execute(&pool)
            .await
            .expect("clear messages");
        sqlx::query("UPDATE members SET unread_count=9 WHERE convo_id=$1 AND user_did=$2")
            .bind(&convo_id)
            .bind(&did)
            .execute(&pool)
            .await
            .expect("unread");
        sqlx::query("INSERT INTO messages (id, convo_id, message_type, epoch, seq, ciphertext) VALUES ($1,$2,'app',1,1,$3)")
            .bind(format!("oversized-{suffix}")).bind(&convo_id)
            .bind(vec![0_u8; (MAX_RAW_RESPONSE_BYTES + 1) as usize])
            .execute(&pool).await.expect("oversized row");
        let reached = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        let proceed = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        *SNAPSHOT_TEST_HOOK
            .get_or_init(|| std::sync::Mutex::new(None))
            .lock()
            .expect("hook") = Some(KeyedSnapshotTestHook {
            convo_id: convo_id.clone(),
            hook: SnapshotTestHook {
                reached: reached.clone(),
                proceed: proceed.clone(),
            },
        });
        let snapshot_pool = pool.clone();
        let snapshot_did = did.clone();
        let snapshot_convo = convo_id.clone();
        let fetch = tokio::spawn(async move {
            fetch_app_messages(
                &snapshot_pool,
                &snapshot_did,
                &snapshot_convo,
                None,
                100,
                None,
                MAX_RAW_RESPONSE_BYTES,
            )
            .await
        });
        reached.wait().await;
        sqlx::query("DELETE FROM messages WHERE convo_id=$1")
            .bind(&convo_id)
            .execute(&pool)
            .await
            .expect("concurrent delete");
        proceed.wait().await;
        let (oversized, _, _, _, had_eligible, _) =
            fetch.await.expect("snapshot task").expect("snapshot fetch");
        assert!(oversized.is_empty());
        assert!(had_eligible);
        *SNAPSHOT_TEST_HOOK
            .get()
            .expect("hook state")
            .lock()
            .expect("hook") = None;
        let empty_output = GetMessagesOutput {
            messages: oversized,
            last_seq: None,
            gap_info: None,
            suppressed_before_join: None,
            extra_data: Default::default(),
        };
        assert_eq!(
            enforce_serialized_budget(empty_output, had_eligible, true).unwrap_err(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        let unread: i32 = sqlx::query_scalar(
            "SELECT unread_count FROM members WHERE convo_id=$1 AND user_did=$2",
        )
        .bind(&convo_id)
        .bind(&did)
        .fetch_one(&pool)
        .await
        .expect("unread after 413");
        assert_eq!(unread, 9);

        // The largest currently accepted artifacts remain individually retrievable.
        sqlx::query("INSERT INTO messages (id, convo_id, message_type, epoch, seq, ciphertext) VALUES ($1,$2,'app',1,1,$3)")
            .bind(format!("max-app-{suffix}")).bind(&convo_id)
            .bind(vec![1_u8; 10 * 1024 * 1024]).execute(&pool).await.expect("max app");
        let (max_app, _, _, _, _, _) = fetch_app_messages(
            &pool,
            &did,
            &convo_id,
            Some(0),
            100,
            None,
            MAX_RAW_RESPONSE_BYTES,
        )
        .await
        .expect("max app fetch");
        assert_eq!(max_app.len(), 1);
        sqlx::query("DELETE FROM messages WHERE convo_id=$1")
            .bind(&convo_id)
            .execute(&pool)
            .await
            .expect("clear app");
        sqlx::query("INSERT INTO messages (id, convo_id, message_type, epoch, wire_epoch, seq, ciphertext) VALUES ($1,$2,'commit',1,0,1,$3)")
            .bind(format!("max-commit-{suffix}")).bind(&convo_id)
            .bind(vec![2_u8; 44 * 1024 * 1024]).execute(&pool).await.expect("max commit");
        let (max_commit, _, _, _) =
            fetch_commits(&pool, &did, &convo_id, 1, Some(1), MAX_RAW_RESPONSE_BYTES)
                .await
                .expect("max commit fetch");
        assert_eq!(max_commit.len(), 1);

        // Tiny rows retain the 100 app / 50 commit / 150 combined caps.
        sqlx::query("DELETE FROM messages WHERE convo_id=$1")
            .bind(&convo_id)
            .execute(&pool)
            .await
            .expect("clear max");
        for seq in 1_i64..=101 {
            sqlx::query("INSERT INTO messages (id, convo_id, message_type, epoch, seq, ciphertext) VALUES ($1,$2,'app',1,$3,$4)")
                .bind(format!("tiny-a-{suffix}-{seq}")).bind(&convo_id).bind(seq)
                .bind(vec![1_u8]).execute(&pool).await.expect("tiny app");
        }
        for wire_epoch in 0_i64..51 {
            let seq = 1000 + wire_epoch;
            sqlx::query("INSERT INTO messages (id, convo_id, message_type, epoch, wire_epoch, seq, ciphertext) VALUES ($1,$2,'commit',$3,$4,$5,$6)")
                .bind(format!("tiny-c-{suffix}-{seq}")).bind(&convo_id)
                .bind(wire_epoch + 1).bind(wire_epoch).bind(seq).bind(vec![2_u8])
                .execute(&pool).await.expect("tiny commit");
        }
        let explain_sql = format!("EXPLAIN (ANALYZE, FORMAT TEXT) {APP_NO_SINCE_QUERY}");
        let plan: Vec<String> = sqlx::query_scalar(&explain_sql)
            .bind(&convo_id)
            .bind(100_i64)
            .bind(None::<i64>)
            .bind(MAX_RAW_RESPONSE_BYTES)
            .fetch_all(&pool)
            .await
            .expect("bounded no-since plan");
        let window_line = plan
            .iter()
            .find(|line| line.contains("WindowAgg") && line.contains("actual time="))
            .expect("WindowAgg execution line");
        let window_rows: i64 = window_line
            .split("actual time=")
            .nth(1)
            .and_then(|actual| actual.split("rows=").nth(1))
            .and_then(|rows| rows.split_whitespace().next())
            .expect("WindowAgg actual rows")
            .parse()
            .expect("numeric WindowAgg rows");
        assert_eq!(
            window_rows, 100,
            "the no-since window must see only the pre-limited candidate page"
        );
        sqlx::query("UPDATE conversations SET current_epoch=51 WHERE id=$1")
            .bind(&convo_id)
            .execute(&pool)
            .await
            .expect("tiny epoch");
        let (tiny_apps, _, _, tiny_app_bytes, _, _) = fetch_app_messages(
            &pool,
            &did,
            &convo_id,
            Some(0),
            100,
            None,
            MAX_RAW_RESPONSE_BYTES,
        )
        .await
        .expect("tiny apps");
        let (tiny_commits, _, _, _) = fetch_commits(
            &pool,
            &did,
            &convo_id,
            1,
            Some(51),
            MAX_RAW_RESPONSE_BYTES - tiny_app_bytes,
        )
        .await
        .expect("tiny commits");
        assert_eq!(tiny_apps.len(), 100);
        assert_eq!(tiny_commits.len(), 50);
        assert_eq!(tiny_apps.len() + tiny_commits.len(), 150);

        // `all` observes app and commit rows from one snapshot. A commit
        // inserted after the commit-priority phase cannot appear in the same response.
        sqlx::query("DELETE FROM messages WHERE convo_id=$1")
            .bind(&convo_id)
            .execute(&pool)
            .await
            .expect("clear tiny");
        sqlx::query("INSERT INTO messages (id,convo_id,message_type,epoch,seq,ciphertext) VALUES ($1,$2,'app',1,1,$3)")
            .bind(format!("snapshot-app-{suffix}")).bind(&convo_id).bind(vec![1_u8])
            .execute(&pool).await.expect("snapshot app");
        sqlx::query("INSERT INTO messages (id,convo_id,message_type,epoch,wire_epoch,seq,ciphertext) VALUES ($1,$2,'commit',1,0,100,$3)")
            .bind(format!("snapshot-commit-{suffix}")).bind(&convo_id).bind(vec![2_u8])
            .execute(&pool).await.expect("snapshot commit");
        sqlx::query("UPDATE conversations SET current_epoch=1 WHERE id=$1")
            .bind(&convo_id)
            .execute(&pool)
            .await
            .expect("snapshot epoch");
        let reached = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        let proceed = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        *COMBINED_SNAPSHOT_TEST_HOOK
            .get_or_init(|| std::sync::Mutex::new(None))
            .lock()
            .expect("combined hook") = Some(KeyedSnapshotTestHook {
            convo_id: convo_id.clone(),
            hook: SnapshotTestHook {
                reached: reached.clone(),
                proceed: proceed.clone(),
            },
        });
        let all_pool = pool.clone();
        let all_did = did.clone();
        let all_convo = convo_id.clone();
        let all_fetch = tokio::spawn(async move {
            fetch_all_messages(
                &all_pool,
                &all_did,
                &all_convo,
                Some(0),
                100,
                None,
                (1, Some(2)),
            )
            .await
        });
        reached.wait().await;
        sqlx::query("INSERT INTO messages (id,convo_id,message_type,epoch,wire_epoch,seq,ciphertext) VALUES ($1,$2,'commit',2,1,101,$3)")
            .bind(format!("snapshot-late-{suffix}")).bind(&convo_id).bind(vec![3_u8])
            .execute(&pool).await.expect("late commit");
        sqlx::query("UPDATE conversations SET current_epoch=2 WHERE id=$1")
            .bind(&convo_id)
            .execute(&pool)
            .await
            .expect("late epoch");
        proceed.wait().await;
        let (snapshot_messages, _, _, _, _, _) =
            all_fetch.await.expect("all task").expect("all snapshot");
        *COMBINED_SNAPSHOT_TEST_HOOK
            .get()
            .expect("combined state")
            .lock()
            .expect("combined hook") = None;
        assert_eq!(
            snapshot_messages
                .iter()
                .map(|message| message.seq)
                .collect::<Vec<_>>(),
            vec![1, 100]
        );

        // Exercise the production 20-second deadline over a real PostgreSQL
        // retrieval stalled after eligibility, and prove unread is untouched.
        sqlx::query("UPDATE members SET unread_count=12 WHERE convo_id=$1 AND user_did=$2")
            .bind(&convo_id)
            .bind(&did)
            .execute(&pool)
            .await
            .expect("timeout unread");
        *SNAPSHOT_TEST_HOOK
            .get()
            .expect("hook state")
            .lock()
            .expect("hook") = Some(KeyedSnapshotTestHook {
            convo_id: convo_id.clone(),
            hook: SnapshotTestHook {
                reached: std::sync::Arc::new(tokio::sync::Barrier::new(2)),
                proceed: std::sync::Arc::new(tokio::sync::Barrier::new(2)),
            },
        });
        let timed_out = with_retrieval_deadline(fetch_app_messages(
            &pool,
            &did,
            &convo_id,
            Some(0),
            100,
            None,
            MAX_RAW_RESPONSE_BYTES,
        ))
        .await;
        assert_eq!(timed_out.unwrap_err(), StatusCode::REQUEST_TIMEOUT);
        *SNAPSHOT_TEST_HOOK
            .get()
            .expect("hook state")
            .lock()
            .expect("hook") = None;
        let unread: i32 = sqlx::query_scalar(
            "SELECT unread_count FROM members WHERE convo_id=$1 AND user_did=$2",
        )
        .bind(&convo_id)
        .bind(&did)
        .fetch_one(&pool)
        .await
        .expect("unread after timeout");
        assert_eq!(unread, 12);

        sqlx::query("DELETE FROM conversations WHERE id=$1")
            .bind(&convo_id)
            .execute(&pool)
            .await
            .expect("cleanup");
    }
}
