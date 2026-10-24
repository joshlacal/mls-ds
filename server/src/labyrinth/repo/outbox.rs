//! Durable DS-to-DS Labyrinth jobs (`labyrinth.relay_outbox`, migration
//! `20261004100009`; second security review, findings 4 and 5).
//!
//! Two jobs exist, both `labyrinthRelay` calls:
//!
//! * `purgeAuthor` (home DS → each remote sequencer of a conversation the
//!   account takes or took part in, departed ones included: they still hold
//!   its authored items) carries the device's signed `deleteAccountData`
//!   write body, which the sequencer accepts for up to
//!   [`PURGE_MAX_AGE_DAYS`] so retries outlive the 5-minute write window;
//! * `invalidateMessages` (sequencer → each remote member's home DS)
//!   announces redacted messages so their attachment references go too.
//!
//! The local transaction that redacts enqueues the jobs, so nothing is lost
//! when a peer is down. A worker (`handlers::labyrinth::outbox`) delivers
//! them with exponential backoff; a job older than [`JOB_MAX_AGE_DAYS`], or
//! refused permanently by the peer, is marked `dead` and logged.

use chrono::{DateTime, Duration, Utc};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::labyrinth::error::{LabyrinthError, LabyrinthResult};
use crate::labyrinth::relay::{RelayOp, RelayRequest};
use crate::labyrinth::wire::bytes::Bytes;
use crate::storage::DbPool;

/// How long a sequencer accepts a relayed `purgeAuthor` after it was signed.
pub const PURGE_MAX_AGE_DAYS: i64 = 30;
/// Jobs are retried for this long (inside the purge acceptance window).
pub const JOB_MAX_AGE_DAYS: i64 = 29;
/// A claimed job is invisible to other workers for this long.
const LEASE_SECONDS: i64 = 120;

/// One claimed job.
pub struct Job {
    pub job_id: i64,
    pub target_ds: String,
    pub request: RelayRequest,
    pub attempts: i32,
    pub created_at: DateTime<Utc>,
}

/// Enqueue `request` for `target_ds`.
pub async fn enqueue(
    conn: &mut PgConnection,
    target_ds: &str,
    request: &RelayRequest,
    at: DateTime<Utc>,
) -> LabyrinthResult<()> {
    let op = RelayOp::parse(&request.op)?;
    if !matches!(op, RelayOp::PurgeAuthor | RelayOp::InvalidateMessages) {
        return Err(LabyrinthError::internal());
    }
    sqlx::query(
        "INSERT INTO labyrinth.relay_outbox \
           (target_ds, op, request, next_attempt_at, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $4, $4)",
    )
    .bind(target_ds)
    .bind(op.name())
    .bind(sqlx::types::Json(request))
    .bind(at)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// The DSes other than this one that are home to some participant of the
/// conversation, past or present (they may hold attachment references).
pub async fn member_home_dses(
    conn: &mut PgConnection,
    conversation: Uuid,
) -> LabyrinthResult<Vec<String>> {
    let all: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT ds_did FROM chat.participants \
          WHERE conversation_id = $1 AND ds_did IS NOT NULL ORDER BY 1",
    )
    .bind(conversation)
    .fetch_all(&mut *conn)
    .await?;
    let me = crate::identity::service_did();
    Ok(all
        .into_iter()
        .filter(|d| !crate::identity::dids_equivalent(d, &me))
        .collect())
}

/// Enqueue an `invalidateMessages` announcement of `author`'s redacted
/// `message_ids` in `conversation` to every remote member home DS.
pub async fn announce_redaction(
    conn: &mut PgConnection,
    conversation: Uuid,
    author: &str,
    message_ids: &[String],
    at: DateTime<Utc>,
) -> LabyrinthResult<()> {
    if message_ids.is_empty() {
        return Ok(());
    }
    let targets = member_home_dses(conn, conversation).await?;
    if targets.is_empty() {
        return Ok(());
    }
    let payload = serde_json::to_vec(&serde_json::json!({
        "threadId": conversation.hyphenated().to_string(),
        "messageIds": message_ids,
    }))
    .map_err(|_| LabyrinthError::internal())?;
    let request = RelayRequest {
        op: RelayOp::InvalidateMessages.name().to_owned(),
        actor_did: author.to_owned(),
        actor_device_id: None,
        query: None,
        payload: Some(Bytes(payload)),
        write_body: None,
        write_signature: None,
        read_header: None,
        read_signature: None,
    };
    for target in targets {
        enqueue(conn, &target, &request, at).await?;
    }
    Ok(())
}

/// Claim up to `limit` due jobs (lease them for a while).
pub async fn claim_due(pool: &DbPool, now: DateTime<Utc>, limit: i64) -> LabyrinthResult<Vec<Job>> {
    let rows: Vec<(i64, String, sqlx::types::Json<RelayRequest>, i32, DateTime<Utc>)> =
        sqlx::query_as(
            "UPDATE labyrinth.relay_outbox o \
                SET attempts = o.attempts + 1, next_attempt_at = $2, updated_at = $1 \
              WHERE o.job_id IN ( \
                    SELECT job_id FROM labyrinth.relay_outbox \
                     WHERE status = 'pending' AND next_attempt_at <= $1 \
                     ORDER BY next_attempt_at LIMIT $3 FOR UPDATE SKIP LOCKED) \
             RETURNING o.job_id, o.target_ds, o.request, o.attempts, o.created_at",
        )
        .bind(now)
        .bind(now + Duration::seconds(LEASE_SECONDS))
        .bind(limit)
        .fetch_all(pool)
        .await?;
    Ok(rows
        .into_iter()
        .map(|(job_id, target_ds, request, attempts, created_at)| Job {
            job_id,
            target_ds,
            request: request.0,
            attempts,
            created_at,
        })
        .collect())
}

/// Mark a job delivered.
pub async fn complete(pool: &DbPool, job_id: i64, now: DateTime<Utc>) -> LabyrinthResult<()> {
    sqlx::query(
        "UPDATE labyrinth.relay_outbox SET status = 'done', last_error = NULL, updated_at = $2 \
          WHERE job_id = $1",
    )
    .bind(job_id)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

/// Record a failed attempt: retry with backoff, or give up when the peer
/// refused for good or the job is too old.
pub async fn fail(
    pool: &DbPool,
    job: &Job,
    error: &str,
    permanent: bool,
    now: DateTime<Utc>,
) -> LabyrinthResult<()> {
    let expired = now - job.created_at > Duration::days(JOB_MAX_AGE_DAYS);
    let dead = permanent || expired;
    let backoff = Duration::seconds(30 * (1i64 << job.attempts.clamp(0, 10)))
        .min(Duration::hours(6));
    if dead {
        tracing::error!(job = job.job_id, target = %job.target_ds, op = %job.request.op,
                        error, "labyrinth relay job abandoned");
    }
    sqlx::query(
        "UPDATE labyrinth.relay_outbox \
            SET status = CASE WHEN $2 THEN 'dead' ELSE 'pending' END, \
                next_attempt_at = $3, last_error = left($4, 2048), updated_at = $5 \
          WHERE job_id = $1",
    )
    .bind(job.job_id)
    .bind(dead)
    .bind(now + backoff)
    .bind(error)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}
