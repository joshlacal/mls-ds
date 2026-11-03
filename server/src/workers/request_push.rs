//! Durable D2 `directRequest` wakes (`blue.catbird.push.deliver`).
//!
//! Two durable queues share one lease/retry state machine:
//! - a coordinator's publication `chat.outbox` notification row, mapped to the
//!   recipient's devices by `chat.direct_request_push_events` in the
//!   publication transaction;
//! - a transport-only recipient home's `chat.direct_request_transport_wakes`
//!   row, enqueued by trigger with each `deliverDirectRequest` inbox row (one
//!   per recipient device) in the ingestion transaction.
//!
//! Every attempt re-checks canonical eligibility in this DS's own database
//! (request still pending and importable, device active and still a leaf) and
//! then wakes only devices homed here that registered a Push Gateway through
//! `registerPushGateway`. A request that stopped being eligible completes with
//! zero wakes. The wake carries coordinates only: never the sender, plaintext,
//! or ciphertext.

use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use sqlx::{PgPool, Row};
use tracing::warn;
use uuid::Uuid;

use crate::{
    chat_protocol::{
        relationship_policy::ProductionRelationshipAuthority,
        repository::relationship::RelationshipRepositoryError,
    },
    handlers::chat::ChatRuntime,
    push_gateway::client::{PushDispatchError, PushGatewayClient, PushWakeDispatch, PushWakeKind},
};

// A claim lease only has to cover the eligibility read; dispatch renews it for
// its bounded gateway attempts (10-second HTTP timeout each, see
// `PushGatewayClient`).
const LEASE_SECONDS: i64 = 15;
const GATEWAY_ATTEMPT_SECONDS: i64 = 11;
// One gateway attempt is bounded by `PushGatewayClient`'s 10-second timeout.
const _: () = assert!(GATEWAY_ATTEMPT_SECONDS > 10);
/// A wake still undelivered a day after its row was created is moot and the
/// row ends `failed`: the wake's own lifetime, not a retry budget. Within it a
/// failure that decided nothing is retried however many attempts it takes.
const WAKE_LIFETIME_HOURS: i64 = 24;

/// Why one wake attempt stopped. This DS's own storage, a relationship source
/// or a gateway that could not answer now decided nothing (`Retry`); an
/// unusable policy answer, an invalid stored row or a gateway's refusal is
/// `Permanent` and fails the row now.
#[derive(Debug)]
enum WakeFailure {
    Retry(String),
    Permanent(String),
}

impl WakeFailure {
    fn policy(error: RelationshipRepositoryError) -> Self {
        use RelationshipRepositoryError as R;
        match error {
            R::Database(error) => Self::Retry(format!("relationship policy storage: {error}")),
            R::Unavailable => Self::Retry("relationship policy source unavailable".to_owned()),
            R::InvalidAuthorityConfiguration(error) => {
                Self::Retry(format!("relationship authority configuration: {error:?}"))
            }
            R::InvalidProjection => {
                Self::Permanent("relationship policy evidence unusable".to_owned())
            }
        }
    }
}

impl From<sqlx::Error> for WakeFailure {
    fn from(error: sqlx::Error) -> Self {
        Self::Retry(format!("direct-request wake storage: {error}"))
    }
}

impl From<PushDispatchError> for WakeFailure {
    fn from(error: PushDispatchError) -> Self {
        match error {
            PushDispatchError::Database(_) | PushDispatchError::Unavailable(_) => {
                Self::Retry(error.to_string())
            }
            PushDispatchError::Rejected(_) => Self::Permanent(error.to_string()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Queue {
    /// `chat.outbox` notification row of a local publication.
    Publication,
    /// `chat.direct_request_transport_wakes` row of a transport-only home.
    Transport,
}

impl Queue {
    fn table(self) -> &'static str {
        match self {
            Self::Publication => "chat.outbox",
            Self::Transport => "chat.direct_request_transport_wakes",
        }
    }

    fn key(self) -> &'static str {
        match self {
            Self::Publication => "outbox_id",
            Self::Transport => "delivery_id",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct ClaimedWake {
    queue: Queue,
    id: Uuid,
    lease_owner: Uuid,
}

/// What one pass over the queues did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WakeRun {
    /// Rows leased by this pass.
    pub claimed: usize,
    /// Gateway deliveries the gateways acknowledged.
    pub woken: usize,
    /// Rows completed without a wake because the request was no longer eligible.
    pub suppressed: usize,
}

pub async fn run_request_push_worker(pool: PgPool, runtime: Arc<ChatRuntime>) {
    let Some(client) = runtime.request_push_client().cloned() else {
        return;
    };
    let authority = runtime.relationship_authority().clone();
    let worker = Uuid::new_v4();
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
    loop {
        interval.tick().await;
        for queue in [Queue::Publication, Queue::Transport] {
            if let Err(error) = run_once(&pool, &client, &authority, worker, queue, None).await {
                warn!(reason = error, ?queue, "direct-request wake deferred");
            }
        }
    }
}

async fn run_once(
    pool: &PgPool,
    client: &PushGatewayClient,
    authority: &ProductionRelationshipAuthority,
    worker: Uuid,
    queue: Queue,
    target: Option<Uuid>,
) -> Result<WakeRun, String> {
    let mut run = WakeRun::default();
    let Some(row) = claim(pool, worker, queue, target)
        .await
        .map_err(|_| "direct-request wake claim failed".to_owned())?
    else {
        return Ok(run);
    };
    run.claimed = 1;
    let wake = match eligible_wake(pool, &row, authority).await {
        Ok(wake) => wake,
        // Fail closed: no wake while the live relationship policy (or the
        // eligibility read) could not answer; retry it with backoff.
        Err(failure) => return settle_failure(pool, &row, failure).await,
    };
    let Some((targets, wake)) = wake else {
        mark_delivered(pool, &row)
            .await
            .map_err(|_| "direct-request wake suppression failed".to_owned())?;
        run.suppressed = 1;
        return Ok(run);
    };
    let seconds = GATEWAY_ATTEMPT_SECONDS.saturating_mul(targets.len() as i64) + LEASE_SECONDS;
    if !renew_lease(pool, row.queue, row.id, row.lease_owner, seconds)
        .await
        .map_err(|_| "direct-request wake lease preparation failed".to_owned())?
    {
        return Ok(run);
    }
    match client
        .dispatch_for_local_recipients(pool, &targets, wake)
        .await
    {
        Ok(woken) => {
            mark_delivered(pool, &row)
                .await
                .map_err(|_| "direct-request wake completion failed".to_owned())?;
            run.woken = woken;
            Ok(run)
        }
        Err(error) => settle_failure(pool, &row, error.into()).await,
    }
}

/// Record `row`'s failed attempt by its class and report it.
async fn settle_failure(
    pool: &PgPool,
    row: &ClaimedWake,
    failure: WakeFailure,
) -> Result<WakeRun, String> {
    let (permanent, reason) = match failure {
        WakeFailure::Retry(reason) => (false, reason),
        WakeFailure::Permanent(reason) => (true, reason),
    };
    mark_retry_or_failed(pool, row, permanent)
        .await
        .map_err(|_| "direct-request wake retry transition failed".to_owned())?;
    let outcome = if permanent { "failed" } else { "deferred" };
    Err(format!("direct-request wake {outcome}: {reason}"))
}

/// Test-support seam for the held-row-lock lease-expiry regression. It invokes
/// the production lock-and-database-clock path without starting an HTTP worker.
#[cfg(feature = "test-support")]
pub async fn renew_request_push_lease_for_test(
    pool: &PgPool,
    outbox_id: Uuid,
    lease_owner: Uuid,
) -> Result<bool, sqlx::Error> {
    renew_lease(
        pool,
        Queue::Publication,
        outbox_id,
        lease_owner,
        LEASE_SECONDS,
    )
    .await
}

/// The runtime's Push Gateway client and relationship authority, as the
/// background worker uses them.
#[cfg(feature = "test-support")]
fn test_parts(
    runtime: &ChatRuntime,
) -> Result<(&PushGatewayClient, &ProductionRelationshipAuthority), String> {
    let client = runtime
        .push_gateway_client()
        .ok_or_else(|| "push gateway client unavailable".to_owned())?;
    Ok((client, runtime.relationship_authority()))
}

/// One production pass over both queues, without the polling loop.
#[cfg(feature = "test-support")]
pub async fn run_request_push_once_for_test(
    pool: &PgPool,
    runtime: &ChatRuntime,
) -> Result<WakeRun, String> {
    let (client, authority) = test_parts(runtime)?;
    let worker = Uuid::new_v4();
    let local = run_once(pool, client, authority, worker, Queue::Publication, None).await?;
    let transport = run_once(pool, client, authority, worker, Queue::Transport, None).await?;
    Ok(WakeRun {
        claimed: local.claimed + transport.claimed,
        woken: local.woken + transport.woken,
        suppressed: local.suppressed + transport.suppressed,
    })
}

/// One production attempt at exactly one publication's push event.
#[cfg(feature = "test-support")]
pub async fn run_request_push_event_once_for_test(
    pool: &PgPool,
    runtime: &ChatRuntime,
    event_id: Uuid,
) -> Result<WakeRun, String> {
    let (client, authority) = test_parts(runtime)?;
    let queue = Queue::Publication;
    run_once(
        pool,
        client,
        authority,
        Uuid::new_v4(),
        queue,
        Some(event_id),
    )
    .await
}

/// One production attempt at exactly one transport inbox row's wake.
#[cfg(feature = "test-support")]
pub async fn run_transport_wake_once_for_test(
    pool: &PgPool,
    runtime: &ChatRuntime,
    delivery_id: Uuid,
) -> Result<WakeRun, String> {
    let (client, authority) = test_parts(runtime)?;
    let queue = Queue::Transport;
    run_once(
        pool,
        client,
        authority,
        Uuid::new_v4(),
        queue,
        Some(delivery_id),
    )
    .await
}

async fn claim(
    pool: &PgPool,
    worker: Uuid,
    queue: Queue,
    target: Option<Uuid>,
) -> Result<Option<ClaimedWake>, sqlx::Error> {
    let claimable = match queue {
        Queue::Publication => {
            "SELECT work.outbox_id AS id FROM chat.outbox work \
               JOIN chat.direct_request_push_events mapped ON mapped.outbox_id=work.outbox_id \
              WHERE work.work_kind='notification' AND ($3::uuid IS NULL OR mapped.event_id=$3) \
                AND ((work.status='pending' AND work.next_attempt_at<=clock_timestamp()) \
                  OR (work.status='leased' AND work.lease_expires_at<=clock_timestamp())) \
              ORDER BY work.event_position FOR UPDATE OF work SKIP LOCKED LIMIT 1"
        }
        Queue::Transport => {
            "SELECT work.delivery_id AS id FROM chat.direct_request_transport_wakes work \
              WHERE ($3::uuid IS NULL OR work.delivery_id=$3) \
                AND ((work.status='pending' AND work.next_attempt_at<=clock_timestamp()) \
                  OR (work.status='leased' AND work.lease_expires_at<=clock_timestamp())) \
              ORDER BY work.created_at,work.delivery_id FOR UPDATE SKIP LOCKED LIMIT 1"
        }
    };
    let id: Option<Uuid> = sqlx::query_scalar(&format!(
        "WITH claimable AS ({claimable}) \
         UPDATE {table} work SET status='leased',lease_owner=$1,\
                lease_expires_at=clock_timestamp()+make_interval(secs=>$2) \
           FROM claimable WHERE work.{key}=claimable.id RETURNING work.{key}",
        table = queue.table(),
        key = queue.key(),
    ))
    .bind(worker)
    .bind(LEASE_SECONDS)
    .bind(target)
    .fetch_optional(pool)
    .await?;
    Ok(id.map(|id| ClaimedWake {
        queue,
        id,
        lease_owner: worker,
    }))
}

/// The devices to wake and the wake itself, or `None` when the request is no
/// longer canonically eligible here. Binding and home checks happen per device
/// in [`PushGatewayClient::dispatch_for_local_recipients`].
async fn eligible_wake(
    pool: &PgPool,
    row: &ClaimedWake,
    authority: &ProductionRelationshipAuthority,
) -> Result<Option<(Vec<(String, Uuid)>, PushWakeDispatch)>, WakeFailure> {
    // ponytail: unlocked READ COMMITTED snapshot; an acceptance committing
    // mid-dispatch can still be woken once (the client refetches and finds it
    // accepted). Lock the conversation row if that ever matters.
    let mut tx = pool.begin().await?;
    let rows = match row.queue {
        Queue::Publication => {
            sqlx::query(
                "SELECT e.conversation_id,e.sender_did,p.generation,t.entry_seq AS seq,s.epoch,\
                        r.recipient_did,r.recipient_device_id \
                   FROM chat.direct_request_push_events e \
                   JOIN chat.direct_request_publications p ON p.request_id=e.request_id \
                   JOIN chat.conversations c ON c.conversation_id=e.conversation_id \
                   JOIN chat.transitions t ON t.transition_id=e.request_id \
                   JOIN chat.generation_states s ON (s.conversation_id,s.generation,s.state_version) \
                        =(p.conversation_id,p.generation,p.state_version) \
                   JOIN chat.direct_request_push_event_recipients r ON r.event_id=e.event_id \
                   JOIN chat.direct_request_device_deliveries d \
                     ON (d.request_id,d.owner_did,d.owner_device_id) \
                       =(r.request_id,r.recipient_did,r.recipient_device_id) \
                   JOIN chat.devices device \
                     ON (device.user_did,device.device_id)=(r.recipient_did,r.recipient_device_id) \
                  WHERE e.outbox_id=$1 AND c.lifecycle='active' AND c.protocol_version='2' \
                    AND p.import_until>clock_timestamp() AND d.import_until>clock_timestamp() \
                    AND device.status='active' \
                    AND NOT EXISTS(SELECT 1 FROM chat.direct_request_lifecycle l \
                         WHERE l.request_id=e.request_id AND l.consent IS NOT NULL) \
                    AND EXISTS(SELECT 1 FROM chat.participants pa \
                         WHERE pa.conversation_id=e.conversation_id AND pa.user_did=e.recipient_did \
                           AND pa.current_membership AND pa.status='pending') \
                    AND EXISTS(SELECT 1 FROM chat.member_devices m \
                         WHERE m.conversation_id=e.conversation_id AND m.generation=c.current_generation \
                           AND m.user_did=r.recipient_did AND m.device_id=r.recipient_device_id \
                           AND m.active AND m.removed_at IS NULL) \
                  ORDER BY r.recipient_device_id::text",
            )
            .bind(row.id)
            .fetch_all(&mut *tx)
            .await
        }
        Queue::Transport => {
            sqlx::query(
                "SELECT i.conversation_id,i.sender_did,i.recipient_did,i.recipient_device_id,\
                        COALESCE(i.request_entry,i.redacted_request_entry) AS entry \
                   FROM chat.direct_request_transport_inbox i \
                   JOIN chat.devices device \
                     ON (device.user_did,device.device_id)=(i.recipient_did,i.recipient_device_id) \
                  WHERE i.delivery_id=$1 AND i.status='pending' \
                    AND i.import_until>clock_timestamp() AND device.status='active'",
            )
            .bind(row.id)
            .fetch_all(&mut *tx)
            .await
        }
    }?;
    let Some(first) = rows.first() else {
        return Ok(None);
    };
    // A block placed after publication must still stop the wake: collect the
    // pair's live block graph now, under this transaction.
    let sender: String = first.get("sender_did");
    let recipient: String = first.get("recipient_did");
    let mut read_set = Sha256::new();
    read_set.update(b"CATBIRD-DIRECT-REQUEST-WAKE-POLICY-READ-SET\0");
    read_set.update(row.queue.table().as_bytes());
    read_set.update(row.id.as_bytes());
    for device in &rows {
        read_set.update(device.get::<Uuid, _>("recipient_device_id").as_bytes());
    }
    let allowed =
        crate::chat_protocol::repository::relationship::verify_direct_request_wake_policy(
            &mut tx,
            &sender,
            &recipient,
            Sha256::digest(b"CATBIRD-DIRECT-REQUEST-WAKE-WORKER\0").into(),
            read_set.finalize().into(),
            authority,
        )
        .await
        .map_err(WakeFailure::policy)?;
    tx.commit().await?;
    if !allowed {
        return Ok(None);
    }
    let (generation, seq, epoch) = match row.queue {
        Queue::Publication => (
            first.get::<i64, _>("generation"),
            first.get::<i64, _>("seq"),
            first.get::<i64, _>("epoch"),
        ),
        Queue::Transport => {
            // The stored opening is the sender-signed entry (or its redaction);
            // its coordinates are the published group's first state.
            let entry: Value =
                serde_json::from_slice(&first.get::<Vec<u8>, _>("entry")).map_err(|error| {
                    WakeFailure::Permanent(format!("stored request entry is not JSON: {error}"))
                })?;
            let next = |field: &str| {
                entry
                    .pointer(&format!("/signedRequest/body/next/{field}"))
                    .and_then(Value::as_i64)
            };
            (
                next("generation").unwrap_or(0),
                entry.get("seq").and_then(Value::as_i64).unwrap_or(1),
                next("epoch").unwrap_or(1),
            )
        }
    };
    let wake = PushWakeDispatch {
        wake_kind: PushWakeKind::DirectRequest,
        conversation_id: first.get("conversation_id"),
        generation,
        seq,
        epoch,
        ciphertext: None,
    };
    let targets = rows
        .iter()
        .map(|device| {
            (
                device.get::<String, _>("recipient_did"),
                device.get::<Uuid, _>("recipient_device_id"),
            )
        })
        .collect();
    Ok(Some((targets, wake)))
}

/// Fail a row past its wake lifetime before any network side effect;
/// otherwise renew only the exact still-live owner lease for `seconds`.
async fn renew_lease(
    pool: &PgPool,
    queue: Queue,
    id: Uuid,
    lease_owner_expected: Uuid,
    seconds: i64,
) -> Result<bool, sqlx::Error> {
    let (table, key) = (queue.table(), queue.key());
    let mut tx = pool.begin().await?;
    let state = sqlx::query(&format!(
        "SELECT status,lease_owner,lease_expires_at,attempt_count,created_at \
           FROM {table} WHERE {key}=$1 FOR UPDATE"
    ))
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(sqlx::Error::RowNotFound)?;
    let status: String = state.get("status");
    let lease_owner: Option<Uuid> = state.get("lease_owner");
    if status != "leased" || lease_owner != Some(lease_owner_expected) {
        return Err(sqlx::Error::Protocol(
            "request push dispatch lease lost or expired".into(),
        ));
    }
    // Sample the database clock only after taking the row lock. A waiter can
    // therefore never renew a lease that expired while another transaction
    // held this row.
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *tx)
        .await?;
    let created_at: DateTime<Utc> = state.get("created_at");
    if created_at <= now - Duration::hours(WAKE_LIFETIME_HOURS) {
        sqlx::query(&format!(
            "UPDATE {table} SET status='failed',lease_owner=NULL,lease_expires_at=NULL \
             WHERE {key}=$1"
        ))
        .bind(id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        return Ok(false);
    }
    let lease_expires_at: Option<DateTime<Utc>> = state.get("lease_expires_at");
    if lease_expires_at.is_none_or(|expires_at| expires_at <= now) {
        return Err(sqlx::Error::Protocol(
            "request push dispatch lease lost or expired".into(),
        ));
    }
    sqlx::query(&format!(
        "UPDATE {table} SET lease_expires_at=$2 WHERE {key}=$1"
    ))
    .bind(id)
    .bind(now + Duration::seconds(seconds))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(true)
}

/// Lock the row and return the database clock iff this worker still holds a
/// live lease on it.
async fn lock_live_lease(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    row: &ClaimedWake,
) -> Result<(sqlx::postgres::PgRow, DateTime<Utc>), sqlx::Error> {
    let state = sqlx::query(&format!(
        "SELECT status,lease_owner,lease_expires_at,attempt_count,created_at \
           FROM {} WHERE {}=$1 FOR UPDATE",
        row.queue.table(),
        row.queue.key()
    ))
    .bind(row.id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(sqlx::Error::RowNotFound)?;
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await?;
    let status: String = state.get("status");
    let lease_owner: Option<Uuid> = state.get("lease_owner");
    let lease_expires_at: Option<DateTime<Utc>> = state.get("lease_expires_at");
    if status != "leased"
        || lease_owner != Some(row.lease_owner)
        || lease_expires_at.is_none_or(|expires_at| expires_at <= now)
    {
        return Err(sqlx::Error::Protocol("request push lease lost".into()));
    }
    Ok((state, now))
}

async fn mark_delivered(pool: &PgPool, row: &ClaimedWake) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    let (_, now) = lock_live_lease(&mut tx, row).await?;
    sqlx::query(&format!(
        "UPDATE {} SET status='delivered',delivered_at=$2 WHERE {}=$1",
        row.queue.table(),
        row.queue.key()
    ))
    .bind(row.id)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    tx.commit().await
}

/// Settle `row`'s failed attempt: `failed` when `permanent` or past the
/// wake's lifetime, otherwise `pending` with backoff, whatever its attempt
/// count.
async fn mark_retry_or_failed(
    pool: &PgPool,
    row: &ClaimedWake,
    permanent: bool,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    let (state, now) = lock_live_lease(&mut tx, row).await?;
    let attempt_count: i64 = state.get("attempt_count");
    let created_at: DateTime<Utc> = state.get("created_at");
    let next_attempt_count = attempt_count.saturating_add(1);
    let next_status = if permanent || created_at <= now - Duration::hours(WAKE_LIFETIME_HOURS) {
        "failed"
    } else {
        "pending"
    };
    sqlx::query(&format!(
        "UPDATE {} SET status=$2,attempt_count=$3,next_attempt_at=$4,\
         lease_owner=NULL,lease_expires_at=NULL WHERE {}=$1",
        row.queue.table(),
        row.queue.key()
    ))
    .bind(row.id)
    .bind(next_status)
    .bind(next_attempt_count)
    .bind(now + Duration::seconds(retry_backoff_seconds(attempt_count)))
    .execute(&mut *tx)
    .await?;
    tx.commit().await
}

fn retry_backoff_seconds(attempt_count: i64) -> i64 {
    5_i64
        .saturating_mul(1_i64 << attempt_count.clamp(0, 9))
        .min(3600)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_backoff_is_bounded() {
        assert_eq!(retry_backoff_seconds(0), 5);
        assert_eq!(retry_backoff_seconds(9), 2560);
        assert_eq!(retry_backoff_seconds(40), 2560);
    }

    #[cfg(feature = "test-support")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn renewal_rechecks_database_clock_after_waiting_for_row_lock() {
        // Hermetic since 2026-11-04. It used to borrow the newest C01-retained
        // push row in the shared request database, which lost that row when it
        // was recreated on 2026-10-31 and only ever worked within 24 h of C01:
        // `renew_lease` fails an over-age row (`created_at` is immutable) before
        // the lease-expiry branch exercised here. The production writers seed
        // one fresh pending notification row; `renew_lease` reads only
        // `chat.outbox`.
        use crate::chat_protocol::repository::delivery::{
            append_event, enqueue_outbox, EventKind, NewEvent, OutboxWorkKind,
        };
        let database = crate::common::fresh_db::fresh_fully_migrated_db("chat_request_push_").await;
        let pool = database.connect(3).await;
        let cursor_key: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
            .bind(vec![0x51_u8; 32])
            .fetch_one(&pool)
            .await
            .expect("derive cursor key");
        let protocol_instance_id: Uuid = sqlx::query_scalar(
            "INSERT INTO chat.protocol_instances(singleton,protocol_version,protocol_instance_id,cursor_key_id) \
             VALUES(TRUE,'1',$1,$2) RETURNING protocol_instance_id",
        )
        .bind(Uuid::new_v4())
        .bind(&cursor_key)
        .fetch_one(&pool)
        .await
        .expect("seed protocol instance");
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&pool)
            .await
            .expect("database clock");
        let outbox_id = Uuid::new_v4();
        let mut seed = pool.begin().await.expect("begin seed");
        let position = append_event(
            &mut seed,
            &NewEvent {
                event_id: Uuid::new_v4(),
                event_kind: EventKind::ConversationChanged,
                payload_bytes: serde_json::to_vec(&serde_json::json!({
                    "$type": "blue.catbird.chat.defs#conversationChangedEvent",
                    "conversationId": Uuid::new_v4().to_string(),
                }))
                .unwrap(),
                created_at: now,
                protocol_instance_id,
            },
        )
        .await
        .expect("append conversation event");
        enqueue_outbox(
            &mut seed,
            outbox_id,
            position,
            OutboxWorkKind::Notification,
            now,
        )
        .await
        .expect("enqueue notification work");
        seed.commit().await.expect("commit seeded work");

        let lease_owner = Uuid::new_v4();
        sqlx::query(
            "UPDATE chat.outbox SET status='leased',attempt_count=0,delivered_at=NULL,\
             lease_owner=$2,lease_expires_at=clock_timestamp()+interval '500 milliseconds' \
             WHERE outbox_id=$1",
        )
        .bind(outbox_id)
        .bind(lease_owner)
        .execute(&pool)
        .await
        .expect("install short test lease");

        let result = async {
            let mut blocker = pool.begin().await?;
            sqlx::query("SELECT outbox_id FROM chat.outbox WHERE outbox_id=$1 FOR UPDATE")
                .bind(outbox_id)
                .fetch_one(&mut *blocker)
                .await?;
            let waiting_pool = pool.clone();
            let waiter = tokio::spawn(async move {
                renew_request_push_lease_for_test(&waiting_pool, outbox_id, lease_owner).await
            });
            tokio::time::sleep(std::time::Duration::from_millis(800)).await;
            blocker.commit().await?;

            let renewal = waiter.await.expect("renewal task joined");
            assert!(renewal.is_err(), "an expired blocked lease was renewed");
            let (status, same_owner, expired): (String, bool, bool) = sqlx::query_as(
                "SELECT status,lease_owner=$2,lease_expires_at<=clock_timestamp() \
                 FROM chat.outbox WHERE outbox_id=$1",
            )
            .bind(outbox_id)
            .bind(lease_owner)
            .fetch_one(&pool)
            .await?;
            assert_eq!(status, "leased");
            assert!(same_owner);
            assert!(expired);
            Ok::<(), sqlx::Error>(())
        }
        .await;
        result.expect("held-row-lock lease regression");
        pool.close().await;
    }

    #[cfg(feature = "test-support")]
    mod wakes {
        //! D2 `directRequest` wakes end to end on real PostgreSQL: the real
        //! `registerPushGateway` route writes the binding, the production
        //! worker delivers to a recording gateway.
        use super::*;
        use crate::{
            chat_protocol::{
                repository::direct_request_receipts::DirectRequestReceiptSigner,
                test_support::{
                    seed_clean_slate_expired_direct_request_fixture,
                    seed_clean_slate_pending_direct_request_fixture,
                    CleanSlatePendingDirectRequestFixture,
                },
            },
            common::http_acceptance as http,
            push_gateway::build_push_gateway_transcript,
        };
        use axum::{body::Bytes, http::HeaderMap, routing::post, Router};
        use base64::{
            engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
            Engine as _,
        };
        use ed25519_dalek::Signer as _;
        use p256::ecdsa::{signature::Verifier as _, Signature, SigningKey};
        use serde_json::json;
        use sha2::{Digest as _, Sha256};
        use std::{
            collections::VecDeque,
            sync::{Arc, Mutex},
        };

        const APP_ID: &str = "blue.catbird";
        const PUSH_KEY: &str = "opaque-gateway-push-key-0123456789abcdef";

        fn pem(key: &SigningKey) -> String {
            use p256::pkcs8::EncodePrivateKey as _;
            p256::SecretKey::from_slice(&key.to_bytes())
                .unwrap()
                .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
                .unwrap()
                .to_string()
        }

        fn ds_key() -> SigningKey {
            SigningKey::from_bytes((&[0x55_u8; 32]).into()).unwrap()
        }

        /// The worker's production pieces: this DS's Push Gateway client and
        /// the runtime's fixed relationship authority (live block policy).
        fn wake_runtime() -> ChatRuntime {
            ChatRuntime::from_env(Arc::new(crate::realtime::SseState::new(8)))
                .unwrap()
                .with_push_gateway_client(Arc::new(PushGatewayClient::new_es256(
                    "did:web:chat.catbird.blue".into(),
                    ds_key(),
                )))
        }

        /// A loopback Push Gateway answering the queued statuses (then 202),
        /// recording `(authorization, body)` of every delivery.
        struct Gateway {
            url: String,
            wakes: Arc<Mutex<Vec<(String, Vec<u8>)>>>,
        }

        async fn gateway(statuses: &[u16]) -> Gateway {
            let wakes = Arc::new(Mutex::new(Vec::new()));
            let queued = Arc::new(Mutex::new(
                statuses.iter().copied().collect::<VecDeque<_>>(),
            ));
            let recorded = wakes.clone();
            let app = Router::new().route(
                "/xrpc/blue.catbird.push.deliver",
                post(move |headers: HeaderMap, body: Bytes| {
                    let recorded = recorded.clone();
                    let queued = queued.clone();
                    async move {
                        let auth = headers
                            .get("authorization")
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or_default()
                            .to_owned();
                        recorded.lock().unwrap().push((auth, body.to_vec()));
                        let status = queued.lock().unwrap().pop_front().unwrap_or(202);
                        axum::http::StatusCode::from_u16(status).unwrap()
                    }
                }),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let url = format!(
                "https://wake-{}.example.test/xrpc/blue.catbird.push.deliver",
                Uuid::new_v4().simple()
            );
            crate::push_gateway::ssrf::register_test_gateway_override(
                &url,
                format!("http://{address}/xrpc/blue.catbird.push.deliver"),
            );
            Gateway { url, wakes }
        }

        async fn database() -> (crate::common::fresh_db::DisposableDatabase, PgPool) {
            let database =
                crate::common::fresh_db::fresh_fully_migrated_db("chat_request_push_").await;
            let pool = database.connect(4).await;
            http::ensure_fence(&pool).await;
            (database, pool)
        }

        fn signer() -> DirectRequestReceiptSigner {
            let receipt = SigningKey::from_bytes((&[0x41_u8; 32]).into()).unwrap();
            let service = SigningKey::from_bytes((&[0x42_u8; 32]).into()).unwrap();
            let document = crate::identity::did_doc::build_direct_request_receipt_did_document(
                "did:web:chat.catbird.blue",
                receipt.verifying_key(),
            );
            DirectRequestReceiptSigner::configured(
                &pem(&receipt),
                &pem(&service),
                &serde_json::to_string(&document).unwrap(),
            )
            .unwrap()
        }

        async fn pending(pool: &PgPool) -> CleanSlatePendingDirectRequestFixture {
            seed_clean_slate_pending_direct_request_fixture(
                pool,
                &signer(),
                &format!(
                    "did:web:alice-{}.request-push.catbird.blue",
                    Uuid::new_v4().simple()
                ),
                &format!(
                    "did:web:bob-{}.request-push.catbird.blue",
                    Uuid::new_v4().simple()
                ),
            )
            .await
            .unwrap()
        }

        /// Bob's device registers its gateway through the real
        /// `blue.catbird.chat.registerPushGateway` route.
        async fn register(
            pool: &PgPool,
            fixture: &CleanSlatePendingDirectRequestFixture,
            gateway_url: &str,
            enabled: bool,
        ) {
            let signing = http::random_p256();
            let jwk = http::public_jwk(&signing);
            let device = http::Device {
                did: fixture.recipient_did.clone(),
                device_id: fixture.recipient_device_id,
                jkt: http::jwk_thumbprint(&jwk),
                signing,
                jwk,
            };
            http::cache_device_did(&device).await;
            let signed_at = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            let transcript = build_push_gateway_transcript(
                &fixture.recipient_device_id,
                &fixture.recipient_key_id,
                1,
                gateway_url,
                APP_ID,
                PUSH_KEY,
                enabled,
                &signed_at,
            )
            .unwrap();
            let signature = ed25519_dalek::SigningKey::from_bytes(&fixture.recipient_ed25519_seed)
                .sign(&transcript);
            let (status, body) = http::send(
                http::router_for_authenticated_acceptance(pool.clone()).await,
                http::unsigned_json_request(
                    &device,
                    "blue.catbird.chat.registerPushGateway",
                    serde_json::to_vec(&json!({
                        "deviceId": fixture.recipient_device_id,
                        "keyId": fixture.recipient_key_id,
                        "authGeneration": 1,
                        "gatewayUrl": gateway_url,
                        "appId": APP_ID,
                        "pushKey": PUSH_KEY,
                        "enabled": enabled,
                        "signedAt": signed_at,
                        "signature": {"$bytes": STANDARD.encode(signature.to_bytes())},
                    }))
                    .unwrap(),
                ),
            )
            .await;
            assert_eq!(status, axum::http::StatusCode::OK, "{body}");
        }

        async fn push_event(pool: &PgPool, request_id: Uuid) -> (Uuid, Uuid) {
            sqlx::query_as(
                "SELECT event_id,outbox_id FROM chat.direct_request_push_events WHERE request_id=$1",
            )
            .bind(request_id)
            .fetch_one(pool)
            .await
            .unwrap()
        }

        async fn queue_state(pool: &PgPool, sql: &str, id: Uuid) -> (String, i64) {
            sqlx::query_as(sql).bind(id).fetch_one(pool).await.unwrap()
        }

        /// The exact D2 body: coordinates only, never sender, plaintext or
        /// ciphertext; authenticated by this DS's `#atproto` ES256 JWT.
        fn assert_wake(gateway_url: &str, wake: &(String, Vec<u8>), conversation: Uuid) {
            let body: Value = serde_json::from_slice(&wake.1).unwrap();
            assert_eq!(
                body,
                json!({
                    "appId": APP_ID,
                    "pushKey": PUSH_KEY,
                    "payload": {
                        "wakeKind": "directRequest",
                        "conversationId": conversation.to_string(),
                        "generation": 0,
                        "seq": 1,
                        "epoch": 1,
                    },
                })
            );
            let jwt = wake.0.strip_prefix("Bearer ").unwrap();
            let parts: Vec<&str> = jwt.split('.').collect();
            let claims: Value =
                serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
            assert_eq!(claims["iss"], "did:web:chat.catbird.blue");
            assert_eq!(claims["htu"], gateway_url);
            assert_eq!(claims["lxm"], "blue.catbird.push.deliver");
            assert_eq!(
                claims["body_sha256"],
                Sha256::digest(&wake.1)
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            );
            ds_key()
                .verifying_key()
                .verify(
                    format!("{}.{}", parts[0], parts[1]).as_bytes(),
                    &Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap(),
                )
                .unwrap();
        }

        const OUTBOX_STATE: &str =
            "SELECT status,attempt_count FROM chat.outbox WHERE outbox_id=$1";
        const TRANSPORT_STATE: &str =
            "SELECT status,attempt_count FROM chat.direct_request_transport_wakes WHERE delivery_id=$1";

        #[tokio::test]
        async fn publication_wake_uses_the_registered_gateway_retries_and_never_repeats() {
            let (_database, pool) = database().await;
            let fixture = pending(&pool).await;
            let gateway = gateway(&[502]).await;
            register(&pool, &fixture, &gateway.url, true).await;
            let binding: (String, String, String) = sqlx::query_as(
                "SELECT gateway_url,app_id,push_key FROM chat.push_gateway_bindings \
                  WHERE user_did=$1 AND device_id=$2",
            )
            .bind(&fixture.recipient_did)
            .bind(fixture.recipient_device_id)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(
                binding,
                (gateway.url.clone(), APP_ID.into(), PUSH_KEY.into())
            );
            let (event, outbox) = push_event(&pool, fixture.request_id).await;
            let client = wake_runtime();

            // The gateway's 502 leaves durable, backed-off retry work.
            let deferred = run_request_push_event_once_for_test(&pool, &client, event).await;
            assert!(deferred.unwrap_err().contains("502"));
            assert_eq!(
                queue_state(&pool, OUTBOX_STATE, outbox).await,
                ("pending".into(), 1)
            );
            assert_eq!(
                run_request_push_event_once_for_test(&pool, &client, event).await,
                Ok(WakeRun::default()),
                "a deferred wake is not redelivered before its backoff"
            );
            sqlx::query(
                "UPDATE chat.outbox SET next_attempt_at=clock_timestamp() WHERE outbox_id=$1",
            )
            .bind(outbox)
            .execute(&pool)
            .await
            .unwrap();
            assert_eq!(
                run_request_push_event_once_for_test(&pool, &client, event).await,
                Ok(WakeRun {
                    claimed: 1,
                    woken: 1,
                    suppressed: 0
                })
            );
            assert_eq!(
                queue_state(&pool, OUTBOX_STATE, outbox).await,
                ("delivered".into(), 1)
            );
            assert_eq!(
                run_request_push_once_for_test(&pool, &client).await,
                Ok(WakeRun::default()),
                "a delivered wake is terminal"
            );

            let wakes = gateway.wakes.lock().unwrap().clone();
            assert_eq!(wakes.len(), 2);
            assert_eq!(wakes[0].1, wakes[1].1, "the retry is the identical wake");
            for wake in &wakes {
                assert_wake(&gateway.url, wake, fixture.conversation_id);
                let text = String::from_utf8_lossy(&wake.1);
                assert!(!text.contains(&fixture.actor_did), "sender leaked: {text}");
            }
            let (ciphertext, metadata): (Vec<u8>, Vec<u8>) = sqlx::query_as(
                "SELECT initial_ciphertext,metadata_snapshot FROM chat.direct_request_publications \
                  WHERE request_id=$1",
            )
            .bind(fixture.request_id)
            .fetch_one(&pool)
            .await
            .unwrap();
            for secret in [STANDARD.encode(&ciphertext), STANDARD.encode(&metadata)] {
                assert!(wakes
                    .iter()
                    .all(|wake| !String::from_utf8_lossy(&wake.1).contains(&secret)));
            }
            pool.close().await;
        }

        /// Make `outbox` due now, `attempts` attempts in (the count never
        /// decreases).
        async fn due_at_attempt(pool: &PgPool, outbox: Uuid, attempts: i64) {
            sqlx::query(
                "UPDATE chat.outbox SET next_attempt_at=clock_timestamp(),attempt_count=$2 \
                  WHERE outbox_id=$1",
            )
            .bind(outbox)
            .bind(attempts)
            .execute(pool)
            .await
            .unwrap();
        }

        /// DQ.G16: a gateway that could not answer (502) is retried past the
        /// old ten-attempt cap, and the identical retry wakes the device.
        #[tokio::test]
        async fn a_gateway_that_could_not_answer_is_retried_past_ten_attempts() {
            let (_database, pool) = database().await;
            let fixture = pending(&pool).await;
            let gateway = gateway(&[502]).await;
            register(&pool, &fixture, &gateway.url, true).await;
            let (event, outbox) = push_event(&pool, fixture.request_id).await;
            let client = wake_runtime();
            due_at_attempt(&pool, outbox, 9).await;
            let deferred = run_request_push_event_once_for_test(&pool, &client, event).await;
            assert!(deferred.unwrap_err().contains("502"));
            assert_eq!(
                queue_state(&pool, OUTBOX_STATE, outbox).await,
                ("pending".into(), 10)
            );
            due_at_attempt(&pool, outbox, 10).await;
            assert_eq!(
                run_request_push_event_once_for_test(&pool, &client, event).await,
                Ok(WakeRun {
                    claimed: 1,
                    woken: 1,
                    suppressed: 0
                })
            );
            pool.close().await;
        }

        /// DQ.G16: a gateway's permanent refusal (400) fails the wake at once.
        #[tokio::test]
        async fn a_gateway_refusal_fails_the_wake_at_once() {
            let (_database, pool) = database().await;
            let fixture = pending(&pool).await;
            let gateway = gateway(&[400]).await;
            register(&pool, &fixture, &gateway.url, true).await;
            let (event, outbox) = push_event(&pool, fixture.request_id).await;
            let failed = run_request_push_event_once_for_test(&pool, &wake_runtime(), event).await;
            assert!(failed.unwrap_err().contains("400"));
            assert_eq!(
                queue_state(&pool, OUTBOX_STATE, outbox).await,
                ("failed".into(), 1)
            );
            pool.close().await;
        }

        /// DQ.G16/RS.G8: a relationship source that could not answer defers
        /// the wake past the old cap without waking anyone; unusable policy
        /// evidence fails it at once.
        #[tokio::test]
        async fn a_policy_outage_defers_the_wake_and_unusable_evidence_fails_it() {
            use crate::chat_protocol::relationship_policy::{
                PublicResponse, SimSourceFault, TransportError,
            };
            let (_database, pool) = database().await;
            let gateway = gateway(&[]).await;
            let fault = SimSourceFault::default();
            let client = wake_runtime()
                .with_sim_faulty_relationships(fault.clone())
                .unwrap();
            *fault.lock().unwrap() = Some(Err(TransportError::Network));
            let outage = pending(&pool).await;
            register(&pool, &outage, &gateway.url, true).await;
            let (event, outbox) = push_event(&pool, outage.request_id).await;
            due_at_attempt(&pool, outbox, 9).await;
            let deferred = run_request_push_event_once_for_test(&pool, &client, event).await;
            assert!(deferred.unwrap_err().contains("deferred"));
            assert_eq!(
                queue_state(&pool, OUTBOX_STATE, outbox).await,
                ("pending".into(), 10)
            );
            assert!(gateway.wakes.lock().unwrap().is_empty());

            *fault.lock().unwrap() = Some(Ok(PublicResponse::new(200, b"{}".to_vec())));
            let unusable = pending(&pool).await;
            register(&pool, &unusable, &gateway.url, true).await;
            let (event, outbox) = push_event(&pool, unusable.request_id).await;
            let failed = run_request_push_event_once_for_test(&pool, &client, event).await;
            assert!(failed.unwrap_err().contains("failed"));
            assert_eq!(
                queue_state(&pool, OUTBOX_STATE, outbox).await,
                ("failed".into(), 1)
            );
            assert!(gateway.wakes.lock().unwrap().is_empty());
            pool.close().await;
        }

        #[tokio::test]
        async fn disabled_registration_and_ineligible_requests_wake_nobody() {
            let (_database, pool) = database().await;
            let gateway = gateway(&[]).await;
            let client = wake_runtime();

            // `enabled: false` deletes the binding, so nothing is woken.
            let fixture = pending(&pool).await;
            register(&pool, &fixture, &gateway.url, true).await;
            register(&pool, &fixture, &gateway.url, false).await;
            let (event, outbox) = push_event(&pool, fixture.request_id).await;
            assert_eq!(
                run_request_push_event_once_for_test(&pool, &client, event).await,
                Ok(WakeRun {
                    claimed: 1,
                    woken: 0,
                    suppressed: 0
                })
            );
            assert_eq!(
                queue_state(&pool, OUTBOX_STATE, outbox).await,
                ("delivered".into(), 0)
            );

            // An import-expired request completes without any gateway call,
            // even though its recipient has a binding.
            let expired = seed_clean_slate_expired_direct_request_fixture(&pool, &signer())
                .await
                .unwrap();
            // Precondition only: the binding the request would otherwise use.
            sqlx::query(
                "INSERT INTO chat.push_gateway_bindings(user_did,device_id,gateway_url,app_id,push_key,\
                     key_id,auth_generation,signed_at,updated_at) \
                 SELECT user_did,device_id,$2,$3,$4,key_id,1,clock_timestamp(),clock_timestamp() \
                   FROM chat.device_keys WHERE user_did=$1",
            )
            .bind(&expired.recipient_did)
            .bind(&gateway.url)
            .bind(APP_ID)
            .bind(PUSH_KEY)
            .execute(&pool)
            .await
            .unwrap();
            let (event, outbox) = push_event(&pool, expired.request_id).await;
            assert_eq!(
                run_request_push_event_once_for_test(&pool, &client, event).await,
                Ok(WakeRun {
                    claimed: 1,
                    woken: 0,
                    suppressed: 1
                })
            );
            assert_eq!(
                queue_state(&pool, OUTBOX_STATE, outbox).await,
                ("delivered".into(), 0)
            );
            assert!(gateway.wakes.lock().unwrap().is_empty());
            pool.close().await;
        }

        async fn deliver_to_transport_home(
            pool: &PgPool,
            fixture: &CleanSlatePendingDirectRequestFixture,
            request: Uuid,
            conversation: Uuid,
            status: &str,
            ciphertext: &[u8],
        ) -> Option<Uuid> {
            let entry = serde_json::to_vec(&json!({
                "$type": "blue.catbird.chat.defs#directRequestEntry",
                "entryId": Uuid::new_v4(),
                "conversationId": conversation,
                "seq": 1,
                "signedRequest": {
                    "body": {
                        "requestId": request,
                        "conversationId": conversation,
                        "next": {"generation": 0, "epoch": 1},
                        "artifacts": {"initialCiphertext": STANDARD.encode(ciphertext)},
                    },
                    "signature": STANDARD.encode([7_u8; 64]),
                },
            }))
            .unwrap();
            // The exact idempotent insert `ingest_remote_direct_request_delivery` runs.
            sqlx::query_scalar(
                "INSERT INTO chat.direct_request_transport_inbox(request_id,conversation_id,\
                     first_message_id,coordinator_did,sender_did,sender_device_id,recipient_did,\
                     recipient_device_id,request_entry,signed_publication,full_welcome,\
                     full_welcome_sha256,provenance,publication_receipt,import_until,status) \
                 VALUES($1,$2,$3,'did:web:coordinator.request-push.catbird.blue',$4,$5,$6,$7,$8,$8,$9,$10,$8,$8,\
                     clock_timestamp()+interval '7 days',$11) \
                 ON CONFLICT (request_id, recipient_device_id) DO NOTHING RETURNING delivery_id",
            )
            .bind(request)
            .bind(conversation)
            .bind(Uuid::new_v4())
            .bind(&fixture.actor_did)
            .bind(fixture.actor_device_id)
            .bind(&fixture.recipient_did)
            .bind(fixture.recipient_device_id)
            .bind(&entry)
            .bind(b"welcome".as_slice())
            .bind(Sha256::digest(b"welcome").as_slice())
            .bind(status)
            .fetch_optional(pool)
            .await
            .unwrap()
        }

        #[tokio::test]
        async fn transport_home_enqueues_one_wake_per_delivery_and_wakes_it_once() {
            let (_database, pool) = database().await;
            let fixture = pending(&pool).await;
            let gateway = gateway(&[]).await;
            register(&pool, &fixture, &gateway.url, true).await;
            let client = wake_runtime();
            let (request, conversation) = (Uuid::new_v4(), Uuid::new_v4());
            let ciphertext = b"transport-held opening ciphertext";

            let delivery = deliver_to_transport_home(
                &pool,
                &fixture,
                request,
                conversation,
                "pending",
                ciphertext,
            )
            .await
            .expect("first delivery inserts");
            assert_eq!(
                deliver_to_transport_home(
                    &pool,
                    &fixture,
                    request,
                    conversation,
                    "pending",
                    ciphertext
                )
                .await,
                None,
                "a replayed delivery inserts nothing"
            );
            let wakes: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM chat.direct_request_transport_wakes WHERE delivery_id=$1",
            )
            .bind(delivery)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(wakes, 1, "exactly one durable wake per delivered device");
            assert_eq!(
                queue_state(&pool, TRANSPORT_STATE, delivery).await,
                ("pending".into(), 0)
            );

            assert_eq!(
                run_transport_wake_once_for_test(&pool, &client, delivery).await,
                Ok(WakeRun {
                    claimed: 1,
                    woken: 1,
                    suppressed: 0
                })
            );
            assert_eq!(
                queue_state(&pool, TRANSPORT_STATE, delivery).await,
                ("delivered".into(), 0)
            );
            assert_eq!(
                run_request_push_once_for_test(&pool, &client)
                    .await
                    .map(|run| run.woken),
                Ok(1),
                "only the coordinator publication's own wake remains"
            );
            let wakes = gateway.wakes.lock().unwrap().clone();
            let transport: Vec<_> = wakes
                .iter()
                .filter(|wake| String::from_utf8_lossy(&wake.1).contains(&conversation.to_string()))
                .collect();
            assert_eq!(transport.len(), 1, "the transport wake is delivered once");
            assert_wake(&gateway.url, transport[0], conversation);
            assert!(
                !String::from_utf8_lossy(&transport[0].1).contains(&STANDARD.encode(ciphertext))
            );

            // A request the recipient already answered is never woken.
            let accepted = deliver_to_transport_home(
                &pool,
                &fixture,
                Uuid::new_v4(),
                Uuid::new_v4(),
                "accepted",
                ciphertext,
            )
            .await
            .unwrap();
            assert_eq!(
                run_transport_wake_once_for_test(&pool, &client, accepted).await,
                Ok(WakeRun {
                    claimed: 1,
                    woken: 0,
                    suppressed: 1
                })
            );
            assert_eq!(gateway.wakes.lock().unwrap().len(), wakes.len());
            pool.close().await;
        }
    }
}
