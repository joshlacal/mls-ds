//! Phase 3 — federation outbox worker.
//!
//! Drains `federation_outbox` rows that the chokepoint wrote in the same
//! Postgres tx as a `delivery_events` INSERT. Each row represents one
//! "this delivery event must be replayed to peer DS X" job.
//!
//! Federation in this plan is intentionally limited: this plan does NOT
//! redesign federated routing or remote sequencer ownership (see
//! locked-decision #2 in `docs/plans (let-me-look-at-abstract-castle.md)`).
//! We persist the rows so the outbox is the durable source of truth, and
//! ship a placeholder dispatcher that logs + marks `done`. Hooking the
//! dispatcher to the existing `federation/outbound.rs` queue is a
//! follow-up — the chokepoint contract is unchanged.
//!
//! ## Why a stub dispatcher
//!
//! The plan acceptance test only requires:
//! "SIGKILL after `delivery_event` commits but before fanout — outbox
//! worker completes the fanout on restart."
//!
//! That test is satisfied by the *worker* completing the row, not by the
//! row reaching a real federation peer. The actual peer dispatch already
//! has its own queue (`federation::outbound::OutboundQueue`); wiring the
//! outbox to that queue is straightforward but out of scope here. We
//! mark the dispatch path with TODO(phase-3-federation-wire) so it shows
//! up in `git grep`.

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use tokio::time::interval;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use super::{
    maintain_federation_outbox_partitions, record_failure, try_reclaim, CLAIM_BATCH_SIZE,
    DEAD_ROWS_MAX_AGE, PARTITION_MAINTENANCE_INTERVAL, POLL_INTERVAL,
};
use crate::chat_protocol::repository::delivery::QUEUED_COPY_OF_PRUNED_ENTRY_SQL;
use crate::federation::FederationError;
use crate::identity::canonical_did;
const TABLE_NAME: &str = "federation_outbox";

#[derive(Debug, Clone, FromRow)]
pub struct FederationOutboxRow {
    pub id: String,
    pub conversation_id: String,
    pub delivery_event_id: Option<String>,
    pub target_service_did: String,
    pub method: String,
    pub payload: Vec<u8>,
    pub payload_sha256: Option<Vec<u8>>,
    pub envelope_version: i32,
    pub attempts: i32,
    pub created_at: DateTime<Utc>,
    pub claim_token: Option<Uuid>,
}
/// Worker entry point. Spawned at server startup from `main.rs`.
///
/// Claims work every [`POLL_INTERVAL`] and maintains monthly terminal-history
/// partitions every [`PARTITION_MAINTENANCE_INTERVAL`].
pub async fn run_federation_outbox_worker(pool: PgPool) {
    info!(
        poll_interval_secs = POLL_INTERVAL.as_secs(),
        batch_size = CLAIM_BATCH_SIZE,
        "starting federation_outbox worker"
    );

    let mut ticker = interval(POLL_INTERVAL);
    let mut maintenance = interval(PARTITION_MAINTENANCE_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if let Err(e) = process_federation_outbox_tick(&pool, CLAIM_BATCH_SIZE).await {
                    error!(error = ?e, "federation_outbox: claim batch failed");
                }
            }
            _ = maintenance.tick() => {
                match maintain_federation_outbox_partitions(&pool, DEAD_ROWS_MAX_AGE).await {
                    Ok(n) if n > 0 => info!(
                        partitions_dropped = n,
                        "federation_outbox: dropped expired terminal-history partitions"
                    ),
                    Ok(_) => {}
                    Err(e) => error!(
                        error = ?e,
                        "federation_outbox: partition maintenance failed"
                    ),
                }
            }
        }
    }
}

/// Execute one production `federation_outbox` handoff iteration:
/// reclaim stuck `in_flight` leases, claim up to `limit` due `pending` rows,
/// and atomically hand each row off to `outbound_queue` (or record retry
/// backoff, or `dead` for a peer-policy denial).
pub async fn process_federation_outbox_tick(
    pool: &PgPool,
    limit: i64,
) -> Result<usize, sqlx::Error> {
    try_reclaim(pool, TABLE_NAME).await;
    let claimed = claim_due_rows(pool, limit).await?;
    if claimed.is_empty() {
        return Ok(0);
    }

    debug!(count = claimed.len(), "federation_outbox: claimed batch");
    let count = claimed.len();

    for row in claimed {
        match handoff_to_outbound_queue(pool, &row).await {
            Ok(()) => {
                debug!(
                    row_id = %row.id,
                    target_did = %row.target_service_did,
                    method = %row.method,
                    "federation_outbox: atomic handoff completed, source marked done"
                );
            }
            Err(e) => {
                let err_msg = format!("{e:#}");
                // A peer-policy denial is permanent. This DS's own storage
                // failing, or the peer's queue being full now, decided
                // nothing: the job is retried however long that takes.
                let permanent = !(e.is_retryable()
                    || matches!(
                        e,
                        FederationError::OutboundQueuePeerCapExceeded { .. }
                            | FederationError::OutboundQueueConvoPeerCapExceeded { .. }
                    ));
                match record_failure(
                    pool,
                    TABLE_NAME,
                    &row.id,
                    row.claim_token,
                    row.attempts,
                    &err_msg,
                    permanent,
                )
                .await
                {
                    Ok(stored_status) => {
                        warn!(
                            row_id = %row.id,
                            target_did = %row.target_service_did,
                            attempts = row.attempts + 1,
                            stored_status,
                            error = %err_msg,
                            "federation_outbox: handoff failed; row transitioned"
                        );
                    }
                    Err(db_err) => {
                        error!(
                            row_id = %row.id,
                            error = ?db_err,
                            "federation_outbox: record_failure DB write failed"
                        );
                    }
                }
            }
        }
    }
    Ok(count)
}

/// Claim up to `limit` due `pending` rows, flipping them to `in_flight`
/// in the same transaction. Returns the claimed rows, in `(next_attempt_at,
/// id)` order, for the caller to dispatch in that order.
///
/// Uses `FOR UPDATE SKIP LOCKED` so that horizontally-scaled workers
/// don't double-claim a row. Without `SKIP LOCKED`, two replicas calling
/// this concurrently would deadlock or block.
pub async fn claim_due_rows(
    pool: &PgPool,
    limit: i64,
) -> Result<Vec<FederationOutboxRow>, sqlx::Error> {
    let now = crate::sim_hooks::current_utc();
    let mut tx = pool.begin().await?;

    let candidates: Vec<(String,)> = sqlx::query_as(
        "SELECT id FROM federation_outbox \
         WHERE status = 'pending' AND next_attempt_at <= $2 \
         ORDER BY next_attempt_at, id \
         LIMIT $1 \
         FOR UPDATE SKIP LOCKED",
    )
    .bind(limit)
    .bind(now)
    .fetch_all(&mut *tx)
    .await?;

    if candidates.is_empty() {
        tx.commit().await?;
        return Ok(Vec::new());
    }

    let ids: Vec<String> = candidates.into_iter().map(|(id,)| id).collect();
    let claim_token =
        crate::sim_hooks::mint_entry_uuid_v4(b"federation_outbox.claim", &[ids[0].as_bytes()]);

    // Neither `RETURNING` nor `ANY` keeps the candidates' order: carry it.
    let rows: Vec<FederationOutboxRow> = sqlx::query_as(
        "WITH claimed AS ( \
             UPDATE federation_outbox q \
                SET status = 'in_flight', \
                    claim_token = $2, \
                    claim_expires_at = $4 + make_interval(secs => $3), \
                    updated_at = $4 \
               FROM unnest($1::text[]) WITH ORDINALITY AS c(id, ord) \
              WHERE q.id = c.id \
             RETURNING c.ord, q.id, q.conversation_id, q.delivery_event_id, \
                       q.target_service_did, q.method, q.payload, q.payload_sha256, \
                       q.envelope_version, q.attempts, q.created_at, q.claim_token \
         ) \
         SELECT id, conversation_id, delivery_event_id, target_service_did, method, payload, \
                payload_sha256, envelope_version, attempts, created_at, claim_token \
         FROM claimed ORDER BY ord",
    )
    .bind(&ids)
    .bind(claim_token)
    .bind(super::IN_FLIGHT_VISIBILITY_TIMEOUT.as_secs() as f64)
    .bind(now)
    .fetch_all(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(rows)
}

/// Atomically hand off one federation outbox row to `outbound_queue` and mark the source row `done`.
pub async fn handoff_to_outbound_queue(
    pool: &PgPool,
    row: &FederationOutboxRow,
) -> Result<(), FederationError> {
    let now = crate::sim_hooks::current_utc();
    let mut tx = pool.begin().await?;

    // 1. Replay check before caps: if outbound_queue already contains this stable ID,
    //    skip insertion and mark source done immediately.
    let already_enqueued: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM outbound_queue WHERE id = $1)")
            .bind(&row.id)
            .fetch_one(&mut *tx)
            .await?;

    if !already_enqueued {
        let canonical_target_ds_did = canonical_did(&row.target_service_did).to_string();
        let policy = crate::federation::peer_policy::enforce_outbound_peer_policy_tx(
            &mut tx,
            &canonical_target_ds_did,
        )
        .await?;

        let (per_peer_cap, per_convo_cap) =
            crate::federation::queue::current_pending_caps_from_env();
        crate::federation::queue::enforce_pending_caps_with_executor(
            &mut *tx,
            &canonical_target_ds_did,
            &row.conversation_id,
            &policy,
            per_peer_cap,
            per_convo_cap,
        )
        .await?;

        sqlx::query(
            "INSERT INTO outbound_queue \
               (id, target_ds_did, target_endpoint, method, payload, convo_id, payload_sha256, envelope_version, status, next_retry_at, retry_count, max_retries, created_at) \
             SELECT $1, $2, '', $3, $4, $5, $6, $7, 'pending', $8, 0, 5, $8 \
              WHERE NOT EXISTS (SELECT 1 FROM outbound_queue WHERE id = $1) \
             ON CONFLICT DO NOTHING",
        )
        .bind(&row.id)
        .bind(&canonical_target_ds_did)
        .bind(&row.method)
        .bind(&row.payload)
        .bind(&row.conversation_id)
        .bind(&row.payload_sha256)
        .bind(row.envelope_version)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    }
    // 2. Mark source federation_outbox row as 'done' in the SAME transaction!
    //    A job of an entry already pruned leaves no row behind: its
    //    `outbound_queue` copy is the one still to be sent (O7).
    let updated: i64 = sqlx::query_scalar(&format!(
        "WITH gone AS ( \
             DELETE FROM federation_outbox q \
              WHERE q.id = $1 AND ($2::uuid IS NULL OR q.claim_token = $2) \
                AND {QUEUED_COPY_OF_PRUNED_ENTRY_SQL} \
             RETURNING 1 \
         ), kept AS ( \
             UPDATE federation_outbox q SET status = 'done', updated_at = $3, last_error = NULL \
              WHERE q.id = $1 AND ($2::uuid IS NULL OR q.claim_token = $2) \
                AND NOT {QUEUED_COPY_OF_PRUNED_ENTRY_SQL} \
             RETURNING 1 \
         ) \
         SELECT (SELECT count(*) FROM gone) + (SELECT count(*) FROM kept)"
    ))
    .bind(&row.id)
    .bind(row.claim_token)
    .bind(now)
    .fetch_one(&mut *tx)
    .await?;

    if updated == 0 {
        return Err(FederationError::Database(sqlx::Error::RowNotFound));
    }

    tx.commit().await?;
    Ok(())
}

/// Execute a single bounded federation outbox + outbound queue dispatch step
/// for one DS under the caller's active `scope_ds_clock` and `scope_sim_ds`.
///
/// Reuses the exact production `process_federation_outbox_tick` handoff and
/// `OutboundQueue::process_pending_batch` signed `OutboundClient` dispatch
/// (including `deliverWelcome`, `deliverMessage`, `deliverDirectRequest`,
/// `deliverAcceptanceEntry`, `deliverMessageEntry`, receipt verification, and
/// retry backoff). Reconciliation runs on the production interval of DS-clock time.
#[cfg(feature = "sim")]
pub async fn step_federation_outbox(
    pool: &PgPool,
    queue: &crate::federation::queue::OutboundQueue,
    outbound: &crate::federation::outbound::OutboundClient,
    service_auth: &crate::federation::ServiceAuthClient,
) -> Result<usize, String> {
    // Paused sim time must not advance pool timers while sqlx releases the
    // single connection through real PostgreSQL I/O.
    crate::sim_hooks::drive_sim_io(async {
        let handed_off = process_federation_outbox_tick(pool, CLAIM_BATCH_SIZE)
            .await
            .map_err(|e| format!("federation_outbox tick failed: {e}"))?;
        let auth_sign = |target_did: &str, method: &str| {
            service_auth
                .sign_request(target_did, method)
                .map_err(|e| e.to_string())
        };
        let dispatched = queue
            .process_pending_batch(outbound, &auth_sign)
            .await
            .map_err(|e| format!("outbound_queue batch failed: {e}"))?;
        let interval = chrono::Duration::seconds(
            crate::federation::reconciliation::reconciliation_interval_secs() as i64,
        );
        if queue.claim_sim_reconciliation(crate::sim_hooks::current_utc(), interval) {
            let _ = crate::federation::reconciliation::run_reconciliation_once_for_sim(
                pool,
                queue.resolver(),
                outbound,
                &auth_sign,
                service_auth.self_did(),
            )
            .await;
        }
        Ok::<_, String>(handed_off.saturating_add(dispatched))
    })
    .await
}

/// Bounded, deterministic drain of due `federation_outbox` + `outbound_queue`
/// items for one DS under the caller's active `scope_ds_clock` and `scope_sim_ds`.
/// Never spins forever: runs at most `max_rounds` iterations and stops early once
/// neither `federation_outbox` nor `outbound_queue` claims any due item.
#[cfg(feature = "sim")]
pub async fn drain_federation_outbox(
    pool: &PgPool,
    queue: &crate::federation::queue::OutboundQueue,
    outbound: &crate::federation::outbound::OutboundClient,
    service_auth: &crate::federation::ServiceAuthClient,
    max_rounds: usize,
) -> Result<usize, String> {
    let mut total = 0_usize;
    for _ in 0..max_rounds {
        let progressed = step_federation_outbox(pool, queue, outbound, service_auth).await?;
        total = total.saturating_add(progressed);
        if progressed == 0 {
            break;
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    mod fresh_db {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/test_support/fresh_db.rs"
        ));
    }
    use super::*;
    use crate::sim_hooks::{current_utc, scope_ds_clock, ManualDsClock};
    use crate::workers::reclaim_stuck_in_flight;
    use std::sync::Arc;

    async fn insert_job(pool: &PgPool, id: &str, due: DateTime<Utc>) {
        sqlx::query(
            "INSERT INTO federation_outbox (id, conversation_id, target_service_did, payload, \
                 status, next_attempt_at, created_at, updated_at) \
             VALUES ($1, $1, 'did:web:peer.example.com', $2, 'pending', $3, $3, $3)",
        )
        .bind(id)
        .bind(b"{}".as_slice())
        .bind(due)
        .execute(pool)
        .await
        .unwrap();
    }

    /// Jobs due at one instant claim, and so hand off, in `(next_attempt_at,
    /// id)` order whatever their rows' history. Retry resets here write the
    /// tied jobs in reverse id order and the job due first holds the largest
    /// id: claimed rows handed back in `RETURNING` order fail. A claim takes
    /// only unclaimed jobs (a locked one is skipped), and an expired lease
    /// re-claims the same order under a new token.
    #[tokio::test]
    async fn equal_deadline_jobs_claim_in_deadline_then_id_order_across_reset_history() {
        let (pool, _db) = fresh_db::fresh_legacy_pool("fed_queue_", 2, 1).await;
        let t0 = DateTime::<Utc>::from_timestamp(1_800_000_000, 0).unwrap();
        let clock = Arc::new(ManualDsClock::new(t0));
        scope_ds_clock(clock.clone(), async {
            let ids = |rows: &[FederationOutboxRow]| {
                rows.iter().map(|row| row.id.clone()).collect::<Vec<_>>()
            };
            for id in ["job-a", "job-b", "job-c"] {
                insert_job(&pool, id, t0).await;
            }
            let first = claim_due_rows(&pool, 10).await.unwrap();
            assert_eq!(ids(&first), ["job-a", "job-b", "job-c"]);
            // Each handoff fails at once, the last first: equal deadlines,
            // written in reverse id order.
            for row in first.iter().rev() {
                let stored = record_failure(
                    &pool,
                    TABLE_NAME,
                    &row.id,
                    row.claim_token,
                    row.attempts,
                    "transient",
                    false,
                )
                .await
                .unwrap();
                assert_eq!(stored, "pending");
            }
            // A job falls due first, under the largest id, written last.
            insert_job(&pool, "job-z", t0 + chrono::TimeDelta::seconds(4)).await;
            clock.advance(chrono::TimeDelta::seconds(5));
            let now = current_utc();

            // A rival worker holds `job-a`: a claim skips it.
            let mut rival = pool.begin().await.unwrap();
            sqlx::query("SELECT 1 FROM federation_outbox WHERE id = 'job-a' FOR UPDATE")
                .execute(&mut *rival)
                .await
                .unwrap();
            let skipped = claim_due_rows(&pool, 2).await.unwrap();
            assert_eq!(ids(&skipped), ["job-z", "job-b"]);
            rival.rollback().await.unwrap();
            let rest = claim_due_rows(&pool, 10).await.unwrap();
            assert_eq!(ids(&rest), ["job-a", "job-c"]);
            assert!(
                claim_due_rows(&pool, 10).await.unwrap().is_empty(),
                "every job is in flight"
            );

            // Each claim leases its jobs for 120 s under one token of its own.
            let (s, r) = (skipped[0].claim_token, rest[0].claim_token);
            assert!(s.is_some() && r.is_some() && s != r);
            let lease = Some(now + chrono::TimeDelta::seconds(120));
            let leases: Vec<(String, String, Option<Uuid>, Option<DateTime<Utc>>)> =
                sqlx::query_as(
                    "SELECT id, status, claim_token, claim_expires_at FROM federation_outbox \
                     ORDER BY id",
                )
                .fetch_all(&pool)
                .await
                .unwrap();
            let in_flight = |id: &str, token| (id.to_owned(), "in_flight".to_owned(), token, lease);
            assert_eq!(
                leases,
                [
                    in_flight("job-a", r),
                    in_flight("job-b", s),
                    in_flight("job-c", r),
                    in_flight("job-z", s),
                ]
            );

            // The leases expire together and reset every job once more.
            clock.advance(chrono::TimeDelta::seconds(119));
            assert_eq!(reclaim_stuck_in_flight(&pool, TABLE_NAME).await.unwrap(), 0);
            clock.advance(chrono::TimeDelta::seconds(1));
            assert_eq!(reclaim_stuck_in_flight(&pool, TABLE_NAME).await.unwrap(), 4);
            let replayed = claim_due_rows(&pool, 10).await.unwrap();
            assert_eq!(ids(&replayed), ["job-z", "job-a", "job-b", "job-c"]);
            let token = replayed[0].claim_token;
            assert!(replayed.iter().all(|row| row.claim_token == token));
            assert!(token != s && token != r);

            // An expired claim settles nothing.
            let late = &skipped[0];
            let stored = record_failure(
                &pool,
                TABLE_NAME,
                &late.id,
                late.claim_token,
                late.attempts,
                "late",
                false,
            )
            .await
            .unwrap();
            assert_eq!(stored, "stale");
        })
        .await;
    }
}
