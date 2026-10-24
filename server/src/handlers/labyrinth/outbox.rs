//! The `labyrinth.relay_outbox` worker (`crate::labyrinth::repo::outbox`):
//! delivers durable `purgeAuthor` / `invalidateMessages` jobs to their DS
//! over `labyrinthRelay`, with backoff.

use std::time::Duration;

use chrono::Utc;

use super::relay_client::RelayClient;
use crate::labyrinth::error::LabyrinthResult;
use crate::labyrinth::repo::outbox;
use crate::storage::DbPool;

/// A job's response is small (`{}` / a count).
const MAX_JOB_RESPONSE: usize = 64 * 1024;

/// Peer answers that retrying cannot change.
const PERMANENT: &[&str] = &[
    "InvalidRequest",
    "InvalidSignature",
    "NotSequencer",
    "NotHomeDs",
];

/// What one pass did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Drained {
    pub delivered: usize,
    pub failed: usize,
}

/// Deliver up to `limit` due jobs once.
pub async fn drain_once(pool: &DbPool, client: &RelayClient, limit: i64) -> LabyrinthResult<Drained> {
    let mut drained = Drained::default();
    for job in outbox::claim_due(pool, Utc::now(), limit).await? {
        match client
            .send(pool, &job.target_ds, &job.request, MAX_JOB_RESPONSE)
            .await
        {
            Ok(_) => {
                outbox::complete(pool, job.job_id, Utc::now()).await?;
                drained.delivered += 1;
            }
            Err(error) => {
                let permanent = PERMANENT.contains(&error.name());
                outbox::fail(pool, &job, &error.to_string(), permanent, Utc::now()).await?;
                drained.failed += 1;
            }
        }
    }
    Ok(drained)
}

/// Run [`drain_once`] every `interval` for the life of the process.
pub async fn worker(pool: DbPool, client: RelayClient, interval: Duration) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        match drain_once(&pool, &client, 100).await {
            Ok(d) if d != Drained::default() => tracing::info!(?d, "labyrinth relay outbox pass"),
            Ok(_) => {}
            Err(error) => tracing::warn!(%error, "labyrinth relay outbox pass failed"),
        }
    }
}
