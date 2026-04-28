//! `DeliveryLogRepository` — server's source-of-truth append-only log.
//!
//! Phase 1: stub. `append` returns `RepositoryError::NotImplemented`;
//! `read_range_by_session` returns an empty vec. Phase 2 introduces the
//! `delivery_events` table and wires this through.

use async_trait::async_trait;
use sqlx::PgPool;

use crate::models::{DeliveryEvent, NewDeliveryEvent};
use crate::repositories::{RepositoryError, RepositoryResult};

#[async_trait]
pub trait DeliveryLogRepository: Send + Sync {
    /// Append a new event. Phase 2 assigns `seq` inside the same transaction
    /// that increments the per-conversation sequence.
    async fn append(&self, event: NewDeliveryEvent) -> RepositoryResult<DeliveryEvent>;

    /// Read events for a session in `[from_seq, from_seq + limit)`. Phase 1
    /// returns empty; Phase 2 wires through.
    async fn read_range_by_session(
        &self,
        crypto_session_id: &str,
        from_seq: i64,
        limit: usize,
    ) -> RepositoryResult<Vec<DeliveryEvent>>;
}

pub struct PostgresDeliveryLogRepository {
    #[allow(dead_code)]
    pool: PgPool,
}

impl PostgresDeliveryLogRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DeliveryLogRepository for PostgresDeliveryLogRepository {
    async fn append(&self, _event: NewDeliveryEvent) -> RepositoryResult<DeliveryEvent> {
        Err(RepositoryError::NotImplemented)
    }

    async fn read_range_by_session(
        &self,
        _crypto_session_id: &str,
        _from_seq: i64,
        _limit: usize,
    ) -> RepositoryResult<Vec<DeliveryEvent>> {
        Ok(Vec::new())
    }
}
