//! `DeliveryLogRepository` — server's source-of-truth append-only log.
//!
//! Phase 2: backed by `delivery_events` table. `append` is idempotent on
//! `(conversation_id, sender_did, sender_device_id, idempotency_key)` and
//! allocates `seq` under a per-conversation advisory transaction lock so
//! concurrent appends to the same conversation cannot race the seq.

use async_trait::async_trait;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::models::{DeliveryEvent, NewDeliveryEvent};
use crate::repositories::{RepositoryError, RepositoryResult};

#[async_trait]
pub trait DeliveryLogRepository: Send + Sync {
    /// Append a new event. Idempotent on
    /// `(conversation_id, sender_did, sender_device_id, idempotency_key)` —
    /// duplicate retries return the same row. Allocates `seq` monotonically
    /// per conversation under an advisory lock.
    async fn append(&self, event: NewDeliveryEvent) -> RepositoryResult<DeliveryEvent>;

    /// Read events for a session in `[from_seq, from_seq + limit)`,
    /// ordered by `seq` ascending.
    async fn read_range_by_session(
        &self,
        crypto_session_id: &str,
        from_seq: i64,
        limit: usize,
    ) -> RepositoryResult<Vec<DeliveryEvent>>;
}

pub struct PostgresDeliveryLogRepository {
    pool: PgPool,
}

impl PostgresDeliveryLogRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// Row mirror for `delivery_events`. sqlx's tuple `FromRow` impls only go up
/// to 16 elements, so we derive on a struct here.
#[derive(Debug, FromRow)]
struct DeliveryEventRow {
    id: String,
    conversation_id: String,
    seq: i64,
    crypto_session_id: Option<String>,
    event_type: String,
    sender_did: Option<String>,
    sender_device_id: Option<String>,
    mls_group_id: Option<String>,
    mls_epoch: Option<i64>,
    idempotency_key: Option<String>,
    payload: Option<Vec<u8>>,
    payload_json: Option<serde_json::Value>,
    origin_service_did: Option<String>,
    home_service_did: Option<String>,
    remote_event_id: Option<String>,
    auth_issuer_did: Option<String>,
    received_via: Option<String>,
    federation_trace_id: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
}

const SELECT_DELIVERY_EVENT_COLS: &str = "id, conversation_id, seq, crypto_session_id, \
    event_type, sender_did, sender_device_id, mls_group_id, mls_epoch, idempotency_key, \
    payload, payload_json, origin_service_did, home_service_did, remote_event_id, \
    auth_issuer_did, received_via, federation_trace_id, created_at";

fn row_to_event(r: DeliveryEventRow) -> DeliveryEvent {
    DeliveryEvent {
        id: r.id,
        conversation_id: r.conversation_id,
        seq: r.seq,
        crypto_session_id: r.crypto_session_id,
        event_type: r.event_type,
        sender_did: r.sender_did,
        sender_device_id: r.sender_device_id,
        mls_group_id: r.mls_group_id,
        mls_epoch: r.mls_epoch,
        idempotency_key: r.idempotency_key,
        payload: r.payload,
        payload_json: r.payload_json,
        origin_service_did: r.origin_service_did,
        home_service_did: r.home_service_did,
        remote_event_id: r.remote_event_id,
        auth_issuer_did: r.auth_issuer_did,
        received_via: r.received_via,
        federation_trace_id: r.federation_trace_id,
        created_at: r.created_at,
    }
}

#[async_trait]
impl DeliveryLogRepository for PostgresDeliveryLogRepository {
    async fn append(&self, event: NewDeliveryEvent) -> RepositoryResult<DeliveryEvent> {
        let id = if event.id.is_empty() {
            Uuid::new_v4().to_string()
        } else {
            event.id.clone()
        };

        // Run idempotency check + seq allocation + insert in one transaction
        // under an advisory lock keyed on conversation_id. The advisory lock
        // serializes concurrent appends for THIS conversation only — different
        // conversations remain fully parallel — and auto-releases on commit.
        let mut tx = self.pool.begin().await?;

        // Per-conversation advisory lock. Hash to fit into bigint (advisory
        // locks take an int8). hashtext() is stable across server restarts.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(&event.conversation_id)
            .execute(&mut *tx)
            .await?;

        // Idempotency check: if a row with the same idempotency tuple
        // already exists, return it instead of inserting. This handles
        // the legitimate-retry case where the original commit succeeded
        // but the response was lost.
        if event.idempotency_key.is_some() {
            let existing: Option<DeliveryEventRow> = sqlx::query_as(&format!(
                "SELECT {SELECT_DELIVERY_EVENT_COLS} FROM delivery_events \
                 WHERE conversation_id = $1 \
                   AND sender_did IS NOT DISTINCT FROM $2 \
                   AND sender_device_id IS NOT DISTINCT FROM $3 \
                   AND idempotency_key IS NOT DISTINCT FROM $4"
            ))
            .bind(&event.conversation_id)
            .bind(&event.sender_did)
            .bind(&event.sender_device_id)
            .bind(&event.idempotency_key)
            .fetch_optional(&mut *tx)
            .await?;

            if let Some(r) = existing {
                tx.commit().await?;
                return Ok(row_to_event(r));
            }
        }

        // Allocate next seq. Backfill seeds seq=0 per conversation, so
        // first real event becomes seq=1 — matches the in-memory fake's
        // semantics post-backfill.
        let next_seq: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(seq), -1) + 1 FROM delivery_events WHERE conversation_id = $1",
        )
        .bind(&event.conversation_id)
        .fetch_one(&mut *tx)
        .await?;

        // Insert. The UNIQUE on (conversation_id, sender_did, sender_device_id,
        // idempotency_key) is a defense-in-depth against the idempotency
        // check above missing a concurrent retry; if the conflict triggers,
        // we re-fetch the conflicting row.
        let inserted: Option<DeliveryEventRow> = sqlx::query_as(&format!(
            "INSERT INTO delivery_events ( \
                id, conversation_id, seq, crypto_session_id, event_type, \
                sender_did, sender_device_id, mls_group_id, mls_epoch, \
                idempotency_key, payload, payload_json, origin_service_did, \
                home_service_did, remote_event_id, auth_issuer_did, \
                received_via, federation_trace_id \
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, \
                $13, $14, $15, $16, $17, $18) \
             ON CONFLICT (conversation_id, sender_did, sender_device_id, idempotency_key) \
             DO NOTHING \
             RETURNING {SELECT_DELIVERY_EVENT_COLS}"
        ))
        .bind(&id)
        .bind(&event.conversation_id)
        .bind(next_seq)
        .bind(&event.crypto_session_id)
        .bind(&event.event_type)
        .bind(&event.sender_did)
        .bind(&event.sender_device_id)
        .bind(&event.mls_group_id)
        .bind(event.mls_epoch)
        .bind(&event.idempotency_key)
        .bind(&event.payload)
        .bind(&event.payload_json)
        .bind(&event.origin_service_did)
        .bind(&event.home_service_did)
        .bind(&event.remote_event_id)
        .bind(&event.auth_issuer_did)
        .bind(&event.received_via)
        .bind(&event.federation_trace_id)
        .fetch_optional(&mut *tx)
        .await?;

        if let Some(r) = inserted {
            tx.commit().await?;
            return Ok(row_to_event(r));
        }

        // ON CONFLICT DO NOTHING returned no row — fetch the existing one
        // that won the race.
        let raced: Option<DeliveryEventRow> = sqlx::query_as(&format!(
            "SELECT {SELECT_DELIVERY_EVENT_COLS} FROM delivery_events \
             WHERE conversation_id = $1 \
               AND sender_did IS NOT DISTINCT FROM $2 \
               AND sender_device_id IS NOT DISTINCT FROM $3 \
               AND idempotency_key IS NOT DISTINCT FROM $4"
        ))
        .bind(&event.conversation_id)
        .bind(&event.sender_did)
        .bind(&event.sender_device_id)
        .bind(&event.idempotency_key)
        .fetch_optional(&mut *tx)
        .await?;

        tx.commit().await?;

        raced
            .map(row_to_event)
            .ok_or_else(|| RepositoryError::Database(sqlx::Error::RowNotFound))
    }

    async fn read_range_by_session(
        &self,
        crypto_session_id: &str,
        from_seq: i64,
        limit: usize,
    ) -> RepositoryResult<Vec<DeliveryEvent>> {
        let limit_i64: i64 = limit.try_into().unwrap_or(i64::MAX);
        let rows: Vec<DeliveryEventRow> = sqlx::query_as(&format!(
            "SELECT {SELECT_DELIVERY_EVENT_COLS} FROM delivery_events \
             WHERE crypto_session_id = $1 AND seq >= $2 \
             ORDER BY seq ASC LIMIT $3"
        ))
        .bind(crypto_session_id)
        .bind(from_seq)
        .bind(limit_i64)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(row_to_event).collect())
    }
}
