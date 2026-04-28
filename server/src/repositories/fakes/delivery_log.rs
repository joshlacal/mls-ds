//! In-memory fake for `DeliveryLogRepository`. Test-only.
//!
//! Mirrors the Phase 2 Postgres semantics:
//! - `append` is idempotent on
//!   `(conversation_id, sender_did, sender_device_id, idempotency_key)`.
//!   Duplicate retries return the existing event.
//! - `seq` is monotonic per conversation, starts at 1 (matches Postgres
//!   semantics post-backfill: backfill seeds seq=0, first real event = 1).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use uuid::Uuid;

use crate::models::{DeliveryEvent, NewDeliveryEvent};
use crate::repositories::{DeliveryLogRepository, RepositoryResult};

#[derive(Clone, Default)]
pub struct InMemoryDeliveryLogRepository {
    /// keyed by conversation_id, value is an ordered Vec of events.
    inner: Arc<Mutex<HashMap<String, Vec<DeliveryEvent>>>>,
}

impl InMemoryDeliveryLogRepository {
    pub fn new() -> Self {
        Self::default()
    }
}

fn idempotency_match(
    e: &DeliveryEvent,
    sender_did: &Option<String>,
    sender_device_id: &Option<String>,
    idempotency_key: &Option<String>,
) -> bool {
    e.sender_did == *sender_did
        && e.sender_device_id == *sender_device_id
        && e.idempotency_key == *idempotency_key
}

#[async_trait]
impl DeliveryLogRepository for InMemoryDeliveryLogRepository {
    async fn append(&self, event: NewDeliveryEvent) -> RepositoryResult<DeliveryEvent> {
        let mut guard = self.inner.lock().expect("fake log mutex poisoned");
        let log = guard.entry(event.conversation_id.clone()).or_default();

        // Idempotency check: if an event with the same tuple already
        // exists, return it.
        if event.idempotency_key.is_some() {
            if let Some(existing) = log.iter().find(|e| {
                idempotency_match(
                    e,
                    &event.sender_did,
                    &event.sender_device_id,
                    &event.idempotency_key,
                )
            }) {
                return Ok(existing.clone());
            }
        }

        let next_seq = log.last().map_or(0, |e| e.seq) + 1;
        let id = if event.id.is_empty() {
            Uuid::new_v4().to_string()
        } else {
            event.id
        };
        let row = DeliveryEvent {
            id,
            conversation_id: event.conversation_id,
            seq: next_seq,
            crypto_session_id: event.crypto_session_id,
            event_type: event.event_type,
            sender_did: event.sender_did,
            sender_device_id: event.sender_device_id,
            mls_group_id: event.mls_group_id,
            mls_epoch: event.mls_epoch,
            idempotency_key: event.idempotency_key,
            payload: event.payload,
            payload_json: event.payload_json,
            origin_service_did: event.origin_service_did,
            home_service_did: event.home_service_did,
            remote_event_id: event.remote_event_id,
            auth_issuer_did: event.auth_issuer_did,
            received_via: event.received_via,
            federation_trace_id: event.federation_trace_id,
            created_at: chrono::Utc::now(),
        };
        log.push(row.clone());
        Ok(row)
    }

    async fn read_range_by_session(
        &self,
        crypto_session_id: &str,
        from_seq: i64,
        limit: usize,
    ) -> RepositoryResult<Vec<DeliveryEvent>> {
        let guard = self.inner.lock().expect("fake log mutex poisoned");
        let mut out = Vec::new();
        for log in guard.values() {
            for e in log.iter().filter(|e| {
                e.crypto_session_id.as_deref() == Some(crypto_session_id) && e.seq >= from_seq
            }) {
                if out.len() >= limit {
                    break;
                }
                out.push(e.clone());
            }
        }
        out.sort_by_key(|e| e.seq);
        out.truncate(limit);
        Ok(out)
    }
}
