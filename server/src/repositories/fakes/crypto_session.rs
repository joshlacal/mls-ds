//! In-memory fake for `CryptoSessionRepository`. Test-only.
//!
//! Mirrors the Phase 2 Postgres semantics:
//! - `create` is idempotent on `(conversation_id, generation)` and returns
//!   the existing row on conflict (instead of allocating a new id).
//! - `mark_superseded` is idempotent — calling it twice on the same row is
//!   a no-op rather than an error.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use uuid::Uuid;

use crate::models::{CryptoSession, NewCryptoSession};
use crate::repositories::{CryptoSessionRepository, RepositoryResult};

#[derive(Clone, Default)]
pub struct InMemoryCryptoSessionRepository {
    /// keyed by `CryptoSession::id`
    inner: Arc<Mutex<HashMap<String, CryptoSession>>>,
}

impl InMemoryCryptoSessionRepository {
    pub fn new() -> Self {
        Self::default()
    }

    /// Test-only helper to insert a session directly. Bypasses tie-break
    /// idempotency — useful for seeding fixtures.
    pub fn insert(&self, session: CryptoSession) {
        let mut guard = self.inner.lock().expect("fake repo mutex poisoned");
        guard.insert(session.id.clone(), session);
    }

    /// Test-only helper to mark a session superseded. Phase 2's trait
    /// `mark_superseded` does the same thing; this exists so legacy tests
    /// that supplied an explicit timestamp continue to work.
    pub fn mark_superseded_for_test(
        &self,
        id: &str,
        superseded_by_id: &str,
        when: chrono::DateTime<chrono::Utc>,
    ) {
        let mut guard = self.inner.lock().expect("fake repo mutex poisoned");
        if let Some(s) = guard.get_mut(id) {
            if matches!(
                s.state.as_str(),
                "active" | "superseding" | "reset_requested"
            ) {
                s.state = "superseded".to_string();
                s.superseded_at = Some(when);
            }
        }
        if let Some(s) = guard.get_mut(superseded_by_id) {
            s.supersedes_id = Some(id.to_string());
        }
    }
}

#[async_trait]
impl CryptoSessionRepository for InMemoryCryptoSessionRepository {
    async fn get_active(&self, conversation_id: &str) -> RepositoryResult<Option<CryptoSession>> {
        let guard = self.inner.lock().expect("fake repo mutex poisoned");
        Ok(guard
            .values()
            .find(|s| s.conversation_id == conversation_id && s.state == "active")
            .cloned())
    }

    async fn get_by_mls_group_id(
        &self,
        mls_group_id: &str,
    ) -> RepositoryResult<Option<CryptoSession>> {
        let guard = self.inner.lock().expect("fake repo mutex poisoned");
        Ok(guard
            .values()
            .find(|s| s.mls_group_id == mls_group_id)
            .cloned())
    }

    async fn create(&self, session: NewCryptoSession) -> RepositoryResult<CryptoSession> {
        let mut guard = self.inner.lock().expect("fake repo mutex poisoned");

        // Idempotency on (conversation_id, generation) — mirror the Postgres
        // UNIQUE constraint. If a session with this key already exists,
        // return it instead of inserting.
        if let Some(existing) = guard.values().find(|s| {
            s.conversation_id == session.conversation_id && s.generation == session.generation
        }) {
            return Ok(existing.clone());
        }

        let id = if session.id.is_empty() {
            Uuid::new_v4().to_string()
        } else {
            session.id
        };
        let now = chrono::Utc::now();
        let activated_at = if session.state == "active" {
            Some(now)
        } else {
            None
        };
        let row = CryptoSession {
            id: id.clone(),
            conversation_id: session.conversation_id,
            generation: session.generation,
            mls_group_id: session.mls_group_id,
            state: session.state,
            cipher_suite: session.cipher_suite,
            last_observed_epoch: session.last_observed_epoch,
            last_confirmation_tag: session.last_confirmation_tag,
            group_info: session.group_info,
            group_info_epoch: session.group_info_epoch,
            group_info_updated_at: None,
            created_by_did: session.created_by_did,
            created_at: now,
            activated_at,
            superseded_at: None,
            supersedes_id: session.supersedes_id,
        };
        guard.insert(id, row.clone());
        Ok(row)
    }

    async fn mark_superseded(&self, id: &str, superseded_by_id: &str) -> RepositoryResult<()> {
        self.mark_superseded_for_test(id, superseded_by_id, chrono::Utc::now());
        Ok(())
    }
}
