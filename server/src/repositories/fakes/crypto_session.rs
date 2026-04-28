//! In-memory fake for `CryptoSessionRepository`. Test-only.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

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

    /// Test-only helper to insert a session directly. Phase 2's `create` will
    /// supersede this with a real path.
    pub fn insert(&self, session: CryptoSession) {
        let mut guard = self.inner.lock().expect("fake repo mutex poisoned");
        guard.insert(session.id.clone(), session);
    }

    /// Test-only helper to mark a session superseded without going through
    /// the trait method (which still returns `NotImplemented` until Phase 2).
    pub fn mark_superseded_for_test(
        &self,
        id: &str,
        superseded_by_id: &str,
        when: chrono::DateTime<chrono::Utc>,
    ) {
        let mut guard = self.inner.lock().expect("fake repo mutex poisoned");
        if let Some(s) = guard.get_mut(id) {
            s.state = "superseded".to_string();
            s.superseded_at = Some(when);
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
        let now = chrono::Utc::now();
        let row = CryptoSession {
            id: session.id,
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
            activated_at: Some(now),
            superseded_at: None,
            supersedes_id: session.supersedes_id,
        };
        let mut guard = self.inner.lock().expect("fake repo mutex poisoned");
        guard.insert(row.id.clone(), row.clone());
        Ok(row)
    }

    async fn mark_superseded(&self, id: &str, superseded_by_id: &str) -> RepositoryResult<()> {
        self.mark_superseded_for_test(id, superseded_by_id, chrono::Utc::now());
        Ok(())
    }
}
