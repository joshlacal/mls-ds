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

use crate::mls_transition::{canonical_receipt_hash, ValidatedMlsTransition};
use crate::models::{
    AppliedMlsTransition, CryptoSession, NewCryptoSession, ResolvedMlsContext, SequencerReceiptRef,
};
use crate::repositories::{CryptoSessionRepository, RepositoryError, RepositoryResult};

#[derive(Clone, Default)]
pub struct InMemoryCryptoSessionRepository {
    /// keyed by `CryptoSession::id`
    inner: Arc<Mutex<HashMap<String, CryptoSession>>>,
    contexts: Arc<Mutex<HashMap<String, ResolvedMlsContext>>>,
    legacy_contexts: Arc<Mutex<HashMap<String, ResolvedMlsContext>>>,
    receipts: Arc<Mutex<HashMap<(String, i32), SequencerReceiptRef>>>,
    next_sequence: Arc<Mutex<HashMap<String, i64>>>,
    next_failure: Arc<Mutex<Option<FakeTransitionFailure>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FakeTransitionFailure {
    Mirror,
    Receipt,
    Event,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeTransitionSnapshot {
    contexts: HashMap<String, ResolvedMlsContext>,
    legacy_contexts: HashMap<String, ResolvedMlsContext>,
    receipts: HashMap<(String, i32), SequencerReceiptRef>,
    next_sequence: HashMap<String, i64>,
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

    pub fn insert_resolved_context(&self, context: ResolvedMlsContext) {
        self.contexts
            .lock()
            .expect("fake context mutex poisoned")
            .insert(context.conversation_id.clone(), context.clone());
        self.legacy_contexts
            .lock()
            .expect("fake legacy context mutex poisoned")
            .insert(context.conversation_id.clone(), context);
    }

    pub fn fail_next_transition_at(&self, failure: FakeTransitionFailure) {
        *self
            .next_failure
            .lock()
            .expect("fake failure mutex poisoned") = Some(failure);
    }

    pub fn transition_snapshot(&self) -> FakeTransitionSnapshot {
        FakeTransitionSnapshot {
            contexts: self
                .contexts
                .lock()
                .expect("fake context mutex poisoned")
                .clone(),
            legacy_contexts: self
                .legacy_contexts
                .lock()
                .expect("fake legacy context mutex poisoned")
                .clone(),
            receipts: self
                .receipts
                .lock()
                .expect("fake receipt mutex poisoned")
                .clone(),
            next_sequence: self
                .next_sequence
                .lock()
                .expect("fake sequence mutex poisoned")
                .clone(),
        }
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
            if matches!(s.state.as_str(), "active" | "superseding") {
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

    async fn resolve_active(
        &self,
        conversation_id: &str,
        _local_service_did: &str,
    ) -> RepositoryResult<Option<ResolvedMlsContext>> {
        let context = self
            .contexts
            .lock()
            .expect("fake context mutex poisoned")
            .get(conversation_id)
            .filter(|context| context.state == "active")
            .cloned();
        if let Some(context) = context.as_ref() {
            let legacy = self
                .legacy_contexts
                .lock()
                .expect("fake legacy context mutex poisoned")
                .get(conversation_id)
                .cloned();
            if legacy.as_ref() != Some(context) {
                return Err(RepositoryError::InvalidContext(
                    "legacy projection disagrees with active session".into(),
                ));
            }
        }
        Ok(context)
    }

    async fn resolve_active_by_mls_group_id(
        &self,
        mls_group_id: &str,
        _local_service_did: &str,
    ) -> RepositoryResult<Option<ResolvedMlsContext>> {
        let context = self
            .contexts
            .lock()
            .expect("fake context mutex poisoned")
            .values()
            .find(|context| context.state == "active" && context.mls_group_id == mls_group_id)
            .cloned();
        if let Some(context) = context.as_ref() {
            let legacy = self
                .legacy_contexts
                .lock()
                .expect("fake legacy context mutex poisoned")
                .get(&context.conversation_id)
                .cloned();
            if legacy.as_ref() != Some(context) {
                return Err(RepositoryError::InvalidContext(
                    "legacy projection disagrees with active session".into(),
                ));
            }
        }
        Ok(context)
    }

    async fn apply_transition(
        &self,
        transition: ValidatedMlsTransition,
    ) -> RepositoryResult<AppliedMlsTransition> {
        let mut contexts_guard = self.contexts.lock().expect("fake context mutex poisoned");
        let mut legacy_guard = self
            .legacy_contexts
            .lock()
            .expect("fake legacy context mutex poisoned");
        let mut receipts_guard = self.receipts.lock().expect("fake receipt mutex poisoned");
        let mut sequences_guard = self
            .next_sequence
            .lock()
            .expect("fake sequence mutex poisoned");
        let failure = self
            .next_failure
            .lock()
            .expect("fake failure mutex poisoned")
            .take();
        let mut contexts = contexts_guard.clone();
        let mut legacy_contexts = legacy_guard.clone();
        let mut receipts = receipts_guard.clone();
        let mut sequences = sequences_guard.clone();
        let current = contexts
            .get_mut(&transition.context.conversation_id)
            .ok_or_else(|| RepositoryError::InvalidContext("active session missing".into()))?;
        if current != &transition.context {
            return Err(RepositoryError::StaleContext);
        }
        let legacy = legacy_contexts
            .get_mut(&transition.context.conversation_id)
            .ok_or_else(|| RepositoryError::InvalidContext("legacy projection missing".into()))?;
        if legacy != &transition.context {
            return Err(RepositoryError::InvalidContext(
                "legacy projection disagrees with active session".into(),
            ));
        }
        if failure == Some(FakeTransitionFailure::Mirror) {
            return Err(RepositoryError::InjectedFailure("mirror"));
        }
        let receipt = transition.receipt.clone().map(|mut receipt| {
            receipt.receipt_hash =
                canonical_receipt_hash(&transition.context.conversation_id, &receipt);
            receipt
        });
        if let Some(receipt) = receipt.as_ref() {
            if failure == Some(FakeTransitionFailure::Receipt) {
                return Err(RepositoryError::InjectedFailure("receipt"));
            }
            let key = (transition.context.conversation_id.clone(), receipt.epoch);
            match receipts.get(&key) {
                Some(existing) if existing == receipt => {}
                Some(_) => return Err(RepositoryError::ReceiptEquivocation),
                None => {
                    receipts.insert(key, receipt.clone());
                }
            }
        }
        current.authoritative_epoch = transition.next_epoch;
        current.confirmation_tag = transition.confirmation_tag.clone();
        current.group_info = Some(transition.group_info.clone());
        current.group_info_epoch = Some(transition.next_epoch);
        current.receipt = receipt.clone();
        *legacy = current.clone();
        let updated = current.clone();
        if failure == Some(FakeTransitionFailure::Event) {
            return Err(RepositoryError::InjectedFailure("event"));
        }
        let sequence = *sequences
            .entry(updated.conversation_id.clone())
            .and_modify(|seq| *seq += 1)
            .or_insert(1);
        *contexts_guard = contexts;
        *legacy_guard = legacy_contexts;
        *receipts_guard = receipts;
        *sequences_guard = sequences;
        Ok(AppliedMlsTransition {
            context: updated,
            delivery_event_id: Uuid::new_v4().to_string(),
            delivery_sequence: sequence,
            receipt,
        })
    }

    async fn record_verified_receipt(
        &self,
        context: &ResolvedMlsContext,
        receipt: SequencerReceiptRef,
    ) -> RepositoryResult<SequencerReceiptRef> {
        if receipt.epoch != context.authoritative_epoch + 1
            || receipt.term != context.sequencer_term
            || receipt.sequencer_did != context.sequencer_did
        {
            return Err(RepositoryError::InvalidContext(
                "receipt does not bind resolved authority".into(),
            ));
        }
        let mut receipt = receipt;
        receipt.receipt_hash = canonical_receipt_hash(&context.conversation_id, &receipt);
        let key = (context.conversation_id.clone(), receipt.epoch);
        let mut receipts = self.receipts.lock().expect("fake receipt mutex poisoned");
        match receipts.get(&key) {
            Some(existing) if existing == &receipt => Ok(existing.clone()),
            Some(_) => Err(RepositoryError::ReceiptEquivocation),
            None => {
                receipts.insert(key, receipt.clone());
                Ok(receipt)
            }
        }
    }
}
