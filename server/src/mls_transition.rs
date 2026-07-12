//! Atomic, server-observable MLS transition contract (ADR-011).

use sha2::{Digest, Sha256};

use crate::models::{ResolvedMlsContext, SequencerReceiptRef};

pub(crate) fn canonical_receipt_hash(
    conversation_id: &str,
    receipt: &SequencerReceiptRef,
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(conversation_id.as_bytes());
    hasher.update(receipt.epoch.to_be_bytes());
    hasher.update(receipt.term.to_be_bytes());
    hasher.update(crate::identity::canonical_did(&receipt.sequencer_did).as_bytes());
    hasher.update(&receipt.commit_hash);
    hasher.update(receipt.issued_at.to_be_bytes());
    hasher.update(&receipt.signature);
    hasher.finalize().to_vec()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionKind {
    Commit,
    AddMembers,
    Update,
    ExternalCommit,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TransitionValidationError {
    #[error("normal MLS transitions cannot rotate group identity")]
    GroupRotation,
    #[error("transition epoch must advance exactly once")]
    InvalidEpoch,
    #[error("authenticated actor and device binding are required")]
    MissingActorBinding,
    #[error("GroupInfo and commit evidence must not be empty")]
    MissingEvidence,
    #[error("receipt does not bind this transition")]
    ReceiptMismatch,
}

/// A server-observable transition whose identity and monotonicity bindings
/// have been checked. GroupInfo parsing/signature verification remains the
/// caller's operation-specific responsibility; construction does not claim
/// cryptographic verification.
#[derive(Debug, Clone)]
pub struct ValidatedMlsTransition {
    pub(crate) context: ResolvedMlsContext,
    pub(crate) kind: TransitionKind,
    pub(crate) actor_did: String,
    pub(crate) actor_device_id: String,
    pub(crate) next_epoch: i32,
    pub(crate) group_info: Vec<u8>,
    pub(crate) group_info_hash: Vec<u8>,
    pub(crate) confirmation_tag: Option<Vec<u8>>,
    pub(crate) commit_hash: Vec<u8>,
    pub(crate) receipt: Option<SequencerReceiptRef>,
}

impl ValidatedMlsTransition {
    #[allow(clippy::too_many_arguments)]
    pub fn new_observed(
        context: ResolvedMlsContext,
        kind: TransitionKind,
        actor_did: String,
        actor_device_id: String,
        observed_group_id: String,
        observed_epoch: i32,
        group_info: Vec<u8>,
        confirmation_tag: Option<Vec<u8>>,
        commit_hash: Vec<u8>,
        receipt: Option<SequencerReceiptRef>,
    ) -> Result<Self, TransitionValidationError> {
        if observed_group_id != context.mls_group_id {
            return Err(TransitionValidationError::GroupRotation);
        }
        if observed_epoch != context.authoritative_epoch.saturating_add(1) {
            return Err(TransitionValidationError::InvalidEpoch);
        }
        if actor_did.is_empty() || actor_device_id.is_empty() {
            return Err(TransitionValidationError::MissingActorBinding);
        }
        if group_info.is_empty() || commit_hash.is_empty() {
            return Err(TransitionValidationError::MissingEvidence);
        }
        let group_info_hash = Sha256::digest(&group_info).to_vec();
        let mut transition = Self {
            context,
            kind,
            actor_did,
            actor_device_id,
            next_epoch: observed_epoch,
            group_info,
            group_info_hash,
            confirmation_tag,
            commit_hash,
            receipt: None,
        };
        if let Some(receipt) = receipt {
            transition.set_verified_receipt(receipt)?;
        }
        Ok(transition)
    }

    pub fn set_verified_receipt(
        &mut self,
        receipt: SequencerReceiptRef,
    ) -> Result<(), TransitionValidationError> {
        if receipt.epoch != self.next_epoch
            || receipt.term != self.context.sequencer_term
            || receipt.sequencer_did != self.context.sequencer_did
            || receipt.commit_hash != self.commit_hash
        {
            return Err(TransitionValidationError::ReceiptMismatch);
        }
        self.receipt = Some(receipt);
        Ok(())
    }

    pub(crate) fn event_type(&self) -> &'static str {
        match self.kind {
            TransitionKind::Commit => "mls_transition_commit",
            TransitionKind::AddMembers => "mls_transition_add_members",
            TransitionKind::Update => "mls_transition_update",
            TransitionKind::ExternalCommit => "mls_transition_external_commit",
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::models::{ResolvedMlsContext, SequencerReceiptRef};
    use crate::repositories::fakes::{FakeTransitionFailure, InMemoryCryptoSessionRepository};
    use crate::repositories::{CryptoSessionRepository, RepositoryError};

    use super::{TransitionKind, ValidatedMlsTransition};

    fn context() -> ResolvedMlsContext {
        ResolvedMlsContext {
            conversation_id: "convo-1".into(),
            crypto_session_id: "session-1".into(),
            mls_group_id: "group-1".into(),
            reset_generation: 2,
            state: "active".into(),
            authoritative_epoch: 9,
            confirmation_tag: Some(vec![1, 2, 3]),
            group_info: Some(vec![0xAA; 128]),
            group_info_epoch: Some(9),
            sequencer_did: "did:web:mls.example.com".into(),
            sequencer_term: 4,
            receipt: None,
        }
    }

    fn transition(context: ResolvedMlsContext) -> ValidatedMlsTransition {
        ValidatedMlsTransition::new_observed(
            context,
            TransitionKind::Commit,
            "did:plc:alice".into(),
            "device-a".into(),
            "group-1".into(),
            10,
            vec![0xAB; 128],
            Some(vec![4, 5, 6]),
            vec![0xCC; 32],
            None,
        )
        .expect("valid transition")
    }

    #[test]
    fn mls_transition_rejects_group_rotation_and_non_monotonic_epoch() {
        let base = context();
        assert!(ValidatedMlsTransition::new_observed(
            base.clone(),
            TransitionKind::Commit,
            "did:plc:alice".into(),
            "device-a".into(),
            "group-2".into(),
            10,
            vec![0xAB; 128],
            None,
            vec![0xCC; 32],
            None,
        )
        .is_err());
        assert!(ValidatedMlsTransition::new_observed(
            base,
            TransitionKind::Commit,
            "did:plc:alice".into(),
            "device-a".into(),
            "group-1".into(),
            9,
            vec![0xAB; 128],
            None,
            vec![0xCC; 32],
            None,
        )
        .is_err());
    }

    #[tokio::test]
    async fn resolved_mls_context_converges_and_rejects_superseded_group() {
        let repo = InMemoryCryptoSessionRepository::new();
        repo.insert_resolved_context(context());

        let by_conversation = repo
            .resolve_active("convo-1", "did:web:mls.example.com")
            .await
            .unwrap();
        let by_group = repo
            .resolve_active_by_mls_group_id("group-1", "did:web:mls.example.com")
            .await
            .unwrap();
        assert_eq!(by_conversation, by_group);
        assert!(repo
            .resolve_active_by_mls_group_id("group-old", "did:web:mls.example.com")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn mls_transition_compare_and_swap_allows_exactly_one_winner() {
        let repo = InMemoryCryptoSessionRepository::new();
        repo.insert_resolved_context(context());
        let candidate = transition(context());

        let winner = repo.apply_transition(candidate.clone()).await.unwrap();
        let loser = repo.apply_transition(candidate).await.unwrap_err();

        assert_eq!(winner.context.authoritative_epoch, 10);
        assert!(matches!(loser, RepositoryError::StaleContext));
        let current = repo
            .resolve_active("convo-1", "did:web:mls.example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current.authoritative_epoch, 10);
        assert_eq!(current.confirmation_tag, Some(vec![4, 5, 6]));
    }

    #[tokio::test]
    async fn sequencer_receipt_replay_is_idempotent_and_conflict_is_rejected() {
        let repo = InMemoryCryptoSessionRepository::new();
        repo.insert_resolved_context(context());
        let receipt = SequencerReceiptRef {
            receipt_hash: Vec::new(),
            epoch: 10,
            term: 4,
            sequencer_did: "did:web:mls.example.com".into(),
            commit_hash: vec![0xCC; 32],
            issued_at: 1_700_000_000,
            signature: vec![8; 64],
        };
        let mut first = transition(context());
        first.set_verified_receipt(receipt.clone()).unwrap();
        let applied = repo.apply_transition(first).await.unwrap();
        let canonical = applied.receipt.unwrap();
        assert_eq!(canonical.receipt_hash.len(), 32);

        assert!(repo
            .record_verified_receipt(
                &context(),
                SequencerReceiptRef {
                    receipt_hash: vec![0xFF; 32],
                    ..receipt.clone()
                },
            )
            .await
            .is_ok());
        let mut conflicting = receipt;
        conflicting.commit_hash = vec![0xDD; 32];
        assert!(matches!(
            repo.record_verified_receipt(&context(), conflicting).await,
            Err(RepositoryError::ReceiptEquivocation)
        ));
    }

    #[tokio::test]
    async fn caller_supplied_receipt_hash_cannot_collide_across_conversations() {
        let repo = InMemoryCryptoSessionRepository::new();
        let first = context();
        let mut second = context();
        second.conversation_id = "convo-2".into();
        second.crypto_session_id = "session-2".into();
        second.mls_group_id = "group-2".into();
        let reused_hash = vec![0xAA; 32];
        let receipt = |commit_hash: u8| SequencerReceiptRef {
            receipt_hash: reused_hash.clone(),
            epoch: 10,
            term: 4,
            sequencer_did: "did:web:mls.example.com".into(),
            commit_hash: vec![commit_hash; 32],
            issued_at: 1_700_000_000,
            signature: vec![8; 64],
        };

        let stored_first = repo
            .record_verified_receipt(&first, receipt(1))
            .await
            .unwrap();
        let stored_second = repo
            .record_verified_receipt(&second, receipt(2))
            .await
            .unwrap();
        assert_ne!(stored_first.receipt_hash, reused_hash);
        assert_ne!(stored_second.receipt_hash, reused_hash);
        assert_ne!(stored_first.receipt_hash, stored_second.receipt_hash);
    }

    #[tokio::test]
    async fn fake_transition_failure_points_roll_back_all_staged_state() {
        for failure in [
            FakeTransitionFailure::Mirror,
            FakeTransitionFailure::Receipt,
            FakeTransitionFailure::Event,
        ] {
            let repo = InMemoryCryptoSessionRepository::new();
            repo.insert_resolved_context(context());
            let before = repo.transition_snapshot();
            let mut candidate = transition(context());
            if failure == FakeTransitionFailure::Receipt {
                candidate
                    .set_verified_receipt(SequencerReceiptRef {
                        receipt_hash: vec![0xEE; 32],
                        epoch: 10,
                        term: 4,
                        sequencer_did: "did:web:mls.example.com".into(),
                        commit_hash: vec![0xCC; 32],
                        issued_at: 1_700_000_000,
                        signature: vec![8; 64],
                    })
                    .unwrap();
            }
            repo.fail_next_transition_at(failure);

            assert!(repo.apply_transition(candidate).await.is_err());
            assert_eq!(repo.transition_snapshot(), before);
        }
    }
}
