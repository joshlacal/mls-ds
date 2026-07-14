use sqlx::{PgPool, Postgres, Transaction};
use tracing::{debug, warn};

use super::receipt::{ReceiptSigner, SequencerReceipt};
use crate::identity::canonical_did;

/// Result of a commit submission.
#[derive(Debug)]
pub enum CommitResult {
    /// Commit accepted, epoch advanced.
    Accepted {
        assigned_epoch: i32,
        receipt: Option<SequencerReceipt>,
    },
    /// Commit rejected due to epoch conflict.
    Conflict { current_epoch: i32, reason: String },
    /// Commit rejected because the provided sequencer term is stale.
    TermStale { current_term: u64, reason: String },
}

/// Handles commit ordering for conversations this DS sequences.
pub struct Sequencer {
    pool: PgPool,
    self_did: String,
    receipt_signer: Option<ReceiptSigner>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LocalReceiptError {
    #[error("resolved sequencer is not this delivery service")]
    WrongSequencer,
    #[error("local receipt signer is unavailable")]
    SignerUnavailable,
    #[error("receipt signer identity is not the canonical resolved sequencer")]
    SignerIdentityMismatch,
}

impl Sequencer {
    pub fn new(pool: PgPool, self_did: String) -> Self {
        Self {
            pool,
            self_did,
            receipt_signer: None,
        }
    }

    /// Set an optional receipt signer for producing sequencer receipts.
    pub fn with_receipt_signer(mut self, signer: Option<ReceiptSigner>) -> Self {
        self.receipt_signer = signer;
        self
    }

    /// Issue a receipt only when the resolved authority names this delivery
    /// service and a production signing key is available.
    pub fn issue_local_receipt(
        &self,
        convo_id: &str,
        epoch: i32,
        sequencer_term: u64,
        commit_ciphertext: &[u8],
        expected_sequencer_did: &str,
    ) -> Result<SequencerReceipt, LocalReceiptError> {
        if canonical_did(expected_sequencer_did) != canonical_did(&self.self_did) {
            return Err(LocalReceiptError::WrongSequencer);
        }
        let receipt = self
            .receipt_signer
            .as_ref()
            .map(|signer| signer.sign_receipt(convo_id, epoch, sequencer_term, commit_ciphertext))
            .ok_or(LocalReceiptError::SignerUnavailable)?;
        if receipt.sequencer_did != canonical_did(expected_sequencer_did) {
            return Err(LocalReceiptError::SignerIdentityMismatch);
        }
        Ok(receipt)
    }

    /// Check if this DS is the sequencer for a conversation.
    /// `sequencer_ds` NULL means we are the sequencer (backward compat).
    pub async fn is_sequencer_for(&self, convo_id: &str) -> Result<bool, sqlx::Error> {
        let row = sqlx::query_scalar::<_, Option<String>>(
            "SELECT sequencer_ds FROM conversations WHERE id = $1",
        )
        .bind(convo_id)
        .fetch_optional(&self.pool)
        .await?;

        let is_sequencer = match row {
            Some(Some(ds)) => canonical_did(&ds) == canonical_did(&self.self_did),
            Some(None) => true,
            None => false,
        };

        Ok(is_sequencer)
    }

    /// Submit a commit for sequencing via CAS on `current_epoch`.
    ///
    /// MIMI-inspired safety invariants for sequencing:
    /// - `sequencer_term` is the lease term for the active sequencer and must
    ///   match exactly for the commit to be accepted.
    /// - `current_epoch` advances by exactly one per accepted commit.
    /// - `(convo_id, current_epoch, sequencer_term)` CAS guarantees a single
    ///   writer per term and fences out stale sequencers during failover.
    ///
    /// `commit_ciphertext` is the raw commit data used to produce a receipt
    /// when a `ReceiptSigner` is configured.
    ///
    /// TASK #36: the CAS now runs on the caller's `&mut Transaction`. All three
    /// CAS predicates (`convo_id`, `current_epoch`, `sequencer_term`) evaluate
    /// on the same connection and same tx as the caller's subsequent
    /// `commits` + `messages` inserts. A crash or rollback after the CAS
    /// advance but before the caller's commit now atomically undoes the epoch
    /// advance — no orphan epochs from the federation path.
    ///
    /// Callers must `tx.commit()` themselves after this returns
    /// `CommitResult::Accepted`. Returning `Conflict` or `TermStale` does NOT
    /// release the tx; caller decides whether to roll back (typical) or
    /// continue with compensating state in the same tx.
    pub async fn submit_commit(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        convo_id: &str,
        current_epoch: i32,
        proposed_epoch: i32,
        sequencer_term: u64,
        commit_ciphertext: &[u8],
    ) -> Result<CommitResult, sqlx::Error> {
        if proposed_epoch != current_epoch + 1 {
            return Ok(CommitResult::Conflict {
                current_epoch,
                reason: format!(
                    "proposed_epoch ({proposed_epoch}) must be current_epoch ({current_epoch}) + 1"
                ),
            });
        }

        // CAS: atomically advance the epoch only if it still matches.
        // Runs on the caller's tx (task #36) so epoch advance + caller's
        // commit-row + message-row inserts are one atomic unit.
        let result = sqlx::query(
            "UPDATE conversations SET current_epoch = $2, updated_at = NOW() \
        WHERE id = $1 AND current_epoch = $3 AND sequencer_term = $4",
        )
        .bind(convo_id)
        .bind(proposed_epoch)
        .bind(current_epoch)
        .bind(sequencer_term as i64)
        .execute(&mut **tx)
        .await?;

        if result.rows_affected() == 1 {
            debug!(convo_id, proposed_epoch, "Commit accepted, epoch advanced");
            let receipt = self.receipt_signer.as_ref().map(|s| {
                s.sign_receipt(convo_id, proposed_epoch, sequencer_term, commit_ciphertext)
            });
            return Ok(CommitResult::Accepted {
                assigned_epoch: proposed_epoch,
                receipt,
            });
        }

        // Either epoch moved or term moved — fetch current values on the
        // same tx so we see the same snapshot the CAS just lost against.
        // (Reading on &self.pool would race: a different concurrent commit
        // could have advanced again between our CAS and the read.)
        let current = sqlx::query_as::<_, (Option<i32>, Option<i64>)>(
            "SELECT current_epoch, sequencer_term FROM conversations WHERE id = $1",
        )
        .bind(convo_id)
        .fetch_optional(&mut **tx)
        .await?;

        match current {
            Some((Some(_actual_epoch), Some(actual_term)))
                if actual_term.max(0) as u64 != sequencer_term =>
            {
                let current_term = actual_term.max(0) as u64;
                warn!(
                    convo_id,
                    provided_term = sequencer_term,
                    current_term,
                    "Commit rejected due to stale sequencer term"
                );
                Ok(CommitResult::TermStale {
                    current_term,
                    reason: format!(
                        "provided sequencer_term ({sequencer_term}) does not match current term ({current_term})"
                    ),
                })
            }
            Some((Some(actual), _)) => {
                warn!(
                    convo_id,
                    proposed_epoch,
                    actual_epoch = actual,
                    "Commit conflict detected"
                );
                Ok(CommitResult::Conflict {
                    current_epoch: actual,
                    reason: format!("Epoch already advanced to {actual}"),
                })
            }
            _ => Ok(CommitResult::Conflict {
                current_epoch: -1,
                reason: "Conversation not found".to_string(),
            }),
        }
    }

    /// Get the current epoch for a conversation.
    pub async fn get_epoch(&self, convo_id: &str) -> Result<Option<i32>, sqlx::Error> {
        sqlx::query_scalar::<_, Option<i32>>(
            "SELECT current_epoch FROM conversations WHERE id = $1",
        )
        .bind(convo_id)
        .fetch_optional(&self.pool)
        .await
        .map(|opt| opt.flatten())
    }

    pub fn self_did(&self) -> &str {
        &self.self_did
    }
}

#[cfg(test)]
mod local_receipt_tests {
    use p256::ecdsa::SigningKey;
    use rand::rngs::OsRng;

    use super::*;

    fn sequencer(signer: Option<ReceiptSigner>) -> Sequencer {
        Sequencer::new(
            PgPool::connect_lazy("postgres://localhost/unused").unwrap(),
            "did:web:ds.example.com".to_string(),
        )
        .with_receipt_signer(signer)
    }

    #[tokio::test]
    async fn local_receipt_requires_matching_canonical_sequencer_did() {
        let signer = ReceiptSigner::new(
            SigningKey::random(&mut OsRng),
            "did:web:ds.example.com".to_string(),
        );
        assert!(matches!(
            sequencer(Some(signer)).issue_local_receipt(
                "convo-1",
                2,
                7,
                b"commit",
                "did:web:attacker.example"
            ),
            Err(LocalReceiptError::WrongSequencer)
        ));
    }

    #[tokio::test]
    async fn local_receipt_requires_configured_signer() {
        assert!(matches!(
            sequencer(None).issue_local_receipt(
                "convo-1",
                2,
                7,
                b"commit",
                "did:web:ds.example.com"
            ),
            Err(LocalReceiptError::SignerUnavailable)
        ));
    }

    #[tokio::test]
    async fn local_receipt_rejects_mismatched_signer_identity() {
        let signer = ReceiptSigner::new(
            SigningKey::random(&mut OsRng),
            "did:web:other.example.com".to_string(),
        );
        assert!(matches!(
            sequencer(Some(signer)).issue_local_receipt(
                "convo-1",
                2,
                7,
                b"commit",
                "did:web:ds.example.com"
            ),
            Err(LocalReceiptError::SignerIdentityMismatch)
        ));
    }

    #[tokio::test]
    async fn local_receipt_is_bound_to_commit_and_authority() {
        let signer = ReceiptSigner::new(
            SigningKey::random(&mut OsRng),
            "did:web:ds.example.com".to_string(),
        );
        let receipt = sequencer(Some(signer))
            .issue_local_receipt("convo-1", 2, 7, b"commit", "did:web:ds.example.com")
            .expect("local receipt");
        assert_eq!(receipt.convo_id, "convo-1");
        assert_eq!(receipt.epoch, 2);
        assert_eq!(receipt.sequencer_term, 7);
        assert_eq!(
            receipt.commit_hash,
            super::super::receipt::hash_commit(b"commit")
        );
        assert_eq!(receipt.sequencer_did, "did:web:ds.example.com");
    }
}
