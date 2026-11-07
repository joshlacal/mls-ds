use std::sync::Arc;

use sqlx::{PgPool, Postgres, Transaction};
use tracing::{debug, warn};

use super::receipt::{I13ReceiptSigner, SequencerReceipt};
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
    receipt_signer: Option<Arc<I13ReceiptSigner>>,
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

    /// Set the process's validated receipt signer, shared with every issuer.
    pub fn with_receipt_signer(mut self, signer: Option<Arc<I13ReceiptSigner>>) -> Self {
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
    /// Local sequencer has `is_remote = FALSE` (`sequencer_ds IS NULL`).
    pub async fn is_sequencer_for(&self, convo_id: &str) -> Result<bool, sqlx::Error> {
        let Ok(convo_uuid) = uuid::Uuid::parse_str(convo_id) else {
            return Ok(false);
        };
        let row = sqlx::query_as::<_, (bool, Option<String>)>(
            "SELECT is_remote, sequencer_ds FROM chat.conversations WHERE conversation_id = $1",
        )
        .bind(convo_uuid)
        .fetch_optional(&self.pool)
        .await?;

        let is_sequencer = match row {
            Some((false, _)) => true,
            Some((true, Some(ds))) => canonical_did(&ds) == canonical_did(&self.self_did),
            Some((true, None)) => false,
            None => false,
        };

        Ok(is_sequencer)
    }

    /// Submit a commit for sequencing via CAS on `current_generation` and `sequencer_term`.
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

        let Ok(convo_uuid) = uuid::Uuid::parse_str(convo_id) else {
            return Ok(CommitResult::Conflict {
                current_epoch: -1,
                reason: "Conversation not found".to_string(),
            });
        };

        let result = sqlx::query(
            "UPDATE chat.conversations SET current_generation = $2 \
             WHERE conversation_id = $1 AND current_generation = $3 AND sequencer_term = $4 AND NOT is_remote",
        )
        .bind(convo_uuid)
        .bind(i64::from(proposed_epoch))
        .bind(i64::from(current_epoch))
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

        let current = sqlx::query_as::<_, (i64, i64)>(
            "SELECT current_generation, sequencer_term FROM chat.conversations WHERE conversation_id = $1",
        )
        .bind(convo_uuid)
        .fetch_optional(&mut **tx)
        .await?;

        match current {
            Some((_actual_epoch, actual_term)) if actual_term.max(0) as u64 != sequencer_term => {
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
            Some((actual, _)) => {
                let actual_i32 = i32::try_from(actual).unwrap_or(i32::MAX);
                warn!(
                    convo_id,
                    proposed_epoch,
                    actual_epoch = actual_i32,
                    "Commit conflict detected"
                );
                Ok(CommitResult::Conflict {
                    current_epoch: actual_i32,
                    reason: format!("Epoch already advanced to {actual_i32}"),
                })
            }
            None => Ok(CommitResult::Conflict {
                current_epoch: -1,
                reason: "Conversation not found".to_string(),
            }),
        }
    }

    /// Get the current generation/epoch for a conversation.
    pub async fn get_epoch(&self, convo_id: &str) -> Result<Option<i32>, sqlx::Error> {
        let Ok(convo_uuid) = uuid::Uuid::parse_str(convo_id) else {
            return Ok(None);
        };
        sqlx::query_scalar::<_, i64>(
            "SELECT current_generation FROM chat.conversations WHERE conversation_id = $1",
        )
        .bind(convo_uuid)
        .fetch_optional(&self.pool)
        .await
        .map(|opt| opt.and_then(|v| i32::try_from(v).ok()))
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

    fn sequencer(signer: Option<I13ReceiptSigner>) -> Sequencer {
        Sequencer::new(
            PgPool::connect_lazy("postgres://localhost/unused").unwrap(),
            "did:web:ds.example.com".to_string(),
        )
        .with_receipt_signer(signer.map(Arc::new))
    }

    #[tokio::test]
    async fn local_receipt_requires_matching_canonical_sequencer_did() {
        let signer = I13ReceiptSigner::new(
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
        let signer = I13ReceiptSigner::new(
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
        let signer = I13ReceiptSigner::new(
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
