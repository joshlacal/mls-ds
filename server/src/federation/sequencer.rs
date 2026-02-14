use sqlx::PgPool;
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
}

/// Handles commit ordering for conversations this DS sequences.
pub struct Sequencer {
    pool: PgPool,
    self_did: String,
    receipt_signer: Option<ReceiptSigner>,
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
    /// `commit_ciphertext` is the raw commit data used to produce a receipt
    /// when a `ReceiptSigner` is configured.
    pub async fn submit_commit(
        &self,
        convo_id: &str,
        current_epoch: i32,
        proposed_epoch: i32,
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

        // CAS: atomically advance the epoch only if it still matches
        let result = sqlx::query(
            "UPDATE conversations SET current_epoch = $2 \
       WHERE id = $1 AND current_epoch = $3",
        )
        .bind(convo_id)
        .bind(proposed_epoch)
        .bind(current_epoch)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 1 {
            debug!(convo_id, proposed_epoch, "Commit accepted, epoch advanced");
            let receipt = self
                .receipt_signer
                .as_ref()
                .map(|s| s.sign_receipt(convo_id, proposed_epoch, commit_ciphertext));
            return Ok(CommitResult::Accepted {
                assigned_epoch: proposed_epoch,
                receipt,
            });
        }

        // Someone else committed first — fetch the actual current epoch
        let actual_epoch = sqlx::query_scalar::<_, Option<i32>>(
            "SELECT current_epoch FROM conversations WHERE id = $1",
        )
        .bind(convo_id)
        .fetch_optional(&self.pool)
        .await?;

        match actual_epoch {
            Some(Some(actual)) => {
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
