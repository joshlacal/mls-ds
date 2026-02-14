use sqlx::PgPool;
use tracing::{info, warn};

use crate::identity::canonical_did;

/// Handles sequencer role transfer between DSes.
pub struct SequencerTransfer {
    pool: PgPool,
    self_did: String,
}

impl SequencerTransfer {
    pub fn new(pool: PgPool, self_did: String) -> Self {
        Self { pool, self_did }
    }

    /// Initiate a sequencer transfer to a new DS.
    ///
    /// Updates the local DB. The actual handoff (notifying the new
    /// sequencer) is handled by the caller via an outbound call.
    pub async fn initiate_transfer(
        &self,
        convo_id: &str,
        new_sequencer_did: &str,
    ) -> Result<TransferResult, TransferError> {
        let current = sqlx::query_scalar::<_, Option<String>>(
            "SELECT sequencer_ds FROM conversations WHERE id = $1",
        )
        .bind(convo_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(TransferError::Database)?;

        match current {
            None => return Err(TransferError::ConversationNotFound(convo_id.to_string())),
            Some(Some(ref ds)) if canonical_did(ds) != canonical_did(&self.self_did) => {
                return Err(TransferError::NotCurrentSequencer {
                    convo_id: convo_id.to_string(),
                    current_sequencer: ds.clone(),
                });
            }
            _ => {} // NULL or our DID — we are the sequencer
        }

        sqlx::query("UPDATE conversations SET sequencer_ds = $2 WHERE id = $1")
            .bind(convo_id)
            .bind(new_sequencer_did)
            .execute(&self.pool)
            .await
            .map_err(TransferError::Database)?;

        info!(
            convo_id,
            new_sequencer = new_sequencer_did,
            "Sequencer transfer initiated"
        );

        Ok(TransferResult::Transferred {
            convo_id: convo_id.to_string(),
            new_sequencer_did: new_sequencer_did.to_string(),
        })
    }

    /// Accept a sequencer transfer (we are the NEW sequencer).
    pub async fn accept_transfer(
        &self,
        convo_id: &str,
        from_sequencer_did: &str,
        _current_epoch: i32,
    ) -> Result<TransferResult, TransferError> {
        let row = sqlx::query_as::<_, (Option<String>, Option<i32>)>(
            "SELECT sequencer_ds, current_epoch FROM conversations \
       WHERE id = $1",
        )
        .bind(convo_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(TransferError::Database)?;

        match row {
            None => return Err(TransferError::ConversationNotFound(convo_id.to_string())),
            Some((seq_ds, _epoch)) => {
                if let Some(ref ds) = seq_ds {
                    if canonical_did(ds) != canonical_did(from_sequencer_did) {
                        warn!(
                          convo_id,
                          claimed = from_sequencer_did,
                          actual = %ds,
                          "Transfer from non-sequencer DS"
                        );
                        return Err(TransferError::NotCurrentSequencer {
                            convo_id: convo_id.to_string(),
                            current_sequencer: ds.clone(),
                        });
                    }
                }
            }
        }

        sqlx::query("UPDATE conversations SET sequencer_ds = $2 WHERE id = $1")
            .bind(convo_id)
            .bind(&self.self_did)
            .execute(&self.pool)
            .await
            .map_err(TransferError::Database)?;

        info!(
            convo_id,
            from = from_sequencer_did,
            "Accepted sequencer transfer"
        );

        Ok(TransferResult::Accepted {
            convo_id: convo_id.to_string(),
        })
    }

    /// Forcefully assume the sequencer role for a conversation.
    ///
    /// Used during client-requested failover when the current sequencer
    /// is unreachable. Unlike `accept_transfer`, this does NOT require
    /// authorisation from the current sequencer, but does require:
    /// 1. Authorization: this DS must have active members in the conversation
    /// 2. CAS: the current sequencer must match `expected_sequencer` to prevent split-brain
    pub async fn assume_sequencer_role(
        &self,
        convo_id: &str,
        expected_sequencer: &str,
    ) -> Result<TransferResult, TransferError> {
        // 1. Verify conversation exists and get current state
        let row = sqlx::query_as::<_, (Option<String>, Option<i32>)>(
            "SELECT sequencer_ds, current_epoch FROM conversations WHERE id = $1",
        )
        .bind(convo_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(TransferError::Database)?;

        match row {
            None => return Err(TransferError::ConversationNotFound(convo_id.to_string())),
            Some((Some(ref ds), _)) if canonical_did(ds) == canonical_did(&self.self_did) => {
                return Ok(TransferResult::Accepted {
                    convo_id: convo_id.to_string(),
                });
            }
            _ => {}
        }

        // 2. Authorization: verify this DS has active members in the conversation
        let has_members: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM members WHERE convo_id = $1 AND left_at IS NULL AND COALESCE(split_part(ds_did, '#', 1), $2) = $2)",
        )
        .bind(convo_id)
        .bind(&self.self_did)
        .fetch_one(&self.pool)
        .await
        .map_err(TransferError::Database)?;

        if !has_members {
            return Err(TransferError::NotAuthorized {
                convo_id: convo_id.to_string(),
                ds_did: self.self_did.clone(),
            });
        }

        // 3. CAS: only take over if the sequencer is still who we expect
        let result = sqlx::query(
            "UPDATE conversations SET sequencer_ds = $2 WHERE id = $1 AND (sequencer_ds = $3 OR sequencer_ds IS NULL)",
        )
        .bind(convo_id)
        .bind(&self.self_did)
        .bind(expected_sequencer)
        .execute(&self.pool)
        .await
        .map_err(TransferError::Database)?;

        if result.rows_affected() == 0 {
            return Err(TransferError::NotCurrentSequencer {
                convo_id: convo_id.to_string(),
                current_sequencer: "unknown (changed during failover)".to_string(),
            });
        }

        warn!(
            convo_id,
            new_sequencer = %self.self_did,
            previous_sequencer = %expected_sequencer,
            "Assumed sequencer role via failover"
        );

        Ok(TransferResult::Accepted {
            convo_id: convo_id.to_string(),
        })
    }

    /// Pick a new sequencer from the conversation's members.
    /// Prefers the oldest admin, falling back to the oldest member.
    pub async fn pick_new_sequencer(
        &self,
        convo_id: &str,
    ) -> Result<Option<String>, TransferError> {
        let new_ds = sqlx::query_scalar::<_, Option<String>>(
            "SELECT COALESCE(split_part(ds_did, '#', 1), $2) FROM members \
       WHERE convo_id = $1 \
       ORDER BY is_admin DESC, joined_at ASC \
       LIMIT 1",
        )
        .bind(convo_id)
        .bind(&self.self_did)
        .fetch_optional(&self.pool)
        .await
        .map_err(TransferError::Database)?;

        Ok(new_ds.flatten())
    }
}

#[derive(Debug)]
pub enum TransferResult {
    Transferred {
        convo_id: String,
        new_sequencer_did: String,
    },
    Accepted {
        convo_id: String,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum TransferError {
    #[error("Conversation not found: {0}")]
    ConversationNotFound(String),

    #[error("Not the current sequencer for {convo_id} (current: {current_sequencer})")]
    NotCurrentSequencer {
        convo_id: String,
        current_sequencer: String,
    },

    #[error("Not authorized to assume sequencer for {convo_id} (ds: {ds_did})")]
    NotAuthorized { convo_id: String, ds_did: String },

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
}
