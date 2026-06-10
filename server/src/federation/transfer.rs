use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tracing::{info, warn};

use crate::identity::canonical_did;

const FAILOVER_MIN_STALE_SECS_ENV: &str = "FEDERATION_SEQUENCER_FAILOVER_MIN_STALE_SECS";
const FAILOVER_MIN_STALE_SECS_DEFAULT: u64 = 30;
const FAILOVER_MIN_STALE_SECS_MAX: u64 = 3_600;
const TRANSFER_MAX_TERM_JUMP_ENV: &str = "FEDERATION_SEQUENCER_TRANSFER_MAX_TERM_JUMP";
const TRANSFER_MAX_TERM_JUMP_DEFAULT: u64 = 8;
const TRANSFER_MAX_TERM_JUMP_MAX: u64 = 1_024;

#[derive(Debug, Clone, Copy)]
struct SequencerFailoverPolicy {
    min_failover_stale_secs: u64,
    max_transfer_term_jump: u64,
}

impl SequencerFailoverPolicy {
    fn from_env() -> Self {
        Self {
            min_failover_stale_secs: parse_u64_env_clamped(
                FAILOVER_MIN_STALE_SECS_ENV,
                FAILOVER_MIN_STALE_SECS_DEFAULT,
                0,
                FAILOVER_MIN_STALE_SECS_MAX,
            ),
            max_transfer_term_jump: parse_u64_env_clamped(
                TRANSFER_MAX_TERM_JUMP_ENV,
                TRANSFER_MAX_TERM_JUMP_DEFAULT,
                1,
                TRANSFER_MAX_TERM_JUMP_MAX,
            ),
        }
    }

    fn transfer_term_jump_allowed(&self, current_term: u64, requested_term: u64) -> bool {
        requested_term > current_term
            && requested_term - current_term <= self.max_transfer_term_jump
    }

    fn failover_lease_is_stale_enough(
        &self,
        lease_observed_at: &DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> bool {
        observed_lease_age_secs(lease_observed_at, now) >= self.min_failover_stale_secs
    }
}

fn parse_clamped_u64(raw: Option<&str>, default: u64, min: u64, max: u64) -> u64 {
    raw.and_then(|value| value.trim().parse::<u64>().ok())
        .map(|parsed| parsed.clamp(min, max))
        .unwrap_or(default)
}

fn parse_u64_env_clamped(name: &str, default: u64, min: u64, max: u64) -> u64 {
    let raw = std::env::var(name).ok();
    parse_clamped_u64(raw.as_deref(), default, min, max)
}

fn observed_lease_age_secs(lease_observed_at: &DateTime<Utc>, now: DateTime<Utc>) -> u64 {
    (now - *lease_observed_at).num_seconds().max(0) as u64
}

/// Handles sequencer role transfer between DSes.
pub struct SequencerTransfer {
    pool: PgPool,
    self_did: String,
    failover_policy: SequencerFailoverPolicy,
}

impl SequencerTransfer {
    pub fn new(pool: PgPool, self_did: String) -> Self {
        Self {
            pool,
            self_did,
            failover_policy: SequencerFailoverPolicy::from_env(),
        }
    }

    /// Initiate a sequencer transfer to a new DS.
    ///
    /// Updates the local DB. The actual handoff (notifying the new
    /// sequencer) is handled by the caller via an outbound call.
    ///
    /// MIMI-inspired handoff invariant: every accepted transfer increments
    /// `sequencer_term`, and a `(convo_id, term)` pair has exactly one
    /// sequencer DS owner.
    pub async fn initiate_transfer(
        &self,
        convo_id: &str,
        new_sequencer_did: &str,
    ) -> Result<TransferResult, TransferError> {
        let current = sqlx::query_as::<_, (Option<String>, Option<i64>)>(
            "SELECT sequencer_ds, sequencer_term FROM conversations WHERE id = $1",
        )
        .bind(convo_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(TransferError::Database)?;

        match current.as_ref() {
            None => return Err(TransferError::ConversationNotFound(convo_id.to_string())),
            Some((Some(ds), _)) if canonical_did(ds) != canonical_did(&self.self_did) => {
                return Err(TransferError::NotCurrentSequencer {
                    convo_id: convo_id.to_string(),
                    current_sequencer: ds.clone(),
                });
            }
            _ => {} // NULL or our DID — we are the sequencer
        }
        let current_term = current
            .as_ref()
            .and_then(|(_, term)| *term)
            .unwrap_or(0)
            .max(0) as u64;
        let new_sequencer_term = current_term + 1;

        sqlx::query(
            "UPDATE conversations SET sequencer_ds = $2, sequencer_term = $3, updated_at = NOW() \
             WHERE id = $1",
        )
        .bind(convo_id)
        .bind(new_sequencer_did)
        .bind(new_sequencer_term as i64)
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
            new_sequencer_term,
        })
    }

    /// Accept a sequencer transfer (we are the NEW sequencer).
    pub async fn accept_transfer(
        &self,
        convo_id: &str,
        from_sequencer_did: &str,
        new_sequencer_term: u64,
    ) -> Result<TransferResult, TransferError> {
        let row = sqlx::query_as::<_, (Option<String>, Option<i32>, Option<i64>)>(
            "SELECT sequencer_ds, current_epoch, sequencer_term FROM conversations \
       WHERE id = $1",
        )
        .bind(convo_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(TransferError::Database)?;

        match row {
            None => Err(TransferError::ConversationNotFound(convo_id.to_string())),
            Some((seq_ds, _epoch, current_term_raw)) => {
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
                let current_term = current_term_raw.unwrap_or(0).max(0) as u64;
                if new_sequencer_term <= current_term {
                    return Err(TransferError::TermStale {
                        convo_id: convo_id.to_string(),
                        current_term,
                        requested_term: new_sequencer_term,
                    });
                }
                if !self
                    .failover_policy
                    .transfer_term_jump_allowed(current_term, new_sequencer_term)
                {
                    return Err(TransferError::TermJumpTooLarge {
                        convo_id: convo_id.to_string(),
                        current_term,
                        requested_term: new_sequencer_term,
                        max_jump: self.failover_policy.max_transfer_term_jump,
                    });
                }

                let observed_sequencer = seq_ds.as_deref().map(canonical_did);
                let updated: Option<(i32, i64)> = sqlx::query_as(
                    "UPDATE conversations \
                     SET sequencer_ds = $2, sequencer_term = $3, updated_at = NOW() \
                     WHERE id = $1 \
                       AND COALESCE(sequencer_term, 0) = $4 \
                       AND ( \
                            ($5::text IS NULL AND sequencer_ds IS NULL) \
                         OR split_part(sequencer_ds, '#', 1) = $5 \
                       ) \
                     RETURNING current_epoch, sequencer_term",
                )
                .bind(convo_id)
                .bind(&self.self_did)
                .bind(new_sequencer_term as i64)
                .bind(current_term as i64)
                .bind(observed_sequencer)
                .fetch_optional(&self.pool)
                .await
                .map_err(TransferError::Database)?;

                let Some((new_epoch, new_term_raw)) = updated else {
                    return Err(TransferError::NotCurrentSequencer {
                        convo_id: convo_id.to_string(),
                        current_sequencer: "unknown (changed during transfer)".to_string(),
                    });
                };

                info!(
                    convo_id,
                    from = from_sequencer_did,
                    new_sequencer_term,
                    "Accepted sequencer transfer"
                );

                Ok(TransferResult::Accepted {
                    convo_id: convo_id.to_string(),
                    new_epoch,
                    new_sequencer_term: new_term_raw.max(0) as u64,
                })
            }
        }
    }

    /// Forcefully assume the sequencer role for a conversation.
    ///
    /// Used during client-requested failover when the current sequencer
    /// is unreachable. Unlike `accept_transfer`, this does NOT require
    /// authorisation from the current sequencer, but does require:
    /// 1. Authorization: this DS must have active members in the conversation
    /// 2. CAS: the current sequencer must match `expected_sequencer` to prevent split-brain
    /// 3. Lease staleness: local lease observation must be stale enough before takeover
    ///
    /// MIMI-inspired failover invariant: takeover fences old writers by
    /// incrementing both `current_epoch` and `sequencer_term` in one CAS step.
    pub async fn assume_sequencer_role(
        &self,
        convo_id: &str,
        expected_sequencer: &str,
    ) -> Result<TransferResult, TransferError> {
        // 1. Verify conversation exists and get current state
        let row = sqlx::query_as::<_, (Option<String>, Option<i32>, Option<i64>, DateTime<Utc>)>(
            "SELECT sequencer_ds, current_epoch, sequencer_term, updated_at FROM conversations WHERE id = $1",
        )
        .bind(convo_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(TransferError::Database)?;

        let expected_term = row
            .as_ref()
            .and_then(|(_, _, term, _)| *term)
            .unwrap_or(0)
            .max(0) as u64;

        match row.as_ref() {
            None => return Err(TransferError::ConversationNotFound(convo_id.to_string())),
            Some((Some(ds), current_epoch, current_term_raw, _))
                if canonical_did(ds) == canonical_did(&self.self_did) =>
            {
                return Ok(TransferResult::Accepted {
                    convo_id: convo_id.to_string(),
                    new_epoch: current_epoch.as_ref().copied().unwrap_or(0),
                    new_sequencer_term: current_term_raw.as_ref().copied().unwrap_or(0).max(0)
                        as u64,
                });
            }
            _ => {}
        }

        let now = Utc::now();
        let lease_observed_at = row
            .as_ref()
            .map(|(_, _, _, updated_at)| *updated_at)
            .expect("conversation existence checked above");
        let observed_age_secs = observed_lease_age_secs(&lease_observed_at, now);
        if !self
            .failover_policy
            .failover_lease_is_stale_enough(&lease_observed_at, now)
        {
            return Err(TransferError::LeaseStillActive {
                convo_id: convo_id.to_string(),
                observed_age_secs,
                required_age_secs: self.failover_policy.min_failover_stale_secs,
            });
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

        // 3. CAS: only take over if the sequencer is still who we expect.
        //
        // `current_epoch` MUST NOT advance here. Bumping it without also
        // writing a commit row (to `messages` and `commits`) orphans the MLS
        // epoch: clients learn about the advance via SSE/GroupInfo but cannot
        // fetch a commit to catch their local MLS state up to it. Fencing is
        // handled by `sequencer_term` alone — the CAS below already rejects
        // concurrent takeovers. Epoch advances must only ever originate from
        // an actual MLS commit landing in `submit_commit` / `commit_group_change`.
        let updated: Option<(i32, i64)> = sqlx::query_as(
            "UPDATE conversations \
             SET sequencer_ds = $2, sequencer_term = sequencer_term + 1, updated_at = NOW() \
             WHERE id = $1 AND (sequencer_ds = $3 OR sequencer_ds IS NULL) AND sequencer_term = $4 \
             RETURNING current_epoch, sequencer_term",
        )
        .bind(convo_id)
        .bind(&self.self_did)
        .bind(expected_sequencer)
        .bind(expected_term as i64)
        .fetch_optional(&self.pool)
        .await
        .map_err(TransferError::Database)?;

        let Some((new_epoch, new_term_raw)) = updated else {
            return Err(TransferError::NotCurrentSequencer {
                convo_id: convo_id.to_string(),
                current_sequencer: "unknown (changed during failover)".to_string(),
            });
        };
        let new_sequencer_term = new_term_raw.max(0) as u64;

        warn!(
            convo_id,
            new_sequencer = %self.self_did,
            previous_sequencer = %expected_sequencer,
            new_epoch,
            new_sequencer_term,
            "Assumed sequencer role via failover"
        );

        Ok(TransferResult::Accepted {
            convo_id: convo_id.to_string(),
            new_epoch,
            new_sequencer_term,
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
        new_sequencer_term: u64,
    },
    Accepted {
        convo_id: String,
        new_epoch: i32,
        new_sequencer_term: u64,
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

    #[error(
        "Stale transfer term for {convo_id}: requested {requested_term}, current {current_term}"
    )]
    TermStale {
        convo_id: String,
        current_term: u64,
        requested_term: u64,
    },

    #[error(
        "Invalid transfer term jump for {convo_id}: requested {requested_term}, current {current_term}, max jump {max_jump}"
    )]
    TermJumpTooLarge {
        convo_id: String,
        current_term: u64,
        requested_term: u64,
        max_jump: u64,
    },

    #[error(
        "Sequencer lease still active for {convo_id}: observed age {observed_age_secs}s, required at least {required_age_secs}s"
    )]
    LeaseStillActive {
        convo_id: String,
        observed_age_secs: u64,
        required_age_secs: u64,
    },

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
}

#[cfg(test)]
mod tests {
    use super::{observed_lease_age_secs, parse_clamped_u64, SequencerFailoverPolicy};
    use chrono::{Duration, Utc};

    #[test]
    fn parse_clamped_u64_defaults_for_missing_or_invalid_values() {
        assert_eq!(parse_clamped_u64(None, 30, 0, 60), 30);
        assert_eq!(parse_clamped_u64(Some("invalid"), 30, 0, 60), 30);
    }

    #[test]
    fn parse_clamped_u64_clamps_to_bounds() {
        assert_eq!(parse_clamped_u64(Some("2"), 30, 5, 60), 5);
        assert_eq!(parse_clamped_u64(Some("120"), 30, 5, 60), 60);
        assert_eq!(parse_clamped_u64(Some("25"), 30, 5, 60), 25);
    }

    #[test]
    fn policy_enforces_transfer_term_jump_and_lease_staleness() {
        let policy = SequencerFailoverPolicy {
            min_failover_stale_secs: 30,
            max_transfer_term_jump: 3,
        };

        assert!(policy.transfer_term_jump_allowed(10, 11));
        assert!(policy.transfer_term_jump_allowed(10, 13));
        assert!(!policy.transfer_term_jump_allowed(10, 14));

        let now = Utc::now();
        let fresh = now - Duration::seconds(10);
        let stale = now - Duration::seconds(30);
        assert!(!policy.failover_lease_is_stale_enough(&fresh, now));
        assert!(policy.failover_lease_is_stale_enough(&stale, now));
        assert_eq!(observed_lease_age_secs(&fresh, now), 10);
    }
}
