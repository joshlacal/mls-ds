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
        let convo_uuid = uuid::Uuid::parse_str(convo_id)
            .map_err(|_| TransferError::ConversationNotFound(convo_id.to_string()))?;
        let current = sqlx::query_as::<_, (bool, Option<String>, i64)>(
            "SELECT is_remote, sequencer_ds, sequencer_term FROM chat.conversations WHERE conversation_id = $1",
        )
        .bind(convo_uuid)
        .fetch_optional(&self.pool)
        .await
        .map_err(TransferError::Database)?;

        let (was_remote, observed_sequencer, current_term_i64) = match current {
            None => return Err(TransferError::ConversationNotFound(convo_id.to_string())),
            Some((true, Some(ds), _)) if canonical_did(&ds) != canonical_did(&self.self_did) => {
                return Err(TransferError::NotCurrentSequencer {
                    convo_id: convo_id.to_string(),
                    current_sequencer: ds,
                });
            }
            Some(row) => row,
        };
        let current_term = current_term_i64.max(0) as u64;
        let new_sequencer_term = current_term + 1;
        let canonical_new = canonical_did(new_sequencer_did).to_string();
        let (next_is_remote, next_sequencer_ds): (bool, Option<String>) =
            if canonical_new == canonical_did(&self.self_did) {
                (false, None)
            } else {
                (true, Some(canonical_new.clone()))
            };

        let updated: Option<i64> = sqlx::query_scalar(
            "UPDATE chat.conversations \
             SET is_remote = $2, sequencer_ds = $3, sequencer_term = $4 \
             WHERE conversation_id = $1 \
               AND sequencer_term = $5 \
               AND is_remote = $6 \
               AND sequencer_ds IS NOT DISTINCT FROM $7 \
             RETURNING sequencer_term",
        )
        .bind(convo_uuid)
        .bind(next_is_remote)
        .bind(next_sequencer_ds)
        .bind(new_sequencer_term as i64)
        .bind(current_term as i64)
        .bind(was_remote)
        .bind(observed_sequencer)
        .fetch_optional(&self.pool)
        .await
        .map_err(TransferError::Database)?;

        let Some(new_term_raw) = updated else {
            warn!(
                convo_id,
                new_sequencer = new_sequencer_did,
                expected_term = current_term,
                "Sequencer transfer initiation lost CAS race; owner/term changed concurrently"
            );
            return Err(TransferError::NotCurrentSequencer {
                convo_id: convo_id.to_string(),
                current_sequencer: "unknown (changed during transfer)".to_string(),
            });
        };

        info!(
            convo_id,
            new_sequencer = new_sequencer_did,
            "Sequencer transfer initiated"
        );

        Ok(TransferResult::Transferred {
            convo_id: convo_id.to_string(),
            new_sequencer_did: canonical_new,
            new_sequencer_term: new_term_raw.max(0) as u64,
        })
    }

    /// Accept a sequencer transfer (we are the NEW sequencer).
    pub async fn accept_transfer(
        &self,
        convo_id: &str,
        from_sequencer_did: &str,
        new_sequencer_term: u64,
    ) -> Result<TransferResult, TransferError> {
        let convo_uuid = uuid::Uuid::parse_str(convo_id)
            .map_err(|_| TransferError::ConversationNotFound(convo_id.to_string()))?;
        let row = sqlx::query_as::<_, (bool, Option<String>, i64, i64)>(
            "SELECT is_remote, sequencer_ds, current_generation, sequencer_term \
             FROM chat.conversations WHERE conversation_id = $1",
        )
        .bind(convo_uuid)
        .fetch_optional(&self.pool)
        .await
        .map_err(TransferError::Database)?;

        match row {
            None => Err(TransferError::ConversationNotFound(convo_id.to_string())),
            Some((was_remote, seq_ds, _epoch, current_term_raw)) => {
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
                let current_term = current_term_raw.max(0) as u64;
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

                let updated: Option<(i64, i64)> = sqlx::query_as(
                    "UPDATE chat.conversations \
                     SET is_remote = FALSE, sequencer_ds = NULL, sequencer_term = $2 \
                     WHERE conversation_id = $1 \
                       AND sequencer_term = $3 \
                       AND is_remote = $4 \
                       AND sequencer_ds IS NOT DISTINCT FROM $5 \
                     RETURNING current_generation, sequencer_term",
                )
                .bind(convo_uuid)
                .bind(new_sequencer_term as i64)
                .bind(current_term as i64)
                .bind(was_remote)
                .bind(seq_ds)
                .fetch_optional(&self.pool)
                .await
                .map_err(TransferError::Database)?;

                let Some((new_epoch_i64, new_term_raw)) = updated else {
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
                    new_epoch: i32::try_from(new_epoch_i64).unwrap_or(i32::MAX),
                    new_sequencer_term: new_term_raw.max(0) as u64,
                })
            }
        }
    }

    /// Forcefully assume the sequencer role for a conversation.
    pub async fn assume_sequencer_role(
        &self,
        convo_id: &str,
        expected_sequencer: &str,
    ) -> Result<TransferResult, TransferError> {
        let convo_uuid = uuid::Uuid::parse_str(convo_id)
            .map_err(|_| TransferError::ConversationNotFound(convo_id.to_string()))?;
        let row = sqlx::query_as::<_, (bool, Option<String>, i64, i64, DateTime<Utc>)>(
            "SELECT c.is_remote, c.sequencer_ds, c.current_generation, c.sequencer_term, \
                    COALESCE((SELECT MAX(s.updated_at) FROM federation_sync_state s WHERE s.convo_id = $2), c.created_at) \
               FROM chat.conversations c WHERE c.conversation_id = $1",
        )
        .bind(convo_uuid)
        .bind(convo_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(TransferError::Database)?;

        let Some((was_remote, seq_ds, current_epoch_i64, current_term_raw, lease_observed_at)) =
            row
        else {
            return Err(TransferError::ConversationNotFound(convo_id.to_string()));
        };

        if !was_remote
            || seq_ds
                .as_deref()
                .is_some_and(|ds| canonical_did(ds) == canonical_did(&self.self_did))
        {
            return Ok(TransferResult::Accepted {
                convo_id: convo_id.to_string(),
                new_epoch: i32::try_from(current_epoch_i64).unwrap_or(0),
                new_sequencer_term: current_term_raw.max(0) as u64,
            });
        }

        let expected_term = current_term_raw.max(0) as u64;
        let now = Utc::now();
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

        let canonical_self = canonical_did(&self.self_did).to_string();
        let has_members: bool = sqlx::query_scalar(
            "SELECT EXISTS( \
               SELECT 1 FROM chat.participants \
               WHERE conversation_id = $1 \
                 AND current_membership = TRUE \
                 AND status = 'active' \
                 AND COALESCE(ds_did, $2) = $2 \
             )",
        )
        .bind(convo_uuid)
        .bind(&canonical_self)
        .fetch_one(&self.pool)
        .await
        .map_err(TransferError::Database)?;

        if !has_members {
            return Err(TransferError::NotAuthorized {
                convo_id: convo_id.to_string(),
                ds_did: self.self_did.clone(),
            });
        }

        let canonical_expected = canonical_did(expected_sequencer);
        let updated: Option<(i64, i64)> = sqlx::query_as(
            "UPDATE chat.conversations \
             SET is_remote = FALSE, sequencer_ds = NULL, sequencer_term = sequencer_term + 1 \
             WHERE conversation_id = $1 AND is_remote = TRUE AND sequencer_ds = $2 AND sequencer_term = $3 \
             RETURNING current_generation, sequencer_term",
        )
        .bind(convo_uuid)
        .bind(canonical_expected)
        .bind(expected_term as i64)
        .fetch_optional(&self.pool)
        .await
        .map_err(TransferError::Database)?;

        let Some((new_epoch_i64, new_term_raw)) = updated else {
            return Err(TransferError::NotCurrentSequencer {
                convo_id: convo_id.to_string(),
                current_sequencer: "unknown (changed during failover)".to_string(),
            });
        };
        let new_epoch = i32::try_from(new_epoch_i64).unwrap_or(i32::MAX);
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

    /// Pick a new sequencer from the conversation's active participants.
    pub async fn pick_new_sequencer(
        &self,
        convo_id: &str,
    ) -> Result<Option<String>, TransferError> {
        let convo_uuid = uuid::Uuid::parse_str(convo_id)
            .map_err(|_| TransferError::ConversationNotFound(convo_id.to_string()))?;
        let canonical_self = canonical_did(&self.self_did).to_string();
        let new_ds = sqlx::query_scalar::<_, Option<String>>(
            "SELECT COALESCE(ds_did, $2) FROM chat.participants \
             WHERE conversation_id = $1 AND current_membership = TRUE AND status = 'active' \
             ORDER BY (role = 'admin') DESC, created_at ASC \
             LIMIT 1",
        )
        .bind(convo_uuid)
        .bind(&canonical_self)
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

/// A mirror records the send order of every application entry it replicates,
/// so after it takes over sequencing it still refuses a device's held send
/// that its replicated history already passed (seed 2323).
#[cfg(all(test, feature = "test-support", feature = "sim"))]
mod send_order_tests {
    use super::{SequencerTransfer, TransferResult};
    use crate::chat_protocol::{
        repository::{
            delivery::{
                resolve_application_send, AppendEntry, ApplicationSend, ApplicationSendDisposition,
                ApplicationSendOutcome, APPLICATION_ENTRY_KIND,
            },
            federation::deliver_message_replication,
        },
        test_support::seed_remote_clean_slate_application_fixture,
        transcript::{build_verified_application_entry, decode_and_verify_signed_mutation},
        validation::{CanonicalTimestamp, CanonicalUuidV4, TrustedRequestInstant},
    };
    use crate::federation::{
        ack::AckSigner,
        envelope::{
            compute_message_envelope_digest, ValidatedEntryLocator, ValidatedEnvelopeHeader,
        },
    };
    use serde_json::Value;
    use sqlx::PgPool;
    use std::sync::Arc;
    use uuid::Uuid;

    const SEQ: &str = "did:web:transfer-sequencer.example.com";
    const HOME: &str = "did:web:transfer-home.example.com";

    /// `request` as a sequencer accepts it at `seq`.
    fn sequenced(
        request: &Value,
        public_key: &[u8],
        conversation_id: Uuid,
        seq: u64,
    ) -> ApplicationSend {
        let signed_request_bytes = serde_json::to_vec(request).unwrap();
        let verified =
            decode_and_verify_signed_mutation(&signed_request_bytes, public_key).unwrap();
        let entry_id = Uuid::new_v4();
        let instant = TrustedRequestInstant::from_datetime(chrono::Utc::now()).unwrap();
        let product = build_verified_application_entry(
            verified,
            CanonicalUuidV4::parse(&entry_id.to_string()).unwrap(),
            CanonicalUuidV4::parse(&conversation_id.to_string()).unwrap(),
            seq,
            &instant,
        )
        .unwrap();
        let body = &request["body"];
        let integer = |pointer: &str| body.pointer(pointer).and_then(Value::as_i64).unwrap();
        let uuid = |field: &str| Uuid::parse_str(body[field].as_str().unwrap()).unwrap();
        ApplicationSend {
            entry: AppendEntry {
                conversation_id,
                entry_id,
                entry_kind: APPLICATION_ENTRY_KIND.to_owned(),
                accepted_payload_bytes: product.canonical_entry_bytes().to_vec(),
                accepted_payload_sha256: product.accepted_payload_sha256().to_vec(),
                signed_request_bytes,
                request_digest: product.mutation().request_digest().to_vec(),
                signature: product.mutation().signature().to_vec(),
                server_fields_bytes: serde_ipld_dagcbor::to_vec(&std::collections::BTreeMap::<
                    String,
                    String,
                >::new())
                .unwrap(),
                outer_entry_fingerprint: product.outer_application_fingerprint().to_vec(),
                actor_did: body["actorDid"].as_str().unwrap().to_owned(),
                actor_device_id: uuid("actorDeviceId"),
                actor_key_id: body["keyId"].as_str().unwrap().to_owned(),
                actor_auth_generation: integer("/authGeneration"),
                generation: Some(integer("/prior/generation")),
                state_version: Some(integer("/prior/stateVersion")),
                transition_id: None,
                message_id: Some(uuid("messageId")),
                received_at: instant.datetime(),
            },
            signing_transcript_bytes: product.mutation().transcript_bytes().to_vec(),
            outcome_bytes: b"{}".to_vec(),
            epoch: integer("/prior/epoch"),
            send_counter: integer("/sendCounter"),
        }
    }

    async fn resolve(pool: &PgPool, send: &ApplicationSend) -> ApplicationSendOutcome {
        let mut tx = pool.begin().await.unwrap();
        let outcome = resolve_application_send(&mut tx, send, ApplicationSendDisposition::Accept)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        outcome
    }

    /// `(next_entry_seq, message_sends rows, every device's send order)`.
    async fn state(pool: &PgPool, conversation_id: Uuid) -> (i64, i64, Vec<(Uuid, i64, i64, i64)>) {
        let (next_entry_seq, sends): (i64, i64) = sqlx::query_as(
            "SELECT c.next_entry_seq, \
                    (SELECT count(*) FROM chat.message_sends s \
                      WHERE s.conversation_id = c.conversation_id) \
               FROM chat.conversations c WHERE c.conversation_id = $1",
        )
        .bind(conversation_id)
        .fetch_one(pool)
        .await
        .unwrap();
        let order = sqlx::query_as(
            "SELECT actor_device_id, generation, epoch, last_send_counter \
               FROM chat.application_send_order WHERE conversation_id = $1 \
              ORDER BY actor_device_id",
        )
        .bind(conversation_id)
        .fetch_all(pool)
        .await
        .unwrap();
        (next_entry_seq, sends, order)
    }

    #[tokio::test]
    async fn a_mirror_that_takes_over_sequencing_refuses_sends_its_replicated_history_passed() {
        takeover_refuses_sends_the_replicated_history_passed(false).await;
    }

    /// MLS-R3-01: the same mirror, populated before migration `20261107000001`.
    /// That migration adds only the send-order table, so dropping it leaves the
    /// prior schema with this history; the upgrade must backfill the order.
    #[tokio::test]
    async fn a_mirror_populated_before_the_send_order_upgrade_refuses_sends_its_history_passed() {
        takeover_refuses_sends_the_replicated_history_passed(true).await;
    }

    async fn takeover_refuses_sends_the_replicated_history_passed(populated_before_upgrade: bool) {
        let db = crate::common::fresh_db::fresh_fully_migrated_db("chat_transfer_").await;
        let pool = db.connect(4).await;
        crate::common::http_acceptance::ensure_fence(&pool).await;
        let hooks = Arc::new(crate::sim_hooks::SimDsHooks {
            service_did: HOME.to_owned(),
            self_endpoint: "https://transfer-home.example.com".to_owned(),
            signing_key_pem: None,
            group_relay_hmac_secret: None,
            http_transport: Arc::new(|_| Box::pin(async { Err("no network here".to_owned()) })),
            dns_resolver: Arc::new(|_| Err("no DNS here".to_owned())),
            retain_application_ciphertext: false,
        });
        crate::sim_hooks::scope_sim_ds(hooks, async {
            // HOME mirrors SEQ's group; D (sender) and E (recipient) are members.
            let fixture =
                seed_remote_clean_slate_application_fixture(&pool, HOME, SEQ, Some([0x5a; 32]))
                    .await
                    .unwrap();
            let cid = fixture.conversation_id;
            let key = |seed: &[u8; 32]| {
                ed25519_dalek::SigningKey::from_bytes(seed)
                    .verifying_key()
                    .to_bytes()
            };
            let (sender_key, recipient_key) = (
                key(&fixture.sender_ed25519_seed),
                key(&fixture.recipient_ed25519_seed),
            );
            // D's sends, sendCounter 1..=4.
            let mut requests = vec![fixture.signed_request.clone()];
            requests.extend((0..3).map(|_| fixture.next_sender_signed_request()));
            let term: i64 = sqlx::query_scalar(
                "SELECT sequencer_term FROM chat.conversations WHERE conversation_id = $1",
            )
            .bind(cid)
            .fetch_one(&pool)
            .await
            .unwrap();

            // SEQ sequenced counters 1..=3 at seqs 4..=6 and replicated them here.
            let ack = AckSigner::new(
                p256::ecdsa::SigningKey::from_slice(&[0x41; 32]).unwrap(),
                HOME.to_owned(),
            );
            for (seq, request) in (4..).zip(&requests[..3]) {
                let send = sequenced(request, &sender_key, cid, seq);
                let locator = ValidatedEntryLocator {
                    entry_id: send.entry.entry_id,
                    seq,
                    accepted_payload_sha256: send.entry.accepted_payload_sha256[..]
                        .try_into()
                        .unwrap(),
                    outer_entry_fingerprint: send.entry.outer_entry_fingerprint[..]
                        .try_into()
                        .unwrap(),
                };
                let mut header = ValidatedEnvelopeHeader {
                    protocol_version: "1".to_owned(),
                    delivery_id: Uuid::new_v4(),
                    conversation_id: cid,
                    sender_ds_did: SEQ.to_owned(),
                    receiver_ds_did: HOME.to_owned(),
                    sequencer_did: SEQ.to_owned(),
                    sequencer_term: term as u64,
                    received_at: CanonicalTimestamp::parse(&chrono::Utc::now().to_rfc3339_opts(
                        chrono::SecondsFormat::Millis,
                        true,
                    ))
                    .unwrap(),
                    payload_sha256: [0; 32],
                };
                header.payload_sha256 = compute_message_envelope_digest(
                    &header,
                    &fixture.recipient_did,
                    &locator,
                    &send.entry.accepted_payload_bytes,
                    &send.entry.signed_request_bytes,
                )
                .unwrap();
                let mut tx = pool.begin().await.unwrap();
                deliver_message_replication(
                    &mut tx,
                    &ack,
                    header,
                    fixture.recipient_did.clone(),
                    locator,
                    send.entry.accepted_payload_bytes.clone(),
                    send.entry.signed_request_bytes.clone(),
                )
                .await
                .unwrap();
                tx.commit().await.unwrap();
            }
            if populated_before_upgrade {
                sqlx::query("DROP TABLE chat.application_send_order")
                    .execute(&pool)
                    .await
                    .unwrap();
                sqlx::raw_sql(include_str!(
                    "../../migrations/20261107000001_application_send_order.sql"
                ))
                .execute(&pool)
                .await
                .unwrap();
            }
            let fourth = sequenced(&requests[3], &sender_key, cid, 7);
            let (generation, epoch) = (fourth.entry.generation.unwrap(), fourth.epoch);
            let replicated = (7, 3, vec![(fixture.sender_device_id, generation, epoch, 3)]);
            assert_eq!(state(&pool, cid).await, replicated);

            // SEQ goes silent and HOME assumes its role.
            sqlx::query(
                "INSERT INTO federation_sync_state(convo_id, sequencer_ds_did, sequencer_term, updated_at) \
                 VALUES ($1, $2, $3, now() - interval '1 hour')",
            )
            .bind(cid.to_string())
            .bind(SEQ)
            .bind(term)
            .execute(&pool)
            .await
            .unwrap();
            let assumed = SequencerTransfer::new(pool.clone(), HOME.to_owned())
                .assume_sequencer_role(&cid.to_string(), SEQ)
                .await
                .unwrap();
            assert!(matches!(assumed, TransferResult::Accepted { .. }));

            // D's held sends, at counters its replicated history passed, under
            // new message ids: refused, nothing written.
            for counter in [2, 3] {
                let mut held = fourth.clone();
                held.entry.entry_id = Uuid::new_v4();
                held.entry.message_id = Some(Uuid::new_v4());
                held.send_counter = counter;
                assert_eq!(
                    resolve(&pool, &held).await,
                    ApplicationSendOutcome::StaleSend
                );
                assert_eq!(state(&pool, cid).await, replicated);
            }
            // SEQ's exact counter-3 send replays the seq it was sequenced at.
            let third = sequenced(&requests[2], &sender_key, cid, 6);
            assert_eq!(
                resolve(&pool, &third).await,
                ApplicationSendOutcome::Accepted { seq: 6 }
            );
            assert_eq!(state(&pool, cid).await, replicated);
            assert_eq!(
                resolve(&pool, &fourth).await,
                ApplicationSendOutcome::Accepted { seq: 7 }
            );
            // E's first send is ordered on its own.
            let other = sequenced(&fixture.next_recipient_signed_request(), &recipient_key, cid, 8);
            assert_eq!(
                resolve(&pool, &other).await,
                ApplicationSendOutcome::Accepted { seq: 8 }
            );
            let mut order = vec![
                (fixture.sender_device_id, generation, epoch, 4),
                (fixture.recipient_device_id, generation, epoch, 1),
            ];
            order.sort();
            assert_eq!(state(&pool, cid).await, (9, 5, order));
        })
        .await;
    }
}
