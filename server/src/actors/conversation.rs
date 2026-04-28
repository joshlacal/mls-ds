use async_trait::async_trait;
use ractor::{Actor, ActorProcessingErr, ActorRef};
use sqlx::PgPool;
use std::{collections::HashMap, sync::Arc};
use tracing::{debug, error, info, warn};

use super::broadcaster::BroadcasterPool;
use super::messages::{
    ConvoMessage, KeyPackageHashEntry, RecordResetVoteOutcome, ResetRequest, ResetTrigger,
    WelcomeEnvelope,
};
use crate::config::QuorumConfig;
use crate::notifications::NotificationService;
use crate::realtime::{SseState, StreamEvent, StreamMessageView};
use tokio::sync::mpsc;

/// Service DID used as `last_reset_by` for system-initiated auto-resets
/// (Path A quorum + Path B sweep). Read from `SERVICE_DID` env once at first
/// access and cached; the fragment (`#atproto_mls`) is stripped because the
/// `groupResetEvent.resetBy` lexicon field is typed `format: "did"` and the
/// Petrel Swift validator rejects DIDs with fragments.
///
/// Phase 2 B6: previously these paths emitted `"system:server_sweep"` /
/// `"system:client_quorum"` here, which iOS rejected as `invalidURI` —
/// the WS handler treated the decode failure as a connection error and
/// reconnected, causing an infinite replay loop where the convo never
/// transitioned out of its broken state despite the server-side reset
/// completing successfully. The reason field already carries the
/// "sweep" vs "quorum" discriminator for ops audit.
fn system_reset_did() -> &'static str {
    static DID: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    DID.get_or_init(|| {
        let raw = std::env::var("SERVICE_DID")
            .unwrap_or_else(|_| "did:web:mlschat.catbird.blue".to_string());
        // Strip `#fragment` — DID format validation in clients is stricter
        // than the AT Protocol spec; safest is to emit a base DID.
        raw.split('#').next().unwrap_or(&raw).to_string()
    })
}

/// Phase 2.5 §7 R2 mitigation: per-incident kill switch for the
/// `subscribeEvents#resetRequestedEvent` SSE broadcast emitted by
/// `dual_emit_reset_requested`.
///
/// Reads the `EMIT_RESET_REQUESTED_EVENT` env var ONCE at first
/// invocation and caches the result for the process lifetime
/// (review-fix G4: avoid the per-call `std::env::var` allocation +
/// locking on every reset event). Default `true`; flip to `false` or
/// `0` and restart the service to suppress the SSE broadcast for an
/// incident.
///
/// The chokepoint Request still persists regardless — only the SSE
/// fan-out is gated. See `server/CLAUDE.md` for the operator runbook.
fn emit_reset_requested_event() -> bool {
    static FLAG: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *FLAG.get_or_init(|| {
        std::env::var("EMIT_RESET_REQUESTED_EVENT")
            .map(|v| !matches!(v.as_str(), "false" | "0"))
            .unwrap_or(true)
    })
}

/// Manages state for a single conversation, ensuring sequential processing
/// of all epoch-modifying operations to prevent race conditions.
///
/// Each `ConversationActor` owns:
/// - Current epoch counter (synchronized with database)
/// - Unread counts for all members (with periodic database sync)
/// - Database connection pool for persistence
///
/// # Concurrency Safety
///
/// All messages are processed sequentially through the actor's mailbox,
/// preventing race conditions that could occur with direct database access.
/// This ensures that operations like adding/removing members, sending messages,
/// and incrementing the epoch are atomic and ordered.
///
/// # Actor Lifecycle
///
/// - **Spawn**: Actors are spawned on-demand via [`ActorRegistry::get_or_spawn`]
/// - **Pre-start**: Loads initial epoch from database
/// - **Message Processing**: Handles [`ConvoMessage`] variants sequentially
/// - **Shutdown**: Gracefully stops on [`ConvoMessage::Shutdown`]
///
/// # Examples
///
/// ```no_run
/// use tokio::sync::oneshot;
///
/// # async fn example(registry: &ActorRegistry) -> anyhow::Result<()> {
/// let actor_ref = registry.get_or_spawn("conv_123").await?;
/// let (tx, rx) = oneshot::channel();
/// actor_ref.send_message(ConvoMessage::GetEpoch { reply: tx })?;
/// let epoch = rx.await?;
/// # Ok(())
/// # }
/// ```
///
/// [`ActorRegistry::get_or_spawn`]: super::registry::ActorRegistry::get_or_spawn
pub struct ConversationActor;

/// Arguments for spawning a new [`ConversationActor`].
///
/// These arguments are passed to the actor during initialization in the
/// [`Actor::pre_start`] method, where they are used to construct the
/// initial [`ConversationActorState`].
///
/// # Fields
///
/// - `convo_id`: Unique identifier for the conversation
/// - `db_pool`: Database connection pool for persistent operations
/// - `sse_state`: SSE state for real-time event broadcasting
#[derive(Clone)]
pub struct ConvoActorArgs {
    pub convo_id: String,
    pub db_pool: PgPool,
    pub sse_state: Arc<SseState>,
    pub notification_service: Option<Arc<NotificationService>>,
    /// ADR-008 D1 (Phase 2): per-actor copy of the quorum knobs so tests can
    /// inject overrides without racing on process-global env vars. Production
    /// callers (registry/supervisor) populate via `QuorumConfig::from_env`.
    pub quorum_config: QuorumConfig,
}

/// Represents a background job to be processed sequentially by the actor's worker.
#[derive(Debug)]
enum SideEffectJob {
    /// Fan-out a new message to all members (envelopes + SSE + Push)
    NotifyNewMessage {
        msg_id: String,
        sender_did: String,
        ciphertext: Vec<u8>,
        seq: i64,
        epoch: i64,
        is_ephemeral: bool,
    },
    /// Fan-out a system message (commit) to all members (envelopes + SSE)
    NotifySystemMessage {
        msg_id: String,
        message_type: String, // "commit", etc.
    },
}

#[async_trait]
impl Actor for ConversationActor {
    type Msg = ConvoMessage;
    type State = ConversationActorState;
    type Arguments = ConvoActorArgs;

    async fn pre_start(
        &self,
        _myself: ActorRef<Self::Msg>,
        args: Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        // Load initial state from database
        let current_epoch = crate::storage::get_current_epoch(&args.db_pool, &args.convo_id)
            .await
            .map_err(|e| format!("Failed to get current epoch: {}", e))?;

        info!(
            "ConversationActor {} starting at epoch {}",
            args.convo_id, current_epoch
        );

        let broadcaster_worker_count = std::env::var("BROADCASTER_POOL_SIZE")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(4);
        let broadcaster_chunk_size = std::env::var("BROADCASTER_CHUNK_SIZE")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(1000);

        let broadcaster_pool = BroadcasterPool::spawn(
            args.db_pool.clone(),
            broadcaster_worker_count,
            broadcaster_chunk_size,
        )
        .await
        .map_err(|e| format!("Failed to initialize broadcaster pool: {}", e))?;

        // Create channel for serialized background jobs
        let (tx, mut rx) = mpsc::channel::<SideEffectJob>(100);

        // Spawn background worker for serialized side effects (Push/SSE)
        let pool = args.db_pool.clone();
        let sse_state = args.sse_state.clone();
        let notification_service = args.notification_service.clone();
        let convo_id = args.convo_id.clone();
        let broadcaster_pool_for_worker = broadcaster_pool.clone();

        tokio::spawn(async move {
            info!(
                "🔄 [actor:worker] Background worker started for {}",
                convo_id
            );
            while let Some(job) = rx.recv().await {
                match job {
                    SideEffectJob::NotifyNewMessage {
                        msg_id,
                        sender_did,
                        ciphertext,
                        seq,
                        epoch,
                        is_ephemeral,
                    } => {
                        debug!("🔄 [actor:worker] Processing NotifyNewMessage: {}", msg_id);
                        handle_notify_new_message(
                            &pool,
                            &sse_state,
                            &broadcaster_pool_for_worker,
                            notification_service.as_deref(),
                            &convo_id,
                            &msg_id,
                            &sender_did,
                            &ciphertext,
                            seq,
                            epoch,
                            is_ephemeral,
                        )
                        .await;
                    }
                    SideEffectJob::NotifySystemMessage {
                        msg_id,
                        message_type,
                    } => {
                        debug!(
                            "🔄 [actor:worker] Processing NotifySystemMessage: {}",
                            msg_id
                        );
                        // Reuse similar logic or dedicated handler for system messages
                        // For commits, we mostly need envelopes + SSE
                        handle_notify_system_message(
                            &pool,
                            &sse_state,
                            &broadcaster_pool_for_worker,
                            &convo_id,
                            &msg_id,
                            &message_type,
                        )
                        .await;
                    }
                }
            }
            info!(
                "🔄 [actor:worker] Background worker stopped for {}",
                convo_id
            );
        });

        Ok(ConversationActorState {
            convo_id: args.convo_id,
            current_epoch: current_epoch as u32,
            unread_counts: HashMap::new(),
            db_pool: args.db_pool,
            sse_state: args.sse_state,
            side_effect_tx: tx,
            broadcaster_pool,
            quorum_config: args.quorum_config,
        })
    }

    async fn handle(
        &self,
        _myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            ConvoMessage::AddMembers {
                did_list,
                commit,
                welcome_message,
                key_package_hashes,
                reply,
            } => {
                let result = state
                    .handle_add_members(did_list, commit, welcome_message, key_package_hashes)
                    .await;
                let _ = reply.send(result);
            }
            ConvoMessage::RemoveMember {
                member_did,
                commit,
                reply,
            } => {
                let result = state.handle_remove_member(member_did, commit).await;
                let _ = reply.send(result);
            }
            ConvoMessage::SendMessage {
                sender_did,
                ciphertext,
                msg_id,
                epoch,
                padded_size,
                idempotency_key,
                reply,
            } => {
                let result = state
                    .handle_send_message(
                        sender_did,
                        ciphertext,
                        msg_id,
                        epoch,
                        padded_size,
                        idempotency_key,
                    )
                    .await;
                let _ = reply.send(result);
            }
            ConvoMessage::IncrementUnread { sender_did } => {
                state.handle_increment_unread(sender_did).await;
            }
            ConvoMessage::ResetUnread { member_did, reply } => {
                let result = state.handle_reset_unread(member_did).await;
                let _ = reply.send(result);
            }
            ConvoMessage::GetEpoch { reply } => {
                let _ = reply.send(state.current_epoch);
            }
            ConvoMessage::RecordResetVote {
                device_did,
                identity_did,
                epoch_authenticator,
                failure_type,
                failure_mode,
                reply,
            } => {
                let result = state
                    .handle_record_reset_vote(
                        device_did,
                        identity_did,
                        epoch_authenticator,
                        failure_type,
                        failure_mode,
                    )
                    .await;
                let _ = reply.send(result);
            }
            ConvoMessage::TriggerSystemReset {
                reason,
                staleness_epochs,
                quiet_duration_secs,
            } => {
                state
                    .handle_trigger_system_reset(reason, staleness_epochs, quiet_duration_secs)
                    .await;
            }
            ConvoMessage::RequestCryptoSessionReset {
                trigger,
                initiator_did,
                reason,
                idempotency_key,
                expected_new_mls_group_id,
                reply,
            } => {
                let result = state
                    .handle_request_crypto_session_reset(
                        trigger,
                        initiator_did,
                        reason,
                        idempotency_key,
                        expected_new_mls_group_id,
                    )
                    .await;
                let _ = reply.send(result);
            }
            ConvoMessage::ActivateCryptoSession {
                reset_request_id,
                trigger,
                new_mls_group_id,
                new_group_info,
                welcomes,
                initiator_did,
                idempotency_key,
                reply,
            } => {
                let result = state
                    .handle_activate_crypto_session(
                        reset_request_id,
                        trigger,
                        new_mls_group_id,
                        new_group_info,
                        welcomes,
                        initiator_did,
                        idempotency_key,
                    )
                    .await;
                let _ = reply.send(result);
            }
            ConvoMessage::Shutdown => {
                info!("ConversationActor shutting down");
                state.broadcaster_pool.shutdown();
                // Could persist state here if needed
            }
        }
        Ok(())
    }
}

/// Mutable state maintained by a [`ConversationActor`].
///
/// This structure holds the runtime state for a single conversation,
/// including the current MLS epoch, unread message counts, and database
/// connection for persistence operations.
///
/// # Fields
///
/// - `convo_id`: Unique identifier for this conversation
/// - `current_epoch`: Current MLS epoch counter (increments on roster changes)
/// - `unread_counts`: In-memory cache of unread counts per member (periodically synced to DB)
/// - `db_pool`: PostgreSQL connection pool for database operations
/// - `sse_state`: SSE state for real-time event broadcasting
///
/// # Concurrency Model
///
/// This state is only accessed by a single actor thread, eliminating the need
/// for locks. All modifications happen sequentially in response to messages.
pub struct ConversationActorState {
    convo_id: String,
    current_epoch: u32,
    unread_counts: HashMap<String, u32>, // member_did -> count
    db_pool: PgPool,
    sse_state: Arc<SseState>,
    side_effect_tx: mpsc::Sender<SideEffectJob>,
    broadcaster_pool: BroadcasterPool,
    /// ADR-008 D1 (Phase 2): quorum knobs. Snapshotted at spawn time from
    /// `ConvoActorArgs::quorum_config` so tests can inject without racing on
    /// process-global env vars.
    quorum_config: QuorumConfig,
}

impl ConversationActorState {
    /// Handles adding new members to the conversation.
    ///
    /// This operation atomically:
    /// 1. Increments the conversation epoch
    /// 2. Stores the MLS commit message (if provided)
    /// 3. Adds new member records to the database
    /// 4. Stores Welcome messages for new members
    ///
    /// # Arguments
    ///
    /// - `did_list`: List of DIDs (decentralized identifiers) for new members
    /// - `commit`: Optional MLS Commit message bytes
    /// - `welcome_message`: Optional base64-encoded MLS Welcome message
    /// - `key_package_hashes`: Optional mapping of DIDs to their key package hashes
    ///
    /// # Returns
    ///
    /// The new epoch number after adding members.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Database transaction fails
    /// - Welcome message is invalid base64
    /// - Member insertion fails
    async fn handle_add_members(
        &mut self,
        did_list: Vec<String>,
        commit: Option<Vec<u8>>,
        welcome_message: Option<String>,
        key_package_hashes: Option<Vec<KeyPackageHashEntry>>,
    ) -> anyhow::Result<u32> {
        use anyhow::Context;

        info!(
            "Adding {} members to conversation {}",
            did_list.len(),
            self.convo_id
        );

        let mut new_epoch = self.current_epoch;
        let now = chrono::Utc::now();

        // Begin transaction for atomicity
        let mut tx = self
            .db_pool
            .begin()
            .await
            .context("Failed to begin transaction")?;

        // Process commit if provided (capture msg_id for later fanout)
        let commit_msg_id = if let Some(commit_bytes) = commit {
            let commit_shape =
                crate::handlers::mls_chat::commit_inspect::inspect_commit_shape(&commit_bytes)
                    .context("Invalid commit framing")?;
            if commit_shape.epoch != self.current_epoch as u64 {
                anyhow::bail!(
                    "Stale commit for convo {}: wire_epoch {} != current_epoch {}",
                    self.convo_id,
                    commit_shape.epoch,
                    self.current_epoch
                );
            }
            let commit_wire_epoch = commit_shape.epoch as i64;
            let msg_id = uuid::Uuid::new_v4().to_string();
            let advanced_epoch = crate::db::try_advance_conversation_epoch_tx(
                &mut tx,
                &self.convo_id,
                self.current_epoch as i32,
            )
            .await
            .context("Failed to advance conversation epoch")?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Epoch conflict for convo {}: expected {}",
                    self.convo_id,
                    self.current_epoch
                )
            })?;

            // Calculate sequence number
            let seq: i64 = sqlx::query_scalar(
                "SELECT CAST(COALESCE(MAX(seq), 0) + 1 AS BIGINT) FROM messages WHERE convo_id = $1"
            )
            .bind(&self.convo_id)
            .fetch_one(&mut *tx)
            .await
            .context("Failed to calculate sequence number")?;

            // Insert commit message with sequence number
            sqlx::query(
                "INSERT INTO messages (id, convo_id, sender_did, message_type, epoch, wire_epoch, seq, ciphertext, created_at) VALUES ($1, $2, $3, 'commit', $4, $5, $6, $7, $8)"
            )
            .bind(&msg_id)
            .bind(&self.convo_id)
            .bind(Option::<&str>::None) // sender_did intentionally NULL — PRIV-001 (docs/PRIVACY.md)
            .bind(advanced_epoch)
            .bind(commit_wire_epoch)
            .bind(seq)
            .bind(&commit_bytes)
            .bind(now)
            .execute(&mut *tx)
            .await
            .context("Failed to insert commit message")?;
            new_epoch = advanced_epoch as u32;

            info!(
                "✅ [actor:add_members] Commit message stored with seq={}, epoch={}",
                seq, new_epoch
            );
            Some(msg_id)
        } else {
            warn!(
                "⚠️ [actor:add_members] add_members without commit; epoch unchanged for {}",
                self.convo_id
            );
            None
        };

        // Add new members
        for target_did in &did_list {
            // Check if already a member
            let is_existing = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM members WHERE convo_id = $1 AND member_did = $2",
            )
            .bind(&self.convo_id)
            .bind(target_did)
            .fetch_one(&mut *tx)
            .await
            .context("Failed to check existing membership")?;

            if is_existing > 0 {
                info!("Member already exists, skipping");
                continue;
            }

            sqlx::query(
                "INSERT INTO members (convo_id, member_did, joined_at) VALUES ($1, $2, $3)",
            )
            .bind(&self.convo_id)
            .bind(target_did)
            .bind(now)
            .execute(&mut *tx)
            .await
            .context(format!("Failed to add member {}", target_did))?;

            info!("Added member to conversation");
        }

        // Store Welcome message for new members
        if let Some(ref welcome_b64) = welcome_message {
            info!(
                "Processing Welcome message for {} new members",
                did_list.len()
            );

            // Decode base64 Welcome message
            let welcome_data =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, welcome_b64)
                    .context("Invalid base64 welcome message")?;

            info!(
                "Single Welcome message ({} bytes) for {} new members",
                welcome_data.len(),
                did_list.len()
            );

            // Store the SAME Welcome for each new member
            for target_did in &did_list {
                let welcome_id = uuid::Uuid::new_v4().to_string();

                // Get the key_package_hash for this member from the input
                let key_package_hash = key_package_hashes.as_ref().and_then(|hashes| {
                    hashes
                        .iter()
                        .find(|entry| entry.did == *target_did)
                        .and_then(|entry| hex::decode(&entry.hash).ok())
                });

                sqlx::query(
                    "INSERT INTO welcome_messages (id, convo_id, recipient_did, welcome_data, key_package_hash, created_at)
                     VALUES ($1, $2, $3, $4, $5, $6)
                     ON CONFLICT (convo_id, recipient_did, COALESCE(key_package_hash, '\\x00'::bytea)) WHERE consumed = false
                     DO NOTHING"
                )
                .bind(&welcome_id)
                .bind(&self.convo_id)
                .bind(target_did)
                .bind(&welcome_data)
                .bind::<Option<Vec<u8>>>(key_package_hash)
                .bind(now)
                .execute(&mut *tx)
                .await
                .context(format!("Failed to store welcome message for {}", target_did))?;

                info!("Welcome stored for member");
            }
        }

        // Commit transaction
        tx.commit().await.context("Failed to commit transaction")?;

        // Send side effect job for fan-out (envelopes + SSE)
        // We use a simplified job for system messages (commits)
        if let Some(msg_id) = commit_msg_id {
            let _ = self
                .side_effect_tx
                .try_send(SideEffectJob::NotifySystemMessage {
                    msg_id,
                    message_type: "commit".to_string(),
                });
        }

        // Update local epoch state
        self.current_epoch = new_epoch;

        info!(
            "Members added, new epoch: {} for conversation {}",
            self.current_epoch, self.convo_id
        );

        Ok(self.current_epoch)
    }

    /// Handles removing a member from the conversation.
    ///
    /// This operation atomically:
    /// 1. Increments the conversation epoch
    /// 2. Stores the MLS commit message (if provided)
    /// 3. Soft-deletes the member by setting their `left_at` timestamp
    /// 4. Removes the member from in-memory unread counts
    ///
    /// # Arguments
    ///
    /// - `member_did`: DID of the member to remove
    /// - `commit`: Optional MLS Commit message bytes
    ///
    /// # Returns
    ///
    /// The new epoch number after removing the member.
    ///
    /// # Errors
    ///
    /// Returns an error if the database transaction fails.
    async fn handle_remove_member(
        &mut self,
        member_did: String,
        commit: Option<Vec<u8>>,
    ) -> anyhow::Result<u32> {
        use anyhow::Context;

        info!(
            "Removing member {} from conversation {}",
            member_did, self.convo_id
        );

        let mut new_epoch = self.current_epoch;
        let now = chrono::Utc::now();

        // Begin transaction for atomicity
        let mut tx = self
            .db_pool
            .begin()
            .await
            .context("Failed to begin transaction")?;

        // Process commit if provided (capture msg_id for later fanout)
        let commit_msg_id = if let Some(commit_bytes) = commit {
            let commit_shape =
                crate::handlers::mls_chat::commit_inspect::inspect_commit_shape(&commit_bytes)
                    .context("Invalid commit framing")?;
            if commit_shape.epoch != self.current_epoch as u64 {
                anyhow::bail!(
                    "Stale commit for convo {}: wire_epoch {} != current_epoch {}",
                    self.convo_id,
                    commit_shape.epoch,
                    self.current_epoch
                );
            }
            let commit_wire_epoch = commit_shape.epoch as i64;
            let msg_id = uuid::Uuid::new_v4().to_string();
            let advanced_epoch = crate::db::try_advance_conversation_epoch_tx(
                &mut tx,
                &self.convo_id,
                self.current_epoch as i32,
            )
            .await
            .context("Failed to advance conversation epoch")?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Epoch conflict for convo {}: expected {}",
                    self.convo_id,
                    self.current_epoch
                )
            })?;

            // Calculate sequence number
            let seq: i64 = sqlx::query_scalar(
                "SELECT CAST(COALESCE(MAX(seq), 0) + 1 AS BIGINT) FROM messages WHERE convo_id = $1"
            )
            .bind(&self.convo_id)
            .fetch_one(&mut *tx)
            .await
            .context("Failed to calculate sequence number")?;

            // Insert commit message with sequence number
            sqlx::query(
                "INSERT INTO messages (id, convo_id, sender_did, message_type, epoch, wire_epoch, seq, ciphertext, created_at) VALUES ($1, $2, $3, 'commit', $4, $5, $6, $7, $8)"
            )
            .bind(&msg_id)
            .bind(&self.convo_id)
            .bind(Option::<&str>::None) // sender_did intentionally NULL — PRIV-001 (docs/PRIVACY.md)
            .bind(advanced_epoch)
            .bind(commit_wire_epoch)
            .bind(seq)
            .bind(&commit_bytes)
            .bind(now)
            .execute(&mut *tx)
            .await
            .context("Failed to insert commit message")?;
            new_epoch = advanced_epoch as u32;

            info!(
                "✅ [actor:remove_member] Commit message stored with seq={}, epoch={}",
                seq, new_epoch
            );
            Some(msg_id)
        } else {
            warn!(
                "⚠️ [actor:remove_member] remove_member without commit; epoch unchanged for {}",
                self.convo_id
            );
            None
        };

        // Mark member as left (soft delete with left_at timestamp)
        sqlx::query("UPDATE members SET left_at = $1 WHERE convo_id = $2 AND member_did = $3")
            .bind(now)
            .bind(&self.convo_id)
            .bind(&member_did)
            .execute(&mut *tx)
            .await
            .context("Failed to mark member as left")?;

        // Commit transaction
        tx.commit().await.context("Failed to commit transaction")?;

        // Send side effect job for fan-out (envelopes + SSE)
        // We use a simplified job for system messages (commits)
        if let Some(msg_id) = commit_msg_id {
            let _ = self
                .side_effect_tx
                .try_send(SideEffectJob::NotifySystemMessage {
                    msg_id,
                    message_type: "commit".to_string(),
                });
        }

        // Update local epoch state
        self.current_epoch = new_epoch;
        self.unread_counts.remove(&member_did);

        info!(
            "Member removed, new epoch: {} for conversation {}",
            self.current_epoch, self.convo_id
        );

        Ok(self.current_epoch)
    }

    /// Handles sending an application message in the conversation.
    ///
    /// This operation:
    /// 1. Checks for duplicate messages via msg_id and idempotency_key
    /// 2. Stores the encrypted message with a sequence number and privacy fields
    /// 3. Updates unread counts for all members except the sender
    /// 4. Spawns an async task to fan out message envelopes to all members
    ///
    /// # Arguments
    ///
    /// - `sender_did`: DID of the message sender
    /// - `ciphertext`: Encrypted message bytes
    /// - `msg_id`: Client-provided ULID/UUID for message deduplication
    /// - `epoch`: Client's epoch number when message was encrypted
    /// - `padded_size`: Padded ciphertext size for metadata privacy
    /// - `idempotency_key`: Optional key for backward-compatible deduplication
    ///
    /// # Returns
    ///
    /// `Ok((msg_id, created_at))` tuple if the message is successfully stored or found as duplicate.
    ///
    /// # Errors
    ///
    /// Returns an error if message insertion or unread count update fails.
    ///
    /// # Notes
    ///
    /// The fan-out operation (creating envelopes for each member) runs
    /// asynchronously to avoid blocking the actor. Errors in fan-out are
    /// logged but don't affect the message send result.
    async fn handle_send_message(
        &mut self,
        sender_did: String,
        ciphertext: Vec<u8>,
        msg_id: String,
        epoch: i64,
        padded_size: i64,
        idempotency_key: Option<String>,
    ) -> anyhow::Result<(String, chrono::DateTime<chrono::Utc>)> {
        use anyhow::Context;

        info!(
            "Storing message from {} in conversation {} ({} bytes, msg_id={}, epoch={}, padded_size={})",
            sender_did,
            self.convo_id,
            ciphertext.len(),
            msg_id,
            epoch,
            padded_size
        );

        let now = chrono::Utc::now();
        let expires_at = now + chrono::Duration::days(30);

        // Quantize timestamp to 2-second buckets for traffic analysis resistance
        let received_bucket_ts = (now.timestamp() / 2) * 2;

        // Calculate sequence number within transaction
        let mut tx = self
            .db_pool
            .begin()
            .await
            .context("Failed to begin transaction")?;

        // Check for duplicate msg_id (protocol-layer deduplication)
        let existing_msg: Option<(String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
            "SELECT id, created_at FROM messages WHERE convo_id = $1 AND msg_id = $2",
        )
        .bind(&self.convo_id)
        .bind(&msg_id)
        .fetch_optional(&mut *tx)
        .await
        .context("Failed to check msg_id")?;

        if let Some((existing_id, existing_created_at)) = existing_msg {
            // Return existing message without creating a duplicate
            tx.rollback().await.ok();
            info!(
                "Duplicate msg_id detected, returning existing message: {}",
                existing_id
            );
            return Ok((existing_id, existing_created_at));
        }

        // If idempotency key is provided, check for existing message
        if let Some(ref idem_key) = idempotency_key {
            let existing_by_idem: Option<(String, chrono::DateTime<chrono::Utc>)> =
                sqlx::query_as("SELECT id, created_at FROM messages WHERE idempotency_key = $1")
                    .bind(idem_key)
                    .fetch_optional(&mut *tx)
                    .await
                    .context("Failed to check idempotency key")?;

            if let Some((existing_id, existing_created_at)) = existing_by_idem {
                // Return existing message without creating a duplicate
                tx.rollback().await.ok();
                info!(
                    "Duplicate idempotency_key detected, returning existing message: {}",
                    existing_id
                );
                return Ok((existing_id, existing_created_at));
            }
        }

        let seq: i64 = sqlx::query_scalar(
            "SELECT CAST(COALESCE(MAX(seq), 0) + 1 AS BIGINT) FROM messages WHERE convo_id = $1",
        )
        .bind(&self.convo_id)
        .fetch_one(&mut *tx)
        .await
        .context("Failed to calculate sequence number")?;

        // Generate unique internal row ID
        let row_id = uuid::Uuid::new_v4().to_string();

        // Insert message into messages table with all privacy fields
        sqlx::query(
            r#"
            INSERT INTO messages (
                id, convo_id, sender_did, message_type, epoch, seq,
                ciphertext, created_at, expires_at,
                msg_id, padded_size, received_bucket_ts,
                idempotency_key
            ) VALUES ($1, $2, $3, 'app', $4, $5, $6, $7, $8, $9, $10, $11, $12)
            "#,
        )
        .bind(&row_id)
        .bind(&self.convo_id)
        .bind(Option::<&str>::None) // sender_did intentionally NULL — PRIV-001 (docs/PRIVACY.md)
        .bind(epoch)
        .bind(seq)
        .bind(&ciphertext)
        .bind(now)
        .bind(expires_at)
        .bind(&msg_id)
        .bind(padded_size)
        .bind(received_bucket_ts)
        .bind(&idempotency_key)
        .execute(&mut *tx)
        .await
        .context("Failed to insert message")?;

        tx.commit().await.context("Failed to commit transaction")?;

        debug!("Message stored with sequence number {}", seq);

        // Update unread counts for all members except sender's devices in database
        // In multi-device mode, user_did is the base DID, so this excludes all sender's devices
        sqlx::query(
            "UPDATE members SET unread_count = unread_count + 1 WHERE convo_id = $1 AND user_did != $2 AND left_at IS NULL"
        )
        .bind(&self.convo_id)
        .bind(&sender_did)
        .execute(&self.db_pool)
        .await
        .context("Failed to update unread counts")?;

        // Submit to serialization queue
        // This replaces the old tokio::spawn logic with a sequential actor-bound queue
        if let Err(_e) = self
            .side_effect_tx
            .try_send(SideEffectJob::NotifyNewMessage {
                msg_id: msg_id.clone(),
                sender_did: sender_did.clone(),
                ciphertext: ciphertext.clone(),
                seq,
                epoch,
                is_ephemeral: false, // Actors generally handle persistent messages
            })
        {
            tracing::error!("❌ [actor:send_message] Failed to enqueue side effects:Full?");
        }

        Ok((row_id, now))
    }

    /// Handles incrementing unread counts for all members except the sender.
    ///
    /// This operation:
    /// 1. Queries all active members in the conversation
    /// 2. Increments in-memory unread count for each member (except sender)
    /// 3. Periodically flushes counts to database (every 10 messages per member)
    ///
    /// # Arguments
    ///
    /// - `sender_did`: DID of the message sender (excluded from unread increment)
    ///
    /// # Notes
    ///
    /// This method uses batched writes to reduce database load. Counts are
    /// flushed to the database every 10 increments per member. In case of
    /// actor restart, some increments may be lost, which is acceptable for
    /// unread counts.
    async fn handle_increment_unread(&mut self, sender_did: String) {
        info!(
            "Incrementing unread counts for conversation {} (sender: {})",
            self.convo_id, sender_did
        );

        // Get all active members with their user_did to properly exclude sender's devices
        let members_result = sqlx::query_as::<_, (String, Option<String>)>(
            r#"
            SELECT member_did, user_did
            FROM members
            WHERE convo_id = $1 AND left_at IS NULL
            "#,
        )
        .bind(&self.convo_id)
        .fetch_all(&self.db_pool)
        .await;

        match members_result {
            Ok(members) => {
                let member_count = members.len();
                // Increment in-memory counter for all members except sender's devices
                // In multi-device mode, we exclude all devices where user_did matches sender_did
                for (member_did, user_did) in members {
                    let is_sender_device = user_did.as_ref() == Some(&sender_did);
                    if !is_sender_device {
                        let count = self.unread_counts.entry(member_did.clone()).or_insert(0);
                        *count += 1;

                        // Optional: flush to database every N increments (e.g., every 10 messages)
                        if (*count).is_multiple_of(10) {
                            if let Err(e) = sqlx::query(
                                "UPDATE members SET unread_count = unread_count + 10 WHERE convo_id = $1 AND member_did = $2"
                            )
                            .bind(&self.convo_id)
                            .bind(&member_did)
                            .execute(&self.db_pool)
                            .await {
                                tracing::warn!("Failed to sync unread count to database: {}", e);
                            } else {
                                // Reset in-memory counter after successful sync
                                *count = 0;
                            }
                        }
                    }
                }
                info!(
                    "Incremented unread counts for {} members",
                    member_count.saturating_sub(1)
                );
            }
            Err(e) => {
                tracing::error!("Failed to get members for unread increment: {}", e);
            }
        }
    }

    /// Handles resetting the unread count for a specific member.
    ///
    /// This operation:
    /// 1. Immediately resets the unread count to 0 in the database
    /// 2. Clears the in-memory unread count for the member
    ///
    /// # Arguments
    ///
    /// - `member_did`: DID of the member whose unread count should be reset
    ///
    /// # Returns
    ///
    /// `Ok(())` if the reset is successful.
    ///
    /// # Errors
    ///
    /// Returns an error if the database update fails.
    ///
    /// # Notes
    ///
    /// This is typically called when a member reads messages in the conversation.
    async fn handle_reset_unread(&mut self, member_did: String) -> anyhow::Result<()> {
        use anyhow::Context;

        info!(
            "Resetting unread count for user {} in conversation {}",
            member_did, self.convo_id
        );

        // Reset in database immediately for all devices of this user
        sqlx::query(
            "UPDATE members SET unread_count = 0 WHERE convo_id = $1 AND user_did = $2 AND left_at IS NULL"
        )
        .bind(&self.convo_id)
        .bind(&member_did)
        .execute(&self.db_pool)
        .await
        .context("Failed to reset unread count in database")?;

        // Reset in-memory counter for all devices of this user
        // Note: member_did here is the user DID, so we need to reset all device DIDs
        // Get all device DIDs for this user in this conversation
        let device_dids = sqlx::query_scalar::<_, String>(
            "SELECT member_did FROM members WHERE convo_id = $1 AND user_did = $2 AND left_at IS NULL"
        )
        .bind(&self.convo_id)
        .bind(&member_did)
        .fetch_all(&self.db_pool)
        .await
        .context("Failed to fetch device DIDs")?;

        for device_did in device_dids {
            self.unread_counts.insert(device_did, 0);
        }

        info!(
            "Unread count reset for user {} in conversation {}",
            member_did, self.convo_id
        );

        Ok(())
    }

    /// Records a quorum-reset vote from one device, with cryptographic proof of
    /// the claimed stuck state (ADR-002 §A7.1). Returns the full outcome for the
    /// HTTP layer to translate into a response body.
    ///
    /// # Pipeline
    ///
    /// 1. Validate the caller is still an active member (defense in depth —
    ///    the HTTP handler also checks).
    /// 2. Validate `epoch_authenticator` against `epoch_authenticators` for this
    ///    conversation. Accept if the authenticator was recorded for one of the
    ///    current epoch, current_epoch-1, or current_epoch-2, OR was recorded
    ///    within the last 5 minutes (quiet-group window). Otherwise reject as
    ///    `stale_authenticator`.
    /// 3. Check per-DID 24h rate limit via `reset_votes.expires_at > NOW()`. On
    ///    a second vote from the same `identity_did` within the window, reject
    ///    as `rate_limited`.
    /// 4. Upsert the vote into `reset_votes` (PK `(convo_id, device_did)`; a
    ///    device may refresh its own vote but identity-level rate limit gates
    ///    above).
    /// 5. Check 30-minute cooldown on `conversations.last_reset_at`. If in
    ///    cooldown, record the vote but return `auto_reset_triggered: false`.
    /// 6. Check rolling 24h circuit breaker: if `auto_reset_history` has >=3
    ///    rows with `reset_triggered_at > NOW() - '24h'`, set
    ///    `auto_reset_disabled_at = NOW()` and return `reason: circuit_breaker`.
    ///    (Also short-circuit on pre-existing `auto_reset_disabled_at`.)
    /// 7. Compute per-DID vote count: a `user_did` contributes one vote iff
    ///    every one of its active devices in the roster has filed a non-expired
    ///    vote row AND every such row's `epoch_authenticator` is valid (which
    ///    we already enforced at insert time — rejected votes never reach
    ///    `reset_votes`).
    /// 8. Compute `member_did_count` = distinct `user_did` values for active
    ///    members (not soft-deleted).
    /// 9. If `per_did_vote_count * 3 >= member_did_count * 2` (ceiling of 2/3),
    ///    execute the auto-reset transaction atomically and emit a
    ///    `GroupResetEvent` + `auto_reset_history` row.
    async fn handle_record_reset_vote(
        &mut self,
        device_did: String,
        identity_did: String,
        epoch_authenticator: String,
        failure_type: String,
        failure_mode: Option<String>,
    ) -> anyhow::Result<RecordResetVoteOutcome> {
        use anyhow::Context;

        info!(
            convo = %crate::crypto::redact_for_log(&self.convo_id),
            device = %crate::crypto::redact_for_log(&device_did),
            identity = %crate::crypto::redact_for_log(&identity_did),
            failure_type = %failure_type,
            failure_mode = ?failure_mode,
            "[actor:record_reset_vote] start"
        );

        // ── 1. Active-member check ────────────────────────────────────────
        let is_member: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM members \
             WHERE convo_id = $1 AND member_did = $2 AND left_at IS NULL)",
        )
        .bind(&self.convo_id)
        .bind(&device_did)
        .fetch_one(&self.db_pool)
        .await
        .context("membership check failed")?;
        if !is_member {
            return Ok(RecordResetVoteOutcome {
                recorded: false,
                reason: Some("not_member".to_string()),
                per_did_vote_count: 0,
                member_did_count: 0,
                auto_reset_triggered: false,
                new_group_id: None,
                reset_count: None,
            });
        }

        // ── 2. Validate epoch_authenticator ───────────────────────────────
        //   Accept if it matches a row recorded in the last 3 epochs OR any row
        //   recorded within the last 5 minutes (quiet-group window).
        //
        //   Sentinel `""` (empty string) means the reporting client lost its
        //   group state entirely and cannot compute an authenticator. The
        //   handler at `report_recovery_failure.rs` substitutes empty for
        //   missing on dispatch (2026-04-28 relaxation). We skip the
        //   cryptographic check in this case — anti-spoof devolves to the
        //   authenticated DID + membership gate (step 1 above) plus the
        //   per-DID rate-limit (step 3 below) plus Mode B quorum filtering
        //   (step 5 below). Mode A no-auth votes still get recorded but
        //   the D1 filter excludes them from auto-reset (telemetry only);
        //   Mode B no-auth votes count toward quorum, which is the only
        //   path to recovery when local state is gone AND the server's
        //   GroupInfo is missing (the trifecta).
        let no_auth_sentinel = epoch_authenticator.is_empty();
        if !no_auth_sentinel {
            let current_epoch = self.current_epoch as i32;
            let epoch_floor = current_epoch.saturating_sub(2);
            let auth_valid: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM epoch_authenticators \
                 WHERE convo_id = $1 \
                 AND authenticator = $2 \
                 AND (epoch BETWEEN $3 AND $4 \
                      OR recorded_at > NOW() - INTERVAL '5 minutes'))",
            )
            .bind(&self.convo_id)
            .bind(&epoch_authenticator)
            .bind(epoch_floor)
            .bind(current_epoch)
            .fetch_one(&self.db_pool)
            .await
            .context("epoch_authenticator lookup failed")?;

            if !auth_valid {
                warn!(
                    convo = %crate::crypto::redact_for_log(&self.convo_id),
                    "[actor:record_reset_vote] stale_authenticator"
                );
                info!(
                    convo_id = %crate::crypto::redact_for_log(&self.convo_id),
                    voter_did = %crate::crypto::redact_for_log(&device_did),
                    vote_count_before = 0_i64,
                    vote_count_after = 0_i64,
                    quorum_threshold = 0_i64,
                    epoch_authenticator_match = false,
                    rate_limited = false,
                    "A7 vote recorded"
                );
                return Ok(RecordResetVoteOutcome {
                    recorded: false,
                    reason: Some("stale_authenticator".to_string()),
                    per_did_vote_count: 0,
                    member_did_count: 0,
                    auto_reset_triggered: false,
                    new_group_id: None,
                    reset_count: None,
                });
            }
        } else {
            info!(
                convo = %crate::crypto::redact_for_log(&self.convo_id),
                voter_did = %crate::crypto::redact_for_log(&device_did),
                failure_mode = ?failure_mode,
                "[actor:record_reset_vote] no-auth sentinel — skipping authenticator validation"
            );
        }

        // ── 3. Per-identity 24h rate limit ────────────────────────────────
        //   A DID may only vote once per 24h per conversation. We gate on
        //   identity_did, not device_did, because every device of the same DID
        //   is considered "one voter" under per-DID counting.
        let has_recent_vote: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM reset_votes \
             WHERE convo_id = $1 AND identity_did = $2 \
             AND expires_at > NOW() AND device_did <> $3)",
        )
        .bind(&self.convo_id)
        .bind(&identity_did)
        .bind(&device_did)
        .fetch_one(&self.db_pool)
        .await
        .context("rate-limit lookup failed")?;
        if has_recent_vote {
            // The DID has a live vote from a *different* device within 24h.
            // We refuse the new device's vote rather than allowing per-device
            // refresh to silently replace it — the 24h window is per-identity.
            info!(
                convo_id = %crate::crypto::redact_for_log(&self.convo_id),
                voter_did = %crate::crypto::redact_for_log(&device_did),
                vote_count_before = 0_i64,
                vote_count_after = 0_i64,
                quorum_threshold = 0_i64,
                epoch_authenticator_match = true,
                rate_limited = true,
                "A7 vote recorded"
            );
            return Ok(RecordResetVoteOutcome {
                recorded: false,
                reason: Some("rate_limited".to_string()),
                per_did_vote_count: 0,
                member_did_count: 0,
                auto_reset_triggered: false,
                new_group_id: None,
                reset_count: None,
            });
        }

        // ── 4. Upsert the vote ────────────────────────────────────────────
        // ADR-008 D1 (spec §8.6.1): persist `failure_mode` so quorum counting
        // can filter Mode A votes when `ENFORCE_FAILURE_MODE_QUORUM` is on.
        sqlx::query(
            "INSERT INTO reset_votes \
                (convo_id, device_did, identity_did, epoch_authenticator, \
                 failure_type, failure_mode, voted_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW() + INTERVAL '24 hours') \
             ON CONFLICT (convo_id, device_did) DO UPDATE SET \
                identity_did = EXCLUDED.identity_did, \
                epoch_authenticator = EXCLUDED.epoch_authenticator, \
                failure_type = EXCLUDED.failure_type, \
                failure_mode = EXCLUDED.failure_mode, \
                voted_at = NOW(), \
                expires_at = NOW() + INTERVAL '24 hours'",
        )
        .bind(&self.convo_id)
        .bind(&device_did)
        .bind(&identity_did)
        .bind(&epoch_authenticator)
        .bind(&failure_type)
        .bind(&failure_mode)
        .execute(&self.db_pool)
        .await
        .context("failed to upsert reset_votes")?;

        // ── 5. Compute per-DID vote count + member_did_count ──────────────
        //   A user_did contributes iff every one of their active member_dids in
        //   this conversation has a non-expired reset_votes row. We compare the
        //   cardinality of the active device set to the cardinality of the voted
        //   device subset per identity.
        let member_did_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(DISTINCT COALESCE(user_did, member_did)) \
             FROM members WHERE convo_id = $1 AND left_at IS NULL",
        )
        .bind(&self.convo_id)
        .fetch_one(&self.db_pool)
        .await
        .context("member_did_count failed")?;

        // ADR-008 D1 (spec §8.6.1 + Phase 2 design §"Server-Side Changes"):
        // when `enforce_failure_mode = true`, only votes with
        // `failure_mode = 'group_state_unrecoverable'` (Mode B) are counted
        // toward quorum. Mode A (`local_state_loss`) and NULL are excluded
        // (NULL → `local_state_loss` per spec). When false, every valid vote
        // counts regardless of `failure_mode` (interim posture; flipped on by
        // default in Phase 2 — see `QuorumConfig::default`).
        let enforce_failure_mode = self.quorum_config.enforce_failure_mode;
        let mode_filter = if enforce_failure_mode {
            "AND rv.failure_mode = 'group_state_unrecoverable' "
        } else {
            ""
        };
        // QUORUM_WINDOW_SECS bounds how stale a vote may be and still count.
        let window_secs = self.quorum_config.window_secs as i64;
        let per_did_vote_sql = format!(
            "SELECT COUNT(*) FROM ( \
                SELECT COALESCE(m.user_did, m.member_did) AS ident \
                FROM members m \
                WHERE m.convo_id = $1 AND m.left_at IS NULL \
                GROUP BY COALESCE(m.user_did, m.member_did) \
                HAVING COUNT(*) = COUNT(CASE WHEN EXISTS ( \
                    SELECT 1 FROM reset_votes rv \
                    WHERE rv.convo_id = m.convo_id \
                    AND rv.device_did = m.member_did \
                    AND rv.expires_at > NOW() \
                    AND rv.voted_at > NOW() - make_interval(secs => $2) \
                    {mode_filter}\
                ) THEN 1 END) \
             ) t",
            mode_filter = mode_filter
        );
        let per_did_vote_count: i64 = sqlx::query_scalar(&per_did_vote_sql)
            .bind(&self.convo_id)
            .bind(window_secs)
            .fetch_one(&self.db_pool)
            .await
            .context("per_did_vote_count failed")?;

        // ADR-008 D1 (Phase 2): per-conversation quorum is computed from
        // `QuorumConfig::required_for`:
        //   - 1:1 (member_did_count == 2): `quorum_threshold_dm` (default 1).
        //   - groups (member_did_count >= 3): max(group_min, ceil(n*group_pct)).
        // For singletons (<2) we treat quorum as impossible.
        let quorum_threshold: i64 = self.quorum_config.required_for(member_did_count);
        info!(
            convo_id = %crate::crypto::redact_for_log(&self.convo_id),
            voter_did = %crate::crypto::redact_for_log(&device_did),
            vote_count_before = per_did_vote_count.saturating_sub(1),
            vote_count_after = per_did_vote_count,
            quorum_threshold,
            epoch_authenticator_match = true,
            rate_limited = false,
            enforce_failure_mode,
            "A7 vote recorded"
        );

        let base_outcome = RecordResetVoteOutcome {
            recorded: true,
            reason: None,
            per_did_vote_count,
            member_did_count,
            auto_reset_triggered: false,
            new_group_id: None,
            reset_count: None,
        };

        // Quorum check.
        if quorum_threshold == 0 || per_did_vote_count < quorum_threshold {
            return Ok(base_outcome);
        }

        // ── 6. Rate-limit gate (MIN_RESET_GAP_SECS, spec default 3600s) ───
        // Per Phase 2 design: a single conversation cannot be auto-reset more
        // often than once per `MIN_RESET_GAP_SECS` (1 hour) regardless of
        // quorum. Implemented inline at the spec's value — no new env knob
        // in this stage; admin/test overrides may follow if needed.
        let recent_reset: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM conversations \
             WHERE id = $1 \
             AND last_reset_at IS NOT NULL \
             AND last_reset_at > NOW() - INTERVAL '1 hour')",
        )
        .bind(&self.convo_id)
        .fetch_one(&self.db_pool)
        .await
        .unwrap_or(false);
        if recent_reset {
            info!("[actor:record_reset_vote] cooldown active");
            return Ok(base_outcome);
        }

        // ── 7. Circuit-breaker check ──────────────────────────────────────
        //   (a) pre-existing manual/latch disable
        let disabled: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM conversations \
             WHERE id = $1 AND auto_reset_disabled_at IS NOT NULL)",
        )
        .bind(&self.convo_id)
        .fetch_one(&self.db_pool)
        .await
        .unwrap_or(false);
        if disabled {
            warn!("[actor:record_reset_vote] auto_reset_disabled_at is set");
            return Ok(RecordResetVoteOutcome {
                reason: Some("circuit_breaker".to_string()),
                ..base_outcome
            });
        }

        //   (b) rolling 24h: if 3+ resets already in the last day, trip it now.
        let recent_reset_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM auto_reset_history \
             WHERE convo_id = $1 \
             AND reset_triggered_at > NOW() - INTERVAL '24 hours'",
        )
        .bind(&self.convo_id)
        .fetch_one(&self.db_pool)
        .await
        .unwrap_or(0);
        if recent_reset_count >= 3 {
            // Latch the breaker for administrative intervention.
            if let Err(e) = sqlx::query(
                "UPDATE conversations SET auto_reset_disabled_at = NOW() \
                 WHERE id = $1 AND auto_reset_disabled_at IS NULL",
            )
            .bind(&self.convo_id)
            .execute(&self.db_pool)
            .await
            {
                error!("[actor:record_reset_vote] failed to latch breaker: {}", e);
            }
            // Emit SSE CircuitBreakerTrippedEvent for observability.
            let tripped_at =
                chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            let cb_cursor = self
                .sse_state
                .cursor_gen
                .next(&self.convo_id, "circuitBreakerTrippedEvent")
                .await;
            let cb_event = StreamEvent::CircuitBreakerTrippedEvent {
                cursor: cb_cursor.clone(),
                convo_id: self.convo_id.clone(),
                reset_count: recent_reset_count as i32,
                tripped_at,
            };
            if let Err(e) = crate::db::store_event(&self.db_pool, &self.convo_id, &cb_event).await {
                error!("[actor:record_reset_vote] store cb event: {:?}", e);
            }
            if let Err(e) = self.sse_state.emit(&self.convo_id, cb_event).await {
                error!("[actor:record_reset_vote] SSE emit cb: {}", e);
            }

            return Ok(RecordResetVoteOutcome {
                reason: Some("circuit_breaker".to_string()),
                ..base_outcome
            });
        }

        // ── 8. Phase 2.5 §5 Stage 1 — dual-emit RequestCryptoSessionReset ──
        // Emit the chokepoint Request + SSE resetRequestedEvent BEFORE the
        // legacy do_reset_group runs. Stage 1 keeps both paths active so
        // unmodified clients still see the legacy GroupResetEvent. Stage 3
        // retires do_reset_group; only the chokepoint path remains.
        //
        // Idempotency key: `req-quorum:{convo_id}:{reset_count}` — keyed off
        // the pre-reset generation so retries during the same threshold-
        // crossing window converge to one Request event. After do_reset_group
        // increments reset_count the key naturally rotates.
        //
        // Phase 2.5 review-fix G1: explicit error handling so a transient
        // DB failure surfaces in logs instead of being silently squashed
        // into `0`. A wrong key here doesn't break correctness (the
        // chokepoint dedupes on the full row), but it can mask
        // duplicate-Request audit signals.
        let pre_reset_count: i32 =
            match sqlx::query_scalar("SELECT reset_count FROM conversations WHERE id = $1")
                .bind(&self.convo_id)
                .fetch_optional(&self.db_pool)
                .await
            {
                Ok(Some(c)) => c,
                Ok(None) => 0,
                Err(e) => {
                    warn!(
                        convo_id = %crate::crypto::redact_for_log(&self.convo_id),
                        error = %e,
                        "Failed to fetch reset_count for idempotency key; defaulting to 0"
                    );
                    0
                }
            };
        let quorum_idempotency_key = format!("req-quorum:{}:{}", self.convo_id, pre_reset_count);
        self.dual_emit_reset_requested(
            ResetTrigger::QuorumVote,
            system_reset_did(),
            "Phase 2.5 indirect-trigger Request: client quorum reached",
            &quorum_idempotency_key,
        )
        .await;

        // ── 8b. Execute auto-reset via the shared helper ──────────────────
        // Phase 2 B6: use service DID (not "system:client_quorum") so the
        // emitted groupResetEvent.resetBy passes iOS lexicon DID validation.
        // Reason field carries the trigger semantic for ops audit.
        let reset_outcome = self
            .do_reset_group(
                system_reset_did(),
                "Automatic recovery: quorum of members reported unrecoverable failure [trigger=client_quorum]",
                None,
                None,
            )
            .await?;
        let (new_group_id, reset_count) = match reset_outcome {
            Some(v) => v,
            None => {
                return Ok(RecordResetVoteOutcome {
                    reason: Some("convo_not_found".to_string()),
                    ..base_outcome
                });
            }
        };

        // Quorum-path-specific structured log retains the
        // `triggering_voter_count` field for operator correlation.
        let rolling_24h_reset_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM auto_reset_history \
             WHERE convo_id = $1 \
             AND reset_triggered_at > NOW() - INTERVAL '24 hours'",
        )
        .bind(&self.convo_id)
        .fetch_one(&self.db_pool)
        .await
        .unwrap_or(0);
        info!(
            convo_id = %crate::crypto::redact_for_log(&self.convo_id),
            new_group_id = %crate::crypto::redact_for_log(&new_group_id),
            reset_generation = reset_count,
            member_count = member_did_count,
            triggering_voter_count = per_did_vote_count,
            rolling_24h_reset_count,
            "A7 auto-reset fired"
        );
        info!(
            convo = %crate::crypto::redact_for_log(&self.convo_id),
            new_group_id = %crate::crypto::redact_for_log(&new_group_id),
            reset_count,
            per_did_vote_count,
            member_did_count,
            "[actor:record_reset_vote] auto-reset complete"
        );

        // Augment auto_reset_history with the vote/member counts (the helper
        // wrote 0/0 placeholders since it has no quorum-specific knowledge).
        if let Err(e) = sqlx::query(
            "UPDATE auto_reset_history \
             SET vote_count = $1, member_count = $2 \
             WHERE id = ( \
                 SELECT id FROM auto_reset_history \
                 WHERE convo_id = $3 \
                 ORDER BY id DESC LIMIT 1 \
             )",
        )
        .bind(per_did_vote_count as i32)
        .bind(member_did_count as i32)
        .bind(&self.convo_id)
        .execute(&self.db_pool)
        .await
        {
            error!(
                "[actor:record_reset_vote] failed to backfill vote/member counts: {}",
                e
            );
        }

        Ok(RecordResetVoteOutcome {
            recorded: true,
            reason: None,
            per_did_vote_count,
            member_did_count,
            auto_reset_triggered: true,
            new_group_id: Some(new_group_id),
            reset_count: Some(reset_count),
        })
    }

    /// Server-sweep handler (Phase 2 §"Detection Design → Path B").
    ///
    /// Bypasses quorum because the sweep query has objectively observed the
    /// group is dead. Still respects the per-conversation circuit breaker
    /// (`auto_reset_disabled_at`) and the 1h reset rate limit (`last_reset_at`).
    async fn handle_trigger_system_reset(
        &mut self,
        reason: String,
        staleness_epochs: i64,
        quiet_duration_secs: i64,
    ) {
        let convo_id = self.convo_id.clone();
        info!(
            convo_id = %crate::crypto::redact_for_log(&convo_id),
            reason = %reason,
            staleness_epochs,
            quiet_duration_secs,
            "system-triggered reset fired"
        );

        // Cooldown gate (defense in depth — sweep query also filters).
        let recent_reset: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM conversations \
             WHERE id = $1 \
             AND last_reset_at IS NOT NULL \
             AND last_reset_at > NOW() - INTERVAL '1 hour')",
        )
        .bind(&convo_id)
        .fetch_one(&self.db_pool)
        .await
        .unwrap_or(false);
        if recent_reset {
            warn!(
                convo_id = %crate::crypto::redact_for_log(&convo_id),
                "[actor:trigger_system_reset] cooldown active — skipping"
            );
            return;
        }

        // Circuit breaker gate.
        let disabled: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM conversations \
             WHERE id = $1 AND auto_reset_disabled_at IS NOT NULL)",
        )
        .bind(&convo_id)
        .fetch_one(&self.db_pool)
        .await
        .unwrap_or(false);
        if disabled {
            warn!(
                convo_id = %crate::crypto::redact_for_log(&convo_id),
                "[actor:trigger_system_reset] auto_reset_disabled_at set — skipping"
            );
            return;
        }

        // Phase 2 B6: use the service DID (not "system:<reason>") so the
        // resulting `groupResetEvent.resetBy` passes lexicon DID validation
        // on iOS. The `reason` field below preserves the sweep-vs-quorum
        // semantic (`reason` here is a free-form string from the sweep
        // dispatcher, e.g. "inline_409_threshold" or "server_sweep").
        let last_reset_by = system_reset_did().to_string();
        let event_reason = format!(
            "Automatic recovery: server sweep observed staleness ({} epochs, {} s quiet) [trigger={}]",
            staleness_epochs, quiet_duration_secs, reason
        );

        // Phase 2.5 §5 Stage 1 — dual-emit RequestCryptoSessionReset BEFORE
        // legacy do_reset_group. The `reason` string discriminates the
        // sweep / inline-409 / inline-404 cases; map to the typed
        // ResetTrigger variant so the chokepoint allowlist (R1 #1) and
        // audit log readers see a stable enum.
        let trigger_kind = match reason.as_str() {
            "inline_409_threshold" => ResetTrigger::InlineCommit409,
            "inline_groupinfo_404_threshold" => ResetTrigger::InlineGroupInfo404,
            // Both sweep modes (server_sweep, server_sweep_groupinfo_missing)
            // and any unknown reason fall back to SystemSweep — they are
            // observationally indistinguishable from the chokepoint's
            // perspective.
            _ => ResetTrigger::SystemSweep,
        };
        // Idempotency-key shape per Phase 2.5 plan §3:
        //   Sweep / inline: req-{trigger}:{convo}:{reset_count}.
        // Keying off pre-reset reset_count makes retries during the
        // same threshold-crossing converge to one Request event; the
        // key naturally rotates after a successful reset.
        //
        // Phase 2.5 review-fix G2: explicit error handling. See G1
        // above for the matching change in the quorum path.
        let pre_reset_count: i32 =
            match sqlx::query_scalar("SELECT reset_count FROM conversations WHERE id = $1")
                .bind(&convo_id)
                .fetch_optional(&self.db_pool)
                .await
            {
                Ok(Some(c)) => c,
                Ok(None) => 0,
                Err(e) => {
                    warn!(
                        convo_id = %crate::crypto::redact_for_log(&convo_id),
                        error = %e,
                        "Failed to fetch reset_count for idempotency key; defaulting to 0"
                    );
                    0
                }
            };
        let trigger_idempotency_key = format!(
            "req-{}:{}:{}",
            trigger_kind.as_str(),
            convo_id,
            pre_reset_count
        );
        self.dual_emit_reset_requested(
            trigger_kind,
            &last_reset_by,
            &event_reason,
            &trigger_idempotency_key,
        )
        .await;

        match self
            .do_reset_group(
                &last_reset_by,
                &event_reason,
                Some(staleness_epochs),
                Some(quiet_duration_secs),
            )
            .await
        {
            Ok(Some((new_group_id, reset_count))) => {
                let rolling_24h_reset_count: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM auto_reset_history \
                     WHERE convo_id = $1 \
                     AND reset_triggered_at > NOW() - INTERVAL '24 hours'",
                )
                .bind(&convo_id)
                .fetch_one(&self.db_pool)
                .await
                .unwrap_or(0);
                info!(
                    convo_id = %crate::crypto::redact_for_log(&convo_id),
                    new_group_id = %crate::crypto::redact_for_log(&new_group_id),
                    reset_generation = reset_count,
                    last_reset_by = %last_reset_by,
                    staleness_epochs,
                    quiet_duration_secs,
                    rolling_24h_reset_count,
                    "system-reset complete"
                );
            }
            Ok(None) => {
                warn!(
                    convo_id = %crate::crypto::redact_for_log(&convo_id),
                    "[actor:trigger_system_reset] convo_not_found"
                );
            }
            Err(e) => {
                error!(
                    convo_id = %crate::crypto::redact_for_log(&convo_id),
                    error = %e,
                    "[actor:trigger_system_reset] reset failed"
                );
            }
        }
    }

    /// Shared reset-execution helper. Used by BOTH the quorum path
    /// (`handle_record_reset_vote`) and the server-sweep path
    /// (`handle_trigger_system_reset`).
    ///
    /// Performs the atomic group_id rotation, clears welcome/pending/vote rows,
    /// inserts an `auto_reset_history` row, commits, then emits the
    /// `GroupResetEvent` (SSE + persisted). Caller is responsible for any
    /// path-specific structured logging beyond what `do_reset_group` emits.
    ///
    /// ⚠ TRUSTED-DS V0 IMPLEMENTATION ⚠
    /// See ADR-008 §D2 / §D3 for the bootstrapper-candidate / continuation-
    /// proof work that this needs before it's safe under federation or
    /// multi-DS routing.
    ///
    /// # Returns
    ///
    /// - `Ok(Some((new_group_id, reset_count)))` on success.
    /// - `Ok(None)` if the conversations row vanished mid-flight.
    /// - `Err(_)` on database error.
    ///
    /// Phase 2 §2.2 — `RequestCryptoSessionReset` handler.
    ///
    /// Opens a single Postgres tx, dispatches to
    /// [`super::reset_chokepoint::request_crypto_session_reset_tx`], commits.
    /// Idempotent on `idempotency_key`; safe to retry.
    async fn handle_request_crypto_session_reset(
        &mut self,
        trigger: ResetTrigger,
        initiator_did: String,
        reason: String,
        idempotency_key: String,
        expected_new_mls_group_id: Option<String>,
    ) -> anyhow::Result<ResetRequest> {
        use anyhow::Context;
        let mut tx = self
            .db_pool
            .begin()
            .await
            .context("begin RequestCryptoSessionReset tx")?;
        let outcome = super::reset_chokepoint::request_crypto_session_reset_tx(
            &mut tx,
            &self.convo_id,
            trigger,
            &initiator_did,
            &reason,
            &idempotency_key,
            expected_new_mls_group_id.as_deref(),
            // Direct callers (Admin, Bootstrap via the message API) do
            // NOT broadcast a `ResetRequestedEvent` SSE — that's only
            // emitted by the indirect-trigger `dual_emit_reset_requested`
            // path. Pass `None` so the chokepoint skips the in-tx
            // event_stream insert.
            None,
        )
        .await?;
        tx.commit()
            .await
            .context("commit RequestCryptoSessionReset tx")?;

        info!(
            convo_id = %crate::crypto::redact_for_log(&self.convo_id),
            request_id = %outcome.request.request_id,
            trigger = %trigger.as_str(),
            "crypto_session_reset_requested"
        );

        // Direct callers (Admin, Bootstrap via the message API) only
        // need the public `ResetRequest`; the `crypto_session_id` /
        // `generation` / `request_event_id` fields of the outcome are
        // for the `dual_emit_reset_requested` SSE-broadcast path.
        Ok(outcome.request)
    }

    /// Phase 2 §2.2 — `ActivateCryptoSession` handler.
    ///
    /// Single-tx core in
    /// [`super::reset_chokepoint::activate_crypto_session_tx`]; this method
    /// commits, then handles the post-commit concerns: in-memory state
    /// reset (preserving `unread_counts` per spec §2.2 step 10) and SSE
    /// `GroupResetEvent` emission.
    #[allow(clippy::too_many_arguments)]
    async fn handle_activate_crypto_session(
        &mut self,
        reset_request_id: Option<String>,
        trigger: ResetTrigger,
        new_mls_group_id: String,
        new_group_info: Option<Vec<u8>>,
        welcomes: Vec<WelcomeEnvelope>,
        initiator_did: String,
        idempotency_key: String,
    ) -> anyhow::Result<crate::models::CryptoSession> {
        use anyhow::Context;
        let mut tx = self
            .db_pool
            .begin()
            .await
            .context("begin ActivateCryptoSession tx")?;
        let result = super::reset_chokepoint::activate_crypto_session_tx(
            &mut tx,
            &self.convo_id,
            reset_request_id.as_deref(),
            trigger,
            &new_mls_group_id,
            new_group_info.as_deref(),
            &welcomes,
            &initiator_did,
            &idempotency_key,
            // codex P1 fix: ask the chokepoint to persist a
            // `groupResetEvent` event_stream row in-tx so reconnecting
            // SSE clients (cursor replay) and the live broadcast both
            // see the SAME cursor. The pre-fix code did `store_event`
            // post-commit, leaving a SIGKILL window where the row was
            // claimed `done` by the worker without anything reaching
            // event_stream.
            Some(super::reset_chokepoint::SseEventKind::GroupReset),
        )
        .await?;
        // Always commit, even on tie-break loss — the chokepoint persists
        // a `failed` crypto_sessions row + `crypto_session_candidate_rejected`
        // delivery_event for audit, and rolling back would discard them.
        tx.commit()
            .await
            .context("commit ActivateCryptoSession tx")?;

        let outcome = match result {
            super::reset_chokepoint::ActivationResult::Won(o) => o,
            super::reset_chokepoint::ActivationResult::CachedReplay(o) => {
                // bug_016 (ultrareview): retry of a prior idempotent
                // activation. The session is fully persisted from the
                // first call; we MUST NOT re-emit SSE GroupResetEvent or
                // re-clobber `self.current_epoch` (which may have already
                // advanced via subsequent commits). Just return the
                // cached session to the caller — handler still gets the
                // same response shape, but the actor side effects from
                // the original Won path don't repeat.
                info!(
                    convo_id = %crate::crypto::redact_for_log(&self.convo_id),
                    new_session_id = %o.session.id,
                    generation = o.generation,
                    trigger = %trigger.as_str(),
                    "ActivateCryptoSession cached replay (no side effects re-fired)"
                );
                return Ok(o.session);
            }
            super::reset_chokepoint::ActivationResult::Lost {
                attempted_generation,
                proposed_mls_group_id,
            } => {
                info!(
                    convo_id = %crate::crypto::redact_for_log(&self.convo_id),
                    attempted_generation,
                    proposed_mls_group_id = %crate::crypto::redact_for_log(&proposed_mls_group_id),
                    trigger = %trigger.as_str(),
                    "crypto_session_candidate_rejected (tie-break loss persisted)"
                );
                return Err(anyhow::anyhow!(
                    "ActivateCryptoSession tie-break lost: another candidate won generation {attempted_generation}"
                ));
            }
        };

        // Post-commit in-memory reset. Per plan §2.2 step 10: update epoch
        // for the new session; DO NOT clear `unread_counts` — those are
        // app data, not crypto state.
        self.current_epoch = 0;

        // codex P1 fix: chokepoint persisted the `groupResetEvent`
        // event_stream row in-tx. We just broadcast the SAME event
        // (with the chokepoint-allocated cursor) for the in-memory
        // fanout; reconnecting subscribers see the same row via
        // cursor-replay, deduped by the `replayed_cursors` HashSet
        // in subscribe_convo_events.
        if let Some(event) = outcome.sse_event.clone() {
            if let Err(e) = self.sse_state.emit(&self.convo_id, event).await {
                error!("[actor:activate_crypto_session] SSE emit GroupReset: {}", e);
            }
        } else {
            // Defense-in-depth: if the chokepoint returned no event
            // despite us asking for `SseEventKind::GroupReset`, that's
            // a bug in the chokepoint contract — log loudly so it's
            // visible in ops, but don't synthesize a fallback (which
            // would clobber the in-tx row's cursor and break the
            // dedupe invariant).
            error!(
                convo_id = %crate::crypto::redact_for_log(&self.convo_id),
                "[actor:activate_crypto_session] chokepoint did not return \
                 sse_event despite SseEventKind::GroupReset — live broadcast skipped"
            );
        }

        info!(
            convo_id = %crate::crypto::redact_for_log(&self.convo_id),
            new_session_id = %outcome.session.id,
            generation = outcome.generation,
            trigger = %trigger.as_str(),
            "crypto_session_activated"
        );

        Ok(outcome.session)
    }

    /// Phase 2.5 §5 Stage 1 — dual-emit `RequestCryptoSessionReset` for
    /// indirect callers that today still mint via `do_reset_group`.
    ///
    /// Indirect callers (quorum vote, system sweep, inline 409, inline
    /// 404) cast `TriggerSystemReset` / call `do_reset_group` because
    /// they don't have MLS material in hand at trigger time. Phase 2.5
    /// adds a parallel path: BEFORE `do_reset_group` runs, emit a
    /// `crypto_session_reset_requested` delivery event with
    /// `expected_new_mls_group_id = None` and broadcast a
    /// `resetRequestedEvent` SSE event to subscribed clients. An elected
    /// client may respond by submitting new MLS material via the
    /// existing `bootstrap_reset_group` / `commit_group_change`
    /// endpoints, which route to `ActivateCryptoSession` and tie-break
    /// via the `UNIQUE (conversation_id, generation)` constraint.
    ///
    /// Stage 1 keeps the legacy `do_reset_group` path running so
    /// unmodified clients still see `groupResetEvent` and reconnect
    /// behavior is unchanged. The dual-emit is the on-ramp; Stage 3
    /// retires the legacy path once telemetry shows zero clients depend
    /// on it.
    ///
    /// **Errors are logged, not returned**: if dual-emit fails, the
    /// caller still proceeds to legacy `do_reset_group`. The Phase 2.5
    /// path is opt-in for clients; a missing Request is a degraded
    /// telemetry signal, not a correctness break.
    ///
    /// **Feature flag**: `EMIT_RESET_REQUESTED_EVENT` env var (default
    /// `true`). When `false`, the SSE broadcast is skipped — but the
    /// chokepoint Request still runs and the `crypto_session_reset_
    /// requested` delivery event is still persisted. The flag isolates
    /// client-rollout impact from server-side rotation correctness.
    async fn dual_emit_reset_requested(
        &self,
        trigger: ResetTrigger,
        initiator_did: &str,
        reason: &str,
        idempotency_key: &str,
    ) {
        use anyhow::Context;

        let mut tx = match self
            .db_pool
            .begin()
            .await
            .context("dual_emit_reset_requested begin tx")
        {
            Ok(t) => t,
            Err(e) => {
                error!(
                    convo_id = %crate::crypto::redact_for_log(&self.convo_id),
                    trigger = %trigger.as_str(),
                    error = %e,
                    "[dual_emit_reset_requested] begin tx failed; \
                     legacy do_reset_group path will still fire"
                );
                return;
            }
        };

        // Phase 2.5 review-fix G3: capture the chokepoint outcome
        // directly. Previously we returned just `ResetRequest` and then
        // re-queried `crypto_sessions` + `delivery_events` post-commit
        // to gather `(crypto_session_id, generation, request_event_id)`
        // for the SSE payload — two extra round-trips. The chokepoint
        // now returns these in-tx via `ResetRequestOutcome`.
        //
        // Phase 3 codex P1 fix: when `EMIT_RESET_REQUESTED_EVENT=true`
        // (the default), pass a `SseEventKind::ResetRequested` intent
        // so the chokepoint persists the matching `event_stream` row
        // INSIDE the same tx as the delivery_event. Live broadcast
        // post-commit uses the event the chokepoint returns (cursor
        // already populated). The env-var kill-switch path passes
        // `None` so neither the in-tx event_stream row nor the live
        // broadcast happens — the chokepoint Request itself still
        // persists, matching Phase 2.5 §7 R2 semantics.
        //
        // Phase 2.5 review-fix G4: env-var read cached via OnceLock;
        // see `emit_reset_requested_event` doc-comment.
        let sse_intent = if emit_reset_requested_event() {
            Some(super::reset_chokepoint::SseEventKind::ResetRequested {
                reason: reason.to_string(),
            })
        } else {
            None
        };

        let outcome = match super::reset_chokepoint::request_crypto_session_reset_tx(
            &mut tx,
            &self.convo_id,
            trigger,
            initiator_did,
            reason,
            idempotency_key,
            None, // expected_new_mls_group_id — indirect triggers don't know yet
            sse_intent,
        )
        .await
        {
            Ok(o) => o,
            Err(e) => {
                let _ = tx.rollback().await;
                warn!(
                    convo_id = %crate::crypto::redact_for_log(&self.convo_id),
                    trigger = %trigger.as_str(),
                    idempotency_key = %idempotency_key,
                    error = %e,
                    "[dual_emit_reset_requested] chokepoint Request failed; \
                     legacy do_reset_group path will still fire"
                );
                return;
            }
        };

        if let Err(e) = tx.commit().await {
            error!(
                convo_id = %crate::crypto::redact_for_log(&self.convo_id),
                trigger = %trigger.as_str(),
                error = %e,
                "[dual_emit_reset_requested] commit tx failed; \
                 legacy do_reset_group path will still fire"
            );
            return;
        }

        info!(
            convo_id = %crate::crypto::redact_for_log(&self.convo_id),
            request_id = %outcome.request.request_id,
            crypto_session_id = %crate::crypto::redact_for_log(&outcome.crypto_session_id),
            generation = outcome.generation,
            trigger = %trigger.as_str(),
            phase_2_5_path = "dual_emit",
            "[dual_emit_reset_requested] crypto_session_reset_requested persisted"
        );

        // codex P1 fix: chokepoint persisted the event_stream row in-tx
        // when an `SseEventKind::ResetRequested` intent was supplied.
        // Take that returned event (cursor populated) and broadcast.
        // When the kill-switch suppressed the broadcast, `outcome.sse_event`
        // is `None` and we skip the broadcast — Request was still
        // persisted, matching the prior behavior.
        let Some(event) = outcome.sse_event else {
            // Either kill-switch is on (emit_reset_requested_event() ==
            // false above) or the chokepoint hit an idempotent-replay /
            // short-circuit path. In all of these the prior call
            // already drove the broadcast, so we MUST NOT re-emit.
            info!(
                convo_id = %crate::crypto::redact_for_log(&self.convo_id),
                request_id = %outcome.request.request_id,
                "[dual_emit_reset_requested] no sse_event returned \
                 (kill-switch or idempotent replay) — broadcast suppressed"
            );
            return;
        };

        if let Err(e) = self.sse_state.emit(&self.convo_id, event).await {
            error!(
                convo_id = %crate::crypto::redact_for_log(&self.convo_id),
                error = %e,
                "[dual_emit_reset_requested] SSE emit failed"
            );
        }
    }

    // TODO(post-#12): funnel through RequestCryptoSessionReset once the
    // elected-client flow ships. This legacy path stays wired to its
    // existing callers (handle_record_reset_vote quorum, handle_trigger_
    // system_reset sweep) until #12 lands a way for clients to respond
    // to a request-only reset. Funneling earlier would either (a) break
    // the API shape of report_recovery_failure (new_group_id: None)
    // or (b) leave indirect-trigger conversations unable to rotate
    // their group_id server-side, since neither path has client
    // material at trigger time. Direct/admin/bootstrap flows funnel
    // through ActivateCryptoSession in `reset_chokepoint.rs` already.
    //
    // This is also the only legacy site still clearing `unread_counts`
    // on reset (line 1933 below). The new chokepoint preserves them
    // per plan §2.2 step 10. Behavior converges when this method is
    // retired.
    async fn do_reset_group(
        &mut self,
        last_reset_by: &str,
        event_reason: &str,
        _staleness_epochs: Option<i64>,
        _quiet_duration_secs: Option<i64>,
    ) -> anyhow::Result<Option<(String, i32)>> {
        use anyhow::Context;

        let new_group_id = format!("{:032x}", uuid::Uuid::new_v4().as_u128());
        let mut tx = self
            .db_pool
            .begin()
            .await
            .context("begin reset tx failed")?;

        let cipher_suite: Option<String> =
            sqlx::query_scalar("SELECT cipher_suite FROM conversations WHERE id = $1")
                .bind(&self.convo_id)
                .fetch_optional(&mut *tx)
                .await
                .context("select cipher_suite failed")?;

        let reset_count: Option<i32> = sqlx::query_scalar(
            "UPDATE conversations SET \
                group_id = $1, current_epoch = 0, \
                group_info = NULL, group_info_epoch = NULL, \
                group_info_updated_at = NULL, \
                confirmation_tag = NULL, \
                reset_count = reset_count + 1, \
                last_reset_at = NOW(), \
                last_reset_by = $3, \
                recent_commit_409_count = 0, \
                recent_groupinfo_404_count = 0, \
                updated_at = NOW() \
             WHERE id = $2 \
             RETURNING reset_count",
        )
        .bind(&new_group_id)
        .bind(&self.convo_id)
        .bind(last_reset_by)
        .fetch_optional(&mut *tx)
        .await
        .context("update conversations failed")?;

        let reset_count = match reset_count {
            Some(rc) => rc,
            None => {
                tx.rollback().await.ok();
                return Ok(None);
            }
        };

        // Phase 2.5 §5 Stage 1 generation-invariant patch (R4): INSERT a
        // parallel crypto_sessions row mirroring the rotation. Without
        // this, any conversation that goes through legacy do_reset_group
        // followed by a Phase-2.5 chokepoint reset would compute
        // `next_generation = prev.generation + 1` from the stale prior
        // (the row before this legacy reset), producing a UNIQUE
        // violation on `(conversation_id, generation)` at the chokepoint.
        // Removed in Stage 3 when do_reset_group itself is retired.
        //
        // Steps:
        //   1. Read current active (or reset_requested, after dual-emit
        //      from indirect-trigger Request) crypto_session row to get
        //      `prior.id` for supersedes_id link.
        //   2. INSERT new crypto_sessions row at generation = reset_count
        //      (post-UPDATE value), state='active'. Mirrors the
        //      activation-tx INSERT shape from
        //      `reset_chokepoint::activate_crypto_session_tx`.
        //   3. UPDATE prior session state='superseded' covering
        //      ('active', 'reset_requested', 'superseding') so the
        //      dual-emit Phase-2.5 path (which leaves the prior in
        //      'reset_requested') is also handled.
        //   4. UPDATE conversations.active_crypto_session_id pointer.
        //
        // No delivery_events emitted from here — the legacy SSE
        // GroupResetEvent emission below is the audit signal. Stage 3
        // moves all rotation events into the chokepoint.
        let prior_session: Option<(String, i32)> = sqlx::query_as(
            "SELECT id, generation FROM crypto_sessions \
             WHERE conversation_id = $1 \
               AND state IN ('active', 'reset_requested', 'superseding') \
             ORDER BY generation DESC \
             LIMIT 1 \
             FOR UPDATE",
        )
        .bind(&self.convo_id)
        .fetch_optional(&mut *tx)
        .await
        .context("read prior crypto_session for legacy do_reset_group rotation")?;

        let new_crypto_session_id = uuid::Uuid::new_v4().to_string();
        let prior_session_id_opt: Option<String> =
            prior_session.as_ref().map(|(id, _g)| id.clone());

        sqlx::query(
            "INSERT INTO crypto_sessions ( \
                id, conversation_id, generation, mls_group_id, state, \
                supersedes_id, cipher_suite, last_observed_epoch, \
                created_by_did, created_at, activated_at \
             ) VALUES ($1, $2, $3, $4, 'active', $5, $6, 0, $7, NOW(), NOW())",
        )
        .bind(&new_crypto_session_id)
        .bind(&self.convo_id)
        .bind(reset_count)
        .bind(&new_group_id)
        .bind(prior_session_id_opt.as_deref())
        .bind(cipher_suite.as_deref())
        .bind(last_reset_by)
        .execute(&mut *tx)
        .await
        .context(
            "INSERT new crypto_session for legacy do_reset_group rotation \
             (Phase 2.5 generation-invariant patch)",
        )?;

        if let Some((prior_id, _prior_gen)) = prior_session.as_ref() {
            sqlx::query(
                "UPDATE crypto_sessions \
                 SET state = 'superseded', \
                     superseded_at = NOW(), \
                     superseded_by_id = $2 \
                 WHERE id = $1 \
                   AND state IN ('active', 'reset_requested', 'superseding')",
            )
            .bind(prior_id)
            .bind(&new_crypto_session_id)
            .execute(&mut *tx)
            .await
            .context("supersede prior crypto_session in legacy do_reset_group")?;
        }

        // Forward the conversations.active_crypto_session_id pointer.
        // The earlier UPDATE conversations clause set the legacy MLS
        // columns but predates the Phase-2 pointer column, so this is
        // a separate UPDATE.
        sqlx::query("UPDATE conversations SET active_crypto_session_id = $1 WHERE id = $2")
            .bind(&new_crypto_session_id)
            .bind(&self.convo_id)
            .execute(&mut *tx)
            .await
            .context("UPDATE conversations.active_crypto_session_id in legacy do_reset_group")?;

        sqlx::query("DELETE FROM welcome_messages WHERE convo_id = $1")
            .bind(&self.convo_id)
            .execute(&mut *tx)
            .await
            .context("delete welcome_messages failed")?;
        sqlx::query("DELETE FROM pending_device_additions WHERE convo_id = $1")
            .bind(&self.convo_id)
            .execute(&mut *tx)
            .await
            .context("delete pending_device_additions failed")?;
        sqlx::query("DELETE FROM reset_votes WHERE convo_id = $1")
            .bind(&self.convo_id)
            .execute(&mut *tx)
            .await
            .context("delete reset_votes failed")?;

        // Hotfix: fill member_count from the active members roster on
        // INSERT so the system-trigger path (sweep, inline 409, inline
        // 404) doesn't write `member_count=0` rows. The quorum path
        // (`handle_record_reset_vote`) UPDATEs member_count post-insert
        // with its own measurement; either source produces the same
        // count for active members because both filter on `left_at IS
        // NULL`. vote_count remains 0 here — system triggers bypass
        // quorum, so 0 is the correct semantic value, not a placeholder.
        sqlx::query(
            "INSERT INTO auto_reset_history \
                (convo_id, reset_triggered_at, triggered_by, new_group_id, \
                 vote_count, member_count) \
             VALUES ($1, NOW(), $2, $3, $4, \
                 (SELECT COUNT(*)::int FROM members \
                  WHERE convo_id = $1 AND left_at IS NULL))",
        )
        .bind(&self.convo_id)
        .bind(last_reset_by)
        .bind(&new_group_id)
        .bind(0_i32)
        .execute(&mut *tx)
        .await
        .context("insert auto_reset_history failed")?;

        tx.commit().await.context("commit reset tx failed")?;

        // Reset in-memory state so the next SendMessage through this actor
        // advances from epoch 0 rather than the stale pre-reset epoch.
        self.current_epoch = 0;
        self.unread_counts.clear();

        // Emit SSE GroupResetEvent.
        let cursor = self
            .sse_state
            .cursor_gen
            .next(&self.convo_id, "groupResetEvent")
            .await;
        let event = StreamEvent::GroupResetEvent {
            cursor: cursor.clone(),
            convo_id: self.convo_id.clone(),
            new_group_id: new_group_id.clone(),
            reset_generation: reset_count,
            reset_by: last_reset_by.to_string(),
            cipher_suite: cipher_suite.unwrap_or_default(),
            reason: Some(event_reason.to_string()),
        };
        if let Err(e) = crate::db::store_event(&self.db_pool, &self.convo_id, &event).await {
            error!("[actor:do_reset_group] store GroupResetEvent: {:?}", e);
        }
        if let Err(e) = self.sse_state.emit(&self.convo_id, event).await {
            error!("[actor:do_reset_group] SSE emit GroupReset: {}", e);
        }

        // Spec invariant: post-reset rows must have group_info=NULL until a
        // bootstrapResetGroup call populates it.
        info!(
            convo_id = %crate::crypto::redact_for_log(&self.convo_id),
            group_info_present = false,
            "A7 post-reset state"
        );

        Ok(Some((new_group_id, reset_count)))
    }
}

/// Helper function to handle serialized notification delivery (Push + SSE + Envelopes)
/// This is called sequentially by the background worker.
async fn handle_notify_new_message(
    pool: &sqlx::PgPool,
    sse_state: &SseState,
    broadcaster_pool: &BroadcasterPool,
    notification_service: Option<&crate::notifications::NotificationService>,
    convo_id: &str,
    msg_id: &str,
    sender_did: &str,
    ciphertext: &[u8],
    seq: i64,
    epoch: i64,
    is_ephemeral: bool,
) {
    let fanout_start = std::time::Instant::now();

    // 1. Fan-out (Envelopes) - Skip for ephemeral
    if !is_ephemeral {
        let members_result = sqlx::query_scalar::<_, String>(
            "SELECT member_did FROM members WHERE convo_id = $1 AND left_at IS NULL",
        )
        .bind(convo_id)
        .fetch_all(pool)
        .await;

        match members_result {
            Ok(member_dids) => {
                if let Err(e) = broadcaster_pool
                    .fanout_envelopes(convo_id, msg_id, member_dids, Some(sender_did))
                    .await
                {
                    error!("❌ [actor:worker] Failed to fan out envelopes: {:?}", e);
                } else {
                    let fanout_duration = fanout_start.elapsed();
                    crate::metrics::record_envelope_write_duration(convo_id, fanout_duration);
                }
            }
            Err(e) => {
                error!("❌ [actor:worker] Failed to get members: {:?}", e);
            }
        }
    }

    // 2. SSE Emission
    let cursor = sse_state.cursor_gen.next(convo_id, "messageEvent").await;

    let message_view: StreamMessageView = crate::generated::blue_catbird::mlsChat::MessageView {
        id: msg_id.to_string().into(),
        convo_id: convo_id.to_string().into(),
        ciphertext: bytes::Bytes::from(ciphertext.to_vec()),
        epoch,
        seq,
        created_at: crate::sqlx_jacquard::chrono_to_datetime(chrono::Utc::now()),
        message_type: Some("app".into()),
        extra_data: Default::default(),
    };

    let event = StreamEvent::MessageEvent {
        cursor: cursor.clone(),
        message: message_view,
        ephemeral: is_ephemeral,
    };

    if !is_ephemeral {
        if let Err(e) = crate::db::store_event(pool, convo_id, &event).await {
            error!("❌ [actor:worker] Failed to store event: {:?}", e);
        }
    }

    if let Err(e) = sse_state.emit(convo_id, event).await {
        error!("❌ [actor:worker] Failed to emit SSE event: {}", e);
    }

    // 3. Push Notifications (Serialized!)
    if !is_ephemeral {
        if let Some(ns) = notification_service {
            // This await is CRITICAL. It ensures we don't start the next push
            // until this one (and its internal retries) is done.
            if let Err(e) = ns
                .notify_new_message(pool, convo_id, msg_id, ciphertext, sender_did, seq, epoch)
                .await
            {
                error!("❌ [actor:worker] Failed to send push notifications: {}", e);
            }
        }
    }
}

async fn handle_notify_system_message(
    pool: &sqlx::PgPool,
    sse_state: &SseState,
    broadcaster_pool: &BroadcasterPool,
    convo_id: &str,
    msg_id: &str,
    _message_type: &str,
) {
    // For commits, we just need to ensure envelopes and SSE are sent.
    // We don't typically send push for commits unless they are important?
    // For now, mirroring legacy behavior which is likely just SSE/Envelopes.

    let members_result = sqlx::query_scalar::<_, String>(
        "SELECT member_did FROM members WHERE convo_id = $1 AND left_at IS NULL",
    )
    .bind(convo_id)
    .fetch_all(pool)
    .await;

    if let Ok(member_dids) = members_result {
        if let Err(e) = broadcaster_pool
            .fanout_envelopes(convo_id, msg_id, member_dids, None)
            .await
        {
            error!(
                "❌ [actor:worker] Failed to fan out system message envelopes: {:?}",
                e
            );
        }
    }

    // 2. SSE — fetch the commit message row and emit it to live subscribers
    let msg_row = sqlx::query_as::<_, (Vec<u8>, i32, i64, chrono::DateTime<chrono::Utc>)>(
        "SELECT ciphertext, epoch, seq, created_at FROM messages WHERE id = $1",
    )
    .bind(msg_id)
    .fetch_optional(pool)
    .await;

    match msg_row {
        Ok(Some((ciphertext, epoch, seq, created_at))) => {
            let cursor = sse_state.cursor_gen.next(convo_id, "messageEvent").await;

            let message_view: StreamMessageView =
                crate::generated::blue_catbird::mlsChat::MessageView {
                    id: msg_id.to_string().into(),
                    convo_id: convo_id.to_string().into(),
                    ciphertext: bytes::Bytes::from(ciphertext),
                    epoch: epoch.into(),
                    seq,
                    created_at: crate::sqlx_jacquard::chrono_to_datetime(created_at),
                    message_type: Some(_message_type.to_string().into()),
                    extra_data: Default::default(),
                };

            let event = StreamEvent::MessageEvent {
                cursor: cursor.clone(),
                message: message_view,
                ephemeral: false,
            };

            if let Err(e) = crate::db::store_event(pool, convo_id, &event).await {
                error!("❌ [actor:worker] Failed to store system event: {:?}", e);
            }

            if let Err(e) = sse_state.emit(convo_id, event).await {
                error!(
                    "❌ [actor:worker] Failed to emit system message SSE event: {}",
                    e
                );
            }
        }
        Ok(None) => {
            error!(
                "❌ [actor:worker] System message {} not found in DB",
                msg_id
            );
        }
        Err(e) => {
            error!(
                "❌ [actor:worker] Failed to fetch system message {}: {:?}",
                msg_id, e
            );
        }
    }
}
