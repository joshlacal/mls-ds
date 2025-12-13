use async_trait::async_trait;
use ractor::{Actor, ActorProcessingErr, ActorRef};
use sqlx::PgPool;
use std::{collections::HashMap, sync::Arc};
use tracing::{debug, info};

use super::messages::{ConvoMessage, KeyPackageHashEntry};
use crate::realtime::{SseState, StreamEvent};

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
pub struct ConvoActorArgs {
    pub convo_id: String,
    pub db_pool: PgPool,
    pub sse_state: Arc<SseState>,
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

        Ok(ConversationActorState {
            convo_id: args.convo_id,
            current_epoch: current_epoch as u32,
            unread_counts: HashMap::new(),
            db_pool: args.db_pool,
            sse_state: args.sse_state,
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
            ConvoMessage::Shutdown => {
                info!("ConversationActor shutting down");
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

        let new_epoch = self.current_epoch + 1;
        let now = chrono::Utc::now();

        // Begin transaction for atomicity
        let mut tx = self
            .db_pool
            .begin()
            .await
            .context("Failed to begin transaction")?;

        // Process commit if provided (capture msg_id for later fanout)
        let commit_msg_id = if let Some(commit_bytes) = commit {
            let msg_id = uuid::Uuid::new_v4().to_string();

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
                "INSERT INTO messages (id, convo_id, sender_did, message_type, epoch, seq, ciphertext, created_at) VALUES ($1, $2, $3, 'commit', $4, $5, $6, $7)"
            )
            .bind(&msg_id)
            .bind(&self.convo_id)
            .bind("system") // Commit messages are system-generated
            .bind(new_epoch as i32)
            .bind(seq)
            .bind(&commit_bytes)
            .bind(&now)
            .execute(&mut *tx)
            .await
            .context("Failed to insert commit message")?;

            info!(
                "✅ [actor:add_members] Commit message stored with seq={}, epoch={}",
                seq, new_epoch
            );
            Some(msg_id)
        } else {
            None
        };

        // Update conversation epoch
        sqlx::query("UPDATE conversations SET current_epoch = $1 WHERE id = $2")
            .bind(new_epoch as i32)
            .bind(&self.convo_id)
            .execute(&mut *tx)
            .await
            .context("Failed to update conversation epoch")?;

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
            .bind(&now)
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
                .bind(&now)
                .execute(&mut *tx)
                .await
                .context(format!("Failed to store welcome message for {}", target_did))?;

                info!("Welcome stored for member");
            }
        }

        // Commit transaction
        tx.commit().await.context("Failed to commit transaction")?;

        // Fan out commit message to all members (if commit was provided)
        if let Some(msg_id) = commit_msg_id {
            let pool = self.db_pool.clone();
            let convo_id = self.convo_id.clone();
            let sse_state = self.sse_state.clone();

            tokio::spawn(async move {
                tracing::debug!("📍 [actor:add_members:fanout] starting commit fan-out");

                // Get all active members
                let members_result = sqlx::query_as::<_, (String,)>(
                    r#"
                    SELECT member_did
                    FROM members
                    WHERE convo_id = $1 AND left_at IS NULL
                    "#,
                )
                .bind(&convo_id)
                .fetch_all(&pool)
                .await;

                match members_result {
                    Ok(members) => {
                        tracing::debug!(
                            "📍 [actor:add_members:fanout] fan-out commit to {} members",
                            members.len()
                        );

                        // Create envelopes for each member
                        for (member_did,) in &members {
                            let envelope_id = uuid::Uuid::new_v4().to_string();

                            let envelope_result = sqlx::query(
                                r#"
                                INSERT INTO envelopes (id, convo_id, recipient_did, message_id, created_at)
                                VALUES ($1, $2, $3, $4, NOW())
                                ON CONFLICT (recipient_did, message_id) DO NOTHING
                                "#,
                            )
                            .bind(&envelope_id)
                            .bind(&convo_id)
                            .bind(member_did)
                            .bind(&msg_id)
                            .execute(&pool)
                            .await;

                            if let Err(e) = envelope_result {
                                tracing::error!(
                                    "❌ [actor:add_members:fanout] Failed to insert envelope for {}: {:?}",
                                    member_did, e
                                );
                            }
                        }

                        tracing::debug!("✅ [actor:add_members:fanout] envelopes created");
                    }
                    Err(e) => {
                        tracing::error!(
                            "❌ [actor:add_members:fanout] Failed to get members: {:?}",
                            e
                        );
                    }
                }

                tracing::debug!("📍 [actor:add_members:fanout] emitting SSE event for commit");
                // Emit SSE event for commit message
                let cursor = sse_state.cursor_gen.next(&convo_id, "messageEvent").await;

                // Fetch the full message from database
                let message_result = sqlx::query!(
                    r#"
                    SELECT id, sender_did, ciphertext, epoch, seq, created_at
                    FROM messages
                    WHERE id = $1
                    "#,
                    &msg_id
                )
                .fetch_one(&pool)
                .await;

                match message_result {
                    Ok(msg) => {
                        let message_view =
                            crate::models::MessageView::from(crate::models::MessageViewData {
                                id: msg.id,
                                convo_id: convo_id.clone(),
                                ciphertext: msg.ciphertext.unwrap_or_default(),
                                epoch: msg.epoch as usize,
                                seq: msg.seq as usize,
                                created_at: crate::sqlx_atrium::chrono_to_datetime(msg.created_at),
                                message_type: None,
                            });

                        let event = StreamEvent::MessageEvent {
                            cursor: cursor.clone(),
                            message: message_view.clone(),
                        };

                        // Store event for cursor-based SSE replay
                        if let Err(e) = crate::db::store_event(
                            &pool,
                            &cursor,
                            &convo_id,
                            "messageEvent",
                            Some(&msg_id),
                        )
                        .await
                        {
                            tracing::error!(
                                "❌ [actor:add_members:fanout] Failed to store event: {:?}",
                                e
                            );
                        }

                        if let Err(e) = sse_state.emit(&convo_id, event).await {
                            tracing::error!("Failed to emit SSE event: {}", e);
                        }
                        tracing::debug!("✅ [actor:add_members:fanout] SSE event emitted");
                    }
                    Err(e) => {
                        tracing::error!(
                            "❌ [actor:add_members:fanout] Failed to fetch message for SSE: {:?}",
                            e
                        );
                    }
                }
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

        let new_epoch = self.current_epoch + 1;
        let now = chrono::Utc::now();

        // Begin transaction for atomicity
        let mut tx = self
            .db_pool
            .begin()
            .await
            .context("Failed to begin transaction")?;

        // Process commit if provided (capture msg_id for later fanout)
        let commit_msg_id = if let Some(commit_bytes) = commit {
            let msg_id = uuid::Uuid::new_v4().to_string();

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
                "INSERT INTO messages (id, convo_id, sender_did, message_type, epoch, seq, ciphertext, created_at) VALUES ($1, $2, $3, 'commit', $4, $5, $6, $7)"
            )
            .bind(&msg_id)
            .bind(&self.convo_id)
            .bind(&member_did)
            .bind(new_epoch as i32)
            .bind(seq)
            .bind(&commit_bytes)
            .bind(&now)
            .execute(&mut *tx)
            .await
            .context("Failed to insert commit message")?;

            info!(
                "✅ [actor:remove_member] Commit message stored with seq={}, epoch={}",
                seq, new_epoch
            );
            Some(msg_id)
        } else {
            None
        };

        // Update conversation epoch
        sqlx::query("UPDATE conversations SET current_epoch = $1 WHERE id = $2")
            .bind(new_epoch as i32)
            .bind(&self.convo_id)
            .execute(&mut *tx)
            .await
            .context("Failed to update conversation epoch")?;

        // Mark member as left (soft delete with left_at timestamp)
        sqlx::query("UPDATE members SET left_at = $1 WHERE convo_id = $2 AND member_did = $3")
            .bind(&now)
            .bind(&self.convo_id)
            .bind(&member_did)
            .execute(&mut *tx)
            .await
            .context("Failed to mark member as left")?;

        // Commit transaction
        tx.commit().await.context("Failed to commit transaction")?;

        // Fan out commit message to all members (if commit was provided)
        if let Some(msg_id) = commit_msg_id {
            let pool = self.db_pool.clone();
            let convo_id = self.convo_id.clone();
            let sse_state = self.sse_state.clone();

            tokio::spawn(async move {
                tracing::debug!("📍 [actor:remove_member:fanout] starting commit fan-out");

                // Get all active members (including the one leaving, so they get the commit)
                let members_result = sqlx::query_as::<_, (String,)>(
                    r#"
                    SELECT member_did
                    FROM members
                    WHERE convo_id = $1 AND left_at IS NULL
                    "#,
                )
                .bind(&convo_id)
                .fetch_all(&pool)
                .await;

                match members_result {
                    Ok(members) => {
                        tracing::debug!(
                            "📍 [actor:remove_member:fanout] fan-out commit to {} members",
                            members.len()
                        );

                        // Create envelopes for each member
                        for (member_did,) in &members {
                            let envelope_id = uuid::Uuid::new_v4().to_string();

                            let envelope_result = sqlx::query(
                                r#"
                                INSERT INTO envelopes (id, convo_id, recipient_did, message_id, created_at)
                                VALUES ($1, $2, $3, $4, NOW())
                                ON CONFLICT (recipient_did, message_id) DO NOTHING
                                "#,
                            )
                            .bind(&envelope_id)
                            .bind(&convo_id)
                            .bind(member_did)
                            .bind(&msg_id)
                            .execute(&pool)
                            .await;

                            if let Err(e) = envelope_result {
                                tracing::error!(
                                    "❌ [actor:remove_member:fanout] Failed to insert envelope for {}: {:?}",
                                    member_did, e
                                );
                            }
                        }

                        tracing::debug!("✅ [actor:remove_member:fanout] envelopes created");
                    }
                    Err(e) => {
                        tracing::error!(
                            "❌ [actor:remove_member:fanout] Failed to get members: {:?}",
                            e
                        );
                    }
                }

                tracing::debug!("📍 [actor:remove_member:fanout] emitting SSE event for commit");
                // Emit SSE event for commit message
                let cursor = sse_state.cursor_gen.next(&convo_id, "messageEvent").await;

                // Fetch the full message from database
                let message_result = sqlx::query!(
                    r#"
                    SELECT id, sender_did, ciphertext, epoch, seq, created_at
                    FROM messages
                    WHERE id = $1
                    "#,
                    &msg_id
                )
                .fetch_one(&pool)
                .await;

                match message_result {
                    Ok(msg) => {
                        let message_view =
                            crate::models::MessageView::from(crate::models::MessageViewData {
                                id: msg.id,
                                convo_id: convo_id.clone(),
                                ciphertext: msg.ciphertext.unwrap_or_default(),
                                epoch: msg.epoch as usize,
                                seq: msg.seq as usize,
                                created_at: crate::sqlx_atrium::chrono_to_datetime(msg.created_at),
                                message_type: None,
                            });

                        let event = StreamEvent::MessageEvent {
                            cursor: cursor.clone(),
                            message: message_view.clone(),
                        };

                        // Store event for cursor-based SSE replay
                        if let Err(e) = crate::db::store_event(
                            &pool,
                            &cursor,
                            &convo_id,
                            "messageEvent",
                            Some(&msg_id),
                        )
                        .await
                        {
                            tracing::error!(
                                "❌ [actor:remove_member:fanout] Failed to store event: {:?}",
                                e
                            );
                        }

                        if let Err(e) = sse_state.emit(&convo_id, event).await {
                            tracing::error!("Failed to emit SSE event: {}", e);
                        }
                        tracing::debug!("✅ [actor:remove_member:fanout] SSE event emitted");
                    }
                    Err(e) => {
                        tracing::error!(
                            "❌ [actor:remove_member:fanout] Failed to fetch message for SSE: {:?}",
                            e
                        );
                    }
                }
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
        .bind(&sender_did)
        .bind(epoch)
        .bind(seq)
        .bind(&ciphertext)
        .bind(&now)
        .bind(&expires_at)
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

        // Spawn async task for fan-out (envelopes)
        let pool_clone = self.db_pool.clone();
        let convo_id = self.convo_id.clone();
        let msg_id_clone = msg_id.clone();

        tokio::spawn(async move {
            let fanout_start = std::time::Instant::now();
            debug!("Starting fan-out for conversation");

            // Get all active members
            let members_result = sqlx::query!(
                r#"
                SELECT member_did
                FROM members
                WHERE convo_id = $1 AND left_at IS NULL
                "#,
                &convo_id
            )
            .fetch_all(&pool_clone)
            .await;

            match members_result {
                Ok(members) => {
                    info!("Fan-out to {} members", members.len());

                    // Write envelopes for message tracking
                    for member in &members {
                        let envelope_id = uuid::Uuid::new_v4().to_string();

                        // Insert envelope
                        let envelope_result = sqlx::query!(
                            r#"
                            INSERT INTO envelopes (id, convo_id, recipient_did, message_id, created_at)
                            VALUES ($1, $2, $3, $4, NOW())
                            ON CONFLICT (recipient_did, message_id) DO NOTHING
                            "#,
                            &envelope_id,
                            &convo_id,
                            &member.member_did,
                            &msg_id_clone,
                        )
                        .execute(&pool_clone)
                        .await;

                        if let Err(e) = envelope_result {
                            tracing::error!(
                                "Failed to insert envelope for {}: {:?}",
                                member.member_did,
                                e
                            );
                        }
                    }

                    info!(
                        "Fan-out completed in {}ms",
                        fanout_start.elapsed().as_millis()
                    );
                }
                Err(e) => {
                    tracing::error!("Failed to get members for fan-out: {:?}", e);
                }
            }
        });

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
                    let is_sender_device =
                        user_did.as_ref().map_or(false, |uid| uid == &sender_did);
                    if !is_sender_device {
                        let count = self.unread_counts.entry(member_did.clone()).or_insert(0);
                        *count += 1;

                        // Optional: flush to database every N increments (e.g., every 10 messages)
                        if *count % 10 == 0 {
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
}
