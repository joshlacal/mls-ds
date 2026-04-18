use anyhow::Result;
use tokio::sync::oneshot;

/// Messages that can be sent to a [`ConversationActor`].
///
/// These messages define the protocol for interacting with conversation actors.
/// Each message variant corresponds to a specific operation on a conversation,
/// such as adding members, sending messages, or querying state.
///
/// # Message Patterns
///
/// - **Request-Reply**: Messages with a `reply` field expect a response via oneshot channel
/// - **Fire-and-Forget**: Messages without `reply` (e.g., [`ConvoMessage::Shutdown`]) don't send responses
///
/// # Ordering Guarantees
///
/// All messages to a single actor are processed sequentially in the order received.
/// This ensures operations like epoch increments are atomic and consistent.
///
/// # Examples
///
/// ```no_run
/// use tokio::sync::oneshot;
///
/// # async fn example(actor_ref: &ActorRef<ConvoMessage>) -> anyhow::Result<()> {
/// // Send a request-reply message
/// let (tx, rx) = oneshot::channel();
/// actor_ref.send_message(ConvoMessage::GetEpoch { reply: tx })?;
/// let epoch = rx.await?;
///
/// // Send a fire-and-forget message
/// actor_ref.cast(ConvoMessage::Shutdown)?;
/// # Ok(())
/// # }
/// ```
///
/// [`ConversationActor`]: super::conversation::ConversationActor
#[derive(Debug)]
pub enum ConvoMessage {
    /// Adds new members to the conversation.
    ///
    /// This is an epoch-incrementing operation that:
    /// - Adds members to the conversation roster
    /// - Stores the MLS Commit message
    /// - Delivers Welcome messages to new members
    ///
    /// # Fields
    ///
    /// - `did_list`: DIDs of members to add
    /// - `commit`: Optional MLS Commit message bytes
    /// - `welcome_message`: Optional base64-encoded Welcome message
    /// - `key_package_hashes`: Optional key package hashes for each new member
    /// - `reply`: Channel to receive the new epoch number
    AddMembers {
        did_list: Vec<String>,
        commit: Option<Vec<u8>>,
        welcome_message: Option<String>,
        key_package_hashes: Option<Vec<KeyPackageHashEntry>>,
        reply: oneshot::Sender<Result<u32>>,
    },

    /// Removes a member from the conversation.
    ///
    /// This is an epoch-incrementing operation that:
    /// - Soft-deletes the member (sets `left_at` timestamp)
    /// - Stores the MLS Commit message
    /// - Updates the conversation roster
    ///
    /// # Fields
    ///
    /// - `member_did`: DID of the member to remove
    /// - `commit`: Optional MLS Commit message bytes
    /// - `reply`: Channel to receive the new epoch number
    RemoveMember {
        member_did: String,
        commit: Option<Vec<u8>>,
        reply: oneshot::Sender<Result<u32>>,
    },

    /// Sends an encrypted application message to the conversation.
    ///
    /// This operation:
    /// - Stores the encrypted message with a sequence number and privacy-enhancing fields
    /// - Implements deduplication via msg_id and idempotency_key
    /// - Updates unread counts for all members except the sender
    /// - Fans out message envelopes to all active members
    ///
    /// # Fields
    ///
    /// - `sender_did`: DID of the message sender
    /// - `ciphertext`: Encrypted message bytes
    /// - `msg_id`: Client-provided ULID/UUID for message deduplication
    /// - `epoch`: Client's epoch number when message was encrypted
    /// - `padded_size`: Padded ciphertext size for metadata privacy
    /// - `idempotency_key`: Optional key for backward-compatible deduplication
    /// - `reply`: Channel to receive (message_id, timestamp) tuple
    SendMessage {
        sender_did: String,
        ciphertext: Vec<u8>,
        msg_id: String,
        epoch: i64,
        padded_size: i64,
        idempotency_key: Option<String>,
        reply: oneshot::Sender<Result<(String, chrono::DateTime<chrono::Utc>)>>,
    },

    /// Increments unread counts for all members except the sender.
    ///
    /// This is a fire-and-forget operation used for optimistic unread tracking.
    /// Counts are batched and periodically synced to the database.
    ///
    /// # Fields
    ///
    /// - `sender_did`: DID of the message sender (excluded from increment)
    IncrementUnread { sender_did: String },

    /// Resets the unread count for a specific member to zero.
    ///
    /// This operation immediately updates both the in-memory count and the
    /// database, typically called when a member reads messages.
    ///
    /// # Fields
    ///
    /// - `member_did`: DID of the member whose count should be reset
    /// - `reply`: Channel to receive acknowledgment
    ResetUnread {
        member_did: String,
        reply: oneshot::Sender<Result<()>>,
    },

    /// Retrieves the current epoch number from actor state.
    ///
    /// This is a fast, read-only operation that doesn't touch the database.
    /// Useful for checking epoch before sending operations.
    ///
    /// # Fields
    ///
    /// - `reply`: Channel to receive the current epoch number
    GetEpoch { reply: oneshot::Sender<u32> },

    /// Records a recovery-failure vote from a device, with cryptographic proof
    /// of the claimed stuck state (ADR-002 §A7).
    ///
    /// This is the only permitted path for recovery-failure reporting. Direct
    /// PgPool writes to `reset_votes` / `recovery_failures` are forbidden per
    /// invariant E6.
    ///
    /// # Fields
    ///
    /// - `device_did`: The authenticating device's DID (from `AuthUser`)
    /// - `identity_did`: The user's MLS identity DID (resolved via `members.user_did`)
    /// - `epoch_authenticator`: Hex-encoded RFC 9420 §8.7 authenticator for the
    ///    reporter's current epoch
    /// - `failure_type`: Categorical failure reason (e.g. `external_commit_exhausted`)
    /// - `reply`: Channel to receive the vote-count + auto-reset decision
    RecordResetVote {
        device_did: String,
        identity_did: String,
        epoch_authenticator: String,
        failure_type: String,
        reply: oneshot::Sender<Result<RecordResetVoteOutcome>>,
    },

    /// Signals the actor to shut down gracefully.
    ///
    /// The actor will complete any in-flight operations before stopping.
    /// This is a fire-and-forget message.
    Shutdown,
}

/// Associates a DID with its corresponding key package hash.
///
/// Used when adding members to ensure the correct key package is consumed
/// for each new member. The hash is stored with the Welcome message to
/// prevent replay attacks.
///
/// # Fields
///
/// - `did`: Decentralized identifier of the member
/// - `hash`: Hex-encoded hash of the member's key package
#[derive(Debug, Clone)]
pub struct KeyPackageHashEntry {
    pub did: String,
    pub hash: String,
}

/// Outcome of a [`ConvoMessage::RecordResetVote`] operation (ADR-002 §A7.1).
///
/// Carries enough detail for the HTTP handler to produce a response body that
/// preserves backward compatibility with the existing `reportRecoveryFailure`
/// lexicon, plus a structured `reason` discriminator for telemetry and client
/// retry logic.
///
/// # Reason values
///
/// - `None` (with `recorded: true`) — vote counted successfully
/// - `Some("stale_authenticator")` — epoch_authenticator didn't match a recent
///   known-good record; not counted, not rate-limited
/// - `Some("missing_authenticator")` — client sent no authenticator (old client);
///   not counted, not rate-limited
/// - `Some("rate_limited")` — DID has already voted within the 24h window
/// - `Some("circuit_breaker")` — conversation has hit the 3-per-24h reset cap;
///   auto_reset_disabled_at is now set
#[derive(Debug, Clone)]
pub struct RecordResetVoteOutcome {
    /// Whether the vote was persisted to `reset_votes` and will count toward quorum.
    pub recorded: bool,
    /// Discriminator for why the vote was rejected (if any), or `None` on success.
    pub reason: Option<String>,
    /// Count of distinct `identity_did`s whose entire active device set has filed
    /// valid votes within the 1h expiry window.
    pub per_did_vote_count: i64,
    /// Count of distinct `identity_did`s in the conversation (active members).
    pub member_did_count: i64,
    /// Whether this vote tripped the quorum and caused an auto-reset.
    pub auto_reset_triggered: bool,
    /// If `auto_reset_triggered`, the new `group_id` assigned to the conversation.
    pub new_group_id: Option<String>,
    /// Lifetime reset count after the reset (cumulative, not rolling).
    pub reset_count: Option<i32>,
}
