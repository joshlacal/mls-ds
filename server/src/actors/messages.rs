use anyhow::Result;
use tokio::sync::oneshot;

use crate::models::CryptoSession;

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
    ///   reporter's current epoch
    /// - `failure_type`: Categorical failure reason (e.g. `external_commit_exhausted`)
    /// - `failure_mode`: ADR-008 D1 classification — `Some("local_state_loss")` (Mode A,
    ///   self-heal, SHOULD NOT count toward quorum), `Some("group_state_unrecoverable")`
    ///   (Mode B, counts toward quorum), or `None` (old client). When the
    ///   `ENFORCE_FAILURE_MODE_QUORUM` env var is true, only Mode B votes are counted.
    ///   Default behavior (false): all votes count regardless of mode. See spec §8.6.1.
    /// - `reply`: Channel to receive the vote-count + auto-reset decision
    RecordResetVote {
        device_did: String,
        identity_did: String,
        epoch_authenticator: String,
        failure_type: String,
        failure_mode: Option<String>,
        reply: oneshot::Sender<Result<RecordResetVoteOutcome>>,
    },

    /// Server-observed sweep trigger (Phase 2 §"Detection Design → Path B").
    ///
    /// Dispatched by the `auto_detect_failed_groups` sweep worker when a
    /// conversation matches all server-side staleness conditions (high
    /// recent_commit_409_count, stale last_successful_commit_at, large
    /// gap between current_epoch and group_info_epoch, no Mode A reports
    /// in the exclusion window). Bypasses quorum because the server has
    /// objectively observed the group is dead, but still respects the
    /// per-conversation circuit breaker (`auto_reset_disabled_at`) and
    /// rate limit (`MIN_RESET_GAP_SECS`).
    ///
    /// # Fields
    ///
    /// - `reason`: Trigger source label (e.g. `"server_sweep"`). Combined with
    ///   `"system:"` prefix to form `last_reset_by`.
    /// - `staleness_epochs`: Observed delta between `current_epoch` and
    ///   `group_info_epoch` at sweep time, for telemetry.
    /// - `quiet_duration_secs`: Observed seconds since `last_successful_commit_at`,
    ///   for telemetry.
    TriggerSystemReset {
        reason: String,
        staleness_epochs: i64,
        quiet_duration_secs: i64,
    },

    /// Phase 2 §2.2 — request that the conversation's current crypto_session
    /// be marked `reset_requested`, signalling clients that a repair is needed.
    ///
    /// Server cannot self-heal: it has no MLS group material. This message
    /// only marks state and emits a `crypto_session_reset_requested` event.
    /// Activation happens later when a client submits material via
    /// [`ConvoMessage::ActivateCryptoSession`].
    ///
    /// Idempotency: dedupes on `idempotency_key` against `delivery_events`.
    /// A duplicate retry returns the existing [`ResetRequest`] unchanged.
    ///
    /// **Idempotency-key namespacing**: callers MUST use distinct keys for
    /// request vs activate operations even from the same DID. The
    /// underlying UNIQUE on `(conversation_id, sender_did, sender_device_id,
    /// idempotency_key)` is shared across all event types, so reusing a
    /// key across operations produces a constraint violation, not a clean
    /// idempotency response. Recommended convention:
    /// `"req-reset:<uuid>"` for this variant; `"activate:<uuid>"` for
    /// [`Self::ActivateCryptoSession`].
    ///
    /// # Fields
    ///
    /// - `trigger`: which subsystem initiated the request
    /// - `initiator_did`: DID that triggered the request
    /// - `reason`: human-readable reason for the request (audit trail)
    /// - `idempotency_key`: unique-per-retry key for the request
    /// - `expected_new_mls_group_id`: bug_010 (ultrareview) — the
    ///   `mls_group_id` the requester expects the eventual activator to
    ///   submit. When `Some(_)`, the chokepoint persists this in the
    ///   `crypto_session_reset_requested` event payload and rejects
    ///   activation if the activator's `new_mls_group_id` doesn't
    ///   match. When `None`, no pre-binding (post-#12 elected-client
    ///   flow placeholder; quorum/sweep also pass `None` since they
    ///   don't know the id yet).
    /// - `reply`: channel to receive the [`ResetRequest`]
    RequestCryptoSessionReset {
        trigger: ResetTrigger,
        initiator_did: String,
        reason: String,
        idempotency_key: String,
        expected_new_mls_group_id: Option<String>,
        reply: oneshot::Sender<Result<ResetRequest>>,
    },

    /// Phase 2 §2.2 — activate a candidate crypto_session: a client has
    /// produced new MLS group material and is asking the server to mark it
    /// active.
    ///
    /// Tie-break: the `crypto_sessions UNIQUE (conversation_id, generation)`
    /// constraint serializes concurrent candidates. First INSERT with the
    /// next generation wins; later candidates are marked `failed` with a
    /// `crypto_session_candidate_rejected` event and their welcomes are NOT
    /// stored as pending.
    ///
    /// Idempotency: dedupes on `idempotency_key` against `delivery_events`.
    /// Duplicate retries return the same [`CryptoSession`]. Tie-break losers
    /// also persist their rejection event keyed on `idempotency_key`, so a
    /// retry of a losing key resolves to the same `Lost` outcome (surfaced
    /// to the caller as an error at the actor message boundary).
    ///
    /// **Idempotency-key namespacing**: callers MUST use distinct keys
    /// across request vs activate operations from the same DID. See
    /// [`Self::RequestCryptoSessionReset`] for the rationale.
    ///
    /// # Fields
    ///
    /// - `reset_request_id`: links to a prior [`ResetRequest`]; `None` for
    ///   admin/bootstrap direct flows where there is no prior request
    /// - `trigger`: which subsystem produced the candidate
    /// - `new_mls_group_id`: hex-encoded MLS group identifier of the candidate
    /// - `new_group_info`: serialized GroupInfo for external commit joins
    /// - `welcomes`: pending welcomes to insert if this candidate wins
    /// - `initiator_did`: DID that produced the material
    /// - `idempotency_key`: unique-per-retry key for the activation
    /// - `reply`: channel to receive the activated [`CryptoSession`]
    ActivateCryptoSession {
        reset_request_id: Option<String>,
        trigger: ResetTrigger,
        new_mls_group_id: String,
        new_group_info: Option<Vec<u8>>,
        welcomes: Vec<WelcomeEnvelope>,
        initiator_did: String,
        idempotency_key: String,
        reply: oneshot::Sender<Result<CryptoSession>>,
    },

    /// Signals the actor to shut down gracefully.
    ///
    /// The actor will complete any in-flight operations before stopping.
    /// This is a fire-and-forget message.
    Shutdown,
}

/// Subsystem that originated a crypto_session reset.
///
/// Used both for [`ConvoMessage::RequestCryptoSessionReset`] and
/// [`ConvoMessage::ActivateCryptoSession`] so audit log readers can
/// correlate the two halves.
///
/// # NULL-binding allowlist (Phase 2.5 §7 R1 Mitigation #1)
///
/// Only `QuorumVote`, `SystemSweep`, `InlineCommit409`, and
/// `InlineGroupInfo404` may emit a `RequestCryptoSessionReset` with
/// `expected_new_mls_group_id = None`. `Admin` and `Bootstrap` MUST
/// always supply `Some(_)`. Enforced at request time in
/// `request_crypto_session_reset_tx` via [`Self::permits_null_binding`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetTrigger {
    /// HTTP `reset_group.rs` admin call.
    Admin,
    /// Quorum vote from `RecordResetVote` reaching threshold.
    QuorumVote,
    /// Server sweep from `auto_detect_failed_groups` job.
    SystemSweep,
    /// `bootstrap_reset_group.rs` initial group bootstrap.
    Bootstrap,
    /// Phase 2.5 inline trigger: `recent_commit_409_count` crossed
    /// threshold via `record_commit_409_with_inline_trigger`.
    InlineCommit409,
    /// Phase 2.5 inline trigger: `recent_groupinfo_404_count` crossed
    /// threshold via `record_groupinfo_404_with_inline_trigger`.
    InlineGroupInfo404,
}

impl ResetTrigger {
    /// String form persisted to the `delivery_events.payload_json` for audit.
    pub fn as_str(self) -> &'static str {
        match self {
            ResetTrigger::Admin => "admin",
            ResetTrigger::QuorumVote => "quorum_vote",
            ResetTrigger::SystemSweep => "system_sweep",
            ResetTrigger::Bootstrap => "bootstrap",
            ResetTrigger::InlineCommit409 => "inline_commit_409",
            ResetTrigger::InlineGroupInfo404 => "inline_groupinfo_404",
        }
    }

    /// Whether this trigger is permitted to emit a
    /// `RequestCryptoSessionReset` with `expected_new_mls_group_id = None`.
    ///
    /// Phase 2.5 §7 R1 Mitigation #1. Indirect callers (quorum, sweep,
    /// inline triggers) don't know the new group_id at trigger time —
    /// they emit Requests with `None` and rely on an elected client
    /// responding via `bootstrap_reset_group` / `commit_group_change`
    /// to supply the material. The activation-time auth gate (R1 #3)
    /// requires the activator's DID to be in `payload_json
    /// .allowed_responders` snapshotted at Request time.
    ///
    /// `Admin` and `Bootstrap` are direct callers that MUST always
    /// supply a concrete `expected_new_mls_group_id`. Allowing them to
    /// pass `None` would let an admin emit an unbound Request that any
    /// member could race-bootstrap into.
    pub fn permits_null_binding(self) -> bool {
        matches!(
            self,
            ResetTrigger::QuorumVote
                | ResetTrigger::SystemSweep
                | ResetTrigger::InlineCommit409
                | ResetTrigger::InlineGroupInfo404
        )
    }
}

/// Returned from [`ConvoMessage::RequestCryptoSessionReset`] to the caller.
///
/// The `request_id` ties this request to a later
/// [`ConvoMessage::ActivateCryptoSession`] via its `reset_request_id` field.
#[derive(Debug, Clone)]
pub struct ResetRequest {
    pub request_id: String,
    pub conversation_id: String,
    pub initiator_did: String,
    pub reason: String,
}

/// MLS Welcome to deliver to a specific recipient device, queued to
/// `pending_welcomes` if the carrying candidate wins activation.
///
/// **Naming**: `recipient_did` is the in-memory field name; the persisted
/// column on `pending_welcomes` is `target_did` (legacy schema). Mapping
/// happens at the SQL boundary — see `activate_crypto_session_tx`.
#[derive(Debug, Clone)]
pub struct WelcomeEnvelope {
    pub recipient_did: String,
    pub recipient_device_id: Option<String>,
    pub welcome_data: Vec<u8>,
    pub key_package_hash: Option<String>,
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
