//! Database models and jacquard-generated type re-exports
//!
//! These models map DB rows to API views using jacquard-generated types
//! with CowStr/Did/Datetime conversions.

use sqlx::FromRow;

// Chat request models (submodule)
pub mod chat_request;
pub use chat_request::{
    AcceptRequestInput, AcceptRequestOutput, ChatRequest, ChatRequestBuilder, ChatRequestParams,
    ChatRequestRateLimit, ChatRequestStatus, HeldMessage, HeldMessageBuilder, HeldMessageParams,
    ListRequestsInput, ListRequestsOutput, SendRequestInput, SendRequestOutput,
};

// Re-export generated types for convenience
//
// NOTE: `ConvoMetadata` is no longer re-exported. Plaintext group metadata is
// retired (Phase E of MLS metadata cutover); group name/description/avatar live
// in encrypted `group_metadata_blobs` payloads and are decoded client-side via
// the `getGroupMetadataBlob` endpoint. Stream C will remove the type from the
// lexicon entirely; this re-export is dropped pre-emptively so handler code
// can't construct it.
pub use crate::generated::blue_catbird::mlsChat::{
    ConvoView, KeyPackageRef, MemberView, MessageView,
};

// Note: handler-specific types (AddMembers, LeaveConvo, etc.) are imported
// directly by each handler from crate::generated::blue_catbird::mlsChat::*

// =============================================================================
// Database-specific models (not in lexicon)
// =============================================================================

/// Database representation of a conversation
/// Maps to `conversations` table (updated schema - id is the group_id)
#[derive(Debug, Clone, FromRow)]
pub struct Conversation {
    pub id: String,          // MLS group identifier (hex-encoded) - canonical ID
    pub creator_did: String, // Stored as TEXT, convert to Did when needed
    pub current_epoch: i32,
    pub cipher_suite: Option<String>, // Optional in current schema
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    // Tree divergence detection
    #[sqlx(default)]
    pub confirmation_tag: Option<Vec<u8>>,
    // Federation support
    #[sqlx(default)]
    pub sequencer_ds: Option<String>, // DID of sequencer DS; NULL = this DS is sequencer
    #[sqlx(default)]
    pub is_remote: bool, // True if this DS is only a participant mailbox
    // Group reset support
    #[sqlx(default)]
    pub group_id: Option<String>, // Current MLS group_id (may differ from id after reset)
    #[sqlx(default)]
    pub reset_count: Option<i32>, // Number of times the group has been reset
    // Auto-reset circuit breaker
    #[sqlx(default)]
    pub auto_reset_disabled_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl Conversation {
    /// Project this `Conversation`'s MLS-related columns into a `CryptoSession`.
    ///
    /// Phase 1 read-only projection. Note: `group_info`, `group_info_epoch`,
    /// and `group_info_updated_at` are not on the `Conversation` struct (they
    /// live on the table but are accessed via separate queries), so they are
    /// returned as `None` here. Handlers that need them go through
    /// `CryptoSessionRepository::get_active`.
    pub fn active_crypto_session(&self) -> CryptoSession {
        CryptoSession {
            id: self.id.clone(),
            conversation_id: self.id.clone(),
            generation: self.reset_count.unwrap_or(0),
            mls_group_id: self.group_id.clone().unwrap_or_else(|| self.id.clone()),
            state: "active".to_string(),
            cipher_suite: self.cipher_suite.clone(),
            last_observed_epoch: self.current_epoch,
            last_confirmation_tag: self.confirmation_tag.clone(),
            group_info: None,
            group_info_epoch: None,
            group_info_updated_at: None,
            created_by_did: Some(self.creator_did.clone()),
            created_at: self.created_at,
            activated_at: None,
            superseded_at: None,
            supersedes_id: None,
        }
    }

    /// Convert to API ConvoView with members
    ///
    /// `local_ds_did` is this DS's own base DID
    /// (`crate::identity::service_did_base_opt()`): a `NULL`
    /// `conversations.sequencer_ds` means "this DS is the sequencer" and must
    /// materialize as the local DS DID in `sequencerDid`, not be omitted
    /// (ADR-010 D4 rules 1-2). Pass `None` only when `SERVICE_DID` is
    /// unconfigured (dev/test), which omits the field (ambiguity A5).
    ///
    /// # Errors
    /// Returns an error if the creator_did is not a valid DID string.
    pub fn to_convo_view(
        &self,
        members: Vec<MemberView<'static>>,
        local_ds_did: Option<&str>,
    ) -> Result<ConvoView<'static>, String> {
        self.to_convo_view_with_last_message_at(members, local_ds_did, None)
    }

    /// Convert to API ConvoView with members and server-observed message activity.
    pub fn to_convo_view_with_last_message_at(
        &self,
        members: Vec<MemberView<'static>>,
        local_ds_did: Option<&str>,
        last_message_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<ConvoView<'static>, String> {
        use jacquard_common::IntoStatic;

        let creator = crate::sqlx_jacquard::try_string_to_did(&self.creator_did)
            .map_err(|e| format!("Invalid creator DID: {}", e))?;

        // ADR-010 D4 (WS-4 rung 2): NULL sequencer_ds == "sequenced locally".
        // Defensively strip any `#fragment` (format: "did" fields must be
        // base DIDs — see system_reset_did precedent) and warn + omit on an
        // invalid stored value rather than failing the whole view.
        let sequencer_did = self
            .sequencer_ds
            .as_deref()
            .or(local_ds_did)
            .map(crate::identity::canonical_did)
            .and_then(|raw| match crate::sqlx_jacquard::try_string_to_did(raw) {
                Ok(did) => Some(did),
                Err(e) => {
                    tracing::warn!(
                        convo = %self.id,
                        "invalid sequencer DID for convoView.sequencerDid; omitting field: {e}"
                    );
                    None
                }
            });

        let conf_tag_b64 = self.confirmation_tag.as_ref().map(|t| {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(t)
        });

        // Use group_id from DB if available (may differ from id after reset), else fall back to id
        let current_group_id = self.group_id.as_deref().unwrap_or(&self.id).to_string();

        let reset_generation = self.reset_count.unwrap_or(0);

        // `resetGeneration` is a top-level field on ConvoView (set below); do NOT
        // also insert it into extra_data or the wire JSON will contain the key
        // twice and strict parsers (serde, kotlinx.serialization) will reject it.
        let mut extra = std::collections::BTreeMap::new();
        extra.insert(
            jacquard_common::smol_str::SmolStr::new("currentGroupId"),
            jacquard_common::types::value::Data::String(
                jacquard_common::types::string::AtprotoStr::String(current_group_id.clone().into()),
            ),
        );

        let view = ConvoView {
            conversation_id: self.id.clone().into(),
            group_id: current_group_id.into(),
            creator,
            members,
            epoch: self.current_epoch as i64,
            cipher_suite: self
                .cipher_suite
                .clone()
                .unwrap_or_else(|| "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519".to_string())
                .into(),
            created_at: crate::sqlx_jacquard::chrono_to_datetime(self.created_at),
            last_message_at: last_message_at.map(crate::sqlx_jacquard::chrono_to_datetime),
            confirmation_tag: conf_tag_b64.map(|s| s.into()),
            reset_generation: Some(reset_generation as i64),
            // Top-level struct field ONLY — never also in extra_data (the
            // duplicate-key hazard documented above for resetGeneration).
            sequencer_did,
            extra_data: Some(extra),
        };
        Ok(view.into_static())
    }
}

// =============================================================================
// CryptoSession — one MLS group generation (Phase 1: read-only projection over
// `conversations` MLS columns). Phase 2 introduces a real `crypto_sessions`
// table; this struct is the seam.
// =============================================================================

/// One MLS group generation. Server-side public observable metadata only —
/// the server is not the cryptographic authority on group state, clients are.
///
/// Phase 1: projected from existing `conversations` columns. Phase 2: backed
/// by a dedicated `crypto_sessions` table with an explicit state machine and
/// supersession pointers.
#[derive(Debug, Clone, FromRow)]
pub struct CryptoSession {
    /// Opaque session id. Phase 1 mirrors `conversation_id`; Phase 2 makes
    /// this an independent UUID.
    pub id: String,
    pub conversation_id: String,
    pub generation: i32,
    pub mls_group_id: String,
    /// One of: pending, active, reset_requested, superseding, superseded,
    /// failed, archived. Phase 1 always returns "active" — there is no
    /// state column on the legacy schema yet.
    pub state: String,
    pub cipher_suite: Option<String>,
    pub last_observed_epoch: i32,
    pub last_confirmation_tag: Option<Vec<u8>>,
    pub group_info: Option<Vec<u8>>,
    pub group_info_epoch: Option<i32>,
    pub group_info_updated_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_by_did: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub activated_at: Option<chrono::DateTime<chrono::Utc>>,
    pub superseded_at: Option<chrono::DateTime<chrono::Utc>>,
    pub supersedes_id: Option<String>,
}

/// New crypto session candidate, used by Phase 2 `CryptoSessionRepository::create`.
/// Phase 1: no callers; the type is here so the trait surface compiles.
#[derive(Debug, Clone)]
pub struct NewCryptoSession {
    pub id: String,
    pub conversation_id: String,
    pub generation: i32,
    pub mls_group_id: String,
    pub state: String,
    pub cipher_suite: Option<String>,
    pub last_observed_epoch: i32,
    pub last_confirmation_tag: Option<Vec<u8>>,
    pub group_info: Option<Vec<u8>>,
    pub group_info_epoch: Option<i32>,
    pub created_by_did: Option<String>,
    pub supersedes_id: Option<String>,
}

/// Immutable, server-observable MLS authority resolved from the active
/// `crypto_sessions` row and its conversation projection (ADR-011).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedMlsContext {
    pub conversation_id: String,
    pub crypto_session_id: String,
    pub mls_group_id: String,
    pub reset_generation: i32,
    pub state: String,
    pub authoritative_epoch: i32,
    pub confirmation_tag: Option<Vec<u8>>,
    pub sequencer_did: String,
    pub sequencer_term: i64,
    pub receipt: Option<SequencerReceiptRef>,
}

/// Reference to a receipt already verified by the operation-specific trust
/// boundary. This type does not verify signatures by itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequencerReceiptRef {
    pub receipt_hash: Vec<u8>,
    pub epoch: i32,
    pub term: i64,
    pub sequencer_did: String,
    pub commit_hash: Vec<u8>,
    pub issued_at: i64,
    pub signature: Vec<u8>,
}

/// Durable result of one repository-level MLS transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedMlsTransition {
    pub context: ResolvedMlsContext,
    pub delivery_event_id: String,
    pub delivery_sequence: i64,
    pub receipt: Option<SequencerReceiptRef>,
}

// =============================================================================
// DeliveryEvent — server's source-of-truth append-only log. Phase 1: domain
// type only, no persistence adapter. Phase 2: backed by `delivery_events`.
// =============================================================================

/// One row in the server's append-only delivery log. Carries provenance fields
/// for future federation; populated as available, NULL otherwise.
#[derive(Debug, Clone)]
pub struct DeliveryEvent {
    pub id: String,
    pub conversation_id: String,
    pub seq: i64,
    pub crypto_session_id: Option<String>,
    pub event_type: String,
    pub sender_did: Option<String>,
    pub sender_device_id: Option<String>,
    pub mls_group_id: Option<String>,
    pub mls_epoch: Option<i64>,
    pub idempotency_key: Option<String>,
    pub payload: Option<Vec<u8>>,
    pub payload_json: Option<serde_json::Value>,
    pub origin_service_did: Option<String>,
    pub home_service_did: Option<String>,
    pub remote_event_id: Option<String>,
    pub auth_issuer_did: Option<String>,
    pub received_via: Option<String>,
    pub federation_trace_id: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// New delivery event to append. Used by Phase 2 `DeliveryLogRepository::append`.
/// Phase 1: no callers; the type is here so the trait surface compiles.
#[derive(Debug, Clone)]
pub struct NewDeliveryEvent {
    pub id: String,
    pub conversation_id: String,
    pub crypto_session_id: Option<String>,
    pub event_type: String,
    pub sender_did: Option<String>,
    pub sender_device_id: Option<String>,
    pub mls_group_id: Option<String>,
    pub mls_epoch: Option<i64>,
    pub idempotency_key: Option<String>,
    pub payload: Option<Vec<u8>>,
    pub payload_json: Option<serde_json::Value>,
    pub origin_service_did: Option<String>,
    pub home_service_did: Option<String>,
    pub remote_event_id: Option<String>,
    pub auth_issuer_did: Option<String>,
    pub received_via: Option<String>,
    pub federation_trace_id: Option<String>,
}

/// Database representation of a membership
/// Maps to `members` table (current schema)
#[derive(Debug, Clone, FromRow)]
pub struct Membership {
    pub convo_id: String,
    pub member_did: String, // Stored as TEXT (device-specific MLS DID)
    pub joined_at: chrono::DateTime<chrono::Utc>,
    pub left_at: Option<chrono::DateTime<chrono::Utc>>,
    pub leaf_index: Option<i32>,
    // Admin fields
    pub is_admin: bool,
    pub promoted_at: Option<chrono::DateTime<chrono::Utc>>,
    pub promoted_by_did: Option<String>,
    // Moderator fields
    pub is_moderator: bool,
    // Rejoin support fields
    pub needs_rejoin: bool,
    pub rejoin_requested_at: Option<chrono::DateTime<chrono::Utc>>,
    pub rejoin_key_package_hash: Option<String>,
    pub unread_count: i32,
    pub last_read_at: Option<chrono::DateTime<chrono::Utc>>,
    // Multi-device support fields
    pub user_did: Option<String>, // Base user DID (without device suffix)
    pub device_id: Option<String>, // Device identifier (UUID)
    pub device_name: Option<String>, // Human-readable device name
    // Federation support
    #[sqlx(default)]
    pub ds_did: Option<String>, // DID of the DS serving this member; NULL = local
}

impl Membership {
    pub fn is_active(&self) -> bool {
        self.left_at.is_none()
    }

    /// Convert to API MemberView
    ///
    /// # Errors
    /// Returns an error if member_did is not a valid DID string or promoted_by_did is invalid.
    pub fn to_member_view(&self) -> Result<MemberView<'static>, String> {
        use jacquard_common::IntoStatic;

        let did_without_fragment = self
            .member_did
            .split('#')
            .next()
            .unwrap_or(&self.member_did);

        let did = crate::sqlx_jacquard::try_string_to_did(did_without_fragment)
            .map_err(|e| format!("Invalid member DID '{}': {}", self.member_did, e))?;

        let promoted_by = if let Some(ref promoted_by_did) = self.promoted_by_did {
            Some(
                crate::sqlx_jacquard::try_string_to_did(promoted_by_did)
                    .map_err(|e| format!("Invalid promoted_by DID '{}': {}", promoted_by_did, e))?,
            )
        } else {
            None
        };

        let user_did = if let Some(ref user_did_str) = self.user_did {
            crate::sqlx_jacquard::try_string_to_did(user_did_str)
                .map_err(|e| format!("Invalid user DID '{}': {}", user_did_str, e))?
        } else {
            did.clone()
        };

        let view = MemberView {
            did,
            user_did,
            device_id: self.device_id.as_deref().map(|s| s.into()),
            device_name: self.device_name.as_deref().map(|s| s.into()),
            joined_at: crate::sqlx_jacquard::chrono_to_datetime(self.joined_at),
            is_admin: self.is_admin,
            is_moderator: Some(self.is_moderator),
            leaf_index: self.leaf_index.map(|i| i as i64),
            credential: None,
            promoted_at: self
                .promoted_at
                .map(crate::sqlx_jacquard::chrono_to_datetime),
            promoted_by,
            extra_data: Default::default(),
        };
        Ok(view.into_static())
    }
}

/// Database representation of a message
/// Maps to `messages` table
#[derive(Debug, Clone, FromRow)]
pub struct Message {
    pub id: String,
    pub convo_id: String,
    /// Intentionally stored as NULL for privacy. Sender identity is derived
    /// from MLS decryption by clients. Used ephemerally during send flow
    /// for unread count exclusion and notification routing, then discarded.
    pub sender_did: Option<String>,
    pub message_type: String,
    pub epoch: i64,
    pub seq: i64,
    pub ciphertext: Vec<u8>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl Message {
    /// Convert to API MessageView
    ///
    /// Note: sender field removed per security hardening - clients derive sender from decrypted MLS content
    pub fn to_message_view(&self) -> Result<MessageView<'static>, String> {
        Ok(MessageView {
            id: self.id.clone().into(),
            convo_id: self.convo_id.clone().into(),
            ciphertext: bytes::Bytes::from(self.ciphertext.clone()),
            epoch: self.epoch,
            seq: self.seq,
            created_at: crate::sqlx_jacquard::chrono_to_datetime(self.created_at),
            message_type: Some(self.message_type.clone().into()),
            extra_data: Default::default(),
        })
    }
}

/// Database representation of a key package
/// Maps to `key_packages` table
#[derive(Debug, Clone, FromRow)]
pub struct KeyPackage {
    pub owner_did: String, // Stored as TEXT
    pub cipher_suite: String,
    pub key_data: Vec<u8>,
    pub key_package_hash: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub consumed_at: Option<chrono::DateTime<chrono::Utc>>, // NULL = available, NOT NULL = consumed
}

impl KeyPackage {
    pub fn is_valid(&self) -> bool {
        self.consumed_at.is_none() && self.expires_at > chrono::Utc::now()
    }

    /// Convert to API KeyPackageRef
    ///
    /// # Errors
    /// Returns an error if the DID is not a valid DID string.
    pub fn to_key_package_ref(&self) -> Result<KeyPackageRef<'static>, String> {
        use base64::Engine;
        let key_package_b64 = base64::engine::general_purpose::STANDARD.encode(&self.key_data);

        let did = crate::sqlx_jacquard::try_string_to_did(&self.owner_did)
            .map_err(|e| format!("Invalid key package DID: {}", e))?;

        Ok(KeyPackageRef {
            did,
            key_package: key_package_b64.into(),
            cipher_suite: self.cipher_suite.clone().into(),
            key_package_hash: Some(self.key_package_hash.clone().into()),
            extra_data: Default::default(),
        })
    }
}

/// Welcome message storage (database-specific)
#[derive(Debug, Clone, FromRow)]
pub struct WelcomeMessage {
    pub id: String,
    pub convo_id: String,
    pub recipient_did: String,
    pub welcome_data: Vec<u8>, // Base64url decoded
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub consumed: bool,
}

/// Commit message storage (database-specific)
#[derive(Debug, Clone, FromRow)]
pub struct CommitMessage {
    pub id: String,
    pub convo_id: String,
    pub sender_did: String,
    pub epoch: i32,
    pub commit_data: Vec<u8>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

// =============================================================================
// NEW: Models for Admin System, Blocks, and Multi-Device Support
// =============================================================================
// NOTE: These models are defined but their database tables need to be created
// in a future migration. See Phase 2 of the implementation plan.

/// User device registration for multi-device support
/// Will map to future `user_devices` table
#[derive(Debug, Clone, FromRow)]
pub struct UserDevice {
    pub device_id: String, // UUID
    pub user_did: String,  // Base user DID (without #device suffix)
    pub mls_did: String,   // Device-specific MLS DID (user_did#device_id)
    pub device_name: String,
    pub signature_public_key: Vec<u8>, // Ed25519 public key
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_seen_at: chrono::DateTime<chrono::Utc>,
    pub is_active: bool,
}

/// Admin action audit log
/// Will map to future `admin_actions` table
#[derive(Debug, Clone, FromRow)]
pub struct AdminAction {
    pub id: String, // ULID
    pub convo_id: String,
    pub actor_did: String,   // Admin who performed the action
    pub target_did: String,  // Member who was acted upon
    pub action_type: String, // "promote", "demote", "remove"
    pub reason: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// E2EE moderation report
/// Will map to future `reports` table
#[derive(Debug, Clone, FromRow)]
pub struct Report {
    pub id: String, // ULID
    pub convo_id: String,
    pub reporter_did: String,
    pub reported_did: String,
    pub category: String,           // "spam", "harassment", "illegal", etc.
    pub encrypted_content: Vec<u8>, // Encrypted report details
    pub message_ids: Option<Vec<String>>, // JSON array of related message IDs
    pub status: String,             // "pending", "resolved", "dismissed"
    pub resolved_at: Option<chrono::DateTime<chrono::Utc>>,
    pub resolved_by: Option<String>, // Admin DID
    pub resolution_notes: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Cached Bluesky block relationships
/// Will map to future `bsky_blocks` table
#[derive(Debug, Clone, FromRow)]
pub struct BskyBlock {
    pub id: i64, // Auto-increment
    pub blocker_did: String,
    pub blocked_did: String,
    pub block_uri: Option<String>, // AT-URI of block record
    pub created_at: chrono::DateTime<chrono::Utc>, // When block was created on Bluesky
    pub cached_at: chrono::DateTime<chrono::Utc>, // When we cached it
    pub checked_at: chrono::DateTime<chrono::Utc>, // Last verification
}

// =============================================================================
// Federation Models
// =============================================================================

/// Cached DS endpoint resolved from AT Protocol repo records
/// Maps to `ds_endpoints` table
#[derive(Debug, Clone, FromRow)]
pub struct DsEndpoint {
    pub did: String,
    pub endpoint: String,
    pub supported_cipher_suites: Option<String>, // JSON array as text
    pub resolved_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

impl DsEndpoint {
    /// Check if the cached endpoint has expired
    pub fn is_expired(&self) -> bool {
        self.expires_at < chrono::Utc::now()
    }
}

/// Outbound delivery queue item for DS-to-DS fan-out with retry
/// Maps to `outbound_queue` table
#[derive(Debug, Clone, FromRow)]
pub struct OutboundQueueItem {
    pub id: String,
    pub target_ds_did: String,
    pub target_endpoint: String,
    pub method: String,
    pub payload: Vec<u8>,
    pub convo_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub next_retry_at: chrono::DateTime<chrono::Utc>,
    pub retry_count: i32,
    pub max_retries: i32,
    pub last_error: Option<String>,
    pub status: String,
}

impl OutboundQueueItem {
    /// Check if this item can still be retried
    pub fn can_retry(&self) -> bool {
        self.retry_count < self.max_retries && self.status == "pending"
    }
}

/// Sequencer receipt: cryptographic proof of epoch assignment for equivocation detection.
/// Maps to `sequencer_receipts` table.
#[derive(Debug, Clone, FromRow)]
pub struct SequencerReceipt {
    pub convo_id: String,
    pub epoch: i32,
    pub sequencer_term: i64,
    pub commit_hash: Vec<u8>,
    pub sequencer_did: String,
    pub issued_at: i64,
    pub signature: Vec<u8>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Pending welcome message for rejoin orchestration
/// Will map to future `pending_welcomes` table
#[derive(Debug, Clone, FromRow)]
pub struct PendingWelcome {
    pub id: String, // ULID
    pub convo_id: String,
    pub recipient_did: String,
    pub welcome_data: Vec<u8>, // Base64url decoded MLS Welcome
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub delivered: bool,
}

#[cfg(test)]
mod tests {
    use super::Conversation;

    fn test_conversation(sequencer_ds: Option<&str>) -> Conversation {
        Conversation {
            id: "convo-1".to_string(),
            creator_did: "did:plc:creatorxyz".to_string(),
            current_epoch: 4,
            cipher_suite: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            confirmation_tag: None,
            sequencer_ds: sequencer_ds.map(|s| s.to_string()),
            is_remote: false,
            group_id: None,
            reset_count: Some(0),
            auto_reset_disabled_at: None,
        }
    }

    // ADR-010 D4 rules 1-2 (WS-4 rung 2): NULL sequencer_ds means "this DS"
    // and must materialize as the local DS DID, not be omitted.
    #[test]
    fn to_convo_view_materializes_null_sequencer_as_local_ds_did() {
        let view = test_conversation(None)
            .to_convo_view(vec![], Some("did:web:local-ds.example"))
            .expect("view");
        assert_eq!(
            view.sequencer_did.as_ref().map(|d| d.as_str()),
            Some("did:web:local-ds.example")
        );
    }

    #[test]
    fn to_convo_view_passes_through_stored_sequencer() {
        let view = test_conversation(Some("did:web:remote-ds.example"))
            .to_convo_view(vec![], Some("did:web:local-ds.example"))
            .expect("view");
        assert_eq!(
            view.sequencer_did.as_ref().map(|d| d.as_str()),
            Some("did:web:remote-ds.example")
        );
    }

    // format: "did" fields must be fragment-free base DIDs (A7); a stored
    // fragment-bearing value is stripped defensively at projection time.
    #[test]
    fn to_convo_view_strips_fragment_from_stored_sequencer() {
        let view = test_conversation(Some("did:web:remote-ds.example#atproto_mls"))
            .to_convo_view(vec![], Some("did:web:local-ds.example"))
            .expect("view");
        assert_eq!(
            view.sequencer_did.as_ref().map(|d| d.as_str()),
            Some("did:web:remote-ds.example")
        );
    }

    // Ambiguity A5: no SERVICE_DID configured and locally sequenced -> the
    // optional field is omitted (skip_serializing_if), not an error.
    #[test]
    fn to_convo_view_omits_field_without_local_did() {
        let view = test_conversation(None)
            .to_convo_view(vec![], None)
            .expect("view");
        assert!(view.sequencer_did.is_none());
        let json = serde_json::to_string(&view).expect("serialize");
        assert!(
            !json.contains("sequencerDid"),
            "None sequencer_did must not serialize: {json}"
        );
    }

    // A malformed stored sequencer_ds row must not break getConvos: warn+omit.
    #[test]
    fn to_convo_view_omits_invalid_stored_sequencer() {
        let view = test_conversation(Some("not a did"))
            .to_convo_view(vec![], Some("did:web:local-ds.example"))
            .expect("view");
        assert!(view.sequencer_did.is_none());
    }

    #[test]
    fn to_convo_view_includes_last_message_at_when_supplied() {
        let last_message_at = chrono::DateTime::parse_from_rfc3339("2026-06-14T07:29:00Z")
            .expect("valid datetime")
            .with_timezone(&chrono::Utc);

        let view = test_conversation(None)
            .to_convo_view_with_last_message_at(
                vec![],
                Some("did:web:local-ds.example"),
                Some(last_message_at),
            )
            .expect("view");

        assert_eq!(
            view.last_message_at.as_ref().map(|dt| dt.as_str()),
            Some("2026-06-14T07:29:00.000000Z")
        );
    }

    // Regression for the extra_data duplicate-key hazard (models.rs comment):
    // the wire JSON must contain `sequencerDid` exactly once.
    #[test]
    fn to_convo_view_serializes_sequencer_did_exactly_once() {
        let view = test_conversation(Some("did:web:remote-ds.example"))
            .to_convo_view(vec![], Some("did:web:local-ds.example"))
            .expect("view");
        let json = serde_json::to_string(&view).expect("serialize");
        assert_eq!(
            json.matches("\"sequencerDid\"").count(),
            1,
            "sequencerDid must appear exactly once in wire JSON: {json}"
        );
        assert!(json.contains("\"sequencerDid\":\"did:web:remote-ds.example\""));
    }
}
