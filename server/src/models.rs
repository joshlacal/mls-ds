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
pub use crate::generated::blue_catbird::mls::{
    ConvoMetadata, ConvoView, KeyPackageRef, MemberView, MessageView,
};

// Note: handler-specific types (AddMembers, LeaveConvo, etc.) are imported
// directly by each handler from crate::generated::blue_catbird::mls::*

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
    pub name: Option<String>, // From metadata
    // Federation support
    #[sqlx(default)]
    pub sequencer_ds: Option<String>, // DID of sequencer DS; NULL = this DS is sequencer
    #[sqlx(default)]
    pub is_remote: bool, // True if this DS is only a participant mailbox
}

impl Conversation {
    /// Convert to API ConvoView with members
    ///
    /// # Errors
    /// Returns an error if the creator_did is not a valid DID string.
    pub fn to_convo_view(
        &self,
        members: Vec<MemberView<'static>>,
    ) -> Result<ConvoView<'static>, String> {
        use jacquard_common::IntoStatic;

        let metadata: Option<ConvoMetadata<'static>> = if self.name.is_some() {
            Some(ConvoMetadata {
                name: self.name.clone().map(|s| s.into()),
                description: None,
                extra_data: Default::default(),
            })
        } else {
            None
        };

        let creator = crate::sqlx_jacquard::try_string_to_did(&self.creator_did)
            .map_err(|e| format!("Invalid creator DID: {}", e))?;

        let view = ConvoView {
            group_id: self.id.clone().into(),
            creator,
            members,
            epoch: self.current_epoch as i64,
            cipher_suite: self
                .cipher_suite
                .clone()
                .unwrap_or_else(|| "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519".to_string())
                .into(),
            created_at: crate::sqlx_jacquard::chrono_to_datetime(self.created_at),
            last_message_at: None,
            metadata,
            extra_data: Default::default(),
        };
        Ok(view.into_static())
    }
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
