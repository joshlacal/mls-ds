//! Database models using generated Atrium types
//!
//! These models use the generated lexicon types directly with sqlx extensions
//! for Atrium types (Did, Datetime, etc.)

use sqlx::FromRow;

// Re-export generated types for convenience
pub use crate::generated::blue::catbird::mls::defs::{
    ConvoMetadata, ConvoMetadataData, ConvoView, ConvoViewData, KeyPackageRef, KeyPackageRefData,
    MemberView, MemberViewData, MessageView, MessageViewData,
};

// Re-export endpoint types that handlers need
pub use crate::generated::blue::catbird::mls::{
    add_members::{Input as AddMembersInput, Output as AddMembersOutput},
    get_welcome::Output as GetWelcomeOutput,
    leave_convo::{Input as LeaveConvoInput, Output as LeaveConvoOutput},
    publish_key_package::Input as PublishKeyPackageInput,
    send_message::{Input as SendMessageInput, Output as SendMessageOutput},
};

// =============================================================================
// Database-specific models (not in lexicon)
// =============================================================================

/// Database representation of a conversation
/// Maps to `conversations` table (updated schema - id is the group_id)
#[derive(Debug, Clone, FromRow)]
pub struct Conversation {
    pub id: String,               // MLS group identifier (hex-encoded) - canonical ID
    pub creator_did: String,      // Stored as TEXT, convert to Did when needed
    pub current_epoch: i32,
    pub cipher_suite: Option<String>, // Optional in current schema
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub name: Option<String>, // From metadata
}

impl Conversation {
    /// Convert to API ConvoView with members
    ///
    /// # Errors
    /// Returns an error if the creator_did is not a valid DID string.
    pub fn to_convo_view(&self, members: Vec<MemberView>) -> Result<ConvoView, String> {
        let metadata = if self.name.is_some() {
            Some(ConvoMetadata::from(ConvoMetadataData {
                name: self.name.clone(),
                description: None, // TODO: Add description column to conversations table
            }))
        } else {
            None
        };

        let creator = self.creator_did.parse().map_err(|e| {
            format!("Invalid creator DID '{}': {}", self.creator_did, e)
        })?;

        Ok(ConvoView::from(ConvoViewData {
            group_id: self.id.clone(),  // id is the group_id (canonical ID)
            creator,
            members,
            epoch: self.current_epoch as usize,
            cipher_suite: self
                .cipher_suite
                .clone()
                .unwrap_or_else(|| "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_string()),
            created_at: crate::sqlx_atrium::chrono_to_datetime(self.created_at),
            last_message_at: None,
            metadata,
        }))
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
    // Rejoin support fields
    pub needs_rejoin: bool,
    pub rejoin_requested_at: Option<chrono::DateTime<chrono::Utc>>,
    pub rejoin_key_package_hash: Option<String>,
    pub unread_count: i32,
    pub last_read_at: Option<chrono::DateTime<chrono::Utc>>,
    // Multi-device support fields
    pub user_did: Option<String>,    // Base user DID (without device suffix)
    pub device_id: Option<String>,   // Device identifier (UUID)
    pub device_name: Option<String>, // Human-readable device name
}

impl Membership {
    pub fn is_active(&self) -> bool {
        self.left_at.is_none()
    }

    /// Convert to API MemberView
    ///
    /// # Errors
    /// Returns an error if member_did is not a valid DID string or promoted_by_did is invalid.
    pub fn to_member_view(&self) -> Result<MemberView, String> {
        let did: atrium_api::types::string::Did = self.member_did.parse().map_err(|e| {
            format!("Invalid member DID '{}': {}", self.member_did, e)
        })?;

        let promoted_by = if let Some(ref promoted_by_did) = self.promoted_by_did {
            Some(promoted_by_did.parse().map_err(|e| {
                format!("Invalid promoted_by DID '{}': {}", promoted_by_did, e)
            })?)
        } else {
            None
        };

        // Parse user_did if present, otherwise fall back to member_did for backward compatibility
        let user_did: atrium_api::types::string::Did = if let Some(ref user_did_str) = self.user_did {
            user_did_str.parse().map_err(|e| {
                format!("Invalid user DID '{}': {}", user_did_str, e)
            })?
        } else {
            // Backward compatibility: use member_did as user_did
            did.clone()
        };

        Ok(MemberView::from(MemberViewData {
            did: did.clone(),
            user_did,
            device_id: self.device_id.clone(),
            device_name: self.device_name.clone(),
            joined_at: crate::sqlx_atrium::chrono_to_datetime(self.joined_at),
            is_admin: self.is_admin,
            leaf_index: self.leaf_index.map(|i| i as usize),
            credential: None,
            promoted_at: self.promoted_at.map(crate::sqlx_atrium::chrono_to_datetime),
            promoted_by,
        }))
    }
}

/// Database representation of a message
/// Maps to `messages` table
#[derive(Debug, Clone, FromRow)]
pub struct Message {
    pub id: String,
    pub convo_id: String,
    pub sender_did: Option<String>, // Made nullable per privacy hardening migration
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
    pub fn to_message_view(&self) -> Result<MessageView, String> {
        Ok(MessageView::from(MessageViewData {
            id: self.id.clone(),
            convo_id: self.convo_id.clone(),
            ciphertext: self.ciphertext.clone(),
            epoch: self.epoch as usize,
            seq: self.seq as usize,
            created_at: crate::sqlx_atrium::chrono_to_datetime(self.created_at),
        }))
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
    pub fn to_key_package_ref(&self) -> Result<KeyPackageRef, String> {
        use base64::Engine;
        let key_package_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(&self.key_data);

        let did = self.owner_did.parse().map_err(|e| {
            format!("Invalid key package DID '{}': {}", self.owner_did, e)
        })?;

        Ok(KeyPackageRef::from(KeyPackageRefData {
            did,
            key_package: key_package_b64,
            cipher_suite: self.cipher_suite.clone(),
            key_package_hash: Some(self.key_package_hash.clone()),
        }))
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
    pub actor_did: String,  // Admin who performed the action
    pub target_did: String, // Member who was acted upon
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
    pub category: String, // "spam", "harassment", "illegal", etc.
    pub encrypted_content: Vec<u8>, // Encrypted report details
    pub message_ids: Option<Vec<String>>, // JSON array of related message IDs
    pub status: String,   // "pending", "resolved", "dismissed"
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
    pub cached_at: chrono::DateTime<chrono::Utc>,  // When we cached it
    pub checked_at: chrono::DateTime<chrono::Utc>, // Last verification
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
