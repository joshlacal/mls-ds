//! Generated types from blue.catbird.mls lexicons
//! Auto-generated from lexicon schemas

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// =============================================================================
// blue.catbird.mls.defs - Shared type definitions
// =============================================================================

/// MLS conversation view with member and epoch information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConvoView {
    /// Conversation identifier
    pub id: String,
    /// MLS group identifier (hex-encoded)
    pub group_id: String,
    /// DID of the conversation creator
    pub creator: String,
    /// Current conversation members
    pub members: Vec<MemberView>,
    /// Current MLS epoch number
    pub epoch: i32,
    /// MLS cipher suite used for this conversation
    pub cipher_suite: String,
    /// Conversation creation timestamp
    pub created_at: DateTime<Utc>,
    /// Timestamp of last message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_message_at: Option<DateTime<Utc>>,
    /// Optional conversation metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ConvoMetadata>,
}

/// Metadata for a conversation (name, description, avatar)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConvoMetadata {
    /// Conversation display name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Conversation description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Conversation avatar image (blob reference)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
}

/// View of a conversation member with MLS credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberView {
    /// Member DID
    pub did: String,
    /// When member joined the conversation
    pub joined_at: DateTime<Utc>,
    /// MLS leaf index in tree structure
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leaf_index: Option<i32>,
}

/// View of an encrypted MLS message
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageView {
    /// Message identifier
    pub id: String,
    /// Conversation identifier
    pub convo_id: String,
    /// DID of message sender
    pub sender: String,
    /// MLS encrypted message ciphertext bytes (base64url-encoded)
    #[serde(with = "base64_bytes")]
    pub ciphertext: Vec<u8>,
    /// MLS epoch when message was sent
    pub epoch: i64,
    /// Sequence number within conversation
    pub seq: i64,
    /// Message creation timestamp
    pub created_at: DateTime<Utc>,
    /// Optional embed type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embed_type: Option<String>,
    /// Optional embed URI reference
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embed_uri: Option<String>,
}

/// Reference to an MLS key package for adding members
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyPackageRef {
    /// Owner DID
    pub did: String,
    /// Base64url-encoded MLS key package bytes
    pub key_package: String,
    /// Supported cipher suite for this key package
    pub cipher_suite: String,
}

/// Reference to a blob (file attachment)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlobRef {
    /// Content identifier (CID)
    pub cid: String,
    /// MIME type of the blob
    pub mime_type: String,
    /// Blob size in bytes (max 50MB)
    pub size: i64,
    /// AT URI reference to blob
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ref_uri: Option<String>,
}

// =============================================================================
// blue.catbird.mls.createConvo
// =============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateConvoInput {
    /// MLS cipher suite to use for this conversation
    pub cipher_suite: String,
    /// DIDs of initial members to add to the conversation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_members: Option<Vec<String>>,
    /// Optional conversation metadata (name, description, avatar)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ConvoMetadata>,
}

// Output is ConvoView

// =============================================================================
// blue.catbird.mls.getConvos
// =============================================================================

#[derive(Debug, Deserialize)]
pub struct GetConvosParams {
    /// Maximum number of conversations to return
    #[serde(default = "default_limit")]
    pub limit: i32,
    /// Pagination cursor from previous response
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

fn default_limit() -> i32 {
    50
}

#[derive(Debug, Serialize)]
pub struct GetConvosOutput {
    /// List of conversations
    pub conversations: Vec<ConvoView>,
    /// Pagination cursor for next page
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

// =============================================================================
// blue.catbird.mls.addMembers
// =============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddMembersInput {
    /// Conversation identifier
    pub convo_id: String,
    /// DIDs of members to add
    pub did_list: Vec<String>,
    /// Optional base64url-encoded MLS Commit message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    /// Optional base64url-encoded MLS Welcome message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub welcome: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddMembersOutput {
    /// Whether the operation succeeded
    pub success: bool,
    /// New epoch number after adding members
    pub new_epoch: i32,
}

// =============================================================================
// blue.catbird.mls.leaveConvo
// =============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LeaveConvoInput {
    /// Conversation identifier
    pub convo_id: String,
    /// DID of member to remove (defaults to caller's DID)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_did: Option<String>,
    /// Optional base64url-encoded MLS Commit message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LeaveConvoOutput {
    /// Whether the operation succeeded
    pub success: bool,
    /// New epoch number after member removal
    pub new_epoch: i32,
}

// =============================================================================
// blue.catbird.mls.sendMessage
// =============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendMessageInput {
    /// Conversation identifier
    pub convo_id: String,
    /// MLS encrypted message ciphertext bytes
    #[serde(with = "base64_bytes")]
    pub ciphertext: Vec<u8>,
    /// MLS epoch number when message was encrypted
    pub epoch: i64,
    /// DID of the message sender
    pub sender_did: String,
    /// Optional embed type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embed_type: Option<String>,
    /// Optional embed URI reference
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embed_uri: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SendMessageOutput {
    /// Created message identifier
    pub message_id: String,
    /// Server timestamp when message was received
    pub received_at: DateTime<Utc>,
}

// =============================================================================
// blue.catbird.mls.getMessages
// =============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetMessagesParams {
    /// Conversation identifier
    pub convo_id: String,
    /// Maximum number of messages to return
    #[serde(default = "default_limit")]
    pub limit: i32,
    /// Message ID to fetch messages after (pagination cursor)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since_message: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct GetMessagesOutput {
    /// List of messages
    pub messages: Vec<MessageView>,
    /// Cursor for next page of messages (if more available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

// =============================================================================
// blue.catbird.mls.publishKeyPackage
// =============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublishKeyPackageInput {
    /// Base64url-encoded MLS key package
    pub key_package: String,
    /// Cipher suite of the key package
    pub cipher_suite: String,
    /// Expiration timestamp (max 90 days from now)
    pub expires: DateTime<Utc>,
}

// Output is empty object

// =============================================================================
// blue.catbird.mls.getKeyPackages
// =============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetKeyPackagesParams {
    /// DIDs to fetch key packages for
    pub dids: Vec<String>,
    /// Filter by cipher suite
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher_suite: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetKeyPackagesOutput {
    /// Available key packages for the requested DIDs
    pub key_packages: Vec<KeyPackageRef>,
    /// DIDs for which no key packages were found
    #[serde(skip_serializing_if = "Option::is_none")]
    pub missing: Option<Vec<String>>,
}

// =============================================================================
// Helper modules for base64 encoding/decoding
// =============================================================================

mod base64_bytes {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Use STANDARD base64 for Swift compatibility
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        // Try STANDARD base64 first (with +/), then fall back to URL_SAFE_NO_PAD
        base64::engine::general_purpose::STANDARD
            .decode(&s)
            .or_else(|_| {
                base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&s)
            })
            .map_err(serde::de::Error::custom)
    }
}
