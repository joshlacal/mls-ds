//! Generated types from blue.catbird.mls lexicons
//! Auto-generated from lexicon schemas
//!
//! This file contains all type definitions for the MLS (Message Layer Security) API.
//! Types are organized by lexicon namespace:
//! - Shared definitions (defs, message.defs)
//! - Endpoint-specific input/output types
//! - Error types for each endpoint

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// =============================================================================
// blue.catbird.mls.defs - Shared type definitions
// =============================================================================

/// MLS conversation view with member and epoch information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConvoView {
    /// Conversation identifier (TID)
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

/// Metadata for a conversation (name, description)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConvoMetadata {
    /// Conversation display name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Conversation description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// View of a conversation member representing a single device
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberView {
    /// Device-specific MLS DID (format: did:plc:user#device-uuid)
    pub did: String,
    /// User DID without device suffix (format: did:plc:user)
    pub user_did: String,
    /// Device identifier (UUID)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    /// Human-readable device name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    /// When this device joined the conversation
    pub joined_at: DateTime<Utc>,
    /// Whether this member (device) has admin privileges
    pub is_admin: bool,
    /// When member was promoted to admin (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub promoted_at: Option<DateTime<Utc>>,
    /// DID of admin who promoted this member (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub promoted_by: Option<String>,
    /// MLS leaf index in ratchet tree structure
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leaf_index: Option<i32>,
    /// MLS credential bytes
    #[serde(skip_serializing_if = "Option::is_none", with = "optional_base64_bytes")]
    pub credential: Option<Vec<u8>>,
}

/// View of an encrypted MLS message.
/// Server follows 'dumb delivery service' model - sender identity must be derived
/// by clients from decrypted MLS content for metadata privacy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageView {
    /// Message identifier (ULID for deduplication)
    pub id: String,
    /// Conversation identifier
    pub convo_id: String,
    /// MLS encrypted message ciphertext bytes
    #[serde(with = "crate::atproto_bytes")]
    pub ciphertext: Vec<u8>,
    /// MLS epoch when message was sent
    pub epoch: i64,
    /// Sequence number within conversation
    pub seq: i64,
    /// Message creation timestamp (bucketed to 2-second intervals for traffic analysis protection)
    pub created_at: DateTime<Utc>,
    /// Message type: 'app' for application messages, 'commit' for MLS protocol control messages
    #[serde(rename = "messageType")]
    pub message_type: String,
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

// =============================================================================
// blue.catbird.mls.message.defs - Message payload definitions
// =============================================================================

/// Decrypted message payload structure (what's inside the encrypted ciphertext)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayloadView {
    /// Payload format version for future compatibility
    pub version: i32,
    /// Message type discriminator
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_type: Option<String>,
    /// Message text content (for messageType: text)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Optional rich media embed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embed: Option<MessageEmbed>,
    /// Admin roster update (for messageType: adminRoster)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_roster: Option<AdminRoster>,
    /// Admin action notification (for messageType: adminAction)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_action: Option<AdminAction>,
}

/// Rich media embed types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "$type")]
pub enum MessageEmbed {
    #[serde(rename = "blue.catbird.mls.message.defs#recordEmbed")]
    Record(RecordEmbed),
    #[serde(rename = "blue.catbird.mls.message.defs#linkEmbed")]
    Link(LinkEmbed),
    #[serde(rename = "blue.catbird.mls.message.defs#gifEmbed")]
    Gif(GifEmbed),
}

/// Bluesky record embed (quote post)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordEmbed {
    /// AT-URI of the referenced record
    pub uri: String,
    /// CID of the record for verification
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cid: Option<String>,
    /// DID of the record author
    pub author_did: String,
    /// Preview text from the record
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview_text: Option<String>,
    /// Timestamp when the record was created
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
}

/// External link preview with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkEmbed {
    /// Full URL of the external link
    pub url: String,
    /// Page title from Open Graph or meta tags
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Page description from Open Graph or meta tags
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Thumbnail/preview image URL
    #[serde(skip_serializing_if = "Option::is_none", rename = "thumbnailURL")]
    pub thumbnail_url: Option<String>,
    /// Canonical domain
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

/// Tenor GIF embed (converted to MP4 for efficient playback)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GifEmbed {
    /// Original Tenor GIF URL
    #[serde(rename = "tenorURL")]
    pub tenor_url: String,
    /// MP4 video URL for efficient playback
    #[serde(rename = "mp4URL")]
    pub mp4_url: String,
    /// GIF title or description from Tenor
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Thumbnail image URL for preview
    #[serde(skip_serializing_if = "Option::is_none", rename = "thumbnailURL")]
    pub thumbnail_url: Option<String>,
    /// GIF/video width in pixels
    #[serde(skip_serializing_if = "Option::is_none")]
    pub width: Option<i32>,
    /// GIF/video height in pixels
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<i32>,
}

/// Encrypted admin roster distributed via MLS application messages
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminRoster {
    /// Monotonic roster version number
    pub version: i32,
    /// List of admin DIDs for this conversation
    pub admins: Vec<String>,
    /// SHA-256 hash for integrity verification
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

/// Admin action notification (E2EE)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminAction {
    /// Type of admin action performed
    pub action: String,
    /// DID of member being acted upon
    pub target_did: String,
    /// When the action was performed
    pub timestamp: DateTime<Utc>,
    /// Optional reason for the action
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

// =============================================================================
// blue.catbird.mls.createConvo
// =============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateConvoInput {
    /// Hex-encoded MLS group identifier
    pub group_id: String,
    /// Client-generated UUID for idempotent request retries
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    /// MLS cipher suite to use for this conversation
    pub cipher_suite: String,
    /// DIDs of initial members to add to the conversation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_members: Option<Vec<String>>,
    /// Base64url-encoded MLS Welcome message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub welcome_message: Option<String>,
    /// Array of {did, hash} objects mapping members to key package hashes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_package_hashes: Option<Vec<KeyPackageHashEntry>>,
    /// Optional conversation metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<MetadataInput>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetadataInput {
    /// Conversation display name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Conversation description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyPackageHashEntry {
    /// DID of the member
    pub did: String,
    /// Hex-encoded SHA-256 hash of the key package used
    pub hash: String,
}

// Output is ConvoView

// =============================================================================
// blue.catbird.mls.getConvos
// =============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetConvosParams {
    /// Maximum number of conversations to return
    #[serde(default = "default_limit_50")]
    pub limit: i32,
    /// Pagination cursor from previous response
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
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
    /// Client-generated UUID for idempotent request retries
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    /// DIDs of members to add
    pub did_list: Vec<String>,
    /// Optional base64url-encoded MLS Commit message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    /// Base64url-encoded MLS Welcome message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub welcome_message: Option<String>,
    /// Array of {did, hash} objects mapping members to key package hashes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_package_hashes: Option<Vec<KeyPackageHashEntry>>,
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
    /// Client-generated ULID for message deduplication
    pub msg_id: String,
    /// Deprecated: Use msgId instead
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    /// MLS encrypted message ciphertext bytes
    #[serde(with = "crate::atproto_bytes")]
    pub ciphertext: Vec<u8>,
    /// MLS epoch number when message was encrypted
    pub epoch: i64,
    /// Original plaintext size before padding
    pub declared_size: i64,
    /// Padded ciphertext size in bytes
    pub padded_size: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SendMessageOutput {
    /// Created message identifier
    pub message_id: String,
    /// Verified sender DID from JWT
    pub sender: String,
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
    #[serde(default = "default_limit_50")]
    pub limit: i32,
    /// Message ID to fetch messages after (pagination cursor)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since_message: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
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
    /// Base64-encoded MLS key package
    pub key_package: String,
    /// Client-generated UUID for idempotent request retries
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    /// Cipher suite of the key package
    pub cipher_suite: String,
    /// Expiration timestamp (max 90 days from now)
    pub expires: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct PublishKeyPackageOutput {}

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
// blue.catbird.mls.getKeyPackageStats
// =============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetKeyPackageStatsParams {
    /// DID to fetch stats for (defaults to authenticated user)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    /// Filter by specific cipher suite
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher_suite: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetKeyPackageStatsOutput {
    /// Number of unconsumed key packages available
    pub available: i32,
    /// Recommended minimum inventory threshold
    pub threshold: i32,
    /// True if available < threshold
    pub needs_replenish: bool,
    /// Human-readable time until oldest key package expires
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oldest_expires_in: Option<String>,
    /// Breakdown by cipher suite
    #[serde(skip_serializing_if = "Option::is_none")]
    pub by_cipher_suite: Option<Vec<CipherSuiteStats>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherSuiteStats {
    /// Cipher suite name
    pub cipher_suite: String,
    /// Available key packages for this suite
    pub available: i32,
    /// Total consumed key packages for this suite
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumed: Option<i32>,
}

// =============================================================================
// blue.catbird.mls.registerDevice
// =============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterDeviceInput {
    /// Human-readable device name
    pub device_name: String,
    /// Ed25519 public key (32 bytes)
    #[serde(with = "base64_bytes")]
    pub signature_public_key: Vec<u8>,
    /// Initial key packages for this device
    pub key_packages: Vec<KeyPackageRef>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterDeviceOutput {
    /// Unique device identifier (UUID)
    pub device_id: String,
    /// Device-specific MLS DID
    pub mls_did: String,
    /// List of conversation IDs where device was automatically added
    pub auto_joined_convos: Vec<String>,
    /// Welcome messages for each auto-joined conversation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub welcome_messages: Option<Vec<WelcomeMessageRef>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WelcomeMessageRef {
    /// Conversation identifier
    pub convo_id: String,
    /// Base64url-encoded MLS Welcome message
    pub welcome: String,
}

// =============================================================================
// blue.catbird.mls.promoteAdmin
// =============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PromoteAdminInput {
    /// Conversation identifier
    pub convo_id: String,
    /// DID of member to promote to admin
    pub target_did: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PromoteAdminOutput {
    /// Whether promotion succeeded
    pub ok: bool,
    /// Timestamp when member was promoted
    pub promoted_at: DateTime<Utc>,
}

// =============================================================================
// blue.catbird.mls.demoteAdmin
// =============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DemoteAdminInput {
    /// Conversation identifier
    pub convo_id: String,
    /// DID of admin to demote
    pub target_did: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DemoteAdminOutput {
    /// Whether demotion succeeded
    pub ok: bool,
}

// =============================================================================
// blue.catbird.mls.removeMember
// =============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveMemberInput {
    /// Conversation identifier
    pub convo_id: String,
    /// DID of member to remove
    pub target_did: String,
    /// Client-generated ULID for idempotent removal operations
    pub idempotency_key: String,
    /// Optional reason for removal
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveMemberOutput {
    /// Whether removal authorization succeeded
    pub ok: bool,
    /// Server's current observed epoch
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch_hint: Option<i32>,
}

// =============================================================================
// blue.catbird.mls.reportMember
// =============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportMemberInput {
    /// Conversation identifier
    pub convo_id: String,
    /// DID of member being reported
    pub reported_did: String,
    /// Report category
    pub category: String,
    /// Encrypted report blob
    #[serde(with = "base64_bytes")]
    pub encrypted_content: Vec<u8>,
    /// Optional list of message IDs being reported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_ids: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportMemberOutput {
    /// Unique report identifier
    pub report_id: String,
    /// When report was submitted
    pub submitted_at: DateTime<Utc>,
}

// =============================================================================
// blue.catbird.mls.getReports
// =============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetReportsParams {
    /// Conversation identifier
    pub convo_id: String,
    /// Filter by report status
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Maximum number of reports to return
    #[serde(default = "default_limit_50")]
    pub limit: i32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetReportsOutput {
    /// List of reports (encrypted content)
    pub reports: Vec<ReportView>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportView {
    /// Report identifier
    pub id: String,
    /// DID of member who submitted report
    pub reporter_did: String,
    /// DID of reported member
    pub reported_did: String,
    /// Encrypted report content
    #[serde(with = "base64_bytes")]
    pub encrypted_content: Vec<u8>,
    /// When report was submitted
    pub created_at: DateTime<Utc>,
    /// Report status
    pub status: String,
    /// DID of admin who resolved report
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_by: Option<String>,
    /// When report was resolved
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<DateTime<Utc>>,
}

// =============================================================================
// blue.catbird.mls.resolveReport
// =============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolveReportInput {
    /// Report identifier to resolve
    pub report_id: String,
    /// Action taken in response to report
    pub action: String,
    /// Optional internal notes about resolution
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolveReportOutput {
    /// Whether resolution succeeded
    pub ok: bool,
}

// =============================================================================
// blue.catbird.mls.checkBlocks
// =============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckBlocksParams {
    /// DIDs to check for mutual blocks (2-100 users)
    pub dids: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckBlocksOutput {
    /// List of block relationships between the provided DIDs
    pub blocks: Vec<BlockRelationship>,
    /// When the block status was checked
    pub checked_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockRelationship {
    /// DID of user who created the block
    pub blocker_did: String,
    /// DID of user who was blocked
    pub blocked_did: String,
    /// When the block was created on Bluesky
    pub created_at: DateTime<Utc>,
    /// AT-URI of the block record on Bluesky
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_uri: Option<String>,
}

// =============================================================================
// blue.catbird.mls.handleBlockChange
// =============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HandleBlockChangeInput {
    /// User who created or removed the block
    pub blocker_did: String,
    /// User who was blocked or unblocked
    pub blocked_did: String,
    /// Whether the block was created or removed
    pub action: String,
    /// AT-URI of the block record on Bluesky
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_uri: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HandleBlockChangeOutput {
    /// Conversations where both users are members
    pub affected_convos: Vec<AffectedConvo>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AffectedConvo {
    /// Conversation identifier
    pub convo_id: String,
    /// Action taken or required by admins
    pub action: String,
    /// Whether conversation admins were notified
    pub admin_notified: bool,
    /// When admin notification was sent
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_sent_at: Option<DateTime<Utc>>,
}

// =============================================================================
// blue.catbird.mls.getBlockStatus
// =============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockStatusParams {
    /// Conversation identifier
    pub convo_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockStatusOutput {
    /// Conversation identifier
    pub convo_id: String,
    /// True if any members have blocked each other
    pub has_conflicts: bool,
    /// List of block relationships between conversation members
    pub blocks: Vec<BlockRelationship>,
    /// When the block status was checked
    pub checked_at: DateTime<Utc>,
    /// Total number of members checked
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_count: Option<i32>,
}

// =============================================================================
// blue.catbird.mls.getAdminStats
// =============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetAdminStatsParams {
    /// Optional: Get stats for specific conversation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub convo_id: Option<String>,
    /// Optional: Only include stats since this timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetAdminStatsOutput {
    /// Aggregate moderation statistics
    pub stats: ModerationStats,
    /// When these statistics were generated
    pub generated_at: DateTime<Utc>,
    /// Conversation ID if stats are for a specific conversation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub convo_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModerationStats {
    /// Total number of member reports submitted
    pub total_reports: i32,
    /// Number of reports awaiting admin review
    pub pending_reports: i32,
    /// Number of reports resolved by admins
    pub resolved_reports: i32,
    /// Total number of members removed by admins
    pub total_removals: i32,
    /// Number of Bluesky block conflicts resolved by admins
    pub block_conflicts_resolved: i32,
    /// Breakdown of reports by category
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reports_by_category: Option<ReportCategoryCounts>,
    /// Average time to resolve reports (in hours)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub average_resolution_time_hours: Option<i32>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportCategoryCounts {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub harassment: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spam: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hate_speech: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub violence: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sexual_content: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impersonation: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privacy_violation: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub other_category: Option<i32>,
}

// =============================================================================
// blue.catbird.mls.rejoin
// =============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RejoinInput {
    /// Conversation identifier to rejoin
    pub convo_id: String,
    /// Base64url-encoded fresh MLS KeyPackage
    pub key_package: String,
    /// Optional reason for rejoin request
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RejoinOutput {
    /// Rejoin request identifier for tracking
    pub request_id: String,
    /// Whether request is pending approval or auto-approved
    pub pending: bool,
    /// Timestamp if request was auto-approved
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_at: Option<DateTime<Utc>>,
}

// =============================================================================
// blue.catbird.mls.getEpoch
// =============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetEpochParams {
    /// Conversation identifier
    pub convo_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetEpochOutput {
    /// Conversation identifier
    pub convo_id: String,
    /// Current MLS epoch number
    pub current_epoch: i32,
}

// =============================================================================
// blue.catbird.mls.getCommits
// =============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetCommitsParams {
    /// Conversation identifier
    pub convo_id: String,
    /// Starting epoch number (inclusive)
    pub from_epoch: i32,
    /// Ending epoch number (inclusive, optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_epoch: Option<i32>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetCommitsOutput {
    /// Conversation identifier
    pub convo_id: String,
    /// List of commit messages in the epoch range
    pub commits: Vec<CommitMessage>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommitMessage {
    /// MLS epoch number for this commit
    pub epoch: i32,
    /// DID of the member who created the commit
    pub sender: String,
    /// MLS commit message bytes
    #[serde(with = "base64_bytes")]
    pub commit_data: Vec<u8>,
    /// Timestamp when commit was created
    pub created_at: DateTime<Utc>,
}

// =============================================================================
// blue.catbird.mls.getWelcome
// =============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetWelcomeParams {
    /// Conversation identifier
    pub convo_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetWelcomeOutput {
    /// Conversation identifier
    pub convo_id: String,
    /// Base64url-encoded MLS Welcome message data
    pub welcome: String,
}

// =============================================================================
// blue.catbird.mls.confirmWelcome
// =============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmWelcomeInput {
    /// Conversation identifier
    pub convo_id: String,
    /// Whether the Welcome message was successfully processed
    pub success: bool,
    /// Optional error details if processing failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_details: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmWelcomeOutput {
    /// Whether the confirmation was accepted
    pub confirmed: bool,
}

// =============================================================================
// blue.catbird.mls.streamConvoEvents
// =============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamConvoEventsParams {
    /// Opaque resume cursor
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Optional conversation filter
    #[serde(skip_serializing_if = "Option::is_none")]
    pub convo_id: Option<String>,
}

/// SSE event types
#[derive(Debug, Serialize)]
#[serde(tag = "$type")]
pub enum ConvoEvent {
    #[serde(rename = "blue.catbird.mls.streamConvoEvents#messageEvent")]
    Message(MessageEvent),
    #[serde(rename = "blue.catbird.mls.streamConvoEvents#reactionEvent")]
    Reaction(ReactionEvent),
    #[serde(rename = "blue.catbird.mls.streamConvoEvents#typingEvent")]
    Typing(TypingEvent),
    #[serde(rename = "blue.catbird.mls.streamConvoEvents#infoEvent")]
    Info(InfoEvent),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageEvent {
    /// Resume cursor for this event position
    pub cursor: String,
    /// The message that was sent
    pub message: MessageView,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReactionEvent {
    /// Resume cursor for this event position
    pub cursor: String,
    /// Conversation identifier
    pub convo_id: String,
    /// ID of the message that was reacted to
    pub message_id: String,
    /// DID of the user who performed the reaction
    pub did: String,
    /// Reaction content (emoji or short code)
    pub reaction: String,
    /// Action performed: 'add' or 'remove'
    pub action: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TypingEvent {
    /// Resume cursor for this event position
    pub cursor: String,
    /// Conversation identifier
    pub convo_id: String,
    /// DID of the user typing
    pub did: String,
    /// True if the user started typing, false if they stopped
    pub is_typing: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InfoEvent {
    /// Resume cursor for this event position
    pub cursor: String,
    /// Human-readable info or keep-alive message
    pub info: String,
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
            .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&s))
            .map_err(serde::de::Error::custom)
    }
}

mod optional_base64_bytes {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match bytes {
            Some(b) => {
                let encoded = base64::engine::general_purpose::STANDARD.encode(b);
                serializer.serialize_some(&encoded)
            }
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: Option<String> = Option::deserialize(deserializer)?;
        match s {
            Some(s) => {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(&s)
                    .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&s))
                    .map_err(serde::de::Error::custom)?;
                Ok(Some(bytes))
            }
            None => Ok(None),
        }
    }
}

// =============================================================================
// Default values
// =============================================================================

fn default_limit_50() -> i32 {
    50
}
