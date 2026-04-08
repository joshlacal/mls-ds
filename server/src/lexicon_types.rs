// Auto-generated types from AT Protocol Lexicons
// DO NOT EDIT - Generated from lexicon/*.json

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// blue.catbird.mlsChat.defs#cipherSuiteEnum
pub type CipherSuite = String;

// blue.catbird.mlsChat.defs#blobRef
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobRef {
    pub cid: String,
    #[serde(rename = "mimeType")]
    pub mime_type: String,
    pub size: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "ref")]
    pub ref_uri: Option<String>,
}

// blue.catbird.mlsChat.defs#memberView
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberView {
    pub did: String,
    #[serde(rename = "joinedAt")]
    pub joined_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "leafIndex")]
    pub leaf_index: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
}

// blue.catbird.mlsChat.defs#convoView metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConvoMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar: Option<BlobRef>,
}

// blue.catbird.mlsChat.defs#convoView
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConvoView {
    pub id: String,
    #[serde(rename = "conversationId")]
    pub conversation_id: String,
    #[serde(rename = "groupId")]
    pub group_id: String,
    pub creator: String,
    pub members: Vec<MemberView>,
    pub epoch: i32,
    #[serde(rename = "cipherSuite")]
    pub cipher_suite: CipherSuite,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "lastMessageAt")]
    pub last_message_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ConvoMetadata>,
}

// blue.catbird.mlsChat.createConvo input metadata
#[derive(Debug, Clone, Deserialize)]
pub struct CreateConvoMetadataInput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar: Option<Vec<u8>>, // Blob data
}

// blue.catbird.mlsChat.createConvo input
#[derive(Debug, Clone, Deserialize)]
pub struct CreateConvoInput {
    #[serde(rename = "cipherSuite")]
    pub cipher_suite: CipherSuite,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "initialMembers")]
    pub initial_members: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<CreateConvoMetadataInput>,
}

// blue.catbird.mlsChat.getConvos output
#[derive(Debug, Clone, Serialize)]
pub struct GetConvosOutput {
    pub conversations: Vec<ConvoView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

// blue.catbird.mlsChat.defs#messageView
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageView {
    pub id: String,
    #[serde(rename = "convoId")]
    pub convo_id: String,
    pub sender: String,
    pub ciphertext: String,
    pub epoch: i32,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "contentType")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachments: Option<Vec<BlobRef>>,
}

// blue.catbird.mlsChat.sendMessage input
#[derive(Debug, Clone, Deserialize)]
pub struct SendMessageInput {
    #[serde(rename = "convoId")]
    pub convo_id: String,
    #[serde(rename = "msgId")]
    pub msg_id: String,
    pub ciphertext: String,
    pub epoch: i32,
    #[serde(rename = "declaredSize")]
    pub declared_size: i32,
    #[serde(rename = "paddedSize")]
    pub padded_size: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "idempotencyKey")]
    pub idempotency_key: Option<String>,
}

// blue.catbird.mlsChat.sendMessage output
#[derive(Debug, Clone, Serialize)]
pub struct SendMessageOutput {
    #[serde(rename = "messageId")]
    pub message_id: String,
    #[serde(rename = "receivedAt")]
    pub received_at: DateTime<Utc>,
}

// blue.catbird.mlsChat.getMessages output
#[derive(Debug, Clone, Serialize)]
pub struct GetMessagesOutput {
    pub messages: Vec<MessageView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

// blue.catbird.mlsChat.addMembers input
#[derive(Debug, Clone, Deserialize)]
pub struct AddMembersInput {
    #[serde(rename = "convoId")]
    pub convo_id: String,
    #[serde(rename = "didList")]
    pub did_list: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub welcome: Option<String>,
}

// blue.catbird.mlsChat.addMembers output
#[derive(Debug, Clone, Serialize)]
pub struct AddMembersOutput {
    pub success: bool,
    #[serde(rename = "newEpoch")]
    pub new_epoch: i32,
}

// blue.catbird.mlsChat.leaveConvo input
#[derive(Debug, Clone, Deserialize)]
pub struct LeaveConvoInput {
    #[serde(rename = "convoId")]
    pub convo_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "targetDid")]
    pub target_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
}

// blue.catbird.mlsChat.leaveConvo output
#[derive(Debug, Clone, Serialize)]
pub struct LeaveConvoOutput {
    pub success: bool,
    #[serde(rename = "newEpoch")]
    pub new_epoch: i32,
}

// blue.catbird.mlsChat.defs#keyPackageRef
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPackageRef {
    pub id: String,
    pub did: String,
    #[serde(rename = "keyPackage")]
    pub key_package: String,
    #[serde(rename = "cipherSuite")]
    pub cipher_suite: CipherSuite,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "expiresAt")]
    pub expires_at: Option<DateTime<Utc>>,
}

// blue.catbird.mlsChat.publishKeyPackage input
#[derive(Debug, Clone, Deserialize)]
pub struct PublishKeyPackageInput {
    #[serde(rename = "keyPackage")]
    pub key_package: String,
    #[serde(rename = "cipherSuite")]
    pub cipher_suite: CipherSuite,
    pub expires: DateTime<Utc>,
}

// blue.catbird.mlsChat.getKeyPackages output
#[derive(Debug, Clone, Serialize)]
pub struct GetKeyPackagesOutput {
    #[serde(rename = "keyPackages")]
    pub key_packages: Vec<KeyPackageRef>,
}

// blue.catbird.mlsChat.uploadBlob output
#[derive(Debug, Clone, Serialize)]
pub struct UploadBlobOutput {
    #[serde(rename = "blobId")]
    pub blob_id: String,
    pub size: i64,
}

// blue.catbird.mlsChat.getKeyPackageStats output
#[derive(Debug, Clone, Serialize)]
pub struct GetKeyPackageStatsOutput {
    pub available: i32,
    pub threshold: i32,
    #[serde(rename = "needsReplenish")]
    pub needs_replenish: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "oldestExpiresIn")]
    pub oldest_expires_in: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "byCipherSuite")]
    pub by_cipher_suite: Option<Vec<KeyPackageStatsByCipherSuite>>,
}

// blue.catbird.mlsChat.getKeyPackageStats cipher suite breakdown
#[derive(Debug, Clone, Serialize)]
pub struct KeyPackageStatsByCipherSuite {
    #[serde(rename = "cipherSuite")]
    pub cipher_suite: String,
    pub available: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumed: Option<i32>,
}
