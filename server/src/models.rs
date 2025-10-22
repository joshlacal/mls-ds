use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Conversation {
    pub id: String,
    pub creator_did: String,
    pub current_epoch: i32,
    pub created_at: DateTime<Utc>,
    pub cipher_suite: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub avatar_blob: Option<String>,
}

impl Conversation {
    pub fn new(creator_did: String, cipher_suite: String, metadata: Option<ConvoMetadata>) -> Self {
        let (name, description, avatar_blob) = if let Some(m) = metadata {
            (m.name, m.description, m.avatar)
        } else {
            (None, None, None)
        };
        
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            creator_did,
            current_epoch: 0,
            created_at: Utc::now(),
            cipher_suite,
            name,
            description,
            avatar_blob,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Membership {
    pub convo_id: String,
    pub member_did: String,
    pub joined_at: DateTime<Utc>,
    pub left_at: Option<DateTime<Utc>>,
    pub unread_count: i32,
}

impl Membership {
    pub fn is_active(&self) -> bool {
        self.left_at.is_none()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Message {
    pub id: String,
    pub convo_id: String,
    pub sender_did: String,
    pub message_type: String, // "app" or "commit"
    pub epoch: i32,
    pub ciphertext: Vec<u8>,
    pub sent_at: DateTime<Utc>,
}

impl Message {
    pub fn new(
        convo_id: String,
        sender_did: String,
        message_type: String,
        epoch: i32,
        ciphertext: Vec<u8>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            convo_id,
            sender_did,
            message_type,
            epoch,
            ciphertext,
            sent_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct KeyPackage {
    pub did: String,
    pub cipher_suite: String,
    pub key_data: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub consumed: bool,
}

impl KeyPackage {
    pub fn is_valid(&self) -> bool {
        !self.consumed && self.expires_at > Utc::now()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Blob {
    pub cid: String,
    pub data: Vec<u8>,
    pub size: i64,
    pub uploaded_by_did: String,
    pub convo_id: Option<String>,
    pub uploaded_at: DateTime<Utc>,
}

// API Request/Response types

#[derive(Debug, Deserialize)]
pub struct CreateConvoInput {
    #[serde(rename = "cipherSuite")]
    pub cipher_suite: String,
    #[serde(rename = "initialMembers")]
    pub initial_members: Option<Vec<String>>,
    pub metadata: Option<ConvoMetadata>,
}

#[derive(Debug, Deserialize)]
pub struct ConvoMetadata {
    pub name: Option<String>,
    pub description: Option<String>,
    pub avatar: Option<String>, // blob reference or base64
}

#[derive(Debug, Serialize)]
pub struct ConvoView {
    pub id: String,
    #[serde(rename = "groupId")]
    pub group_id: String,
    pub creator: String,
    pub members: Vec<MemberView>,
    pub epoch: i32,
    #[serde(rename = "cipherSuite")]
    pub cipher_suite: String,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "lastMessageAt")]
    pub last_message_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ConvoMetadataView>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MemberInfo {
    pub did: String,
}

#[derive(Debug, Serialize)]
pub struct MemberView {
    pub did: String,
    #[serde(rename = "joinedAt")]
    pub joined_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "leafIndex")]
    pub leaf_index: Option<i32>,
}

#[derive(Debug, Serialize)]
pub struct ConvoMetadataView {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar: Option<BlobRef>,
}

#[derive(Debug, Deserialize)]
pub struct AddMembersInput {
    #[serde(rename = "convoId")]
    pub convo_id: String,
    #[serde(rename = "didList")]
    pub did_list: Vec<String>,
    pub commit: Option<String>, // base64url encoded
    pub welcome: Option<String>, // base64url encoded
}

#[derive(Debug, Serialize)]
pub struct AddMembersOutput {
    pub success: bool,
    #[serde(rename = "newEpoch")]
    pub new_epoch: i32,
}

#[derive(Debug, Deserialize)]
pub struct SendMessageInput {
    #[serde(rename = "convoId")]
    pub convo_id: String,
    pub ciphertext: String, // base64url encoded
    pub epoch: i32,
    #[serde(rename = "senderDid")]
    pub sender_did: String,
}

#[derive(Debug, Serialize)]
pub struct SendMessageOutput {
    #[serde(rename = "messageId")]
    pub message_id: String,
    #[serde(rename = "receivedAt")]
    pub received_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct LeaveConvoInput {
    #[serde(rename = "convoId")]
    pub convo_id: String,
    #[serde(rename = "targetDid")]
    pub target_did: Option<String>,
    pub commit: Option<String>, // base64url encoded
}

#[derive(Debug, Serialize)]
pub struct LeaveConvoOutput {
    pub success: bool,
    #[serde(rename = "newEpoch")]
    pub new_epoch: i32,
}

#[derive(Debug, Serialize)]
pub struct MessageView {
    pub id: String,
    pub ciphertext: String, // base64url
    pub epoch: i32,
    pub sender: MemberInfo,
    #[serde(rename = "sentAt")]
    pub sent_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct PublishKeyPackageInput {
    #[serde(rename = "keyPackage")]
    pub key_package: String, // base64url
    #[serde(rename = "cipherSuite")]
    pub cipher_suite: String,
    pub expires: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct KeyPackageInfo {
    pub did: String,
    #[serde(rename = "keyPackage")]
    pub key_package: String, // base64url
    #[serde(rename = "cipherSuite")]
    pub cipher_suite: String,
}

#[derive(Debug, Serialize)]
pub struct BlobRef {
    pub cid: String,
    pub size: i64,
}
