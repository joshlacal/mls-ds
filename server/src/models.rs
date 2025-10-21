use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Conversation {
    pub id: String,
    pub creator_did: String,
    pub current_epoch: i32,
    pub created_at: DateTime<Utc>,
    pub title: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Membership {
    pub convo_id: String,
    pub member_did: String,
    pub joined_at: DateTime<Utc>,
    pub left_at: Option<DateTime<Utc>>,
    pub unread_count: i32,
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

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct KeyPackage {
    pub did: String,
    pub cipher_suite: String,
    pub key_data: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub consumed: bool,
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
    #[serde(rename = "didList")]
    pub did_list: Option<Vec<String>>,
    pub title: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ConvoView {
    pub id: String,
    pub members: Vec<MemberInfo>,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[serde(rename = "unreadCount")]
    pub unread_count: i32,
    pub epoch: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MemberInfo {
    pub did: String,
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
