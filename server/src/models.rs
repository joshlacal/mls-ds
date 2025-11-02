use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Conversation {
    pub id: String,
    pub creator_did: String,
    pub current_epoch: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub title: Option<String>,
    pub group_id: Option<String>,
    pub cipher_suite: Option<String>,
}

impl Conversation {
    pub fn new(creator_did: String, metadata: Option<ConvoMetadata>) -> Self {
        let (title, _description) = if let Some(m) = metadata {
            (m.name, m.description)
        } else {
            (None, None)
        };
        
        let now = Utc::now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            creator_did,
            current_epoch: 0,
            created_at: now,
            updated_at: now,
            title,
            group_id: None,
            cipher_suite: None,
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
    pub epoch: i64,
    pub seq: i64,
    pub ciphertext: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl Message {
    pub fn new(
        convo_id: String,
        sender_did: String,
        message_type: String,
        epoch: i64,
        seq: i64,
        ciphertext: Vec<u8>,
    ) -> Self {
        let now = Utc::now();
        let expires_at = now + chrono::Duration::days(30);
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            convo_id,
            sender_did,
            message_type,
            epoch,
            seq,
            ciphertext,
            created_at: now,
            expires_at: Some(expires_at),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct KeyPackage {
    pub did: String,
    pub cipher_suite: String,
    pub key_data: Vec<u8>,
    pub key_package_hash: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub consumed: bool,
}

impl KeyPackage {
    pub fn is_valid(&self) -> bool {
        !self.consumed && self.expires_at > Utc::now()
    }
}

// API Request/Response types

#[derive(Debug, Deserialize)]
pub struct KeyPackageHashEntry {
    #[serde(rename = "$type")]
    pub type_field: Option<String>,
    pub did: String,
    pub hash: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateConvoInput {
    #[serde(rename = "groupId")]
    pub group_id: String,
    #[serde(rename = "cipherSuite")]
    pub cipher_suite: String,
    #[serde(rename = "initialMembers")]
    pub initial_members: Option<Vec<String>>,
    pub metadata: Option<ConvoMetadata>,
    /// Single Welcome message for ALL initial members (base64url encoded)
    /// Contains encrypted secrets that each member can decrypt
    #[serde(rename = "welcomeMessage", skip_serializing_if = "Option::is_none")]
    pub welcome_message: Option<String>,
    /// Array of {did, hash} objects for each initial member
    /// This tells the server which key package was used for each member's Welcome
    #[serde(rename = "keyPackageHashes", skip_serializing_if = "Option::is_none")]
    pub key_package_hashes: Option<Vec<KeyPackageHashEntry>>,
    /// Optional idempotency key for preventing duplicate conversations
    #[serde(rename = "idempotencyKey", skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ConvoMetadata {
    pub name: Option<String>,
    pub description: Option<String>,
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
}

#[derive(Debug, Deserialize)]
pub struct AddMembersInput {
    #[serde(rename = "convoId")]
    pub convo_id: String,
    #[serde(rename = "didList")]
    pub did_list: Vec<String>,
    pub commit: Option<String>, // base64url encoded
    /// Single Welcome message for ALL new members (base64url encoded)
    /// Contains encrypted secrets that each member can decrypt
    #[serde(rename = "welcomeMessage", skip_serializing_if = "Option::is_none")]
    pub welcome_message: Option<String>,
    /// Array of {did, hash} objects for each new member
    /// This tells the server which key package was used for each member's Welcome
    #[serde(rename = "keyPackageHashes", skip_serializing_if = "Option::is_none")]
    pub key_package_hashes: Option<Vec<KeyPackageHashEntry>>,
    /// Optional idempotency key for preventing duplicate member additions
    #[serde(rename = "idempotencyKey", skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
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
    /// Direct ciphertext payload stored in PostgreSQL
    /// Contains encrypted JSON with version, text, and optional embed
    #[serde(with = "base64_bytes")]
    pub ciphertext: Vec<u8>,
    pub epoch: i64,
    #[serde(rename = "senderDid")]
    pub sender_did: String,
    /// Optional idempotency key for preventing duplicate messages
    #[serde(rename = "idempotencyKey", skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

mod base64_bytes {
    use serde::{Deserialize, Deserializer, Serializer};
    use base64::Engine;
    use serde_json::Value;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Handle both formats:
        // 1. Plain base64 string: "base64data"
        // 2. AT Protocol $bytes format: {"$bytes": "base64data"}
        let value = Value::deserialize(deserializer)?;

        let base64_str = match value {
            Value::String(s) => s,
            Value::Object(mut map) => {
                map.remove("$bytes")
                    .and_then(|v| v.as_str().map(String::from))
                    .ok_or_else(|| serde::de::Error::custom("Expected $bytes field in object"))?
            }
            _ => return Err(serde::de::Error::custom("Expected string or $bytes object")),
        };

        // Try STANDARD base64 first (with +/), then fall back to URL_SAFE_NO_PAD
        base64::engine::general_purpose::STANDARD
            .decode(&base64_str)
            .or_else(|_| {
                base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&base64_str)
            })
            .map_err(serde::de::Error::custom)
    }

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Use STANDARD base64 for Swift compatibility
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);

        // Serialize as AT Protocol $bytes format: {"$bytes": "base64data"}
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry("$bytes", &encoded)?;
        map.end()
    }
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
    #[serde(rename = "convoId")]
    pub convo_id: String,
    pub sender: String, // DID
    #[serde(with = "base64_bytes")]
    pub ciphertext: Vec<u8>,
    pub epoch: i64,
    pub seq: i64,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
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
    #[serde(rename = "keyPackageHash")]
    pub key_package_hash: String,
}

// Welcome message models


#[derive(Debug, Serialize)]
pub struct GetWelcomeOutput {
    #[serde(rename = "convoId")]
    pub convo_id: String,
    /// Base64url-encoded Welcome message data
    pub welcome: String,
}

#[derive(Debug, Serialize)]
pub struct ConfirmWelcomeOutput {
    pub confirmed: bool,
}
