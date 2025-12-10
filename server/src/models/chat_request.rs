//! Chat request models for E2EE message holding system
//!
//! Allows users to send chat requests that hold encrypted messages
//! until accepted, with rate limiting and expiration.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

// =============================================================================
// Chat Request Status
// =============================================================================

/// Status of a chat request
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "chat_request_status", rename_all = "lowercase")]
pub enum ChatRequestStatus {
    #[serde(rename = "pending")]
    Pending,
    #[serde(rename = "accepted")]
    Accepted,
    #[serde(rename = "declined")]
    Declined,
    #[serde(rename = "blocked")]
    Blocked,
    #[serde(rename = "expired")]
    Expired,
}

impl std::fmt::Display for ChatRequestStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Accepted => write!(f, "accepted"),
            Self::Declined => write!(f, "declined"),
            Self::Blocked => write!(f, "blocked"),
            Self::Expired => write!(f, "expired"),
        }
    }
}

impl ChatRequestStatus {
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Pending)
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Accepted | Self::Declined | Self::Blocked | Self::Expired)
    }
}

// =============================================================================
// Chat Request
// =============================================================================

/// Database representation of a chat request
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ChatRequest {
    pub id: String,  // ULID
    pub sender_did: String,
    pub recipient_did: String,
    pub status: ChatRequestStatus,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    
    // Group invite fields
    pub is_group_invite: bool,
    pub group_id: Option<String>,
    
    // Held message metadata
    pub held_message_count: i32,
    pub first_message_preview: Option<String>,
    
    // Acceptance tracking
    pub accepted_at: Option<DateTime<Utc>>,
    pub accepted_convo_id: Option<String>,
    
    // Blocking
    pub blocked_at: Option<DateTime<Utc>>,
    pub blocked_reason: Option<String>,
}

impl ChatRequest {
    /// Check if request is still pending and not expired
    pub fn is_pending(&self) -> bool {
        self.status == ChatRequestStatus::Pending && self.expires_at > Utc::now()
    }

    /// Check if request is expired
    pub fn is_expired(&self) -> bool {
        self.status == ChatRequestStatus::Pending && self.expires_at <= Utc::now()
    }

    /// Check if request can be accepted
    pub fn can_accept(&self) -> bool {
        self.is_pending() && !self.is_group_invite
    }

    /// Check if request can be declined
    pub fn can_decline(&self) -> bool {
        self.status == ChatRequestStatus::Pending
    }

    /// Check if request is a group invite
    pub fn is_group_request(&self) -> bool {
        self.is_group_invite && self.group_id.is_some()
    }

    /// Get the conversation ID (either accepted_convo_id or group_id for invites)
    pub fn conversation_id(&self) -> Option<&str> {
        self.accepted_convo_id.as_deref()
            .or_else(|| self.group_id.as_deref())
    }
}

// =============================================================================
// Held Message
// =============================================================================

/// Database representation of a held encrypted message
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct HeldMessage {
    pub id: String,  // ULID
    pub request_id: String,
    
    // MLS ciphertext
    #[sqlx(default)]
    pub ciphertext: Vec<u8>,
    
    // Ephemeral key material
    pub eph_pub_key: Option<Vec<u8>>,
    
    // Ordering
    pub sequence: i32,
    pub created_at: DateTime<Utc>,
    
    // Privacy
    pub padded_size: i32,
}

impl HeldMessage {
    /// Get the sequence number as usize
    pub fn sequence_num(&self) -> usize {
        self.sequence as usize
    }

    /// Get the padded size as usize
    pub fn size(&self) -> usize {
        self.padded_size as usize
    }
}

// =============================================================================
// Rate Limiting
// =============================================================================

/// Database representation of rate limiting state for chat requests
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ChatRequestRateLimit {
    pub sender_did: String,
    pub recipient_did: String,
    
    // Rate limiting counters
    pub request_count: i32,
    pub last_request_at: DateTime<Utc>,
    pub window_start: DateTime<Utc>,
    
    // Block tracking
    pub blocked_until: Option<DateTime<Utc>>,
    pub block_count: i32,
}

impl ChatRequestRateLimit {
    /// Check if sender is currently blocked
    pub fn is_blocked(&self) -> bool {
        self.blocked_until
            .map(|until| until > Utc::now())
            .unwrap_or(false)
    }

    /// Check if rate limit window has expired (typically 24 hours)
    pub fn is_window_expired(&self, window_duration: chrono::Duration) -> bool {
        Utc::now() - self.window_start > window_duration
    }

    /// Get remaining time until unblocked
    pub fn blocked_duration(&self) -> Option<chrono::Duration> {
        self.blocked_until
            .map(|until| until - Utc::now())
            .filter(|d| d.num_seconds() > 0)
    }
}

// =============================================================================
// Builder Patterns and Helpers
// =============================================================================

/// Builder for creating a new chat request
pub struct ChatRequestBuilder {
    sender_did: String,
    recipient_did: String,
    expires_at: Option<DateTime<Utc>>,
    is_group_invite: bool,
    group_id: Option<String>,
    first_message_preview: Option<String>,
}

impl ChatRequestBuilder {
    pub fn new(sender_did: String, recipient_did: String) -> Self {
        Self {
            sender_did,
            recipient_did,
            expires_at: None,
            is_group_invite: false,
            group_id: None,
            first_message_preview: None,
        }
    }

    pub fn expires_at(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    pub fn expires_in_days(mut self, days: i64) -> Self {
        self.expires_at = Some(Utc::now() + chrono::Duration::days(days));
        self
    }

    pub fn group_invite(mut self, group_id: String) -> Self {
        self.is_group_invite = true;
        self.group_id = Some(group_id);
        self
    }

    pub fn with_preview(mut self, preview: String) -> Self {
        self.first_message_preview = Some(preview);
        self
    }

    pub fn build(self) -> ChatRequestParams {
        ChatRequestParams {
            sender_did: self.sender_did,
            recipient_did: self.recipient_did,
            expires_at: self.expires_at.unwrap_or_else(|| Utc::now() + chrono::Duration::days(7)),
            is_group_invite: self.is_group_invite,
            group_id: self.group_id,
            first_message_preview: self.first_message_preview,
        }
    }
}

/// Parameters for creating a chat request
#[derive(Debug, Clone)]
pub struct ChatRequestParams {
    pub sender_did: String,
    pub recipient_did: String,
    pub expires_at: DateTime<Utc>,
    pub is_group_invite: bool,
    pub group_id: Option<String>,
    pub first_message_preview: Option<String>,
}

/// Builder for creating a held message
pub struct HeldMessageBuilder {
    request_id: String,
    ciphertext: Vec<u8>,
    sequence: i32,
    eph_pub_key: Option<Vec<u8>>,
    padded_size: Option<i32>,
}

impl HeldMessageBuilder {
    pub fn new(request_id: String, ciphertext: Vec<u8>, sequence: i32) -> Self {
        Self {
            request_id,
            ciphertext,
            sequence,
            eph_pub_key: None,
            padded_size: None,
        }
    }

    pub fn with_ephemeral_key(mut self, key: Vec<u8>) -> Self {
        self.eph_pub_key = Some(key);
        self
    }

    pub fn with_padded_size(mut self, size: i32) -> Self {
        self.padded_size = Some(size);
        self
    }

    pub fn build(self) -> HeldMessageParams {
        let actual_size = self.ciphertext.len() as i32;
        HeldMessageParams {
            request_id: self.request_id,
            ciphertext: self.ciphertext,
            sequence: self.sequence,
            eph_pub_key: self.eph_pub_key,
            padded_size: self.padded_size.unwrap_or(actual_size),
        }
    }
}

/// Parameters for creating a held message
#[derive(Debug, Clone)]
pub struct HeldMessageParams {
    pub request_id: String,
    pub ciphertext: Vec<u8>,
    pub sequence: i32,
    pub eph_pub_key: Option<Vec<u8>>,
    pub padded_size: i32,
}

// =============================================================================
// Input/Output Types for Handlers
// =============================================================================

/// Input for sending a chat request
#[derive(Debug, Deserialize)]
pub struct SendRequestInput {
    pub recipient_did: String,
    pub held_ciphertext: Option<Vec<u8>>,
    pub held_eph_pub_key: Option<Vec<u8>>,
    pub group_id: Option<String>,
}

/// Output for sending a chat request
#[derive(Debug, Serialize)]
pub struct SendRequestOutput {
    pub request_id: Option<String>,
    pub status: String,
    pub bypass_request: bool,
}

/// Input for listing chat requests
#[derive(Debug, Deserialize)]
pub struct ListRequestsInput {
    pub cursor: Option<String>,
    pub limit: Option<i32>,
}

/// Output for listing chat requests
#[derive(Debug, Serialize)]
pub struct ListRequestsOutput {
    pub requests: Vec<ChatRequest>,
    pub cursor: Option<String>,
}

/// Input for accepting a chat request
#[derive(Debug, Deserialize)]
pub struct AcceptRequestInput {
    pub request_id: String,
}

/// Output for accepting a chat request
#[derive(Debug, Serialize)]
pub struct AcceptRequestOutput {
    pub conversation_id: String,
    pub welcome_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chat_request_status() {
        assert!(ChatRequestStatus::Pending.is_active());
        assert!(!ChatRequestStatus::Accepted.is_active());
        assert!(ChatRequestStatus::Accepted.is_terminal());
        assert!(!ChatRequestStatus::Pending.is_terminal());
    }

    #[test]
    fn test_chat_request_builder() {
        let params = ChatRequestBuilder::new(
            "did:plc:sender".to_string(),
            "did:plc:recipient".to_string()
        )
        .expires_in_days(7)
        .with_preview("Hello!".to_string())
        .build();

        assert_eq!(params.sender_did, "did:plc:sender");
        assert_eq!(params.recipient_did, "did:plc:recipient");
        assert_eq!(params.first_message_preview, Some("Hello!".to_string()));
        assert!(!params.is_group_invite);
    }

    #[test]
    fn test_rate_limit_blocked() {
        let mut limit = ChatRequestRateLimit {
            sender_did: "did:plc:sender".to_string(),
            recipient_did: "did:plc:recipient".to_string(),
            request_count: 5,
            last_request_at: Utc::now(),
            window_start: Utc::now() - chrono::Duration::hours(1),
            blocked_until: Some(Utc::now() + chrono::Duration::hours(1)),
            block_count: 1,
        };

        assert!(limit.is_blocked());

        limit.blocked_until = Some(Utc::now() - chrono::Duration::hours(1));
        assert!(!limit.is_blocked());
    }
}
