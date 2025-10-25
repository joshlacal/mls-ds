use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::info;

/// Envelope representing a message delivery target
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub id: String,
    pub convo_id: String,
    pub recipient_did: String,
    pub message_id: String,
}

/// Trait for pluggable mailbox backends
#[async_trait]
pub trait MailboxBackend: Send + Sync {
    /// Notify the backend about a new envelope
    async fn notify(&self, envelope: &Envelope) -> Result<()>;

    /// Backend identifier
    fn provider_name(&self) -> &'static str;
}

/// Null backend for clients relying solely on realtime events
pub struct NullBackend;

#[async_trait]
impl MailboxBackend for NullBackend {
    async fn notify(&self, envelope: &Envelope) -> Result<()> {
        info!(
            envelope_id = %envelope.id,
            recipient = %envelope.recipient_did,
            "Null backend, no mailbox notification sent (relying on SSE)"
        );
        Ok(())
    }

    fn provider_name(&self) -> &'static str {
        "null"
    }
}

/// Factory for creating mailbox backends
pub struct MailboxFactory;

impl MailboxFactory {
    pub fn create(_provider: &str, _config: &MailboxConfig) -> Box<dyn MailboxBackend> {
        // For text-only v1, always use NullBackend (rely on SSE)
        Box::new(NullBackend)
    }
}

/// Configuration for mailbox backends
#[derive(Clone)]
pub struct MailboxConfig {
    // Reserved for future use
}

impl Default for MailboxConfig {
    fn default() -> Self {
        Self {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_null_backend() {
        let backend = NullBackend;
        let envelope = Envelope {
            id: "env1".to_string(),
            convo_id: "convo1".to_string(),
            recipient_did: "did:plc:test".to_string(),
            message_id: "msg1".to_string(),
        };

        assert!(backend.notify(&envelope).await.is_ok());
        assert_eq!(backend.provider_name(), "null");
    }

    #[test]
    fn test_factory() {
        let config = MailboxConfig::default();

        let backend = MailboxFactory::create("any", &config);
        assert_eq!(backend.provider_name(), "null");
    }
}
