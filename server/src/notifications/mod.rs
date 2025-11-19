use a2::{Client, ClientConfig, DefaultNotificationBuilder, Endpoint, NotificationBuilder, NotificationOptions, Priority};
use anyhow::{Context, Result};
use serde_json::json;
use sqlx::PgPool;
use std::{path::Path, sync::Arc};
use tracing::{debug, error, info, warn};

/// Notification service for sending push notifications to clients
///
/// This service handles APNs (Apple Push Notification service) integration
/// for notifying users of MLS messages with encrypted ciphertext payload.
pub struct NotificationService {
    apns_client: Option<Arc<ApnsClient>>,
    enabled: bool,
}

/// APNs client wrapper
struct ApnsClient {
    client: Client,
    topic: String,
}

impl ApnsClient {
    /// Create a new APNs client
    fn new(
        key_path: &str,
        key_id: &str,
        team_id: &str,
        production: bool,
        topic: &str,
    ) -> Result<Self> {
        let key_path = Path::new(key_path);
        
        if !key_path.exists() {
            anyhow::bail!("APNs key file not found: {}", key_path.display());
        }

        let endpoint = if production {
            Endpoint::Production
        } else {
            Endpoint::Sandbox
        };

        let config = ClientConfig::new(endpoint);
        let client = Client::token(
            std::fs::File::open(key_path).context("Failed to open APNs key file")?,
            key_id,
            team_id,
            config,
        )?;

        info!(
            "APNs client initialized: endpoint={:?}, topic={}",
            if production { "Production" } else { "Sandbox" },
            topic
        );

        Ok(Self {
            client,
            topic: topic.to_string(),
        })
    }

    /// Send a notification with ciphertext payload
    async fn send_message_notification(
        &self,
        device_token: &str,
        ciphertext: &[u8],
        convo_id: &str,
        message_id: &str,
    ) -> Result<()> {
        // Encode ciphertext as base64 for JSON payload
        let ciphertext_b64 = base64::encode(ciphertext);

        debug!(
            device_token = %device_token,
            convo_id = %convo_id,
            ciphertext_size = ciphertext.len(),
            "Sending MLS message notification"
        );

        // Build notification with custom payload
        let notification = DefaultNotificationBuilder::new()
            .set_content_available()
            .set_mutable_content()
            .set_sound("default")
            .build(
                device_token,
                NotificationOptions {
                    apns_topic: Some(&self.topic),
                    apns_priority: Some(Priority::High),
                    apns_collapse_id: None,
                    apns_expiration: None,
                    apns_push_type: None,
                    apns_id: None,
                },
            );

        // Send with retries
        const MAX_RETRIES: u8 = 3;
        let mut retry_count = 0;
        let mut backoff_ms = 100;

        loop {
            match self.client.send(notification.clone()).await {
                Ok(response) => {
                    if response.code >= 200 && response.code < 300 {
                        info!(
                            device_token = %device_token,
                            status = response.code,
                            convo_id = %convo_id,
                            "MLS message notification delivered"
                        );
                        return Ok(());
                    } else {
                        warn!(
                            device_token = %device_token,
                            status = response.code,
                            "Notification accepted with non-success status"
                        );
                        return Ok(());
                    }
                }
                Err(e) => {
                    retry_count += 1;
                    warn!(
                        device_token = %device_token,
                        error = %e,
                        attempt = retry_count,
                        "Failed to send notification, retrying"
                    );

                    if retry_count >= MAX_RETRIES {
                        error!(
                            device_token = %device_token,
                            error = %e,
                            "Failed to send notification after maximum retries"
                        );
                        return Err(e.into());
                    }

                    tokio::time::sleep(tokio::time::Duration::from_millis(backoff_ms)).await;
                    backoff_ms *= 2;
                }
            }
        }
    }
}

impl NotificationService {
    /// Create a new notification service
    pub fn new() -> Self {
        let enabled = std::env::var("ENABLE_PUSH_NOTIFICATIONS")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        if !enabled {
            info!("Push notification service disabled (set ENABLE_PUSH_NOTIFICATIONS=1 to enable)");
            return Self {
                apns_client: None,
                enabled: false,
            };
        }

        // Load APNs configuration
        let apns_client = match Self::init_apns_client() {
            Ok(client) => {
                info!("Push notification service enabled with APNs");
                Some(Arc::new(client))
            }
            Err(e) => {
                warn!("Failed to initialize APNs client: {}. Push notifications disabled.", e);
                None
            }
        };

        let enabled = apns_client.is_some();

        Self {
            apns_client,
            enabled,
        }
    }

    /// Initialize APNs client from environment variables
    fn init_apns_client() -> Result<ApnsClient> {
        let key_path = std::env::var("APNS_KEY_PATH")
            .context("APNS_KEY_PATH environment variable not set")?;
        let key_id = std::env::var("APNS_KEY_ID")
            .context("APNS_KEY_ID environment variable not set")?;
        let team_id = std::env::var("APNS_TEAM_ID")
            .context("APNS_TEAM_ID environment variable not set")?;
        let topic = std::env::var("APNS_TOPIC")
            .context("APNS_TOPIC environment variable not set")?;
        let production = std::env::var("APNS_PRODUCTION")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

        ApnsClient::new(&key_path, &key_id, &team_id, production, &topic)
    }

    /// Send a message notification to all devices for members of a conversation
    ///
    /// # Arguments
    /// * `pool` - Database connection pool
    /// * `convo_id` - Conversation ID
    /// * `message_id` - Message ID
    /// * `ciphertext` - Encrypted message ciphertext to include in push payload
    /// * `sender_did` - DID of the sender (to exclude from notifications)
    pub async fn notify_new_message(
        &self,
        pool: &PgPool,
        convo_id: &str,
        message_id: &str,
        ciphertext: &[u8],
        sender_did: &str,
    ) -> Result<()> {
        if !self.enabled || self.apns_client.is_none() {
            debug!("Push notifications disabled, skipping notification");
            return Ok(());
        }

        let client = self.apns_client.as_ref().unwrap();

        // Get all devices for members of this conversation (excluding sender)
        let devices = sqlx::query_as::<_, (String, String)>(
            r#"
            SELECT DISTINCT d.push_token, d.user_did
            FROM devices d
            JOIN members m ON m.user_did = d.user_did
            WHERE m.convo_id = $1
              AND m.left_at IS NULL
              AND d.push_token IS NOT NULL
              AND d.user_did != $2
            "#,
        )
        .bind(convo_id)
        .bind(sender_did)
        .fetch_all(pool)
        .await?;

        if devices.is_empty() {
            debug!(
                convo_id = %convo_id,
                "No devices with push tokens found for conversation"
            );
            return Ok(());
        }

        debug!(
            convo_id = %convo_id,
            device_count = devices.len(),
            "Sending push notifications to devices"
        );

        // Send to all devices in parallel
        let mut tasks = Vec::new();
        for (device_token, _user_did) in devices {
            let client = Arc::clone(client);
            let convo_id = convo_id.to_string();
            let message_id = message_id.to_string();
            let ciphertext = ciphertext.to_vec();

            let task = tokio::spawn(async move {
                client
                    .send_message_notification(&device_token, &ciphertext, &convo_id, &message_id)
                    .await
            });
            tasks.push(task);
        }

        // Await all tasks and collect results
        let mut success_count = 0;
        let mut error_count = 0;

        for task in tasks {
            match task.await {
                Ok(Ok(_)) => success_count += 1,
                Ok(Err(e)) => {
                    error_count += 1;
                    error!("Push notification failed: {}", e);
                }
                Err(e) => {
                    error_count += 1;
                    error!("Push notification task panicked: {}", e);
                }
            }
        }

        info!(
            convo_id = %convo_id,
            success = success_count,
            errors = error_count,
            "Push notifications sent"
        );

        Ok(())
    }

    /// Send a low key package inventory notification to a user
    ///
    /// # Arguments
    /// * `user_did` - DID of the user to notify
    /// * `available_count` - Current number of available key packages
    /// * `threshold` - Recommended minimum threshold
    pub async fn notify_low_key_packages(
        &self,
        user_did: &str,
        available_count: i64,
        threshold: i64,
    ) -> Result<()> {
        if !self.enabled {
            debug!(
                "Notification service disabled, skipping notification for {}",
                user_did
            );
            return Ok(());
        }

        info!(
            "Sending low key package notification to {}: {} available (threshold: {})",
            user_did, available_count, threshold
        );

        // For now, just log - key package notifications can be added later
        warn!(
            "Key package notifications not yet implemented for {}",
            user_did
        );

        Ok(())
    }
}

impl Default for NotificationService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_notification_service_creation() {
        let service = NotificationService::new();
        assert!(!service.enabled); // Disabled by default without env var
    }

    #[tokio::test]
    async fn test_notify_low_key_packages() {
        let service = NotificationService::new();

        // Should not error even when disabled
        let result = service
            .notify_low_key_packages("did:plc:test123", 3, 10)
            .await;

        assert!(result.is_ok());
    }
}
