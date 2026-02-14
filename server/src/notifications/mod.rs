use a2::{
    Client, ClientConfig, DefaultNotificationBuilder, Endpoint, NotificationBuilder,
    NotificationOptions, Priority, PushType,
};
use anyhow::{Context, Result};
use base64::Engine;
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

fn mask_device_token(device_token: &str) -> String {
    if device_token.len() <= 12 {
        return format!("{}...", &device_token[..device_token.len().min(4)]);
    }

    format!(
        "{}...{}",
        &device_token[..8],
        &device_token[device_token.len().saturating_sub(4)..]
    )
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
        recipient_did: &str,
        seq: i64,
        epoch: i64,
    ) -> Result<()> {
        info!("🔔 [push_notification] Starting send_message_notification");

        // Encode ciphertext as base64 for JSON payload
        let ciphertext_b64 = base64::engine::general_purpose::STANDARD.encode(ciphertext);
        let masked_device_token = mask_device_token(device_token);

        info!(
            device_token = %masked_device_token,
            convo_id = %convo_id,
            message_id = %message_id,
            recipient_did = %recipient_did,
            ciphertext_size = ciphertext.len(),
            ciphertext_b64_length = ciphertext_b64.len(),
            "🔔 [push_notification] Preparing MLS message notification"
        );

        info!("🔔 [push_notification] Building notification payload with custom MLS data");

        // Build notification with mutable-content for Notification Service Extension
        // IMPORTANT: We MUST set an initial alert (title/body) for iOS to display a banner.
        // The Notification Service Extension will then decrypt and REPLACE these with the real content.
        // Without an alert, iOS only plays a sound but shows no banner.
        let mut notification = DefaultNotificationBuilder::new()
            .set_title("New Message")
            .set_body("Decrypting...")
            .set_mutable_content() // Enables Notification Service Extension to modify the alert
            .set_sound("default")
            .build(
                device_token,
                NotificationOptions {
                    apns_topic: Some(&self.topic),
                    apns_priority: Some(Priority::High),
                    apns_collapse_id: None,
                    apns_expiration: None,
                    apns_push_type: Some(PushType::Alert), // Required for Notification Service Extension
                    apns_id: None,
                },
            );

        // Add custom data fields at the top level of the payload (sibling to "aps")
        // These are read by the Notification Service Extension to decrypt the message
        notification.add_custom_data("type", &"mls_message")?;
        notification.add_custom_data("ciphertext", &ciphertext_b64)?;
        notification.add_custom_data("convo_id", &convo_id)?;
        notification.add_custom_data("message_id", &message_id)?;
        notification.add_custom_data("recipient_did", &recipient_did)?;
        notification.add_custom_data("seq", &seq.to_string())?; // Add sequence number
        notification.add_custom_data("epoch", &epoch.to_string())?; // Add epoch

        info!(
            "🔔 [push_notification] Notification built with custom MLS data, starting delivery (max retries: {})",
            3
        );

        // Send with retries
        const MAX_RETRIES: u8 = 3;
        let mut retry_count = 0;
        let mut backoff_ms = 100;

        loop {
            info!(
                "🔔 [push_notification] Attempt {} of {} - sending to APNs",
                retry_count + 1,
                MAX_RETRIES + 1
            );

            match self.client.send(notification.clone()).await {
                Ok(response) => {
                    info!(
                        "🔔 [push_notification] Received APNs response: status_code={}",
                        response.code
                    );

                    if response.code >= 200 && response.code < 300 {
                        info!(
                            device_token = %masked_device_token,
                            status = response.code,
                            convo_id = %convo_id,
                            message_id = %message_id,
                            recipient_did = %recipient_did,
                            attempts = retry_count + 1,
                            "✅ [push_notification] MLS message notification delivered successfully"
                        );
                        return Ok(());
                    } else {
                        warn!(
                            device_token = %masked_device_token,
                            status = response.code,
                            convo_id = %convo_id,
                            message_id = %message_id,
                            "⚠️ [push_notification] Notification accepted with non-success status"
                        );
                        return Ok(());
                    }
                }
                Err(e) => {
                    retry_count += 1;
                    warn!(
                        device_token = %masked_device_token,
                        error = %e,
                        attempt = retry_count,
                        max_retries = MAX_RETRIES,
                        backoff_ms = backoff_ms,
                        convo_id = %convo_id,
                        message_id = %message_id,
                        "⚠️ [push_notification] Failed to send notification, will retry"
                    );

                    if retry_count >= MAX_RETRIES {
                        error!(
                            device_token = %masked_device_token,
                            error = %e,
                            total_attempts = retry_count,
                            convo_id = %convo_id,
                            message_id = %message_id,
                            recipient_did = %recipient_did,
                            "❌ [push_notification] Failed to send notification after maximum retries"
                        );
                        return Err(e.into());
                    }

                    info!(
                        "🔔 [push_notification] Backing off for {}ms before retry",
                        backoff_ms
                    );
                    tokio::time::sleep(tokio::time::Duration::from_millis(backoff_ms)).await;
                    backoff_ms *= 2;
                }
            }
        }
    }

    /// Send a key package replenish request notification
    async fn send_key_package_replenish_notification(
        &self,
        device_token: &str,
        target_did: &str,
        requester_did: &str,
        requested_at: &str,
        reason: Option<&str>,
        convo_id: Option<&str>,
    ) -> Result<()> {
        let masked_device_token = mask_device_token(device_token);

        let mut notification = DefaultNotificationBuilder::new()
            .set_title("Security Update Needed")
            .set_body("Open Catbird to refresh message keys.")
            .set_mutable_content()
            .set_sound("default")
            .build(
                device_token,
                NotificationOptions {
                    apns_topic: Some(&self.topic),
                    apns_priority: Some(Priority::High),
                    apns_collapse_id: None,
                    apns_expiration: None,
                    apns_push_type: Some(PushType::Alert),
                    apns_id: None,
                },
            );

        notification.add_custom_data("type", &"key_package_replenish_request")?;
        notification.add_custom_data("target_did", &target_did)?;
        notification.add_custom_data("requester_did", &requester_did)?;
        notification.add_custom_data("requested_at", &requested_at)?;

        if let Some(reason) = reason {
            notification.add_custom_data("reason", &reason)?;
        }

        if let Some(convo_id) = convo_id {
            notification.add_custom_data("convo_id", &convo_id)?;
        }

        const MAX_RETRIES: u8 = 3;
        let mut retry_count = 0;
        let mut backoff_ms = 100;

        loop {
            match self.client.send(notification.clone()).await {
                Ok(response) if (200..300).contains(&response.code) => {
                    info!(
                        device_token = %masked_device_token,
                        status = response.code,
                        target_did = %target_did,
                        requester_did = %requester_did,
                        "✅ [push_notification] Key package replenish request delivered successfully"
                    );
                    return Ok(());
                }
                Ok(response) if response.code == 429 || response.code >= 500 => {
                    retry_count += 1;
                    warn!(
                        device_token = %masked_device_token,
                        status = response.code,
                        attempt = retry_count,
                        max_retries = MAX_RETRIES,
                        target_did = %target_did,
                        requester_did = %requester_did,
                        backoff_ms = backoff_ms,
                        "⚠️ [push_notification] Transient APNs status for replenish request, retrying"
                    );

                    if retry_count >= MAX_RETRIES {
                        error!(
                            device_token = %masked_device_token,
                            status = response.code,
                            target_did = %target_did,
                            requester_did = %requester_did,
                            "❌ [push_notification] Replenish request failed after maximum retries"
                        );
                        return Err(anyhow::anyhow!(
                            "APNs replenish request failed with transient status {} after retries",
                            response.code
                        ));
                    }

                    tokio::time::sleep(tokio::time::Duration::from_millis(backoff_ms)).await;
                    backoff_ms *= 2;
                }
                Ok(response) => {
                    warn!(
                        device_token = %masked_device_token,
                        status = response.code,
                        target_did = %target_did,
                        requester_did = %requester_did,
                        "⚠️ [push_notification] Permanent APNs failure for replenish request (not retrying)"
                    );
                    return Err(anyhow::anyhow!(
                        "APNs rejected replenish request with permanent status {}",
                        response.code
                    ));
                }
                Err(e) => {
                    retry_count += 1;
                    warn!(
                        device_token = %masked_device_token,
                        error = %e,
                        attempt = retry_count,
                        max_retries = MAX_RETRIES,
                        target_did = %target_did,
                        requester_did = %requester_did,
                        backoff_ms = backoff_ms,
                        "⚠️ [push_notification] Transport error sending replenish request, retrying"
                    );

                    if retry_count >= MAX_RETRIES {
                        error!(
                            device_token = %masked_device_token,
                            error = %e,
                            target_did = %target_did,
                            requester_did = %requester_did,
                            "❌ [push_notification] Replenish request failed after maximum transport retries"
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
                warn!(
                    "Failed to initialize APNs client: {}. Push notifications disabled.",
                    e
                );
                None
            }
        };

        let enabled = apns_client.is_some();

        Self {
            apns_client,
            enabled,
        }
    }

    pub fn can_send_pushes(&self) -> bool {
        self.enabled && self.apns_client.is_some()
    }

    /// Initialize APNs client from environment variables
    fn init_apns_client() -> Result<ApnsClient> {
        let key_path =
            std::env::var("APNS_KEY_PATH").context("APNS_KEY_PATH environment variable not set")?;
        let key_id =
            std::env::var("APNS_KEY_ID").context("APNS_KEY_ID environment variable not set")?;
        let team_id =
            std::env::var("APNS_TEAM_ID").context("APNS_TEAM_ID environment variable not set")?;
        let topic =
            std::env::var("APNS_TOPIC").context("APNS_TOPIC environment variable not set")?;
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
    /// * `seq` - Message sequence number for ordering
    /// * `epoch` - Message epoch for reconstruction
    pub async fn notify_new_message(
        &self,
        pool: &PgPool,
        convo_id: &str,
        message_id: &str,
        ciphertext: &[u8],
        sender_did: &str,
        seq: i64,
        epoch: i64,
    ) -> Result<()> {
        info!(
            "🔔 [push_notification] notify_new_message called for convo={}, message={}, ciphertext_size={}, sender={}",
            convo_id, message_id, ciphertext.len(), sender_did
        );

        if !self.enabled || self.apns_client.is_none() {
            info!(
                "🔔 [push_notification] Push notifications disabled (enabled={}, client_exists={}), skipping notification",
                self.enabled,
                self.apns_client.is_some()
            );
            return Ok(());
        }

        info!("🔔 [push_notification] Push notifications enabled, proceeding with notification delivery");

        let client = self.apns_client.as_ref().unwrap();

        info!("🔔 [push_notification] Querying database for recipient devices");

        // Get all devices for members of this conversation (excluding sender)
        // Join is robust to legacy rows where members.user_did is NULL.
        let devices = sqlx::query_as::<_, (String, String)>(
            r#"
            SELECT DISTINCT d.push_token, d.user_did
            FROM members m
            JOIN devices d
              ON d.push_token IS NOT NULL
             AND (
                   (m.user_did IS NOT NULL AND d.user_did = m.user_did)
                OR d.credential_did = m.member_did
                OR d.user_did = m.member_did
             )
            WHERE m.convo_id = $1
              AND m.left_at IS NULL
              AND d.user_did != $2
            "#,
        )
        .bind(convo_id)
        .bind(sender_did)
        .fetch_all(pool)
        .await
        .map_err(|e| {
            error!(
                "❌ [push_notification] Database query failed for devices: {}",
                e
            );
            e
        })?;

        info!(
            "🔔 [push_notification] Database query returned {} devices",
            devices.len()
        );

        if devices.is_empty() {
            info!(
                convo_id = %convo_id,
                sender_did = %sender_did,
                "🔔 [push_notification] No devices with push tokens found for conversation (all members may have left or sender is only member)"
            );
            return Ok(());
        }

        info!(
            convo_id = %convo_id,
            device_count = devices.len(),
            "🔔 [push_notification] Starting SEQUENTIAL notification delivery to {} devices",
            devices.len()
        );

        // Log each device (for debugging)
        for (idx, (token, did)) in devices.iter().enumerate() {
            info!(
                "🔔 [push_notification] Device {}/{}: token={}, user_did={}",
                idx + 1,
                devices.len(),
                mask_device_token(token),
                did
            );
        }

        // Send to all devices SEQUENTIALLY to preserve message ordering
        // This ensures that for a given conversation, messages are delivered to APNs in order.
        // The SideEffectJob worker already processes messages sequentially per conversation,
        // so this sequential delivery maintains end-to-end ordering guarantees.
        let total_devices = devices.len();
        let mut success_count = 0;
        let mut error_count = 0;

        for (idx, (device_token, user_did)) in devices.into_iter().enumerate() {
            let task_num = idx + 1;

            info!(
                "🔔 [push_notification] Sending {}/{} to device token={}, user_did={}",
                task_num,
                total_devices,
                mask_device_token(&device_token),
                user_did
            );

            let result = client
                .send_message_notification(
                    &device_token,
                    ciphertext,
                    convo_id,
                    message_id,
                    &user_did,
                    seq,
                    epoch,
                )
                .await;

            match result {
                Ok(_) => {
                    success_count += 1;
                    info!(
                        "🔔 [push_notification] Device {}/{} result: SUCCESS (total success: {})",
                        task_num, total_devices, success_count
                    );
                }
                Err(e) => {
                    error_count += 1;
                    error!(
                        "❌ [push_notification] Device {}/{} result: FAILED - {} (total errors: {})",
                        task_num, total_devices, e, error_count
                    );
                    // Continue to remaining devices - don't fail entire batch on single device error
                }
            }
        }

        info!(
            convo_id = %convo_id,
            message_id = %message_id,
            success = success_count,
            errors = error_count,
            total = total_devices,
            "✅ [push_notification] SEQUENTIAL push notification delivery complete: {}/{} succeeded, {}/{} failed",
            success_count, total_devices, error_count, total_devices
        );

        Ok(())
    }

    pub async fn notify_key_package_replenish_request(
        &self,
        device_token: &str,
        target_did: &str,
        requester_did: &str,
        requested_at: &str,
        reason: Option<&str>,
        convo_id: Option<&str>,
    ) -> Result<()> {
        if !self.enabled || self.apns_client.is_none() {
            debug!(
                target_did = %target_did,
                requester_did = %requester_did,
                "Notification service disabled, skipping key package replenish request notification"
            );
            return Ok(());
        }

        self.apns_client
            .as_ref()
            .unwrap()
            .send_key_package_replenish_notification(
                device_token,
                target_did,
                requester_did,
                requested_at,
                reason,
                convo_id,
            )
            .await
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
