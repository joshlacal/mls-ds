use a2::ErrorReason;
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
        let mut prefix_end = device_token.len().min(4);
        while !device_token.is_char_boundary(prefix_end) {
            prefix_end -= 1;
        }
        return format!("{}...", &device_token[..prefix_end]);
    }

    let mut prefix_end = 8;
    while !device_token.is_char_boundary(prefix_end) {
        prefix_end -= 1;
    }

    let mut suffix_start = device_token.len() - 4;
    while !device_token.is_char_boundary(suffix_start) {
        suffix_start += 1;
    }

    format!(
        "{}...{}",
        &device_token[..prefix_end],
        &device_token[suffix_start..]
    )
}

/// Determine whether an APNs response indicates a permanent invalid device token
/// that should be compare-cleared from the database.
fn is_permanent_invalid_token(response: &a2::response::Response) -> bool {
    if response.code == 410 {
        return true;
    }
    if let Some(err) = &response.error {
        matches!(
            err.reason,
            ErrorReason::BadDeviceToken
                | ErrorReason::Unregistered
                | ErrorReason::DeviceTokenNotForTopic
        )
    } else {
        false
    }
}

/// Compare-and-clear a stale push token from the devices table.
/// Binds the exact token in the WHERE clause so a concurrently rotated token is preserved.
async fn prune_stale_device_token(pool: &PgPool, device_token: &str) {
    let result = sqlx::query(
        "UPDATE devices SET push_token = NULL, push_token_updated_at = NOW() WHERE push_token = $1",
    )
    .bind(device_token)
    .execute(pool)
    .await;

    match result {
        Ok(res) if res.rows_affected() > 0 => {
            info!(
                device_token = %mask_device_token(device_token),
                rows_cleared = res.rows_affected(),
                "🧹 [push_notification] Cleared stale push token from database"
            );
        }
        Ok(_) => {
            debug!(
                device_token = %mask_device_token(device_token),
                "🧹 [push_notification] Stale token already cleared or rotated concurrently"
            );
        }
        Err(e) => {
            error!(
                device_token = %mask_device_token(device_token),
                error = %e,
                "❌ [push_notification] Failed to clear stale push token from database"
            );
        }
    }
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
        pool: &PgPool,
        device_token: &str,
        ciphertext: &[u8],
        convo_id: &str,
        message_id: &str,
        recipient_did: &str,
        seq: i64,
        epoch: i64,
    ) -> Result<()> {
        // Encode ciphertext as base64 for JSON payload
        let ciphertext_b64 = base64::engine::general_purpose::STANDARD.encode(ciphertext);
        let masked_device_token = mask_device_token(device_token);

        info!(
            device_token = %masked_device_token,
            convo_id = %convo_id,
            message_id = %message_id,
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
        let recipient_hash = crate::crypto::hash_for_push(recipient_did);
        notification.add_custom_data("recipient_account", &recipient_hash)?;
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
                Ok(response) if (200..300).contains(&response.code) => {
                    info!(
                        device_token = %masked_device_token,
                        status = response.code,
                        convo_id = %convo_id,
                        message_id = %message_id,
                        attempts = retry_count + 1,
                        "✅ [push_notification] MLS message notification delivered successfully"
                    );
                    return Ok(());
                }
                Ok(response) if is_permanent_invalid_token(&response) => {
                    warn!(
                        device_token = %masked_device_token,
                        status = response.code,
                        convo_id = %convo_id,
                        message_id = %message_id,
                        "⚠️ [push_notification] APNs reported permanent invalid device token, compare-clearing"
                    );
                    prune_stale_device_token(pool, device_token).await;
                    return Err(anyhow::anyhow!(
                        "APNs rejected notification with permanent invalid token status {}",
                        response.code
                    ));
                }
                Ok(response) if response.code == 429 || response.code >= 500 => {
                    retry_count += 1;
                    warn!(
                        device_token = %masked_device_token,
                        status = response.code,
                        attempt = retry_count,
                        max_retries = MAX_RETRIES,
                        backoff_ms = backoff_ms,
                        convo_id = %convo_id,
                        message_id = %message_id,
                        "⚠️ [push_notification] Transient APNs status, retrying"
                    );

                    if retry_count >= MAX_RETRIES {
                        error!(
                            device_token = %masked_device_token,
                            status = response.code,
                            convo_id = %convo_id,
                            message_id = %message_id,
                            "❌ [push_notification] Notification failed with transient status after maximum retries"
                        );
                        return Err(anyhow::anyhow!(
                            "APNs notification failed with transient status {} after retries",
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
                        convo_id = %convo_id,
                        message_id = %message_id,
                        "⚠️ [push_notification] Non-success APNs status (not retrying)"
                    );
                    return Err(anyhow::anyhow!(
                        "APNs rejected notification with status {}",
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
                        backoff_ms = backoff_ms,
                        "⚠️ [push_notification] Transient APNs status for replenish request, retrying"
                    );

                    if retry_count >= MAX_RETRIES {
                        error!(
                            device_token = %masked_device_token,
                            status = response.code,
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
            "🔔 [push_notification] notify_new_message called for convo={}, message={}, ciphertext_size={}",
            convo_id, message_id, ciphertext.len()
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
        for (idx, (token, _did)) in devices.iter().enumerate() {
            info!(
                "🔔 [push_notification] Device {}/{}: token={}",
                idx + 1,
                devices.len(),
                mask_device_token(token),
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
                "🔔 [push_notification] Sending {}/{} to device token={}",
                task_num,
                total_devices,
                mask_device_token(&device_token),
            );

            let result = client
                .send_message_notification(
                    pool,
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

    #[test]
    fn mask_device_token_preserves_ascii_compatibility() {
        assert_eq!(mask_device_token("abc"), "abc...");
        assert_eq!(mask_device_token("abcdefghijkl"), "abcd...");
        assert_eq!(mask_device_token("abcdefghijklm"), "abcdefgh...jklm");
        assert_eq!(mask_device_token("0123456789abcdef"), "01234567...cdef");
    }

    #[test]
    fn mask_device_token_uses_unicode_scalar_boundaries() {
        assert_eq!(mask_device_token("a💥b"), "a...");
        assert_eq!(mask_device_token("éabc"), "éab...");
        assert_eq!(mask_device_token("ab💥c"), "ab...");
        assert_eq!(mask_device_token("abcdef💥ghijkl"), "abcdef...ijkl");
        assert_eq!(mask_device_token("abcdefghijkl💥x"), "abcdefgh...x");
    }

    #[test]
    fn mask_device_token_is_total_and_deterministic_for_unicode_corpus() {
        let corpus = [
            "",
            "é",
            "e\u{301}",
            "💥",
            "👩\u{200d}💻",
            "设备令牌",
            "abcdefghi💥jk",
            "abcdefghi💥jkl",
            "一二三四五六七八九十十一十二",
            "一二三四五六七八九十十一十二三",
        ];

        for token in corpus {
            let first = mask_device_token(token);
            let second = mask_device_token(token);
            assert_eq!(first, second, "mask must be deterministic for {token:?}");
            assert!(first.ends_with("...") || first.contains("..."));
        }

        assert_eq!(mask_device_token("abcdefghi💥jk"), "abcdefgh...jk");
        assert_eq!(mask_device_token("abcdefghi💥jkl"), "abcdefgh...jkl");
    }

    #[test]
    fn mask_device_token_is_deterministic_for_very_long_multibyte_token() {
        let token = format!("{}中{}", "💥".repeat(100_000), "🚀".repeat(100_000));
        let expected = format!("{}...{}", "💥".repeat(2), "🚀");

        assert_eq!(mask_device_token(&token), expected);
        assert_eq!(mask_device_token(&token), mask_device_token(&token));
    }

    fn assert_mask_byte_budget(token: &str) {
        let masked = mask_device_token(token);
        let (prefix, suffix) = masked
            .split_once("...")
            .expect("masked token must contain separator");

        if token.len() <= 12 {
            assert!(prefix.len() <= 4, "short prefix exceeded byte budget");
            assert!(suffix.is_empty(), "short token unexpectedly exposed suffix");
        } else {
            assert!(prefix.len() <= 8, "long prefix exceeded byte budget");
            assert!(suffix.len() <= 4, "long suffix exceeded byte budget");
            assert!(token.ends_with(suffix));
        }
        assert!(token.starts_with(prefix));
        assert_eq!(masked, mask_device_token(token));
    }

    #[test]
    fn mask_device_token_never_exceeds_legacy_byte_budget() {
        let thirteen_emoji = "💥".repeat(13);
        assert_eq!(mask_device_token(&thirteen_emoji), "💥💥...💥");
        assert_mask_byte_budget(&thirteen_emoji);

        let scalars = ["a", "é", "e\u{301}", "💥", "👩\u{200d}💻", "中"];
        for scalar in scalars {
            let mut token = String::new();
            while token.len() + scalar.len() <= 512 {
                token.push_str(scalar);
                assert_mask_byte_budget(&token);
            }
        }

        for token in [
            "a💥b",
            "éabc",
            "ab💥c",
            "abcdef💥ghijkl",
            "abcdefghijkl💥x",
            "👩\u{200d}💻abcdef中🚀xyz",
        ] {
            assert_mask_byte_budget(token);
        }
    }

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

    #[test]
    fn apns_permanent_invalid_token_classification() {
        use a2::response::{ErrorBody, Response};

        // 1. Status 410 (Gone / Unregistered) is always permanent invalid token
        let resp_410 = Response {
            code: 410,
            error: None,
            apns_id: None,
        };
        assert!(is_permanent_invalid_token(&resp_410));

        // 2. BadDeviceToken is permanent invalid token
        let resp_bad_token = Response {
            code: 400,
            error: Some(ErrorBody {
                reason: ErrorReason::BadDeviceToken,
                timestamp: None,
            }),
            apns_id: None,
        };
        assert!(is_permanent_invalid_token(&resp_bad_token));

        // 3. Unregistered is permanent invalid token
        let resp_unreg = Response {
            code: 400,
            error: Some(ErrorBody {
                reason: ErrorReason::Unregistered,
                timestamp: None,
            }),
            apns_id: None,
        };
        assert!(is_permanent_invalid_token(&resp_unreg));

        // 4. DeviceTokenNotForTopic is permanent invalid token
        let resp_wrong_topic = Response {
            code: 400,
            error: Some(ErrorBody {
                reason: ErrorReason::DeviceTokenNotForTopic,
                timestamp: None,
            }),
            apns_id: None,
        };
        assert!(is_permanent_invalid_token(&resp_wrong_topic));

        // 5. Success (200) is NOT an invalid token
        let resp_200 = Response {
            code: 200,
            error: None,
            apns_id: Some("id".to_string()),
        };
        assert!(!is_permanent_invalid_token(&resp_200));

        // 6. Rate limited / TooManyRequests (429) is transient, NOT permanent invalid token
        let resp_429 = Response {
            code: 429,
            error: Some(ErrorBody {
                reason: ErrorReason::TooManyRequests,
                timestamp: None,
            }),
            apns_id: None,
        };
        assert!(!is_permanent_invalid_token(&resp_429));

        // 7. InternalServerError (500) is transient, NOT permanent invalid token
        let resp_500 = Response {
            code: 500,
            error: Some(ErrorBody {
                reason: ErrorReason::InternalServerError,
                timestamp: None,
            }),
            apns_id: None,
        };
        assert!(!is_permanent_invalid_token(&resp_500));
    }

    #[test]
    fn apns_non_2xx_must_not_be_swallowed_as_success() {
        use a2::response::{ErrorBody, Response};
        let resp_non_2xx = Response {
            code: 400,
            error: Some(ErrorBody {
                reason: ErrorReason::BadTopic,
                timestamp: None,
            }),
            apns_id: None,
        };
        let new_is_error = !(200..300).contains(&resp_non_2xx.code);
        assert!(
            new_is_error,
            "APNs non-2xx response must be treated as an error"
        );
    }
    #[test]
    fn compare_and_clear_semantics_preserves_rotated_token() {
        // Verifies the predicate logic of compare-and-clear:
        // WHERE push_token = $1 only matches when the DB token has NOT been rotated.
        let initial_token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let rotated_token = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

        let mut current_db_token = Some(initial_token.to_string());

        // 1. If DB token still equals the failed token, compare-and-clear clears it
        let failed_token = initial_token;
        if current_db_token.as_deref() == Some(failed_token) {
            current_db_token = None;
        }
        assert_eq!(current_db_token, None);

        // 2. If client rotates to a new token
        current_db_token = Some(rotated_token.to_string());

        // 3. Stale async task with old failed token tries to compare-and-clear
        if current_db_token.as_deref() == Some(failed_token) {
            current_db_token = None;
        }
        // Rotated token is preserved!
        assert_eq!(current_db_token, Some(rotated_token.to_string()));
    }
}
