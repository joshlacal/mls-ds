# MLS Server Push Notifications Setup Guide

This guide explains how to set up Apple Push Notifications (APNs) for the MLS server to deliver encrypted messages directly to iOS devices.

## Overview

The MLS server integrates with APNs to send push notifications containing the encrypted message ciphertext. This allows:

1. **Instant delivery**: Messages are pushed immediately to offline devices
2. **Rich previews**: Clients can decrypt and preview messages in the notification (if user enables)
3. **End-to-end encryption**: The ciphertext is sent in the push payload, maintaining E2EE
4. **Shared APNs keys**: Uses the same APNs configuration as the bluesky-push-notifier service

## Architecture

```
┌─────────────┐
│   Client    │
│  (iOS App)  │
└──────┬──────┘
       │ 1. Register device token
       ▼
┌─────────────────────┐
│   MLS Server        │
│  - Store token      │
│  - Link to device   │
└──────┬──────────────┘
       │ 2. Message arrives
       ▼
┌─────────────────────┐
│  Push Notification  │
│  Service            │
│  - Get recipients   │
│  - Send APNs        │
│    with ciphertext  │
└──────┬──────────────┘
       │ 3. APNs Push
       ▼
┌─────────────┐
│   Client    │
│  - Decrypt  │
│  - Show     │
│    preview  │
└─────────────┘
```

## Configuration

### 1. APNs Credentials

The server uses the same APNs key as the bluesky-push-notifier service:

- **Key Location**: `/home/ubuntu/.config/bluesky-push-notifier/keys/AuthKey_A5C849F4W8.p8`
- **Key ID**: `A5C849F4W8`
- **Team ID**: Get from Apple Developer account
- **Topic**: `blue.catbird.app` (your app bundle ID)

### 2. Environment Variables

Add to your `.env` file or Doppler configuration:

```bash
# Enable push notifications
ENABLE_PUSH_NOTIFICATIONS=true

# APNs configuration (shared with bluesky-push-notifier)
APNS_KEY_PATH=/home/ubuntu/.config/bluesky-push-notifier/keys/AuthKey_A5C849F4W8.p8
APNS_KEY_ID=A5C849F4W8
APNS_TEAM_ID=YOUR_TEAM_ID_HERE
APNS_TOPIC=blue.catbird.app

# Use sandbox for development, production for release
APNS_PRODUCTION=false
```

### 3. Database Migration

The push notification system requires a database migration to store device tokens:

```bash
cd /home/ubuntu/mls/server
sqlx migrate run
```

This creates the `push_token` and `push_token_updated_at` columns in the `devices` table.

## Client Integration

### 1. Register Device Token

When your iOS app receives a device token from APNs, register it with the MLS server:

```swift
// Swift example
func application(_ application: UIApplication, 
                didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
    let token = deviceToken.map { String(format: "%02.2hhx", $0) }.joined()
    
    // Register with MLS server
    let request = RegisterDeviceTokenRequest(
        deviceId: deviceId, // Your device UUID
        pushToken: token,
        deviceName: UIDevice.current.name,
        platform: "ios"
    )
    
    mlsClient.registerDeviceToken(request) { result in
        // Handle result
    }
}
```

### 2. Handle Push Notifications

When a push notification arrives, extract and decrypt the ciphertext:

```swift
// Swift example
func userNotificationCenter(_ center: UNUserNotificationCenter,
                          didReceive response: UNNotificationResponse,
                          withCompletionHandler completionHandler: @escaping () -> Void) {
    let userInfo = response.notification.request.content.userInfo
    
    guard let type = userInfo["type"] as? String,
          type == "mlsMessage",
          let convoId = userInfo["convoId"] as? String,
          let messageId = userInfo["messageId"] as? String,
          let ciphertextB64 = userInfo["ciphertext"] as? String,
          let ciphertext = Data(base64Encoded: ciphertextB64) else {
        completionHandler()
        return
    }
    
    // Decrypt the message using OpenMLS
    mlsGroup.processMessage(ciphertext) { decryptedMessage in
        // Show the message or update UI
        completionHandler()
    }
}
```

### 3. Rich Notification Previews (Optional)

To show message previews in notifications, implement a Notification Service Extension:

```swift
// NotificationService.swift
class NotificationService: UNNotificationServiceExtension {
    override func didReceive(_ request: UNNotificationRequest,
                           withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void) {
        guard let bestAttemptContent = request.content.mutableCopy() as? UNMutableNotificationContent,
              let ciphertextB64 = bestAttemptContent.userInfo["ciphertext"] as? String,
              let ciphertext = Data(base64Encoded: ciphertextB64) else {
            contentHandler(request.content)
            return
        }
        
        // Decrypt in the extension
        mlsGroup.decryptMessage(ciphertext) { result in
            switch result {
            case .success(let plaintext):
                // Update notification with decrypted content
                bestAttemptContent.body = String(data: plaintext, encoding: .utf8) ?? "New message"
                bestAttemptContent.sound = .default
            case .failure:
                bestAttemptContent.body = "New encrypted message"
            }
            contentHandler(bestAttemptContent)
        }
    }
}
```

## API Endpoints

### Register Device Token
```
POST /xrpc/blue.catbird.mls.registerDeviceToken
Authorization: Bearer <jwt>

{
  "deviceId": "device-uuid",
  "pushToken": "apns-device-token-hex",
  "deviceName": "Josh's iPhone",
  "platform": "ios"
}

Response: { "success": true }
```

### Unregister Device Token
```
POST /xrpc/blue.catbird.mls.unregisterDeviceToken
Authorization: Bearer <jwt>

{
  "deviceId": "device-uuid"
}

Response: { "success": true }
```

## Push Notification Payload

When a message is sent, the server sends this payload via APNs:

```json
{
  "aps": {
    "content-available": 1,
    "mutable-content": 1,
    "sound": "default"
  },
  "type": "mlsMessage",
  "convoId": "conversation-id",
  "messageId": "message-id",
  "ciphertext": "base64-encoded-mls-ciphertext"
}
```

The ciphertext is the same MLS encrypted message that would be fetched via `getMessages`. This allows the client to:
- Decrypt immediately upon receiving the push
- Show rich previews if the user enables them
- Update the conversation UI instantly

## Security Considerations

1. **End-to-End Encryption Maintained**: The ciphertext is sent through APNs, but it's still encrypted with MLS
2. **APNs Trust**: You're trusting Apple's APNs infrastructure to deliver the encrypted payload
3. **Token Storage**: Device tokens are stored securely and associated with authenticated users
4. **No Plaintext**: The server never has access to plaintext messages

## Testing

### 1. Development Testing

Use APNs Sandbox for testing:
```bash
APNS_PRODUCTION=false
```

### 2. Test Push Notification

After registering a device token, send a test message:

```bash
curl -X POST https://your-server.com/xrpc/blue.catbird.mls.sendMessage \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "convoId": "test-convo",
    "msgId": "test-msg",
    "ciphertext": "...",
    "epoch": 0,
    "paddedSize": 512
  }'
```

Check logs for push notification delivery:
```bash
tail -f /home/ubuntu/mls/server.log | grep -i "push\|apns"
```

## Monitoring

The push notification service logs:
- Successful deliveries
- Failed deliveries with error codes
- Device token registrations
- APNs connection issues

Key metrics to monitor:
- Push delivery success rate
- Average delivery latency
- Failed token removals (410 status from APNs)

## Troubleshooting

### Push notifications not arriving

1. **Check APNs configuration**:
   ```bash
   # Verify environment variables
   echo $APNS_KEY_PATH
   echo $APNS_KEY_ID
   echo $APNS_TEAM_ID
   echo $APNS_TOPIC
   ```

2. **Verify device token is registered**:
   ```sql
   SELECT user_did, device_id, push_token, push_token_updated_at 
   FROM devices 
   WHERE push_token IS NOT NULL;
   ```

3. **Check server logs**:
   ```bash
   grep "Push notification" /home/ubuntu/mls/server.log
   ```

4. **Verify APNs key file exists**:
   ```bash
   ls -la /home/ubuntu/.config/bluesky-push-notifier/keys/
   ```

### Invalid device tokens

APNs returns a 410 status for invalid/expired tokens. The server automatically removes these from the database.

### Rate limiting

APNs has rate limits. If you're sending many notifications, implement batching or throttling.

## Production Deployment

For production:

1. Set `APNS_PRODUCTION=true`
2. Use production APNs endpoint
3. Verify certificates are valid
4. Monitor delivery rates
5. Set up alerting for failed deliveries

## Doppler Integration

To add APNs configuration to Doppler:

```bash
cd /home/ubuntu/bluesky-push-notifier
doppler secrets set APNS_KEY_ID=A5C849F4W8 --config prd
doppler secrets set APNS_TEAM_ID=YOUR_TEAM_ID --config prd
doppler secrets set APNS_TOPIC=blue.catbird.app --config prd
doppler secrets set APNS_PRODUCTION=false --config prd

# For MLS server
cd /home/ubuntu/mls
doppler secrets set ENABLE_PUSH_NOTIFICATIONS=true --config prd
doppler secrets set APNS_KEY_PATH=/home/ubuntu/.config/bluesky-push-notifier/keys/AuthKey_A5C849F4W8.p8 --config prd
doppler secrets set APNS_KEY_ID=A5C849F4W8 --config prd
doppler secrets set APNS_TEAM_ID=YOUR_TEAM_ID --config prd
doppler secrets set APNS_TOPIC=blue.catbird.app --config prd
doppler secrets set APNS_PRODUCTION=false --config prd
```

## Related Documentation

- [APNs Provider API](https://developer.apple.com/documentation/usernotifications/setting_up_a_remote_notification_server)
- [MLS Protocol](https://messaginglayersecurity.rocks/)
- [Device Registration](./server/src/handlers/register_device_token.rs)
- [Notification Service](./server/src/notifications/mod.rs)
