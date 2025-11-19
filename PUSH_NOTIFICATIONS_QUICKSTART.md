# Push Notifications Quick Start

## Enable Push Notifications (3 steps)

### 1. Get Your Apple Team ID
Visit https://developer.apple.com/account → Membership → Team ID

### 2. Set Environment Variables
```bash
export ENABLE_PUSH_NOTIFICATIONS=true
export APNS_KEY_PATH=/home/ubuntu/.config/bluesky-push-notifier/keys/AuthKey_A5C849F4W8.p8
export APNS_KEY_ID=A5C849F4W8
export APNS_TEAM_ID=<YOUR_TEAM_ID_HERE>
export APNS_TOPIC=blue.catbird.app
export APNS_PRODUCTION=false
```

Or add to `.env` file:
```bash
cd /home/ubuntu/mls
nano .env
# Add the above variables
```

### 3. Run Migration & Start Server
```bash
# Apply migration (if not already done)
cd /home/ubuntu/mls/server
sqlx migrate run

# Or manually:
psql $DATABASE_URL -c "
ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS push_token TEXT,
    ADD COLUMN IF NOT EXISTS push_token_updated_at TIMESTAMPTZ;
"

# Start server
cd /home/ubuntu/mls
cargo run --release
```

## iOS Client Integration

### Register Device Token
```swift
func application(_ application: UIApplication, 
                didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
    let token = deviceToken.map { String(format: "%02.2hhx", $0) }.joined()
    
    mlsClient.registerDeviceToken(
        deviceId: myDeviceUUID,
        pushToken: token,
        deviceName: UIDevice.current.name,
        platform: "ios"
    )
}
```

### Handle Push Notification
```swift
func userNotificationCenter(_ center: UNUserNotificationCenter,
                          didReceive response: UNNotificationResponse) {
    let userInfo = response.notification.request.content.userInfo
    
    guard let ciphertextB64 = userInfo["ciphertext"] as? String,
          let ciphertext = Data(base64Encoded: ciphertextB64) else { return }
    
    // Decrypt with OpenMLS
    mlsGroup.processMessage(ciphertext) { decryptedMessage in
        // Update UI
    }
}
```

## API Endpoints

```bash
# Register token
POST /xrpc/blue.catbird.mls.registerDeviceToken
Authorization: Bearer <jwt>
{
  "deviceId": "uuid",
  "pushToken": "hex-token",
  "deviceName": "iPhone",
  "platform": "ios"
}

# Unregister token
POST /xrpc/blue.catbird.mls.unregisterDeviceToken
Authorization: Bearer <jwt>
{
  "deviceId": "uuid"
}
```

## Verify Setup

```bash
# Check APNs key exists
ls -la /home/ubuntu/.config/bluesky-push-notifier/keys/AuthKey_A5C849F4W8.p8

# Check migration status
psql $DATABASE_URL -c "\d devices" | grep push_token

# Test server startup
cd /home/ubuntu/mls
ENABLE_PUSH_NOTIFICATIONS=true cargo run 2>&1 | grep -i apns
# Should see: "APNs client initialized"

# Monitor push notifications
tail -f server.log | grep -i "push\|notification"
```

## Troubleshooting

**APNs client fails to initialize:**
- Check APNS_KEY_PATH points to valid .p8 file
- Verify APNS_KEY_ID matches key filename
- Confirm APNS_TEAM_ID is correct

**Push notifications not arriving:**
- Verify device token is registered (check `devices` table)
- Check server logs for delivery errors
- Ensure iOS app has notification permissions
- For sandbox: Use development provisioning profile
- For production: Set APNS_PRODUCTION=true

**Database errors:**
- Run migration: `sqlx migrate run`
- Or manually add columns (see step 3 above)

## Documentation

- **Full Guide**: `/home/ubuntu/mls/PUSH_NOTIFICATIONS_SETUP.md`
- **Implementation Details**: `/home/ubuntu/mls/PUSH_NOTIFICATION_IMPLEMENTATION.md`
- **Code**: `server/src/notifications/mod.rs`
