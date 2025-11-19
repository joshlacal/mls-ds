# Push Notification Setup Complete ✅

## Summary

I've successfully set up push notifications for the MLS server with the following features:

### What Was Implemented

1. **APNs Integration** 
   - Added `a2` crate (v0.10) for Apple Push Notifications
   - Configured to use the same APNs key as `bluesky-push-notifier`
   - Key location: `/home/ubuntu/.config/bluesky-push-notifier/keys/AuthKey_A5C849F4W8.p8`

2. **Database Support**
   - Created migration `20251119_001_push_notification_tokens.sql`
   - Adds `push_token` and `push_token_updated_at` columns to `devices` table
   - Includes indexes for efficient lookups

3. **Server Implementation**
   - Enhanced `NotificationService` with full APNs client (`server/src/notifications/mod.rs`)
   - Sends ciphertext in push payload for instant decryption on client
   - Automatic retry logic with exponential backoff
   - Parallel notification sending to all conversation members

4. **API Endpoints**
   - `POST /xrpc/blue.catbird.mls.registerDeviceToken` - Register/update device push token
   - `POST /xrpc/blue.catbird.mls.unregisterDeviceToken` - Remove push token
   - Handler: `server/src/handlers/register_device_token.rs`

5. **Integration with Message Flow**
   - Modified `send_message` handler to trigger push notifications
   - Notifications sent asynchronously after message is stored
   - Only sends to conversation members (excluding sender)
   - Includes full MLS ciphertext for client-side decryption

### Push Notification Payload Format

```json
{
  "aps": {
    "content-available": 1,
    "mutable-content": 1,
    "sound": "default"
  },
  "type": "mlsMessage",
  "convoId": "conversation-uuid",
  "messageId": "message-uuid",
  "ciphertext": "base64-encoded-mls-ciphertext"
}
```

This allows clients to:
- Decrypt message immediately upon receiving push
- Show rich previews if user enables (like iMessage)
- Update UI instantly without polling

### Configuration Required

Add to `.env` or Doppler:

```bash
# Enable push notifications
ENABLE_PUSH_NOTIFICATIONS=true

# APNs credentials (shared with bluesky-push-notifier)
APNS_KEY_PATH=/home/ubuntu/.config/bluesky-push-notifier/keys/AuthKey_A5C849F4W8.p8
APNS_KEY_ID=A5C849F4W8
APNS_TEAM_ID=<YOUR_APPLE_TEAM_ID>
APNS_TOPIC=blue.catbird.app
APNS_PRODUCTION=false  # Use true for production
```

### Next Steps

1. **Get Apple Team ID**
   ```bash
   # You'll need to get this from Apple Developer account
   # Update the .env or Doppler with the actual team ID
   ```

2. **Run Database Migration**
   ```bash
   cd /home/ubuntu/mls/server
   sqlx migrate run
   ```
   
   Or manually apply the migration:
   ```sql
   ALTER TABLE devices
       ADD COLUMN IF NOT EXISTS push_token TEXT,
       ADD COLUMN IF NOT EXISTS push_token_updated_at TIMESTAMPTZ;
   
   CREATE INDEX IF NOT EXISTS idx_devices_push_token 
       ON devices(push_token) WHERE push_token IS NOT NULL;
   
   CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_unique_push_token 
       ON devices(push_token) WHERE push_token IS NOT NULL;
   ```

3. **Update Environment**
   ```bash
   # Add to your .env file
   cp .env.example .env
   # Then edit .env with your specific configuration
   ```

4. **Add to Doppler (Optional)**
   ```bash
   cd /home/ubuntu/mls
   doppler secrets set ENABLE_PUSH_NOTIFICATIONS=true
   doppler secrets set APNS_KEY_PATH=/home/ubuntu/.config/bluesky-push-notifier/keys/AuthKey_A5C849F4W8.p8
   doppler secrets set APNS_KEY_ID=A5C849F4W8
   doppler secrets set APNS_TEAM_ID=YOUR_TEAM_ID
   doppler secrets set APNS_TOPIC=blue.catbird.app
   doppler secrets set APNS_PRODUCTION=false
   ```

5. **Client Integration**
   - Implement device token registration in iOS app
   - Handle incoming push notifications
   - Decrypt ciphertext using OpenMLS
   - (Optional) Add Notification Service Extension for rich previews

### Files Created/Modified

**New Files:**
- `server/migrations/20251119_001_push_notification_tokens.sql` - Database migration
- `server/src/handlers/register_device_token.rs` - Device token management
- `PUSH_NOTIFICATIONS_SETUP.md` - Comprehensive documentation

**Modified Files:**
- `server/Cargo.toml` - Added `a2` dependency
- `server/src/notifications/mod.rs` - Full APNs implementation
- `server/src/handlers/send_message.rs` - Integrated push notifications
- `server/src/handlers/mod.rs` - Exported new handlers
- `server/src/main.rs` - Added route endpoints
- `.env.example` - Added APNs configuration template

### Architecture

```
Client sends message
       ↓
MLS Server stores message
       ↓
Fan-out task (async):
  1. Create envelopes
  2. Emit SSE event
  3. Send push notifications → APNs → iOS Devices
       ↓
Client receives push with ciphertext
       ↓
Client decrypts with MLS
       ↓
Show notification preview
```

### Security Features

✅ **End-to-End Encryption Maintained**: Ciphertext sent through APNs is still MLS-encrypted
✅ **No Server Plaintext Access**: Server never sees message contents
✅ **Token Security**: Device tokens tied to authenticated users
✅ **Automatic Cleanup**: Invalid tokens (410 status) automatically removed
✅ **Privacy-Preserving**: No metadata exposed in push payload beyond conversation/message IDs

### Testing

1. **Verify APNs Key**:
   ```bash
   ls -la /home/ubuntu/.config/bluesky-push-notifier/keys/
   # Should show AuthKey_A5C849F4W8.p8
   ```

2. **Check Server Logs**:
   ```bash
   # After starting server with ENABLE_PUSH_NOTIFICATIONS=true
   tail -f server.log | grep -i "push\|apns"
   ```

3. **Test Registration** (from iOS client):
   ```swift
   mlsClient.registerDeviceToken(
       deviceId: deviceUUID,
       pushToken: apnsToken,
       deviceName: "iPhone",
       platform: "ios"
   )
   ```

### Documentation

Full setup guide available in: `PUSH_NOTIFICATIONS_SETUP.md`

Includes:
- Architecture diagrams
- Configuration details
- Client integration examples (Swift)
- Rich notification preview implementation
- Troubleshooting guide
- Production deployment checklist

### Build Status

✅ Server builds successfully with new push notification features
✅ All handlers registered and routed correctly
✅ Notification service initializes on startup
✅ Compatible with existing actor system

### Performance Considerations

- Push notifications sent in parallel to all recipients
- Non-blocking async operations
- Automatic retry with exponential backoff
- Failed deliveries logged for monitoring

---

**Ready to use!** Just need to:
1. Add your Apple Team ID to configuration
2. Run the database migration  
3. Start the server with `ENABLE_PUSH_NOTIFICATIONS=true`
4. Register device tokens from iOS clients
