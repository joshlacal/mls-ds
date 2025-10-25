# CloudKit/R2/External Assets Removal - Implementation Summary

## Overview
Successfully transformed the MLS messaging system from a hybrid CloudKit/R2/PostgreSQL architecture to a pure PostgreSQL text-only system with Bluesky embeds, reactions, and Tenor GIFs support.

## Date
October 24, 2025

## Changes Made

### 1. Lexicon Updates

**File: `lexicon/blue/catbird/mls/blue.catbird.mls.defs.json`**
- ✅ Removed `externalAsset` definition (CloudKit/R2 storage pointers)
- ✅ Removed `blobRef` definition (file attachments)
- ✅ Removed `avatar` field from `convoMetadata` (now text-only with name/description)
- ✅ Kept `messageView` with `embedType`/`embedUri` for Tenor GIFs and Bluesky embeds

**File: `lexicon/blue/catbird/mls/blue.catbird.mls.uploadBlob.json`**
- ✅ Deleted entirely (no blob uploads needed for text-only system)

### 2. Handler Updates

**File: `server/src/handlers/upload_blob.rs`**
- ✅ Deleted entirely

**File: `server/src/handlers/mod.rs`**
- ✅ Removed `mod upload_blob;`
- ✅ Removed `pub use upload_blob::upload_blob;`

**File: `server/src/handlers/create_convo.rs`**
- ✅ Removed avatar field extraction from metadata
- ✅ Updated INSERT query to only include title (removed avatar_blob)
- ✅ Removed avatar from ConvoMetadataView construction
- ✅ Fixed test code to use new CreateConvoInput structure

**File: `server/src/handlers/get_convos.rs`**
- ✅ Updated SELECT query to fetch title instead of name, description, avatar_blob
- ✅ Removed avatar from ConvoMetadataView construction

**File: `server/src/handlers/send_message.rs`**
- ✅ Removed unused CloudKit/fanout imports (Envelope, MailboxConfig, MailboxFactory)
- ✅ Simplified envelope creation (no provider/zone fields)

### 3. Model Simplification

**File: `server/src/models.rs`**
- ✅ Removed `Blob` struct
- ✅ Removed `BlobRef` struct
- ✅ Removed `cloudkit_zone_id` and `storage_model` fields from Conversation
- ✅ Removed `avatar` field from ConvoMetadata and ConvoMetadataView
- ✅ Field names remain: `creator` (not created_by) for ConvoView

### 4. Database Layer Changes

**File: `server/src/db.rs`**
- ✅ Removed all blob operation functions:
  - `store_blob`
  - `get_blob`
  - `list_blobs_by_conversation`
  - `delete_blob`
  - `get_user_storage_size`
- ✅ Updated `get_conversation` query to exclude cloudkit_zone_id, storage_model
- ✅ Simplified `create_envelope` to remove mailbox_provider and cloudkit_zone parameters
- ✅ Removed `get_member_mailbox_config` function entirely
- ✅ `create_message` signature: (pool, convo_id, sender_did, ciphertext, epoch, embed_type, embed_uri)

### 5. Fanout Simplification

**File: `server/src/fanout/mod.rs`**
- ✅ Removed `CloudKitBackend` implementation
- ✅ Removed `cloudkit_zone` and `mailbox_provider` fields from Envelope
- ✅ Simplified to only `NullBackend` (SSE-based delivery)
- ✅ Removed `MailboxConfig` `cloudkit_enabled` field

### 6. Route Updates

**File: `server/src/main.rs`**
- ✅ Removed `/xrpc/blue.catbird.mls.uploadBlob` route

### 7. Database Migration

**File: `server/migrations/20251024000001_remove_cloudkit_columns.sql`**
```sql
-- Drop CloudKit-related columns from conversations
ALTER TABLE conversations DROP COLUMN IF EXISTS cloudkit_zone_id;
ALTER TABLE conversations DROP COLUMN IF EXISTS storage_model;

-- Drop mailbox provider columns from envelopes
ALTER TABLE envelopes DROP COLUMN IF EXISTS mailbox_provider;
ALTER TABLE envelopes DROP COLUMN IF EXISTS cloudkit_zone;

-- Drop mailbox configuration from members
ALTER TABLE members DROP COLUMN IF EXISTS mailbox_provider;
ALTER TABLE members DROP COLUMN IF EXISTS mailbox_zone;

-- Drop the entire blobs table (no longer needed)
DROP TABLE IF EXISTS blobs CASCADE;
```

### 8. Test Updates

**File: `server/tests/db_tests.rs`**
- ✅ Removed blob operation tests
- ✅ Fixed `create_message` calls to use correct signature (7 params)
- ✅ Changed `sent_at` references to `created_at`
- ✅ Updated TRUNCATE statement to remove blobs table

## Architecture Changes

### Before
- **Storage**: CloudKit (iOS), R2 (general), PostgreSQL (metadata)
- **Message Flow**: Hybrid fanout to CloudKit zones or R2 buckets
- **Blob Support**: Full file upload/download with external storage
- **Avatar Support**: Blob references in conversation metadata

### After
- **Storage**: PostgreSQL only (text-only messages with embeds)
- **Message Flow**: Direct PostgreSQL storage with SSE real-time delivery
- **Embed Support**: Tenor GIFs (URLs) and Bluesky posts (AT-URIs)
- **Avatar Support**: None (text-only metadata with name/description)

## Build Status
✅ **Compilation Successful** - Build completes with only minor warnings about unused imports

## What Was Preserved

1. **MLS Protocol**: Core MLS encryption and group management
2. **Real-time Delivery**: SSE (Server-Sent Events) for live updates
3. **Embeds**: Support for Tenor GIFs and Bluesky post embeds via URLs/AT-URIs
4. **Reactions**: Emoji reactions on messages
5. **PostgreSQL Storage**: All message ciphertext stored directly in database
6. **Authentication**: AT Protocol DID-based auth remains unchanged

## System Capabilities

The system is now a **pure text-only MLS messaging framework** with:
- ✅ End-to-end encrypted group chats
- ✅ PostgreSQL-only storage (no external blob storage)
- ✅ Tenor GIF embeds (via URL references)
- ✅ Bluesky post embeds (via AT-URI references)
- ✅ Message reactions
- ✅ Real-time delivery via SSE
- ✅ AT Protocol identity integration

## Migration Path

To apply these changes to an existing database:
```bash
cd server
sqlx migrate run
```

This will execute the migration `20251024000001_remove_cloudkit_columns.sql` which:
1. Drops CloudKit-related columns from conversations, envelopes, and members tables
2. Drops the entire blobs table
3. Preserves all conversation, member, message, and key package data

## Next Steps

1. **Test the System**: Run integration tests to verify functionality
2. **Update Documentation**: Reflect the text-only architecture in user/developer guides
3. **Client Updates**: Update iOS/Android clients to remove blob upload code
4. **Deploy Migration**: Apply database migration to production systems

## Benefits

1. **Simplified Architecture**: Single storage backend (PostgreSQL)
2. **Reduced Costs**: No CloudKit or R2 storage fees
3. **Better Performance**: Direct database queries, no external API calls
4. **Easier Maintenance**: Fewer moving parts, single data source
5. **AT Protocol Alignment**: Pure XRPC-based interoperable messaging
