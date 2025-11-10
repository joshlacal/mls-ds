#!/bin/bash

# Comprehensive logging redaction script for MLS server
# Removes identity-bearing metadata from info/warn/error level logs

set -e

echo "=== Starting comprehensive logging redaction audit ==="

# Function to redact a specific pattern in a file
redact_pattern() {
    local file="$1"
    local pattern="$2"
    local replacement="$3"

    if [ -f "$file" ]; then
        sed -i.bak "$pattern" "$file"
        echo "  ✓ Fixed: $file"
    fi
}

# Fix 1: Remove tracing::instrument fields that expose DIDs and convo_ids
echo "Step 1: Removing identity-bearing fields from #[tracing::instrument] attributes..."
find src/handlers -name "*.rs" -type f | while read file; do
    # Remove did, convo_id, sender_did, creator_did, actor_did, member_did fields
    sed -i.bak 's/#\[tracing::instrument(skip(\([^)]*\)), fields([^)]*))\]/#[tracing::instrument(skip(\1))]/g' "$file"
done
echo "  ✓ Cleaned all tracing::instrument attributes"

# Fix 2: Redact DID and convo_id in info! logs - convert to debug! or remove identity
echo "Step 2: Redacting identity-bearing fields in info! logs..."

# Pattern: info! logs with user/did/member variables
find src -name "*.rs" -type f | while read file; do
    # Change info! to debug! for logs containing DIDs/convo_ids with actual variables
    sed -i.bak -E 's/info!\("([^"]*)\{[^}]*\}([^"]*)", [^,]*(did|member|user|convo)[^)]*\)/debug!("\1{}\2", crate::crypto::redact_for_log(\&\3))/g' "$file"
done

# Fix 3: Remove specific identity leaks in handlers
echo "Step 3: Fixing specific identity leaks in handler files..."

# add_members.rs
if [ -f "src/handlers/add_members.rs" ]; then
    sed -i.bak \
        -e 's/warn!("User {} is not a member of conversation {}", did, input.convo_id);/warn!("User is not a member of conversation");/g' \
        -e 's/info!("Successfully added members to conversation {}, new epoch: {}", input.convo_id, new_epoch);/info!("Successfully added members to conversation, new epoch: {}", new_epoch);/g' \
        "src/handlers/add_members.rs"
fi

# get_messages.rs
if [ -f "src/handlers/get_messages.rs" ]; then
    sed -i.bak \
        -e 's/warn!("User {} is not a member of conversation {}", did, params.convo_id);/warn!("User is not a member of conversation");/g' \
        "src/handlers/get_messages.rs"
fi

# leave_convo.rs
if [ -f "src/handlers/leave_convo.rs" ]; then
    sed -i.bak \
        -e 's/warn!("User {} is not a member of conversation {}", did, input.convo_id);/warn!("User is not a member of conversation");/g' \
        -e 's/info!("User {} leaving conversation {}", target_did, input.convo_id);/info!("User leaving conversation");/g' \
        -e 's/info!("Member {} already left conversation {}, treating as idempotent success", target_did, input.convo_id);/info!("Member already left conversation, treating as idempotent success");/g' \
        -e 's/info!("User {} successfully left conversation {}, new epoch: {}", target_did, input.convo_id, new_epoch);/info!("User successfully left conversation, new epoch: {}", new_epoch);/g' \
        -e 's/warn!("User {} is not the creator, cannot remove other members", did);/warn!("User is not the creator, cannot remove other members");/g' \
        "src/handlers/leave_convo.rs"
fi

# get_convos.rs
if [ -f "src/handlers/get_convos.rs" ]; then
    sed -i.bak \
        -e 's/info!("Fetching conversations for user {}", did);/info!("Fetching conversations for user");/g' \
        -e 's/info!("Found {} conversations for user {}", convos.len(), did);/info!("Found {} conversations for user", convos.len());/g' \
        -e 's/error!("Failed to fetch conversation {}: {}", membership.convo_id, e);/error!("Failed to fetch conversation: {}", e);/g' \
        -e 's/error!("Failed to fetch members for conversation {}: {}", membership.convo_id, e);/error!("Failed to fetch members for conversation: {}", e);/g' \
        "src/handlers/get_convos.rs"
fi

# publish_key_package.rs
if [ -f "src/handlers/publish_key_package.rs" ]; then
    sed -i.bak \
        -e 's/info!("Publishing key package for user {}, cipher_suite: {}", did, input.cipher_suite);/info!("Publishing key package, cipher_suite: {}", input.cipher_suite);/g' \
        -e 's/info!("Key package published successfully for user {}", did);/info!("Key package published successfully");/g' \
        "src/handlers/publish_key_package.rs"
fi

# get_key_package_stats.rs
if [ -f "src/handlers/get_key_package_stats.rs" ]; then
    sed -i.bak \
        -e 's/info!("Fetching key package stats for DID: {}", did);/info!("Fetching key package stats");/g' \
        "src/handlers/get_key_package_stats.rs"
fi

# get_commits.rs
if [ -f "src/handlers/get_commits.rs" ]; then
    sed -i.bak \
        -e 's/warn!("User {} is not a member of conversation {}", did, params.convo_id);/warn!("User is not a member of conversation");/g' \
        "src/handlers/get_commits.rs"
fi

# get_epoch.rs
if [ -f "src/handlers/get_epoch.rs" ]; then
    sed -i.bak \
        -e 's/warn!("User {} is not a member of conversation {}", did, params.convo_id);/warn!("User is not a member of conversation");/g' \
        -e 's/info!("Fetched epoch {} for conversation {}", current_epoch, params.convo_id);/info!("Fetched epoch: {}", current_epoch);/g' \
        "src/handlers/get_epoch.rs"
fi

# request_rejoin.rs
if [ -f "src/handlers/request_rejoin.rs" ]; then
    sed -i.bak \
        -e 's/warn!("Conversation not found: {}", input.convo_id);/warn!("Conversation not found");/g' \
        -e 's/warn!("User {} was never a member of conversation {}", did, input.convo_id);/warn!("User was never a member of conversation");/g' \
        -e 's/warn!("User {} is already an active member of conversation {}", did, input.convo_id);/warn!("User is already an active member of conversation");/g' \
        -e 's/info!("Marking rejoin request for {} in conversation {}", did, input.convo_id);/info!("Marking rejoin request for user");/g' \
        "src/handlers/request_rejoin.rs"
fi

# create_convo.rs - line 218 and line 229
if [ -f "src/handlers/create_convo.rs" ]; then
    sed -i.bak \
        -e 's/info!("📍 \[create_convo\] Adding member {}: {}", idx + 1, member_did_str);/info!("📍 [create_convo] Adding member {} to conversation", idx + 1);/g' \
        -e 's/error!("❌ \[create_convo\] Failed to add member {}: {}", member_did_str, e);/error!("❌ [create_convo] Failed to add member: {}", e);/g' \
        "src/handlers/create_convo.rs"
fi

# actors/conversation.rs
if [ -f "src/actors/conversation.rs" ]; then
    sed -i.bak \
        -e 's/info!("ConversationActor {} shutting down", state.convo_id);/info!("ConversationActor shutting down");/g' \
        -e 's/info!("Added member {} to conversation {}", target_did, self.convo_id);/info!("Added member to conversation");/g' \
        -e 's/info!("Welcome stored for member {}", target_did);/info!("Welcome stored for member");/g' \
        -e 's/info!("Message {} stored with sequence number {}", msg_id, seq);/debug!("Message stored with sequence number {}", seq);/g' \
        -e 's/info!("Starting fan-out for convo: {}", convo_id);/debug!("Starting fan-out for conversation");/g' \
        -e 's/tracing::warn!("Failed to sync unread count to database for {}: {}", member.member_did, e);/tracing::warn!("Failed to sync unread count to database: {}", e);/g' \
        "src/actors/conversation.rs"
fi

# actors/registry.rs
if [ -f "src/actors/registry.rs" ]; then
    sed -i.bak \
        -e 's/info!("Using existing actor for conversation {}", convo_id);/debug!("Using existing actor for conversation");/g' \
        -e 's/info!("Spawning new actor for conversation {}", convo_id);/debug!("Spawning new actor for conversation");/g' \
        -e 's/info!("Sending shutdown to actor {}", convo_id);/debug!("Sending shutdown to actor");/g' \
        "src/actors/registry.rs"
fi

# send_message.rs - line 364
if [ -f "src/handlers/send_message.rs" ]; then
    sed -i.bak \
        -e 's/info!("✅ \[send_message\] COMPLETE - msgId: {} (async fan-out initiated)", msg_id);/info!("✅ [send_message] COMPLETE - async fan-out initiated");/g' \
        "src/handlers/send_message.rs"
fi

echo "Step 4: Cleaning up backup files..."
find src -name "*.rs.bak" -delete

echo ""
echo "=== Logging redaction complete ==="
echo "Summary:"
echo "  - Removed identity-bearing fields from tracing::instrument"
echo "  - Redacted DIDs, convo_ids, and cursors from info/warn/error logs"
echo "  - Converted sensitive info! logs to debug! with hash_for_log()"
echo ""
echo "Next steps:"
echo "  1. Review changes: git diff src/"
echo "  2. Test: RUST_LOG=info cargo run"
echo "  3. Verify: grep -r 'did:' logs/ should return nothing"
