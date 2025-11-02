#!/bin/bash
set -e

echo "🔄 Rebuilding MLS Server with Code Changes"
echo "=========================================="

# Step 1: Build locally to generate Cargo.lock and verify compilation
echo "📦 Step 1: Building Rust code locally..."
cd /home/ubuntu/mls/server
cargo build --release

# Step 2: Copy the built binary for Docker
echo "📁 Step 2: Copying binary for Docker..."
cp ../target/release/catbird-server ./catbird-server

# Step 3: Restart Docker with the new binary
echo "🐳 Step 3: Rebuilding Docker container..."
docker compose down
docker compose build --no-cache mls-server
docker compose up -d

# Step 4: Wait for server to start
echo "⏳ Step 4: Waiting for server to start..."
sleep 10

# Step 5: Check health
echo "🏥 Step 5: Checking server health..."
docker logs catbird-mls-server --tail 20

echo ""
echo "✅ Deployment complete!"
echo ""
echo "To verify the new query is deployed, check logs for:"
echo "docker logs catbird-mls-server 2>&1 | grep 'SELECT wm.id, wm.welcome_data, wm.key_package_hash'"
