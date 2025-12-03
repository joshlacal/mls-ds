#!/bin/bash
set -e

echo "🔄 Rebuilding MLS Server with Code Changes"
echo "=========================================="

# Step 1: Build locally to generate Cargo.lock and verify compilation
echo "📦 Step 1: Building Rust code..."
cd /home/ubuntu/mls/server
cargo build --release

# Step 2: Restart the systemd service
echo "🔄 Step 2: Restarting server..."
sudo systemctl restart catbird-mls-server

# Step 3: Wait for server to start
echo "⏳ Step 3: Waiting for server to start..."
sleep 5

# Step 4: Check health
echo "🏥 Step 4: Checking server health..."
sudo journalctl -u catbird-mls-server -n 20 --no-pager

echo ""
echo "✅ Deployment complete!"
echo ""
echo "To view logs: sudo journalctl -u catbird-mls-server -f"
