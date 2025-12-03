#!/bin/bash
set -e

echo "🧹 Starting clean rebuild and host deployment..."

# Step 1: Stop the existing service
echo "🛑 Stopping catbird-mls-server service..."
sudo systemctl stop catbird-mls-server 2>/dev/null || true

# Step 2: Clean cargo build artifacts
echo "🗑️  Cleaning build artifacts..."
cd /home/ubuntu/mls
cargo clean

# Step 3: Deploy to host using deploy.sh
echo "🚀 Deploying to host machine..."
cd /home/ubuntu/mls
if [ -f "./deploy.sh" ]; then
    ./deploy.sh
else
    echo "❌ deploy.sh not found!"
    exit 1
fi

echo "✅ Clean rebuild and deployment complete!"
