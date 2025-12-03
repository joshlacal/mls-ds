#!/bin/bash
# Script to rebuild and redeploy the MLS server

set -e  # Exit on error

echo "🔨 Building Rust release binary..."
cd "$(dirname "$0")"
cargo build --release

echo "🚀 Restarting server..."
sudo systemctl restart catbird-mls-server

echo "⏳ Waiting for server to be healthy..."
sleep 5

echo "✅ Checking server status..."
sudo systemctl status catbird-mls-server --no-pager || true

echo ""
echo "🎉 Deployment complete!"
echo ""
echo "To view logs: sudo journalctl -u catbird-mls-server -f"
echo "To check health: curl http://localhost:3000/health"
