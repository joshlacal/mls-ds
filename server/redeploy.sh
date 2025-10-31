#!/bin/bash
# Script to rebuild and redeploy the MLS server Docker container

set -e  # Exit on error

echo "🔨 Building Rust release binary..."
cd "$(dirname "$0")"
cargo build --release

echo "📦 Copying binary to server directory..."
cp ../target/release/catbird-server .

echo "🐳 Building Docker image..."
docker compose build mls-server

echo "🚀 Redeploying containers..."
docker compose up -d

echo "⏳ Waiting for server to be healthy..."
sleep 5

echo "✅ Checking server status..."
docker compose ps
docker logs --tail 10 catbird-mls-server

echo ""
echo "🎉 Deployment complete!"
echo ""
echo "To view logs: docker logs -f catbird-mls-server"
echo "To check health: curl http://localhost:3000/health"
