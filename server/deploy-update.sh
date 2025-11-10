#!/bin/bash
set -e

# =============================================================================
# Catbird MLS Server - Update Deployment Script
# =============================================================================
# This script updates the server binary WITHOUT wiping data:
#   1. Builds latest release binary
#   2. Rebuilds Docker image with new binary
#   3. Restarts mls-server container (preserves volumes)
#
# Use this for production updates that need to preserve data.
# Use deploy-fresh.sh if you need to wipe the database.
# =============================================================================

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║   Catbird MLS Server - Update Deployment                      ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "This deployment will:"
echo "  1. Build latest release binary"
echo "  2. Rebuild Docker image"
echo "  3. Restart mls-server (preserves database & redis data)"
echo ""
echo "✓ Database and Redis data will be PRESERVED"
echo ""

# Navigate to server directory
cd "$(dirname "$0")"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "Step 1/5: Building release binary..."
echo "═══════════════════════════════════════════════════════════════"
cargo build --release

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "Step 2/5: Copying binary to server directory..."
echo "═══════════════════════════════════════════════════════════════"
cp ../target/release/catbird-server ./catbird-server
chmod +x ./catbird-server
ls -lh ./catbird-server

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "Step 3/5: Rebuilding Docker image..."
echo "═══════════════════════════════════════════════════════════════"
docker build -f Dockerfile.prebuilt -t catbird-mls-server:latest .

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "Step 4/5: Restarting mls-server..."
echo "═══════════════════════════════════════════════════════════════"
docker compose up -d --force-recreate --no-deps mls-server

echo ""
echo "⏳ Waiting for server to be healthy..."
sleep 10

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "Step 5/5: Verifying deployment..."
echo "═══════════════════════════════════════════════════════════════"
docker compose ps

echo ""
echo "Health Check:"
curl -s http://localhost:3000/health | jq . 2>/dev/null || curl -s http://localhost:3000/health || echo "⚠️  Health check endpoint not responding"

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║   ✅ Update Deployment Complete!                               ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "Next steps:"
echo "  • View logs:          docker compose logs -f mls-server"
echo "  • Check data:         docker compose exec postgres psql -U catbird -d catbird -c 'SELECT COUNT(*) FROM users;'"
echo ""
