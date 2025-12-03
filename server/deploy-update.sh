#!/bin/bash
set -e

# =============================================================================
# Catbird MLS Server - Update Deployment Script
# =============================================================================
# Host-based deployment that updates the server WITHOUT wiping data:
#   1. Builds latest release binary
#   2. Restarts the systemd service
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
echo "  2. Restart the server"
echo ""
echo "✓ Database will be PRESERVED"
echo ""

# Navigate to server directory
cd "$(dirname "$0")"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "Step 1/3: Building release binary..."
echo "═══════════════════════════════════════════════════════════════"
cargo build --release

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "Step 2/3: Restarting server..."
echo "═══════════════════════════════════════════════════════════════"
sudo systemctl restart catbird-mls-server

echo ""
echo "⏳ Waiting for server to be healthy..."
sleep 5

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "Step 3/3: Verifying deployment..."
echo "═══════════════════════════════════════════════════════════════"
sudo systemctl status catbird-mls-server --no-pager || true

echo ""
echo "Health Check:"
curl -s http://localhost:3000/health | jq . 2>/dev/null || curl -s http://localhost:3000/health || echo "⚠️  Health check endpoint not responding"

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║   ✅ Update Deployment Complete!                               ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "Next steps:"
echo "  • View logs:          sudo journalctl -u catbird-mls-server -f"
echo "  • Check data:         psql -h localhost -U catbird -d catbird -c 'SELECT COUNT(*) FROM users;'"
echo ""
