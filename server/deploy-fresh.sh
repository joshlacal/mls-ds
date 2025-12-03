#!/bin/bash
set -e

# =============================================================================
# Catbird MLS Server - Fresh Deployment Script
# =============================================================================
# Host-based deployment that performs a COMPLETE wipe and rebuild:
#   1. Stops the systemd service
#   2. Clears the database
#   3. Builds latest release binary
#   4. Runs migrations (applies greenfield schema)
#   5. Starts the service
#
# WARNING: This will DELETE ALL DATA!
# Use deploy-update.sh for production updates that preserve data.
# =============================================================================

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║   Catbird MLS Server - Fresh Deployment                       ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "⚠️  WARNING: This will DELETE ALL DATA!"
echo ""
echo "This deployment will:"
echo "  1. Stop the server"
echo "  2. Clear ALL database tables"
echo "  3. Build latest release binary (cargo build --release)"
echo "  4. Start the server with fresh schema"
echo ""

# Check if running in CI/automated mode
if [ "$CI" != "true" ] && [ "$SKIP_CONFIRM" != "true" ]; then
    read -p "Continue? (yes/no): " -r
    echo
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        echo "❌ Deployment cancelled"
        exit 1
    fi
fi

# Navigate to server directory
cd "$(dirname "$0")"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "Step 1/5: Stopping server..."
echo "═══════════════════════════════════════════════════════════════"
sudo systemctl stop catbird-mls-server 2>/dev/null || true
echo "✓ Server stopped"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "Step 2/5: Clearing database..."
echo "═══════════════════════════════════════════════════════════════"
./scripts/clear-db-fast.sh
echo "✓ Database cleared"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "Step 3/5: Building release binary..."
echo "═══════════════════════════════════════════════════════════════"
cargo build --release

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "Step 4/5: Running migrations..."
echo "═══════════════════════════════════════════════════════════════"
source .env
./scripts/run-migrations.sh "$DATABASE_URL"
echo "✓ Migrations complete"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "Step 5/5: Starting server..."
echo "═══════════════════════════════════════════════════════════════"
sudo systemctl start catbird-mls-server

echo ""
echo "⏳ Waiting for server to be healthy..."
sleep 5

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "Service Status:"
echo "═══════════════════════════════════════════════════════════════"
sudo systemctl status catbird-mls-server --no-pager || true

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "Health Check:"
echo "═══════════════════════════════════════════════════════════════"
curl -s http://localhost:3000/health | jq . 2>/dev/null || curl -s http://localhost:3000/health || echo "⚠️  Health check endpoint not responding"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "Database Tables:"
echo "═══════════════════════════════════════════════════════════════"
psql -h localhost -U catbird -d catbird -c '\dt' 2>/dev/null | head -30 || echo "⚠️  Could not list tables"

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║   ✅ Fresh Deployment Complete!                                ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "Next steps:"
echo "  • View logs:          sudo journalctl -u catbird-mls-server -f"
echo "  • Check schema:       psql -h localhost -U catbird -d catbird -c '\\d messages'"
echo "  • Test endpoint:      curl http://localhost:3000/health"
echo "  • Stop server:        sudo systemctl stop catbird-mls-server"
echo ""
