#!/bin/bash
set -e

# =============================================================================
# Catbird MLS Server - Fresh Deployment Script
# =============================================================================
# This script performs a COMPLETE wipe and rebuild:
#   1. Builds latest release binary
#   2. Stops all services
#   3. Removes ALL volumes (postgres_data, redis_data)
#   4. Rebuilds Docker image with new binary
#   5. Starts services with fresh greenfield schema
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
echo "  1. Build latest release binary (cargo build --release)"
echo "  2. Stop all services"
echo "  3. Remove database volume (ALL DATA WILL BE LOST)"
echo "  4. Remove redis volume (ALL CACHE WILL BE LOST)"
echo "  5. Rebuild Docker image"
echo "  6. Start services with fresh greenfield schema"
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
echo "Step 1/6: Building release binary..."
echo "═══════════════════════════════════════════════════════════════"
cargo build --release

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "Step 2/6: Copying binary to server directory..."
echo "═══════════════════════════════════════════════════════════════"
cp ../target/release/catbird-server ./catbird-server
chmod +x ./catbird-server
ls -lh ./catbird-server

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "Step 3/6: Stopping services..."
echo "═══════════════════════════════════════════════════════════════"
docker compose down

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "Step 4/6: Removing volumes..."
echo "═══════════════════════════════════════════════════════════════"
docker volume rm server_postgres_data server_redis_data 2>/dev/null || true
echo "✓ Volumes removed (if they existed)"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "Step 5/6: Rebuilding Docker image..."
echo "═══════════════════════════════════════════════════════════════"
docker build --no-cache -f Dockerfile.prebuilt -t catbird-mls-server:latest .

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "Step 6/6: Starting services..."
echo "═══════════════════════════════════════════════════════════════"
docker compose up -d

echo ""
echo "⏳ Waiting for services to be healthy..."
sleep 15

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "Service Status:"
echo "═══════════════════════════════════════════════════════════════"
docker compose ps

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "Health Check:"
echo "═══════════════════════════════════════════════════════════════"
curl -s http://localhost:3000/health | jq . 2>/dev/null || curl -s http://localhost:3000/health || echo "⚠️  Health check endpoint not responding"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "Database Tables:"
echo "═══════════════════════════════════════════════════════════════"
docker compose exec -T postgres psql -U catbird -d catbird -c '\dt' 2>/dev/null | head -30 || echo "⚠️  Could not list tables"

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║   ✅ Fresh Deployment Complete!                                ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "Next steps:"
echo "  • View logs:          docker compose logs -f mls-server"
echo "  • Check schema:       docker compose exec postgres psql -U catbird -d catbird -c '\\d messages'"
echo "  • Test endpoint:      curl http://localhost:3000/health"
echo "  • Stop services:      docker compose down"
echo ""
