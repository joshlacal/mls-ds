#!/bin/bash
#
# Catbird MLS Server Deployment Script (Host Deployment)
# Usage: ./deploy.sh
#
# This script:
# 1. Pulls latest code
# 2. Builds the release binary (in-place, used directly by systemd)
# 3. Runs pending SQL migrations via sqlx
# 4. Restarts the systemd service
# 5. Verifies the service is healthy
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration — derive repo root from script location
MLS_ROOT="$(cd "$(dirname "$0")" && pwd)"
TARGET_DIR="$MLS_ROOT/target"
BINARY_NAME="catbird-server"
SERVICE_NAME="catbird-mls-server"

echo -e "${GREEN}=== Catbird MLS Server Host Deployment ===${NC}"
echo

# Step 1: Pull latest code
echo -e "${YELLOW}[1/4] Pulling latest code...${NC}"
cd "$MLS_ROOT"
git pull --ff-only
echo -e "${GREEN}✓ Code updated${NC}"
echo

# Step 2: Build release binary
echo -e "${YELLOW}[2/4] Building release binary...${NC}"
cd "$MLS_ROOT/server"
SQLX_OFFLINE=true cargo build --release
echo -e "${GREEN}✓ Build complete${NC}"
echo

# Step 3: Verify binary
echo -e "${YELLOW}[3/5] Verifying binary...${NC}"
if [ ! -f "$TARGET_DIR/release/$BINARY_NAME" ]; then
    echo -e "${RED}ERROR: Binary not found at $TARGET_DIR/release/$BINARY_NAME${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Binary found${NC}"
echo "  Path: $TARGET_DIR/release/$BINARY_NAME"
echo "  Size: $(du -h "$TARGET_DIR/release/$BINARY_NAME" | cut -f1)"
echo

# Step 4: Run SQL migrations BEFORE restart
# Must run before restart so the new binary boots against a correctly-shaped
# schema. SKIP_MIGRATIONS=true in systemd env disables the startup check,
# so this step is the only place migrations actually run.
echo -e "${YELLOW}[4/5] Running database migrations...${NC}"
if ! command -v doppler &> /dev/null; then
    echo -e "${RED}ERROR: doppler CLI not found — cannot source DATABASE_URL${NC}"
    exit 1
fi
doppler run --project catbird-mls --config prd -- \
    "$MLS_ROOT/server/scripts/run-migrations.sh"
echo -e "${GREEN}✓ Migrations applied${NC}"
echo

# Step 5: Restart service
echo -e "${YELLOW}[5/5] Restarting service and verifying...${NC}"
sudo systemctl restart $SERVICE_NAME
echo -e "${GREEN}✓ Service restarted${NC}"
sleep 2

# Check service is running
if ! systemctl is-active --quiet $SERVICE_NAME; then
    echo -e "${RED}ERROR: Service is not running${NC}"
    echo "Service status:"
    sudo systemctl status $SERVICE_NAME --no-pager | tail -20
    exit 1
fi

echo -e "${GREEN}✓ Service is running${NC}"
echo

# Show recent logs
echo "Recent logs:"
sudo journalctl -u $SERVICE_NAME --no-pager -n 10 | tail -5
echo

echo -e "${GREEN}=== Deployment Complete ===${NC}"
echo "The server is now running with the latest binary on host."
echo
echo "Useful commands:"
echo "  View logs:    sudo journalctl -u $SERVICE_NAME -f"
echo "  Stop server:  sudo systemctl stop $SERVICE_NAME"
echo "  Restart:      sudo systemctl restart $SERVICE_NAME"
echo "  Status:       sudo systemctl status $SERVICE_NAME"
