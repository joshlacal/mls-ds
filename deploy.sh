#!/bin/bash
#
# Catbird MLS Server Deployment Script (Host Deployment)
# Usage: ./deploy.sh
#
# This script:
# 1. Builds the release binary
# 2. Copies it to /usr/local/bin
# 3. Restarts the systemd service
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
MLS_ROOT="/home/ubuntu/mls"
TARGET_DIR="$MLS_ROOT/target"
BINARY_NAME="catbird-server"
SERVICE_NAME="catbird-mls-server"

echo -e "${GREEN}=== Catbird MLS Server Host Deployment ===${NC}"
echo

# Step 1: Build release binary
echo -e "${YELLOW}[1/4] Building release binary...${NC}"
cd "$MLS_ROOT/server"
SQLX_OFFLINE=true cargo build --release
echo -e "${GREEN}✓ Build complete${NC}"
echo

# Step 2: Verify binary exists
echo -e "${YELLOW}[2/4] Verifying binary...${NC}"
if [ ! -f "$TARGET_DIR/release/$BINARY_NAME" ]; then
    echo -e "${RED}ERROR: Binary not found at $TARGET_DIR/release/$BINARY_NAME${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Binary found${NC}"
echo "  Path: $TARGET_DIR/release/$BINARY_NAME"
echo "  Size: $(du -h "$TARGET_DIR/release/$BINARY_NAME" | cut -f1)"
echo "  Date: $(date -r "$TARGET_DIR/release/$BINARY_NAME" '+%Y-%m-%d %H:%M:%S')"
echo

# Step 3: Copy binary and restart service
echo -e "${YELLOW}[3/4] Installing binary and restarting service...${NC}"
sudo cp -f "$TARGET_DIR/release/$BINARY_NAME" /usr/local/bin/$BINARY_NAME
sudo chmod +x /usr/local/bin/$BINARY_NAME
sudo systemctl restart $SERVICE_NAME
echo -e "${GREEN}✓ Service restarted${NC}"
echo

# Step 4: Verify deployment
echo -e "${YELLOW}[4/4] Verifying deployment...${NC}"
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
