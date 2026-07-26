#!/bin/bash
#
# Catbird MLS Server Deployment Script (Host Deployment)
# Usage: ./deploy.sh
#
# This script:
# 1. Verifies deployment prerequisites
# 2. Pulls latest code
# 3. Builds and verifies the release binary
# 4. Stops the systemd service for a migration maintenance window
# 5. Bootstraps and runs pending SQL migrations via sqlx
# 6. Starts and verifies the service only after every migration succeeds
#

set -euo pipefail

# Source cargo env (not available in non-login shells on the deploy host)
if [ -f "$HOME/.cargo/env" ]; then
    source "$HOME/.cargo/env"
fi

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

# Step 1: Verify every prerequisite before changing code or service state.
echo -e "${YELLOW}[1/7] Verifying deployment prerequisites...${NC}"
for prerequisite in git cargo doppler sudo systemctl; do
    if ! command -v "$prerequisite" >/dev/null 2>&1; then
        echo -e "${RED}ERROR: Required command not found: $prerequisite${NC}"
        exit 1
    fi
done
for migration_script in \
    "$MLS_ROOT/server/scripts/bootstrap-sqlx-migrations.sh" \
    "$MLS_ROOT/server/scripts/run-migrations.sh"
do
    if [ ! -x "$migration_script" ]; then
        echo -e "${RED}ERROR: Required migration script is not executable: $migration_script${NC}"
        exit 1
    fi
done
echo -e "${GREEN}✓ Prerequisites verified${NC}"
echo

# Step 2: Pull latest code
echo -e "${YELLOW}[2/7] Pulling latest code...${NC}"
cd "$MLS_ROOT"
git pull --ff-only
echo -e "${GREEN}✓ Code updated${NC}"
echo

# Step 3: Build release binary
echo -e "${YELLOW}[3/7] Building release binary...${NC}"
cd "$MLS_ROOT/server"
SQLX_OFFLINE=true cargo build --release
echo -e "${GREEN}✓ Build complete${NC}"
echo

# Step 4: Verify binary
echo -e "${YELLOW}[4/7] Verifying binary...${NC}"
if [ ! -f "$TARGET_DIR/release/$BINARY_NAME" ]; then
    echo -e "${RED}ERROR: Binary not found at $TARGET_DIR/release/$BINARY_NAME${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Binary found${NC}"
echo "  Path: $TARGET_DIR/release/$BINARY_NAME"
echo "  Size: $(du -h "$TARGET_DIR/release/$BINARY_NAME" | cut -f1)"
echo

# Step 5: Stop service before the migration bootstrap begins. This maintenance
# gate prevents old writers from running in the A -> A2 micro-window.
echo -e "${YELLOW}[5/7] Stopping service for migration maintenance...${NC}"
if ! sudo systemctl stop "$SERVICE_NAME"; then
    echo -e "${RED}ERROR: Could not stop $SERVICE_NAME; migrations were not started${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Service stopped${NC}"
echo

# Step 6: Run SQL migrations while the service remains stopped.
# SKIP_MIGRATIONS=true in systemd env disables the startup check, so this is the
# only deployment path that advances the SQLx ledger.
#
# Bootstrap-first: mark historical 14-digit-format migrations as applied
# (prod was seeded outside sqlx; _sqlx_migrations is missing those rows).
# Idempotent — no-op after first successful run on each DB.
echo -e "${YELLOW}[6/7] Running database migrations...${NC}"
if ! doppler run --project catbird-mls --config prd -- \
    "$MLS_ROOT/server/scripts/bootstrap-sqlx-migrations.sh"
then
    echo -e "${RED}ERROR: SQLx migration bootstrap failed; $SERVICE_NAME remains stopped${NC}"
    exit 1
fi
if ! doppler run --project catbird-mls --config prd -- \
    "$MLS_ROOT/server/scripts/run-migrations.sh"
then
    echo -e "${RED}ERROR: Database migration failed; $SERVICE_NAME remains stopped${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Migrations applied${NC}"
echo

# Step 7: Start only after the complete migration sequence succeeds.
echo -e "${YELLOW}[7/7] Starting service and verifying...${NC}"
if ! sudo systemctl start "$SERVICE_NAME"; then
    echo -e "${RED}ERROR: Service start failed; $SERVICE_NAME remains stopped${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Service started${NC}"
sleep 2

# Check service is running
if ! systemctl is-active --quiet "$SERVICE_NAME"; then
    echo -e "${RED}ERROR: Service is not running${NC}"
    echo "Service status:"
    sudo systemctl status "$SERVICE_NAME" --no-pager | tail -20
    exit 1
fi

echo -e "${GREEN}✓ Service is running${NC}"
echo

# Show recent logs
echo "Recent logs:"
sudo journalctl -u "$SERVICE_NAME" --no-pager -n 10 | tail -5
echo

echo -e "${GREEN}=== Deployment Complete ===${NC}"
echo "The server is now running with the latest binary on host."
echo
echo "Useful commands:"
echo "  View logs:    sudo journalctl -u $SERVICE_NAME -f"
echo "  Stop server:  sudo systemctl stop $SERVICE_NAME"
echo "  Start:        sudo systemctl start $SERVICE_NAME"
echo "  Status:       sudo systemctl status $SERVICE_NAME"
