#!/bin/bash
set -euo pipefail

# Rollback Script for MLS Server (Host-based)
# Restores a previous binary version

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

BACKUP_DIR="/home/ubuntu/mls/backups"
BINARY_PATH="/home/ubuntu/mls/target/release/catbird-server"

echo "=========================================="
echo "  MLS Server Rollback"
echo "=========================================="
echo ""

# Check for backup binaries
if [ ! -d "$BACKUP_DIR" ]; then
    log_error "No backup directory found at $BACKUP_DIR"
    echo ""
    echo "To create a backup before deploying, run:"
    echo "  mkdir -p $BACKUP_DIR"
    echo "  cp $BINARY_PATH $BACKUP_DIR/catbird-server.\$(date +%Y%m%d_%H%M%S)"
    exit 1
fi

# List available backups
log_info "Available backups:"
ls -lt "$BACKUP_DIR"/catbird-server.* 2>/dev/null || {
    log_error "No backup binaries found in $BACKUP_DIR"
    exit 1
}

echo ""
read -p "Enter backup filename to restore (or 'latest' for most recent): " BACKUP_CHOICE

if [ "$BACKUP_CHOICE" = "latest" ]; then
    BACKUP_FILE=$(ls -t "$BACKUP_DIR"/catbird-server.* 2>/dev/null | head -1)
else
    BACKUP_FILE="$BACKUP_DIR/$BACKUP_CHOICE"
fi

if [ ! -f "$BACKUP_FILE" ]; then
    log_error "Backup file not found: $BACKUP_FILE"
    exit 1
fi

log_warn "This will rollback to: $BACKUP_FILE"
read -p "Are you sure you want to continue? (yes/no): " -r
if [ "$REPLY" != "yes" ]; then
    log_info "Rollback cancelled"
    exit 0
fi

# Stop the service
log_info "Stopping server..."
sudo systemctl stop catbird-mls-server

# Backup current binary
CURRENT_BACKUP="$BACKUP_DIR/catbird-server.$(date +%Y%m%d_%H%M%S).pre-rollback"
log_info "Backing up current binary to $CURRENT_BACKUP..."
cp "$BINARY_PATH" "$CURRENT_BACKUP" 2>/dev/null || true

# Restore the backup
log_info "Restoring backup..."
cp "$BACKUP_FILE" "$BINARY_PATH"
chmod +x "$BINARY_PATH"

# Start the service
log_info "Starting server..."
sudo systemctl start catbird-mls-server

# Wait and check health
log_info "Waiting for server to be healthy..."
sleep 5

# Run health checks
log_info "Running health checks..."
if curl -sf http://localhost:3000/health > /dev/null 2>&1; then
    log_success "Health check passed"
else
    log_error "Health check failed - consider rolling forward"
    sudo journalctl -u catbird-mls-server -n 20 --no-pager
    exit 1
fi

log_success "Rollback completed successfully!"
log_info "Restored from: $BACKUP_FILE"

echo ""
echo "To verify the rollback:"
echo "  curl http://localhost:3000/health"
echo "  sudo journalctl -u catbird-mls-server -f"
echo ""
echo "To undo this rollback:"
echo "  cp $CURRENT_BACKUP $BINARY_PATH"
echo "  sudo systemctl restart catbird-mls-server"

exit 0
