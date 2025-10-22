#!/bin/bash
set -euo pipefail

# Database Restore Script for MLS Server
# This script restores a PostgreSQL database from a backup file

# Configuration
BACKUP_DIR="${BACKUP_DIR:-/backups}"
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-catbird}"
DB_USER="${DB_USER:-catbird}"
BACKUP_FILE="${1:-}"
S3_BUCKET="${BACKUP_S3_BUCKET:-}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

usage() {
    echo "Usage: $0 <backup_file>"
    echo "  backup_file: Name of the backup file to restore (in $BACKUP_DIR)"
    echo ""
    echo "Examples:"
    echo "  $0 catbird_db_20231201_120000.sql.gz"
    echo "  $0 s3://bucket/path/backup.sql.gz  # Download from S3 first"
    echo ""
    echo "List available backups:"
    echo "  ls -lh $BACKUP_DIR/catbird_db_*.sql.gz"
    exit 1
}

# Check if backup file is provided
if [ -z "$BACKUP_FILE" ]; then
    log_error "No backup file specified"
    usage
fi

# Download from S3 if needed
if [[ "$BACKUP_FILE" == s3://* ]]; then
    if [ -z "$S3_BUCKET" ]; then
        log_error "S3_BUCKET not configured"
        exit 1
    fi
    log_info "Downloading backup from S3..."
    LOCAL_FILE=$(basename "$BACKUP_FILE")
    if aws s3 cp "$BACKUP_FILE" "${BACKUP_DIR}/${LOCAL_FILE}"; then
        BACKUP_FILE="$LOCAL_FILE"
        log_info "Downloaded to ${BACKUP_DIR}/${LOCAL_FILE}"
    else
        log_error "Failed to download from S3"
        exit 1
    fi
fi

# Check if backup file exists
BACKUP_PATH="${BACKUP_DIR}/${BACKUP_FILE}"
if [ ! -f "$BACKUP_PATH" ]; then
    log_error "Backup file not found: $BACKUP_PATH"
    log_info "Available backups:"
    ls -lh "$BACKUP_DIR"/catbird_db_*.sql.gz 2>/dev/null || echo "No backups found"
    exit 1
fi

log_warn "WARNING: This will overwrite the current database!"
log_info "Database: $DB_NAME on $DB_HOST:$DB_PORT"
log_info "Backup file: $BACKUP_PATH"
echo ""

# Confirmation prompt
read -p "Are you sure you want to continue? (yes/no): " -r
if [ "$REPLY" != "yes" ]; then
    log_info "Restore cancelled"
    exit 0
fi

# Create a pre-restore backup
log_info "Creating pre-restore backup..."
PRE_RESTORE_BACKUP="${BACKUP_DIR}/pre_restore_$(date +%Y%m%d_%H%M%S).sql.gz"
if PGPASSWORD="${DB_PASSWORD}" pg_dump -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
    --format=plain --clean --if-exists | gzip > "$PRE_RESTORE_BACKUP"; then
    log_info "Pre-restore backup created: $PRE_RESTORE_BACKUP"
else
    log_warn "Failed to create pre-restore backup, continuing anyway..."
fi

# Terminate existing connections
log_info "Terminating existing database connections..."
PGPASSWORD="${DB_PASSWORD}" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres <<EOF
SELECT pg_terminate_backend(pg_stat_activity.pid)
FROM pg_stat_activity
WHERE pg_stat_activity.datname = '$DB_NAME'
  AND pid <> pg_backend_pid();
EOF

# Restore database
log_info "Restoring database from backup..."
if gunzip -c "$BACKUP_PATH" | PGPASSWORD="${DB_PASSWORD}" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME"; then
    log_info "Database restored successfully"
else
    log_error "Failed to restore database"
    log_info "Pre-restore backup is available at: $PRE_RESTORE_BACKUP"
    exit 1
fi

# Verify restore
log_info "Verifying database..."
TABLE_COUNT=$(PGPASSWORD="${DB_PASSWORD}" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public';")
log_info "Tables found: $TABLE_COUNT"

if [ "$TABLE_COUNT" -lt 1 ]; then
    log_error "Database appears to be empty after restore!"
    exit 1
fi

# Run migrations if needed
if [ -d "./migrations" ]; then
    log_info "Running database migrations..."
    DATABASE_URL="postgresql://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}" \
        sqlx migrate run --source ./migrations || log_warn "Migration failed or not needed"
fi

log_info "Restore completed successfully"
log_info "Pre-restore backup kept at: $PRE_RESTORE_BACKUP"

exit 0
