#!/bin/bash
set -euo pipefail

# Database Backup Script for MLS Server
# This script creates timestamped backups of the PostgreSQL database

# Configuration
BACKUP_DIR="${BACKUP_DIR:-/backups}"
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-catbird}"
DB_USER="${DB_USER:-catbird}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-7}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="catbird_db_${TIMESTAMP}.sql.gz"
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

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

log_info "Starting database backup..."
log_info "Database: $DB_NAME"
log_info "Backup file: $BACKUP_FILE"

# Perform backup
log_info "Creating backup..."
if PGPASSWORD="${DB_PASSWORD}" pg_dump -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
    --format=plain --clean --if-exists | gzip > "${BACKUP_DIR}/${BACKUP_FILE}"; then
    log_info "Database backup created successfully"
else
    log_error "Failed to create database backup"
    exit 1
fi

# Verify backup
BACKUP_SIZE=$(stat -f%z "${BACKUP_DIR}/${BACKUP_FILE}" 2>/dev/null || stat -c%s "${BACKUP_DIR}/${BACKUP_FILE}")
if [ "$BACKUP_SIZE" -lt 1000 ]; then
    log_error "Backup file is suspiciously small ($BACKUP_SIZE bytes)"
    exit 1
fi

log_info "Backup size: $(numfmt --to=iec-i --suffix=B "$BACKUP_SIZE" 2>/dev/null || echo "$BACKUP_SIZE bytes")"

# Upload to S3 if configured
if [ -n "$S3_BUCKET" ]; then
    log_info "Uploading backup to S3..."
    if aws s3 cp "${BACKUP_DIR}/${BACKUP_FILE}" "s3://${S3_BUCKET}/backups/database/${BACKUP_FILE}"; then
        log_info "Backup uploaded to S3 successfully"
    else
        log_warn "Failed to upload backup to S3"
    fi
fi

# Clean up old backups
log_info "Cleaning up backups older than $RETENTION_DAYS days..."
find "$BACKUP_DIR" -name "catbird_db_*.sql.gz" -type f -mtime +$RETENTION_DAYS -delete
OLD_BACKUP_COUNT=$(find "$BACKUP_DIR" -name "catbird_db_*.sql.gz" -type f | wc -l)
log_info "Remaining backups: $OLD_BACKUP_COUNT"

# Clean up old S3 backups if configured
if [ -n "$S3_BUCKET" ]; then
    log_info "Cleaning up old S3 backups..."
    DELETE_DATE=$(date -u -d "$RETENTION_DAYS days ago" +%Y%m%d 2>/dev/null || date -u -v-${RETENTION_DAYS}d +%Y%m%d)
    aws s3 ls "s3://${S3_BUCKET}/backups/database/" | while read -r line; do
        BACKUP_NAME=$(echo "$line" | awk '{print $4}')
        BACKUP_DATE=$(echo "$BACKUP_NAME" | grep -oP '\d{8}' | head -1 || echo "")
        if [ -n "$BACKUP_DATE" ] && [ "$BACKUP_DATE" -lt "$DELETE_DATE" ]; then
            log_info "Deleting old S3 backup: $BACKUP_NAME"
            aws s3 rm "s3://${S3_BUCKET}/backups/database/${BACKUP_NAME}"
        fi
    done
fi

log_info "Backup completed successfully"
log_info "Backup location: ${BACKUP_DIR}/${BACKUP_FILE}"

# Create backup metadata
cat > "${BACKUP_DIR}/${BACKUP_FILE}.meta" <<EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "database": "$DB_NAME",
  "host": "$DB_HOST",
  "size_bytes": $BACKUP_SIZE,
  "backup_file": "$BACKUP_FILE"
}
EOF

exit 0
