#!/bin/bash
set -e

# Database backup script
# Usage: ./backup-db.sh [BACKUP_DIR]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_DIR="${1:-/var/backups/catbird}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="catbird_backup_${TIMESTAMP}.sql.gz"

# Database connection details from environment or defaults
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-catbird}"
DB_USER="${DB_USER:-catbird}"
PGPASSWORD="${DB_PASSWORD:-changeme}"

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

echo "Starting database backup..."
echo "Database: $DB_NAME@$DB_HOST:$DB_PORT"
echo "Backup file: $BACKUP_DIR/$BACKUP_FILE"

# Perform backup
export PGPASSWORD
pg_dump -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
    --format=plain \
    --no-owner \
    --no-acl \
    | gzip > "$BACKUP_DIR/$BACKUP_FILE"

unset PGPASSWORD

# Check if backup was successful
if [ -f "$BACKUP_DIR/$BACKUP_FILE" ]; then
    BACKUP_SIZE=$(du -h "$BACKUP_DIR/$BACKUP_FILE" | cut -f1)
    echo "Backup completed successfully!"
    echo "File: $BACKUP_DIR/$BACKUP_FILE"
    echo "Size: $BACKUP_SIZE"
    
    # Keep only last 30 days of backups
    find "$BACKUP_DIR" -name "catbird_backup_*.sql.gz" -mtime +30 -delete
    echo "Cleaned up backups older than 30 days"
else
    echo "Error: Backup failed!"
    exit 1
fi
