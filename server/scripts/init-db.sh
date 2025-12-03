#!/bin/bash
set -e

# Database initialization script for greenfield deployment
# Usage: ./init-db.sh
#
# This script initializes a fresh database with the greenfield schema.
# It uses the schema_greenfield.sql file in the parent directory.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Database connection details
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-catbird}"
DB_USER="${DB_USER:-catbird}"

echo "Initializing Catbird database with greenfield schema..."
echo "Database: $DB_NAME@$DB_HOST:$DB_PORT"

# Check if schema file exists
SCHEMA_FILE="$PROJECT_DIR/schema_greenfield.sql"
if [ ! -f "$SCHEMA_FILE" ]; then
    echo "Error: Schema file not found: $SCHEMA_FILE"
    exit 1
fi

# Apply the schema
echo "Applying greenfield schema..."
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -f "$SCHEMA_FILE"

echo "✅ Greenfield schema applied successfully!"
