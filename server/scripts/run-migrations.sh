#!/bin/bash
set -e

# Run database migrations
# Usage: ./run-migrations.sh [DATABASE_URL]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Get database URL from argument or environment
DATABASE_URL="${1:-${DATABASE_URL}}"

if [ -z "$DATABASE_URL" ]; then
    echo "Error: DATABASE_URL not provided"
    echo "Usage: $0 [DATABASE_URL]"
    echo "Or set DATABASE_URL environment variable"
    exit 1
fi

echo "Running database migrations..."
echo "Database: ${DATABASE_URL%%\?*}"  # Hide password in output

# Check if sqlx-cli is installed
if ! command -v sqlx &> /dev/null; then
    echo "sqlx-cli not found. Installing..."
    cargo install sqlx-cli --no-default-features --features postgres
fi

# Run migrations
cd "$PROJECT_DIR"
sqlx migrate run --database-url "$DATABASE_URL"

echo "Migrations completed successfully!"
