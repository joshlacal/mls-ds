#!/bin/bash
set -e

# Deploy script for Catbird MLS Server (Host-based)
# Usage: ./deploy.sh [environment]

ENVIRONMENT="${1:-production}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "Deploying Catbird MLS Server to $ENVIRONMENT..."

# Load environment-specific configuration
if [ -f "$PROJECT_DIR/.env.$ENVIRONMENT" ]; then
    echo "Loading environment configuration..."
    source "$PROJECT_DIR/.env.$ENVIRONMENT"
elif [ -f "$PROJECT_DIR/.env" ]; then
    echo "Loading .env configuration..."
    source "$PROJECT_DIR/.env"
else
    echo "Warning: No .env file found"
fi

# Build binary
echo "Building release binary..."
cd "$PROJECT_DIR"
cargo build --release

# Run migrations
echo "Running database migrations..."
if [ -n "$DATABASE_URL" ]; then
    ./scripts/run-migrations.sh "$DATABASE_URL"
else
    echo "Warning: DATABASE_URL not set, skipping migrations"
fi

# Restart service
echo "Restarting server..."
sudo systemctl restart catbird-mls-server

# Wait for service to be healthy
echo "Waiting for server to be healthy..."
sleep 5

# Health check
MAX_RETRIES=30
RETRY_COUNT=0
while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if curl -sf http://localhost:3000/health/ready > /dev/null 2>&1; then
        echo "✓ Server is healthy and ready!"
        break
    fi
    echo "Waiting for server to be ready... ($((RETRY_COUNT + 1))/$MAX_RETRIES)"
    sleep 2
    RETRY_COUNT=$((RETRY_COUNT + 1))
done

if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
    echo "Error: Server failed to become ready"
    sudo journalctl -u catbird-mls-server -n 50 --no-pager
    exit 1
fi

echo "Deployment completed successfully!"
echo "Server is running at http://localhost:3000"
