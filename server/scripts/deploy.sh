#!/bin/bash
set -e

# Deploy script for Catbird MLS Server
# Usage: ./deploy.sh [environment]

ENVIRONMENT="${1:-production}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "Deploying Catbird MLS Server to $ENVIRONMENT..."

# Load environment-specific configuration
if [ -f "$PROJECT_DIR/.env.$ENVIRONMENT" ]; then
    echo "Loading environment configuration..."
    source "$PROJECT_DIR/.env.$ENVIRONMENT"
else
    echo "Warning: No .env.$ENVIRONMENT file found"
fi

# Build Docker image
echo "Building Docker image..."
cd "$PROJECT_DIR"
docker build -t catbird-mls-server:latest -t catbird-mls-server:$ENVIRONMENT .

# Run migrations
echo "Running database migrations..."
if [ -n "$DATABASE_URL" ]; then
    ./scripts/run-migrations.sh "$DATABASE_URL"
else
    echo "Warning: DATABASE_URL not set, skipping migrations"
fi

# Deploy with docker-compose
echo "Deploying with docker-compose..."
docker-compose -f docker-compose.yml pull postgres redis
docker-compose -f docker-compose.yml up -d --force-recreate

# Wait for services to be healthy
echo "Waiting for services to be healthy..."
sleep 10

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
    docker-compose logs mls-server
    exit 1
fi

echo "Deployment completed successfully!"
echo "Server is running at http://localhost:3000"
