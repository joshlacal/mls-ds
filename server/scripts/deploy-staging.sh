#!/bin/bash
set -euo pipefail

# Deploy MLS Server to Staging Environment
# Usage: ./deploy-staging.sh

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

echo "=========================================="
echo "  MLS Server Staging Deployment"
echo "=========================================="
echo ""

# Change to server directory
cd "$(dirname "$0")"

# Check if .env.staging exists
if [ ! -f staging/.env ]; then
    log_error "staging/.env file not found!"
    log_info "Copy staging/.env.staging to staging/.env and configure it first"
    exit 1
fi

# Build the application
log_info "Building application..."
if cargo build --release; then
    log_success "Build completed successfully"
else
    log_error "Build failed"
    exit 1
fi

# Run tests
log_info "Running tests..."
if cargo test --release; then
    log_success "Tests passed"
else
    log_warn "Tests failed, continuing anyway..."
fi

# Stop existing staging environment
log_info "Stopping existing staging environment..."
cd staging
docker-compose -f docker-compose.staging.yml down || true

# Pull latest images
log_info "Pulling latest Docker images..."
docker-compose -f docker-compose.staging.yml pull

# Build new image
log_info "Building staging image..."
docker-compose -f docker-compose.staging.yml build --no-cache mls-server

# Start services
log_info "Starting staging environment..."
docker-compose -f docker-compose.staging.yml up -d

# Wait for services
log_info "Waiting for services to start..."
sleep 15

# Check health
log_info "Checking service health..."
max_attempts=30
attempt=0
while [ $attempt -lt $max_attempts ]; do
    if curl -f http://localhost:3000/health >/dev/null 2>&1; then
        log_success "Health check passed!"
        break
    fi
    attempt=$((attempt + 1))
    echo -n "."
    sleep 2
done

echo ""

if [ $attempt -eq $max_attempts ]; then
    log_error "Health check failed after $max_attempts attempts"
    log_info "Checking logs..."
    docker-compose -f docker-compose.staging.yml logs --tail=50 mls-server
    exit 1
fi

# Show service status
log_info "Service status:"
docker-compose -f docker-compose.staging.yml ps

echo ""
log_success "Deployment completed successfully!"
echo ""
echo "Service URLs:"
echo "  MLS Server:    http://localhost:3000"
echo "  Health:        http://localhost:3000/health"
echo "  Metrics:       http://localhost:3000/metrics"
echo "  Grafana:       http://localhost:3001"
echo "  Prometheus:    http://localhost:9090"
echo ""
echo "View logs:"
echo "  docker-compose -f docker-compose.staging.yml logs -f mls-server"
echo ""
echo "Run API tests:"
echo "  cd .. && ./test_api.sh"
echo ""
