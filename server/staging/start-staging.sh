#!/bin/bash
set -euo pipefail

# Staging Environment Startup Script

# Colors
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

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

echo "=========================================="
echo "  Starting MLS Server Staging Environment"
echo "=========================================="
echo ""

# Check if .env exists
if [ ! -f .env ]; then
    log_warn ".env file not found, creating from template..."
    cp .env.staging .env
    log_warn "Please edit .env with your configuration before continuing"
    exit 1
fi

# Start services
log_info "Starting Docker services..."
docker-compose -f docker-compose.staging.yml up -d

# Wait for services to be healthy
log_info "Waiting for services to be healthy..."
sleep 10

# Check service health
log_info "Checking service health..."
docker-compose -f docker-compose.staging.yml ps

# Wait for database
log_info "Waiting for database to be ready..."
timeout=30
while ! docker-compose -f docker-compose.staging.yml exec -T postgres pg_isready -U catbird >/dev/null 2>&1; do
    timeout=$((timeout - 1))
    if [ $timeout -le 0 ]; then
        log_warn "Database not ready after 30 seconds"
        break
    fi
    sleep 1
done

if [ $timeout -gt 0 ]; then
    log_success "Database is ready"
fi

# Display service URLs
echo ""
log_success "Staging environment started successfully!"
echo ""
echo "Service URLs:"
echo "  MLS Server:    http://localhost:3000"
echo "  Grafana:       http://localhost:3001"
echo "  Prometheus:    http://localhost:9090"
echo "  AlertManager:  http://localhost:9093"
echo ""
echo "Health Check:"
echo "  curl http://localhost:3000/health"
echo ""
echo "View Logs:"
echo "  docker-compose -f docker-compose.staging.yml logs -f mls-server"
echo ""
echo "Stop Services:"
echo "  docker-compose -f docker-compose.staging.yml down"
echo ""
