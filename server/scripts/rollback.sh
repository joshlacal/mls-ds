#!/bin/bash
set -euo pipefail

# Rollback Script for MLS Server
# Performs blue-green deployment rollback

ENVIRONMENT="${1:-staging}"
NAMESPACE="${ENVIRONMENT}"

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

usage() {
    echo "Usage: $0 <environment>"
    echo "  environment: staging or production"
    exit 1
}

if [ "$ENVIRONMENT" != "staging" ] && [ "$ENVIRONMENT" != "production" ]; then
    log_error "Invalid environment: $ENVIRONMENT"
    usage
fi

echo "=========================================="
echo "  MLS Server Rollback"
echo "  Environment: $ENVIRONMENT"
echo "=========================================="
echo ""

log_warn "This will rollback the deployment to the previous version"
read -p "Are you sure you want to continue? (yes/no): " -r
if [ "$REPLY" != "yes" ]; then
    log_info "Rollback cancelled"
    exit 0
fi

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    log_error "kubectl not found. Please install kubectl."
    exit 1
fi

# Check current deployment status
log_info "Checking current deployment status..."
kubectl get deployments -n "$NAMESPACE" -l app=mls-server

# Get current active version
CURRENT_VERSION=$(kubectl get service mls-server -n "$NAMESPACE" -o jsonpath='{.spec.selector.version}' || echo "unknown")
log_info "Current active version: $CURRENT_VERSION"

if [ "$CURRENT_VERSION" = "blue" ]; then
    TARGET_VERSION="green"
    CURRENT_DEPLOYMENT="mls-server-blue"
    TARGET_DEPLOYMENT="mls-server-green"
elif [ "$CURRENT_VERSION" = "green" ]; then
    TARGET_VERSION="blue"
    CURRENT_DEPLOYMENT="mls-server-green"
    TARGET_DEPLOYMENT="mls-server-blue"
else
    log_error "Cannot determine current version"
    exit 1
fi

log_info "Rolling back to: $TARGET_VERSION"

# Check if target deployment exists and is ready
log_info "Verifying target deployment..."
TARGET_READY=$(kubectl get deployment "$TARGET_DEPLOYMENT" -n "$NAMESPACE" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
TARGET_DESIRED=$(kubectl get deployment "$TARGET_DEPLOYMENT" -n "$NAMESPACE" -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "0")

if [ "$TARGET_READY" -lt "$TARGET_DESIRED" ]; then
    log_warn "Target deployment is not fully ready (${TARGET_READY}/${TARGET_DESIRED})"
    log_info "Scaling up target deployment..."
    kubectl scale deployment "$TARGET_DEPLOYMENT" -n "$NAMESPACE" --replicas=3
    kubectl rollout status deployment "$TARGET_DEPLOYMENT" -n "$NAMESPACE" --timeout=5m
fi

# Switch service to target version
log_info "Switching traffic to $TARGET_VERSION..."
kubectl patch service mls-server -n "$NAMESPACE" \
    -p "{\"spec\":{\"selector\":{\"version\":\"$TARGET_VERSION\"}}}"

log_success "Traffic switched to $TARGET_VERSION"

# Wait and monitor
log_info "Monitoring for 30 seconds..."
sleep 30

# Run health checks
log_info "Running health checks..."
SERVICE_IP=$(kubectl get service mls-server -n "$NAMESPACE" -o jsonpath='{.status.loadBalancer.ingress[0].ip}' || echo "localhost")
if curl -f "http://${SERVICE_IP}/health" -m 10; then
    log_success "Health check passed"
else
    log_error "Health check failed"
    exit 1
fi

# Scale down current (now old) deployment
log_info "Scaling down $CURRENT_VERSION deployment..."
kubectl scale deployment "$CURRENT_DEPLOYMENT" -n "$NAMESPACE" --replicas=1

log_success "Rollback completed successfully!"
log_info "Current active version: $TARGET_VERSION"
log_info "Previous version ($CURRENT_VERSION) scaled to 1 replica"

echo ""
echo "To verify the rollback:"
echo "  kubectl get pods -n $NAMESPACE -l app=mls-server"
echo "  kubectl get service mls-server -n $NAMESPACE"
echo ""
echo "To completely remove the old version:"
echo "  kubectl scale deployment $CURRENT_DEPLOYMENT -n $NAMESPACE --replicas=0"

exit 0
