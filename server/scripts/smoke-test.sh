#!/bin/bash
set -euo pipefail

# Smoke Test Script for MLS Server
# Tests basic functionality after deployment

BASE_URL="${1:-http://localhost:3000}"
TIMEOUT=30
FAILED_TESTS=0

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
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((FAILED_TESTS++))
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

test_endpoint() {
    local name="$1"
    local endpoint="$2"
    local expected_status="${3:-200}"
    local method="${4:-GET}"
    
    log_info "Testing $name..."
    
    response=$(curl -s -w "\n%{http_code}" -X "$method" "$BASE_URL$endpoint" --max-time "$TIMEOUT" || echo "000")
    status_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')
    
    if [ "$status_code" = "$expected_status" ]; then
        log_success "$name - Status: $status_code"
        echo "$body" | jq . 2>/dev/null || true
        return 0
    else
        log_fail "$name - Expected: $expected_status, Got: $status_code"
        return 1
    fi
}

echo "=========================================="
echo "  MLS Server Smoke Tests"
echo "  Target: $BASE_URL"
echo "=========================================="
echo ""

# Test 1: Liveness probe
test_endpoint "Liveness probe" "/health/live" "200"

# Test 2: Readiness probe
test_endpoint "Readiness probe" "/health/ready" "200"

# Test 3: Health endpoint
test_endpoint "Health endpoint" "/health" "200"

# Test 4: Health endpoint validation
log_info "Validating health response..."
health_response=$(curl -s "$BASE_URL/health")
if echo "$health_response" | jq -e '.status == "healthy"' >/dev/null 2>&1; then
    log_success "Health status is healthy"
else
    log_fail "Health status is not healthy"
fi

if echo "$health_response" | jq -e '.checks.database == "healthy"' >/dev/null 2>&1; then
    log_success "Database check passed"
else
    log_fail "Database check failed"
fi

# Test 5: Invalid endpoint returns 404
log_info "Testing invalid endpoint..."
response=$(curl -s -w "\n%{http_code}" "$BASE_URL/invalid-endpoint" || echo "000")
status_code=$(echo "$response" | tail -n1)
if [ "$status_code" = "404" ]; then
    log_success "Invalid endpoint returns 404"
else
    log_fail "Invalid endpoint - Expected: 404, Got: $status_code"
fi

# Test 6: Response time check
log_info "Testing response time..."
start_time=$(date +%s%N)
curl -s "$BASE_URL/health/live" > /dev/null
end_time=$(date +%s%N)
elapsed=$((($end_time - $start_time) / 1000000))

if [ $elapsed -lt 1000 ]; then
    log_success "Response time: ${elapsed}ms (< 1000ms)"
else
    log_warn "Response time: ${elapsed}ms (slow)"
fi

# Test 7: CORS headers (if applicable)
log_info "Checking CORS headers..."
cors_response=$(curl -s -I -H "Origin: https://catbird.blue" "$BASE_URL/health")
if echo "$cors_response" | grep -i "access-control-allow-origin" >/dev/null; then
    log_success "CORS headers present"
else
    log_warn "CORS headers not found (may be expected)"
fi

# Test 8: Security headers
log_info "Checking security headers..."
security_response=$(curl -s -I "$BASE_URL/health")

# Check for basic security headers
if echo "$security_response" | grep -i "x-frame-options" >/dev/null; then
    log_success "X-Frame-Options header present"
else
    log_warn "X-Frame-Options header missing"
fi

# Test 9: Connection pooling
log_info "Testing concurrent requests..."
for i in {1..10}; do
    curl -s "$BASE_URL/health/live" > /dev/null &
done
wait

if [ $? -eq 0 ]; then
    log_success "Handled concurrent requests"
else
    log_fail "Failed to handle concurrent requests"
fi

# Test 10: Database connectivity (via health endpoint)
log_info "Testing database connectivity..."
db_check=$(curl -s "$BASE_URL/health/ready" | jq -r '.checks.database')
if [ "$db_check" = "true" ]; then
    log_success "Database connectivity verified"
else
    log_fail "Database connectivity check failed"
fi

echo ""
echo "=========================================="
echo "  Test Summary"
echo "=========================================="

if [ $FAILED_TESTS -eq 0 ]; then
    log_success "All smoke tests passed! ✓"
    exit 0
else
    log_fail "$FAILED_TESTS test(s) failed"
    exit 1
fi
