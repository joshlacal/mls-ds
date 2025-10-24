#!/bin/bash
# Load testing script for MLS Server
# Requires: curl, jq, bc

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

# Configuration
BASE_URL="${BASE_URL:-http://localhost:3000}"
NUM_USERS="${NUM_USERS:-10}"
MESSAGES_PER_USER="${MESSAGES_PER_USER:-100}"
CONCURRENT="${CONCURRENT:-5}"

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

# Check dependencies
for cmd in curl jq bc; do
    if ! command -v $cmd &> /dev/null; then
        log_error "$cmd is required but not installed"
        exit 1
    fi
done

echo "=========================================="
echo "  MLS Server Load Test"
echo "=========================================="
echo ""
echo "Configuration:"
echo "  Base URL: $BASE_URL"
echo "  Users: $NUM_USERS"
echo "  Messages per user: $MESSAGES_PER_USER"
echo "  Concurrent requests: $CONCURRENT"
echo ""

# Generate test token
log_info "Generating test JWT token..."
cd "$(dirname "$0")"
TOKEN=$(python3 generate_test_jwt.py 2>/dev/null | grep "Token:" | awk '{print $2}' | tail -1)

if [ -z "$TOKEN" ]; then
    log_error "Failed to generate token"
    exit 1
fi

log_success "Token generated"

# Health check
log_info "Checking server health..."
if ! curl -sf "$BASE_URL/health" > /dev/null; then
    log_error "Server health check failed"
    exit 1
fi
log_success "Server is healthy"

# Results directory
RESULTS_DIR="load_test_results_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"

log_info "Results will be saved to: $RESULTS_DIR"

# Test 1: Create conversations
log_info "Test 1: Creating conversations..."
start_time=$(date +%s.%N)
success_count=0
error_count=0

for i in $(seq 1 $NUM_USERS); do
    response=$(curl -s -w "\n%{http_code}" \
        -X POST "$BASE_URL/xrpc/blue.catbird.mls.createConvo" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519\",\"metadata\":{\"name\":\"Load Test $i\"}}" \
        2>/dev/null) || true
    
    http_code=$(echo "$response" | tail -n1)
    
    if [ "$http_code" = "200" ]; then
        success_count=$((success_count + 1))
        echo -n "."
    else
        error_count=$((error_count + 1))
        echo -n "x"
    fi
    
    # Rate limiting
    if [ $((i % CONCURRENT)) -eq 0 ]; then
        sleep 0.1
    fi
done

end_time=$(date +%s.%N)
duration=$(echo "$end_time - $start_time" | bc)
throughput=$(echo "scale=2; $success_count / $duration" | bc)

echo ""
log_success "Created $success_count conversations (${error_count} errors) in ${duration}s"
log_info "Throughput: ${throughput} req/s"

echo "$success_count,$error_count,$duration,$throughput" > "$RESULTS_DIR/create_convo.csv"

# Test 2: Send messages
log_info "Test 2: Sending messages..."
start_time=$(date +%s.%N)
success_count=0
error_count=0
total_messages=$((NUM_USERS * MESSAGES_PER_USER))

# Generate random ciphertext
ciphertext=$(openssl rand -base64 1024 | tr -d '\n')

for i in $(seq 1 $total_messages); do
    convo_id="test-convo-$((i % NUM_USERS + 1))"
    
    response=$(curl -s -w "\n%{http_code}" \
        -X POST "$BASE_URL/xrpc/blue.catbird.mls.sendMessage" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"convoId\":\"$convo_id\",\"senderDid\":\"did:plc:test123\",\"ciphertext\":\"$ciphertext\",\"epoch\":0}" \
        2>/dev/null) || true
    
    http_code=$(echo "$response" | tail -n1)
    
    if [ "$http_code" = "200" ]; then
        success_count=$((success_count + 1))
        echo -n "."
    else
        error_count=$((error_count + 1))
        echo -n "x"
    fi
    
    # Progress indicator
    if [ $((i % 100)) -eq 0 ]; then
        echo " [$i/$total_messages]"
    fi
    
    # Rate limiting
    if [ $((i % CONCURRENT)) -eq 0 ]; then
        sleep 0.01
    fi
done

end_time=$(date +%s.%N)
duration=$(echo "$end_time - $start_time" | bc)
throughput=$(echo "scale=2; $success_count / $duration" | bc)

echo ""
log_success "Sent $success_count messages (${error_count} errors) in ${duration}s"
log_info "Throughput: ${throughput} msg/s"

echo "$success_count,$error_count,$duration,$throughput" > "$RESULTS_DIR/send_message.csv"

# Test 3: Read messages
log_info "Test 3: Reading messages..."
start_time=$(date +%s.%N)
success_count=0
error_count=0

for i in $(seq 1 $NUM_USERS); do
    convo_id="test-convo-$i"
    
    response=$(curl -s -w "\n%{http_code}" \
        "$BASE_URL/xrpc/blue.catbird.mls.getMessages?convoId=$convo_id&limit=50" \
        -H "Authorization: Bearer $TOKEN" \
        2>/dev/null) || true
    
    http_code=$(echo "$response" | tail -n1)
    
    if [ "$http_code" = "200" ]; then
        success_count=$((success_count + 1))
        echo -n "."
    else
        error_count=$((error_count + 1))
        echo -n "x"
    fi
done

end_time=$(date +%s.%N)
duration=$(echo "$end_time - $start_time" | bc)
throughput=$(echo "scale=2; $success_count / $duration" | bc)

echo ""
log_success "Read $success_count conversations (${error_count} errors) in ${duration}s"
log_info "Throughput: ${throughput} req/s"

echo "$success_count,$error_count,$duration,$throughput" > "$RESULTS_DIR/get_messages.csv"

# Test 4: Concurrent stress test
log_info "Test 4: Concurrent stress test..."
start_time=$(date +%s.%N)
success_count=0
error_count=0

STRESS_REQUESTS=1000
for i in $(seq 1 $STRESS_REQUESTS); do
    (
        response=$(curl -s -w "\n%{http_code}" \
            "$BASE_URL/health" \
            2>/dev/null) || echo "000"
        echo "$response" >> "$RESULTS_DIR/stress_temp.txt"
    ) &
    
    # Limit concurrent processes
    if [ $((i % CONCURRENT)) -eq 0 ]; then
        wait
    fi
done
wait

success_count=$(grep -c "200" "$RESULTS_DIR/stress_temp.txt" || echo "0")
error_count=$((STRESS_REQUESTS - success_count))

end_time=$(date +%s.%N)
duration=$(echo "$end_time - $start_time" | bc)
throughput=$(echo "scale=2; $STRESS_REQUESTS / $duration" | bc)

rm -f "$RESULTS_DIR/stress_temp.txt"

log_success "Completed $success_count requests (${error_count} errors) in ${duration}s"
log_info "Throughput: ${throughput} req/s"

echo "$success_count,$error_count,$duration,$throughput" > "$RESULTS_DIR/stress_test.csv"

# Get metrics
log_info "Fetching server metrics..."
curl -s "$BASE_URL/metrics" > "$RESULTS_DIR/metrics.txt" || true

# Generate summary report
cat > "$RESULTS_DIR/summary.txt" << EOF
MLS Server Load Test Summary
========================================
Date: $(date)
Base URL: $BASE_URL
Configuration:
  - Users: $NUM_USERS
  - Messages per user: $MESSAGES_PER_USER
  - Concurrent requests: $CONCURRENT

Results:
--------
Create Conversations:
$(cat "$RESULTS_DIR/create_convo.csv")

Send Messages:
$(cat "$RESULTS_DIR/send_message.csv")

Get Messages:
$(cat "$RESULTS_DIR/get_messages.csv")

Stress Test:
$(cat "$RESULTS_DIR/stress_test.csv")

Format: success_count,error_count,duration_seconds,throughput_per_second
EOF

echo ""
log_success "Load test completed!"
echo ""
cat "$RESULTS_DIR/summary.txt"
echo ""
log_info "Full results saved to: $RESULTS_DIR"
