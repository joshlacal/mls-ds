#!/bin/bash
# Rate Limiting Test Script
# Tests per-IP and per-DID endpoint-specific rate limits

set -e

SERVER_URL="${SERVER_URL:-http://localhost:8080}"
TEST_DID="${TEST_DID:-did:plc:test123}"
TEST_JWT="${TEST_JWT}"

echo "=========================================="
echo "Rate Limiting Test Suite"
echo "=========================================="
echo "Server: $SERVER_URL"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test 1: Per-IP Rate Limiting (Unauthenticated)
echo -e "${YELLOW}Test 1: Per-IP Rate Limiting (60 req/min for unauthenticated)${NC}"
echo "Sending 70 requests to health endpoint without auth..."

success_count=0
rate_limited_count=0

for i in {1..70}; do
    response=$(curl -s -w "\n%{http_code}" "$SERVER_URL/health" 2>/dev/null)
    status_code=$(echo "$response" | tail -1)

    if [ "$status_code" == "200" ]; then
        ((success_count++))
    elif [ "$status_code" == "429" ]; then
        ((rate_limited_count++))
        if [ $rate_limited_count -eq 1 ]; then
            echo -e "${GREEN}✓ First rate limit hit at request $i${NC}"
            retry_after=$(curl -s -I "$SERVER_URL/health" 2>/dev/null | grep -i "retry-after" | cut -d' ' -f2 | tr -d '\r')
            if [ -n "$retry_after" ]; then
                echo -e "${GREEN}✓ Retry-After header present: $retry_after seconds${NC}"
            fi
        fi
    fi

    # Brief delay to avoid overwhelming the server
    sleep 0.01
done

echo "Success: $success_count, Rate Limited: $rate_limited_count"

if [ $rate_limited_count -gt 0 ]; then
    echo -e "${GREEN}✓ Per-IP rate limiting is working${NC}"
else
    echo -e "${RED}✗ Per-IP rate limiting NOT working (no 429s received)${NC}"
fi

echo ""

# Test 2: Per-DID Endpoint-Specific Rate Limits (Authenticated)
if [ -z "$TEST_JWT" ]; then
    echo -e "${YELLOW}Skipping per-DID tests: TEST_JWT not provided${NC}"
    echo "To test DID-based rate limits, set TEST_JWT environment variable"
    echo "Example: export TEST_JWT='your-jwt-token-here'"
else
    echo -e "${YELLOW}Test 2: Per-DID Rate Limiting for sendMessage (100 req/min)${NC}"
    echo "Sending 110 requests to sendMessage endpoint..."

    success_count=0
    rate_limited_count=0

    for i in {1..110}; do
        response=$(curl -s -w "\n%{http_code}" \
            -H "Authorization: Bearer $TEST_JWT" \
            -H "Content-Type: application/json" \
            -X POST \
            -d '{"convoId":"test123","message":"test"}' \
            "$SERVER_URL/xrpc/blue.catbird.mls.sendMessage" 2>/dev/null)
        status_code=$(echo "$response" | tail -1)

        if [ "$status_code" == "200" ] || [ "$status_code" == "400" ]; then
            ((success_count++))
        elif [ "$status_code" == "429" ]; then
            ((rate_limited_count++))
            if [ $rate_limited_count -eq 1 ]; then
                echo -e "${GREEN}✓ sendMessage rate limit hit at request $i${NC}"
            fi
        fi

        sleep 0.01
    done

    echo "Success/Valid: $success_count, Rate Limited: $rate_limited_count"

    if [ $rate_limited_count -gt 0 ] && [ $success_count -le 105 ]; then
        echo -e "${GREEN}✓ sendMessage rate limiting is working (100/min)${NC}"
    else
        echo -e "${RED}✗ sendMessage rate limiting may not be working correctly${NC}"
    fi

    echo ""

    # Test 3: createConvo endpoint (5 req/min)
    echo -e "${YELLOW}Test 3: Per-DID Rate Limiting for createConvo (5 req/min)${NC}"
    echo "Sending 10 requests to createConvo endpoint..."

    success_count=0
    rate_limited_count=0

    for i in {1..10}; do
        response=$(curl -s -w "\n%{http_code}" \
            -H "Authorization: Bearer $TEST_JWT" \
            -H "Content-Type: application/json" \
            -X POST \
            -d '{"name":"test","didList":["did:plc:test1"]}' \
            "$SERVER_URL/xrpc/blue.catbird.mls.createConvo" 2>/dev/null)
        status_code=$(echo "$response" | tail -1)

        if [ "$status_code" == "200" ] || [ "$status_code" == "400" ]; then
            ((success_count++))
        elif [ "$status_code" == "429" ]; then
            ((rate_limited_count++))
            if [ $rate_limited_count -eq 1 ]; then
                echo -e "${GREEN}✓ createConvo rate limit hit at request $i${NC}"
            fi
        fi

        sleep 0.01
    done

    echo "Success/Valid: $success_count, Rate Limited: $rate_limited_count"

    if [ $rate_limited_count -gt 0 ] && [ $success_count -le 7 ]; then
        echo -e "${GREEN}✓ createConvo rate limiting is working (5/min)${NC}"
    else
        echo -e "${RED}✗ createConvo rate limiting may not be working correctly${NC}"
    fi

    echo ""

    # Test 4: publishKeyPackage endpoint (20 req/min)
    echo -e "${YELLOW}Test 4: Per-DID Rate Limiting for publishKeyPackage (20 req/min)${NC}"
    echo "Sending 25 requests to publishKeyPackage endpoint..."

    success_count=0
    rate_limited_count=0

    for i in {1..25}; do
        response=$(curl -s -w "\n%{http_code}" \
            -H "Authorization: Bearer $TEST_JWT" \
            -H "Content-Type: application/json" \
            -X POST \
            -d '{"keyPackages":["test"]}' \
            "$SERVER_URL/xrpc/blue.catbird.mls.publishKeyPackage" 2>/dev/null)
        status_code=$(echo "$response" | tail -1)

        if [ "$status_code" == "200" ] || [ "$status_code" == "400" ]; then
            ((success_count++))
        elif [ "$status_code" == "429" ]; then
            ((rate_limited_count++))
            if [ $rate_limited_count -eq 1 ]; then
                echo -e "${GREEN}✓ publishKeyPackage rate limit hit at request $i${NC}"
            fi
        fi

        sleep 0.01
    done

    echo "Success/Valid: $success_count, Rate Limited: $rate_limited_count"

    if [ $rate_limited_count -gt 0 ] && [ $success_count -le 22 ]; then
        echo -e "${GREEN}✓ publishKeyPackage rate limiting is working (20/min)${NC}"
    else
        echo -e "${RED}✗ publishKeyPackage rate limiting may not be working correctly${NC}"
    fi
fi

echo ""
echo "=========================================="
echo "Rate Limiting Test Suite Complete"
echo "=========================================="
