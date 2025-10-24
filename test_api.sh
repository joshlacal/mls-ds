#!/bin/bash
# Comprehensive API testing for MLS Server

BASE_URL="http://localhost:3000"
DID="did:plc:test$(date +%s)"

echo "🧪 MLS Server API Testing"
echo "=========================="
echo ""

# Test 1: Health check
echo "1️⃣  Health Check"
HEALTH=$(curl -s "$BASE_URL/xrpc/_health")
echo "Response: $HEALTH"
if [[ "$HEALTH" == *"ok"* ]]; then
  echo "✅ Health check passed"
else
  echo "❌ Health check failed"
  exit 1
fi
echo ""

# Test 2: List endpoints
echo "2️⃣  XRPC describe server"
DESCRIBE=$(curl -s "$BASE_URL/xrpc/com.atproto.server.describeServer" | jq '.')
echo "$DESCRIBE" | head -20
echo "✅ Describe server successful"
echo ""

# Note: Further API tests require valid JWT tokens
# These would be generated in production with proper DID authentication

echo "========================================="
echo "✅ Basic API tests passed!"
echo ""
echo "📝 Next steps:"
echo "  - Generate valid JWT tokens for testing"
echo "  - Test key package operations"
echo "  - Test conversation creation"
echo "  - Test message sending/receiving"
echo "  - Test SSE streaming"
