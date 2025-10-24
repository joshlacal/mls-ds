#!/bin/bash
# Generate test JWT tokens for API testing

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Generating Test JWT Tokens${NC}"
echo "=================================="

# Load environment variables
if [ -f .env ]; then
    source .env
fi

# Default values
JWT_SECRET=${JWT_SECRET:-"dev-secret-key-change-in-production"}
SERVICE_DID=${SERVICE_DID:-"did:web:catbird.social"}
ISSUER_DID=${ISSUER_DID:-"did:plc:test123"}

# Generate tokens with different expiration times
generate_token() {
    local exp_hours=$1
    local description=$2
    local lxm=$3
    
    local now=$(date +%s)
    local exp=$((now + exp_hours * 3600))
    local iat=$now
    local jti=$(openssl rand -hex 16)
    
    # Build claims JSON
    local claims=$(cat <<EOF
{
  "iss": "$ISSUER_DID",
  "aud": "$SERVICE_DID",
  "exp": $exp,
  "iat": $iat,
  "sub": "$ISSUER_DID",
  "jti": "$jti"
EOF
)
    
    if [ -n "$lxm" ]; then
        claims="$claims,\n  \"lxm\": \"$lxm\""
    fi
    
    claims="$claims\n}"
    
    # Create header
    local header='{"alg":"HS256","typ":"JWT"}'
    
    # Base64url encode
    local header_b64=$(echo -n "$header" | openssl base64 -e -A | tr '+/' '-_' | tr -d '=')
    local payload_b64=$(echo -e "$claims" | openssl base64 -e -A | tr '+/' '-_' | tr -d '=')
    
    # Create signature
    local signature=$(echo -n "${header_b64}.${payload_b64}" | openssl dgst -sha256 -hmac "$JWT_SECRET" -binary | openssl base64 -e -A | tr '+/' '-_' | tr -d '=')
    
    local token="${header_b64}.${payload_b64}.${signature}"
    
    echo -e "\n${GREEN}$description${NC}"
    echo "Expires: $(date -r $exp)"
    echo "Token: $token"
    echo ""
    
    # Save to file
    echo "$token" > "test_token_${exp_hours}h.txt"
}

echo ""
echo "Using configuration:"
echo "  JWT_SECRET: ${JWT_SECRET:0:10}..."
echo "  SERVICE_DID: $SERVICE_DID"
echo "  ISSUER_DID: $ISSUER_DID"
echo ""

# Generate various test tokens
generate_token 1 "Short-lived token (1 hour)" "blue.mls.createGroup"
generate_token 24 "Medium-lived token (24 hours)" "blue.mls.sendMessage"
generate_token 168 "Long-lived token (1 week)" ""
generate_token 720 "Extended token (30 days)" ""

echo -e "${GREEN}✓ Test tokens generated successfully!${NC}"
echo ""
echo "Tokens saved to:"
echo "  - test_token_1h.txt (expires in 1 hour)"
echo "  - test_token_24h.txt (expires in 24 hours)"
echo "  - test_token_168h.txt (expires in 1 week)"
echo "  - test_token_720h.txt (expires in 30 days)"
echo ""
echo "Usage example:"
echo '  curl -H "Authorization: Bearer $(cat test_token_24h.txt)" http://localhost:3000/xrpc/blue.mls.listGroups'
