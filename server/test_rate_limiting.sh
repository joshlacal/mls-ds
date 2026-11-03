#!/usr/bin/env bash
# Live check of the limits in RATE_LIMITING.md against a running catbird-server.
#
#   SERVER_URL    server base URL (default http://localhost:8080)
#   IP_BURST      the server's IP_RATE_BURST (default 300, the server default)
#   TEST_JWT_CMD  optional command, split on spaces, that prints a fresh
#                 service-auth JWT for the blue.catbird.chat NSID passed as its
#                 last argument. Every chat call needs its own jti and an exact
#                 lxm, so one static token cannot spend a quota. The server must
#                 have CHAT_CUTOVER_ENABLED set.
#
# The per-account checks run first: the per-IP check empties this client's IP
# bucket. Exits non-zero when a check sees no 429.

set -euo pipefail

SERVER_URL="${SERVER_URL:-http://localhost:8080}"
IP_BURST="${IP_BURST:-300}"
TEST_JWT_CMD="${TEST_JWT_CMD:-}"
failures=0

health_status() {
    curl -s -o /dev/null -w '%{http_code}' "$SERVER_URL/health"
}

chat_status() {
    local token
    # shellcheck disable=SC2086 # TEST_JWT_CMD is a command line
    token="$($TEST_JWT_CMD "$1")"
    curl -s -o /dev/null -w '%{http_code}' -X POST \
        -H "Authorization: Bearer $token" -H 'Content-Type: application/json' -d '{}' \
        "$SERVER_URL/xrpc/blue.catbird.chat.$1"
}

# check LABEL QUOTA MAX COMMAND...: run COMMAND (prints an HTTP status) up to
# MAX times and pass at the first 429. MAX leaves room for the bucket refilling
# while requests are sent.
check() {
    local label="$1" quota="$2" max="$3" i
    shift 3
    for ((i = 1; i <= max; i++)); do
        if [ "$("$@")" = 429 ]; then
            echo "✓ $label: first 429 at request $i (limit $quota)"
            return 0
        fi
    done
    echo "✗ $label: no 429 in $max requests (limit $quota)"
    failures=$((failures + 1))
    return 1
}

echo "Rate limiting checks against $SERVER_URL"

if [ -n "$TEST_JWT_CMD" ]; then
    check "sendMessage per account" 100 220 chat_status sendMessage || true
    check "createConversation per account" 5 30 chat_status createConversation || true
    check "replenishKeyPackages per account" 50 120 chat_status replenishKeyPackages || true
else
    echo "Skipping per-account checks: set TEST_JWT_CMD"
fi

if check "per IP (/health)" "$IP_BURST" $((IP_BURST * 2 + 20)) health_status; then
    if curl -s -D - -o /dev/null "$SERVER_URL/health" | grep -qi '^retry-after:'; then
        echo "✓ 429 carries Retry-After"
    else
        echo "✗ 429 without Retry-After"
        failures=$((failures + 1))
    fi
fi

[ "$failures" -eq 0 ]
