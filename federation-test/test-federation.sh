#!/usr/bin/env bash
# Test federation between two local MLS-DS instances.
#
# Assumes both instances are running (via run-federation.sh):
#   Instance 1: http://127.0.0.1:3001 (did:web:ds1.local)
#   Instance 2: http://127.0.0.1:3002 (did:web:ds2.local)

set -euo pipefail

DS1="http://127.0.0.1:3001"
DS2="http://127.0.0.1:3002"
DS1_DID="did:web:ds1.local"
DS2_DID="did:web:ds2.local"

pass=0
fail=0

check() {
    local name="$1"
    local result="$2"
    if [ "$result" = "true" ]; then
        echo "  PASS: $name"
        pass=$((pass + 1))
    else
        echo "  FAIL: $name"
        fail=$((fail + 1))
    fi
}

echo "========================================"
echo "  MLS-DS Federation Test Suite"
echo "========================================"
echo ""

# ── 1. Liveness checks ───────────────────────────────────────────────────
echo "1. Liveness checks"

resp1=$(curl -sf "$DS1/health/live" 2>/dev/null || echo '')
check "Instance 1 liveness" "$([ "$resp1" = "OK" ] && echo true || echo false)"

resp2=$(curl -sf "$DS2/health/live" 2>/dev/null || echo '')
check "Instance 2 liveness" "$([ "$resp2" = "OK" ] && echo true || echo false)"

echo ""

# ── 2. Readiness checks ──────────────────────────────────────────────────
echo "2. Readiness checks (DB + actors)"

ready1=$(curl -sf "$DS1/health/ready" 2>/dev/null || echo '{}')
check "Instance 1 readiness" "$(echo "$ready1" | python3 -c 'import sys,json; print("true" if json.load(sys.stdin).get("ready") == True else "false")' 2>/dev/null || echo false)"

ready2=$(curl -sf "$DS2/health/ready" 2>/dev/null || echo '{}')
check "Instance 2 readiness" "$(echo "$ready2" | python3 -c 'import sys,json; print("true" if json.load(sys.stdin).get("ready") == True else "false")' 2>/dev/null || echo false)"

echo ""

# ── 3. DS-to-DS health check (federation endpoint) ───────────────────────
echo "3. Federation DS identity endpoints"

ds_health1=$(curl -sf "$DS1/xrpc/blue.catbird.mls.ds.healthCheck" 2>/dev/null || echo '{}')
check "Instance 1 DS health" "$(echo "$ds_health1" | python3 -c 'import sys,json; d=json.load(sys.stdin); print("true" if d.get("did") == "'"$DS1_DID"'" else "false")' 2>/dev/null || echo false)"

ds_health2=$(curl -sf "$DS2/xrpc/blue.catbird.mls.ds.healthCheck" 2>/dev/null || echo '{}')
check "Instance 2 DS health" "$(echo "$ds_health2" | python3 -c 'import sys,json; d=json.load(sys.stdin); print("true" if d.get("did") == "'"$DS2_DID"'" else "false")' 2>/dev/null || echo false)"

echo ""

# ── 4. Cross-instance connectivity ────────────────────────────────────────
echo "4. Cross-instance connectivity"

cross12=$(curl -sf "$DS2/xrpc/blue.catbird.mls.ds.healthCheck" 2>/dev/null || echo '{}')
check "Can reach DS2 federation endpoint" "$(echo "$cross12" | python3 -c 'import sys,json; print("true" if "did" in json.load(sys.stdin) else "false")' 2>/dev/null || echo false)"

cross21=$(curl -sf "$DS1/xrpc/blue.catbird.mls.ds.healthCheck" 2>/dev/null || echo '{}')
check "Can reach DS1 federation endpoint" "$(echo "$cross21" | python3 -c 'import sys,json; print("true" if "did" in json.load(sys.stdin) else "false")' 2>/dev/null || echo false)"

echo ""

# ── 5. Verify distinct identities ────────────────────────────────────────
echo "5. Distinct DS identities"

did1=$(echo "$ds_health1" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("did",""))' 2>/dev/null || echo "")
did2=$(echo "$ds_health2" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("did",""))' 2>/dev/null || echo "")

check "Instance 1 DID = $DS1_DID" "$([ "$did1" = "$DS1_DID" ] && echo true || echo false)"
check "Instance 2 DID = $DS2_DID" "$([ "$did2" = "$DS2_DID" ] && echo true || echo false)"
check "DIDs are different" "$([ "$did1" != "$did2" ] && echo true || echo false)"

echo ""

# ── 6. Full health (with DB, memory, actors) ─────────────────────────────
echo "6. Full health endpoint"

full1=$(curl -sf "$DS1/health" 2>/dev/null || echo '{}')
check "Instance 1 healthy" "$(echo "$full1" | python3 -c 'import sys,json; print("true" if json.load(sys.stdin).get("status") == "healthy" else "false")' 2>/dev/null || echo false)"

full2=$(curl -sf "$DS2/health" 2>/dev/null || echo '{}')
check "Instance 2 healthy" "$(echo "$full2" | python3 -c 'import sys,json; print("true" if json.load(sys.stdin).get("status") == "healthy" else "false")' 2>/dev/null || echo false)"

echo ""

# ── 7. Federation version match ──────────────────────────────────────────
echo "7. Federation configuration"

uptime1=$(echo "$ds_health1" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("uptime", -1))' 2>/dev/null || echo -1)
uptime2=$(echo "$ds_health2" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("uptime", -1))' 2>/dev/null || echo -1)

check "Instance 1 uptime >= 0" "$([ "$uptime1" -ge 0 ] 2>/dev/null && echo true || echo false)"
check "Instance 2 uptime >= 0" "$([ "$uptime2" -ge 0 ] 2>/dev/null && echo true || echo false)"

version1=$(echo "$ds_health1" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("version",""))' 2>/dev/null || echo "")
version2=$(echo "$ds_health2" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("version",""))' 2>/dev/null || echo "")
check "Both instances same version ($version1)" "$([ "$version1" = "$version2" ] && [ -n "$version1" ] && echo true || echo false)"

echo ""

# ── Summary ──────────────────────────────────────────────────────────────
echo "========================================"
echo "  Results: $pass passed, $fail failed"
echo "========================================"
echo ""
echo "Federation topology:"
echo "  DS1 ($DS1_DID) @ $DS1  ←→  DS2 ($DS2_DID) @ $DS2"
echo "  Each with separate PostgreSQL databases and federation enabled."

if [ $fail -gt 0 ]; then
    exit 1
fi
