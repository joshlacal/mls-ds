#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/e2e-tests/docker-compose.federation.yml"
FIXTURES_DIR="$REPO_ROOT/e2e-tests/fixtures"

STATE_FILE="/tmp/mls-fed-harness-project-${UID:-$(id -u)}"

if [[ -n "${COMPOSE_PROJECT_NAME:-}" ]]; then
  PROJECT_NAME="$COMPOSE_PROJECT_NAME"
  EXPLICIT_PROJECT=1
elif [[ -n "${FED_HARNESS_PROJECT_NAME:-}" ]]; then
  PROJECT_NAME="$FED_HARNESS_PROJECT_NAME"
  EXPLICIT_PROJECT=1
elif [[ -f "$STATE_FILE" ]] && [[ "${1:-}" != "up" ]]; then
  PROJECT_NAME="$(cat "$STATE_FILE")"
  EXPLICIT_PROJECT=0
else
  PROJECT_NAME="mls-fed-$(date +%s)-$RANDOM"
  EXPLICIT_PROJECT=0
fi

export APP_ENV="${APP_ENV:-test}"
export FEDERATION_MODE="${FEDERATION_MODE:-allowlist}"
export FEDERATION_ENABLED="${FEDERATION_ENABLED:-true}"
export FEDERATION_CAPABILITIES="${FEDERATION_CAPABILITIES:-baseline,reconciliation-v1}"

# Default to 0 for ephemeral host port allocation; explicit overrides allowed for interactive reuse
export DS1_PORT="${DS1_PORT:-0}"
export DS2_PORT="${DS2_PORT:-0}"
export DS1_DB_PORT="${DS1_DB_PORT:-0}"
export DS2_DB_PORT="${DS2_DB_PORT:-0}"
export DS1_REDIS_PORT="${DS1_REDIS_PORT:-0}"
export DS2_REDIS_PORT="${DS2_REDIS_PORT:-0}"

export DS1_SERVICE_DID="${DS1_SERVICE_DID:-did:web:ds1.local}"
export DS2_SERVICE_DID="${DS2_SERVICE_DID:-did:web:ds2.local}"
export DS1_SELF_ENDPOINT="${DS1_SELF_ENDPOINT:-http://ds1:3001}"
export DS2_SELF_ENDPOINT="${DS2_SELF_ENDPOINT:-http://ds2:3001}"

export FEDERATION_ALLOW_INSECURE_HTTP="${FEDERATION_ALLOW_INSECURE_HTTP:-true}"
export ENFORCE_LXM="${ENFORCE_LXM:-true}"
export ENFORCE_JTI="${ENFORCE_JTI:-true}"
export RUST_LOG="${RUST_LOG:-info}"

compose() {
  (cd "$REPO_ROOT" && docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" "$@")
}

require_tools() {
  command -v docker >/dev/null 2>&1 || {
    echo "docker is required for federation harness commands"
    exit 1
  }
  command -v curl >/dev/null 2>&1 || {
    echo "curl is required for federation harness smoke checks"
    exit 1
  }
  command -v openssl >/dev/null 2>&1 || {
    echo "openssl is required for federation harness token generation"
    exit 1
  }
  command -v python3 >/dev/null 2>&1 || {
    echo "python3 is required for federation harness token generation"
    exit 1
  }
}

get_service_host_port() {
  local service="$1"
  local container_port="${2:-3001}"
  local port_output
  port_output="$(compose port "$service" "$container_port" 2>/dev/null || true)"
  if [[ -z "$port_output" ]]; then
    echo ""
    return 1
  fi
  echo "$port_output" | sed -E 's/.*:([0-9]+)$/\1/'
}

generate_service_jwt() {
  local key_path="$1"
  local iss="$2"
  local aud="$3"
  local lxm="$4"
  python3 -c "
import sys, json, time, base64, subprocess, os

def b64url(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def der_to_raw(der_bytes):
    idx = 2
    if der_bytes[1] & 0x80:
        idx += (der_bytes[1] & 0x7f)
    assert der_bytes[idx] == 0x02
    rlen = der_bytes[idx+1]
    r = der_bytes[idx+2 : idx+2+rlen]
    idx = idx + 2 + rlen
    assert der_bytes[idx] == 0x02
    slen = der_bytes[idx+1]
    s = der_bytes[idx+2 : idx+2+slen]
    r = r.lstrip(b'\x00').rjust(32, b'\x00')
    s = s.lstrip(b'\x00').rjust(32, b'\x00')
    return r + s

now = int(time.time())
header = {'alg': 'ES256', 'typ': 'JWT'}
payload = {
    'iss': '$iss',
    'aud': '$aud',
    'exp': now + 60,
    'iat': now,
    'jti': f'smoke-jti-{now}-{os.getpid()}',
    'lxm': '$lxm'
}
h_b64 = b64url(json.dumps(header))
p_b64 = b64url(json.dumps(payload))
signing_input = f'{h_b64}.{p_b64}'.encode()

proc = subprocess.Popen(
    ['openssl', 'dgst', '-sha256', '-sign', '$key_path'],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
)
der_sig, err = proc.communicate(input=signing_input)
if proc.returncode != 0:
    sys.exit(1)
raw_sig = der_to_raw(der_sig)
sig_b64 = b64url(raw_sig)
print(f'{h_b64}.{p_b64}.{sig_b64}')
"
}

wait_for_url() {
  local label="$1"
  local url="$2"
  local attempts="${3:-60}"

  for ((i = 1; i <= attempts; i++)); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      echo "✓ $label"
      return 0
    fi
    sleep 1
  done

  echo "✗ $label failed: $url"
  return 1
}

check_federation_endpoint() {
  local node="$1"
  local base_url="$2"
  local expected_did="$3"
  local endpoint="$base_url/xrpc/blue.catbird.mlsDS.healthCheck"

  local payload
  payload="$(curl -fsS "$endpoint")"
  local compact
  compact="$(printf '%s' "$payload" | tr -d '[:space:]')"

  if [[ "$compact" != *"\"did\":\"$expected_did\""* ]]; then
    echo "✗ Federation health check DID mismatch for $node"
    echo "  expected did: $expected_did"
    echo "  response: $payload"
    return 1
  fi

  if [[ "$compact" != *"baseline"* ]] || [[ "$compact" != *"reconciliation-v1"* ]]; then
    echo "✗ Federation health check capabilities mismatch for $node"
    echo "  expected capabilities: baseline, reconciliation-v1"
    echo "  response: $payload"
    return 1
  fi

  echo "✓ Federation endpoint responded for $node ($expected_did, capabilities verified)"
}

check_signer_and_service_auth() {
  local ds1_url="$1"
  local ds2_url="$2"
  local ds1_key="$FIXTURES_DIR/ds1-key.pem"
  local ds2_key="$FIXTURES_DIR/ds2-key.pem"

  if [[ ! -f "$ds1_key" ]] || [[ ! -f "$ds2_key" ]]; then
    echo "✗ Deterministic fixture keys missing: $ds1_key / $ds2_key"
    return 1
  fi

  echo "Verifying signer and service-auth enforcement..."

  # 1. Unauthenticated request to authenticated endpoint must fail with 401
  local unauth_status
  unauth_status="$(curl -s -o /dev/null -w "%{http_code}" "$ds2_url/xrpc/blue.catbird.mlsDS.getConvoDigest?convoId=01J00000000000000000000000" || true)"
  if [[ "$unauth_status" != "401" ]]; then
    echo "✗ Unauthenticated request to getConvoDigest should return 401, got $unauth_status"
    return 1
  fi
  echo "✓ Unauthenticated request rejected with HTTP 401"

  # 2. Invalid token must fail with 401
  local invalid_token_status
  invalid_token_status="$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer invalid.token.payload" "$ds2_url/xrpc/blue.catbird.mlsDS.getConvoDigest?convoId=01J00000000000000000000000" || true)"
  if [[ "$invalid_token_status" != "401" ]]; then
    echo "✗ Invalid token request should return 401, got $invalid_token_status"
    return 1
  fi
  echo "✓ Malformed token rejected with HTTP 401"

  # 3. Wrong audience token must fail with 401
  local wrong_aud_jwt
  wrong_aud_jwt="$(generate_service_jwt "$ds1_key" "$DS1_SERVICE_DID" "did:web:wrong-aud.local" "blue.catbird.mlsDS.getConvoDigest")"
  local wrong_aud_status
  wrong_aud_status="$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $wrong_aud_jwt" "$ds2_url/xrpc/blue.catbird.mlsDS.getConvoDigest?convoId=01J00000000000000000000000" || true)"
  if [[ "$wrong_aud_status" != "401" ]]; then
    echo "✗ Wrong audience token should return 401, got $wrong_aud_status"
    return 1
  fi
  echo "✓ Wrong audience token rejected with HTTP 401"

  # 4. Allowlist peer DS via authenticated admin endpoint (proves admin signer auth)
  local admin_jwt_1
  admin_jwt_1="$(generate_service_jwt "$ds1_key" "$DS1_SERVICE_DID" "$DS2_SERVICE_DID" "blue.catbird.mlsDS.upsertFederationPeer")"
  local upsert_status_1
  upsert_status_1="$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Authorization: Bearer $admin_jwt_1" -H "Content-Type: application/json" -d "{\"dsDid\":\"$DS1_SERVICE_DID\",\"status\":\"allow\"}" "$ds2_url/xrpc/blue.catbird.mlsDS.upsertFederationPeer" || true)"
  if [[ "$upsert_status_1" != "200" ]]; then
    echo "✗ Failed to allowlist DS1 on DS2 via admin endpoint (HTTP $upsert_status_1)"
    return 1
  fi
  echo "✓ DS1 admin signer -> DS2 upsertFederationPeer verified (HTTP 200)"

  local admin_jwt_2
  admin_jwt_2="$(generate_service_jwt "$ds2_key" "$DS2_SERVICE_DID" "$DS1_SERVICE_DID" "blue.catbird.mlsDS.upsertFederationPeer")"
  local upsert_status_2
  upsert_status_2="$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Authorization: Bearer $admin_jwt_2" -H "Content-Type: application/json" -d "{\"dsDid\":\"$DS2_SERVICE_DID\",\"status\":\"allow\"}" "$ds1_url/xrpc/blue.catbird.mlsDS.upsertFederationPeer" || true)"
  if [[ "$upsert_status_2" != "200" ]]; then
    echo "✗ Failed to allowlist DS2 on DS1 via admin endpoint (HTTP $upsert_status_2)"
    return 1
  fi
  echo "✓ DS2 admin signer -> DS1 upsertFederationPeer verified (HTTP 200)"

  # 5. Valid token signed by DS1 key for DS2 audience must pass service-auth validation (non-401)
  local ds1_to_ds2_jwt
  ds1_to_ds2_jwt="$(generate_service_jwt "$ds1_key" "$DS1_SERVICE_DID" "$DS2_SERVICE_DID" "blue.catbird.mlsDS.getConvoDigest")"
  local auth_status
  auth_status="$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $ds1_to_ds2_jwt" "$ds2_url/xrpc/blue.catbird.mlsDS.getConvoDigest?convoId=01J00000000000000000000000" || true)"
  if [[ "$auth_status" == "401" ]]; then
    echo "✗ Valid DS1 service-auth token was rejected with 401 on DS2"
    return 1
  fi
  echo "✓ DS1 signer -> DS2 service-auth verification succeeded (HTTP $auth_status, not 401)"

  # 6. Valid token signed by DS2 key for DS1 audience must pass service-auth validation (non-401)
  local ds2_to_ds1_jwt
  ds2_to_ds1_jwt="$(generate_service_jwt "$ds2_key" "$DS2_SERVICE_DID" "$DS1_SERVICE_DID" "blue.catbird.mlsDS.getConvoDigest")"
  local auth_status_2
  auth_status_2="$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $ds2_to_ds1_jwt" "$ds1_url/xrpc/blue.catbird.mlsDS.getConvoDigest?convoId=01J00000000000000000000000" || true)"
  if [[ "$auth_status_2" == "401" ]]; then
    echo "✗ Valid DS2 service-auth token was rejected with 401 on DS1"
    return 1
  fi
  echo "✓ DS2 signer -> DS1 service-auth verification succeeded (HTTP $auth_status_2, not 401)"

  # 7. In-container cross-DS connectivity
  compose exec -T ds1 curl -fsS "http://ds2:3001/xrpc/blue.catbird.mlsDS.healthCheck" >/dev/null
  echo "✓ Cross-DS in-network call ds1 -> ds2 verified"
  compose exec -T ds2 curl -fsS "http://ds1:3001/xrpc/blue.catbird.mlsDS.healthCheck" >/dev/null
  echo "✓ Cross-DS in-network call ds2 -> ds1 verified"
}

cmd_env() {
  cat <<ENV
Harness defaults:
  PROJECT_NAME=$PROJECT_NAME (explicit=$EXPLICIT_PROJECT)
  APP_ENV=$APP_ENV
  FEDERATION_ENABLED=$FEDERATION_ENABLED
  FEDERATION_MODE=$FEDERATION_MODE
  FEDERATION_CAPABILITIES=$FEDERATION_CAPABILITIES
  ENFORCE_LXM=$ENFORCE_LXM
  ENFORCE_JTI=$ENFORCE_JTI
  DS1: SERVICE_DID=$DS1_SERVICE_DID SELF_ENDPOINT=$DS1_SELF_ENDPOINT
  DS2: SERVICE_DID=$DS2_SERVICE_DID SELF_ENDPOINT=$DS2_SELF_ENDPOINT
ENV
}

cmd_smoke() {
  require_tools

  local ds1_port
  ds1_port="$(get_service_host_port ds1 3001)"
  local ds2_port
  ds2_port="$(get_service_host_port ds2 3001)"

  if [[ -z "$ds1_port" ]] || [[ -z "$ds2_port" ]]; then
    echo "✗ Failed to discover ephemeral ports for ds1/ds2 via docker compose port"
    return 1
  fi

  local ds1="http://127.0.0.1:${ds1_port}"
  local ds2="http://127.0.0.1:${ds2_port}"

  echo "Discovered host ports: DS1=$ds1_port, DS2=$ds2_port"

  wait_for_url "DS1 readiness" "$ds1/health/ready"
  wait_for_url "DS2 readiness" "$ds2/health/ready"

  check_federation_endpoint "DS1" "$ds1" "$DS1_SERVICE_DID"
  check_federation_endpoint "DS2" "$ds2" "$DS2_SERVICE_DID"

  check_signer_and_service_auth "$ds1" "$ds2"

  echo "Federation two-node signer-authenticated smoke checks passed"
}

cmd_up() {
  require_tools
  if [[ "$EXPLICIT_PROJECT" -eq 0 ]]; then
    echo "$PROJECT_NAME" > "$STATE_FILE"
  fi
  echo "Starting deterministic DS1/DS2 federation harness with project '$PROJECT_NAME'..."
  compose up -d --build
  cmd_smoke
}

cmd_down() {
  require_tools
  echo "Stopping and tearing down federation harness project '$PROJECT_NAME'..."
  compose down --volumes --remove-orphans
  if [[ "$EXPLICIT_PROJECT" -eq 0 ]]; then
    rm -f "$STATE_FILE"
  fi
  echo "✓ Teardown complete"
}

cmd_status() {
  require_tools
  compose ps
}

cmd_logs() {
  require_tools
  if [[ "$#" -eq 0 ]]; then
    compose logs --tail=200 ds1 ds2
  else
    compose logs --tail=200 "$@"
  fi
}

cmd_help() {
  cat <<HELP
Usage: $0 {up|down|status|smoke|logs|env|help}

Commands:
  up      Build and start DS1/DS2 containers with ephemeral ports, run signer-authenticated smoke
  down    Stop and remove containers, networks, volumes, and orphans
  smoke   Run readiness, health, signer, and service-auth checks against running containers
  status  Show compose container status
  logs    Show logs for ds1 and ds2 (or pass service names)
  env     Print current configuration environment
  help    Show this message
HELP
}

case "${1:-help}" in
  up)
    cmd_up
    ;;
  down)
    cmd_down
    ;;
  status)
    cmd_status
    ;;
  smoke)
    cmd_smoke
    ;;
  logs)
    shift
    cmd_logs "$@"
    ;;
  env)
    cmd_env
    ;;
  help|--help|-h)
    cmd_help
    ;;
  *)
    echo "Unknown command: $1"
    cmd_help
    exit 1
    ;;
esac
