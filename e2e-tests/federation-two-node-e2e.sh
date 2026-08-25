#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
HARNESS_SCRIPT="$REPO_ROOT/scripts/federation-two-node-harness.sh"
COMPOSE_FILE="$REPO_ROOT/e2e-tests/docker-compose.federation.yml"
if [[ -n "${FED_HARNESS_PROJECT_NAME:-}" ]]; then
  EXPLICIT_PROJECT=1
  PROJECT_NAME="$FED_HARNESS_PROJECT_NAME"
elif [[ -n "${COMPOSE_PROJECT_NAME:-}" ]]; then
  EXPLICIT_PROJECT=1
  PROJECT_NAME="$COMPOSE_PROJECT_NAME"
else
  EXPLICIT_PROJECT=0
  PROJECT_NAME="mls-fed-e2e-$(date +%s)-$RANDOM-$$"
fi

export FED_HARNESS_PROJECT_NAME="$PROJECT_NAME"
export COMPOSE_PROJECT_NAME="$PROJECT_NAME"

export DS1_PORT="${DS1_PORT:-0}"
export DS2_PORT="${DS2_PORT:-0}"
export DS1_SERVICE_DID="${DS1_SERVICE_DID:-did:web:ds1.catbird.blue}"
export DS2_SERVICE_DID="${DS2_SERVICE_DID:-did:web:ds2.catbird.blue}"
export DS1_SELF_ENDPOINT="${DS1_SELF_ENDPOINT:-http://ds1:3001}"
export DS2_SELF_ENDPOINT="${DS2_SELF_ENDPOINT:-http://ds2:3001}"
MODE="full"
NO_CLEANUP="false"
STARTED_HARNESS=0

info() {
  echo "[INFO] $*"
}

pass() {
  echo "✓ $*"
}

fail() {
  echo "✗ $*"
  exit 1
}

usage() {
  cat <<HELP
Usage: $0 [full|verify|dry-run] [--no-cleanup]

Modes:
  full      Boot DS1/DS2 via harness, run federation E2E checks, then clean up (default)
  verify    Run federation E2E checks against an already-running harness (requires explicit project name)
  dry-run   Print planned checks without starting containers

Options:
  --no-cleanup   Keep harness containers running after checks (only applies to full mode)
HELP
}

compose() {
  (cd "$REPO_ROOT" && docker compose -p "$FED_HARNESS_PROJECT_NAME" -f "$COMPOSE_FILE" "$@")
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
wait_for_url() {
  local label="$1"
  local url="$2"
  local attempts="${3:-60}"

  for ((i = 1; i <= attempts; i++)); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      pass "$label"
      return 0
    fi
    sleep 1
  done

  fail "$label failed: $url"
}

assert_json_contains() {
  local label="$1"
  local payload="$2"
  local expected_fragment="$3"
  local compact
  compact="$(printf '%s' "$payload" | tr -d '[:space:]')"

  if [[ "$compact" == *"$expected_fragment"* ]]; then
    pass "$label"
    return 0
  fi

  echo "  expected fragment: $expected_fragment"
  echo "  response: $payload"
  fail "$label mismatch"
}

check_readiness() {
  local ds1_port
  ds1_port="$(get_service_host_port ds1 3001)"
  local ds2_port
  ds2_port="$(get_service_host_port ds2 3001)"
  local ds1="http://127.0.0.1:${ds1_port}"
  local ds2="http://127.0.0.1:${ds2_port}"
  wait_for_url "DS1 readiness" "$ds1/health/ready"
  wait_for_url "DS2 readiness" "$ds2/health/ready"
}

check_ds_health() {
  local ds1_port
  ds1_port="$(get_service_host_port ds1 3001)"
  local ds2_port
  ds2_port="$(get_service_host_port ds2 3001)"
  local ds1="http://127.0.0.1:${ds1_port}"
  local ds2="http://127.0.0.1:${ds2_port}"
  local payload

  payload="$(curl -fsS "$ds1/xrpc/blue.catbird.mlsDS.healthCheck")"
  assert_json_contains "DS1 federation health DID" "$payload" "\"did\":\"$DS1_SERVICE_DID\""
  assert_json_contains "DS1 federation capabilities" "$payload" "baseline"
  assert_json_contains "DS1 federation capabilities v1" "$payload" "reconciliation-v1"

  payload="$(curl -fsS "$ds2/xrpc/blue.catbird.mlsDS.healthCheck")"
  assert_json_contains "DS2 federation health DID" "$payload" "\"did\":\"$DS2_SERVICE_DID\""
  assert_json_contains "DS2 federation capabilities" "$payload" "baseline"
  assert_json_contains "DS2 federation capabilities v1" "$payload" "reconciliation-v1"
}

check_local_getrecord_shim_removed() {
  local ds1_port
  ds1_port="$(get_service_host_port ds1 3001)"
  local ds2_port
  ds2_port="$(get_service_host_port ds2 3001)"
  local ds1="http://127.0.0.1:${ds1_port}"
  local ds2="http://127.0.0.1:${ds2_port}"
  local status

  status="$(curl -sS -o /dev/null -w '%{http_code}' --get \
    "$ds1/xrpc/com.atproto.repo.getRecord" \
    --data-urlencode "repo=$DS1_SERVICE_DID" \
    --data-urlencode "collection=blue.catbird.mls.profile" \
    --data-urlencode "rkey=self")"
  [[ "$status" == "404" ]] && pass "DS1 local getRecord route removed (use DID->PDS/AppView discovery)" || fail "DS1 expected 404 for local getRecord route; discovery must use DID->PDS/AppView (got $status)"

  status="$(curl -sS -o /dev/null -w '%{http_code}' --get \
    "$ds2/xrpc/com.atproto.repo.getRecord" \
    --data-urlencode "repo=$DS2_SERVICE_DID" \
    --data-urlencode "collection=blue.catbird.mls.profile" \
    --data-urlencode "rkey=self")"
  [[ "$status" == "404" ]] && pass "DS2 local getRecord route removed (use DID->PDS/AppView discovery)" || fail "DS2 expected 404 for local getRecord route; discovery must use DID->PDS/AppView (got $status)"
}

check_cross_ds_federated_path() {
  local payload

  payload="$(compose exec -T ds1 curl -fsS "http://ds2:3001/xrpc/blue.catbird.mlsDS.healthCheck")"
  assert_json_contains "DS1 -> DS2 federated API path" "$payload" "\"did\":\"$DS2_SERVICE_DID\""

  payload="$(compose exec -T ds2 curl -fsS "http://ds1:3001/xrpc/blue.catbird.mlsDS.healthCheck")"
  assert_json_contains "DS2 -> DS1 federated API path" "$payload" "\"did\":\"$DS1_SERVICE_DID\""
}

run_checks() {
  info "Running federation two-node E2E checks"
  check_readiness
  check_ds_health
  check_local_getrecord_shim_removed
  check_cross_ds_federated_path
  echo "Federation two-node E2E checks passed"
}

cleanup() {
  local status="$1"
  set +e
  if [[ "$STARTED_HARNESS" -eq 1 && "$NO_CLEANUP" != "true" ]]; then
    info "Cleaning up two-node federation harness for project '$FED_HARNESS_PROJECT_NAME'"
    "$HARNESS_SCRIPT" down >/dev/null 2>&1
  fi
  if [[ "$status" -ne 0 ]]; then
    echo "Federation two-node E2E checks failed"
  fi
}

trap 'cleanup $?' EXIT

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    full|verify|dry-run)
      MODE="$1"
      ;;
    --no-cleanup)
      NO_CLEANUP="true"
      ;;
    help|--help|-h)
      usage
      exit 0
      ;;
    *)
      usage
      exit 1
      ;;
  esac
  shift
done

if [[ ! -x "$HARNESS_SCRIPT" ]]; then
  fail "Harness script is missing or not executable: $HARNESS_SCRIPT"
fi

case "$MODE" in
  dry-run)
    info "Dry-run complete (no commands executed) for project '$FED_HARNESS_PROJECT_NAME'"
    echo "Planned checks:"
    echo "  - DS1/DS2 readiness (/health/ready)"
    echo "  - DS1/DS2 federation health (/xrpc/blue.catbird.mlsDS.healthCheck)"
    echo "  - DS1/DS2 local /xrpc/com.atproto.repo.getRecord returns 404 (discovery requires DID->PDS/AppView)"
    echo "  - DS1->DS2 and DS2->DS1 federated API path health checks (inside harness network)"
    ;;
  verify)
    if [[ "$EXPLICIT_PROJECT" -eq 0 ]]; then
      fail "Verify mode requires an explicit project name. Set FED_HARNESS_PROJECT_NAME or COMPOSE_PROJECT_NAME."
    fi
    run_checks
    ;;
  full)
    info "Booting DS1/DS2 federation harness for project '$FED_HARNESS_PROJECT_NAME'"
    STARTED_HARNESS=1
    "$HARNESS_SCRIPT" up
    run_checks
    ;;
esac
