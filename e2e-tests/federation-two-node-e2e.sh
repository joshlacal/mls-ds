#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
HARNESS_SCRIPT="$REPO_ROOT/scripts/federation-two-node-harness.sh"
COMPOSE_FILE="$REPO_ROOT/scripts/federation-two-node.compose.yml"
PROJECT_NAME="${FED_HARNESS_PROJECT_NAME:-mls-federation-harness}"

export DS1_PORT="${DS1_PORT:-3101}"
export DS2_PORT="${DS2_PORT:-3102}"
export DS1_SERVICE_DID="${DS1_SERVICE_DID:-did:web:ds1.local}"
export DS2_SERVICE_DID="${DS2_SERVICE_DID:-did:web:ds2.local}"
export DS1_SELF_ENDPOINT="${DS1_SELF_ENDPOINT:-http://127.0.0.1:${DS1_PORT}}"
export DS2_SELF_ENDPOINT="${DS2_SELF_ENDPOINT:-http://127.0.0.1:${DS2_PORT}}"

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
  verify    Run federation E2E checks against an already-running harness
  dry-run   Print planned checks without starting containers

Options:
  --no-cleanup   Keep harness containers running after checks (only applies to full mode)
HELP
}

compose() {
  (cd "$REPO_ROOT" && docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" "$@")
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
  local ds1="http://127.0.0.1:${DS1_PORT}"
  local ds2="http://127.0.0.1:${DS2_PORT}"
  wait_for_url "DS1 readiness" "$ds1/health/ready"
  wait_for_url "DS2 readiness" "$ds2/health/ready"
}

check_ds_health() {
  local ds1="http://127.0.0.1:${DS1_PORT}"
  local ds2="http://127.0.0.1:${DS2_PORT}"
  local payload

  payload="$(curl -fsS "$ds1/xrpc/blue.catbird.mls.ds.healthCheck")"
  assert_json_contains "DS1 federation health DID" "$payload" "\"did\":\"$DS1_SERVICE_DID\""

  payload="$(curl -fsS "$ds2/xrpc/blue.catbird.mls.ds.healthCheck")"
  assert_json_contains "DS2 federation health DID" "$payload" "\"did\":\"$DS2_SERVICE_DID\""
}

check_local_getrecord_shim_removed() {
  local ds1="http://127.0.0.1:${DS1_PORT}"
  local ds2="http://127.0.0.1:${DS2_PORT}"
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

  payload="$(compose exec -T ds1 curl -fsS "http://ds2:${DS2_PORT}/xrpc/blue.catbird.mls.ds.healthCheck")"
  assert_json_contains "DS1 -> DS2 federated API path" "$payload" "\"did\":\"$DS2_SERVICE_DID\""

  payload="$(compose exec -T ds2 curl -fsS "http://ds1:${DS1_PORT}/xrpc/blue.catbird.mls.ds.healthCheck")"
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
    info "Cleaning up two-node federation harness"
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
    info "Dry-run complete (no commands executed)"
    echo "Planned checks:"
    echo "  - DS1/DS2 readiness (/health/ready)"
    echo "  - DS1/DS2 federation health (/xrpc/blue.catbird.mls.ds.healthCheck)"
    echo "  - DS1/DS2 local /xrpc/com.atproto.repo.getRecord returns 404 (discovery requires DID->PDS/AppView)"
    echo "  - DS1->DS2 and DS2->DS1 federated API path health checks (inside harness network)"
    ;;
  verify)
    run_checks
    ;;
  full)
    info "Booting DS1/DS2 federation harness"
    STARTED_HARNESS=1
    "$HARNESS_SCRIPT" up
    run_checks
    ;;
esac
