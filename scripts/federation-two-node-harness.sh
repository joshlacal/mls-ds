#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/federation-two-node.compose.yml"
PROJECT_NAME="${FED_HARNESS_PROJECT_NAME:-mls-federation-harness}"

export FEDERATION_MODE="${FEDERATION_MODE:-allowlist}"
export FEDERATION_ENABLED="${FEDERATION_ENABLED:-true}"

export DS1_PORT="${DS1_PORT:-3101}"
export DS2_PORT="${DS2_PORT:-3102}"
export DS1_DB_PORT="${DS1_DB_PORT:-5541}"
export DS2_DB_PORT="${DS2_DB_PORT:-5542}"
export DS1_REDIS_PORT="${DS1_REDIS_PORT:-6381}"
export DS2_REDIS_PORT="${DS2_REDIS_PORT:-6382}"

export DS1_SERVICE_DID="${DS1_SERVICE_DID:-did:web:ds1.local}"
export DS2_SERVICE_DID="${DS2_SERVICE_DID:-did:web:ds2.local}"
export DS1_SELF_ENDPOINT="${DS1_SELF_ENDPOINT:-http://127.0.0.1:${DS1_PORT}}"
export DS2_SELF_ENDPOINT="${DS2_SELF_ENDPOINT:-http://127.0.0.1:${DS2_PORT}}"

export JWT_SECRET="${JWT_SECRET:?Set JWT_SECRET environment variable}"
export FEDERATION_ALLOW_INSECURE_HTTP="${FEDERATION_ALLOW_INSECURE_HTTP:-true}"
export ENFORCE_LXM="${ENFORCE_LXM:-false}"
export ENFORCE_JTI="${ENFORCE_JTI:-false}"
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
  local endpoint="$base_url/xrpc/blue.catbird.mls.ds.healthCheck"

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

  echo "✓ Federation endpoint responded for $node ($expected_did)"
}

cmd_env() {
  cat <<ENV
Harness defaults:
  FEDERATION_ENABLED=$FEDERATION_ENABLED
  FEDERATION_MODE=$FEDERATION_MODE
  DS1: SERVICE_DID=$DS1_SERVICE_DID SELF_ENDPOINT=$DS1_SELF_ENDPOINT PORT=$DS1_PORT DB_PORT=$DS1_DB_PORT REDIS_PORT=$DS1_REDIS_PORT
  DS2: SERVICE_DID=$DS2_SERVICE_DID SELF_ENDPOINT=$DS2_SELF_ENDPOINT PORT=$DS2_PORT DB_PORT=$DS2_DB_PORT REDIS_PORT=$DS2_REDIS_PORT
ENV
}

cmd_smoke() {
  require_tools

  local ds1="http://127.0.0.1:${DS1_PORT}"
  local ds2="http://127.0.0.1:${DS2_PORT}"

  wait_for_url "DS1 readiness" "$ds1/health/ready"
  wait_for_url "DS2 readiness" "$ds2/health/ready"

  check_federation_endpoint "DS1" "$ds1" "$DS1_SERVICE_DID"
  check_federation_endpoint "DS2" "$ds2" "$DS2_SERVICE_DID"

  echo "Federation two-node smoke checks passed"
}

cmd_up() {
  require_tools
  echo "Starting deterministic DS1/DS2 federation harness..."
  compose up -d --build
  cmd_smoke
}

cmd_down() {
  require_tools
  compose down --remove-orphans
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

Single-command bootstrap:
  $0 up

Commands:
  up      Build and start DS1 + DS2 with isolated Postgres/Redis and federation defaults
  down    Stop harness containers
  status  Show harness container status
  smoke   Verify /health/ready and federation /xrpc/blue.catbird.mls.ds.healthCheck on both nodes
  logs    Show DS1/DS2 logs (pass service name to filter)
  env     Print effective federation defaults for both nodes
  help    Show this message
HELP
}

case "${1:-help}" in
  up) cmd_up ;;
  down) cmd_down ;;
  status) cmd_status ;;
  smoke) cmd_smoke ;;
  logs) shift; cmd_logs "$@" ;;
  env) cmd_env ;;
  help|--help|-h) cmd_help ;;
  *)
    cmd_help
    exit 1
    ;;
esac
