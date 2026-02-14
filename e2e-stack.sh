#!/usr/bin/env bash
set -euo pipefail

# E2E test stack for mls-ds using Apple's `container` CLI
# Usage:
#   ./e2e-stack.sh up      # Build + start postgres, redis, mls-ds
#   ./e2e-stack.sh down    # Stop and remove all E2E containers
#   ./e2e-stack.sh status  # Show container status
#   ./e2e-stack.sh test    # Run E2E tests against the stack
#   ./e2e-stack.sh stress  # Run stress tests against the stack
#   ./e2e-stack.sh logs    # Tail mls-ds logs

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVER_DIR="$SCRIPT_DIR/server"
E2E_DIR="$SCRIPT_DIR/e2e-tests"

# Container names
PG_NAME="e2e-postgres"
REDIS_NAME="e2e-redis"
MLS_NAME="e2e-mls-ds"
MLS_IMAGE="mls-ds-e2e:latest"

# Credentials
PG_USER="catbird"
PG_PASS="catbird"
PG_DB="catbird_mls"
JWT_SECRET="test-secret-for-e2e"

wait_for_container() {
  local name="$1"
  local max_wait="${2:-60}"
  local elapsed=0
  echo "  Waiting for $name to be running..."
  while true; do
    state=$(container inspect "$name" 2>/dev/null | grep -o '"state":"[^"]*"' | head -1 | cut -d'"' -f4 || echo "unknown")
    if [[ "$state" == "running" ]]; then
      break
    fi
    if (( elapsed >= max_wait )); then
      echo "  ✗ $name did not start within ${max_wait}s"
      return 1
    fi
    sleep 2
    elapsed=$((elapsed + 2))
  done
  echo "  ✓ $name is running"
}

wait_for_health() {
  local name="$1"
  local cmd="$2"
  local max_wait="${3:-60}"
  local elapsed=0
  echo "  Waiting for $name to be healthy..."
  while true; do
    if container exec "$name" sh -c "$cmd" >/dev/null 2>&1; then
      break
    fi
    if (( elapsed >= max_wait )); then
      echo "  ✗ $name health check failed after ${max_wait}s"
      return 1
    fi
    sleep 2
    elapsed=$((elapsed + 2))
  done
  echo "  ✓ $name is healthy"
}

get_ip() {
  container inspect "$1" 2>/dev/null | grep -o '"addr":"[^"]*"' | head -1 | cut -d'"' -f4
}

cmd_up() {
  echo "=== Starting E2E Stack ==="

  # Ensure system is running
  container system start 2>/dev/null || true

  # --- PostgreSQL ---
  if container inspect "$PG_NAME" >/dev/null 2>&1; then
    echo "→ $PG_NAME already exists, starting..."
    container start "$PG_NAME" 2>/dev/null || true
  else
    echo "→ Creating $PG_NAME..."
    container run \
      --name "$PG_NAME" \
      --detach \
      --env POSTGRES_USER="$PG_USER" \
      --env POSTGRES_PASSWORD="$PG_PASS" \
      --env POSTGRES_DB="$PG_DB" \
      docker.io/postgres:16-bookworm
  fi
  wait_for_container "$PG_NAME"
  wait_for_health "$PG_NAME" "pg_isready -U $PG_USER -d $PG_DB" 30

  local pg_ip
  pg_ip=$(get_ip "$PG_NAME")
  echo "  PostgreSQL IP: $pg_ip"

  # --- Redis ---
  if container inspect "$REDIS_NAME" >/dev/null 2>&1; then
    echo "→ $REDIS_NAME already exists, starting..."
    container start "$REDIS_NAME" 2>/dev/null || true
  else
    echo "→ Creating $REDIS_NAME..."
    container run \
      --name "$REDIS_NAME" \
      --detach \
      docker.io/redis:7-bookworm
  fi
  wait_for_container "$REDIS_NAME"
  wait_for_health "$REDIS_NAME" "redis-cli ping" 20

  local redis_ip
  redis_ip=$(get_ip "$REDIS_NAME")
  echo "  Redis IP: $redis_ip"

  # --- Build mls-ds image ---
  echo "→ Building $MLS_IMAGE..."
  container build --tag "$MLS_IMAGE" --file "$SERVER_DIR/Dockerfile" "$SERVER_DIR"

  # --- mls-ds server ---
  # Remove old if exists
  if container inspect "$MLS_NAME" >/dev/null 2>&1; then
    echo "→ Removing old $MLS_NAME..."
    container stop "$MLS_NAME" 2>/dev/null || true
    container rm "$MLS_NAME" 2>/dev/null || true
  fi

  echo "→ Creating $MLS_NAME..."
  container run \
    --name "$MLS_NAME" \
    --detach \
    --env DATABASE_URL="postgres://${PG_USER}:${PG_PASS}@${pg_ip}:5432/${PG_DB}" \
    --env REDIS_URL="redis://${redis_ip}:6379" \
    --env SERVER_PORT="3001" \
    --env JWT_SECRET="$JWT_SECRET" \
    --env SERVICE_DID="did:web:localhost" \
    --env ENFORCE_LXM="false" \
    --env ENFORCE_JTI="false" \
    --env RUST_LOG="info" \
    "$MLS_IMAGE"

  wait_for_container "$MLS_NAME"

  local mls_ip
  mls_ip=$(get_ip "$MLS_NAME")
  echo "  mls-ds IP: $mls_ip"

  # Wait for HTTP health
  echo "  Waiting for mls-ds HTTP health..."
  local elapsed=0
  while true; do
    if container exec "$MLS_NAME" curl -sf http://localhost:3001/health/ready >/dev/null 2>&1; then
      break
    fi
    if (( elapsed >= 120 )); then
      echo "  ✗ mls-ds did not become healthy"
      echo "  Logs:"
      container logs "$MLS_NAME" 2>&1 | tail -20
      return 1
    fi
    sleep 3
    elapsed=$((elapsed + 3))
  done
  echo "  ✓ mls-ds is healthy at http://${mls_ip}:3001"

  echo ""
  echo "=== Stack Ready ==="
  echo "  PostgreSQL: $pg_ip:5432"
  echo "  Redis:      $redis_ip:6379"
  echo "  mls-ds:     http://${mls_ip}:3001"
  echo ""
  echo "Run tests with:"
  echo "  E2E_BASE_URL=http://${mls_ip}:3001 cargo test -p mls-e2e-tests -- --ignored"
  echo ""
  echo "Or: ./e2e-stack.sh test"
}

cmd_down() {
  echo "=== Stopping E2E Stack ==="
  for name in "$MLS_NAME" "$REDIS_NAME" "$PG_NAME"; do
    if container inspect "$name" >/dev/null 2>&1; then
      echo "→ Stopping $name..."
      container stop "$name" 2>/dev/null || true
      container rm "$name" 2>/dev/null || true
    fi
  done
  echo "✓ Stack stopped"
}

cmd_status() {
  echo "=== E2E Stack Status ==="
  container ls -a 2>&1 | grep -E "(ID|e2e-)" || echo "No E2E containers found"
}

cmd_test() {
  local mls_ip
  mls_ip=$(get_ip "$MLS_NAME" 2>/dev/null || echo "")
  if [[ -z "$mls_ip" ]]; then
    echo "Error: mls-ds not running. Run './e2e-stack.sh up' first."
    exit 1
  fi

  echo "=== Running E2E Tests against http://${mls_ip}:3001 ==="
  cd "$E2E_DIR"
  E2E_BASE_URL="http://${mls_ip}:3001" E2E_JWT_SECRET="$JWT_SECRET" \
    cargo test -- --ignored --nocapture "$@"
}

cmd_stress() {
  local mls_ip
  mls_ip=$(get_ip "$MLS_NAME" 2>/dev/null || echo "")
  if [[ -z "$mls_ip" ]]; then
    echo "Error: mls-ds not running. Run './e2e-stack.sh up' first."
    exit 1
  fi

  echo "=== Running Stress Tests against http://${mls_ip}:3001 ==="
  cd "$E2E_DIR"
  E2E_BASE_URL="http://${mls_ip}:3001" E2E_JWT_SECRET="$JWT_SECRET" \
    cargo test stress -- --ignored --nocapture "$@"
}

cmd_logs() {
  container logs "$MLS_NAME" "$@"
}

case "${1:-help}" in
  up)     cmd_up ;;
  down)   cmd_down ;;
  status) cmd_status ;;
  test)   shift; cmd_test "$@" ;;
  stress) shift; cmd_stress "$@" ;;
  logs)   shift; cmd_logs "$@" ;;
  *)
    echo "Usage: $0 {up|down|status|test|stress|logs}"
    echo ""
    echo "  up      Build and start postgres + redis + mls-ds"
    echo "  down    Stop and remove all E2E containers"
    echo "  status  Show container status"
    echo "  test    Run E2E integration tests"
    echo "  stress  Run stress tests"
    echo "  logs    Show mls-ds server logs"
    ;;
esac
