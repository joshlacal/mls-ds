#!/usr/bin/env bash
# Federation test: runs 2 MLS-DS instances on localhost with federation enabled.
#
# Instance 1: port 3001, DB catbird_mls_1, DID did:web:ds1.local
# Instance 2: port 3002, DB catbird_mls_2, DID did:web:ds2.local
#
# Usage:
#   ./federation-test/run-federation.sh          # Start both instances
#   ./federation-test/run-federation.sh stop      # Stop both instances
#   ./federation-test/run-federation.sh status     # Check status

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
KEYS_DIR="$SCRIPT_DIR/keys"
LOGS_DIR="$SCRIPT_DIR/logs"
PID_DIR="$SCRIPT_DIR/pids"
BINARY="$PROJECT_DIR/target/release/catbird-server"

mkdir -p "$LOGS_DIR" "$PID_DIR" "$KEYS_DIR"

# ── Generate PKCS8 ES256 keys if not present ──────────────────────────────
generate_keys() {
    if [ ! -f "$KEYS_DIR/instance1_pkcs8.pem" ]; then
        echo "Generating ES256 key for instance 1..."
        openssl ecparam -name prime256v1 -genkey -noout | \
            openssl pkcs8 -topk8 -nocrypt -out "$KEYS_DIR/instance1_pkcs8.pem"
    fi
    if [ ! -f "$KEYS_DIR/instance2_pkcs8.pem" ]; then
        echo "Generating ES256 key for instance 2..."
        openssl ecparam -name prime256v1 -genkey -noout | \
            openssl pkcs8 -topk8 -nocrypt -out "$KEYS_DIR/instance2_pkcs8.pem"
    fi
}

# ── Ensure PostgreSQL databases exist ──────────────────────────────────────
setup_databases() {
    echo "Setting up databases..."
    sudo -u postgres psql -v ON_ERROR_STOP=0 <<'SQL'
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'catbird') THEN
    CREATE ROLE catbird WITH LOGIN PASSWORD 'catbird';
  END IF;
END $$;

-- The migration GRANT references "catbird" db, so ensure it exists
SELECT 'CREATE DATABASE catbird OWNER catbird'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'catbird')
\gexec

SELECT 'CREATE DATABASE catbird_mls_1 OWNER catbird'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'catbird_mls_1')
\gexec

SELECT 'CREATE DATABASE catbird_mls_2 OWNER catbird'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'catbird_mls_2')
\gexec
SQL

    for db in catbird_mls_1 catbird_mls_2; do
        sudo -u postgres psql -d "$db" -c 'CREATE EXTENSION IF NOT EXISTS pgcrypto;' 2>/dev/null || true
        sudo -u postgres psql -d "$db" -c 'CREATE EXTENSION IF NOT EXISTS "uuid-ossp";' 2>/dev/null || true
    done
    echo "Databases ready."
}

# ── Ensure Redis is running ────────────────────────────────────────────────
ensure_redis() {
    if ! redis-cli ping &>/dev/null; then
        echo "Starting Redis..."
        redis-server --daemonize yes --port 6379
    fi
    echo "Redis ready."
}

# ── Common environment for both instances ──────────────────────────────────
common_env() {
    cat <<'ENV'
RUST_LOG=info,catbird_server::federation=debug,catbird_server::handlers::ds=debug
ENFORCE_LXM=false
ENFORCE_JTI=false
ALLOW_UNSAFE_AUTH=true
FEDERATION_ENABLED=true
FEDERATION_ALLOW_INSECURE_HTTP=true
FEDERATION_DNS_TIMEOUT_MS=5000
APP_ENV=development
ENV
}

# ── Start an instance ──────────────────────────────────────────────────────
start_instance() {
    local num="$1"
    local port="$2"
    local db="catbird_mls_$num"
    local did="did:web:ds${num}.local"
    local endpoint="http://127.0.0.1:${port}"
    local key_file="$KEYS_DIR/instance${num}_pkcs8.pem"
    local other_port="$3"
    local other_endpoint="http://127.0.0.1:${other_port}"

    local signing_key
    signing_key="$(cat "$key_file")"

    echo "Starting Instance $num on port $port (DID: $did)..."

    # Use different Redis DB numbers to isolate the two instances
    local redis_db=$((num - 1))

    # Build environment
    env \
        $(common_env | grep -v '^#' | tr '\n' ' ') \
        DATABASE_URL="postgresql://catbird:catbird@127.0.0.1:5432/$db" \
        REDIS_URL="redis://127.0.0.1:6379/$redis_db" \
        SERVER_PORT="$port" \
        SERVICE_DID="$did" \
        SELF_ENDPOINT="$endpoint" \
        SIGNING_KEY_PEM="$signing_key" \
        DEFAULT_DS_ENDPOINT="$other_endpoint" \
        TICKET_SECRET="test-ticket-secret-$num" \
        "$BINARY" \
        > "$LOGS_DIR/instance${num}.log" 2>&1 &

    local pid=$!
    echo "$pid" > "$PID_DIR/instance${num}.pid"
    echo "  Instance $num started (PID: $pid)"
    echo "  Log: $LOGS_DIR/instance${num}.log"
    echo "  Endpoint: $endpoint"
}

# ── Stop instances ─────────────────────────────────────────────────────────
stop_instances() {
    echo "Stopping federation instances..."
    for num in 1 2; do
        local pidfile="$PID_DIR/instance${num}.pid"
        if [ -f "$pidfile" ]; then
            local pid
            pid="$(cat "$pidfile")"
            if kill -0 "$pid" 2>/dev/null; then
                kill "$pid" && echo "  Instance $num (PID $pid) stopped."
            else
                echo "  Instance $num (PID $pid) already stopped."
            fi
            rm -f "$pidfile"
        fi
    done
}

# ── Check status ───────────────────────────────────────────────────────────
check_status() {
    echo "Federation instance status:"
    for num in 1 2; do
        local port=$((3000 + num))
        local pidfile="$PID_DIR/instance${num}.pid"
        local running="no"
        if [ -f "$pidfile" ]; then
            local pid
            pid="$(cat "$pidfile")"
            if kill -0 "$pid" 2>/dev/null; then
                running="yes (PID $pid)"
            fi
        fi

        local healthy="no"
        if curl -sf "http://127.0.0.1:${port}/health/live" &>/dev/null; then
            healthy="yes"
        fi

        echo "  Instance $num (port $port): running=$running, healthy=$healthy"
    done
}

# ── Wait for a single instance to be ready ─────────────────────────────────
wait_for_instance() {
    local num="$1"
    local port="$2"
    local url="http://127.0.0.1:${port}/health/live"
    local attempts=0
    while [ $attempts -lt 30 ]; do
        if curl -sf "$url" &>/dev/null; then
            echo "  Instance $num ready."
            return 0
        fi
        attempts=$((attempts + 1))
        sleep 1
    done
    echo "  WARNING: Instance $num did not become ready within 30s"
    echo "  Last log lines:"
    tail -10 "$LOGS_DIR/instance${num}.log" 2>/dev/null || true
    return 1
}

# ── Main ───────────────────────────────────────────────────────────────────
case "${1:-start}" in
    start)
        if [ ! -f "$BINARY" ]; then
            echo "Binary not found at $BINARY"
            echo "Build with: cd server && cargo build --release"
            exit 1
        fi

        stop_instances 2>/dev/null || true
        generate_keys
        setup_databases
        ensure_redis

        # Start sequentially to avoid migration race conditions
        start_instance 1 3001 3002
        echo "Waiting for Instance 1 to run migrations and become ready..."
        wait_for_instance 1 3001

        start_instance 2 3002 3001
        echo "Waiting for Instance 2 to run migrations and become ready..."
        wait_for_instance 2 3002

        check_status

        echo ""
        echo "Federation test environment is running!"
        echo "  Instance 1: http://127.0.0.1:3001 (did:web:ds1.local)"
        echo "  Instance 2: http://127.0.0.1:3002 (did:web:ds2.local)"
        echo ""
        echo "Test federation health:"
        echo "  curl http://127.0.0.1:3001/xrpc/blue.catbird.mls.ds.healthCheck"
        echo "  curl http://127.0.0.1:3002/xrpc/blue.catbird.mls.ds.healthCheck"
        echo ""
        echo "Stop with: $0 stop"
        ;;
    stop)
        stop_instances
        ;;
    status)
        check_status
        ;;
    restart)
        stop_instances 2>/dev/null || true
        sleep 1
        exec "$0" start
        ;;
    *)
        echo "Usage: $0 {start|stop|status|restart}"
        exit 1
        ;;
esac
