#!/bin/bash
# Start MLS Server (Development - runs directly without systemd)
#
# For production, use: ./deploy.sh
# This script is for local development/testing only.

export DATABASE_URL="postgresql://catbird:changeme@localhost:5432/catbird"
export REDIS_URL="redis://localhost:6379"
export RUST_LOG="info,catbird_server=debug"
export SERVICE_DID="did:web:mlschat.catbird.blue"
export SERVER_PORT=3000

echo "🚀 Starting MLS Server (Development Mode)"
echo "=========================================="
echo "Database: $DATABASE_URL"
echo "Redis:    $REDIS_URL"
echo "Port:     $SERVER_PORT"
echo ""
echo "For production deployment, use: ./deploy.sh"
echo ""

cd "$(dirname "$0")"
cargo run --bin catbird-server --release
