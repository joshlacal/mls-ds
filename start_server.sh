#!/bin/bash
# Start MLS Server (Development - runs directly without systemd)
#
# For production, use: ./deploy.sh
# This script is for local development/testing only.

export DATABASE_URL="${DATABASE_URL:?Set DATABASE_URL environment variable}"
export RUST_LOG="${RUST_LOG:-info,catbird_server=debug}"
export SERVICE_DID="${SERVICE_DID:-did:web:chat.catbird.blue}"
export SERVER_PORT="${SERVER_PORT:-3000}"

echo "🚀 Starting MLS Server (Development Mode)"
echo "=========================================="
echo "Port:     $SERVER_PORT"
echo ""
echo "For production deployment, use: ./deploy.sh"
echo ""

cd "$(dirname "$0")"
cargo run --bin catbird-server --release
