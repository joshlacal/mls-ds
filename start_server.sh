#!/bin/bash
# Start MLS Server

export DATABASE_URL="postgresql://localhost/mls_dev"
export RUST_LOG="info,catbird_server=debug"
export JWT_SECRET="test-jwt-secret-for-development"
export SERVICE_DID="did:web:localhost"
export SERVER_PORT=3000

echo "🚀 Starting MLS Server"
echo "======================="
echo "Database: $DATABASE_URL"
echo "Port: $SERVER_PORT"
echo ""

cd "$(dirname "$0")"
cargo run --bin catbird-server --release
