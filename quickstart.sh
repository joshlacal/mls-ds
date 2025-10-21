#!/bin/bash

set -e

echo "🐦 Catbird MLS - Quick Start"
echo ""

# Check if Rust is installed
if ! command -v cargo &> /dev/null; then
    echo "❌ Rust not found. Installing..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    source $HOME/.cargo/env
fi

echo "✅ Rust $(rustc --version)"

# Build server
echo ""
echo "📦 Building server..."
cd server
cargo build
cd ..

# Build FFI
echo ""
echo "📦 Building MLS FFI..."
cd mls-ffi
cargo build
cd ..

# Run tests
echo ""
echo "🧪 Running tests..."
cd server
cargo test --quiet
cd ..

# Setup database
echo ""
echo "💾 Setting up database..."
cd server
export DATABASE_URL="sqlite:../catbird.db"

# Start server
echo ""
echo "🚀 Starting server on http://localhost:3000"
echo ""
echo "Press Ctrl+C to stop"
echo ""

cargo run

