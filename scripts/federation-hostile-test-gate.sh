#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "[federation-gate] Running hostile federation tests..."
SQLX_OFFLINE=true cargo test -p catbird-server --test federation_hostile_peers -- --nocapture

echo "[federation-gate] Running catbird-server library checks..."
SQLX_OFFLINE=true cargo check -p catbird-server --lib

echo "[federation-gate] PASS"
