#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS_SCRIPT="$SCRIPT_DIR/../scripts/federation-two-node-harness.sh"
E2E_SCRIPT="$SCRIPT_DIR/federation-two-node-e2e.sh"

if [[ ! -x "$HARNESS_SCRIPT" ]]; then
  echo "Harness script is missing or not executable: $HARNESS_SCRIPT"
  exit 1
fi

case "${1:-smoke}" in
  e2e)
    shift
    "$E2E_SCRIPT" "$@"
    ;;
  up|down|status|smoke|logs|env|help|--help|-h)
    "$HARNESS_SCRIPT" "$@"
    ;;
  *)
    echo "Usage: $0 [up|down|status|smoke|logs|env|e2e|help]"
    exit 1
    ;;
esac
