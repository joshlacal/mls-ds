#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-server/src}"

if ! command -v rg >/dev/null 2>&1; then
  echo "ripgrep (rg) is required for did:web lint"
  exit 1
fi

# Forbid ad-hoc did:web -> URL mapping outside the shared utility.
# Allowed implementation lives in server/src/identity.rs.
PATTERN='replace\("did:web:",\s*"https://"\)|\.well-known/did\.json'
ALLOW='server/src/identity\.rs|did-web-test'

matches="$(rg -n --pcre2 "$PATTERN" "$ROOT" -g '*.rs' | rg -v "$ALLOW" || true)"
if [[ -n "$matches" ]]; then
  echo "Found disallowed direct did:web URL construction outside shared utility:"
  echo "$matches"
  exit 1
fi

echo "did:web URL builder lint passed"
