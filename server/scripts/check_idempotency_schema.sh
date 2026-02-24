#!/usr/bin/env bash
set -euo pipefail

GREENFIELD="${1:-server/migrations/20250101000000_greenfield_schema.sql}"
SCOPED_MIGRATION="${2:-server/migrations/20260215000000_idempotency_cache_caller_did.sql}"

require_pattern() {
  local file="$1"
  local pattern="$2"
  local message="$3"
  if ! rg -n --pcre2 "$pattern" "$file" >/dev/null 2>&1; then
    echo "$message ($file)"
    exit 1
  fi
}

forbid_pattern() {
  local file="$1"
  local pattern="$2"
  local message="$3"
  if rg -n --pcre2 "$pattern" "$file" >/tmp/idempotency_schema_forbidden.txt 2>/dev/null; then
    echo "$message ($file)"
    cat /tmp/idempotency_schema_forbidden.txt
    exit 1
  fi
}

require_pattern "$GREENFIELD" 'CREATE TABLE idempotency_cache' "Missing idempotency_cache in greenfield schema"
require_pattern "$GREENFIELD" 'PRIMARY KEY\s*\(\s*caller_did\s*,\s*endpoint\s*,\s*key\s*\)' \
  "Greenfield schema must scope idempotency_cache by caller_did + endpoint + key"
forbid_pattern "$GREENFIELD" 'PRIMARY KEY\s*\(\s*key\s*\)' \
  "Greenfield schema must not use global idempotency key primary key"

require_pattern "$SCOPED_MIGRATION" 'PRIMARY KEY\s*\(\s*caller_did\s*,\s*endpoint\s*,\s*key\s*\)' \
  "Scoped idempotency migration must enforce caller_did + endpoint + key primary key"

echo "Idempotency schema checks passed"
