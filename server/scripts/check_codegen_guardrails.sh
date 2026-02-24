#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

RUNTIME_ROOT="server/src"
RUNTIME_GLOBS=(--glob '**/*.rs' --glob '!generated/**')
ALLOWED_GENERATED_TYPES_FILES=(
  "server/src/db.rs"
  "server/src/realtime/mod.rs"
)

fail=0
tmp_matches="$(mktemp)"
tmp_hits="$(mktemp)"
tmp_disallowed="$(mktemp)"
trap 'rm -f "$tmp_matches" "$tmp_hits" "$tmp_disallowed"' EXIT

check_forbidden_pattern() {
  local pattern="$1"
  local label="$2"
  if rg -n --no-heading "${RUNTIME_GLOBS[@]}" "$pattern" "$RUNTIME_ROOT" >"$tmp_matches"; then
    echo "[codegen-guardrail] Forbidden ${label} reference(s) found:"
    cat "$tmp_matches"
    fail=1
  fi
}

check_forbidden_pattern 'generated::blue_catbird::mls::' 'generated::blue_catbird::mls::'
check_forbidden_pattern 'crate::blue_catbird::mls::' 'crate::blue_catbird::mls::'

if rg -n --no-heading "${RUNTIME_GLOBS[@]}" 'generated_types::' "$RUNTIME_ROOT" >"$tmp_hits"; then
  while IFS= read -r hit; do
    file="${hit%%:*}"
    case "$file" in
      "${ALLOWED_GENERATED_TYPES_FILES[0]}"|"${ALLOWED_GENERATED_TYPES_FILES[1]}")
        ;;
      *)
        echo "$hit" >>"$tmp_disallowed"
        ;;
    esac
  done <"$tmp_hits"

  if [ -s "$tmp_disallowed" ]; then
    echo "[codegen-guardrail] generated_types:: is only allowed in:"
    for file in "${ALLOWED_GENERATED_TYPES_FILES[@]}"; do
      echo "  - $file"
    done
    echo "[codegen-guardrail] Disallowed generated_types:: reference(s) found:"
    cat "$tmp_disallowed"
    fail=1
  fi
fi

if [ "$fail" -ne 0 ]; then
  exit 1
fi

echo "[codegen-guardrail] PASS"
