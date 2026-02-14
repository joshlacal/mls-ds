#!/usr/bin/env bash
set -euo pipefail

TARGET_DIR="${1:-src/handlers/mls_chat}"

if [ ! -d "$TARGET_DIR" ]; then
  echo "Target directory not found: $TARGET_DIR"
  exit 1
fi

# Flag format-style logging lines (message + args) that mention DID/conversation identifiers without explicit
# redaction helper. This intentionally does NOT try to catch structured fields like `did = %user_did` — those
# are handled by `violations_structured` below.
violations_inline=$(rg -n --glob '*.rs' '(trace!|debug!|info!|warn!|error!).*(did\\b|_did|convo_id|convoId|convo\\b)' "$TARGET_DIR" | rg -v 'redact_for_log' || true)

# Flag structured tracing fields (e.g. `did = %user_did`) that directly emit identifiers without redaction.
# This is kept separate from `violations_inline` so each pattern can be tuned independently without creating gaps.
violations_structured=$(rg -n --glob '*.rs' '(did|_did|convo_id|convoId|target_ds|sequencer|new_sequencer)\\s*=\\s*%[^,)]+' "$TARGET_DIR" | rg -v 'redact_for_log' || true)

violations=""
if [ -n "$violations_inline" ]; then
  violations="$violations_inline"
fi
if [ -n "$violations_structured" ]; then
  if [ -n "$violations" ]; then
    violations="$violations"$'\n'"$violations_structured"
  else
    violations="$violations_structured"
  fi
fi

if [ -n "$violations" ]; then
  echo "Found potential unredacted identity logging in $TARGET_DIR:"
  echo "$violations"
  echo
  echo "Use crate::crypto::redact_for_log(...) for DID/conversation identifiers in logs."
  exit 1
fi

echo "Log redaction lint passed for $TARGET_DIR"
