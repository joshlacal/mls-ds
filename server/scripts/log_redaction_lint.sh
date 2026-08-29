#!/usr/bin/env bash
set -euo pipefail

TARGET_DIR="${1:-src/chat_protocol}"

if [ ! -d "$TARGET_DIR" ]; then
  echo "Target directory not found: $TARGET_DIR"
  exit 1
fi

# Flag structured tracing fields like `convo_id = %convo_id` and
# `did = %user_did` — these directly emit the bound value into the log line.
# We deliberately do NOT match string-literal mentions like
# `warn!("addMembers: missing member_dids")` because those are static text,
# not interpolated values. The accepted redaction sigil is either `redact_for_log`
# or `hash_for_log` (both are documented helpers in `crate::crypto`).
violations_structured=$(rg -n --glob '*.rs' '((did|_did|convo_id|conversation_id|convoId|target_ds|sequencer|new_sequencer)\s*=\s*%[^,)]+|%(convo_id|conversation_id)\b)' "$TARGET_DIR" | rg -v 'redact_for_log|hash_for_log' || true)

# Flag format-style logging WHEN the actual interpolation slot
# `{user_did}` / `{convo_id}` etc. appears in the message. Bare mentions
# of an identifier name in a static message string are not violations.
# We require an interpolation slot (`{...}`) AND a non-redacted argument.
# This avoids the previous false positives on lines like
# `warn!("Empty convo_id provided")` which contain no interpolated value.
violations_inline=$(rg -n --glob '*.rs' '(trace!|debug!|info!|warn!|error!)\(.*\{[^}]*\}.*,(.*?)(did|_did|convo_id|conversation_id|convoId)([^_a-zA-Z]|$)' "$TARGET_DIR" | rg -v 'redact_for_log|hash_for_log' || true)

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
