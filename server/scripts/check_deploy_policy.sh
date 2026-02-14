#!/usr/bin/env bash
set -euo pipefail

WORKFLOW_FILE="${1:-.github/workflows/mls-deploy.yml}"

if [ ! -f "$WORKFLOW_FILE" ]; then
  echo "Deployment workflow not found: $WORKFLOW_FILE"
  exit 1
fi

fail_if_match() {
  local pattern="$1"
  local message="$2"
  if rg -n "$pattern" "$WORKFLOW_FILE" >/tmp/deploy_policy_matches.txt 2>/dev/null; then
    echo "$message"
    cat /tmp/deploy_policy_matches.txt
    exit 1
  fi
}

# Block obvious insecure toggles in deployment workflow definitions.
fail_if_match 'ALLOW_UNSAFE_AUTH[[:space:]]*[:=][[:space:]]*("?true"?|"?1"?)' \
  "Blocked insecure deploy config: ALLOW_UNSAFE_AUTH=true"
fail_if_match 'FEDERATION_ALLOW_INSECURE_HTTP[[:space:]]*[:=][[:space:]]*("?true"?|"?1"?)' \
  "Blocked insecure deploy config: FEDERATION_ALLOW_INSECURE_HTTP=true"

echo "Deployment policy checks passed for $WORKFLOW_FILE"
