#!/usr/bin/env bash
# Hostile-federation gate. The 2026-02 `federation_hostile_peers` suite was
# deleted with the clean-slate consolidation; these are its current
# replacements. The DB-backed cases need the test database environment in
# server/README.md#tests, so the gate refuses to run without it instead of
# letting them skip.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../server"
: "${TEST_DATABASE_URL:?set TEST_DATABASE_URL as in server/README.md#tests}"
: "${CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED:?set CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED as in server/README.md#tests}"
export SQLX_OFFLINE=true

run() {
    echo "[federation-gate] $*"
    "$@"
}

# S2S bearer and HMAC callers cannot bypass the peer allowlist; group relay
# and terminal-close authority.
run cargo test --features sim,test-support --lib federation::group_relay::security_tests
# Peer policy: allow, block, suspend, risk tiers and the inbound gate.
run cargo test --features test-support --lib federation::peer_policy
# An untrusted JWT issuer cannot act for another DID.
run cargo test --features test-support --lib untrusted_issuer
# Hostile bootstrap network admission and reducer authority.
run cargo test --features test-support --test chat_protocol_remote_prefix_bootstrap hostile
# Forged, mis-signed or field-mismatched delivery receipts.
run cargo test --features test-support --test chat_protocol_federation_outbox_retry receipt
# An unresolvable or untrusted peer causes zero writes.
run cargo test --features test-support --test chat_protocol_federation_routing untrusted_peer
run cargo check --lib

echo "[federation-gate] PASS"
