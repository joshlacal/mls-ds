#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_DIR="$(cd "$SERVER_DIR/.." && pwd)"
MANIFEST_PATH="$SERVER_DIR/Cargo.toml"
PROOF_FEATURE="chat-protocol-production-proof"
SHIPPING_FEATURES="namespace-bluecatbird,server-bin"

metadata_file="$(mktemp)"
guard_output="$(mktemp)"
trap 'rm -f "$metadata_file" "$guard_output"' EXIT

cargo metadata \
  --format-version 1 \
  --no-deps \
  --manifest-path "$MANIFEST_PATH" \
  >"$metadata_file"

python3 - "$metadata_file" "$PROOF_FEATURE" <<'PY'
import json
import sys

metadata_path, proof_feature = sys.argv[1:]
with open(metadata_path, encoding="utf-8") as metadata_file:
    metadata = json.load(metadata_file)

packages = [
    package
    for package in metadata["packages"]
    if package["name"] == "catbird-server"
]
if len(packages) != 1:
    raise SystemExit(
        f"expected exactly one catbird-server package, found {len(packages)}"
    )

package = packages[0]
features = package["features"]
defaults = set(features.get("default", []))
required_defaults = {"namespace-bluecatbird", "server-bin"}
if defaults != required_defaults:
    raise SystemExit(
        "catbird-server default features must be exactly "
        f"{sorted(required_defaults)}, found {sorted(defaults)}"
    )

if proof_feature not in features:
    raise SystemExit(f"missing non-default feature {proof_feature}")
if proof_feature in defaults:
    raise SystemExit(f"{proof_feature} must not be a default feature")

targets = {(target["kind"][0], target["name"]): target for target in package["targets"]}
for binary_name in ("catbird-server", "deadletter_recover"):
    target = targets.get(("bin", binary_name))
    if target is None:
        raise SystemExit(f"missing explicit shipping binary target {binary_name}")
    required_features = set(target.get("required-features", []))
    if required_features != {"server-bin"}:
        raise SystemExit(
            f"{binary_name} must require exactly server-bin, "
            f"found {sorted(required_features)}"
        )

proof_target = targets.get(("test", "chat_protocol_production_cfg"))
if proof_target is None:
    raise SystemExit("missing chat_protocol_production_cfg integration-test target")
required_features = set(proof_target.get("required-features", []))
if required_features != {proof_feature}:
    raise SystemExit(
        "chat_protocol_production_cfg must require exactly "
        f"{proof_feature}, found {sorted(required_features)}"
    )
PY

# The compiler guard is the authority for forbidden feature coexistence. Prove
# that Cargo reaches that exact guard, rather than accepting an unrelated build
# failure as evidence.
if cargo check \
  --quiet \
  --locked \
  --manifest-path "$MANIFEST_PATH" \
  --lib \
  --no-default-features \
  --features "$SHIPPING_FEATURES,$PROOF_FEATURE" \
  >"$guard_output" 2>&1
then
  echo "forbidden feature combination unexpectedly compiled" >&2
  exit 1
fi

if ! grep -Fq \
  "\`chat-protocol-production-proof\` is a non-shipping test surface and cannot coexist with \`server-bin\`" \
  "$guard_output"
then
  echo "forbidden feature check failed before reaching the crate-level guard" >&2
  cat "$guard_output" >&2
  exit 1
fi

# Shipping and deployment configuration must never opt into the proof feature.
# Keep this list limited to actual shipping/CI surfaces; Cargo.toml, lib.rs,
# this policy checker, and the named proof test necessarily name the feature.
shipping_paths=(
  "$REPO_DIR/.github/workflows"
  "$REPO_DIR/deploy.sh"
  "$REPO_DIR/docker-compose.yml"
  "$SERVER_DIR/Dockerfile"
  "$SERVER_DIR/catbird-mls-server.service"
  "$SERVER_DIR/deploy-fresh.sh"
  "$SERVER_DIR/deploy-update.sh"
  "$SERVER_DIR/deploy.sh"
  "$SERVER_DIR/scripts/deploy.sh"
)

existing_shipping_paths=()
for path in "${shipping_paths[@]}"; do
  if [ -e "$path" ]; then
    existing_shipping_paths+=("$path")
  fi
done

if rg -n --fixed-strings "$PROOF_FEATURE" "${existing_shipping_paths[@]}"; then
  echo "shipping configuration must not enable or name $PROOF_FEATURE" >&2
  exit 1
fi

echo "Chat protocol production-proof containment policy passed"
