#!/usr/bin/env bash
set -euo pipefail

# Check the released mechanism's alloc graph independently: the XMLDSig
# workspace currently activates std on unrelated Unicode dependencies.
readonly repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Discovery also resolves a fresh checkout's ignored workspace lockfile.
# The independent registry-package qualification below remains locked.
readonly manifest="$(cargo metadata --manifest-path "$repo_root/Cargo.toml" --format-version 1 |
  jq -er '.packages | map(select(.name == "structured-pkix")) |
    if length == 1 and (.[0].source | startswith("registry+"))
    then .[0].manifest_path else error("expected one registry PKIX package") end')"
readonly target_dir="$repo_root/target/shared-pkix-alloc"

if [[ "$manifest" != */registry/src/*/structured-pkix-*/Cargo.toml ]]; then
  printf 'shared PKIX qualification requires the published registry package\n' >&2
  exit 1
fi

for target in thumbv7em-none-eabihf wasm32-unknown-unknown; do
  cargo check --manifest-path "$manifest" --locked --no-default-features \
    --features alloc --target "$target" --target-dir "$target_dir"
done
