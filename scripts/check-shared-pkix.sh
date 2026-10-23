#!/usr/bin/env bash
set -euo pipefail

# Check the released mechanisms' alloc graphs independently: the XMLDSig
# workspace activates std and cannot qualify its shared dependencies' no_std path.
readonly repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Discovery also resolves a fresh checkout's ignored workspace lockfile.
# The independent registry-package qualification below remains locked.
manifests="$(cargo metadata --manifest-path "$repo_root/Cargo.toml" --format-version 1 |
  jq -er '.packages | map(select(.name == "structured-asn1" or .name == "structured-pkix" or
    .name == "structured-cms" or .name == "structured-ltv" or .name == "structured-xades")) as $shared |
    if ($shared | length) == 5 and
       ([$shared[].name] | sort) == ["structured-asn1", "structured-cms", "structured-ltv", "structured-pkix", "structured-xades"] and
       ([$shared[].version] | unique | length) == 1 and
       all($shared[]; (.source | type) == "string" and (.source | startswith("registry+")))
    then $shared[] | select(.name == "structured-pkix" or .name == "structured-xades") | .manifest_path
    else error("expected one coordinated registry ASN1/PKIX/CMS/LTV/XAdES graph") end')"
readonly manifests
readonly target_dir="$repo_root/target/shared-pkix-alloc"

while IFS= read -r manifest; do
  case "$manifest" in
    */registry/src/*/structured-pkix-*/Cargo.toml|*/registry/src/*/structured-xades-*/Cargo.toml) ;;
    *) printf 'shared qualification requires published registry packages\n' >&2; exit 1 ;;
  esac
  for target in thumbv7em-none-eabihf wasm32-unknown-unknown; do
    cargo check --manifest-path "$manifest" --locked --no-default-features \
      --features alloc --target "$target" --target-dir "$target_dir"
  done
done <<< "$manifests"
