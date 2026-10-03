#!/usr/bin/env bash
set -euo pipefail

# Import the released, checksum-verified source. Refuse to overwrite a patched
# checkout: an update must explicitly review and reapply the upstream delta.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="0.1.1"
checksum="add6b9d92e496f16f4526d68ff29da1483aba4b119baeab8bed3b9e3544a6f3d"
target="$repo_root/src/rustcrypto_ml_dsa"
patch_file="$repo_root/scripts/patches/ml-dsa-$version.patch"
mode="${1:---import}"
case "$mode" in
  --import|--verify|--refresh-patch) ;;
  *) printf 'usage: %s [--import|--verify|--refresh-patch]\n' "$0" >&2; exit 2 ;;
esac
if [[ "$mode" == --import && -e "$target" ]]; then
  printf 'source already exists; inspect the maintained patch before importing again: %s\n' "$target" >&2
  exit 1
fi
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
curl --fail --location --retry 3 "https://static.crates.io/crates/ml-dsa/ml-dsa-$version.crate" -o "$scratch/source.crate"
printf '%s  %s\n' "$checksum" "$scratch/source.crate" | shasum -a 256 --check
tar -xf "$scratch/source.crate" -C "$scratch"
source="$scratch/ml-dsa-$version"
files=(lib.rs algebra.rs crypto.rs encode.rs hint.rs ntt.rs param.rs pkcs8.rs sampling.rs signing.rs verifying.rs)
if [[ "$mode" == --refresh-patch ]]; then
  # This is a generated delta against the checksum-pinned release, not a second
  # hand-maintained implementation. Inspect the delta whenever the donor changes.
  : > "$scratch/delta.patch"
  for file in "${files[@]}"; do
    if diff -u --label "a/ml-dsa/src/$file" --label "b/ml-dsa/src/$file" \
      "$source/src/$file" "$target/$file" >> "$scratch/delta.patch"; then
      :
    else
      status=$?
      if [[ "$status" != 1 ]]; then exit "$status"; fi
    fi
  done
  mkdir -p "$(dirname "$patch_file")"
  install -m 0644 "$scratch/delta.patch" "$patch_file"
  printf 'Generated maintained delta: %s\n' "$patch_file"
  exit 0
fi
patch --batch --forward --strip=3 --directory="$source/src" < "$patch_file"
if [[ "$mode" == --verify ]]; then
  for file in "${files[@]}"; do
    diff -u "$source/src/$file" "$target/$file"
  done
  for file in README.md LICENSE-APACHE LICENSE-MIT; do
    diff -u "$source/$file" "$target/$file"
  done
  printf 'Verified maintained RustCrypto ml-dsa %s source.\n' "$version"
  exit 0
fi
mkdir -p "$target"
for file in "${files[@]}"; do
  install -m 0644 "$source/src/$file" "$target/$file"
done
for file in README.md LICENSE-APACHE LICENSE-MIT; do
  install -m 0644 "$source/$file" "$target/$file"
done
printf 'Imported RustCrypto ml-dsa %s (%s).\n' "$version" "$checksum"
