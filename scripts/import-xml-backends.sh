#!/usr/bin/env bash
set -euo pipefail

# Keep maintained parser sources inside the published package. Cargo [patch]
# entries would only protect this checkout, not downstream applications.
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
backend="${1:?usage: import-xml-backends.sh roxmltree|xmloxide [--import|--verify|--refresh-patch]}"
mode="${2:---import}"
case "$backend" in
  roxmltree)
    version=0.21.1
    checksum=f1964b10c76125c36f8afe190065a4bf9a87bf324842c05701330bba9f1cacbb
    files=(lib.rs parse.rs tokenizer.rs tokenizer_tests.rs)
    notices=(README.md LICENSE-APACHE LICENSE-MIT)
    ;;
  xmloxide)
    version=0.5.0
    checksum=58666a3723753360aa92f2eda5c6f5392285c6d7f063b4c2b07f47c697a22b47
    # XML parsing only: HTML, schema validation, XPath and acquisition are not
    # this backend's responsibility. Its existing XML/DTD kernel is retained.
    files=(lib.rs parser/mod.rs parser/input.rs parser/xml.rs parser/push.rs
      tree/mod.rs tree/node.rs error/mod.rs encoding/mod.rs
      validation/mod.rs validation/dtd.rs serial/mod.rs serial/xml.rs)
    notices=(README.md LICENSE)
    ;;
  *) printf 'unknown backend: %s\n' "$backend" >&2; exit 2 ;;
esac
case "$mode" in
  --import|--verify|--refresh-patch) ;;
  *) printf 'unknown mode: %s\n' "$mode" >&2; exit 2 ;;
esac
target="$root/src/parser_$backend"
delta="$root/scripts/patches/$backend-$version.patch"
if [[ "$mode" == --import && -e "$target" ]]; then
  printf 'refusing to overwrite maintained parser: %s\n' "$target" >&2
  exit 1
fi
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
archive="$scratch/source.crate"
cache="${CARGO_HOME:-$HOME/.cargo}/registry/cache"
cached=()
if [[ -d "$cache" ]]; then
  while IFS= read -r candidate; do cached+=("$candidate"); done < <(
    find "$cache" -mindepth 2 -maxdepth 2 -name "$backend-$version.crate" -type f
  )
fi
if [[ ${#cached[@]} -gt 0 ]]; then
  install -m 0644 "${cached[0]}" "$archive"
else
  curl --fail --location --retry 3 \
    "https://static.crates.io/crates/$backend/$backend-$version.crate" -o "$archive"
fi
printf '%s  %s\n' "$checksum" "$archive" | shasum -a 256 --check
tar -xf "$archive" -C "$scratch"
source="$scratch/$backend-$version"
if [[ "$mode" == --refresh-patch ]]; then
  perl "$root/scripts/xml-kernel-examples.pl" "$backend" "$target" "${files[@]}"
  rustfmt --edition 2024 "$target/documentation_tests.rs"
  : > "$scratch/delta.patch"
  for file in "${files[@]}"; do
    if diff -u --label "a/$backend/src/$file" --label "b/$backend/src/$file" \
      "$source/src/$file" "$target/$file" >> "$scratch/delta.patch"; then
      :
    else
      status=$?
      if [[ "$status" != 1 ]]; then exit "$status"; fi
    fi
  done
  install -m 0644 "$scratch/delta.patch" "$delta"
  printf 'Generated maintained delta: %s\n' "$delta"
  exit 0
fi
if [[ -s "$delta" ]]; then
  patch --batch --forward --strip=3 --directory="$source/src" < "$delta"
fi
perl "$root/scripts/xml-kernel-examples.pl" "$backend" "$source/src" "${files[@]}"
rustfmt --edition 2024 "$source/src/documentation_tests.rs"
files+=(documentation_tests.rs)
if [[ "$mode" == --verify ]]; then
  for file in "${files[@]}"; do diff -u "$source/src/$file" "$target/$file"; done
  for file in "${notices[@]}"; do diff -u "$source/$file" "$target/$file"; done
  printf 'Verified maintained %s %s source.\n' "$backend" "$version"
  exit 0
fi
for file in "${files[@]}"; do
  mkdir -p "$target/$(dirname "$file")"
  install -m 0644 "$source/src/$file" "$target/$file"
done
for file in "${notices[@]}"; do install -m 0644 "$source/$file" "$target/$file"; done
printf 'Imported %s %s (%s).\n' "$backend" "$version" "$checksum"
