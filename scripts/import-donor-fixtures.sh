#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
donor_root="$repo_root/donors/xmlsec/tests"
fixture_root="$repo_root/tests/fixtures/xmldsig"

fixture_paths=("$@")
if (( ${#fixture_paths[@]} == 0 )); then
  fixture_paths=(
    "aleksey-xmldsig-01/enveloping-rsa-x509chain.xml"
  )
fi

for relative_path in "${fixture_paths[@]}"; do
  target="$fixture_root/$relative_path"
  mkdir -p "$(dirname "$target")"
  install -m 0644 "$donor_root/$relative_path" "$target"
done
