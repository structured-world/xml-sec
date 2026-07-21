#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
donor_root="${XMLSEC_DONOR_ROOT:-$repo_root/donors/xmlsec/tests}"
fixture_root="$repo_root/tests/fixtures"

fixture_paths=("$@")
if (( ${#fixture_paths[@]} == 0 )); then
  fixture_paths=(
    "xmldsig/aleksey-xmldsig-01/enveloping-rsa-x509chain.xml"
  )
fi

for relative_path in "${fixture_paths[@]}"; do
  donor_path="${relative_path#xmldsig/}"
  if [[ "$relative_path" == xmlenc/* ]]; then
    donor_path="${relative_path#xmlenc/}"
  fi
  target="$fixture_root/$relative_path"
  mkdir -p "$(dirname "$target")"
  install -m 0644 "$donor_root/$donor_path" "$target"
done
