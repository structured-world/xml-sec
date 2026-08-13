#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
donor_tests="${XMLSEC_DONOR_ROOT:-$repo_root/donors/xmlsec/tests}"
target="$repo_root/tools/xmlsec1/tests/fixtures/upstream"
mode="${1:-import}"
if [[ "$mode" != "import" && "$mode" != "--check" ]]; then
  printf 'usage: %s [--check]\n' "$0" >&2
  exit 2
fi
mkdir -p "$(dirname "$target")"
staging="$(mktemp -d "${target}.import.XXXXXX")"

cleanup() {
  rm -rf "$staging"
}
trap cleanup EXIT

assets=(
  "testrun.sh"
  "testDSig.sh"
  "testEnc.sh"
  "testKeys.sh"
  "phaos-xmldsig-three/signature-rsa-enveloped-bad-digest-val.xml"
  "phaos-xmldsig-three/certs/rsa-ca-cert.der"
  "xmlenc11-interop-2012/xenc11-example-AES128-GCM.xml"
  "xmlenc11-interop-2012/xenc11-example-AES128-GCM.tmpl"
  "xmlenc11-interop-2012/xenc11-example-AES128-GCM.data"
  "xmlenc11-interop-2012/xenc11-example-AES128-GCM.key"
)

for asset in "${assets[@]}"; do
  source="$donor_tests/$asset"
  if [[ ! -f "$source" ]]; then
    printf 'pinned donor asset is missing: %s\n' "$source" >&2
    exit 1
  fi
  mkdir -p "$staging/$(dirname "$asset")"
  mode=0644
  if [[ "$asset" == *.sh ]]; then
    mode=0755
  fi
  install -m "$mode" "$source" "$staging/$asset"
done

printf '%s\n' "$(<"$repo_root/compatibility/libxmlsec1-1.3.13-donor-commit.txt")" \
  > "$staging/DONOR_COMMIT"

backup="${target}.backup.$$"
if [[ "$mode" == "--check" ]]; then
  diff --recursive --brief "$target" "$staging"
  exit
fi
if [[ -e "$target" ]]; then
  mv "$target" "$backup"
fi
if mv "$staging" "$target"; then
  rm -rf "$backup"
else
  if [[ -e "$backup" ]]; then
    mv "$backup" "$target"
  fi
  exit 1
fi
