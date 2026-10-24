#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
cleanup=true
case ${1:-} in
  '') ;;
  --cache-managed) cleanup=false ;;
  *) printf 'Unknown conformance option: %s\n' "$1" >&2; exit 2 ;;
esac
: "${LIBXSLT_SOURCE_DIR:?set the pinned libxslt source checkout}"
: "${XMLSEC1_BIN:?set the explicitly provisioned xmlsec1 oracle}"
oracle_prefix=$(cd "$(dirname "$XMLSEC1_BIN")/.." && pwd)
pinned=$(cat compatibility/libxmlsec1-1.3.13-donor-commit.txt)
[[ -f "$oracle_prefix/.xmlsec-source-commit" ]] &&
  [[ "$(cat "$oracle_prefix/.xmlsec-source-commit")" == "$pinned" ]] || {
  printf 'Oracle source provenance must match the pinned installer revision\n' >&2
  exit 1
}
version=$("$XMLSEC1_BIN" --version)
[[ "$version" == 'xmlsec1 1.3.13 '* ]] || {
  printf 'Expected xmlsec1 1.3.13, got %s\n' "$version" >&2
  exit 1
}
transforms=$("$XMLSEC1_BIN" --list-transforms)
[[ "$transforms" == *'"xslt"'* ]] || {
  printf 'The oracle must provide its XSLT transform\n' >&2
  exit 1
}

# Developer case slicing is useful for diagnosis, never for a conformance gate.
unset XML_SEC_LIBXSLT_CASE_RANGE XML_SEC_LIBXSLT_CASE
bash scripts/import-libxslt-oracle-fixtures.sh --check
cargo nextest run -p xml-sec-xslt --no-fail-fast
# The admitted oracle may live under target; retain it for both parts of this
# gate so cleanup cannot silently disable reciprocal interoperability checks.
cargo nextest run -p xml-sec --features xslt,xml-backends-all \
  --test xslt_transform_integration --test xmlsec1_interop \
  --test donor_interop_suite --test merlin_interop --test phaos_interop \
  --test capability_ledger -E 'not binary(xmlsec1_interop) or test(xslt)' --no-fail-fast
if [[ "$cleanup" == true ]]; then cargo clean; fi
printf 'XSLT conformance: engine, Recommendation examples, donor signatures and reciprocal oracle passed\n'
