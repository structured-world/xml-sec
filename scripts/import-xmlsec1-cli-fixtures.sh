#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
donor_tests="${XMLSEC_DONOR_ROOT:-$repo_root/donors/xmlsec/tests}"
target="${XMLSEC_FIXTURE_TARGET:-$repo_root/tools/xmlsec1/tests/fixtures/upstream}"
operation="${1:-import}"
if [[ "$operation" != "import" && "$operation" != "--check" ]]; then
  printf 'usage: %s [--check]\n' "$0" >&2
  exit 2
fi
mkdir -p "$(dirname "$target")"
staging="$(mktemp -d "${target}.import.XXXXXX")"
backup=""

cleanup() {
  local status="${1:-$?}"
  trap - EXIT INT TERM HUP
  rm -rf "$staging"
  if [[ -n "$backup" && -e "$backup" ]]; then
    if [[ -e "$target" ]]; then
      rm -rf "$backup"
    elif ! mv "$backup" "$target"; then
      printf 'failed to restore fixture snapshot from %s\n' "$backup" >&2
      status=1
    fi
  fi
  exit "$status"
}
trap 'cleanup $?' EXIT
trap 'cleanup 130' INT
trap 'cleanup 143' TERM
trap 'cleanup 129' HUP

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

donor_commit_file="$repo_root/compatibility/libxmlsec1-1.3.13-donor-commit.txt"
if [[ ! -s "$donor_commit_file" ]]; then
  printf 'donor commit pin is missing or empty: %s\n' "$donor_commit_file" >&2
  exit 1
fi
donor_commit="$(<"$donor_commit_file")"
if [[ ! "$donor_commit" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]]; then
  printf 'donor commit pin is not a Git object ID: %s\n' "$donor_commit_file" >&2
  exit 1
fi
if ! donor_repo="$(git -C "$donor_tests" rev-parse --show-toplevel 2>/dev/null)" ||
   ! donor_head="$(git -C "$donor_tests" rev-parse HEAD 2>/dev/null)"; then
  printf 'donor tests must belong to a Git checkout: %s\n' "$donor_tests" >&2
  exit 1
fi
if [[ "$(cd "$donor_tests" && pwd -P)" != "$(cd "$donor_repo/tests" && pwd -P)" ]]; then
  printf 'donor root must be the tests directory of its Git checkout: %s\n' "$donor_tests" >&2
  exit 1
fi
if [[ "$donor_head" != "$donor_commit" ]]; then
  printf 'donor checkout revision %s does not match pin %s\n' "$donor_head" "$donor_commit" >&2
  exit 1
fi

for asset in "${assets[@]}"; do
  source="$donor_tests/$asset"
  if [[ ! -f "$source" ]]; then
    printf 'pinned donor asset is missing: %s\n' "$source" >&2
    exit 1
  fi
  mkdir -p "$staging/$(dirname "$asset")"
  file_mode=0644
  if [[ "$asset" == *.sh ]]; then
    file_mode=0755
  fi
  if ! git -C "$donor_repo" ls-files --error-unmatch "tests/$asset" >/dev/null 2>&1 ||
     ! git -C "$donor_repo" diff --quiet "$donor_commit" -- "tests/$asset"; then
    printf 'pinned donor asset has uncommitted changes: %s\n' "$source" >&2
    exit 1
  fi
  install -m "$file_mode" "$source" "$staging/$asset"
done

printf '%s\n' "$donor_commit" > "$staging/DONOR_COMMIT"

backup="${target}.backup.$$"
if [[ "$operation" == "--check" ]]; then
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
