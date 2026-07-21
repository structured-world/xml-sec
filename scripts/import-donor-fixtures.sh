#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
donor_root="${XMLSEC_DONOR_ROOT:-$repo_root/donors/xmlsec/tests}"
fixture_root="$repo_root/tests/fixtures"

fixture_paths=("$@")
if (( ${#fixture_paths[@]} == 0 )); then
  fixture_paths=(
    "xmldsig/aleksey-xmldsig-01/enveloping-rsa-x509chain.xml"
    "xmlenc/aleksey-xmlenc-01/enc-aes128cbc-keyname.tmpl"
    "xmlenc/aleksey-xmlenc-01/enc-aes128gcm-keyname.tmpl"
    "xmlenc/aleksey-xmlenc-01/enc-aes256cbc-keyname.tmpl"
    "xmlenc/aleksey-xmlenc-01/enc-aes256gcm-keyname.tmpl"
    "xmlenc/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha1-params.tmpl"
    "xmlenc/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_enc11_sha512_mgf1_sha512.tmpl"
  )
fi

for relative_path in "${fixture_paths[@]}"; do
  case "$relative_path" in
    xmldsig/*) donor_path="${relative_path#xmldsig/}" ;;
    xmlenc/*) donor_path="${relative_path#xmlenc/}" ;;
    *)
      printf 'fixture path must start with xmldsig/ or xmlenc/: %s\n' "$relative_path" >&2
      exit 1
      ;;
  esac
  if [[ -z "$donor_path" || "/$donor_path/" == *"/../"* ]]; then
    printf 'fixture path must not be empty or contain ..: %s\n' "$relative_path" >&2
    exit 1
  fi
  target="$fixture_root/$relative_path"
  source="$donor_root/$donor_path"
  if [[ -d "$source" ]]; then
    # A directory argument represents a complete donor snapshot. Recreate the
    # destination so upstream deletions cannot leave stale tracked fixtures.
    rm -rf "$target"
    mkdir -p "$target"
    while IFS= read -r -d '' donor_file; do
      suffix="${donor_file#"$source/"}"
      target_file="$target/$suffix"
      mkdir -p "$(dirname "$target_file")"
      install -m 0644 "$donor_file" "$target_file"
    done < <(find "$source" -type f -print0)
  else
    mkdir -p "$(dirname "$target")"
    install -m 0644 "$source" "$target"
  fi
done
