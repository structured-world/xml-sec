#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
donor_root="${XMLSEC_DONOR_ROOT:-$repo_root/donors/xmlsec/tests}"
fixture_root="$repo_root/tests/fixtures"

replace_target() {
  local replacement="$1"
  local target="$2"
  local target_parent target_name backup=""
  target_parent="$(dirname "$target")"
  target_name="$(basename "$target")"

  if [[ -e "$target" || -L "$target" ]]; then
    backup="$(mktemp -d "$target_parent/.${target_name}.backup.XXXXXX")"
    rm -rf "$backup"
    if ! mv "$target" "$backup"; then
      rm -rf "$replacement"
      return 1
    fi
  fi

  if mv "$replacement" "$target"; then
    if [[ -n "$backup" ]]; then
      rm -rf "$backup"
    fi
    return 0
  fi

  rm -rf "$replacement"
  if [[ -n "$backup" ]] && ! mv "$backup" "$target"; then
    printf 'failed to restore fixture target after replacement failure: %s\n' "$target" >&2
  fi
  return 1
}

normalize_imported_snapshot() {
  local relative_path="$1"
  local staging="$2"
  local donor

  if [[ "$relative_path" == "xmldsig/merlin-xmldsig-twenty-three" ]]; then
    # The donor README contains unresolved placeholders and is not executable
    # fixture data. Keep the imported corpus curated rather than publishing
    # upstream prose as project documentation.
    rm -f "$staging/Readme.txt"

    # xmlsec 1.3.13's historical "-40" filenames contain an 80-bit HMAC,
    # matching XMLDSig 1.1's security floor. Normalize only the local names;
    # file contents remain byte-for-byte donor data.
    for extension in tmpl xml; do
      donor="$staging/signature-enveloping-hmac-sha1-40.$extension"
      if [[ ! -f "$donor" ]]; then
        printf 'donor snapshot no longer provides %s; update normalize_imported_snapshot\n' \
          "${donor##*/}" >&2
        return 1
      fi
      normalized="$staging/signature-enveloping-hmac-sha1-80.$extension"
      if [[ -e "$normalized" ]]; then
        printf 'donor snapshot provides both historical and normalized HMAC fixtures: %s\n' \
          "${normalized##*/}" >&2
        return 1
      fi
      if ! mv "$donor" "$normalized"; then
        printf 'failed to normalize donor fixture: %s\n' "${donor##*/}" >&2
        return 1
      fi
    done
  fi
}

fixture_paths=("$@")
if (( ${#fixture_paths[@]} == 0 )); then
  fixture_paths=(
    "xmldsig/aleksey-xmldsig-01/enveloping-rsa-x509chain.xml"
    "xmldsig/aleksey-xmldsig-01/enveloped-x509-digest-sha256.xml"
    "xmldsig/merlin-xmldsig-twenty-three"
    "xmldsig/external-data/xml-stylesheet-2005"
    "xmldsig/external-data/xml-stylesheet-2005.b64"
    "xmlenc/aleksey-xmlenc-01/enc-aes128cbc-keyname.tmpl"
    "xmlenc/aleksey-xmlenc-01/enc-aes128gcm-keyname.tmpl"
    "xmlenc/aleksey-xmlenc-01/enc-aes256cbc-keyname.tmpl"
    "xmlenc/aleksey-xmlenc-01/enc-aes256gcm-keyname.tmpl"
    "xmlenc/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha1-params.tmpl"
    "xmlenc/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_enc11_sha512_mgf1_sha512.tmpl"
  )
fi

for relative_path in "${fixture_paths[@]}"; do
  # Normalize directory notation before deriving source and target prefixes.
  while [[ "$relative_path" == */ ]]; do
    relative_path="${relative_path%/}"
  done
  case "$relative_path" in
    xmldsig/*) donor_path="${relative_path#xmldsig/}" ;;
    xmlenc/*) donor_path="${relative_path#xmlenc/}" ;;
    *)
      printf 'fixture path must start with xmldsig/ or xmlenc/: %s\n' "$relative_path" >&2
      exit 1
      ;;
  esac
  if [[ -z "$donor_path"
    || "$donor_path" == /*
    || "$donor_path" == *//*
    || "/$donor_path/" == *"/./"*
    || "/$donor_path/" == *"/../"* ]]; then
    printf 'fixture path contains an empty, current, or parent component: %s\n' "$relative_path" >&2
    exit 1
  fi
  target="$fixture_root/$relative_path"
  source="$donor_root/$donor_path"
  if [[ -d "$source" ]]; then
    # Build the complete snapshot before replacing the last known-good target.
    target_parent="$(dirname "$target")"
    target_name="$(basename "$target")"
    mkdir -p "$target_parent"
    staging="$(mktemp -d "$target_parent/.${target_name}.import.XXXXXX")"
    manifest="$(mktemp "$target_parent/.${target_name}.files.XXXXXX")"
    if ! find "$source" -type f -print0 > "$manifest"; then
      rm -rf "$staging" "$manifest"
      exit 1
    fi
    copy_failed=false
    while IFS= read -r -d '' donor_file; do
      suffix="${donor_file#"$source/"}"
      target_file="$staging/$suffix"
      if ! mkdir -p "$(dirname "$target_file")" \
        || ! install -m 0644 "$donor_file" "$target_file"; then
        copy_failed=true
        break
      fi
    done < "$manifest"
    rm -f "$manifest"
    if [[ "$copy_failed" == true ]]; then
      rm -rf "$staging"
      exit 1
    fi
    if ! normalize_imported_snapshot "$relative_path" "$staging"; then
      rm -rf "$staging"
      exit 1
    fi
    replace_target "$staging" "$target"
  else
    target_parent="$(dirname "$target")"
    target_name="$(basename "$target")"
    mkdir -p "$target_parent"
    staging="$(mktemp "$target_parent/.${target_name}.import.XXXXXX")"
    if ! install -m 0644 "$source" "$staging"; then
      rm -f "$staging"
      exit 1
    fi
    replace_target "$staging" "$target"
  fi
done
