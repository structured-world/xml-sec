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
    replace_target "$staging" "$target"
  else
    mkdir -p "$(dirname "$target")"
    install -m 0644 "$source" "$target"
  fi
done
