#!/usr/bin/env bash
set -euo pipefail

readonly XMLSEC1_VERSION="1.3.13"
readonly XMLSEC1_COMMIT="5fdd47dc35753438bdc38b6e96c1a3805c67a483"
readonly XMLSEC1_ARCHIVE_SHA256="0917b7304ee2452e2110a60d18e501825c132fa5857558e0308d40457fa0992f"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
prefix="${XMLSEC1_PREFIX:-$repo_root/.tools/xmlsec1-${XMLSEC1_VERSION}-${XMLSEC1_COMMIT:0:12}}"
marker="$prefix/.xmlsec-source-commit"

if [[ "$prefix" != /* ]]; then
  printf 'XMLSEC1_PREFIX must be an absolute path: %s\n' "$prefix" >&2
  exit 1
fi

if [[ -x "$prefix/bin/xmlsec1" && -f "$marker" ]] \
  && [[ "$(<"$marker")" == "$XMLSEC1_COMMIT" ]]; then
  printf 'xmlsec1 %s is already installed at %s\n' "$XMLSEC1_VERSION" "$prefix"
  exit 0
fi

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/xmlsec1-${XMLSEC1_VERSION}.XXXXXX")"
previous_install="$work_dir/previous-install"
had_previous_install=false

cleanup() {
  local status=$?
  local remove_work_dir=true
  trap - EXIT

  # Keep replacement transactional through the version smoke test. The
  # staged move is not a commit if installation or validation fails.
  if (( status != 0 )) && [[ "$had_previous_install" == true ]]; then
    rm -rf "$prefix"
    if ! mv "$previous_install" "$prefix"; then
      printf 'failed to restore previous xmlsec1 installation at %s; backup remains at %s\n' \
        "$prefix" "$previous_install" >&2
      status=1
      remove_work_dir=false
    fi
  fi
  if [[ "$remove_work_dir" == true ]]; then
    rm -rf "$work_dir"
  fi
  exit "$status"
}
trap cleanup EXIT
archive="$work_dir/xmlsec.tar.gz"
source_dir="$work_dir/xmlsec-$XMLSEC1_COMMIT"
build_dir="$work_dir/build"
stage_dir="$work_dir/stage"

curl --fail --location --retry 3 --output "$archive" \
  "https://codeload.github.com/lsh123/xmlsec/tar.gz/$XMLSEC1_COMMIT"

if command -v sha256sum >/dev/null 2>&1; then
  printf '%s  %s\n' "$XMLSEC1_ARCHIVE_SHA256" "$archive" | sha256sum --check -
else
  actual_sha256="$(shasum -a 256 "$archive" | awk '{print $1}')"
  if [[ "$actual_sha256" != "$XMLSEC1_ARCHIVE_SHA256" ]]; then
    printf 'xmlsec1 archive checksum mismatch: expected %s, got %s\n' \
      "$XMLSEC1_ARCHIVE_SHA256" "$actual_sha256" >&2
    exit 1
  fi
fi

tar --extract --file "$archive" --directory "$work_dir"
mkdir -p "$build_dir" "$stage_dir"
OBJ_DIR="$build_dir" "$source_dir/autogen.sh" \
  --prefix="$prefix" \
  --disable-static \
  --without-gnutls \
  --without-nss \
  --with-openssl

if command -v nproc >/dev/null 2>&1; then
  build_jobs="$(nproc)"
else
  build_jobs="$(sysctl -n hw.ncpu)"
fi
make --directory "$build_dir" --jobs "$build_jobs"
make --directory "$build_dir" install DESTDIR="$stage_dir"

staged_prefix="$stage_dir$prefix"
mkdir -p "$(dirname "$prefix")"
if [[ -e "$prefix" ]]; then
  mv "$prefix" "$previous_install"
  had_previous_install=true
fi
mv "$staged_prefix" "$prefix"
printf '%s\n' "$XMLSEC1_COMMIT" > "$marker"

if [[ "$(uname -s)" == "Darwin" ]]; then
  DYLD_LIBRARY_PATH="$prefix/lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" \
    "$prefix/bin/xmlsec1" --version
else
  LD_LIBRARY_PATH="$prefix/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
    "$prefix/bin/xmlsec1" --version
fi

rm -rf "$previous_install"
had_previous_install=false

printf 'installed xmlsec1 %s snapshot %s at %s\n' \
  "$XMLSEC1_VERSION" "${XMLSEC1_COMMIT:0:12}" "$prefix"
