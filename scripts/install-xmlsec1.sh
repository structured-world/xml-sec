#!/usr/bin/env bash
set -euo pipefail

readonly repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly XMLSEC1_VERSION="1.3.13"
readonly XMLSEC1_COMMIT="$(<"$repo_root/compatibility/libxmlsec1-1.3.13-donor-commit.txt")"
readonly XMLSEC1_REPOSITORY="https://github.com/lsh123/xmlsec.git"

if [[ ! "$XMLSEC1_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
  printf 'invalid xmlsec1 donor commit: %s\n' "$XMLSEC1_COMMIT" >&2
  exit 1
fi

prefix="${XMLSEC1_PREFIX:-$repo_root/.tools/xmlsec1-${XMLSEC1_VERSION}-${XMLSEC1_COMMIT:0:12}}"
marker="$prefix/.xmlsec-source-commit"

xmlsec_version_output() {
  if [[ "$(uname -s)" == "Darwin" ]]; then
    DYLD_LIBRARY_PATH="$prefix/lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" \
      "$prefix/bin/xmlsec1" --version
  else
    LD_LIBRARY_PATH="$prefix/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
      "$prefix/bin/xmlsec1" --version
  fi
}

xmlsec_version_is_expected() {
  local output="$1"
  local program=""
  local version=""
  read -r program version _ <<< "$output" || true
  [[ "$program" == "xmlsec1" && "$version" == "$XMLSEC1_VERSION" ]]
}

if [[ "$prefix" != /* ]]; then
  printf 'XMLSEC1_PREFIX must be an absolute path: %s\n' "$prefix" >&2
  exit 1
fi

if [[ -x "$prefix/bin/xmlsec1" && -f "$marker" ]] \
  && [[ "$(<"$marker")" == "$XMLSEC1_COMMIT" ]]; then
  if version_output="$(xmlsec_version_output)" \
    && xmlsec_version_is_expected "$version_output"; then
    printf '%s\n' "$version_output"
    printf 'xmlsec1 %s is already installed at %s\n' "$XMLSEC1_VERSION" "$prefix"
    exit 0
  fi
  printf 'cached xmlsec1 at %s failed version validation; rebuilding\n' "$prefix" >&2
fi

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/xmlsec1-${XMLSEC1_VERSION}.XXXXXX")"
previous_install="$work_dir/previous-install"
previous_install_staged=false
promoted_install=false

cleanup() {
  local status=$?
  local remove_work_dir=true
  trap - EXIT

  # Keep replacement transactional through the version smoke test. The
  # staged move is not a commit if installation or validation fails.
  if (( status != 0 )); then
    if [[ "$promoted_install" == true ]]; then
      rm -rf "$prefix"
    fi
    if [[ "$previous_install_staged" == true ]]; then
      if ! mv "$previous_install" "$prefix"; then
        printf 'failed to restore previous xmlsec1 installation at %s; backup remains at %s\n' \
          "$prefix" "$previous_install" >&2
        status=1
        remove_work_dir=false
      fi
    fi
  fi
  if [[ "$remove_work_dir" == true ]]; then
    rm -rf "$work_dir"
  fi
  exit "$status"
}
trap cleanup EXIT
source_dir="$work_dir/xmlsec"
build_dir="$work_dir/build"
stage_dir="$work_dir/stage"

if [[ -n "${XMLSEC1_SOURCE_DIR:-}" ]]; then
  local_source_dir="$XMLSEC1_SOURCE_DIR"
  if [[ "$local_source_dir" != /* || ! -d "$local_source_dir" ]]; then
    printf 'XMLSEC1_SOURCE_DIR must be an absolute git checkout: %s\n' "$local_source_dir" >&2
    exit 1
  fi
  if [[ "$(git -C "$local_source_dir" rev-parse --is-inside-work-tree 2>/dev/null)" != "true" ]]; then
    printf 'XMLSEC1_SOURCE_DIR must be an absolute git checkout: %s\n' "$local_source_dir" >&2
    exit 1
  fi
  source_commit="$(git -C "$local_source_dir" rev-parse HEAD)"
  if [[ "$source_commit" != "$XMLSEC1_COMMIT" ]]; then
    printf 'xmlsec1 source revision mismatch: expected %s, got %s\n' \
      "$XMLSEC1_COMMIT" "$source_commit" >&2
    exit 1
  fi
  mkdir -p "$source_dir"
  # Configure/autoreconf writes generated files into the source tree. Export
  # the verified commit so a CI checkout remains immutable and reusable by
  # ledger and fixture checks.
  git -C "$local_source_dir" archive "$XMLSEC1_COMMIT" | tar -x -C "$source_dir"
else
  git init "$source_dir"
  git -C "$source_dir" remote add origin "$XMLSEC1_REPOSITORY"
  git -C "$source_dir" fetch --depth=1 origin "$XMLSEC1_COMMIT"
  fetched_commit="$(git -C "$source_dir" rev-parse FETCH_HEAD)"
  if [[ "$fetched_commit" != "$XMLSEC1_COMMIT" ]]; then
    printf 'xmlsec1 source revision mismatch: expected %s, got %s\n' \
      "$XMLSEC1_COMMIT" "$fetched_commit" >&2
    exit 1
  fi
  git -C "$source_dir" checkout --detach "$XMLSEC1_COMMIT"
fi

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
  previous_install_staged=true
fi
mv "$staged_prefix" "$prefix"
promoted_install=true

version_output="$(xmlsec_version_output)"
if ! xmlsec_version_is_expected "$version_output"; then
  printf 'xmlsec1 version mismatch: expected xmlsec1 %s, got %s\n' \
    "$XMLSEC1_VERSION" "${version_output:-<empty output>}" >&2
  exit 1
fi
printf '%s\n' "$version_output"
printf '%s\n' "$XMLSEC1_COMMIT" > "$marker"

rm -rf "$previous_install"
previous_install_staged=false

printf 'installed xmlsec1 %s snapshot %s at %s\n' \
  "$XMLSEC1_VERSION" "${XMLSEC1_COMMIT:0:12}" "$prefix"
