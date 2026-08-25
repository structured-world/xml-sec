#!/usr/bin/env bash

set -euo pipefail

package="${1:?package name is required}"
version="$(
  cargo metadata --no-deps --format-version 1 |
    jq -r --arg package "${package}" '.packages[] | select(.name == $package) | .version'
)"

if [[ -z "${version}" ]]; then
  echo "workspace package ${package} was not found" >&2
  exit 1
fi

published() {
  # Without an explicit registry Cargo resolves the checked-out workspace
  # package and falsely reports an unpublished release as already available.
  cargo info --registry crates-io "${package}@${version}" >/dev/null 2>&1
}

wait_until_published() {
  for attempt in $(seq 1 30); do
    if published; then
      return 0
    fi
    echo "${package} ${version} is not visible yet (attempt ${attempt}/30)"
    sleep 10
  done
  return 1
}

if published; then
  echo "${package} ${version} is already published"
  exit 0
fi

# crates.io can accept an immutable upload before Cargo times out waiting for
# the sparse index. Distinguish that state from a real publish failure so a
# workflow rerun never attempts to upload the same version again.
publish_succeeded=false
if cargo publish -p "${package}"; then
  publish_succeeded=true
fi

if wait_until_published; then
  if [[ "${publish_succeeded}" == false ]]; then
    echo "${package} ${version} became visible after the publish command failed"
  fi
  exit 0
fi

echo "${package} ${version} was not published" >&2
exit 1
