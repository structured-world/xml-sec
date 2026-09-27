#!/usr/bin/env bash

set -euo pipefail

base="${1:?base commit or tag is required}"
git rev-parse --verify "${base}^{commit}" >/dev/null

for manifest in \
  vendor/sxd-document-no-unsafe/Cargo.toml \
  vendor/sxd-xpath-no-unsafe/Cargo.toml \
  crates/xml-sec-xml-input/Cargo.toml \
  crates/xml-sec-xslt/Cargo.toml; do
  directory="${manifest%/Cargo.toml}"
  if ! git cat-file -e "${base}:${manifest}" 2>/dev/null; then
    continue # A crate added by this change has no prior version to compare.
  fi
  if git diff --quiet "${base}" HEAD -- "${directory}"; then
    continue
  fi
  old_version="$(git show "${base}:${manifest}" | awk -F '"' '/^version = "/ { print $2; exit }')"
  new_version="$(awk -F '"' '/^version = "/ { print $2; exit }' "${manifest}")"
  if [[ -z "${old_version}" || -z "${new_version}" ]]; then
    echo "cannot determine support-crate version in ${manifest}" >&2
    exit 1
  fi
  if [[ "${old_version}" == "${new_version}" ]]; then
    echo "${directory} changed without a version bump (${new_version}); crates.io versions are immutable" >&2
    exit 1
  fi
done

# A bumped support crate must also become the consumer's minimum registry version.
# Otherwise an existing Cargo.lock can continue selecting the older published code.
metadata="$(cargo metadata --no-deps --format-version 1 --offline)"
while IFS=$'\t' read -r consumer dependency requirement; do
  version="$(jq -r --arg name "$dependency" '.packages[] | select(.name == $name) | .version' <<< "$metadata")"
  if [[ -z "$version" || "$requirement" != "^${version}" ]]; then
    echo "${consumer} requires ${dependency} ${requirement}; expected ^${version} for the workspace support crate" >&2
    exit 1
  fi
done < <(
  jq -r '
    .packages[] as $consumer
    | $consumer.dependencies[]
    | select(.path != null)
    | select(.name == "xml-sec-sxd-document" or .name == "xml-sec-sxd-xpath" or .name == "xml-sec-xml-input" or .name == "xml-sec-xslt")
    | [$consumer.name, .name, .req] | @tsv
  ' <<< "$metadata"
)
