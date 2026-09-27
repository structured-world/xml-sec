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
  if ! jq -ne --arg old "$old_version" --arg new "$new_version" '
    def parsed:
      capture("^(?<major>0|[1-9][0-9]*)\\.(?<minor>0|[1-9][0-9]*)\\.(?<patch>0|[1-9][0-9]*)(?:-(?<pre>[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*))?(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?$")
      | {core: [.major, .minor, .patch] | map(tonumber), pre: (.pre // "" | if . == "" then [] else split(".") end)};
    def prerelease_lt($a; $b):
      if ($a | length) == 0 then false
      elif ($b | length) == 0 then true
      else
        (reduce range(0; [($a | length), ($b | length)] | min) as $i
          (0; if . != 0 then . else
            ($a[$i] | test("^(0|[1-9][0-9]*)$")) as $an
            | ($b[$i] | test("^(0|[1-9][0-9]*)$")) as $bn
            | if $a[$i] == $b[$i] then 0
              elif $an and $bn then (($a[$i] | tonumber) < ($b[$i] | tonumber) | if . then -1 else 1 end)
              elif $an then -1 elif $bn then 1
              elif $a[$i] < $b[$i] then -1 elif $a[$i] > $b[$i] then 1 else 0 end
          end)) as $order
        | if $order == 0 then ($a | length) < ($b | length) else $order < 0 end
      end;
    try (($old | parsed) as $a | ($new | parsed) as $b |
      if $a.core == $b.core then prerelease_lt($a.pre; $b.pre)
      else $a.core < $b.core end) catch false
  ' >/dev/null; then
    echo "${directory} changed without a higher version (${old_version} -> ${new_version}); crates.io versions are immutable" >&2
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
