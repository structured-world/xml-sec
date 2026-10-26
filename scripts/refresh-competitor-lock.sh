#!/usr/bin/env bash
# The competitor lockfile pins Bergshamra but also records the xml-sec crate the
# project builds from this checkout. Refresh only that entry, and fail when the
# refresh would move any other locked package: a product dependency the locked
# graph cannot satisfy changes the competitor's graph, which is a reviewed
# lockfile change, not a side effect of a run.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
manifest="$root/benchmarks/competitors/Cargo.toml"
lock="$root/benchmarks/competitors/Cargo.lock"
# Every [[package]] block except xml-sec's; Cargo.lock separates blocks by blank lines.
others() { awk 'BEGIN { RS = "" } !/^\[\[package\]\]\nname = "xml-sec"\n/' "$lock"; }
before=$(others)
cargo update --manifest-path "$manifest" -p xml-sec
[[ $before == "$(others)" ]] || {
  printf 'Refreshing xml-sec changed other entries of %s; update and commit that lockfile deliberately\n' "$lock" >&2
  exit 1
}
