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
# A rejected refresh puts the lockfile back, so a rerun cannot take the
# rewritten graph as its baseline and accept what this run refused.
saved=$(mktemp)
trap 'rm -f "$saved"' EXIT
cp "$lock" "$saved"
reject() { cp "$saved" "$lock"; printf '%s\n' "$1" >&2; exit 1; }
before=$(others)
cargo update --manifest-path "$manifest" -p xml-sec || reject "Refreshing xml-sec in $lock failed"
[[ $before == "$(others)" ]] ||
  reject "Refreshing xml-sec changed other entries of $lock; update and commit that lockfile deliberately"
