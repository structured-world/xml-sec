#!/usr/bin/env bash
# Per-case child processes make RSS/CPU observations independent of earlier cases.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
output=${1:?usage: benchmark-security.sh OUTPUT_DIR [SAMPLES] [EXTRA_FEATURES]}
samples=${2:-1000}
if [[ ! $samples =~ ^[0-9]{1,6}$ ]] || (( 10#$samples < 1 || 10#$samples > 100000 )); then
  printf 'Samples must be an integer in 1..=100000.\n' >&2
  exit 2
fi
samples=$((10#$samples))
features=benchmark-internals
if [[ -n ${3:-} ]]; then features="$features,$3"; fi
if [[ -e $output ]]; then
  printf 'Output directory already exists: %s\n' "$output" >&2
  exit 2
fi
mkdir -p "$output"
output=$(cd "$output" && pwd)
case "$(uname -s)" in
  Darwin) time_args=(-l) ;;
  Linux) time_args=(-v) ;;
  *) printf 'RSS runner requires macOS or Linux; Divan works independently.\n' >&2; exit 2 ;;
esac
source_identity() {
  git rev-parse HEAD
  git diff --binary HEAD -- Cargo.toml src benches examples scripts
  shasum -a 256 Cargo.toml benches/security.rs benches/support/mod.rs examples/benchmark_latency.rs scripts/benchmark-security.sh src/benchmark_support.rs src/xml/dom/benchmark.rs
}
source_identity > "$output/source-identity.txt"
{
  git rev-parse HEAD
  git status --porcelain
  git diff --stat
  shasum -a 256 Cargo.toml benches/security.rs benches/support/mod.rs examples/benchmark_latency.rs scripts/benchmark-security.sh src/benchmark_support.rs src/xml/dom/benchmark.rs src/xml/dom/roxmltree.rs src/xml/dom/xmloxide.rs
  rustc -Vv
  uname -a
  uptime
  printf 'features=%s samples=%s\n' "$features" "$samples"
  if command -v sysctl >/dev/null; then sysctl -n machdep.cpu.brand_string || true; fi
} > "$output/environment.txt"
command -v jq >/dev/null || { printf 'The measurement runner requires jq.\n' >&2; exit 2; }
cargo build --release --example benchmark_latency --features "$features" --message-format=json > "$output/build.jsonl"
# Direct child execution must preserve Cargo's native library search paths,
# especially the dynamically linked AWS-LC FIPS module on macOS.
native_paths=$(jq -rs '[.[] | select(.reason == "build-script-executed") | .linked_paths[] | select(startswith("native=") or startswith("all=")) | split("=")[1: ] | join("=")] | unique | join(":")' "$output/build.jsonl")
loader_env=()
if [[ -n $native_paths ]]; then
  # macOS protected /usr/bin/time strips DYLD_* from its inherited environment;
  # restore it in the child immediately before exec, outside operation timing.
  case "$(uname -s)" in
    Darwin) loader_env=(/usr/bin/env "DYLD_LIBRARY_PATH=$native_paths${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}") ;;
    Linux) loader_env=(/usr/bin/env "LD_LIBRARY_PATH=$native_paths${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}") ;;
  esac
fi
# Persist the resolved graph: this repository does not track the workspace lockfile.
cp Cargo.lock "$output/Cargo.lock"
cargo metadata --locked --features "$features" --format-version 1 > "$output/dependencies.json"
binary=${CARGO_TARGET_DIR:-target}/release/examples/benchmark_latency
"${loader_env[@]}" "$binary" --list > "$output/cases.txt"
while read -r operation shape units backend provider; do
  name="$operation-$shape-$units-$backend-$provider"
  /usr/bin/time "${time_args[@]}" "${loader_env[@]}" "$binary" "$operation" "$shape" "$units" "$backend" "$provider" "$samples" > "$output/$name.json" 2> "$output/$name.resources.txt"
done < "$output/cases.txt"
# Allocation counters perturb time. Their timing columns are never the latency baseline.
cargo bench --locked --bench security --features "$features" -- --sample-count "$samples" --sample-size 1 > "$output/divan-timing.txt"
cargo bench --locked --bench security --features "$features,benchmark-alloc" -- --sample-count "$samples" --sample-size 1 > "$output/divan-allocations.txt"
source_identity > "$output/source-identity-after.txt"
if ! cmp -s "$output/source-identity.txt" "$output/source-identity-after.txt" || ! cmp -s Cargo.lock "$output/Cargo.lock"; then
  printf 'Source or dependency graph changed during measurement; discard this run.\n' >&2
  exit 3
fi
