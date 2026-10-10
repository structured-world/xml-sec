#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
output=${1:?usage: benchmark-compare.sh NEW_OUTPUT_DIR [SAMPLES] [--heap]}
samples=${2:-30}
heap=${3:-}
[[ ! -e $output ]] || { printf 'Output already exists\n' >&2; exit 2; }
[[ $samples =~ ^[0-9]{1,4}$ ]] && (( 10#$samples >= 1 && 10#$samples <= 1000 )) || { printf 'Invalid sample count\n' >&2; exit 2; }
[[ -z $heap || $heap == --heap ]] || { printf 'Unknown profiling mode\n' >&2; exit 2; }
revision=$(cat compatibility/bergshamra-0.9.2-benchmark-commit.txt)
[[ $revision =~ ^[0-9a-f]{40}$ ]]
source=${BERGSHAMRA_SOURCE_DIR:-$root/.tools/benchmark-bergshamra-$revision}
if [[ ! -e $source ]]; then
  git init "$source"
  git -C "$source" remote add origin https://github.com/kushaldas/bergshamra.git
  git -C "$source" fetch --depth=1 origin "$revision"
  git -C "$source" checkout --detach "$revision"
fi
[[ $(git -C "$source" rev-parse HEAD) == "$revision" ]]
[[ -z $(git -C "$source" status --porcelain) ]] || { printf 'Competitor checkout must be clean\n' >&2; exit 2; }
target=${CARGO_TARGET_DIR:-$root/target}
[[ $target == /* ]] || target="$root/$target"
export XML_SEC_BENCH_BIN="$target/release/xmlsec1"
export BENCH_EXPORT_BIN="$target/release/examples/benchmark_latency"
export BERGSHAMRA_BIN="$target/competitors/bergshamra/release/bergshamra"
export XMLSEC1_PREFIX=${XMLSEC1_PREFIX:-$root/.tools/xmlsec1-1.3.13-$(cut -c1-12 compatibility/libxmlsec1-1.3.13-donor-commit.txt)}
export XMLSEC1_BIN="$XMLSEC1_PREFIX/bin/xmlsec1"
bash scripts/install-xmlsec1.sh
# Both Rust binaries use the same declared compiler, including in containers
# where the project's `stable` override would otherwise download another one.
export RUSTUP_TOOLCHAIN=${BENCH_RUST_TOOLCHAIN:-1.92.0}
source_identity() {
  git ls-files -c -o --exclude-standard -z -- Cargo.toml rust-toolchain.toml src crates vendor benches examples scripts benchmarks compatibility/bergshamra-0.9.2-benchmark-commit.txt compatibility/libxmlsec1-1.3.13-donor-commit.txt tests/fixtures/keys/rsa |
    sort -zu | xargs -0 shasum -a 256
}
before=$(source_identity)
# The library repository does not track Cargo.lock. Resolve once, then freeze
# the resulting graph for measurement and retain it with the evidence.
cargo build --release --bin xmlsec1 --example benchmark_latency --features benchmark-internals
cargo build --release --locked --manifest-path "$source/Cargo.toml" -p bergshamra --no-default-features --features rustcrypto --target-dir "$target/competitors/bergshamra"
[[ $before == "$(source_identity)" ]] || { printf 'Source changed during build; discard binaries\n' >&2; exit 3; }
locks_before=$(shasum -a 256 Cargo.lock "$source/Cargo.lock")
case "$(uname -s)" in
  Darwin) export DYLD_LIBRARY_PATH="$XMLSEC1_PREFIX/lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" ;;
  Linux) export LD_LIBRARY_PATH="$XMLSEC1_PREFIX/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" ;;
esac
node scripts/compare-security.mjs "$output" "$samples" "$heap"
after=$(source_identity)
[[ $before == "$after" ]] || { printf 'Source changed during measurement; discard results\n' >&2; exit 3; }
[[ $locks_before == "$(shasum -a 256 Cargo.lock "$source/Cargo.lock")" ]] || { printf 'Dependency graph changed during measurement; discard results\n' >&2; exit 3; }
cp Cargo.lock "$output/xml-sec.Cargo.lock"
cp "$source/Cargo.lock" "$output/bergshamra.Cargo.lock"
printf '%s\n' "$before" > "$output/source-sha256.txt"
cargo metadata --locked --features benchmark-internals --format-version 1 > "$output/xml-sec.dependencies.json"
cargo metadata --locked --manifest-path "$source/Cargo.toml" --no-default-features --features rustcrypto --format-version 1 > "$output/bergshamra.dependencies.json"
{
  printf 'bergshamra=%s\nlibxmlsec1=%s\n' "$revision" "$(cat compatibility/libxmlsec1-1.3.13-donor-commit.txt)"
  rustc -Vv
  printf 'RUSTFLAGS=%s\nCFLAGS=%s\n' "${RUSTFLAGS:-}" "${CFLAGS:-}"
  cc --version
  if [[ $heap == --heap ]]; then valgrind --version; fi
  uname -a
  uptime
  if [[ $(uname -s) == Darwin ]]; then
    otool -L "$XMLSEC1_BIN"
  else
    ldd "$XMLSEC1_BIN"
  fi
} > "$output/build-environment.txt"
