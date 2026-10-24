#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
selection=${1:?usage: fuzz-security.sh TARGET|asan [smoke|campaign|replay] [--cache-managed]}
mode=${2:-smoke}
cleanup=true
case ${3:-} in
  '') ;;
  --cache-managed) cleanup=false ;;
  *) printf 'Unknown cleanup option: %s\n' "$3" >&2; exit 2 ;;
esac
targets=("$selection")
if [[ "$selection" == asan ]]; then
  targets=(xmldsig_verify xml_semantics security_roundtrip transform_parameters xslt_execution key_formats policy_compilation provider_operations)
fi
case "$mode" in
  # Smoke replays the whole evolving corpus under ASan; an optimized build with
  # debug assertions keeps overflow checks while replaying ~20x faster than --dev.
  smoke) arguments=(); build=(--debug-assertions) ;;
  campaign) arguments=(-max_total_time=600); build=(--codegen-units 16) ;;
  replay) arguments=(-runs=0); build=(--dev) ;;
  *) printf 'Unknown fuzz mode: %s\n' "$mode" >&2; exit 2 ;;
esac
available=$(cargo +nightly fuzz list)
for target in "${targets[@]}"; do
  if ! printf '%s\n' "$available" | grep -Fxq -- "$target"; then
    printf 'Unknown fuzz target: %s\n' "$target" >&2
    exit 2
  fi
done
base_output=${FUZZ_OUTPUT:-$root/fuzz/evidence/$selection}
output=$base_output
finish() {
  status=$?
  trap - EXIT
  if [[ -f fuzz/Cargo.lock ]]; then
    cp fuzz/Cargo.lock "$output/Cargo.lock" || status=1
  fi
  if (( status == 0 )) && [[ "$cleanup" == true ]]; then
    cargo +nightly clean --manifest-path fuzz/Cargo.toml || status=$?
  fi
  exit "$status"
}
trap finish EXIT

for target in "${targets[@]}"; do
corpus="$root/fuzz/corpus/$target"
output=$base_output
if [[ "$selection" == asan ]]; then output="$base_output/$target"; fi
crashes="$root/fuzz/artifacts/$target"
mkdir -p "$corpus" "$output" "$crashes"
# Selection metadata, not a recursive import of every third-party fixture.
# Source files retain their repository provenance and licence notices.
while IFS=$'\t' read -r selected source; do
  [[ -n "$selected" && "$selected" != \#* ]] || continue
  [[ "$selected" == "$target" ]] || continue
  [[ -f "$source" ]] || { printf 'Missing seed: %s\n' "$source" >&2; exit 2; }
  digest=$(shasum -a 256 "$source")
  cp "$source" "$corpus/seed-${digest%% *}"
done < fuzz/seeds.tsv

if [[ "$mode" == smoke ]]; then
  # Seed execution counts toward libFuzzer's -runs. Reserve the requested new
  # mutations in addition to every retained seed and the initial empty input.
  count=$(find "$corpus" -type f -print0 | tr -cd '\000' | wc -c)
  arguments=("-runs=$((count + 257))")
fi

git rev-parse HEAD > "$output/revision.txt"
git status --short --untracked-files=normal > "$output/worktree.txt"
rustc +nightly -Vv > "$output/toolchain.txt"
features=()
sanitizer=address
if [[ "${FUZZ_AWS_LC_FIPS:-0}" == 1 ]]; then
  features=(--features aws-lc-fips)
  # AWS-LC disables FIPS integrity checks in ASAN builds; keep the real FIPS
  # module here and retain ASAN in the separate RustCrypto campaign.
  # https://github.com/aws/aws-lc-rs/blob/v1.18.1/aws-lc-rs/src/lib.rs#L443-L447
  sanitizer=none
fi
# Bash 3.2 treats an empty array as unset under nounset; preserve zero arguments.
printf '%q ' cargo +nightly fuzz run "$target" "${build[@]}" ${features[@]+"${features[@]}"} --sanitizer "$sanitizer" "$corpus" -- \
  "${arguments[@]}" -max_len=65536 -timeout=30 -rss_limit_mb=2048 \
  "-artifact_prefix=$crashes/" > "$output/command.txt"
printf '\n' >> "$output/command.txt"
# Pipefail preserves crashes/timeouts. Failed runs retain artifacts and build
# output for diagnosis. A block shares compilation until every target completes;
# cache-managed CI saves dependencies before its registered post action cleans.
cargo +nightly fuzz run "$target" "${build[@]}" ${features[@]+"${features[@]}"} --sanitizer "$sanitizer" "$corpus" -- \
  "${arguments[@]}" -max_len=65536 -timeout=30 -rss_limit_mb=2048 \
  "-artifact_prefix=$crashes/" 2>&1 | tee "$output/run.log"
if [[ -f fuzz/Cargo.lock ]]; then cp fuzz/Cargo.lock "$output/Cargo.lock"; fi
done
