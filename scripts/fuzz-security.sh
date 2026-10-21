#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
target=${1:?usage: fuzz-security.sh TARGET [smoke|campaign|replay]}
mode=${2:-smoke}
case "$mode" in
  smoke) arguments=(); build=(--dev) ;;
  campaign) arguments=(-max_total_time=600); build=(--codegen-units 16) ;;
  replay) arguments=(-runs=0); build=(--dev) ;;
  *) printf 'Unknown fuzz mode: %s\n' "$mode" >&2; exit 2 ;;
esac
available=$(cargo +nightly fuzz list)
if ! printf '%s\n' "$available" | grep -Fxq -- "$target"; then
  printf 'Unknown fuzz target: %s\n' "$target" >&2
  exit 2
fi
corpus="$root/fuzz/corpus/$target"
output=${FUZZ_OUTPUT:-$root/fuzz/evidence/$target}
crashes="$root/fuzz/artifacts/$target"
mkdir -p "$corpus" "$output" "$crashes"
finish() {
  status=$?
  trap - EXIT
  if [[ -f fuzz/Cargo.lock ]]; then
    cp fuzz/Cargo.lock "$output/Cargo.lock" || status=1
  fi
  if (( status == 0 )); then
    cargo +nightly clean --manifest-path fuzz/Cargo.toml || status=$?
  fi
  exit "$status"
}
trap finish EXIT

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
if [[ "${FUZZ_AWS_LC_FIPS:-0}" == 1 ]]; then
  features=(--features aws-lc-fips)
fi
printf '%q ' cargo +nightly fuzz run "$target" "${build[@]}" "${features[@]}" "$corpus" -- \
  "${arguments[@]}" -max_len=65536 -timeout=30 -rss_limit_mb=2048 \
  "-artifact_prefix=$crashes/" > "$output/command.txt"
printf '\n' >> "$output/command.txt"
# Pipefail preserves crashes/timeouts. Failed runs retain artifacts and build
# output for diagnosis; successful campaigns immediately remove only this crate's output.
cargo +nightly fuzz run "$target" "${build[@]}" "${features[@]}" "$corpus" -- \
  "${arguments[@]}" -max_len=65536 -timeout=30 -rss_limit_mb=2048 \
  "-artifact_prefix=$crashes/" 2>&1 | tee "$output/run.log"
