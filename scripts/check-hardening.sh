#!/usr/bin/env bash
# Run from the workspace root; preserve coverage evidence outside build output.
set -euo pipefail
phase=${1:-all}
case "$phase" in all|coverage|dependencies|safety) ;; *) echo "unknown hardening phase: $phase" >&2; exit 2 ;; esac
if [[ "$phase" == all || "$phase" == dependencies ]]; then
    cargo deny --all-features check --config deny.toml advisories sources
    cargo deny --manifest-path fuzz/Cargo.toml --all-features check --config deny.toml advisories sources
fi
if [[ "$phase" == all || "$phase" == safety ]]; then
    # Diagnostic allocator probes in tests/benches are not native library code.
    cargo clippy --workspace --lib --all-features -- -D warnings -D unsafe_code
fi
if [[ "$phase" == all || "$phase" == coverage ]]; then
    output=${2:?pass a new coverage evidence directory outside target}
    : "${PKCS11_MODULE:?pass an explicit isolated-test SoftHSM module}"
    mkdir "$output"
    root=$(pwd -P)
    # One physical implementation is compiled both embedded and standalone.
    # Remap before instrumentation: LLVM must merge the executions, not a
    # postprocessor choosing the better of two independent percentages.
    flags=${CARGO_ENCODED_RUSTFLAGS:-}
    if [[ -z "$flags" && -n "${RUSTFLAGS:-}" ]]; then
        read -r -a words <<< "$RUSTFLAGS"
        for word in "${words[@]}"; do flags+="${flags:+$'\x1f'}$word"; done
    fi
    for alias in crates/xml-sec-xslt/../.. vendor/sxd-document-no-unsafe/../.. \
        vendor/sxd-xpath-no-unsafe/../.. crates/xml-sec-xml-input/src/../../..; do
        flags+="${flags:+$'\x1f'}--remap-path-prefix=$root/$alias=$root"
    done
    export CARGO_ENCODED_RUSTFLAGS=$flags
    # Keep first-install rustup output outside show-env's shell program.
    rustup component add llvm-tools-preview
    cargo llvm-cov clean --workspace
    environment=$(cargo llvm-cov show-env --sh)
    eval "$environment"
    bash scripts/test-pkcs11.sh "$PKCS11_MODULE" --workspace --all-features
    # show-env mode consumes the completed instrumented build. Select every
    # package explicitly: the report default covers only the root package.
    cargo llvm-cov report --package '*' --fail-under-lines 85 \
        --json --summary-only --output-path "$output/coverage.json"
    node scripts/check-coverage-report.mjs "$output/coverage.json"
    cargo llvm-cov report --package '*' --lcov --output-path "$output/coverage.lcov"
    git rev-parse HEAD > "$output/revision.txt"
    rustc -Vv > "$output/toolchain.txt"
fi
