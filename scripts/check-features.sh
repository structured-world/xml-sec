#!/usr/bin/env bash
# Isolate the core package: workspace feature unification can hide broken gates.
set -euo pipefail
profile=${1:?pass a documented feature profile}
phase=${2:-all}
case "$phase" in all|lint|test|doc) ;; *) echo "unknown phase: $phase" >&2; exit 2 ;; esac
# This library repository intentionally does not track a Cargo.lock file.
args=(-p xml-sec)
tests=(--lib)
features=
case "$profile" in
    default) tests+=(--test rust_api) ;;
    dom-xmloxide) features=xml-backend-xmloxide ;;
    dom-roxmltree) features=xml-backend-roxmltree ;;
    c14n-xmloxide) features=c14n,xml-backend-xmloxide ;;
    c14n-roxmltree) features=c14n,xml-backend-roxmltree ;;
    dsig-xmloxide) features=xmldsig,xml-backend-xmloxide ;;
    dsig-roxmltree) features=xmldsig,xml-backend-roxmltree ;;
    xmlenc-xmloxide) features=xmlenc,xml-backend-xmloxide ;;
    xmlenc-roxmltree) features=xmlenc,xml-backend-roxmltree ;;
    xslt) features=xslt,xml-backend-xmloxide ;;
    legacy) features=xmldsig,legacy-algorithms,xml-backend-xmloxide ;;
    experimental) features=experimental-pq,xml-backend-xmloxide ;;
    fips-dsig) features=aws-lc-fips,xml-backend-xmloxide; tests+=(--test aws_lc_provider) ;;
    pkcs11) features=pkcs11,xml-backend-xmloxide ;;
    no-backend)
        diagnostic=$(mktemp "${TMPDIR:-/tmp}/xml-sec-no-backend.XXXXXXXX")
        trap 'rm -f "$diagnostic"' EXIT
        if cargo check -p xml-sec --lib --no-default-features >"$diagnostic" 2>&1; then
            echo "missing XML backend unexpectedly compiled" >&2
            exit 1
        fi
        cat "$diagnostic"
        grep -F 'compile at least one XML backend' "$diagnostic" >/dev/null
        exit 0
        ;;
    *) echo "unknown feature profile: $profile" >&2; exit 2 ;;
esac
if [[ -n "$features" ]]; then
    args+=(--no-default-features --features "$features")
fi
case "$profile" in
    default|dom-*|c14n-*) ;;
    *) tests+=(--test rust_api) ;;
esac
if [[ "$profile" == pkcs11 && ( "$phase" == all || "$phase" == test ) ]]; then
    : "${PKCS11_MODULE:?pass an explicit disposable-test SoftHSM module via PKCS11_MODULE}"
fi
if [[ "$phase" == all || "$phase" == lint ]]; then
    # clippy before 1.94 reports the libtest descriptor array of a large test
    # crate as a spanless large_stack_arrays finding (rust-lang/rust-clippy#13774,
    # fixed by rust-lang/rust-clippy#16347); newer clippy keeps the check.
    harness_lint=()
    rustc_minor=$(rustc --version)
    rustc_minor=${rustc_minor#rustc 1.}
    rustc_minor=${rustc_minor%%.*}
    if (( rustc_minor < 94 )); then
        harness_lint=(-A clippy::large_stack_arrays)
    fi
    # Bash 3.2 treats an empty array expansion as unset under nounset.
    cargo clippy "${args[@]}" --all-targets -- -D warnings ${harness_lint[@]+"${harness_lint[@]}"}
fi
if [[ "$phase" == all || "$phase" == test ]]; then
    if [[ "$profile" == pkcs11 ]]; then
        bash scripts/test-pkcs11.sh "$PKCS11_MODULE" "${args[@]}" "${tests[@]}"
    else
        cargo nextest run "${args[@]}" "${tests[@]}"
    fi
fi
if [[ "$phase" == all || "$phase" == doc ]]; then
    cargo test --doc "${args[@]}"
fi
