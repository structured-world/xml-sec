#!/usr/bin/env bash
# Qualify the published core contract and execute the examples users actually read.
set -euo pipefail
phase=${1:-all}
case "$phase" in all|docs) ;; *) echo "unknown documentation phase: $phase" >&2; exit 2 ;; esac
RUSTDOCFLAGS="${RUSTDOCFLAGS:-} -D warnings -D missing-docs" \
    cargo doc -p xml-sec -p xml-sec-config --all-features --no-deps
if [[ "$phase" == docs ]]; then exit 0; fi
cargo test --doc --workspace --all-features
cargo nextest run -p xml-sec-config --test documentation
cargo run --quiet -p xml-sec --example policy_roundtrip
store=$(mktemp -d "${TMPDIR:-/tmp}/xml-sec-doc-examples.XXXXXXXX")
trap 'rm -rf "$store"' EXIT
cargo run --quiet -p xml-sec --example sign >"$store/signed.xml"
cargo run --quiet -p xml-sec --example verify -- "$store/signed.xml" \
    tests/fixtures/keys/rsa/rsa-2048-pubkey.pem invoice-2026-07
sed 's/42\.00/99.00/' "$store/signed.xml" >"$store/tampered.xml"
grep -F '99.00' "$store/tampered.xml" >/dev/null
if cargo run --quiet -p xml-sec --example verify -- "$store/tampered.xml" \
    tests/fixtures/keys/rsa/rsa-2048-pubkey.pem invoice-2026-07 >"$store/rejection" 2>&1; then
    echo "verification example accepted tampered signed content" >&2
    exit 1
fi
# A compiler/setup error is not proof of a cryptographic rejection.
grep -F 'expected target was not authenticated' "$store/rejection" >/dev/null
cargo run --quiet -p xml-sec --example encrypt >"$store/encrypted.xml"
cargo run --quiet -p xml-sec-cli --bin xmlsec1 -- policy check \
    --file docs/examples/policy-v1.toml --profile tenant --target-evidence
