#!/usr/bin/env bash
# Run the actual WASM C14N and XMLDSig verification paths rather than treating
# compilation as execution.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly root
readonly manifest="$root/tests/wasm-smoke/Cargo.toml"
cargo build --manifest-path "$manifest" --target-dir "$root/target/wasm-smoke" \
  --target wasm32-unknown-unknown
node --input-type=module - "$root/target/wasm-smoke/wasm32-unknown-unknown/debug/xml_sec_wasm_smoke.wasm" <<'JS'
import { readFile } from 'node:fs/promises';
import assert from 'node:assert/strict';
const bytes = await readFile(process.argv[2]);
const { instance } = await WebAssembly.instantiate(bytes);
assert.equal(instance.exports.xml_sec_wasm_smoke(), 1, 'WASM canonicalization must produce exact expected bytes');
console.log('WASM C14N execution passed');
assert.equal(instance.exports.xml_sec_wasm_verify(), 1, 'WASM XMLDSig verification must accept the signed response and reject tampering');
console.log('WASM XMLDSig verification passed');
JS
