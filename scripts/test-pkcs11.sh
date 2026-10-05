#!/usr/bin/env bash
# Token initialization is permitted only inside this isolated disposable store.
set -euo pipefail
module=${1:?pass the explicit SoftHSM module path}
shift
store=$(mktemp -d "${TMPDIR:-/tmp}/xml-sec-pkcs11.XXXXXXXX")
trap 'rm -rf "$store"' EXIT
mkdir "$store/tokens"
printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' "$store" > "$store/softhsm.conf"
export SOFTHSM2_CONF="$store/softhsm.conf"
export XML_SEC_PKCS11_TEST_MODULE="$module"
export XML_SEC_PKCS11_TEST_STORE="$store"
if [[ ${1:-} == --workspace ]]; then
    shift
    cargo nextest run --workspace --features pkcs11 "$@"
else
    cargo nextest run --features pkcs11 --test pkcs11 "$@" --no-capture
fi
