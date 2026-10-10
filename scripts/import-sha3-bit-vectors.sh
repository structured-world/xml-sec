#!/usr/bin/env bash
# Import the independent NIST CAVP bit-oriented regression corpus unchanged.
set -euo pipefail
root="$(git rev-parse --show-toplevel)"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
url='https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha-3bittestvectors.zip'
curl --fail --location "$url" --output "$stage/vectors.zip"
actual="$(shasum -a 256 "$stage/vectors.zip")"
expected='339454bb4b96e299fefcad403797523f1952462a28d2418c108aea30263643ae'
if [[ "${actual%% *}" != "$expected" ]]; then
    printf '%s\n' 'NIST SHA-3 archive changed; review provenance before importing.' >&2
    exit 1
fi
mkdir "$stage/testdata"
for width in 224 256 384 512; do
    unzip -p "$stage/vectors.zip" "SHA3_${width}ShortMsg.rsp" > "$stage/testdata/SHA3_${width}ShortMsg.rsp"
done
destination="$root/src/rustcrypto_sha3/testdata"
if [[ -d "$destination" ]]; then
    diff -qr "$stage/testdata" "$destination"
else
    mv "$stage/testdata" "$destination"
fi
