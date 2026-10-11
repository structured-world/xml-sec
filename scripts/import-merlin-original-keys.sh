#!/usr/bin/env bash
# Recover original published credentials without changing the pinned donor.
set -euo pipefail
root="$(git rev-parse --show-toplevel)"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
url='https://lists.w3.org/Archives/Public/xml-encryption/2002Mar/att-0008/merlin-xmlenc-five.tar.gz'
curl --fail --location "$url" --output "$stage/original.tar.gz"
actual="$(shasum -a 256 "$stage/original.tar.gz")"
expected='219d984ed14a83543d8eebc13d69178988890c2d35bc9d9115562e4d6f8055bb'
if [[ "${actual%% *}" != "$expected" ]]; then
    printf '%s\n' 'Merlin archive changed; review provenance before importing.' >&2
    exit 1
fi
mkdir "$stage/keys"
for name in dh0.p8 dh1.p8 dsa.p8 rsa.p8 ids.p12 Readme.txt plaintext.txt; do
    tar -xOf "$stage/original.tar.gz" "merlin-xmlenc-five/$name" > "$stage/keys/$name"
done
destination="$root/tests/fixtures/xmlenc/merlin-original-keys"
if [[ -d "$destination" ]]; then
    diff -qr "$stage/keys" "$destination"
else
    mv "$stage/keys" "$destination"
fi
