#!/usr/bin/env bash
# Regenerate the delta CRL fixtures of tests/delta_crl.rs.
#
# OpenSSL acts as an independent certificate authority: it issues one complete
# CRL and two delta CRLs against it, one silent and one revoking the leaf. Its
# own verifier checks both pairs here, so the fixtures carry its answer. It only
# reads a delta for a certificate that has freshestCRL (RFC 5280 4.2.1.15).
#
# Usage: scripts/generate-delta-crl-fixtures.sh
# DELTA_CRL_FIXTURE_OUTPUT optionally selects an absolute output directory.
# Requires OpenSSL 3.4 or later for fixed certificate validity dates.
set -euo pipefail

repository="$(cd "$(dirname "$0")/.." && pwd)"
output="${DELTA_CRL_FIXTURE_OUTPUT:-$repository/tests/fixtures/x509/delta-crl}"
mkdir -p "$output"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"

NOT_BEFORE=20260101000000Z
NOT_AFTER=20450101000000Z
# 2040-01-01T00:00:00Z, after any revocation made while generating.
VERIFICATION_TIME=2208988800

cat >ca.cnf <<'EOF'
[ca]
default_ca = authority

[authority]
database = index.txt
crlnumber = crlnumber
default_md = sha256
crl_extensions = complete

[complete]
authorityKeyIdentifier = keyid

[delta]
authorityKeyIdentifier = keyid
2.5.29.27 = critical,ASN1:INTEGER:5
EOF
: >index.txt
echo 05 >crlnumber

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ca.key 2>/dev/null
openssl req -x509 -new -key ca.key -out ca.pem \
  -not_before "$NOT_BEFORE" -not_after "$NOT_AFTER" \
  -subj "/CN=xml-sec Test Delta CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out leaf.key 2>/dev/null
openssl req -x509 -new -key leaf.key -CA ca.pem -CAkey ca.key -out leaf.pem \
  -not_before "$NOT_BEFORE" -not_after "$NOT_AFTER" \
  -subj "/CN=xml-sec Test Delta Leaf" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "freshestCRL=URI:https://example.test/delta.crl" 2>/dev/null

# list <file> <extension section>: the next CRL of this authority.
list() {
  openssl ca -gencrl -config ca.cnf -keyfile ca.key -cert ca.pem \
    -crlexts "$2" -crl_lastupdate "$NOT_BEFORE" -crl_nextupdate "$NOT_AFTER" \
    -out "$1"
}

list complete.pem complete
list silent.pem delta
openssl ca -revoke leaf.pem -config ca.cnf -keyfile ca.key -cert ca.pem 2>/dev/null
list revoking.pem delta

# accepted <delta>: the verifier's answer for the leaf under that pair.
accepted() {
  openssl verify -CAfile ca.pem -CRLfile complete.pem -CRLfile "$1" \
    -crl_check -use_deltas -attime "$VERIFICATION_TIME" leaf.pem >/dev/null 2>&1
}

accepted silent.pem
if accepted revoking.pem; then
  echo "OpenSSL accepted a leaf its delta CRL revokes" >&2
  exit 1
fi

openssl x509 -in ca.pem -outform DER -out "$output/ca.der"
openssl x509 -in leaf.pem -outform DER -out "$output/leaf.der"
for name in complete silent revoking; do
  openssl crl -in "$name.pem" -outform DER -out "$output/$name.crl"
done
