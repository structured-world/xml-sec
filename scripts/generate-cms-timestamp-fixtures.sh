#!/usr/bin/env bash
# Regenerate the RFC 3161 timestamp fixtures of tests/cms_timestamp.rs.
#
# OpenSSL acts as an independent time-stamping authority. For each key type it
# issues a self-signed TSA certificate with the critical timeStamping extended
# key usage (RFC 3161 §2.3). `openssl ts` stamps the payload with RSA and ECDSA
# keys. Its PKCS #7 signer supports neither Ed25519 nor RSA-PSS, so for those
# keys `openssl cms` signs the TSTInfo of the RSA token as id-ct-TSTInfo
# content, with the ESS signingCertificateV2 attribute (-cades). Trust in the
# TSA is outside these fixtures; they exercise CMS signature and imprint checks.
#
# Usage: scripts/generate-cms-timestamp-fixtures.sh
# CMS_FIXTURE_OUTPUT optionally selects an absolute output directory.
# Requires OpenSSL 3.4 or later for fixed certificate validity dates.
set -euo pipefail

repository="$(cd "$(dirname "$0")/.." && pwd)"
output="${CMS_FIXTURE_OUTPUT:-$repository/tests/fixtures/cms/timestamp}"
mkdir -p "$output"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"

NOT_BEFORE=20260101000000Z
NOT_AFTER=20450101000000Z
TST_INFO=1.2.840.113549.1.9.16.1.4

printf 'Time-stamped payload\n' >payload.txt
cp payload.txt "$output/payload.txt"
openssl ts -query -data payload.txt -sha256 -cert -no_nonce -out payload.tsq 2>/dev/null

cat >ts.cnf <<'EOF'
[tsa]
default_tsa = tsa_config

[tsa_config]
serial = ./serial
crypto_device = builtin
signer_digest = sha256
default_policy = 1.3.6.1.4.1.55555.1
digests = sha256, sha384, sha512
accuracy = secs:1
ordering = no
tsa_name = no
ess_cert_id_chain = no
ess_cert_id_alg = sha256
EOF

# authority <name> <openssl genpkey arguments...>
authority() {
  local name="$1"
  shift
  openssl genpkey "$@" -out "$name.key" 2>/dev/null
  openssl req -x509 -new -key "$name.key" -out "$name.pem" \
    -not_before "$NOT_BEFORE" -not_after "$NOT_AFTER" \
    -subj "/CN=xml-sec Test TSA $name" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "keyUsage=critical,digitalSignature" \
    -addext "extendedKeyUsage=critical,timeStamping" 2>/dev/null
  openssl x509 -in "$name.pem" -outform DER -out "$output/$name.der"
}

# stamp <name>: an `openssl ts` token signed by that authority.
stamp() {
  echo 01 >serial
  openssl ts -reply -config ts.cnf -queryfile payload.tsq \
    -signer "$1.pem" -inkey "$1.key" -token_out -out "$output/$1.tst" 2>/dev/null
}

# resign <name> <openssl cms -sign options...>: the RSA token's TSTInfo signed
# by that authority.
resign() {
  local name="$1"
  shift
  openssl cms -sign -binary -nodetach -in tstinfo.der -econtent_type "$TST_INFO" \
    -signer "$name.pem" -inkey "$name.key" -cades -nosmimecap "$@" \
    -outform DER -out "$output/$name.tst"
}

authority rsa -algorithm RSA -pkeyopt rsa_keygen_bits:2048
stamp rsa
authority ecdsa-p256 -algorithm EC -pkeyopt ec_paramgen_curve:P-256
stamp ecdsa-p256

openssl cms -verify -noverify -inform DER -in "$output/rsa.tst" -out tstinfo.der 2>/dev/null
authority ed25519 -algorithm ED25519
resign ed25519 -md sha512
authority rsa-pss -algorithm RSA -pkeyopt rsa_keygen_bits:2048
resign rsa-pss -md sha256 -keyopt rsa_padding_mode:pss -keyopt rsa_pss_saltlen:32
