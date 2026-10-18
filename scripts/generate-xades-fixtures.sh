#!/usr/bin/env bash
# Regenerate the XAdES baseline fixtures of crates/xml-sec-xades.
#
# OpenSSL issues a real root -> intermediate -> signer path. This script writes
# the XAdES qualifying properties; xmlsec1, an independent XMLDSig
# implementation, computes every reference digest and signature value.
# Adversarial fixtures are still valid XMLDSig signatures: only their XAdES
# properties violate EN 319 132-1.
#
# Usage: XMLSEC1_BIN=/path/to/xmlsec1 scripts/generate-xades-fixtures.sh
set -euo pipefail

repository="$(cd "$(dirname "$0")/.." && pwd)"
output="$repository/crates/xml-sec-xades/tests/fixtures"
xmlsec1="${XMLSEC1_BIN:-xmlsec1}"
# XADES_FIXTURE_WORK keeps the keys and templates for inspection.
if [ -n "${XADES_FIXTURE_WORK:-}" ]; then
  work="$XADES_FIXTURE_WORK"
  mkdir -p "$work"
else
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' EXIT
fi
cd "$work"

DS="http://www.w3.org/2000/09/xmldsig#"
XADES="http://uri.etsi.org/01903/v1.3.2#"
SIGNED_PROPERTIES="http://uri.etsi.org/01903#SignedProperties"
SHA256="http://www.w3.org/2001/04/xmlenc#sha256"
MD5="http://www.w3.org/2001/04/xmldsig-more#md5"
EXC_C14N="http://www.w3.org/2001/10/xml-exc-c14n#"
ENVELOPED="http://www.w3.org/2000/09/xmldsig#enveloped-signature"
RSA_SHA256="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

openssl req -x509 -newkey rsa:2048 -nodes -keyout root.key -out root.pem -days 7300 \
  -subj "/CN=xml-sec XAdES Test Root" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout intermediate.key -out intermediate.csr \
  -subj "/CN=xml-sec XAdES Test Intermediate" 2>/dev/null
printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' >intermediate.ext
openssl x509 -req -in intermediate.csr -CA root.pem -CAkey root.key -out intermediate.pem \
  -days 7000 -extfile intermediate.ext 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout signer.key -out signer.csr \
  -subj "/CN=xml-sec XAdES Test Signer" 2>/dev/null
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,nonRepudiation\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' >signer.ext
openssl x509 -req -in signer.csr -CA intermediate.pem -CAkey intermediate.key -out signer.pem \
  -days 6900 -extfile signer.ext 2>/dev/null

digest() { openssl x509 -in "$1" -outform DER | openssl dgst "-$2" -binary | openssl base64 -A; }
signer_sha256="$(digest signer.pem sha256)"
root_sha256="$(digest root.pem sha256)"
signer_md5="$(digest signer.pem md5)"

# signature ID, SignedProperties ID, data Reference, DataObjectFormat MIME,
# SigningTime, CertDigest method, CertDigest value, extra Cert attributes,
# QualifyingProperties Target, SignedProperties Reference Type attribute,
# Object elements preceding the qualifying properties, X509Data content,
# UnsignedProperties element.
signature() {
  local id="$1" properties="$2" data_reference="$3" mime="$4" time="$5"
  local method="$6" value="$7" cert_attributes="$8" target="$9" type="${10}"
  local objects="${11:-}" x509="${12:-<ds:X509Certificate/>}" unsigned="${13:-}"
  cat <<EOF
<ds:Signature xmlns:ds="$DS" Id="$id">
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="$EXC_C14N"/>
    <ds:SignatureMethod Algorithm="$RSA_SHA256"/>
    $data_reference
    <ds:Reference $type URI="#$properties">
      <ds:Transforms><ds:Transform Algorithm="$EXC_C14N"/></ds:Transforms>
      <ds:DigestMethod Algorithm="$SHA256"/>
      <ds:DigestValue/>
    </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue Id="$id-value"/>
  <ds:KeyInfo><ds:X509Data>$x509</ds:X509Data></ds:KeyInfo>
  $objects
  <ds:Object>
    <xades:QualifyingProperties xmlns:xades="$XADES" Target="$target">
      <xades:SignedProperties Id="$properties">
        <xades:SignedSignatureProperties>
          <xades:SigningTime>$time</xades:SigningTime>
          <xades:SigningCertificateV2>
            <xades:Cert$cert_attributes>
              <xades:CertDigest>
                <ds:DigestMethod Algorithm="$method"/>
                <ds:DigestValue>$value</ds:DigestValue>
              </xades:CertDigest>
            </xades:Cert>
          </xades:SigningCertificateV2>
        </xades:SignedSignatureProperties>
        <xades:SignedDataObjectProperties>
          <xades:DataObjectFormat ObjectReference="#$id-data">
            <xades:MimeType>$mime</xades:MimeType>
          </xades:DataObjectFormat>
        </xades:SignedDataObjectProperties>
      </xades:SignedProperties>
      $unsigned
    </xades:QualifyingProperties>
  </ds:Object>
</ds:Signature>
EOF
}

enveloped_reference() {
  cat <<EOF
<ds:Reference Id="$1-data" URI="">
      <ds:Transforms>
        <ds:Transform Algorithm="$ENVELOPED"/>
        <ds:Transform Algorithm="$EXC_C14N"/>
      </ds:Transforms>
      <ds:DigestMethod Algorithm="$SHA256"/>
      <ds:DigestValue/>
    </ds:Reference>
EOF
}

target_reference() {
  cat <<EOF
<ds:Reference Id="$1-data" URI="$2">
      <ds:Transforms><ds:Transform Algorithm="$EXC_C14N"/></ds:Transforms>
      <ds:DigestMethod Algorithm="$SHA256"/>
      <ds:DigestValue/>
    </ds:Reference>
EOF
}

detached_reference() {
  cat <<EOF
<ds:Reference Id="$1-data" URI="$2">
      <ds:DigestMethod Algorithm="$SHA256"/>
      <ds:DigestValue/>
    </ds:Reference>
EOF
}

# A plain XMLDSig countersignature over the parent's complete SignatureValue
# element (EN 319 132-1 §5.2.7.2).
counter_signature() {
  cat <<EOF
<xades:UnsignedProperties>
        <xades:UnsignedSignatureProperties>
          <xades:CounterSignature>
            <ds:Signature Id="$1">
              <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="$EXC_C14N"/>
                <ds:SignatureMethod Algorithm="$RSA_SHA256"/>
                <ds:Reference Type="http://uri.etsi.org/01903#CountersignedSignature" URI="#$2">
                  <ds:Transforms><ds:Transform Algorithm="$EXC_C14N"/></ds:Transforms>
                  <ds:DigestMethod Algorithm="$SHA256"/>
                  <ds:DigestValue/>
                </ds:Reference>
              </ds:SignedInfo>
              <ds:SignatureValue/>
              <ds:KeyInfo><ds:X509Data><ds:X509Certificate/></ds:X509Data></ds:KeyInfo>
            </ds:Signature>
          </xades:CounterSignature>
        </xades:UnsignedSignatureProperties>
      </xades:UnsignedProperties>
EOF
}

sign() {
  local input="$1" result="$2" node="$3" key="${4:-signer.key,signer.pem,intermediate.pem}"
  "$xmlsec1" --sign --lax-key-search \
    --privkey-pem "$key" \
    --id-attr:Id "$DS:Signature" \
    --id-attr:Id "$DS:Object" \
    --id-attr:Id "$DS:SignatureValue" \
    --id-attr:Id "$XADES:SignedProperties" \
    --id-attr:Id Data \
    --node-id "$node" \
    --output "$result" "$input"
}

TIME="2026-10-18T12:00:00Z"
TYPE="Type=\"$SIGNED_PROPERTIES\""

# enveloped: signature over the whole document except itself.
enveloped() {
  local name="$1" time="$2" method="$3" value="$4" cert_attributes="$5" target="$6" type="$7"
  {
    echo '<Document><Data Id="payload">Enveloped baseline payload</Data>'
    signature sig sp "$(enveloped_reference sig)" text/xml "$time" "$method" "$value" \
      "$cert_attributes" "$target" "$type"
    echo '</Document>'
  } >"$name.template.xml"
  sign "$name.template.xml" "$output/$name.xml" sig
}

enveloped enveloped "$TIME" "$SHA256" "$signer_sha256" "" "#sig" "$TYPE"
enveloped signing-time-without-zone "2026-10-18T12:00:00" "$SHA256" "$signer_sha256" "" "#sig" "$TYPE"
enveloped certificate-digest-mismatch "$TIME" "$SHA256" "$root_sha256" "" "#sig" "$TYPE"
enveloped certificate-digest-md5 "$TIME" "$MD5" "$signer_md5" "" "#sig" "$TYPE"
enveloped certificate-uri "$TIME" "$SHA256" "$signer_sha256" ' URI="https://example.invalid/signer.cer"' "#sig" "$TYPE"
enveloped wrong-target "$TIME" "$SHA256" "$signer_sha256" "" "#payload" "$TYPE"
enveloped untyped-signed-properties "$TIME" "$SHA256" "$signer_sha256" "" "#sig" ""

# The signing certificate is identified only by issuer and serial number;
# B-B requires the certificate itself in KeyInfo (EN 319 132-1 §6.3(a)).
{
  echo '<Document><Data Id="payload">Enveloped baseline payload</Data>'
  signature sig sp "$(enveloped_reference sig)" text/xml "$TIME" "$SHA256" "$signer_sha256" \
    "" "#sig" "$TYPE" "" "<ds:X509IssuerSerial/>"
  echo '</Document>'
} >issuer-serial-only.template.xml
sign issuer-serial-only.template.xml "$output/issuer-serial-only.xml" sig signer.key,signer.pem

# countersigned: the parent is signed first; the enveloped countersignature
# then covers the parent's final SignatureValue.
{
  echo '<Document><Data Id="payload">Countersigned baseline payload</Data>'
  signature sig sp "$(enveloped_reference sig)" text/xml "$TIME" "$SHA256" "$signer_sha256" \
    "" "#sig" "$TYPE" "" "<ds:X509Certificate/>" "$(counter_signature counter sig-value)"
  echo '</Document>'
} >countersigned.template.xml
sign countersigned.template.xml countersigned.parent.xml sig
sign countersigned.parent.xml "$output/countersigned.xml" counter

# enveloping: the payload is an Object inside the Signature.
signature sig sp "$(target_reference sig '#object')" text/plain "$TIME" "$SHA256" \
  "$signer_sha256" "" "#sig" "$TYPE" \
  '<ds:Object Id="object">Enveloping baseline payload</ds:Object>' >enveloping.template.xml
sign enveloping.template.xml "$output/enveloping.xml" sig

# detached: the payload is a caller-supplied external resource.
printf 'Detached baseline payload\n' >detached.txt
cp detached.txt "$output/detached.txt"
{
  echo '<Document>'
  signature sig sp "$(detached_reference sig detached.txt)" text/plain "$TIME" "$SHA256" \
    "$signer_sha256" "" "#sig" "$TYPE"
  echo '</Document>'
} >detached.template.xml
sign detached.template.xml "$output/detached.xml" sig

# parallel: two independent signatures over distinct payloads.
{
  echo '<Document><Data Id="first">First payload</Data><Data Id="second">Second payload</Data>'
  signature first-sig first-sp "$(target_reference first-sig '#first')" text/xml "$TIME" \
    "$SHA256" "$signer_sha256" "" "#first-sig" "$TYPE"
  signature second-sig second-sp "$(target_reference second-sig '#second')" text/xml "$TIME" \
    "$SHA256" "$signer_sha256" "" "#second-sig" "$TYPE"
  echo '</Document>'
} >parallel.template.xml
sign parallel.template.xml parallel.first.xml first-sig
sign parallel.first.xml "$output/parallel.xml" second-sig

for certificate in root intermediate signer; do
  openssl x509 -in "$certificate.pem" -outform DER -out "$output/$certificate.der"
done
