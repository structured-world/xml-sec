# XMLDSig Donor Fixtures

This directory contains the XMLDSig test documents used by integration tests.
They are checked into the repository so CI never depends on a local donor clone.
The current compatibility oracle is the xmlsec1 1.3.13 development snapshot at
the commit recorded in the canonical
[`libxmlsec1-1.3.13-donor-commit.txt`](../../../compatibility/libxmlsec1-1.3.13-donor-commit.txt)
pin; upstream had bumped the
version but had not published a release tag when this snapshot was pinned.
`scripts/install-xmlsec1.sh` verifies both that source commit and the live
`xmlsec1 --version` output before reusing a cached development installation.

## Importing Vectors

The source corpus is vendored under `donors/xmlsec/tests/` in development
checkouts. Import a selected upstream file with the repository helper:

```sh
scripts/import-donor-fixtures.sh \
  xmldsig/xmldsig11-interop-2012/signature-enveloping-p256_sha256.xml
```

The helper preserves the path beneath `tests/fixtures/xmldsig/` and uses a
fixed mode. Do not copy test vectors with ad-hoc shell commands: that makes
fixture provenance and CI coverage difficult to audit.

## Fixture Families

### `aleksey-xmldsig-01`

Core xmlsec1-generated XMLDSig vectors used by the signing and verification
pipeline tests. They cover RSA SHA-1/SHA-256/SHA-384/SHA-512, ECDSA P-256 and
P-384, SHA-256/SHA-512 X.509 digest selectors, X.509 KeyInfo, and template
signing.

### `merlin-xmldsig-twenty-three`

W3C/Merlin basic signature vectors. DSA-SHA1 and HMAC-SHA1 are supported for
legacy verification, including XMLDSig's permitted HMAC truncation. Unsupported
DSA and HMAC variants remain fail-closed.

### `xmldsig11-interop-2012`

XMLDSig 1.1 interoperability corpus. The test suite verifies the implemented
ECKeyValue cases and records every other vector as fail-closed until its
required algorithm, key source, or transform is implemented.

Currently verified as valid:

- P-256 with SHA-256 and raw XMLDSig `r || s` encoding.
- P-384 with SHA-384 and raw XMLDSig `r || s` encoding.
- The DER-encoded ECDSA interoperability document, accepted as an explicit
  parser compatibility path.

Currently fail-closed:

- HMAC algorithms other than HMAC-SHA1.
- SHA-224 digest or signature algorithms.
- P-521 KeyValue resolution.
- `KeyInfoReference` dereference.
- X.509 digest lookup without configured certificate policy.
- RSA documents lacking an allowed verification-key source.

### `xmldsig2ed-tests`

XMLDSig Second Edition errata vectors. They exercise HMAC-SHA1, external URI
references, XPath transforms, and Canonical XML 1.1. XPath and C14N 1.1 are
implemented; HMAC-SHA1 is supported for verification, while documents that
require another HMAC variant, an unavailable external resource, or an
unsupported key source remain explicitly classified as fail-closed.

### `merlin-xpath-filter2`

W3C/Merlin XPath Filter 2.0 subset input used for byte-exact canonicalization.
The fixture is derived from the upstream sign-spec vector and exercises ordered
intersect/subtract/union processing before inclusive C14N. Reciprocal xmlsec1
tests separately cover signing and verification interoperability.

### `phaos-xmldsig-three`

Complete Phaos XMLDSig 3 interoperability corpus: all 28 signed documents plus
their keys, certificates, CRL, detached payloads, stylesheet inputs, and the
offline RFC 3161 resource. `tests/phaos_interop.rs` requires exact set equality
between the fixture directory and its case manifest, then executes every case
through `VerifyContext`; additions and removals cannot become implicit skips.

Supported RSA, DSA, HMAC-SHA1, Base64, XPath, Manifest, detached-resource, and
X.509 selection paths verify to their exact public result. Invalid vectors
assert the first stable typed failure. XSLT, HMAC-MD5, and MD5-signed
certificate paths remain explicit fail-closed classifications until those
capabilities are implemented; corpus accounting therefore does not imply
blanket algorithm support.

The historical `-40-` filenames contain 80-bit HMAC values. The artifacts are
kept byte-for-byte rather than renamed, and the case configuration follows the
encoded `HMACOutputLength`. The upstream corpus also lacks a separately named
expired-certificate signature, so expiry coverage uses the original Phaos leaf
and CA at a fixed modern verification time without modifying donor data.

## Test Contract

Merlin `.tmpl` files are byte-preserved donor templates whose relative URIs are
interpreted from the upstream xmlsec runner working directory. Their paths are
not rewritten to the repository fixture layout. The corresponding signed `.xml`
files contain the materialized URI identities exercised by `VerifyContext` and
the caller-provided resource map. This distinction is part of fixture provenance,
not a missing local file reference.

Positive fixtures must be validated end-to-end through `VerifyContext`; a
successful XML parse alone is never sufficient. Negative fixtures must assert
the specific processing or validation boundary that rejects them where the
contract is stable.

`DsigStatus::Invalid` means cryptographic processing completed but validation
failed. `DsigError` means the document could not be safely processed, for
example because XML structure, KeyInfo metadata, URI policy, or an algorithm is
unsupported. Both outcomes are fail-closed; tests must not collapse them into a
single generic success condition.

## Adding a Fixture

1. Identify the upstream file and the XMLDSig feature it covers.
2. Import it with `scripts/import-donor-fixtures.sh`.
3. Add a positive assertion or an explicit fail-closed classification.
4. Run the focused `cargo nextest run` target and the full all-features suite.
5. Update this document when the supported set changes.

Do not weaken an expected failure merely because a donor document uses a
legacy algorithm. Any compatibility expansion requires an explicit public API
decision, tests for both valid and invalid inputs, and review of its security
policy impact.
