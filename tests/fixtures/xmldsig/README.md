# XMLDSig Donor Fixtures

This directory contains the XMLDSig test documents used by integration tests.
They are checked into the repository so CI never depends on a local donor clone.

## Importing Vectors

The source corpus is vendored under `donors/xmlsec/tests/` in development
checkouts. Import a selected upstream file with the repository helper:

```sh
scripts/import-donor-fixtures.sh \
  xmldsig11-interop-2012/signature-enveloping-p256_sha256.xml
```

The helper preserves the path beneath `tests/fixtures/xmldsig/` and uses a
fixed mode. Do not copy test vectors with ad-hoc shell commands: that makes
fixture provenance and CI coverage difficult to audit.

## Fixture Families

### `aleksey-xmldsig-01`

Core xmlsec1-generated XMLDSig vectors used by the signing and verification
pipeline tests. They cover RSA SHA-1/SHA-256/SHA-384/SHA-512, ECDSA P-256 and
P-384, X.509 KeyInfo, and template signing.

### `merlin-xmldsig-twenty-three`

W3C/Merlin basic signature vectors. Some files intentionally remain outside
the supported algorithm set, such as DSA, and are accounted for as skips or
fail-closed cases by the donor verification suite.

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

- HMAC algorithms.
- SHA-224 digest or signature algorithms.
- P-521 KeyValue resolution.
- `KeyInfoReference` dereference.
- X.509 digest lookup without configured certificate policy.
- RSA documents lacking an allowed verification-key source.

### `xmldsig2ed-tests`

XMLDSig Second Edition errata vectors. They exercise HMAC-SHA1, external URI
references, XPath transforms, and Canonical XML 1.1. Those facilities are not
enabled by the default XMLDSig verification policy, so the interop inventory
asserts that each document fails closed.

### `phaos-xmldsig-three`

Third-party negative vectors. The regression suite currently imports the
historical RSA enveloped baseline and its bad-digest and bad-signature variants.
All carry inconsistent X.509 selector metadata and must fail during strict
KeyInfo parsing before the certificate becomes a verification candidate.

## Test Contract

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
