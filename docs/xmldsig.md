# XML Digital Signatures

The `xmldsig` feature provides signing and verification pipelines for same-document XML
signatures. It supports inclusive and exclusive canonicalization, enveloped signatures,
Base64, XPath 1.0, and XPath Filter 2.0 transforms, RSA PKCS#1 v1.5, ECDSA P-256/P-384,
embedded X.509 certificates, and configured key resolution.

## Examples

`examples/sign.rs` builds an enveloped RSA-SHA256 signature with an embedded X.509
certificate. `examples/verify.rs` verifies that document through `DefaultKeyResolver`:

```sh
cargo run --example sign --all-features > signed.xml
cargo run --example verify --all-features -- signed.xml
```

The signing and verification contexts share the same reference-transform implementation.
`XPathHereSemantics::Standard` follows the XMLDSig `<XPath>` contract; callers interoperating
with legacy libxmlsec1 `here()` behavior can explicitly select
`XPathHereSemantics::XmlSecLegacy` on both contexts.

## Verification Policy

For production verification, configure `KeyResolverConfig` with explicit trust anchors when
certificate-chain validation is required. Embedded certificates provide key material; they do
not become trusted merely because they appear in `<KeyInfo>`.

A `Valid` status means the cryptographic signature and every processed reference succeeded.
`Invalid(reason)` means the document was processed but failed validation, such as a reference
digest mismatch or invalid signature value.

Malformed XMLDSig structure, unsupported algorithms, disallowed reference URIs, and
inconsistent `KeyInfo` metadata are processing errors rather than validity statuses. Treat both
`Invalid(reason)` and an API error as a rejected document; never continue an authentication flow
after either outcome.

## Current Scope

Implemented algorithms include RSA PKCS#1 v1.5 with SHA-1/SHA-256/SHA-384/SHA-512 for
verification, SHA-256/SHA-384/SHA-512 for signing, and ECDSA P-256/SHA-256 and P-384/SHA-384.
DSA, HMAC signatures, RSA-PSS, and unauthenticated external reference loading are not currently
supported.

