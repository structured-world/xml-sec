# Executable API Examples

Run these from a source checkout. All credentials under `tests/fixtures` are
public test material, never deployment credentials. Examples do not discover
configuration, fetch keys or authorize an identity from document-controlled
KeyInfo. Application input I/O, key custody and protocol authorization remain
caller responsibilities.

## Policy-Bound Application API

```sh
cargo run --example policy_roundtrip
```

[The source](../examples/policy_roundtrip.rs) compiles `Modern` for one explicit
RustCrypto provider, signs a retained document, requests the exact Invoice
identity, and checks `evidence.accepted(&document)`. The same valid signature
must not authorize an unsigned sibling; changing the signed amount must fail.
It then generates an AES-256 key through the selected provider and performs
authenticated encrypt/decrypt with exact plaintext comparison.

The pre-shared content key has two independently owning, zeroizing request
handles for this demonstration. A real recipient deployment can instead use
the [opaque key and recipient APIs](crypto-providers.md). Success is not a
SAML audience/replay decision, XAdES level validation, or certificate trust grant.

## Low-Level Template API

```sh
cargo run --example sign > signed.xml
cargo run --example verify -- signed.xml \
  tests/fixtures/keys/rsa/rsa-2048-pubkey.pem invoice-2026-07
cargo run --example encrypt
```

[`sign`](../examples/sign.rs) demonstrates explicit template construction,
reference transforms and a certificate KeyInfo writer. [`encrypt`](../examples/encrypt.rs)
uses an explicit RSA recipient and AES-GCM. These low-level contexts use their
typed default policies; applications needing composed deployment restrictions
should use the policy-bound API or pass the same compiled snapshot explicitly.

[`verify`](../examples/verify.rs) intentionally supports only pinned RSA-SHA256
SPKI public keys and a caller-selected ID. It does not accept a certificate as
a public-key PEM, infer the key algorithm from XML, or trust an embedded key.
It returns nonzero for bad signatures, missing or unsigned expected targets,
malformed input and wrong keys. Use the [key inventory](key-management.md) and
selected provider for other algorithms, opaque keys or path-validated discovery.

Never replace `accepted(document)` with `all_valid()` or `DsigStatus::Valid`
when consuming application data. Retain the document/generation that produced
the evidence; after mutation the old evidence cannot authorize its new contents.
