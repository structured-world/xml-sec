# xml-sec

[![crates.io](https://img.shields.io/crates/v/xml-sec.svg)](https://crates.io/crates/xml-sec)
[![docs.rs](https://docs.rs/xml-sec/badge.svg)](https://docs.rs/xml-sec)
[![CI](https://github.com/structured-world/xml-sec/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/structured-world/xml-sec/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/rustc-1.92%2B-blue.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/crates/l/xml-sec.svg)](https://github.com/structured-world/xml-sec/blob/main/LICENSE)

Pure Rust XML Security library. Drop-in replacement for libxmlsec1.

**No C dependencies. No cmake. No system libraries. Just `cargo add xml-sec`.**

> [!WARNING]
> Early-stage pre-release. The API is unstable, XMLDSig/XMLEnc coverage is still incomplete,
> and this crate should not yet be used in production.

## Features

- **C14N** — XML Canonicalization (inclusive + exclusive, W3C compliant)
- **XMLDSig** — XML Digital Signatures (verify and signing pipelines, X.509 `KeyInfo`, and xmlsec1 CLI interoperability)
- **XMLEnc** — XML Encryption encrypt/decrypt pipelines (direct, RSA-OAEP, and AES-KW keys)
- **X.509** — Certificate-based key extraction and validation

## Why?

Every SAML, SOAP, and WS-Security implementation depends on libxmlsec1 — a C library that:
- Requires cmake + libxml2 + OpenSSL/NSS/GnuTLS to build
- Breaks on Alpine/musl static linking
- Has decades of CVEs in XML parsing and signature validation
- Cannot cross-compile easily

`xml-sec` is a ground-up Rust rewrite using `roxmltree` for parsing, `quick-xml` for writing, RustCrypto for RSA/ECDSA/SHA, and `x509-parser` for certificates. Single `cargo build`, works everywhere Rust works.

## Status

**Pre-release.** API is unstable. Not ready for production use.

Currently implemented (core paths):
- C14N 1.0, C14N 1.1, and Exclusive C14N
- XMLDSig parsing, same-document URI dereference, transform chains, and digest verification
- XMLDSig full verify pipeline (`SignedInfo` canonicalization + `SignatureValue` verification)
- XMLDSig template signing pipeline (`DigestValue` fill + `SignedInfo` canonicalization + `SignatureValue` fill), including enveloped SAML Response templates
- XMLDSig signing KeyInfo writer for embedded X.509 certificates
- Built-in verification-key resolution from embedded X.509/DER/`KeyValue` sources and configured `KeyName`, X.509 subject, issuer/serial, SKI, or digest selectors
- RSA PKCS#1 v1.5 verification helpers for SHA-1 / SHA-256 / SHA-384 / SHA-512
- ECDSA verification helpers for P-256/SHA-256 and P-384/SHA-384
- RSA PKCS#1 v1.5 and ECDSA P-256/P-384 signing from PKCS#8 private keys
- Opt-in X.509 certificate-chain validation with explicit trust anchors, validity checks, CA constraints, and CRLs
- XMLEnc AES-128/256-CBC and AES-128/256-GCM encryption/decryption with direct
  keys, RSA-OAEP key transport, AES-128/256-KW, multiple recipients, and
  Element/Content document replacement

Still in progress:
- Broader XMLDSig and XMLEnc donor/CLI interop coverage

## XMLDSig Usage

`examples/sign.rs` builds an enveloped RSA-SHA256 signature with an embedded
X.509 certificate. `examples/verify.rs` verifies a document through
`DefaultKeyResolver` using that embedded certificate:

```sh
cargo run --example sign --all-features > signed.xml
cargo run --example verify --all-features -- signed.xml
```

For production verification, configure `KeyResolverConfig` with explicit trust
anchors when certificate-chain validation is required. A `Valid` status means
the cryptographic and reference checks succeeded; `Invalid(reason)` means the
document was processed successfully but did not validate.

Malformed XMLDSig structure, unsupported algorithms, disallowed reference
URIs, and inconsistent `KeyInfo` metadata are processing errors rather than
validity statuses. Treat both `Invalid(reason)` and an API error as a rejected
document; never continue an authentication flow after either outcome.

## XMLEnc Usage

Enable the `xmlenc` feature. `EncryptedDataBuilder` can encrypt opaque bytes,
one XML element, an XML content fragment, or a selected element in a complete
document. This direct-key example creates a complete `EncryptedData` fragment
and verifies it through the reciprocal decrypt path:

```rust
use xml_sec::xmlenc::{
    DataEncryptionAlgorithm, DecryptedContent, EncryptedDataBuilder,
    SymmetricKeyDecryptor, decrypt,
};

# fn example() -> Result<(), Box<dyn std::error::Error>> {
let key = [0x42_u8; 16];
let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
    .direct_key(key)
    .direct_key_name("application-content-key")
    .encrypt_xml("<secret>value</secret>")?;

assert_eq!(
    decrypt(
        &encrypted.encrypted_data_xml,
        &SymmetricKeyDecryptor::new(key),
    )?,
    DecryptedContent::Xml("<secret>value</secret>".into()),
);
# Ok(())
# }
```

For recipient transport, add one or more `EncryptionRecipient::rsa_oaep`
entries with recipient public keys, or use `recipient_aes_kw` with a shared
KEK. A fresh content key is generated from the operating-system RNG and wrapped
once per recipient. XMLEnc 1.1 RSA-OAEP defaults to SHA-256/MGF1-SHA-256;
legacy SHA-1 OAEP must be selected explicitly.

`encrypt_document` selects the root or an element by `Id`, `ID`, or `id`, then
replaces either the complete element or only its child content according to
`EncryptedDataType`. The caller retains ownership of the resulting XML string.
See `examples/encrypt.rs` for RSA-OAEP document encryption.

To decrypt either a standalone XML fragment or an `EncryptedData` value parsed
once and retained by the caller:

```rust
use xml_sec::xmlenc::{
    DecryptedContent, SymmetricKeyDecryptor, decrypt_data, parse_encrypted_data,
};

# fn example(encrypted_xml: &str) -> Result<(), Box<dyn std::error::Error>> {
let encrypted = parse_encrypted_data(encrypted_xml)?;
let resolver = SymmetricKeyDecryptor::new([0_u8; 16]);
let plaintext = decrypt_data(&encrypted, &resolver)?;

match plaintext {
    DecryptedContent::Xml(xml) => println!("{xml}"),
    DecryptedContent::Bytes(bytes) => println!("{} plaintext bytes", bytes.len()),
}
# Ok(())
# }
```

`PrivateKeyDecryptor` unwraps embedded RSA-OAEP `EncryptedKey` values and
`KekDecryptor` unwraps AES-KW values. RSA PKCS#1 v1.5 transport, CipherReference,
and unauthenticated external resource loading are rejected; only inline
`CipherValue` is accepted. Encryption inputs and recipient counts are bounded
before allocation.

Use `decrypt_document` to replace one typed `EncryptedData` in a caller-owned
XML string. Pass its `Id` when the document contains multiple encrypted
regions. DTD parsing remains disabled by default; legacy documents that need
an internal DTD can opt in through `decrypt_document_with_options` and
`DocumentDecryptionOptions`. That API never installs an external entity
resolver.

Current toolchain target: latest stable Rust.
Current MSRV: Rust 1.92.

## Specifications

| Spec | Status |
|------|--------|
| [Canonical XML 1.0](https://www.w3.org/TR/xml-c14n/) | Partially implemented |
| [Canonical XML 1.1](https://www.w3.org/TR/xml-c14n11/) | Partially implemented |
| [Exclusive C14N](https://www.w3.org/TR/xml-exc-c14n/) | Partially implemented |
| [XMLDSig](https://www.w3.org/TR/xmldsig-core1/) | Partially implemented |
| [XMLEnc](https://www.w3.org/TR/xmlenc-core1/) | AES-CBC/GCM encryption and decryption subset implemented |

## License

Apache-2.0

## Support the Project

If `xml-sec` is useful in your stack, you can help fund continued implementation and maintenance.

![USDT TRC-20 Donation QR Code](assets/usdt-qr.svg)

USDT (TRC-20): `TFDsezHa1cBkoeZT5q2T49Wp66K8t2DmdA`
