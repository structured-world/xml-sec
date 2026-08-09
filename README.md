# xml-sec

[![crates.io](https://img.shields.io/crates/v/xml-sec.svg)](https://crates.io/crates/xml-sec)
[![docs.rs](https://docs.rs/xml-sec/badge.svg)](https://docs.rs/xml-sec)
[![CI](https://github.com/structured-world/xml-sec/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/structured-world/xml-sec/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/rustc-1.92%2B-blue.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/crates/l/xml-sec.svg)](https://github.com/structured-world/xml-sec/blob/main/LICENSE)

XML Security in pure Rust, built to replace libxmlsec1.

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

libxmlsec1 is the established XML Security implementation, but its native dependency stack adds
libxml2, a crypto backend, platform packages, and cross-compilation work to every deployment.

`xml-sec` rebuilds that functionality on memory-safe Rust foundations: `roxmltree` for parsing,
`quick-xml` for writing, RustCrypto for cryptography, and `x509-parser` for certificates. One
Cargo dependency, no system XML or crypto libraries.

## Status

**Pre-release.** API is unstable. Not ready for production use.

Currently implemented (core paths):
- C14N 1.0, C14N 1.1, and Exclusive C14N
- XMLDSig parsing, same-document URI dereference, enveloped/C14N/Base64/XPath 1.0/XPath Filter 2.0 transform chains, and digest verification
- XMLDSig full verify pipeline (`SignedInfo` canonicalization + `SignatureValue` verification)
- XMLDSig template signing pipeline (`DigestValue` fill + `SignedInfo` canonicalization + `SignatureValue` fill), including enveloped SAML Response templates
- Typed signing and verification policy covers XML parsing, explicit transforms, implicit reference canonicalization, and `SignedInfo` canonicalization under shared work limits
- XMLDSig signing KeyInfo writer for embedded X.509 certificates
- Built-in verification-key resolution from embedded X.509/DER/`KeyValue` sources and configured `KeyName`, X.509 subject, issuer/serial, SKI, or digest selectors
- RSA PKCS#1 v1.5 verification helpers for SHA-1 / SHA-256 / SHA-384 / SHA-512
- ECDSA SHA-256/SHA-384 verification for P-256, P-384, and P-521 keys
- Legacy DSA-SHA1 and HMAC-SHA1 verification, including truncated HMAC output
- RSA PKCS#1 v1.5 and ECDSA SHA-256/SHA-384 signing with P-256/P-384 PKCS#8 keys
- Opt-in X.509 certificate-chain validation with explicit trust anchors, validity checks, CA constraints, and authenticated CRLs
- Caller-supplied external references and X.509 `RetrievalMethod` resolution with bounded RFC 3986 `xml:base` processing and no implicit I/O
- XMLEnc AES-128/256-CBC and AES-128/256-GCM encryption/decryption with direct
  keys, RSA-OAEP key transport, AES-128/256-KW, multiple recipients, and
  Element/Content document replacement; document, node, and aggregate recipient
  limits cover caller-constructed ciphertext and generated replacement output
  before expensive work. CBC failures expose no decrypted
  padding details, but CBC remains unauthenticated and can be excluded by policy

Still in progress:
- XMLDSig DSA-SHA256, broader HMAC verification/signing, and RSA-PSS algorithms
- Complete XMLDSig and XMLEnc conformance-suite classification
- Expanded fuzz coverage, benchmarks, production hardening, and API stabilization

## XMLDSig Usage

`examples/sign.rs` builds an enveloped RSA-SHA256 signature and `examples/verify.rs`
verifies it through the embedded X.509 certificate:

```sh
cargo run --example sign --all-features > signed.xml
cargo run --example verify --all-features -- signed.xml
```

See [XML Digital Signatures](docs/xmldsig.md) for supported algorithms, transform
semantics, key-resolution policy, and validation failure handling.

## XMLEnc Usage

Enable the `xmlenc` feature. `EncryptedDataBuilder` supports direct symmetric keys,
RSA-OAEP recipients, AES Key Wrap recipients, and Element/Content document replacement:

```rust
use xml_sec::xmlenc::{DataEncryptionAlgorithm, EncryptedDataBuilder};

fn example() -> Result<(), Box<dyn std::error::Error>> {
    let key = [0x42_u8; 16];
    let encrypted_data = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .direct_key(key)
        .direct_key_name("application-content-key")
        .encrypt_xml("<secret>value</secret>")?;

    assert!(encrypted_data.encrypted_data_xml.contains("EncryptedData"));
    Ok(())
}
```

See [XML Encryption](docs/xmlenc.md) for reciprocal decryption, recipient transport,
document replacement, input bounds, and parser security policy.

Current toolchain target: latest stable Rust.
Current MSRV: Rust 1.92.

## Specifications

| Spec | Status |
|------|--------|
| [Canonical XML 1.0](https://www.w3.org/TR/xml-c14n/) | Implemented; full-document and document-subset vectors |
| [Canonical XML 1.1](https://www.w3.org/TR/xml-c14n11/) | Implemented; `xml:id` and `xml:base` subset rules |
| [Exclusive C14N](https://www.w3.org/TR/xml-exc-c14n/) | Implemented; `InclusiveNamespaces PrefixList` support |
| [XMLDSig](https://www.w3.org/TR/xmldsig-core1/) | Core sign/verify pipelines and the complete Merlin corpus implemented; additional algorithms and conformance suites in progress |
| [XMLEnc](https://www.w3.org/TR/xmlenc-core1/) | Core AES-CBC/GCM encrypt/decrypt with RSA-OAEP and AES-KW implemented; broader conformance coverage in progress |

## License

Apache-2.0

## Support the Project

If `xml-sec` is useful in your stack, you can help fund continued implementation and maintenance.

![USDT TRC-20 Donation QR Code](assets/usdt-qr.svg)

USDT (TRC-20): `TFDsezHa1cBkoeZT5q2T49Wp66K8t2DmdA`
