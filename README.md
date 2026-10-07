# xml-sec: Pure Rust XML Security

[![crates.io](https://img.shields.io/crates/v/xml-sec.svg)](https://crates.io/crates/xml-sec)
[![docs.rs](https://docs.rs/xml-sec/badge.svg)](https://docs.rs/xml-sec)
[![CI](https://github.com/structured-world/xml-sec/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/structured-world/xml-sec/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/rustc-1.92%2B-blue.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/crates/l/xml-sec.svg)](https://github.com/structured-world/xml-sec/blob/main/LICENSE)

Pure Rust XML Security for **XMLDSig**, **XML Encryption**, **C14N**, **SAML 2.0**, and
**X.509**, built to replace libxmlsec1 workflows without a C toolchain or system libraries.

**No C dependencies in the default build. No CMake. No system XML or crypto packages.
Just `cargo add xml-sec`.**

> [!WARNING]
> Early-stage pre-release. The API is unstable, XMLDSig/XMLEnc coverage is still incomplete,
> and this crate should not yet be used in production.

## Why xml-sec?

- **End-to-end XML security**: sign, verify, encrypt, and decrypt through public Rust APIs.
- **Modern signature algorithms**: curve-independent ECDSA with SHA-2/SHA-3, Ed25519/Ed448
  with context/prehash variants, and opt-in experimental ML-DSA/SLH-DSA through `CryptoProvider`.
- **SAML-ready primitives**: enveloped signatures, encrypted assertions, X.509 keys, XPath,
  canonicalization, and strict same-document ID handling.
- **Pure Rust deployment**: RustCrypto, `x509-parser`, and selectable Rust XML backends replace
  the libxml2/OpenSSL-style native dependency stack.
- **Optional AWS-LC FIPS provider**: select a native cryptographic engine explicitly through
  the same provider contracts, without silent fallback to RustCrypto.
- **Fail-closed security policy**: typed immutable policy controls algorithms, trust, XML parsing,
  transforms, external resources, and cumulative operation budgets.
- **Identity-bound verification evidence**: bounded multi-signature reports, explicit trusted-key
  requests, and expected-element coverage checks resist signature wrapping and stale-document reuse.
- **xmlsec1 interoperability**: a native `xmlsec1` CLI surface plus deterministic offline
  compatibility corpora and generated parity ledgers.
- **Encoding-aware XML input**: strict bounded decoding for UTF-8, UTF-16, UTF-32, and supported
  legacy XML encodings before backend-independent semantic parsing.
- **Reusable safe-Rust XSLT 1.0 engine**: an isolated workspace crate with explicit resolver,
  clock, extension, and resource capabilities.

## Install

```sh
cargo add xml-sec
```

Default features provide C14N, XMLDSig, XMLEnc, and the `xmloxide` XML backend. Adding the crate as
a dependency builds the library; install the command-line tool from the same package:

```sh
cargo install xml-sec
xmlsec1 version
```

Applications can build only the capabilities they need:

```toml
xml-sec = { version = "0.1", default-features = false, features = ["xmldsig", "c14n", "xml-backend-xmloxide"] }
```

## Capabilities

| Area | Available today |
|------|-----------------|
| Canonicalization | Canonical XML 1.0/1.1, Exclusive C14N, comments, and document subsets |
| XML signatures | XMLDSig signing and verification, RSA-PSS/PKCS#1, DSA/ECDSA/HMAC, XPath transforms, `Manifest`, `KeyInfo`, and caller-provided references |
| XML encryption | AES-CBC/GCM, RSA-OAEP, AES Key Wrap, ECDH/X25519/DH, bounded KDFs, referenced ciphertext, nested recipients, and Element/Content replacement |
| Optional compatibility algorithms | `legacy-algorithms`: MD5/RIPEMD-160 signatures and digests, AES-192, TripleDES-CBC/CMS wrap, and RSA-1.5 transport; library policy denies these by default |
| X.509 | Certificate key extraction, chain validation, CRLs, required key authorization by default, and typed trust evidence |
| Key management | Caller-owned named inventory, usage-restricted keys, xmlsec `keys.xml`, encrypted PKCS#8, and bounded RustCrypto-backed PKCS#12 import |
| SAML 2.0 | Signed assertions and encrypted-assertion workflows covered by integration tests |
| XML input | Strict bounded byte decoding, entity/depth/node limits, stable node identities, and generation-safe mutation |
| Crypto | RustCrypto by default; optional AWS-LC FIPS and PKCS#11 external-key adapters through provider-neutral contracts and opaque private-key handles |
| CLI | Native `xmlsec1` process interface for sign, verify, encrypt, decrypt, keys, and capability discovery |

Unsupported algorithms, unavailable provider capabilities, untrusted key sources, implicit external
I/O, malformed encodings, and exhausted budgets return explicit errors. Initial parsing, recursive
transforms, resolver work, staged mutations, and decryption retries share one operation-wide budget
instead of resetting limits inside helpers.

## XMLDSig

`examples/sign.rs` creates an enveloped RSA-SHA256 signature and `examples/verify.rs` verifies it
through the embedded X.509 certificate:

```sh
cargo run --example sign > signed.xml
cargo run --example verify -- signed.xml
```

The signing and verification pipelines support same-document and caller-provided references,
XPath 1.0 and XPath Filter 2 transforms, `Manifest`, structured `KeyInfo`, and policy-controlled
X.509 validation. See [XML Digital Signatures](docs/xmldsig.md) for algorithms, transform semantics,
key resolution, failure handling, and current interoperability boundaries.
See [Key management](docs/key-management.md) for inventory ownership, format import,
password handling, and CLI key-store behavior.

## XML Encryption

`EncryptedDataBuilder` supports direct symmetric keys, policy-bound key derivation and
agreement, RSA-OAEP/AES Key Wrap recipients, and Element/Content document replacement:

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

RSA encryption and decryption default to a 2048-bit minimum. Applications accepting legacy
keys must explicitly select a lower operation-policy minimum; importing a key does not bypass it.

Decryption supports caller-owned `CipherReference` resources, transformed key retrieval,
nested/detached `EncryptedKey`, and trusted application bindings for ConcatKDF, HKDF,
PBKDF2 and ECDH/X25519/DH. No document can trigger implicit filesystem or network access.
See [XML Encryption](docs/xmlenc.md) and [crypto providers](docs/crypto-providers.md)
for key establishment, cumulative budgets, interoperability and provider capabilities.

## XML Backends

`xmloxide` and `roxmltree` are independent parsers behind one source-preserving semantic DOM.
C14N, XPath, XMLDSig, XMLEnc, and mutation code do not branch on parser-specific tree types.

Use `xml-backend-roxmltree` for a thin alternative build, or compile `xml-backends-all` to select
`Xmloxide`, `Roxmltree`, or fail-closed `Differential` parsing per operation:

```toml
xml-sec = { version = "0.1", default-features = false, features = ["xmldsig", "xmlenc", "c14n", "xml-backends-all"] }
```

```rust
use xml_sec::XmlBackend;
use xml_sec::xmldsig::VerifyContext;

# let xml = "<root/>";
let result = VerifyContext::new()
    .xml_backend(XmlBackend::Roxmltree)
    .verify(xml);
# let _ = result;
```

Runtime selection never falls back to an implementation absent from the build. Differential mode
requires both complete semantic arenas to agree on topology, expanded names, attributes,
namespaces, text, processing instructions, source order, and ranges. Each backend receives the
full configured allowance; the mode does not split one parser budget in half.

Raw-byte APIs select XML encoding from the BOM, byte signature, declaration, or trusted resolver
metadata. UTF-8 remains borrowed when possible; other supported encodings are strictly transcoded
under the same materialization ceiling. Conflicting declarations, malformed byte sequences,
ambiguous BOM-less UTF-16/UTF-32, and unsupported EBCDIC variants fail explicitly.

**API migration for this pre-release change:** `encoding::decode_xml_octets` now requires a
maximum decoded-byte count as its second argument. `encoding::XmlEncodingError` is now the
shared, non-exhaustive `xml_sec::encoding::XmlEncodingError`; update matches to handle the new error
variants and include a fallback arm. Code constructing `ResourcePolicy` with every field must
also set `max_xml_namespace_bindings` (or start from `ResourcePolicy::default()` and override
selected fields). These changes keep decoding and namespace-scope allocation under explicit
resource limits. For trusted resolver-provided encoding metadata, use
`xml_input::decode_xml_bounded(bytes, Some(encoding), maximum_decoded_bytes)`; the unbounded
decoder remains internal.

## Native xmlsec1 CLI

```sh
xmlsec1 list-transforms
xmlsec1 list-key-data
xmlsec1 verify --xml-backend xmloxide signed.xml
```

The binary covers sign/verify, template-preserving encrypt/decrypt, AES key generation, capability
queries, donor option syntax, and deterministic process statuses through the same policy and
provider pipelines as the library. A fat build accepts
`--xml-backend xmloxide|roxmltree|differential`; a thin build rejects unavailable backends.

With the optional `aws-lc-fips` feature, `--crypto aws-lc-fips` selects the FIPS-linked
engine; `--crypto rustcrypto` remains the default. Unsupported mechanisms fail explicitly,
not through another engine. See [cryptographic providers](docs/crypto-providers.md) for the
API, supported mechanisms, native build requirements, and FIPS deployment boundaries.

See the [CLI compatibility guide](docs/cli.md) for commands, formats, key lookup, diagnostics, and
interoperability boundaries.

## Interoperability

Interoperability evidence is deterministic and offline. The complete Phaos XMLDSig 3, XMLDSig 1.1,
and XMLDSig Second Edition corpora execute through public sign/verify APIs with exact valid,
invalid, and fail-closed classifications. Selected unmodified upstream XMLDSig, XML Encryption,
and key-management scenarios execute against the Rust `xmlsec1` binary without network access or
a system libxmlsec1 installation.

The generated [compatibility ledger](docs/compatibility-ledger.md) tracks libxmlsec1 1.3.13 public
surface and operation behavior with source and test evidence.

## Safe-Rust XSLT

[`xml-sec-xslt`](crates/xml-sec-xslt) is an XML-security-neutral XSLT 1.0 compiler and runtime. It
owns stylesheet compilation, XPath/XSLT semantics, template execution, result-tree construction,
deterministic budgets, and XML/HTML/text serialization. Its `ExecutionEnvironment` makes resolver
access, XInclude processing, and operation time explicit. The default grants no XInclude or ambient
clock access; callers may supply a fixed clock for reproducible EXSLT date functions or explicitly
request host-clock compatibility.

The engine currently remains an in-repository workspace crate rather than a separately published
package; `xml-sec` is the only crate published to crates.io. The main crate continues to reject XMLDSig
XSLT transforms until the policy, resource identity, and node-set adapter contracts are connected.
The shared strict byte-decoding and lexical source is compiled into `xml-sec` and reused by the
internal XSLT workspace crate.

## Specifications

| Specification | Status |
|---------------|--------|
| [Canonical XML 1.0](https://www.w3.org/TR/xml-c14n/) | Implemented; full-document and document-subset vectors |
| [Canonical XML 1.1](https://www.w3.org/TR/xml-c14n11/) | Implemented; `xml:id` and `xml:base` subset rules |
| [Exclusive C14N](https://www.w3.org/TR/xml-exc-c14n/) | Implemented; `InclusiveNamespaces PrefixList` support |
| [XMLDSig 1.0/1.1](https://www.w3.org/TR/xmldsig-core1/) | Core sign/verify pipelines; complete Merlin, Phaos 3, XMLDSig 1.1, and Second Edition corpora classified and executed |
| [XML Encryption](https://www.w3.org/TR/xmlenc-core1/) | Core AES-CBC/GCM, RSA-OAEP, and AES-KW pipelines implemented; broader conformance work continues |
| [XSLT 1.0](https://www.w3.org/TR/xslt-10/) | Separate safe-Rust engine implemented; XMLDSig transform adapter not yet connected |

The project tracks stable Rust and supports Rust 1.92 or newer. Detailed contracts and limitations
live in the [XMLDSig guide](docs/xmldsig.md), [XML Encryption guide](docs/xmlenc.md), and
[CLI guide](docs/cli.md).

## License

Apache-2.0

## Support the Project

If `xml-sec` is useful in your stack, you can help fund continued implementation and maintenance.

![USDT TRC-20 Donation QR Code](assets/usdt-qr.svg)

USDT (TRC-20): `TFDsezHa1cBkoeZT5q2T49Wp66K8t2DmdA`
