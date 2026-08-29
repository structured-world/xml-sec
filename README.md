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
- **Native CLI** — `xmlsec1` command surface backed by the same Rust policy and provider pipelines
- **Provider-neutral crypto** — typed capabilities and opaque key handles with RustCrypto as the pure-Rust default
- **Reusable XML documents** — policy-aware retained parsing, stable semantic identities, shared indexes, and generation-safe mutation across C14N, XMLDSig, and XMLEnc
- **Compiled operations** — deterministic dependency plans keep policy, cumulative budgets, resolver/cache state, authenticated identities, and mutation gates in one operation context
- **Selectable XML backend** — `xmloxide` and `roxmltree` are interchangeable compile-time parsers behind one backend-neutral semantic DOM
- **Reusable XSLT engine** — the workspace includes a safe-Rust, XML-security-neutral XSLT 1.0 compiler and runtime crate

## Why?

libxmlsec1 is the established XML Security implementation, but its native dependency stack adds
libxml2, a crypto backend, platform packages, and cross-compilation work to every deployment.

`xml-sec` rebuilds that functionality on memory-safe Rust foundations: a bounded `quick-xml`
preflight before DOM allocation, one feature-selected XML parser projected into a shared semantic
arena for C14N/XPath/mutation, `quick-xml` for writing, RustCrypto for cryptography, and
`x509-parser` for certificates. One Cargo dependency, no system XML or crypto libraries.

## Install

Use the library from Rust code:

```sh
cargo add xml-sec
```

Default features provide C14N, XMLDSig, and XMLEnc. Applications that need a
smaller dependency graph can select only the required library capabilities:

```toml
xml-sec = { version = "0.1", default-features = false, features = ["xmldsig", "c14n", "xml-backend-xmloxide"] }
```

Select `xml-backend-roxmltree` instead for a thin build containing only `roxmltree`, or compile
`xml-backends-all` when the application must select `Xmloxide`, `Roxmltree`, or fail-closed
`Differential` parsing at runtime. Compiled implementations and runtime selection are separate:
selecting an implementation absent from a thin build returns a typed error and never falls back.
Both adapters populate the same source-preserving semantic arena, and no C14N, XPath, signature,
encryption, or mutation code branches on parser type. A bounded streaming preflight
rejects byte, node, and depth limits before either backend allocates its DOM; stack-safe
internal-entity traversal consumes the same cumulative parse-work budget. The `xmloxide` adapter
adds a lexical position sidecar because its native tree does not retain the source ranges required
for namespace-correct mutation.

```toml
xml-sec = { version = "0.1", default-features = false, features = ["xmldsig", "c14n", "xml-backend-roxmltree"] }
```

```toml
# Fat build: xmloxide remains the default; applications select per operation.
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

`xml-backend-differential` remains a compatibility feature for CI and fuzzing: it compiles both
adapters and selects `Differential` by default. Differential parsing fails closed unless the full
semantic arenas agree, including topology, expanded names, attributes, namespace axes, character
data, comments, processing instructions, semantic order, and source ranges. It is an explicit
diagnostic mode, not a production fallback. Both implementations are checked against the same
per-backend parser-work allowance, so differential validation does not halve the operation budget.

Cryptographic implementation and runtime selection follow the same separation through the
`CryptoProvider` contract: operation contexts receive one provider explicitly. The current package
ships the RustCrypto provider; a future AWS-LC feature can add another compiled implementation
without changing signing, verification, encryption, or decryption policy semantics. Crypto has no
differential mode: a fat crypto build selects exactly one provider for each operation.

Install the `xmlsec1` command from the same package:

```sh
cargo install xml-sec
xmlsec1 verify --xml-backend xmloxide signed.xml
```

Adding `xml-sec` as a dependency builds its library target, not the executable.
`cargo install` builds and installs the binary target.
The CLI accepts `--xml-backend xmloxide|roxmltree|differential` on every XML
Security operation. A thin binary rejects a backend that was not compiled;
install a fat build with `--features xml-backends-all` when runtime switching is required.

## Capabilities

| Area | Available today |
|------|-----------------|
| Canonicalization | C14N 1.0, C14N 1.1, Exclusive C14N, comments and document subsets |
| Signatures | End-to-end XMLDSig signing and verification, same-document and caller-provided references, XPath transforms, `Manifest`, `KeyInfo`, and X.509 validation |
| Encryption | AES-CBC/GCM, RSA-OAEP, AES Key Wrap, multiple recipients, and Element/Content replacement |
| Policy | Typed immutable policies for algorithms, trust, parsing, external resources, transforms, and work limits |
| Providers | Provider-neutral crypto contracts with a pure-Rust RustCrypto implementation |
| CLI | Native `xmlsec1` process interface for sign, verify, encrypt, decrypt, keys, and capability discovery |

The implementation is fail-closed: unsupported algorithms, unavailable provider
capabilities, untrusted key sources, implicit external I/O, and exhausted resource
budgets produce explicit errors rather than compatibility fallbacks.
XML parsing work is cumulative per operation: initial input, recursive transform
adapters, staged mutations, dependency levels, and decryption retries share one
policy allowance rather than resetting limits inside helpers.

Interoperability evidence is deterministic and offline. The complete Phaos
XMLDSig 3, XMLDSig 1.1, and XMLDSig Second Edition interoperability corpora
are executed through the public sign/verify APIs with exact valid, invalid,
and fail-closed classifications; the generated
[compatibility ledger](docs/compatibility-ledger.md) keeps remaining
libxmlsec1 parity work explicit.

## Workspace Crates

[`xml-sec-xslt`](crates/xml-sec-xslt) is the reusable XSLT 1.0 engine. It owns
stylesheet compilation, XPath/XSLT value semantics, template execution,
result-tree construction, deterministic budgets, and XML/HTML/text serialization
without depending on XMLDSig, XMLEnc, cryptography, or system libraries.
Its `ExecutionEnvironment` makes resolver access, operation time, and extension
permissions explicit; callers can inject a fixed clock or reject nondeterministic
EXSLT date functions for reproducible security transforms.

The engine remains a separate architectural boundary. Runtime external-document
resolution and the `xml-sec` XMLDSig transform adapter are subsequent integration
layers; the main `xml-sec` crate therefore continues to reject XSLT transforms
until those policy and node-identity contracts are connected.

## Native CLI

Inspect the installed binary's runtime capability registry:

```sh
xmlsec1 version
xmlsec1 list-transforms
xmlsec1 list-key-data
```

The native binary covers sign/verify, template-preserving encrypt/decrypt, AES
key generation, capability queries, donor option syntax, and deterministic
process statuses through the same policy and provider pipelines as the library.
Unsupported algorithms, formats, providers, and policy controls fail closed;
document-selected certificates require explicit trust unless `--insecure` is
chosen. Selected unmodified upstream DSig, Enc, and Keys scenarios run against
the Rust binary without network access or a system `xmlsec1`. See the
[CLI compatibility guide](docs/cli.md) for exact commands, formats, key lookup,
diagnostics, and interoperability boundaries.

## XMLDSig Usage

`examples/sign.rs` builds an enveloped RSA-SHA256 signature and `examples/verify.rs`
verifies it through the embedded X.509 certificate:

```sh
cargo run --example sign > signed.xml
cargo run --example verify -- signed.xml
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

## Project Status

Current development focuses on remaining XMLDSig/XMLEnc algorithms, complete
upstream conformance classification, fuzzing, benchmarks, hardening, and API
stabilization.

The [compatibility ledgers](docs/compatibility-ledger.md) track libxmlsec1 1.3.13
public surface and operation-level behavior with source and test evidence. See
the [XMLDSig guide](docs/xmldsig.md), [XMLEnc guide](docs/xmlenc.md), and
[CLI compatibility guide](docs/cli.md) for detailed contracts and limitations.

The project tracks stable Rust and supports Rust 1.92 or newer.

## Specifications

| Spec | Status |
|------|--------|
| [Canonical XML 1.0](https://www.w3.org/TR/xml-c14n/) | Implemented; full-document and document-subset vectors |
| [Canonical XML 1.1](https://www.w3.org/TR/xml-c14n11/) | Implemented; `xml:id` and `xml:base` subset rules |
| [Exclusive C14N](https://www.w3.org/TR/xml-exc-c14n/) | Implemented; `InclusiveNamespaces PrefixList` support |
| [XMLDSig 1.0/1.1](https://www.w3.org/TR/xmldsig-core1/) | Core sign/verify pipelines; complete Merlin, Phaos 3, 2012 XMLDSig 1.1, and Second Edition interop corpora classified and executed |
| [XMLEnc](https://www.w3.org/TR/xmlenc-core1/) | Core AES-CBC/GCM encrypt/decrypt with RSA-OAEP and AES-KW implemented; broader conformance coverage in progress |

## License

Apache-2.0

## Support the Project

If `xml-sec` is useful in your stack, you can help fund continued implementation and maintenance.

![USDT TRC-20 Donation QR Code](assets/usdt-qr.svg)

USDT (TRC-20): `TFDsezHa1cBkoeZT5q2T49Wp66K8t2DmdA`
