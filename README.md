# xml-sec

Pure Rust XML Security library. Drop-in replacement for libxmlsec1.

**No C dependencies. No cmake. No system libraries. Just `cargo add xml-sec`.**

## Features

- **C14N** — XML Canonicalization (inclusive + exclusive, W3C compliant)
- **XMLDSig** — XML Digital Signatures (sign + verify, enveloped/enveloping/detached)
- **XMLEnc** — XML Encryption (symmetric + asymmetric)
- **X.509** — Certificate-based key extraction and validation

## Why?

Every SAML, SOAP, and WS-Security implementation depends on libxmlsec1 — a C library that:
- Requires cmake + libxml2 + OpenSSL/NSS/GnuTLS to build
- Breaks on Alpine/musl static linking
- Has decades of CVEs in XML parsing and signature validation
- Cannot cross-compile easily

`xml-sec` is a ground-up Rust rewrite using `roxmltree` + `ring` + `x509-parser`. Single `cargo build`, works everywhere Rust works.

## Status

**Pre-release.** API is unstable. Not ready for production use.

Current toolchain target: latest stable Rust.
Current MSRV: Rust 1.92.

## Specifications

| Spec | Status |
|------|--------|
| [Canonical XML 1.0](https://www.w3.org/TR/xml-c14n/) | Planned |
| [Exclusive C14N](https://www.w3.org/TR/xml-exc-c14n/) | Planned |
| [XMLDSig](https://www.w3.org/TR/xmldsig-core1/) | Planned |
| [XMLEnc](https://www.w3.org/TR/xmlenc-core1/) | Planned |

## License

Apache-2.0
