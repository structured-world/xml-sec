# XML Security Documentation

These guides describe the current source tree. Versioned rustdoc on
[docs.rs](https://docs.rs/xml-sec) describes the published crate, which may lag
`main`; use the matching release tag when reproducing a deployed API. In
particular the policy-bound `XmlSecurity` facade is an unreleased API after 0.2.0.
No 1.0 release, full C compatibility or independent security certification is
implied by this documentation.

## Start Here

| Goal | Guide |
| --- | --- |
| Sign, authorize signed targets, encrypt and decrypt in Rust | [Policy-bound Rust API](rust-api.md) |
| Run high-level and low-level examples | [Executable examples](examples.md) |
| Select a deployment profile and compose restrictions | [Profiles](policy-profiles.md), [deployment runbook](deployment.md) |
| Load explicit policy configuration | [Configuration](policy-configuration.md), [schema v1](policy-schema-v1.md) |
| Replace a libxmlsec1 workflow | [Migration guide](migration-libxmlsec1.md), [native CLI](cli.md) |
| Choose a provider and understand unsupported operations | [Provider capability table](crypto-providers.md#capability-summary), [features](features.md) |

## Mechanisms And Evidence

- [XMLDSig and authenticated reference queries](xmldsig.md)
- [XML Encryption and replacement](xmlenc.md)
- [Key inventory, certificates and caller UTC facts](key-management.md)
- [OPC Relationship transforms](relationship-transforms.md)
- [Compatibility and unsupported-case ledger](compatibility-ledger.md)
- [XSLT conformance](xslt-conformance.md) and [performance](xslt-performance.md)
- [Security invariants](security-invariants.md), [historical regressions](historical-security.md)
  and [CVE inventory](cve-inventory.md)
- [Benchmarks and measurement boundaries](benchmarks.md)
- [Normative sources](standards-sources.tsv) and [standards audit](standards-audit.md)
- [Required CI, coverage and dependency gates](ci-hardening.md)
- [Unreleased and published changes](../CHANGELOG.md)

## Reproduce Documentation Checks

Run `cargo run -p xml-sec-tools -- documentation`.
It rejects missing core/config public rustdoc and broken intra-doc links, compiles
doctests, executes both API levels and their rejection paths, and tests the
exact policy sample through the real configuration loader/compiler. It needs
Rust, cargo-nextest and the [native FIPS build toolchain](features.md) for
all-feature rustdoc, but no network oracle or token.
`cargo run -p xml-sec-tools -- documentation docs` runs only the core/config rustdoc gate.

Public core rustdoc covers exported library items, not the unpublished private
XPath/parser implementation kernels. Alloc-only (no `std`) and native-provider
qualification remain separate gates; a documentation pass does
not replace interoperability, fuzzing or an audit.
