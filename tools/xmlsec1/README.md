# xmlsec1-cli

Pure-Rust `xmlsec1` command-line interface backed by the
[`xml-sec`](https://crates.io/crates/xml-sec) XMLDSig, XMLEnc, policy, and
cryptographic-provider pipelines.

```sh
cargo install xmlsec1-cli
xmlsec1 version
xmlsec1 list-transforms
```

See the repository's [CLI compatibility guide](https://github.com/structured-world/xml-sec/blob/main/docs/cli.md) for command
examples, supported key formats, fail-closed behavior, and upstream runner
coverage.

## Options and output

Exact donor long names and short aliases are accepted; singleton and repeatable
options are enforced by the parser registry. `--print-debug` emits text and
`--print-xml-debug` emits parseable operation contexts. As in libxmlsec1,
diagnostics follow transformed data on stdout when `--output` is absent;
selecting `--output` routes the data to a file and leaves diagnostics on stdout.
Verification has no transformed document, so `verify --output` is reported as
recognized but inapplicable rather than as malformed command syntax. XML inputs
accept UTF-8 and BOM-marked UTF-16LE/BE; transcoded declarations are emitted as
UTF-8 so the declaration remains consistent with output bytes. Explicit
UTF-16LE/BE declarations must agree with the BOM byte order.
UTF-8 octets must either omit the encoding declaration or declare `UTF-8`/`UTF8`;
contradictory labels are rejected before XML processing.

## Keys and certificates

Bounded PEM and DER loaders support RSA, P-256/P-384, SPKI, PKCS#1, PKCS#8, and
X.509 inputs for their corresponding operations. Signing certificate lists are
leaf-first and can populate an existing `KeyInfo`; document-selected
certificates require caller trust unless `--insecure` is explicit. Named and
lax key lookup remains fail-closed on ambiguous or contradictory identity data,
including preserved signing `KeyValue`, `DEREncodedKeyValue`, and `X509Data`.
Generated signing certificates replace stale X.509 identity assertions without
discarding caller-owned CRLs, extension children, or `X509Data` attributes.

## Encryption

AES-CBC/GCM and RSA-OAEP operations preserve validated XML Encryption template
metadata. XML Element and Content payloads retain namespace and lexical text
semantics, standalone untyped ciphertext decrypts to bytes, and malformed or
unsupported templates fail before output. `keys --gen-key[:name]` generates AES
key-store entries; RSA is supported as operation key data, not as a generation
algorithm.

## Identifiers

`--node-id`, `--add-id-attr`, and scoped `--id-attr` registrations drive the
same fail-closed XML ID resolution used by XMLDSig references and XMLEnc
operation selection. See the full compatibility guide for namespace matching,
key selection, limits, aliases, diagnostics, and selected donor-runner coverage.
