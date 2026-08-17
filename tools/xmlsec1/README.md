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
options are enforced by the parser registry. `--print-debug` emits text,
`--print-xml-debug` emits parseable operation contexts, and `--output` keeps
diagnostics on stdout while routing transformed data to a file.

## Keys and certificates

Bounded PEM and DER loaders support RSA, P-256/P-384, SPKI, PKCS#1, PKCS#8, and
X.509 inputs for their corresponding operations. Signing certificate lists are
leaf-first and can populate an existing `KeyInfo`; document-selected
certificates require caller trust unless `--insecure` is explicit. Named and
lax key lookup remains fail-closed on ambiguous or contradictory identity data.

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
