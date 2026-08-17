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

The parser rejects repeated singleton options, including mixed canonical and
alias spellings, while preserving donor multi-value key and certificate inputs.
`--print-debug` is text; `--print-xml-debug` emits parseable donor-shaped
signature, verification, encryption, and decryption contexts. When `--output`
is present, transformed data goes to the file while diagnostics remain on
stdout. Verification output covers both successful and invalid results,
including aggregate failures from authenticated Manifest references.

All key and certificate files are bounded before decoding. `--aes-key` consumes
raw binary key material (`--aeskey` remains a compatible alias); it is never
guessed to be Base64 text. Decrypting a standalone
`EncryptedData` returns opaque decrypted bytes; embedded encrypted data uses
in-document replacement and supports operation-start selection with
`--node-id`. Encryption retains template metadata and RSA-OAEP parameters;
signing accepts PKCS#1 RSA and unencrypted PKCS#8 private keys, verification
accepts SPKI, PKCS#1 RSA public keys, and X.509 certificates, and RSA encryption
accepts public keys or recipient certificates. Supported formats are normalized
into the corresponding core pipeline from PEM or DER.
Preserved recipient `RSAKeyValue`, X.509 certificate, and
`DEREncodedKeyValue` metadata must identify the selected RSA wrapping key;
contradictory metadata fails before ciphertext is emitted.
Content and recipient templates require exactly one direct `CipherData` and
`CipherValue`; `EncryptedData` children must follow the XML Encryption sequence,
and incomplete, duplicate, or out-of-order payload containers fail before output.
Multi-recipient RSA templates preserve named and unnamed identities and consume
distinct lax-search wrapping keys in command-line order.
Untyped `--xml-data` templates gain the inferred XML Element type. XML payloads
are parsed as documents: Element encrypts the root element and Content encrypts
its children with inherited namespace bindings materialized, excluding the
declaration and document-boundary nodes. Text children preserve entity and
CDATA lexical forms rather than becoming markup. Source-document and
encrypted-plaintext limits are enforced independently. Direct AES keys reject
recipient `EncryptedKey` templates they cannot refresh.
Signing options validate every certificate from `key,leaf,intermediate,...` and embed the chain
when the template provides a `KeyInfo` placeholder, filling an empty `X509Data`
without erasing sibling key sources; verification accepts
stdin as `-` and can select one signature subtree with `--node-id`.
The CLI supports request-local custom IDs through global `--add-id-attr NAME` and
element-scoped `--id-attr[:ATTR] [NAMESPACE-URI:]ELEMENT`; the same
registrations drive Reference resolution and XMLEnc operation selection. An
unqualified element name matches its local name in any namespace; an explicit
namespace component restricts the match to that expanded name.
Output paths support the upstream `{inputfile}` basename template. `--gen-key`
emits one unnamed AES key-store entry, while `--gen-key:<name>` emits one named
entry. `help-all` is generated from
the parser registry. Named signing keys require a template `KeyName`; named
verification and encryption/decryption options form key sets and require the
selected XML `KeyName` to identify exactly one entry, unless lax lookup is
explicit. Lax lookup searches compatible entries in command-line order instead
of enforcing `KeyName`; preserved RSA, DER, and X.509 cryptographic identity
metadata must still match the selected key. Unnamed verification
and encryption templates leave the sole explicit key unconstrained. Embedded
X.509 certificates require a caller trust anchor unless `--insecure` is
explicit; an explicit certificate remains a caller-pinned identity. Binary
payloads cannot be emitted with XML Element/Content type metadata.
