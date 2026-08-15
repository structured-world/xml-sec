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
`--print-debug` is text; `--print-xml-debug` emits a parseable donor-shaped
`VerificationContext` for both successful and invalid verification results,
including aggregate failures from authenticated Manifest references.

`--aes-key` files are raw binary key material (`--aeskey` remains a compatible
alias). Decrypting a standalone
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
Untyped `--xml-data` templates gain the inferred XML Element type, while direct
AES keys reject recipient `EncryptedKey` templates they cannot refresh.
Signing options validate every certificate from `key,leaf,intermediate,...` and embed the chain
when the template provides a `KeyInfo` placeholder, filling an empty `X509Data`
without erasing sibling key sources; verification accepts
stdin as `-` and can select one signature subtree with `--node-id`. Output paths
support the upstream `{inputfile}` basename template, and `--gen-key[:name]`
emits both named and unnamed AES key-store entries. `help-all` is generated from
the parser registry. Named signing keys require a template `KeyName`; named
verification and encryption/decryption options form key sets and require the
selected XML `KeyName` to identify exactly one entry, unless lax lookup is
explicit. Unnamed verification
and encryption templates leave the sole explicit key unconstrained. Embedded
X.509 certificates require a caller trust anchor unless `--insecure` is
explicit; an explicit certificate remains a caller-pinned identity. Binary
payloads cannot be emitted with XML Element/Content type metadata.
