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

`--aes-key` files are raw binary key material (`--aeskey` remains a compatible
alias). Decrypting a standalone
`EncryptedData` returns opaque decrypted bytes; embedded encrypted data uses
in-document replacement and supports operation-start selection with
`--node-id`. Encryption retains template metadata and RSA-OAEP parameters;
PKCS#1 RSA, unencrypted PKCS#8, SPKI, and X.509 PEM or DER key material is
normalized into the same core signing, verification, and encryption pipelines.
Signing options validate every certificate from `key,leaf,intermediate,...` and embed the chain
when the template provides a `KeyInfo` placeholder; verification accepts
stdin as `-` and can select one signature subtree with `--node-id`. Output paths
support the upstream `{inputfile}` basename template, and `--gen-key[:name]`
emits both named and unnamed AES key-store entries. `help-all` is generated from
the parser registry. Named signing keys require a template `KeyName`; named
verification and encryption/decryption keys require an exact match when the
selected XML names a key, unless lax lookup is explicit. Unnamed verification
and encryption templates leave the sole explicit key unconstrained. Binary
payloads cannot be emitted with XML Element/Content type metadata.
