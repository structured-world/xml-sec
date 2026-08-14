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

`--aeskey` files are raw binary key material. Decryption accepts standalone
`EncryptedData` and performs in-document replacement, optionally selected by
`--node-id`. Encryption retains template metadata and RSA-OAEP parameters;
PKCS#1 RSA and PKCS#8/SPKI/X.509 PEM or DER key material is normalized into the
same core signing, verification, and encryption pipelines. Signing options
embed every certificate from `key,leaf,intermediate,...`; verification accepts
stdin as `-` and can select one signature subtree with `--node-id`. Output paths
support the upstream `{inputfile}` basename template, and `--gen-key[:name]`
emits both named and unnamed AES key-store entries.
