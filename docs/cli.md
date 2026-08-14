# Native `xmlsec1` CLI

The workspace ships a pure-Rust `xmlsec1` binary for applications and test
harnesses that use libxmlsec1 through its process interface. It delegates XML
Security operations to the same `xml-sec` policy and provider pipelines as the
library; it does not bind to libxml2, OpenSSL, or the libxmlsec1 C ABI.

```sh
cargo install xmlsec1-cli
xmlsec1 version
xmlsec1 list-transforms
xmlsec1 list-key-data
```

## Commands

The binary recognizes libxmlsec1's command names and leading-dash aliases for
`sign`, `verify`, `encrypt`, `decrypt`, `keys`, `list-transforms`,
`check-transforms`, `list-key-data`, `check-key-data`, `help`, and `version`.
Successful operations exit zero. Invalid arguments, unavailable capabilities,
policy violations, invalid signatures, decryption failures, and I/O errors exit
non-zero.

Capability checks and runtime dispatch use one registry. A transform or key-data
class absent from `list-*` is not silently substituted and causes `check-*` to
fail. Backend selection is equally strict: `--crypto rustcrypto` and
`--crypto default` select the built-in provider; other backend names do not
fall back to RustCrypto. The upstream runners pass `--crypto-config` for every
backend. RustCrypto accepts an absent or empty configuration directory because
it has no external backend configuration; a non-empty path is rejected rather
than ignored.

`help-all` enumerates every registered command and canonical option, including
which options accept `[:name]` and which consume a value. The listing is built
from the parser's option metadata, so it cannot advertise a syntax the parser
does not recognize. A `:<parameter>` suffix on flags or unrelated valued
options is rejected rather than silently activating the underlying option.

## Examples

Sign an existing XMLDSig template and verify it with an explicit public key:

```sh
xmlsec1 sign --privkey-pem signing-key.pem --output signed.xml template.xml
xmlsec1 verify --pubkey-pem signing-key.pub.pem signed.xml
```

Signing key options accept libxmlsec1's comma-separated certificate form,
`key.pem,leaf.pem,intermediate.pem,...`. Every certificate is validated and
embedded in order under `X509Data`; the first certificate must contain the
signing key's public key. Named keys are matched against the template's
`KeyName` even when only one key is supplied. `--lax-key-search` explicitly
opts out of that name match.

Verification accepts `-` as the conventional stdin marker. For documents with
multiple signatures, `--node-id <id>` selects an ID-bearing start node and
verifies the single `Signature` in its subtree; missing and duplicate IDs fail
closed.
Named `--pubkey-pem:name` and `--pubkey-der:name` inputs must match the selected
signature's `KeyName`; `--lax-key-search` is the explicit opt-out.

`--output` follows the upstream filename-template contract. The first
`{inputfile}` token is replaced with the input file's basename after removing
its final extension, for example `--output 'signed-{inputfile}.xml'` with
`templates/order.tmpl` writes `signed-order.xml`.

Encrypt and decrypt binary data with a direct AES key:

```sh
xmlsec1 encrypt --aeskey:content content.key \
  --binary-data plaintext.bin --output encrypted.xml encrypted-data.tmpl
xmlsec1 decrypt --aeskey:content content.key \
  --output plaintext.bin encrypted.xml
```

Files passed through `--aeskey` use libxmlsec1's binary-key contract: their
bytes are consumed verbatim rather than guessed to be Base64 text. `decrypt`
accepts both standalone `EncryptedData` and encrypted elements embedded in a
larger XML document; `--node-id` selects an embedded `EncryptedData` by `Id`.
Encryption preserves the template's `Id`, `Type`, `MimeType`, `KeyInfo`,
`EncryptionProperties`, and RSA-OAEP parameters while replacing only the
cryptographic `CipherValue` payloads.
For direct AES encryption, a named key must match an existing template
`KeyName` unless `--lax-key-search` is supplied. `--binary-data` rejects
templates explicitly typed as XML `Element` or `Content`; use `--xml-data` for
those templates so ciphertext metadata cannot mislabel arbitrary bytes as XML.

Generate an AES key store using the upstream command shape:

```sh
xmlsec1 keys --gen-key:content aes-256 keys.xml
```

The key name is optional. `--gen-key aes-128` writes an unnamed key without a
`KeyName` element, while `--gen-key:content aes-128` writes the supplied name.

## Compatibility boundary

The command and status surface is available now, while individual key formats,
algorithms, selectors, and policy controls remain capability-limited. Current
private-key loading accepts unencrypted PKCS#8 RSA, P-256, and P-384 plus
PKCS#1 RSA in PEM or DER; `--privkey-p8-pem` and `--privkey-p8-der` are accepted
as upstream PKCS#8 aliases. Public verification accepts SubjectPublicKeyInfo,
PKCS#1 RSA public keys, and X.509 certificates. Explicit certificate options
pin verification to that certificate's public key instead of permitting an
embedded `KeyInfo` to select another identity. When `--trusted-pem` or
`--trusted-der` is also supplied, the explicit certificate must build a valid
path through any `--untrusted-*` intermediates to a supplied anchor; `--insecure`
is the explicit opt-out. Direct XMLEnc keys accept
AES-128/256; RSA-OAEP supports both the XMLEnc 1.0 `rsa-oaep-mgf1p` and XMLEnc
1.1 parameter contracts. Encrypted
PKCS#8, PKCS#12, platform crypto stores, external DTDs, implicit network access,
and unsupported CLI policy knobs fail rather than weakening policy or falling
back.

The compatibility CLI accepts `--X509-skip-strict-checks`. libxmlsec1 uses
that switch to lower provider security levels for legacy certificate
signatures; RustCrypto has no corresponding provider strict mode and verifies
every certificate signature algorithm implemented by the selected provider,
so no additional policy relaxation is applied.

Filesystem arguments remain native `OsString` values, so Unix paths are not
required to be UTF-8. Values immediately following valued options are consumed
verbatim, including names beginning with `-`, matching the upstream parser.

The integration suite invokes a minimal checked-in snapshot of libxmlsec1 1.3.13
`testDSig.sh`, `testEnc.sh`, and `testKeys.sh` files without modification or a
Python translation layer. Covered runner cases include signature failure
classification, an AES-GCM decrypt/encrypt/decrypt cycle, and AES key-store
generation. `scripts/import-xmlsec1-cli-fixtures.sh` refreshes only those
scripts and selected vectors from the pinned donor commit; CI verifies the
snapshot in the donor-backed ledger job. The native CLI package tests require
no network checkout or system `xmlsec1`; separate workspace interoperability
tests still build the pinned C implementation as an external oracle. The generated
[compatibility ledger](compatibility-ledger.md)
records implemented commands and options separately from planned surface.
