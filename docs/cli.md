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
non-zero. Commands absent from the pinned 1.3.13 surface are not advertised;
historical `sign-tmpl` spellings are rejected instead of being routed to `sign`
without template-generation semantics.

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
Native aliases from the same donor metadata are accepted, including
`--pubkey-cert`, `--binary`, and command-local `-h`.

## Examples

Sign an existing XMLDSig template and verify it with an explicit public key:

```sh
xmlsec1 sign --privkey-pem signing-key.pem --output signed.xml template.xml
xmlsec1 verify --pubkey-pem signing-key.pub.pem signed.xml
```

Signing key options accept libxmlsec1's comma-separated certificate form,
`key.pem,leaf.pem,intermediate.pem,...`. Every certificate is structurally
validated, and the first certificate must contain the signing key. When the
template contains the optional direct `KeyInfo`
placeholder, the chain is embedded there in order under `X509Data`; omitting
that placeholder leaves the signed output without `KeyInfo`. Named signing keys
require a matching template `KeyName` even when only one key is supplied. A
named key with no template `KeyName` fails unless `--lax-key-search` explicitly
opts out of lookup. Verification and encryption instead leave a `KeyName`-less
template unconstrained when one explicit key is supplied.

Verification accepts `-` as the conventional stdin marker. For documents with
multiple signatures, `--node-id <id>` selects an ID-bearing start node and
verifies the single `Signature` in its subtree; missing and duplicate IDs fail
closed. Signing applies the same start-node contract and mutates only the
selected template's digest, signature, and optional key-info placeholders.
XPath and XPath Filter 2.0 verification uses libxmlsec1's legacy `here()`
binding at this CLI compatibility boundary. The Rust library API retains the
XMLDSig specification binding by default and requires an explicit opt-in for
legacy documents.
When the selected signature contains `KeyName`, named raw public-key and
explicit certificate inputs must match it; `--lax-key-search` is the explicit
opt-out. A signature without `KeyName` does not request a different identity,
so its sole explicit key remains usable even when that key has a registry name.

`--output` follows the upstream filename-template contract. The first
`{inputfile}` token is replaced with the input file's basename after removing
its final extension, for example `--output 'signed-{inputfile}.xml'` with
`templates/order.tmpl` writes `signed-order.xml`.

Encrypt and decrypt binary data with a direct AES key:

```sh
xmlsec1 encrypt --aes-key:content content.key \
  --binary-data plaintext.bin --output encrypted.xml encrypted-data.tmpl
xmlsec1 decrypt --aes-key:content content.key \
  --output plaintext.bin encrypted.xml
```

Files passed through `--aes-key` (`--aeskey` is an alias) use libxmlsec1's
binary-key contract: their
bytes are consumed verbatim rather than guessed to be Base64 text. `decrypt`
accepts both standalone `EncryptedData` and encrypted elements embedded in a
larger XML document; `--node-id` selects an ID-bearing operation start node and
then requires exactly one `EncryptedData` in its subtree.
Encryption preserves the template's `Id`, `Type`, `MimeType`, `KeyInfo`,
`EncryptionProperties`, and RSA-OAEP parameters while replacing only the
cryptographic `CipherValue` payloads.
For `--xml-data`, a missing template `Type` is materialized as XML Element
metadata so a later embedded-document decrypt can perform XML replacement.
When an encryption template contains a direct content-key `KeyName`, a named
AES key must match it. Likewise, an RSA wrapping key must match a recipient
`KeyName` inside `EncryptedKey`. An unnamed template does not constrain the sole
explicit key; an explicit mismatch fails unless `--lax-key-search` is supplied.
RSA private-key decryption accepts the upstream
`key.pem,certificate.pem,...` option syntax, consumes the first component as
the decryption key, and validates every certificate companion before decrypting.
Named AES and RSA decryption keys obey the selected `EncryptedData` or nested
`EncryptedKey` name unless lax lookup is requested. Selecting a standalone
`EncryptedData` by its own `Id` still returns opaque decrypted bytes rather than
routing them through XML document replacement. `--binary-data` rejects
templates explicitly typed as XML `Element` or `Content`; use `--xml-data` for
those templates so ciphertext metadata cannot mislabel arbitrary bytes as XML.
Supplying `--binary-data` and `--xml-data` together is rejected before either
payload is read; encryption requires exactly one payload mode.
A direct `--aes-key` cannot satisfy an `EncryptedKey` recipient embedded in the
template, so that inconsistent combination is rejected rather than preserving
a stale wrapped key.

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
PKCS#1 RSA public keys, and X.509 certificates. Encryption accepts RSA public
keys or RSA X.509 recipient certificates in PEM or DER. Explicit verification
certificate options pin verification to that certificate's public key instead
of permitting an embedded `KeyInfo` to select another identity. Certificates
discovered from document-controlled `X509Data` require a path through any
`--untrusted-*` intermediates to a caller-supplied `--trusted-pem` or
`--trusted-der` anchor. They are accepted without an anchor only when
`--insecure` explicitly disables trust validation. An explicit certificate
remains a caller-pinned identity; when separate anchors are supplied, it must
also build a valid path to one of them. Direct XMLEnc keys accept
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
