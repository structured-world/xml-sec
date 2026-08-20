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
`check-transforms`, `list-key-data`, `check-key-data`, `help`, `help-all`, and
`version`. Command-specific help uses the donor's `help-<command>` grammar, such
as `help-sign`, `help-verify`, `help-encrypt`, and `help-keys`.
Successful operations exit `0`. Invalid arguments, unavailable capabilities,
policy violations, invalid signatures, decryption failures, and I/O errors all
exit `1`; the current CLI does not assign category-specific failure statuses.
Commands absent from the pinned 1.3.13 surface are not advertised;
historical `sign-tmpl` spellings are rejected instead of being routed to `sign`
without template-generation semantics.

`--print-debug` emits donor-style text context diagnostics, while
`--print-xml-debug` emits a well-formed operation context. Signing and
verification use `SignatureContext` and `VerificationContext`; encryption and
decryption use `DataEncryptionContext` and `DataDecryptionContext`. With
`--output`, the transformed payload is written to the requested file and
diagnostics remain on stdout. Verification diagnostics retain donor
`OK`/`FAILED` status and failure-reason vocabulary and are emitted for invalid
signatures before the command returns its required non-zero status.
Without `--output`, signing, encryption, and decryption preserve libxmlsec1's
stdout ordering: the transformed payload is followed by requested diagnostics
on the same stream. Select `--output` whenever a downstream process requires a
standalone XML or binary payload while diagnostics are enabled.
Verification produces status and diagnostics rather than a transformed
document. `verify --output` therefore fails with a command-specific "not
applicable" diagnostic instead of reporting generic malformed syntax.
`--ignore-manifests` is accepted by both DSig commands; for signing it is a
compatibility no-op because signing processes only `SignedInfo` references.
XML file and `--xml-data` inputs accept XML 1.0 UTF-8 and BOM-marked UTF-16LE or
UTF-16BE, with resource limits charged against source bytes before decoding.
`--print-crypto-library-errors` is accepted for donor argv compatibility. The
fixed RustCrypto provider has no process-global OpenSSL error queue, so the flag
does not add a second diagnostic stream beyond the operation error already
reported by the CLI.
`--verbose` is likewise accepted so unmodified donor runners can invoke the
binary, but libxmlsec1's flag-controlled detailed error mode is not implemented
yet and remains classified as planned compatibility work.
PEM, DER, and PKCS#8 key and certificate options enforce the encoding and
container named by the selected option; the CLI does not guess another format
when decoding fails.

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
The same metadata enforces option multiplicity: key, certificate, ID-attribute,
and key-generation options may repeat where libxmlsec1 marks them as
multi-value; repeating singleton output, provider, payload, selector, password,
or policy options is rejected even when canonical and alias spellings are mixed.
Only exact donor prefixes are accepted: canonical and long alias names use `--`,
while one-character aliases use `-`. The first standalone `--` explicitly ends
option parsing. The first positional argument also ends option parsing. After
either event, every later argument, including `--`, is positional even when it
begins with `-`.

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
placeholder, the chain is embedded there in order under `X509Data`. An empty
`X509Data` child is populated in place, preserving sibling sources such as the
`KeyName` used to select the signing key. Placeholder attributes are preserved;
non-conflicting attributes emitted by the writer are added, while conflicting
expanded names fail closed. KeyInfo
materialization occurs before reference digest computation, so a template may
sign its populated `KeyInfo` by ID. Omitting `KeyInfo` leaves the signed output
without `KeyInfo`. Preserved RSA/EC `KeyValue`, `DEREncodedKeyValue`, and X.509
identity sources must identify the selected signing key; selector-only
`X509Data` additionally requires a matching signing-certificate companion.
Named signing keys
require a matching template `KeyName` even when only one key is supplied. A
named key with no template `KeyName` fails unless `--lax-key-search` explicitly
opts out of lookup. Verification and encryption instead leave a `KeyName`-less
template unconstrained when one explicit key is supplied. Lax signing treats
each comma-separated key and certificate chain as one candidate and continues
past malformed, mismatched, algorithm-incompatible, or policy-rejected
candidates until it finds a usable one; it never weakens the compiled signing
policy. Every private-key source and certificate companion is charged to one
invocation-wide external-material byte budget before private-key decoding, so
lax search cannot multiply bounded per-file parsing work without bound.

Verification accepts `-` as the conventional stdin marker. Verification starts
at the document root and uses the first descendant `Signature` in document order.
For documents with multiple operation subtrees, `--node-id <id>` moves that start
node and verifies its first descendant `Signature`, matching libxmlsec1's
depth-first `xmlSecFindNode` selection; missing and duplicate IDs fail closed.
The standard `ID`, `Id`, and `id` local names are recognized whether
unqualified or namespace-qualified, including `wsu:Id` and `xml:id`. Signing
applies the same start-node contract and mutates only the
selected template's digest, signature, and optional key-info placeholders.
Custom ID declarations match libxmlsec1's two request-local forms:
`--add-id-attr NAME` registers an attribute local name on every element, while
`--id-attr[:ATTR] [NAMESPACE-URI:]ELEMENT` (default `ATTR` is `id`) limits the
registration to one element local name. Without `NAMESPACE-URI:`, that local
name matches elements in any namespace, as in libxmlsec1; with the component
present, it matches that exact namespace (`:ELEMENT` means no namespace).
Registrations affect both
`--node-id` selection and same-document reference resolution; duplicate ID
values remain ambiguous and fail closed.
XPath and XPath Filter 2.0 signing and verification use libxmlsec1's legacy
`here()` binding at this CLI compatibility boundary, so CLI-produced signatures
round-trip with the donor. The Rust library API retains the XMLDSig specification
binding by default and requires an explicit opt-in for legacy documents.
Repeatable named raw public-key and explicit-certificate options form a key set.
Every direct `KeyName` in the selected signature participates in lookup and must
identify exactly one supplied key; duplicate matches for the same name fail as
ambiguous, while distinct names are searched in document order.
`--lax-key-search` is the explicit opt-out. A signature without `KeyName` does
not request a different identity, so its sole explicit key remains usable even
when that key has a registry name. For a repeated explicit key set, lax lookup
ignores `KeyName` identity and selects the first compatible option in command-line
order, matching libxmlsec1's key-type search rather than treating ambiguity as a
strict lookup failure. Both strict and lax searches parse the document, process
References, and canonicalize `SignedInfo` once; only the final signature
primitive is retried across candidates.

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
bytes are consumed verbatim rather than guessed to be Base64 text. Reads are
bounded to the largest supported AES key before allocation. `decrypt`
accepts both standalone `EncryptedData` and encrypted elements embedded in a
larger XML document; `--node-id` selects an ID-bearing operation start node and
then requires exactly one `EncryptedData` in its subtree.
Encryption preserves the template's `Id`, `Type`, `MimeType`, existing `KeyInfo`
metadata, `EncryptionProperties`, and RSA-OAEP parameters. It may populate an
empty `KeyInfo` placeholder with generated key or recipient metadata while
replacing the cryptographic `CipherValue` payloads.
The selected `EncryptedData` and every existing template `EncryptedKey` must
contain exactly one direct `CipherData` with one direct `CipherValue`. Each
`EncryptedKey` must also contain exactly one direct `EncryptionMethod`;
optional `DigestMethod`, `MGF`, and `OAEPparams` children must each occur at
most once. Ambiguous or incomplete recipient metadata is rejected before key
wrapping. The content `EncryptionMethod` is validated under the same structural
contract before encryption: optional `KeySize` is singular, positive, and must
match the fixed AES algorithm URI, while OAEP-only children are rejected.
When nested recipient `KeyInfo` already carries `RSAKeyValue`, an X.509
certificate, or `DEREncodedKeyValue`, that cryptographic identity must match
the selected RSA wrapping key. Unmatchable or contradictory metadata is
rejected before encryption rather than being preserved beside ciphertext for
a different recipient. Selector-only `X509Data` (`X509SubjectName`,
`X509IssuerSerial`, `X509SKI`, or `X509Digest`) is matched against certificates
supplied through `--pubkey-cert-pem` or `--pubkey-cert-der`; a bare public key
cannot satisfy certificate identity metadata. `KeyName` remains a lookup hint
and empty `X509Data` remains a non-binding placeholder.
For `--xml-data`, a missing template `Type` is materialized as XML Element
metadata so a later embedded-document decrypt can perform XML replacement. As
in libxmlsec1, the input is parsed as an XML document: Element encryption
serializes its document element, while Content encryption serializes only that
element's children and materializes inherited namespace bindings on those
children. Text children retain their XML lexical representation, including
entity references and CDATA sections, so text cannot become markup. XML
declarations and document-boundary nodes are not encrypted as replacement
plaintext. The source document and resulting plaintext are checked against
their respective compiled resource ceilings.
Repeatable AES or RSA key options form a key set. A direct content-key `KeyName`
must select exactly one AES key, while a recipient `KeyName` inside
each `EncryptedKey` must select exactly one RSA wrapping key. Multi-recipient
templates build one wrapped content key per recipient, preserving each
recipient's OAEP parameters and document order; every recipient must resolve
without missing or duplicate key matches. Under lax lookup, compatible wrapping
keys are consumed in command-line order rather than reused for every recipient.
Compatibility includes any preserved `RSAKeyValue`, X.509, or
`DEREncodedKeyValue` identity, so lax lookup skips an earlier syntactically
valid key when it contradicts the recipient metadata.
Named and unnamed recipient slots remain distinct identities. An unnamed template
does not constrain the sole explicit key; missing and duplicate matches fail
unless `--lax-key-search` is supplied.
An empty template `KeyInfo` is populated with generated direct-key identity or
recipient metadata, so strict decryption retains the selected key name.
RSA private-key decryption accepts the upstream
`key.pem,certificate.pem,...` option syntax, consumes the first component as
the decryption key, and validates every certificate companion before decrypting.
The first companion certificate must contain the private key's public key;
remaining companions must be structurally valid certificates. Lax lookup skips
an invalid compound candidate as a unit rather than retaining its private key.
All asymmetric key and certificate files are read through one absolute
process-safety ceiling before format decoding. Certificate companions are
charged by source bytes before decoded DER is retained, so PEM padding and
repeated paths cannot bypass the aggregate external-resource budget.
Verification also deduplicates
repeated certificates within each lookup or trust role, validates every
explicit trust input even when a raw public key is selected, and charges every
read certificate source to the compiled aggregate external-resource budget
before retained DER is deduplicated.
Repeatable named private keys form one resolver: each nested `EncryptedKey` is
matched to its own key, and duplicate keys for the same recipient fail as
ambiguous instead of preventing distinct recipients from sharing an invocation.
Strict verification treats every selected public-key option as explicit
configuration and fails on any load, certificate-resolution, or key-policy
error. Only `--lax-key-search` may skip an unusable verification candidate.
Named AES and RSA decryption keys obey the selected `EncryptedData` or nested
`EncryptedKey` name unless lax lookup is requested. Selecting a standalone
`EncryptedData` by its own `Id` still returns opaque decrypted bytes rather than
routing them through XML document replacement. `--binary-data` requires a
standalone `EncryptedData` template and rejects templates explicitly typed as
XML `Element` or `Content`; embedded templates require `--xml-data` so every
successful encryption has a reciprocal document-replacement decryption path.
Supplying `--binary-data` and `--xml-data` together is rejected before either
payload is read; encryption requires exactly one payload mode.
Lax AES-GCM lookup retries a bounded key set inside one authenticated
decryption operation and releases each rejected plaintext before trying the
next key. Standalone decryption stops at the first authenticated plaintext;
document replacement stops at the first plaintext that also satisfies the XML
replacement contract. AES-CBC provides no key authentication, so decryption
requires metadata to select exactly one distinct key identity and rejects
unordered distinct candidates rather than treating valid padding as proof of
the correct key. Repeated copies of identical key bytes remain one identity,
while every source lookup or unwrap still consumes the operation work budget.
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
also build a valid path to one of them. `--verify-crls` applies to that validated
path and does not turn a pinned certificate without anchors into a chain-based
trust source. Direct XMLEnc keys accept
AES-128/256; RSA-OAEP supports both the XMLEnc 1.0 `rsa-oaep-mgf1p` and XMLEnc
1.1 parameter contracts. Encrypted
PKCS#8, PKCS#12, platform crypto stores, external DTDs, implicit network access,
and unsupported CLI policy knobs fail rather than weakening policy or falling
back.

The compatibility CLI accepts `--X509-skip-strict-checks` at the explicit donor
boundary. libxmlsec1 uses that switch to lower provider security levels for
legacy certificate signatures; RustCrypto has no corresponding strict mode and
already verifies every certificate signature algorithm implemented by the
selected provider, so no additional relaxation is applied.

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
