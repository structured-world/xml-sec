# Key management

`xml_sec::key_manager::KeyInventory` is a caller-owned inventory of named key
material. The library imports bytes supplied by the caller; it never discovers
files, reads the environment, or fetches network resources. Applications keep
the inventory for as long as its keys are needed and pass the selected signer or
resolver to the normal XMLDSig/XMLEnc operation context. Import and execution
are both bounded by the operation's `ResourcePolicy` and cryptographic policy.
`KeyInventory::from_xml_bytes` accepts the same signing, verification,
encryption, or decryption policy snapshot used by the operation, so XML parser
allowances and resource limits cannot diverge. `decryption_resolver` also
requires the decryption snapshot and checks selected key material before
copying or decoding it. A permitted document `KeyName` may select a caller-owned
public key even when document-supplied key bytes are disabled; all sources in
the document's original `KeyInfo` remain subject to the source policy.
The `xmlenc` Cargo feature also enables `xmldsig`: the shared inventory uses
XMLDSig `KeyInfo` to represent named public recipients. Thus the inventory API
is available when an application selects `xmlenc` and an XML backend without
separately naming `xmldsig`.

The inventory accepts raw HMAC and AES secrets, public SPKI DER or PEM (also
PKCS#1 RSA public PEM), private PKCS#8 DER or PEM (including password-protected
PKCS#8), RSA PKCS#1 private DER or PEM, PKCS#12 bundles, DER X.509 certificates
and CRLs, and libxmlsec1 `keys.xml` bytes. The `keys.xml` importer recognizes
HMAC, AES, RSA, EC, and libxmlsec1's private DSA extension. DES key entries
are rejected because this build has no DES encryption operation. Unknown
algorithms in a mixed xmlsec key store are skipped; malformed supported entries
and ambiguous names fail. A PKCS#12 bundle with more than one private key is
rejected rather than assigning arbitrary aliases. A matching leaf certificate
is retained with its imported private key; byte-identical duplicate leaf bags
count as one certificate. Other certificates are retained as
untrusted chain material. `matching_certificate_chain()` returns a chain only
when its first certificate matches the private key; a CA-only PKCS#12 bundle
can still sign without emitting an unrelated signing certificate. A private
bundle's certificates do not become verification lookup candidates implicitly;
register a certificate explicitly for lookup or trust when needed.

Each imported key has an explicit `KeyUsages` set. For example, a key registered
for `Verify` cannot sign, and an `Encrypt`-only key cannot decrypt. Imported
public and PKCS#12 keys can be restricted at import with
`add_public_der_with_usages`, `add_public_pem_with_usages`, and
`add_pkcs12_with_usages`; the shorter methods authorize only operations
supported by that key family. An EC/DSA private key may sign but cannot be
assigned RSA decryption usage. Incompatible or empty usage sets are rejected.
EC and DSA public keys can verify but cannot be authorized as RSA encryption
recipients, including when imported from `keys.xml`. Imported certificates
are lookup candidates, **not trust anchors**, unless the caller
explicitly registers them as trusted. The operation's immutable policy still
decides algorithm acceptance, key minima, certificate validation, CRL checks,
and resource limits. An imported key is never permission to bypass that policy.
Caller-provided key names are bounded before import and charged to the retained
material budget for every stored copy, including public-key `KeyName` metadata.
Selection methods return `KeyStoreError::Policy` for operation-policy denials,
distinct from candidate-local `KeyStoreError::Selection` failures. Callers
must not retry another key after a policy rejection.
An already-selected public entry can expose its RSA recipient key directly via
`StoredPublicKey::rsa_encryption_key(&encryption_policy)` without a second
inventory name lookup. The operation policy is required so source sizes are
checked before RSA decoding. Direct and XML key-store imports accept only
16-, 24-, or 32-byte AES keys; unsupported public-key algorithms are rejected
at import rather than acquiring verification permission.
Public DSA entries must contain independently usable parameters; the inventory
does not infer missing parameters from another entry. Verification validates the
complete policy snapshot before selecting or copying any key, including HMAC.
EC SPKI and certificate imports use the verifier's uncompressed SEC1 profile;
compressed points are rejected before granting verification usage. Each complete
KeyValue is one resource for selection limits, not one resource per component.
When a named certificate is selected, enabled CRL checking retains both inventory
and document CRLs, with their combined resource budget checked before copying.

`add_private_der_with_password_callback` asks the caller for a zeroizing byte
password only for encrypted PKCS#8; plaintext input does not invoke it.
`add_pkcs12_with_password_callback` obtains a zeroizing string password before
decoding the bundle, after checking encoded size, visible bag/container counts,
and all visible MAC/encryption KDF parameters against one aggregate work budget.
KDF parameters inside encrypted SafeContents cannot be inspected without the
password: they are checked immediately after outer decryption, before running
the inner derivation (RFC 7292 sections 4.1 and 4.2.2). A missing
or wrong password returns a redacted error and never
triggers an unprotected fallback. Oversized encoded bundles return a typed
resource-policy error without invoking the callback.
`ResourcePolicy::max_key_import_kdf_work` and
`max_key_import_kdf_memory_bytes` can tighten protected-key derivation; both
are capped by implementation safety ceilings and checked before decryption.
Exceeding a recognized KDF's work or memory limit returns a policy error;
missing or incorrect passwords remain protected-container errors.
The CLI applies the same pre-decryption KDF limits to explicit protected PKCS#8
PEM/DER keys, including the generic private-key options, as to inventory imports.
When the PKCS#12 parser rejects an oversized salt, that distinct resource
rejection also returns a typed policy error.
The importer uses RustCrypto primitives with borrowed BER views; it supports
PBES2/PBKDF2 with AES-CBC and legacy SHA-1/3DES containers, plus SHA-1/SHA-2 MACs.
Private keys and decrypted temporary buffers are zeroized. Nested safe bags
share the same candidate and KDF budgets; a count denial is not a password error.
Temporary import allocations share the aggregate allowance with material already
retained by the inventory, and KDF workspaces are checked before derivation.
Named direct AES keys participate only in direct content-key resolution, not
in recipient-key unwrapping, so recipient hints cannot duplicate their candidate.

```rust
use xml_sec::key_manager::{KeyInventory, KeyUsages, SymmetricKeyKind};
use xml_sec::policy::ResourcePolicy;

let mut keys = KeyInventory::default();
keys.add_symmetric(
    "signer".into(),
    SymmetricKeyKind::Hmac,
    b"caller-owned-secret".to_vec(),
    KeyUsages::SIGN,
    &ResourcePolicy::default(),
)?;
```

The CLI is the explicit file-I/O compatibility boundary. `xmlsec1
sign|verify|encrypt|decrypt --keys-file keys.xml` loads one or more bounded
xmlsec key stores. `sign` and `decrypt` also accept `--pkcs12[:NAME] file.p12
--pwd PASSWORD`; password handling happens before protected-key decoding, and
a wrong or missing password fails without a plaintext fallback. Key files are
not silently combined with conflicting explicit key options. `KeyName` in a
signature or encryption template selects the corresponding inventory entry;
distinct matches are ambiguous unless the caller explicitly requests the CLI's
compatibility search mode. The CLI uses the same signing, verification,
encryption, and decryption policy checks as direct key options. During
decryption, a named direct AES key from `--keys-file` can be selected even
when `EncryptedData` also contains an `EncryptedKey` recipient.
For multiple RSA encryption recipients, `--lax-key-search` prefers an exact
name and then tries remaining compatible entries in store order. Each selected
entry is consumed once for that operation; insufficient entries fail before
any encrypted output is written.
Entries explicitly named by later recipient slots are reserved before assigning
fallbacks only when they match that slot's key metadata. An unnamed slot cannot
consume a later compatible exact match, but a stale name contradicted by metadata
does not reserve an incompatible key.
Reservation retains a decoded matching RSA candidate. Assignment moves that
candidate from the cache without decoding or charging it again; the candidate
work limit counts actual inspections, not reuse of an already inspected key.

For production applications, do not put passwords on a process command line:
load them through the application's secret channel and call the byte-oriented
library import API instead.
