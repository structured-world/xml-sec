# Cryptographic providers

## Optional PKCS#11 external keys

The `pkcs11` feature enables the `cryptoki` adapter. Load and initialize
the module explicitly, then create `provider::pkcs11::Pkcs11Provider` from that
module and a caller-selected slot and call `login`. The adapter opens a read-only
session: cryptographic operations and transient session objects do not require
token-write access. The core never discovers a
module, reads a PIN from configuration, initializes a token, or retries credentials.
Keep the module loaded until worker threads have stopped: native modules can
register thread-local cleanup callbacks that must run before library unloading.

Resolve persistent objects by exact binary `CKA_ID` with `rsa_private_key`,
`rsa_public_key`, `aes_key`, or `agreement_key`. Ambiguous IDs are rejected.
RSA PKCS#1 v1.5 signatures/verification with SHA-1/224/256/384/512, RSA-OAEP
recovery, AES-CBC/GCM decryption, AES key unwrap and P-256/P-384/P-521 ECDH run
in the token. Private RSA/EC attributes are never
read. AES-unwrapped content keys are sensitive, non-extractable session objects;
`RecoveredContentKey::into_key` rejects their export. ECDH returns the derived
shared secret for an explicitly selected subsequent KDF, not the private scalar.
RSA-OAEP recovery uses token-side `C_Decrypt`, validates the recovered CEK width,
then imports it as a non-extractable session object. The transient host CEK is
zeroized on success and failure. This is not a guarantee that RSA-recovered
symmetric bytes never enter host memory; private RSA key material never does.

Pass the provider to the existing XML operation context. Use
`PrivateKeyDecryptor::provider_key`, `OpaqueContentKeyResolver`, or
`OpaqueKekDecryptor` for RSA recipients, direct opaque CEKs, or opaque KEKs.
One immutable operation policy still controls acceptance; token `CKA_SIGN`,
`CKA_VERIFY`, `CKA_DECRYPT`, `CKA_UNWRAP` and `CKA_DERIVE` enforce key usage
independently. A handle is bound to its exact provider instance, not just the
engine name. Clones share a serialized session; independent instances use
independent sessions. There is no fallback to software keys or another engine.
Selection is currently through the library API; the CLI does not discover modules
or accept token credentials.

Mechanism enumeration cannot prove support for every parameter combination.
For example SoftHSM rejects SHA-256 OAEP parameters despite listing OAEP; this
is an explicit unsupported-parameters result, not permission to downgrade to
SHA-1. Operational errors expose typed redacted classes, never raw module
diagnostics or credentials. An explicit invalid-ciphertext result maps to
`AuthenticationFailed`; a module's generic failure remains an operational error,
not proof of a bad authentication tag. Both paths release no plaintext.
RSA-PSS signing/verification supports SHA-1/256/384/512 with independent
MGF1 SHA-1/224/256/384/512 and explicit salt length, when the token accepts
the selected parameters. SHA-224/SHA-3 PSS message digests are not advertised
because the adapter does not expose matching combined token mechanisms.
ECDSA signing, certificate/CRL verification,
private software key import, raw symmetric encryption, and KDF execution are
not advertised by this adapter.

Run `bash scripts/test-pkcs11.sh /absolute/path/to/libsofthsm2.so` for the
integration suite, or add `--workspace` for all workspace tests with this
feature. The harness creates and removes its own token store and cannot reset
tokens from a normal SoftHSM configuration. Tests cover complete XML signature
and encryption pipelines, usage restrictions, wrong PINs, tampering, stale
objects, provider binding and concurrent operations. CI runs both parser
backends and differential mode against this same harness.

RustCrypto is the default. Enable `aws-lc-fips` to additionally compile the official
`aws-lc-rs` wrapper with its `fips` feature and without its default features. This
links the AWS-LC FIPS module, not the ordinary AWS-LC module. It requires the native
toolchain described in the [AWS build requirements](https://aws.github.io/aws-lc-rs/requirements/index.html).

Provider choice is explicit operation context, independent of the immutable security
policy. Pass `AwsLcFipsProvider` to `SignContext::provider`, `VerifyContext::provider`,
`EncryptedDataBuilder::provider`, or `DecryptContext::provider`. Use
`KeyInventory::signing_key_with_provider` and
`KeyInventory::decryption_resolver_with_provider` to import private material directly
into the chosen engine. Native private handles reject use through another provider;
public SPKI bytes can be verified by either engine. There is no automatic fallback.

Key-container decoding remains a distinct inventory import boundary: encrypted
PKCS#8 and PKCS#12 password-based container processing uses the existing RustCrypto
importer. Selecting AWS-LC does not turn that importer into an approved FIPS service.
The CLI's generic `--privkey-pem`/`--privkey-der` options also preserve traditional
RSA PKCS#1 and EC SEC1 containers independently of the provider. Traditional
OpenSSL encrypted PEM is decrypted at this same container boundary. Normalization
is resource-bounded; selecting AWS-LC still imports the resulting key into its
native handle without falling back to RustCrypto for the requested operation.
Explicit `--pkcs8-pem`/`--pkcs8-der` options remain PKCS#8-only. Missing or incorrect
passwords are terminal, including during lax key search.
Applications requiring an exclusively native secret-processing boundary should supply
plain PKCS#8 directly to `AwsLcSigningKey::from_pkcs8_der` or
`AwsLcRsaPrivateKey::from_pkcs8_der`, rather than using protected-container import.

The native `xmlsec1` accepts `--crypto aws-lc-fips` when this feature is compiled.
Without it, that selection is an explicit unavailable-provider error.

## Mechanisms

With `xmlenc`, RustCrypto exposes X25519 and P-256/P-384/P-521 ECDH through
`CryptoProvider::agree_key`, using opaque `RustCryptoX25519Key` and
`RustCryptoEcdhKey` handles. ECDH validates peer points and preserves fixed-width
shared secrets; X25519 rejects noncontributory peers. These handles do not expose
private-key bytes. Returned shared-secret bytes belong to the caller, which must
retain them in zeroizing storage until derivation finishes.

`RustCryptoDhKey` adds finite-field DH with explicitly supplied p/q/g/private
components. Import borrows the shared `KeyEstablishmentBudget` and selected
provider's randomness. Prime checks use bounded independent Miller-Rabin bases;
domain/order and peer-subgroup checks precede private exponentiation. The handle
preserves the modulus-width shared secret, including leading zero octets. This is
probable-prime validation, not proof of generation provenance or FIPS approval.
DH is denied by default. Granting it does not disable the policy's default
2048-bit modulus and 224-bit subgroup minima; legacy domains need explicit
lower minima, which are rechecked under the policy of every consuming operation.
Finite-field modular work and boxed workspace consume the same monotonic
operation allowance as agreement and derivation, including failed attempts.

`CryptoProvider::derive_key` supports HKDF extract-and-expand with
HMAC-SHA-1/224/256/384/512, preserving salt, info and requested output length.
The [RFC 5869 section 2.3](https://www.rfc-editor.org/rfc/rfc5869.html#section-2.3)
output bound is checked before output allocation. Primitive capability is not
XML operation support or policy permission: callers must enforce their operation
policy and cumulative resource budgets before dispatch.

The same provider also implements PBKDF2 with explicit HMAC-SHA-1/224/256/384/512
PRFs and ConcatKDF with SHA-1/224/256/384/512. PBKDF2 accepts positive iteration
counts without truncating the API's 64-bit value. ConcatKDF preserves arbitrary
MSB-first context bit strings through `KdfContext::Bits`; malformed padding is
rejected rather than silently hashing storage octets. SHA framing uses RustCrypto
compression, with no per-block concatenation allocation. These primitive APIs
do not themselves resolve `AgreementMethod`, `DerivedKey`, or external resources.

The legacy DH KDF uses `KdfContext::LegacyDh` to keep the consuming algorithm URI
and decoded nonce distinct. Decimal KeySize is derived from the requested output
width; the two-character uppercase counter is bounded to 255 digest blocks.
This follows [XMLEnc 1.1 section 5.6.2.2](https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-DHKeyAgreementLegacyKDF),
including the corrected example digest in [erratum E01](https://www.w3.org/2008/xmlsec/errata/xmlenc-core-11-errata.html).
KDF capability does not imply finite-field DH key-agreement capability.

`xmlenc::parse_key_derivation_method` validates the ConcatKDF, PBKDF2 and
libxmlsec1 HKDFParams XML layouts under the operation's XML/metadata policy.
`KeyDerivationMethod::parameters` rejects a contradictory explicit KeyLength.
ConcatKDF retains both the unpadded combined bit string and individual field
boundaries for application-specific algorithm/party identity validation, without
duplicating field buffers. Parsing parameters is not permission to execute them.

`KeyDerivationMethod::derive_key` uses a caller's shared `KeyEstablishmentBudget`
to check the compiled `KeyEstablishmentPolicy` before provider dispatch. The
same policy type is composed into encryption and decryption policy snapshots.
Its default permits SHA-2 KDFs and ECDH/X25519 agreement, not legacy DH or SHA-1;
those require explicit grants independent of primitive capability. Budgets count
conservative SHA compression blocks (including HMAC framing), not just PBKDF2
iterations, and reserve cumulative shared-secret and derived-key output bytes
before allocation.
Every recipient and retry in an enclosing operation must share the budget;
provider failures do not refund it. Returned derived keys use zeroizing storage.

`DerivedKeyDecryptor::content` and `DerivedKeyDecryptor::wrapping` bind parsed
KDF parameters and borrowed application secrets to an explicitly selected
content or wrapping algorithm. `DerivedKeyInput` accepts borrowed secret bytes
or a caller-owned opaque agreement handle and encoded peer. Public decrypt
invokes agreement and derivation inside its
operation's key-resolution gate and uses the operation snapshot, regardless of
the policy used earlier to parse parameters. Nested resolvers must forward the
same `KeyCandidateBudget`; its `derive_key` and `agree_and_derive` methods retain cumulative KDF usage
across sources and failed attempts. Agreement checks KDF permission and reserves
both shared-secret and derived-key buffers before scalar multiplication.
Wrapping-key recovery reuses the existing
policy-aware KEK path without copying the derived KEK. The complete attempt's
candidate allowance is checked before agreement or derivation, so an exhausted
unwrap allowance does not initiate unusable KDF work. Parsed `DerivedKey`
descriptors are matched against the explicit request before provider dispatch;
`MasterKeyName` is whitespace significant and requires the caller's exact
`master_key_name` association. An omitted XML method requires the request's
explicit method. Raw content-key resolvers cannot bypass a transported derivation.
Parsed `AgreementMethod` descriptors preserve originator/recipient key metadata,
KDF parameters and legacy DH nonce/digest fields. `AgreementDecryptor::content`
and `AgreementDecryptor::wrapping` bind the complete expected descriptor to
caller-owned handles, peer bytes and the consuming algorithm. Descriptor
agreement is checked before the provider runs; a raw KEK or content resolver
cannot bypass an advertised agreement source.

Nested encrypted keys resolve through the distinct
`resolve_key_encryption_keys_with_policy` callback. Its consuming algorithm is
the actual key-wrap algorithm, not a same-width content-cipher proxy. Every
level shares the operation budget and preserves implicit-rejection state until
final content authentication. Non-exportable handles are never converted into
software keys to satisfy an unsupported provider operation.

`EncryptedDataBuilder::derived_key` retains an explicit KDF request and a
zeroizing secret; `agreement_key` retains an opaque handle and public peer.
Both defer cryptographic execution to the operation's key-resolution gate.
Replacing the builder policy therefore affects the actual derivation, rather
than accepting a key generated under an earlier policy. Direct raw content keys
are borrowed during execution, not cloned for encryption. Generated keys and
derived outputs are zeroized on success and error paths. `derived_key` emits an
XML `DerivedKey` descriptor; the matching master material remains request-owned.
`KeyDerivationMethod::to_xml` preserves ConcatKDF field bit boundaries and checks
metadata and output size before allocating the serialized result. The final
EncryptedData serializer preflights escaped output size and streams base64 with
a fixed scratch buffer rather than copying the entire ciphertext encoding.
`agreement_key` emits `AgreementMethod` and its KDF descriptor. Public key role
metadata may be omitted when the agreement keys are explicitly supplied by
application context, as permitted by XMLEnc 1.1 section 5.6.
`KA-Nonce` is preserved in descriptor matching and enters the legacy DH KDF
exactly as specified in section 5.6.2.2. Explicit KDFs consume their declared
salt/context fields; xml-sec does not invent an extra nonce concatenation.
Applications requiring fresh output with the same agreement keys must vary
those explicit KDF inputs as well, not merely the transported nonce.

Reciprocal libxmlsec1 1.3.13 tests cover all five SHA-1/SHA-2 families for PBKDF2,
HKDFParams and byte-aligned ConcatKDF fields. Non-octet-aligned ConcatKDF follows
[XMLEnc 1.1 section 5.4.1](https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-ConcatKDF)
and has separate exact-bit tests: libxmlsec1's `xmlSecTransformConcatKdfParamsReadsBitsAttr`
rejects such fields, so that donor limitation is not imposed on xml-sec.
Reciprocal ECDH tests additionally execute XML agreement with P-256, P-384 and
P-521 keys and ConcatKDF against libxmlsec1, in both directions.

`parse_hkdf_agreement_method` separately adapts the
[RFC 9231 section 2.8.1](https://www.rfc-editor.org/rfc/rfc9231.html#section-2.8.1)
HKDF layout. Its salt, initial key material and KA-Nonce are hexadecimal;
its worked-example KeySize is an octet count, not EncryptionMethod's bit count.
Both the hash URI described by the text and the HMAC URI used by its example
normalize to one HKDF PRF. An absent initial key material value requires an
explicit caller request; simultaneous XML and caller values are rejected.
This adapter does not resolve asymmetric agreement keys or external resources.

RustCrypto implements all nine fixed RSA-PSS SHA-1/SHA-2/SHA-3 signature URIs
and parameterized `rsa-pss` via `SignatureAlgorithm::RsaPss(RsaPssParameters)`.
Message hash and MGF1 hash may differ; salt length is exact, including zero,
and must fit the RSA modulus. XML defaults are SHA-256, digest-sized salt and
trailer 1 ([RFC 9231 section 2.3.9](https://www.rfc-editor.org/rfc/rfc9231.html#section-2.3.9)).
SHA-1 in either hash requires explicit legacy policy permission. Fixed URI
variants reject parameters rather than silently overriding their contract.
The narrow [local padding adaptation](rsa-pss-patch.md) retains sad-rsa arithmetic.

`legacy-algorithms` adds RustCrypto MD5/RIPEMD-160 signatures and digests, AES-192
content encryption and key wrap, TripleDES content encryption and CMS wrap, and RSA-1.5
transport. All operations still go through `CryptoProvider` and require explicit library policy
permission. The AWS FIPS adapter reports these optional mechanisms unavailable; compiling both
providers never falls back to RustCrypto. This describes the adapter's supported operations, not
every primitive present in the underlying AWS-LC library or an approved-service claim.

The AWS provider supports SHA-1/SHA-2 and SHA3-256/384/512 digests; RSA PKCS#1 v1.5
signing with SHA-256/384/512 and verification with those digests or SHA-1; native
RSA-PSS signing/verification with SHA-256/384/512, matching MGF1 and digest-sized salt;
ECDSA curve/digest combinations exposed by AWS-LC; AES-128/256 CBC and GCM;
AES-128/256 key wrap; and RSA-OAEP with SHA-1/256/384/512 when MGF uses the same
digest. RSA-OAEP labels are preserved. Certificate and CRL verification uses DER
ECDSA encoding rather than XMLDSig's fixed-width encoding.

SHA3-224, DSA, HMAC signatures, EdDSA, post-quantum signatures, RSA-PSS certificate
signatures, mixed-digest OAEP, and unavailable ECDSA combinations return unsupported
errors. Consult `CryptoProvider::supports` before requesting a mechanism; actual
key parameters are checked at import/use as well. RSA PKCS#1 verification supports
2048-8192-bit moduli, including certificate and CRL issuer keys. Keys outside this
native range return unsupported rather than a signature mismatch, even when caller
policy permits their size. Availability never overrides policy.

## FIPS boundary

Linking a FIPS module is not certification of xml-sec or of the caller's application.
The exact module version, validated operating environment, approved service, and
deployment requirements must match the applicable AWS security policy and validation.
`AwsLcFipsProvider::module_version` and `fips_module_version` expose the linked
module's own version information for deployment diagnostics.
The module also exposes mechanisms that are not approved services. This adapter does
not attest an approved-service indicator or relax algorithm policy based on its name.
See [AWS-LC FIPS documentation](https://github.com/aws/aws-lc/blob/main/crypto/fipsmodule/FIPS.md)
and [supported platforms](https://aws.github.io/aws-lc-rs/platform_support.html).

Default pure-Rust builds and the alloc-only XML-input path remain independent of this
optional native dependency. Tests compare supported primitives between engines and
exercise complete XML operation paths, malformed inputs, tampering, and provider binding.
