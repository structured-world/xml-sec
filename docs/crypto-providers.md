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
RSA-PSS/ECDSA signing, certificate/CRL verification,
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

`legacy-algorithms` adds RustCrypto MD5/RIPEMD-160 signatures and digests, AES-192
content encryption and key wrap, TripleDES content encryption and CMS wrap, and RSA-1.5
transport. All operations still go through `CryptoProvider` and require explicit library policy
permission. The AWS FIPS adapter reports these optional mechanisms unavailable; compiling both
providers never falls back to RustCrypto. This describes the adapter's supported operations, not
every primitive present in the underlying AWS-LC library or an approved-service claim.

The AWS provider supports SHA-1/SHA-2 and SHA3-256/384/512 digests; RSA PKCS#1 v1.5
signing with SHA-256/384/512 and verification with those digests or SHA-1; native
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
