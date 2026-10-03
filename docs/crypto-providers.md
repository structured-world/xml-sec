# Cryptographic providers

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
Applications requiring an exclusively native secret-processing boundary should supply
plain PKCS#8 directly to `AwsLcSigningKey::from_pkcs8_der` or
`AwsLcRsaPrivateKey::from_pkcs8_der`, rather than using protected-container import.

The native `xmlsec1` accepts `--crypto aws-lc-fips` when this feature is compiled.
Without it, that selection is an explicit unavailable-provider error.

## Mechanisms

The AWS provider supports SHA-1/SHA-2 and SHA3-256/384/512 digests; RSA PKCS#1 v1.5
signing with SHA-256/384/512 and verification with those digests or SHA-1; native
ECDSA curve/digest combinations exposed by AWS-LC; AES-128/256 CBC and GCM;
AES-128/256 key wrap; and RSA-OAEP with SHA-1/256/384/512 when MGF uses the same
digest. RSA-OAEP labels are preserved. Certificate and CRL verification uses DER
ECDSA encoding rather than XMLDSig's fixed-width encoding.

SHA3-224, DSA, HMAC signatures, EdDSA, post-quantum signatures, RSA-PSS certificate
signatures, mixed-digest OAEP, and unavailable ECDSA combinations return unsupported
errors. Consult `CryptoProvider::supports` before requesting a mechanism; actual
key parameters are checked at import/use as well. Availability never overrides policy.

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
