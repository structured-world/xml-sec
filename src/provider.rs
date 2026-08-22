//! Provider-neutral cryptographic operations.
//!
//! XML parsing and protocol orchestration depend on this contract rather than
//! concrete cryptographic crates. Secret-bearing keys remain opaque behind
//! operation-specific handles; this provider owns primitive dispatch and
//! randomness.

#[cfg(feature = "xmlenc")]
use std::borrow::Cow;

#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
use getrandom::rand_core::TryCryptoRng;
use getrandom::{SysRng, rand_core::TryRng};

#[cfg(feature = "xmldsig")]
use crate::xmldsig::DigestAlgorithm;
#[cfg(feature = "xmlenc")]
use crate::xmlenc::{DataEncryptionAlgorithm, KeyWrapAlgorithm, RsaOaepParameters};

/// A cryptographic operation advertised by a provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ProviderOperation {
    /// Message digest computation.
    Digest,
    /// Public-key signature generation.
    Sign,
    /// Public-key signature verification.
    Verify,
    /// X.509 certificate or CRL signature verification.
    VerifyCertificate,
    /// Authenticated or padded symmetric encryption.
    Encrypt,
    /// Authenticated or padded symmetric decryption.
    Decrypt,
    /// Symmetric key wrapping.
    KeyWrap,
    /// Symmetric key unwrapping.
    KeyUnwrap,
    /// Public-key key transport.
    KeyTransport,
    /// Key agreement.
    KeyAgreement,
    /// Key derivation.
    Kdf,
    /// Cryptographically secure random bytes.
    Random,
}

/// One exact provider capability, including operation-specific parameters.
///
/// Capability discovery describes mechanisms, not policy permission. Callers
/// must still apply the immutable operation policy before provider dispatch.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum ProviderCapability<'a> {
    /// Message digest computation for an XMLDSig digest method.
    #[cfg(feature = "xmldsig")]
    Digest(DigestAlgorithm),
    /// Signature generation for an XMLDSig signature method.
    #[cfg(feature = "xmldsig")]
    Sign(crate::xmldsig::SignatureAlgorithm),
    /// Signature verification for an XMLDSig signature method.
    #[cfg(feature = "xmldsig")]
    Verify(crate::xmldsig::SignatureAlgorithm),
    /// X.509 signature verification with complete algorithm parameters.
    #[cfg(feature = "xmldsig")]
    VerifyCertificate(X509SignatureAlgorithm),
    /// XMLEnc content encryption.
    #[cfg(feature = "xmlenc")]
    Encrypt(DataEncryptionAlgorithm),
    /// XMLEnc content decryption.
    #[cfg(feature = "xmlenc")]
    Decrypt(DataEncryptionAlgorithm),
    /// RFC 3394 key wrapping.
    #[cfg(feature = "xmlenc")]
    KeyWrap(KeyWrapAlgorithm),
    /// RFC 3394 key unwrapping.
    #[cfg(feature = "xmlenc")]
    KeyUnwrap(KeyWrapAlgorithm),
    /// RSA-OAEP key transport with complete digest, MGF, and label parameters.
    #[cfg(feature = "xmlenc")]
    KeyTransport(&'a RsaOaepParameters),
    /// Provider-defined key agreement identified by its standard URI.
    KeyAgreement(&'a KeyAgreementParameters<'a>),
    /// Provider-defined key derivation identified by its standard URI.
    Kdf(&'a KdfParameters<'a>),
    /// Cryptographically secure random byte generation.
    Random,
}

impl ProviderCapability<'_> {
    /// Operation category used in diagnostics.
    #[must_use]
    pub const fn operation(&self) -> ProviderOperation {
        match self {
            #[cfg(feature = "xmldsig")]
            Self::Digest(_) => ProviderOperation::Digest,
            #[cfg(feature = "xmldsig")]
            Self::Sign(_) => ProviderOperation::Sign,
            #[cfg(feature = "xmldsig")]
            Self::Verify(_) => ProviderOperation::Verify,
            #[cfg(feature = "xmldsig")]
            Self::VerifyCertificate(_) => ProviderOperation::VerifyCertificate,
            #[cfg(feature = "xmlenc")]
            Self::Encrypt(_) => ProviderOperation::Encrypt,
            #[cfg(feature = "xmlenc")]
            Self::Decrypt(_) => ProviderOperation::Decrypt,
            #[cfg(feature = "xmlenc")]
            Self::KeyWrap(_) => ProviderOperation::KeyWrap,
            #[cfg(feature = "xmlenc")]
            Self::KeyUnwrap(_) => ProviderOperation::KeyUnwrap,
            #[cfg(feature = "xmlenc")]
            Self::KeyTransport(_) => ProviderOperation::KeyTransport,
            Self::KeyAgreement(_) => ProviderOperation::KeyAgreement,
            Self::Kdf(_) => ProviderOperation::Kdf,
            Self::Random => ProviderOperation::Random,
        }
    }

    /// Standard algorithm identifier used in unsupported-operation errors.
    #[must_use]
    pub fn algorithm(&self) -> Option<&str> {
        match self {
            #[cfg(feature = "xmldsig")]
            Self::Digest(algorithm) => Some(algorithm.uri()),
            #[cfg(feature = "xmldsig")]
            Self::Sign(algorithm) | Self::Verify(algorithm) => Some(algorithm.uri()),
            #[cfg(feature = "xmldsig")]
            Self::VerifyCertificate(algorithm) => Some(algorithm.oid()),
            #[cfg(feature = "xmlenc")]
            Self::Encrypt(algorithm) | Self::Decrypt(algorithm) => Some(algorithm.uri()),
            #[cfg(feature = "xmlenc")]
            Self::KeyWrap(algorithm) | Self::KeyUnwrap(algorithm) => Some(algorithm.uri()),
            #[cfg(feature = "xmlenc")]
            Self::KeyTransport(parameters) => Some(parameters.algorithm.uri()),
            Self::KeyAgreement(parameters) => Some(parameters.algorithm),
            Self::Kdf(parameters) => Some(parameters.algorithm),
            Self::Random => None,
        }
    }
}

/// Provider-neutral parameters for an asymmetric key-agreement operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyAgreementParameters<'a> {
    /// Standard key-agreement algorithm URI.
    pub algorithm: &'a str,
    /// Encoded peer public key in the algorithm's standard wire format.
    pub peer_public_key: &'a [u8],
}

/// Provider-neutral parameters for a key-derivation operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParameters<'a> {
    /// Standard KDF algorithm URI.
    pub algorithm: &'a str,
    /// Optional digest or PRF URI selected by the KDF parameters.
    pub digest: Option<&'a str>,
    /// Caller-provided salt, when the KDF defines one.
    pub salt: &'a [u8],
    /// Algorithm-specific context bytes such as ConcatKDF OtherInfo or HKDF info.
    pub info: &'a [u8],
    /// Policy-validated iteration count for iterative KDFs; zero when not applicable.
    pub iterations: u64,
    /// Policy-validated requested output length in bytes.
    pub output_len: usize,
}

/// Provider-neutral X.509 certificate and CRL signature parameters.
#[cfg(feature = "xmldsig")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum X509SignatureAlgorithm {
    /// DSA with the selected message digest.
    Dsa(DigestAlgorithm),
    /// RSASSA-PKCS1-v1_5 with the selected message digest.
    RsaPkcs1v15(DigestAlgorithm),
    /// RSASSA-PSS with explicit RFC 4055 parameters.
    RsaPss {
        /// Message digest applied to the signed certificate data.
        digest: DigestAlgorithm,
        /// Digest used by MGF1.
        mgf_digest: DigestAlgorithm,
        /// Salt length in octets.
        salt_len: usize,
    },
    /// ECDSA with the selected message digest; SPKI selects the curve.
    Ecdsa(DigestAlgorithm),
    /// Pure Ed25519 as specified by RFC 8410.
    Ed25519,
}

#[cfg(feature = "xmldsig")]
impl X509SignatureAlgorithm {
    /// Return the standard AlgorithmIdentifier OID used for capability queries.
    #[must_use]
    pub const fn oid(self) -> &'static str {
        match self {
            Self::Dsa(DigestAlgorithm::Sha1) => "1.2.840.10040.4.3",
            Self::Dsa(DigestAlgorithm::Sha256) => "2.16.840.1.101.3.4.3.2",
            Self::Dsa(DigestAlgorithm::Sha384) => "2.16.840.1.101.3.4.3.3",
            Self::Dsa(DigestAlgorithm::Sha512) => "2.16.840.1.101.3.4.3.4",
            Self::RsaPkcs1v15(DigestAlgorithm::Sha1) => "1.2.840.113549.1.1.5",
            Self::RsaPkcs1v15(DigestAlgorithm::Sha256) => "1.2.840.113549.1.1.11",
            Self::RsaPkcs1v15(DigestAlgorithm::Sha384) => "1.2.840.113549.1.1.12",
            Self::RsaPkcs1v15(DigestAlgorithm::Sha512) => "1.2.840.113549.1.1.13",
            Self::RsaPss { .. } => "1.2.840.113549.1.1.10",
            Self::Ecdsa(DigestAlgorithm::Sha1) => "1.2.840.10045.4.1",
            Self::Ecdsa(DigestAlgorithm::Sha256) => "1.2.840.10045.4.3.2",
            Self::Ecdsa(DigestAlgorithm::Sha384) => "1.2.840.10045.4.3.3",
            Self::Ecdsa(DigestAlgorithm::Sha512) => "1.2.840.10045.4.3.4",
            Self::Ed25519 => "1.3.101.112",
        }
    }
}

/// Structured invalid-input reasons returned by cryptographic providers.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProviderInputError {
    /// A primitive rejected a key or IV after its public preconditions were checked.
    #[error("failed to initialize {0}")]
    PrimitiveInitialization(&'static str),
    /// AES-CBC input does not contain an IV followed by complete blocks.
    #[error("invalid AES-CBC framing")]
    AesCbcFraming,
    /// AES-CBC block decryption failed.
    #[error("invalid AES-CBC ciphertext")]
    AesCbcCiphertext,
    /// AES-GCM input does not contain a nonce and authentication tag.
    #[error("invalid AES-GCM framing")]
    AesGcmFraming,
    /// AES key-wrap input or output framing is invalid.
    #[error("invalid AES key-wrap framing")]
    AesKeyWrapFraming,
    /// The legacy RSA-OAEP URI requires MGF1-SHA1.
    #[error("legacy RSA-OAEP requires MGF1-SHA1")]
    LegacyRsaOaepMgf,
}

/// Failure returned by a cryptographic provider.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProviderError {
    /// The selected provider does not implement the operation/parameters.
    #[error("provider does not support {operation:?} with algorithm {algorithm:?}")]
    Unsupported {
        /// Requested operation.
        operation: ProviderOperation,
        /// Requested algorithm URI or name.
        algorithm: Option<String>,
    },
    /// A key has the wrong size for the selected algorithm.
    #[error("invalid key size: expected {expected} bytes, got {actual}")]
    InvalidKeySize {
        /// Required key length.
        expected: usize,
        /// Supplied key length.
        actual: usize,
    },
    /// A provider reported success but returned bytes that violate the selected
    /// operation's fixed-size output contract.
    #[error(
        "invalid provider output size for {operation:?}: expected {expected} bytes, got {actual}"
    )]
    InvalidOutputSize {
        /// Operation whose output contract was violated.
        operation: ProviderOperation,
        /// Exact output length required by the algorithm.
        expected: usize,
        /// Actual provider output length.
        actual: usize,
    },
    /// A provider reported success but returned bytes outside the selected
    /// operation's variable-size output contract.
    #[error(
        "invalid provider output size for {operation:?}: expected {minimum}..={maximum} bytes, got {actual}"
    )]
    InvalidOutputSizeRange {
        /// Operation whose output contract was violated.
        operation: ProviderOperation,
        /// Smallest output length permitted by the algorithm.
        minimum: usize,
        /// Largest output length permitted by the algorithm.
        maximum: usize,
        /// Actual provider output length.
        actual: usize,
    },
    /// Input framing, padding, or primitive initialization is invalid.
    #[error("invalid cryptographic input: {0}")]
    InvalidInput(ProviderInputError),
    /// Authenticated decryption or key-wrap integrity validation failed.
    #[error("cryptographic authentication failed")]
    AuthenticationFailed,
    /// Operating-system randomness was unavailable.
    #[error("operating-system random number generation failed: {0}")]
    Random(String),
}

/// Opaque public-key handle used for asymmetric key transport.
///
/// Implementations own their key material and operation. The orchestration
/// layer can inspect only public RSA components needed for policy validation
/// and output framing; it cannot recover a backend-specific key object.
#[cfg(feature = "xmlenc")]
pub trait KeyTransportKey: Send + Sync {
    /// RSA modulus bytes without redundant leading zero octets.
    ///
    /// These components must identify the exact key used by
    /// [`Self::transport_with_provider`]; returning metadata for another key
    /// would violate the policy boundary.
    fn rsa_modulus(&self) -> Cow<'_, [u8]>;

    /// RSA public exponent bytes without redundant leading zero octets.
    fn rsa_exponent(&self) -> Cow<'_, [u8]>;

    /// Execute OAEP key transport using the selected provider's randomness.
    fn transport_with_provider(
        &self,
        provider: &dyn CryptoProvider,
        parameters: &RsaOaepParameters,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProviderError>;
}

/// Opaque private-key handle used to recover transported key bytes.
///
/// Private key material never crosses this boundary. The ciphertext size is
/// public metadata required to reject malformed RSA inputs before dispatch.
#[cfg(feature = "xmlenc")]
pub trait KeyRecoveryKey: Send + Sync {
    /// Exact RSA ciphertext width in bytes for the key used by
    /// [`Self::recover_with_provider`].
    fn ciphertext_len(&self) -> usize;

    /// Execute OAEP recovery using the selected provider's randomness.
    fn recover_with_provider(
        &self,
        provider: &dyn CryptoProvider,
        parameters: &RsaOaepParameters,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ProviderError>;
}

/// Opaque private-key handle used for provider-defined key agreement.
pub trait KeyAgreementKey: Send + Sync {
    /// Derive the raw shared secret for the supplied peer and parameters.
    fn agree(&self, parameters: &KeyAgreementParameters<'_>) -> Result<Vec<u8>, ProviderError>;
}

/// Stateless provider operations used by the XML Security pipelines.
pub trait CryptoProvider: Send + Sync {
    /// Stable provider name for diagnostics and capability reporting.
    fn name(&self) -> &'static str;

    /// Return whether this build supports the requested operation and parameters.
    fn supports(&self, capability: ProviderCapability<'_>) -> bool;

    /// Fill caller-owned output with cryptographically secure random bytes.
    fn fill_random(&self, output: &mut [u8]) -> Result<(), ProviderError>;

    /// Compute a message digest.
    #[cfg(feature = "xmldsig")]
    fn digest(&self, algorithm: DigestAlgorithm, data: &[u8]) -> Result<Vec<u8>, ProviderError>;

    /// Sign bytes with an opaque key handle.
    ///
    /// Providers that delegate primitive signing to the supplied key must call
    /// [`crate::xmldsig::SigningKey::sign_with_provider`] so randomized
    /// primitives consume this provider's randomness.
    #[cfg(feature = "xmldsig")]
    fn sign(
        &self,
        key: &dyn crate::xmldsig::SigningKey,
        algorithm: crate::xmldsig::SignatureAlgorithm,
        data: &[u8],
    ) -> Result<Vec<u8>, crate::xmldsig::SigningKeyError>;

    /// Verify bytes with an opaque key handle.
    ///
    /// The XMLDSig facade validates algorithm- and key-specific signature
    /// framing before this provider boundary.
    #[cfg(feature = "xmldsig")]
    fn verify(
        &self,
        key: &dyn crate::xmldsig::VerifyingKey,
        algorithm: crate::xmldsig::SignatureAlgorithm,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, crate::xmldsig::DsigError>;

    /// Verify an X.509 certificate or CRL signature under its issuer SPKI.
    #[cfg(feature = "xmldsig")]
    fn verify_x509_signature(
        &self,
        algorithm: X509SignatureAlgorithm,
        signed_data: &[u8],
        signature: &[u8],
        issuer_spki_der: &[u8],
    ) -> Result<bool, ProviderError> {
        let _ = (signed_data, signature, issuer_spki_der);
        Err(ProviderError::Unsupported {
            operation: ProviderOperation::VerifyCertificate,
            algorithm: Some(algorithm.oid().to_owned()),
        })
    }

    /// Encrypt XMLEnc content bytes, including standard framing.
    #[cfg(feature = "xmlenc")]
    fn encrypt_data(
        &self,
        algorithm: DataEncryptionAlgorithm,
        key: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProviderError>;

    /// Decrypt XMLEnc content bytes, including framing validation.
    #[cfg(feature = "xmlenc")]
    fn decrypt_data(
        &self,
        algorithm: DataEncryptionAlgorithm,
        key: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ProviderError>;

    /// Wrap a content key with RFC 3394 AES Key Wrap.
    ///
    /// Successful output contains the complete RFC 3394 value and is exactly
    /// eight bytes longer than `key`. The XMLEnc facade validates that framing
    /// before serializing provider output.
    #[cfg(feature = "xmlenc")]
    fn wrap_key(
        &self,
        algorithm: KeyWrapAlgorithm,
        kek: &[u8],
        key: &[u8],
    ) -> Result<Vec<u8>, ProviderError>;

    /// Unwrap a content key with RFC 3394 AES Key Wrap.
    #[cfg(feature = "xmlenc")]
    fn unwrap_key(
        &self,
        algorithm: KeyWrapAlgorithm,
        kek: &[u8],
        wrapped: &[u8],
    ) -> Result<Vec<u8>, ProviderError>;

    /// Wrap key bytes using an opaque RSA public-key operation.
    #[cfg(feature = "xmlenc")]
    fn transport_key(
        &self,
        key: &dyn KeyTransportKey,
        parameters: &RsaOaepParameters,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProviderError>;

    /// Recover key bytes using an opaque RSA private-key operation.
    #[cfg(feature = "xmlenc")]
    fn recover_key(
        &self,
        key: &dyn KeyRecoveryKey,
        parameters: &RsaOaepParameters,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ProviderError>;

    /// Perform key agreement with an opaque provider-owned private key.
    fn agree_key(
        &self,
        key: &dyn KeyAgreementKey,
        parameters: &KeyAgreementParameters<'_>,
    ) -> Result<Vec<u8>, ProviderError> {
        self.require_capability(ProviderCapability::KeyAgreement(parameters))?;
        key.agree(parameters)
    }

    /// Derive key bytes from caller-owned secret material.
    fn derive_key(
        &self,
        parameters: &KdfParameters<'_>,
        secret: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        let _ = secret;
        self.require_capability(ProviderCapability::Kdf(parameters))?;
        Err(ProviderError::Unsupported {
            operation: ProviderOperation::Kdf,
            algorithm: Some(parameters.algorithm.to_owned()),
        })
    }

    /// Reject an unavailable exact capability without falling back.
    fn require_capability(&self, capability: ProviderCapability<'_>) -> Result<(), ProviderError> {
        if self.supports(capability) {
            Ok(())
        } else {
            Err(ProviderError::Unsupported {
                operation: capability.operation(),
                algorithm: capability.algorithm().map(str::to_owned),
            })
        }
    }
}

/// Pure-Rust provider backed by RustCrypto crates.
#[derive(Debug, Clone, Copy, Default)]
pub struct RustCryptoProvider;

/// Opaque RSA public-key handle for the built-in RustCrypto provider.
#[cfg(feature = "xmlenc")]
#[derive(Clone)]
pub struct RustCryptoRsaPublicKey {
    key: rsa::RsaPublicKey,
    modulus: Vec<u8>,
    exponent: Vec<u8>,
}

#[cfg(feature = "xmlenc")]
impl RustCryptoRsaPublicKey {
    /// Wrap an already parsed RustCrypto RSA public key.
    #[must_use]
    pub fn new(key: rsa::RsaPublicKey) -> Self {
        use rsa::traits::PublicKeyParts as _;
        let modulus = key.n().to_be_bytes_trimmed_vartime().into_vec();
        let exponent = key.e().to_be_bytes_trimmed_vartime().into_vec();
        Self {
            key,
            modulus,
            exponent,
        }
    }
}

#[cfg(feature = "xmlenc")]
impl From<rsa::RsaPublicKey> for RustCryptoRsaPublicKey {
    fn from(key: rsa::RsaPublicKey) -> Self {
        Self::new(key)
    }
}

#[cfg(feature = "xmlenc")]
impl KeyTransportKey for RustCryptoRsaPublicKey {
    fn rsa_modulus(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(&self.modulus)
    }

    fn rsa_exponent(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(&self.exponent)
    }

    fn transport_with_provider(
        &self,
        provider: &dyn CryptoProvider,
        parameters: &RsaOaepParameters,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        rustcrypto::transport_key(provider, &self.key, parameters, plaintext)
    }
}

#[cfg(feature = "xmlenc")]
impl KeyTransportKey for rsa::RsaPublicKey {
    fn rsa_modulus(&self) -> Cow<'_, [u8]> {
        use rsa::traits::PublicKeyParts as _;
        Cow::Owned(self.n().to_be_bytes_trimmed_vartime().into_vec())
    }

    fn rsa_exponent(&self) -> Cow<'_, [u8]> {
        use rsa::traits::PublicKeyParts as _;
        Cow::Owned(self.e().to_be_bytes_trimmed_vartime().into_vec())
    }

    fn transport_with_provider(
        &self,
        provider: &dyn CryptoProvider,
        parameters: &RsaOaepParameters,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        rustcrypto::transport_key(provider, self, parameters, plaintext)
    }
}

/// Opaque RSA private-key handle for the built-in RustCrypto provider.
#[cfg(feature = "xmlenc")]
#[derive(Clone)]
pub struct RustCryptoRsaPrivateKey {
    key: rsa::RsaPrivateKey,
    ciphertext_len: usize,
}

#[cfg(feature = "xmlenc")]
impl RustCryptoRsaPrivateKey {
    /// Wrap an already parsed RustCrypto RSA private key.
    #[must_use]
    pub fn new(key: rsa::RsaPrivateKey) -> Self {
        use rsa::traits::PublicKeyParts as _;
        let ciphertext_len = key.size();
        Self {
            key,
            ciphertext_len,
        }
    }
}

#[cfg(feature = "xmlenc")]
impl From<rsa::RsaPrivateKey> for RustCryptoRsaPrivateKey {
    fn from(key: rsa::RsaPrivateKey) -> Self {
        Self::new(key)
    }
}

#[cfg(feature = "xmlenc")]
impl KeyRecoveryKey for RustCryptoRsaPrivateKey {
    fn ciphertext_len(&self) -> usize {
        self.ciphertext_len
    }

    fn recover_with_provider(
        &self,
        provider: &dyn CryptoProvider,
        parameters: &RsaOaepParameters,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        rustcrypto::recover_key(provider, &self.key, parameters, ciphertext)
    }
}

#[cfg(feature = "xmlenc")]
impl KeyRecoveryKey for rsa::RsaPrivateKey {
    fn ciphertext_len(&self) -> usize {
        use rsa::traits::PublicKeyParts as _;
        self.size()
    }

    fn recover_with_provider(
        &self,
        provider: &dyn CryptoProvider,
        parameters: &RsaOaepParameters,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        rustcrypto::recover_key(provider, self, parameters, ciphertext)
    }
}

/// Process-wide immutable default provider. It contains no mutable state or keys.
pub static RUST_CRYPTO_PROVIDER: RustCryptoProvider = RustCryptoProvider;

/// Borrow the pure-Rust default provider.
#[must_use]
pub fn default_provider() -> &'static dyn CryptoProvider {
    &RUST_CRYPTO_PROVIDER
}

/// Adapter used when a RustCrypto primitive requires a fallible RNG object.
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub(crate) struct ProviderRng<'a>(pub(crate) &'a dyn CryptoProvider);

#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
impl TryRng for ProviderRng<'_> {
    type Error = ProviderError;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0_u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0_u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
        self.0.fill_random(output)
    }
}

#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
impl TryCryptoRng for ProviderRng<'_> {}

impl CryptoProvider for RustCryptoProvider {
    fn name(&self) -> &'static str {
        "rustcrypto"
    }

    fn supports(&self, capability: ProviderCapability<'_>) -> bool {
        match capability {
            #[cfg(feature = "xmldsig")]
            ProviderCapability::Digest(_) => true,
            #[cfg(feature = "xmldsig")]
            ProviderCapability::Sign(algorithm) => is_supported_signing_uri(algorithm.uri()),
            #[cfg(feature = "xmldsig")]
            ProviderCapability::Verify(algorithm) => is_supported_signature_uri(algorithm.uri()),
            #[cfg(feature = "xmldsig")]
            ProviderCapability::VerifyCertificate(algorithm) => {
                is_supported_x509_signature(algorithm)
            }
            #[cfg(feature = "xmlenc")]
            ProviderCapability::Encrypt(_) | ProviderCapability::Decrypt(_) => true,
            #[cfg(feature = "xmlenc")]
            ProviderCapability::KeyWrap(_) | ProviderCapability::KeyUnwrap(_) => true,
            #[cfg(feature = "xmlenc")]
            ProviderCapability::KeyTransport(parameters) => {
                parameters.algorithm != crate::xmlenc::KeyTransportAlgorithm::RsaOaepMgf1p
                    || parameters.mgf_digest == crate::xmlenc::OaepDigestAlgorithm::Sha1
            }
            ProviderCapability::Random => true,
            ProviderCapability::KeyAgreement(_) | ProviderCapability::Kdf(_) => false,
        }
    }

    fn fill_random(&self, output: &mut [u8]) -> Result<(), ProviderError> {
        SysRng
            .try_fill_bytes(output)
            .map_err(|error| ProviderError::Random(error.to_string()))
    }

    #[cfg(feature = "xmldsig")]
    fn digest(&self, algorithm: DigestAlgorithm, data: &[u8]) -> Result<Vec<u8>, ProviderError> {
        use sha1::Sha1;
        use sha2::{Digest, Sha256, Sha384, Sha512};
        Ok(match algorithm {
            DigestAlgorithm::Sha1 => Sha1::digest(data).to_vec(),
            DigestAlgorithm::Sha256 => Sha256::digest(data).to_vec(),
            DigestAlgorithm::Sha384 => Sha384::digest(data).to_vec(),
            DigestAlgorithm::Sha512 => Sha512::digest(data).to_vec(),
        })
    }

    #[cfg(feature = "xmldsig")]
    fn sign(
        &self,
        key: &dyn crate::xmldsig::SigningKey,
        algorithm: crate::xmldsig::SignatureAlgorithm,
        data: &[u8],
    ) -> Result<Vec<u8>, crate::xmldsig::SigningKeyError> {
        self.require_capability(ProviderCapability::Sign(algorithm))?;
        key.sign_with_provider(self, algorithm, data)
    }

    #[cfg(feature = "xmldsig")]
    fn verify(
        &self,
        key: &dyn crate::xmldsig::VerifyingKey,
        algorithm: crate::xmldsig::SignatureAlgorithm,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, crate::xmldsig::DsigError> {
        self.require_capability(ProviderCapability::Verify(algorithm))?;
        key.verify(algorithm, data, signature)
    }

    #[cfg(feature = "xmldsig")]
    fn verify_x509_signature(
        &self,
        algorithm: X509SignatureAlgorithm,
        signed_data: &[u8],
        signature: &[u8],
        issuer_spki_der: &[u8],
    ) -> Result<bool, ProviderError> {
        rustcrypto_x509::verify_signature(algorithm, signed_data, signature, issuer_spki_der)
    }

    #[cfg(feature = "xmlenc")]
    fn encrypt_data(
        &self,
        algorithm: DataEncryptionAlgorithm,
        key: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        rustcrypto::encrypt_data(self, algorithm, key, plaintext)
    }

    #[cfg(feature = "xmlenc")]
    fn decrypt_data(
        &self,
        algorithm: DataEncryptionAlgorithm,
        key: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        rustcrypto::decrypt_data(algorithm, key, ciphertext)
    }

    #[cfg(feature = "xmlenc")]
    fn wrap_key(
        &self,
        algorithm: KeyWrapAlgorithm,
        kek: &[u8],
        key: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        rustcrypto::wrap_key(algorithm, kek, key)
    }

    #[cfg(feature = "xmlenc")]
    fn unwrap_key(
        &self,
        algorithm: KeyWrapAlgorithm,
        kek: &[u8],
        wrapped: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        rustcrypto::unwrap_key(algorithm, kek, wrapped)
    }

    #[cfg(feature = "xmlenc")]
    fn transport_key(
        &self,
        key: &dyn KeyTransportKey,
        parameters: &RsaOaepParameters,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        validate_oaep_parameters(parameters)?;
        self.require_capability(ProviderCapability::KeyTransport(parameters))?;
        key.transport_with_provider(self, parameters, plaintext)
    }

    #[cfg(feature = "xmlenc")]
    fn recover_key(
        &self,
        key: &dyn KeyRecoveryKey,
        parameters: &RsaOaepParameters,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        validate_oaep_parameters(parameters)?;
        self.require_capability(ProviderCapability::KeyTransport(parameters))?;
        key.recover_with_provider(self, parameters, ciphertext)
    }
}

#[cfg(feature = "xmlenc")]
fn validate_oaep_parameters(parameters: &RsaOaepParameters) -> Result<(), ProviderError> {
    if parameters.algorithm == crate::xmlenc::KeyTransportAlgorithm::RsaOaepMgf1p
        && parameters.mgf_digest != crate::xmlenc::OaepDigestAlgorithm::Sha1
    {
        Err(ProviderError::InvalidInput(
            ProviderInputError::LegacyRsaOaepMgf,
        ))
    } else {
        Ok(())
    }
}

#[cfg(feature = "xmldsig")]
fn is_supported_signature_uri(algorithm: &str) -> bool {
    matches!(
        algorithm,
        "http://www.w3.org/2000/09/xmldsig#dsa-sha1"
            | "http://www.w3.org/2000/09/xmldsig#hmac-sha1"
            | "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
            | "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
            | "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
            | "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
            | "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
            | "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
    )
}

#[cfg(feature = "xmldsig")]
fn is_supported_signing_uri(algorithm: &str) -> bool {
    matches!(
        algorithm,
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
            | "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
            | "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
            | "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
            | "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
    )
}

#[cfg(feature = "xmldsig")]
fn is_supported_x509_signature(algorithm: X509SignatureAlgorithm) -> bool {
    match algorithm {
        X509SignatureAlgorithm::Dsa(DigestAlgorithm::Sha1)
        | X509SignatureAlgorithm::RsaPkcs1v15(_)
        | X509SignatureAlgorithm::Ecdsa(DigestAlgorithm::Sha256 | DigestAlgorithm::Sha384)
        | X509SignatureAlgorithm::Ed25519 => true,
        X509SignatureAlgorithm::RsaPss {
            digest, mgf_digest, ..
        } => {
            matches!(
                digest,
                DigestAlgorithm::Sha256 | DigestAlgorithm::Sha384 | DigestAlgorithm::Sha512
            ) && digest == mgf_digest
        }
        X509SignatureAlgorithm::Dsa(_)
        | X509SignatureAlgorithm::Ecdsa(DigestAlgorithm::Sha1 | DigestAlgorithm::Sha512) => false,
    }
}

#[cfg(feature = "xmldsig")]
mod rustcrypto_x509 {
    use der::Decode as _;
    use dsa::pkcs8::DecodePublicKey as _;
    use rsa::{
        RsaPublicKey,
        pkcs1::DecodeRsaPublicKey as _,
        pss::{Signature as RsaPssSignature, VerifyingKey as RsaPssVerifyingKey},
    };
    use sha1::Digest as _;
    use sha2::{Sha256, Sha384, Sha512};
    use signature::{Verifier as _, hazmat::PrehashVerifier as _};
    use x509_parser::prelude::FromDer as _;

    use super::{ProviderError, X509SignatureAlgorithm};
    use crate::xmldsig::{
        DigestAlgorithm, DsigError, SignatureAlgorithm, VerificationKey, VerifyingKey as _,
    };

    pub(super) fn verify_signature(
        algorithm: X509SignatureAlgorithm,
        signed_data: &[u8],
        signature: &[u8],
        issuer_spki_der: &[u8],
    ) -> Result<bool, ProviderError> {
        match algorithm {
            X509SignatureAlgorithm::Dsa(DigestAlgorithm::Sha1) => {
                // Certificate signatures are ASN.1 DER integers sized by the
                // issuer's q parameter. XMLDSig's fixed 20-byte r||s framing
                // applies only to SignatureValue, never to X.509 signatures.
                let Ok(key) = dsa::VerifyingKey::from_public_key_der(issuer_spki_der) else {
                    return Ok(false);
                };
                let Ok(signature) = dsa::Signature::from_der(signature) else {
                    return Ok(false);
                };
                let digest = sha1::Sha1::digest(signed_data);
                Ok(key.verify_prehash(&digest, &signature).is_ok())
            }
            X509SignatureAlgorithm::RsaPkcs1v15(digest) => {
                let Some(algorithm) = rsa_pkcs1_algorithm(digest) else {
                    return unsupported(X509SignatureAlgorithm::RsaPkcs1v15(digest));
                };
                verify_xml_signature(algorithm, signed_data, signature, issuer_spki_der)
            }
            X509SignatureAlgorithm::Ecdsa(digest) => {
                let Some(algorithm) = ecdsa_algorithm(digest) else {
                    return unsupported(X509SignatureAlgorithm::Ecdsa(digest));
                };
                verify_xml_signature(algorithm, signed_data, signature, issuer_spki_der)
            }
            X509SignatureAlgorithm::RsaPss {
                digest,
                mgf_digest,
                salt_len,
            } => {
                // RFC 4055 key restrictions are part of signature validity. Check
                // them before provider capability so an incompatible key is a
                // deterministic non-match even when the requested MGF is unsupported.
                let Some(key) = compatible_rsa_pss_public_key_from_spki(issuer_spki_der, algorithm)
                else {
                    return Ok(false);
                };
                if digest != mgf_digest {
                    return unsupported(algorithm);
                }
                verify_rsa_pss(digest, salt_len, signed_data, signature, key)
            }
            X509SignatureAlgorithm::Ed25519 => {
                let Ok(key) = ed25519_dalek::VerifyingKey::from_public_key_der(issuer_spki_der)
                else {
                    return Ok(false);
                };
                let Ok(signature) = ed25519_dalek::Signature::try_from(signature) else {
                    return Ok(false);
                };
                Ok(key.verify_strict(signed_data, &signature).is_ok())
            }
            _ => unsupported(algorithm),
        }
    }

    fn verify_xml_signature(
        algorithm: SignatureAlgorithm,
        signed_data: &[u8],
        signature: &[u8],
        issuer_spki_der: &[u8],
    ) -> Result<bool, ProviderError> {
        let key = VerificationKey {
            algorithm,
            public_key_bytes: issuer_spki_der.to_vec(),
            certificate_der: None,
            name: None,
        };
        match key.verify(algorithm, signed_data, signature) {
            Ok(verified) => Ok(verified),
            Err(DsigError::Provider(error)) => Err(error),
            Err(_) => Ok(false),
        }
    }

    fn verify_rsa_pss(
        digest: DigestAlgorithm,
        salt_len: usize,
        signed_data: &[u8],
        signature: &[u8],
        key: RsaPublicKey,
    ) -> Result<bool, ProviderError> {
        let Ok(signature) = RsaPssSignature::try_from(signature) else {
            return Ok(false);
        };
        let verified = match digest {
            DigestAlgorithm::Sha256 => {
                RsaPssVerifyingKey::<Sha256>::new_with_salt_len(key, salt_len)
                    .verify(signed_data, &signature)
            }
            DigestAlgorithm::Sha384 => {
                RsaPssVerifyingKey::<Sha384>::new_with_salt_len(key, salt_len)
                    .verify(signed_data, &signature)
            }
            DigestAlgorithm::Sha512 => {
                RsaPssVerifyingKey::<Sha512>::new_with_salt_len(key, salt_len)
                    .verify(signed_data, &signature)
            }
            DigestAlgorithm::Sha1 => {
                return unsupported(X509SignatureAlgorithm::RsaPss {
                    digest,
                    mgf_digest: digest,
                    salt_len,
                });
            }
        };
        Ok(verified.is_ok())
    }

    fn compatible_rsa_pss_public_key_from_spki(
        spki_der: &[u8],
        signature_algorithm: X509SignatureAlgorithm,
    ) -> Option<RsaPublicKey> {
        let (_, spki) = x509_parser::x509::SubjectPublicKeyInfo::from_der(spki_der).ok()?;
        match spki.algorithm.algorithm.to_id_string().as_str() {
            "1.2.840.113549.1.1.1" => RsaPublicKey::from_public_key_der(spki_der).ok(),
            "1.2.840.113549.1.1.10" => {
                // RFC 4055 section 3.3 applies key restrictions only when
                // RSASSA-PSS-params is present in SubjectPublicKeyInfo.
                if spki
                    .algorithm
                    .parameters
                    .as_ref()
                    .is_some_and(|parameters| {
                        !rsa_pss_key_parameters_allow(parameters, signature_algorithm)
                    })
                {
                    return None;
                }
                RsaPublicKey::from_pkcs1_der(&spki.subject_public_key.data).ok()
            }
            _ => None,
        }
    }

    fn rsa_pss_key_parameters_allow(
        parameters: &x509_parser::asn1_rs::Any<'_>,
        signature_algorithm: X509SignatureAlgorithm,
    ) -> bool {
        let X509SignatureAlgorithm::RsaPss {
            digest,
            mgf_digest,
            salt_len,
        } = signature_algorithm
        else {
            return false;
        };
        let Ok(parameters) =
            x509_parser::signature_algorithm::RsaSsaPssParams::try_from(parameters)
        else {
            return false;
        };
        let Ok(mask) = parameters.mask_gen_algorithm() else {
            return false;
        };
        parameters.trailer_field() == 1
            && x509_digest_from_oid(&parameters.hash_algorithm_oid().to_id_string()) == Some(digest)
            && mask.mgf.to_id_string() == "1.2.840.113549.1.1.8"
            && x509_digest_from_oid(&mask.hash.to_id_string()) == Some(mgf_digest)
            && usize::try_from(parameters.salt_length()).is_ok_and(|minimum| salt_len >= minimum)
    }

    fn x509_digest_from_oid(oid: &str) -> Option<DigestAlgorithm> {
        match oid {
            "1.3.14.3.2.26" => Some(DigestAlgorithm::Sha1),
            "2.16.840.1.101.3.4.2.1" => Some(DigestAlgorithm::Sha256),
            "2.16.840.1.101.3.4.2.2" => Some(DigestAlgorithm::Sha384),
            "2.16.840.1.101.3.4.2.3" => Some(DigestAlgorithm::Sha512),
            _ => None,
        }
    }

    const fn rsa_pkcs1_algorithm(digest: DigestAlgorithm) -> Option<SignatureAlgorithm> {
        match digest {
            DigestAlgorithm::Sha1 => Some(SignatureAlgorithm::RsaSha1),
            DigestAlgorithm::Sha256 => Some(SignatureAlgorithm::RsaSha256),
            DigestAlgorithm::Sha384 => Some(SignatureAlgorithm::RsaSha384),
            DigestAlgorithm::Sha512 => Some(SignatureAlgorithm::RsaSha512),
        }
    }

    const fn ecdsa_algorithm(digest: DigestAlgorithm) -> Option<SignatureAlgorithm> {
        match digest {
            DigestAlgorithm::Sha256 => Some(SignatureAlgorithm::EcdsaSha256),
            DigestAlgorithm::Sha384 => Some(SignatureAlgorithm::EcdsaSha384),
            DigestAlgorithm::Sha1 | DigestAlgorithm::Sha512 => None,
        }
    }

    fn unsupported<T>(algorithm: X509SignatureAlgorithm) -> Result<T, ProviderError> {
        Err(ProviderError::Unsupported {
            operation: super::ProviderOperation::VerifyCertificate,
            algorithm: Some(algorithm.oid().to_owned()),
        })
    }
}

#[cfg(feature = "xmlenc")]
mod rustcrypto {
    use aes::{
        Aes128, Aes256,
        cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, block_padding::NoPadding},
    };
    use aes_gcm::{
        Aes128Gcm, Aes256Gcm, Nonce,
        aead::{AeadInOut, KeyInit},
    };
    use aes_kw::{KwAes128, KwAes256};
    use cbc::{Decryptor, Encryptor};
    use rsa::{Oaep, traits::PaddingScheme};
    use sha1::Sha1;
    use sha2::{Sha256, Sha384, Sha512};

    use super::{CryptoProvider, ProviderError, ProviderInputError};
    use crate::xmlenc::{
        DataEncryptionAlgorithm, KeyTransportAlgorithm, KeyWrapAlgorithm, OaepDigestAlgorithm,
        RsaOaepParameters,
    };

    pub(super) fn encrypt_data(
        provider: &dyn CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        key: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        check_key(algorithm.key_len(), key)?;
        match algorithm {
            DataEncryptionAlgorithm::Aes128Cbc => encrypt_cbc::<Aes128>(provider, key, plaintext),
            DataEncryptionAlgorithm::Aes256Cbc => encrypt_cbc::<Aes256>(provider, key, plaintext),
            DataEncryptionAlgorithm::Aes128Gcm => {
                encrypt_gcm::<Aes128Gcm>(provider, key, plaintext)
            }
            DataEncryptionAlgorithm::Aes256Gcm => {
                encrypt_gcm::<Aes256Gcm>(provider, key, plaintext)
            }
        }
    }

    pub(super) fn decrypt_data(
        algorithm: DataEncryptionAlgorithm,
        key: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        check_key(algorithm.key_len(), key)?;
        match algorithm {
            DataEncryptionAlgorithm::Aes128Cbc => decrypt_cbc::<Aes128>(key, ciphertext),
            DataEncryptionAlgorithm::Aes256Cbc => decrypt_cbc::<Aes256>(key, ciphertext),
            DataEncryptionAlgorithm::Aes128Gcm => decrypt_gcm::<Aes128Gcm>(key, ciphertext),
            DataEncryptionAlgorithm::Aes256Gcm => decrypt_gcm::<Aes256Gcm>(key, ciphertext),
        }
    }

    fn check_key(expected: usize, key: &[u8]) -> Result<(), ProviderError> {
        if key.len() == expected {
            Ok(())
        } else {
            Err(ProviderError::InvalidKeySize {
                expected,
                actual: key.len(),
            })
        }
    }

    fn encrypt_cbc<C>(
        provider: &dyn CryptoProvider,
        key: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProviderError>
    where
        C: aes::cipher::BlockCipherEncrypt + aes::cipher::KeyInit,
    {
        let mut iv = [0_u8; 16];
        provider.fill_random(&mut iv)?;
        let pad_len = 16 - (plaintext.len() % 16);
        let mut padded = vec![0_u8; plaintext.len() + pad_len];
        padded[..plaintext.len()].copy_from_slice(plaintext);
        if pad_len > 1 {
            let last = padded.len() - 1;
            provider.fill_random(&mut padded[plaintext.len()..last])?;
        }
        *padded.last_mut().expect("padding is non-empty") = pad_len as u8;
        Encryptor::<C>::new_from_slices(key, &iv)
            .map_err(|_| {
                ProviderError::InvalidInput(ProviderInputError::PrimitiveInitialization("AES-CBC"))
            })?
            .encrypt_padded::<NoPadding>(&mut padded, plaintext.len() + pad_len)
            .map_err(|_| {
                ProviderError::InvalidInput(ProviderInputError::PrimitiveInitialization(
                    "AES-CBC padding",
                ))
            })?;
        let mut output = Vec::with_capacity(16 + padded.len());
        output.extend_from_slice(&iv);
        output.extend_from_slice(&padded);
        Ok(output)
    }

    fn decrypt_cbc<C>(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, ProviderError>
    where
        C: aes::cipher::BlockCipherDecrypt + aes::cipher::KeyInit,
    {
        if ciphertext.len() < 32 || !(ciphertext.len() - 16).is_multiple_of(16) {
            return Err(ProviderError::InvalidInput(
                ProviderInputError::AesCbcFraming,
            ));
        }
        let (iv, body) = ciphertext.split_at(16);
        let mut plaintext = body.to_vec();
        Decryptor::<C>::new_from_slices(key, iv)
            .map_err(|_| {
                ProviderError::InvalidInput(ProviderInputError::PrimitiveInitialization("AES-CBC"))
            })?
            .decrypt_padded::<NoPadding>(&mut plaintext)
            .map_err(|_| ProviderError::InvalidInput(ProviderInputError::AesCbcCiphertext))?;
        let pad_len = *plaintext.last().ok_or(ProviderError::InvalidInput(
            ProviderInputError::AesCbcCiphertext,
        ))?;
        let padding_bytes = usize::from(pad_len);
        if !(1..=16).contains(&padding_bytes) || padding_bytes > plaintext.len() {
            return Err(ProviderError::InvalidInput(
                ProviderInputError::AesCbcCiphertext,
            ));
        }
        plaintext.truncate(plaintext.len() - padding_bytes);
        Ok(plaintext)
    }

    fn encrypt_gcm<C>(
        provider: &dyn CryptoProvider,
        key: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProviderError>
    where
        C: AeadInOut + KeyInit,
    {
        let mut nonce = [0_u8; 12];
        provider.fill_random(&mut nonce)?;
        let cipher = C::new_from_slice(key).map_err(|_| {
            ProviderError::InvalidInput(ProviderInputError::PrimitiveInitialization("AES-GCM"))
        })?;
        let mut output = plaintext.to_vec();
        let nonce = Nonce::try_from(nonce.as_slice()).map_err(|_| {
            ProviderError::InvalidInput(ProviderInputError::PrimitiveInitialization(
                "AES-GCM nonce",
            ))
        })?;
        cipher
            .encrypt_in_place(&nonce, &[], &mut output)
            .map_err(|_| ProviderError::AuthenticationFailed)?;
        let mut framed = Vec::with_capacity(12 + output.len());
        framed.extend_from_slice(&nonce);
        framed.extend_from_slice(&output);
        Ok(framed)
    }

    fn decrypt_gcm<C>(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, ProviderError>
    where
        C: AeadInOut + KeyInit,
    {
        if ciphertext.len() < 28 {
            return Err(ProviderError::InvalidInput(
                ProviderInputError::AesGcmFraming,
            ));
        }
        let (nonce, body) = ciphertext.split_at(12);
        let cipher = C::new_from_slice(key).map_err(|_| {
            ProviderError::InvalidInput(ProviderInputError::PrimitiveInitialization("AES-GCM"))
        })?;
        let mut plaintext = body.to_vec();
        let nonce = Nonce::try_from(nonce).map_err(|_| {
            ProviderError::InvalidInput(ProviderInputError::PrimitiveInitialization(
                "AES-GCM nonce",
            ))
        })?;
        cipher
            .decrypt_in_place(&nonce, &[], &mut plaintext)
            .map_err(|_| ProviderError::AuthenticationFailed)?;
        Ok(plaintext)
    }

    pub(super) fn wrap_key(
        algorithm: KeyWrapAlgorithm,
        kek: &[u8],
        key: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        check_key(algorithm.key_len(), kek)?;
        let mut output = vec![0_u8; key.len() + 8];
        match algorithm {
            KeyWrapAlgorithm::AesKw128 => KwAes128::new_from_slice(kek)
                .map_err(|_| ProviderError::InvalidKeySize {
                    expected: 16,
                    actual: kek.len(),
                })?
                .wrap_key(key, &mut output),
            KeyWrapAlgorithm::AesKw256 => KwAes256::new_from_slice(kek)
                .map_err(|_| ProviderError::InvalidKeySize {
                    expected: 32,
                    actual: kek.len(),
                })?
                .wrap_key(key, &mut output),
        }
        .map_err(|_| ProviderError::InvalidInput(ProviderInputError::AesKeyWrapFraming))?;
        Ok(output)
    }

    pub(super) fn unwrap_key(
        algorithm: KeyWrapAlgorithm,
        kek: &[u8],
        wrapped: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        check_key(algorithm.key_len(), kek)?;
        if wrapped.len() < 16 || !wrapped.len().is_multiple_of(8) {
            return Err(ProviderError::InvalidInput(
                ProviderInputError::AesKeyWrapFraming,
            ));
        }
        let mut output = vec![0_u8; wrapped.len() - 8];
        let key = match algorithm {
            KeyWrapAlgorithm::AesKw128 => KwAes128::new_from_slice(kek)
                .map_err(|_| ProviderError::InvalidKeySize {
                    expected: 16,
                    actual: kek.len(),
                })?
                .unwrap_key(wrapped, &mut output),
            KeyWrapAlgorithm::AesKw256 => KwAes256::new_from_slice(kek)
                .map_err(|_| ProviderError::InvalidKeySize {
                    expected: 32,
                    actual: kek.len(),
                })?
                .unwrap_key(wrapped, &mut output),
        }
        .map_err(|_| ProviderError::AuthenticationFailed)?;
        Ok(key.to_vec())
    }

    pub(super) fn transport_key(
        provider: &dyn CryptoProvider,
        key: &rsa::RsaPublicKey,
        parameters: &RsaOaepParameters,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        if parameters.algorithm == KeyTransportAlgorithm::RsaOaepMgf1p
            && parameters.mgf_digest != OaepDigestAlgorithm::Sha1
        {
            return Err(ProviderError::InvalidInput(
                ProviderInputError::LegacyRsaOaepMgf,
            ));
        }
        let mut rng = super::ProviderRng(provider);
        macro_rules! encrypt_with {
            ($digest:ty, $mgf:ty) => {
                Oaep::<$digest, $mgf>::new_with_mgf_hash_and_label(parameters.label.clone())
                    .encrypt(&mut rng, key, plaintext)
            };
        }
        let result = match (parameters.digest, parameters.mgf_digest) {
            (OaepDigestAlgorithm::Sha1, OaepDigestAlgorithm::Sha1) => {
                encrypt_with!(Sha1, Sha1)
            }
            (OaepDigestAlgorithm::Sha1, OaepDigestAlgorithm::Sha256) => {
                encrypt_with!(Sha1, Sha256)
            }
            (OaepDigestAlgorithm::Sha1, OaepDigestAlgorithm::Sha384) => {
                encrypt_with!(Sha1, Sha384)
            }
            (OaepDigestAlgorithm::Sha1, OaepDigestAlgorithm::Sha512) => {
                encrypt_with!(Sha1, Sha512)
            }
            (OaepDigestAlgorithm::Sha256, OaepDigestAlgorithm::Sha1) => {
                encrypt_with!(Sha256, Sha1)
            }
            (OaepDigestAlgorithm::Sha256, OaepDigestAlgorithm::Sha256) => {
                encrypt_with!(Sha256, Sha256)
            }
            (OaepDigestAlgorithm::Sha256, OaepDigestAlgorithm::Sha384) => {
                encrypt_with!(Sha256, Sha384)
            }
            (OaepDigestAlgorithm::Sha256, OaepDigestAlgorithm::Sha512) => {
                encrypt_with!(Sha256, Sha512)
            }
            (OaepDigestAlgorithm::Sha384, OaepDigestAlgorithm::Sha1) => {
                encrypt_with!(Sha384, Sha1)
            }
            (OaepDigestAlgorithm::Sha384, OaepDigestAlgorithm::Sha256) => {
                encrypt_with!(Sha384, Sha256)
            }
            (OaepDigestAlgorithm::Sha384, OaepDigestAlgorithm::Sha384) => {
                encrypt_with!(Sha384, Sha384)
            }
            (OaepDigestAlgorithm::Sha384, OaepDigestAlgorithm::Sha512) => {
                encrypt_with!(Sha384, Sha512)
            }
            (OaepDigestAlgorithm::Sha512, OaepDigestAlgorithm::Sha1) => {
                encrypt_with!(Sha512, Sha1)
            }
            (OaepDigestAlgorithm::Sha512, OaepDigestAlgorithm::Sha256) => {
                encrypt_with!(Sha512, Sha256)
            }
            (OaepDigestAlgorithm::Sha512, OaepDigestAlgorithm::Sha384) => {
                encrypt_with!(Sha512, Sha384)
            }
            (OaepDigestAlgorithm::Sha512, OaepDigestAlgorithm::Sha512) => {
                encrypt_with!(Sha512, Sha512)
            }
        };
        result.map_err(map_rsa_error)
    }

    pub(super) fn recover_key(
        provider: &dyn CryptoProvider,
        key: &rsa::RsaPrivateKey,
        parameters: &RsaOaepParameters,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        if parameters.algorithm == KeyTransportAlgorithm::RsaOaepMgf1p
            && parameters.mgf_digest != OaepDigestAlgorithm::Sha1
        {
            return Err(ProviderError::InvalidInput(
                ProviderInputError::LegacyRsaOaepMgf,
            ));
        }
        let mut rng = super::ProviderRng(provider);
        macro_rules! decrypt_with {
            ($digest:ty, $mgf:ty) => {
                Oaep::<$digest, $mgf>::new_with_mgf_hash_and_label(parameters.label.clone())
                    .decrypt(Some(&mut rng), key, ciphertext)
            };
        }
        let result = match (parameters.digest, parameters.mgf_digest) {
            (OaepDigestAlgorithm::Sha1, OaepDigestAlgorithm::Sha1) => {
                decrypt_with!(Sha1, Sha1)
            }
            (OaepDigestAlgorithm::Sha1, OaepDigestAlgorithm::Sha256) => {
                decrypt_with!(Sha1, Sha256)
            }
            (OaepDigestAlgorithm::Sha1, OaepDigestAlgorithm::Sha384) => {
                decrypt_with!(Sha1, Sha384)
            }
            (OaepDigestAlgorithm::Sha1, OaepDigestAlgorithm::Sha512) => {
                decrypt_with!(Sha1, Sha512)
            }
            (OaepDigestAlgorithm::Sha256, OaepDigestAlgorithm::Sha1) => {
                decrypt_with!(Sha256, Sha1)
            }
            (OaepDigestAlgorithm::Sha256, OaepDigestAlgorithm::Sha256) => {
                decrypt_with!(Sha256, Sha256)
            }
            (OaepDigestAlgorithm::Sha256, OaepDigestAlgorithm::Sha384) => {
                decrypt_with!(Sha256, Sha384)
            }
            (OaepDigestAlgorithm::Sha256, OaepDigestAlgorithm::Sha512) => {
                decrypt_with!(Sha256, Sha512)
            }
            (OaepDigestAlgorithm::Sha384, OaepDigestAlgorithm::Sha1) => {
                decrypt_with!(Sha384, Sha1)
            }
            (OaepDigestAlgorithm::Sha384, OaepDigestAlgorithm::Sha256) => {
                decrypt_with!(Sha384, Sha256)
            }
            (OaepDigestAlgorithm::Sha384, OaepDigestAlgorithm::Sha384) => {
                decrypt_with!(Sha384, Sha384)
            }
            (OaepDigestAlgorithm::Sha384, OaepDigestAlgorithm::Sha512) => {
                decrypt_with!(Sha384, Sha512)
            }
            (OaepDigestAlgorithm::Sha512, OaepDigestAlgorithm::Sha1) => {
                decrypt_with!(Sha512, Sha1)
            }
            (OaepDigestAlgorithm::Sha512, OaepDigestAlgorithm::Sha256) => {
                decrypt_with!(Sha512, Sha256)
            }
            (OaepDigestAlgorithm::Sha512, OaepDigestAlgorithm::Sha384) => {
                decrypt_with!(Sha512, Sha384)
            }
            (OaepDigestAlgorithm::Sha512, OaepDigestAlgorithm::Sha512) => {
                decrypt_with!(Sha512, Sha512)
            }
        };
        result.map_err(map_rsa_error)
    }

    fn map_rsa_error(error: rsa::Error) -> ProviderError {
        match error {
            rsa::Error::Rng => ProviderError::Random("RSA-OAEP randomness failed".into()),
            _ => ProviderError::AuthenticationFailed,
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "xmldsig")]
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    #[cfg(feature = "xmldsig")]
    struct CountingRandomProvider {
        random_calls: AtomicUsize,
        reject_digest: Option<DigestAlgorithm>,
        extra_digest_byte: bool,
        accept_signatures: bool,
    }

    #[cfg(feature = "xmldsig")]
    impl CryptoProvider for CountingRandomProvider {
        fn name(&self) -> &'static str {
            "counting-random"
        }

        fn supports(&self, capability: ProviderCapability<'_>) -> bool {
            RUST_CRYPTO_PROVIDER.supports(capability)
        }

        fn fill_random(&self, output: &mut [u8]) -> Result<(), ProviderError> {
            self.random_calls.fetch_add(1, Ordering::Relaxed);
            RUST_CRYPTO_PROVIDER.fill_random(output)
        }

        fn digest(
            &self,
            algorithm: DigestAlgorithm,
            data: &[u8],
        ) -> Result<Vec<u8>, ProviderError> {
            if self.reject_digest == Some(algorithm) {
                return Err(ProviderError::Unsupported {
                    operation: ProviderOperation::Digest,
                    algorithm: Some(algorithm.uri().to_owned()),
                });
            }
            let mut digest = RUST_CRYPTO_PROVIDER.digest(algorithm, data)?;
            if self.extra_digest_byte {
                digest.push(0);
            }
            Ok(digest)
        }

        fn sign(
            &self,
            key: &dyn crate::xmldsig::SigningKey,
            algorithm: crate::xmldsig::SignatureAlgorithm,
            data: &[u8],
        ) -> Result<Vec<u8>, crate::xmldsig::SigningKeyError> {
            key.sign_with_provider(self, algorithm, data)
        }

        fn verify(
            &self,
            key: &dyn crate::xmldsig::VerifyingKey,
            algorithm: crate::xmldsig::SignatureAlgorithm,
            data: &[u8],
            signature: &[u8],
        ) -> Result<bool, crate::xmldsig::DsigError> {
            if self.accept_signatures {
                return Ok(true);
            }
            RUST_CRYPTO_PROVIDER.verify(key, algorithm, data, signature)
        }

        #[cfg(feature = "xmlenc")]
        fn encrypt_data(
            &self,
            algorithm: DataEncryptionAlgorithm,
            key: &[u8],
            plaintext: &[u8],
        ) -> Result<Vec<u8>, ProviderError> {
            RUST_CRYPTO_PROVIDER.encrypt_data(algorithm, key, plaintext)
        }

        #[cfg(feature = "xmlenc")]
        fn decrypt_data(
            &self,
            algorithm: DataEncryptionAlgorithm,
            key: &[u8],
            ciphertext: &[u8],
        ) -> Result<Vec<u8>, ProviderError> {
            RUST_CRYPTO_PROVIDER.decrypt_data(algorithm, key, ciphertext)
        }

        #[cfg(feature = "xmlenc")]
        fn wrap_key(
            &self,
            algorithm: KeyWrapAlgorithm,
            kek: &[u8],
            key: &[u8],
        ) -> Result<Vec<u8>, ProviderError> {
            RUST_CRYPTO_PROVIDER.wrap_key(algorithm, kek, key)
        }

        #[cfg(feature = "xmlenc")]
        fn unwrap_key(
            &self,
            algorithm: KeyWrapAlgorithm,
            kek: &[u8],
            wrapped: &[u8],
        ) -> Result<Vec<u8>, ProviderError> {
            RUST_CRYPTO_PROVIDER.unwrap_key(algorithm, kek, wrapped)
        }

        #[cfg(feature = "xmlenc")]
        fn transport_key(
            &self,
            key: &dyn KeyTransportKey,
            parameters: &RsaOaepParameters,
            plaintext: &[u8],
        ) -> Result<Vec<u8>, ProviderError> {
            RUST_CRYPTO_PROVIDER.transport_key(key, parameters, plaintext)
        }

        #[cfg(feature = "xmlenc")]
        fn recover_key(
            &self,
            key: &dyn KeyRecoveryKey,
            parameters: &RsaOaepParameters,
            ciphertext: &[u8],
        ) -> Result<Vec<u8>, ProviderError> {
            RUST_CRYPTO_PROVIDER.recover_key(key, parameters, ciphertext)
        }
    }

    #[cfg(feature = "xmldsig")]
    #[test]
    fn capability_query_is_explicit_about_unimplemented_operations() {
        assert!(RUST_CRYPTO_PROVIDER.supports(ProviderCapability::Digest(DigestAlgorithm::Sha256)));
        let agreement = KeyAgreementParameters {
            algorithm: "urn:unsupported:agreement",
            peer_public_key: &[],
        };
        assert!(!RUST_CRYPTO_PROVIDER.supports(ProviderCapability::KeyAgreement(&agreement)));
        assert!(!RUST_CRYPTO_PROVIDER.supports(ProviderCapability::Sign(
            crate::xmldsig::SignatureAlgorithm::RsaSha1
        )));
        assert!(RUST_CRYPTO_PROVIDER.supports(ProviderCapability::Verify(
            crate::xmldsig::SignatureAlgorithm::RsaSha1
        )));
    }

    #[cfg(all(feature = "xmldsig", feature = "xmlenc"))]
    #[test]
    fn capability_queries_include_oaep_and_pss_parameters() {
        use crate::xmlenc::{KeyTransportAlgorithm, OaepDigestAlgorithm};

        let invalid_legacy = RsaOaepParameters {
            algorithm: KeyTransportAlgorithm::RsaOaepMgf1p,
            digest: OaepDigestAlgorithm::Sha256,
            mgf_digest: OaepDigestAlgorithm::Sha256,
            label: Vec::new(),
        };
        assert!(!RUST_CRYPTO_PROVIDER.supports(ProviderCapability::KeyTransport(&invalid_legacy)));
        let modern =
            RsaOaepParameters::xmlenc11(OaepDigestAlgorithm::Sha256, OaepDigestAlgorithm::Sha512)
                .label(b"label".to_vec());
        assert!(RUST_CRYPTO_PROVIDER.supports(ProviderCapability::KeyTransport(&modern)));

        let supported_pss = X509SignatureAlgorithm::RsaPss {
            digest: DigestAlgorithm::Sha256,
            mgf_digest: DigestAlgorithm::Sha256,
            salt_len: 32,
        };
        assert!(
            RUST_CRYPTO_PROVIDER.supports(ProviderCapability::VerifyCertificate(supported_pss))
        );
        let unsupported_pss = X509SignatureAlgorithm::RsaPss {
            digest: DigestAlgorithm::Sha256,
            mgf_digest: DigestAlgorithm::Sha384,
            salt_len: 32,
        };
        assert!(
            !RUST_CRYPTO_PROVIDER.supports(ProviderCapability::VerifyCertificate(unsupported_pss))
        );
    }

    struct RecordingAgreementKey(AtomicBool);

    impl KeyAgreementKey for RecordingAgreementKey {
        fn agree(
            &self,
            _parameters: &KeyAgreementParameters<'_>,
        ) -> Result<Vec<u8>, ProviderError> {
            self.0.store(true, Ordering::Relaxed);
            Ok(vec![0x42])
        }
    }

    #[test]
    fn unsupported_agreement_and_kdf_fail_without_dispatch_or_fallback() {
        let agreement = KeyAgreementParameters {
            algorithm: "urn:example:agreement",
            peer_public_key: b"peer",
        };
        let key = RecordingAgreementKey(AtomicBool::new(false));
        let error = RUST_CRYPTO_PROVIDER
            .agree_key(&key, &agreement)
            .expect_err("unsupported agreement must fail closed");
        assert!(matches!(
            error,
            ProviderError::Unsupported {
                operation: ProviderOperation::KeyAgreement,
                algorithm: Some(ref algorithm),
            } if algorithm == agreement.algorithm
        ));
        assert!(!key.0.load(Ordering::Relaxed));

        let kdf = KdfParameters {
            algorithm: "urn:example:kdf",
            digest: Some("urn:example:digest"),
            salt: b"salt",
            info: b"info",
            iterations: 1,
            output_len: 32,
        };
        assert!(matches!(
            RUST_CRYPTO_PROVIDER.derive_key(&kdf, b"secret"),
            Err(ProviderError::Unsupported {
                operation: ProviderOperation::Kdf,
                algorithm: Some(ref algorithm),
            }) if algorithm == kdf.algorithm
        ));
    }

    #[cfg(feature = "xmldsig")]
    #[test]
    fn rsa_signing_uses_the_selected_providers_randomness() {
        use crate::xmldsig::{RsaSigningKey, SignatureAlgorithm};

        // RSA PKCS#1 v1.5 uses randomness for blinding even though its wire
        // signature is deterministic; the selected provider owns that source.
        let key = RsaSigningKey::from_pkcs8_pem(include_str!(
            "../tests/fixtures/keys/rsa/rsa-2048-key.pem"
        ))
        .expect("RSA fixture must parse");
        let provider = CountingRandomProvider {
            random_calls: AtomicUsize::new(0),
            reject_digest: None,
            extra_digest_byte: false,
            accept_signatures: false,
        };

        let signature = provider
            .sign(&key, SignatureAlgorithm::RsaSha256, b"signed info")
            .expect("RSA signing must succeed");

        assert!(!signature.is_empty());
        assert!(provider.random_calls.load(Ordering::Relaxed) > 0);
    }

    #[cfg(feature = "xmldsig")]
    #[test]
    fn ecdsa_signing_uses_the_selected_providers_digest() {
        use crate::xmldsig::{
            EcdsaP256SigningKey, EcdsaP384SigningKey, SignatureAlgorithm, SigningKeyError,
        };

        // SignatureMethod chooses the hash independently of the EC key curve.
        // Both built-in ECDSA keys must therefore ask the selected provider for
        // that digest instead of hashing behind the provider boundary.
        let cases: [(
            Box<dyn crate::xmldsig::SigningKey>,
            SignatureAlgorithm,
            DigestAlgorithm,
        ); 2] = [
            (
                Box::new(
                    EcdsaP256SigningKey::from_pkcs8_pem(include_str!(
                        "../tests/fixtures/keys/ec/ec-prime256v1-key.pem"
                    ))
                    .expect("P-256 fixture must parse"),
                ),
                SignatureAlgorithm::EcdsaSha384,
                DigestAlgorithm::Sha384,
            ),
            (
                Box::new(
                    EcdsaP384SigningKey::from_pkcs8_pem(include_str!(
                        "../tests/fixtures/keys/ec/ec-prime384v1-key.pem"
                    ))
                    .expect("P-384 fixture must parse"),
                ),
                SignatureAlgorithm::EcdsaSha256,
                DigestAlgorithm::Sha256,
            ),
        ];

        for (key, signature_algorithm, digest_algorithm) in cases {
            let provider = CountingRandomProvider {
                random_calls: AtomicUsize::new(0),
                reject_digest: Some(digest_algorithm),
                extra_digest_byte: false,
                accept_signatures: false,
            };
            let error = provider
                .sign(key.as_ref(), signature_algorithm, b"signed info")
                .expect_err("provider digest rejection must stop ECDSA signing");

            assert!(matches!(
                error,
                SigningKeyError::Provider(ProviderError::Unsupported {
                    operation: ProviderOperation::Digest,
                    algorithm: Some(ref uri),
                }) if uri == digest_algorithm.uri()
            ));
        }
    }

    #[cfg(feature = "xmldsig")]
    #[test]
    fn ecdsa_signing_rejects_provider_digests_with_the_wrong_length() {
        use crate::xmldsig::{
            EcdsaP256SigningKey, EcdsaP384SigningKey, SignatureAlgorithm, SigningKeyError,
        };

        // Prehash signers may truncate oversized input, so the provider
        // boundary must reject it before either curve receives the digest.
        let cases: [(
            Box<dyn crate::xmldsig::SigningKey>,
            SignatureAlgorithm,
            usize,
        ); 2] = [
            (
                Box::new(
                    EcdsaP256SigningKey::from_pkcs8_pem(include_str!(
                        "../tests/fixtures/keys/ec/ec-prime256v1-key.pem"
                    ))
                    .expect("P-256 fixture must parse"),
                ),
                SignatureAlgorithm::EcdsaSha256,
                32,
            ),
            (
                Box::new(
                    EcdsaP384SigningKey::from_pkcs8_pem(include_str!(
                        "../tests/fixtures/keys/ec/ec-prime384v1-key.pem"
                    ))
                    .expect("P-384 fixture must parse"),
                ),
                SignatureAlgorithm::EcdsaSha384,
                48,
            ),
        ];

        for (key, algorithm, expected) in cases {
            let provider = CountingRandomProvider {
                random_calls: AtomicUsize::new(0),
                reject_digest: None,
                extra_digest_byte: true,
                accept_signatures: false,
            };
            let error = provider
                .sign(key.as_ref(), algorithm, b"signed info")
                .expect_err("an oversized provider digest must not reach ECDSA prehash signing");

            assert!(matches!(
                error,
                SigningKeyError::Provider(ProviderError::InvalidOutputSize {
                    operation: ProviderOperation::Digest,
                    expected: actual_expected,
                    actual,
                }) if actual_expected == expected && actual == expected + 1
            ));
        }
    }

    #[cfg(feature = "xmldsig")]
    #[test]
    fn verification_facade_rejects_malformed_dsa_before_provider_dispatch() {
        use crate::xmldsig::{
            DefaultKeyResolver, DsigStatus, FailureReason, SignatureAlgorithm, VerifyContext,
        };

        let original = include_str!(
            "../tests/fixtures/xmldsig/merlin-xmldsig-twenty-three/signature-enveloping-dsa.xml"
        );
        let value_start = original
            .find("<SignatureValue>")
            .expect("Merlin fixture must contain SignatureValue")
            + "<SignatureValue>".len();
        let value_end = original[value_start..]
            .find("</SignatureValue>")
            .map(|offset| value_start + offset)
            .expect("Merlin fixture must close SignatureValue");
        let mut malformed = original.to_owned();
        malformed.replace_range(value_start..value_end, "AQ==");
        let provider = CountingRandomProvider {
            random_calls: AtomicUsize::new(0),
            reject_digest: None,
            extra_digest_byte: false,
            accept_signatures: true,
        };

        let mut policy = crate::policy::VerificationPolicy::default();
        policy
            .key_trust
            .allowed_legacy_signature_algorithms
            .insert(SignatureAlgorithm::DsaSha1);
        policy.key_trust.dsa_keys.minimum_modulus_bits = 1024;
        let result = VerifyContext::new()
            .policy(policy)
            .provider(&provider)
            .key_resolver(&DefaultKeyResolver::default())
            .verify(&malformed)
            .expect("malformed framing must be a verification miss");

        assert_eq!(
            result.status,
            DsigStatus::Invalid(FailureReason::SignatureMismatch)
        );
    }

    #[cfg(feature = "xmldsig")]
    #[test]
    fn rustcrypto_provider_verifies_parameterized_rsa_pss_certificates() {
        use der::{Decode as _, Encode as _};
        use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
        use rsa::{RsaPrivateKey, pkcs8::EncodePublicKey, pss::SigningKey as RsaPssSigningKey};
        use sha2::Sha256;
        use signature::{RandomizedSigner, SignatureEncoding};
        use x509_cert::spki::{AlgorithmIdentifierOwned, ObjectIdentifier};

        // X.509 RSASSA-PSS carries salt and MGF parameters that cannot be
        // represented by the XMLDSig SignatureAlgorithm enum.
        let mut rng = ChaCha20Rng::from_seed([0x5a; 32]);
        let private_key =
            RsaPrivateKey::new(&mut rng, 2048).expect("deterministic RSA key generation");
        let public_key = private_key
            .to_public_key()
            .to_public_key_der()
            .expect("RSA public key must encode as SPKI");
        let signing_key = RsaPssSigningKey::<Sha256>::new_with_salt_len(private_key, 32);
        let signed_data = b"certificate tbs bytes";
        let signature = signing_key
            .try_sign_with_rng(&mut rng, signed_data)
            .expect("RSA-PSS signing must succeed")
            .to_vec();

        assert!(
            RUST_CRYPTO_PROVIDER
                .verify_x509_signature(
                    X509SignatureAlgorithm::RsaPss {
                        digest: DigestAlgorithm::Sha256,
                        mgf_digest: DigestAlgorithm::Sha256,
                        salt_len: 32,
                    },
                    signed_data,
                    &signature,
                    public_key.as_bytes(),
                )
                .expect("standard RSA-PSS parameters must be supported")
        );

        let mut parameterless_pss_spki =
            x509_cert::SubjectPublicKeyInfo::from_der(public_key.as_bytes())
                .expect("RSA SPKI must decode");
        parameterless_pss_spki.algorithm = AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10"),
            parameters: None,
        };
        let parameterless_pss_spki = parameterless_pss_spki
            .to_der()
            .expect("parameterless PSS SPKI must encode");
        assert!(
            RUST_CRYPTO_PROVIDER
                .verify_x509_signature(
                    X509SignatureAlgorithm::RsaPss {
                        digest: DigestAlgorithm::Sha256,
                        mgf_digest: DigestAlgorithm::Sha256,
                        salt_len: 32,
                    },
                    signed_data,
                    &signature,
                    &parameterless_pss_spki,
                )
                .expect("parameterless PSS keys impose no signature restrictions")
        );

        let mut pss_spki = x509_cert::SubjectPublicKeyInfo::from_der(public_key.as_bytes())
            .expect("RSA SPKI must decode");
        let pss_parameters = der::asn1::Any::from_der(&[
            0x30, 0x34, 0xa0, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
            0x04, 0x02, 0x01, 0x05, 0x00, 0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48,
            0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
            0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0xa2, 0x03, 0x02, 0x01, 0x20,
        ])
        .expect("standard SHA-256 PSS parameters must decode");
        pss_spki.algorithm = AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10"),
            parameters: Some(pss_parameters),
        };
        let pss_spki = pss_spki.to_der().expect("PSS SPKI must encode");

        assert!(
            RUST_CRYPTO_PROVIDER
                .verify_x509_signature(
                    X509SignatureAlgorithm::RsaPss {
                        digest: DigestAlgorithm::Sha256,
                        mgf_digest: DigestAlgorithm::Sha256,
                        salt_len: 32,
                    },
                    signed_data,
                    &signature,
                    &pss_spki,
                )
                .expect("RFC 4055 PSS SubjectPublicKeyInfo must be supported")
        );

        for incompatible in [
            X509SignatureAlgorithm::RsaPss {
                digest: DigestAlgorithm::Sha384,
                mgf_digest: DigestAlgorithm::Sha256,
                salt_len: 32,
            },
            X509SignatureAlgorithm::RsaPss {
                digest: DigestAlgorithm::Sha256,
                mgf_digest: DigestAlgorithm::Sha384,
                salt_len: 32,
            },
            X509SignatureAlgorithm::RsaPss {
                digest: DigestAlgorithm::Sha256,
                mgf_digest: DigestAlgorithm::Sha256,
                salt_len: 16,
            },
        ] {
            assert!(
                !RUST_CRYPTO_PROVIDER
                    .verify_x509_signature(incompatible, signed_data, &signature, &pss_spki,)
                    .expect("incompatible PSS key restrictions are invalid, not unsupported")
            );
        }
    }

    #[cfg(feature = "xmldsig")]
    #[test]
    fn rustcrypto_provider_verifies_dsa_certificate_signature_at_q_width() {
        use base64::Engine as _;

        // OpenSSL-generated L=2048/N=224 DSA material. X.509 carries DER r/s
        // integers at q width, not XMLDSig's legacy fixed 20-byte components.
        let spki = base64::engine::general_purpose::STANDARD
            .decode("MIIDQzCCAjYGByqGSM44BAEwggIpAoIBAQDEkm7mUEj1dizQRRrcU6ehyhpQ1NAkcKi9XyNcBJDZlyTdVH09XZ04UZNuXAWRL1hEDvDAvFimuwmW7k099j0PRM+WypsfOOgZPJhIVNZu9poTPGINKpbMTXFmR+qhrYM4z+NSKxuUBWZwX5HibBIG5INbx8IDHWAxZqxgHQsebDej1+yZyCTTpmDS9nKGkBRVaxsJgZt958UPNlIz1ECf4n4P4mPLAl7W5xV8VSWMqlXdkOAPbLC/mChjFoCj0jmCQpbcOvd7a6cWhcyhw/yikoVoKEPNWr9xLtdJV37f1/4q/xTvoPKWhMmgMQ/DigUnYgPzmexyS82m5HLZ/vOJAh0A/ckrg9g9PsZesUsH/4bEijeNwWGXB5e+/LCt0QKCAQEAuBGFzyjZEmvbDKbb+8tz+zqw4lK7RGwOjVM3v9xPS6LuG5L1OwCNQcUcVIsU9VxBnEx9oMnl8eVX1nq3kfdiZB2F9ESxwX5FzBt+KLjMOzBa8rPlzVcyCZ3sT3orAQ2D/q7ffDhTCUt+v8UNiAhVbaNnR/vI7AkVoP9crRjpOSV/7b5MGa0BcjIyEzTtqM58wppfSQt8jkj7WT3+Bww/Y9rOtshDE2QosaX/7xoDnzyeZ3amLjTe3/MjBcsKlbK2z4QuaI6xoQBVd/QjP8FjXpZBhXWFIAsOL/sz6uR2Er0ovdX8DBA0EJpuzlTX94Lvf+Eh+5/83ESAm97fk4pnhQOCAQUAAoIBAEwSwKuLFPeR7UJGXkWM9egyYewhqHpIXPBEWOVPqwTw3xLc3EkufpYY9wkhJS08KD+J92jMjm//0bYeVf7fXisc6PHtGY4wx5XBm1g9HKw9lwRjbk7nH495dlZdl0BXHa14TJ8myE2zOM1jsaFyz6jAFTaRnKYIj6WlKOj59d2iAXtLZRme9r+7U4G6zDUkphyIEcIGH4vhb6gm3URr1zAV5kJjTlsPAiqgeH/PgxU52tmvLphJgv/xPxsuX5W0/s7iKbphIb2YWh/gtTWXvRQHiQQ2fCncI3TAMnZ75dBY0gPOVLQJhUyffeRbk9UULux/jc8QBPgKBS7GM5DnNSw=")
            .expect("DSA SPKI fixture must decode");
        let signature = base64::engine::general_purpose::STANDARD
            .decode("MD0CHQChtB1c+f5BmTJCtT7Gi4cyQiR2igj0znRQYCJ3Ahw4NGg4pL5jgA8Ri07ESV9Yr90WfUmRrbRcnjsY")
            .expect("DSA signature fixture must decode");
        let message = b"certificate tbs bytes for dsa q-width regression";

        assert!(
            rustcrypto_x509::verify_signature(
                X509SignatureAlgorithm::Dsa(DigestAlgorithm::Sha1),
                message,
                &signature,
                &spki,
            )
            .expect("supported DSA-SHA1 certificate signature")
        );

        let mut tampered = signature;
        *tampered.last_mut().expect("DER signature is non-empty") ^= 1;
        assert!(
            !rustcrypto_x509::verify_signature(
                X509SignatureAlgorithm::Dsa(DigestAlgorithm::Sha1),
                message,
                &tampered,
                &spki,
            )
            .expect("tampered DSA-SHA1 certificate signature is a verification miss")
        );
    }

    #[cfg(feature = "xmldsig")]
    #[test]
    fn primitive_provider_does_not_embed_rsa_strength_policy() {
        use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
        use rsa::{RsaPrivateKey, pkcs8::EncodePublicKey, pss::SigningKey as RsaPssSigningKey};
        use sha2::Sha256;
        use signature::{RandomizedSigner, SignatureEncoding};

        let mut rng = ChaCha20Rng::from_seed([0x3c; 32]);
        let private_key =
            RsaPrivateKey::new(&mut rng, 1024).expect("deterministic weak RSA key generation");
        let public_key = private_key
            .to_public_key()
            .to_public_key_der()
            .expect("weak RSA public key must encode as SPKI");
        let signed_data = b"certificate tbs bytes";
        let signature = RsaPssSigningKey::<Sha256>::new_with_salt_len(private_key, 32)
            .try_sign_with_rng(&mut rng, signed_data)
            .expect("weak RSA-PSS key can still produce a cryptographic signature")
            .to_vec();

        assert!(
            RUST_CRYPTO_PROVIDER
                .verify_x509_signature(
                    X509SignatureAlgorithm::RsaPss {
                        digest: DigestAlgorithm::Sha256,
                        mgf_digest: DigestAlgorithm::Sha256,
                        salt_len: 32,
                    },
                    signed_data,
                    &signature,
                    public_key.as_bytes(),
                )
                .expect(
                    "provider must evaluate structurally valid RSA-PSS independently of policy"
                )
        );
    }

    #[cfg(feature = "xmlenc")]
    #[test]
    fn legacy_oaep_mgf_constraint_is_symmetric() {
        use rsa::pkcs8::DecodePrivateKey;

        // The legacy URI fixes MGF1 to SHA-1 for both directions; rejecting
        // before RSA processing keeps transport and recovery capabilities equal.
        let key = rsa::RsaPrivateKey::from_pkcs8_pem(include_str!(
            "../tests/fixtures/keys/rsa/rsa-2048-key.pem"
        ))
        .expect("RSA fixture must parse");
        let parameters = crate::xmlenc::RsaOaepParameters {
            algorithm: crate::xmlenc::KeyTransportAlgorithm::RsaOaepMgf1p,
            digest: crate::xmlenc::OaepDigestAlgorithm::Sha256,
            mgf_digest: crate::xmlenc::OaepDigestAlgorithm::Sha256,
            label: Vec::new(),
        };

        assert!(matches!(
            RUST_CRYPTO_PROVIDER.recover_key(&key, &parameters, &[0_u8; 256]),
            Err(ProviderError::InvalidInput(
                ProviderInputError::LegacyRsaOaepMgf
            ))
        ));
        assert!(matches!(
            RUST_CRYPTO_PROVIDER.transport_key(&key.to_public_key(), &parameters, &[0_u8; 16]),
            Err(ProviderError::InvalidInput(
                ProviderInputError::LegacyRsaOaepMgf
            ))
        ));
    }
}
