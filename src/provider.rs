//! Provider-neutral cryptographic operations.
//!
//! XML parsing and protocol orchestration depend on this contract rather than
//! concrete cryptographic crates. Secret-bearing keys remain opaque behind
//! operation-specific handles; this provider owns primitive dispatch and
//! randomness.

#[cfg(feature = "aws-lc-fips")]
mod aws_lc;
#[cfg(feature = "pkcs11")]
pub mod pkcs11;
#[cfg(all(feature = "xmlenc", feature = "legacy-algorithms"))]
mod rsa_pkcs1v15;
#[cfg(feature = "xmldsig")]
pub(crate) mod rsa_pss;

/// Secret candidate whose recovery validity is retained until content work ends.
/// Debug output never exposes key bytes or padding validity.
#[cfg(feature = "xmlenc")]
pub struct RecoveredContentKey {
    bytes: zeroize::Zeroizing<Vec<u8>>,
    valid: subtle::Choice,
    opaque: Option<std::sync::Arc<dyn ContentDecryptionKey>>,
}

#[cfg(feature = "xmlenc")]
impl std::fmt::Debug for RecoveredContentKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveredContentKey")
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "xmlenc")]
impl RecoveredContentKey {
    /// An explicitly supplied key, or one recovered by an integrity-checking
    /// mechanism such as OAEP or key wrap. Not for implicit-rejection output.
    pub fn confirmed(bytes: Vec<u8>) -> Self {
        Self {
            bytes: zeroize::Zeroizing::new(bytes),
            valid: subtle::Choice::from(1),
            opaque: None,
        }
    }

    #[cfg(feature = "legacy-algorithms")]
    /// Preserve a trusted provider's constant-time padding-validation result.
    /// `bytes` must already contain the fixed-width real-or-fallback candidate;
    /// the caller must not branch on `valid` during recovery. The enclosing
    /// content operation consumes this state only after primitive decryption.
    pub fn recovery(bytes: zeroize::Zeroizing<Vec<u8>>, valid: subtle::Choice) -> Self {
        Self {
            bytes,
            valid,
            opaque: None,
        }
    }

    /// Retain a non-exportable content key until the content operation ends.
    pub fn opaque(key: std::sync::Arc<dyn ContentDecryptionKey>) -> Self {
        Self {
            bytes: zeroize::Zeroizing::new(Vec::new()),
            valid: subtle::Choice::from(1),
            opaque: Some(key),
        }
    }

    /// Public content-key width without exposing the key value.
    pub fn key_len(&self) -> usize {
        self.opaque
            .as_ref()
            .map_or(self.bytes.len(), |key| key.key_len())
    }

    pub(crate) fn same_candidate(&self, other: &Self) -> bool {
        match (&self.opaque, &other.opaque) {
            (Some(a), Some(b)) => std::sync::Arc::ptr_eq(a, b),
            (None, None) => self.bytes == other.bytes && self.valid() == other.valid(),
            _ => false,
        }
    }

    pub(crate) fn decrypt(
        &self,
        provider: &dyn CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        match &self.opaque {
            Some(key) => provider.decrypt_content_key(algorithm, key.as_ref(), ciphertext),
            None => provider.decrypt_data(algorithm, &self.bytes, ciphertext),
        }
    }

    #[cfg(test)]
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(crate) fn valid(&self) -> bool {
        bool::from(self.valid)
    }
    /// Consume a completed recovery outside a content operation. Content
    /// operations must retain the candidate until after primitive decryption.
    pub fn into_key(mut self) -> Result<Vec<u8>, ProviderError> {
        if self.opaque.is_some() {
            return Err(ProviderError::KeyNotExportable);
        }
        if !self.valid() {
            return Err(ProviderError::AuthenticationFailed);
        }
        Ok(core::mem::take(&mut *self.bytes))
    }
}
#[cfg(all(feature = "aws-lc-fips", feature = "xmlenc"))]
pub use aws_lc::AwsLcRsaPrivateKey;
#[cfg(feature = "aws-lc-fips")]
pub use aws_lc::{AwsLcFipsProvider, AwsLcSigningKey};

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
    /// Private-key recovery of transported key bytes.
    KeyRecovery,
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
    /// Provider dispatch for an XMLDSig signing method.
    ///
    /// The opaque signing key remains responsible for accepting the method and
    /// implementing its primitive.
    #[cfg(feature = "xmldsig")]
    Sign(crate::xmldsig::SignatureAlgorithm),
    /// Provider dispatch for an XMLDSig verification method.
    ///
    /// The opaque verification key remains responsible for accepting the
    /// method and implementing its primitive.
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
    /// RSA-OAEP key recovery with complete digest, MGF, and label parameters.
    #[cfg(feature = "xmlenc")]
    KeyRecovery(&'a RsaOaepParameters),
    /// Historical RSAES-PKCS1-v1_5 transport, without OAEP parameters.
    #[cfg(all(feature = "xmlenc", feature = "legacy-algorithms"))]
    Pkcs1v15Transport,
    /// Historical RSAES-PKCS1-v1_5 fixed-length content-key recovery.
    #[cfg(all(feature = "xmlenc", feature = "legacy-algorithms"))]
    Pkcs1v15Recovery,
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
            #[cfg(feature = "xmlenc")]
            Self::KeyRecovery(_) => ProviderOperation::KeyRecovery,
            #[cfg(all(feature = "xmlenc", feature = "legacy-algorithms"))]
            Self::Pkcs1v15Transport => ProviderOperation::KeyTransport,
            #[cfg(all(feature = "xmlenc", feature = "legacy-algorithms"))]
            Self::Pkcs1v15Recovery => ProviderOperation::KeyRecovery,
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
            Self::VerifyCertificate(algorithm) => algorithm.oid(),
            #[cfg(feature = "xmlenc")]
            Self::Encrypt(algorithm) | Self::Decrypt(algorithm) => Some(algorithm.uri()),
            #[cfg(feature = "xmlenc")]
            Self::KeyWrap(algorithm) | Self::KeyUnwrap(algorithm) => Some(algorithm.uri()),
            #[cfg(feature = "xmlenc")]
            Self::KeyTransport(parameters) | Self::KeyRecovery(parameters) => {
                Some(parameters.algorithm.uri())
            }
            Self::KeyAgreement(parameters) => Some(parameters.algorithm),
            #[cfg(all(feature = "xmlenc", feature = "legacy-algorithms"))]
            Self::Pkcs1v15Transport | Self::Pkcs1v15Recovery => {
                Some(crate::xmlenc::KeyTransportAlgorithm::RsaPkcs1v15.uri())
            }
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    /// Pure Ed448 as specified by RFC 8410.
    Ed448,
    /// Pure ML-DSA or SLH-DSA with the PKIX-mandated empty context.
    PostQuantum(crate::xmldsig::PqAlgorithm),
}

#[cfg(feature = "xmldsig")]
impl X509SignatureAlgorithm {
    /// Return the assigned AlgorithmIdentifier OID, or `None` for unsupported combinations.
    #[must_use]
    pub const fn oid(self) -> Option<&'static str> {
        Some(match self {
            #[cfg(feature = "legacy-algorithms")]
            Self::Dsa(DigestAlgorithm::Md5 | DigestAlgorithm::Ripemd160)
            | Self::RsaPkcs1v15(DigestAlgorithm::Md5 | DigestAlgorithm::Ripemd160)
            | Self::Ecdsa(DigestAlgorithm::Md5 | DigestAlgorithm::Ripemd160) => return None,
            Self::Dsa(DigestAlgorithm::Sha1) => "1.2.840.10040.4.3",
            Self::Dsa(DigestAlgorithm::Sha224) => "2.16.840.1.101.3.4.3.1",
            Self::Dsa(DigestAlgorithm::Sha256) => "2.16.840.1.101.3.4.3.2",
            Self::Dsa(DigestAlgorithm::Sha384) => "2.16.840.1.101.3.4.3.3",
            Self::Dsa(DigestAlgorithm::Sha512) => "2.16.840.1.101.3.4.3.4",
            Self::Dsa(DigestAlgorithm::Sha3_224) => "2.16.840.1.101.3.4.3.5",
            Self::Dsa(DigestAlgorithm::Sha3_256) => "2.16.840.1.101.3.4.3.6",
            Self::Dsa(DigestAlgorithm::Sha3_384) => "2.16.840.1.101.3.4.3.7",
            Self::Dsa(DigestAlgorithm::Sha3_512) => "2.16.840.1.101.3.4.3.8",
            Self::RsaPkcs1v15(DigestAlgorithm::Sha1) => "1.2.840.113549.1.1.5",
            Self::RsaPkcs1v15(DigestAlgorithm::Sha224) => "1.2.840.113549.1.1.14",
            Self::RsaPkcs1v15(DigestAlgorithm::Sha256) => "1.2.840.113549.1.1.11",
            Self::RsaPkcs1v15(DigestAlgorithm::Sha384) => "1.2.840.113549.1.1.12",
            Self::RsaPkcs1v15(DigestAlgorithm::Sha512) => "1.2.840.113549.1.1.13",
            Self::RsaPkcs1v15(DigestAlgorithm::Sha3_224) => "2.16.840.1.101.3.4.3.13",
            Self::RsaPkcs1v15(DigestAlgorithm::Sha3_256) => "2.16.840.1.101.3.4.3.14",
            Self::RsaPkcs1v15(DigestAlgorithm::Sha3_384) => "2.16.840.1.101.3.4.3.15",
            Self::RsaPkcs1v15(DigestAlgorithm::Sha3_512) => "2.16.840.1.101.3.4.3.16",
            Self::RsaPss { .. } => "1.2.840.113549.1.1.10",
            Self::Ecdsa(DigestAlgorithm::Sha1) => "1.2.840.10045.4.1",
            Self::Ecdsa(DigestAlgorithm::Sha224) => "1.2.840.10045.4.3.1",
            Self::Ecdsa(DigestAlgorithm::Sha256) => "1.2.840.10045.4.3.2",
            Self::Ecdsa(DigestAlgorithm::Sha384) => "1.2.840.10045.4.3.3",
            Self::Ecdsa(DigestAlgorithm::Sha512) => "1.2.840.10045.4.3.4",
            Self::Ecdsa(DigestAlgorithm::Sha3_224) => "2.16.840.1.101.3.4.3.9",
            Self::Ecdsa(DigestAlgorithm::Sha3_256) => "2.16.840.1.101.3.4.3.10",
            Self::Ecdsa(DigestAlgorithm::Sha3_384) => "2.16.840.1.101.3.4.3.11",
            Self::Ecdsa(DigestAlgorithm::Sha3_512) => "2.16.840.1.101.3.4.3.12",
            Self::Ed25519 => "1.3.101.112",
            Self::Ed448 => "1.3.101.113",
            Self::PostQuantum(algorithm) => algorithm.oid(),
        })
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
    /// Legacy compatibility variant retained for downstream construction and matching.
    ///
    /// Explicit MGF parameters are valid for both RSA-OAEP URIs, so current providers never
    /// return this reason.
    #[deprecated(note = "explicit MGF parameters are supported for both RSA-OAEP URIs")]
    #[error("legacy RSA-OAEP requires MGF1-SHA1")]
    LegacyRsaOaepMgf,
}

/// Failure returned by a cryptographic provider.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProviderError {
    /// A secret-bearing external handle cannot be exported as bytes.
    #[error("key is not exportable")]
    KeyNotExportable,
    /// Redacted external-provider failure: never includes credentials or selectors.
    #[error("external cryptographic provider failed: {0}")]
    External(ExternalProviderError),
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

/// Operational failure classes for an explicitly selected external provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ExternalProviderError {
    /// The module, token or device is unavailable.
    #[error("module or token unavailable")]
    Unavailable,
    /// Authentication failed or the operation requires authentication.
    #[error("authentication failed")]
    Credentials,
    /// The selected object does not exist, is ambiguous, or has expired.
    #[error("key object unavailable or ambiguous")]
    Object,
    /// Token key usage does not authorize this primitive.
    #[error("key usage denied")]
    Usage,
    /// The key and selected provider do not share an execution domain.
    #[error("key provider binding mismatch")]
    Binding,
    /// A provider-side operation or synchronization failed.
    #[error("token operation failed")]
    Operation,
}

/// Caller-owned identity for external-provider handles, independent of engine name.
#[derive(Clone, Default)]
pub struct ProviderBinding(std::sync::Arc<()>);

impl ProviderBinding {
    /// Test identity without copying secret or public key material.
    pub fn matches(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.0, &other.0)
    }
}

/// Non-exportable symmetric key used for content decryption.
#[cfg(feature = "xmlenc")]
pub trait ContentDecryptionKey: Send + Sync {
    /// Exact external domain owning this handle.
    fn provider_binding(&self) -> &ProviderBinding;
    /// Public key width in bytes.
    fn key_len(&self) -> usize;
    /// Execute within the selected provider's execution domain.
    fn decrypt_with_provider(
        &self,
        provider: &dyn CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ProviderError>;
}

/// An opaque KEK that unwraps directly into a non-exportable content key.
#[cfg(feature = "xmlenc")]
pub trait KeyUnwrappingKey: Send + Sync {
    /// Exact external domain owning this handle.
    fn provider_binding(&self) -> &ProviderBinding;
    /// Unwrap within the selected execution domain without reading CKA_VALUE.
    fn unwrap_with_provider(
        &self,
        provider: &dyn CryptoProvider,
        algorithm: KeyWrapAlgorithm,
        content_algorithm: DataEncryptionAlgorithm,
        wrapped: &[u8],
    ) -> Result<RecoveredContentKey, ProviderError>;
}

/// Opaque public-key handle used for asymmetric key transport.
///
/// Implementations own their key material and operation. The orchestration
/// layer can inspect only public RSA components needed for policy validation
/// and output framing; it cannot recover a backend-specific key object.
#[cfg(feature = "xmlenc")]
pub trait KeyTransportKey: Send + Sync {
    /// External execution domain, or `None` for software-owned public keys.
    fn provider_binding(&self) -> Option<&ProviderBinding> {
        None
    }
    /// Execute historical transport; unsupported opaque handles never fall back.
    #[cfg(feature = "legacy-algorithms")]
    fn transport_pkcs1v15(
        &self,
        _provider: &dyn CryptoProvider,
        _plaintext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        Err(ProviderError::Unsupported {
            operation: ProviderOperation::KeyTransport,
            algorithm: Some(
                crate::xmlenc::KeyTransportAlgorithm::RsaPkcs1v15
                    .uri()
                    .into(),
            ),
        })
    }
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
    /// Recover without exporting a CEK when supported by the execution domain.
    fn recover_content_with_provider(
        &self,
        provider: &dyn CryptoProvider,
        parameters: &RsaOaepParameters,
        _content_algorithm: DataEncryptionAlgorithm,
        ciphertext: &[u8],
    ) -> Result<RecoveredContentKey, ProviderError> {
        self.recover_with_provider(provider, parameters, ciphertext)
            .map(RecoveredContentKey::confirmed)
    }
    /// Recover a content key of the caller's already validated algorithm width.
    #[cfg(feature = "legacy-algorithms")]
    fn recover_pkcs1v15(
        &self,
        _provider: &dyn CryptoProvider,
        _ciphertext: &[u8],
        _key_len: usize,
    ) -> Result<RecoveredContentKey, ProviderError> {
        Err(ProviderError::Unsupported {
            operation: ProviderOperation::KeyRecovery,
            algorithm: Some(
                crate::xmlenc::KeyTransportAlgorithm::RsaPkcs1v15
                    .uri()
                    .into(),
            ),
        })
    }
    /// Native engine binding; an incompatible provider must reject this handle.
    fn provider_name(&self) -> Option<&'static str> {
        None
    }
    /// Borrow the matching public SPKI when available for certificate binding.
    fn public_spki(&self) -> Option<&[u8]> {
        None
    }
    /// Exact mathematical bit length of the recovery key's public modulus,
    /// excluding leading zero padding. Not the rounded ciphertext width.
    fn rsa_modulus_bits(&self) -> usize;

    /// Public exponent of that same key, or `None` if wider than 64 bits.
    /// Opaque providers expose public metadata without copying private material.
    fn rsa_public_exponent(&self) -> Option<u64>;

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
    /// External execution domain, when the private key resides outside this process.
    fn provider_binding(&self) -> Option<&ProviderBinding> {
        None
    }
    /// Derive the raw shared secret for the supplied peer and parameters.
    fn agree(&self, parameters: &KeyAgreementParameters<'_>) -> Result<Vec<u8>, ProviderError>;
}

/// Provider operations used by the XML Security pipelines.
pub trait CryptoProvider: Send + Sync {
    /// External execution domain. Different instances of one engine are not interchangeable.
    fn binding(&self) -> Option<&ProviderBinding> {
        None
    }

    /// Recover a candidate without requiring its symmetric value to leave the provider.
    #[cfg(feature = "xmlenc")]
    fn recover_content_key(
        &self,
        key: &dyn KeyRecoveryKey,
        parameters: &RsaOaepParameters,
        _content_algorithm: DataEncryptionAlgorithm,
        ciphertext: &[u8],
    ) -> Result<RecoveredContentKey, ProviderError> {
        self.recover_key(key, parameters, ciphertext)
            .map(RecoveredContentKey::confirmed)
    }

    /// Unwrap into an opaque content key. Providers must opt in explicitly.
    #[cfg(feature = "xmlenc")]
    fn unwrap_content_key(
        &self,
        _key: &dyn KeyUnwrappingKey,
        algorithm: KeyWrapAlgorithm,
        _content_algorithm: DataEncryptionAlgorithm,
        _wrapped: &[u8],
    ) -> Result<RecoveredContentKey, ProviderError> {
        Err(ProviderError::Unsupported {
            operation: ProviderOperation::KeyUnwrap,
            algorithm: Some(algorithm.uri().into()),
        })
    }

    /// Decrypt with an opaque key; capability remains distinct from policy permission.
    #[cfg(feature = "xmlenc")]
    fn decrypt_content_key(
        &self,
        algorithm: DataEncryptionAlgorithm,
        _key: &dyn ContentDecryptionKey,
        _ciphertext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        Err(ProviderError::Unsupported {
            operation: ProviderOperation::Decrypt,
            algorithm: Some(algorithm.uri().into()),
        })
    }
    /// Stable provider name for diagnostics and capability reporting.
    fn name(&self) -> &'static str;

    /// Import original PKCS#8 input into this engine without exporting another
    /// provider's private handle. Policy and input budgets are enforced by the caller.
    #[cfg(feature = "xmldsig")]
    fn import_signing_key(
        &self,
        algorithm: crate::xmldsig::SignatureAlgorithm,
        _pkcs8: &[u8],
    ) -> Result<Box<dyn crate::xmldsig::SigningKey>, crate::xmldsig::SigningKeyError> {
        Err(ProviderError::Unsupported {
            operation: ProviderOperation::Sign,
            algorithm: Some(algorithm.uri().into()),
        }
        .into())
    }

    /// Import original PKCS#8 input into a provider-owned RSA recovery handle.
    #[cfg(feature = "xmlenc")]
    fn import_recovery_key(
        &self,
        _pkcs8: &[u8],
    ) -> Result<std::sync::Arc<dyn KeyRecoveryKey>, ProviderError> {
        Err(ProviderError::Unsupported {
            operation: ProviderOperation::KeyRecovery,
            algorithm: None,
        })
    }

    /// Return whether this build can dispatch the requested capability.
    ///
    /// [`ProviderCapability::Sign`] and [`ProviderCapability::Verify`] describe
    /// provider dispatch only: the supplied opaque key performs the executable
    /// algorithm-support check when the operation runs.
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

    /// Sign with explicit domain separation; unsupported contexts must not be discarded.
    #[cfg(feature = "xmldsig")]
    fn sign_with_context(
        &self,
        key: &dyn crate::xmldsig::SigningKey,
        algorithm: crate::xmldsig::SignatureAlgorithm,
        context: &crate::xmldsig::SignatureContext,
        data: &[u8],
    ) -> Result<Vec<u8>, crate::xmldsig::SigningKeyError> {
        if !context.as_bytes().is_empty() {
            return Err(crate::xmldsig::SigningKeyError::UnsupportedAlgorithm {
                uri: algorithm.uri().to_owned(),
            });
        }
        self.sign(key, algorithm, data)
    }

    /// Verify with explicit domain separation; unsupported contexts fail closed.
    #[cfg(feature = "xmldsig")]
    fn verify_with_context(
        &self,
        key: &dyn crate::xmldsig::VerifyingKey,
        algorithm: crate::xmldsig::SignatureAlgorithm,
        context: &crate::xmldsig::SignatureContext,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, crate::xmldsig::DsigError> {
        if !context.as_bytes().is_empty() {
            return Err(
                crate::xmldsig::SignatureVerificationError::UnsupportedAlgorithm {
                    uri: algorithm.uri().to_owned(),
                }
                .into(),
            );
        }
        self.verify(key, algorithm, data, signature)
    }

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
            algorithm: algorithm.oid().map(str::to_owned),
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

    /// Transport using RSAES-PKCS1-v1_5; not an OAEP configuration.
    #[cfg(all(feature = "xmlenc", feature = "legacy-algorithms"))]
    fn transport_pkcs1v15(
        &self,
        _key: &dyn KeyTransportKey,
        _plaintext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        Err(ProviderError::Unsupported {
            operation: ProviderOperation::KeyTransport,
            algorithm: Some(
                crate::xmlenc::KeyTransportAlgorithm::RsaPkcs1v15
                    .uri()
                    .into(),
            ),
        })
    }

    /// Recover a fixed-width content key without exposing padding validity.
    #[cfg(all(feature = "xmlenc", feature = "legacy-algorithms"))]
    fn recover_pkcs1v15(
        &self,
        _key: &dyn KeyRecoveryKey,
        _ciphertext: &[u8],
        _key_len: usize,
    ) -> Result<RecoveredContentKey, ProviderError> {
        Err(ProviderError::Unsupported {
            operation: ProviderOperation::KeyRecovery,
            algorithm: Some(
                crate::xmlenc::KeyTransportAlgorithm::RsaPkcs1v15
                    .uri()
                    .into(),
            ),
        })
    }

    /// Perform key agreement with an opaque provider-owned private key.
    fn agree_key(
        &self,
        key: &dyn KeyAgreementKey,
        parameters: &KeyAgreementParameters<'_>,
    ) -> Result<Vec<u8>, ProviderError> {
        self.require_capability(ProviderCapability::KeyAgreement(parameters))?;
        if let Some(binding) = key.provider_binding()
            && !self
                .binding()
                .is_some_and(|selected| selected.matches(binding))
        {
            return Err(ProviderError::External(ExternalProviderError::Binding));
        }
        key.agree(parameters)
    }

    /// Derive key bytes from caller-owned secret material.
    ///
    /// Implementations that advertise [`ProviderCapability::Kdf`] must perform
    /// the advertised derivation here. This method is required so capability
    /// discovery cannot silently inherit a contradictory unsupported default.
    fn derive_key(
        &self,
        parameters: &KdfParameters<'_>,
        secret: &[u8],
    ) -> Result<Vec<u8>, ProviderError>;

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
    #[cfg(feature = "legacy-algorithms")]
    fn transport_pkcs1v15(
        &self,
        provider: &dyn CryptoProvider,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        rustcrypto::transport_pkcs1v15(provider, &self.key, plaintext)
    }
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
    #[cfg(feature = "legacy-algorithms")]
    fn transport_pkcs1v15(
        &self,
        provider: &dyn CryptoProvider,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        rustcrypto::transport_pkcs1v15(provider, self, plaintext)
    }
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
    #[cfg(feature = "legacy-algorithms")]
    fn recover_pkcs1v15(
        &self,
        provider: &dyn CryptoProvider,
        ciphertext: &[u8],
        key_len: usize,
    ) -> Result<RecoveredContentKey, ProviderError> {
        rsa_pkcs1v15::recover(provider, &self.key, ciphertext, key_len)
    }
    fn rsa_modulus_bits(&self) -> usize {
        KeyRecoveryKey::rsa_modulus_bits(&self.key)
    }
    fn rsa_public_exponent(&self) -> Option<u64> {
        KeyRecoveryKey::rsa_public_exponent(&self.key)
    }
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
    #[cfg(feature = "legacy-algorithms")]
    fn recover_pkcs1v15(
        &self,
        provider: &dyn CryptoProvider,
        ciphertext: &[u8],
        key_len: usize,
    ) -> Result<RecoveredContentKey, ProviderError> {
        rsa_pkcs1v15::recover(provider, self, ciphertext, key_len)
    }
    fn rsa_modulus_bits(&self) -> usize {
        use rsa::traits::PublicKeyParts as _;
        self.n().bits_vartime() as usize
    }
    fn rsa_public_exponent(&self) -> Option<u64> {
        use rsa::traits::PublicKeyParts as _;
        if self.e().bits_vartime() > 64 {
            return None;
        }
        let mut exponent = 0_u64;
        let word_bits = crypto_bigint::Word::BITS as usize;
        for (index, word) in self.e().as_words().iter().take(64 / word_bits).enumerate() {
            #[cfg(target_pointer_width = "64")]
            let word = *word;
            #[cfg(target_pointer_width = "32")]
            let word = u64::from(*word);
            exponent |= word << (index * word_bits);
        }
        Some(exponent)
    }
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
    #[cfg(all(feature = "xmlenc", feature = "legacy-algorithms"))]
    fn transport_pkcs1v15(
        &self,
        key: &dyn KeyTransportKey,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        self.require_capability(ProviderCapability::Pkcs1v15Transport)?;
        key.transport_pkcs1v15(self, plaintext)
    }

    #[cfg(all(feature = "xmlenc", feature = "legacy-algorithms"))]
    fn recover_pkcs1v15(
        &self,
        key: &dyn KeyRecoveryKey,
        ciphertext: &[u8],
        key_len: usize,
    ) -> Result<RecoveredContentKey, ProviderError> {
        self.require_capability(ProviderCapability::Pkcs1v15Recovery)?;
        key.recover_pkcs1v15(self, ciphertext, key_len)
    }
    fn name(&self) -> &'static str {
        "rustcrypto"
    }

    #[cfg(feature = "xmlenc")]
    fn import_recovery_key(
        &self,
        pkcs8: &[u8],
    ) -> Result<std::sync::Arc<dyn KeyRecoveryKey>, ProviderError> {
        use rsa::pkcs8::DecodePrivateKey as _;
        let key = rsa::RsaPrivateKey::from_pkcs8_der(pkcs8).map_err(|_| {
            ProviderError::InvalidInput(ProviderInputError::PrimitiveInitialization(
                "RSA recovery key",
            ))
        })?;
        Ok(std::sync::Arc::new(RustCryptoRsaPrivateKey::new(key)))
    }

    #[cfg(feature = "xmldsig")]
    fn import_signing_key(
        &self,
        algorithm: crate::xmldsig::SignatureAlgorithm,
        der: &[u8],
    ) -> Result<Box<dyn crate::xmldsig::SigningKey>, crate::xmldsig::SigningKeyError> {
        use crate::xmldsig::{SignatureAlgorithm as A, *};
        Ok(match algorithm {
            #[cfg(feature = "experimental-pq")]
            A::PostQuantum(parameter) => {
                Box::new(PostQuantumSigningKey::from_pkcs8_der(parameter, der)?)
            }
            A::Ed25519 | A::Ed25519Ctx | A::Ed25519Ph | A::Ed448 | A::Ed448Ph => {
                Box::new(EdDsaSigningKey::from_pkcs8_der(algorithm, der)?)
            }
            method if method.is_rsa() => Box::new(RsaSigningKey::from_pkcs8_der(der)?),
            A::DsaSha1 | A::DsaSha256 => Box::new(DsaSigningKey::from_pkcs8_der(der)?),
            method if method.ecdsa_digest().is_some() => {
                if let Ok(key) = EcdsaP256SigningKey::from_pkcs8_der(der) {
                    Box::new(key)
                } else if let Ok(key) = EcdsaP384SigningKey::from_pkcs8_der(der) {
                    Box::new(key)
                } else {
                    Box::new(EcdsaP521SigningKey::from_pkcs8_der(der)?)
                }
            }
            _ => {
                return Err(SigningKeyError::UnsupportedAlgorithm {
                    uri: algorithm.uri().into(),
                });
            }
        })
    }

    fn supports(&self, capability: ProviderCapability<'_>) -> bool {
        match capability {
            #[cfg(feature = "xmldsig")]
            ProviderCapability::Digest(_) => true,
            #[cfg(feature = "xmldsig")]
            // Opaque keys own these primitives and reject unsupported methods
            // during dispatch; the provider advertises its dispatch surface.
            ProviderCapability::Sign(algorithm) | ProviderCapability::Verify(algorithm) => {
                if let Some(parameters) = algorithm.rsa_pss_parameters()
                    && parameters.salt_len > i32::MAX as usize
                {
                    return false;
                }
                !matches!(
                    algorithm,
                    crate::xmldsig::SignatureAlgorithm::PostQuantum(_)
                ) || cfg!(feature = "experimental-pq")
            }
            #[cfg(feature = "xmldsig")]
            ProviderCapability::VerifyCertificate(algorithm) => {
                is_supported_x509_signature(algorithm)
            }
            #[cfg(feature = "xmlenc")]
            ProviderCapability::Encrypt(_) | ProviderCapability::Decrypt(_) => true,
            #[cfg(feature = "xmlenc")]
            ProviderCapability::KeyWrap(_) | ProviderCapability::KeyUnwrap(_) => true,
            #[cfg(feature = "xmlenc")]
            ProviderCapability::KeyTransport(_) | ProviderCapability::KeyRecovery(_) => true,
            #[cfg(all(feature = "xmlenc", feature = "legacy-algorithms"))]
            ProviderCapability::Pkcs1v15Transport | ProviderCapability::Pkcs1v15Recovery => true,
            ProviderCapability::Random => true,
            ProviderCapability::KeyAgreement(_) | ProviderCapability::Kdf(_) => false,
        }
    }

    fn fill_random(&self, output: &mut [u8]) -> Result<(), ProviderError> {
        SysRng
            .try_fill_bytes(output)
            .map_err(|error| ProviderError::Random(error.to_string()))
    }

    fn derive_key(
        &self,
        parameters: &KdfParameters<'_>,
        _secret: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        self.require_capability(ProviderCapability::Kdf(parameters))?;
        Err(ProviderError::Unsupported {
            operation: ProviderOperation::Kdf,
            algorithm: Some(parameters.algorithm.to_owned()),
        })
    }

    #[cfg(feature = "xmldsig")]
    fn digest(&self, algorithm: DigestAlgorithm, data: &[u8]) -> Result<Vec<u8>, ProviderError> {
        use sha1::Sha1;
        use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
        use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
        Ok(match algorithm {
            #[cfg(feature = "legacy-algorithms")]
            DigestAlgorithm::Md5 => md5::Md5::digest(data).to_vec(),
            #[cfg(feature = "legacy-algorithms")]
            DigestAlgorithm::Ripemd160 => ripemd::Ripemd160::digest(data).to_vec(),
            DigestAlgorithm::Sha1 => Sha1::digest(data).to_vec(),
            DigestAlgorithm::Sha224 => Sha224::digest(data).to_vec(),
            DigestAlgorithm::Sha256 => Sha256::digest(data).to_vec(),
            DigestAlgorithm::Sha384 => Sha384::digest(data).to_vec(),
            DigestAlgorithm::Sha512 => Sha512::digest(data).to_vec(),
            DigestAlgorithm::Sha3_224 => Sha3_224::digest(data).to_vec(),
            DigestAlgorithm::Sha3_256 => Sha3_256::digest(data).to_vec(),
            DigestAlgorithm::Sha3_384 => Sha3_384::digest(data).to_vec(),
            DigestAlgorithm::Sha3_512 => Sha3_512::digest(data).to_vec(),
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
    fn sign_with_context(
        &self,
        key: &dyn crate::xmldsig::SigningKey,
        algorithm: crate::xmldsig::SignatureAlgorithm,
        context: &crate::xmldsig::SignatureContext,
        data: &[u8],
    ) -> Result<Vec<u8>, crate::xmldsig::SigningKeyError> {
        self.require_capability(ProviderCapability::Sign(algorithm))?;
        key.sign_with_provider_context(self, algorithm, context, data)
    }

    #[cfg(feature = "xmldsig")]
    fn verify_with_context(
        &self,
        key: &dyn crate::xmldsig::VerifyingKey,
        algorithm: crate::xmldsig::SignatureAlgorithm,
        context: &crate::xmldsig::SignatureContext,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, crate::xmldsig::DsigError> {
        self.require_capability(ProviderCapability::Verify(algorithm))?;
        if key.provider_binding().is_some() {
            return Err(ProviderError::External(ExternalProviderError::Binding).into());
        }
        key.verify_with_context(algorithm, context, data, signature)
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
        if key.provider_binding().is_some() {
            return Err(ProviderError::External(ExternalProviderError::Binding).into());
        }
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
        rustcrypto::wrap_key(self, algorithm, kek, key)
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
        self.require_capability(ProviderCapability::KeyRecovery(parameters))?;
        key.recover_with_provider(self, parameters, ciphertext)
    }
}

#[cfg(feature = "xmldsig")]
fn is_supported_x509_signature(algorithm: X509SignatureAlgorithm) -> bool {
    match algorithm {
        X509SignatureAlgorithm::Dsa(DigestAlgorithm::Sha1)
        | X509SignatureAlgorithm::Ed25519
        | X509SignatureAlgorithm::Ed448 => true,
        X509SignatureAlgorithm::Ecdsa(digest) => rustcrypto_x509::ecdsa_algorithm(digest).is_some(),
        X509SignatureAlgorithm::PostQuantum(_) => cfg!(feature = "experimental-pq"),
        X509SignatureAlgorithm::RsaPkcs1v15(digest) => matches!(
            digest,
            DigestAlgorithm::Sha1
                | DigestAlgorithm::Sha224
                | DigestAlgorithm::Sha256
                | DigestAlgorithm::Sha384
                | DigestAlgorithm::Sha512
        ),
        X509SignatureAlgorithm::RsaPss {
            digest, mgf_digest, ..
        } => {
            matches!(
                digest,
                DigestAlgorithm::Sha256 | DigestAlgorithm::Sha384 | DigestAlgorithm::Sha512
            ) && digest == mgf_digest
        }
        X509SignatureAlgorithm::Dsa(_) => false,
    }
}

#[cfg(feature = "xmldsig")]
pub(crate) mod rustcrypto_x509 {
    use der::Decode as _;
    use dsa::pkcs8::DecodePublicKey as _;
    use rsa::{
        RsaPublicKey,
        pkcs1::DecodeRsaPublicKey as _,
        pss::{Signature as RsaPssSignature, VerifyingKey as RsaPssVerifyingKey},
        traits::PublicKeyParts as _,
    };
    use sha1::Digest as _;
    use sha2::{Sha256, Sha384, Sha512};
    use signature::{Verifier as _, hazmat::PrehashVerifier as _};
    use x509_parser::prelude::FromDer as _;

    use super::{ProviderError, X509SignatureAlgorithm};
    use crate::xmldsig::signature::verify_ecdsa_signature_spki_asn1_der;
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
                let Ok(key) = crate::xmldsig::signature::decode_dsa_verifying_key(issuer_spki_der)
                else {
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
                // RFC 5280 ECDSA certificate signatures are always ASN.1 DER;
                // XMLDSig's SignatureValue framing policy is irrelevant here.
                match verify_ecdsa_signature_spki_asn1_der(
                    algorithm,
                    issuer_spki_der,
                    signed_data,
                    signature,
                ) {
                    Ok(verified) => Ok(verified),
                    Err(_) => Ok(false),
                }
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
            X509SignatureAlgorithm::Ed448 => {
                // RFC 8410 sections 3 and 6 select pure Ed448 without context
                // or external prehash: https://www.rfc-editor.org/rfc/rfc8410.html#section-6
                let Ok(key) = ed448_goldilocks::VerifyingKey::from_public_key_der(issuer_spki_der)
                else {
                    return Ok(false);
                };
                let Ok(signature) = ed448_goldilocks::Signature::try_from(signature) else {
                    return Ok(false);
                };
                Ok(key.verify_raw(&signature, signed_data).is_ok())
            }
            #[cfg(feature = "experimental-pq")]
            X509SignatureAlgorithm::PostQuantum(algorithm) => {
                // RFC 9881 §3 and RFC 9909 §§1, 4 require pure signatures
                // over the DER object with an empty context, not an XML context.
                // https://www.rfc-editor.org/rfc/rfc9881.html#section-3
                // https://www.rfc-editor.org/rfc/rfc9909.html#section-4
                Ok(crate::xmldsig::post_quantum::verify(
                    algorithm,
                    issuer_spki_der,
                    &crate::xmldsig::SignatureContext::default(),
                    signed_data,
                    signature,
                )
                .unwrap_or(false))
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
        if !rsa_pss_salt_fits_key(&key, digest, salt_len) {
            return Ok(false);
        }
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
            _ => {
                return unsupported(X509SignatureAlgorithm::RsaPss {
                    digest,
                    mgf_digest: digest,
                    salt_len,
                });
            }
        };
        Ok(verified.is_ok())
    }

    pub(super) fn rsa_pss_salt_fits_key(
        key: &RsaPublicKey,
        digest: DigestAlgorithm,
        salt_len: usize,
    ) -> bool {
        let Some(em_bits) = key.n().bits().checked_sub(1) else {
            return false;
        };
        let Ok(em_len) = usize::try_from(em_bits.div_ceil(8)) else {
            return false;
        };
        digest
            .output_len()
            .checked_add(salt_len)
            .and_then(|length| length.checked_add(2))
            .is_some_and(|required| required <= em_len)
    }

    pub(crate) fn compatible_rsa_pss_public_key_from_spki(
        spki_der: &[u8],
        signature_algorithm: X509SignatureAlgorithm,
    ) -> Option<RsaPublicKey> {
        let (rest, spki) = x509_parser::x509::SubjectPublicKeyInfo::from_der(spki_der).ok()?;
        if !rest.is_empty() {
            return None;
        }
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

    pub(crate) fn rsa_pss_key_parameters_allow(
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
            "2.16.840.1.101.3.4.2.4" => Some(DigestAlgorithm::Sha224),
            "2.16.840.1.101.3.4.2.1" => Some(DigestAlgorithm::Sha256),
            "2.16.840.1.101.3.4.2.2" => Some(DigestAlgorithm::Sha384),
            "2.16.840.1.101.3.4.2.3" => Some(DigestAlgorithm::Sha512),
            "2.16.840.1.101.3.4.2.7" => Some(DigestAlgorithm::Sha3_224),
            "2.16.840.1.101.3.4.2.8" => Some(DigestAlgorithm::Sha3_256),
            "2.16.840.1.101.3.4.2.9" => Some(DigestAlgorithm::Sha3_384),
            "2.16.840.1.101.3.4.2.10" => Some(DigestAlgorithm::Sha3_512),
            _ => None,
        }
    }

    const fn rsa_pkcs1_algorithm(digest: DigestAlgorithm) -> Option<SignatureAlgorithm> {
        match digest {
            DigestAlgorithm::Sha1 => Some(SignatureAlgorithm::RsaSha1),
            DigestAlgorithm::Sha224 => Some(SignatureAlgorithm::RsaSha224),
            DigestAlgorithm::Sha256 => Some(SignatureAlgorithm::RsaSha256),
            DigestAlgorithm::Sha384 => Some(SignatureAlgorithm::RsaSha384),
            DigestAlgorithm::Sha512 => Some(SignatureAlgorithm::RsaSha512),
            _ => None,
        }
    }

    pub(super) const fn ecdsa_algorithm(digest: DigestAlgorithm) -> Option<SignatureAlgorithm> {
        match digest {
            #[cfg(feature = "legacy-algorithms")]
            DigestAlgorithm::Md5 | DigestAlgorithm::Ripemd160 => None,
            DigestAlgorithm::Sha1 => Some(SignatureAlgorithm::EcdsaSha1),
            DigestAlgorithm::Sha224 => Some(SignatureAlgorithm::EcdsaSha224),
            DigestAlgorithm::Sha256 => Some(SignatureAlgorithm::EcdsaSha256),
            DigestAlgorithm::Sha384 => Some(SignatureAlgorithm::EcdsaSha384),
            DigestAlgorithm::Sha512 => Some(SignatureAlgorithm::EcdsaSha512),
            DigestAlgorithm::Sha3_224 => Some(SignatureAlgorithm::EcdsaSha3_224),
            DigestAlgorithm::Sha3_256 => Some(SignatureAlgorithm::EcdsaSha3_256),
            DigestAlgorithm::Sha3_384 => Some(SignatureAlgorithm::EcdsaSha3_384),
            DigestAlgorithm::Sha3_512 => Some(SignatureAlgorithm::EcdsaSha3_512),
        }
    }

    fn unsupported<T>(algorithm: X509SignatureAlgorithm) -> Result<T, ProviderError> {
        Err(ProviderError::Unsupported {
            operation: super::ProviderOperation::VerifyCertificate,
            algorithm: algorithm.oid().map(str::to_owned),
        })
    }
}

#[cfg(feature = "xmlenc")]
mod rustcrypto {
    #[cfg(feature = "legacy-algorithms")]
    use aes::Aes192;
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
    #[cfg(feature = "legacy-algorithms")]
    use des::TdesEde3;
    use rsa::{Oaep, traits::PaddingScheme};
    use sha1::Sha1;
    use sha2::{Sha256, Sha384, Sha512};

    use super::{CryptoProvider, ProviderError, ProviderInputError};
    use crate::xmlenc::{
        DataEncryptionAlgorithm, KeyWrapAlgorithm, OaepDigestAlgorithm, RsaOaepParameters,
    };

    pub(super) fn encrypt_data(
        provider: &dyn CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        key: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        check_key(algorithm.key_len(), key)?;
        match algorithm {
            #[cfg(feature = "legacy-algorithms")]
            DataEncryptionAlgorithm::TripleDesCbc => {
                encrypt_cbc::<TdesEde3>(provider, key, plaintext)
            }
            #[cfg(feature = "legacy-algorithms")]
            DataEncryptionAlgorithm::Aes192Cbc => encrypt_cbc::<Aes192>(provider, key, plaintext),
            #[cfg(feature = "legacy-algorithms")]
            DataEncryptionAlgorithm::Aes192Gcm => encrypt_gcm::<
                aes_gcm::AesGcm<Aes192, aes_gcm::aead::consts::U12>,
            >(provider, key, plaintext),
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
            #[cfg(feature = "legacy-algorithms")]
            DataEncryptionAlgorithm::TripleDesCbc => decrypt_cbc::<TdesEde3>(key, ciphertext),
            #[cfg(feature = "legacy-algorithms")]
            DataEncryptionAlgorithm::Aes192Cbc => decrypt_cbc::<Aes192>(key, ciphertext),
            #[cfg(feature = "legacy-algorithms")]
            DataEncryptionAlgorithm::Aes192Gcm => {
                decrypt_gcm::<aes_gcm::AesGcm<Aes192, aes_gcm::aead::consts::U12>>(key, ciphertext)
            }
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
        let block = C::block_size();
        let pad_len = block - (plaintext.len() % block);
        let length = plaintext
            .len()
            .checked_add(pad_len)
            .and_then(|len| len.checked_add(block))
            .ok_or(ProviderError::InvalidInput(
                ProviderInputError::AesCbcFraming,
            ))?;
        let mut output = zeroize::Zeroizing::new(vec![0_u8; length]);
        let (iv, padded) = output.split_at_mut(block);
        provider.fill_random(iv)?;
        padded[..plaintext.len()].copy_from_slice(plaintext);
        if pad_len > 1 {
            let last = padded.len() - 1;
            provider.fill_random(&mut padded[plaintext.len()..last])?;
        }
        *padded.last_mut().expect("padding is non-empty") = pad_len as u8;
        Encryptor::<C>::new_from_slices(key, iv)
            .map_err(|_| {
                ProviderError::InvalidInput(ProviderInputError::PrimitiveInitialization("AES-CBC"))
            })?
            .encrypt_padded::<NoPadding>(padded, plaintext.len() + pad_len)
            .map_err(|_| {
                ProviderError::InvalidInput(ProviderInputError::PrimitiveInitialization(
                    "AES-CBC padding",
                ))
            })?;
        Ok(core::mem::take(&mut *output))
    }

    fn decrypt_cbc<C>(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, ProviderError>
    where
        C: aes::cipher::BlockCipherDecrypt + aes::cipher::KeyInit,
    {
        let block = C::block_size();
        if ciphertext.len() < 2 * block || !(ciphertext.len() - block).is_multiple_of(block) {
            return Err(ProviderError::InvalidInput(
                ProviderInputError::AesCbcFraming,
            ));
        }
        let (iv, body) = ciphertext.split_at(block);
        let mut plaintext = zeroize::Zeroizing::new(body.to_vec());
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
        if !(1..=block).contains(&padding_bytes) || padding_bytes > plaintext.len() {
            return Err(ProviderError::InvalidInput(
                ProviderInputError::AesCbcCiphertext,
            ));
        }
        let length = plaintext.len() - padding_bytes;
        plaintext.truncate(length);
        Ok(core::mem::take(&mut *plaintext))
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
        let length = plaintext
            .len()
            .checked_add(28)
            .ok_or(ProviderError::InvalidInput(
                ProviderInputError::PrimitiveInitialization("AES-GCM length"),
            ))?;
        // Encrypt directly in the final nonce-prefixed allocation rather than
        // copying an intermediate ciphertext into another document-sized Vec.
        let mut output = zeroize::Zeroizing::new(Vec::with_capacity(length));
        output.extend_from_slice(&nonce);
        output.extend_from_slice(plaintext);
        let nonce = Nonce::try_from(nonce.as_slice()).map_err(|_| {
            ProviderError::InvalidInput(ProviderInputError::PrimitiveInitialization(
                "AES-GCM nonce",
            ))
        })?;
        let tag = cipher
            .encrypt_inout_detached(&nonce, &[], output[12..].as_mut().into())
            .map_err(|_| ProviderError::AuthenticationFailed)?;
        output.extend_from_slice(&tag);
        Ok(core::mem::take(&mut *output))
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
        let mut plaintext = zeroize::Zeroizing::new(body.to_vec());
        let nonce = Nonce::try_from(nonce).map_err(|_| {
            ProviderError::InvalidInput(ProviderInputError::PrimitiveInitialization(
                "AES-GCM nonce",
            ))
        })?;
        cipher
            .decrypt_in_place(&nonce, &[], &mut *plaintext)
            .map_err(|_| ProviderError::AuthenticationFailed)?;
        Ok(core::mem::take(&mut *plaintext))
    }

    pub(super) fn wrap_key(
        provider: &dyn CryptoProvider,
        algorithm: KeyWrapAlgorithm,
        kek: &[u8],
        key: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        check_key(algorithm.key_len(), kek)?;
        #[cfg(feature = "legacy-algorithms")]
        if algorithm == KeyWrapAlgorithm::TripleDes {
            return wrap_des3(provider, kek, key);
        }
        #[cfg(not(feature = "legacy-algorithms"))]
        let _ = provider;
        // RFC 3394 §2.2.1 requires at least two 64-bit plaintext blocks.
        // Reject before allocating: the primitive also accepts the one-block
        // degenerate case, which is not this XML Encryption algorithm.
        // https://www.rfc-editor.org/rfc/rfc3394.html#section-2.2.1
        if key.len() < 16 || !key.len().is_multiple_of(8) {
            return Err(ProviderError::InvalidInput(
                ProviderInputError::AesKeyWrapFraming,
            ));
        }
        let length =
            key.len()
                .checked_add(algorithm.overhead())
                .ok_or(ProviderError::InvalidInput(
                    ProviderInputError::AesKeyWrapFraming,
                ))?;
        let mut output = vec![0_u8; length];
        match algorithm {
            #[cfg(feature = "legacy-algorithms")]
            KeyWrapAlgorithm::AesKw192 => aes_kw::KwAes192::new_from_slice(kek)
                .map_err(|_| ProviderError::InvalidKeySize {
                    expected: 24,
                    actual: kek.len(),
                })?
                .wrap_key(key, &mut output),
            #[cfg(feature = "legacy-algorithms")]
            KeyWrapAlgorithm::TripleDes => unreachable!("CMS wrapping dispatched before AES"),
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
        #[cfg(feature = "legacy-algorithms")]
        if algorithm == KeyWrapAlgorithm::TripleDes {
            return unwrap_des3(kek, wrapped);
        }
        if wrapped.len() < 24 || !wrapped.len().is_multiple_of(8) {
            return Err(ProviderError::InvalidInput(
                ProviderInputError::AesKeyWrapFraming,
            ));
        }
        let mut output = zeroize::Zeroizing::new(vec![0_u8; wrapped.len() - 8]);
        match algorithm {
            #[cfg(feature = "legacy-algorithms")]
            KeyWrapAlgorithm::AesKw192 => aes_kw::KwAes192::new_from_slice(kek)
                .map_err(|_| ProviderError::InvalidKeySize {
                    expected: 24,
                    actual: kek.len(),
                })?
                .unwrap_key(wrapped, &mut output),
            #[cfg(feature = "legacy-algorithms")]
            KeyWrapAlgorithm::TripleDes => unreachable!("CMS unwrapping dispatched before AES"),
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
        Ok(core::mem::take(&mut *output))
    }

    #[cfg(feature = "legacy-algorithms")]
    const CMS_IV: [u8; 8] = [0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05];

    #[cfg(feature = "legacy-algorithms")]
    fn wrap_des3(
        provider: &dyn CryptoProvider,
        kek: &[u8],
        key: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        use sha1::Digest as _;
        // XMLEnc 1.1 §5.7.1 permits other key types in addition to RFC 3217's
        // DES CEK. Preserve opaque key octets (especially AES); generated DES
        // content keys are normalized to odd parity at their generation boundary.
        // https://www.w3.org/TR/xmlenc-core1/#sec-CMS-3DES
        if key.len() < 16 || !key.len().is_multiple_of(8) {
            return Err(ProviderError::InvalidInput(
                ProviderInputError::AesKeyWrapFraming,
            ));
        }
        let length = key
            .len()
            .checked_add(16)
            .ok_or(ProviderError::InvalidInput(
                ProviderInputError::AesKeyWrapFraming,
            ))?;
        let mut output = zeroize::Zeroizing::new(vec![0; length]);
        provider.fill_random(&mut output[..8])?;
        output[8..8 + key.len()].copy_from_slice(key);
        output[8 + key.len()..].copy_from_slice(&Sha1::digest(key)[..8]);
        let (iv, body) = output.split_at_mut(8);
        let body_len = body.len();
        Encryptor::<TdesEde3>::new_from_slices(kek, iv)
            .map_err(|_| ProviderError::AuthenticationFailed)?
            .encrypt_padded::<NoPadding>(body, body_len)
            .map_err(|_| ProviderError::AuthenticationFailed)?;
        output.reverse();
        Encryptor::<TdesEde3>::new_from_slices(kek, &CMS_IV)
            .map_err(|_| ProviderError::AuthenticationFailed)?
            .encrypt_padded::<NoPadding>(&mut output, length)
            .map_err(|_| ProviderError::AuthenticationFailed)?;
        Ok(core::mem::take(&mut *output))
    }

    #[cfg(feature = "legacy-algorithms")]
    fn unwrap_des3(kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, ProviderError> {
        use sha1::Digest as _;
        use subtle::ConstantTimeEq as _;
        // RFC 3217 §3.2: undo the outer CBC, octet reversal and inner CBC,
        // then authenticate the checksum before exposing any recovered bytes.
        // https://www.rfc-editor.org/rfc/rfc3217#section-3.2
        if wrapped.len() < 32 || !wrapped.len().is_multiple_of(8) {
            return Err(ProviderError::InvalidInput(
                ProviderInputError::AesKeyWrapFraming,
            ));
        }
        let mut output = zeroize::Zeroizing::new(wrapped.to_vec());
        Decryptor::<TdesEde3>::new_from_slices(kek, &CMS_IV)
            .map_err(|_| ProviderError::AuthenticationFailed)?
            .decrypt_padded::<NoPadding>(&mut output)
            .map_err(|_| ProviderError::AuthenticationFailed)?;
        output.reverse();
        let (iv, body) = output.split_at_mut(8);
        Decryptor::<TdesEde3>::new_from_slices(kek, iv)
            .map_err(|_| ProviderError::AuthenticationFailed)?
            .decrypt_padded::<NoPadding>(body)
            .map_err(|_| ProviderError::AuthenticationFailed)?;
        let key_len = body.len() - 8;
        if !bool::from(Sha1::digest(&body[..key_len])[..8].ct_eq(&body[key_len..])) {
            return Err(ProviderError::AuthenticationFailed);
        }
        output.copy_within(8..8 + key_len, 0);
        zeroize::Zeroize::zeroize(&mut output[key_len..]);
        output.truncate(key_len);
        Ok(core::mem::take(&mut *output))
    }

    #[cfg(feature = "legacy-algorithms")]
    pub(super) fn transport_pkcs1v15(
        provider: &dyn CryptoProvider,
        key: &rsa::RsaPublicKey,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        rsa::Pkcs1v15Encrypt
            .encrypt(&mut super::ProviderRng(provider), key, plaintext)
            .map_err(map_rsa_error)
    }

    pub(super) fn transport_key(
        provider: &dyn CryptoProvider,
        key: &rsa::RsaPublicKey,
        parameters: &RsaOaepParameters,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        if parameters.algorithm.requires_explicit_permission() {
            return Err(ProviderError::InvalidInput(
                ProviderInputError::PrimitiveInitialization("RSA-OAEP algorithm"),
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
        if parameters.algorithm.requires_explicit_permission() {
            return Err(ProviderError::InvalidInput(
                ProviderInputError::PrimitiveInitialization("RSA-OAEP algorithm"),
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

    pub(super) fn map_rsa_error(error: rsa::Error) -> ProviderError {
        match error {
            rsa::Error::Rng => ProviderError::Random("RSA randomness failed".into()),
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

    #[cfg(all(feature = "legacy-algorithms", feature = "xmlenc"))]
    #[test]
    fn legacy_ciphers_cover_empty_and_block_boundary_plaintexts() {
        // Each cipher's own framing, including DES's 8-byte blocks, must agree
        // with the public size preflight for empty and non-aligned messages.
        for algorithm in [
            DataEncryptionAlgorithm::TripleDesCbc,
            DataEncryptionAlgorithm::Aes192Cbc,
            DataEncryptionAlgorithm::Aes192Gcm,
        ] {
            let key = [0x31; 24];
            for length in [0, 1, 7, 8, 15, 16, 17, 31, 32, 33] {
                let plaintext = vec![0x41; length];
                let ciphertext = RUST_CRYPTO_PROVIDER
                    .encrypt_data(algorithm, &key, &plaintext)
                    .expect("valid legacy encryption must succeed");
                assert_eq!(
                    Some(ciphertext.len()),
                    algorithm.ciphertext_len_for_plaintext(length)
                );
                assert_eq!(
                    RUST_CRYPTO_PROVIDER
                        .decrypt_data(algorithm, &key, &ciphertext)
                        .expect("matching legacy key must recover plaintext"),
                    plaintext
                );
                assert!(
                    RUST_CRYPTO_PROVIDER
                        .encrypt_data(algorithm, &key[..23], &plaintext)
                        .is_err()
                );
                assert!(
                    RUST_CRYPTO_PROVIDER
                        .decrypt_data(algorithm, &key[..23], &ciphertext)
                        .is_err()
                );
                assert!(
                    RUST_CRYPTO_PROVIDER
                        .decrypt_data(algorithm, &key, &ciphertext[..ciphertext.len() - 1])
                        .is_err()
                );
                if algorithm == DataEncryptionAlgorithm::Aes192Gcm {
                    let mut corrupted = ciphertext;
                    corrupted[12] ^= 1;
                    assert!(matches!(
                        RUST_CRYPTO_PROVIDER.decrypt_data(algorithm, &key, &corrupted),
                        Err(ProviderError::AuthenticationFailed)
                    ));
                }
            }
        }
    }

    #[cfg(all(feature = "legacy-algorithms", feature = "xmlenc"))]
    #[test]
    fn cms_triple_des_unwrap_matches_rfc3217_vector() {
        // RFC 3217 §3.4 independently validates both CBC passes and reversal;
        // a round-trip alone could hide matching errors in wrap and unwrap.
        // https://www.rfc-editor.org/rfc/rfc3217.html#section-3.4
        let kek = hex_literal::hex!("255e0d1c07b646dfb3134cc843ba8aa71f025b7c0838251f");
        let key = hex_literal::hex!("2923bf85e06dd6ae529149f1f1bae9eab3a7da3d860d3e98");
        let wrapped = hex_literal::hex!(
            "690107618ef092b3b48ca1796b234ae9fa33ebb4159604037db5d6a84eb3aac2768c632775a467d4"
        );
        assert_eq!(
            RUST_CRYPTO_PROVIDER
                .unwrap_key(KeyWrapAlgorithm::TripleDes, &kek, &wrapped)
                .expect("RFC 3217 vector must authenticate"),
            key
        );
        for offset in 0..wrapped.len() {
            let mut corrupted = wrapped;
            corrupted[offset] ^= 1;
            assert!(matches!(
                RUST_CRYPTO_PROVIDER.unwrap_key(KeyWrapAlgorithm::TripleDes, &kek, &corrupted),
                Err(ProviderError::AuthenticationFailed)
            ));
        }
    }

    #[cfg(all(feature = "legacy-algorithms", feature = "xmlenc"))]
    #[test]
    fn legacy_wrap_preserves_opaque_key_bytes_and_checks_integrity() {
        // XMLEnc permits wrapping non-DES keys; parity normalization must not
        // corrupt opaque AES key octets. Each algorithm has its own overhead.
        for algorithm in [KeyWrapAlgorithm::AesKw192, KeyWrapAlgorithm::TripleDes] {
            let kek = [0x37; 24];
            for length in [16, 24, 32] {
                let key: Vec<_> = (0..length).map(|byte| byte as u8).collect();
                let mut wrapped = RUST_CRYPTO_PROVIDER
                    .wrap_key(algorithm, &kek, &key)
                    .expect("valid content key must wrap");
                assert_eq!(wrapped.len(), key.len() + algorithm.overhead());
                assert_eq!(
                    RUST_CRYPTO_PROVIDER
                        .unwrap_key(algorithm, &kek, &wrapped)
                        .expect("matching KEK must recover exact key octets"),
                    key
                );
                assert!(
                    RUST_CRYPTO_PROVIDER
                        .unwrap_key(algorithm, &[0x38; 24], &wrapped)
                        .is_err()
                );
                wrapped[0] ^= 1;
                assert!(
                    RUST_CRYPTO_PROVIDER
                        .unwrap_key(algorithm, &kek, &wrapped)
                        .is_err()
                );
            }
            for length in [0, 1, 8, 15, 17] {
                assert!(
                    RUST_CRYPTO_PROVIDER
                        .wrap_key(algorithm, &kek, &vec![0; length])
                        .is_err()
                );
            }
        }
    }

    #[cfg(all(feature = "legacy-algorithms", feature = "xmldsig"))]
    #[test]
    fn legacy_digests_match_known_answers() {
        // Published empty/abc answers prevent URI wiring from silently choosing
        // a different hash with the same output width.
        for (algorithm, expected) in [
            (
                DigestAlgorithm::Md5,
                &hex_literal::hex!("900150983cd24fb0d6963f7d28e17f72")[..],
            ),
            (
                DigestAlgorithm::Ripemd160,
                &hex_literal::hex!("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")[..],
            ),
        ] {
            assert_eq!(
                RUST_CRYPTO_PROVIDER
                    .digest(algorithm, b"abc")
                    .expect("compiled digest must be supported"),
                expected
            );
            assert_eq!(DigestAlgorithm::from_uri(algorithm.uri()), Some(algorithm));
            assert!(algorithm.requires_explicit_permission());
            assert!(!algorithm.signing_allowed());
        }
    }

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

        fn derive_key(
            &self,
            parameters: &KdfParameters<'_>,
            secret: &[u8],
        ) -> Result<Vec<u8>, ProviderError> {
            RUST_CRYPTO_PROVIDER.derive_key(parameters, secret)
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
        assert!(RUST_CRYPTO_PROVIDER.supports(ProviderCapability::Sign(
            crate::xmldsig::SignatureAlgorithm::RsaSha1
        )));
        assert!(RUST_CRYPTO_PROVIDER.supports(ProviderCapability::Verify(
            crate::xmldsig::SignatureAlgorithm::RsaSha1
        )));
        for digest in [DigestAlgorithm::Sha1, DigestAlgorithm::Sha512] {
            assert!(
                RUST_CRYPTO_PROVIDER.supports(ProviderCapability::VerifyCertificate(
                    X509SignatureAlgorithm::Ecdsa(digest)
                ))
            );
        }
        // Certificate capabilities must agree with the actual execution
        // mapping, not merely with the presence of an ECDSA primitive.
        #[cfg(feature = "legacy-algorithms")]
        for digest in [DigestAlgorithm::Md5, DigestAlgorithm::Ripemd160] {
            assert!(
                !RUST_CRYPTO_PROVIDER.supports(ProviderCapability::VerifyCertificate(
                    X509SignatureAlgorithm::Ecdsa(digest)
                ))
            );
        }
    }

    #[cfg(feature = "xmldsig")]
    #[test]
    fn x509_digest_key_info_uses_the_selected_provider() {
        use crate::xmldsig::{
            DigestAlgorithm, KeyInfoWriteError, KeyInfoWriter, RsaSigningKey,
            X509DigestKeyInfoWriter,
        };

        // KeyInfo generation is part of the signing operation's provider
        // boundary; a writer must not silently fall back to RustCrypto.
        let key = RsaSigningKey::from_pkcs8_pem(include_str!(
            "../tests/fixtures/keys/rsa/rsa-2048-key.pem"
        ))
        .expect("RSA fixture must parse");
        let writer = X509DigestKeyInfoWriter::from_pem(
            include_str!("../tests/fixtures/keys/rsa/rsa-2048-cert.pem"),
            DigestAlgorithm::Sha224,
        )
        .expect("certificate fixture must parse");
        let provider = CountingRandomProvider {
            random_calls: AtomicUsize::new(0),
            reject_digest: Some(DigestAlgorithm::Sha224),
            extra_digest_byte: false,
            accept_signatures: false,
        };

        let error = writer
            .write_key_info_with_provider(&key, &provider)
            .expect_err("the selected provider must control X509Digest");
        assert!(matches!(
            error,
            KeyInfoWriteError::Provider(ProviderError::Unsupported {
                operation: ProviderOperation::Digest,
                ..
            })
        ));
    }

    #[cfg(feature = "xmldsig")]
    #[test]
    fn x509_digest_writer_rejects_trailing_certificate_der() {
        use crate::xmldsig::{DigestAlgorithm, KeyInfoWriteError, X509DigestKeyInfoWriter};

        // The writer retains both digest bytes and the validated signing-key
        // identity, so construction must accept exactly one DER certificate.
        let (_, certificate) = x509_parser::pem::parse_x509_pem(include_bytes!(
            "../tests/fixtures/keys/rsa/rsa-2048-cert.pem"
        ))
        .expect("certificate fixture must parse");
        let mut certificate_der = certificate.contents;
        certificate_der.push(0);

        assert!(matches!(
            X509DigestKeyInfoWriter::from_der(&certificate_der, DigestAlgorithm::Sha256),
            Err(KeyInfoWriteError::InvalidCertificateDer)
        ));
    }

    #[cfg(all(feature = "xmldsig", feature = "xmlenc"))]
    #[test]
    fn capability_queries_include_oaep_and_pss_parameters() {
        use crate::xmlenc::{KeyTransportAlgorithm, OaepDigestAlgorithm};

        let explicit_legacy = RsaOaepParameters {
            algorithm: KeyTransportAlgorithm::RsaOaepMgf1p,
            digest: OaepDigestAlgorithm::Sha256,
            mgf_digest: OaepDigestAlgorithm::Sha256,
            label: Vec::new(),
        };
        assert!(RUST_CRYPTO_PROVIDER.supports(ProviderCapability::KeyTransport(&explicit_legacy)));
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
        policy.key_trust.mode = crate::policy::VerificationTrustMode::CryptographicOnly;
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

    #[cfg(feature = "xmldsig")]
    #[test]
    fn oversized_rsa_pss_salt_is_a_verification_miss() {
        use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
        use rsa::{RsaPrivateKey, pkcs8::EncodePublicKey as _, traits::PublicKeyParts as _};

        // ASN.1 saltLength is attacker-controlled. It must not reach the
        // dependency's unchecked hLen + saltLen + 2 arithmetic.
        let mut rng = ChaCha20Rng::from_seed([0x55; 32]);
        let public_key = RsaPrivateKey::new(&mut rng, 1024)
            .expect("deterministic RSA key generation")
            .to_public_key();
        let spki = public_key
            .to_public_key_der()
            .expect("RSA public key must encode as SPKI");

        assert!(rustcrypto_x509::rsa_pss_salt_fits_key(
            &public_key,
            DigestAlgorithm::Sha256,
            0,
        ));
        assert!(rustcrypto_x509::rsa_pss_salt_fits_key(
            &public_key,
            DigestAlgorithm::Sha256,
            94,
        ));
        assert!(!rustcrypto_x509::rsa_pss_salt_fits_key(
            &public_key,
            DigestAlgorithm::Sha256,
            95,
        ));

        assert!(
            !RUST_CRYPTO_PROVIDER
                .verify_x509_signature(
                    X509SignatureAlgorithm::RsaPss {
                        digest: DigestAlgorithm::Sha256,
                        mgf_digest: DigestAlgorithm::Sha256,
                        salt_len: usize::MAX,
                    },
                    b"certificate tbs bytes",
                    &vec![0_u8; public_key.size()],
                    spki.as_bytes(),
                )
                .expect("oversized PSS salt must fail without panicking")
        );
    }
}
