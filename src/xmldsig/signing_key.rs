//! Signing-key contract shared by `CryptoProvider` and the signing pipeline.
//!
//! The provider trait names these types in every `XMLDSig` build, so they exist
//! without `xmldsig-sign`; key types and the signing pipeline need that feature.

use alloc::{borrow::ToOwned, string::String, vec::Vec};

use super::parse::SignatureAlgorithm;

/// Errors while parsing or using `XMLDSig` signing keys.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SigningKeyError {
    /// The selected provider cannot execute the requested operation.
    #[error("cryptographic provider error: {0}")]
    Provider(#[from] crate::provider::ProviderError),

    /// PEM input could not be parsed.
    #[error("invalid PEM private key")]
    InvalidKeyPem,

    /// PEM block was not an unencrypted PKCS#8 private key.
    #[error("invalid key format: expected PRIVATE KEY PEM, got {label}")]
    InvalidKeyFormat {
        /// Actual PEM label.
        label: String,
    },

    /// DER bytes could not be decoded for the requested key type.
    #[error("invalid PKCS#8 private key DER")]
    InvalidKeyDer,

    /// The signing key cannot produce the requested `XMLDSig` algorithm.
    #[error("signing key does not support algorithm: {uri}")]
    UnsupportedAlgorithm {
        /// `XMLDSig` signature algorithm URI.
        uri: String,
    },

    /// The private-key signing operation failed.
    #[error("private-key signing operation failed")]
    SigningFailed,

    /// Public-key encoding failed for a supported signing key.
    #[error("failed to encode signing public key as SPKI DER")]
    PublicKeyEncodingFailed,

    /// Public-key metadata cannot determine the `XMLDSig` signature framing.
    #[error("invalid signing public-key metadata")]
    InvalidPublicKeyInfo,
}

/// Public key material corresponding to a private `XMLDSig` signing key.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SigningPublicKeyInfo {
    /// RSA public key with DER `SubjectPublicKeyInfo` and normalized parameters.
    Rsa {
        /// DER-encoded `SubjectPublicKeyInfo` bytes.
        spki_der: Vec<u8>,
        /// Unsigned big-endian RSA modulus (`n`), normalized without leading zeroes.
        modulus: Vec<u8>,
        /// Unsigned big-endian RSA public exponent (`e`), normalized without leading zeroes.
        exponent: Vec<u8>,
    },
    /// EC public key with DER `SubjectPublicKeyInfo` and `XMLDSig` 1.1 `KeyValue` data.
    Ec {
        /// DER-encoded `SubjectPublicKeyInfo` bytes.
        spki_der: Vec<u8>,
        /// Bare named-curve OID, without the `XMLDSig` `urn:oid:` prefix.
        curve_oid: &'static str,
        /// Uncompressed SEC1 point (`0x04 || x || y`).
        public_key: Vec<u8>,
    },
    /// DSA public key and signature component width.
    Dsa {
        /// DER-encoded `SubjectPublicKeyInfo` bytes.
        spki_der: Vec<u8>,
        /// Prime modulus P, normalized as unsigned big-endian bytes.
        p: Vec<u8>,
        /// Prime divisor Q, normalized as unsigned big-endian bytes.
        q: Vec<u8>,
        /// Generator G, normalized as unsigned big-endian bytes.
        g: Vec<u8>,
        /// Public value Y, normalized as unsigned big-endian bytes.
        y: Vec<u8>,
        /// Prime modulus width used for signing policy.
        modulus_bits: usize,
        /// Fixed `XMLDSig` width of each `r` and `s` component.
        component_len: usize,
    },
    /// Symmetric HMAC key metadata without exposing secret bytes.
    Hmac {
        /// Secret length used for signing policy.
        key_bits: usize,
    },
    /// `EdDSA` key metadata; the algorithm fixes its wire format and width.
    EdDsa {
        /// Pure `EdDSA` method supported by this key.
        algorithm: SignatureAlgorithm,
        /// DER `SubjectPublicKeyInfo` with absent RFC 8410 parameters.
        spki_der: Vec<u8>,
    },
    /// Experimental PQ key metadata; permission is independent of this capability.
    PostQuantum {
        /// Exact FIPS parameter set.
        algorithm: super::PqAlgorithm,
        /// DER `SubjectPublicKeyInfo` with absent parameters.
        spki_der: Vec<u8>,
    },
}

impl SigningPublicKeyInfo {
    /// Return DER-encoded `SubjectPublicKeyInfo` bytes for this public key.
    #[must_use]
    pub fn spki_der(&self) -> Option<&[u8]> {
        match self {
            Self::Rsa { spki_der, .. }
            | Self::Ec { spki_der, .. }
            | Self::Dsa { spki_der, .. }
            | Self::EdDsa { spki_der, .. }
            | Self::PostQuantum { spki_der, .. } => Some(spki_der),
            Self::Hmac { .. } => None,
        }
    }
}

/// Private key abstraction used by the signing pipeline and `CryptoProvider`.
pub trait SigningKey {
    /// Native engine binding, if this handle must not run under another provider.
    fn provider_name(&self) -> Option<&'static str> {
        None
    }
    /// Primitive hook preserving validated `SignatureMethod` context.
    ///
    /// # Errors
    /// Returns an unsupported domain-separation context or the selected
    /// provider-aware primitive's signing failure.
    fn sign_with_provider_context(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        algorithm: SignatureAlgorithm,
        context: &super::SignatureContext,
        data: &[u8],
    ) -> Result<Vec<u8>, SigningKeyError> {
        if !context.as_bytes().is_empty() {
            return Err(SigningKeyError::UnsupportedAlgorithm {
                uri: algorithm.uri().to_owned(),
            });
        }
        self.sign_with_provider(provider, algorithm, data)
    }
    /// Sign canonicalized `<SignedInfo>` bytes for the declared `XMLDSig` method.
    ///
    /// # Errors
    /// Returns an unsupported method/key pairing, invalid key metadata,
    /// randomness failure or a primitive/provider signing failure.
    fn sign(
        &self,
        algorithm: SignatureAlgorithm,
        canonical_signed_info: &[u8],
    ) -> Result<Vec<u8>, SigningKeyError>;

    /// Sign while sourcing any primitive randomness from the selected provider.
    ///
    /// Deterministic or externally managed keys can rely on this default. Keys
    /// whose primitive uses randomness, including RSA blinding, must override it.
    ///
    /// # Errors
    /// Propagates signing failures, including unsupported methods and failures
    /// obtaining the selected provider's digest or randomness.
    fn sign_with_provider(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        algorithm: SignatureAlgorithm,
        canonical_signed_info: &[u8],
    ) -> Result<Vec<u8>, SigningKeyError> {
        let _ = provider;
        self.sign(algorithm, canonical_signed_info)
    }

    /// Return structured public key material corresponding to this signing key.
    ///
    /// # Errors
    /// Returns invalid or unavailable public-key metadata or its encoding failure.
    fn public_key_info(&self) -> Result<SigningPublicKeyInfo, SigningKeyError>;
}
