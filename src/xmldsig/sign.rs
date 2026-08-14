//! Signing-side XMLDSig digest computation.
//!
//! This pass fills `<DigestValue>` elements before `<SignedInfo>` is
//! canonicalized and signed. It intentionally uses a signing-template parser
//! instead of [`crate::xmldsig::parse::parse_signed_info`], because verification
//! must continue to reject empty or malformed stored digest values.

use base64::Engine;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use p256::pkcs8::{DecodePrivateKey, EncodePublicKey};
use p384::ecdsa::{Signature as P384Signature, SigningKey as P384SigningKey};
use roxmltree::{Document, Node};
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::Signature as RsaPkcs1v15Signature;
use rsa::pkcs1v15::SigningKey as RsaPkcs1v15SigningKey;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::traits::PublicKeyParts;
use sha2::{Sha256, Sha384, Sha512};
use signature::hazmat::PrehashSigner;
use std::collections::HashSet;
use x509_parser::prelude::FromDer;

use crate::c14n::{canonicalize_bounded_with_xml_base_budget, is_output_limit_error};

use super::builder::{SignatureBuilder, SignatureBuilderError};
use super::digest::DigestAlgorithm;
use super::mutation::{
    XmlMutationError, append_signature_to_root_with_options, fill_key_info_at_index_with_options,
    fill_signature_value_at_index_with_options, fill_signed_info_digest_values,
    fill_signed_info_digest_values_at_index_with_options,
    fill_signed_info_digest_values_with_options,
};
use super::parse::{
    MAX_REFERENCES_PER_SIGNATURE, SignatureAlgorithm, XMLDSIG_NS, parse_signed_info,
};
use super::transforms::{
    DEFAULT_IMPLICIT_C14N_URI, Transform, TransformExecutionBudget, TransformOptions,
    XPathHereSemantics, XPathSignatureParseBudget, execute_transforms_with_options_and_budget,
    parse_transforms_with_budget, transform_chain_produces_binary,
};
use super::types::TransformError;
use super::uri::UriReferenceResolver;

/// Result for one computed signing-template reference digest.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "use the computed digest value to fill the corresponding <DigestValue>"]
pub struct ComputedReferenceDigest {
    /// Zero-based reference index in `<SignedInfo>` document order.
    pub index: usize,
    /// Reference URI used for same-document dereference.
    pub uri: String,
    /// Digest algorithm declared by `<DigestMethod>`.
    pub digest_method: DigestAlgorithm,
    /// Base64-encoded digest value ready for `<DigestValue>`.
    pub digest_value: String,
}

/// Errors returned by the XMLDSig signing digest pass.
#[derive(Debug, thiserror::Error)]
pub enum SigningDigestError {
    /// The selected provider could not compute a reference digest.
    #[error("cryptographic provider error: {0}")]
    Provider(#[from] crate::provider::ProviderError),

    /// The compiled signing policy rejected an operation input.
    #[error("signing policy violation: {0}")]
    Policy(#[from] crate::policy::PolicyViolation),

    /// The input XML document is not well-formed.
    #[error("XML parse error: {0}")]
    XmlParse(#[from] roxmltree::Error),

    /// Required XMLDSig element is missing.
    #[error("missing required element: <{element}>")]
    MissingElement {
        /// Required element name.
        element: &'static str,
    },

    /// XMLDSig template structure is invalid.
    #[error("invalid signing template: {0}")]
    InvalidStructure(String),

    /// Digest algorithm URI is not supported.
    #[error("unsupported digest algorithm: {uri}")]
    UnsupportedAlgorithm {
        /// Unrecognized algorithm URI.
        uri: String,
    },

    /// Digest algorithm is supported for verification but disabled for signing.
    #[error("digest algorithm is disabled for signing: {uri}")]
    SigningAlgorithmDisabled {
        /// Algorithm URI rejected for new signatures.
        uri: &'static str,
    },

    /// URI dereference or transform execution failed.
    #[error("reference processing error: {0}")]
    Transform(#[from] TransformError),

    /// Writing computed digest values back into XML failed.
    #[error("XML mutation error: {0}")]
    XmlMutation(#[from] XmlMutationError),
}

/// Errors returned by the full XMLDSig signing pipeline.
#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    /// The compiled signing policy rejected an operation input.
    #[error("signing policy violation: {0}")]
    Policy(#[from] crate::policy::PolicyViolation),

    /// Reference digest computation failed.
    #[error("signing digest pass failed: {0}")]
    Digest(#[from] SigningDigestError),

    /// Parsing the digest-filled `<SignedInfo>` failed.
    #[error("failed to parse SignedInfo after digest fill: {0}")]
    ParseSignedInfo(#[from] super::parse::ParseError),

    /// SignedInfo canonicalization failed.
    #[error("SignedInfo canonicalization failed: {0}")]
    Canonicalization(#[from] crate::c14n::C14nError),

    /// Signing key preparation or signing failed.
    #[error("signing key error: {0}")]
    Key(#[from] SigningKeyError),

    /// A signing provider returned bytes that cannot encode this key's signature.
    #[error("signature output must be {expected} bytes, got {actual}")]
    InvalidSignatureOutputLength {
        /// Exact XMLDSig wire length implied by the signing public key.
        expected: usize,
        /// Actual provider output length.
        actual: usize,
    },

    /// Writing `<SignatureValue>` failed.
    #[error("XML mutation error: {0}")]
    XmlMutation(#[from] XmlMutationError),

    /// Writing `<KeyInfo>` failed.
    #[error("KeyInfo writer error: {0}")]
    KeyInfo(#[from] KeyInfoWriteError),

    /// Signature template generation failed.
    #[error("signature template error: {0}")]
    Template(#[from] SignatureBuilderError),
}

/// Errors while parsing or using XMLDSig signing keys.
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

    /// The signing key cannot produce the requested XMLDSig algorithm.
    #[error("signing key does not support algorithm: {uri}")]
    UnsupportedAlgorithm {
        /// XMLDSig signature algorithm URI.
        uri: String,
    },

    /// The private-key signing operation failed.
    #[error("private-key signing operation failed")]
    SigningFailed,

    /// Public-key encoding failed for a supported signing key.
    #[error("failed to encode signing public key as SPKI DER")]
    PublicKeyEncodingFailed,

    /// Public-key metadata cannot determine the XMLDSig signature framing.
    #[error("invalid signing public-key metadata")]
    InvalidPublicKeyInfo,
}

/// Public key material corresponding to a private XMLDSig signing key.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SigningPublicKeyInfo {
    /// RSA public key with DER SubjectPublicKeyInfo and normalized parameters.
    Rsa {
        /// DER-encoded SubjectPublicKeyInfo bytes.
        spki_der: Vec<u8>,
        /// Unsigned big-endian RSA modulus (`n`), normalized without leading zeroes.
        modulus: Vec<u8>,
        /// Unsigned big-endian RSA public exponent (`e`), normalized without leading zeroes.
        exponent: Vec<u8>,
    },
    /// EC public key with DER SubjectPublicKeyInfo and XMLDSig 1.1 KeyValue data.
    Ec {
        /// DER-encoded SubjectPublicKeyInfo bytes.
        spki_der: Vec<u8>,
        /// Bare named-curve OID, without the XMLDSig `urn:oid:` prefix.
        curve_oid: &'static str,
        /// Uncompressed SEC1 point (`0x04 || x || y`).
        public_key: Vec<u8>,
    },
}

impl SigningPublicKeyInfo {
    /// Return DER-encoded SubjectPublicKeyInfo bytes for this public key.
    #[must_use]
    pub fn spki_der(&self) -> &[u8] {
        match self {
            Self::Rsa { spki_der, .. } | Self::Ec { spki_der, .. } => spki_der,
        }
    }
}

fn expected_signature_output_len(
    key: &dyn SigningKey,
    algorithm: SignatureAlgorithm,
    policy: &crate::policy::SigningPolicy,
) -> Result<usize, SigningError> {
    let public_key = key.public_key_info()?;
    let expected = match (algorithm, public_key) {
        (
            SignatureAlgorithm::RsaSha1
            | SignatureAlgorithm::RsaSha256
            | SignatureAlgorithm::RsaSha384
            | SignatureAlgorithm::RsaSha512,
            SigningPublicKeyInfo::Rsa {
                modulus, exponent, ..
            },
        ) => policy
            .rsa_keys
            .validate_components("signing", &modulus, &exponent)?,
        (
            SignatureAlgorithm::EcdsaSha256 | SignatureAlgorithm::EcdsaSha384,
            SigningPublicKeyInfo::Ec { public_key, .. },
        ) if public_key.first() == Some(&0x04)
            && public_key.len() > 1
            && (public_key.len() - 1).is_multiple_of(2) =>
        {
            // XMLDSig serializes ECDSA as fixed-width r || s. An uncompressed
            // SEC1 public point is 0x04 || x || y with the same field width.
            public_key.len() - 1
        }
        (
            SignatureAlgorithm::RsaSha1
            | SignatureAlgorithm::RsaSha256
            | SignatureAlgorithm::RsaSha384
            | SignatureAlgorithm::RsaSha512,
            SigningPublicKeyInfo::Ec { .. },
        )
        | (
            SignatureAlgorithm::EcdsaSha256 | SignatureAlgorithm::EcdsaSha384,
            SigningPublicKeyInfo::Rsa { .. },
        ) => {
            return Err(SigningKeyError::UnsupportedAlgorithm {
                uri: algorithm.uri().to_owned(),
            }
            .into());
        }
        _ => return Err(SigningKeyError::InvalidPublicKeyInfo.into()),
    };
    Ok(expected)
}

fn validate_signature_output(expected: usize, signature: &[u8]) -> Result<(), SigningError> {
    if signature.len() != expected {
        return Err(SigningError::InvalidSignatureOutputLength {
            expected,
            actual: signature.len(),
        });
    }
    Ok(())
}

/// Private key abstraction used by [`SignContext`].
pub trait SigningKey {
    /// Sign canonicalized `<SignedInfo>` bytes for the declared XMLDSig method.
    fn sign(
        &self,
        algorithm: SignatureAlgorithm,
        canonical_signed_info: &[u8],
    ) -> Result<Vec<u8>, SigningKeyError>;

    /// Sign while sourcing any primitive randomness from the selected provider.
    ///
    /// Deterministic or externally managed keys can rely on this default. Keys
    /// whose primitive uses randomness, including RSA blinding, must override it.
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
    fn public_key_info(&self) -> Result<SigningPublicKeyInfo, SigningKeyError>;
}

/// Writes signing key metadata into a template `<KeyInfo>` element.
pub trait KeyInfoWriter {
    /// Return XML child content for the direct `<Signature>/<KeyInfo>` element.
    fn write_key_info(&self, signing_key: &dyn SigningKey) -> Result<String, KeyInfoWriteError>;
}

/// Errors while preparing XMLDSig signing `<KeyInfo>` output.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KeyInfoWriteError {
    /// PEM input could not be parsed.
    #[error("invalid PEM certificate")]
    InvalidCertificatePem,

    /// PEM block was not an X.509 certificate.
    #[error("invalid certificate format: expected CERTIFICATE PEM, got {label}")]
    InvalidCertificateFormat {
        /// Actual PEM label.
        label: String,
    },

    /// DER bytes could not be decoded as one complete X.509 certificate.
    #[error("invalid X.509 certificate DER")]
    InvalidCertificateDer,

    /// A certificate-backed KeyInfo writer requires at least one certificate.
    #[error("X.509 certificate chain must not be empty")]
    EmptyCertificateChain,

    /// The signing key could not expose public-key material for validation.
    #[error("signing key public-key extraction failed: {0}")]
    SigningKey(#[from] SigningKeyError),

    /// The configured certificate does not contain the signing key's public key.
    #[error("X.509 certificate public key does not match signing key")]
    CertificateKeyMismatch,
}

/// `<KeyInfo>` writer that embeds an ordered DER X.509 certificate chain.
pub struct X509CertificateKeyInfoWriter {
    certificates_der: Vec<Vec<u8>>,
}

impl X509CertificateKeyInfoWriter {
    /// Parse a PEM `CERTIFICATE` block for XMLDSig `<X509Certificate>` output.
    pub fn from_pem(certificate_pem: &str) -> Result<Self, KeyInfoWriteError> {
        Self::from_pem_chain([certificate_pem])
    }

    /// Parse an ordered sequence of PEM `CERTIFICATE` blocks for `<X509Data>`.
    pub fn from_pem_chain<I, S>(certificate_pems: I) -> Result<Self, KeyInfoWriteError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut certificates_der = Vec::new();
        for certificate_pem in certificate_pems {
            certificates_der.push(parse_certificate_pem(certificate_pem.as_ref())?);
        }
        Self::from_der_chain(certificates_der)
    }

    /// Validate and store DER certificate bytes for XMLDSig `<X509Certificate>` output.
    pub fn from_der(certificate_der: &[u8]) -> Result<Self, KeyInfoWriteError> {
        Self::from_der_chain([certificate_der])
    }

    /// Validate and store an ordered DER certificate chain for `<X509Data>`.
    pub fn from_der_chain<I, B>(certificates_der: I) -> Result<Self, KeyInfoWriteError>
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        let certificates_der = certificates_der
            .into_iter()
            .map(|certificate_der| {
                let certificate_der = certificate_der.as_ref();
                let (rest, _) =
                    x509_parser::certificate::X509Certificate::from_der(certificate_der)
                        .map_err(|_| KeyInfoWriteError::InvalidCertificateDer)?;
                if !rest.is_empty() {
                    return Err(KeyInfoWriteError::InvalidCertificateDer);
                }
                Ok(certificate_der.to_vec())
            })
            .collect::<Result<Vec<_>, _>>()?;
        if certificates_der.is_empty() {
            return Err(KeyInfoWriteError::EmptyCertificateChain);
        }
        Ok(Self { certificates_der })
    }
}

fn parse_certificate_pem(certificate_pem: &str) -> Result<Vec<u8>, KeyInfoWriteError> {
    let (rest, pem) = x509_parser::pem::parse_x509_pem(certificate_pem.as_bytes())
        .map_err(|_| KeyInfoWriteError::InvalidCertificatePem)?;
    if !rest.iter().all(|byte| byte.is_ascii_whitespace()) {
        return Err(KeyInfoWriteError::InvalidCertificatePem);
    }
    if pem.label != "CERTIFICATE" {
        return Err(KeyInfoWriteError::InvalidCertificateFormat { label: pem.label });
    }
    Ok(pem.contents)
}

impl KeyInfoWriter for X509CertificateKeyInfoWriter {
    fn write_key_info(&self, signing_key: &dyn SigningKey) -> Result<String, KeyInfoWriteError> {
        let leaf_der = &self.certificates_der[0];
        let (rest, certificate) = x509_parser::certificate::X509Certificate::from_der(leaf_der)
            .map_err(|_| KeyInfoWriteError::InvalidCertificateDer)?;
        if !rest.is_empty() {
            return Err(KeyInfoWriteError::InvalidCertificateDer);
        }
        let signing_public_key = signing_key.public_key_info()?;
        if certificate.public_key().raw != signing_public_key.spki_der() {
            return Err(KeyInfoWriteError::CertificateKeyMismatch);
        }

        let mut xml = format!("<X509Data xmlns=\"{XMLDSIG_NS}\">");
        for certificate_der in &self.certificates_der {
            let certificate_b64 = base64::engine::general_purpose::STANDARD.encode(certificate_der);
            xml.push_str("<X509Certificate>");
            xml.push_str(&certificate_b64);
            xml.push_str("</X509Certificate>");
        }
        xml.push_str("</X509Data>");
        Ok(xml)
    }
}

/// RSA PKCS#1 v1.5 private key for XMLDSig signing.
pub struct RsaSigningKey {
    key: RsaPrivateKey,
}

impl RsaSigningKey {
    /// Parse an unencrypted PKCS#8 `PRIVATE KEY` PEM block.
    pub fn from_pkcs8_pem(private_key_pem: &str) -> Result<Self, SigningKeyError> {
        let private_key_der = parse_private_key_pem(private_key_pem)?;
        Self::from_pkcs8_der(&private_key_der)
    }

    /// Parse unencrypted PKCS#8 private key DER.
    pub fn from_pkcs8_der(private_key_der: &[u8]) -> Result<Self, SigningKeyError> {
        let key = RsaPrivateKey::from_pkcs8_der(private_key_der)
            .map_err(|_| SigningKeyError::InvalidKeyDer)?;
        Ok(Self { key })
    }
}

impl SigningKey for RsaSigningKey {
    fn sign(
        &self,
        algorithm: SignatureAlgorithm,
        canonical_signed_info: &[u8],
    ) -> Result<Vec<u8>, SigningKeyError> {
        self.sign_with_provider(
            crate::provider::default_provider(),
            algorithm,
            canonical_signed_info,
        )
    }

    fn sign_with_provider(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        algorithm: SignatureAlgorithm,
        canonical_signed_info: &[u8],
    ) -> Result<Vec<u8>, SigningKeyError> {
        match algorithm {
            SignatureAlgorithm::RsaSha256 => sign_rsa_pkcs1v15_with_rng(
                provider,
                RsaPkcs1v15SigningKey::<Sha256>::new(self.key.clone()),
                canonical_signed_info,
            ),
            SignatureAlgorithm::RsaSha384 => sign_rsa_pkcs1v15_with_rng(
                provider,
                RsaPkcs1v15SigningKey::<Sha384>::new(self.key.clone()),
                canonical_signed_info,
            ),
            SignatureAlgorithm::RsaSha512 => sign_rsa_pkcs1v15_with_rng(
                provider,
                RsaPkcs1v15SigningKey::<Sha512>::new(self.key.clone()),
                canonical_signed_info,
            ),
            _ => Err(SigningKeyError::UnsupportedAlgorithm {
                uri: algorithm.uri().to_string(),
            }),
        }
    }

    fn public_key_info(&self) -> Result<SigningPublicKeyInfo, SigningKeyError> {
        let public_key = self.key.to_public_key();
        let spki_der = public_key
            .to_public_key_der()
            .map(|doc| doc.as_bytes().to_vec())
            .map_err(|_| SigningKeyError::PublicKeyEncodingFailed)?;
        Ok(SigningPublicKeyInfo::Rsa {
            spki_der,
            modulus: public_key.n().to_be_bytes_trimmed_vartime().into_vec(),
            exponent: public_key.e().to_be_bytes_trimmed_vartime().into_vec(),
        })
    }
}

fn sign_rsa_pkcs1v15_with_rng(
    provider: &dyn crate::provider::CryptoProvider,
    key: impl RandomizedSigner<RsaPkcs1v15Signature>,
    canonical_signed_info: &[u8],
) -> Result<Vec<u8>, SigningKeyError> {
    let mut rng = crate::provider::ProviderRng(provider);
    let signature = key
        .try_sign_with_rng(&mut rng, canonical_signed_info)
        .map_err(|_| SigningKeyError::SigningFailed)?;
    Ok(signature.to_vec())
}

/// ECDSA P-256 private key for XMLDSig signing.
pub struct EcdsaP256SigningKey {
    key: P256SigningKey,
}

impl EcdsaP256SigningKey {
    /// Parse an unencrypted PKCS#8 `PRIVATE KEY` PEM block.
    pub fn from_pkcs8_pem(private_key_pem: &str) -> Result<Self, SigningKeyError> {
        let private_key_der = parse_private_key_pem(private_key_pem)?;
        Self::from_pkcs8_der(&private_key_der)
    }

    /// Parse unencrypted PKCS#8 private key DER.
    pub fn from_pkcs8_der(private_key_der: &[u8]) -> Result<Self, SigningKeyError> {
        let key = P256SigningKey::from_pkcs8_der(private_key_der)
            .map_err(|_| SigningKeyError::InvalidKeyDer)?;
        Ok(Self { key })
    }
}

impl SigningKey for EcdsaP256SigningKey {
    fn sign(
        &self,
        algorithm: SignatureAlgorithm,
        canonical_signed_info: &[u8],
    ) -> Result<Vec<u8>, SigningKeyError> {
        self.sign_with_provider(
            crate::provider::default_provider(),
            algorithm,
            canonical_signed_info,
        )
    }

    fn sign_with_provider(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        algorithm: SignatureAlgorithm,
        canonical_signed_info: &[u8],
    ) -> Result<Vec<u8>, SigningKeyError> {
        let digest_algorithm = match algorithm {
            SignatureAlgorithm::EcdsaSha256 => DigestAlgorithm::Sha256,
            SignatureAlgorithm::EcdsaSha384 => DigestAlgorithm::Sha384,
            _ => {
                return Err(SigningKeyError::UnsupportedAlgorithm {
                    uri: algorithm.uri().to_string(),
                });
            }
        };
        let prehash =
            super::compute_digest_with_provider(provider, digest_algorithm, canonical_signed_info)?;
        let signature: P256Signature = self
            .key
            .sign_prehash(&prehash)
            .map_err(|_| SigningKeyError::SigningFailed)?;
        Ok(signature.to_bytes().to_vec())
    }

    fn public_key_info(&self) -> Result<SigningPublicKeyInfo, SigningKeyError> {
        let verifying_key = self.key.verifying_key();
        let spki_der = verifying_key
            .to_public_key_der()
            .map(|doc| doc.as_bytes().to_vec())
            .map_err(|_| SigningKeyError::PublicKeyEncodingFailed)?;
        Ok(SigningPublicKeyInfo::Ec {
            spki_der,
            curve_oid: "1.2.840.10045.3.1.7",
            public_key: verifying_key.to_sec1_point(false).as_bytes().to_vec(),
        })
    }
}

/// ECDSA P-384 private key for XMLDSig signing.
pub struct EcdsaP384SigningKey {
    key: P384SigningKey,
}

impl EcdsaP384SigningKey {
    /// Parse an unencrypted PKCS#8 `PRIVATE KEY` PEM block.
    pub fn from_pkcs8_pem(private_key_pem: &str) -> Result<Self, SigningKeyError> {
        let private_key_der = parse_private_key_pem(private_key_pem)?;
        Self::from_pkcs8_der(&private_key_der)
    }

    /// Parse unencrypted PKCS#8 private key DER.
    pub fn from_pkcs8_der(private_key_der: &[u8]) -> Result<Self, SigningKeyError> {
        let key = P384SigningKey::from_pkcs8_der(private_key_der)
            .map_err(|_| SigningKeyError::InvalidKeyDer)?;
        Ok(Self { key })
    }
}

impl SigningKey for EcdsaP384SigningKey {
    fn sign(
        &self,
        algorithm: SignatureAlgorithm,
        canonical_signed_info: &[u8],
    ) -> Result<Vec<u8>, SigningKeyError> {
        self.sign_with_provider(
            crate::provider::default_provider(),
            algorithm,
            canonical_signed_info,
        )
    }

    fn sign_with_provider(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        algorithm: SignatureAlgorithm,
        canonical_signed_info: &[u8],
    ) -> Result<Vec<u8>, SigningKeyError> {
        let digest_algorithm = match algorithm {
            SignatureAlgorithm::EcdsaSha256 => DigestAlgorithm::Sha256,
            SignatureAlgorithm::EcdsaSha384 => DigestAlgorithm::Sha384,
            _ => {
                return Err(SigningKeyError::UnsupportedAlgorithm {
                    uri: algorithm.uri().to_string(),
                });
            }
        };
        let prehash =
            super::compute_digest_with_provider(provider, digest_algorithm, canonical_signed_info)?;
        let signature: P384Signature = self
            .key
            .sign_prehash(&prehash)
            .map_err(|_| SigningKeyError::SigningFailed)?;
        Ok(signature.to_bytes().to_vec())
    }

    fn public_key_info(&self) -> Result<SigningPublicKeyInfo, SigningKeyError> {
        let verifying_key = self.key.verifying_key();
        let spki_der = verifying_key
            .to_public_key_der()
            .map(|doc| doc.as_bytes().to_vec())
            .map_err(|_| SigningKeyError::PublicKeyEncodingFailed)?;
        Ok(SigningPublicKeyInfo::Ec {
            spki_der,
            curve_oid: "1.3.132.0.34",
            public_key: verifying_key.to_sec1_point(false).as_bytes().to_vec(),
        })
    }
}

/// XMLDSig signing context.
pub struct SignContext<'a> {
    signing_key: &'a dyn SigningKey,
    key_info_writer: Option<&'a dyn KeyInfoWriter>,
    start_node_id: Option<&'a str>,
    policy: crate::policy::SigningPolicy,
    provider: &'a dyn crate::provider::CryptoProvider,
}

impl<'a> SignContext<'a> {
    /// Create a signing context using the supplied private key.
    pub fn new(signing_key: &'a dyn SigningKey) -> Self {
        Self {
            signing_key,
            key_info_writer: None,
            start_node_id: None,
            policy: crate::policy::SigningPolicy::default(),
            provider: crate::provider::default_provider(),
        }
    }

    /// Replace the complete immutable signing policy snapshot.
    #[must_use]
    pub fn policy(mut self, policy: crate::policy::SigningPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Select the cryptographic provider for digest and randomness operations.
    #[must_use]
    pub fn provider(mut self, provider: &'a dyn crate::provider::CryptoProvider) -> Self {
        self.provider = provider;
        self
    }

    /// Configure signing to populate the direct `<Signature>/<KeyInfo>` placeholder.
    #[must_use]
    pub fn key_info_writer(mut self, writer: &'a dyn KeyInfoWriter) -> Self {
        self.key_info_writer = Some(writer);
        self
    }

    /// Select an operation start node by ID and sign the first XMLDSig
    /// `<Signature>` in that node's subtree.
    #[must_use]
    pub fn start_node_id(mut self, id: &'a str) -> Self {
        self.start_node_id = Some(id);
        self
    }

    /// Select the node returned by XPath's `here()` extension function.
    ///
    /// The default follows XMLDSig and returns the `<XPath>` parameter.
    /// [`XPathHereSemantics::XmlSecLegacy`] is available only for producing
    /// signatures compatible with libxmlsec1's `<Transform>` interpretation.
    #[must_use]
    pub fn xpath_here_semantics(mut self, semantics: XPathHereSemantics) -> Self {
        self.policy.xpath_here_semantics = semantics;
        self
    }

    /// Sign XML that already contains a `<Signature>` template.
    ///
    /// The template must include empty `<DigestValue>` and `<SignatureValue>`
    /// targets. The pipeline fills reference digests, reparses the result,
    /// canonicalizes `<SignedInfo>`, signs those canonical bytes, and fills the
    /// base64 `<SignatureValue>`.
    pub fn sign_template(&self, xml: &str) -> Result<String, SigningError> {
        self.policy.validate()?;
        self.policy.resources.validate_xml_document_len(xml.len())?;
        let document = parse_signing_document(xml, Some(&self.policy))
            .map_err(SigningDigestError::XmlParse)?;
        let target_signature = signing_signature_index(&document, self.start_node_id)?;
        let execution_budget = TransformExecutionBudget::from_resources(&self.policy.resources);
        let transform_options = TransformOptions::default()
            .allow_internal_dtd(self.policy.xml.allow_internal_dtd)
            .xpath_here_semantics(self.policy.xpath_here_semantics);
        let with_digests = fill_reference_digest_values_with_options(
            xml,
            transform_options,
            Some(&self.policy),
            self.provider,
            &execution_budget,
            Some(target_signature),
        )?;
        self.policy
            .resources
            .validate_xml_document_len(with_digests.len())?;
        let (algorithm, canonical_signed_info) = canonicalize_signed_info(
            &with_digests,
            &self.policy,
            &execution_budget,
            target_signature,
        )?;
        execution_budget
            .charge_c14n_output(canonical_signed_info.len())
            .map_err(SigningDigestError::Transform)?;
        if !algorithm.signing_allowed()
            || self
                .policy
                .signature_algorithms
                .as_ref()
                .is_some_and(|allowed| !allowed.contains(&algorithm))
        {
            return Err(crate::policy::PolicyViolation::Algorithm {
                operation: "signing",
                algorithm: algorithm.uri().to_string(),
            }
            .into());
        }
        let expected_signature_len =
            expected_signature_output_len(self.signing_key, algorithm, &self.policy)?;
        let signature_value =
            self.provider
                .sign(self.signing_key, algorithm, &canonical_signed_info)?;
        validate_signature_output(expected_signature_len, &signature_value)?;
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature_value);
        let signed = fill_signature_value_at_index_with_options(
            &with_digests,
            &signature_b64,
            target_signature,
            Some(&self.policy),
        )?;
        self.policy
            .resources
            .validate_xml_document_len(signed.len())?;
        if let Some(writer) = self.key_info_writer {
            let key_info_content = writer.write_key_info(self.signing_key)?;
            let signed = fill_key_info_at_index_with_options(
                &signed,
                &key_info_content,
                target_signature,
                Some(&self.policy),
            )?;
            self.policy
                .resources
                .validate_xml_document_len(signed.len())?;
            Ok(signed)
        } else {
            Ok(signed)
        }
    }

    /// Build a signature template, append it to the source root, then sign it.
    pub fn sign_with_builder(
        &self,
        xml: &str,
        builder: &SignatureBuilder,
    ) -> Result<String, SigningError> {
        self.policy.validate()?;
        self.policy.resources.validate_xml_document_len(xml.len())?;
        let template = builder.build_template()?;
        let templated = append_signature_to_root_with_options(xml, &template, Some(&self.policy))?;
        self.sign_template(&templated)
    }
}

#[derive(Debug)]
struct SigningReference {
    uri: String,
    transforms: Vec<Transform>,
    digest_method: DigestAlgorithm,
}

/// Compute base64 digest values for every `<Reference>` in the signing template.
///
/// References are processed in `<SignedInfo>` document order under the last
/// XMLDSig `<Signature>` element. `sign_with_builder()` appends a new template
/// at the end of the source root, so older signatures in an already-signed
/// document must not become the signing target.
pub fn compute_reference_digest_values(
    xml: &str,
) -> Result<Vec<ComputedReferenceDigest>, SigningDigestError> {
    let execution_budget = TransformExecutionBudget::default();
    compute_reference_digest_values_with_options(
        xml,
        TransformOptions::default(),
        None,
        crate::provider::default_provider(),
        &execution_budget,
        None,
    )
}

fn compute_reference_digest_values_with_options(
    xml: &str,
    transform_options: TransformOptions,
    policy: Option<&crate::policy::SigningPolicy>,
    provider: &dyn crate::provider::CryptoProvider,
    execution_budget: &TransformExecutionBudget,
    target_signature: Option<usize>,
) -> Result<Vec<ComputedReferenceDigest>, SigningDigestError> {
    let doc = parse_signing_document(xml, policy)?;
    let signature = find_signing_signature_node(&doc, target_signature)?;
    let signed_info = find_required_child(signature, "SignedInfo")?;
    let references = parse_signing_references(signed_info)?;
    if let Some(policy) = policy {
        if references.len() > policy.resources.max_references {
            return Err(crate::policy::PolicyViolation::ResourceLimit {
                resource: "signature references",
                maximum: policy.resources.max_references,
                actual: references.len(),
            }
            .into());
        }
        for reference in &references {
            if reference.transforms.len() > policy.resources.max_transforms_per_reference {
                return Err(crate::policy::PolicyViolation::ResourceLimit {
                    resource: "reference transforms",
                    maximum: policy.resources.max_transforms_per_reference,
                    actual: reference.transforms.len(),
                }
                .into());
            }
            if let Some(allowed) = policy.transforms.as_ref() {
                for transform in &reference.transforms {
                    let uri = transform.algorithm_uri();
                    if !allowed.contains(uri) {
                        return Err(crate::policy::PolicyViolation::Algorithm {
                            operation: "signing transform",
                            algorithm: uri.to_owned(),
                        }
                        .into());
                    }
                }
                let initial_binary = !reference.uri.is_empty() && !reference.uri.starts_with('#');
                if !transform_chain_produces_binary(initial_binary, &reference.transforms)
                    && !allowed.contains(DEFAULT_IMPLICIT_C14N_URI)
                {
                    return Err(crate::policy::PolicyViolation::Algorithm {
                        operation: "signing transform",
                        algorithm: DEFAULT_IMPLICIT_C14N_URI.to_owned(),
                    }
                    .into());
                }
            }
        }
    }
    let resolver = UriReferenceResolver::new(&doc);
    references
        .into_iter()
        .enumerate()
        .map(|(index, reference)| {
            if policy.is_some_and(|policy| {
                policy
                    .digest_algorithms
                    .as_ref()
                    .is_some_and(|allowed| !allowed.contains(&reference.digest_method))
            }) {
                return Err(crate::policy::PolicyViolation::Algorithm {
                    operation: "signing",
                    algorithm: reference.digest_method.uri().to_string(),
                }
                .into());
            }
            let initial_data = resolver.dereference_with_budget(
                &reference.uri,
                execution_budget.node_set_materialization(),
            )?;
            let pre_digest = execute_transforms_with_options_and_budget(
                signature,
                initial_data,
                &reference.transforms,
                transform_options,
                execution_budget,
            )?;
            let digest = super::compute_digest_with_provider(
                provider,
                reference.digest_method,
                &pre_digest,
            )?;
            let digest_value = base64::engine::general_purpose::STANDARD.encode(digest);
            Ok(ComputedReferenceDigest {
                index,
                uri: reference.uri,
                digest_method: reference.digest_method,
                digest_value,
            })
        })
        .collect()
}

/// Compute and fill all signing-template `<DigestValue>` elements.
///
/// This is the signing counterpart to verification reference processing: it
/// dereferences each `<Reference>`, applies transforms, computes the digest,
/// and writes the base64 digest into the matching `<DigestValue>` in document
/// order.
pub fn fill_reference_digest_values(xml: &str) -> Result<String, SigningDigestError> {
    let execution_budget = TransformExecutionBudget::default();
    fill_reference_digest_values_with_options(
        xml,
        TransformOptions::default(),
        None,
        crate::provider::default_provider(),
        &execution_budget,
        None,
    )
}

fn fill_reference_digest_values_with_options(
    xml: &str,
    transform_options: TransformOptions,
    policy: Option<&crate::policy::SigningPolicy>,
    provider: &dyn crate::provider::CryptoProvider,
    execution_budget: &TransformExecutionBudget,
    target_signature: Option<usize>,
) -> Result<String, SigningDigestError> {
    let digest_values = compute_reference_digest_values_with_options(
        xml,
        transform_options,
        policy,
        provider,
        execution_budget,
        target_signature,
    )?
    .into_iter()
    .map(|digest| digest.digest_value);
    Ok(if let Some(target_signature) = target_signature {
        fill_signed_info_digest_values_at_index_with_options(
            xml,
            digest_values,
            target_signature,
            policy,
        )?
    } else if let Some(policy) = policy {
        fill_signed_info_digest_values_with_options(xml, digest_values, Some(policy))?
    } else {
        fill_signed_info_digest_values(xml, digest_values)?
    })
}

fn canonicalize_signed_info(
    xml: &str,
    policy: &crate::policy::SigningPolicy,
    execution_budget: &TransformExecutionBudget,
    target_signature: usize,
) -> Result<(SignatureAlgorithm, Vec<u8>), SigningError> {
    let doc = parse_signing_document(xml, Some(policy)).map_err(SigningDigestError::XmlParse)?;
    let signature =
        find_signing_signature_node(&doc, Some(target_signature)).map_err(SigningError::Digest)?;
    let signed_info_node =
        find_required_child(signature, "SignedInfo").map_err(SigningError::Digest)?;
    let signed_info = parse_signed_info(signed_info_node)?;
    if policy
        .transforms
        .as_ref()
        .is_some_and(|allowed| !allowed.contains(signed_info.c14n_method.uri()))
    {
        return Err(crate::policy::PolicyViolation::Algorithm {
            operation: "SignedInfo canonicalization",
            algorithm: signed_info.c14n_method.uri().to_owned(),
        }
        .into());
    }
    let signed_info_subtree: HashSet<_> = signed_info_node
        .descendants()
        .map(|node: Node<'_, '_>| node.id())
        .collect();
    let mut canonical_signed_info = Vec::new();
    canonicalize_bounded_with_xml_base_budget(
        &doc,
        Some(&|node| signed_info_subtree.contains(&node.id())),
        &signed_info.c14n_method,
        execution_budget.remaining_c14n_output(),
        execution_budget.xml_base_resolution(),
        &mut canonical_signed_info,
    )
    .map_err(|error| {
        if is_output_limit_error(&error) {
            SigningError::Digest(SigningDigestError::Transform(
                TransformError::C14nOutputTooLarge {
                    max_bytes: execution_budget.c14n_output_limit(),
                },
            ))
        } else {
            SigningError::Canonicalization(error)
        }
    })?;
    Ok((signed_info.signature_method, canonical_signed_info))
}

fn parse_signing_document<'a>(
    xml: &'a str,
    policy: Option<&crate::policy::SigningPolicy>,
) -> Result<Document<'a>, roxmltree::Error> {
    super::mutation::parse_with_options(xml, policy)
}

fn parse_private_key_pem(private_key_pem: &str) -> Result<Vec<u8>, SigningKeyError> {
    let (rest, pem) = x509_parser::pem::parse_x509_pem(private_key_pem.as_bytes())
        .map_err(|_| SigningKeyError::InvalidKeyPem)?;
    if !rest.iter().all(|byte| byte.is_ascii_whitespace()) {
        return Err(SigningKeyError::InvalidKeyPem);
    }
    if pem.label != "PRIVATE KEY" {
        return Err(SigningKeyError::InvalidKeyFormat { label: pem.label });
    }
    Ok(pem.contents)
}

fn find_signing_signature_node<'a>(
    doc: &'a Document<'a>,
    target_signature: Option<usize>,
) -> Result<Node<'a, 'a>, SigningDigestError> {
    let mut signatures = doc.descendants().filter(|node| {
        node.is_element()
            && node.tag_name().name() == "Signature"
            && node.tag_name().namespace() == Some(XMLDSIG_NS)
    });
    match target_signature {
        Some(index) => signatures.nth(index),
        None => signatures.next_back(),
    }
    .ok_or(SigningDigestError::MissingElement {
        element: "Signature",
    })
}

fn signing_signature_index(
    doc: &Document<'_>,
    start_node_id: Option<&str>,
) -> Result<usize, SigningDigestError> {
    let selected = if let Some(id) = start_node_id {
        let start = UriReferenceResolver::new(doc)
            .node_for_id(id)
            .ok_or_else(|| {
                SigningDigestError::InvalidStructure(format!(
                    "selected node ID is missing or ambiguous: {id}"
                ))
            })?;
        start
            .descendants()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "Signature")))
            .ok_or_else(|| {
                SigningDigestError::InvalidStructure(format!(
                    "selected node subtree has no Signature: {id}"
                ))
            })?
    } else {
        find_signing_signature_node(doc, None)?
    };
    doc.descendants()
        .filter(|node| node.has_tag_name((XMLDSIG_NS, "Signature")))
        .position(|node| node == selected)
        .ok_or(SigningDigestError::MissingElement {
            element: "Signature",
        })
}

fn parse_signing_references(
    signed_info: Node<'_, '_>,
) -> Result<Vec<SigningReference>, SigningDigestError> {
    verify_ds_element(signed_info, "SignedInfo")?;
    let mut children = element_children(signed_info);

    let c14n_node = children.next().ok_or(SigningDigestError::MissingElement {
        element: "CanonicalizationMethod",
    })?;
    verify_ds_element(c14n_node, "CanonicalizationMethod")?;
    required_algorithm_attr(c14n_node, "CanonicalizationMethod")?;

    let signature_method_node = children.next().ok_or(SigningDigestError::MissingElement {
        element: "SignatureMethod",
    })?;
    verify_ds_element(signature_method_node, "SignatureMethod")?;
    required_algorithm_attr(signature_method_node, "SignatureMethod")?;

    let mut references = Vec::new();
    let mut xpath_budget = XPathSignatureParseBudget::default();
    for child in children {
        verify_ds_element(child, "Reference")?;
        if references.len() == MAX_REFERENCES_PER_SIGNATURE {
            return Err(SigningDigestError::InvalidStructure(format!(
                "SignedInfo contains more than {MAX_REFERENCES_PER_SIGNATURE} Reference elements"
            )));
        }
        references.push(parse_signing_reference(child, &mut xpath_budget)?);
    }
    if references.is_empty() {
        return Err(SigningDigestError::MissingElement {
            element: "Reference",
        });
    }
    Ok(references)
}

fn parse_signing_reference(
    reference_node: Node<'_, '_>,
    xpath_budget: &mut XPathSignatureParseBudget,
) -> Result<SigningReference, SigningDigestError> {
    let uri = reference_node
        .attribute("URI")
        .ok_or_else(|| {
            SigningDigestError::InvalidStructure(
                "signing Reference must include URI attribute".into(),
            )
        })?
        .to_string();
    let mut children = element_children(reference_node);

    let mut transforms = Vec::new();
    let mut next = children.next().ok_or(SigningDigestError::MissingElement {
        element: "DigestMethod",
    })?;
    if next.tag_name().name() == "Transforms" && next.tag_name().namespace() == Some(XMLDSIG_NS) {
        transforms = parse_transforms_with_budget(next, xpath_budget)?;
        next = children.next().ok_or(SigningDigestError::MissingElement {
            element: "DigestMethod",
        })?;
    }

    verify_ds_element(next, "DigestMethod")?;
    let digest_uri = required_algorithm_attr(next, "DigestMethod")?;
    let digest_method = DigestAlgorithm::from_uri(digest_uri).ok_or_else(|| {
        SigningDigestError::UnsupportedAlgorithm {
            uri: digest_uri.to_string(),
        }
    })?;
    if !digest_method.signing_allowed() {
        return Err(SigningDigestError::SigningAlgorithmDisabled {
            uri: digest_method.uri(),
        });
    }

    let digest_value_node = children.next().ok_or(SigningDigestError::MissingElement {
        element: "DigestValue",
    })?;
    verify_ds_element(digest_value_node, "DigestValue")?;

    if let Some(unexpected) = children.next() {
        return Err(SigningDigestError::InvalidStructure(format!(
            "unexpected element <{}> after <DigestValue> in <Reference>",
            unexpected.tag_name().name()
        )));
    }

    Ok(SigningReference {
        uri,
        transforms,
        digest_method,
    })
}

fn find_required_child<'a>(
    parent: Node<'a, 'a>,
    child_name: &'static str,
) -> Result<Node<'a, 'a>, SigningDigestError> {
    parent
        .children()
        .find(|node| {
            node.is_element()
                && node.tag_name().name() == child_name
                && node.tag_name().namespace() == Some(XMLDSIG_NS)
        })
        .ok_or(SigningDigestError::MissingElement {
            element: child_name,
        })
}

fn element_children<'a>(node: Node<'a, 'a>) -> impl Iterator<Item = Node<'a, 'a>> {
    node.children().filter(Node::is_element)
}

fn verify_ds_element(
    node: Node<'_, '_>,
    expected_name: &'static str,
) -> Result<(), SigningDigestError> {
    if !node.is_element() {
        return Err(SigningDigestError::InvalidStructure(format!(
            "expected element <{expected_name}>, got non-element node"
        )));
    }
    let tag = node.tag_name();
    if tag.name() != expected_name || tag.namespace() != Some(XMLDSIG_NS) {
        return Err(SigningDigestError::InvalidStructure(format!(
            "expected <ds:{expected_name}>, got <{}>",
            tag.name()
        )));
    }
    Ok(())
}

fn required_algorithm_attr<'a>(
    node: Node<'a, 'a>,
    element_name: &'static str,
) -> Result<&'a str, SigningDigestError> {
    node.attribute("Algorithm").ok_or_else(|| {
        SigningDigestError::InvalidStructure(format!(
            "missing Algorithm attribute on <{element_name}>"
        ))
    })
}
