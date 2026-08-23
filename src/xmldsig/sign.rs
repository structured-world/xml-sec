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
use roxmltree::{Document, Node, NodeId};
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::Signature as RsaPkcs1v15Signature;
use rsa::pkcs1v15::SigningKey as RsaPkcs1v15SigningKey;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::traits::PublicKeyParts;
use sha2::{Sha256, Sha384, Sha512};
use signature::hazmat::PrehashSigner;
use std::{collections::HashSet, ops::Range};
use x509_parser::prelude::FromDer;

use crate::c14n::canonicalize_bounded_with_xml_base_budget;

use super::builder::{SignatureBuilder, SignatureBuilderError};
use super::digest::DigestAlgorithm;
use super::mutation::{
    XmlMutationError, append_signature_to_element_with_options,
    append_signature_to_root_with_options,
    fill_selected_manifest_digest_values_at_index_with_options,
    fill_selected_signed_info_digest_values_at_index_with_options,
    fill_signature_value_at_index_with_options, fill_signed_info_digest_values,
    fill_signed_info_digest_values_at_index_with_options,
    fill_signed_info_digest_values_with_options, merge_key_info_source_at_index_with_options,
};
use super::parse::{
    MAX_REFERENCES_PER_SIGNATURE, SignatureAlgorithm, XMLDSIG_NS,
    parse_signed_info_with_xpath_budget,
};
use super::transforms::{
    Transform, TransformExecutionBudget, TransformOptions, XPathHereSemantics,
    XPathSignatureParseBudget, execute_transforms_with_dependency_nodes,
    execute_transforms_with_options_and_budget, map_c14n_resource_policy_violation,
    parse_transforms_with_budget, validate_signing_transform_policy,
};
use super::types::TransformError;
use super::uri::{UriReferenceResolver, validate_signing_reference_uri};
use super::verify::parse_signature_children;

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

    /// The compiled signing policy rejected input while processing References.
    ///
    /// The lower-level digest APIs return this variant directly. The full
    /// signing pipeline promotes every policy failure to [`SigningError::Policy`].
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
    /// The compiled signing policy rejected input outside the Reference digest stage.
    #[error("signing policy violation: {0}")]
    Policy(#[from] crate::policy::PolicyViolation),

    /// Reference digest computation failed.
    #[error("signing digest pass failed: {0}")]
    Digest(SigningDigestError),

    /// Parsing the digest-filled `<SignedInfo>` failed.
    #[error("failed to parse SignedInfo after digest fill: {0}")]
    ParseSignedInfo(super::parse::ParseError),

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
    XmlMutation(XmlMutationError),

    /// Writing `<KeyInfo>` failed.
    #[error("KeyInfo writer error: {0}")]
    KeyInfo(#[from] KeyInfoWriteError),

    /// Signature template generation failed.
    #[error("signature template error: {0}")]
    Template(SignatureBuilderError),
}

impl From<SigningDigestError> for SigningError {
    fn from(error: SigningDigestError) -> Self {
        match error {
            SigningDigestError::XmlMutation(XmlMutationError::Policy(error)) => Self::Policy(error),
            SigningDigestError::Policy(error)
            | SigningDigestError::Transform(TransformError::Policy(error)) => Self::Policy(error),
            error => Self::Digest(error),
        }
    }
}

impl From<super::parse::ParseError> for SigningError {
    fn from(error: super::parse::ParseError) -> Self {
        match error {
            super::parse::ParseError::Policy(error)
            | super::parse::ParseError::Transform(TransformError::Policy(error)) => {
                Self::Policy(error)
            }
            error => Self::ParseSignedInfo(error),
        }
    }
}

impl From<XmlMutationError> for SigningError {
    fn from(error: XmlMutationError) -> Self {
        match error {
            XmlMutationError::Policy(error) => Self::Policy(error),
            error => Self::XmlMutation(error),
        }
    }
}

impl From<SignatureBuilderError> for SigningError {
    fn from(error: SignatureBuilderError) -> Self {
        match error {
            SignatureBuilderError::Policy(error) => Self::Policy(error),
            error => Self::Template(error),
        }
    }
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

/// Validate that a key can produce the requested algorithm under `policy`.
///
/// Key registries can use this preflight before selecting a candidate, ensuring
/// lax ordered searches skip keys that the signing operation would reject.
pub fn validate_signing_key(
    key: &dyn SigningKey,
    algorithm: SignatureAlgorithm,
    policy: &crate::policy::SigningPolicy,
) -> Result<(), SigningError> {
    if !algorithm.signing_allowed() {
        return Err(SigningKeyError::UnsupportedAlgorithm {
            uri: algorithm.uri().to_owned(),
        }
        .into());
    }
    expected_signature_output_len(key, algorithm, policy).map(|_| ())
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

    /// Parse a leaf-first sequence of PEM `CERTIFICATE` blocks for `<X509Data>`.
    ///
    /// The first certificate must identify the signing key. Remaining issuer
    /// certificates are emitted in caller order; this writer does not build or
    /// validate issuer relationships because trust remains caller-owned.
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

    /// Validate and store a leaf-first DER certificate chain for `<X509Data>`.
    ///
    /// The first certificate must identify the signing key. Remaining issuer
    /// certificates are emitted in caller order; this writer does not build or
    /// validate issuer relationships because trust remains caller-owned.
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

/// Select which existing XMLDSig template [`SignContext::sign_template`] signs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SignatureTemplateSelection {
    /// Select the first descendant template in document order.
    FirstDescendant,
    /// Select the last descendant template, matching append-then-sign workflows.
    #[default]
    LastDescendant,
}

impl SignatureTemplateSelection {
    const fn target(self) -> SigningSignatureTarget {
        match self {
            Self::FirstDescendant => SigningSignatureTarget::First,
            Self::LastDescendant => SigningSignatureTarget::Last,
        }
    }
}

/// XMLDSig signing context.
pub struct SignContext<'a> {
    signing_key: &'a dyn SigningKey,
    key_info_writer: Option<&'a dyn KeyInfoWriter>,
    start_node_id: Option<&'a str>,
    id_attributes: &'a [crate::IdAttributeRegistration],
    template_selection: SignatureTemplateSelection,
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
            id_attributes: &[],
            template_selection: SignatureTemplateSelection::default(),
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

    /// Select an operation start node by ID and scope template selection to its subtree.
    ///
    /// [`Self::sign_with_builder`] instead uses the selected node as the append
    /// location and signs the newly appended direct `<Signature>` child.
    #[must_use]
    pub fn start_node_id(mut self, id: &'a str) -> Self {
        self.start_node_id = Some(id);
        self
    }

    /// Select which existing `<Signature>` template [`Self::sign_template`] signs.
    ///
    /// The default is [`SignatureTemplateSelection::LastDescendant`], preserving
    /// append-then-sign behavior. Compatibility boundaries that model donor
    /// document-order lookup can explicitly select `FirstDescendant`.
    #[must_use]
    pub fn signature_template_selection(mut self, selection: SignatureTemplateSelection) -> Self {
        self.template_selection = selection;
        self
    }

    /// Add caller-declared ID attributes for start-node and Reference lookup.
    #[must_use]
    pub fn id_attributes(mut self, registrations: &'a [crate::IdAttributeRegistration]) -> Self {
        self.id_attributes = registrations;
        self
    }

    /// Select the node returned by XPath's `here()` extension function.
    ///
    /// The default follows XMLDSig and returns the `<XPath>` parameter.
    /// [`XPathHereSemantics::XmlSecLegacy`] is available only for producing
    /// signatures compatible with libxmlsec1's `<Transform>` interpretation.
    #[must_use]
    pub fn xpath_here_semantics(mut self, semantics: XPathHereSemantics) -> Self {
        self.policy.transforms.xpath_here_semantics = semantics;
        self
    }

    /// Sign XML that already contains a `<Signature>` template.
    ///
    /// The template must include empty `<DigestValue>` and `<SignatureValue>`
    /// targets. The pipeline first materializes configured `<KeyInfo>` content,
    /// then fills reference digests, reparses the result, canonicalizes
    /// `<SignedInfo>`, signs those canonical bytes, and fills the base64
    /// `<SignatureValue>`. This ordering permits `<KeyInfo>` to be referenced
    /// from `<SignedInfo>` without producing a stale digest.
    pub fn sign_template(&self, xml: &str) -> Result<String, SigningError> {
        self.policy.validate()?;
        self.policy.resources.validate_xml_document_len(xml.len())?;
        let document = parse_signing_document(xml, Some(&self.policy))
            .map_err(SigningDigestError::XmlParse)?;
        let target_signature = signing_signature_index(
            &document,
            self.start_node_id,
            self.id_attributes,
            self.template_selection,
        )?;
        self.sign_template_at_index(xml, target_signature)
    }

    fn sign_template_at_index(
        &self,
        xml: &str,
        target_signature: usize,
    ) -> Result<String, SigningError> {
        let mut budgets = SigningOperationBudgets::from_resources(&self.policy.resources);
        self.sign_template_at_index_with_budgets(xml, target_signature, &mut budgets)
    }

    fn sign_template_at_index_with_budgets(
        &self,
        xml: &str,
        target_signature: usize,
        budgets: &mut SigningOperationBudgets,
    ) -> Result<String, SigningError> {
        let document = parse_signing_document(xml, Some(&self.policy))
            .map_err(SigningDigestError::XmlParse)?;
        let signature = find_signing_signature_node(
            &document,
            SigningSignatureTarget::Index(target_signature),
        )?;
        parse_signature_children(signature)
            .map_err(|error| SigningDigestError::InvalidStructure(error.to_string()))?;
        let transform_options = TransformOptions::default()
            .allow_internal_dtd(self.policy.xml.allow_internal_dtd)
            .xpath_here_semantics(self.policy.transforms.xpath_here_semantics);
        let with_key_info = if let Some(writer) = self.key_info_writer {
            let key_info_content = writer.write_key_info(self.signing_key)?;
            // Writer output is a separate untrusted XML input. Bound it before
            // namespace wrapping or parsing, then bound the merged document below.
            self.policy
                .resources
                .validate_xml_document_len(key_info_content.len())?;
            let populated = merge_key_info_source_at_index_with_options(
                xml,
                &key_info_content,
                target_signature,
                Some(&self.policy),
            )?;
            self.policy
                .resources
                .validate_xml_document_len(populated.len())?;
            Some(populated)
        } else {
            None
        };
        let prepared_xml = with_key_info.as_deref().unwrap_or(xml);
        let with_digests = fill_reference_digest_values_in_dependency_order(
            prepared_xml,
            transform_options,
            &self.policy,
            self.provider,
            budgets,
            target_signature,
            self.id_attributes,
        )?;
        self.policy
            .resources
            .validate_xml_document_len(with_digests.len())?;
        let (algorithm, canonical_signed_info) =
            canonicalize_signed_info(&with_digests, &self.policy, budgets, target_signature)?;
        budgets
            .transforms
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
        let signature_placeholder =
            base64::engine::general_purpose::STANDARD.encode(vec![0_u8; expected_signature_len]);
        fill_signature_value_at_index_with_options(
            &with_digests,
            &signature_placeholder,
            target_signature,
            Some(&self.policy),
        )?;
        self.provider
            .require_capability(crate::provider::ProviderCapability::Sign(algorithm))
            .map_err(SigningKeyError::from)?;
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
        Ok(signed)
    }

    /// Build a signature template, append it to the selected start node (or
    /// the document root when no selector is set), then sign that new template.
    pub fn sign_with_builder(
        &self,
        xml: &str,
        builder: &SignatureBuilder,
    ) -> Result<String, SigningError> {
        self.policy.validate()?;
        self.policy.resources.validate_xml_document_len(xml.len())?;
        let expected_signature_len = expected_signature_output_len(
            self.signing_key,
            builder.signature_method(),
            &self.policy,
        )?;
        let mut budgets = SigningOperationBudgets::from_resources(&self.policy.resources);
        let template = builder.build_template_with_policy_for_signature_output(
            &self.policy,
            expected_signature_len,
            &budgets.transforms,
            &mut budgets.xpath_parse,
        )?;
        let templated = if let Some(id) = self.start_node_id {
            let document = parse_signing_document(xml, Some(&self.policy))
                .map_err(SigningDigestError::XmlParse)?;
            let start = signing_start_node(&document, id, self.id_attributes)?;
            append_signature_to_element_with_options(
                xml,
                &template,
                start.range(),
                Some(&self.policy),
            )?
        } else {
            append_signature_to_root_with_options(xml, &template, Some(&self.policy))?
        };
        self.policy
            .resources
            .validate_xml_document_len(templated.len())?;
        let document = parse_signing_document(&templated, Some(&self.policy))
            .map_err(SigningDigestError::XmlParse)?;
        // Nodes and ranges are document-bound: the pre-mutation parse selects
        // the insertion range, while this post-mutation parse identifies the
        // newly appended Signature in the resulting document.
        let signature_parent = if let Some(id) = self.start_node_id {
            signing_start_node(&document, id, self.id_attributes)?
        } else {
            document.root_element()
        };
        let appended = signature_parent
            .children()
            .rfind(|node| node.has_tag_name((XMLDSIG_NS, "Signature")))
            .ok_or(SigningDigestError::MissingElement {
                element: "Signature",
            })?;
        let target_signature = signature_index(&document, appended)?;
        self.sign_template_at_index_with_budgets(&templated, target_signature, &mut budgets)
    }
}

#[derive(Debug, Clone)]
struct SigningReference {
    uri: String,
    transforms: Vec<Transform>,
    digest_method: DigestAlgorithm,
    digest_value_range: Range<usize>,
    digest_value_node_id: NodeId,
}

#[derive(Default)]
struct SigningOperationBudgets {
    transforms: TransformExecutionBudget,
    xpath_parse: XPathSignatureParseBudget,
}

impl SigningOperationBudgets {
    fn from_resources(resources: &crate::policy::ResourcePolicy) -> Self {
        Self {
            transforms: TransformExecutionBudget::from_resources(resources),
            xpath_parse: XPathSignatureParseBudget::from_resources(resources),
        }
    }
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
        &[],
    )
}

fn compute_reference_digest_values_with_options(
    xml: &str,
    transform_options: TransformOptions,
    policy: Option<&crate::policy::SigningPolicy>,
    provider: &dyn crate::provider::CryptoProvider,
    execution_budget: &TransformExecutionBudget,
    target_signature: Option<usize>,
    id_attributes: &[crate::IdAttributeRegistration],
) -> Result<Vec<ComputedReferenceDigest>, SigningDigestError> {
    let doc = parse_signing_document(xml, policy)?;
    let signature = find_signing_signature_node(
        &doc,
        target_signature.map_or(SigningSignatureTarget::Last, SigningSignatureTarget::Index),
    )?;
    let signed_info = find_required_child(signature, "SignedInfo")?;
    let references = parse_signing_references(signed_info)?;
    validate_signing_references(&references, references.len(), policy)?;
    compute_signing_reference_digests(
        &doc,
        signature,
        references,
        transform_options,
        provider,
        execution_budget,
        id_attributes,
    )
}

fn fill_reference_digest_values_in_dependency_order(
    xml: &str,
    transform_options: TransformOptions,
    policy: &crate::policy::SigningPolicy,
    provider: &dyn crate::provider::CryptoProvider,
    budgets: &mut SigningOperationBudgets,
    target_signature: usize,
    id_attributes: &[crate::IdAttributeRegistration],
) -> Result<String, SigningDigestError> {
    let doc = parse_signing_document(xml, Some(policy))?;
    let signature =
        find_signing_signature_node(&doc, SigningSignatureTarget::Index(target_signature))?;
    let signed_info = find_required_child(signature, "SignedInfo")?;
    let signed_info_references =
        parse_signing_references_with_budget(signed_info, &mut budgets.xpath_parse)?;
    validate_signing_references(
        &signed_info_references,
        signed_info_references.len(),
        Some(policy),
    )?;
    let reference_limit = policy
        .resources
        .max_references
        .min(MAX_REFERENCES_PER_SIGNATURE);
    let process_manifests =
        policy.manifest_processing == crate::policy::ManifestProcessing::Process;
    let manifest_references = if process_manifests {
        parse_signing_manifest_references(
            signature,
            &mut budgets.xpath_parse,
            reference_limit.saturating_sub(signed_info_references.len()),
            reference_limit,
        )?
    } else {
        Vec::new()
    };
    let total_references = signed_info_references
        .len()
        .checked_add(manifest_references.len())
        .ok_or_else(|| SigningDigestError::InvalidStructure("reference count overflow".into()))?;
    validate_signing_references(&manifest_references, total_references, Some(policy))?;
    let placeholder = "AA==";
    let analysis_xml = fill_signed_info_digest_values_at_index_with_options(
        xml,
        std::iter::repeat_n(placeholder, signed_info_references.len()),
        target_signature,
        Some(policy),
    )?;
    let analysis_xml = if manifest_references.is_empty() {
        analysis_xml
    } else {
        fill_selected_manifest_digest_values_at_index_with_options(
            &analysis_xml,
            (0..manifest_references.len()).map(|index| (index, placeholder)),
            target_signature,
            Some(policy),
        )?
    };
    // SignatureValue is the final mutable value in the signing pipeline. Give
    // it concrete character data during analysis so references that retain the
    // existing or future text cannot be mistaken for stable inputs.
    let analysis_xml = fill_signature_value_at_index_with_options(
        &analysis_xml,
        placeholder,
        target_signature,
        Some(policy),
    )?;
    let analysis_doc = parse_signing_document(&analysis_xml, Some(policy))?;
    let analysis_signature = find_signing_signature_node(
        &analysis_doc,
        SigningSignatureTarget::Index(target_signature),
    )?;
    let analysis_signed_info = find_required_child(analysis_signature, "SignedInfo")?;
    let mut analysis_references =
        parse_signing_references_with_budget(analysis_signed_info, &mut budgets.xpath_parse)?;
    if process_manifests {
        analysis_references.extend(parse_signing_manifest_references(
            analysis_signature,
            &mut budgets.xpath_parse,
            reference_limit.saturating_sub(signed_info_references.len()),
            reference_limit,
        )?);
    }
    let dependency_plan = reference_dependency_levels(
        &analysis_doc,
        analysis_signature,
        &analysis_references,
        transform_options,
        &budgets.transforms,
        id_attributes,
    )?;
    let mut filled = xml.to_owned();
    for level in dependency_plan {
        let current_doc = parse_signing_document(&filled, Some(policy))?;
        let current_signature = find_signing_signature_node(
            &current_doc,
            SigningSignatureTarget::Index(target_signature),
        )?;
        let current_signed_info = find_required_child(current_signature, "SignedInfo")?;
        let current_signed_info_references =
            parse_signing_references_with_budget(current_signed_info, &mut budgets.xpath_parse)?;
        let current_manifest_references = if process_manifests {
            parse_signing_manifest_references(
                current_signature,
                &mut budgets.xpath_parse,
                reference_limit.saturating_sub(signed_info_references.len()),
                reference_limit,
            )?
        } else {
            Vec::new()
        };
        if current_signed_info_references.len() != signed_info_references.len()
            || current_manifest_references.len() != manifest_references.len()
        {
            return Err(SigningDigestError::InvalidStructure(
                "signing Reference set changed while filling digests".into(),
            ));
        }
        let mut signed_info_replacements = Vec::new();
        let mut manifest_replacements = Vec::new();
        let mut destinations = Vec::with_capacity(level.len());
        let mut level_references = Vec::with_capacity(level.len());
        for index in level {
            let (reference, local_index, signed_info) = if index < signed_info_references.len() {
                let reference = current_signed_info_references.get(index).ok_or_else(|| {
                    SigningDigestError::InvalidStructure(
                        "signing Reference set changed while filling digests".into(),
                    )
                })?;
                (reference, index, true)
            } else {
                let local_index = index - signed_info_references.len();
                let reference = current_manifest_references
                    .get(local_index)
                    .ok_or_else(|| {
                        SigningDigestError::InvalidStructure(
                            "signing Reference set changed while filling digests".into(),
                        )
                    })?;
                (reference, local_index, false)
            };
            destinations.push((local_index, signed_info));
            level_references.push(reference.clone());
        }
        let computed = compute_signing_reference_digests(
            &current_doc,
            current_signature,
            level_references,
            transform_options,
            provider,
            &budgets.transforms,
            id_attributes,
        )?;
        if computed.len() != destinations.len() {
            return Err(SigningDigestError::InvalidStructure(
                "signing Reference set changed while computing digests".into(),
            ));
        }
        for ((local_index, signed_info), digest) in destinations.into_iter().zip(computed) {
            let digest_value = digest.digest_value;
            if signed_info {
                signed_info_replacements.push((local_index, digest_value));
            } else {
                manifest_replacements.push((local_index, digest_value));
            }
        }
        if !signed_info_replacements.is_empty() {
            filled = fill_selected_signed_info_digest_values_at_index_with_options(
                &filled,
                signed_info_replacements,
                target_signature,
                Some(policy),
            )?;
        }
        if !manifest_replacements.is_empty() {
            filled = fill_selected_manifest_digest_values_at_index_with_options(
                &filled,
                manifest_replacements,
                target_signature,
                Some(policy),
            )?;
        }
    }
    Ok(filled)
}

fn reference_dependency_levels(
    doc: &Document<'_>,
    signature: Node<'_, '_>,
    references: &[SigningReference],
    transform_options: TransformOptions,
    execution_budget: &TransformExecutionBudget,
    id_attributes: &[crate::IdAttributeRegistration],
) -> Result<Vec<Vec<usize>>, SigningDigestError> {
    let resolver = UriReferenceResolver::with_id_registrations(doc, id_attributes);
    let terminal_signature_value_index = references.len();
    let signature_value = find_required_child(signature, "SignatureValue")?;
    let mut tracked_mutable_nodes = references
        .iter()
        .enumerate()
        .flat_map(|(index, reference)| {
            std::iter::once((index, reference.digest_value_node_id)).chain(
                doc.get_node(reference.digest_value_node_id)
                    .into_iter()
                    .flat_map(|node| node.children())
                    .filter(|node| node.is_text())
                    .map(move |node| (index, node.id())),
            )
        })
        .collect::<Vec<_>>();
    tracked_mutable_nodes.push((terminal_signature_value_index, signature_value.id()));
    tracked_mutable_nodes.extend(
        signature_value
            .children()
            .filter(|node| node.is_text())
            .map(|node| (terminal_signature_value_index, node.id())),
    );
    let analyses = references
        .iter()
        .map(|reference| {
            let initial_data = resolver.dereference_with_budget(
                &reference.uri,
                execution_budget.node_set_materialization(),
            )?;
            let output = execute_transforms_with_dependency_nodes(
                signature,
                initial_data,
                &reference.transforms,
                transform_options,
                execution_budget,
                tracked_mutable_nodes.clone(),
            )?;
            Ok(output.dependencies)
        })
        .collect::<Result<Vec<_>, SigningDigestError>>()?;
    if analyses
        .iter()
        .any(|dependencies| dependencies.contains(&terminal_signature_value_index))
    {
        return Err(SigningDigestError::InvalidStructure(
            "Reference dependency cycle includes the mutable SignatureValue".into(),
        ));
    }
    let mut dependencies = analyses;
    let mut completed = vec![false; references.len()];
    let mut levels = Vec::new();
    while completed.iter().any(|done| !done) {
        let ready = dependencies
            .iter()
            .enumerate()
            .filter_map(|(index, dependencies)| {
                (!completed[index] && dependencies.is_empty()).then_some(index)
            })
            .collect::<Vec<_>>();
        if ready.is_empty() {
            return Err(SigningDigestError::InvalidStructure(
                "Manifest Reference digest dependency cycle".into(),
            ));
        }
        for index in &ready {
            completed[*index] = true;
        }
        for dependency_set in &mut dependencies {
            dependency_set.retain(|dependency| !completed[*dependency]);
        }
        levels.push(ready);
    }

    // Every mutable DigestValue belongs to the selected Signature;
    // an enveloped transform excludes that complete subtree and therefore
    // removes all such dependencies from its input node-set.
    debug_assert!(references.iter().all(|reference| {
        signature.range().start <= reference.digest_value_range.start
            && signature.range().end >= reference.digest_value_range.end
    }));
    Ok(levels)
}

fn validate_signing_references(
    references: &[SigningReference],
    total_references: usize,
    policy: Option<&crate::policy::SigningPolicy>,
) -> Result<(), SigningDigestError> {
    let Some(policy) = policy else {
        return Ok(());
    };
    if total_references > policy.resources.max_references {
        return Err(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::SIGNATURE_REFERENCES,
            maximum: policy.resources.max_references,
            actual: total_references,
        }
        .into());
    }
    for reference in references {
        validate_signing_reference_uri(&reference.uri, policy)?;
        if reference.transforms.len() > policy.resources.max_transforms_per_reference {
            return Err(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::REFERENCE_TRANSFORMS,
                maximum: policy.resources.max_transforms_per_reference,
                actual: reference.transforms.len(),
            }
            .into());
        }
        if policy
            .digest_algorithms
            .as_ref()
            .is_some_and(|allowed| !allowed.contains(&reference.digest_method))
        {
            return Err(crate::policy::PolicyViolation::Algorithm {
                operation: "signing",
                algorithm: reference.digest_method.uri().to_string(),
            }
            .into());
        }
        let initial_binary = !reference.uri.is_empty() && !reference.uri.starts_with('#');
        validate_signing_transform_policy(
            initial_binary,
            &reference.transforms,
            policy.transforms.allowed_algorithms.as_ref(),
        )?;
    }
    Ok(())
}

fn compute_signing_reference_digests(
    doc: &Document<'_>,
    signature: Node<'_, '_>,
    references: Vec<SigningReference>,
    transform_options: TransformOptions,
    provider: &dyn crate::provider::CryptoProvider,
    execution_budget: &TransformExecutionBudget,
    id_attributes: &[crate::IdAttributeRegistration],
) -> Result<Vec<ComputedReferenceDigest>, SigningDigestError> {
    let resolver = UriReferenceResolver::with_id_registrations(doc, id_attributes);
    references
        .into_iter()
        .enumerate()
        .map(|(index, reference)| {
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
        &[],
    )
}

fn fill_reference_digest_values_with_options(
    xml: &str,
    transform_options: TransformOptions,
    policy: Option<&crate::policy::SigningPolicy>,
    provider: &dyn crate::provider::CryptoProvider,
    execution_budget: &TransformExecutionBudget,
    target_signature: Option<usize>,
    id_attributes: &[crate::IdAttributeRegistration],
) -> Result<String, SigningDigestError> {
    let digest_values = compute_reference_digest_values_with_options(
        xml,
        transform_options,
        policy,
        provider,
        execution_budget,
        target_signature,
        id_attributes,
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
    budgets: &mut SigningOperationBudgets,
    target_signature: usize,
) -> Result<(SignatureAlgorithm, Vec<u8>), SigningError> {
    let doc = parse_signing_document(xml, Some(policy)).map_err(SigningDigestError::XmlParse)?;
    let signature =
        find_signing_signature_node(&doc, SigningSignatureTarget::Index(target_signature))
            .map_err(SigningError::Digest)?;
    let signed_info_node =
        find_required_child(signature, "SignedInfo").map_err(SigningError::Digest)?;
    let signed_info =
        parse_signed_info_with_xpath_budget(signed_info_node, &mut budgets.xpath_parse)?;
    if policy
        .transforms
        .allowed_algorithms
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
        budgets.transforms.remaining_c14n_output(),
        budgets.transforms.xml_base_resolution(),
        &mut canonical_signed_info,
    )
    .map_err(|error| {
        if let Some(violation) = map_c14n_resource_policy_violation(
            &error,
            crate::policy::resource_name::CANONICALIZED_BYTES,
            budgets.transforms.c14n_output_limit(),
        ) {
            SigningError::Policy(violation)
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

enum SigningSignatureTarget {
    First,
    Last,
    Index(usize),
}

fn find_signing_signature_node<'a>(
    doc: &'a Document<'a>,
    target: SigningSignatureTarget,
) -> Result<Node<'a, 'a>, SigningDigestError> {
    let mut signatures = doc.descendants().filter(|node| {
        node.is_element()
            && node.tag_name().name() == "Signature"
            && node.tag_name().namespace() == Some(XMLDSIG_NS)
    });
    match target {
        SigningSignatureTarget::First => signatures.next(),
        SigningSignatureTarget::Last => signatures.next_back(),
        SigningSignatureTarget::Index(index) => signatures.nth(index),
    }
    .ok_or(SigningDigestError::MissingElement {
        element: "Signature",
    })
}

fn signing_signature_index(
    doc: &Document<'_>,
    start_node_id: Option<&str>,
    id_attributes: &[crate::IdAttributeRegistration],
    selection: SignatureTemplateSelection,
) -> Result<usize, SigningDigestError> {
    let selected = if let Some(id) = start_node_id {
        let start = signing_start_node(doc, id, id_attributes)?;
        let mut signatures = start
            .descendants()
            .filter(|node| node.has_tag_name((XMLDSIG_NS, "Signature")));
        match selection.target() {
            SigningSignatureTarget::First => signatures.next(),
            SigningSignatureTarget::Last => signatures.next_back(),
            SigningSignatureTarget::Index(_) => unreachable!("public selection is not indexed"),
        }
        .ok_or_else(|| {
            SigningDigestError::InvalidStructure(format!(
                "selected node subtree has no Signature: {id}"
            ))
        })?
    } else {
        find_signing_signature_node(doc, selection.target())?
    };
    signature_index(doc, selected)
}

fn signing_start_node<'a>(
    doc: &'a Document<'a>,
    id: &str,
    id_attributes: &[crate::IdAttributeRegistration],
) -> Result<Node<'a, 'a>, SigningDigestError> {
    UriReferenceResolver::with_id_registrations(doc, id_attributes)
        .node_for_id(id)
        .ok_or_else(|| {
            SigningDigestError::InvalidStructure(format!(
                "selected node ID is missing or ambiguous: {id}"
            ))
        })
}

fn signature_index(
    doc: &Document<'_>,
    selected: Node<'_, '_>,
) -> Result<usize, SigningDigestError> {
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
    parse_signing_references_with_budget(signed_info, &mut XPathSignatureParseBudget::default())
}

fn parse_signing_references_with_budget(
    signed_info: Node<'_, '_>,
    xpath_budget: &mut XPathSignatureParseBudget,
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
    for child in children {
        verify_ds_element(child, "Reference")?;
        if references.len() == MAX_REFERENCES_PER_SIGNATURE {
            return Err(SigningDigestError::InvalidStructure(format!(
                "SignedInfo contains more than {MAX_REFERENCES_PER_SIGNATURE} Reference elements"
            )));
        }
        references.push(parse_signing_reference(child, xpath_budget)?);
    }
    if references.is_empty() {
        return Err(SigningDigestError::MissingElement {
            element: "Reference",
        });
    }
    Ok(references)
}

fn parse_signing_manifest_references(
    signature: Node<'_, '_>,
    xpath_budget: &mut XPathSignatureParseBudget,
    mut remaining_capacity: usize,
    maximum_references: usize,
) -> Result<Vec<SigningReference>, SigningDigestError> {
    let mut references = Vec::new();
    for manifest in signature
        .children()
        .filter(|node| node.has_tag_name((XMLDSIG_NS, "Object")))
        .flat_map(|object| {
            object
                .children()
                .filter(|node| node.has_tag_name((XMLDSIG_NS, "Manifest")))
        })
    {
        let mut manifest_references = 0usize;
        for child in element_children(manifest) {
            verify_ds_element(child, "Reference")?;
            if remaining_capacity == 0 {
                return Err(crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::SIGNATURE_REFERENCES,
                    maximum: maximum_references,
                    actual: maximum_references.saturating_add(1),
                }
                .into());
            }
            remaining_capacity -= 1;
            references.push(parse_signing_reference(child, xpath_budget)?);
            manifest_references += 1;
        }
        if manifest_references == 0 {
            return Err(SigningDigestError::MissingElement {
                element: "Reference",
            });
        }
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
        digest_value_range: digest_value_node.range(),
        digest_value_node_id: digest_value_node.id(),
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

#[cfg(test)]
mod error_conversion_tests {
    use super::*;
    use crate::policy::PolicyViolation;

    struct RejectingSigningKey;

    impl SigningKey for RejectingSigningKey {
        fn sign(
            &self,
            _algorithm: SignatureAlgorithm,
            _canonical_signed_info: &[u8],
        ) -> Result<Vec<u8>, SigningKeyError> {
            Err(SigningKeyError::SigningFailed)
        }

        fn public_key_info(&self) -> Result<SigningPublicKeyInfo, SigningKeyError> {
            Err(SigningKeyError::PublicKeyEncodingFailed)
        }
    }

    #[test]
    fn signing_error_promotes_every_policy_failure() {
        // All policy refusals use one public pipeline variant regardless of
        // which internal signing stage first enforces the immutable snapshot.
        let digest = SigningError::from(SigningDigestError::Policy(PolicyViolation::Algorithm {
            operation: "signing",
            algorithm: "urn:test:digest".into(),
        }));
        assert!(matches!(digest, SigningError::Policy(_)));

        let mutation = SigningError::from(SigningDigestError::XmlMutation(
            XmlMutationError::Policy(PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XML_DOCUMENT,
                maximum: 1,
                actual: 2,
            }),
        ));
        assert!(matches!(mutation, SigningError::Policy(_)));
    }

    #[test]
    fn manifest_reparse_consumes_the_signature_wide_xpath_budget() {
        // Signing reparses Manifest references after each dependency level.
        // Repeated parser/compiler work must consume the original signature
        // budget rather than receiving a fresh allowance for every level.
        let filter = r#"<xf:XPath xmlns:xf="http://www.w3.org/2002/06/xmldsig-filter2" Filter="intersect">true()</xf:XPath>"#;
        let signed_info_transforms = format!(
            r#"<ds:Transform Algorithm="http://www.w3.org/2002/06/xmldsig-filter2">{}</ds:Transform><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>true()</ds:XPath></ds:Transform><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>true()</ds:XPath></ds:Transform>"#,
            filter.repeat(64)
        );
        let signed_info_references = (0..62)
            .map(|index| {
                let extra = if index == 0 {
                    r#"<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>true()</ds:XPath></ds:Transform>"#
                } else {
                    ""
                };
                format!(
                    r##"<ds:Reference URI="#payload"><ds:Transforms>{signed_info_transforms}{extra}</ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference>"##
                )
            })
            .collect::<String>();
        let manifest_reference = |id: &str| {
            format!(
                r##"<ds:Reference URI="#{id}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>true()</ds:XPath></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference>"##
            )
        };
        let xml = format!(
            r##"<root><payload Id="payload"/><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>{signed_info_references}</ds:SignedInfo><ds:SignatureValue/><ds:Object><ds:Manifest>{}{}</ds:Manifest></ds:Object></ds:Signature></root>"##,
            manifest_reference("payload"),
            manifest_reference("payload")
        );
        let policy = crate::policy::SigningPolicy {
            manifest_processing: crate::policy::ManifestProcessing::Process,
            ..crate::policy::SigningPolicy::default()
        };

        let error = fill_reference_digest_values_in_dependency_order(
            &xml,
            TransformOptions::default(),
            &policy,
            crate::provider::default_provider(),
            &mut SigningOperationBudgets::default(),
            0,
            &[],
        )
        .expect_err("Manifest reparse must not reset the XPath parse budget");

        assert!(
            matches!(
                &error,
                SigningDigestError::Transform(TransformError::Policy(
                    crate::policy::PolicyViolation::ResourceLimit {
                        resource: "XPath expressions",
                        ..
                    }
                ))
            ),
            "expected the shared XPath budget error, got: {error:?}"
        );
    }

    #[test]
    fn final_signed_info_parse_consumes_the_signing_xpath_budget() {
        // One XPath Reference is parsed while discovering references, while
        // analyzing dependencies, and while filling its dependency level. The
        // final SignedInfo parse must consume the same operation-wide budget.
        let xml = r##"<root><payload Id="payload">content</payload><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#payload"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>true()</ds:XPath></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/></ds:Signature></root>"##;
        let mut policy = crate::policy::SigningPolicy::default();
        policy.resources.max_xpath_expressions = 3;

        let error = SignContext::new(&RejectingSigningKey)
            .policy(policy)
            .sign_template(xml)
            .expect_err("the final SignedInfo parse must not reset the XPath budget");

        assert!(
            matches!(
                error,
                SigningError::Policy(PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XPATH_EXPRESSIONS,
                    maximum: 3,
                    ..
                })
            ),
            "expected the shared XPath parse budget error, got: {error:?}"
        );
    }

    #[test]
    fn signing_rejects_xpath_control_dependencies_on_digest_values() {
        // The second Reference excludes DigestValue nodes from its output but
        // reads the first DigestValue to decide whether payload remains. Filling
        // both references in one level would therefore invalidate the result.
        let xml = r##"<root><payload Id="payload">content</payload><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#payload"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference><ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>not(ancestor-or-self::ds:DigestValue) and (not(self::payload) or string(//ds:Reference[1]/ds:DigestValue) = '')</ds:XPath></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/></ds:Signature></root>"##;

        let error = fill_reference_digest_values_in_dependency_order(
            xml,
            TransformOptions::default(),
            &crate::policy::SigningPolicy::default(),
            crate::provider::default_provider(),
            &mut SigningOperationBudgets::default(),
            0,
            &[],
        )
        .expect_err("mutable XPath control dependencies must fail closed");

        assert!(
            matches!(
                &error,
                SigningDigestError::InvalidStructure(message)
                    if message.contains("dependency cycle")
            ),
            "expected a dependency-cycle rejection, got: {error:?}"
        );
    }

    #[test]
    fn signing_allows_payload_local_xpath_value_predicates() {
        // Attribute comparisons read payload metadata, not mutable values in a
        // disjoint Signature subtree. They must not manufacture a self-cycle.
        let xml = r##"<root><payload Id="payload" kind="include">content</payload><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#payload"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>@kind = 'include'</ds:XPath></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/></ds:Signature></root>"##;

        let filled = fill_reference_digest_values_in_dependency_order(
            xml,
            TransformOptions::default(),
            &crate::policy::SigningPolicy::default(),
            crate::provider::default_provider(),
            &mut SigningOperationBudgets::default(),
            0,
            &[],
        )
        .expect("payload-local XPath predicates must not depend on Signature values");

        assert_ne!(filled, xml);
    }

    #[test]
    fn signing_rejects_references_that_retain_signature_value() {
        // SignatureValue is filled after every Reference digest. A Reference
        // retaining that node is therefore an unavoidable signing cycle even
        // when all DigestValue nodes are excluded from the resulting node-set.
        let xml = r##"<root><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>not(ancestor-or-self::ds:DigestValue)</ds:XPath></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/></ds:Signature></root>"##;

        let error = fill_reference_digest_values_in_dependency_order(
            xml,
            TransformOptions::default(),
            &crate::policy::SigningPolicy::default(),
            crate::provider::default_provider(),
            &mut SigningOperationBudgets::default(),
            0,
            &[],
        )
        .expect_err("a mutable SignatureValue dependency must fail before signing");

        assert!(
            matches!(
                &error,
                SigningDigestError::InvalidStructure(message)
                    if message.contains("SignatureValue") && message.contains("cycle")
            ),
            "expected a SignatureValue dependency-cycle rejection, got: {error:?}"
        );
    }
}
