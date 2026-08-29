//! Signing-side XMLDSig digest computation.
//!
//! This pass fills `<DigestValue>` elements before `<SignedInfo>` is
//! canonicalized and signed. It intentionally uses a signing-template parser
//! instead of [`crate::xmldsig::parse::parse_signed_info`], because verification
//! must continue to reject empty or malformed stored digest values.

use crate::xml::dom::{Document, Node, NodeId};
use base64::Engine;
use hmac::{KeyInit, Mac};
use p256::ecdsa::{
    Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
};
use p256::pkcs8::{DecodePrivateKey, EncodePublicKey};
use p384::ecdsa::{
    Signature as P384Signature, SigningKey as P384SigningKey, VerifyingKey as P384VerifyingKey,
};
use p521::ecdsa::{
    Signature as P521Signature, SigningKey as P521SigningKey, VerifyingKey as P521VerifyingKey,
};
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::Signature as RsaPkcs1v15Signature;
use rsa::pkcs1v15::SigningKey as RsaPkcs1v15SigningKey;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::traits::PublicKeyParts;
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};
use signature::hazmat::{PrehashSigner, RandomizedPrehashSigner};
use std::{
    collections::{HashMap, HashSet},
    ops::Range,
};
use x509_parser::prelude::FromDer;
use zeroize::Zeroizing;

use crate::c14n::canonicalize_bounded_with_xml_base_budget;
use crate::operation::{
    OperationExecutionContext, OperationNodeId, OperationNodeKind, OperationPlanError,
    OperationStage,
};

use super::builder::{SignatureBuilder, SignatureBuilderError};
use super::digest::DigestAlgorithm;
use super::mutation::{
    XmlMutationError, fill_signed_info_digest_values_at_index_with_budget,
    merge_key_info_source_at_index_with_budget, padded_base64_len_for_xml,
};
use super::parse::{
    EC_P256_OID, EC_P384_OID, EC_P521_OID, MAX_REFERENCES_PER_SIGNATURE, SignatureAlgorithm,
    XMLDSIG_NS, parse_signed_info_with_xpath_budget,
};
use super::signature::{encode_ecdsa_signature_as_der, maximum_ecdsa_der_signature_len};
use super::transforms::{
    BASE64_TRANSFORM_URI, ENVELOPED_SIGNATURE_URI, MAX_TRANSFORMS_PER_REFERENCE, Transform,
    TransformExecutionBudget, TransformOptions, XPATH_FILTER2_TRANSFORM_URI, XPATH_TRANSFORM_URI,
    XPathHereSemantics, XPathSignatureParseBudget, execute_transforms_with_dependency_nodes,
    execute_transforms_with_options_and_budget, map_c14n_resource_policy_violation,
    parse_transforms_with_budget, validate_signing_transform_policy,
};
use super::types::TransformError;
use super::uri::{
    ExternalResourceContext, UriReferenceResolver, validate_signing_reference_request,
    validate_signing_reference_uri,
};
use super::verify::parse_signature_children;
use crate::document::{DocumentParseSettings, XmlDocument, XmlDocumentError, XmlParseWorkBudget};

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
    XmlParse(#[from] crate::xml::dom::ParseError),

    /// The owned document boundary rejected a signing mutation.
    #[error("XML document error: {0}")]
    Document(#[from] XmlDocumentError),

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

impl From<OperationPlanError> for SigningDigestError {
    fn from(error: OperationPlanError) -> Self {
        Self::InvalidStructure(error.to_string())
    }
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

    /// The owned XML document boundary rejected an identity or mutation.
    #[error("XML document error: {0}")]
    Document(#[from] XmlDocumentError),

    /// Signature template generation failed.
    #[error("signature template error: {0}")]
    Template(SignatureBuilderError),
}

impl From<OperationPlanError> for SigningError {
    fn from(error: OperationPlanError) -> Self {
        SigningDigestError::from(error).into()
    }
}

impl From<SigningDigestError> for SigningError {
    fn from(error: SigningDigestError) -> Self {
        match error {
            SigningDigestError::XmlMutation(XmlMutationError::Policy(error)) => Self::Policy(error),
            SigningDigestError::Policy(error)
            | SigningDigestError::Transform(TransformError::Policy(error)) => Self::Policy(error),
            SigningDigestError::Document(error) => Self::Document(error),
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
    /// DSA public key and signature component width.
    Dsa {
        /// DER-encoded SubjectPublicKeyInfo bytes.
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
        /// Fixed XMLDSig width of each `r` and `s` component.
        component_len: usize,
    },
    /// Symmetric HMAC key metadata without exposing secret bytes.
    Hmac {
        /// Secret length used for signing policy.
        key_bits: usize,
    },
}

impl SigningPublicKeyInfo {
    /// Return DER-encoded SubjectPublicKeyInfo bytes for this public key.
    #[must_use]
    pub fn spki_der(&self) -> Option<&[u8]> {
        match self {
            Self::Rsa { spki_der, .. } | Self::Ec { spki_der, .. } | Self::Dsa { spki_der, .. } => {
                Some(spki_der)
            }
            Self::Hmac { .. } => None,
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
    policy.resources.validate_key_candidates(1)?;
    policy.check_signature_algorithm(algorithm)?;
    expected_signature_output_len(key, algorithm, policy, None).map(|_| ())
}

fn expected_signature_output_len(
    key: &dyn SigningKey,
    algorithm: SignatureAlgorithm,
    policy: &crate::policy::SigningPolicy,
    hmac_output_length_bits: Option<usize>,
) -> Result<usize, SigningError> {
    let public_key = key.public_key_info()?;
    let expected = match (algorithm, public_key) {
        (
            SignatureAlgorithm::RsaSha1
            | SignatureAlgorithm::RsaSha224
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
            SignatureAlgorithm::EcdsaSha1
            | SignatureAlgorithm::EcdsaSha224
            | SignatureAlgorithm::EcdsaSha256
            | SignatureAlgorithm::EcdsaSha384
            | SignatureAlgorithm::EcdsaSha512,
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
            algorithm @ (SignatureAlgorithm::DsaSha1 | SignatureAlgorithm::DsaSha256),
            SigningPublicKeyInfo::Dsa {
                modulus_bits,
                component_len,
                ..
            },
        ) => {
            policy.dsa_keys.validate_modulus_bits(modulus_bits)?;
            let required_component_len = algorithm
                .dsa_component_len()
                .expect("DSA algorithm matched above");
            if component_len != required_component_len {
                return Err(crate::policy::PolicyViolation::InvalidKeyMaterial {
                    operation: "signing",
                    key_type: "DSA",
                    reason: match algorithm {
                        SignatureAlgorithm::DsaSha1 => "DSA-SHA1 requires a 160-bit q parameter",
                        SignatureAlgorithm::DsaSha256 => {
                            "DSA-SHA256 requires a 256-bit q parameter"
                        }
                        _ => unreachable!("DSA algorithm matched above"),
                    },
                }
                .into());
            }
            component_len.saturating_mul(2)
        }
        (
            SignatureAlgorithm::HmacSha1
            | SignatureAlgorithm::HmacSha224
            | SignatureAlgorithm::HmacSha256
            | SignatureAlgorithm::HmacSha384
            | SignatureAlgorithm::HmacSha512,
            SigningPublicKeyInfo::Hmac { key_bits },
        ) => {
            policy.hmac.validate_key_bits(key_bits)?;
            let output_bits = hmac_output_length_bits.unwrap_or(
                algorithm
                    .hmac_output_bits()
                    .ok_or(SigningKeyError::InvalidPublicKeyInfo)?,
            );
            policy.hmac.validate_output(algorithm, output_bits)?;
            output_bits / 8
        }
        (
            SignatureAlgorithm::RsaSha1
            | SignatureAlgorithm::RsaSha224
            | SignatureAlgorithm::RsaSha256
            | SignatureAlgorithm::RsaSha384
            | SignatureAlgorithm::RsaSha512,
            SigningPublicKeyInfo::Ec { .. }
            | SigningPublicKeyInfo::Dsa { .. }
            | SigningPublicKeyInfo::Hmac { .. },
        )
        | (
            SignatureAlgorithm::EcdsaSha1
            | SignatureAlgorithm::EcdsaSha224
            | SignatureAlgorithm::EcdsaSha256
            | SignatureAlgorithm::EcdsaSha384
            | SignatureAlgorithm::EcdsaSha512,
            SigningPublicKeyInfo::Rsa { .. }
            | SigningPublicKeyInfo::Dsa { .. }
            | SigningPublicKeyInfo::Hmac { .. },
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

    /// Write key metadata through the cryptographic provider selected for the operation.
    ///
    /// Writers that do not perform cryptographic operations can rely on this
    /// default. Digest- or signature-producing writers must override it.
    fn write_key_info_with_provider(
        &self,
        signing_key: &dyn SigningKey,
        provider: &dyn crate::provider::CryptoProvider,
    ) -> Result<String, KeyInfoWriteError> {
        let _ = provider;
        self.write_key_info(signing_key)
    }
}

/// Errors while preparing XMLDSig signing `<KeyInfo>` output.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KeyInfoWriteError {
    /// The selected provider could not produce cryptographic key metadata.
    #[error("cryptographic provider error: {0}")]
    Provider(#[from] crate::provider::ProviderError),

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

    /// Symmetric signing keys cannot expose an asymmetric public key value.
    #[error("signing key has no DER-encodable public key")]
    MissingPublicKey,

    /// The selected writer cannot represent this public-key family.
    #[error("signing key cannot be represented as XMLDSig KeyValue")]
    UnsupportedKeyValue,

    /// The configured certificate does not contain the signing key's public key.
    #[error("X.509 certificate public key does not match signing key")]
    CertificateKeyMismatch,
}

/// Writes the signing key's SPKI as XMLDSig 1.1 `DEREncodedKeyValue`.
#[derive(Debug, Clone, Copy, Default)]
pub struct DerEncodedKeyValueInfoWriter;

impl KeyInfoWriter for DerEncodedKeyValueInfoWriter {
    fn write_key_info(&self, signing_key: &dyn SigningKey) -> Result<String, KeyInfoWriteError> {
        let public_key = signing_key.public_key_info()?;
        let spki_der = public_key
            .spki_der()
            .ok_or(KeyInfoWriteError::MissingPublicKey)?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(spki_der);
        Ok(format!(
            "<dsig11:DEREncodedKeyValue xmlns:dsig11=\"http://www.w3.org/2009/xmldsig11#\">{encoded}</dsig11:DEREncodedKeyValue>"
        ))
    }
}

/// Writes RSA, DSA, or XMLDSig 1.1 EC public parameters as `KeyValue`.
#[derive(Debug, Clone, Copy, Default)]
pub struct KeyValueInfoWriter;

impl KeyInfoWriter for KeyValueInfoWriter {
    fn write_key_info(&self, signing_key: &dyn SigningKey) -> Result<String, KeyInfoWriteError> {
        let encode = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
        match signing_key.public_key_info()? {
            SigningPublicKeyInfo::Rsa {
                modulus, exponent, ..
            } => Ok(format!(
                "<ds:KeyValue xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:RSAKeyValue><ds:Modulus>{}</ds:Modulus><ds:Exponent>{}</ds:Exponent></ds:RSAKeyValue></ds:KeyValue>",
                encode(&modulus),
                encode(&exponent)
            )),
            SigningPublicKeyInfo::Ec {
                curve_oid,
                public_key,
                ..
            } => Ok(format!(
                "<ds:KeyValue xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><dsig11:ECKeyValue xmlns:dsig11=\"http://www.w3.org/2009/xmldsig11#\"><dsig11:NamedCurve URI=\"urn:oid:{curve_oid}\"/><dsig11:PublicKey>{}</dsig11:PublicKey></dsig11:ECKeyValue></ds:KeyValue>",
                encode(&public_key)
            )),
            SigningPublicKeyInfo::Dsa { p, q, g, y, .. } => Ok(format!(
                "<ds:KeyValue xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:DSAKeyValue><ds:P>{}</ds:P><ds:Q>{}</ds:Q><ds:G>{}</ds:G><ds:Y>{}</ds:Y></ds:DSAKeyValue></ds:KeyValue>",
                encode(&p),
                encode(&q),
                encode(&g),
                encode(&y)
            )),
            SigningPublicKeyInfo::Hmac { .. } => Err(KeyInfoWriteError::UnsupportedKeyValue),
        }
    }
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
        if signing_public_key.spki_der() != Some(certificate.public_key().raw) {
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

/// Writes an XMLDSig 1.1 `X509Digest` selector for the signing certificate.
pub struct X509DigestKeyInfoWriter {
    certificate_der: Vec<u8>,
    certificate_spki_der: Vec<u8>,
    digest_algorithm: DigestAlgorithm,
}

impl X509DigestKeyInfoWriter {
    /// Validate and retain a DER certificate and selector digest algorithm.
    pub fn from_der(
        certificate_der: &[u8],
        digest_algorithm: DigestAlgorithm,
    ) -> Result<Self, KeyInfoWriteError> {
        let (rest, certificate) =
            x509_parser::certificate::X509Certificate::from_der(certificate_der)
                .map_err(|_| KeyInfoWriteError::InvalidCertificateDer)?;
        if !rest.is_empty() {
            return Err(KeyInfoWriteError::InvalidCertificateDer);
        }
        Ok(Self {
            certificate_der: certificate_der.to_vec(),
            certificate_spki_der: certificate.public_key().raw.to_vec(),
            digest_algorithm,
        })
    }

    /// Parse a PEM certificate and retain its selector digest algorithm.
    pub fn from_pem(
        certificate_pem: &str,
        digest_algorithm: DigestAlgorithm,
    ) -> Result<Self, KeyInfoWriteError> {
        Self::from_der(&parse_certificate_pem(certificate_pem)?, digest_algorithm)
    }
}

impl KeyInfoWriter for X509DigestKeyInfoWriter {
    fn write_key_info(&self, signing_key: &dyn SigningKey) -> Result<String, KeyInfoWriteError> {
        self.write_key_info_with_provider(signing_key, crate::provider::default_provider())
    }

    fn write_key_info_with_provider(
        &self,
        signing_key: &dyn SigningKey,
        provider: &dyn crate::provider::CryptoProvider,
    ) -> Result<String, KeyInfoWriteError> {
        if signing_key.public_key_info()?.spki_der() != Some(self.certificate_spki_der.as_slice()) {
            return Err(KeyInfoWriteError::CertificateKeyMismatch);
        }
        let digest = super::compute_digest_with_provider(
            provider,
            self.digest_algorithm,
            &self.certificate_der,
        )?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(digest);
        Ok(format!(
            "<ds:X509Data xmlns:ds=\"{XMLDSIG_NS}\"><dsig11:X509Digest xmlns:dsig11=\"http://www.w3.org/2009/xmldsig11#\" Algorithm=\"{}\">{encoded}</dsig11:X509Digest></ds:X509Data>",
            self.digest_algorithm.uri()
        ))
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

    /// Decrypt and parse a password-protected PKCS#8 `ENCRYPTED PRIVATE KEY` PEM block.
    pub fn from_pkcs8_encrypted_pem(
        private_key_pem: &str,
        password: impl AsRef<[u8]>,
    ) -> Result<Self, SigningKeyError> {
        let key = RsaPrivateKey::from_pkcs8_encrypted_pem(private_key_pem, password)
            .map_err(|_| SigningKeyError::InvalidKeyDer)?;
        Ok(Self { key })
    }

    /// Decrypt and parse password-protected PKCS#8 DER.
    pub fn from_pkcs8_encrypted_der(
        private_key_der: &[u8],
        password: impl AsRef<[u8]>,
    ) -> Result<Self, SigningKeyError> {
        let key = RsaPrivateKey::from_pkcs8_encrypted_der(private_key_der, password)
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
            SignatureAlgorithm::RsaSha1 => sign_rsa_pkcs1v15_with_rng(
                provider,
                RsaPkcs1v15SigningKey::<Sha1>::new(self.key.clone()),
                canonical_signed_info,
            ),
            SignatureAlgorithm::RsaSha224 => sign_rsa_pkcs1v15_with_rng(
                provider,
                RsaPkcs1v15SigningKey::<Sha224>::new(self.key.clone()),
                canonical_signed_info,
            ),
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

/// Symmetric key for XMLDSig HMAC signing.
///
/// Owned secret bytes are zeroized when the key is dropped.
pub struct HmacSigningKey {
    secret: Zeroizing<Vec<u8>>,
}

impl HmacSigningKey {
    /// Construct a signing key from non-empty caller-owned secret bytes.
    pub fn new(secret: impl Into<Vec<u8>>) -> Result<Self, SigningKeyError> {
        let secret = secret.into();
        if secret.is_empty() {
            return Err(SigningKeyError::InvalidKeyDer);
        }
        Ok(Self {
            secret: Zeroizing::new(secret),
        })
    }
}

impl SigningKey for HmacSigningKey {
    fn sign(
        &self,
        algorithm: SignatureAlgorithm,
        canonical_signed_info: &[u8],
    ) -> Result<Vec<u8>, SigningKeyError> {
        macro_rules! sign_hmac {
            ($digest:ty) => {{
                let mut mac = hmac::Hmac::<$digest>::new_from_slice(&self.secret)
                    .map_err(|_| SigningKeyError::InvalidKeyDer)?;
                mac.update(canonical_signed_info);
                mac.finalize().into_bytes().to_vec()
            }};
        }
        Ok(match algorithm {
            SignatureAlgorithm::HmacSha1 => sign_hmac!(sha1::Sha1),
            SignatureAlgorithm::HmacSha224 => sign_hmac!(sha2::Sha224),
            SignatureAlgorithm::HmacSha256 => sign_hmac!(sha2::Sha256),
            SignatureAlgorithm::HmacSha384 => sign_hmac!(sha2::Sha384),
            SignatureAlgorithm::HmacSha512 => sign_hmac!(sha2::Sha512),
            _ => {
                return Err(SigningKeyError::UnsupportedAlgorithm {
                    uri: algorithm.uri().to_owned(),
                });
            }
        })
    }

    fn public_key_info(&self) -> Result<SigningPublicKeyInfo, SigningKeyError> {
        Ok(SigningPublicKeyInfo::Hmac {
            key_bits: self.secret.len().saturating_mul(8),
        })
    }
}

/// DSA private key for XMLDSig 1.1 signing.
pub struct DsaSigningKey {
    key: dsa::SigningKey,
}

impl DsaSigningKey {
    /// Parse an unencrypted PKCS#8 `PRIVATE KEY` PEM block.
    pub fn from_pkcs8_pem(private_key_pem: &str) -> Result<Self, SigningKeyError> {
        let private_key_der = parse_private_key_pem(private_key_pem)?;
        Self::from_pkcs8_der(&private_key_der)
    }

    /// Parse unencrypted PKCS#8 private key DER.
    pub fn from_pkcs8_der(private_key_der: &[u8]) -> Result<Self, SigningKeyError> {
        let key = dsa::SigningKey::from_pkcs8_der(private_key_der)
            .map_err(|_| SigningKeyError::InvalidKeyDer)?;
        Ok(Self { key })
    }

    /// Decrypt and parse a password-protected PKCS#8 `ENCRYPTED PRIVATE KEY` PEM block.
    pub fn from_pkcs8_encrypted_pem(
        private_key_pem: &str,
        password: impl AsRef<[u8]>,
    ) -> Result<Self, SigningKeyError> {
        let key = dsa::SigningKey::from_pkcs8_encrypted_pem(private_key_pem, password)
            .map_err(|_| SigningKeyError::InvalidKeyDer)?;
        Ok(Self { key })
    }

    /// Decrypt and parse password-protected PKCS#8 DER.
    pub fn from_pkcs8_encrypted_der(
        private_key_der: &[u8],
        password: impl AsRef<[u8]>,
    ) -> Result<Self, SigningKeyError> {
        let key = dsa::SigningKey::from_pkcs8_encrypted_der(private_key_der, password)
            .map_err(|_| SigningKeyError::InvalidKeyDer)?;
        Ok(Self { key })
    }
}

impl SigningKey for DsaSigningKey {
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
            SignatureAlgorithm::DsaSha1 => DigestAlgorithm::Sha1,
            SignatureAlgorithm::DsaSha256 => DigestAlgorithm::Sha256,
            _ => {
                return Err(SigningKeyError::UnsupportedAlgorithm {
                    uri: algorithm.uri().to_owned(),
                });
            }
        };
        let component_len =
            usize::try_from(self.key.verifying_key().components().q().bits_vartime())
                .map_err(|_| SigningKeyError::InvalidPublicKeyInfo)?
                .div_ceil(8);
        if algorithm.dsa_component_len() != Some(component_len) {
            return Err(SigningKeyError::InvalidPublicKeyInfo);
        }
        let digest =
            super::compute_digest_with_provider(provider, digest_algorithm, canonical_signed_info)?;
        let mut rng = crate::provider::ProviderRng(provider);
        let signature: dsa::Signature = self
            .key
            .sign_prehash_with_rng(&mut rng, &digest)
            .map_err(|_| SigningKeyError::SigningFailed)?;
        let mut output = Vec::with_capacity(component_len.saturating_mul(2));
        for component in [signature.r(), signature.s()] {
            let bytes = component.to_be_bytes_trimmed_vartime();
            if bytes.len() > component_len {
                return Err(SigningKeyError::SigningFailed);
            }
            output.resize(output.len() + component_len - bytes.len(), 0);
            output.extend_from_slice(bytes.as_ref());
        }
        Ok(output)
    }

    fn public_key_info(&self) -> Result<SigningPublicKeyInfo, SigningKeyError> {
        let verifying_key = self.key.verifying_key();
        let spki_der = verifying_key
            .to_public_key_der()
            .map(|doc| doc.as_bytes().to_vec())
            .map_err(|_| SigningKeyError::PublicKeyEncodingFailed)?;
        let modulus_bits = usize::try_from(verifying_key.components().p().bits_vartime())
            .map_err(|_| SigningKeyError::InvalidPublicKeyInfo)?;
        let component_len = usize::try_from(verifying_key.components().q().bits_vartime())
            .map_err(|_| SigningKeyError::InvalidPublicKeyInfo)?
            .div_ceil(8);
        let components = verifying_key.components();
        Ok(SigningPublicKeyInfo::Dsa {
            spki_der,
            p: components.p().to_be_bytes_trimmed_vartime().to_vec(),
            q: components.q().to_be_bytes_trimmed_vartime().to_vec(),
            g: components.g().to_be_bytes_trimmed_vartime().to_vec(),
            y: verifying_key.y().to_be_bytes_trimmed_vartime().to_vec(),
            modulus_bits,
            component_len,
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

fn ecdsa_digest_algorithm(
    algorithm: SignatureAlgorithm,
) -> Result<DigestAlgorithm, SigningKeyError> {
    match algorithm {
        SignatureAlgorithm::EcdsaSha1 => Ok(DigestAlgorithm::Sha1),
        SignatureAlgorithm::EcdsaSha224 => Ok(DigestAlgorithm::Sha224),
        SignatureAlgorithm::EcdsaSha256 => Ok(DigestAlgorithm::Sha256),
        SignatureAlgorithm::EcdsaSha384 => Ok(DigestAlgorithm::Sha384),
        SignatureAlgorithm::EcdsaSha512 => Ok(DigestAlgorithm::Sha512),
        _ => Err(SigningKeyError::UnsupportedAlgorithm {
            uri: algorithm.uri().to_owned(),
        }),
    }
}

fn sign_ecdsa_with_provider<S, K>(
    key: &K,
    provider: &dyn crate::provider::CryptoProvider,
    algorithm: SignatureAlgorithm,
    canonical_signed_info: &[u8],
) -> Result<Vec<u8>, SigningKeyError>
where
    K: PrehashSigner<S>,
    S: SignatureEncoding,
{
    let digest_algorithm = ecdsa_digest_algorithm(algorithm)?;
    let prehash =
        super::compute_digest_with_provider(provider, digest_algorithm, canonical_signed_info)?;
    let signature = key
        .sign_prehash(&prehash)
        .map_err(|_| SigningKeyError::SigningFailed)?;
    Ok(signature.to_vec())
}

trait EcdsaPublicKeyEncoding {
    fn spki_der(&self) -> Result<Vec<u8>, SigningKeyError>;
    fn uncompressed_sec1(&self) -> Vec<u8>;
}

macro_rules! impl_ecdsa_public_key_encoding {
    ($key:ty) => {
        impl EcdsaPublicKeyEncoding for $key {
            fn spki_der(&self) -> Result<Vec<u8>, SigningKeyError> {
                self.to_public_key_der()
                    .map(|document| document.as_bytes().to_vec())
                    .map_err(|_| SigningKeyError::PublicKeyEncodingFailed)
            }

            fn uncompressed_sec1(&self) -> Vec<u8> {
                self.to_sec1_point(false).as_bytes().to_vec()
            }
        }
    };
}

impl_ecdsa_public_key_encoding!(P256VerifyingKey);
impl_ecdsa_public_key_encoding!(P384VerifyingKey);
impl_ecdsa_public_key_encoding!(P521VerifyingKey);

fn ecdsa_public_key_info(
    key: &impl EcdsaPublicKeyEncoding,
    curve_oid: &'static str,
) -> Result<SigningPublicKeyInfo, SigningKeyError> {
    Ok(SigningPublicKeyInfo::Ec {
        spki_der: key.spki_der()?,
        curve_oid,
        public_key: key.uncompressed_sec1(),
    })
}

/// ECDSA P-256 private key for XMLDSig signing.
pub struct EcdsaP256SigningKey {
    key: P256SigningKey,
}

impl EcdsaP256SigningKey {
    /// Parse an unencrypted SEC1 `EC PRIVATE KEY` PEM block.
    pub fn from_sec1_pem(private_key_pem: &str) -> Result<Self, SigningKeyError> {
        let key = p256::SecretKey::from_sec1_pem(private_key_pem)
            .map(P256SigningKey::from)
            .map_err(|_| SigningKeyError::InvalidKeyDer)?;
        Ok(Self { key })
    }

    /// Parse unencrypted SEC1 `ECPrivateKey` DER.
    pub fn from_sec1_der(private_key_der: &[u8]) -> Result<Self, SigningKeyError> {
        let key = p256::SecretKey::from_sec1_der(private_key_der)
            .map(P256SigningKey::from)
            .map_err(|_| SigningKeyError::InvalidKeyDer)?;
        Ok(Self { key })
    }

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

    /// Decrypt and parse a password-protected PKCS#8 `ENCRYPTED PRIVATE KEY` PEM block.
    pub fn from_pkcs8_encrypted_pem(
        private_key_pem: &str,
        password: impl AsRef<[u8]>,
    ) -> Result<Self, SigningKeyError> {
        let key = P256SigningKey::from_pkcs8_encrypted_pem(private_key_pem, password)
            .map_err(|_| SigningKeyError::InvalidKeyDer)?;
        Ok(Self { key })
    }

    /// Decrypt and parse password-protected PKCS#8 DER.
    pub fn from_pkcs8_encrypted_der(
        private_key_der: &[u8],
        password: impl AsRef<[u8]>,
    ) -> Result<Self, SigningKeyError> {
        let key = P256SigningKey::from_pkcs8_encrypted_der(private_key_der, password)
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
        sign_ecdsa_with_provider::<P256Signature, _>(
            &self.key,
            provider,
            algorithm,
            canonical_signed_info,
        )
    }

    fn public_key_info(&self) -> Result<SigningPublicKeyInfo, SigningKeyError> {
        ecdsa_public_key_info(self.key.verifying_key(), EC_P256_OID)
    }
}

/// ECDSA P-384 private key for XMLDSig signing.
pub struct EcdsaP384SigningKey {
    key: P384SigningKey,
}

impl EcdsaP384SigningKey {
    /// Parse an unencrypted SEC1 `EC PRIVATE KEY` PEM block.
    pub fn from_sec1_pem(private_key_pem: &str) -> Result<Self, SigningKeyError> {
        let key = p384::SecretKey::from_sec1_pem(private_key_pem)
            .map(P384SigningKey::from)
            .map_err(|_| SigningKeyError::InvalidKeyDer)?;
        Ok(Self { key })
    }

    /// Parse unencrypted SEC1 `ECPrivateKey` DER.
    pub fn from_sec1_der(private_key_der: &[u8]) -> Result<Self, SigningKeyError> {
        let key = p384::SecretKey::from_sec1_der(private_key_der)
            .map(P384SigningKey::from)
            .map_err(|_| SigningKeyError::InvalidKeyDer)?;
        Ok(Self { key })
    }

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

    /// Decrypt and parse a password-protected PKCS#8 `ENCRYPTED PRIVATE KEY` PEM block.
    pub fn from_pkcs8_encrypted_pem(
        private_key_pem: &str,
        password: impl AsRef<[u8]>,
    ) -> Result<Self, SigningKeyError> {
        let key = P384SigningKey::from_pkcs8_encrypted_pem(private_key_pem, password)
            .map_err(|_| SigningKeyError::InvalidKeyDer)?;
        Ok(Self { key })
    }

    /// Decrypt and parse password-protected PKCS#8 DER.
    pub fn from_pkcs8_encrypted_der(
        private_key_der: &[u8],
        password: impl AsRef<[u8]>,
    ) -> Result<Self, SigningKeyError> {
        let key = P384SigningKey::from_pkcs8_encrypted_der(private_key_der, password)
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
        sign_ecdsa_with_provider::<P384Signature, _>(
            &self.key,
            provider,
            algorithm,
            canonical_signed_info,
        )
    }

    fn public_key_info(&self) -> Result<SigningPublicKeyInfo, SigningKeyError> {
        ecdsa_public_key_info(self.key.verifying_key(), EC_P384_OID)
    }
}

/// ECDSA P-521 private key for XMLDSig signing.
pub struct EcdsaP521SigningKey {
    key: P521SigningKey,
}

impl EcdsaP521SigningKey {
    /// Parse an unencrypted SEC1 `EC PRIVATE KEY` PEM block.
    pub fn from_sec1_pem(private_key_pem: &str) -> Result<Self, SigningKeyError> {
        let key = p521::SecretKey::from_sec1_pem(private_key_pem)
            .map(P521SigningKey::from)
            .map_err(|_| SigningKeyError::InvalidKeyDer)?;
        Ok(Self { key })
    }

    /// Parse unencrypted SEC1 `ECPrivateKey` DER.
    pub fn from_sec1_der(private_key_der: &[u8]) -> Result<Self, SigningKeyError> {
        let key = p521::SecretKey::from_sec1_der(private_key_der)
            .map(P521SigningKey::from)
            .map_err(|_| SigningKeyError::InvalidKeyDer)?;
        Ok(Self { key })
    }

    /// Parse an unencrypted PKCS#8 `PRIVATE KEY` PEM block.
    pub fn from_pkcs8_pem(private_key_pem: &str) -> Result<Self, SigningKeyError> {
        let private_key_der = parse_private_key_pem(private_key_pem)?;
        Self::from_pkcs8_der(&private_key_der)
    }

    /// Parse unencrypted PKCS#8 private key DER.
    pub fn from_pkcs8_der(private_key_der: &[u8]) -> Result<Self, SigningKeyError> {
        let key = P521SigningKey::from_pkcs8_der(private_key_der)
            .map_err(|_| SigningKeyError::InvalidKeyDer)?;
        Ok(Self { key })
    }

    /// Decrypt and parse a password-protected PKCS#8 `ENCRYPTED PRIVATE KEY` PEM block.
    pub fn from_pkcs8_encrypted_pem(
        private_key_pem: &str,
        password: impl AsRef<[u8]>,
    ) -> Result<Self, SigningKeyError> {
        let key = P521SigningKey::from_pkcs8_encrypted_pem(private_key_pem, password)
            .map_err(|_| SigningKeyError::InvalidKeyDer)?;
        Ok(Self { key })
    }

    /// Decrypt and parse password-protected PKCS#8 DER.
    pub fn from_pkcs8_encrypted_der(
        private_key_der: &[u8],
        password: impl AsRef<[u8]>,
    ) -> Result<Self, SigningKeyError> {
        let key = P521SigningKey::from_pkcs8_encrypted_der(private_key_der, password)
            .map_err(|_| SigningKeyError::InvalidKeyDer)?;
        Ok(Self { key })
    }
}

impl SigningKey for EcdsaP521SigningKey {
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
        sign_ecdsa_with_provider::<P521Signature, _>(
            &self.key,
            provider,
            algorithm,
            canonical_signed_info,
        )
    }

    fn public_key_info(&self) -> Result<SigningPublicKeyInfo, SigningKeyError> {
        ecdsa_public_key_info(self.key.verifying_key(), EC_P521_OID)
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
    external_resources: Option<&'a HashMap<String, Vec<u8>>>,
    template_selection: SignatureTemplateSelection,
    policy: crate::policy::SigningPolicy,
    provider: &'a dyn crate::provider::CryptoProvider,
    xml_backend: crate::XmlBackend,
}

impl<'a> SignContext<'a> {
    /// Create a signing context using the supplied private key.
    pub fn new(signing_key: &'a dyn SigningKey) -> Self {
        Self {
            signing_key,
            key_info_writer: None,
            start_node_id: None,
            id_attributes: &[],
            external_resources: None,
            template_selection: SignatureTemplateSelection::default(),
            policy: crate::policy::SigningPolicy::default(),
            provider: crate::provider::default_provider(),
            xml_backend: crate::XmlBackend::default(),
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

    /// Select the compiled XML parser backend for this signing operation.
    #[must_use]
    pub fn xml_backend(mut self, backend: crate::XmlBackend) -> Self {
        self.xml_backend = backend;
        self
    }

    fn document_parse_settings(&self) -> DocumentParseSettings {
        DocumentParseSettings::from_policy(&self.policy.xml, &self.policy.resources)
            .with_backend(self.xml_backend)
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

    /// Provide detached Reference payloads explicitly.
    ///
    /// The map is the complete external I/O boundary: signing never performs
    /// network or filesystem access. External URI classes must also be enabled
    /// by [`crate::policy::SigningPolicy::uris`]. Keys are normalized RFC 3986
    /// URI identities with dot segments removed and query/fragment retained.
    #[must_use]
    pub fn external_resources(mut self, resources: &'a HashMap<String, Vec<u8>>) -> Self {
        self.external_resources = Some(resources);
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
        let mut budgets = SigningOperationBudgets::from_resources_with_backend(
            &self.policy.resources,
            self.xml_backend,
        );
        let mut document = XmlDocument::parse_with_settings_and_budget(
            xml.to_owned(),
            self.document_parse_settings(),
            budgets.transforms.xml_parse_work(),
        )
        .map_err(|error| match owned_document_policy_violation(error) {
            Ok(error) => SigningError::Policy(error),
            Err(XmlDocumentError::Parse(error)) => {
                SigningError::Digest(SigningDigestError::XmlParse(error))
            }
            Err(error) => SigningError::Document(error),
        })?;
        self.validate_owned_document_input(&document)?;
        self.sign_document_in_place(&mut document, &mut budgets)?;
        Ok(document.into_xml())
    }

    /// Sign a template in a reusable owned document.
    ///
    /// Signing is atomic: failures leave both serialization and generation
    /// unchanged. Success commits the complete signature as one generation.
    pub fn sign_document(&self, document: &mut XmlDocument) -> Result<(), SigningError> {
        self.validate_owned_document_input(document)?;
        let mut budgets = SigningOperationBudgets::from_resources_with_backend(
            &self.policy.resources,
            self.xml_backend,
        );
        let mut staged = document
            .staged_copy_with_budget(
                self.document_parse_settings(),
                budgets.transforms.xml_parse_work(),
            )
            .map_err(map_owned_document_mutation_error)?;
        self.sign_document_in_place(&mut staged, &mut budgets)?;
        commit_signed_staged(document, staged, &self.policy)
    }

    fn sign_document_in_place(
        &self,
        document: &mut XmlDocument,
        budgets: &mut SigningOperationBudgets,
    ) -> Result<(), SigningError> {
        let target_signature = document.with_view(|view| {
            signing_signature_index(
                view.document(),
                self.start_node_id,
                self.id_attributes,
                self.template_selection,
            )
        })?;
        self.policy.resources.validate_key_candidates(1)?;
        self.sign_template_at_index_with_budgets(document, target_signature, budgets)?;
        Ok(())
    }

    fn validate_owned_document_input(&self, document: &XmlDocument) -> Result<(), SigningError> {
        self.policy.validate()?;
        document.validate_operation_policy(&self.policy.xml, &self.policy.resources)?;
        Ok(())
    }

    fn sign_template_at_index_with_budgets(
        &self,
        document: &mut XmlDocument,
        target_signature: usize,
        budgets: &mut SigningOperationBudgets,
    ) -> Result<(), SigningError> {
        document.with_view(|view| {
            let signature = find_signing_signature_node(
                view.document(),
                SigningSignatureTarget::Index(target_signature),
            )?;
            parse_signature_children(signature)
                .map_err(|error| SigningDigestError::InvalidStructure(error.to_string()))?;
            validate_signing_signed_info_methods(signature, &self.policy)?;
            Ok::<_, SigningError>(())
        })?;
        let transform_options = TransformOptions::default()
            .allow_internal_dtd(self.policy.xml.allow_internal_dtd)
            .xpath_here_semantics(self.policy.transforms.xpath_here_semantics);
        let external_resources = ExternalResourceContext::new(
            self.external_resources,
            self.policy.resources.max_external_resource_bytes,
            self.policy.resources.max_external_resource_total_bytes,
        );
        let binding = (document.identity(), document.generation());
        let mut operation =
            OperationExecutionContext::new(self.policy.clone(), &mut *budgets, Some(binding));
        let key_info = operation.add_node(
            OperationNodeKind::Key { index: 0 },
            OperationStage::Resolve,
            None,
        );
        operation.compile()?;
        let key_info_content = operation.run(key_info, || {
            let Some(writer) = self.key_info_writer else {
                return Ok::<_, SigningError>(None);
            };
            let key_info_content =
                writer.write_key_info_with_provider(self.signing_key, self.provider)?;
            // Writer output is a separate untrusted XML input. Bound it before
            // namespace wrapping or parsing, then bound the merged document below.
            self.policy
                .resources
                .validate_xml_document_len(key_info_content.len())?;
            Ok(Some(key_info_content))
        })?;
        operation.extend();
        // Validate reference inputs and build the normalization candidate only after
        // independent key output has passed its own byte boundary. The execution pass
        // revalidates the resulting document defensively after controlled mutations.
        let c14n_candidate = materialize_second_edition_c14n11_candidate(
            document,
            target_signature,
            &self.policy,
            external_resources.is_configured(),
        )?;
        let normalization = if let Some(candidate) = c14n_candidate {
            let mutation =
                operation.add_node(OperationNodeKind::Mutation, OperationStage::Resolve, None);
            operation.add_dependency(mutation, key_info)?;
            operation.compile()?;
            operation.run_document_transition(mutation, document, |document, budgets| {
                document
                    .replace_serialized_with_settings(
                        candidate,
                        self.document_parse_settings(),
                        Some(budgets.transforms.xml_parse_work()),
                    )
                    .map_err(map_owned_document_mutation_error)
            })?;
            operation.extend();
            Some(mutation)
        } else {
            None
        };
        let setup_gate = normalization.unwrap_or(key_info);
        let setup_gate = if let Some(key_info_content) = key_info_content {
            let mutation =
                operation.add_node(OperationNodeKind::Mutation, OperationStage::Resolve, None);
            operation.add_dependency(mutation, setup_gate)?;
            operation.compile()?;
            operation.run_document_transition(mutation, document, |document, budgets| {
                // The mutation helper checks its namespace wrapper and every projected
                // replacement against policy before allocating the committed candidate.
                let populated = merge_key_info_source_at_index_with_budget(
                    document.as_xml(),
                    &key_info_content,
                    target_signature,
                    Some(&self.policy),
                    Some(budgets.transforms.xml_parse_work()),
                )?;
                self.policy
                    .resources
                    .validate_xml_document_len(populated.len())?;
                document
                    .replace_serialized_with_settings(
                        populated,
                        self.document_parse_settings(),
                        Some(budgets.transforms.xml_parse_work()),
                    )
                    .map_err(map_owned_document_mutation_error)
            })?;
            operation.extend();
            mutation
        } else {
            setup_gate
        };
        let plan_nodes = fill_reference_digest_values_in_dependency_order_with_operation(
            document,
            transform_options,
            self.provider,
            &mut operation,
            SigningReferenceRequest {
                target_signature,
                id_attributes: self.id_attributes,
                external_resources: &external_resources,
            },
            Some(setup_gate),
        )?;
        self.policy
            .resources
            .validate_xml_document_len(document.as_xml().len())?;
        let (algorithm, hmac_output_length_bits, canonical_signed_info) = operation
            .run_with_budgets(plan_nodes.canonicalization, |budgets| {
                let result =
                    canonicalize_signed_info(document, &self.policy, budgets, target_signature)?;
                budgets
                    .transforms
                    .charge_c14n_output(result.2.len())
                    .map_err(SigningDigestError::Transform)?;
                Ok::<_, SigningError>(result)
            })?;
        self.policy.check_signature_algorithm(algorithm)?;
        let expected_signature_len = expected_signature_output_len(
            self.signing_key,
            algorithm,
            &self.policy,
            hmac_output_length_bits,
        )?;
        let projected_signature_len = projected_signature_output_len(
            algorithm,
            expected_signature_len,
            self.policy.ecdsa_signature_value_encoding,
        )?;
        let encoded_signature_len =
            padded_base64_len_for_xml(projected_signature_len, &self.policy)?;
        let signature_value_node = document.with_view(|view| {
            let signature = find_signing_signature_node(
                view.document(),
                SigningSignatureTarget::Index(target_signature),
            )?;
            let signature_value = find_required_child(signature, "SignatureValue")?;
            Ok::<_, SigningError>(view.node_identity(signature_value))
        })?;
        let projected_document_len = document
            .projected_content_replacement_len(signature_value_node, encoded_signature_len)?;
        self.policy
            .resources
            .validate_xml_document_len(projected_document_len)?;
        let signature_value = operation.run(plan_nodes.crypto, || {
            self.provider
                .require_capability(crate::provider::ProviderCapability::Sign(algorithm))
                .map_err(SigningKeyError::from)?;
            let mut signature_value =
                self.provider
                    .sign(self.signing_key, algorithm, &canonical_signed_info)?;
            if algorithm.hmac_output_bits().is_some() {
                signature_value.truncate(expected_signature_len);
            }
            validate_signature_output(expected_signature_len, &signature_value)?;
            Ok::<_, SigningError>(signature_value)
        })?;
        let signature_b64 = operation.run(plan_nodes.evidence, || {
            let signature_value = encode_signature_output(
                algorithm,
                signature_value,
                self.policy.ecdsa_signature_value_encoding,
            )?;
            Ok::<_, SigningError>(base64::engine::general_purpose::STANDARD.encode(signature_value))
        })?;
        operation.run_document_transition(plan_nodes.mutation, document, |document, budgets| {
            document
                .replace_base64_contents_with_budget(
                    &[(signature_value_node, signature_b64)],
                    self.document_parse_settings(),
                    budgets.transforms.xml_parse_work(),
                )
                .map_err(map_owned_document_mutation_error)
        })?;
        self.policy
            .resources
            .validate_xml_document_len(document.as_xml().len())?;
        Ok(())
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
        let mut budgets = SigningOperationBudgets::from_resources_with_backend(
            &self.policy.resources,
            self.xml_backend,
        );
        let mut document = XmlDocument::parse_with_settings_and_budget(
            xml.to_owned(),
            self.document_parse_settings(),
            budgets.transforms.xml_parse_work(),
        )
        .map_err(|error| match owned_document_policy_violation(error) {
            Ok(error) => SigningError::Policy(error),
            Err(XmlDocumentError::Parse(error)) => {
                SigningError::XmlMutation(XmlMutationError::XmlParse(error))
            }
            Err(error) => SigningError::Document(error),
        })?;
        self.validate_owned_document_input(&document)?;
        self.sign_document_with_builder_in_place(&mut document, builder, &mut budgets)?;
        Ok(document.into_xml())
    }

    /// Build, append, and sign a signature in an owned document.
    pub fn sign_document_with_builder(
        &self,
        document: &mut XmlDocument,
        builder: &SignatureBuilder,
    ) -> Result<(), SigningError> {
        self.validate_owned_document_input(document)?;
        let mut budgets = SigningOperationBudgets::from_resources_with_backend(
            &self.policy.resources,
            self.xml_backend,
        );
        let mut staged = document
            .staged_copy_with_budget(
                self.document_parse_settings(),
                budgets.transforms.xml_parse_work(),
            )
            .map_err(map_owned_document_mutation_error)?;
        self.sign_document_with_builder_in_place(&mut staged, builder, &mut budgets)?;
        commit_signed_staged(document, staged, &self.policy)
    }

    fn sign_document_with_builder_in_place(
        &self,
        document: &mut XmlDocument,
        builder: &SignatureBuilder,
        budgets: &mut SigningOperationBudgets,
    ) -> Result<(), SigningError> {
        self.policy.resources.validate_key_candidates(1)?;
        let expected_signature_len = expected_signature_output_len(
            self.signing_key,
            builder.signature_method(),
            &self.policy,
            None,
        )?;
        let template = builder.build_template_with_policy_for_signature_output(
            &self.policy,
            expected_signature_len,
            &budgets.transforms,
            &mut budgets.xpath_parse,
        )?;
        let signature_parent = if let Some(id) = self.start_node_id {
            document.with_view(|view| {
                let start = signing_start_node(view.document(), id, self.id_attributes)?;
                Ok::<_, SigningError>(view.node_identity(start))
            })?
        } else {
            document.with_view(|view| view.root_element())
        };
        let projected_document_len =
            document.projected_child_append_len(signature_parent, template.len())?;
        self.policy
            .resources
            .validate_xml_document_len(projected_document_len)?;
        let binding = (document.identity(), document.generation());
        let mut operation =
            OperationExecutionContext::new(self.policy.clone(), &mut *budgets, Some(binding));
        let mutation =
            operation.add_node(OperationNodeKind::Mutation, OperationStage::Mutation, None);
        operation.compile()?;
        operation.run_document_transition(mutation, document, |document, budgets| {
            document
                .append_generated_child_with_budget(
                    signature_parent,
                    &template,
                    self.document_parse_settings(),
                    budgets.transforms.xml_parse_work(),
                )
                .map_err(map_owned_document_mutation_error)
        })?;
        drop(operation);
        self.policy
            .resources
            .validate_xml_document_len(document.as_xml().len())?;
        let target_signature = document.with_view(|view| {
            let parent = if let Some(id) = self.start_node_id {
                signing_start_node(view.document(), id, self.id_attributes)?
            } else {
                view.document().root_element()
            };
            let appended = parent
                .children()
                .rfind(|node| node.has_tag_name((XMLDSIG_NS, "Signature")))
                .ok_or(SigningDigestError::MissingElement {
                    element: "Signature",
                })?;
            signature_index(view.document(), appended).map_err(SigningError::from)
        })?;
        self.sign_template_at_index_with_budgets(document, target_signature, budgets)?;
        Ok(())
    }
}

fn projected_signature_output_len(
    algorithm: SignatureAlgorithm,
    raw_signature_len: usize,
    encoding: crate::policy::EcdsaSignatureValueEncoding,
) -> Result<usize, SigningError> {
    if matches!(
        (algorithm, encoding),
        (
            SignatureAlgorithm::EcdsaSha1
                | SignatureAlgorithm::EcdsaSha224
                | SignatureAlgorithm::EcdsaSha256
                | SignatureAlgorithm::EcdsaSha384
                | SignatureAlgorithm::EcdsaSha512,
            crate::policy::EcdsaSignatureValueEncoding::XmlSecAsn1Der
        )
    ) {
        return maximum_ecdsa_der_signature_len(raw_signature_len)
            .ok_or(SigningKeyError::InvalidPublicKeyInfo.into());
    }
    Ok(raw_signature_len)
}

fn map_owned_document_mutation_error(error: XmlDocumentError) -> SigningError {
    match owned_document_policy_violation(error) {
        Ok(error) => SigningError::Policy(error),
        Err(error) => SigningError::Document(error),
    }
}

fn map_owned_document_digest_mutation_error(error: XmlDocumentError) -> SigningDigestError {
    match owned_document_policy_violation(error) {
        Ok(error) => SigningDigestError::Policy(error),
        Err(error) => SigningDigestError::Document(error),
    }
}

fn owned_document_policy_violation(
    error: XmlDocumentError,
) -> Result<crate::policy::PolicyViolation, XmlDocumentError> {
    match error {
        XmlDocumentError::Policy(error) => Ok(error),
        XmlDocumentError::DocumentTooLarge { maximum, actual } => {
            Ok(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XML_DOCUMENT,
                maximum,
                actual,
            })
        }
        XmlDocumentError::DocumentTooDeep { maximum, actual } => {
            Ok(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XML_DEPTH,
                maximum,
                actual,
            })
        }
        XmlDocumentError::ProjectedNodeLimit { maximum } => {
            Ok(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XML_NODES,
                maximum,
                actual: maximum.saturating_add(1),
            })
        }
        error => Err(error),
    }
}

fn encode_signature_output(
    algorithm: SignatureAlgorithm,
    signature: Vec<u8>,
    encoding: crate::policy::EcdsaSignatureValueEncoding,
) -> Result<Vec<u8>, SigningError> {
    if matches!(
        (algorithm, encoding),
        (
            SignatureAlgorithm::EcdsaSha1
                | SignatureAlgorithm::EcdsaSha224
                | SignatureAlgorithm::EcdsaSha256
                | SignatureAlgorithm::EcdsaSha384
                | SignatureAlgorithm::EcdsaSha512,
            crate::policy::EcdsaSignatureValueEncoding::XmlSecAsn1Der
        )
    ) {
        return encode_ecdsa_signature_as_der(&signature)
            .ok_or(SigningKeyError::InvalidPublicKeyInfo.into());
    }
    Ok(signature)
}

#[derive(Debug, Clone)]
struct SigningReference {
    uri: String,
    origin_node_id: NodeId,
    transforms: Vec<Transform>,
    digest_method: DigestAlgorithm,
    digest_value_range: Range<usize>,
    digest_value_node_id: NodeId,
}

struct SigningOperationBudgets {
    transforms: TransformExecutionBudget,
    xpath_parse: XPathSignatureParseBudget,
}

struct SigningReferenceRequest<'a, 'resources> {
    target_signature: usize,
    id_attributes: &'a [crate::IdAttributeRegistration],
    external_resources: &'a ExternalResourceContext<'resources>,
}

struct SigningPlanNodes {
    canonicalization: OperationNodeId,
    crypto: OperationNodeId,
    evidence: OperationNodeId,
    mutation: OperationNodeId,
}

impl SigningOperationBudgets {
    fn from_resources(resources: &crate::policy::ResourcePolicy) -> Self {
        Self {
            transforms: TransformExecutionBudget::from_resources(resources),
            xpath_parse: XPathSignatureParseBudget::from_resources(resources),
        }
    }

    fn from_resources_with_backend(
        resources: &crate::policy::ResourcePolicy,
        backend: crate::XmlBackend,
    ) -> Self {
        Self {
            transforms: TransformExecutionBudget::from_resources(resources)
                .with_xml_backend(backend),
            xpath_parse: XPathSignatureParseBudget::from_resources(resources),
        }
    }
}

impl Default for SigningOperationBudgets {
    fn default() -> Self {
        Self::from_resources(&crate::policy::ResourcePolicy::default())
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
    let resource_policy = policy
        .map(|policy| &policy.resources)
        .cloned()
        .unwrap_or_default();
    let external_resources = ExternalResourceContext::new(
        None,
        resource_policy.max_external_resource_bytes,
        resource_policy.max_external_resource_total_bytes,
    );
    let doc = parse_signing_document(
        xml,
        policy,
        execution_budget.xml_parse_work(),
        crate::XmlBackend::default(),
    )?;
    let signature = find_signing_signature_node(
        &doc,
        target_signature.map_or(SigningSignatureTarget::Last, SigningSignatureTarget::Index),
    )?;
    let signed_info = find_required_child(signature, "SignedInfo")?;
    let references = parse_signing_references(signed_info)?;
    validate_signing_references(&references, references.len(), policy, false)?;
    compute_signing_reference_digests(
        &doc,
        signature,
        references,
        transform_options,
        provider,
        execution_budget,
        SigningUriResolution {
            id_attributes,
            same_document_id_semantics: policy.map_or(
                crate::policy::SameDocumentIdSemantics::Specification,
                |policy| policy.transforms.same_document_id_semantics,
            ),
            external_resources: &external_resources,
        },
    )
}

fn fill_reference_digest_values_in_dependency_order_with_operation(
    document: &mut XmlDocument,
    transform_options: TransformOptions,
    provider: &dyn crate::provider::CryptoProvider,
    operation: &mut OperationExecutionContext<
        crate::policy::SigningPolicy,
        &mut SigningOperationBudgets,
    >,
    request: SigningReferenceRequest<'_, '_>,
    setup_gate: Option<OperationNodeId>,
) -> Result<SigningPlanNodes, SigningDigestError> {
    let policy = operation.policy().clone();
    let reference_limit = policy
        .resources
        .max_references
        .min(MAX_REFERENCES_PER_SIGNATURE);
    let process_manifests =
        policy.manifest_processing == crate::policy::ManifestProcessing::Process;
    let (signed_info_references, manifest_references) = {
        let budgets = operation.budgets_mut();
        document.with_view(|view| {
            let signature = find_signing_signature_node(
                view.document(),
                SigningSignatureTarget::Index(request.target_signature),
            )?;
            let signed_info = find_required_child(signature, "SignedInfo")?;
            let signed_info_references =
                parse_signing_references_with_budget(signed_info, &mut budgets.xpath_parse)?;
            validate_signing_references(
                &signed_info_references,
                signed_info_references.len(),
                Some(&policy),
                request.external_resources.is_configured(),
            )?;
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
            Ok::<_, SigningDigestError>((signed_info_references, manifest_references))
        })?
    };
    let total_references = signed_info_references
        .len()
        .checked_add(manifest_references.len())
        .ok_or_else(|| SigningDigestError::InvalidStructure("reference count overflow".into()))?;
    validate_signing_references(
        &manifest_references,
        total_references,
        Some(&policy),
        request.external_resources.is_configured(),
    )?;
    let placeholder = "AA==";
    // SignatureValue is the final mutable value in the signing pipeline. Give
    // it concrete character data during analysis so references that retain the
    // existing or future text cannot be mistaken for stable inputs.
    let analysis_replacements = document.with_view(|view| {
        let signature = find_signing_signature_node(
            view.document(),
            SigningSignatureTarget::Index(request.target_signature),
        )?;
        let signature_value = find_required_child(signature, "SignatureValue")?;
        let mut replacements = signed_info_references
            .iter()
            .chain(&manifest_references)
            .map(|reference| {
                (
                    view.node_identity_by_id(reference.digest_value_node_id),
                    placeholder.to_owned(),
                )
            })
            .collect::<Vec<_>>();
        replacements.push((view.node_identity(signature_value), placeholder.to_owned()));
        Ok::<_, SigningDigestError>(replacements)
    })?;
    let analysis_xml = document
        .project_base64_contents(
            &analysis_replacements,
            policy.resources.max_xml_document_bytes,
        )
        .map_err(map_owned_document_digest_mutation_error)?;
    let analysis_doc = parse_signing_document(
        &analysis_xml,
        Some(&policy),
        operation.budgets().transforms.xml_parse_work(),
        document.xml_backend(),
    )?;
    let analysis_signature = find_signing_signature_node(
        &analysis_doc,
        SigningSignatureTarget::Index(request.target_signature),
    )?;
    let analysis_signed_info = find_required_child(analysis_signature, "SignedInfo")?;
    let mut analysis_references = parse_signing_references_with_budget(
        analysis_signed_info,
        &mut operation.budgets_mut().xpath_parse,
    )?;
    if process_manifests {
        analysis_references.extend(parse_signing_manifest_references(
            analysis_signature,
            &mut operation.budgets_mut().xpath_parse,
            reference_limit.saturating_sub(signed_info_references.len()),
            reference_limit,
        )?);
    }
    let dependency_plan = reference_dependency_levels(
        &analysis_doc,
        analysis_signature,
        &analysis_references,
        transform_options,
        &operation.budgets().transforms,
        SigningUriResolution {
            id_attributes: request.id_attributes,
            same_document_id_semantics: policy.transforms.same_document_id_semantics,
            external_resources: request.external_resources,
        },
    )?;
    let (node_levels, plan_nodes) =
        compile_signing_operation_plan(operation, &dependency_plan, setup_gate)?;
    for (level, node_level) in dependency_plan.levels.into_iter().zip(node_levels) {
        operation.run_document_transition_batch_with_budgets(
            &node_level,
            document,
            |document, budgets| {
                let replacements = document.with_view(|view| {
                    let current_doc = view.document();
                    let current_signature = find_signing_signature_node(
                        current_doc,
                        SigningSignatureTarget::Index(request.target_signature),
                    )?;
                    let current_signed_info = find_required_child(current_signature, "SignedInfo")?;
                    let current_signed_info_references = parse_signing_references_with_budget(
                        current_signed_info,
                        &mut budgets.xpath_parse,
                    )?;
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
                    let mut destinations = Vec::with_capacity(level.len());
                    let mut level_references = Vec::with_capacity(level.len());
                    for index in &level {
                        let reference = if *index < signed_info_references.len() {
                            current_signed_info_references.get(*index)
                        } else {
                            current_manifest_references.get(*index - signed_info_references.len())
                        }
                        .ok_or_else(|| {
                            SigningDigestError::InvalidStructure(
                                "signing Reference set changed while filling digests".into(),
                            )
                        })?;
                        destinations.push(view.node_identity_by_id(reference.digest_value_node_id));
                        level_references.push(reference.clone());
                    }
                    let computed = compute_signing_reference_digests(
                        current_doc,
                        current_signature,
                        level_references,
                        transform_options,
                        provider,
                        &budgets.transforms,
                        SigningUriResolution {
                            id_attributes: request.id_attributes,
                            same_document_id_semantics: policy
                                .transforms
                                .same_document_id_semantics,
                            external_resources: request.external_resources,
                        },
                    )?;
                    if computed.len() != destinations.len() {
                        return Err(SigningDigestError::InvalidStructure(
                            "signing Reference set changed while computing digests".into(),
                        ));
                    }
                    Ok::<_, SigningDigestError>(
                        destinations
                            .into_iter()
                            .zip(computed)
                            .map(|(target, digest)| (target, digest.digest_value))
                            .collect::<Vec<_>>(),
                    )
                })?;
                document
                    .replace_base64_contents_with_budget(
                        &replacements,
                        DocumentParseSettings::from_policy(&policy.xml, &policy.resources)
                            .with_backend(document.xml_backend()),
                        budgets.transforms.xml_parse_work(),
                    )
                    .map_err(map_owned_document_digest_mutation_error)
            },
        )?;
    }
    Ok(plan_nodes)
}

#[cfg(test)]
fn fill_reference_digest_values_in_dependency_order(
    document: &mut XmlDocument,
    transform_options: TransformOptions,
    policy: &crate::policy::SigningPolicy,
    provider: &dyn crate::provider::CryptoProvider,
    budgets: &mut SigningOperationBudgets,
    target_signature: usize,
    id_attributes: &[crate::IdAttributeRegistration],
) -> Result<(), SigningDigestError> {
    let external_resources = ExternalResourceContext::new(
        None,
        policy.resources.max_external_resource_bytes,
        policy.resources.max_external_resource_total_bytes,
    );
    let binding = (document.identity(), document.generation());
    let mut operation = OperationExecutionContext::new(policy.clone(), budgets, Some(binding));
    fill_reference_digest_values_in_dependency_order_with_operation(
        document,
        transform_options,
        provider,
        &mut operation,
        SigningReferenceRequest {
            target_signature,
            id_attributes,
            external_resources: &external_resources,
        },
        None,
    )
    .map(|_| ())
}

struct SigningDependencyPlan {
    dependencies: Vec<HashSet<usize>>,
    levels: Vec<Vec<usize>>,
}

fn reference_dependency_levels(
    doc: &Document<'_>,
    signature: Node<'_, '_>,
    references: &[SigningReference],
    transform_options: TransformOptions,
    execution_budget: &TransformExecutionBudget,
    uri_resolution: SigningUriResolution<'_, '_>,
) -> Result<SigningDependencyPlan, SigningDigestError> {
    let resolver = uri_resolution.external_resources.bind(
        doc,
        uri_resolution.id_attributes,
        uri_resolution.same_document_id_semantics,
    );
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
            let origin = signing_reference_origin(doc, reference)?;
            let initial_data = resolver.dereference_from_with_budget(
                &reference.uri,
                origin,
                execution_budget.node_set_materialization(),
                execution_budget.xml_base_resolution(),
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
    let mut remaining_dependencies = analyses.clone();
    let mut completed = vec![false; references.len()];
    let mut levels = Vec::new();
    while completed.iter().any(|done| !done) {
        let ready = remaining_dependencies
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
        for dependency_set in &mut remaining_dependencies {
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
    Ok(SigningDependencyPlan {
        dependencies: analyses,
        levels,
    })
}

fn signing_reference_origin<'doc, 'input>(
    doc: &'doc Document<'input>,
    reference: &SigningReference,
) -> Result<Node<'doc, 'input>, SigningDigestError> {
    doc.get_node(reference.origin_node_id).ok_or_else(|| {
        SigningDigestError::InvalidStructure(
            "signing Reference origin changed while computing digests".into(),
        )
    })
}

fn compile_signing_operation_plan(
    operation: &mut OperationExecutionContext<
        crate::policy::SigningPolicy,
        &mut SigningOperationBudgets,
    >,
    dependency_plan: &SigningDependencyPlan,
    setup_gate: Option<OperationNodeId>,
) -> Result<(Vec<Vec<OperationNodeId>>, SigningPlanNodes), SigningDigestError> {
    let reference_count = dependency_plan.levels.iter().map(Vec::len).sum::<usize>();
    let mut digest_nodes = vec![None; reference_count];
    for (index, digest_slot) in digest_nodes.iter_mut().enumerate() {
        let digest_node = operation.add_node(
            OperationNodeKind::Digest { index },
            OperationStage::Digest,
            None,
        );
        if let Some(setup_gate) = setup_gate {
            operation
                .add_dependency(digest_node, setup_gate)
                .map_err(map_signing_digest_plan_error)?;
        }
        *digest_slot = Some(digest_node);
    }

    let mut node_levels = Vec::with_capacity(dependency_plan.levels.len());
    for level in &dependency_plan.levels {
        let nodes = level
            .iter()
            .map(|index| {
                digest_nodes
                    .get(*index)
                    .and_then(|node| *node)
                    .ok_or_else(|| {
                        SigningDigestError::InvalidStructure(
                            "compiled signing Reference index is unavailable".into(),
                        )
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        for (index, node) in level.iter().zip(&nodes) {
            for dependency_index in &dependency_plan.dependencies[*index] {
                let dependency = digest_nodes
                    .get(*dependency_index)
                    .and_then(|node| *node)
                    .ok_or_else(|| {
                        SigningDigestError::InvalidStructure(
                            "compiled signing dependency index is unavailable".into(),
                        )
                    })?;
                operation
                    .add_dependency(*node, dependency)
                    .map_err(map_signing_digest_plan_error)?;
            }
        }
        node_levels.push(nodes);
    }

    let canonicalization = operation.add_node(
        OperationNodeKind::Canonicalization,
        OperationStage::Canonicalization,
        None,
    );
    for digest in digest_nodes.iter().flatten() {
        operation
            .add_dependency(canonicalization, *digest)
            .map_err(map_signing_digest_plan_error)?;
    }
    let crypto = operation.add_node(OperationNodeKind::Crypto, OperationStage::Crypto, None);
    operation
        .add_dependency(crypto, canonicalization)
        .map_err(map_signing_digest_plan_error)?;
    let evidence = operation.add_node(OperationNodeKind::Evidence, OperationStage::Evidence, None);
    operation
        .add_dependency(evidence, crypto)
        .map_err(map_signing_digest_plan_error)?;
    let mutation = operation.add_node(OperationNodeKind::Mutation, OperationStage::Mutation, None);
    operation
        .add_dependency(mutation, evidence)
        .map_err(map_signing_digest_plan_error)?;
    operation.compile().map_err(map_signing_digest_plan_error)?;

    Ok((
        node_levels,
        SigningPlanNodes {
            canonicalization,
            crypto,
            evidence,
            mutation,
        },
    ))
}

fn map_signing_digest_plan_error(error: OperationPlanError) -> SigningDigestError {
    SigningDigestError::InvalidStructure(error.to_string())
}

fn commit_signed_staged(
    document: &mut XmlDocument,
    staged: XmlDocument,
    policy: &crate::policy::SigningPolicy,
) -> Result<(), SigningError> {
    let mut operation = OperationExecutionContext::new(
        policy.clone(),
        (),
        Some((document.identity(), document.generation())),
    );
    let mutation = operation.add_node(OperationNodeKind::Mutation, OperationStage::Mutation, None);
    operation.compile()?;
    operation.run_document_transition(mutation, document, |document, _| {
        document
            .commit_staged(staged)
            .map_err(map_owned_document_mutation_error)
    })
}

fn validate_signing_references(
    references: &[SigningReference],
    total_references: usize,
    policy: Option<&crate::policy::SigningPolicy>,
    has_external_resources: bool,
) -> Result<(), SigningDigestError> {
    if let Some(policy) = policy
        && total_references > policy.resources.max_references
    {
        return Err(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::SIGNATURE_REFERENCES,
            maximum: policy.resources.max_references,
            actual: total_references,
        }
        .into());
    }
    for reference in references {
        if let Some(policy) = policy {
            validate_signing_reference_uri(&reference.uri, policy)?;
            validate_signing_reference_request(&reference.uri, has_external_resources)?;
        }
        if let Some(policy) = policy
            && reference.transforms.len() > policy.resources.max_transforms_per_reference
        {
            return Err(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::REFERENCE_TRANSFORMS,
                maximum: policy.resources.max_transforms_per_reference,
                actual: reference.transforms.len(),
            }
            .into());
        }
        if let Some(policy) = policy {
            policy.check_digest_algorithm(reference.digest_method)?;
        } else if !reference.digest_method.signing_allowed() {
            return Err(SigningDigestError::SigningAlgorithmDisabled {
                uri: reference.digest_method.uri(),
            });
        }
        let initial_binary = !reference.uri.is_empty() && !reference.uri.starts_with('#');
        validate_signing_transform_policy(
            initial_binary,
            &reference.transforms,
            policy.and_then(|policy| policy.transforms.allowed_algorithms.as_ref()),
        )?;
    }
    Ok(())
}

fn validate_signing_signed_info_methods(
    signature: Node<'_, '_>,
    policy: &crate::policy::SigningPolicy,
) -> Result<(), SigningDigestError> {
    let signed_info = find_required_child(signature, "SignedInfo")?;
    let canonicalization_method =
        element_children(signed_info)
            .next()
            .ok_or(SigningDigestError::MissingElement {
                element: "CanonicalizationMethod",
            })?;
    verify_ds_element(canonicalization_method, "CanonicalizationMethod")?;
    let algorithm = required_algorithm_attr(canonicalization_method, "CanonicalizationMethod")?;
    if policy
        .transforms
        .allowed_algorithms
        .as_ref()
        .is_some_and(|allowed| !allowed.contains(algorithm))
    {
        return Err(crate::policy::PolicyViolation::Algorithm {
            operation: "SignedInfo canonicalization",
            algorithm: algorithm.to_owned(),
        }
        .into());
    }
    Ok(())
}

struct SigningUriResolution<'a, 'resources> {
    id_attributes: &'a [crate::IdAttributeRegistration],
    same_document_id_semantics: crate::policy::SameDocumentIdSemantics,
    external_resources: &'a ExternalResourceContext<'resources>,
}

fn compute_signing_reference_digests(
    doc: &Document<'_>,
    signature: Node<'_, '_>,
    references: Vec<SigningReference>,
    transform_options: TransformOptions,
    provider: &dyn crate::provider::CryptoProvider,
    execution_budget: &TransformExecutionBudget,
    uri_resolution: SigningUriResolution<'_, '_>,
) -> Result<Vec<ComputedReferenceDigest>, SigningDigestError> {
    let resolver = uri_resolution.external_resources.bind(
        doc,
        uri_resolution.id_attributes,
        uri_resolution.same_document_id_semantics,
    );
    references
        .into_iter()
        .enumerate()
        .map(|(index, reference)| {
            let origin = signing_reference_origin(doc, &reference)?;
            let initial_data = resolver.dereference_from_with_budget(
                &reference.uri,
                origin,
                execution_budget.node_set_materialization(),
                execution_budget.xml_base_resolution(),
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
/// order. As required for Second Edition generation, any reference chain that
/// still produces a node-set is first made explicit with Canonical XML 1.1.
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
    let default_policy = crate::policy::SigningPolicy::default();
    let effective_policy = policy.unwrap_or(&default_policy);
    let settings =
        DocumentParseSettings::from_policy(&effective_policy.xml, &effective_policy.resources);
    let document = XmlDocument::parse_with_settings_and_budget(
        xml.to_owned(),
        settings,
        execution_budget.xml_parse_work(),
    )
    .map_err(map_owned_document_digest_mutation_error)?;
    let target_signature = if let Some(target_signature) = target_signature {
        target_signature
    } else {
        document.with_view(|view| {
            let selected =
                find_signing_signature_node(view.document(), SigningSignatureTarget::Last)?;
            signature_index(view.document(), selected)
        })?
    };
    let materialized = materialize_second_edition_c14n11_candidate(
        &document,
        target_signature,
        effective_policy,
        false,
    )?;
    let xml = materialized.as_deref().unwrap_or(xml);
    let digest_values = compute_reference_digest_values_with_options(
        xml,
        transform_options,
        Some(effective_policy),
        provider,
        execution_budget,
        Some(target_signature),
        id_attributes,
    )?
    .into_iter()
    .map(|digest| digest.digest_value);
    Ok(fill_signed_info_digest_values_at_index_with_budget(
        xml,
        digest_values,
        target_signature,
        Some(effective_policy),
        Some(execution_budget.xml_parse_work()),
    )?)
}

fn canonicalize_signed_info(
    document: &XmlDocument,
    policy: &crate::policy::SigningPolicy,
    budgets: &mut SigningOperationBudgets,
    target_signature: usize,
) -> Result<(SignatureAlgorithm, Option<usize>, Vec<u8>), SigningError> {
    document.with_view(|view| {
        let doc = view.document();
        let signature =
            find_signing_signature_node(doc, SigningSignatureTarget::Index(target_signature))
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
            doc,
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
        Ok((
            signed_info.signature_method,
            signed_info.hmac_output_length_bits,
            canonical_signed_info,
        ))
    })
}

const SECOND_EDITION_GENERATION_C14N_URI: &str = "http://www.w3.org/2006/12/xml-c14n11";

struct SourceEdit {
    range: Range<usize>,
    replacement: String,
}

fn materialize_second_edition_c14n11_candidate(
    document: &XmlDocument,
    target_signature: usize,
    policy: &crate::policy::SigningPolicy,
    has_external_resources: bool,
) -> Result<Option<String>, SigningDigestError> {
    let edits = document.with_view(|view| {
        let signature = find_signing_signature_node(
            view.document(),
            SigningSignatureTarget::Index(target_signature),
        )?;
        let signed_info = find_required_child(signature, "SignedInfo")?;
        let mut reference_nodes = element_children(signed_info)
            .filter(|node| node.has_tag_name((XMLDSIG_NS, "Reference")))
            .collect::<Vec<_>>();
        if policy.manifest_processing == crate::policy::ManifestProcessing::Process {
            let reference_limit = policy
                .resources
                .max_references
                .min(MAX_REFERENCES_PER_SIGNATURE);
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
                    if reference_nodes.len() == reference_limit {
                        return Err(crate::policy::PolicyViolation::ResourceLimit {
                            resource: crate::policy::resource_name::SIGNATURE_REFERENCES,
                            maximum: reference_limit,
                            actual: reference_limit.saturating_add(1),
                        }
                        .into());
                    }
                    reference_nodes.push(child);
                    manifest_references += 1;
                }
                if manifest_references == 0 {
                    return Err(SigningDigestError::MissingElement {
                        element: "Reference",
                    });
                }
            }
        }
        if reference_nodes.len() > policy.resources.max_references {
            return Err(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::SIGNATURE_REFERENCES,
                maximum: policy.resources.max_references,
                actual: reference_nodes.len(),
            }
            .into());
        }

        let mut edits = Vec::new();
        for reference_node in reference_nodes {
            let structure = parse_signing_reference_structure(reference_node)?;
            validate_signing_reference_uri(structure.uri, policy)?;
            validate_signing_reference_request(structure.uri, has_external_resources)?;
            let digest_uri = required_algorithm_attr(structure.digest_method_node, "DigestMethod")?;
            let digest_method = DigestAlgorithm::from_uri(digest_uri).ok_or_else(|| {
                SigningDigestError::UnsupportedAlgorithm {
                    uri: digest_uri.to_owned(),
                }
            })?;
            policy.check_digest_algorithm(digest_method)?;

            let transform_uris = generation_transform_uris(structure.transforms_node)?;
            if transform_uris.len() > policy.resources.max_transforms_per_reference {
                return Err(crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::REFERENCE_TRANSFORMS,
                    maximum: policy.resources.max_transforms_per_reference,
                    actual: transform_uris.len(),
                }
                .into());
            }
            if let Some(allowed) = policy.transforms.allowed_algorithms.as_ref()
                && let Some(disallowed) = transform_uris
                    .iter()
                    .find(|algorithm| !allowed.contains(**algorithm))
            {
                return Err(crate::policy::PolicyViolation::Algorithm {
                    operation: "signing transform",
                    algorithm: (*disallowed).to_owned(),
                }
                .into());
            }
            let initial_binary = !structure.uri.is_empty() && !structure.uri.starts_with('#');
            if generation_chain_produces_binary(initial_binary, &transform_uris) {
                continue;
            }
            if transform_uris.len() >= policy.resources.max_transforms_per_reference {
                return Err(crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::REFERENCE_TRANSFORMS,
                    maximum: policy.resources.max_transforms_per_reference,
                    actual: transform_uris.len().saturating_add(1),
                }
                .into());
            }
            if policy
                .transforms
                .allowed_algorithms
                .as_ref()
                .is_some_and(|allowed| !allowed.contains(SECOND_EDITION_GENERATION_C14N_URI))
            {
                return Err(crate::policy::PolicyViolation::Algorithm {
                    operation: "signing transform",
                    algorithm: SECOND_EDITION_GENERATION_C14N_URI.to_owned(),
                }
                .into());
            }

            let edit = if let Some(transforms_node) = structure.transforms_node {
                c14n11_edit_for_transforms(view.xml(), transforms_node)?
            } else {
                let prefix = reference_node.prefix().unwrap_or_default();
                let qualifier = xml_qualifier(prefix);
                SourceEdit {
                    range: structure.digest_method_node.range().start
                        ..structure.digest_method_node.range().start,
                    replacement: format!(
                        "<{qualifier}Transforms><{qualifier}Transform Algorithm=\"{SECOND_EDITION_GENERATION_C14N_URI}\"/></{qualifier}Transforms>"
                    ),
                }
            };
            edits.push(edit);
        }
        Ok::<_, SigningDigestError>(edits)
    })?;
    if edits.is_empty() {
        return Ok(None);
    }

    let projected_len = edits
        .iter()
        .try_fold(document.as_xml().len(), |total, edit| {
            total
                .checked_sub(edit.range.len())
                .and_then(|value| value.checked_add(edit.replacement.len()))
                .ok_or_else(|| {
                    SigningDigestError::InvalidStructure("document length overflow".into())
                })
        })?;
    policy
        .resources
        .validate_xml_document_len(projected_len)
        .map_err(SigningDigestError::Policy)?;

    let mut candidate = document.as_xml().to_owned();
    let mut edits = edits;
    edits.sort_unstable_by_key(|edit| std::cmp::Reverse(edit.range.start));
    for edit in edits {
        candidate.replace_range(edit.range, &edit.replacement);
    }
    Ok(Some(candidate))
}

fn c14n11_edit_for_transforms(
    xml: &str,
    transforms_node: Node<'_, '_>,
) -> Result<SourceEdit, SigningDigestError> {
    let range = transforms_node.range();
    let source = xml.get(range.clone()).ok_or_else(|| {
        SigningDigestError::InvalidStructure("Transforms source range is unavailable".into())
    })?;
    let prefix = transforms_node.prefix().unwrap_or_default();
    let qualifier = xml_qualifier(prefix);
    let transform =
        format!("<{qualifier}Transform Algorithm=\"{SECOND_EDITION_GENERATION_C14N_URI}\"/>");
    if source.trim_end().ends_with("/>") {
        let trimmed = source.trim_end();
        let opening = trimmed.strip_suffix("/>").ok_or_else(|| {
            SigningDigestError::InvalidStructure(
                "self-closing Transforms source is unavailable".into(),
            )
        })?;
        let trailing = &source[trimmed.len()..];
        return Ok(SourceEdit {
            range,
            replacement: format!("{opening}>{transform}</{qualifier}Transforms>{trailing}"),
        });
    }
    let closing = source.rfind("</").ok_or_else(|| {
        SigningDigestError::InvalidStructure("Transforms closing tag is unavailable".into())
    })?;
    let offset = range.start + closing;
    Ok(SourceEdit {
        range: offset..offset,
        replacement: transform,
    })
}

fn generation_transform_uris<'a>(
    transforms_node: Option<Node<'a, 'a>>,
) -> Result<Vec<&'a str>, SigningDigestError> {
    let Some(transforms_node) = transforms_node else {
        return Ok(Vec::new());
    };
    let mut algorithms = Vec::new();
    for child in element_children(transforms_node) {
        if algorithms.len() == MAX_TRANSFORMS_PER_REFERENCE {
            return Err(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::REFERENCE_TRANSFORMS,
                maximum: MAX_TRANSFORMS_PER_REFERENCE,
                actual: MAX_TRANSFORMS_PER_REFERENCE.saturating_add(1),
            }
            .into());
        }
        if !child.has_tag_name((XMLDSIG_NS, "Transform")) {
            return Err(TransformError::UnsupportedTransform(
                "unexpected child element of <ds:Transforms>; only <ds:Transform> is allowed"
                    .into(),
            )
            .into());
        }
        let algorithm = child.attribute("Algorithm").ok_or_else(|| {
            TransformError::UnsupportedTransform(
                "missing Algorithm attribute on <Transform>".into(),
            )
        })?;
        if algorithm != ENVELOPED_SIGNATURE_URI
            && algorithm != BASE64_TRANSFORM_URI
            && algorithm != XPATH_TRANSFORM_URI
            && algorithm != XPATH_FILTER2_TRANSFORM_URI
            && crate::c14n::C14nAlgorithm::from_uri(algorithm).is_none()
        {
            return Err(TransformError::UnsupportedTransform(algorithm.to_owned()).into());
        }
        algorithms.push(algorithm);
    }
    Ok(algorithms)
}

fn generation_chain_produces_binary(initial_binary: bool, algorithms: &[&str]) -> bool {
    algorithms.last().map_or(initial_binary, |algorithm| {
        *algorithm == BASE64_TRANSFORM_URI
            || crate::c14n::C14nAlgorithm::from_uri(algorithm).is_some()
    })
}

fn xml_qualifier(prefix: &str) -> String {
    if prefix.is_empty() {
        String::new()
    } else {
        format!("{prefix}:")
    }
}

fn parse_signing_document<'a>(
    xml: &'a str,
    policy: Option<&crate::policy::SigningPolicy>,
    budget: &XmlParseWorkBudget,
    backend: crate::XmlBackend,
) -> Result<Document<'a>, SigningDigestError> {
    let settings = policy
        .map(|policy| DocumentParseSettings::from_policy(&policy.xml, &policy.resources))
        .unwrap_or_default()
        .with_backend(backend);
    super::mutation::parse_with_options_and_budget(xml, settings, Some(budget)).map_err(|error| {
        match error.into_policy_violation(settings) {
            Ok(error) => SigningDigestError::Policy(error),
            Err(XmlDocumentError::Parse(error)) => SigningDigestError::XmlParse(error),
            Err(error) => SigningDigestError::Document(error),
        }
    })
}

fn parse_private_key_pem(private_key_pem: &str) -> Result<Zeroizing<Vec<u8>>, SigningKeyError> {
    let (rest, pem) = x509_parser::pem::parse_x509_pem(private_key_pem.as_bytes())
        .map_err(|_| SigningKeyError::InvalidKeyPem)?;
    if !rest.iter().all(|byte| byte.is_ascii_whitespace()) {
        return Err(SigningKeyError::InvalidKeyPem);
    }
    if pem.label != "PRIVATE KEY" {
        return Err(SigningKeyError::InvalidKeyFormat { label: pem.label });
    }
    Ok(Zeroizing::new(pem.contents))
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
    let structure = parse_signing_reference_structure(reference_node)?;
    let transforms = structure.transforms_node.map_or_else(
        || Ok(Vec::new()),
        |node| parse_transforms_with_budget(node, xpath_budget),
    )?;
    let digest_uri = required_algorithm_attr(structure.digest_method_node, "DigestMethod")?;
    let digest_method = DigestAlgorithm::from_uri(digest_uri).ok_or_else(|| {
        SigningDigestError::UnsupportedAlgorithm {
            uri: digest_uri.to_string(),
        }
    })?;

    Ok(SigningReference {
        uri: structure.uri.to_owned(),
        origin_node_id: reference_node.id(),
        transforms,
        digest_method,
        digest_value_range: structure.digest_value_node.range(),
        digest_value_node_id: structure.digest_value_node.id(),
    })
}

struct SigningReferenceStructure<'a> {
    uri: &'a str,
    transforms_node: Option<Node<'a, 'a>>,
    digest_method_node: Node<'a, 'a>,
    digest_value_node: Node<'a, 'a>,
}

fn parse_signing_reference_structure<'a>(
    reference_node: Node<'a, 'a>,
) -> Result<SigningReferenceStructure<'a>, SigningDigestError> {
    let uri = reference_node.attribute("URI").ok_or_else(|| {
        SigningDigestError::InvalidStructure("signing Reference must include URI attribute".into())
    })?;
    let mut children = element_children(reference_node);
    let first = children.next().ok_or(SigningDigestError::MissingElement {
        element: "DigestMethod",
    })?;
    let (transforms_node, digest_method_node) = if first.has_tag_name((XMLDSIG_NS, "Transforms")) {
        (
            Some(first),
            children.next().ok_or(SigningDigestError::MissingElement {
                element: "DigestMethod",
            })?,
        )
    } else {
        (None, first)
    };
    verify_ds_element(digest_method_node, "DigestMethod")?;
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
    Ok(SigningReferenceStructure {
        uri,
        transforms_node,
        digest_method_node,
        digest_value_node,
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

    struct FixedRsaSigningKey;

    impl SigningKey for FixedRsaSigningKey {
        fn sign(
            &self,
            _algorithm: SignatureAlgorithm,
            _canonical_signed_info: &[u8],
        ) -> Result<Vec<u8>, SigningKeyError> {
            Ok(vec![0x5a; 256])
        }

        fn public_key_info(&self) -> Result<SigningPublicKeyInfo, SigningKeyError> {
            Ok(SigningPublicKeyInfo::Rsa {
                spki_der: Vec::new(),
                modulus: vec![0x80; 256],
                exponent: vec![1, 0, 1],
            })
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

        let mut document = XmlDocument::parse(xml).expect("fixture must parse");
        let error = fill_reference_digest_values_in_dependency_order(
            &mut document,
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
    fn dependency_levels_share_the_xml_parse_work_budget() {
        // Nested Manifest dependencies require successive digest generations.
        // Analysis mutations and every level's validation/commit parses must
        // consume one monotonic budget instead of resetting in recursive work.
        let xml = r##"<root><payload Id="payload">nested payload</payload><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#outer"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/><ds:Object><ds:Manifest Id="outer"><ds:Reference URI="#inner"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:Manifest><ds:Manifest Id="inner"><ds:Reference URI="#payload"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:Manifest></ds:Object></ds:Signature></root>"##;
        let policy = crate::policy::SigningPolicy {
            manifest_processing: crate::policy::ManifestProcessing::Process,
            ..crate::policy::SigningPolicy::default()
        };
        let mut document = XmlDocument::parse(xml).expect("fixture must parse");
        let mut budgets = SigningOperationBudgets::from_resources(&policy.resources);

        fill_reference_digest_values_in_dependency_order(
            &mut document,
            TransformOptions::default(),
            &policy,
            crate::provider::default_provider(),
            &mut budgets,
            0,
            &[],
        )
        .expect("the default cumulative budget must cover nested dependencies");
        let consumed = budgets.transforms.xml_parse_work().consumed();
        assert!(
            consumed > xml.len().saturating_mul(6),
            "analysis and dependency reparses must all be charged"
        );

        let mut constrained_policy = policy;
        constrained_policy.resources.max_xml_parse_work_bytes = consumed - 1;
        let mut constrained_document = XmlDocument::parse(xml).expect("fixture must parse");
        let mut constrained_budgets =
            SigningOperationBudgets::from_resources(&constrained_policy.resources);
        let error = fill_reference_digest_values_in_dependency_order(
            &mut constrained_document,
            TransformOptions::default(),
            &constrained_policy,
            crate::provider::default_provider(),
            &mut constrained_budgets,
            0,
            &[],
        )
        .expect_err("one byte below measured work must fail closed");

        assert!(matches!(
            error,
            SigningDigestError::Policy(PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XML_PARSE_WORK_BYTES,
                maximum,
                actual,
            }) if maximum == consumed - 1 && actual >= consumed
        ));
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
    fn signing_initial_parse_consumes_the_operation_xml_parse_budget() {
        // The input parse and every later retained-document reparse belong to
        // one monotonic operation allowance; helpers must not create a fresh
        // budget before digest or mutation work begins.
        let xml = r##"<root><payload Id="payload"/><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#payload"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/></ds:Signature></root>"##;
        let mut policy = crate::policy::SigningPolicy::default();
        policy.resources.max_xml_parse_work_bytes = 0;

        let error = SignContext::new(&RejectingSigningKey)
            .policy(policy)
            .sign_template(xml)
            .expect_err("a zero parse-work budget must reject the initial parse");

        assert!(matches!(
            error,
            SigningError::Policy(PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XML_PARSE_WORK_BYTES,
                maximum: 0,
                actual,
            }) if actual == xml.len()
        ));
    }

    #[test]
    fn signing_string_entry_point_enforces_policy_depth() {
        // Operation parsing must use the compiled policy depth rather than the
        // process-wide hard ceiling, before template discovery or key use.
        let mut policy = crate::policy::SigningPolicy::default();
        policy.resources.max_xml_depth = 2;
        let xml = "<root><child><leaf/></child></root>";

        assert!(matches!(
            SignContext::new(&RejectingSigningKey)
                .policy(policy)
                .sign_template(xml),
            Err(SigningError::Policy(PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XML_DEPTH,
                maximum: 2,
                actual: 3,
            }))
        ));
    }

    #[test]
    fn builder_append_reports_policy_depth() {
        // The generated template fits as a standalone tree, but its methods
        // cross the same depth policy after the Signature is appended.
        let mut policy = crate::policy::SigningPolicy::default();
        policy.resources.max_xml_depth = 4;
        let builder = SignatureBuilder::new(
            crate::c14n::C14nAlgorithm::new(crate::c14n::C14nMode::Exclusive1_0, false),
            SignatureAlgorithm::RsaSha256,
        )
        .add_reference(crate::xmldsig::ReferenceBuilder::new(DigestAlgorithm::Sha256).uri(""));

        let result = SignContext::new(&FixedRsaSigningKey)
            .policy(policy)
            .sign_with_builder("<root/>", &builder);
        assert!(
            matches!(
                result,
                Err(SigningError::Policy(PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XML_DEPTH,
                    maximum: 4,
                    actual: 5,
                }))
            ),
            "unexpected builder depth result: {result:?}"
        );
    }

    #[test]
    fn owned_signing_staged_copies_preserve_policy_errors() {
        // Both retained-document entry points must expose operation policy
        // exhaustion directly and leave the caller's generation untouched.
        let mut policy = crate::policy::SigningPolicy::default();
        policy.resources.max_xml_parse_work_bytes = 0;
        let context = SignContext::new(&RejectingSigningKey).policy(policy);

        let mut template_document = XmlDocument::parse("<root/>").expect("fixture must parse");
        let template_before = template_document.as_xml().to_owned();
        let error = context
            .sign_document(&mut template_document)
            .expect_err("the staged template copy must exhaust the operation budget");
        assert!(matches!(
            error,
            SigningError::Policy(PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XML_PARSE_WORK_BYTES,
                maximum: 0,
                actual,
            }) if actual == template_before.len()
        ));
        assert_eq!(template_document.as_xml(), template_before);
        assert_eq!(template_document.generation(), 0);

        let mut builder_document = XmlDocument::parse("<root/>").expect("fixture must parse");
        let builder_before = builder_document.as_xml().to_owned();
        let builder = SignatureBuilder::new(
            crate::c14n::C14nAlgorithm::new(crate::c14n::C14nMode::Exclusive1_0, false),
            SignatureAlgorithm::RsaSha256,
        );
        let error = context
            .sign_document_with_builder(&mut builder_document, &builder)
            .expect_err("the staged builder copy must exhaust the operation budget");
        assert!(matches!(
            error,
            SigningError::Policy(PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XML_PARSE_WORK_BYTES,
                maximum: 0,
                actual,
            }) if actual == builder_before.len()
        ));
        assert_eq!(builder_document.as_xml(), builder_before);
        assert_eq!(builder_document.generation(), 0);
    }

    #[test]
    fn owned_signing_commits_the_validated_stage_without_reparsing() {
        // Atomic commit must adopt the already validated staged cell. Charging
        // another complete backend parse makes valid maximum-size inputs exceed
        // the operation ceiling only because they use the owned entry point.
        let xml = r##"<root><payload Id="payload">content</payload><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#payload"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/></ds:Signature></root>"##;
        let policy = crate::policy::SigningPolicy::default();
        let context = SignContext::new(&FixedRsaSigningKey).policy(policy.clone());
        let source = XmlDocument::parse(xml).expect("fixture must parse");
        let mut measured = SigningOperationBudgets::from_resources(&policy.resources);
        let mut staged = source
            .staged_copy_with_budget(
                DocumentParseSettings::from_policy(&policy.xml, &policy.resources),
                measured.transforms.xml_parse_work(),
            )
            .expect("staging must parse");
        context
            .sign_document_in_place(&mut staged, &mut measured)
            .expect("staged signing must succeed");
        let exact_stage_work = measured.transforms.xml_parse_work().consumed();

        let mut constrained_policy = policy;
        constrained_policy.resources.max_xml_parse_work_bytes = exact_stage_work;
        let mut document = XmlDocument::parse(xml).expect("fixture must parse");
        SignContext::new(&FixedRsaSigningKey)
            .policy(constrained_policy)
            .sign_document(&mut document)
            .expect("commit must not parse the validated stage again");

        assert_eq!(document.generation(), 1);
        assert!(!document.as_xml().contains("<ds:DigestValue/>"));
        assert!(!document.as_xml().contains("<ds:SignatureValue/>"));
    }

    #[test]
    fn builder_signing_fits_the_document_to_parse_work_ratio() {
        // A builder operation at the configured document ceiling must fit the
        // implementation's hard allowance. Generated base64 text and the
        // appended generated template need one committed candidate parse each,
        // not an untrusted-fragment validation parse plus commit. Differential
        // builds meter their comparison backend without reducing this envelope.
        let padding = "x".repeat(64 * 1024);
        let xml = format!("<root><payload Id=\"payload\"/><padding>{padding}</padding></root>");
        let builder = SignatureBuilder::new(
            crate::c14n::C14nAlgorithm::new(crate::c14n::C14nMode::Exclusive1_0, false),
            SignatureAlgorithm::RsaSha256,
        )
        .add_reference(
            crate::xmldsig::ReferenceBuilder::new(DigestAlgorithm::Sha256).uri("#payload"),
        );
        let maximum_document_bytes = xml.len() + 4 * 1024;
        let mut policy = crate::policy::SigningPolicy::default();
        policy.resources.max_xml_document_bytes = maximum_document_bytes;
        policy.resources.max_xml_parse_work_bytes =
            maximum_document_bytes * crate::hard_limits::XML_PARSE_WORK_PASS_CEILING;

        let mut measurement_policy = policy.clone();
        measurement_policy.resources.max_xml_parse_work_bytes =
            crate::hard_limits::XML_PARSE_WORK_BYTE_CEILING;
        let measurement_context =
            SignContext::new(&FixedRsaSigningKey).policy(measurement_policy.clone());
        let mut measurement_budgets =
            SigningOperationBudgets::from_resources(&measurement_policy.resources);
        let mut measurement_document = XmlDocument::parse_with_settings_and_budget(
            xml.clone(),
            DocumentParseSettings::from_policy(
                &measurement_policy.xml,
                &measurement_policy.resources,
            ),
            measurement_budgets.transforms.xml_parse_work(),
        )
        .expect("measurement input must parse");
        measurement_context
            .sign_document_with_builder_in_place(
                &mut measurement_document,
                &builder,
                &mut measurement_budgets,
            )
            .expect("measurement signing must succeed");
        let consumed = measurement_budgets.transforms.xml_parse_work().consumed();
        assert!(
            consumed <= maximum_document_bytes * crate::hard_limits::XML_PARSE_WORK_PASS_CEILING,
            "builder signing consumed {consumed} bytes for a {maximum_document_bytes}-byte ceiling"
        );

        let signed = SignContext::new(&FixedRsaSigningKey)
            .policy(policy.clone())
            .sign_with_builder(&xml, &builder)
            .expect("string builder signing must fit the advertised parse-work ratio");
        assert!(signed.contains("DigestValue>"));
        assert!(signed.contains("SignatureValue>"));

        let mut owned = XmlDocument::parse(&xml).expect("fixture must parse");
        SignContext::new(&FixedRsaSigningKey)
            .policy(policy)
            .sign_document_with_builder(&mut owned, &builder)
            .expect("owned builder signing must fit the advertised parse-work ratio");
        assert!(owned.as_xml().contains("DigestValue>"));
        assert!(owned.as_xml().contains("SignatureValue>"));
    }

    #[test]
    fn dtd_capable_staged_copy_charges_both_parser_passes() {
        // DTD-capable documents run a provenance parse before the retained
        // document parse. Both passes belong to the signing operation budget.
        let xml = "<root/>";
        let mut parsing_policy = crate::policy::SigningPolicy::default();
        parsing_policy.xml.allow_internal_dtd = true;
        let document = XmlDocument::parse_with_policy(xml, &parsing_policy)
            .expect("the fixture must retain DTD-capable parse settings");

        parsing_policy.resources.max_xml_parse_work_bytes = xml.len();
        let budget = XmlParseWorkBudget::from_resources(&parsing_policy.resources);
        assert!(matches!(
            document.staged_copy_with_budget(DocumentParseSettings::default(), &budget),
            Err(XmlDocumentError::Policy(PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XML_PARSE_WORK_BYTES,
                maximum,
                actual,
            })) if maximum == xml.len() && actual == xml.len() * 2
        ));
    }

    #[test]
    fn owned_signing_mappers_preserve_document_size_policy_errors() {
        // Template and digest mutations share one resource-error contract even
        // though their surrounding signing error types differ.
        let maximum = 8;
        let actual = 9;
        assert!(matches!(
            map_owned_document_mutation_error(XmlDocumentError::DocumentTooLarge {
                maximum,
                actual,
            }),
            SigningError::Policy(PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XML_DOCUMENT,
                maximum: 8,
                actual: 9,
            })
        ));
        assert!(matches!(
            map_owned_document_digest_mutation_error(XmlDocumentError::DocumentTooLarge {
                maximum,
                actual,
            }),
            SigningDigestError::Policy(PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XML_DOCUMENT,
                maximum: 8,
                actual: 9,
            })
        ));
    }

    #[test]
    fn signing_rejects_xpath_control_dependencies_on_digest_values() {
        // The second Reference excludes DigestValue nodes from its output but
        // reads the first DigestValue to decide whether payload remains. Filling
        // both references in one level would therefore invalidate the result.
        let xml = r##"<root><payload Id="payload">content</payload><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#payload"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference><ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>not(ancestor-or-self::ds:DigestValue) and (not(self::payload) or string(//ds:Reference[1]/ds:DigestValue) = '')</ds:XPath></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/></ds:Signature></root>"##;

        let mut document = XmlDocument::parse(xml).expect("fixture must parse");
        let error = fill_reference_digest_values_in_dependency_order(
            &mut document,
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

        let mut document = XmlDocument::parse(xml).expect("fixture must parse");
        fill_reference_digest_values_in_dependency_order(
            &mut document,
            TransformOptions::default(),
            &crate::policy::SigningPolicy::default(),
            crate::provider::default_provider(),
            &mut SigningOperationBudgets::default(),
            0,
            &[],
        )
        .expect("payload-local XPath predicates must not depend on Signature values");

        assert_ne!(document.as_xml(), xml);
    }

    #[test]
    fn signing_rejects_references_that_retain_signature_value() {
        // SignatureValue is filled after every Reference digest. A Reference
        // retaining that node is therefore an unavoidable signing cycle even
        // when all DigestValue nodes are excluded from the resulting node-set.
        let xml = r##"<root><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>not(ancestor-or-self::ds:DigestValue)</ds:XPath></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/></ds:Signature></root>"##;

        let mut document = XmlDocument::parse(xml).expect("fixture must parse");
        let error = fill_reference_digest_values_in_dependency_order(
            &mut document,
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

    #[test]
    fn second_edition_c14n_materialization_handles_both_reference_shapes() {
        // Templates may omit <Transforms> entirely or serialize an empty
        // prefixed element. Both forms must become one valid explicit chain.
        let xml = r##"<root><payload Id="payload"/><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#payload"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference><ds:Reference URI="#payload"><ds:Transforms/><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/></ds:Signature></root>"##;
        let document = XmlDocument::parse(xml).expect("fixture must parse");
        let candidate = materialize_second_edition_c14n11_candidate(
            &document,
            0,
            &crate::policy::SigningPolicy::default(),
            false,
        )
        .expect("materialization planning must succeed")
        .expect("both node-set chains require explicit canonicalization");

        assert_eq!(
            candidate
                .matches(SECOND_EDITION_GENERATION_C14N_URI)
                .count(),
            3
        );
        assert!(candidate.contains("<ds:Transforms><ds:Transform"));
        XmlDocument::parse(candidate).expect("materialized candidate must remain well-formed");
    }

    #[test]
    fn second_edition_c14n_materialization_is_idempotent_for_binary_chains() {
        // An explicit canonicalization already produces octets; planning must
        // avoid both duplicate transforms and a no-op document generation.
        let xml = r##"<root><payload Id="payload"/><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#payload"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2006/12/xml-c14n11"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/></ds:Signature></root>"##;
        let document = XmlDocument::parse(xml).expect("fixture must parse");
        let candidate = materialize_second_edition_c14n11_candidate(
            &document,
            0,
            &crate::policy::SigningPolicy::default(),
            false,
        )
        .expect("materialization planning must succeed");

        assert!(candidate.is_none());
    }
}
