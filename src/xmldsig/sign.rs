//! Signing-side `XMLDSig` digest computation.
//!
//! This pass fills `<DigestValue>` elements before `<SignedInfo>` is
//! canonicalized and signed. It intentionally uses a signing-template parser
//! instead of [`crate::xmldsig::parse::parse_signed_info`], because verification
//! must continue to reject empty or malformed stored digest values.

use crate::rsa_encoding::{RsaPrivateKeyEncoding as _, RsaPublicKeyEncoding as _};
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
    borrow::Cow,
    collections::{BTreeMap, HashMap, HashSet},
    ops::Range,
};
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
    merge_key_info_source_in_document, padded_base64_len_for_xml,
};
use super::parse::{
    EC_P256_OID, EC_P384_OID, EC_P521_OID, MAX_REFERENCES_PER_SIGNATURE, SignatureAlgorithm,
    XMLDSIG_NS, parse_signed_info_with_pending_digests,
};
use super::signature::{encode_ecdsa_signature_as_der, maximum_ecdsa_der_signature_len};
use super::signing_key::{SigningKey, SigningKeyError, SigningPublicKeyInfo};
use super::transforms::{
    BASE64_TRANSFORM_URI, ENVELOPED_SIGNATURE_URI, MAX_TRANSFORMS_PER_REFERENCE, Transform,
    TransformExecutionBudget, TransformOptions, XPATH_FILTER2_TRANSFORM_URI, XPATH_TRANSFORM_URI,
    XPathHereSemantics, XPathSignatureParseBudget, execute_transforms_with_dependency_nodes,
    map_c14n_resource_policy_violation, parse_transforms_with_budget,
    validate_signing_transform_policy,
};
use super::types::TransformError;
use super::uri::{
    ExternalResourceContext, ExternalResourceMapError, UriReferenceResolver,
    validate_external_resource_map, validate_signing_reference_request,
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

/// Errors returned by the `XMLDSig` signing digest pass.
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

    /// Required `XMLDSig` element is missing.
    #[error("missing required element: <{element}>")]
    MissingElement {
        /// Required element name.
        element: &'static str,
    },

    /// `XMLDSig` template structure is invalid.
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

/// Errors returned by the full `XMLDSig` signing pipeline.
#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    /// Key establishment failed before the consuming HMAC operation.
    #[error(transparent)]
    KeyEstablishment(#[from] crate::key_establishment::KeyEstablishmentError),
    /// The compiled signing policy rejected input outside the Reference digest stage.
    #[error("signing policy violation: {0}")]
    Policy(#[from] crate::policy::PolicyViolation),

    /// Reference digest computation failed.
    #[error("signing digest pass failed: {0}")]
    Digest(SigningDigestError),

    /// Parsing `<SignedInfo>` or its methods failed during template validation.
    #[error("failed to parse SignedInfo: {0}")]
    ParseSignedInfo(super::parse::ParseError),

    /// `SignedInfo` canonicalization failed.
    #[error("SignedInfo canonicalization failed: {0}")]
    Canonicalization(#[from] crate::c14n::C14nError),

    /// Signing key preparation or signing failed.
    #[error("signing key error: {0}")]
    Key(#[from] SigningKeyError),

    /// A signing provider returned bytes that cannot encode this key's signature.
    #[error("signature output must be {expected} bytes, got {actual}")]
    InvalidSignatureOutputLength {
        /// Exact `XMLDSig` wire length implied by the signing public key.
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
            SigningDigestError::XmlMutation(XmlMutationError::Policy(error))
            | SigningDigestError::Policy(error)
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

/// Validate that a key can produce the requested algorithm under `policy`.
///
/// Key registries can use this preflight before selecting a candidate, ensuring
/// lax ordered searches skip keys that the signing operation would reject.
///
/// # Errors
/// Returns candidate-budget or algorithm-policy refusal, invalid key metadata,
/// an unsupported key/method pairing, or the key's metadata callback failure.
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
    // Method parameters are untrusted; reject them before external key callbacks.
    if let Some(full_bits) = algorithm.hmac_output_bits() {
        policy
            .hmac
            .validate_output(algorithm, hmac_output_length_bits.unwrap_or(full_bits))?;
    }
    let public_key = key.public_key_info()?;
    let expected = match (algorithm, public_key) {
        (
            SignatureAlgorithm::PostQuantum(algorithm),
            SigningPublicKeyInfo::PostQuantum {
                algorithm: key_algorithm,
                ..
            },
        ) if algorithm == key_algorithm => algorithm.signature_len(),
        (
            algorithm,
            SigningPublicKeyInfo::EdDsa {
                algorithm: key_algorithm,
                ..
            },
        ) if algorithm.eddsa_key_algorithm() == Some(key_algorithm) => algorithm
            .eddsa_signature_len()
            .ok_or(SigningKeyError::InvalidPublicKeyInfo)?,
        (
            method,
            SigningPublicKeyInfo::Rsa {
                modulus, exponent, ..
            },
        ) if method.is_rsa() => expected_rsa_signature_len(method, &modulus, &exponent, policy)?,
        (method, SigningPublicKeyInfo::Ec { public_key, .. })
            if method.ecdsa_digest().is_some()
                && public_key.first() == Some(&0x04)
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
                return Err(SigningKeyError::UnsupportedAlgorithm {
                    uri: algorithm.uri().to_owned(),
                }
                .into());
            }
            component_len.saturating_mul(2)
        }
        (method, SigningPublicKeyInfo::Hmac { key_bits })
            if method.hmac_output_bits().is_some() =>
        {
            policy.hmac.validate_key_bits(key_bits)?;
            let output_bits = hmac_output_length_bits.unwrap_or(
                algorithm
                    .hmac_output_bits()
                    .ok_or(SigningKeyError::InvalidPublicKeyInfo)?,
            );
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
            | SignatureAlgorithm::EcdsaSha512
            | SignatureAlgorithm::EcdsaSha3_224
            | SignatureAlgorithm::EcdsaSha3_256
            | SignatureAlgorithm::EcdsaSha3_384
            | SignatureAlgorithm::EcdsaSha3_512,
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

fn expected_rsa_signature_len(
    method: SignatureAlgorithm,
    modulus: &[u8],
    exponent: &[u8],
    policy: &crate::policy::SigningPolicy,
) -> Result<usize, SigningError> {
    let width = policy
        .rsa_keys
        .validate_components("signing", modulus, exponent)?;
    if let Some(parameters) = method.rsa_pss_parameters() {
        let normalized = modulus
            .iter()
            .position(|byte| *byte != 0)
            .map(|start| &modulus[start..])
            .ok_or(SigningKeyError::InvalidPublicKeyInfo)?;
        let bits = normalized.len() * 8 - normalized[0].leading_zeros() as usize;
        if !parameters.fits_modulus_bits(bits) {
            return Err(SigningKeyError::InvalidPublicKeyInfo.into());
        }
    }
    Ok(width)
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

/// Writes signing key metadata into a template `<KeyInfo>` element.
pub trait KeyInfoWriter {
    /// Return XML child content for the direct `<Signature>/<KeyInfo>` element.
    ///
    /// # Errors
    /// Returns key metadata, unsupported key representation, certificate
    /// mismatch, policy or serialization failures from the selected writer.
    fn write_key_info(&self, signing_key: &dyn SigningKey) -> Result<String, KeyInfoWriteError>;

    /// Write key metadata through the cryptographic provider selected for the operation.
    ///
    /// Writers that do not perform cryptographic operations can rely on this
    /// default. Digest- or signature-producing writers must override it.
    ///
    /// # Errors
    /// Propagates metadata/serialization failures and any selected-provider
    /// failure needed to produce the writer's key information.
    fn write_key_info_with_provider(
        &self,
        signing_key: &dyn SigningKey,
        provider: &dyn crate::provider::CryptoProvider,
    ) -> Result<String, KeyInfoWriteError> {
        let _ = provider;
        self.write_key_info(signing_key)
    }

    /// Write with the operation's retained certificate admission account.
    /// Certificate-processing writers override this hook; other writers retain
    /// their provider-aware serialization contract without creating a parser.
    ///
    /// # Errors
    /// Propagates writer failures and, for certificate-processing writers,
    /// resource admission and certificate parsing errors from this session.
    fn write_key_info_in_session(
        &self,
        signing_key: &dyn SigningKey,
        provider: &dyn crate::provider::CryptoProvider,
        parsing: &mut super::parse::KeyInfoParsingSession<'_>,
    ) -> Result<String, KeyInfoWriteError> {
        let _ = parsing;
        self.write_key_info_with_provider(signing_key, provider)
    }
}

/// Errors while preparing `XMLDSig` signing `<KeyInfo>` output.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KeyInfoWriteError {
    /// Certificate processing exceeded the operation's resource allowance.
    #[error("certificate processing rejected by policy: {0}")]
    Policy(#[from] crate::policy::PolicyViolation),
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

    /// A certificate-backed `KeyInfo` writer requires at least one certificate.
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

/// Writes the signing key's SPKI as `XMLDSig` 1.1 `DEREncodedKeyValue`.
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

/// Writes RSA, DSA, or `XMLDSig` 1.1 EC public parameters as `KeyValue`.
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
            SigningPublicKeyInfo::Hmac { .. }
            | SigningPublicKeyInfo::EdDsa { .. }
            | SigningPublicKeyInfo::PostQuantum { .. } => {
                Err(KeyInfoWriteError::UnsupportedKeyValue)
            }
        }
    }
}

/// `<KeyInfo>` writer that embeds an ordered DER X.509 certificate chain.
pub struct X509CertificateKeyInfoWriter {
    certificates_der: Vec<Vec<u8>>,
}

impl X509CertificateKeyInfoWriter {
    /// Parse a PEM `CERTIFICATE` block for `XMLDSig` `<X509Certificate>` output.
    ///
    /// # Errors
    /// Returns malformed PEM/certificate framing or certificate parsing and
    /// resource failures from the DER constructor.
    pub fn from_pem(certificate_pem: &str) -> Result<Self, KeyInfoWriteError> {
        Self::from_pem_chain([certificate_pem])
    }

    /// Parse a leaf-first sequence of PEM `CERTIFICATE` blocks for `<X509Data>`.
    ///
    /// The first certificate must identify the signing key. Remaining issuer
    /// certificates are emitted in caller order; this writer does not build or
    /// validate issuer relationships because trust remains caller-owned.
    ///
    /// # Errors
    /// Returns invalid PEM/certificate framing, an empty chain, or certificate
    /// parsing and resource admission failures.
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

    /// Validate and store DER certificate bytes for `XMLDSig` `<X509Certificate>` output.
    ///
    /// # Errors
    /// Returns certificate parsing or resource admission failures.
    pub fn from_der(certificate_der: &[u8]) -> Result<Self, KeyInfoWriteError> {
        Self::from_der_chain([certificate_der])
    }

    /// Validate and store a leaf-first DER certificate chain for `<X509Data>`.
    ///
    /// The first certificate must identify the signing key. Remaining issuer
    /// certificates are emitted in caller order; this writer does not build or
    /// validate issuer relationships because trust remains caller-owned.
    ///
    /// # Errors
    /// Returns an empty chain, invalid certificate encoding or refusal by the
    /// standalone constructor's default certificate-resource account.
    pub fn from_der_chain<I, B>(certificates_der: I) -> Result<Self, KeyInfoWriteError>
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        let resources = crate::policy::ResourcePolicy::default();
        let mut parsing = super::parse::KeyInfoParsingSession::new(&resources)
            .map_err(certificate_parse_write_error)?;
        Self::from_der_chain_in_session(certificates_der, &mut parsing)
    }

    /// Validate and retain certificates in the caller's bounded ingestion account.
    /// Unlike the default standalone constructor, this does not restore defaults.
    ///
    /// # Errors
    /// Returns an empty chain, certificate parsing failure or refusal by the
    /// caller's retained certificate-resource account.
    pub fn from_der_chain_in_session<I, B>(
        chain: I,
        parsing: &mut super::parse::KeyInfoParsingSession<'_>,
    ) -> Result<Self, KeyInfoWriteError>
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        let certificates_der = chain
            .into_iter()
            .map(|certificate_der| {
                let certificate_der = certificate_der.as_ref();
                parsing
                    .with_certificate_public_key(certificate_der, |_| ())
                    .map_err(certificate_parse_write_error)?;
                Ok::<_, KeyInfoWriteError>(certificate_der.to_vec())
            })
            .collect::<Result<Vec<_>, _>>()?;
        if certificates_der.is_empty() {
            return Err(KeyInfoWriteError::EmptyCertificateChain);
        }
        Ok(Self { certificates_der })
    }
}

fn certificate_parse_write_error(error: super::parse::ParseError) -> KeyInfoWriteError {
    match error {
        super::parse::ParseError::Policy(error) => KeyInfoWriteError::Policy(error),
        _ => KeyInfoWriteError::InvalidCertificateDer,
    }
}

fn parse_certificate_pem(certificate_pem: &str) -> Result<Vec<u8>, KeyInfoWriteError> {
    let mut pem = super::signature::PemBlock::decode(certificate_pem)
        .ok_or(KeyInfoWriteError::InvalidCertificatePem)?;
    if pem.label != "CERTIFICATE" {
        return Err(KeyInfoWriteError::InvalidCertificateFormat { label: pem.label });
    }
    // A certificate is public; take the buffer instead of copying it.
    Ok(std::mem::take(&mut *pem.contents))
}

impl KeyInfoWriter for X509CertificateKeyInfoWriter {
    fn write_key_info(&self, signing_key: &dyn SigningKey) -> Result<String, KeyInfoWriteError> {
        let resources = crate::policy::ResourcePolicy::default();
        let mut parsing = super::parse::KeyInfoParsingSession::new(&resources)
            .map_err(certificate_parse_write_error)?;
        self.write_key_info_in_session(
            signing_key,
            crate::provider::default_provider(),
            &mut parsing,
        )
    }

    fn write_key_info_in_session(
        &self,
        signing_key: &dyn SigningKey,
        _provider: &dyn crate::provider::CryptoProvider,
        parsing: &mut super::parse::KeyInfoParsingSession<'_>,
    ) -> Result<String, KeyInfoWriteError> {
        for (index, der) in self.certificates_der.iter().enumerate() {
            parsing
                .with_certificate_public_key(der, |spki| {
                    if index == 0 && signing_key.public_key_info()?.spki_der() != Some(spki) {
                        return Err(KeyInfoWriteError::CertificateKeyMismatch);
                    }
                    Ok(())
                })
                .map_err(certificate_parse_write_error)??;
        }
        let start = "<X509Data xmlns=\"http://www.w3.org/2000/09/xmldsig#\">";
        let mut length = start.len() + "</X509Data>".len();
        for der in &self.certificates_der {
            length = length
                .checked_add(
                    der.len()
                        .div_ceil(3)
                        .checked_mul(4)
                        .ok_or(KeyInfoWriteError::InvalidCertificateDer)?
                        + "<X509Certificate></X509Certificate>".len(),
                )
                .ok_or(KeyInfoWriteError::InvalidCertificateDer)?;
        }
        parsing.resources().validate_xml_document_len(length)?;
        let mut xml = String::with_capacity(length);
        xml.push_str(start);
        for certificate_der in &self.certificates_der {
            xml.push_str("<X509Certificate>");
            base64::engine::general_purpose::STANDARD.encode_string(certificate_der, &mut xml);
            xml.push_str("</X509Certificate>");
        }
        xml.push_str("</X509Data>");
        Ok(xml)
    }
}

/// Writes an `XMLDSig` 1.1 `X509Digest` selector for the signing certificate.
pub struct X509DigestKeyInfoWriter {
    certificate_der: Vec<u8>,
    digest_algorithm: DigestAlgorithm,
}

impl X509DigestKeyInfoWriter {
    /// Validate and retain a DER certificate and selector digest algorithm.
    ///
    /// # Errors
    /// Returns invalid certificate encoding or refusal by the standalone
    /// constructor's default certificate-resource account.
    pub fn from_der(
        certificate_der: &[u8],
        digest_algorithm: DigestAlgorithm,
    ) -> Result<Self, KeyInfoWriteError> {
        let resources = crate::policy::ResourcePolicy::default();
        let mut parsing = super::parse::KeyInfoParsingSession::new(&resources)
            .map_err(certificate_parse_write_error)?;
        Self::from_der_in_session(certificate_der, digest_algorithm, &mut parsing)
    }

    /// Validate and retain a certificate in the caller's bounded ingestion account.
    ///
    /// # Errors
    /// Returns certificate parsing failure or refusal by the supplied session's account.
    pub fn from_der_in_session(
        certificate_der: &[u8],
        digest_algorithm: DigestAlgorithm,
        parsing: &mut super::parse::KeyInfoParsingSession<'_>,
    ) -> Result<Self, KeyInfoWriteError> {
        parsing
            .with_certificate_public_key(certificate_der, |_| ())
            .map_err(certificate_parse_write_error)?;
        Ok(Self {
            certificate_der: certificate_der.to_vec(),
            digest_algorithm,
        })
    }

    /// Parse a PEM certificate and retain its selector digest algorithm.
    ///
    /// # Errors
    /// Returns invalid PEM/certificate framing or the DER constructor's parsing
    /// and resource admission failures.
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
        let resources = crate::policy::ResourcePolicy::default();
        let mut parsing = super::parse::KeyInfoParsingSession::new(&resources)
            .map_err(certificate_parse_write_error)?;
        self.write_key_info_in_session(signing_key, provider, &mut parsing)
    }

    fn write_key_info_in_session(
        &self,
        signing_key: &dyn SigningKey,
        provider: &dyn crate::provider::CryptoProvider,
        parsing: &mut super::parse::KeyInfoParsingSession<'_>,
    ) -> Result<String, KeyInfoWriteError> {
        parsing
            .with_certificate_public_key(&self.certificate_der, |spki| {
                if signing_key.public_key_info()?.spki_der() != Some(spki) {
                    return Err(KeyInfoWriteError::CertificateKeyMismatch);
                }
                Ok(())
            })
            .map_err(certificate_parse_write_error)??;
        let digest = super::compute_digest_with_provider(
            provider,
            self.digest_algorithm,
            &self.certificate_der,
        )?;
        let start = "<ds:X509Data xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><dsig11:X509Digest xmlns:dsig11=\"http://www.w3.org/2009/xmldsig11#\" Algorithm=\"";
        let end = "</dsig11:X509Digest></ds:X509Data>";
        let length = start.len()
            + self.digest_algorithm.uri().len()
            + "\">".len()
            + digest.len().div_ceil(3) * 4
            + end.len();
        parsing.resources().validate_xml_document_len(length)?;
        let mut xml = String::with_capacity(length);
        xml.push_str(start);
        xml.push_str(self.digest_algorithm.uri());
        xml.push_str("\">");
        base64::engine::general_purpose::STANDARD.encode_string(digest, &mut xml);
        xml.push_str(end);
        Ok(xml)
    }
}

/// RSA PKCS#1 v1.5 private key for `XMLDSig` signing.
pub struct RsaSigningKey {
    key: RsaPrivateKey,
}

impl RsaSigningKey {
    /// Parse an unencrypted PKCS#8 `PRIVATE KEY` PEM block.
    ///
    /// # Errors
    /// Returns invalid PEM framing or an invalid RSA PKCS#8 encoding.
    pub fn from_pkcs8_pem(private_key_pem: &str) -> Result<Self, SigningKeyError> {
        let private_key_der = parse_private_key_pem(private_key_pem)?;
        Self::from_pkcs8_der(&private_key_der)
    }

    /// Parse unencrypted PKCS#8 private key DER.
    ///
    /// # Errors
    /// Returns `InvalidKeyDer` for malformed containers, unsupported algorithm
    /// parameters or invalid RSA private components.
    pub fn from_pkcs8_der(private_key_der: &[u8]) -> Result<Self, SigningKeyError> {
        let key = RsaPrivateKey::from_pkcs8_der(private_key_der)
            .map_err(|_| SigningKeyError::InvalidKeyDer)?;
        Ok(Self { key })
    }

    /// Decrypt and parse a password-protected PKCS#8 `ENCRYPTED PRIVATE KEY` PEM block.
    ///
    /// # Errors
    /// Returns `InvalidKeyDer` for malformed PEM/protection parameters, failed
    /// decryption (including a wrong password) or invalid decrypted RSA material.
    pub fn from_pkcs8_encrypted_pem(
        private_key_pem: &str,
        password: impl AsRef<[u8]>,
    ) -> Result<Self, SigningKeyError> {
        let key = RsaPrivateKey::from_pkcs8_encrypted_pem(private_key_pem, password)
            .map_err(|_| SigningKeyError::InvalidKeyDer)?;
        Ok(Self { key })
    }

    /// Decrypt and parse password-protected PKCS#8 DER.
    ///
    /// # Errors
    /// Returns `InvalidKeyDer` for malformed protection parameters, failed
    /// decryption (including a wrong password) or invalid decrypted RSA material.
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
        if let Some(parameters) = algorithm.rsa_pss_parameters() {
            return crate::provider::rsa_pss::sign(
                provider,
                &self.key,
                parameters,
                canonical_signed_info,
            );
        }
        match algorithm {
            #[cfg(feature = "legacy-algorithms")]
            SignatureAlgorithm::RsaMd5 => sign_rsa_pkcs1v15_with_rng(
                provider,
                &RsaPkcs1v15SigningKey::<md5::Md5>::new(self.key.clone()),
                canonical_signed_info,
            ),
            #[cfg(feature = "legacy-algorithms")]
            SignatureAlgorithm::RsaRipemd160 => sign_rsa_pkcs1v15_with_rng(
                provider,
                &RsaPkcs1v15SigningKey::<ripemd::Ripemd160>::new(self.key.clone()),
                canonical_signed_info,
            ),
            SignatureAlgorithm::RsaSha1 => sign_rsa_pkcs1v15_with_rng(
                provider,
                &RsaPkcs1v15SigningKey::<Sha1>::new(self.key.clone()),
                canonical_signed_info,
            ),
            SignatureAlgorithm::RsaSha224 => sign_rsa_pkcs1v15_with_rng(
                provider,
                &RsaPkcs1v15SigningKey::<Sha224>::new(self.key.clone()),
                canonical_signed_info,
            ),
            SignatureAlgorithm::RsaSha256 => sign_rsa_pkcs1v15_with_rng(
                provider,
                &RsaPkcs1v15SigningKey::<Sha256>::new(self.key.clone()),
                canonical_signed_info,
            ),
            SignatureAlgorithm::RsaSha384 => sign_rsa_pkcs1v15_with_rng(
                provider,
                &RsaPkcs1v15SigningKey::<Sha384>::new(self.key.clone()),
                canonical_signed_info,
            ),
            SignatureAlgorithm::RsaSha512 => sign_rsa_pkcs1v15_with_rng(
                provider,
                &RsaPkcs1v15SigningKey::<Sha512>::new(self.key.clone()),
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

/// Symmetric key for `XMLDSig` HMAC signing.
///
/// Owned secret bytes are zeroized when the key is dropped.
pub struct HmacSigningKey {
    secret: Zeroizing<Vec<u8>>,
}

impl HmacSigningKey {
    /// Construct a signing key from non-empty caller-owned secret bytes.
    ///
    /// # Errors
    /// Returns `InvalidKeyDer` for an empty secret. Strength minima are enforced
    /// separately by the signing operation's immutable policy.
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
            #[cfg(feature = "legacy-algorithms")]
            SignatureAlgorithm::HmacMd5 => sign_hmac!(md5::Md5),
            #[cfg(feature = "legacy-algorithms")]
            SignatureAlgorithm::HmacRipemd160 => sign_hmac!(ripemd::Ripemd160),
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

/// DSA private key for `XMLDSig` 1.1 signing.
pub struct DsaSigningKey {
    key: dsa::SigningKey,
}

impl DsaSigningKey {
    /// Parse an unencrypted PKCS#8 `PRIVATE KEY` PEM block.
    ///
    /// # Errors
    /// Returns invalid PEM framing or an invalid DSA PKCS#8 encoding.
    pub fn from_pkcs8_pem(private_key_pem: &str) -> Result<Self, SigningKeyError> {
        let private_key_der = parse_private_key_pem(private_key_pem)?;
        Self::from_pkcs8_der(&private_key_der)
    }

    /// Parse unencrypted PKCS#8 private key DER.
    ///
    /// # Errors
    /// Returns `InvalidKeyDer` for malformed DSA parameters/components,
    /// above-ceiling fields or an inconsistent supplied public component.
    pub fn from_pkcs8_der(private_key_der: &[u8]) -> Result<Self, SigningKeyError> {
        use der::Decode;
        let info = pkcs8::PrivateKeyInfoRef::from_der(private_key_der)
            .map_err(|_| SigningKeyError::InvalidKeyDer)?;
        let key = decode_dsa_signing_key(info)?;
        Ok(Self { key })
    }

    /// Decrypt and parse a password-protected PKCS#8 `ENCRYPTED PRIVATE KEY` PEM block.
    ///
    /// # Errors
    /// Returns `InvalidKeyDer` for an incorrect PEM label, malformed protection
    /// parameters, failed decryption or invalid decrypted DSA material.
    pub fn from_pkcs8_encrypted_pem(
        private_key_pem: &str,
        password: impl AsRef<[u8]>,
    ) -> Result<Self, SigningKeyError> {
        let (label, encrypted) = pkcs8::SecretDocument::from_pem(private_key_pem)
            .map_err(|_| SigningKeyError::InvalidKeyDer)?;
        if label != "ENCRYPTED PRIVATE KEY" {
            return Err(SigningKeyError::InvalidKeyDer);
        }
        Self::from_pkcs8_encrypted_der(encrypted.as_bytes(), password)
    }

    /// Decrypt and parse password-protected PKCS#8 DER.
    ///
    /// # Errors
    /// Returns `InvalidKeyDer` for malformed protection parameters, a wrong
    /// password or invalid decrypted DSA parameters/components.
    pub fn from_pkcs8_encrypted_der(
        private_key_der: &[u8],
        password: impl AsRef<[u8]>,
    ) -> Result<Self, SigningKeyError> {
        use der::Decode;
        let encrypted = pkcs8::EncryptedPrivateKeyInfoRef::from_der(private_key_der)
            .map_err(|_| SigningKeyError::InvalidKeyDer)?;
        let plain = encrypted
            .decrypt(password)
            .map_err(|_| SigningKeyError::InvalidKeyDer)?;
        Self::from_pkcs8_der(plain.as_bytes())
    }
}

pub(crate) fn preflight_dsa_private_key(
    info: &pkcs8::PrivateKeyInfoRef<'_>,
) -> Result<(), SigningKeyError> {
    use der::Decode;
    if info.algorithm.oid != dsa::OID {
        return Err(SigningKeyError::InvalidKeyDer);
    }
    let parameters = info
        .algorithm
        .parameters
        .as_ref()
        .ok_or(SigningKeyError::InvalidKeyDer)?
        .decode_as::<super::signature::BorrowedDsaPublicParameters<'_>>()
        .map_err(|_| SigningKeyError::InvalidKeyDer)?;
    let x = der::asn1::UintRef::from_der(info.private_key.as_bytes())
        .map_err(|_| SigningKeyError::InvalidKeyDer)?;
    // Process-safety ceiling, not deployment policy: inspect borrowed DER
    // before the provider allocates bigints or derives a public component.
    for component in [parameters.p, parameters.q, parameters.g, x] {
        if component.as_bytes().len() > crate::hard_limits::DSA_KEY_COMPONENT_BYTE_CEILING {
            return Err(SigningKeyError::InvalidKeyDer);
        }
    }
    if let Some(public) = info.public_key {
        let bytes = public.as_bytes().ok_or(SigningKeyError::InvalidKeyDer)?;
        let y = der::asn1::UintRef::from_der(bytes).map_err(|_| SigningKeyError::InvalidKeyDer)?;
        if y.as_bytes().len() > crate::hard_limits::DSA_KEY_COMPONENT_BYTE_CEILING {
            return Err(SigningKeyError::InvalidKeyDer);
        }
    }
    Ok(())
}

pub(crate) fn decode_dsa_signing_key(
    mut info: pkcs8::PrivateKeyInfoRef<'_>,
) -> Result<dsa::SigningKey, SigningKeyError> {
    use der::Decode;
    preflight_dsa_private_key(&info)?;
    let public = info.public_key.take();
    // RFC 5958 section 2 carries both components of one asymmetric key:
    // https://www.rfc-editor.org/rfc/rfc5958.html#section-2
    // Derive y from x rather than trusting the optional supplied publicKey.
    // Rejecting inconsistency is our import invariant, not an RFC validation algorithm.
    let key = dsa::SigningKey::try_from(info).map_err(|_| SigningKeyError::InvalidKeyDer)?;
    if let Some(public) = public {
        let y = der::asn1::UintRef::from_der(public.raw_bytes())
            .map_err(|_| SigningKeyError::InvalidKeyDer)?;
        let supplied = crypto_bigint::BoxedUint::from_be_slice_vartime(y.as_bytes());
        if supplied != **key.verifying_key().y() {
            return Err(SigningKeyError::InvalidKeyDer);
        }
    }
    Ok(key)
}

#[cfg(test)]
mod dsa_import_tests;

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
    key: &impl RandomizedSigner<RsaPkcs1v15Signature>,
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
    algorithm
        .ecdsa_digest()
        .ok_or_else(|| SigningKeyError::UnsupportedAlgorithm {
            uri: algorithm.uri().to_owned(),
        })
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

/// ECDSA P-256 private key for `XMLDSig` signing.
pub struct EcdsaP256SigningKey {
    key: P256SigningKey,
}

impl EcdsaP256SigningKey {
    /// Parse an unencrypted SEC1 `EC PRIVATE KEY` PEM block.
    ///
    /// # Errors
    /// Returns `InvalidKeyDer` for malformed SEC1 PEM or an invalid P-256 scalar/key.
    pub fn from_sec1_pem(private_key_pem: &str) -> Result<Self, SigningKeyError> {
        let key = p256::SecretKey::from_sec1_pem(private_key_pem)
            .map(P256SigningKey::from)
            .map_err(|_| SigningKeyError::InvalidKeyDer)?;
        Ok(Self { key })
    }

    /// Parse unencrypted SEC1 `ECPrivateKey` DER.
    ///
    /// # Errors
    /// Returns `InvalidKeyDer` for malformed SEC1 or an invalid P-256 scalar/key.
    pub fn from_sec1_der(private_key_der: &[u8]) -> Result<Self, SigningKeyError> {
        let key = p256::SecretKey::from_sec1_der(private_key_der)
            .map(P256SigningKey::from)
            .map_err(|_| SigningKeyError::InvalidKeyDer)?;
        Ok(Self { key })
    }

    /// Parse an unencrypted PKCS#8 `PRIVATE KEY` PEM block.
    ///
    /// # Errors
    /// Returns invalid PEM framing or an invalid P-256 PKCS#8 encoding.
    pub fn from_pkcs8_pem(private_key_pem: &str) -> Result<Self, SigningKeyError> {
        let private_key_der = parse_private_key_pem(private_key_pem)?;
        Self::from_pkcs8_der(&private_key_der)
    }

    /// Parse unencrypted PKCS#8 private key DER.
    ///
    /// # Errors
    /// Returns `InvalidKeyDer` for malformed containers, wrong curve parameters
    /// or an invalid P-256 private scalar/key.
    pub fn from_pkcs8_der(private_key_der: &[u8]) -> Result<Self, SigningKeyError> {
        let key = P256SigningKey::from_pkcs8_der(private_key_der)
            .map_err(|_| SigningKeyError::InvalidKeyDer)?;
        Ok(Self { key })
    }

    /// Decrypt and parse a password-protected PKCS#8 `ENCRYPTED PRIVATE KEY` PEM block.
    ///
    /// # Errors
    /// Returns `InvalidKeyDer` for malformed protection/PEM, failed decryption
    /// (including a wrong password) or invalid decrypted P-256 material.
    pub fn from_pkcs8_encrypted_pem(
        private_key_pem: &str,
        password: impl AsRef<[u8]>,
    ) -> Result<Self, SigningKeyError> {
        let key = P256SigningKey::from_pkcs8_encrypted_pem(private_key_pem, password)
            .map_err(|_| SigningKeyError::InvalidKeyDer)?;
        Ok(Self { key })
    }

    /// Decrypt and parse password-protected PKCS#8 DER.
    ///
    /// # Errors
    /// Returns `InvalidKeyDer` for malformed protection, failed decryption
    /// (including a wrong password) or invalid decrypted P-256 material.
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

/// ECDSA P-384 private key for `XMLDSig` signing.
pub struct EcdsaP384SigningKey {
    key: P384SigningKey,
}

impl EcdsaP384SigningKey {
    /// Parse an unencrypted SEC1 `EC PRIVATE KEY` PEM block.
    ///
    /// # Errors
    /// Returns `InvalidKeyDer` for malformed SEC1 PEM or an invalid P-384 scalar/key.
    pub fn from_sec1_pem(private_key_pem: &str) -> Result<Self, SigningKeyError> {
        let key = p384::SecretKey::from_sec1_pem(private_key_pem)
            .map(P384SigningKey::from)
            .map_err(|_| SigningKeyError::InvalidKeyDer)?;
        Ok(Self { key })
    }

    /// Parse unencrypted SEC1 `ECPrivateKey` DER.
    ///
    /// # Errors
    /// Returns `InvalidKeyDer` for malformed SEC1 or an invalid P-384 scalar/key.
    pub fn from_sec1_der(private_key_der: &[u8]) -> Result<Self, SigningKeyError> {
        let key = p384::SecretKey::from_sec1_der(private_key_der)
            .map(P384SigningKey::from)
            .map_err(|_| SigningKeyError::InvalidKeyDer)?;
        Ok(Self { key })
    }

    /// Parse an unencrypted PKCS#8 `PRIVATE KEY` PEM block.
    ///
    /// # Errors
    /// Returns invalid PEM framing or an invalid P-384 PKCS#8 encoding.
    pub fn from_pkcs8_pem(private_key_pem: &str) -> Result<Self, SigningKeyError> {
        let private_key_der = parse_private_key_pem(private_key_pem)?;
        Self::from_pkcs8_der(&private_key_der)
    }

    /// Parse unencrypted PKCS#8 private key DER.
    ///
    /// # Errors
    /// Returns `InvalidKeyDer` for malformed containers, wrong curve parameters
    /// or an invalid P-384 private scalar/key.
    pub fn from_pkcs8_der(private_key_der: &[u8]) -> Result<Self, SigningKeyError> {
        let key = P384SigningKey::from_pkcs8_der(private_key_der)
            .map_err(|_| SigningKeyError::InvalidKeyDer)?;
        Ok(Self { key })
    }

    /// Decrypt and parse a password-protected PKCS#8 `ENCRYPTED PRIVATE KEY` PEM block.
    ///
    /// # Errors
    /// Returns `InvalidKeyDer` for malformed protection/PEM, failed decryption
    /// (including a wrong password) or invalid decrypted P-384 material.
    pub fn from_pkcs8_encrypted_pem(
        private_key_pem: &str,
        password: impl AsRef<[u8]>,
    ) -> Result<Self, SigningKeyError> {
        let key = P384SigningKey::from_pkcs8_encrypted_pem(private_key_pem, password)
            .map_err(|_| SigningKeyError::InvalidKeyDer)?;
        Ok(Self { key })
    }

    /// Decrypt and parse password-protected PKCS#8 DER.
    ///
    /// # Errors
    /// Returns `InvalidKeyDer` for malformed protection, failed decryption
    /// (including a wrong password) or invalid decrypted P-384 material.
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

/// ECDSA P-521 private key for `XMLDSig` signing.
pub struct EcdsaP521SigningKey {
    key: P521SigningKey,
}

impl EcdsaP521SigningKey {
    /// Parse an unencrypted SEC1 `EC PRIVATE KEY` PEM block.
    ///
    /// # Errors
    /// Returns `InvalidKeyDer` for malformed SEC1 PEM or an invalid P-521 scalar/key.
    pub fn from_sec1_pem(private_key_pem: &str) -> Result<Self, SigningKeyError> {
        let key = p521::SecretKey::from_sec1_pem(private_key_pem)
            .map(P521SigningKey::from)
            .map_err(|_| SigningKeyError::InvalidKeyDer)?;
        Ok(Self { key })
    }

    /// Parse unencrypted SEC1 `ECPrivateKey` DER.
    ///
    /// # Errors
    /// Returns `InvalidKeyDer` for malformed SEC1 or an invalid P-521 scalar/key.
    pub fn from_sec1_der(private_key_der: &[u8]) -> Result<Self, SigningKeyError> {
        let key = p521::SecretKey::from_sec1_der(private_key_der)
            .map(P521SigningKey::from)
            .map_err(|_| SigningKeyError::InvalidKeyDer)?;
        Ok(Self { key })
    }

    /// Parse an unencrypted PKCS#8 `PRIVATE KEY` PEM block.
    ///
    /// # Errors
    /// Returns invalid PEM framing or an invalid P-521 PKCS#8 encoding.
    pub fn from_pkcs8_pem(private_key_pem: &str) -> Result<Self, SigningKeyError> {
        let private_key_der = parse_private_key_pem(private_key_pem)?;
        Self::from_pkcs8_der(&private_key_der)
    }

    /// Parse unencrypted PKCS#8 private key DER.
    ///
    /// # Errors
    /// Returns `InvalidKeyDer` for malformed containers, wrong curve parameters
    /// or an invalid P-521 private scalar/key.
    pub fn from_pkcs8_der(private_key_der: &[u8]) -> Result<Self, SigningKeyError> {
        let key = P521SigningKey::from_pkcs8_der(private_key_der)
            .map_err(|_| SigningKeyError::InvalidKeyDer)?;
        Ok(Self { key })
    }

    /// Decrypt and parse a password-protected PKCS#8 `ENCRYPTED PRIVATE KEY` PEM block.
    ///
    /// # Errors
    /// Returns `InvalidKeyDer` for malformed protection/PEM, failed decryption
    /// (including a wrong password) or invalid decrypted P-521 material.
    pub fn from_pkcs8_encrypted_pem(
        private_key_pem: &str,
        password: impl AsRef<[u8]>,
    ) -> Result<Self, SigningKeyError> {
        let key = P521SigningKey::from_pkcs8_encrypted_pem(private_key_pem, password)
            .map_err(|_| SigningKeyError::InvalidKeyDer)?;
        Ok(Self { key })
    }

    /// Decrypt and parse password-protected PKCS#8 DER.
    ///
    /// # Errors
    /// Returns `InvalidKeyDer` for malformed protection, failed decryption
    /// (including a wrong password) or invalid decrypted P-521 material.
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

/// Select which existing `XMLDSig` template [`SignContext::sign_template`] signs.
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

/// `XMLDSig` signing context.
pub struct SignContext<'a> {
    signing_key: Option<&'a dyn SigningKey>,
    encapsulation_key: Option<&'a dyn crate::provider::KeyEncapsulationKey>,
    key_info_writer: Option<&'a dyn KeyInfoWriter>,
    start_node_id: Option<&'a str>,
    id_attributes: &'a [crate::IdAttributeRegistration],
    external_resources: Option<&'a BTreeMap<String, Vec<u8>>>,
    template_selection: SignatureTemplateSelection,
    policy: crate::policy::SigningPolicy,
    provider: &'a dyn crate::provider::CryptoProvider,
    xml_backend: crate::XmlBackend,
}

impl<'a> SignContext<'a> {
    /// Create a signing context using the supplied private key.
    pub fn new(signing_key: &'a dyn SigningKey) -> Self {
        Self {
            signing_key: Some(signing_key),
            encapsulation_key: None,
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

    /// Establish an HMAC key from an explicit recipient public key. The template
    /// must contain one experimental `EncapsulationMechanism`; policy must grant
    /// its exact algorithm. KEM/HMAC alone does not authenticate the sender.
    pub fn new_encapsulation(key: &'a dyn crate::provider::KeyEncapsulationKey) -> Self {
        Self {
            signing_key: None,
            encapsulation_key: Some(key),
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
        DocumentParseSettings::from_policy(self.policy.xml, &self.policy.resources)
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
    pub fn external_resources(mut self, resources: &'a BTreeMap<String, Vec<u8>>) -> Self {
        self.external_resources = Some(resources);
        self
    }

    /// Select the node returned by `XPath`'s `here()` extension function.
    ///
    /// The default follows `XMLDSig` and returns the `<XPath>` parameter.
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
    ///
    /// # Errors
    /// Returns XML/template, policy/resource, key-info, reference-processing,
    /// selected-provider signing or final mutation failures.
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
        .map_err(map_template_parse_error)?;
        self.validate_owned_document_input(&document)?;
        self.sign_document_in_place::<SerializeText>(&mut document, &mut budgets)
    }

    /// Sign a parsed template the caller hands over, and return the signed XML.
    ///
    /// The same pipeline as [`Self::sign_template`] on a document parsed under
    /// this context's policy, for example with
    /// [`XmlDocument::parse_with_policy_and_backend`], so a caller that already
    /// read the template's metadata does not parse it twice. The parser work
    /// spent on the document is charged to the operation, exactly as
    /// `sign_template` charges its own parse. The document is consumed: a
    /// failure leaves nothing to roll back.
    ///
    /// # Errors
    /// Returns document provenance, template, policy/resource, key-info,
    /// reference, selected-provider signing or final mutation failures.
    pub fn sign_template_document(
        &self,
        mut document: XmlDocument,
    ) -> Result<String, SigningError> {
        self.validate_owned_document_input(&document)?;
        let mut budgets = SigningOperationBudgets::from_resources_with_backend(
            &self.policy.resources,
            self.xml_backend,
        );
        // max_xml_parse_work_bytes is cumulative over the whole operation,
        // whose initial parse the caller ran on our behalf.
        budgets
            .transforms
            .xml_parse_work()
            .charge(document.parse_work())
            .map_err(map_template_parse_error)?;
        self.sign_document_in_place::<SerializeText>(&mut document, &mut budgets)
    }

    /// Sign a template in a reusable owned document.
    ///
    /// Signing is atomic: failures leave both serialization and generation
    /// unchanged. Success commits the complete signature as one generation.
    ///
    /// # Errors
    /// Returns document provenance, template, policy/resource, key-info,
    /// reference or signing failures without committing the staged copy.
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
        self.sign_document_in_place::<CommitDocument>(&mut staged, &mut budgets)?;
        commit_signed_staged(document, staged, &self.policy)
    }

    fn sign_document_in_place<O: SignedOutput>(
        &self,
        document: &mut XmlDocument,
        budgets: &mut SigningOperationBudgets,
    ) -> Result<O::Output, SigningError> {
        let target_signature = document.with_view(|view| {
            signing_signature_index(
                view.document(),
                self.start_node_id,
                self.id_attributes,
                self.template_selection,
            )
        })?;
        self.policy.resources.validate_key_candidates(1)?;
        self.sign_template_at_index_with_budgets::<O>(document, target_signature, budgets)
    }

    fn validate_owned_document_input(&self, document: &XmlDocument) -> Result<(), SigningError> {
        self.policy.validate()?;
        document.validate_operation_policy(self.policy.xml, &self.policy.resources)?;
        if let Some(resources) = self.external_resources {
            validate_external_resource_map(
                resources,
                self.policy.resources.max_external_resource_bytes,
                self.policy.resources.max_external_resource_total_bytes,
            )
            .map_err(map_signing_external_resource_map_error)?;
        }
        Ok(())
    }

    fn signing_template_algorithm(
        &self,
        document: &XmlDocument,
        target_signature: usize,
        budget: &TransformExecutionBudget,
    ) -> Result<SignatureAlgorithm, SigningError> {
        document.with_view(|view| {
            let signature = find_signing_signature_node(
                view.document(),
                SigningSignatureTarget::Index(target_signature),
            )?;
            parse_signature_children(signature)
                .map_err(|error| SigningDigestError::InvalidStructure(error.to_string()))?;
            self.policy.signature_constraints.check(signature, budget)?;
            let (algorithm, output_bits) =
                validate_signing_signed_info_methods(signature, &self.policy)?;
            self.policy.check_signature_algorithm(algorithm)?;
            if let Some(full_bits) = algorithm.hmac_output_bits() {
                // Reject weak HMAC parameters before callbacks or reference work;
                // XMLDSig 1.1 section 4.4.2 explicitly requires max(80, hash_bits/2);
                // section 6.3.1 separately requires octet-aligned truncation.
                // https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/#sec-SignatureMethod
                // This is parameter validation only: key metadata belongs to the
                // later key preflight, not a second external/HSM callback here.
                self.policy
                    .hmac
                    .validate_output(algorithm, output_bits.unwrap_or(full_bits))?;
            }
            Ok::<_, SigningError>(algorithm)
        })
    }

    fn signing_encapsulation_target(
        &self,
        document: &XmlDocument,
        target_signature: usize,
        external_resources: &ExternalResourceContext<'_>,
        budgets: &mut SigningOperationBudgets,
    ) -> Result<Option<crate::NodeIdentity>, SigningError> {
        document.with_view(|view| {
            let signature = find_signing_signature_node(
                view.document(),
                SigningSignatureTarget::Index(target_signature),
            )?;
            let children = parse_signature_children(signature)
                .map_err(|error| SigningDigestError::InvalidStructure(error.to_string()))?;
            let metadata_error = |error| match error {
                super::DsigError::Policy(violation) => SigningError::Policy(violation),
                error => SigningDigestError::InvalidStructure(error.to_string()).into(),
            };
            let resolver = external_resources.bind(
                view.document(),
                self.id_attributes,
                self.policy.transforms.same_document_id_semantics,
            );
            if self.encapsulation_key.is_none() {
                if let Some(info) = children.key_info
                    && super::verify::has_signing_encapsulation_with_budget(
                        info,
                        &resolver,
                        &self.policy,
                        &budgets.transforms,
                        self.xml_backend,
                    )
                    .map_err(metadata_error)?
                {
                    return Err(crate::key_establishment::KeyEstablishmentError::Structure(
                        "mechanism and explicit recipient key must be supplied together",
                    )
                    .into());
                }
                return Ok(None);
            }
            let metadata = children
                .key_info
                .map(|node| {
                    super::verify::inspect_signing_key_info_with_budgets(
                        node,
                        &resolver,
                        &self.policy,
                        self.provider,
                        &budgets.transforms,
                        &mut budgets.xpath_parse,
                        self.xml_backend,
                    )
                })
                .transpose()
                .map_err(metadata_error)?;
            let mechanism =
                metadata.and_then(|metadata| metadata.encapsulation.zip(metadata.cipher_value));
            if mechanism.is_some() != self.encapsulation_key.is_some() {
                return Err(crate::key_establishment::KeyEstablishmentError::Structure(
                    "mechanism and explicit recipient key must be supplied together",
                )
                .into());
            }
            mechanism
                .map(|(algorithm, target)| {
                    self.policy
                        .key_establishment
                        .check_encapsulation(algorithm)?;
                    if self
                        .encapsulation_key
                        .is_some_and(|key| key.algorithm() != algorithm)
                    {
                        return Err(crate::key_establishment::KeyEstablishmentError::Structure(
                            "recipient parameter set mismatch",
                        )
                        .into());
                    }
                    let target = view.document().get_node(target).ok_or(
                        crate::key_establishment::KeyEstablishmentError::Structure(
                            "missing ciphertext target",
                        ),
                    )?;
                    Ok::<_, SigningError>(view.node_identity(target))
                })
                .transpose()
        })
    }

    fn prepare_signing_key_output(
        &self,
        document: &XmlDocument,
        target_signature: usize,
        signing_algorithm: SignatureAlgorithm,
        external_resources: &ExternalResourceContext<'_>,
        budgets: &mut SigningOperationBudgets,
    ) -> Result<SigningKeyOutput, SigningError> {
        let mechanism = self.signing_encapsulation_target(
            document,
            target_signature,
            external_resources,
            budgets,
        )?;
        if let Some(key) = self.encapsulation_key {
            if self.key_info_writer.is_some() {
                return Err(crate::key_establishment::KeyEstablishmentError::Structure(
                    "KeyInfo writer cannot overwrite EncapsulationMechanism",
                )
                .into());
            }
            if signing_algorithm.hmac_output_bits().is_none() {
                return Err(crate::key_establishment::KeyEstablishmentError::Structure(
                    "encapsulation requires HMAC",
                )
                .into());
            }
            self.policy.hmac.validate_key_bits(256)?;
            let target = mechanism.expect("recipient requires mechanism");
            let encoded_len = key.algorithm().ciphertext_len().div_ceil(3) * 4;
            // Reserve the consumer's output before executing the primitive;
            // encapsulate separately reserves its raw ciphertext allocation.
            self.policy.resources.validate_xml_document_len(
                document.projected_content_replacement_len(target, encoded_len)?,
            )?;
            budgets.key_establishment.commit_all(
                &self.policy.key_establishment,
                0,
                0,
                32 + encoded_len as u128,
            )?;
            let result = budgets.key_establishment.encapsulate(
                &self.policy.key_establishment,
                self.provider,
                key,
            )?;
            return Ok((None, Some((target, result))));
        }
        let Some(writer) = self.key_info_writer else {
            return Ok::<_, SigningError>((None, None));
        };
        let certificates = budgets
            .certificates
            .get_or_insert_with(|| super::pkix::CertificateSession::new(&self.policy.resources));
        let mut parsing = super::parse::KeyInfoParsingSession::with_certificate_account(
            &self.policy.resources,
            certificates,
        )
        .map_err(SigningError::from)?;
        let key_info_content = writer
            .write_key_info_in_session(
                self.signing_key.expect("ordinary signing request"),
                self.provider,
                &mut parsing,
            )
            .map_err(|error| match error {
                KeyInfoWriteError::Policy(error) => SigningError::Policy(error),
                error => SigningError::KeyInfo(error),
            })?;
        // Writer output is a separate untrusted XML input. Bound it before
        // namespace wrapping or parsing, then bound the merged document below.
        self.policy
            .resources
            .validate_xml_document_len(key_info_content.len())?;
        Ok((Some(key_info_content), None))
    }

    fn apply_signing_setup(
        &self,
        document: &mut XmlDocument,
        target_signature: usize,
        operation: &mut SigningExecution<'_>,
        key_info: OperationNodeId,
        output: SigningKeyOutput,
        has_external_resources: bool,
    ) -> Result<OperationNodeId, SigningError> {
        let (key_info_content, encapsulated) = output;
        operation.extend();
        let kem_mutation = if let Some((target, result)) = encapsulated {
            let mutation =
                operation.add_node(OperationNodeKind::Mutation, OperationStage::Resolve, None);
            operation.add_dependency(mutation, key_info)?;
            operation.compile()?;
            operation.run_document_transition(mutation, document, |document, budgets| {
                let encoded = base64::engine::general_purpose::STANDARD.encode(&result.ciphertext);
                document
                    .replace_base64_contents_with_budget(
                        &[(target, encoded)],
                        self.document_parse_settings(),
                        budgets.transforms.xml_parse_work(),
                    )
                    .map_err(map_owned_document_mutation_error)
            })?;
            operation.extend();
            Some(mutation)
        } else {
            None
        };
        // Validate reference inputs and build the normalization candidate only after
        // independent key output has passed its own byte boundary. The execution pass
        // revalidates the resulting document defensively after controlled mutations.
        let c14n_candidate = materialize_second_edition_c14n11_candidate(
            document,
            target_signature,
            &self.policy,
            has_external_resources,
        )?;
        let normalization = if let Some(candidate) = c14n_candidate {
            let mutation =
                operation.add_node(OperationNodeKind::Mutation, OperationStage::Resolve, None);
            operation.add_dependency(mutation, kem_mutation.unwrap_or(key_info))?;
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
        let setup_gate = normalization.or(kem_mutation).unwrap_or(key_info);
        self.populate_signing_key_info(
            document,
            target_signature,
            operation,
            setup_gate,
            key_info_content,
        )
    }

    fn populate_signing_key_info(
        &self,
        document: &mut XmlDocument,
        target_signature: usize,
        operation: &mut SigningExecution<'_>,
        setup_gate: OperationNodeId,
        key_info_content: Option<String>,
    ) -> Result<OperationNodeId, SigningError> {
        let setup_gate = if let Some(key_info_content) = key_info_content {
            let mutation =
                operation.add_node(OperationNodeKind::Mutation, OperationStage::Resolve, None);
            operation.add_dependency(mutation, setup_gate)?;
            operation.compile()?;
            operation.run_document_transition(mutation, document, |document, budgets| {
                // The mutation helper checks its namespace wrapper and every projected
                // replacement against policy before allocating the committed candidate;
                // the commit below parses and validates the merged document.
                let populated = document.with_view(|view| {
                    merge_key_info_source_in_document(
                        view.document(),
                        view.xml(),
                        &key_info_content,
                        target_signature,
                        Some(&self.policy),
                        Some(budgets.transforms.xml_parse_work()),
                    )
                })?;
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
        Ok(setup_gate)
    }

    fn admit_signature_output(
        &self,
        document: &XmlDocument,
        target_signature: usize,
        signing_key: &dyn SigningKey,
        algorithm: SignatureAlgorithm,
        hmac_output_length_bits: Option<usize>,
        pending_digests: &[(crate::NodeIdentity, String)],
    ) -> Result<(usize, crate::NodeIdentity), SigningError> {
        let expected_signature_len = expected_signature_output_len(
            signing_key,
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
        let mut projected_document_len = document
            .projected_content_replacement_len(signature_value_node, encoded_signature_len)?;
        // A DigestValue without semantic children may still hold source bytes
        // (references to an empty entity), so a replacement can also shrink
        // the document. The replaced ranges are disjoint, so the running total
        // never drops below what one replacement removes.
        for (digest_value_node, digest) in pending_digests {
            let replaced =
                document.projected_content_replacement_len(*digest_value_node, digest.len())?;
            projected_document_len = projected_document_len.checked_add(replaced).ok_or(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XML_DOCUMENT,
                    maximum: self.policy.resources.max_xml_document_bytes,
                    actual: usize::MAX,
                },
            )? - document.as_xml().len();
        }
        self.policy
            .resources
            .validate_xml_document_len(projected_document_len)?;
        Ok((expected_signature_len, signature_value_node))
    }

    fn finish_signing_template<O: SignedOutput>(
        &self,
        document: &mut XmlDocument,
        target_signature: usize,
        operation: &mut SigningExecution<'_>,
        (plan_nodes, pending_digests): (SigningPlanNodes, Vec<(crate::NodeIdentity, String)>),
        signing_key: &dyn SigningKey,
    ) -> Result<O::Output, SigningError> {
        self.policy
            .resources
            .validate_xml_document_len(document.as_xml().len())?;
        let (algorithm, hmac_output_length_bits, canonical_signed_info, signature_context) =
            operation.run_with_budgets(plan_nodes.canonicalization, |budgets| {
                let result = canonicalize_signed_info(
                    document,
                    &self.policy,
                    budgets,
                    target_signature,
                    &pending_digests,
                )?;
                budgets
                    .transforms
                    .charge_c14n_output(result.2.len())
                    .map_err(SigningDigestError::Transform)?;
                Ok::<_, SigningError>(result)
            })?;
        self.policy.check_signature_algorithm(algorithm)?;
        let (expected_signature_len, signature_value_node) = self.admit_signature_output(
            document,
            target_signature,
            signing_key,
            algorithm,
            hmac_output_length_bits,
            &pending_digests,
        )?;
        let signature_value = operation.run(plan_nodes.crypto, || {
            self.provider
                .require_capability(crate::provider::ProviderCapability::Sign(algorithm))
                .map_err(SigningKeyError::from)?;
            let mut signature_value = self.provider.sign_with_context(
                signing_key,
                algorithm,
                &signature_context,
                &canonical_signed_info,
            )?;
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
        let mut replacement = pending_digests;
        replacement.push((signature_value_node, signature_b64));
        O::finish(self, operation, plan_nodes.mutation, document, &replacement)
    }

    fn sign_template_at_index_with_budgets<O: SignedOutput>(
        &self,
        document: &mut XmlDocument,
        target_signature: usize,
        budgets: &mut SigningOperationBudgets,
    ) -> Result<O::Output, SigningError> {
        let signing_algorithm =
            self.signing_template_algorithm(document, target_signature, &budgets.transforms)?;
        let transform_options = TransformOptions::default()
            .id_attributes(self.id_attributes)
            .allow_internal_dtd(self.policy.xml.allow_internal_dtd)
            .xpath_here_semantics(self.policy.transforms.xpath_here_semantics)
            .opc_relationship_edition(self.policy.transforms.opc_relationship_edition)
            .xslt_stylesheet_semantics(self.policy.transforms.xslt_stylesheet_semantics);
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
        let (key_info_content, encapsulated) = operation.run_with_budgets(key_info, |budgets| {
            self.prepare_signing_key_output(
                document,
                target_signature,
                signing_algorithm,
                &external_resources,
                budgets,
            )
        })?;
        let established_key = if let Some((_, result)) = encapsulated.as_ref() {
            Some(HmacSigningKey::new(result.shared_secret.to_vec())?)
        } else {
            None
        };
        let signing_key: &dyn SigningKey = match (&established_key, self.signing_key) {
            (Some(key), _) => key,
            (None, Some(key)) => key,
            _ => {
                return Err(crate::key_establishment::KeyEstablishmentError::Structure(
                    "missing signing key",
                )
                .into());
            }
        };
        let setup_gate = self.apply_signing_setup(
            document,
            target_signature,
            &mut operation,
            key_info,
            (key_info_content, encapsulated),
            external_resources.is_configured(),
        )?;
        let (plan_nodes, pending_digests) =
            fill_reference_digest_values_in_dependency_order_with_operation(
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
                true,
            )?;
        self.finish_signing_template::<O>(
            document,
            target_signature,
            &mut operation,
            (plan_nodes, pending_digests),
            signing_key,
        )
    }

    /// Build a signature template, append it to the selected start node (or
    /// the document root when no selector is set), then sign that new template.
    ///
    /// # Errors
    /// Returns XML/target selection, template construction, policy/resource,
    /// reference-processing, key-info or signing failures.
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
        self.sign_document_with_builder_in_place::<SerializeText>(
            &mut document,
            builder,
            &mut budgets,
        )
    }

    /// Build, append, and sign a signature in an owned document.
    ///
    /// # Errors
    /// Returns provenance/target, template, policy/resource, key-info,
    /// reference or signing failures without committing a partial mutation.
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
        self.sign_document_with_builder_in_place::<CommitDocument>(
            &mut staged,
            builder,
            &mut budgets,
        )?;
        commit_signed_staged(document, staged, &self.policy)
    }

    fn sign_document_with_builder_in_place<O: SignedOutput>(
        &self,
        document: &mut XmlDocument,
        builder: &SignatureBuilder,
        budgets: &mut SigningOperationBudgets,
    ) -> Result<O::Output, SigningError> {
        self.policy.resources.validate_key_candidates(1)?;
        let expected_signature_len = if let Some(key) = self.signing_key {
            expected_signature_output_len(key, builder.signature_method(), &self.policy, None)?
        } else {
            self.policy.hmac.validate_key_bits(256)?;
            builder.signature_method().hmac_output_bits().ok_or(
                crate::key_establishment::KeyEstablishmentError::Structure(
                    "encapsulation requires HMAC",
                ),
            )? / 8
        };
        let template = builder.build_template_with_policy_for_signature_output(
            &self.policy,
            expected_signature_len,
            self.encapsulation_key
                .map(crate::provider::KeyEncapsulationKey::algorithm),
            &budgets.transforms,
            &mut budgets.xpath_parse,
        )?;
        let signature_parent = if let Some(id) = self.start_node_id {
            document.with_view(|view| {
                let start = signing_start_node(view.document(), id, self.id_attributes)?;
                Ok::<_, SigningError>(view.node_identity(start))
            })?
        } else {
            document.with_view(signing_document_root)
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
        self.sign_template_at_index_with_budgets::<O>(document, target_signature, budgets)
    }
}

/// How a signing operation hands over its final generation.
trait SignedOutput {
    type Output;

    /// Apply the final base64 values to `document` under the mutation node.
    fn finish(
        context: &SignContext<'_>,
        operation: &mut SigningExecution<'_>,
        mutation: OperationNodeId,
        document: &mut XmlDocument,
        replacement: &[(crate::NodeIdentity, String)],
    ) -> Result<Self::Output, SigningError>;
}

/// Commit a validated generation to the caller's retained document.
struct CommitDocument;

impl SignedOutput for CommitDocument {
    type Output = ();

    fn finish(
        context: &SignContext<'_>,
        operation: &mut SigningExecution<'_>,
        mutation: OperationNodeId,
        document: &mut XmlDocument,
        replacement: &[(crate::NodeIdentity, String)],
    ) -> Result<(), SigningError> {
        operation.run_document_transition(mutation, document, |document, budgets| {
            document
                .replace_base64_contents_with_budget(
                    replacement,
                    context.document_parse_settings(),
                    budgets.transforms.xml_parse_work(),
                )
                .map_err(map_owned_document_mutation_error)
        })?;
        context
            .policy
            .resources
            .validate_xml_document_len(document.as_xml().len())?;
        Ok(())
    }
}

/// Return the serialization of the final generation; the working document is discarded.
struct SerializeText;

impl SignedOutput for SerializeText {
    type Output = String;

    fn finish(
        context: &SignContext<'_>,
        operation: &mut SigningExecution<'_>,
        mutation: OperationNodeId,
        document: &mut XmlDocument,
        replacement: &[(crate::NodeIdentity, String)],
    ) -> Result<String, SigningError> {
        let signed = operation.run_document_projection(mutation, document, |document| {
            document
                .project_base64_commit(replacement, context.document_parse_settings())
                .map_err(map_owned_document_mutation_error)
        })?;
        context
            .policy
            .resources
            .validate_xml_document_len(signed.len())?;
        Ok(signed)
    }
}

fn projected_signature_output_len(
    algorithm: SignatureAlgorithm,
    raw_signature_len: usize,
    encoding: crate::policy::EcdsaSignatureValueEncoding,
) -> Result<usize, SigningError> {
    if algorithm.ecdsa_digest().is_some()
        && encoding == crate::policy::EcdsaSignatureValueEncoding::XmlSecAsn1Der
    {
        return maximum_ecdsa_der_signature_len(raw_signature_len)
            .ok_or(SigningKeyError::InvalidPublicKeyInfo.into());
    }
    Ok(raw_signature_len)
}

/// The error of a template's initial parse or of charging its parser work.
fn map_template_parse_error(error: XmlDocumentError) -> SigningError {
    match owned_document_policy_violation(error) {
        Ok(error) => SigningError::Policy(error),
        Err(XmlDocumentError::Parse(error)) => {
            SigningError::Digest(SigningDigestError::XmlParse(error))
        }
        Err(error) => SigningError::Document(error),
    }
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

fn map_signing_external_resource_map_error(error: ExternalResourceMapError) -> SigningError {
    match error {
        ExternalResourceMapError::Policy(error) => SigningError::Policy(error),
        ExternalResourceMapError::TotalLengthOverflow => {
            SigningDigestError::InvalidStructure("external resource total length overflow".into())
                .into()
        }
    }
}

fn owned_document_policy_violation(
    error: XmlDocumentError,
) -> Result<crate::policy::PolicyViolation, XmlDocumentError> {
    match error {
        XmlDocumentError::Policy(error) => Ok(error),
        XmlDocumentError::Parse(crate::xml::dom::ParseError::NamespaceBindingLimitReached {
            maximum,
            actual,
        }) => Ok(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::XML_NAMESPACE_BINDINGS,
            maximum,
            actual,
        }),
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
    if algorithm.ecdsa_digest().is_some()
        && encoding == crate::policy::EcdsaSignatureValueEncoding::XmlSecAsn1Der
    {
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

type SigningExecution<'a> =
    OperationExecutionContext<crate::policy::SigningPolicy, &'a mut SigningOperationBudgets>;

type SigningKeyOutput = (
    Option<String>,
    Option<(crate::NodeIdentity, crate::provider::EncapsulatedKey)>,
);

struct SigningOperationBudgets {
    certificates: Option<super::pkix::CertificateSession>,
    key_establishment: crate::key_establishment::KeyEstablishmentUsage,
    transforms: TransformExecutionBudget,
    xpath_parse: XPathSignatureParseBudget,
}

#[derive(Clone, Copy)]
struct SigningReferenceRequest<'a, 'resources> {
    target_signature: usize,
    id_attributes: &'a [crate::IdAttributeRegistration],
    external_resources: &'a ExternalResourceContext<'resources>,
}

impl<'a, 'resources> SigningReferenceRequest<'a, 'resources> {
    fn uri_resolution(
        self,
        same_document_id_semantics: crate::policy::SameDocumentIdSemantics,
    ) -> SigningUriResolution<'a, 'resources> {
        SigningUriResolution {
            id_attributes: self.id_attributes,
            same_document_id_semantics,
            external_resources: self.external_resources,
        }
    }
}

#[derive(Clone, Copy)]
struct SigningPlanNodes {
    canonicalization: OperationNodeId,
    crypto: OperationNodeId,
    evidence: OperationNodeId,
    mutation: OperationNodeId,
}

impl SigningOperationBudgets {
    fn from_resources(resources: &crate::policy::ResourcePolicy) -> Self {
        let transforms = TransformExecutionBudget::from_resources(resources);
        let xpath_parse = XPathSignatureParseBudget::for_execution(resources, &transforms);
        Self {
            certificates: None,
            key_establishment: crate::key_establishment::KeyEstablishmentUsage::default(),
            transforms,
            xpath_parse,
        }
    }

    fn from_resources_with_backend(
        resources: &crate::policy::ResourcePolicy,
        backend: crate::XmlBackend,
    ) -> Self {
        let transforms =
            TransformExecutionBudget::from_resources(resources).with_xml_backend(backend);
        let xpath_parse = XPathSignatureParseBudget::for_execution(resources, &transforms);
        Self {
            certificates: None,
            key_establishment: crate::key_establishment::KeyEstablishmentUsage::default(),
            transforms,
            xpath_parse,
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
/// `XMLDSig` `<Signature>` element. `sign_with_builder()` appends a new template
/// at the end of the source root, so older signatures in an already-signed
/// document must not become the signing target.
///
/// # Errors
/// Returns malformed XML/template, URI resolution, algorithm/transform policy,
/// resource admission or selected-provider digest failures.
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
    transform_options: TransformOptions<'_>,
    policy: Option<&crate::policy::SigningPolicy>,
    provider: &dyn crate::provider::CryptoProvider,
    execution_budget: &TransformExecutionBudget,
    target_signature: Option<usize>,
    id_attributes: &[crate::IdAttributeRegistration],
) -> Result<Vec<ComputedReferenceDigest>, SigningDigestError> {
    let (prepared, target_signature) =
        prepare_reference_digest_input(xml, policy, execution_budget, target_signature)?;
    compute_prepared_reference_digest_values_with_options(
        prepared.as_ref(),
        transform_options,
        policy,
        provider,
        execution_budget,
        target_signature,
        id_attributes,
    )
}

fn compute_prepared_reference_digest_values_with_options(
    xml: &str,
    transform_options: TransformOptions<'_>,
    policy: Option<&crate::policy::SigningPolicy>,
    provider: &dyn crate::provider::CryptoProvider,
    execution_budget: &TransformExecutionBudget,
    target_signature: usize,
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
    let signature =
        find_signing_signature_node(&doc, SigningSignatureTarget::Index(target_signature))?;
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

fn prepare_reference_digest_input<'a>(
    xml: &'a str,
    policy: Option<&crate::policy::SigningPolicy>,
    execution_budget: &TransformExecutionBudget,
    target_signature: Option<usize>,
) -> Result<(Cow<'a, str>, usize), SigningDigestError> {
    let default_policy = crate::policy::SigningPolicy::default();
    let effective_policy = policy.unwrap_or(&default_policy);
    let settings =
        DocumentParseSettings::from_policy(effective_policy.xml, &effective_policy.resources);
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
    // Preserve the public compute helper's precise pre-policy errors before
    // applying the default generation policy to the normalized candidate.
    document.with_view(|view| {
        let signature = find_signing_signature_node(
            view.document(),
            SigningSignatureTarget::Index(target_signature),
        )?;
        let signed_info = find_required_child(signature, "SignedInfo")?;
        let references = parse_signing_references(signed_info)?;
        validate_signing_references(&references, references.len(), policy, false)
    })?;
    let materialized = materialize_second_edition_c14n11_candidate(
        &document,
        target_signature,
        effective_policy,
        false,
    )?;
    Ok((
        materialized.map_or(Cow::Borrowed(xml), Cow::Owned),
        target_signature,
    ))
}

struct SigningReferenceInputs {
    signed_info: Vec<SigningReference>,
    manifests: Vec<SigningReference>,
    maximum: usize,
    process_manifests: bool,
}

fn collect_signing_reference_inputs(
    document: &XmlDocument,
    policy: &crate::policy::SigningPolicy,
    budgets: &mut SigningOperationBudgets,
    request: SigningReferenceRequest<'_, '_>,
) -> Result<SigningReferenceInputs, SigningDigestError> {
    let reference_limit = policy
        .resources
        .max_references
        .min(MAX_REFERENCES_PER_SIGNATURE);
    let process_manifests =
        policy.manifest_processing == crate::policy::ManifestProcessing::Process;
    let (signed_info_references, manifest_references) = {
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
                Some(policy),
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
        Some(policy),
        request.external_resources.is_configured(),
    )?;
    Ok(SigningReferenceInputs {
        signed_info: signed_info_references,
        manifests: manifest_references,
        maximum: reference_limit,
        process_manifests,
    })
}

fn analyze_signing_reference_inputs(
    document: &XmlDocument,
    policy: &crate::policy::SigningPolicy,
    budgets: &mut SigningOperationBudgets,
    request: SigningReferenceRequest<'_, '_>,
    transform_options: TransformOptions<'_>,
    references: &SigningReferenceInputs,
) -> Result<SigningDependencyPlan, SigningDigestError> {
    let signed_info_references = &references.signed_info;
    let manifest_references = &references.manifests;
    let reference_limit = references.maximum;
    let process_manifests = references.process_manifests;
    let all_references = signed_info_references.iter().chain(manifest_references);
    if all_references.clone().all(|reference| {
        reference.transforms.iter().all(|transform| {
            matches!(
                transform,
                Transform::Enveloped | Transform::XpathExcludeAllSignatures | Transform::C14n(_)
            )
        })
    }) {
        // These transforms keep or remove whole subtrees, so a DigestValue or
        // SignatureValue element is covered exactly when its future text is:
        // the current tree decides every dependency without placeholder text.
        // That holds only while filling a value removes nothing but text; a
        // value holding other nodes needs the placeholder tree, where those
        // nodes are already gone.
        let analysis_references = all_references.clone().cloned().collect::<Vec<_>>();
        let current_tree = document.with_view(|view| {
            let signature = find_signing_signature_node(
                view.document(),
                SigningSignatureTarget::Index(request.target_signature),
            )?;
            let signature_value = find_required_child(signature, "SignatureValue")?;
            let text_only = all_references
                .filter_map(|reference| view.document().get_node(reference.digest_value_node_id))
                .chain([signature_value])
                .all(|value| value.children().all(|child| child.is_text()));
            if !text_only {
                return Ok(None);
            }
            reference_dependency_levels(
                view.document(),
                signature,
                &analysis_references,
                transform_options,
                &budgets.transforms,
                request.uri_resolution(policy.transforms.same_document_id_semantics),
            )
            .map(Some)
        })?;
        if let Some(plan) = current_tree {
            return Ok(plan);
        }
    }
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
            .chain(manifest_references)
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
        Some(policy),
        budgets.transforms.xml_parse_work(),
        document.xml_backend(),
    )?;
    let analysis_signature = find_signing_signature_node(
        &analysis_doc,
        SigningSignatureTarget::Index(request.target_signature),
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
    reference_dependency_levels(
        &analysis_doc,
        analysis_signature,
        &analysis_references,
        transform_options,
        &budgets.transforms,
        request.uri_resolution(policy.transforms.same_document_id_semantics),
    )
}

#[derive(Clone, Copy)]
struct LevelDigestRequest<'a, 'resources> {
    transform_options: TransformOptions<'a>,
    provider: &'a dyn crate::provider::CryptoProvider,
    target_signature: usize,
    uri_resolution: SigningUriResolution<'a, 'resources>,
}

/// Reparse the References of a committed intermediate generation and compute
/// the digests of one dependency level against it.
fn reparsed_level_digests(
    view: crate::document::DocumentView<'_>,
    budgets: &mut SigningOperationBudgets,
    level: &[usize],
    references: &SigningReferenceInputs,
    request: LevelDigestRequest<'_, '_>,
) -> Result<Vec<(crate::NodeIdentity, String)>, SigningDigestError> {
    let signed_info_references = &references.signed_info;
    let reference_limit = references.maximum;
    let current_doc = view.document();
    let current_signature = find_signing_signature_node(
        current_doc,
        SigningSignatureTarget::Index(request.target_signature),
    )?;
    let current_signed_info = find_required_child(current_signature, "SignedInfo")?;
    let current_signed_info_references =
        parse_signing_references_with_budget(current_signed_info, &mut budgets.xpath_parse)?;
    let current_manifest_references = if references.process_manifests {
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
        || current_manifest_references.len() != references.manifests.len()
    {
        return Err(SigningDigestError::InvalidStructure(
            "signing Reference set changed while filling digests".into(),
        ));
    }
    let mut destinations = Vec::with_capacity(level.len());
    let mut level_references = Vec::with_capacity(level.len());
    for index in level {
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
        request.transform_options,
        request.provider,
        &budgets.transforms,
        request.uri_resolution,
    )?;
    if computed.len() != destinations.len() {
        return Err(SigningDigestError::InvalidStructure(
            "signing Reference set changed while computing digests".into(),
        ));
    }
    Ok(destinations
        .into_iter()
        .zip(computed)
        .map(|(target, digest)| (target, digest.digest_value))
        .collect())
}

/// Compute the digests of a dependency level from the current generation and
/// return them with their `DigestValue` identities, uncommitted.
fn compute_deferred_reference_digests(
    operation: &mut SigningExecution<'_>,
    node_level: &[OperationNodeId],
    document: &XmlDocument,
    level: &[usize],
    references: &SigningReferenceInputs,
    request: LevelDigestRequest<'_, '_>,
) -> Result<Vec<(crate::NodeIdentity, String)>, SigningDigestError> {
    operation.run_document_batch_with_budgets(node_level, document, |document, budgets| {
        document.with_view(|view| {
            let current_doc = view.document();
            let signature = find_signing_signature_node(
                current_doc,
                SigningSignatureTarget::Index(request.target_signature),
            )?;
            let level_references = level
                .iter()
                .map(|index| {
                    references
                        .signed_info
                        .iter()
                        .chain(&references.manifests)
                        .nth(*index)
                        .cloned()
                        .ok_or_else(|| {
                            SigningDigestError::InvalidStructure(
                                "compiled signing Reference index is unavailable".into(),
                            )
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let destinations = level_references
                .iter()
                .map(|reference| view.node_identity_by_id(reference.digest_value_node_id))
                .collect::<Vec<_>>();
            let computed = compute_signing_reference_digests(
                current_doc,
                signature,
                level_references,
                request.transform_options,
                request.provider,
                &budgets.transforms,
                request.uri_resolution,
            )?;
            if computed.len() != destinations.len() {
                return Err(SigningDigestError::InvalidStructure(
                    "signing Reference set changed while computing digests".into(),
                ));
            }
            Ok(destinations
                .into_iter()
                .zip(computed)
                .map(|(target, digest)| (target, digest.digest_value))
                .collect())
        })
    })
}

fn fill_reference_digest_values_in_dependency_order_with_operation(
    document: &mut XmlDocument,
    transform_options: TransformOptions<'_>,
    provider: &dyn crate::provider::CryptoProvider,
    operation: &mut OperationExecutionContext<
        crate::policy::SigningPolicy,
        &mut SigningOperationBudgets,
    >,
    request: SigningReferenceRequest<'_, '_>,
    setup_gate: Option<OperationNodeId>,
    defer_digests: bool,
) -> Result<(SigningPlanNodes, Vec<(crate::NodeIdentity, String)>), SigningDigestError> {
    let policy = operation.policy().clone();
    let references =
        collect_signing_reference_inputs(document, &policy, operation.budgets_mut(), request)?;
    let dependency_plan = analyze_signing_reference_inputs(
        document,
        &policy,
        operation.budgets_mut(),
        request,
        transform_options,
        &references,
    )?;
    let (node_levels, plan_nodes) =
        compile_signing_operation_plan(operation, &dependency_plan, setup_gate)?;
    let level_request = LevelDigestRequest {
        transform_options,
        provider,
        target_signature: request.target_signature,
        uri_resolution: request.uri_resolution(policy.transforms.same_document_id_semantics),
    };
    // When no Reference reads another's digest and every DigestValue is empty,
    // all digests come from the current generation; SignedInfo canonicalization
    // and the final commit receive them instead of an intermediate generation.
    if defer_digests
        && let [level] = dependency_plan.levels.as_slice()
        && let [node_level] = node_levels.as_slice()
        && document.with_view(|view| {
            references
                .signed_info
                .iter()
                .chain(&references.manifests)
                .all(|reference| {
                    view.document()
                        .get_node(reference.digest_value_node_id)
                        .is_some_and(|node| node.children().next().is_none())
                })
        })
    {
        let pending = compute_deferred_reference_digests(
            operation,
            node_level,
            document,
            level,
            &references,
            level_request,
        )?;
        return Ok((plan_nodes, pending));
    }
    for (level, node_level) in dependency_plan.levels.into_iter().zip(node_levels) {
        operation.run_document_transition_batch_with_budgets(
            &node_level,
            document,
            |document, budgets| {
                let replacements = document.with_view(|view| {
                    reparsed_level_digests(view, budgets, &level, &references, level_request)
                })?;
                document
                    .replace_base64_contents_with_budget(
                        &replacements,
                        DocumentParseSettings::from_policy(policy.xml, &policy.resources)
                            .with_backend(document.xml_backend()),
                        budgets.transforms.xml_parse_work(),
                    )
                    .map_err(map_owned_document_digest_mutation_error)
            },
        )?;
    }
    Ok((plan_nodes, Vec::new()))
}

#[cfg(test)]
fn fill_reference_digest_values_in_dependency_order(
    document: &mut XmlDocument,
    transform_options: TransformOptions<'_>,
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
        false,
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
    transform_options: TransformOptions<'_>,
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
                    .flat_map(Node::children)
                    .filter(Node::is_text)
                    .map(move |node| (index, node.id())),
            )
        })
        .collect::<Vec<_>>();
    tracked_mutable_nodes.push((terminal_signature_value_index, signature_value.id()));
    tracked_mutable_nodes.extend(
        signature_value
            .children()
            .filter(Node::is_text)
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
                .map_err(|error| map_signing_digest_plan_error(&error))?;
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
                    .map_err(|error| map_signing_digest_plan_error(&error))?;
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
            .map_err(|error| map_signing_digest_plan_error(&error))?;
    }
    let crypto = operation.add_node(OperationNodeKind::Crypto, OperationStage::Crypto, None);
    operation
        .add_dependency(crypto, canonicalization)
        .map_err(|error| map_signing_digest_plan_error(&error))?;
    let evidence = operation.add_node(OperationNodeKind::Evidence, OperationStage::Evidence, None);
    operation
        .add_dependency(evidence, crypto)
        .map_err(|error| map_signing_digest_plan_error(&error))?;
    let mutation = operation.add_node(OperationNodeKind::Mutation, OperationStage::Mutation, None);
    operation
        .add_dependency(mutation, evidence)
        .map_err(|error| map_signing_digest_plan_error(&error))?;
    operation
        .compile()
        .map_err(|error| map_signing_digest_plan_error(&error))?;

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

fn map_signing_digest_plan_error(error: &OperationPlanError) -> SigningDigestError {
    SigningDigestError::InvalidStructure(error.to_string())
}

// A free function preserves the scoped view's late-bound lifetime.
fn signing_document_root(view: crate::document::DocumentView<'_>) -> crate::NodeIdentity {
    view.root_element()
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
    operation.run_document_transition(mutation, document, |document, ()| {
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
        super::transforms::validate_relationship_chain(
            &reference.transforms,
            policy.map_or(crate::policy::OpcRelationshipEdition::default(), |policy| {
                policy.transforms.opc_relationship_edition
            }),
        )?;
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
) -> Result<(SignatureAlgorithm, Option<usize>), SigningError> {
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
    let signature_method =
        element_children(signed_info)
            .nth(1)
            .ok_or(SigningDigestError::MissingElement {
                element: "SignatureMethod",
            })?;
    super::parse::parse_signature_method(signature_method, &policy.resources)
        .map(|(algorithm, hmac, _context)| (algorithm, hmac))
        .map_err(SigningError::from)
}

#[derive(Clone, Copy)]
struct SigningUriResolution<'a, 'resources> {
    id_attributes: &'a [crate::IdAttributeRegistration],
    same_document_id_semantics: crate::policy::SameDocumentIdSemantics,
    external_resources: &'a ExternalResourceContext<'resources>,
}

fn compute_signing_reference_digests(
    doc: &Document<'_>,
    signature: Node<'_, '_>,
    references: Vec<SigningReference>,
    transform_options: TransformOptions<'_>,
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
            let digest = super::transforms::digest_reference_transforms_with_budget(
                signature,
                Some(signature),
                initial_data,
                &reference.transforms,
                transform_options,
                execution_budget,
                execution_budget.xml_parse_work(),
                super::transforms::DigestRequest {
                    provider,
                    algorithm: reference.digest_method,
                    retain_pre_digest: false,
                },
            )
            .map_err(|error| -> SigningDigestError {
                match error {
                    super::transforms::ReferenceDigestError::Transform(error) => error.into(),
                    super::transforms::ReferenceDigestError::Provider(error) => error.into(),
                }
            })?
            .digest;
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
///
/// # Errors
/// Returns XML/template, URI/transform, algorithm-policy, resource, digest
/// provider or document mutation failures.
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
    transform_options: TransformOptions<'_>,
    policy: Option<&crate::policy::SigningPolicy>,
    provider: &dyn crate::provider::CryptoProvider,
    execution_budget: &TransformExecutionBudget,
    target_signature: Option<usize>,
    id_attributes: &[crate::IdAttributeRegistration],
) -> Result<String, SigningDigestError> {
    let default_policy = crate::policy::SigningPolicy::default();
    let effective_policy = policy.unwrap_or(&default_policy);
    let (prepared, target_signature) =
        prepare_reference_digest_input(xml, policy, execution_budget, target_signature)?;
    let digest_values = compute_prepared_reference_digest_values_with_options(
        prepared.as_ref(),
        transform_options,
        Some(effective_policy),
        provider,
        execution_budget,
        target_signature,
        id_attributes,
    )?
    .into_iter()
    .map(|digest| digest.digest_value);
    Ok(fill_signed_info_digest_values_at_index_with_budget(
        prepared.as_ref(),
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
    pending_digests: &[(crate::NodeIdentity, String)],
) -> Result<
    (
        SignatureAlgorithm,
        Option<usize>,
        Vec<u8>,
        super::SignatureContext,
    ),
    SigningError,
> {
    document.with_view(|view| {
        let doc = view.document();
        let signature =
            find_signing_signature_node(doc, SigningSignatureTarget::Index(target_signature))
                .map_err(SigningError::Digest)?;
        let signed_info_node =
            find_required_child(signature, "SignedInfo").map_err(SigningError::Digest)?;
        let pending_digests = pending_digests
            .iter()
            .map(|(identity, digest)| {
                let node = view
                    .resolve_node(*identity)
                    .expect("pending digests address the generation being canonicalized");
                (node.id(), digest.as_str())
            })
            .collect::<Vec<_>>();
        let signed_info = parse_signed_info_with_pending_digests(
            signed_info_node,
            &mut budgets.xpath_parse,
            &policy.resources,
            &pending_digests,
        )?;
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
        let canonicalized = if pending_digests.is_empty() {
            canonicalize_bounded_with_xml_base_budget(
                doc,
                Some(&|node| signed_info_subtree.contains(&node.id())),
                &signed_info.c14n_method,
                budgets.transforms.remaining_c14n_output(),
                budgets.transforms.xml_base_resolution(),
                &mut canonical_signed_info,
            )
        } else {
            canonicalize_with_pending_digests(
                doc,
                &signed_info_subtree,
                &signed_info.c14n_method,
                budgets,
                &pending_digests,
                &mut canonical_signed_info,
            )
        };
        canonicalized.map_err(|error| {
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
            signed_info.signature_context,
        ))
    })
}

const SECOND_EDITION_GENERATION_C14N_URI: &str = "http://www.w3.org/2006/12/xml-c14n11";

/// Canonicalize `SignedInfo` as if each pending digest already filled its empty
/// `DigestValue`. C14N writes an empty element as a start tag followed by its
/// end tag and escapes `<` in attribute values, so the first `</` after the
/// element's start is that end tag. Base64 text needs no escaping (C14N 1.0
/// section 5.2), so inserting it there yields the canonical form of the filled
/// element. Digests outside `SignedInfo` are not part of its output.
/// <https://www.w3.org/TR/2001/REC-xml-c14n-20010315#ProcessingModel>
fn canonicalize_with_pending_digests(
    document: &Document<'_>,
    signed_info_subtree: &HashSet<NodeId>,
    algorithm: &crate::c14n::C14nAlgorithm,
    budgets: &SigningOperationBudgets,
    pending_digests: &[(NodeId, &str)],
    output: &mut Vec<u8>,
) -> Result<(), crate::c14n::C14nError> {
    let digests = pending_digests
        .iter()
        .copied()
        .filter(|(node, _)| signed_info_subtree.contains(node))
        .collect::<HashMap<_, _>>();
    let tracked = digests.keys().copied().collect::<Vec<_>>();
    let inserted = digests.values().map(|digest| digest.len()).sum::<usize>();
    let remaining = budgets.transforms.remaining_c14n_output();
    // Output that cannot hold the inserted digests exceeds the limit in either form.
    let Some(allowance) = remaining.checked_sub(inserted) else {
        return Err(crate::c14n::C14nError::OutputLimitExceeded {
            max_bytes: remaining,
        });
    };
    let mut unfilled = Vec::new();
    let mut positions = crate::c14n::canonicalize_bounded_with_xml_base_budget_and_positions(
        document,
        &|node| signed_info_subtree.contains(&node.id()),
        algorithm,
        &tracked,
        allowance,
        budgets.transforms.xml_base_resolution(),
        &mut unfilled,
    )?;
    debug_assert_eq!(
        positions.len(),
        tracked.len(),
        "every SignedInfo element is visible to its own canonicalization"
    );
    positions.sort_unstable_by_key(|(_, position)| *position);
    output.reserve(unfilled.len() + inserted);
    let mut cursor = 0;
    for (node, start) in positions {
        let end_tag = unfilled[start..]
            .windows(2)
            .position(|bytes| bytes == b"</")
            .map(|offset| start + offset)
            .expect("a canonical element is closed by an end tag");
        output.extend_from_slice(&unfilled[cursor..end_tag]);
        output.extend_from_slice(digests[&node].as_bytes());
        cursor = end_tag;
    }
    output.extend_from_slice(&unfilled[cursor..]);
    Ok(())
}

struct SourceEdit {
    range: Range<usize>,
    replacement: String,
}

fn generation_reference_nodes<'a>(
    signature: Node<'a, 'a>,
    policy: &crate::policy::SigningPolicy,
) -> Result<Vec<Node<'a, 'a>>, SigningDigestError> {
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

    Ok(reference_nodes)
}

fn c14n11_edit_for_reference(
    xml: &str,
    reference: Node<'_, '_>,
    structure: &SigningReferenceStructure<'_>,
) -> Result<SourceEdit, SigningDigestError> {
    let edit = if let Some(transforms_node) = structure.transforms_node {
        c14n11_edit_for_transforms(xml, transforms_node)?
    } else {
        let prefix = reference.prefix().unwrap_or_default();
        let qualifier = xml_qualifier(prefix);
        SourceEdit {
            range: structure.digest_method_node.range().start
                ..structure.digest_method_node.range().start,
            replacement: format!(
                "<{qualifier}Transforms><{qualifier}Transform Algorithm=\"{SECOND_EDITION_GENERATION_C14N_URI}\"/></{qualifier}Transforms>"
            ),
        }
    };
    Ok(edit)
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
        let reference_nodes = generation_reference_nodes(signature, policy)?;

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

            let edit = c14n11_edit_for_reference(view.xml(), reference_node, &structure)?;
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
            && algorithm != super::RELATIONSHIP_TRANSFORM_URI
            && !(cfg!(feature = "xslt") && algorithm == super::XSLT_TRANSFORM_URI)
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
            || *algorithm == super::RELATIONSHIP_TRANSFORM_URI
            || (cfg!(feature = "xslt") && *algorithm == super::XSLT_TRANSFORM_URI)
            || crate::c14n::C14nAlgorithm::from_uri(algorithm).is_some()
    })
}

#[cfg(test)]
mod generation_output_tests;

#[cfg(test)]
mod deferred_commit_tests;

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
        .map(|policy| DocumentParseSettings::from_policy(policy.xml, &policy.resources))
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
    let pem = super::signature::PemBlock::decode(private_key_pem)
        .ok_or(SigningKeyError::InvalidKeyPem)?;
    if pem.label != "PRIVATE KEY" {
        return Err(SigningKeyError::InvalidKeyFormat { label: pem.label });
    }
    Ok(pem.contents)
}

#[derive(Clone, Copy)]
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
mod error_conversion_tests;
