//! Signing-side XMLDSig digest computation.
//!
//! This pass fills `<DigestValue>` elements before `<SignedInfo>` is
//! canonicalized and signed. It intentionally uses a signing-template parser
//! instead of [`crate::xmldsig::parse::parse_signed_info`], because verification
//! must continue to reject empty or malformed stored digest values.

use base64::Engine;
use getrandom::SysRng;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use p256::pkcs8::{DecodePrivateKey, EncodePublicKey};
use p384::ecdsa::{Signature as P384Signature, SigningKey as P384SigningKey};
use roxmltree::{Document, Node};
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::Signature as RsaPkcs1v15Signature;
use rsa::pkcs1v15::SigningKey as RsaPkcs1v15SigningKey;
use rsa::signature::{RandomizedSigner, SignatureEncoding, Signer};
use rsa::traits::PublicKeyParts;
use sha2::{Sha256, Sha384, Sha512};
use std::collections::HashSet;
use x509_parser::prelude::FromDer;

use crate::c14n::canonicalize;

use super::builder::{SignatureBuilder, SignatureBuilderError};
use super::digest::{DigestAlgorithm, compute_digest};
use super::mutation::{
    XmlMutationError, append_signature_to_root, fill_key_info, fill_signature_value,
    fill_signed_info_digest_values,
};
use super::parse::{SignatureAlgorithm, XMLDSIG_NS, parse_signed_info};
use super::transforms::{Transform, execute_transforms, parse_transforms};
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

/// Private key abstraction used by [`SignContext`].
pub trait SigningKey {
    /// Sign canonicalized `<SignedInfo>` bytes for the declared XMLDSig method.
    fn sign(
        &self,
        algorithm: SignatureAlgorithm,
        canonical_signed_info: &[u8],
    ) -> Result<Vec<u8>, SigningKeyError>;

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

    /// The signing key could not expose public-key material for validation.
    #[error("signing key public-key extraction failed: {0}")]
    SigningKey(#[from] SigningKeyError),

    /// The configured certificate does not contain the signing key's public key.
    #[error("X.509 certificate public key does not match signing key")]
    CertificateKeyMismatch,
}

/// `<KeyInfo>` writer that embeds one DER X.509 certificate.
pub struct X509CertificateKeyInfoWriter {
    certificate_der: Vec<u8>,
}

impl X509CertificateKeyInfoWriter {
    /// Parse a PEM `CERTIFICATE` block for XMLDSig `<X509Certificate>` output.
    pub fn from_pem(certificate_pem: &str) -> Result<Self, KeyInfoWriteError> {
        let (rest, pem) = x509_parser::pem::parse_x509_pem(certificate_pem.as_bytes())
            .map_err(|_| KeyInfoWriteError::InvalidCertificatePem)?;
        if !rest.iter().all(|byte| byte.is_ascii_whitespace()) {
            return Err(KeyInfoWriteError::InvalidCertificatePem);
        }
        if pem.label != "CERTIFICATE" {
            return Err(KeyInfoWriteError::InvalidCertificateFormat { label: pem.label });
        }
        Self::from_der(&pem.contents)
    }

    /// Validate and store DER certificate bytes for XMLDSig `<X509Certificate>` output.
    pub fn from_der(certificate_der: &[u8]) -> Result<Self, KeyInfoWriteError> {
        let (rest, _) = x509_parser::certificate::X509Certificate::from_der(certificate_der)
            .map_err(|_| KeyInfoWriteError::InvalidCertificateDer)?;
        if !rest.is_empty() {
            return Err(KeyInfoWriteError::InvalidCertificateDer);
        }
        Ok(Self {
            certificate_der: certificate_der.to_vec(),
        })
    }
}

impl KeyInfoWriter for X509CertificateKeyInfoWriter {
    fn write_key_info(&self, signing_key: &dyn SigningKey) -> Result<String, KeyInfoWriteError> {
        let (rest, certificate) =
            x509_parser::certificate::X509Certificate::from_der(&self.certificate_der)
                .map_err(|_| KeyInfoWriteError::InvalidCertificateDer)?;
        if !rest.is_empty() {
            return Err(KeyInfoWriteError::InvalidCertificateDer);
        }
        let signing_public_key = signing_key.public_key_info()?;
        if certificate.public_key().raw != signing_public_key.spki_der() {
            return Err(KeyInfoWriteError::CertificateKeyMismatch);
        }

        let certificate_b64 =
            base64::engine::general_purpose::STANDARD.encode(&self.certificate_der);
        Ok(format!(
            "<X509Data xmlns=\"{XMLDSIG_NS}\"><X509Certificate>{certificate_b64}</X509Certificate></X509Data>"
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
}

impl SigningKey for RsaSigningKey {
    fn sign(
        &self,
        algorithm: SignatureAlgorithm,
        canonical_signed_info: &[u8],
    ) -> Result<Vec<u8>, SigningKeyError> {
        match algorithm {
            SignatureAlgorithm::RsaSha256 => sign_rsa_pkcs1v15_with_rng(
                RsaPkcs1v15SigningKey::<Sha256>::new(self.key.clone()),
                canonical_signed_info,
            ),
            SignatureAlgorithm::RsaSha384 => sign_rsa_pkcs1v15_with_rng(
                RsaPkcs1v15SigningKey::<Sha384>::new(self.key.clone()),
                canonical_signed_info,
            ),
            SignatureAlgorithm::RsaSha512 => sign_rsa_pkcs1v15_with_rng(
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
    key: impl RandomizedSigner<RsaPkcs1v15Signature>,
    canonical_signed_info: &[u8],
) -> Result<Vec<u8>, SigningKeyError> {
    let signature = key
        .try_sign_with_rng(&mut SysRng, canonical_signed_info)
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
        if algorithm != SignatureAlgorithm::EcdsaP256Sha256 {
            return Err(SigningKeyError::UnsupportedAlgorithm {
                uri: algorithm.uri().to_string(),
            });
        }
        let signature: P256Signature = self
            .key
            .try_sign(canonical_signed_info)
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
        if algorithm != SignatureAlgorithm::EcdsaP384Sha384 {
            return Err(SigningKeyError::UnsupportedAlgorithm {
                uri: algorithm.uri().to_string(),
            });
        }
        let signature: P384Signature = self
            .key
            .try_sign(canonical_signed_info)
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
}

impl<'a> SignContext<'a> {
    /// Create a signing context using the supplied private key.
    pub fn new(signing_key: &'a dyn SigningKey) -> Self {
        Self {
            signing_key,
            key_info_writer: None,
        }
    }

    /// Configure signing to populate the direct `<Signature>/<KeyInfo>` placeholder.
    #[must_use]
    pub fn key_info_writer(mut self, writer: &'a dyn KeyInfoWriter) -> Self {
        self.key_info_writer = Some(writer);
        self
    }

    /// Sign XML that already contains a `<Signature>` template.
    ///
    /// The template must include empty `<DigestValue>` and `<SignatureValue>`
    /// targets. The pipeline fills reference digests, reparses the result,
    /// canonicalizes `<SignedInfo>`, signs those canonical bytes, and fills the
    /// base64 `<SignatureValue>`.
    pub fn sign_template(&self, xml: &str) -> Result<String, SigningError> {
        let with_digests = fill_reference_digest_values(xml)?;
        let (algorithm, canonical_signed_info) = canonicalize_signed_info(&with_digests)?;
        let signature_value = self.signing_key.sign(algorithm, &canonical_signed_info)?;
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature_value);
        let signed = fill_signature_value(&with_digests, &signature_b64)?;
        if let Some(writer) = self.key_info_writer {
            let key_info_content = writer.write_key_info(self.signing_key)?;
            Ok(fill_key_info(&signed, &key_info_content)?)
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
        let template = builder.build_template()?;
        let templated = append_signature_to_root(xml, &template)?;
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
    let doc = Document::parse(xml)?;
    let signature = find_signing_signature_node(&doc)?;
    let signed_info = find_required_child(signature, "SignedInfo")?;
    let references = parse_signing_references(signed_info)?;
    let resolver = UriReferenceResolver::new(&doc);

    references
        .into_iter()
        .enumerate()
        .map(|(index, reference)| {
            let initial_data = resolver.dereference(&reference.uri)?;
            let pre_digest = execute_transforms(signature, initial_data, &reference.transforms)?;
            let digest = compute_digest(reference.digest_method, &pre_digest);
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
    let digest_values = compute_reference_digest_values(xml)?
        .into_iter()
        .map(|digest| digest.digest_value);
    Ok(fill_signed_info_digest_values(xml, digest_values)?)
}

fn canonicalize_signed_info(xml: &str) -> Result<(SignatureAlgorithm, Vec<u8>), SigningError> {
    let doc = Document::parse(xml).map_err(SigningDigestError::XmlParse)?;
    let signature = find_signing_signature_node(&doc).map_err(SigningError::Digest)?;
    let signed_info_node =
        find_required_child(signature, "SignedInfo").map_err(SigningError::Digest)?;
    let signed_info = parse_signed_info(signed_info_node)?;
    let signed_info_subtree: HashSet<_> = signed_info_node
        .descendants()
        .map(|node: Node<'_, '_>| node.id())
        .collect();
    let mut canonical_signed_info = Vec::new();
    canonicalize(
        &doc,
        Some(&|node| signed_info_subtree.contains(&node.id())),
        &signed_info.c14n_method,
        &mut canonical_signed_info,
    )?;
    Ok((signed_info.signature_method, canonical_signed_info))
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
) -> Result<Node<'a, 'a>, SigningDigestError> {
    doc.descendants()
        .rfind(|node| {
            node.is_element()
                && node.tag_name().name() == "Signature"
                && node.tag_name().namespace() == Some(XMLDSIG_NS)
        })
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
    for child in children {
        verify_ds_element(child, "Reference")?;
        references.push(parse_signing_reference(child)?);
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
        transforms = parse_transforms(next)?;
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
