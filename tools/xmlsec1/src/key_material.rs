use std::{
    fs::File,
    io::Read as _,
    path::{Path, PathBuf},
};

use crypto_bigint::{
    BoxedUint,
    modular::{BoxedMontyForm, BoxedMontyParams},
};
use der::{Decode as _, asn1::UintRef};
use dsa::{
    Components as DsaComponents, SigningKey as NativeDsaSigningKey, VerifyingKey as DsaVerifyingKey,
};
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs1::{DecodeRsaPrivateKey as _, DecodeRsaPublicKey as _},
    pkcs8::{
        DecodePrivateKey as _, DecodePublicKey as _, EncodePrivateKey as _, EncodePublicKey as _,
        EncryptedPrivateKeyInfoRef, PrivateKeyInfoRef,
    },
};
use x509_parser::prelude::FromDer as _;
use xml_sec::policy::{PolicyViolation, SigningPolicy, VerificationPolicy};
use xml_sec::xmldsig::{
    DsaSigningKey, DsigError, EcdsaP256SigningKey, EcdsaP384SigningKey, EcdsaP521SigningKey,
    KeyInfo, ReferenceProcessingError, RsaSigningKey, SignatureAlgorithm, SigningKey,
    VerificationKey, find_signature_node, materialize_signing_key_info_references,
    materialize_verification_key_info_references, parse_key_info, parse_signed_info,
    uri::UriReferenceResolver,
};
use xml_sec::{
    XmlDomDocument as Document, XmlDomNode as Node, XmlDomParsingOptions as ParsingOptions,
};
use zeroize::Zeroizing;

// This is an absolute process-safety ceiling, not deployment policy. Parsed
// key sizes remain governed by the operation policy after bounded ingestion.
const KEY_MATERIAL_BYTE_CEILING: usize = 8 * 1024 * 1024;
const MAX_AES_KEY_BYTES: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum KeyMaterialError {
    #[error("failed to read key file {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid PEM key in {}", .0.display())]
    InvalidPem(PathBuf),
    #[error("unsupported private key in {}", .0.display())]
    UnsupportedPrivateKey(PathBuf),
    #[error("unsupported public key in {}", .0.display())]
    UnsupportedPublicKey(PathBuf),
    #[error("invalid X.509 certificate in {}", .0.display())]
    InvalidCertificate(PathBuf),
    #[error("signature template does not contain a valid SignedInfo")]
    MissingSignedInfo,
    #[error("selected node ID is missing or ambiguous: {0}")]
    SelectedNodeUnavailable(String),
    #[error("invalid XML signature: {0}")]
    Signature(String),
    #[error("invalid symmetric key length: expected {expected} bytes, got {actual}")]
    SymmetricLength { expected: usize, actual: usize },
    #[error("symmetric key exceeds maximum {maximum} bytes")]
    SymmetricTooLarge { maximum: usize },
    #[error(
        "key material in {} exceeds maximum {maximum} bytes",
        path.display()
    )]
    KeyMaterialTooLarge { path: PathBuf, maximum: usize },
    #[error("invalid operation policy: {0}")]
    Policy(#[from] PolicyViolation),
}

#[derive(Debug, Eq, PartialEq)]
pub struct SignatureMetadata {
    pub algorithm: SignatureAlgorithm,
    pub key_names: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationKeyNameResolution {
    IgnoreDocumentKeyInfo,
    ResolveDocumentKeyInfo,
}

#[derive(Debug, Eq, PartialEq)]
pub struct SigningTemplateMetadata {
    pub algorithm: SignatureAlgorithm,
    pub key_names: Vec<String>,
    pub key_info: Option<KeyInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateKeyFormat {
    Pem,
    Der,
    Pkcs8Pem,
    Pkcs8Der,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicKeyEncoding {
    Pem,
    Der,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateEncoding {
    Pem,
    Der,
}

pub fn read(path: impl AsRef<Path>) -> Result<Vec<u8>, KeyMaterialError> {
    let path = path.as_ref();
    let mut bytes = Vec::with_capacity(KEY_MATERIAL_BYTE_CEILING.min(64 * 1024));
    File::open(path)
        .map_err(|source| KeyMaterialError::Read {
            path: path.to_owned(),
            source,
        })?
        .take(KEY_MATERIAL_BYTE_CEILING.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| KeyMaterialError::Read {
            path: path.to_owned(),
            source,
        })?;
    if bytes.len() > KEY_MATERIAL_BYTE_CEILING {
        return Err(KeyMaterialError::KeyMaterialTooLarge {
            path: path.to_owned(),
            maximum: KEY_MATERIAL_BYTE_CEILING,
        });
    }
    Ok(bytes)
}

/// Read metadata from the first descendant signature below the selected start node.
///
/// libxmlsec1 uses a depth-first `xmlSecFindNode` lookup from the operation start
/// node, so later signatures in the same subtree do not make selection ambiguous.
/// Reference materialization is a key-selection concern: callers that pin a
/// complete direct identity should request `IgnoreDocumentKeyInfo` and leave unused
/// document references to the core resolver's `consumes_document_key_info`
/// contract.
pub fn verification_signature_metadata(
    xml: &str,
    start_node_id: Option<&str>,
    id_attributes: &[xml_sec::IdAttributeRegistration],
    policy: &VerificationPolicy,
    key_name_resolution: VerificationKeyNameResolution,
    xml_backend: xml_sec::XmlBackend,
) -> Result<SignatureMetadata, KeyMaterialError> {
    policy.validate()?;
    let document = parse_signature_document(
        xml,
        policy.xml.allow_internal_dtd,
        policy.resources.max_xml_nodes,
        xml_backend,
    )?;
    let signature = select_signature(&document, start_node_id, id_attributes)?;
    let signed_info = signature
        .children()
        .find(|node| node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "SignedInfo")))
        .ok_or(KeyMaterialError::MissingSignedInfo)?;
    let algorithm = parse_signed_info(signed_info)
        .map(|info| info.signature_method)
        .map_err(|error| KeyMaterialError::Signature(error.to_string()))?;
    let key_info = if key_name_resolution == VerificationKeyNameResolution::IgnoreDocumentKeyInfo {
        None
    } else {
        let mut key_info = signature_key_info(signature)
            .map(parse_key_info)
            .transpose()
            .map_err(|error| KeyMaterialError::Signature(error.to_string()))?;
        if let Some(key_info) = &mut key_info {
            let resolver = UriReferenceResolver::with_id_registrations(&document, id_attributes);
            materialize_verification_key_info_references(
                key_info,
                resolver,
                policy,
                xml_sec::provider::default_provider(),
                xml_backend,
            )
            .map_err(map_key_info_reference_error)?;
        }
        key_info
    };
    Ok(SignatureMetadata {
        algorithm,
        key_names: key_names(&key_info),
    })
}

pub fn signing_signature_metadata(
    xml: &str,
    start_node_id: Option<&str>,
    id_attributes: &[xml_sec::IdAttributeRegistration],
    policy: &SigningPolicy,
    xml_backend: xml_sec::XmlBackend,
) -> Result<SigningTemplateMetadata, KeyMaterialError> {
    policy.validate()?;
    let document = parse_signature_document(
        xml,
        policy.xml.allow_internal_dtd,
        policy.resources.max_xml_nodes,
        xml_backend,
    )?;
    let signature = select_signature(&document, start_node_id, id_attributes)?;
    let algorithm_uri = signature
        .children()
        .find(|node| node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "SignedInfo")))
        .and_then(|signed_info| {
            signed_info.children().find(|node| {
                node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "SignatureMethod"))
            })
        })
        .and_then(|method| method.attribute("Algorithm"))
        .ok_or(KeyMaterialError::MissingSignedInfo)?;
    let algorithm = SignatureAlgorithm::from_uri(algorithm_uri).ok_or_else(|| {
        KeyMaterialError::Signature(format!("unsupported signature algorithm: {algorithm_uri}"))
    })?;
    let mut key_info = signature_key_info(signature)
        .map(parse_key_info)
        .transpose()
        .map_err(|error| KeyMaterialError::Signature(error.to_string()))?;
    if let Some(key_info) = &mut key_info {
        let resolver = UriReferenceResolver::with_id_registrations(&document, id_attributes);
        materialize_signing_key_info_references(
            key_info,
            resolver,
            policy,
            xml_sec::provider::default_provider(),
            xml_backend,
        )
        .map_err(map_key_info_reference_error)?;
    }
    Ok(SigningTemplateMetadata {
        algorithm,
        key_names: key_names(&key_info),
        key_info,
    })
}

fn map_key_info_reference_error(error: DsigError) -> KeyMaterialError {
    match error {
        DsigError::Policy(error) => KeyMaterialError::Policy(error),
        DsigError::InvalidStructure { reason } => KeyMaterialError::Signature(reason.to_owned()),
        DsigError::Reference(ReferenceProcessingError::UriDereference(error)) => {
            KeyMaterialError::Signature(error.to_string())
        }
        DsigError::ParseKeyInfo(error) => KeyMaterialError::Signature(error.to_string()),
        error => KeyMaterialError::Signature(error.to_string()),
    }
}

fn select_signature<'a>(
    document: &'a Document<'a>,
    start_node_id: Option<&str>,
    id_attributes: &[xml_sec::IdAttributeRegistration],
) -> Result<Node<'a, 'a>, KeyMaterialError> {
    match start_node_id {
        Some(id) => UriReferenceResolver::with_id_registrations(document, id_attributes)
            .node_for_id(id)
            .ok_or_else(|| KeyMaterialError::SelectedNodeUnavailable(id.to_owned()))?
            .descendants()
            .find(|node| node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "Signature"))),
        None => find_signature_node(document),
    }
    .ok_or(KeyMaterialError::MissingSignedInfo)
}

fn parse_signature_document(
    xml: &str,
    allow_internal_dtd: bool,
    max_xml_nodes: usize,
    xml_backend: xml_sec::XmlBackend,
) -> Result<Document<'_>, KeyMaterialError> {
    let nodes_limit = u32::try_from(max_xml_nodes).map_err(|_| {
        KeyMaterialError::Signature("XML node ceiling does not fit the parser limit".into())
    })?;
    Document::parse_with_options_and_backend(
        xml,
        ParsingOptions {
            allow_dtd: allow_internal_dtd,
            nodes_limit,
        },
        xml_backend,
    )
    .map_err(|error| KeyMaterialError::Signature(error.to_string()))
}

fn key_names(key_info: &Option<KeyInfo>) -> Vec<String> {
    key_info
        .iter()
        .flat_map(|key_info| &key_info.sources)
        .filter_map(|source| match source {
            xml_sec::xmldsig::KeyInfoSource::KeyName(name) => Some(name.clone()),
            _ => None,
        })
        .collect()
}

fn signature_key_info<'a, 'input>(signature: Node<'a, 'input>) -> Option<Node<'a, 'input>> {
    signature
        .children()
        .find(|node| node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "KeyInfo")))
}

/// Decode caller-owned signing key bytes after the operation layer has charged
/// their source length to its aggregate external-material budget.
///
/// `--pwd` is a credential available while reading a key, not a declaration
/// that the selected container is encrypted. Container structure selects the
/// decoder first, so a wrong password cannot fall through into plaintext key
/// parsing while an unencrypted key remains valid when a password was supplied.
pub fn decode_signing_key(
    path: &Path,
    bytes: &[u8],
    format: PrivateKeyFormat,
    algorithm: SignatureAlgorithm,
    password: Option<&[u8]>,
) -> Result<Box<dyn SigningKey>, KeyMaterialError> {
    match algorithm {
        SignatureAlgorithm::RsaSha1
        | SignatureAlgorithm::RsaSha224
        | SignatureAlgorithm::RsaSha256
        | SignatureAlgorithm::RsaSha384
        | SignatureAlgorithm::RsaSha512 => decode_rsa_signing_key(path, bytes, format, password),
        SignatureAlgorithm::DsaSha1 | SignatureAlgorithm::DsaSha256 => {
            decode_dsa_signing_key(path, bytes, format, password)
        }
        SignatureAlgorithm::EcdsaSha1
        | SignatureAlgorithm::EcdsaSha224
        | SignatureAlgorithm::EcdsaSha256
        | SignatureAlgorithm::EcdsaSha384
        | SignatureAlgorithm::EcdsaSha512 => {
            decode_ecdsa_signing_key(path, bytes, format, password)
        }
        SignatureAlgorithm::HmacSha1
        | SignatureAlgorithm::HmacSha224
        | SignatureAlgorithm::HmacSha256
        | SignatureAlgorithm::HmacSha384
        | SignatureAlgorithm::HmacSha512 => {
            Err(KeyMaterialError::UnsupportedPrivateKey(path.to_owned()))
        }
        _ => Err(KeyMaterialError::UnsupportedPrivateKey(path.to_owned())),
    }
}

trait Pkcs8SigningKey: SigningKey + Sized + 'static {
    fn decode_pkcs8_pem(text: &str) -> Result<Self, xml_sec::xmldsig::SigningKeyError>;
    fn decode_pkcs8_der(bytes: &[u8]) -> Result<Self, xml_sec::xmldsig::SigningKeyError>;
    fn decode_pkcs8_encrypted_pem(
        text: &str,
        password: &[u8],
    ) -> Result<Self, xml_sec::xmldsig::SigningKeyError>;
    fn decode_pkcs8_encrypted_der(
        bytes: &[u8],
        password: &[u8],
    ) -> Result<Self, xml_sec::xmldsig::SigningKeyError>;
}

trait Sec1SigningKey: SigningKey + Sized + 'static {
    fn decode_sec1_pem(text: &str) -> Result<Self, xml_sec::xmldsig::SigningKeyError>;
    fn decode_sec1_der(bytes: &[u8]) -> Result<Self, xml_sec::xmldsig::SigningKeyError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Pkcs8ContainerKind {
    Plain,
    Encrypted,
}

#[derive(der::Sequence)]
struct TraditionalDsaPrivateKey<'a> {
    version: u8,
    p: UintRef<'a>,
    q: UintRef<'a>,
    g: UintRef<'a>,
    y: UintRef<'a>,
    x: UintRef<'a>,
}

fn pkcs8_container_kind(bytes: &[u8], format: PrivateKeyFormat) -> Option<Pkcs8ContainerKind> {
    match format {
        PrivateKeyFormat::Pem | PrivateKeyFormat::Pkcs8Pem => {
            match rsa::pkcs8::der::pem::decode_label(bytes).ok()? {
                "PRIVATE KEY" => Some(Pkcs8ContainerKind::Plain),
                "ENCRYPTED PRIVATE KEY" => Some(Pkcs8ContainerKind::Encrypted),
                _ => None,
            }
        }
        PrivateKeyFormat::Der | PrivateKeyFormat::Pkcs8Der => {
            if PrivateKeyInfoRef::try_from(bytes).is_ok() {
                Some(Pkcs8ContainerKind::Plain)
            } else if EncryptedPrivateKeyInfoRef::try_from(bytes).is_ok() {
                Some(Pkcs8ContainerKind::Encrypted)
            } else {
                None
            }
        }
    }
}

macro_rules! impl_pkcs8_signing_key {
    ($($key:ty),+ $(,)?) => {
        $(
            impl Pkcs8SigningKey for $key {
                fn decode_pkcs8_pem(
                    text: &str,
                ) -> Result<Self, xml_sec::xmldsig::SigningKeyError> {
                    Self::from_pkcs8_pem(text)
                }

                fn decode_pkcs8_der(
                    bytes: &[u8],
                ) -> Result<Self, xml_sec::xmldsig::SigningKeyError> {
                    Self::from_pkcs8_der(bytes)
                }

                fn decode_pkcs8_encrypted_pem(
                    text: &str,
                    password: &[u8],
                ) -> Result<Self, xml_sec::xmldsig::SigningKeyError> {
                    Self::from_pkcs8_encrypted_pem(text, password)
                }

                fn decode_pkcs8_encrypted_der(
                    bytes: &[u8],
                    password: &[u8],
                ) -> Result<Self, xml_sec::xmldsig::SigningKeyError> {
                    Self::from_pkcs8_encrypted_der(bytes, password)
                }
            }
        )+
    };
}

impl_pkcs8_signing_key!(
    RsaSigningKey,
    DsaSigningKey,
    EcdsaP256SigningKey,
    EcdsaP384SigningKey,
    EcdsaP521SigningKey,
);

macro_rules! impl_sec1_signing_key {
    ($($key:ty),+ $(,)?) => {
        $(
            impl Sec1SigningKey for $key {
                fn decode_sec1_pem(
                    text: &str,
                ) -> Result<Self, xml_sec::xmldsig::SigningKeyError> {
                    Self::from_sec1_pem(text)
                }

                fn decode_sec1_der(
                    bytes: &[u8],
                ) -> Result<Self, xml_sec::xmldsig::SigningKeyError> {
                    Self::from_sec1_der(bytes)
                }
            }
        )+
    };
}

impl_sec1_signing_key!(
    EcdsaP256SigningKey,
    EcdsaP384SigningKey,
    EcdsaP521SigningKey,
);

fn decode_pkcs8_signing_key<K: Pkcs8SigningKey>(
    path: &Path,
    bytes: &[u8],
    format: PrivateKeyFormat,
    password: Option<&[u8]>,
) -> Result<Box<dyn SigningKey>, KeyMaterialError> {
    let key = match (format, pkcs8_container_kind(bytes, format), password) {
        (
            PrivateKeyFormat::Pem | PrivateKeyFormat::Pkcs8Pem,
            Some(Pkcs8ContainerKind::Plain),
            _,
        ) => std::str::from_utf8(bytes)
            .ok()
            .and_then(|text| K::decode_pkcs8_pem(text).ok()),
        (
            PrivateKeyFormat::Der | PrivateKeyFormat::Pkcs8Der,
            Some(Pkcs8ContainerKind::Plain),
            _,
        ) => K::decode_pkcs8_der(bytes).ok(),
        (
            PrivateKeyFormat::Pem | PrivateKeyFormat::Pkcs8Pem,
            Some(Pkcs8ContainerKind::Encrypted),
            Some(password),
        ) => std::str::from_utf8(bytes)
            .ok()
            .and_then(|text| K::decode_pkcs8_encrypted_pem(text, password).ok()),
        (
            PrivateKeyFormat::Der | PrivateKeyFormat::Pkcs8Der,
            Some(Pkcs8ContainerKind::Encrypted),
            Some(password),
        ) => K::decode_pkcs8_encrypted_der(bytes, password).ok(),
        (_, Some(Pkcs8ContainerKind::Encrypted) | None, _) => None,
    };
    key.map(|key| Box::new(key) as Box<dyn SigningKey>)
        .ok_or_else(|| KeyMaterialError::UnsupportedPrivateKey(path.to_owned()))
}

fn decode_ecdsa_signing_key(
    path: &Path,
    bytes: &[u8],
    format: PrivateKeyFormat,
    password: Option<&[u8]>,
) -> Result<Box<dyn SigningKey>, KeyMaterialError> {
    decode_ecdsa_curve::<EcdsaP256SigningKey>(path, bytes, format, password)
        .or_else(|_| decode_ecdsa_curve::<EcdsaP384SigningKey>(path, bytes, format, password))
        .or_else(|_| decode_ecdsa_curve::<EcdsaP521SigningKey>(path, bytes, format, password))
}

fn decode_ecdsa_curve<K: Pkcs8SigningKey + Sec1SigningKey>(
    path: &Path,
    bytes: &[u8],
    format: PrivateKeyFormat,
    password: Option<&[u8]>,
) -> Result<Box<dyn SigningKey>, KeyMaterialError> {
    if pkcs8_container_kind(bytes, format).is_some() {
        return decode_pkcs8_signing_key::<K>(path, bytes, format, password);
    }

    let key = match format {
        PrivateKeyFormat::Pem => std::str::from_utf8(bytes)
            .ok()
            .and_then(|text| K::decode_sec1_pem(text).ok()),
        PrivateKeyFormat::Der => K::decode_sec1_der(bytes).ok(),
        PrivateKeyFormat::Pkcs8Pem | PrivateKeyFormat::Pkcs8Der => None,
    };
    key.map(|key| Box::new(key) as Box<dyn SigningKey>)
        .ok_or_else(|| KeyMaterialError::UnsupportedPrivateKey(path.to_owned()))
}

fn decode_dsa_signing_key(
    path: &Path,
    bytes: &[u8],
    format: PrivateKeyFormat,
    password: Option<&[u8]>,
) -> Result<Box<dyn SigningKey>, KeyMaterialError> {
    if pkcs8_container_kind(bytes, format).is_some() {
        return decode_pkcs8_signing_key::<DsaSigningKey>(path, bytes, format, password);
    }

    let pem_der = match format {
        PrivateKeyFormat::Pem => {
            let text = std::str::from_utf8(bytes)
                .map_err(|_| KeyMaterialError::UnsupportedPrivateKey(path.to_owned()))?;
            Some(Zeroizing::new(
                parse_pem(text, "DSA PRIVATE KEY", path)
                    .map_err(|_| KeyMaterialError::UnsupportedPrivateKey(path.to_owned()))?,
            ))
        }
        PrivateKeyFormat::Der => None,
        PrivateKeyFormat::Pkcs8Pem | PrivateKeyFormat::Pkcs8Der => {
            return Err(KeyMaterialError::UnsupportedPrivateKey(path.to_owned()));
        }
    };
    let der = pem_der.as_deref().map_or(bytes, Vec::as_slice);
    let traditional = TraditionalDsaPrivateKey::from_der(der)
        .map_err(|_| KeyMaterialError::UnsupportedPrivateKey(path.to_owned()))?;
    if traditional.version != 0 {
        return Err(KeyMaterialError::UnsupportedPrivateKey(path.to_owned()));
    }

    let p = BoxedUint::from_be_slice_vartime(traditional.p.as_bytes());
    let q = BoxedUint::from_be_slice_vartime(traditional.q.as_bytes());
    let g = BoxedUint::from_be_slice_vartime(traditional.g.as_bytes());
    let y = BoxedUint::from_be_slice_vartime(traditional.y.as_bytes());
    let x = BoxedUint::from_be_slice_vartime(traditional.x.as_bytes());
    let components = DsaComponents::from_components(p, q, g)
        .map_err(|_| KeyMaterialError::UnsupportedPrivateKey(path.to_owned()))?;

    let params = BoxedMontyParams::new(components.p().clone());
    let expected_y = BoxedMontyForm::new((**components.g()).clone(), &params)
        .pow(&x)
        .retrieve();
    if expected_y != y {
        return Err(KeyMaterialError::UnsupportedPrivateKey(path.to_owned()));
    }

    let verifying_key = DsaVerifyingKey::from_components(components, y)
        .map_err(|_| KeyMaterialError::UnsupportedPrivateKey(path.to_owned()))?;
    let key = NativeDsaSigningKey::from_components(verifying_key, x)
        .map_err(|_| KeyMaterialError::UnsupportedPrivateKey(path.to_owned()))?;
    let normalized = key
        .to_pkcs8_der()
        .map_err(|_| KeyMaterialError::UnsupportedPrivateKey(path.to_owned()))?;
    DsaSigningKey::from_pkcs8_der(normalized.as_bytes())
        .map(|key| Box::new(key) as Box<dyn SigningKey>)
        .map_err(|_| KeyMaterialError::UnsupportedPrivateKey(path.to_owned()))
}

fn decode_rsa_signing_key(
    path: &Path,
    bytes: &[u8],
    format: PrivateKeyFormat,
    password: Option<&[u8]>,
) -> Result<Box<dyn SigningKey>, KeyMaterialError> {
    if pkcs8_container_kind(bytes, format).is_some() {
        return decode_pkcs8_signing_key::<RsaSigningKey>(path, bytes, format, password);
    }
    match format {
        PrivateKeyFormat::Pem => std::str::from_utf8(bytes)
            .ok()
            .and_then(|text| RsaPrivateKey::from_pkcs1_pem(text).ok())
            .map_or_else(
                || Err(KeyMaterialError::UnsupportedPrivateKey(path.to_owned())),
                |key| normalize_rsa_signing_key(key, path),
            ),
        PrivateKeyFormat::Der => RsaPrivateKey::from_pkcs1_der(bytes).map_or_else(
            |_| Err(KeyMaterialError::UnsupportedPrivateKey(path.to_owned())),
            |key| normalize_rsa_signing_key(key, path),
        ),
        PrivateKeyFormat::Pkcs8Pem | PrivateKeyFormat::Pkcs8Der => {
            Err(KeyMaterialError::UnsupportedPrivateKey(path.to_owned()))
        }
    }
}

fn normalize_rsa_signing_key(
    rsa: RsaPrivateKey,
    path: &Path,
) -> Result<Box<dyn SigningKey>, KeyMaterialError> {
    let der = rsa
        .to_pkcs8_der()
        .map_err(|_| KeyMaterialError::UnsupportedPrivateKey(path.to_owned()))?;
    RsaSigningKey::from_pkcs8_der(der.as_bytes())
        .map(|key| Box::new(key) as Box<dyn SigningKey>)
        .map_err(|_| KeyMaterialError::UnsupportedPrivateKey(path.to_owned()))
}

#[cfg(test)]
pub fn load_verification_key(
    path: impl AsRef<Path>,
    encoding: PublicKeyEncoding,
    algorithm: SignatureAlgorithm,
) -> Result<VerificationKey, KeyMaterialError> {
    let path = path.as_ref();
    let bytes = read(path)?;
    decode_verification_key(path, &bytes, encoding, algorithm)
}

/// Decode caller-owned verification key bytes after the operation layer has
/// charged their source length to its aggregate external-material budget.
pub fn decode_verification_key(
    path: &Path,
    bytes: &[u8],
    encoding: PublicKeyEncoding,
    algorithm: SignatureAlgorithm,
) -> Result<VerificationKey, KeyMaterialError> {
    let public_key_bytes = match encoding {
        PublicKeyEncoding::Pem => {
            let text = std::str::from_utf8(bytes)
                .map_err(|_| KeyMaterialError::UnsupportedPublicKey(path.to_owned()))?;
            parse_pem(text, "PUBLIC KEY", path).or_else(|_| {
                RsaPublicKey::from_pkcs1_pem(text)
                    .ok()
                    .and_then(|key| key.to_public_key_der().ok())
                    .map(|der| der.as_bytes().to_vec())
                    .ok_or_else(|| KeyMaterialError::UnsupportedPublicKey(path.to_owned()))
            })?
        }
        PublicKeyEncoding::Der if valid_spki(bytes) => bytes.to_vec(),
        PublicKeyEncoding::Der => RsaPublicKey::from_pkcs1_der(bytes)
            .ok()
            .and_then(|key| key.to_public_key_der().ok())
            .map(|der| der.as_bytes().to_vec())
            .ok_or_else(|| KeyMaterialError::UnsupportedPublicKey(path.to_owned()))?,
    };
    if !valid_spki(&public_key_bytes) {
        return Err(KeyMaterialError::UnsupportedPublicKey(path.to_owned()));
    }
    Ok(VerificationKey {
        algorithm,
        public_key_bytes,
        certificate_der: None,
        name: None,
    })
}

fn valid_spki(bytes: &[u8]) -> bool {
    x509_parser::x509::SubjectPublicKeyInfo::from_der(bytes).is_ok_and(|(rest, _)| rest.is_empty())
}

#[cfg(test)]
pub(crate) fn load_certificate_with_source_len(
    path: impl AsRef<Path>,
    encoding: CertificateEncoding,
) -> Result<(Vec<u8>, usize), KeyMaterialError> {
    let path = path.as_ref();
    let bytes = read(path)?;
    let source_len = bytes.len();
    let der = decode_certificate(path, &bytes, encoding)?;
    Ok((der, source_len))
}

/// Decode certificate bytes after the operation layer has charged the source.
pub(crate) fn decode_certificate(
    path: &Path,
    bytes: &[u8],
    encoding: CertificateEncoding,
) -> Result<Vec<u8>, KeyMaterialError> {
    let der = match encoding {
        CertificateEncoding::Pem => {
            let text = std::str::from_utf8(bytes)
                .map_err(|_| KeyMaterialError::InvalidCertificate(path.to_owned()))?;
            parse_pem(text, "CERTIFICATE", path)
                .map_err(|_| KeyMaterialError::InvalidCertificate(path.to_owned()))?
        }
        CertificateEncoding::Der => bytes.to_vec(),
    };
    let (rest, _) = x509_parser::certificate::X509Certificate::from_der(&der)
        .map_err(|_| KeyMaterialError::InvalidCertificate(path.to_owned()))?;
    if !rest.is_empty() {
        return Err(KeyMaterialError::InvalidCertificate(path.to_owned()));
    }
    Ok(der)
}

fn parse_pem(text: &str, expected_label: &str, path: &Path) -> Result<Vec<u8>, KeyMaterialError> {
    let (rest, pem) = x509_parser::pem::parse_x509_pem(text.as_bytes())
        .map_err(|_| KeyMaterialError::InvalidPem(path.to_owned()))?;
    if !rest.iter().all(u8::is_ascii_whitespace) || pem.label != expected_label {
        return Err(KeyMaterialError::InvalidPem(path.to_owned()));
    }
    Ok(pem.contents)
}

#[cfg(test)]
pub fn load_rsa_private(
    path: impl AsRef<Path>,
    format: PrivateKeyFormat,
) -> Result<RsaPrivateKey, KeyMaterialError> {
    let path = path.as_ref();
    let bytes = read(path)?;
    decode_rsa_private(path, &bytes, format)
}

/// Decode caller-owned RSA private-key bytes after the operation layer has
/// charged their source length to its aggregate external-material budget.
pub fn decode_rsa_private(
    path: &Path,
    bytes: &[u8],
    format: PrivateKeyFormat,
) -> Result<RsaPrivateKey, KeyMaterialError> {
    match format {
        PrivateKeyFormat::Pem => std::str::from_utf8(bytes).ok().and_then(|text| {
            RsaPrivateKey::from_pkcs8_pem(text)
                .or_else(|_| RsaPrivateKey::from_pkcs1_pem(text))
                .ok()
        }),
        PrivateKeyFormat::Der => RsaPrivateKey::from_pkcs8_der(bytes)
            .or_else(|_| RsaPrivateKey::from_pkcs1_der(bytes))
            .ok(),
        PrivateKeyFormat::Pkcs8Pem => std::str::from_utf8(bytes)
            .ok()
            .and_then(|text| RsaPrivateKey::from_pkcs8_pem(text).ok()),
        PrivateKeyFormat::Pkcs8Der => RsaPrivateKey::from_pkcs8_der(bytes).ok(),
    }
    .ok_or_else(|| KeyMaterialError::UnsupportedPrivateKey(path.to_owned()))
}

/// Decode caller-owned RSA public-key bytes after the operation layer has
/// charged their source length to its aggregate external-material budget.
pub fn decode_rsa_public(
    path: &Path,
    bytes: &[u8],
    encoding: PublicKeyEncoding,
) -> Result<RsaPublicKey, KeyMaterialError> {
    match encoding {
        PublicKeyEncoding::Pem => std::str::from_utf8(bytes).ok().and_then(|text| {
            RsaPublicKey::from_public_key_pem(text)
                .or_else(|_| RsaPublicKey::from_pkcs1_pem(text))
                .ok()
        }),
        PublicKeyEncoding::Der => RsaPublicKey::from_public_key_der(bytes)
            .or_else(|_| RsaPublicKey::from_pkcs1_der(bytes))
            .ok(),
    }
    .ok_or_else(|| KeyMaterialError::UnsupportedPublicKey(path.to_owned()))
}

/// Decode an RSA certificate after the operation layer has charged its source.
pub(crate) fn decode_rsa_certificate_public(
    path: &Path,
    bytes: &[u8],
    encoding: CertificateEncoding,
) -> Result<(RsaPublicKey, Vec<u8>), KeyMaterialError> {
    let der = decode_certificate(path, bytes, encoding)?;
    let (_, certificate) = x509_parser::certificate::X509Certificate::from_der(&der)
        .map_err(|_| KeyMaterialError::InvalidCertificate(path.to_owned()))?;
    let public_key = RsaPublicKey::from_public_key_der(certificate.public_key().raw)
        .map_err(|_| KeyMaterialError::UnsupportedPublicKey(path.to_owned()))?;
    Ok((public_key, der))
}

pub fn load_symmetric(
    path: impl AsRef<Path>,
    expected: Option<usize>,
) -> Result<Vec<u8>, KeyMaterialError> {
    // libxmlsec1's binary-key options consume the file verbatim. In particular,
    // ASCII bytes must not be guessed to be a textual Base64 representation.
    let path = path.as_ref();
    let key = read_symmetric(path, expected)?;
    decode_symmetric(key, expected)
}

/// Read a bounded symmetric-key source before operation-level accounting.
pub(crate) fn read_symmetric(
    path: impl AsRef<Path>,
    expected: Option<usize>,
) -> Result<Vec<u8>, KeyMaterialError> {
    let path = path.as_ref();
    let maximum = expected.unwrap_or(MAX_AES_KEY_BYTES);
    let mut key = Vec::with_capacity(maximum.saturating_add(1));
    File::open(path)
        .map_err(|source| KeyMaterialError::Read {
            path: path.to_owned(),
            source,
        })?
        .take(maximum.saturating_add(1) as u64)
        .read_to_end(&mut key)
        .map_err(|source| KeyMaterialError::Read {
            path: path.to_owned(),
            source,
        })?;
    Ok(key)
}

/// Validate symmetric-key bytes after their source has been charged.
pub(crate) fn decode_symmetric(
    key: Vec<u8>,
    expected: Option<usize>,
) -> Result<Vec<u8>, KeyMaterialError> {
    let maximum = expected.unwrap_or(MAX_AES_KEY_BYTES);
    if key.len() > maximum {
        return match expected {
            Some(expected) => Err(KeyMaterialError::SymmetricLength {
                expected,
                actual: key.len(),
            }),
            None => Err(KeyMaterialError::SymmetricTooLarge { maximum }),
        };
    }
    if let Some(expected) = expected
        && key.len() != expected
    {
        return Err(KeyMaterialError::SymmetricLength {
            expected,
            actual: key.len(),
        });
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use der::Encode as _;
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng as _};
    use rsa::pkcs1::{EncodeRsaPrivateKey as _, EncodeRsaPublicKey as _};

    use super::*;

    fn load_signing_key(
        path: impl AsRef<Path>,
        format: PrivateKeyFormat,
    ) -> Result<Box<dyn SigningKey>, KeyMaterialError> {
        let path = path.as_ref();
        let bytes = read(path)?;
        decode_signing_key(path, &bytes, format, SignatureAlgorithm::RsaSha256, None)
    }

    fn traditional_dsa_der(key: &NativeDsaSigningKey, version: u8, y: &[u8]) -> Vec<u8> {
        let verifying_key = key.verifying_key();
        let components = verifying_key.components();
        let p = components.p().to_be_bytes_trimmed_vartime();
        let q = components.q().to_be_bytes_trimmed_vartime();
        let g = components.g().to_be_bytes_trimmed_vartime();
        let x = key.x().to_be_bytes_trimmed_vartime();
        TraditionalDsaPrivateKey {
            version,
            p: UintRef::new(p.as_ref()).unwrap(),
            q: UintRef::new(q.as_ref()).unwrap(),
            g: UintRef::new(g.as_ref()).unwrap(),
            y: UintRef::new(y).unwrap(),
            x: UintRef::new(x.as_ref()).unwrap(),
        }
        .to_der()
        .unwrap()
    }

    #[test]
    #[expect(
        deprecated,
        reason = "traditional OpenSSL DSA compatibility includes legacy 1024/160 containers"
    )]
    fn traditional_dsa_decoder_rejects_ambiguous_or_inconsistent_containers() {
        // The generic DER option accepts the OpenSSL DSA structure only when
        // its complete ASN.1 container and public/private components agree.
        let mut rng = ChaCha20Rng::seed_from_u64(0xD5A1_D5A1);
        let components = DsaComponents::try_generate_from_rng_with_key_size(
            &mut rng,
            dsa::KeySize::DSA_1024_160,
        )
        .unwrap();
        let key = NativeDsaSigningKey::try_generate_from_rng_with_components(&mut rng, components)
            .unwrap();
        let y = key.verifying_key().y().to_be_bytes_trimmed_vartime();
        let valid = traditional_dsa_der(&key, 0, y.as_ref());
        let path = Path::new("traditional-dsa.der");
        decode_signing_key(
            path,
            &valid,
            PrivateKeyFormat::Der,
            SignatureAlgorithm::DsaSha256,
            None,
        )
        .expect("valid traditional DSA DER must decode");

        let mut trailing = valid.clone();
        trailing.push(0);
        let mut mismatched_y = y.to_vec();
        *mismatched_y.last_mut().unwrap() ^= 1;
        for (bytes, format) in [
            (
                traditional_dsa_der(&key, 1, y.as_ref()),
                PrivateKeyFormat::Der,
            ),
            (trailing, PrivateKeyFormat::Der),
            (
                traditional_dsa_der(&key, 0, &mismatched_y),
                PrivateKeyFormat::Der,
            ),
            (valid, PrivateKeyFormat::Pkcs8Der),
        ] {
            assert!(
                decode_signing_key(path, &bytes, format, SignatureAlgorithm::DsaSha256, None,)
                    .is_err(),
                "malformed or misclassified traditional DSA must be rejected"
            );
        }
    }

    fn signing_template_with_key_info(key_info: &str, targets: &str) -> String {
        format!(
            r##"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:dsig11="http://www.w3.org/2009/xmldsig11#"><ds:SignedInfo><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/></ds:SignedInfo><ds:SignatureValue/>{key_info}{targets}</ds:Signature>"##
        )
    }

    #[test]
    fn signing_metadata_rejects_invalid_key_info_reference_graphs() {
        // Signing key selection must fail closed on the same malformed graph
        // shapes rejected by verification rather than silently discarding the
        // reference and selecting an unconstrained key.
        let cases = [
            (
                "<ds:KeyInfo><dsig11:KeyInfoReference URI=\"#missing\"/></ds:KeyInfo>",
                "",
                "KeyInfoReference target is missing or ambiguous",
            ),
            (
                "<ds:KeyInfo><dsig11:KeyInfoReference URI=\"#target\"/></ds:KeyInfo>",
                "<ds:Object Id=\"target\"/>",
                "KeyInfoReference target must be KeyInfo",
            ),
            (
                "<ds:KeyInfo><dsig11:KeyInfoReference URI=\"#target\"/></ds:KeyInfo>",
                "<ds:KeyInfo Id=\"target\"><dsig11:KeyInfoReference URI=\"#target\"/></ds:KeyInfo>",
                "KeyInfoReference cycle detected",
            ),
            (
                "<ds:KeyInfo><dsig11:KeyInfoReference URI=\"keys.xml#target\"/></ds:KeyInfo>",
                "",
                "KeyInfoReference URI policy rejected the operation",
            ),
        ];
        for (key_info, targets, expected) in cases {
            let error = signing_signature_metadata(
                &signing_template_with_key_info(key_info, targets),
                None,
                &[],
                &SigningPolicy::default(),
                xml_sec::XmlBackend::default(),
            )
            .expect_err("invalid KeyInfoReference graph must be rejected");
            assert!(error.to_string().contains(expected), "{error}");
        }
    }

    #[test]
    fn signing_metadata_bounds_key_info_reference_depth() {
        // Acyclic chains remain attacker-controlled, so traversal depth must
        // consume the operation policy limit before parsing the next target.
        let maximum = SigningPolicy::default()
            .resources
            .max_key_info_reference_depth;
        let targets = (0..=maximum)
            .map(|index| {
                if index == maximum {
                    format!("<ds:KeyInfo Id=\"level-{index}\"><ds:KeyName>key</ds:KeyName></ds:KeyInfo>")
                } else {
                    format!("<ds:KeyInfo Id=\"level-{index}\"><dsig11:KeyInfoReference URI=\"#level-{}\"/></ds:KeyInfo>", index + 1)
                }
            })
            .collect::<String>();
        let error = signing_signature_metadata(
            &signing_template_with_key_info(
                "<ds:KeyInfo><dsig11:KeyInfoReference URI=\"#level-0\"/></ds:KeyInfo>",
                &targets,
            ),
            None,
            &[],
            &SigningPolicy::default(),
            xml_sec::XmlBackend::default(),
        )
        .expect_err("over-deep KeyInfoReference chain must be rejected");
        assert!(
            error
                .to_string()
                .contains(&format!("policy maximum {maximum}")),
            "{error}"
        );
    }

    #[test]
    fn signing_metadata_bounds_key_info_reference_candidate_work() {
        // Referenced sources share one aggregate candidate budget with the
        // reference nodes themselves; each nested KeyInfo cannot reset it.
        let mut policy = SigningPolicy::default();
        policy.resources.max_key_candidates = 2;
        let error = signing_signature_metadata(
            &signing_template_with_key_info(
                "<ds:KeyInfo><dsig11:KeyInfoReference URI=\"#target\"/></ds:KeyInfo>",
                "<ds:KeyInfo Id=\"target\"><ds:KeyName>one</ds:KeyName><ds:KeyName>two</ds:KeyName></ds:KeyInfo>",
            ),
            None,
            &[],
            &policy,
            xml_sec::XmlBackend::default(),
        )
        .expect_err("aggregate candidate work must respect operation policy");
        assert!(
            error
                .to_string()
                .contains("key candidates exceeds policy maximum 2"),
            "{error}"
        );
    }

    #[test]
    fn signing_metadata_enforces_key_info_reference_uri_policy() {
        // The signing policy can disable KeyInfoReference independently of
        // ordinary signed-payload references; metadata selection must honor it
        // before dereferencing even a valid same-document target.
        let mut policy = SigningPolicy::default();
        policy.uris.key_info_references = xml_sec::xmldsig::UriTypeSet::new(false, false, false);
        let error = signing_signature_metadata(
            &signing_template_with_key_info(
                "<ds:KeyInfo><dsig11:KeyInfoReference URI=\"#target\"/></ds:KeyInfo>",
                "<ds:KeyInfo Id=\"target\"><ds:KeyName>key</ds:KeyName></ds:KeyInfo>",
            ),
            None,
            &[],
            &policy,
            xml_sec::XmlBackend::default(),
        )
        .expect_err("disabled KeyInfoReference URI class must be rejected");
        assert!(
            error
                .to_string()
                .contains("KeyInfoReference URI policy rejected the operation"),
            "{error}"
        );
    }

    #[test]
    fn normalizes_pkcs1_private_and_public_keys() {
        // PKCS#1 is a donor-supported RSA container. The CLI normalizes it to
        // the core's PKCS#8/SPKI contracts. Generating the source key keeps this
        // unit test runnable from the published crate without repository paths.
        let original = RsaPrivateKey::new(&mut ChaCha20Rng::from_seed([7; 32]), 1024).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let private = temp.path().join("private.pem");
        let public = temp.path().join("public.der");
        fs::write(&private, original.to_pkcs1_pem(Default::default()).unwrap()).unwrap();
        fs::write(
            &public,
            original.to_public_key().to_pkcs1_der().unwrap().as_bytes(),
        )
        .unwrap();

        load_signing_key(&private, PrivateKeyFormat::Pem)
            .expect("PKCS#1 private key must normalize");
        let key = load_verification_key(
            &public,
            PublicKeyEncoding::Der,
            SignatureAlgorithm::RsaSha256,
        )
        .expect("PKCS#1 public key must normalize");
        RsaPublicKey::from_public_key_der(&key.public_key_bytes)
            .expect("verification key must use SPKI DER");
    }

    #[test]
    fn asymmetric_loaders_enforce_the_selected_option_format() {
        // CLI option names are format contracts: accepting a different
        // container would hide configuration errors and diverge from xmlsec1.
        let original = RsaPrivateKey::new(&mut ChaCha20Rng::from_seed([8; 32]), 1024).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let private_pem = temp.path().join("private.pem");
        let private_der = temp.path().join("private.der");
        let public_pem = temp.path().join("public.pem");
        let public_der = temp.path().join("public.der");
        fs::write(
            &private_pem,
            original.to_pkcs1_pem(Default::default()).unwrap(),
        )
        .unwrap();
        fs::write(&private_der, original.to_pkcs1_der().unwrap().as_bytes()).unwrap();
        fs::write(
            &public_pem,
            original
                .to_public_key()
                .to_pkcs1_pem(Default::default())
                .unwrap(),
        )
        .unwrap();
        fs::write(
            &public_der,
            original.to_public_key().to_pkcs1_der().unwrap().as_bytes(),
        )
        .unwrap();

        assert!(load_signing_key(&private_pem, PrivateKeyFormat::Der).is_err());
        assert!(load_signing_key(&private_der, PrivateKeyFormat::Pem).is_err());
        assert!(load_signing_key(&private_pem, PrivateKeyFormat::Pkcs8Pem).is_err());
        assert!(load_signing_key(&private_der, PrivateKeyFormat::Pkcs8Der).is_err());
        assert!(
            load_verification_key(
                &public_pem,
                PublicKeyEncoding::Der,
                SignatureAlgorithm::RsaSha256,
            )
            .is_err()
        );
        assert!(
            load_verification_key(
                &public_der,
                PublicKeyEncoding::Pem,
                SignatureAlgorithm::RsaSha256,
            )
            .is_err()
        );
    }

    #[test]
    fn malformed_pem_error_names_the_source_path() {
        // Diagnostics must identify the failing file rather than a PEM label.
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("broken-key.pem");
        fs::write(
            &path,
            "-----BEGIN PUBLIC KEY-----\ninvalid\n-----END PUBLIC KEY-----",
        )
        .unwrap();
        let error =
            load_verification_key(&path, PublicKeyEncoding::Pem, SignatureAlgorithm::RsaSha256)
                .unwrap_err();
        assert!(error.to_string().contains(path.to_str().unwrap()));
        assert!(!error.to_string().contains("in PUBLIC KEY"));
    }

    #[test]
    fn utf8_spki_der_is_not_misclassified_as_pem() {
        // Container detection follows successful decoding, not UTF-8 validity.
        // This minimal unknown-algorithm SPKI is entirely ASCII/control bytes.
        let spki = [
            0x30, 0x0a, 0x30, 0x05, 0x06, 0x03, 0x2a, 0x03, 0x04, 0x03, 0x01, 0x00,
        ];
        assert!(std::str::from_utf8(&spki).is_ok());
        assert!(valid_spki(&spki));
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("public.der");
        fs::write(&path, spki).unwrap();

        let key =
            load_verification_key(&path, PublicKeyEncoding::Der, SignatureAlgorithm::RsaSha256)
                .expect("valid UTF-8 DER must reach the DER decoder");
        assert_eq!(key.public_key_bytes, spki);
    }

    #[test]
    fn certificate_loader_does_not_guess_an_encoding() {
        // The selected option, not UTF-8 validity, controls the decoder.
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("certificate.pem");
        fs::write(&path, b"not a PEM container").unwrap();
        assert!(load_certificate_with_source_len(&path, CertificateEncoding::Pem).is_err());
        assert!(load_certificate_with_source_len(&path, CertificateEncoding::Der).is_err());
    }

    #[test]
    fn symmetric_key_loader_rejects_input_above_the_supported_ceiling() {
        // Decryption does not know the exact AES width until it parses the
        // ciphertext, but the CLI must still reject data beyond every supported
        // AES key size instead of treating an arbitrary file as key material.
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("oversized.key");
        fs::write(&path, [0_u8; 33]).unwrap();

        let error = load_symmetric(&path, None).unwrap_err();

        assert!(error.to_string().contains("maximum 32 bytes"));
    }

    #[test]
    fn oversized_asymmetric_material_is_rejected_before_decoding() {
        // Key and certificate inputs are caller-controlled files. An invalid
        // oversized file must hit the read ceiling before a decoder sees it.
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("oversized.pem");
        fs::write(&path, vec![b'x'; KEY_MATERIAL_BYTE_CEILING + 1]).unwrap();

        let error = match load_signing_key(&path, PrivateKeyFormat::Pem) {
            Ok(_) => panic!("oversized key material must be rejected"),
            Err(error) => error,
        };

        let message = error.to_string();
        assert!(message.contains(&path.display().to_string()));
        assert!(message.contains(&format!("maximum {KEY_MATERIAL_BYTE_CEILING} bytes")));
    }

    #[test]
    fn selected_signature_controls_verification_key_algorithm() {
        // Key decoding must inspect the same selected Signature as verification;
        // an unrelated earlier signature may use a different key family.
        let digest = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0_u8; 32]);
        let signature = |id: &str, algorithm: &str| {
            format!(
                r#"<ds:Signature Id="{id}" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:SignedInfo>
<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
<ds:SignatureMethod Algorithm="{algorithm}"/>
<ds:Reference URI=""><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference>
</ds:SignedInfo><ds:SignatureValue>AA==</ds:SignatureValue></ds:Signature>"#
            )
        };
        let xml = format!(
            "<root>{}{}</root>",
            signature("rsa", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"),
            signature("ec", "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256")
        );

        let metadata = verification_signature_metadata(
            &xml,
            Some("ec"),
            &[],
            &xml_sec::policy::VerificationPolicy::default(),
            VerificationKeyNameResolution::IgnoreDocumentKeyInfo,
            xml_sec::XmlBackend::default(),
        )
        .unwrap();
        assert_eq!(metadata.algorithm, SignatureAlgorithm::EcdsaSha256);
    }

    #[test]
    fn direct_verification_metadata_ignores_malformed_document_keys() {
        // A pinned caller key makes document KeyInfo irrelevant. Malformed key
        // metadata must therefore remain for the core verifier to ignore.
        let digest = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0_u8; 32]);
        let xml = format!(
            r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:dsig11="http://www.w3.org/2009/xmldsig11#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI=""><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>AA==</ds:SignatureValue><ds:KeyInfo><dsig11:DEREncodedKeyValue>not-base64!</dsig11:DEREncodedKeyValue></ds:KeyInfo></ds:Signature>"#
        );

        let metadata = verification_signature_metadata(
            &xml,
            None,
            &[],
            &VerificationPolicy::default(),
            VerificationKeyNameResolution::IgnoreDocumentKeyInfo,
            xml_sec::XmlBackend::default(),
        )
        .expect("unused malformed document keys must not block a pinned key");

        assert_eq!(metadata.algorithm, SignatureAlgorithm::RsaSha256);
        assert!(metadata.key_names.is_empty());
    }

    #[test]
    fn signature_metadata_preserves_every_key_name_for_resolution() {
        // KeyInfo is an ordered list of lookup sources; collapsing it to the
        // first KeyName makes later valid key-manager entries unreachable.
        let digest = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0_u8; 32]);
        let xml = format!(
            r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI=""><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>AA==</ds:SignatureValue><ds:KeyInfo><ds:KeyName>old</ds:KeyName><ds:KeyName>wan<!--split-->ted</ds:KeyName></ds:KeyInfo></ds:Signature>"#
        );

        let metadata = verification_signature_metadata(
            &xml,
            None,
            &[],
            &xml_sec::policy::VerificationPolicy::default(),
            VerificationKeyNameResolution::ResolveDocumentKeyInfo,
            xml_sec::XmlBackend::default(),
        )
        .unwrap();

        assert_eq!(metadata.key_names, ["old", "wanted"]);
    }

    #[test]
    fn verification_metadata_resolves_referenced_key_names() {
        // CLI candidate selection precedes core verification, so it must see
        // the same bounded KeyInfoReference graph as the verifier.
        let digest = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0_u8; 32]);
        let xml = format!(
            r##"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:dsig11="http://www.w3.org/2009/xmldsig11#"><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI=""><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>AA==</ds:SignatureValue><ds:KeyInfo><dsig11:KeyInfoReference URI="#target"/></ds:KeyInfo></ds:Signature><ds:KeyInfo Id="target"><ds:KeyName>wanted</ds:KeyName></ds:KeyInfo></root>"##
        );

        let metadata = verification_signature_metadata(
            &xml,
            None,
            &[],
            &VerificationPolicy::default(),
            VerificationKeyNameResolution::ResolveDocumentKeyInfo,
            xml_sec::XmlBackend::default(),
        )
        .expect("same-document KeyInfoReference must resolve before candidate selection");

        assert_eq!(metadata.key_names, ["wanted"]);

        let mut disabled = VerificationPolicy::default();
        disabled.key_sources.key_info_reference = false;
        let error = verification_signature_metadata(
            &xml,
            None,
            &[],
            &disabled,
            VerificationKeyNameResolution::ResolveDocumentKeyInfo,
            xml_sec::XmlBackend::default(),
        )
        .expect_err("metadata selection must honor the verification key-source policy");
        assert!(error.to_string().contains("key sources are disabled"));
    }

    #[test]
    fn signature_discovery_obeys_the_verification_node_ceiling() {
        // Metadata discovery runs before cryptographic verification and must
        // not allocate a DOM larger than the operation policy permits.
        let digest = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0_u8; 32]);
        let xml = format!(
            r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI=""><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>AA==</ds:SignatureValue></ds:Signature>"#
        );
        let policy = xml_sec::policy::VerificationPolicy {
            resources: xml_sec::policy::ResourcePolicy {
                max_xml_nodes: 4,
                ..xml_sec::policy::ResourcePolicy::default()
            },
            ..xml_sec::policy::VerificationPolicy::default()
        };

        let error = verification_signature_metadata(
            &xml,
            None,
            &[],
            &policy,
            VerificationKeyNameResolution::IgnoreDocumentKeyInfo,
            xml_sec::XmlBackend::default(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("nodes limit"));
    }
}
