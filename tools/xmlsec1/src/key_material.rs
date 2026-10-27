use std::{
    fs::File,
    io::Read as _,
    path::{Path, PathBuf},
};

use aes::cipher::{BlockModeDecrypt as _, KeyIvInit as _, block_padding::Pkcs7};
use crypto_bigint::{
    BoxedUint,
    modular::{BoxedMontyForm, BoxedMontyParams},
};
use der::{
    Decode as _, Encode as _,
    asn1::{AnyRef, BitStringRef, ObjectIdentifier, OctetStringRef, UintRef},
};
use dsa::{
    Components as DsaComponents, SigningKey as NativeDsaSigningKey, VerifyingKey as DsaVerifyingKey,
};
use md5::{Digest as _, Md5};
use pkcs8::{EncodePrivateKey as _, EncryptedPrivateKeyInfoRef, PrivateKeyInfoRef};
use rsa::{RsaPrivateKey, RsaPublicKey};
use xml_sec::key_manager::{KeyInventory, KeyUsages};
use xml_sec::policy::{PolicyViolation, ResourcePolicy, SigningPolicy, VerificationPolicy};
use xml_sec::rsa_encoding::{RsaPrivateKeyEncoding as _, RsaPublicKeyEncoding as _};
use xml_sec::xmldsig::{
    DsaSigningKey, DsigError, EcdsaP256SigningKey, EcdsaP384SigningKey, EcdsaP521SigningKey,
    KeyInfo, ReferenceProcessingError, RsaSigningKey, SignatureAlgorithm, SigningKey,
    VerificationKey, find_signature_node, inspect_signing_key_info, inspect_verification_key_info,
    parse_signed_info, uri::UriReferenceResolver,
};
use xml_sec::{
    XmlDomDocument as Document, XmlDomNode as Node, XmlDomParsingOptions as ParsingOptions,
};
use zeroize::Zeroizing;

// This is an absolute process-safety ceiling, not deployment policy. Parsed
// key sizes remain governed by the operation policy after bounded ingestion.
pub(crate) const KEY_MATERIAL_BYTE_CEILING: usize = 8 * 1024 * 1024;
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
    #[error("protected key container could not be decoded")]
    ProtectedContainer,
    #[error("private key component preflight failed: {0}")]
    PrivateKeyComponents(xml_sec::key_manager::KeyStoreError),
    #[error("{0}")]
    KeyStore(xml_sec::key_manager::KeyStoreError),
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
    pub encapsulation: Option<xml_sec::provider::KeyEncapsulationAlgorithm>,
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
    pub encapsulation: Option<xml_sec::provider::KeyEncapsulationAlgorithm>,
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
    read_with_limit(path, KEY_MATERIAL_BYTE_CEILING)
}

pub fn read_with_limit(
    path: impl AsRef<Path>,
    maximum_bytes: usize,
) -> Result<Vec<u8>, KeyMaterialError> {
    let path = path.as_ref();
    let maximum = maximum_bytes.min(KEY_MATERIAL_BYTE_CEILING);
    let mut bytes = Vec::with_capacity(maximum.min(64 * 1024));
    File::open(path)
        .map_err(|source| KeyMaterialError::Read {
            path: path.to_owned(),
            source,
        })?
        .take(maximum.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| KeyMaterialError::Read {
            path: path.to_owned(),
            source,
        })?;
    if bytes.len() > maximum {
        return Err(KeyMaterialError::KeyMaterialTooLarge {
            path: path.to_owned(),
            maximum,
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
    provider: &dyn xml_sec::provider::CryptoProvider,
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
    // Pinning a key ignores lookup hints, not operation instructions. Discover
    // local KEM instructions without parsing unrelated key material first.
    let ignore_hints = key_name_resolution == VerificationKeyNameResolution::IgnoreDocumentKeyInfo;
    let metadata = signature_key_info(signature)
        .map(|info| {
            let resolver = UriReferenceResolver::with_id_registrations(&document, id_attributes);
            if ignore_hints {
                xml_sec::xmldsig::inspect_pinned_verification_key_info(
                    info,
                    resolver,
                    policy,
                    provider,
                    xml_backend,
                )
            } else {
                inspect_verification_key_info(info, resolver, policy, provider, xml_backend)
                    .map(Some)
            }
        })
        .transpose()
        .map_err(map_key_info_reference_error)?
        .flatten();
    let encapsulation = metadata.as_ref().and_then(|info| info.encapsulation);
    if let Some(algorithm) = encapsulation {
        policy.key_establishment.check_encapsulation(algorithm)?;
    }
    let key_info = if key_name_resolution == VerificationKeyNameResolution::IgnoreDocumentKeyInfo {
        None
    } else {
        metadata.map(|metadata| metadata.key_info)
    };
    Ok(SignatureMetadata {
        algorithm,
        key_names: key_names(key_info.as_ref()),
        encapsulation,
    })
}

pub fn signing_signature_metadata(
    xml: &str,
    start_node_id: Option<&str>,
    id_attributes: &[xml_sec::IdAttributeRegistration],
    policy: &SigningPolicy,
    xml_backend: xml_sec::XmlBackend,
    provider: &dyn xml_sec::provider::CryptoProvider,
) -> Result<SigningTemplateMetadata, KeyMaterialError> {
    policy.validate()?;
    let document = parse_signature_document(
        xml,
        policy.xml.allow_internal_dtd,
        policy.resources.max_xml_nodes,
        xml_backend,
    )?;
    let signature = select_signature(&document, start_node_id, id_attributes)?;
    let method = signature
        .children()
        .find(|node| node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "SignedInfo")))
        .and_then(|signed_info| {
            signed_info.children().find(|node| {
                node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "SignatureMethod"))
            })
        })
        .ok_or(KeyMaterialError::MissingSignedInfo)?;
    let algorithm = xml_sec::xmldsig::parse::parse_signature_method(method, &policy.resources)
        .map(|(algorithm, _, _)| algorithm)
        .map_err(|error| KeyMaterialError::Signature(error.to_string()))?;
    let metadata = signature_key_info(signature)
        .map(|info| {
            inspect_signing_key_info(
                info,
                UriReferenceResolver::with_id_registrations(&document, id_attributes),
                policy,
                provider,
                xml_backend,
            )
        })
        .transpose()
        .map_err(map_key_info_reference_error)?;
    let encapsulation = metadata.as_ref().and_then(|info| info.encapsulation);
    if let Some(algorithm) = encapsulation {
        policy.key_establishment.check_encapsulation(algorithm)?;
    }
    let key_info = metadata.map(|metadata| metadata.key_info);
    Ok(SigningTemplateMetadata {
        algorithm,
        key_names: key_names(key_info.as_ref()),
        key_info,
        encapsulation,
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

fn key_names(key_info: Option<&KeyInfo>) -> Vec<String> {
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
        method if method.is_rsa() => decode_rsa_signing_key(path, bytes, format, password),
        SignatureAlgorithm::DsaSha1 | SignatureAlgorithm::DsaSha256 => {
            // XMLDSig defines DSA signature methods only for SHA-1 and
            // SHA-256. SHA-224 URIs exist for other key families, not DSA.
            decode_dsa_signing_key(path, bytes, format, password)
        }
        method if method.ecdsa_digest().is_some() => {
            decode_ecdsa_signing_key(path, bytes, format, password)
        }
        SignatureAlgorithm::HmacSha1
        | SignatureAlgorithm::HmacSha224
        | SignatureAlgorithm::HmacSha256
        | SignatureAlgorithm::HmacSha384
        | SignatureAlgorithm::HmacSha512 => {
            Err(KeyMaterialError::UnsupportedPrivateKey(path.to_owned()))
        }
        SignatureAlgorithm::Ed25519
        | SignatureAlgorithm::Ed25519Ctx
        | SignatureAlgorithm::Ed25519Ph
        | SignatureAlgorithm::Ed448
        | SignatureAlgorithm::Ed448Ph
        | SignatureAlgorithm::PostQuantum(_) => {
            decode_modern_signing_key(path, bytes, format, algorithm)
        }
        _ => Err(KeyMaterialError::UnsupportedPrivateKey(path.to_owned())),
    }
}

fn decode_modern_signing_key(
    path: &Path,
    bytes: &[u8],
    format: PrivateKeyFormat,
    algorithm: SignatureAlgorithm,
) -> Result<Box<dyn SigningKey>, KeyMaterialError> {
    // Protected PKCS#8 is admitted by the caller's inventory/KDF policy path,
    // never by a parallel decoder with independent limits.
    if pkcs8_container_kind(bytes, format) == Some(Pkcs8ContainerKind::Encrypted) {
        return Err(KeyMaterialError::ProtectedContainer);
    }
    let decoded;
    let der = match format {
        PrivateKeyFormat::Pem | PrivateKeyFormat::Pkcs8Pem => {
            decoded = decode_plain_pkcs8_pem(bytes, path)?;
            decoded.as_slice()
        }
        PrivateKeyFormat::Der | PrivateKeyFormat::Pkcs8Der => bytes,
    };
    let error = |_| KeyMaterialError::UnsupportedPrivateKey(path.to_owned());
    match algorithm {
        #[cfg(feature = "experimental-pq")]
        SignatureAlgorithm::PostQuantum(parameter) => {
            xml_sec::xmldsig::PostQuantumSigningKey::from_pkcs8_der(parameter, der)
                .map(|key| Box::new(key) as Box<dyn SigningKey>)
                .map_err(error)
        }
        _ => xml_sec::xmldsig::EdDsaSigningKey::from_pkcs8_der(algorithm, der)
            .map(|key| Box::new(key) as Box<dyn SigningKey>)
            .map_err(error),
    }
}

#[cfg(test)]
mod modern_import_tests;

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

pub(crate) fn is_encrypted_pkcs8_container(bytes: &[u8], format: PrivateKeyFormat) -> bool {
    pkcs8_container_kind(bytes, format) == Some(Pkcs8ContainerKind::Encrypted)
}

fn pkcs8_container_kind(bytes: &[u8], format: PrivateKeyFormat) -> Option<Pkcs8ContainerKind> {
    match format {
        PrivateKeyFormat::Pem | PrivateKeyFormat::Pkcs8Pem => {
            match pkcs8::der::pem::decode_label(bytes).ok()? {
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
    if pkcs8_container_kind(bytes, format).is_some() {
        return decode_pkcs8_signing_key::<EcdsaP256SigningKey>(path, bytes, format, password)
            .or_else(|_| {
                decode_pkcs8_signing_key::<EcdsaP384SigningKey>(path, bytes, format, password)
            })
            .or_else(|_| {
                decode_pkcs8_signing_key::<EcdsaP521SigningKey>(path, bytes, format, password)
            });
    }
    decode_ecdsa_sec1_key(path, bytes, format, password)
}

fn decode_ecdsa_sec1_key(
    path: &Path,
    bytes: &[u8],
    format: PrivateKeyFormat,
    password: Option<&[u8]>,
) -> Result<Box<dyn SigningKey>, KeyMaterialError> {
    // Decode the envelope once; curve selection only borrows the same secret.
    let decoded = match format {
        PrivateKeyFormat::Pem => {
            let text = std::str::from_utf8(bytes)
                .map_err(|_| KeyMaterialError::UnsupportedPrivateKey(path.to_owned()))?;
            Some(decode_openssl_traditional_pem(
                text,
                "EC PRIVATE KEY",
                password,
                path,
            )?)
        }
        PrivateKeyFormat::Der => None,
        PrivateKeyFormat::Pkcs8Pem | PrivateKeyFormat::Pkcs8Der => {
            return Err(KeyMaterialError::UnsupportedPrivateKey(path.to_owned()));
        }
    };
    let der = decoded.as_ref().map_or(bytes, |key| key.der.as_slice());
    macro_rules! try_curve {
        ($key:ty) => {
            if let Ok(key) = <$key>::decode_sec1_der(der) {
                return Ok(Box::new(key));
            }
        };
    }
    try_curve!(EcdsaP256SigningKey);
    try_curve!(EcdsaP384SigningKey);
    try_curve!(EcdsaP521SigningKey);
    Err(traditional_key_decode_error(decoded.as_ref(), path))
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
            // Generic PEM uses the same password-aware OpenSSL envelope
            // contract for DSA as for traditional RSA and SEC1 keys.
            Some(decode_openssl_traditional_pem(
                text,
                "DSA PRIVATE KEY",
                password,
                path,
            )?)
        }
        PrivateKeyFormat::Der => None,
        PrivateKeyFormat::Pkcs8Pem | PrivateKeyFormat::Pkcs8Der => {
            return Err(KeyMaterialError::UnsupportedPrivateKey(path.to_owned()));
        }
    };
    let der = pem_der.as_ref().map_or(bytes, |key| key.der.as_slice());
    let decode_error = || traditional_key_decode_error(pem_der.as_ref(), path);
    let traditional = TraditionalDsaPrivateKey::from_der(der).map_err(|_| decode_error())?;
    if traditional.version != 0 {
        return Err(decode_error());
    }

    let p = BoxedUint::from_be_slice_vartime(traditional.p.as_bytes());
    let q = BoxedUint::from_be_slice_vartime(traditional.q.as_bytes());
    let g = BoxedUint::from_be_slice_vartime(traditional.g.as_bytes());
    let public = BoxedUint::from_be_slice_vartime(traditional.y.as_bytes());
    let secret = BoxedUint::from_be_slice_vartime(traditional.x.as_bytes());
    let components = DsaComponents::from_components(p, q, g).map_err(|_| decode_error())?;

    // FIPS 186-4 4.1: the stored public key must equal g^x mod p.
    let params = BoxedMontyParams::new(components.p().clone());
    let expected_public = BoxedMontyForm::new((**components.g()).clone(), &params)
        .pow(&secret)
        .retrieve();
    if expected_public != public {
        return Err(decode_error());
    }

    let verifying_key =
        DsaVerifyingKey::from_components(components, public).map_err(|_| decode_error())?;
    let key =
        NativeDsaSigningKey::from_components(verifying_key, secret).map_err(|_| decode_error())?;
    let normalized = key.to_pkcs8_der().map_err(|_| decode_error())?;
    DsaSigningKey::from_pkcs8_der(normalized.as_bytes())
        .map(|key| Box::new(key) as Box<dyn SigningKey>)
        .map_err(|_| decode_error())
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
        PrivateKeyFormat::Pem => {
            let text = std::str::from_utf8(bytes)
                .map_err(|_| KeyMaterialError::UnsupportedPrivateKey(path.to_owned()))?;
            let key = decode_traditional_rsa_pem(text, password, path)?;
            normalize_rsa_signing_key(&key, path)
        }
        PrivateKeyFormat::Der => RsaPrivateKey::from_pkcs1_der(bytes).map_or_else(
            |_| Err(KeyMaterialError::UnsupportedPrivateKey(path.to_owned())),
            |key| normalize_rsa_signing_key(&key, path),
        ),
        PrivateKeyFormat::Pkcs8Pem | PrivateKeyFormat::Pkcs8Der => {
            Err(KeyMaterialError::UnsupportedPrivateKey(path.to_owned()))
        }
    }
}

fn decode_traditional_rsa_pem(
    text: &str,
    password: Option<&[u8]>,
    path: &Path,
) -> Result<RsaPrivateKey, KeyMaterialError> {
    let der = decode_openssl_traditional_pem(text, "RSA PRIVATE KEY", password, path)?;
    preflight_rsa_der(&der.der, false, path).map_err(|error| {
        if der.encrypted && !matches!(error, KeyMaterialError::PrivateKeyComponents(_)) {
            KeyMaterialError::ProtectedContainer
        } else {
            error
        }
    })?;
    RsaPrivateKey::from_pkcs1_der(&der.der)
        .map_err(|_| traditional_key_decode_error(Some(&der), path))
}

fn preflight_rsa_der(bytes: &[u8], pkcs8_only: bool, path: &Path) -> Result<(), KeyMaterialError> {
    let components = match PrivateKeyInfoRef::try_from(bytes) {
        Ok(info) if info.algorithm.oid == pkcs1::ALGORITHM_OID => info.private_key.as_bytes(),
        Err(_) if !pkcs8_only => bytes,
        Ok(_) | Err(_) => return Err(KeyMaterialError::UnsupportedPrivateKey(path.to_owned())),
    };
    xml_sec::key_manager::preflight_rsa_pkcs1_components(components).map_err(|error| match error {
        xml_sec::key_manager::KeyStoreError::Selection("invalid RSA private key") => {
            KeyMaterialError::UnsupportedPrivateKey(path.to_owned())
        }
        error => KeyMaterialError::PrivateKeyComponents(error),
    })
}

fn decode_plain_pkcs8_pem(
    bytes: &[u8],
    path: &Path,
) -> Result<Zeroizing<Vec<u8>>, KeyMaterialError> {
    let (label, der) =
        der::pem::decode_vec(bytes).map_err(|_| KeyMaterialError::InvalidPem(path.to_owned()))?;
    let der = Zeroizing::new(der);
    if label != "PRIVATE KEY" {
        return Err(KeyMaterialError::UnsupportedPrivateKey(path.to_owned()));
    }
    Ok(der)
}

struct TraditionalPemKey {
    der: Zeroizing<Vec<u8>>,
    encrypted: bool,
}

pub(crate) struct PrivateKeyImport<'a> {
    pub path: &'a Path,
    pub name: &'a str,
    pub format: PrivateKeyFormat,
    pub password: Option<&'a [u8]>,
    pub usages: KeyUsages,
    pub resources: &'a ResourcePolicy,
}

/// A traditional SEC1 `ECPrivateKey` wrapped as PKCS#8, or `None` when `der`
/// is not one. `live` bytes already count against the import ceiling.
fn normalize_traditional_ec(
    der: &[u8],
    decoded: Option<&TraditionalPemKey>,
    path: &Path,
    resources: &ResourcePolicy,
    live: usize,
) -> Result<Option<Zeroizing<Vec<u8>>>, KeyMaterialError> {
    let Ok(ec) = TraditionalEcPrivateKey::from_der(der) else {
        return Ok(None);
    };
    if ec.version != 1 {
        return Err(traditional_key_decode_error(decoded, path));
    }
    // RFC 5915 sections 1/3 and RFC 5958 section 2: preserve the original
    // ECPrivateKey octets; the PKCS#8 algorithm carries its named curve.
    // https://www.rfc-editor.org/rfc/rfc5915#section-1
    let curve = match ec.parameters {
        Some(curve) => curve,
        // RFC 5915 section 3 requires parameters in conforming generators.
        // Existing generic CLI compatibility also accepts SEC1 without them:
        // preserve the typed decoder's curve/public-key validation, not a
        // length-only guess. Explicit PKCS#8 aliases never enter this path.
        // https://www.rfc-editor.org/rfc/rfc5915#section-3
        None if p256::SecretKey::from_sec1_der(der).is_ok() => {
            ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7")
        }
        None if p384::SecretKey::from_sec1_der(der).is_ok() => {
            ObjectIdentifier::new_unwrap("1.3.132.0.34")
        }
        None if p521::SecretKey::from_sec1_der(der).is_ok() => {
            ObjectIdentifier::new_unwrap("1.3.132.0.35")
        }
        None => return Err(traditional_key_decode_error(decoded, path)),
    };
    let algorithm = pkcs8::AlgorithmIdentifierRef {
        oid: ObjectIdentifier::new_unwrap("1.2.840.10045.2.1"),
        parameters: Some(AnyRef::from(&curve)),
    };
    let info = PrivateKeyInfoRef::new(
        algorithm,
        OctetStringRef::new(der).map_err(|_| traditional_key_decode_error(decoded, path))?,
    );
    let size = usize::try_from(
        info.encoded_len()
            .map_err(|_| traditional_key_decode_error(decoded, path))?,
    )
    .map_err(|_| import_memory_error(resources))?;
    check_import_memory(resources, live, size)?;
    Ok(Some(Zeroizing::new(info.to_der().map_err(|_| {
        traditional_key_decode_error(decoded, path)
    })?)))
}

/// Normalize CLI-compatible containers without selecting a cryptographic engine.
pub(crate) fn import_private_key(
    inventory: &mut KeyInventory,
    bytes: &[u8],
    import: &PrivateKeyImport<'_>,
) -> Result<(), KeyMaterialError> {
    let &PrivateKeyImport {
        path,
        name,
        format,
        password,
        usages,
        resources,
    } = import;
    let store_error = KeyMaterialError::KeyStore;
    check_import_memory(resources, 0, bytes.len())?;
    let generic = matches!(format, PrivateKeyFormat::Pem | PrivateKeyFormat::Der);
    if !generic && pkcs8_container_kind(bytes, format).is_none() {
        return Err(KeyMaterialError::UnsupportedPrivateKey(path.to_owned()));
    }
    if !generic || pkcs8_container_kind(bytes, format).is_some() {
        return match format {
            PrivateKeyFormat::Pem | PrivateKeyFormat::Pkcs8Pem => {
                inventory.add_private_pem(name.into(), bytes, password, usages, resources)
            }
            PrivateKeyFormat::Der | PrivateKeyFormat::Pkcs8Der => {
                inventory.add_private_der(name.into(), bytes, password, usages, resources)
            }
        }
        .map_err(store_error);
    }
    let decoded = if format == PrivateKeyFormat::Pem {
        Some(decode_bounded_traditional_pem(
            bytes, password, path, resources,
        )?)
    } else {
        None
    };
    let der = decoded.as_ref().map_or(bytes, |key| key.der.as_slice());
    let mut remaining = resources.clone();
    // The encoded input remains live during PEM decoding and native import.
    let live = if let Some(decoded) = &decoded {
        bytes
            .len()
            .checked_add(decoded.der.capacity())
            .ok_or_else(|| import_memory_error(resources))?
    } else {
        bytes.len()
    };
    let normalized = normalize_traditional_ec(der, decoded.as_ref(), path, resources, live)?;
    // Inventory owns the normalized key; subtract the other live allocations
    // from the same operation ceiling, not a separate caller-selectable policy.
    let extra_live = if normalized.is_some() {
        live
    } else if let Some(decoded) = decoded.as_ref() {
        bytes.len() + (decoded.der.capacity() - decoded.der.len())
    } else {
        0
    };
    remaining.max_external_resource_total_bytes = remaining
        .max_external_resource_total_bytes
        .checked_sub(extra_live)
        .ok_or_else(|| import_memory_error(resources))?;
    let result = inventory.add_private_der(
        name.into(),
        normalized.as_ref().map_or(der, |key| key.as_slice()),
        None,
        usages,
        &remaining,
    );
    result.map_err(|error| match error {
        xml_sec::key_manager::KeyStoreError::Policy(_) => store_error(error),
        _ if decoded.as_ref().is_some_and(|key| key.encrypted) => {
            KeyMaterialError::ProtectedContainer
        }
        _ => store_error(error),
    })
}

#[derive(der::Sequence)]
struct TraditionalEcPrivateKey<'a> {
    version: u8,
    private_key: &'a OctetStringRef,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    parameters: Option<ObjectIdentifier>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    public_key: Option<BitStringRef<'a>>,
}

fn import_memory_error(resources: &ResourcePolicy) -> KeyMaterialError {
    KeyMaterialError::Policy(PolicyViolation::ResourceLimitExceeded {
        resource: "aggregate external resource bytes",
        maximum: resources.max_external_resource_total_bytes,
    })
}

fn check_import_memory(
    resources: &ResourcePolicy,
    live: usize,
    output: usize,
) -> Result<(), KeyMaterialError> {
    if output > resources.max_external_resource_bytes {
        return Err(KeyMaterialError::Policy(
            PolicyViolation::ResourceLimitExceeded {
                resource: "external resource bytes",
                maximum: resources.max_external_resource_bytes,
            },
        ));
    }
    if live
        .checked_add(output)
        .is_none_or(|peak| peak > resources.max_external_resource_total_bytes)
    {
        return Err(import_memory_error(resources));
    }
    Ok(())
}

struct PemPayloadReader<'a> {
    bytes: std::slice::Iter<'a, u8>,
}

impl std::io::Read for PemPayloadReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let mut written = 0;
        while written < output.len() {
            let Some(&byte) = self.bytes.next() else {
                break;
            };
            if !byte.is_ascii_whitespace() {
                output[written] = byte;
                written += 1;
            }
        }
        Ok(written)
    }
}

fn decode_bounded_traditional_pem(
    bytes: &[u8],
    password: Option<&[u8]>,
    path: &Path,
    resources: &ResourcePolicy,
) -> Result<TraditionalPemKey, KeyMaterialError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| KeyMaterialError::UnsupportedPrivateKey(path.to_owned()))?
        .trim_start_matches(|c: char| c.is_ascii_whitespace());
    let tag = if text.starts_with("-----BEGIN EC PRIVATE KEY-----") {
        "EC PRIVATE KEY"
    } else {
        "RSA PRIVATE KEY"
    };
    decode_traditional_pem(bytes, tag, password, path, |live, output| {
        check_import_memory(resources, live, output)
    })
}

/// Decode a PEM base64 body into exactly its declared length, reserving that
/// length (beside the `source_len` input) before allocating it.
fn decode_pem_payload(
    payload: &str,
    source_len: usize,
    invalid_payload: impl Fn() -> KeyMaterialError,
    reserve: &impl Fn(usize, usize) -> Result<(), KeyMaterialError>,
) -> Result<Zeroizing<Vec<u8>>, KeyMaterialError> {
    let symbols = payload
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .count();
    let padding = payload
        .trim_end()
        .bytes()
        .rev()
        .take_while(|byte| *byte == b'=')
        .count();
    if !symbols.is_multiple_of(4) || padding > 2 {
        return Err(invalid_payload());
    }
    let decoded_len = (symbols / 4)
        .checked_mul(3)
        .and_then(|len| len.checked_sub(padding))
        .ok_or_else(&invalid_payload)?;
    reserve(source_len, decoded_len)?;
    let mut der = Zeroizing::new(vec![0; decoded_len]);
    let mut reader = base64::read::DecoderReader::new(
        PemPayloadReader {
            bytes: payload.as_bytes().iter(),
        },
        &base64::engine::general_purpose::STANDARD,
    );
    reader.read_exact(&mut der).map_err(|_| invalid_payload())?;
    if reader.read(&mut [0]).map_err(|_| invalid_payload())? != 0 {
        return Err(invalid_payload());
    }
    Ok(der)
}

fn decode_traditional_pem(
    bytes: &[u8],
    expected_tag: &str,
    password: Option<&[u8]>,
    path: &Path,
    reserve: impl Fn(usize, usize) -> Result<(), KeyMaterialError>,
) -> Result<TraditionalPemKey, KeyMaterialError> {
    let invalid = || KeyMaterialError::UnsupportedPrivateKey(path.to_owned());
    let text = std::str::from_utf8(bytes)
        .map_err(|_| invalid())?
        .trim_matches(|c: char| c.is_ascii_whitespace());
    let (begin, end) = match expected_tag {
        "EC PRIVATE KEY" => (
            "-----BEGIN EC PRIVATE KEY-----",
            "-----END EC PRIVATE KEY-----",
        ),
        "RSA PRIVATE KEY" => (
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----END RSA PRIVATE KEY-----",
        ),
        "DSA PRIVATE KEY" => (
            "-----BEGIN DSA PRIVATE KEY-----",
            "-----END DSA PRIVATE KEY-----",
        ),
        _ => return Err(invalid()),
    };
    let mut payload = text
        .strip_prefix(begin)
        .and_then(|body| body.strip_suffix(end))
        .ok_or_else(invalid)?
        .trim_start_matches(['\r', '\n']);
    let mut proc_type = None;
    let mut dek_info = None;
    while let Some((line, rest)) = payload.split_once('\n') {
        let line = line.trim();
        let Some((header, value)) = line.split_once(':') else {
            break;
        };
        match header {
            "Proc-Type" if proc_type.is_none() => proc_type = Some(value.trim()),
            "DEK-Info" if dek_info.is_none() => dek_info = Some(value.trim()),
            _ if proc_type.is_some() || dek_info.is_some() => {
                return Err(KeyMaterialError::ProtectedContainer);
            }
            _ => return Err(invalid()),
        }
        payload = rest.trim_start_matches(['\r', '\n']);
    }
    let encrypted = proc_type.is_some() || dek_info.is_some();
    let protection = if encrypted {
        if proc_type != Some("4,ENCRYPTED") {
            return Err(KeyMaterialError::ProtectedContainer);
        }
        let (cipher, encoded_iv) = dek_info
            .and_then(|value| value.split_once(','))
            .ok_or(KeyMaterialError::ProtectedContainer)?;
        // All accepted legacy envelope IVs are at most 16 bytes. Validate the
        // fixed workspace before invoking the cipher or allocating decoded DER.
        let iv_len = match cipher {
            "AES-128-CBC" | "AES-192-CBC" | "AES-256-CBC" => 16,
            "DES-CBC" | "DES-EDE-CBC" | "DES-EDE3-CBC" => 8,
            _ => return Err(KeyMaterialError::ProtectedContainer),
        };
        if encoded_iv.len() != iv_len * 2
            || !encoded_iv.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(KeyMaterialError::ProtectedContainer);
        }
        Some((
            cipher,
            encoded_iv,
            password.ok_or(KeyMaterialError::ProtectedContainer)?,
        ))
    } else {
        None
    };
    let invalid_payload = || {
        if encrypted {
            KeyMaterialError::ProtectedContainer
        } else {
            invalid()
        }
    };
    let mut der = decode_pem_payload(payload, bytes.len(), invalid_payload, &reserve)?;
    if let Some((cipher, encoded_iv, password)) = protection {
        // IV and derived-key vectors coexist with the source and decoded DER.
        reserve(bytes.len() + der.capacity(), 48)?;
        let iv = decode_hex(encoded_iv).ok_or_else(invalid)?;
        der = decrypt_openssl_legacy_pem_in_place(cipher, &iv, der, password, path)
            .map_err(|_| KeyMaterialError::ProtectedContainer)?;
    }
    Ok(TraditionalPemKey { der, encrypted })
}

fn traditional_key_decode_error(key: Option<&TraditionalPemKey>, path: &Path) -> KeyMaterialError {
    // CBC padding is not authentication. Once an encrypted envelope has been
    // recognized, invalid decoded key material must not enable lax fallback.
    if key.is_some_and(|key| key.encrypted) {
        KeyMaterialError::ProtectedContainer
    } else {
        KeyMaterialError::UnsupportedPrivateKey(path.to_owned())
    }
}

fn decode_openssl_traditional_pem(
    text: &str,
    expected_tag: &str,
    password: Option<&[u8]>,
    path: &Path,
) -> Result<TraditionalPemKey, KeyMaterialError> {
    // The generic compatibility decoder and native importer share framing,
    // header validation and in-place decryption. The former is bounded by the
    // CLI ingestion ceiling; the inventory importer additionally reserves the
    // operation's remaining workspace before either allocation.
    decode_traditional_pem(text.as_bytes(), expected_tag, password, path, |_, _| Ok(()))
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return None;
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|digits| {
            let pair = std::str::from_utf8(digits).ok()?;
            if !pair.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return None;
            }
            u8::from_str_radix(pair, 16).ok()
        })
        .collect()
}

fn decrypt_openssl_legacy_pem_in_place(
    cipher: &str,
    iv: &[u8],
    mut plaintext: Zeroizing<Vec<u8>>,
    password: &[u8],
    path: &Path,
) -> Result<Zeroizing<Vec<u8>>, KeyMaterialError> {
    let (key_len, iv_len) = match cipher {
        "AES-128-CBC" => (16, 16),
        "AES-192-CBC" => (24, 16),
        "AES-256-CBC" => (32, 16),
        "DES-CBC" => (8, 8),
        "DES-EDE-CBC" => (16, 8),
        "DES-EDE3-CBC" => (24, 8),
        _ => return Err(KeyMaterialError::UnsupportedPrivateKey(path.to_owned())),
    };
    if iv.len() != iv_len || plaintext.is_empty() || !plaintext.len().is_multiple_of(iv_len) {
        return Err(KeyMaterialError::UnsupportedPrivateKey(path.to_owned()));
    }

    let key = openssl_legacy_key(password, &iv[..8], key_len);
    macro_rules! decrypt {
        ($cipher:ty) => {{
            let length = cbc::Decryptor::<$cipher>::new_from_slices(&key, iv)
                .map_err(|_| KeyMaterialError::UnsupportedPrivateKey(path.to_owned()))?
                .decrypt_padded::<Pkcs7>(&mut plaintext)
                .map_err(|_| KeyMaterialError::ProtectedContainer)?
                .len();
            plaintext.truncate(length);
        }};
    }
    match cipher {
        "AES-128-CBC" => decrypt!(aes::Aes128),
        "AES-192-CBC" => decrypt!(aes::Aes192),
        "AES-256-CBC" => decrypt!(aes::Aes256),
        "DES-CBC" => decrypt!(des::Des),
        "DES-EDE-CBC" => decrypt!(des::TdesEde2),
        "DES-EDE3-CBC" => decrypt!(des::TdesEde3),
        _ => unreachable!("cipher allowlist was checked above"),
    }
    Ok(plaintext)
}

fn openssl_legacy_key(password: &[u8], salt: &[u8], key_len: usize) -> Zeroizing<Vec<u8>> {
    // Traditional PEM uses OpenSSL EVP_BytesToKey with one MD5 iteration and
    // the first eight IV bytes as salt. Only the key is derived; DEK-Info
    // carries the complete IV used by CBC.
    // Derivation emits full MD5 blocks even for a 24-byte DES key. Reserve
    // those blocks once so truncation does not leave a reallocated 48-byte buffer.
    let mut key = Zeroizing::new(Vec::with_capacity(key_len.div_ceil(16) * 16));
    let mut previous: Option<Zeroizing<[u8; 16]>> = None;
    while key.len() < key_len {
        let mut digest = Md5::new();
        if let Some(previous) = previous.as_deref() {
            digest.update(previous);
        }
        digest.update(password);
        digest.update(salt);
        let block = Zeroizing::new(<[u8; 16]>::from(digest.finalize()));
        key.extend_from_slice(block.as_ref());
        previous = Some(block);
    }
    key.truncate(key_len);
    key
}

fn normalize_rsa_signing_key(
    rsa: &RsaPrivateKey,
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

/// A DER parser for one standalone key or certificate input, bounded by the
/// core's default X.509 work and workspace allowances.
fn pkix_parser() -> structured_asn1::Parser {
    let resources = ResourcePolicy::default();
    structured_asn1::Parser::der(structured_asn1::memory::Memory::new(std::sync::Arc::new(
        structured_asn1::memory::MemoryAccount::new(
            resources.max_x509_workspace_bytes,
            resources.max_x509_work,
        ),
    )))
}

/// Exactly one RFC 5280 4.1.2.7 `SubjectPublicKeyInfo`, read by the shared PKIX reader.
fn valid_spki(bytes: &[u8]) -> bool {
    const FIELD: &str = "subjectPublicKeyInfo";
    let parser = pkix_parser();
    let Ok(mut reader) = parser.read(bytes, 0) else {
        return false;
    };
    let Ok(Some(element)) = reader.next_element() else {
        return false;
    };
    structured_pkix::PublicKeyInfo::read_element(&reader, &element, FIELD).is_ok()
        && reader.is_empty()
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
    let der = certificate_der(path, bytes, encoding)?;
    // One certificate and nothing else, as the shared PKIX reader requires.
    structured_pkix::Certificate::read(&pkix_parser(), &der, 0)
        .map_err(|_| KeyMaterialError::InvalidCertificate(path.to_owned()))?;
    Ok(der)
}

fn certificate_der(
    path: &Path,
    bytes: &[u8],
    encoding: CertificateEncoding,
) -> Result<Vec<u8>, KeyMaterialError> {
    Ok(match encoding {
        CertificateEncoding::Pem => {
            let text = std::str::from_utf8(bytes)
                .map_err(|_| KeyMaterialError::InvalidCertificate(path.to_owned()))?;
            parse_pem(text, "CERTIFICATE", path)
                .map_err(|_| KeyMaterialError::InvalidCertificate(path.to_owned()))?
        }
        CertificateEncoding::Der => bytes.to_vec(),
    })
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
#[cfg(test)]
pub fn decode_rsa_private(
    path: &Path,
    bytes: &[u8],
    format: PrivateKeyFormat,
) -> Result<RsaPrivateKey, KeyMaterialError> {
    decode_rsa_private_with_password(path, bytes, format, None, &ResourcePolicy::default())
}

/// Decode an RSA transport key without retrying plaintext formats after a
/// protected container fails password verification.
pub fn decode_rsa_private_with_password(
    path: &Path,
    bytes: &[u8],
    format: PrivateKeyFormat,
    password: Option<&[u8]>,
    resources: &ResourcePolicy,
) -> Result<RsaPrivateKey, KeyMaterialError> {
    decode_rsa_private_with_inventory(
        path,
        bytes,
        format,
        password,
        resources,
        &mut KeyInventory::default(),
    )
}

/// Use the operation's import session so protected-key work is observable even
/// when password validation or native RSA decoding fails.
pub fn decode_rsa_private_with_inventory(
    path: &Path,
    bytes: &[u8],
    format: PrivateKeyFormat,
    password: Option<&[u8]>,
    resources: &ResourcePolicy,
    inventory: &mut KeyInventory,
) -> Result<RsaPrivateKey, KeyMaterialError> {
    if pkcs8_container_kind(bytes, format) == Some(Pkcs8ContainerKind::Encrypted) {
        let password = password.ok_or(KeyMaterialError::ProtectedContainer)?;
        let imported = match format {
            PrivateKeyFormat::Pem | PrivateKeyFormat::Pkcs8Pem => inventory.add_private_pem(
                "cli-rsa".into(),
                bytes,
                Some(password),
                KeyUsages::DECRYPT,
                resources,
            ),
            PrivateKeyFormat::Der | PrivateKeyFormat::Pkcs8Der => inventory.add_private_der(
                "cli-rsa".into(),
                bytes,
                Some(password),
                KeyUsages::DECRYPT,
                resources,
            ),
        };
        imported.map_err(|error| match error {
            xml_sec::key_manager::KeyStoreError::ProtectedContainer => {
                KeyMaterialError::ProtectedContainer
            }
            xml_sec::key_manager::KeyStoreError::Policy(violation) => violation.into(),
            _ => KeyMaterialError::UnsupportedPrivateKey(path.to_owned()),
        })?;
        return inventory
            .private_keys()
            .first()
            .and_then(|entry| RsaPrivateKey::from_pkcs8_der(entry.pkcs8_der()).ok())
            .ok_or_else(|| KeyMaterialError::UnsupportedPrivateKey(path.to_owned()));
    }
    let pem_der;
    let der = match format {
        PrivateKeyFormat::Pem => {
            let text = std::str::from_utf8(bytes)
                .map_err(|_| KeyMaterialError::UnsupportedPrivateKey(path.to_owned()))?;
            if pkcs8_container_kind(bytes, format) == Some(Pkcs8ContainerKind::Plain) {
                pem_der = decode_plain_pkcs8_pem(text.as_bytes(), path)?;
                pem_der.as_slice()
            } else {
                return decode_traditional_rsa_pem(text, password, path);
            }
        }
        PrivateKeyFormat::Pkcs8Pem => {
            pem_der = decode_plain_pkcs8_pem(bytes, path)?;
            pem_der.as_slice()
        }
        PrivateKeyFormat::Der | PrivateKeyFormat::Pkcs8Der => bytes,
    };
    let pkcs8_only = format != PrivateKeyFormat::Der;
    preflight_rsa_der(der, pkcs8_only, path)?;
    if PrivateKeyInfoRef::try_from(der).is_ok() {
        RsaPrivateKey::from_pkcs8_der(der).ok()
    } else {
        RsaPrivateKey::from_pkcs1_der(der).ok()
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
    let der = certificate_der(path, bytes, encoding)?;
    let public_key = {
        let parser = pkix_parser();
        let certificate = structured_pkix::Certificate::read(&parser, &der, 0)
            .map_err(|_| KeyMaterialError::InvalidCertificate(path.to_owned()))?;
        RsaPublicKey::from_public_key_der(certificate.tbs().public_key().as_bytes())
            .map_err(|_| KeyMaterialError::UnsupportedPublicKey(path.to_owned()))?
    };
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
mod tests;
