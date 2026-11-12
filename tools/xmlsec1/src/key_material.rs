use std::{
    fs::File,
    io::Read as _,
    path::{Path, PathBuf},
};

use pkcs8::{EncryptedPrivateKeyInfoRef, PrivateKeyInfoRef};
use rsa::{RsaPrivateKey, RsaPublicKey};
use xml_sec::key_manager::{KeyInventory, KeyStoreError, KeyUsages, PrivateKeyContainer};
use xml_sec::policy::{PolicyViolation, ResourcePolicy, SigningPolicy, VerificationPolicy};
use xml_sec::rsa_encoding::{RsaPrivateKeyEncoding as _, RsaPublicKeyEncoding as _};
use xml_sec::xmldsig::{
    DsaSigningKey, DsigError, EcdsaP256SigningKey, EcdsaP384SigningKey, EcdsaP521SigningKey,
    KeyInfo, ReferenceProcessingError, RsaSigningKey, SignatureAlgorithm, SigningKey,
    VerificationKey, find_signature_node, inspect_signing_key_info, inspect_verification_key_info,
    parse_signed_info, uri::UriReferenceResolver,
};
use xml_sec::{XmlDomDocument as Document, XmlDomNode as Node};
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

impl KeyMaterialError {
    /// Whether lax key search may skip the candidate that failed and try the
    /// next one: not after a failed protected-container authentication, a
    /// policy refusal or a resource limit, which hold for the invocation.
    pub fn is_candidate_miss(&self) -> bool {
        !matches!(
            self,
            Self::ProtectedContainer
                | Self::PrivateKeyComponents(_)
                | Self::Policy(_)
                | Self::KeyMaterialTooLarge { .. }
                | Self::KeyStore(
                    xml_sec::key_manager::KeyStoreError::ProtectedContainer
                        | xml_sec::key_manager::KeyStoreError::Policy(_)
                )
        )
    }
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
    document: &xml_sec::XmlDocument,
    start_node_id: Option<&str>,
    id_attributes: &[xml_sec::IdAttributeRegistration],
    policy: &VerificationPolicy,
    key_name_resolution: VerificationKeyNameResolution,
    xml_backend: xml_sec::XmlBackend,
    provider: &dyn xml_sec::provider::CryptoProvider,
) -> Result<SignatureMetadata, KeyMaterialError> {
    policy.validate()?;
    document.with_view(|view| {
        verification_metadata_in(
            view.document(),
            start_node_id,
            id_attributes,
            policy,
            key_name_resolution,
            xml_backend,
            provider,
        )
    })
}

/// Parse an operation's input once under its policy; the metadata readers and
/// the operation itself all use this document.
pub fn parse_operation_document(
    xml: String,
    policy: &impl xml_sec::XmlDocumentPolicy,
    xml_backend: xml_sec::XmlBackend,
) -> Result<xml_sec::XmlDocument, KeyMaterialError> {
    xml_sec::XmlDocument::parse_with_policy_and_backend(xml, policy, xml_backend).map_err(|error| {
        match error {
            // Parser failures keep the parser's own text in CLI diagnostics.
            xml_sec::XmlDocumentError::Parse(error) => {
                KeyMaterialError::Signature(error.to_string())
            }
            error => KeyMaterialError::Signature(error.to_string()),
        }
    })
}

fn verification_metadata_in(
    document: &Document<'_>,
    start_node_id: Option<&str>,
    id_attributes: &[xml_sec::IdAttributeRegistration],
    policy: &VerificationPolicy,
    key_name_resolution: VerificationKeyNameResolution,
    xml_backend: xml_sec::XmlBackend,
    provider: &dyn xml_sec::provider::CryptoProvider,
) -> Result<SignatureMetadata, KeyMaterialError> {
    let signature = select_signature(document, start_node_id, id_attributes)?;
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
            let resolver = UriReferenceResolver::with_id_registrations(document, id_attributes);
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
    document: &xml_sec::XmlDocument,
    start_node_id: Option<&str>,
    id_attributes: &[xml_sec::IdAttributeRegistration],
    policy: &SigningPolicy,
    xml_backend: xml_sec::XmlBackend,
    provider: &dyn xml_sec::provider::CryptoProvider,
) -> Result<SigningTemplateMetadata, KeyMaterialError> {
    policy.validate()?;
    document.with_view(|view| {
        signing_metadata_in(
            view.document(),
            start_node_id,
            id_attributes,
            policy,
            xml_backend,
            provider,
        )
    })
}

fn signing_metadata_in(
    document: &Document<'_>,
    start_node_id: Option<&str>,
    id_attributes: &[xml_sec::IdAttributeRegistration],
    policy: &SigningPolicy,
    xml_backend: xml_sec::XmlBackend,
    provider: &dyn xml_sec::provider::CryptoProvider,
) -> Result<SigningTemplateMetadata, KeyMaterialError> {
    let signature = select_signature(document, start_node_id, id_attributes)?;
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
                UriReferenceResolver::with_id_registrations(document, id_attributes),
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
    resources: &ResourcePolicy,
) -> Result<Box<dyn SigningKey>, KeyMaterialError> {
    // Every container decodes to at most its own size (PEM's Base64 to less,
    // DER to itself), and the source stays live beside what it decodes to:
    // both fit what the operation has left before any decoder allocates.
    let maximum = resources.max_external_resource_total_bytes;
    if bytes.len().checked_mul(2).is_none_or(|peak| peak > maximum) {
        return Err(KeyMaterialError::KeyMaterialTooLarge {
            path: path.to_owned(),
            maximum,
        });
    }
    let key = KeySource {
        path,
        bytes,
        format,
        password,
        resources,
    };
    match algorithm {
        method if method.is_rsa() => decode_rsa_signing_key(&key),
        SignatureAlgorithm::DsaSha1 | SignatureAlgorithm::DsaSha256 => {
            // XMLDSig defines DSA signature methods only for SHA-1 and
            // SHA-256. SHA-224 URIs exist for other key families, not DSA.
            decode_dsa_signing_key(&key)
        }
        method if method.ecdsa_digest().is_some() => decode_ecdsa_signing_key(&key),
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Pkcs8ContainerKind {
    Plain,
    Encrypted,
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

/// The private key a signing operation reads and how it is framed.
struct KeySource<'a> {
    path: &'a Path,
    bytes: &'a [u8],
    format: PrivateKeyFormat,
    password: Option<&'a [u8]>,
    resources: &'a ResourcePolicy,
}

impl KeySource<'_> {
    /// The PKCS#8 container the source holds, decoded as `K`; `None` when it
    /// holds a traditional key instead.
    fn pkcs8<K: Pkcs8SigningKey>(&self) -> Option<Result<Box<dyn SigningKey>, KeyMaterialError>> {
        pkcs8_container_kind(self.bytes, self.format).map(|_| {
            decode_pkcs8_signing_key::<K>(self.path, self.bytes, self.format, self.password)
        })
    }

    /// The source normalized to PKCS#8 by the core's OpenSSL container
    /// importer, decoded by `decode`.
    fn traditional(
        &self,
        decode: impl FnOnce(&[u8]) -> Option<Box<dyn SigningKey>>,
    ) -> Result<Box<dyn SigningKey>, KeyMaterialError> {
        let mut inventory = KeyInventory::default();
        let der = import_openssl_pkcs8(
            &mut inventory,
            self.path,
            self.bytes,
            self.format,
            self.password,
            KeyUsages::SIGN,
            self.resources,
        )?;
        decode(der).ok_or_else(|| KeyMaterialError::UnsupportedPrivateKey(self.path.to_owned()))
    }
}

fn decode_ecdsa_signing_key(key: &KeySource<'_>) -> Result<Box<dyn SigningKey>, KeyMaterialError> {
    if pkcs8_container_kind(key.bytes, key.format).is_some() {
        let KeySource {
            path,
            bytes,
            format,
            password,
            ..
        } = *key;
        return decode_pkcs8_signing_key::<EcdsaP256SigningKey>(path, bytes, format, password)
            .or_else(|_| {
                decode_pkcs8_signing_key::<EcdsaP384SigningKey>(path, bytes, format, password)
            })
            .or_else(|_| {
                decode_pkcs8_signing_key::<EcdsaP521SigningKey>(path, bytes, format, password)
            });
    }
    key.traditional(|der| {
        macro_rules! try_curve {
            ($key:ty) => {
                if let Ok(key) = <$key>::decode_pkcs8_der(der) {
                    return Some(Box::new(key));
                }
            };
        }
        try_curve!(EcdsaP256SigningKey);
        try_curve!(EcdsaP384SigningKey);
        try_curve!(EcdsaP521SigningKey);
        None
    })
}

fn decode_dsa_signing_key(key: &KeySource<'_>) -> Result<Box<dyn SigningKey>, KeyMaterialError> {
    if let Some(decoded) = key.pkcs8::<DsaSigningKey>() {
        return decoded;
    }
    key.traditional(|der| {
        DsaSigningKey::from_pkcs8_der(der)
            .ok()
            .map(|key| Box::new(key) as Box<dyn SigningKey>)
    })
}

fn decode_rsa_signing_key(key: &KeySource<'_>) -> Result<Box<dyn SigningKey>, KeyMaterialError> {
    if let Some(decoded) = key.pkcs8::<RsaSigningKey>() {
        return decoded;
    }
    key.traditional(|der| {
        RsaSigningKey::from_pkcs8_der(der)
            .ok()
            .map(|key| Box::new(key) as Box<dyn SigningKey>)
    })
}

/// The core's container for a CLI private-key format.
fn container(format: PrivateKeyFormat) -> PrivateKeyContainer {
    match format {
        PrivateKeyFormat::Pem => PrivateKeyContainer::Pem,
        PrivateKeyFormat::Der => PrivateKeyContainer::Der,
        PrivateKeyFormat::Pkcs8Pem => PrivateKeyContainer::Pkcs8Pem,
        PrivateKeyFormat::Pkcs8Der => PrivateKeyContainer::Pkcs8Der,
    }
}

/// The PKCS#8 DER of the private key `bytes` hold in `format`, imported
/// into `inventory` through the core's OpenSSL container importer.
fn import_openssl_pkcs8<'i>(
    inventory: &'i mut KeyInventory,
    path: &Path,
    bytes: &[u8],
    format: PrivateKeyFormat,
    password: Option<&[u8]>,
    usages: KeyUsages,
    resources: &ResourcePolicy,
) -> Result<&'i [u8], KeyMaterialError> {
    inventory
        .add_openssl_private_key(
            "cli".to_owned(),
            bytes,
            container(format),
            password,
            usages,
            resources,
        )
        .map_err(|error| container_error(error, path))?;
    inventory
        .private_keys()
        .last()
        .map(xml_sec::key_manager::StoredPrivateKey::pkcs8_der)
        .ok_or_else(|| KeyMaterialError::UnsupportedPrivateKey(path.to_owned()))
}

/// The CLI error of a failed container import.
fn container_error(error: KeyStoreError, path: &Path) -> KeyMaterialError {
    match error {
        KeyStoreError::Policy(violation) => violation.into(),
        error => terminal_import_error(error)
            .unwrap_or_else(|_| KeyMaterialError::UnsupportedPrivateKey(path.to_owned())),
    }
}

/// The import failures each importer classifies alike, both terminal to lax
/// key search: a failed protected-container authentication and a component
/// safety limit. Any other error comes back; a policy refusal is terminal in
/// whichever form an importer reports it.
fn terminal_import_error(error: KeyStoreError) -> Result<KeyMaterialError, KeyStoreError> {
    match error {
        KeyStoreError::ProtectedContainer => Ok(KeyMaterialError::ProtectedContainer),
        KeyStoreError::Selection(reason) if reason.contains("safety limit") => {
            Ok(KeyMaterialError::PrivateKeyComponents(error))
        }
        error => Err(error),
    }
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

pub(crate) struct PrivateKeyImport<'a> {
    pub path: &'a Path,
    pub name: &'a str,
    pub format: PrivateKeyFormat,
    pub password: Option<&'a [u8]>,
    pub usages: KeyUsages,
    pub resources: &'a ResourcePolicy,
}

/// Import a private key through the core's OpenSSL container importer,
/// which normalizes every CLI-compatible container without selecting a
/// cryptographic engine.
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
    inventory
        .add_openssl_private_key(
            name.to_owned(),
            bytes,
            container(format),
            password,
            usages,
            resources,
        )
        .map_err(|error| {
            terminal_import_error(error).unwrap_or_else(|error| match error {
                KeyStoreError::Selection("unsupported private key container") => {
                    KeyMaterialError::UnsupportedPrivateKey(path.to_owned())
                }
                error => KeyMaterialError::KeyStore(error),
            })
        })
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
                "cli-rsa",
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
    // Unprotected containers spend no KDF work; a temporary inventory keeps
    // the operation's session free of their names.
    let mut temporary = KeyInventory::default();
    let der = import_openssl_pkcs8(
        &mut temporary,
        path,
        bytes,
        format,
        password,
        KeyUsages::DECRYPT,
        resources,
    )?;
    RsaPrivateKey::from_pkcs8_der(der)
        .map_err(|_| KeyMaterialError::UnsupportedPrivateKey(path.to_owned()))
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
