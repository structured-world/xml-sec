use std::{
    fs::File,
    io::Read as _,
    path::{Path, PathBuf},
};

use roxmltree::Document;
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs1::{DecodeRsaPrivateKey as _, DecodeRsaPublicKey as _},
    pkcs8::{
        DecodePrivateKey as _, DecodePublicKey as _, EncodePrivateKey as _, EncodePublicKey as _,
    },
};
use x509_parser::prelude::FromDer as _;
use xml_sec::policy::{PolicyViolation, SigningPolicy, VerificationPolicy};
use xml_sec::xmldsig::{
    EcdsaP256SigningKey, EcdsaP384SigningKey, RsaSigningKey, SignatureAlgorithm, SigningKey,
    VerificationKey, find_signature_node, parse_signed_info, uri::UriReferenceResolver,
};

// This is an absolute process-safety ceiling, not deployment policy. Parsed
// key sizes remain governed by the operation policy after bounded ingestion.
const KEY_MATERIAL_BYTE_CEILING: usize = 8 * 1024 * 1024;

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

#[derive(Debug, Eq, PartialEq)]
pub struct SigningTemplateMetadata {
    pub algorithm: SignatureAlgorithm,
    pub key_names: Vec<String>,
    pub has_key_info: bool,
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

pub fn read_text(path: impl AsRef<Path>) -> Result<String, KeyMaterialError> {
    let path = path.as_ref();
    String::from_utf8(read(path)?).map_err(|_| KeyMaterialError::InvalidPem(path.to_owned()))
}

/// Read metadata from the first descendant signature below the selected start node.
///
/// libxmlsec1 uses a depth-first `xmlSecFindNode` lookup from the operation start
/// node, so later signatures in the same subtree do not make selection ambiguous.
pub fn verification_signature_metadata(
    xml: &str,
    start_node_id: Option<&str>,
    id_attributes: &[xml_sec::IdAttributeRegistration],
    policy: &VerificationPolicy,
) -> Result<SignatureMetadata, KeyMaterialError> {
    policy.validate()?;
    let document = parse_signature_document(
        xml,
        policy.xml.allow_internal_dtd,
        policy.resources.max_xml_nodes,
    )?;
    let signature = match start_node_id {
        Some(id) => {
            let start = UriReferenceResolver::with_id_registrations(&document, id_attributes)
                .node_for_id(id)
                .ok_or_else(|| KeyMaterialError::SelectedNodeUnavailable(id.to_owned()))?;
            start
                .descendants()
                .find(|node| node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "Signature")))
        }
        None => find_signature_node(&document),
    }
    .ok_or(KeyMaterialError::MissingSignedInfo)?;
    let signed_info = signature
        .children()
        .find(|node| node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "SignedInfo")))
        .ok_or(KeyMaterialError::MissingSignedInfo)?;
    let algorithm = parse_signed_info(signed_info)
        .map(|info| info.signature_method)
        .map_err(|error| KeyMaterialError::Signature(error.to_string()))?;
    Ok(SignatureMetadata {
        algorithm,
        key_names: signature_key_names(signature),
    })
}

pub fn signing_signature_metadata(
    xml: &str,
    start_node_id: Option<&str>,
    id_attributes: &[xml_sec::IdAttributeRegistration],
    policy: &SigningPolicy,
) -> Result<SigningTemplateMetadata, KeyMaterialError> {
    policy.validate()?;
    let document = parse_signature_document(
        xml,
        policy.xml.allow_internal_dtd,
        policy.resources.max_xml_nodes,
    )?;
    let signature = match start_node_id {
        Some(id) => {
            let start = UriReferenceResolver::with_id_registrations(&document, id_attributes)
                .node_for_id(id)
                .ok_or_else(|| KeyMaterialError::SelectedNodeUnavailable(id.to_owned()))?;
            start
                .descendants()
                .find(|node| node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "Signature")))
        }
        None => document
            .descendants()
            .rfind(|node| node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "Signature"))),
    }
    .ok_or(KeyMaterialError::MissingSignedInfo)?;
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
    Ok(SigningTemplateMetadata {
        algorithm,
        key_names: signature_key_names(signature),
        has_key_info: signature_key_info(signature).is_some(),
    })
}

fn parse_signature_document(
    xml: &str,
    allow_internal_dtd: bool,
    max_xml_nodes: usize,
) -> Result<Document<'_>, KeyMaterialError> {
    let nodes_limit = u32::try_from(max_xml_nodes).map_err(|_| {
        KeyMaterialError::Signature("XML node ceiling does not fit the parser limit".into())
    })?;
    Document::parse_with_options(
        xml,
        roxmltree::ParsingOptions {
            allow_dtd: allow_internal_dtd,
            nodes_limit,
            entity_resolver: None,
        },
    )
    .map_err(|error| KeyMaterialError::Signature(error.to_string()))
}

fn signature_key_names(signature: roxmltree::Node<'_, '_>) -> Vec<String> {
    signature_key_info(signature)
        .into_iter()
        .flat_map(|key_info| key_info.children())
        .filter(|node| node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "KeyName")))
        .map(|key_name| {
            key_name
                .children()
                .filter(roxmltree::Node::is_text)
                .filter_map(|child| child.text())
                .collect()
        })
        .collect()
}

fn signature_key_info<'a, 'input>(
    signature: roxmltree::Node<'a, 'input>,
) -> Option<roxmltree::Node<'a, 'input>> {
    signature
        .children()
        .find(|node| node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "KeyInfo")))
}

pub fn load_signing_key(path: impl AsRef<Path>) -> Result<Box<dyn SigningKey>, KeyMaterialError> {
    let path = path.as_ref();
    let bytes = read(path)?;
    if let Ok(text) = std::str::from_utf8(&bytes) {
        if let Ok(key) = RsaSigningKey::from_pkcs8_pem(text) {
            return Ok(Box::new(key));
        }
        if let Ok(key) = EcdsaP256SigningKey::from_pkcs8_pem(text) {
            return Ok(Box::new(key));
        }
        if let Ok(key) = EcdsaP384SigningKey::from_pkcs8_pem(text) {
            return Ok(Box::new(key));
        }
    }
    if let Ok(key) = RsaSigningKey::from_pkcs8_der(&bytes) {
        return Ok(Box::new(key));
    }
    if let Ok(key) = EcdsaP256SigningKey::from_pkcs8_der(&bytes) {
        return Ok(Box::new(key));
    }
    if let Ok(key) = EcdsaP384SigningKey::from_pkcs8_der(&bytes) {
        return Ok(Box::new(key));
    }
    let rsa = std::str::from_utf8(&bytes)
        .ok()
        .and_then(|text| RsaPrivateKey::from_pkcs1_pem(text).ok())
        .or_else(|| RsaPrivateKey::from_pkcs1_der(&bytes).ok());
    if let Some(rsa) = rsa {
        let der = rsa
            .to_pkcs8_der()
            .map_err(|_| KeyMaterialError::UnsupportedPrivateKey(path.to_owned()))?;
        return RsaSigningKey::from_pkcs8_der(der.as_bytes())
            .map(|key| Box::new(key) as Box<dyn SigningKey>)
            .map_err(|_| KeyMaterialError::UnsupportedPrivateKey(path.to_owned()));
    }
    Err(KeyMaterialError::UnsupportedPrivateKey(path.to_owned()))
}

pub fn load_verification_key(
    path: impl AsRef<Path>,
    algorithm: SignatureAlgorithm,
) -> Result<VerificationKey, KeyMaterialError> {
    let path = path.as_ref();
    let bytes = read(path)?;
    let public_key_bytes = if let Ok(text) = std::str::from_utf8(&bytes) {
        if let Ok(spki) = parse_pem(text, "PUBLIC KEY", path) {
            spki
        } else if let Ok(key) = RsaPublicKey::from_pkcs1_pem(text) {
            key.to_public_key_der()
                .map_err(|_| KeyMaterialError::UnsupportedPublicKey(path.to_owned()))?
                .as_bytes()
                .to_vec()
        } else {
            return Err(KeyMaterialError::UnsupportedPublicKey(path.to_owned()));
        }
    } else if valid_spki(&bytes) {
        bytes
    } else if let Ok(key) = RsaPublicKey::from_pkcs1_der(&bytes) {
        key.to_public_key_der()
            .map_err(|_| KeyMaterialError::UnsupportedPublicKey(path.to_owned()))?
            .as_bytes()
            .to_vec()
    } else {
        return Err(KeyMaterialError::UnsupportedPublicKey(path.to_owned()));
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

pub fn load_certificate(path: impl AsRef<Path>) -> Result<Vec<u8>, KeyMaterialError> {
    let path = path.as_ref();
    let bytes = read(path)?;
    let der = if std::str::from_utf8(&bytes).is_ok() {
        let (rest, pem) = x509_parser::pem::parse_x509_pem(&bytes)
            .map_err(|_| KeyMaterialError::InvalidCertificate(path.to_owned()))?;
        if !rest.iter().all(u8::is_ascii_whitespace) || pem.label != "CERTIFICATE" {
            return Err(KeyMaterialError::InvalidCertificate(path.to_owned()));
        }
        pem.contents
    } else {
        bytes
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

pub fn load_rsa_private(path: impl AsRef<Path>) -> Result<RsaPrivateKey, KeyMaterialError> {
    let path = path.as_ref();
    let bytes = read(path)?;
    if let Ok(text) = std::str::from_utf8(&bytes) {
        if let Ok(key) = RsaPrivateKey::from_pkcs8_pem(text) {
            return Ok(key);
        }
        if let Ok(key) = RsaPrivateKey::from_pkcs1_pem(text) {
            return Ok(key);
        }
    }
    RsaPrivateKey::from_pkcs8_der(&bytes)
        .or_else(|_| RsaPrivateKey::from_pkcs1_der(&bytes))
        .map_err(|_| KeyMaterialError::UnsupportedPrivateKey(path.to_owned()))
}

pub fn load_rsa_public(path: impl AsRef<Path>) -> Result<RsaPublicKey, KeyMaterialError> {
    let path = path.as_ref();
    let bytes = read(path)?;
    if let Ok(text) = std::str::from_utf8(&bytes) {
        if let Ok(key) = RsaPublicKey::from_public_key_pem(text) {
            return Ok(key);
        }
        if let Ok(key) = RsaPublicKey::from_pkcs1_pem(text) {
            return Ok(key);
        }
        if let Ok(private) = RsaPrivateKey::from_pkcs8_pem(text) {
            return Ok(private.to_public_key());
        }
    }
    RsaPublicKey::from_public_key_der(&bytes)
        .or_else(|_| RsaPublicKey::from_pkcs1_der(&bytes))
        .map_err(|_| KeyMaterialError::UnsupportedPublicKey(path.to_owned()))
}

pub fn load_rsa_certificate_public(
    path: impl AsRef<Path>,
) -> Result<RsaPublicKey, KeyMaterialError> {
    let path = path.as_ref();
    let der = load_certificate(path)?;
    let (_, certificate) = x509_parser::certificate::X509Certificate::from_der(&der)
        .map_err(|_| KeyMaterialError::InvalidCertificate(path.to_owned()))?;
    RsaPublicKey::from_public_key_der(certificate.public_key().raw)
        .map_err(|_| KeyMaterialError::UnsupportedPublicKey(path.to_owned()))
}

pub fn load_symmetric(
    path: impl AsRef<Path>,
    expected: Option<usize>,
) -> Result<Vec<u8>, KeyMaterialError> {
    // libxmlsec1's binary-key options consume the file verbatim. In particular,
    // ASCII bytes must not be guessed to be a textual Base64 representation.
    const MAX_AES_KEY_BYTES: usize = 32;

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

    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng as _};
    use rsa::pkcs1::{EncodeRsaPrivateKey as _, EncodeRsaPublicKey as _};

    use super::*;

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

        load_signing_key(&private).expect("PKCS#1 private key must normalize");
        let key = load_verification_key(&public, SignatureAlgorithm::RsaSha256)
            .expect("PKCS#1 public key must normalize");
        RsaPublicKey::from_public_key_der(&key.public_key_bytes)
            .expect("verification key must use SPKI DER");
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
        let error = load_verification_key(&path, SignatureAlgorithm::RsaSha256).unwrap_err();
        assert!(error.to_string().contains(path.to_str().unwrap()));
        assert!(!error.to_string().contains("in PUBLIC KEY"));
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

        let error = match load_signing_key(&path) {
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
        )
        .unwrap();
        assert_eq!(metadata.algorithm, SignatureAlgorithm::EcdsaSha256);
    }

    #[test]
    fn signature_metadata_preserves_every_direct_key_name() {
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
        )
        .unwrap();

        assert_eq!(metadata.key_names, ["old", "wanted"]);
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

        let error = verification_signature_metadata(&xml, None, &[], &policy).unwrap_err();
        assert!(error.to_string().contains("nodes limit"));
    }
}
