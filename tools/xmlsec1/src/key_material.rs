use std::fs;

use roxmltree::Document;
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs1::{DecodeRsaPrivateKey as _, DecodeRsaPublicKey as _},
    pkcs8::{DecodePrivateKey as _, DecodePublicKey as _},
};
use xml_sec::xmldsig::{
    EcdsaP256SigningKey, EcdsaP384SigningKey, RsaSigningKey, SignatureAlgorithm, SigningKey,
    VerificationKey, find_signature_node, parse_signed_info,
};

#[derive(Debug, thiserror::Error)]
pub enum KeyMaterialError {
    #[error("failed to read key file {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("invalid PEM key in {0}")]
    InvalidPem(String),
    #[error("unsupported private key in {0}")]
    UnsupportedPrivateKey(String),
    #[error("unsupported public key in {0}")]
    UnsupportedPublicKey(String),
    #[error("signature template does not contain a valid SignedInfo")]
    MissingSignedInfo,
    #[error("invalid XML signature: {0}")]
    Signature(String),
    #[error("invalid symmetric key length: expected {expected} bytes, got {actual}")]
    SymmetricLength { expected: usize, actual: usize },
}

pub fn read(path: &str) -> Result<Vec<u8>, KeyMaterialError> {
    fs::read(path).map_err(|source| KeyMaterialError::Read {
        path: path.to_owned(),
        source,
    })
}

pub fn read_text(path: &str) -> Result<String, KeyMaterialError> {
    String::from_utf8(read(path)?).map_err(|_| KeyMaterialError::InvalidPem(path.to_owned()))
}

pub fn signature_algorithm(xml: &str) -> Result<SignatureAlgorithm, KeyMaterialError> {
    let document =
        Document::parse(xml).map_err(|error| KeyMaterialError::Signature(error.to_string()))?;
    let signature = find_signature_node(&document).ok_or(KeyMaterialError::MissingSignedInfo)?;
    let signed_info = signature
        .children()
        .find(|node| node.is_element() && node.tag_name().name() == "SignedInfo")
        .ok_or(KeyMaterialError::MissingSignedInfo)?;
    parse_signed_info(signed_info)
        .map(|info| info.signature_method)
        .map_err(|error| KeyMaterialError::Signature(error.to_string()))
}

pub fn load_signing_key(path: &str) -> Result<Box<dyn SigningKey>, KeyMaterialError> {
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
    Err(KeyMaterialError::UnsupportedPrivateKey(path.to_owned()))
}

pub fn load_verification_key(
    path: &str,
    algorithm: SignatureAlgorithm,
) -> Result<VerificationKey, KeyMaterialError> {
    let bytes = read(path)?;
    let public_key_bytes = if let Ok(text) = std::str::from_utf8(&bytes) {
        parse_pem(text, "PUBLIC KEY")?
    } else {
        bytes
    };
    Ok(VerificationKey {
        algorithm,
        public_key_bytes,
        certificate_der: None,
        name: None,
    })
}

pub fn load_certificate(path: &str) -> Result<Vec<u8>, KeyMaterialError> {
    let bytes = read(path)?;
    if let Ok(text) = std::str::from_utf8(&bytes) {
        parse_pem(text, "CERTIFICATE")
    } else {
        Ok(bytes)
    }
}

fn parse_pem(text: &str, expected_label: &str) -> Result<Vec<u8>, KeyMaterialError> {
    let (rest, pem) = x509_parser::pem::parse_x509_pem(text.as_bytes())
        .map_err(|_| KeyMaterialError::InvalidPem(expected_label.to_owned()))?;
    if !rest.iter().all(u8::is_ascii_whitespace) || pem.label != expected_label {
        return Err(KeyMaterialError::InvalidPem(expected_label.to_owned()));
    }
    Ok(pem.contents)
}

pub fn load_rsa_private(path: &str) -> Result<RsaPrivateKey, KeyMaterialError> {
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

pub fn load_rsa_public(path: &str) -> Result<RsaPublicKey, KeyMaterialError> {
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

pub fn load_symmetric(path: &str, expected: Option<usize>) -> Result<Vec<u8>, KeyMaterialError> {
    // libxmlsec1's binary-key options consume the file verbatim. In particular,
    // ASCII bytes must not be guessed to be a textual Base64 representation.
    let key = read(path)?;
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
