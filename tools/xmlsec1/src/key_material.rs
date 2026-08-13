use std::{
    fs,
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
use xml_sec::xmldsig::{
    EcdsaP256SigningKey, EcdsaP384SigningKey, RsaSigningKey, SignatureAlgorithm, SigningKey,
    VerificationKey, find_signature_node, parse_signed_info,
};

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
    #[error("invalid XML signature: {0}")]
    Signature(String),
    #[error("invalid symmetric key length: expected {expected} bytes, got {actual}")]
    SymmetricLength { expected: usize, actual: usize },
}

pub fn read(path: impl AsRef<Path>) -> Result<Vec<u8>, KeyMaterialError> {
    let path = path.as_ref();
    fs::read(path).map_err(|source| KeyMaterialError::Read {
        path: path.to_owned(),
        source,
    })
}

pub fn read_text(path: impl AsRef<Path>) -> Result<String, KeyMaterialError> {
    let path = path.as_ref();
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
    let der = if let Ok(text) = std::str::from_utf8(&bytes) {
        parse_pem(text, "CERTIFICATE", path)?
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

pub fn load_symmetric(
    path: impl AsRef<Path>,
    expected: Option<usize>,
) -> Result<Vec<u8>, KeyMaterialError> {
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

#[cfg(test)]
mod tests {
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
}
