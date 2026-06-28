//! Configuration and key material for XMLDSig key resolution.

use std::{collections::HashMap, time::SystemTime};

use x509_parser::{
    prelude::{FromDer, X509Certificate},
    public_key::PublicKey,
    x509::SubjectPublicKeyInfo,
};

use super::{
    DsigError, KeyInfo, KeyInfoSource, KeyResolver, SignatureAlgorithm, VerifyingKey,
    X509ChainOptions, X509DataInfo, verify_ecdsa_signature_spki, verify_rsa_signature_spki,
    verify_x509_certificate_chain,
};

/// A public verification key available to key resolvers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationKey {
    /// Signature algorithm this key is configured to verify.
    pub algorithm: SignatureAlgorithm,
    /// DER-encoded SubjectPublicKeyInfo bytes.
    pub public_key_bytes: Vec<u8>,
    /// DER certificate from which the key was extracted, when applicable.
    pub certificate_der: Option<Vec<u8>>,
    /// Name used to register this key for `<KeyName>` resolution.
    pub name: Option<String>,
}

impl VerifyingKey for VerificationKey {
    fn verify(
        &self,
        algorithm: SignatureAlgorithm,
        signed_data: &[u8],
        signature_value: &[u8],
    ) -> Result<bool, DsigError> {
        if algorithm != self.algorithm {
            return Err(KeyResolutionError::AlgorithmMismatch.into());
        }
        let result = match algorithm {
            SignatureAlgorithm::RsaSha1
            | SignatureAlgorithm::RsaSha256
            | SignatureAlgorithm::RsaSha384
            | SignatureAlgorithm::RsaSha512 => verify_rsa_signature_spki(
                algorithm,
                &self.public_key_bytes,
                signed_data,
                signature_value,
            ),
            SignatureAlgorithm::EcdsaP256Sha256 | SignatureAlgorithm::EcdsaP384Sha384 => {
                verify_ecdsa_signature_spki(
                    algorithm,
                    &self.public_key_bytes,
                    signed_data,
                    signature_value,
                )
            }
        };
        result.map_err(DsigError::Crypto)
    }
}

/// Failures while applying [`KeyResolverConfig`] to parsed key material.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KeyResolutionError {
    /// A configured or embedded key does not match the signature method.
    #[error("verification key does not match the signature algorithm")]
    AlgorithmMismatch,
    /// An embedded certificate could not be parsed completely.
    #[error("invalid embedded certificate DER")]
    InvalidCertificate,
    /// Embedded certificate path validation failed.
    #[error("certificate chain validation failed: {0}")]
    Chain(#[from] super::X509ChainError),
    /// System time was unavailable for certificate validation.
    #[error("system time is unavailable")]
    SystemTime,
}

/// Configuration for the default XMLDSig key resolver.
///
/// The configuration owns all key material and has no global registry. Chain
/// verification is opt-in so callers that pin an embedded certificate can use
/// the documented TOFU model without constructing a certificate path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyResolverConfig {
    /// DER-encoded certificates accepted as trust anchors.
    pub trusted_certs: Vec<Vec<u8>>,
    /// Verification keys addressable by `<KeyName>` content.
    pub named_keys: HashMap<String, VerificationKey>,
    /// Whether embedded X.509 certificate chains must terminate at a trust anchor.
    pub verify_chains: bool,
    /// Certificate verification time override; `None` selects the system clock.
    pub verification_time: Option<SystemTime>,
    /// Maximum certificates in a validated path, including the trust anchor.
    pub max_chain_depth: usize,
}

impl Default for KeyResolverConfig {
    fn default() -> Self {
        Self {
            trusted_certs: Vec::new(),
            named_keys: HashMap::new(),
            verify_chains: false,
            verification_time: None,
            max_chain_depth: 9,
        }
    }
}

/// Configuration-driven resolver for embedded certificates, DER keys, and key names.
#[derive(Debug, Clone, Default)]
pub struct DefaultKeyResolver {
    config: KeyResolverConfig,
}

impl DefaultKeyResolver {
    /// Construct a resolver from explicit caller-owned key policy.
    #[must_use]
    pub fn new(config: KeyResolverConfig) -> Self {
        Self { config }
    }

    /// Borrow the active resolver configuration.
    #[must_use]
    pub fn config(&self) -> &KeyResolverConfig {
        &self.config
    }

    fn resolve_x509(
        &self,
        info: &X509DataInfo,
        algorithm: SignatureAlgorithm,
    ) -> Result<Option<VerificationKey>, KeyResolutionError> {
        let Some(&signing_index) = info.certificate_chain.first() else {
            return Ok(None);
        };
        let certificate_der = info
            .certificates
            .get(signing_index)
            .ok_or(KeyResolutionError::InvalidCertificate)?;

        if self.config.verify_chains {
            let options = X509ChainOptions {
                trusted_certs: &self.config.trusted_certs,
                verification_time: self
                    .config
                    .verification_time
                    .unwrap_or_else(SystemTime::now),
                max_chain_depth: self.config.max_chain_depth,
                check_crls: false,
            };
            verify_x509_certificate_chain(info, &options)?;
        }

        let (rest, certificate) = X509Certificate::from_der(certificate_der)
            .map_err(|_| KeyResolutionError::InvalidCertificate)?;
        if !rest.is_empty() {
            return Err(KeyResolutionError::InvalidCertificate);
        }
        let public_key_bytes = certificate.public_key().raw.to_vec();
        validate_spki_algorithm(&public_key_bytes, algorithm)?;
        Ok(Some(VerificationKey {
            algorithm,
            public_key_bytes,
            certificate_der: Some(certificate_der.clone()),
            name: None,
        }))
    }
}

impl KeyResolver for DefaultKeyResolver {
    fn resolve<'a>(
        &'a self,
        key_info: Option<&KeyInfo>,
        algorithm: SignatureAlgorithm,
    ) -> Result<Option<Box<dyn VerifyingKey + 'a>>, DsigError> {
        let Some(key_info) = key_info else {
            return Ok(None);
        };
        for source in &key_info.sources {
            let resolved = match source {
                KeyInfoSource::X509Data(info) => self.resolve_x509(info, algorithm)?,
                KeyInfoSource::DerEncodedKeyValue(public_key_bytes) => {
                    validate_spki_algorithm(public_key_bytes, algorithm)?;
                    Some(VerificationKey {
                        algorithm,
                        public_key_bytes: public_key_bytes.clone(),
                        certificate_der: None,
                        name: None,
                    })
                }
                KeyInfoSource::KeyName(name) => self
                    .config
                    .named_keys
                    .get(name)
                    .map(|key| {
                        if key.algorithm != algorithm {
                            return Err(KeyResolutionError::AlgorithmMismatch);
                        }
                        validate_spki_algorithm(&key.public_key_bytes, algorithm)?;
                        Ok(key.clone())
                    })
                    .transpose()?,
                KeyInfoSource::KeyValue(_) => None,
            };
            if let Some(key) = resolved {
                return Ok(Some(Box::new(key)));
            }
        }
        Ok(None)
    }

    fn consumes_document_key_info(&self) -> bool {
        true
    }
}

fn validate_spki_algorithm(
    public_key_bytes: &[u8],
    algorithm: SignatureAlgorithm,
) -> Result<(), KeyResolutionError> {
    let (rest, spki) = SubjectPublicKeyInfo::from_der(public_key_bytes)
        .map_err(|_| KeyResolutionError::InvalidCertificate)?;
    if !rest.is_empty() {
        return Err(KeyResolutionError::InvalidCertificate);
    }
    let parsed = spki
        .parsed()
        .map_err(|_| KeyResolutionError::InvalidCertificate)?;
    let curve_oid = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|value| value.as_oid().ok())
        .map(|oid| oid.to_id_string());
    match (algorithm, parsed) {
        (
            SignatureAlgorithm::RsaSha1
            | SignatureAlgorithm::RsaSha256
            | SignatureAlgorithm::RsaSha384
            | SignatureAlgorithm::RsaSha512,
            PublicKey::RSA(_),
        ) => Ok(()),
        (SignatureAlgorithm::EcdsaP256Sha256, PublicKey::EC(_))
            if curve_oid.as_deref() == Some("1.2.840.10045.3.1.7") =>
        {
            Ok(())
        }
        // The XMLDSig ecdsa-sha384 URI identifies the digest, not a curve. The
        // verifier intentionally supports the donor P-521/SHA-384 interop case.
        (SignatureAlgorithm::EcdsaP384Sha384, PublicKey::EC(_))
            if matches!(curve_oid.as_deref(), Some("1.3.132.0.34" | "1.3.132.0.35")) =>
        {
            Ok(())
        }
        _ => Err(KeyResolutionError::AlgorithmMismatch),
    }
}

#[cfg(test)]
mod tests {
    use base64::{Engine, engine::general_purpose::STANDARD};

    use super::*;

    const SIGNED_SAML: &str =
        include_str!("../../tests/fixtures/saml/response_signed_by_idp_ecdsa.xml");
    const SAML_PUBLIC_KEY: &str =
        include_str!("../../tests/fixtures/keys/ec/saml-idp-ecdsa-pubkey.pem");
    const RSA_PUBLIC_KEY: &str = include_str!("../../tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");

    fn replace_key_info(xml: &str, replacement: &str) -> String {
        let start = xml.find("<ds:KeyInfo>").expect("fixture has KeyInfo");
        let end = xml
            .find("</ds:KeyInfo>")
            .expect("fixture has closing KeyInfo")
            + "</ds:KeyInfo>".len();
        format!("{}{}{}", &xml[..start], replacement, &xml[end..])
    }

    fn public_key_der(pem_text: &str) -> Vec<u8> {
        let (rest, pem) = x509_parser::pem::parse_x509_pem(pem_text.as_bytes())
            .expect("fixture public key is PEM");
        assert!(rest.iter().all(|byte| byte.is_ascii_whitespace()));
        assert_eq!(pem.label, "PUBLIC KEY");
        pem.contents
    }

    #[test]
    fn defaults_match_key_resolution_policy() {
        // Defaults must remain compatible with xmlsec1's depth and opt-in trust policy.
        let config = KeyResolverConfig::default();

        assert!(config.trusted_certs.is_empty());
        assert!(config.named_keys.is_empty());
        assert!(!config.verify_chains);
        assert_eq!(config.verification_time, None);
        assert_eq!(config.max_chain_depth, 9);
    }

    #[test]
    fn stores_named_verification_key_metadata() {
        // Named resolution must retain every field needed by the later resolver wiring.
        let key = VerificationKey {
            algorithm: SignatureAlgorithm::RsaSha256,
            public_key_bytes: vec![1, 2, 3],
            certificate_der: Some(vec![4, 5, 6]),
            name: Some("idp-signing".into()),
        };
        let mut config = KeyResolverConfig::default();
        config.named_keys.insert("idp-signing".into(), key.clone());

        assert_eq!(config.named_keys.get("idp-signing"), Some(&key));
    }

    #[test]
    fn resolves_embedded_certificate_end_to_end() {
        // The default resolver must make parsed X509Data usable by VerifyContext.
        let resolver = DefaultKeyResolver::default();
        let result = super::super::VerifyContext::new()
            .key_resolver(&resolver)
            .verify(SIGNED_SAML)
            .expect("embedded certificate should resolve");

        assert_eq!(result.status, super::super::DsigStatus::Valid);
    }

    #[test]
    fn resolves_named_key_end_to_end() {
        // KeyName lookup must preserve the same cryptographic result as embedded X509Data.
        let xml = replace_key_info(
            SIGNED_SAML,
            "<ds:KeyInfo><ds:KeyName>idp-signing</ds:KeyName></ds:KeyInfo>",
        );
        let mut config = KeyResolverConfig::default();
        config.named_keys.insert(
            "idp-signing".into(),
            VerificationKey {
                algorithm: SignatureAlgorithm::EcdsaP256Sha256,
                public_key_bytes: public_key_der(SAML_PUBLIC_KEY),
                certificate_der: None,
                name: Some("idp-signing".into()),
            },
        );
        let resolver = DefaultKeyResolver::new(config);
        let result = super::super::VerifyContext::new()
            .key_resolver(&resolver)
            .verify(&xml)
            .expect("named key should resolve");

        assert_eq!(result.status, super::super::DsigStatus::Valid);
    }

    #[test]
    fn resolves_der_encoded_key_end_to_end() {
        // DSig 1.1 DEREncodedKeyValue must feed the same SPKI verifier path.
        let encoded = STANDARD.encode(public_key_der(SAML_PUBLIC_KEY));
        let xml = replace_key_info(
            SIGNED_SAML,
            &format!(
                "<ds:KeyInfo><dsig11:DEREncodedKeyValue xmlns:dsig11=\"http://www.w3.org/2009/xmldsig11#\">{encoded}</dsig11:DEREncodedKeyValue></ds:KeyInfo>"
            ),
        );
        let resolver = DefaultKeyResolver::default();
        let result = super::super::VerifyContext::new()
            .key_resolver(&resolver)
            .verify(&xml)
            .expect("DER key should resolve");

        assert_eq!(result.status, super::super::DsigStatus::Valid);
    }

    #[test]
    fn chain_verification_rejects_untrusted_embedded_certificate() {
        // Enabling chain policy must fail closed when no trust anchor is configured.
        let resolver = DefaultKeyResolver::new(KeyResolverConfig {
            verify_chains: true,
            ..KeyResolverConfig::default()
        });
        let error = super::super::VerifyContext::new()
            .key_resolver(&resolver)
            .verify(SIGNED_SAML)
            .expect_err("untrusted certificate must fail chain validation");

        assert!(matches!(
            error,
            DsigError::KeyResolution(KeyResolutionError::Chain(
                super::super::X509ChainError::UntrustedRoot
            ))
        ));
    }

    #[test]
    fn named_key_algorithm_mismatch_fails_closed() {
        // A key registered for RSA must never be attempted for an ECDSA signature.
        let xml = replace_key_info(
            SIGNED_SAML,
            "<ds:KeyInfo><ds:KeyName>wrong-algorithm</ds:KeyName></ds:KeyInfo>",
        );
        let mut config = KeyResolverConfig::default();
        config.named_keys.insert(
            "wrong-algorithm".into(),
            VerificationKey {
                algorithm: SignatureAlgorithm::RsaSha256,
                public_key_bytes: public_key_der(SAML_PUBLIC_KEY),
                certificate_der: None,
                name: Some("wrong-algorithm".into()),
            },
        );
        let resolver = DefaultKeyResolver::new(config);
        let error = super::super::VerifyContext::new()
            .key_resolver(&resolver)
            .verify(&xml)
            .expect_err("algorithm mismatch must fail closed");

        assert!(matches!(
            error,
            DsigError::KeyResolution(KeyResolutionError::AlgorithmMismatch)
        ));
    }

    #[test]
    fn named_key_spki_type_mismatch_fails_during_resolution() {
        // The configured algorithm label cannot override the actual SPKI key type.
        let xml = replace_key_info(
            SIGNED_SAML,
            "<ds:KeyInfo><ds:KeyName>mislabeled</ds:KeyName></ds:KeyInfo>",
        );
        let mut config = KeyResolverConfig::default();
        config.named_keys.insert(
            "mislabeled".into(),
            VerificationKey {
                algorithm: SignatureAlgorithm::EcdsaP256Sha256,
                public_key_bytes: public_key_der(RSA_PUBLIC_KEY),
                certificate_der: None,
                name: Some("mislabeled".into()),
            },
        );
        let resolver = DefaultKeyResolver::new(config);
        let error = super::super::VerifyContext::new()
            .key_resolver(&resolver)
            .verify(&xml)
            .expect_err("mislabeled named key must fail during resolution");

        assert!(matches!(
            error,
            DsigError::KeyResolution(KeyResolutionError::AlgorithmMismatch)
        ));
    }
}
