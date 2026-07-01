//! Configuration and key material for XMLDSig key resolution.

use std::{collections::HashMap, time::SystemTime};

use p256::pkcs8::EncodePublicKey;
use x509_parser::{
    prelude::{FromDer, X509Certificate},
    public_key::PublicKey,
    x509::SubjectPublicKeyInfo,
};

use super::{
    DsigError, KeyInfo, KeyInfoSource, KeyResolver, KeyValueInfo, SignatureAlgorithm, VerifyingKey,
    X509ChainOptions, X509DataInfo,
    parse::{
        EC_P256_OID, EC_P384_OID, ParseError, parse_x509_certificate,
        x509_certificate_matches_selectors, x509_data_has_lookup_identifiers,
    },
    verify_ecdsa_signature_spki, verify_rsa_signature_spki, verify_x509_certificate_chain,
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
    /// Configured or embedded public key DER could not be parsed completely.
    #[error("invalid public key DER")]
    InvalidPublicKey,
    /// More than one configured certificate satisfies all X.509 selectors.
    #[error("X.509 lookup selectors match multiple configured certificates")]
    AmbiguousCertificate,
    /// An X.509 selector uses a digest algorithm unsupported by this crate.
    #[error("unsupported X.509 digest algorithm: {0}")]
    UnsupportedDigestAlgorithm(String),
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
        let certificate_der = if let Some(&signing_index) = info.certificate_chain.first() {
            let certificate_der = info
                .certificates
                .get(signing_index)
                .ok_or(KeyResolutionError::InvalidCertificate)?;
            if self.config.verify_chains {
                self.verify_x509_policy(info)?;
            }
            certificate_der
        } else {
            let Some(certificate) = self.resolve_configured_x509(info)? else {
                return Ok(None);
            };
            if self.config.verify_chains {
                let parsed = parse_x509_certificate(certificate)
                    .map_err(|_| KeyResolutionError::InvalidCertificate)?;
                let selected = X509DataInfo {
                    certificates: vec![certificate.clone()],
                    parsed_certificates: vec![parsed],
                    certificate_chain: vec![0],
                    ..X509DataInfo::default()
                };
                self.verify_x509_policy(&selected)?;
            }
            certificate
        };

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

    fn verify_x509_policy(&self, info: &X509DataInfo) -> Result<(), KeyResolutionError> {
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
        Ok(())
    }

    fn resolve_configured_x509<'a>(
        &'a self,
        info: &X509DataInfo,
    ) -> Result<Option<&'a Vec<u8>>, KeyResolutionError> {
        if !x509_data_has_lookup_identifiers(info) {
            return Ok(None);
        }

        let mut matched = None;
        for certificate_der in &self.config.trusted_certs {
            let parsed = parse_x509_certificate(certificate_der)
                .map_err(|_| KeyResolutionError::InvalidCertificate)?;
            let is_match = x509_certificate_matches_selectors(info, &parsed, certificate_der)
                .map_err(|error| match error {
                    ParseError::UnsupportedAlgorithm { uri } => {
                        KeyResolutionError::UnsupportedDigestAlgorithm(uri)
                    }
                    _ => KeyResolutionError::InvalidCertificate,
                })?;
            if is_match && matched.replace(certificate_der).is_some() {
                return Err(KeyResolutionError::AmbiguousCertificate);
            }
        }
        Ok(matched)
    }

    fn resolve_key_value(
        key_value: &KeyValueInfo,
        algorithm: SignatureAlgorithm,
    ) -> Result<Option<VerificationKey>, KeyResolutionError> {
        let public_key_bytes = match key_value {
            KeyValueInfo::Rsa { modulus, exponent } => {
                if !matches!(
                    algorithm,
                    SignatureAlgorithm::RsaSha1
                        | SignatureAlgorithm::RsaSha256
                        | SignatureAlgorithm::RsaSha384
                        | SignatureAlgorithm::RsaSha512
                ) {
                    return Err(KeyResolutionError::AlgorithmMismatch);
                }
                rsa_key_value_to_spki_der(modulus, exponent)?
            }
            KeyValueInfo::Ec {
                curve_oid,
                public_key,
            } => {
                if !matches!(
                    algorithm,
                    SignatureAlgorithm::EcdsaP256Sha256 | SignatureAlgorithm::EcdsaP384Sha384
                ) {
                    return Ok(None);
                }
                ec_key_value_to_spki_der(curve_oid, public_key)?
            }
            KeyValueInfo::InvalidEcKeyValue => return Err(KeyResolutionError::InvalidPublicKey),
            KeyValueInfo::Unsupported { .. } => return Ok(None),
        };
        validate_spki_algorithm(&public_key_bytes, algorithm)?;

        Ok(Some(VerificationKey {
            algorithm,
            public_key_bytes,
            certificate_der: None,
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
        let mut deferred_key_value_error = None;
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
                KeyInfoSource::KeyValue(key_value) => {
                    match Self::resolve_key_value(key_value, algorithm) {
                        Ok(resolved) => resolved,
                        Err(error) if ec_key_value_error_allows_fallback(key_value, &error) => {
                            deferred_key_value_error.get_or_insert(error);
                            None
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
            };
            if let Some(key) = resolved {
                return Ok(Some(Box::new(key)));
            }
        }
        if let Some(error) = deferred_key_value_error {
            return Err(error.into());
        }
        Ok(None)
    }

    fn consumes_document_key_info(&self) -> bool {
        true
    }
}

fn rsa_key_value_to_spki_der(
    modulus: &[u8],
    exponent: &[u8],
) -> Result<Vec<u8>, KeyResolutionError> {
    let key = rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(modulus),
        rsa::BigUint::from_bytes_be(exponent),
    )
    .map_err(|_| KeyResolutionError::InvalidPublicKey)?;
    key.to_public_key_der()
        .map_err(|_| KeyResolutionError::InvalidPublicKey)
        .map(|der| der.as_bytes().to_vec())
}

fn ec_key_value_to_spki_der(
    curve_oid: &str,
    public_key: &[u8],
) -> Result<Vec<u8>, KeyResolutionError> {
    match curve_oid {
        EC_P256_OID => p256::PublicKey::from_sec1_bytes(public_key)
            .map_err(|_| KeyResolutionError::InvalidPublicKey)?
            .to_public_key_der()
            .map_err(|_| KeyResolutionError::InvalidPublicKey)
            .map(|der| der.as_bytes().to_vec()),
        EC_P384_OID => p384::PublicKey::from_sec1_bytes(public_key)
            .map_err(|_| KeyResolutionError::InvalidPublicKey)?
            .to_public_key_der()
            .map_err(|_| KeyResolutionError::InvalidPublicKey)
            .map(|der| der.as_bytes().to_vec()),
        _ => Err(KeyResolutionError::InvalidPublicKey),
    }
}

fn ec_key_value_error_allows_fallback(
    key_value: &KeyValueInfo,
    error: &KeyResolutionError,
) -> bool {
    matches!(
        key_value,
        KeyValueInfo::Ec { .. } | KeyValueInfo::InvalidEcKeyValue
    ) && matches!(
        error,
        KeyResolutionError::InvalidPublicKey | KeyResolutionError::AlgorithmMismatch
    )
}

fn validate_spki_algorithm(
    public_key_bytes: &[u8],
    algorithm: SignatureAlgorithm,
) -> Result<(), KeyResolutionError> {
    let (rest, spki) = SubjectPublicKeyInfo::from_der(public_key_bytes)
        .map_err(|_| KeyResolutionError::InvalidPublicKey)?;
    if !rest.is_empty() {
        return Err(KeyResolutionError::InvalidPublicKey);
    }
    let parsed = spki
        .parsed()
        .map_err(|_| KeyResolutionError::InvalidPublicKey)?;
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
        // xmlsec's OpenSSL backend maps ecdsa-sha384 to EVP_sha384() plus the
        // generic EC key class, without restricting the curve to P-384. Keep
        // P-521/SHA-384 compatible with that donor contract.
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
    use rsa::{pkcs8::DecodePublicKey, traits::PublicKeyParts};

    use super::*;

    const SIGNED_SAML: &str =
        include_str!("../../tests/fixtures/saml/response_signed_by_idp_ecdsa.xml");
    const SAML_PUBLIC_KEY: &str =
        include_str!("../../tests/fixtures/keys/ec/saml-idp-ecdsa-pubkey.pem");
    const RSA_PUBLIC_KEY: &str = include_str!("../../tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");
    const RSA_4096_CERTIFICATE: &str =
        include_str!("../../tests/fixtures/keys/rsa/rsa-4096-cert.pem");
    const X509_DIGEST_SIGNATURE: &str = include_str!(
        "../../tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloped-x509-digest-sha512.xml"
    );
    const RSA_KEY_VALUE_SIGNATURE: &str = include_str!(
        "../../tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.xml"
    );
    const LEGACY_RSA_KEY_VALUE_SIGNATURE: &str = include_str!(
        "../../tests/fixtures/xmldsig/merlin-xmldsig-twenty-three/signature-enveloping-rsa.xml"
    );
    const EC_P256_KEY_VALUE_SIGNATURE: &str = include_str!(
        "../../tests/fixtures/xmldsig/xmldsig11-interop-2012/signature-enveloping-p256_sha256.xml"
    );
    const EC_P384_KEY_VALUE_SIGNATURE: &str = include_str!(
        "../../tests/fixtures/xmldsig/xmldsig11-interop-2012/signature-enveloping-p384_sha384.xml"
    );

    fn replace_key_info(xml: &str, replacement: &str) -> String {
        let start = xml.find("<ds:KeyInfo>").expect("fixture has KeyInfo");
        let end = xml
            .find("</ds:KeyInfo>")
            .expect("fixture has closing KeyInfo")
            + "</ds:KeyInfo>".len();
        format!("{}{}{}", &xml[..start], replacement, &xml[end..])
    }

    fn replace_unprefixed_key_info(xml: &str, replacement: &str) -> String {
        let start = xml.find("<KeyInfo>").expect("fixture has KeyInfo");
        let end = xml.find("</KeyInfo>").expect("fixture has closing KeyInfo") + "</KeyInfo>".len();
        format!("{}{}{}", &xml[..start], replacement, &xml[end..])
    }

    fn public_key_der(pem_text: &str) -> Vec<u8> {
        let (rest, pem) = x509_parser::pem::parse_x509_pem(pem_text.as_bytes())
            .expect("fixture public key is PEM");
        assert!(rest.iter().all(|byte| byte.is_ascii_whitespace()));
        assert_eq!(pem.label, "PUBLIC KEY");
        pem.contents
    }

    fn certificate_der(pem_text: &str) -> Vec<u8> {
        let (rest, pem) = x509_parser::pem::parse_x509_pem(pem_text.as_bytes())
            .expect("fixture certificate is PEM");
        assert!(rest.iter().all(|byte| byte.is_ascii_whitespace()));
        assert_eq!(pem.label, "CERTIFICATE");
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
    fn resolves_x509_digest_from_configured_certificates() {
        // Selector-only X509Data must locate the signing certificate without
        // embedding key material or supplying a preset verification key.
        let certificate_der = certificate_der(RSA_4096_CERTIFICATE);
        let resolver = DefaultKeyResolver::new(KeyResolverConfig {
            trusted_certs: vec![certificate_der],
            ..KeyResolverConfig::default()
        });
        let result = super::super::VerifyContext::new()
            .key_resolver(&resolver)
            .verify(X509_DIGEST_SIGNATURE)
            .expect("X509Digest should resolve a configured certificate");

        assert_eq!(result.status, super::super::DsigStatus::Valid);
    }

    #[test]
    fn selector_resolved_certificate_obeys_chain_policy() {
        // Enabling chain verification must apply validity policy even when
        // X509Data contains only selectors and the matching cert is configured.
        let certificate_der = certificate_der(RSA_4096_CERTIFICATE);
        let resolver = DefaultKeyResolver::new(KeyResolverConfig {
            trusted_certs: vec![certificate_der],
            verify_chains: true,
            verification_time: Some(SystemTime::UNIX_EPOCH),
            ..KeyResolverConfig::default()
        });
        let error = super::super::VerifyContext::new()
            .key_resolver(&resolver)
            .verify(X509_DIGEST_SIGNATURE)
            .expect_err("selector-resolved certificate must satisfy chain policy");

        assert!(matches!(
            error,
            DsigError::KeyResolution(KeyResolutionError::Chain(
                super::super::X509ChainError::CertificateNotValid(_)
            ))
        ));
    }

    #[test]
    fn resolves_each_x509_selector_from_configured_certificates() {
        // Every selector form documented by KeyInfo must independently locate
        // the same configured RSA certificate without embedded key material.
        let selectors = [
            "<X509SubjectName>C=US, ST=California, O=XML Security Library (http://www.aleksey.com/xmlsec), CN=Test Key rsa-2048</X509SubjectName>",
            "<X509IssuerSerial><X509IssuerName>C=US, ST=California, O=XML Security Library (http://www.aleksey.com/xmlsec), OU=Second level CA, CN=Aleksey Sanin, Email=xmlsec@aleksey.com</X509IssuerName><X509SerialNumber>680572598617295163017172295025714171905498632019</X509SerialNumber></X509IssuerSerial>",
            "<X509SKI>bcOXN/nsVl8GatRbcKrPbzIbw0Y=</X509SKI>",
        ];
        let configured_certificate = certificate_der(include_str!(
            "../../tests/fixtures/keys/rsa/rsa-2048-cert.pem"
        ));

        for selector in selectors {
            let key_info = format!("<KeyInfo><X509Data>{selector}</X509Data></KeyInfo>");
            let xml = replace_unprefixed_key_info(RSA_KEY_VALUE_SIGNATURE, &key_info);
            let resolver = DefaultKeyResolver::new(KeyResolverConfig {
                trusted_certs: vec![configured_certificate.clone()],
                ..KeyResolverConfig::default()
            });
            let result = super::super::VerifyContext::new()
                .key_resolver(&resolver)
                .verify(&xml)
                .expect("X509 selector should resolve configured certificate");

            assert_eq!(result.status, super::super::DsigStatus::Valid);
        }
    }

    #[test]
    fn unmatched_x509_selector_does_not_resolve() {
        // A selector mismatch must not fall back to arbitrary configured key material.
        let key_info = "<KeyInfo><X509Data><X509SubjectName>CN=not-the-signer</X509SubjectName></X509Data></KeyInfo>";
        let xml = replace_unprefixed_key_info(RSA_KEY_VALUE_SIGNATURE, key_info);
        let resolver = DefaultKeyResolver::new(KeyResolverConfig {
            trusted_certs: vec![certificate_der(include_str!(
                "../../tests/fixtures/keys/rsa/rsa-2048-cert.pem"
            ))],
            ..KeyResolverConfig::default()
        });
        let result = super::super::VerifyContext::new()
            .key_resolver(&resolver)
            .verify(&xml)
            .expect("an unmatched selector is a key miss, not a parser failure");

        assert!(matches!(
            result.status,
            super::super::DsigStatus::Invalid(super::super::FailureReason::KeyNotFound)
        ));
    }

    #[test]
    fn ambiguous_x509_digest_selector_fails_closed() {
        // Duplicate configured certificates must not make key selection order-dependent.
        let certificate = certificate_der(RSA_4096_CERTIFICATE);
        let resolver = DefaultKeyResolver::new(KeyResolverConfig {
            trusted_certs: vec![certificate.clone(), certificate],
            ..KeyResolverConfig::default()
        });
        let error = super::super::VerifyContext::new()
            .key_resolver(&resolver)
            .verify(X509_DIGEST_SIGNATURE)
            .expect_err("ambiguous X509Digest lookup must fail closed");

        assert!(matches!(
            error,
            DsigError::KeyResolution(KeyResolutionError::AmbiguousCertificate)
        ));
    }

    #[test]
    fn unsupported_x509_digest_selector_fails_closed() {
        // Unknown digest URIs must not be treated as a normal key miss because
        // that would silently weaken the caller's explicit selector policy.
        let key_info = "<KeyInfo xmlns:dsig11=\"http://www.w3.org/2009/xmldsig11#\"><X509Data><dsig11:X509Digest Algorithm=\"urn:unsupported\">AQ==</dsig11:X509Digest></X509Data></KeyInfo>";
        let xml = replace_unprefixed_key_info(RSA_KEY_VALUE_SIGNATURE, key_info);
        let resolver = DefaultKeyResolver::new(KeyResolverConfig {
            trusted_certs: vec![certificate_der(include_str!(
                "../../tests/fixtures/keys/rsa/rsa-2048-cert.pem"
            ))],
            ..KeyResolverConfig::default()
        });
        let error = super::super::VerifyContext::new()
            .key_resolver(&resolver)
            .verify(&xml)
            .expect_err("unsupported X509Digest algorithm must fail closed");

        assert!(matches!(
            error,
            DsigError::KeyResolution(KeyResolutionError::UnsupportedDigestAlgorithm(uri))
                if uri == "urn:unsupported"
        ));
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
    fn resolves_rsa_key_value_end_to_end() {
        // Embedded CryptoBinary parameters must verify the original RSA-2048 donor signature.
        let public_key = rsa::RsaPublicKey::from_public_key_pem(RSA_PUBLIC_KEY)
            .expect("fixture must contain an RSA public key");
        let key_info = format!(
            "<KeyInfo><KeyValue><RSAKeyValue><Modulus>{}</Modulus><Exponent>{}</Exponent></RSAKeyValue></KeyValue></KeyInfo>",
            STANDARD.encode(public_key.n().to_bytes_be()),
            STANDARD.encode(public_key.e().to_bytes_be()),
        );
        let xml = replace_unprefixed_key_info(RSA_KEY_VALUE_SIGNATURE, &key_info);
        let resolver = DefaultKeyResolver::default();
        let result = super::super::VerifyContext::new()
            .key_resolver(&resolver)
            .verify(&xml)
            .expect("RSAKeyValue should resolve");

        assert_eq!(result.status, super::super::DsigStatus::Valid);
    }

    #[test]
    fn rsa_key_value_rejects_legacy_weak_modulus() {
        // Embedded keys must obey the same 2048-bit minimum as certificate and DER keys.
        let resolver = DefaultKeyResolver::default();
        let error = super::super::VerifyContext::new()
            .key_resolver(&resolver)
            .verify(LEGACY_RSA_KEY_VALUE_SIGNATURE)
            .expect_err("1024-bit RSAKeyValue must fail closed");

        assert!(matches!(
            error,
            DsigError::Crypto(super::super::SignatureVerificationError::InvalidKeyDer)
        ));
    }

    #[test]
    fn rsa_key_value_rejects_ecdsa_signature_method() {
        // Embedded RSA parameters must not be relabeled for an ECDSA SignatureMethod.
        let public_key = rsa::RsaPublicKey::from_public_key_pem(RSA_PUBLIC_KEY)
            .expect("fixture must contain an RSA public key");
        let key_info = format!(
            "<ds:KeyInfo><ds:KeyValue><ds:RSAKeyValue><ds:Modulus>{}</ds:Modulus><ds:Exponent>{}</ds:Exponent></ds:RSAKeyValue></ds:KeyValue></ds:KeyInfo>",
            STANDARD.encode(public_key.n().to_bytes_be()),
            STANDARD.encode(public_key.e().to_bytes_be()),
        );
        let xml = replace_key_info(SIGNED_SAML, &key_info);
        let resolver = DefaultKeyResolver::default();
        let error = super::super::VerifyContext::new()
            .key_resolver(&resolver)
            .verify(&xml)
            .expect_err("RSAKeyValue must not resolve for ECDSA");

        assert!(matches!(
            error,
            DsigError::KeyResolution(KeyResolutionError::AlgorithmMismatch)
        ));
    }

    #[test]
    fn resolves_ec_p256_key_value_end_to_end() {
        // XMLDSig 1.1 ECKeyValue must verify without a preset key or certificate.
        let resolver = DefaultKeyResolver::default();
        let result = super::super::VerifyContext::new()
            .key_resolver(&resolver)
            .verify(EC_P256_KEY_VALUE_SIGNATURE)
            .expect("P-256 ECKeyValue should resolve");

        assert_eq!(result.status, super::super::DsigStatus::Valid);
    }

    #[test]
    fn resolves_ec_p384_key_value_end_to_end() {
        // The donor P-384 vector uses NamedCurve + uncompressed PublicKey.
        let resolver = DefaultKeyResolver::default();
        let result = super::super::VerifyContext::new()
            .key_resolver(&resolver)
            .verify(EC_P384_KEY_VALUE_SIGNATURE)
            .expect("P-384 ECKeyValue should resolve");

        assert_eq!(result.status, super::super::DsigStatus::Valid);
    }

    #[test]
    fn ec_key_value_ignored_for_rsa_signature_method() {
        // Embedded EC key material must not be relabeled for an RSA SignatureMethod.
        let key_info = r#"<KeyInfo xmlns:dsig11="http://www.w3.org/2009/xmldsig11#"><KeyValue><dsig11:ECKeyValue><dsig11:NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"/><dsig11:PublicKey>BJ/yaXNlq4FRObyJCBhb5jAz8GVzinK3bBGLjSDfjbJwNfydtgjnlS4EsDmxSRhWyJWq6GIqy5wvnaiARK04uB4=</dsig11:PublicKey></dsig11:ECKeyValue></KeyValue></KeyInfo>"#;
        let xml = replace_unprefixed_key_info(RSA_KEY_VALUE_SIGNATURE, key_info);
        let resolver = DefaultKeyResolver::default();
        let result = super::super::VerifyContext::new()
            .key_resolver(&resolver)
            .verify(&xml)
            .expect("single incompatible ECKeyValue should be ignored");

        assert_eq!(
            result.status,
            super::super::DsigStatus::Invalid(super::super::FailureReason::KeyNotFound)
        );
    }

    #[test]
    fn incompatible_ec_key_value_falls_back_to_later_rsa_key_value() {
        // Mixed KeyInfo should keep scanning after an incompatible ECKeyValue source.
        let public_key = rsa::RsaPublicKey::from_public_key_pem(RSA_PUBLIC_KEY)
            .expect("fixture must contain an RSA public key");
        let key_info = format!(
            r#"<KeyInfo xmlns:dsig11="http://www.w3.org/2009/xmldsig11#"><KeyValue><dsig11:ECKeyValue><dsig11:NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"/><dsig11:PublicKey>BJ/yaXNlq4FRObyJCBhb5jAz8GVzinK3bBGLjSDfjbJwNfydtgjnlS4EsDmxSRhWyJWq6GIqy5wvnaiARK04uB4=</dsig11:PublicKey></dsig11:ECKeyValue></KeyValue><KeyValue><RSAKeyValue><Modulus>{}</Modulus><Exponent>{}</Exponent></RSAKeyValue></KeyValue></KeyInfo>"#,
            STANDARD.encode(public_key.n().to_bytes_be()),
            STANDARD.encode(public_key.e().to_bytes_be()),
        );
        let xml = replace_unprefixed_key_info(RSA_KEY_VALUE_SIGNATURE, &key_info);
        let resolver = DefaultKeyResolver::default();
        let result = super::super::VerifyContext::new()
            .key_resolver(&resolver)
            .verify(&xml)
            .expect("later RSAKeyValue should resolve");

        assert_eq!(result.status, super::super::DsigStatus::Valid);
    }

    #[test]
    fn unsupported_ec_key_value_falls_back_to_later_key_name() {
        // Unsupported curves are non-fatal so a later compatible source can verify.
        let key_info = r#"<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:dsig11="http://www.w3.org/2009/xmldsig11#"><ds:KeyValue><dsig11:ECKeyValue><dsig11:NamedCurve URI="urn:oid:1.3.132.0.35"/><dsig11:PublicKey>BA==</dsig11:PublicKey></dsig11:ECKeyValue></ds:KeyValue><ds:KeyName>idp-signing</ds:KeyName></ds:KeyInfo>"#;
        let xml = replace_key_info(SIGNED_SAML, key_info);
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
            .expect("later KeyName should resolve");

        assert_eq!(result.status, super::super::DsigStatus::Valid);
    }

    #[test]
    fn invalid_ec_key_value_falls_back_to_later_key_name() {
        // Off-curve EC points are typed errors only if no later source can verify.
        let key_info = r#"<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:dsig11="http://www.w3.org/2009/xmldsig11#"><ds:KeyValue><dsig11:ECKeyValue><dsig11:NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"/><dsig11:PublicKey>BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</dsig11:PublicKey></dsig11:ECKeyValue></ds:KeyValue><ds:KeyName>idp-signing</ds:KeyName></ds:KeyInfo>"#;
        let xml = replace_key_info(SIGNED_SAML, key_info);
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
            .expect("later KeyName should resolve after invalid ECKeyValue");

        assert_eq!(result.status, super::super::DsigStatus::Valid);
    }

    #[test]
    fn malformed_ec_key_value_falls_back_to_later_key_name() {
        // Parse-level EC point errors remain non-fatal while later sources exist.
        let key_info = r#"<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:dsig11="http://www.w3.org/2009/xmldsig11#"><ds:KeyValue><dsig11:ECKeyValue><dsig11:NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"/><dsig11:PublicKey>AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</dsig11:PublicKey></dsig11:ECKeyValue></ds:KeyValue><ds:KeyName>idp-signing</ds:KeyName></ds:KeyInfo>"#;
        let xml = replace_key_info(SIGNED_SAML, key_info);
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
            .expect("later KeyName should resolve after malformed ECKeyValue");

        assert_eq!(result.status, super::super::DsigStatus::Valid);
    }

    #[test]
    fn invalid_base64_ec_key_value_falls_back_to_later_key_name() {
        // A bad ECKeyValue payload is an unusable source, not a reason to skip
        // later ordered KeyInfo sources that can verify the signature.
        let key_info = r#"<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:dsig11="http://www.w3.org/2009/xmldsig11#"><ds:KeyValue><dsig11:ECKeyValue><dsig11:NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"/><dsig11:PublicKey>not base64!</dsig11:PublicKey></dsig11:ECKeyValue></ds:KeyValue><ds:KeyName>idp-signing</ds:KeyName></ds:KeyInfo>"#;
        let xml = replace_key_info(SIGNED_SAML, key_info);
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
            .expect("later KeyName should resolve after bad ECKeyValue base64");

        assert_eq!(result.status, super::super::DsigStatus::Valid);
    }

    #[test]
    fn missing_curve_uri_ec_key_value_falls_back_to_later_key_name() {
        // Missing EC curve parameters make only this KeyValue source unusable.
        let key_info = r#"<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:dsig11="http://www.w3.org/2009/xmldsig11#"><ds:KeyValue><dsig11:ECKeyValue><dsig11:NamedCurve/><dsig11:PublicKey>BA==</dsig11:PublicKey></dsig11:ECKeyValue></ds:KeyValue><ds:KeyName>idp-signing</ds:KeyName></ds:KeyInfo>"#;
        let xml = replace_key_info(SIGNED_SAML, key_info);
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
            .expect("later KeyName should resolve after missing EC curve URI");

        assert_eq!(result.status, super::super::DsigStatus::Valid);
    }

    #[test]
    fn malformed_ec_key_value_children_fall_back_to_later_key_name() {
        // An unusable EC source must not prevent later ordered KeyInfo sources
        // from resolving, regardless of which required child-shape check fails.
        let malformed_ec_key_values = [
            r#"<dsig11:NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"/>"#,
            r#"<dsig11:NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"/><dsig11:NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"/>"#,
            r#"<dsig11:NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"/><dsig11:PublicKey>BA==</dsig11:PublicKey><dsig11:PublicKey>BA==</dsig11:PublicKey>"#,
        ];

        for malformed_children in malformed_ec_key_values {
            let key_info = format!(
                r#"<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:dsig11="http://www.w3.org/2009/xmldsig11#"><ds:KeyValue><dsig11:ECKeyValue>{malformed_children}</dsig11:ECKeyValue></ds:KeyValue><ds:KeyName>idp-signing</ds:KeyName></ds:KeyInfo>"#
            );
            let xml = replace_key_info(SIGNED_SAML, &key_info);
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
                .expect("later KeyName should resolve after malformed EC child shape");

            assert_eq!(result.status, super::super::DsigStatus::Valid);
        }
    }

    #[test]
    fn mismatched_ec_curve_falls_back_to_later_key_name() {
        // A valid P-384 key is unusable for an ECDSA-SHA256 signature but must not
        // prevent a later P-256 KeyName from resolving the same document.
        let key_info = r#"<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:dsig11="http://www.w3.org/2009/xmldsig11#"><ds:KeyValue><dsig11:ECKeyValue><dsig11:NamedCurve URI="urn:oid:1.3.132.0.34"/><dsig11:PublicKey>BO/yd/OZzDfjX4qivDY/vsUIuh6KWAxoxW5P4ukvwd+T6pVljWsX2UBJNNy5MdhTwB8e2YwB8kUbJwdsAS/XGi/fz8unFrs+lVlAgIs6s/xBYFbfUoRiAacD2SpVDe6XBA==</dsig11:PublicKey></dsig11:ECKeyValue></ds:KeyValue><ds:KeyName>idp-signing</ds:KeyName></ds:KeyInfo>"#;
        let xml = replace_key_info(SIGNED_SAML, key_info);
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
            .expect("later KeyName should resolve after mismatched ECKeyValue");

        assert_eq!(result.status, super::super::DsigStatus::Valid);
    }

    #[test]
    fn lone_malformed_ec_key_value_reports_invalid_public_key() {
        let key_info = r#"<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:dsig11="http://www.w3.org/2009/xmldsig11#"><ds:KeyValue><dsig11:ECKeyValue><dsig11:NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"/><dsig11:PublicKey>AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</dsig11:PublicKey></dsig11:ECKeyValue></ds:KeyValue></ds:KeyInfo>"#;
        let xml = replace_key_info(SIGNED_SAML, key_info);
        let error = super::super::VerifyContext::new()
            .key_resolver(&DefaultKeyResolver::default())
            .verify(&xml)
            .expect_err("lone malformed ECKeyValue should surface typed key error");

        assert!(matches!(
            error,
            DsigError::KeyResolution(KeyResolutionError::InvalidPublicKey)
        ));
    }

    #[test]
    fn lone_mismatched_ec_curve_reports_algorithm_mismatch() {
        let key_info = r#"<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:dsig11="http://www.w3.org/2009/xmldsig11#"><ds:KeyValue><dsig11:ECKeyValue><dsig11:NamedCurve URI="urn:oid:1.3.132.0.34"/><dsig11:PublicKey>BO/yd/OZzDfjX4qivDY/vsUIuh6KWAxoxW5P4ukvwd+T6pVljWsX2UBJNNy5MdhTwB8e2YwB8kUbJwdsAS/XGi/fz8unFrs+lVlAgIs6s/xBYFbfUoRiAacD2SpVDe6XBA==</dsig11:PublicKey></dsig11:ECKeyValue></ds:KeyValue></ds:KeyInfo>"#;
        let xml = replace_key_info(SIGNED_SAML, key_info);
        let error = super::super::VerifyContext::new()
            .key_resolver(&DefaultKeyResolver::default())
            .verify(&xml)
            .expect_err("lone mismatched ECKeyValue should surface typed key error");

        assert!(matches!(
            error,
            DsigError::KeyResolution(KeyResolutionError::AlgorithmMismatch)
        ));
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

    #[test]
    fn malformed_named_key_reports_public_key_error() {
        // Non-certificate SPKI failures must not be mislabeled as certificate errors.
        let xml = replace_key_info(
            SIGNED_SAML,
            "<ds:KeyInfo><ds:KeyName>malformed</ds:KeyName></ds:KeyInfo>",
        );
        let mut config = KeyResolverConfig::default();
        config.named_keys.insert(
            "malformed".into(),
            VerificationKey {
                algorithm: SignatureAlgorithm::EcdsaP256Sha256,
                public_key_bytes: vec![1, 2, 3],
                certificate_der: None,
                name: Some("malformed".into()),
            },
        );
        let resolver = DefaultKeyResolver::new(config);
        let error = super::super::VerifyContext::new()
            .key_resolver(&resolver)
            .verify(&xml)
            .expect_err("malformed named key must fail during resolution");

        assert!(matches!(
            error,
            DsigError::KeyResolution(KeyResolutionError::InvalidPublicKey)
        ));
    }
}
