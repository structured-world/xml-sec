//! Configuration and key material for XMLDSig key resolution.

use std::{collections::HashMap, fmt, time::SystemTime};

use crypto_bigint::BoxedUint;
use dsa::pkcs8::{DecodePublicKey as DsaDecodePublicKey, EncodePublicKey as DsaEncodePublicKey};
use hmac::{KeyInit, Mac};
use x509_parser::{
    prelude::{FromDer, X509Certificate},
    public_key::PublicKey,
    x509::SubjectPublicKeyInfo,
};

use super::signature::{
    signature_value_matches_spki, validate_dsa_signature_spki_with_minimum,
    validate_rsa_signature_spki_with_minimum, verify_dsa_signature_spki_primitive,
    verify_dsa_signature_spki_with_minimum, verify_rsa_signature_spki_primitive,
    verify_rsa_signature_spki_with_minimum,
};
use super::{
    DsigError, KeyInfo, KeyInfoSource, KeyResolver, KeyValueInfo, SignatureAlgorithm, VerifyingKey,
    X509ChainOptions, X509DataInfo,
    parse::{
        EC_P256_OID, EC_P384_OID, ParseError, X509ChainBuildError,
        build_x509_certificate_paths_to_selector_targets,
        build_x509_certificate_paths_to_trusted_prefix, distinguished_names_equal,
        parse_x509_certificate, x509_certificate_matches_any_selector,
        x509_data_has_lookup_identifiers, x509_selector_categories_match_chain,
    },
    verify_ecdsa_signature_spki,
    x509::verify_x509_certificate_chain_with_provider,
};

/// Caller-owned HMAC-SHA1 verification key.
#[derive(Clone)]
pub struct HmacSha1VerificationKey {
    secret: Vec<u8>,
    output_len: usize,
}

impl fmt::Debug for HmacSha1VerificationKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HmacSha1VerificationKey")
            .field("output_length_bits", &(self.output_len * 8))
            .finish_non_exhaustive()
    }
}

impl HmacSha1VerificationKey {
    /// Construct a key from non-empty secret bytes.
    pub fn new(secret: impl Into<Vec<u8>>) -> Result<Self, KeyResolutionError> {
        let secret = secret.into();
        if secret.is_empty() {
            return Err(KeyResolutionError::InvalidPublicKey);
        }
        Ok(Self {
            secret,
            output_len: 20,
        })
    }

    /// Bind this key to an XMLDSig HMAC output length in bits.
    pub fn with_output_length_bits(
        mut self,
        output_length_bits: u16,
    ) -> Result<Self, KeyResolutionError> {
        if !(80..=160).contains(&output_length_bits) || !output_length_bits.is_multiple_of(8) {
            return Err(KeyResolutionError::InvalidHmacOutputLength);
        }
        self.output_len = usize::from(output_length_bits / 8);
        Ok(self)
    }
}

impl VerifyingKey for HmacSha1VerificationKey {
    fn validate_signature_value(
        &self,
        algorithm: SignatureAlgorithm,
        signature_value: &[u8],
    ) -> Result<bool, DsigError> {
        if algorithm != SignatureAlgorithm::HmacSha1 {
            return Err(KeyResolutionError::AlgorithmMismatch.into());
        }
        Ok(signature_value.len() == self.output_len)
    }

    fn verify(
        &self,
        algorithm: SignatureAlgorithm,
        signed_data: &[u8],
        signature_value: &[u8],
    ) -> Result<bool, DsigError> {
        if algorithm != SignatureAlgorithm::HmacSha1 {
            return Err(KeyResolutionError::AlgorithmMismatch.into());
        }
        if signature_value.len() != self.output_len {
            return Ok(false);
        }
        let mut mac = hmac::Hmac::<sha1::Sha1>::new_from_slice(&self.secret)
            .map_err(|_| KeyResolutionError::InvalidPublicKey)?;
        mac.update(signed_data);
        let expected = mac.finalize().into_bytes();
        Ok(subtle::ConstantTimeEq::ct_eq(&expected[..self.output_len], signature_value).into())
    }
}

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
    fn validate_policy(&self, policy: &crate::policy::VerificationPolicy) -> Result<(), DsigError> {
        let result = match self.algorithm {
            SignatureAlgorithm::DsaSha1 => validate_dsa_signature_spki_with_minimum(
                &self.public_key_bytes,
                policy.key_trust.dsa_keys.minimum_modulus_bits,
            ),
            SignatureAlgorithm::RsaSha1
            | SignatureAlgorithm::RsaSha256
            | SignatureAlgorithm::RsaSha384
            | SignatureAlgorithm::RsaSha512 => validate_rsa_signature_spki_with_minimum(
                self.algorithm,
                &self.public_key_bytes,
                policy.key_trust.rsa_keys.minimum_modulus_bits,
            ),
            SignatureAlgorithm::HmacSha1
            | SignatureAlgorithm::EcdsaSha256
            | SignatureAlgorithm::EcdsaSha384 => Ok(()),
        };
        result.map_err(DsigError::Crypto)
    }

    fn validate_signature_value(
        &self,
        algorithm: SignatureAlgorithm,
        signature_value: &[u8],
    ) -> Result<bool, DsigError> {
        if algorithm != self.algorithm {
            return Err(KeyResolutionError::AlgorithmMismatch.into());
        }
        signature_value_matches_spki(algorithm, &self.public_key_bytes, signature_value)
            .map_err(DsigError::Crypto)
    }

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
            SignatureAlgorithm::DsaSha1 => verify_dsa_signature_spki_primitive(
                algorithm,
                &self.public_key_bytes,
                signed_data,
                signature_value,
            ),
            SignatureAlgorithm::HmacSha1 => {
                return Err(KeyResolutionError::AlgorithmMismatch.into());
            }
            SignatureAlgorithm::RsaSha1
            | SignatureAlgorithm::RsaSha256
            | SignatureAlgorithm::RsaSha384
            | SignatureAlgorithm::RsaSha512 => verify_rsa_signature_spki_primitive(
                algorithm,
                &self.public_key_bytes,
                signed_data,
                signature_value,
            ),
            SignatureAlgorithm::EcdsaSha256 | SignatureAlgorithm::EcdsaSha384 => {
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

struct PolicyBoundVerificationKey {
    key: VerificationKey,
    rsa_minimum_bits: usize,
    dsa_minimum_bits: usize,
}

impl VerifyingKey for PolicyBoundVerificationKey {
    fn validate_signature_value(
        &self,
        algorithm: SignatureAlgorithm,
        signature_value: &[u8],
    ) -> Result<bool, DsigError> {
        self.key
            .validate_signature_value(algorithm, signature_value)
    }

    fn verify(
        &self,
        algorithm: SignatureAlgorithm,
        signed_data: &[u8],
        signature_value: &[u8],
    ) -> Result<bool, DsigError> {
        if algorithm != self.key.algorithm {
            return Err(KeyResolutionError::AlgorithmMismatch.into());
        }
        let result = match algorithm {
            SignatureAlgorithm::DsaSha1 => verify_dsa_signature_spki_with_minimum(
                algorithm,
                &self.key.public_key_bytes,
                signed_data,
                signature_value,
                self.dsa_minimum_bits,
            ),
            SignatureAlgorithm::RsaSha1
            | SignatureAlgorithm::RsaSha256
            | SignatureAlgorithm::RsaSha384
            | SignatureAlgorithm::RsaSha512 => verify_rsa_signature_spki_with_minimum(
                algorithm,
                &self.key.public_key_bytes,
                signed_data,
                signature_value,
                self.rsa_minimum_bits,
            ),
            _ => return self.key.verify(algorithm, signed_data, signature_value),
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
    /// HMAC-SHA1 output length is outside XMLDSig's byte-aligned 80-160 bit range.
    #[error("HMAC-SHA1 output length must be byte-aligned and between 80 and 160 bits")]
    InvalidHmacOutputLength,
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
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyResolverConfig {
    /// DER-encoded certificates available to X.509 selectors and as untrusted
    /// path intermediates. They establish trust only by chaining to an entry in
    /// [`Self::trusted_certs`].
    pub lookup_certs: Vec<Vec<u8>>,
    /// DER-encoded certificates accepted as trust anchors.
    pub trusted_certs: Vec<Vec<u8>>,
    /// Verification keys addressable by `<KeyName>` content.
    pub named_keys: HashMap<String, VerificationKey>,
}

/// Configuration-driven resolver for embedded certificates, DER keys, and key names.
#[derive(Debug, Clone, Default)]
pub struct DefaultKeyResolver {
    config: KeyResolverConfig,
}

struct KeyCandidateBudget {
    maximum: usize,
    attempted: usize,
}

impl KeyCandidateBudget {
    fn new(maximum: usize) -> Self {
        Self {
            maximum,
            attempted: 0,
        }
    }

    fn charge(&mut self) -> Result<(), DsigError> {
        self.attempted = self.attempted.saturating_add(1);
        if self.attempted > self.maximum {
            return Err(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::KEY_CANDIDATES,
                maximum: self.maximum,
                actual: self.attempted,
            }
            .into());
        }
        Ok(())
    }
}

impl DefaultKeyResolver {
    /// Construct a resolver from explicit caller-owned key and certificate stores.
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
        trust: &crate::policy::KeyTrustPolicy,
        provider: &dyn crate::provider::CryptoProvider,
        budget: &mut KeyCandidateBudget,
    ) -> Result<Option<VerificationKey>, DsigError> {
        let certificate_der = if let Some(&signing_index) = info.certificate_chain.first() {
            if trust.verify_x509_chains {
                self.prepare_embedded_x509(info, signing_index, trust, provider, budget)?;
            } else {
                let mut unique = Vec::<&[u8]>::new();
                for certificate in &info.certificates {
                    if unique.contains(&certificate.as_slice()) {
                        continue;
                    }
                    budget.charge()?;
                    unique.push(certificate);
                }
            }
            info.certificates
                .get(signing_index)
                .ok_or(KeyResolutionError::InvalidCertificate)?
                .clone()
        } else {
            let Some(selected) = self.resolve_configured_x509(info, trust, provider, budget)?
            else {
                return Ok(None);
            };
            selected
                .certificate_chain
                .first()
                .and_then(|index| selected.certificates.get(*index))
                .ok_or(KeyResolutionError::InvalidCertificate)?
                .clone()
        };

        let (rest, certificate) = X509Certificate::from_der(&certificate_der)
            .map_err(|_| KeyResolutionError::InvalidCertificate)?;
        if !rest.is_empty() {
            return Err(KeyResolutionError::InvalidCertificate.into());
        }
        let public_key_bytes = certificate.public_key().raw.to_vec();
        validate_spki_algorithm(&public_key_bytes, algorithm)?;
        Ok(Some(VerificationKey {
            algorithm,
            public_key_bytes,
            certificate_der: Some(certificate_der),
            name: None,
        }))
    }

    fn verify_x509_policy(
        &self,
        info: &X509DataInfo,
        trust: &crate::policy::KeyTrustPolicy,
        provider: &dyn crate::provider::CryptoProvider,
    ) -> Result<(), KeyResolutionError> {
        let options = X509ChainOptions {
            trusted_certs: &self.config.trusted_certs,
            verification_time: trust.verification_time.unwrap_or_else(SystemTime::now),
            max_chain_depth: trust.max_x509_chain_depth,
            check_crls: trust.check_crls,
            allowed_extended_key_usages: Some(&trust.allowed_extended_key_usages),
            rsa_keys: trust.rsa_keys,
            dsa_keys: trust.dsa_keys,
        };
        verify_x509_certificate_chain_with_provider(info, &options, provider)?;
        Ok(())
    }

    fn prepare_embedded_x509(
        &self,
        info: &X509DataInfo,
        signing_index: usize,
        trust: &crate::policy::KeyTrustPolicy,
        provider: &dyn crate::provider::CryptoProvider,
        budget: &mut KeyCandidateBudget,
    ) -> Result<X509DataInfo, DsigError> {
        let signing_der = info
            .certificates
            .get(signing_index)
            .ok_or(KeyResolutionError::InvalidCertificate)?;
        let mut available = X509DataInfo {
            crls: info.crls.clone(),
            ..X509DataInfo::default()
        };
        let mut trusted_prefix_len = 0;
        for certificate in &self.config.trusted_certs {
            if available
                .certificates
                .iter()
                .any(|known| known == certificate)
            {
                continue;
            }
            budget.charge()?;
            available.parsed_certificates.push(
                parse_x509_certificate(certificate)
                    .map_err(|_| KeyResolutionError::InvalidCertificate)?,
            );
            available.certificates.push(certificate.clone());
            trusted_prefix_len += 1;
        }
        for certificate in self.config.lookup_certs.iter().chain(&info.certificates) {
            if available
                .certificates
                .iter()
                .any(|known| known == certificate)
            {
                continue;
            }
            budget.charge()?;
            available.parsed_certificates.push(
                parse_x509_certificate(certificate)
                    .map_err(|_| KeyResolutionError::InvalidCertificate)?,
            );
            available.certificates.push(certificate.clone());
        }
        let signing_index = available
            .certificates
            .iter()
            .position(|certificate| certificate == signing_der)
            .ok_or(KeyResolutionError::InvalidCertificate)?;
        self.select_valid_x509_path(
            &mut available,
            signing_index,
            trusted_prefix_len,
            trust,
            provider,
            None,
        )?;
        Ok(available)
    }

    fn select_valid_x509_path(
        &self,
        available: &mut X509DataInfo,
        signing_index: usize,
        trusted_prefix_len: usize,
        trust: &crate::policy::KeyTrustPolicy,
        provider: &dyn crate::provider::CryptoProvider,
        selectors: Option<&X509DataInfo>,
    ) -> Result<bool, KeyResolutionError> {
        let candidates = build_x509_certificate_paths_to_trusted_prefix(
            available,
            signing_index,
            trusted_prefix_len,
            trust.max_x509_chain_depth,
            trust.max_x509_candidate_paths,
            provider,
        )
        .map_err(|error| match error {
            X509ChainBuildError::AmbiguousIssuer => KeyResolutionError::AmbiguousCertificate,
            X509ChainBuildError::Provider(error) => {
                KeyResolutionError::Chain(super::X509ChainError::Provider(error))
            }
            X509ChainBuildError::UnsupportedSignatureAlgorithm { oid } => {
                KeyResolutionError::Chain(super::X509ChainError::UnsupportedSignatureAlgorithm {
                    oid,
                })
            }
            _ => KeyResolutionError::InvalidCertificate,
        })?;
        let mut first_error = None;
        let mut valid_path_without_selector_match = false;
        for candidate in candidates {
            available.certificate_chain = candidate;
            match self.verify_x509_policy(available, trust, provider) {
                Ok(()) => {
                    if match selectors {
                        Some(selectors) => {
                            selected_x509_path_matches_selectors(available, selectors, provider)?
                        }
                        None => true,
                    } {
                        return Ok(true);
                    }
                    valid_path_without_selector_match = true;
                }
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        if valid_path_without_selector_match {
            return Ok(false);
        }
        Err(first_error.unwrap_or(KeyResolutionError::Chain(
            super::X509ChainError::UntrustedRoot,
        )))
    }

    fn select_x509_selector_path(
        &self,
        available: &mut X509DataInfo,
        signing_index: usize,
        matching_indices: &[usize],
        trust: &crate::policy::KeyTrustPolicy,
        provider: &dyn crate::provider::CryptoProvider,
        selectors: &X509DataInfo,
    ) -> Result<bool, KeyResolutionError> {
        let targets = matching_indices
            .iter()
            .copied()
            .filter(|index| *index != signing_index)
            .collect::<Vec<_>>();
        if targets.is_empty() {
            return Ok(false);
        }
        let candidates = build_x509_certificate_paths_to_selector_targets(
            available,
            signing_index,
            &targets,
            trust.max_x509_chain_depth,
            trust.max_x509_candidate_paths,
            provider,
        )
        .map_err(|error| match error {
            X509ChainBuildError::AmbiguousIssuer => KeyResolutionError::AmbiguousCertificate,
            X509ChainBuildError::Provider(error) => {
                KeyResolutionError::Chain(super::X509ChainError::Provider(error))
            }
            X509ChainBuildError::UnsupportedSignatureAlgorithm { oid } => {
                KeyResolutionError::Chain(super::X509ChainError::UnsupportedSignatureAlgorithm {
                    oid,
                })
            }
            _ => KeyResolutionError::InvalidCertificate,
        })?;
        for candidate in candidates {
            available.certificate_chain = candidate;
            if selected_x509_path_matches_selectors(available, selectors, provider)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn resolve_configured_x509(
        &self,
        info: &X509DataInfo,
        trust: &crate::policy::KeyTrustPolicy,
        provider: &dyn crate::provider::CryptoProvider,
        budget: &mut KeyCandidateBudget,
    ) -> Result<Option<X509DataInfo>, DsigError> {
        if !x509_data_has_lookup_identifiers(info) {
            return Ok(None);
        }

        let mut available = X509DataInfo {
            subject_names: info.subject_names.clone(),
            issuer_serials: info.issuer_serials.clone(),
            skis: info.skis.clone(),
            crls: info.crls.clone(),
            digests: info.digests.clone(),
            ..X509DataInfo::default()
        };
        let mut matches = Vec::new();
        let mut trusted_prefix_len = 0usize;
        for (trusted, certificate_der) in self
            .config
            .trusted_certs
            .iter()
            .map(|certificate| (true, certificate))
            .chain(
                self.config
                    .lookup_certs
                    .iter()
                    .map(|certificate| (false, certificate)),
            )
        {
            if available
                .certificates
                .iter()
                .any(|available_der| available_der == certificate_der)
            {
                continue;
            }
            budget.charge()?;
            let parsed = parse_x509_certificate(certificate_der)
                .map_err(|_| KeyResolutionError::InvalidCertificate)?;
            let is_match =
                x509_certificate_matches_any_selector(info, &parsed, certificate_der, provider)
                    .map_err(map_x509_selector_error)?;
            if is_match {
                matches.push((available.certificates.len(), parsed.clone()));
            }
            available.certificates.push(certificate_der.clone());
            available.parsed_certificates.push(parsed);
            if trusted {
                trusted_prefix_len += 1;
            }
        }

        let matched_chain = X509DataInfo {
            certificates: matches
                .iter()
                .map(|(index, _)| available.certificates[*index].clone())
                .collect(),
            parsed_certificates: matches.iter().map(|(_, parsed)| parsed.clone()).collect(),
            ..X509DataInfo::default()
        };
        if !x509_selector_categories_match_chain(
            &X509DataInfo {
                subject_names: info.subject_names.clone(),
                issuer_serials: info.issuer_serials.clone(),
                skis: info.skis.clone(),
                digests: info.digests.clone(),
                ..matched_chain
            },
            provider,
        )
        .map_err(map_x509_selector_error)?
        {
            return Ok(None);
        }

        let signing_index = match matches.as_slice() {
            [] => return Ok(None),
            [(index, _)] => *index,
            _ => {
                let leaves = matches
                    .iter()
                    .filter(|(_, candidate)| {
                        !distinguished_names_equal(&candidate.subject_dn, &candidate.issuer_dn)
                            && !matches.iter().any(|(_, other)| {
                                distinguished_names_equal(&other.issuer_dn, &candidate.subject_dn)
                            })
                    })
                    .collect::<Vec<_>>();
                match leaves.as_slice() {
                    [(index, _)] => *index,
                    _ => return Err(KeyResolutionError::AmbiguousCertificate.into()),
                }
            }
        };
        let matching_indices = matches.iter().map(|(index, _)| *index).collect::<Vec<_>>();
        // `available` preserves trusted certificates as a prefix. Selecting
        // one of those exact certificates is already a terminal trust
        // decision, even when the certificate is not self-signed.
        available.certificate_chain =
            if signing_index < trusted_prefix_len || !trust.verify_x509_chains {
                vec![signing_index]
            } else {
                if !self.select_valid_x509_path(
                    &mut available,
                    signing_index,
                    trusted_prefix_len,
                    trust,
                    provider,
                    Some(info),
                )? {
                    return Ok(None);
                }
                available.certificate_chain.clone()
            };
        if trust.verify_x509_chains && signing_index < trusted_prefix_len {
            self.verify_x509_policy(&available, trust, provider)?;
        }
        if !trust.verify_x509_chains || signing_index < trusted_prefix_len {
            let direct_match = selected_x509_path_matches_selectors(&available, info, provider)?;
            if !direct_match
                && (signing_index < trusted_prefix_len
                    || !self.select_x509_selector_path(
                        &mut available,
                        signing_index,
                        &matching_indices,
                        trust,
                        provider,
                        info,
                    )?)
            {
                return Ok(None);
            }
        }
        Ok(Some(available))
    }

    fn resolve_key_value(
        key_value: &KeyValueInfo,
        algorithm: SignatureAlgorithm,
    ) -> Result<Option<VerificationKey>, KeyResolutionError> {
        let public_key_bytes = match key_value {
            KeyValueInfo::Dsa { p, q, g, y } => {
                if algorithm != SignatureAlgorithm::DsaSha1 {
                    return Err(KeyResolutionError::AlgorithmMismatch);
                }
                let (Some(p), Some(q), Some(g)) = (p.as_deref(), q.as_deref(), g.as_deref()) else {
                    return Err(KeyResolutionError::InvalidPublicKey);
                };
                dsa_key_value_to_spki_der(p, q, g, y)?
            }
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
                    SignatureAlgorithm::EcdsaSha256 | SignatureAlgorithm::EcdsaSha384
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

    fn resolve_with_trust<'a>(
        &'a self,
        key_info: Option<&KeyInfo>,
        algorithm: SignatureAlgorithm,
        sources: crate::policy::KeySourcePolicy,
        trust: &crate::policy::KeyTrustPolicy,
        resources: &crate::policy::ResourcePolicy,
        provider: &dyn crate::provider::CryptoProvider,
    ) -> Result<Option<Box<dyn VerifyingKey + 'a>>, DsigError> {
        trust.validate()?;
        resources.validate()?;
        let Some(key_info) = key_info else {
            return Ok(None);
        };
        let mut candidate_budget = KeyCandidateBudget::new(resources.max_key_candidates);
        let mut deferred_key_value_error = None;
        for source in &key_info.sources {
            let resolved = match source {
                KeyInfoSource::X509Data(info) => {
                    if !sources.x509_data {
                        return Err(crate::policy::PolicyViolation::KeyTrust {
                            reason: "X509Data key sources are disabled",
                        }
                        .into());
                    }
                    self.resolve_x509(info, algorithm, trust, provider, &mut candidate_budget)?
                }
                KeyInfoSource::DerEncodedKeyValue(public_key_bytes) => {
                    candidate_budget.charge()?;
                    if !sources.der_encoded_key_value {
                        return Err(crate::policy::PolicyViolation::KeyTrust {
                            reason: "DEREncodedKeyValue key sources are disabled",
                        }
                        .into());
                    }
                    validate_spki_algorithm(public_key_bytes, algorithm)?;
                    Some(VerificationKey {
                        algorithm,
                        public_key_bytes: public_key_bytes.clone(),
                        certificate_der: None,
                        name: None,
                    })
                }
                KeyInfoSource::KeyName(name) => {
                    candidate_budget.charge()?;
                    if !sources.key_name {
                        return Err(crate::policy::PolicyViolation::KeyTrust {
                            reason: "KeyName key sources are disabled",
                        }
                        .into());
                    }
                    self.config
                        .named_keys
                        .get(name)
                        .map(|key| {
                            if key.algorithm != algorithm {
                                return Err(KeyResolutionError::AlgorithmMismatch);
                            }
                            validate_spki_algorithm(&key.public_key_bytes, algorithm)?;
                            Ok(key.clone())
                        })
                        .transpose()?
                }
                KeyInfoSource::KeyValue(key_value) => {
                    candidate_budget.charge()?;
                    if !sources.key_value {
                        return Err(crate::policy::PolicyViolation::KeyTrust {
                            reason: "KeyValue key sources are disabled",
                        }
                        .into());
                    }
                    match Self::resolve_key_value(key_value, algorithm) {
                        Ok(resolved) => resolved,
                        Err(error) if key_value_error_allows_fallback(key_value, &error) => {
                            deferred_key_value_error.get_or_insert(error);
                            None
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
                KeyInfoSource::RetrievalMethod { .. } => {
                    candidate_budget.charge()?;
                    None
                }
            };
            if let Some(key) = resolved {
                return Ok(Some(Box::new(PolicyBoundVerificationKey {
                    key,
                    rsa_minimum_bits: trust.rsa_keys.minimum_modulus_bits,
                    dsa_minimum_bits: trust.dsa_keys.minimum_modulus_bits,
                })));
            }
        }
        if let Some(error) = deferred_key_value_error {
            return Err(error.into());
        }
        Ok(None)
    }
}

impl KeyResolver for DefaultKeyResolver {
    fn resolve<'a>(
        &'a self,
        key_info: Option<&KeyInfo>,
        algorithm: SignatureAlgorithm,
    ) -> Result<Option<Box<dyn VerifyingKey + 'a>>, DsigError> {
        let policy = crate::policy::VerificationPolicy::default();
        self.resolve_with_trust(
            key_info,
            algorithm,
            policy.key_sources,
            &policy.key_trust,
            &policy.resources,
            crate::provider::default_provider(),
        )
    }

    fn resolve_with_policy<'a>(
        &'a self,
        key_info: Option<&KeyInfo>,
        algorithm: SignatureAlgorithm,
        policy: &crate::policy::VerificationPolicy,
    ) -> Result<Option<Box<dyn VerifyingKey + 'a>>, DsigError> {
        self.resolve_with_policy_and_provider(
            key_info,
            algorithm,
            policy,
            crate::provider::default_provider(),
        )
    }

    fn resolve_with_policy_and_provider<'a>(
        &'a self,
        key_info: Option<&KeyInfo>,
        algorithm: SignatureAlgorithm,
        policy: &crate::policy::VerificationPolicy,
        provider: &dyn crate::provider::CryptoProvider,
    ) -> Result<Option<Box<dyn VerifyingKey + 'a>>, DsigError> {
        self.resolve_with_trust(
            key_info,
            algorithm,
            policy.key_sources,
            &policy.key_trust,
            &policy.resources,
            provider,
        )
    }

    fn consumes_document_key_info(&self) -> bool {
        true
    }
}

fn map_x509_selector_error(error: ParseError) -> DsigError {
    match error {
        ParseError::Provider(error) => DsigError::Provider(error),
        ParseError::UnsupportedAlgorithm { uri } => {
            KeyResolutionError::UnsupportedDigestAlgorithm(uri).into()
        }
        _ => KeyResolutionError::InvalidCertificate.into(),
    }
}

fn selected_x509_path_matches_selectors(
    available: &X509DataInfo,
    selectors: &X509DataInfo,
    provider: &dyn crate::provider::CryptoProvider,
) -> Result<bool, KeyResolutionError> {
    let selected = X509DataInfo {
        subject_names: selectors.subject_names.clone(),
        issuer_serials: selectors.issuer_serials.clone(),
        skis: selectors.skis.clone(),
        digests: selectors.digests.clone(),
        certificates: available
            .certificate_chain
            .iter()
            .map(|index| available.certificates[*index].clone())
            .collect(),
        parsed_certificates: available
            .certificate_chain
            .iter()
            .map(|index| available.parsed_certificates[*index].clone())
            .collect(),
        ..X509DataInfo::default()
    };
    x509_selector_categories_match_chain(&selected, provider).map_err(|error| match error {
        ParseError::Provider(error) => {
            KeyResolutionError::Chain(super::X509ChainError::Provider(error))
        }
        ParseError::UnsupportedAlgorithm { uri } => {
            KeyResolutionError::UnsupportedDigestAlgorithm(uri)
        }
        _ => KeyResolutionError::InvalidCertificate,
    })
}

fn rsa_key_value_to_spki_der(
    modulus: &[u8],
    exponent: &[u8],
) -> Result<Vec<u8>, KeyResolutionError> {
    let key = rsa::RsaPublicKey::new(
        BoxedUint::from_be_slice_vartime(modulus),
        BoxedUint::from_be_slice_vartime(exponent),
    )
    .map_err(|_| KeyResolutionError::InvalidPublicKey)?;
    key.to_public_key_der()
        .map_err(|_| KeyResolutionError::InvalidPublicKey)
        .map(|der| der.as_bytes().to_vec())
}

fn dsa_key_value_to_spki_der(
    p: &[u8],
    q: &[u8],
    g: &[u8],
    y: &[u8],
) -> Result<Vec<u8>, KeyResolutionError> {
    let components = dsa::Components::from_components(
        BoxedUint::from_be_slice_vartime(p),
        BoxedUint::from_be_slice_vartime(q),
        BoxedUint::from_be_slice_vartime(g),
    )
    .map_err(|_| KeyResolutionError::InvalidPublicKey)?;
    dsa::VerifyingKey::from_components(components, BoxedUint::from_be_slice_vartime(y))
        .map_err(|_| KeyResolutionError::InvalidPublicKey)?
        .to_public_key_der()
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

fn key_value_error_allows_fallback(key_value: &KeyValueInfo, error: &KeyResolutionError) -> bool {
    matches!(
        key_value,
        KeyValueInfo::Dsa { .. } | KeyValueInfo::Ec { .. } | KeyValueInfo::InvalidEcKeyValue
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
        (SignatureAlgorithm::DsaSha1, PublicKey::DSA(_)) => {
            let _ = dsa::VerifyingKey::from_public_key_der(public_key_bytes)
                .map_err(|_| KeyResolutionError::AlgorithmMismatch)?;
            Ok(())
        }
        (
            SignatureAlgorithm::RsaSha1
            | SignatureAlgorithm::RsaSha256
            | SignatureAlgorithm::RsaSha384
            | SignatureAlgorithm::RsaSha512,
            PublicKey::RSA(_),
        ) => Ok(()),
        (SignatureAlgorithm::EcdsaSha256 | SignatureAlgorithm::EcdsaSha384, PublicKey::EC(_))
            if matches!(
                curve_oid.as_deref(),
                Some("1.2.840.10045.3.1.7" | "1.3.132.0.34" | "1.3.132.0.35")
            ) =>
        {
            Ok(())
        }
        _ => Err(KeyResolutionError::AlgorithmMismatch),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use base64::{Engine, engine::general_purpose::STANDARD};
    use rsa::{pkcs8::DecodePublicKey, traits::PublicKeyParts};

    use super::*;

    struct RejectSecondSha512Provider {
        sha512_calls: AtomicUsize,
        verification_calls: AtomicUsize,
        reject_verification_call: Option<usize>,
        rejected_verification_data: Option<Vec<u8>>,
    }

    impl crate::provider::CryptoProvider for RejectSecondSha512Provider {
        fn name(&self) -> &'static str {
            "reject-second-sha512"
        }

        fn supports(&self, capability: crate::provider::ProviderCapability<'_>) -> bool {
            crate::provider::default_provider().supports(capability)
        }

        fn fill_random(&self, output: &mut [u8]) -> Result<(), crate::provider::ProviderError> {
            crate::provider::default_provider().fill_random(output)
        }

        fn derive_key(
            &self,
            parameters: &crate::provider::KdfParameters<'_>,
            secret: &[u8],
        ) -> Result<Vec<u8>, crate::provider::ProviderError> {
            crate::provider::default_provider().derive_key(parameters, secret)
        }

        fn digest(
            &self,
            algorithm: super::super::DigestAlgorithm,
            data: &[u8],
        ) -> Result<Vec<u8>, crate::provider::ProviderError> {
            if algorithm == super::super::DigestAlgorithm::Sha512
                && self.sha512_calls.fetch_add(1, Ordering::Relaxed) > 0
            {
                return Err(crate::provider::ProviderError::Unsupported {
                    operation: crate::provider::ProviderOperation::Digest,
                    algorithm: Some(algorithm.uri().to_owned()),
                });
            }
            crate::provider::default_provider().digest(algorithm, data)
        }

        fn sign(
            &self,
            key: &dyn super::super::SigningKey,
            algorithm: SignatureAlgorithm,
            data: &[u8],
        ) -> Result<Vec<u8>, super::super::SigningKeyError> {
            crate::provider::default_provider().sign(key, algorithm, data)
        }

        fn verify(
            &self,
            key: &dyn VerifyingKey,
            algorithm: SignatureAlgorithm,
            data: &[u8],
            signature: &[u8],
        ) -> Result<bool, DsigError> {
            let call = self.verification_calls.fetch_add(1, Ordering::Relaxed);
            if self.reject_verification_call == Some(call)
                || self
                    .rejected_verification_data
                    .as_deref()
                    .is_some_and(|rejected| rejected == data)
            {
                return Err(crate::provider::ProviderError::Unsupported {
                    operation: crate::provider::ProviderOperation::Verify,
                    algorithm: Some(algorithm.uri().to_owned()),
                }
                .into());
            }
            crate::provider::default_provider().verify(key, algorithm, data, signature)
        }

        fn verify_x509_signature(
            &self,
            algorithm: crate::provider::X509SignatureAlgorithm,
            data: &[u8],
            signature: &[u8],
            issuer_spki_der: &[u8],
        ) -> Result<bool, crate::provider::ProviderError> {
            let call = self.verification_calls.fetch_add(1, Ordering::Relaxed);
            if self.reject_verification_call == Some(call)
                || self
                    .rejected_verification_data
                    .as_deref()
                    .is_some_and(|rejected| rejected == data)
            {
                return Err(crate::provider::ProviderError::Unsupported {
                    operation: crate::provider::ProviderOperation::VerifyCertificate,
                    algorithm: Some(algorithm.oid().to_owned()),
                });
            }
            crate::provider::default_provider().verify_x509_signature(
                algorithm,
                data,
                signature,
                issuer_spki_der,
            )
        }

        #[cfg(feature = "xmlenc")]
        fn encrypt_data(
            &self,
            algorithm: crate::xmlenc::DataEncryptionAlgorithm,
            key: &[u8],
            plaintext: &[u8],
        ) -> Result<Vec<u8>, crate::provider::ProviderError> {
            crate::provider::default_provider().encrypt_data(algorithm, key, plaintext)
        }

        #[cfg(feature = "xmlenc")]
        fn decrypt_data(
            &self,
            algorithm: crate::xmlenc::DataEncryptionAlgorithm,
            key: &[u8],
            ciphertext: &[u8],
        ) -> Result<Vec<u8>, crate::provider::ProviderError> {
            crate::provider::default_provider().decrypt_data(algorithm, key, ciphertext)
        }

        #[cfg(feature = "xmlenc")]
        fn wrap_key(
            &self,
            algorithm: crate::xmlenc::KeyWrapAlgorithm,
            kek: &[u8],
            key: &[u8],
        ) -> Result<Vec<u8>, crate::provider::ProviderError> {
            crate::provider::default_provider().wrap_key(algorithm, kek, key)
        }

        #[cfg(feature = "xmlenc")]
        fn unwrap_key(
            &self,
            algorithm: crate::xmlenc::KeyWrapAlgorithm,
            kek: &[u8],
            wrapped: &[u8],
        ) -> Result<Vec<u8>, crate::provider::ProviderError> {
            crate::provider::default_provider().unwrap_key(algorithm, kek, wrapped)
        }

        #[cfg(feature = "xmlenc")]
        fn transport_key(
            &self,
            key: &dyn crate::provider::KeyTransportKey,
            parameters: &crate::xmlenc::RsaOaepParameters,
            plaintext: &[u8],
        ) -> Result<Vec<u8>, crate::provider::ProviderError> {
            crate::provider::default_provider().transport_key(key, parameters, plaintext)
        }

        #[cfg(feature = "xmlenc")]
        fn recover_key(
            &self,
            key: &dyn crate::provider::KeyRecoveryKey,
            parameters: &crate::xmlenc::RsaOaepParameters,
            ciphertext: &[u8],
        ) -> Result<Vec<u8>, crate::provider::ProviderError> {
            crate::provider::default_provider().recover_key(key, parameters, ciphertext)
        }
    }

    fn chain_policy() -> crate::policy::KeyTrustPolicy {
        crate::policy::KeyTrustPolicy {
            verify_x509_chains: true,
            ..crate::policy::KeyTrustPolicy::default()
        }
    }

    fn chain_policy_at(verification_time: SystemTime) -> crate::policy::KeyTrustPolicy {
        crate::policy::KeyTrustPolicy {
            verification_time: Some(verification_time),
            ..chain_policy()
        }
    }

    fn verification_policy_with_trust(
        key_trust: crate::policy::KeyTrustPolicy,
    ) -> crate::policy::VerificationPolicy {
        crate::policy::VerificationPolicy {
            key_trust,
            ..crate::policy::VerificationPolicy::default()
        }
    }

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
    const X509_DIGEST_SHA256_SIGNATURE: &str = include_str!(
        "../../tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloped-x509-digest-sha256.xml"
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

    fn rsa_key_value_parts(public_key: &rsa::RsaPublicKey) -> (String, String) {
        (
            STANDARD.encode(public_key.n().to_be_bytes_trimmed_vartime()),
            STANDARD.encode(public_key.e().to_be_bytes_trimmed_vartime()),
        )
    }

    fn x509_signature_with_leaf_subject() -> String {
        replace_unprefixed_key_info(
            X509_DIGEST_SIGNATURE,
            "<KeyInfo><X509Data><X509SubjectName>CN=Test Key rsa-4096,O=XML Security Library (http://www.aleksey.com/xmlsec),ST=California,C=US</X509SubjectName></X509Data></KeyInfo>",
        )
    }

    fn fixture_certificate_time() -> SystemTime {
        // 2027-01-15 UTC, inside the donor certificates' 2026-2126 validity window.
        SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_800_000_000)
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

    fn crl_der(pem_text: &str) -> Vec<u8> {
        let (rest, pem) =
            x509_parser::pem::parse_x509_pem(pem_text.as_bytes()).expect("fixture CRL is PEM");
        assert!(rest.iter().all(|byte| byte.is_ascii_whitespace()));
        assert_eq!(pem.label, "X509 CRL");
        pem.contents
    }

    fn generated_certificate_params(common_name: &str, is_ca: bool) -> rcgen::CertificateParams {
        let mut params = rcgen::CertificateParams::new(Vec::new())
            .expect("empty SAN list should produce valid certificate parameters");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, common_name);
        if is_ca {
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        }
        params
    }

    fn x509_info(certificates: Vec<Vec<u8>>, signing_index: usize) -> X509DataInfo {
        let parsed_certificates = certificates
            .iter()
            .map(|certificate| {
                parse_x509_certificate(certificate)
                    .expect("generated certificate should have supported metadata")
            })
            .collect();
        X509DataInfo {
            certificates,
            parsed_certificates,
            certificate_chain: vec![signing_index],
            ..X509DataInfo::default()
        }
    }

    #[test]
    fn defaults_match_key_resolution_policy() {
        // Defaults must remain compatible with xmlsec1's depth and opt-in trust policy.
        let config = KeyResolverConfig::default();

        assert!(config.trusted_certs.is_empty());
        assert!(config.lookup_certs.is_empty());
        assert!(config.named_keys.is_empty());
        let trust = crate::policy::VerificationPolicy::default().key_trust;
        assert!(!trust.verify_x509_chains);
        assert!(!trust.check_crls);
        assert_eq!(trust.verification_time, None);
        assert_eq!(trust.max_x509_chain_depth, 9);
    }

    #[test]
    fn verification_policy_controls_leaf_extended_key_usage() {
        // The immutable operation snapshot must reach certificate-path
        // validation; resolver-local trust defaults cannot bypass EKU policy.
        let root = rcgen::CertifiedIssuer::self_signed(
            generated_certificate_params("EKU policy root", true),
            rcgen::KeyPair::generate().expect("root key generation should succeed"),
        )
        .expect("root should be self-signable");
        let mut leaf_params = generated_certificate_params("TLS-only XML signer", false);
        leaf_params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        leaf_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = leaf_params
            .signed_by(
                &rcgen::KeyPair::generate().expect("leaf key generation should succeed"),
                &root,
            )
            .expect("root should sign leaf certificate");
        let key_info = KeyInfo {
            sources: vec![KeyInfoSource::X509Data(x509_info(
                vec![leaf.der().to_vec(), root.der().to_vec()],
                0,
            ))],
        };
        let resolver = DefaultKeyResolver::new(KeyResolverConfig {
            trusted_certs: vec![root.der().to_vec()],
            ..KeyResolverConfig::default()
        });
        let mut policy = crate::policy::VerificationPolicy::default();
        policy.key_trust.verify_x509_chains = true;

        let error = match resolver.resolve_with_policy(
            Some(&key_info),
            SignatureAlgorithm::EcdsaSha256,
            &policy,
        ) {
            Ok(_) => panic!("unapproved restricted EKU must be rejected"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            DsigError::KeyResolution(KeyResolutionError::Chain(
                super::super::X509ChainError::InvalidKeyUsage {
                    position: 0,
                    required: "an approved extended key usage",
                }
            ))
        ));

        policy.key_trust.allowed_extended_key_usages =
            std::collections::HashSet::from([crate::policy::ExtendedKeyPurpose::ServerAuth]);
        assert!(
            resolver
                .resolve_with_policy(Some(&key_info), SignatureAlgorithm::EcdsaSha256, &policy,)
                .expect("approved restricted EKU must pass path validation")
                .is_some()
        );
    }

    #[test]
    fn operation_policy_rejects_zero_x509_resource_limits() {
        // X.509 work limits belong to the immutable operation snapshot and are
        // rejected before resolver-owned certificate material is inspected.
        for trust in [
            crate::policy::KeyTrustPolicy {
                verify_x509_chains: true,
                max_x509_chain_depth: 0,
                ..crate::policy::KeyTrustPolicy::default()
            },
            crate::policy::KeyTrustPolicy {
                verify_x509_chains: true,
                max_x509_candidate_paths: 0,
                ..crate::policy::KeyTrustPolicy::default()
            },
        ] {
            let certificate = certificate_der(RSA_4096_CERTIFICATE);
            let resolver = DefaultKeyResolver::new(KeyResolverConfig {
                trusted_certs: vec![certificate],
                ..KeyResolverConfig::default()
            });
            let policy = crate::policy::VerificationPolicy {
                key_trust: trust,
                ..crate::policy::VerificationPolicy::default()
            };
            let error = super::super::VerifyContext::new()
                .policy(policy)
                .key_resolver(&resolver)
                .verify(&x509_signature_with_leaf_subject())
                .expect_err("zero composed X.509 limits must fail as policy errors");

            assert!(matches!(
                error,
                DsigError::Policy(crate::policy::PolicyViolation::InvalidResourceLimit {
                    requirement: "limit must be nonzero",
                    actual: 0,
                    ..
                })
            ));
        }
    }

    #[test]
    fn operation_policy_rejects_crl_checking_without_chain_validation() {
        // CRL authentication is part of path validation. A resolver must not
        // accept a configuration that would silently skip the requested check.
        let resolver = DefaultKeyResolver::new(KeyResolverConfig {
            lookup_certs: vec![certificate_der(RSA_4096_CERTIFICATE)],
            ..KeyResolverConfig::default()
        });
        let policy = crate::policy::VerificationPolicy {
            key_trust: crate::policy::KeyTrustPolicy {
                check_crls: true,
                ..crate::policy::KeyTrustPolicy::default()
            },
            ..crate::policy::VerificationPolicy::default()
        };
        let error = super::super::VerifyContext::new()
            .policy(policy)
            .key_resolver(&resolver)
            .verify(&x509_signature_with_leaf_subject())
            .expect_err("CRL-only trust policy must fail before certificate use");

        assert!(matches!(
            error,
            DsigError::Policy(crate::policy::PolicyViolation::KeyTrust {
                reason: "CRL checking requires X.509 chain validation"
            })
        ));
    }

    #[test]
    fn hmac_key_rejects_empty_secret_and_wrong_algorithm() {
        // HMAC secrets are caller-owned and cannot be reused as asymmetric keys.
        assert!(matches!(
            HmacSha1VerificationKey::new(Vec::new()),
            Err(KeyResolutionError::InvalidPublicKey)
        ));
        let key = HmacSha1VerificationKey::new(b"secret".to_vec())
            .expect("non-empty HMAC secret must be accepted");
        assert!(matches!(
            key.verify(SignatureAlgorithm::RsaSha256, b"data", b"signature"),
            Err(DsigError::KeyResolution(
                KeyResolutionError::AlgorithmMismatch
            ))
        ));
    }

    #[test]
    fn hmac_key_enforces_its_bound_output_length() {
        let full = HmacSha1VerificationKey::new(b"secret".to_vec())
            .expect("the fixture HMAC secret is non-empty");
        let truncated = HmacSha1VerificationKey::new(b"secret".to_vec())
            .expect("the fixture HMAC secret is non-empty")
            .with_output_length_bits(80)
            .expect("80 bits is a valid HMAC-SHA1 output length");
        let mut mac = hmac::Hmac::<sha1::Sha1>::new_from_slice(b"secret")
            .expect("HMAC accepts an arbitrary non-empty secret");
        mac.update(b"data");
        let expected = mac.finalize().into_bytes();

        assert!(
            !full
                .verify(SignatureAlgorithm::HmacSha1, b"data", &expected[..10])
                .expect("the key and algorithm match")
        );
        assert!(
            truncated
                .verify(SignatureAlgorithm::HmacSha1, b"data", &expected[..10])
                .expect("the key and algorithm match")
        );
        assert!(matches!(
            HmacSha1VerificationKey::new(b"secret".to_vec())
                .expect("the fixture HMAC secret is non-empty")
                .with_output_length_bits(79),
            Err(KeyResolutionError::InvalidHmacOutputLength)
        ));
        assert!(matches!(
            HmacSha1VerificationKey::new(b"secret".to_vec())
                .expect("the fixture HMAC secret is non-empty")
                .with_output_length_bits(81),
            Err(KeyResolutionError::InvalidHmacOutputLength)
        ));
    }

    #[test]
    fn hmac_key_debug_redacts_secret_material() {
        // Debug output may expose public verification parameters, never caller secrets.
        let secret = b"unique-debug-secret-marker";
        let key = HmacSha1VerificationKey::new(secret.to_vec())
            .expect("the fixture HMAC secret is non-empty")
            .with_output_length_bits(80)
            .expect("80 bits is a valid HMAC-SHA1 output length");

        let debug = format!("{key:?}");
        assert!(
            !debug
                .contains(std::str::from_utf8(secret).expect("the debug marker is literal ASCII"))
        );
        assert!(!debug.contains(&format!("{secret:?}")));
        assert!(debug.contains("output_length_bits"));
        assert!(debug.contains("80"));
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
        let leaf_certificate_der = certificate_der(RSA_4096_CERTIFICATE);
        let resolver = DefaultKeyResolver::new(KeyResolverConfig {
            lookup_certs: vec![leaf_certificate_der],
            trusted_certs: vec![
                certificate_der(include_str!("../../tests/fixtures/keys/ca2cert.pem")),
                certificate_der(include_str!("../../tests/fixtures/keys/cacert.pem")),
            ],
            ..KeyResolverConfig::default()
        });
        for signature in [X509_DIGEST_SHA256_SIGNATURE, X509_DIGEST_SIGNATURE] {
            let result = super::super::VerifyContext::new()
                .key_resolver(&resolver)
                .verify(signature)
                .expect("X509Digest should resolve a configured certificate");

            assert_eq!(result.status, super::super::DsigStatus::Valid);
        }
    }

    #[test]
    fn selector_resolved_certificate_obeys_chain_policy() {
        // Enabling chain verification must apply validity policy even when
        // X509Data contains only selectors and the matching cert is configured.
        let leaf_certificate_der = certificate_der(RSA_4096_CERTIFICATE);
        let resolver = DefaultKeyResolver::new(KeyResolverConfig {
            lookup_certs: vec![leaf_certificate_der],
            trusted_certs: vec![
                certificate_der(include_str!("../../tests/fixtures/keys/ca2cert.pem")),
                certificate_der(include_str!("../../tests/fixtures/keys/cacert.pem")),
            ],
            ..KeyResolverConfig::default()
        });
        let error = super::super::VerifyContext::new()
            .policy(verification_policy_with_trust(chain_policy_at(
                SystemTime::UNIX_EPOCH,
            )))
            .key_resolver(&resolver)
            .verify(&x509_signature_with_leaf_subject())
            .expect_err("selector-resolved certificate must satisfy chain policy");

        assert!(
            matches!(
                &error,
                DsigError::KeyResolution(KeyResolutionError::Chain(
                    super::super::X509ChainError::CertificateNotValid(_)
                ))
            ),
            "unexpected selector policy error: {error:?}"
        );
    }

    #[test]
    fn selector_resolved_configured_root_remains_a_trust_anchor() {
        // A certificate explicitly configured in trusted_certs remains an
        // anchor when X509Data selects it by subject instead of embedding it.
        let mut params = rcgen::CertificateParams::new(Vec::new())
            .expect("empty SAN list should produce valid certificate parameters");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "configured root");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key_pair = rcgen::KeyPair::generate().expect("test key generation should succeed");
        let certificate = params
            .self_signed(&key_pair)
            .expect("test root should be self-signable");
        let certificate_der = certificate.der().to_vec();
        let key_info_xml = concat!(
            "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">",
            "<X509Data><X509SubjectName>CN=configured root</X509SubjectName></X509Data>",
            "</KeyInfo>"
        );
        let document = roxmltree::Document::parse(key_info_xml)
            .expect("static selector KeyInfo should parse as XML");
        let key_info = super::super::parse_key_info(document.root_element())
            .expect("static selector KeyInfo should satisfy XMLDSig structure");
        let resolver = DefaultKeyResolver::new(KeyResolverConfig {
            trusted_certs: vec![certificate_der],
            ..KeyResolverConfig::default()
        });

        let resolved = resolver
            .resolve_with_policy(
                Some(&key_info),
                SignatureAlgorithm::EcdsaSha256,
                &verification_policy_with_trust(chain_policy()),
            )
            .expect("configured self-signed certificate should validate as its own anchor");

        assert!(resolved.is_some());
    }

    #[test]
    fn selector_resolved_non_self_signed_trust_anchor_terminates_the_path() {
        // Trust is assigned to the exact configured certificate, not inferred
        // from self-signing. A lookup-only issuer must not extend that anchor
        // into a new path that requires another trust decision.
        let mut issuer_params = rcgen::CertificateParams::new(Vec::new())
            .expect("empty issuer SAN list should be valid");
        issuer_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "lookup-only issuer");
        issuer_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        issuer_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let issuer = rcgen::CertifiedIssuer::self_signed(
            issuer_params,
            rcgen::KeyPair::generate().expect("issuer key generation should succeed"),
        )
        .expect("issuer certificate should be self-signable");

        let mut anchor_params = rcgen::CertificateParams::new(Vec::new())
            .expect("empty anchor SAN list should be valid");
        anchor_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "direct trust anchor");
        let anchor = anchor_params
            .signed_by(
                &rcgen::KeyPair::generate().expect("anchor key generation should succeed"),
                &issuer,
            )
            .expect("issuer should sign the directly trusted certificate");
        let key_info_xml = concat!(
            "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">",
            "<X509Data><X509SubjectName>CN=direct trust anchor</X509SubjectName></X509Data>",
            "</KeyInfo>"
        );
        let document = roxmltree::Document::parse(key_info_xml)
            .expect("static selector KeyInfo should parse as XML");
        let key_info = super::super::parse_key_info(document.root_element())
            .expect("static selector KeyInfo should satisfy XMLDSig structure");
        let resolver = DefaultKeyResolver::new(KeyResolverConfig {
            trusted_certs: vec![anchor.der().to_vec()],
            lookup_certs: vec![issuer.der().to_vec()],
            ..KeyResolverConfig::default()
        });

        let resolved = resolver
            .resolve_with_policy(
                Some(&key_info),
                SignatureAlgorithm::EcdsaSha256,
                &verification_policy_with_trust(chain_policy()),
            )
            .expect("an explicitly trusted selected certificate must terminate its path");

        assert!(resolved.is_some());
    }

    #[test]
    fn selector_resolved_leaf_stops_at_non_self_signed_trust_anchor() {
        // A configured anchor terminates trust even when a lookup certificate
        // could continue the issuer-name chain beyond it.
        let external_issuer = rcgen::CertifiedIssuer::self_signed(
            generated_certificate_params("external issuer", true),
            rcgen::KeyPair::generate().expect("external issuer key generation should succeed"),
        )
        .expect("external issuer should be self-signable");
        let anchor = rcgen::CertifiedIssuer::signed_by(
            generated_certificate_params("non-self-signed anchor", true),
            rcgen::KeyPair::generate().expect("anchor key generation should succeed"),
            &external_issuer,
        )
        .expect("external issuer should sign the anchor");
        let leaf = generated_certificate_params("anchor leaf", false)
            .signed_by(
                &rcgen::KeyPair::generate().expect("leaf key generation should succeed"),
                &anchor,
            )
            .expect("anchor should sign the leaf");
        let leaf_metadata = parse_x509_certificate(leaf.der())
            .expect("generated leaf should have supported metadata");
        let key_info = KeyInfo {
            sources: vec![KeyInfoSource::X509Data(X509DataInfo {
                subject_names: vec![leaf_metadata.subject_dn],
                ..X509DataInfo::default()
            })],
        };
        let resolver = DefaultKeyResolver::new(KeyResolverConfig {
            trusted_certs: vec![anchor.der().to_vec()],
            lookup_certs: vec![leaf.der().to_vec(), external_issuer.der().to_vec()],
            ..KeyResolverConfig::default()
        });

        let resolved = resolver
            .resolve_with_policy(
                Some(&key_info),
                SignatureAlgorithm::EcdsaSha256,
                &verification_policy_with_trust(chain_policy()),
            )
            .expect("path construction must stop at the configured anchor");

        assert!(resolved.is_some());
    }

    #[test]
    fn selector_resolved_leaf_does_not_anchor_itself() {
        // A certificate available for selector lookup is not automatically a
        // trust anchor; chain verification still requires a separate issuer.
        let certificate_der = certificate_der(RSA_4096_CERTIFICATE);
        let resolver = DefaultKeyResolver::new(KeyResolverConfig {
            lookup_certs: vec![certificate_der],
            ..KeyResolverConfig::default()
        });
        let error = super::super::VerifyContext::new()
            .policy(verification_policy_with_trust(chain_policy_at(
                fixture_certificate_time(),
            )))
            .key_resolver(&resolver)
            .verify(&x509_signature_with_leaf_subject())
            .expect_err("selector-resolved leaf must not trust itself");

        assert!(matches!(
            error,
            DsigError::KeyResolution(KeyResolutionError::Chain(
                super::super::X509ChainError::UntrustedRoot
            ))
        ));
    }

    #[test]
    fn selector_resolved_leaf_uses_separate_anchor() {
        // Selector lookup may use the leaf from the configured set, but chain
        // verification must terminate at a different configured certificate.
        let leaf = certificate_der(RSA_4096_CERTIFICATE);
        let issuer = certificate_der(include_str!("../../tests/fixtures/keys/ca2cert.pem"));
        let resolver = DefaultKeyResolver::new(KeyResolverConfig {
            lookup_certs: vec![leaf],
            trusted_certs: vec![issuer],
            ..KeyResolverConfig::default()
        });
        let result = super::super::VerifyContext::new()
            .policy(verification_policy_with_trust(chain_policy_at(
                fixture_certificate_time(),
            )))
            .key_resolver(&resolver)
            .verify(&x509_signature_with_leaf_subject())
            .expect("selector-resolved leaf should chain to its configured issuer");

        assert_eq!(result.status, super::super::DsigStatus::Valid);
    }

    #[test]
    fn selector_resolved_leaf_uses_lookup_intermediate() {
        // Lookup certificates may complete an untrusted path, but only the
        // separately configured root is allowed to establish trust.
        let mut root_params =
            rcgen::CertificateParams::new(Vec::new()).expect("empty root SAN list should be valid");
        root_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "lookup root");
        root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        root_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let root = rcgen::CertifiedIssuer::self_signed(
            root_params,
            rcgen::KeyPair::generate().expect("root key generation should succeed"),
        )
        .expect("root certificate should be self-signable");

        let mut intermediate_params = rcgen::CertificateParams::new(Vec::new())
            .expect("empty intermediate SAN list should be valid");
        intermediate_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "lookup intermediate");
        intermediate_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        intermediate_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let intermediate = rcgen::CertifiedIssuer::signed_by(
            intermediate_params,
            rcgen::KeyPair::generate().expect("intermediate key generation should succeed"),
            &root,
        )
        .expect("root should sign the intermediate certificate");

        let mut leaf_params =
            rcgen::CertificateParams::new(Vec::new()).expect("empty leaf SAN list should be valid");
        leaf_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "lookup leaf");
        let leaf = leaf_params
            .signed_by(
                &rcgen::KeyPair::generate().expect("leaf key generation should succeed"),
                &intermediate,
            )
            .expect("intermediate should sign the leaf certificate");
        let key_info_xml = concat!(
            "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">",
            "<X509Data><X509SubjectName>CN=lookup leaf</X509SubjectName></X509Data>",
            "</KeyInfo>"
        );
        let document = roxmltree::Document::parse(key_info_xml)
            .expect("static selector KeyInfo should parse as XML");
        let key_info = super::super::parse_key_info(document.root_element())
            .expect("static selector KeyInfo should satisfy XMLDSig structure");
        let resolver = DefaultKeyResolver::new(KeyResolverConfig {
            lookup_certs: vec![leaf.der().to_vec(), intermediate.der().to_vec()],
            trusted_certs: vec![root.der().to_vec()],
            ..KeyResolverConfig::default()
        });

        let resolved = resolver
            .resolve_with_policy(
                Some(&key_info),
                SignatureAlgorithm::EcdsaSha256,
                &verification_policy_with_trust(chain_policy()),
            )
            .expect("selector-resolved leaf should chain through the lookup intermediate");

        assert!(resolved.is_some());
    }

    #[test]
    fn x509_path_signatures_use_the_operation_provider() {
        // Embedded and selector-resolved certificates converge on the same
        // path validator. Neither source may fall back to a crate-global
        // verifier when the operation provider rejects certificate signatures.
        let root = rcgen::CertifiedIssuer::self_signed(
            generated_certificate_params("provider root", true),
            rcgen::KeyPair::generate().expect("root key generation should succeed"),
        )
        .expect("root should be self-signable");
        let leaf = generated_certificate_params("provider leaf", false)
            .signed_by(
                &rcgen::KeyPair::generate().expect("leaf key generation should succeed"),
                &root,
            )
            .expect("root should sign the leaf");
        let leaf_der = leaf.der().to_vec();
        let leaf_metadata =
            parse_x509_certificate(&leaf_der).expect("generated leaf metadata should parse");
        let policy = crate::policy::VerificationPolicy {
            key_trust: chain_policy(),
            ..crate::policy::VerificationPolicy::default()
        };

        let cases = [
            (
                KeyInfo {
                    sources: vec![KeyInfoSource::X509Data(x509_info(
                        vec![leaf_der.clone()],
                        0,
                    ))],
                },
                Vec::new(),
            ),
            (
                KeyInfo {
                    sources: vec![KeyInfoSource::X509Data(X509DataInfo {
                        subject_names: vec![leaf_metadata.subject_dn],
                        ..X509DataInfo::default()
                    })],
                },
                vec![leaf_der],
            ),
        ];

        for (key_info, lookup_certs) in cases {
            let provider = RejectSecondSha512Provider {
                sha512_calls: AtomicUsize::new(0),
                verification_calls: AtomicUsize::new(0),
                reject_verification_call: Some(0),
                rejected_verification_data: None,
            };
            let resolver = DefaultKeyResolver::new(KeyResolverConfig {
                trusted_certs: vec![root.der().to_vec()],
                lookup_certs,
                ..KeyResolverConfig::default()
            });
            let error = match resolver.resolve_with_policy_and_provider(
                Some(&key_info),
                SignatureAlgorithm::EcdsaSha256,
                &policy,
                &provider,
            ) {
                Ok(_) => panic!("the operation provider must gate every X.509 path signature"),
                Err(error) => error,
            };

            assert!(matches!(
                error,
                DsigError::KeyResolution(KeyResolutionError::Chain(
                    super::super::X509ChainError::UnsupportedSignatureAlgorithm { ref oid }
                )) if oid == "1.2.840.10045.4.3.2"
            ));
            assert_eq!(provider.verification_calls.load(Ordering::Relaxed), 1);
        }

        // A provider rejection after path construction proves complete-path
        // validation does not switch back to the crate-global provider.
        let provider = RejectSecondSha512Provider {
            sha512_calls: AtomicUsize::new(0),
            verification_calls: AtomicUsize::new(0),
            reject_verification_call: Some(1),
            rejected_verification_data: None,
        };
        let resolver = DefaultKeyResolver::new(KeyResolverConfig {
            trusted_certs: vec![root.der().to_vec()],
            ..KeyResolverConfig::default()
        });
        let key_info = KeyInfo {
            sources: vec![KeyInfoSource::X509Data(x509_info(
                vec![leaf.der().to_vec()],
                0,
            ))],
        };
        let error = match resolver.resolve_with_policy_and_provider(
            Some(&key_info),
            SignatureAlgorithm::EcdsaSha256,
            &policy,
            &provider,
        ) {
            Ok(_) => panic!("complete-path validation must retain the operation provider"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            DsigError::KeyResolution(KeyResolutionError::Chain(
                super::super::X509ChainError::Provider(_)
            ))
        ));
        assert_eq!(provider.verification_calls.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn embedded_leaf_uses_lookup_intermediate_with_duplicate_anchor() {
        // Deduplicating repeated trust anchors must not shift an untrusted
        // lookup intermediate into the trusted prefix used by path building.
        let trusted_root = rcgen::CertifiedIssuer::self_signed(
            generated_certificate_params("unrelated trusted root", true),
            rcgen::KeyPair::generate().expect("root key generation should succeed"),
        )
        .expect("root should be self-signable");
        let issuer_root = rcgen::CertifiedIssuer::self_signed(
            generated_certificate_params("untrusted issuer root", true),
            rcgen::KeyPair::generate().expect("issuer root key generation should succeed"),
        )
        .expect("issuer root should be self-signable");
        let intermediate = rcgen::CertifiedIssuer::signed_by(
            generated_certificate_params("embedded intermediate", true),
            rcgen::KeyPair::generate().expect("intermediate key generation should succeed"),
            &issuer_root,
        )
        .expect("issuer root should sign the intermediate");
        let leaf = generated_certificate_params("embedded leaf", false)
            .signed_by(
                &rcgen::KeyPair::generate().expect("leaf key generation should succeed"),
                &intermediate,
            )
            .expect("intermediate should sign the leaf");
        let key_info = KeyInfo {
            sources: vec![KeyInfoSource::X509Data(x509_info(
                vec![leaf.der().to_vec()],
                0,
            ))],
        };
        let resolver = DefaultKeyResolver::new(KeyResolverConfig {
            lookup_certs: vec![intermediate.der().to_vec()],
            trusted_certs: vec![trusted_root.der().to_vec(), trusted_root.der().to_vec()],
            ..KeyResolverConfig::default()
        });

        let policy = verification_policy_with_trust(chain_policy());
        let error = match resolver.resolve_with_policy(
            Some(&key_info),
            SignatureAlgorithm::EcdsaSha256,
            &policy,
        ) {
            Ok(_) => panic!("an untrusted lookup intermediate must not become a trust anchor"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            DsigError::KeyResolution(KeyResolutionError::Chain(
                super::super::X509ChainError::UntrustedRoot
            ))
        ));
    }

    #[test]
    fn selector_resolved_leaf_chooses_unique_valid_same_key_path() {
        // Cross-signing can produce issuer certificates with the same subject
        // and public key. Trust policy, not the immediate signature edge, must
        // select the sole path that reaches a configured anchor.
        let trusted_root = rcgen::CertifiedIssuer::self_signed(
            generated_certificate_params("trusted cross-sign root", true),
            rcgen::KeyPair::generate().expect("trusted root key generation should succeed"),
        )
        .expect("trusted root should be self-signable");
        let untrusted_root = rcgen::CertifiedIssuer::self_signed(
            generated_certificate_params("untrusted cross-sign root", true),
            rcgen::KeyPair::generate().expect("untrusted root key generation should succeed"),
        )
        .expect("untrusted root should be self-signable");
        let shared_params = generated_certificate_params("shared cross-sign issuer", true);
        let shared_key =
            rcgen::KeyPair::generate().expect("shared issuer key generation should succeed");
        let trusted_intermediate = shared_params
            .signed_by(&shared_key, &trusted_root)
            .expect("trusted root should cross-sign the shared issuer key");
        let untrusted_intermediate = shared_params
            .signed_by(&shared_key, &untrusted_root)
            .expect("untrusted root should cross-sign the shared issuer key");
        let shared_issuer = rcgen::Issuer::from_params(&shared_params, &shared_key);
        let leaf = generated_certificate_params("cross-signed leaf", false)
            .signed_by(
                &rcgen::KeyPair::generate().expect("leaf key generation should succeed"),
                &shared_issuer,
            )
            .expect("shared issuer key should sign the leaf");
        let leaf_metadata = parse_x509_certificate(leaf.der())
            .expect("generated leaf should have supported metadata");
        let key_info = KeyInfo {
            sources: vec![KeyInfoSource::X509Data(X509DataInfo {
                subject_names: vec![leaf_metadata.subject_dn],
                ..X509DataInfo::default()
            })],
        };
        let resolver = DefaultKeyResolver::new(KeyResolverConfig {
            trusted_certs: vec![trusted_root.der().to_vec()],
            lookup_certs: vec![
                leaf.der().to_vec(),
                untrusted_intermediate.der().to_vec(),
                trusted_intermediate.der().to_vec(),
                untrusted_root.der().to_vec(),
            ],
            ..KeyResolverConfig::default()
        });

        let resolved = resolver
            .resolve_with_policy(
                Some(&key_info),
                SignatureAlgorithm::EcdsaSha256,
                &verification_policy_with_trust(chain_policy()),
            )
            .expect("the sole path to a configured anchor should be selected");

        assert!(resolved.is_some());
    }

    #[test]
    fn self_issued_rollover_continues_to_same_name_trusted_signer() {
        // Subject/issuer name equality does not prove self-signing: rollover
        // certificates may be issued by a distinct same-name trust anchor.
        let root = rcgen::CertifiedIssuer::self_signed(
            generated_certificate_params("rollover authority", true),
            rcgen::KeyPair::generate().expect("root key generation should succeed"),
        )
        .expect("root should be self-signable");
        let rollover_params = generated_certificate_params("rollover authority", true);
        let rollover_key =
            rcgen::KeyPair::generate().expect("rollover key generation should succeed");
        let rollover_certificate = rollover_params
            .signed_by(&rollover_key, &root)
            .expect("root should sign the same-name rollover certificate");
        let rollover_issuer = rcgen::Issuer::from_params(&rollover_params, &rollover_key);
        let leaf = generated_certificate_params("rollover leaf", false)
            .signed_by(
                &rcgen::KeyPair::generate().expect("leaf key generation should succeed"),
                &rollover_issuer,
            )
            .expect("rollover key should sign the leaf");
        let leaf_metadata =
            parse_x509_certificate(leaf.der()).expect("generated leaf metadata should parse");
        let key_info = KeyInfo {
            sources: vec![KeyInfoSource::X509Data(X509DataInfo {
                subject_names: vec![leaf_metadata.subject_dn],
                ..X509DataInfo::default()
            })],
        };
        let resolver = DefaultKeyResolver::new(KeyResolverConfig {
            trusted_certs: vec![root.der().to_vec()],
            lookup_certs: vec![leaf.der().to_vec(), rollover_certificate.der().to_vec()],
            ..KeyResolverConfig::default()
        });

        let resolved = resolver
            .resolve_with_policy(
                Some(&key_info),
                SignatureAlgorithm::EcdsaSha256,
                &verification_policy_with_trust(chain_policy()),
            )
            .expect("same-name rollover path must reach its configured signer");

        assert!(resolved.is_some());
    }

    #[test]
    fn x509_candidate_limit_counts_generated_partial_paths() {
        // A narrow DFS frontier can still generate unbounded partial paths over
        // time, so the resource limit must account for every generated state.
        let root = rcgen::CertifiedIssuer::self_signed(
            generated_certificate_params("candidate root", true),
            rcgen::KeyPair::generate().expect("root key generation should succeed"),
        )
        .expect("root should be self-signable");
        let intermediate = rcgen::CertifiedIssuer::signed_by(
            generated_certificate_params("candidate intermediate", true),
            rcgen::KeyPair::generate().expect("intermediate key generation should succeed"),
            &root,
        )
        .expect("root should sign the intermediate");
        let leaf = generated_certificate_params("candidate leaf", false)
            .signed_by(
                &rcgen::KeyPair::generate().expect("leaf key generation should succeed"),
                &intermediate,
            )
            .expect("intermediate should sign the leaf");
        let info = x509_info(
            vec![
                root.der().to_vec(),
                intermediate.der().to_vec(),
                leaf.der().to_vec(),
            ],
            2,
        );

        assert!(matches!(
            build_x509_certificate_paths_to_trusted_prefix(
                &info,
                2,
                1,
                9,
                2,
                crate::provider::default_provider(),
            ),
            Err(X509ChainBuildError::AmbiguousIssuer)
        ));
    }

    #[test]
    fn selector_resolved_leaf_disambiguates_same_subject_issuers_by_signature() {
        // Certificate renewal may leave multiple configured intermediates with
        // the same subject DN. The leaf signature, not pool order, identifies
        // the one issuer that belongs to the verification path.
        let mut root_params =
            rcgen::CertificateParams::new(Vec::new()).expect("empty root SAN list should be valid");
        root_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "shared-issuer root");
        root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        root_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let root = rcgen::CertifiedIssuer::self_signed(
            root_params,
            rcgen::KeyPair::generate().expect("root key generation should succeed"),
        )
        .expect("root certificate should be self-signable");

        let intermediate = |key: rcgen::KeyPair| {
            let mut params = rcgen::CertificateParams::new(Vec::new())
                .expect("empty intermediate SAN list should be valid");
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "renewed intermediate");
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
            rcgen::CertifiedIssuer::signed_by(params, key, &root)
                .expect("root should sign the intermediate certificate")
        };
        let unrelated_intermediate = intermediate(
            rcgen::KeyPair::generate().expect("unrelated intermediate key generation should work"),
        );
        let signing_intermediate = intermediate(
            rcgen::KeyPair::generate().expect("signing intermediate key generation should work"),
        );

        let mut leaf_params =
            rcgen::CertificateParams::new(Vec::new()).expect("empty leaf SAN list should be valid");
        leaf_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "same-subject leaf");
        let leaf = leaf_params
            .signed_by(
                &rcgen::KeyPair::generate().expect("leaf key generation should succeed"),
                &signing_intermediate,
            )
            .expect("the selected intermediate should sign the leaf certificate");
        let key_info_xml = concat!(
            "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">",
            "<X509Data><X509SubjectName>CN=same-subject leaf</X509SubjectName></X509Data>",
            "</KeyInfo>"
        );
        let document = roxmltree::Document::parse(key_info_xml)
            .expect("static selector KeyInfo should parse as XML");
        let key_info = super::super::parse_key_info(document.root_element())
            .expect("static selector KeyInfo should satisfy XMLDSig structure");
        let resolver = DefaultKeyResolver::new(KeyResolverConfig {
            lookup_certs: vec![
                leaf.der().to_vec(),
                unrelated_intermediate.der().to_vec(),
                signing_intermediate.der().to_vec(),
            ],
            trusted_certs: vec![root.der().to_vec()],
            ..KeyResolverConfig::default()
        });

        let resolved = resolver
            .resolve_with_policy(
                Some(&key_info),
                SignatureAlgorithm::EcdsaSha256,
                &verification_policy_with_trust(chain_policy()),
            )
            .expect("the leaf signature should select its unique same-subject issuer");

        assert!(resolved.is_some());
    }

    #[test]
    fn x509_path_builder_skips_branch_local_unsupported_algorithms() {
        // An untrusted intermediate can share both the subject and public key
        // of the valid path while using an unsupported signature algorithm on
        // its own parent edge. That branch must not suppress the valid path.
        let root = rcgen::CertifiedIssuer::self_signed(
            generated_certificate_params("unsupported-edge root", true),
            rcgen::KeyPair::generate().expect("root key generation should succeed"),
        )
        .expect("root certificate should be self-signable");
        let signing_intermediate = rcgen::CertifiedIssuer::signed_by(
            generated_certificate_params("shared unsupported-edge issuer", true),
            rcgen::KeyPair::generate().expect("signing issuer key generation should succeed"),
            &root,
        )
        .expect("root should sign the intermediate certificate");
        let key_unsupported_intermediate = rcgen::CertifiedIssuer::signed_by(
            generated_certificate_params("shared unsupported-edge issuer", true),
            rcgen::KeyPair::generate().expect("unsupported issuer key generation should succeed"),
            &root,
        )
        .expect("root should sign the alternate intermediate certificate");
        let leaf = generated_certificate_params("unsupported-edge leaf", false)
            .signed_by(
                &rcgen::KeyPair::generate().expect("leaf key generation should succeed"),
                &signing_intermediate,
            )
            .expect("signing intermediate should sign the leaf");

        let ordered = x509_info(
            vec![
                leaf.der().to_vec(),
                key_unsupported_intermediate.der().to_vec(),
                signing_intermediate.der().to_vec(),
                root.der().to_vec(),
            ],
            0,
        );
        let key_selective_provider = RejectSecondSha512Provider {
            sha512_calls: AtomicUsize::new(0),
            verification_calls: AtomicUsize::new(0),
            reject_verification_call: Some(0),
            rejected_verification_data: None,
        };
        assert_eq!(
            super::super::parse::build_x509_certificate_chain_from(
                &ordered,
                0,
                &key_selective_provider,
            )
            .expect("one unsupported issuer key must not suppress a usable candidate"),
            vec![0, 2, 3]
        );

        let anchored_same_edge = x509_info(
            vec![
                root.der().to_vec(),
                leaf.der().to_vec(),
                key_unsupported_intermediate.der().to_vec(),
                signing_intermediate.der().to_vec(),
            ],
            1,
        );
        let first_candidate_unsupported = RejectSecondSha512Provider {
            sha512_calls: AtomicUsize::new(0),
            verification_calls: AtomicUsize::new(0),
            reject_verification_call: Some(0),
            rejected_verification_data: None,
        };
        assert_eq!(
            build_x509_certificate_paths_to_trusted_prefix(
                &anchored_same_edge,
                1,
                1,
                4,
                8,
                &first_candidate_unsupported,
            )
            .expect("a later same-DN issuer must survive an earlier provider capability miss"),
            vec![vec![1, 3, 0]]
        );

        let mut unsupported_intermediate = signing_intermediate.der().to_vec();
        let ecdsa_sha256_oid = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
        let offsets = unsupported_intermediate
            .windows(ecdsa_sha256_oid.len())
            .enumerate()
            .filter_map(|(offset, window)| (window == ecdsa_sha256_oid).then_some(offset))
            .collect::<Vec<_>>();
        assert_eq!(
            offsets.len(),
            2,
            "certificate must repeat its signature OID"
        );
        for offset in offsets {
            unsupported_intermediate[offset + ecdsa_sha256_oid.len() - 1] = 0x04;
        }

        let anchored = x509_info(
            vec![
                root.der().to_vec(),
                leaf.der().to_vec(),
                signing_intermediate.der().to_vec(),
                unsupported_intermediate,
            ],
            1,
        );
        assert_eq!(
            build_x509_certificate_paths_to_trusted_prefix(
                &anchored,
                1,
                1,
                4,
                8,
                crate::provider::default_provider(),
            )
            .expect("a branch-local provider gap must not abort path enumeration"),
            vec![vec![1, 2, 0]]
        );

        let unsupported_only = x509_info(
            vec![
                root.der().to_vec(),
                leaf.der().to_vec(),
                anchored.certificates[3].clone(),
            ],
            1,
        );
        assert!(matches!(
            build_x509_certificate_paths_to_trusted_prefix(
                &unsupported_only,
                1,
                1,
                4,
                8,
                crate::provider::default_provider(),
            ),
            Err(X509ChainBuildError::UnsupportedSignatureAlgorithm { ref oid })
                if oid == "1.2.840.10045.4.3.4"
        ));
    }

    #[test]
    fn selector_resolved_certificate_preserves_supplied_crls() {
        let selector = "<KeyInfo><X509Data><X509SubjectName>CN=Test Key rsa-2048,O=XML Security Library (http://www.aleksey.com/xmlsec),ST=California,C=US</X509SubjectName><X509CRL>CRL_PLACEHOLDER</X509CRL></X509Data></KeyInfo>";
        let crl = crl_der(include_str!(
            "../../tests/fixtures/keys/rsa/rsa-2048-cert-revoked-crl.pem"
        ));
        let (_, parsed_crl) =
            x509_parser::revocation_list::CertificateRevocationList::from_der(&crl)
                .expect("tracked CRL must parse");
        let crl_signed_data = parsed_crl.tbs_cert_list.as_ref().to_vec();
        let xml = replace_unprefixed_key_info(
            RSA_KEY_VALUE_SIGNATURE,
            &selector.replace("CRL_PLACEHOLDER", &STANDARD.encode(&crl)),
        );
        let resolver = DefaultKeyResolver::new(KeyResolverConfig {
            lookup_certs: vec![certificate_der(include_str!(
                "../../tests/fixtures/keys/rsa/rsa-2048-cert.pem"
            ))],
            trusted_certs: vec![
                certificate_der(include_str!("../../tests/fixtures/keys/ca2cert.pem")),
                certificate_der(include_str!("../../tests/fixtures/keys/cacert.pem")),
            ],
            ..KeyResolverConfig::default()
        });
        let policy = verification_policy_with_trust(crate::policy::KeyTrustPolicy {
            check_crls: true,
            max_x509_chain_depth: 3,
            ..chain_policy_at(
                SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_773_964_800),
            )
        });

        let error = super::super::VerifyContext::new()
            .policy(policy.clone())
            .key_resolver(&resolver)
            .verify(&xml)
            .expect_err("selector lookup must retain and enforce the supplied CRL");
        assert!(matches!(
            error,
            DsigError::KeyResolution(KeyResolutionError::Chain(
                super::super::X509ChainError::Revoked(0)
            ))
        ));

        // Match the exact TBSCertList bytes so earlier certificate-edge
        // verification succeeds and the provider rejection occurs at CRL
        // authentication itself.
        let provider = RejectSecondSha512Provider {
            sha512_calls: AtomicUsize::new(0),
            verification_calls: AtomicUsize::new(0),
            reject_verification_call: None,
            rejected_verification_data: Some(crl_signed_data),
        };
        let error = super::super::VerifyContext::new()
            .policy(policy)
            .key_resolver(&resolver)
            .provider(&provider)
            .verify(&xml)
            .expect_err("CRL authentication must retain the operation provider");
        assert!(matches!(
            error,
            DsigError::KeyResolution(KeyResolutionError::Chain(
                super::super::X509ChainError::Provider(_)
            ))
        ));
    }

    #[test]
    fn resolves_each_x509_selector_from_configured_certificates() {
        // Every selector form documented by KeyInfo must independently locate
        // the same configured RSA certificate without embedded key material.
        let selectors = [
            "<X509SubjectName>CN=Test Key rsa-2048,O=XML Security Library (http://www.aleksey.com/xmlsec),ST=California,C=US</X509SubjectName>",
            "<X509SubjectName>CN=  test   key rsa-2048  ,O=xml security library (HTTP://WWW.ALEKSEY.COM/XMLSEC),ST=california,C=us</X509SubjectName>",
            "<X509IssuerSerial><X509IssuerName>Email=xmlsec@aleksey.com,CN=Aleksey Sanin,OU=Second level CA,O=XML Security Library (http://www.aleksey.com/xmlsec),ST=California,C=US</X509IssuerName><X509SerialNumber>680572598617295163017172295025714171905498632019</X509SerialNumber></X509IssuerSerial>",
            "<X509SKI>bcOXN/nsVl8GatRbcKrPbzIbw0Y=</X509SKI>",
        ];
        let configured_certificate = certificate_der(include_str!(
            "../../tests/fixtures/keys/rsa/rsa-2048-cert.pem"
        ));

        for selector in selectors {
            let key_info = format!("<KeyInfo><X509Data>{selector}</X509Data></KeyInfo>");
            let xml = replace_unprefixed_key_info(RSA_KEY_VALUE_SIGNATURE, &key_info);
            let resolver = DefaultKeyResolver::new(KeyResolverConfig {
                lookup_certs: vec![configured_certificate.clone()],
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
    fn resolves_configured_chain_selectors_across_certificates() {
        // Selector categories may identify different members of one configured
        // chain; the unique leaf remains the signing certificate.
        let key_info = r#"<KeyInfo><X509Data><X509SubjectName>CN=Test Key rsa-2048,O=XML Security Library (http://www.aleksey.com/xmlsec),ST=California,C=US</X509SubjectName><X509SKI>0X0XrEVCio75sBcl1TxymJ2IOiU=</X509SKI></X509Data></KeyInfo>"#;
        let xml = replace_unprefixed_key_info(RSA_KEY_VALUE_SIGNATURE, key_info);
        let resolver = DefaultKeyResolver::new(KeyResolverConfig {
            lookup_certs: vec![
                certificate_der(include_str!(
                    "../../tests/fixtures/keys/rsa/rsa-2048-cert.pem"
                )),
                certificate_der(include_str!("../../tests/fixtures/keys/ca2cert.pem")),
            ],
            ..KeyResolverConfig::default()
        });
        let result = super::super::VerifyContext::new()
            .key_resolver(&resolver)
            .verify(&xml)
            .expect("selectors across one configured chain should resolve its leaf");

        assert_eq!(result.status, super::super::DsigStatus::Valid);
    }

    #[test]
    fn selectors_must_all_match_the_selected_certificate_path() {
        // Selector categories may identify different certificates only when
        // those certificates belong to the one path chosen for the signer.
        let signing_certificate = certificate_der(include_str!(
            "../../tests/fixtures/keys/rsa/rsa-2048-cert.pem"
        ));
        let issuer_certificate =
            certificate_der(include_str!("../../tests/fixtures/keys/ca2cert.pem"));
        let unrelated = generated_certificate_params("unrelated selector certificate", false)
            .self_signed(
                &rcgen::KeyPair::generate().expect("unrelated key generation should succeed"),
            )
            .expect("unrelated certificate should be self-signable")
            .der()
            .to_vec();
        let digest = crate::provider::default_provider()
            .digest(super::super::DigestAlgorithm::Sha256, &unrelated)
            .expect("SHA-256 selector digest must be available");
        let key_info_xml = format!(
            "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:dsig11=\"http://www.w3.org/2009/xmldsig11#\"><X509Data><X509SubjectName>CN=Test Key rsa-2048,O=XML Security Library (http://www.aleksey.com/xmlsec),ST=California,C=US</X509SubjectName><dsig11:X509Digest Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\">{}</dsig11:X509Digest></X509Data></KeyInfo>",
            STANDARD.encode(digest)
        );
        let document = roxmltree::Document::parse(&key_info_xml)
            .expect("generated selector KeyInfo must be XML");
        let key_info = super::super::parse_key_info(document.root_element())
            .expect("generated selector KeyInfo must be structurally valid");
        let resolver = DefaultKeyResolver::new(KeyResolverConfig {
            lookup_certs: vec![signing_certificate, issuer_certificate, unrelated],
            ..KeyResolverConfig::default()
        });

        assert!(
            resolver
                .resolve(Some(&key_info), SignatureAlgorithm::RsaSha256)
                .expect("disjoint selector matches are a key miss")
                .is_none()
        );
    }

    #[test]
    fn unmatched_x509_selector_does_not_resolve() {
        // A selector mismatch must not fall back to arbitrary configured key material.
        let key_info = "<KeyInfo><X509Data><X509SubjectName>CN=not-the-signer</X509SubjectName></X509Data></KeyInfo>";
        let xml = replace_unprefixed_key_info(RSA_KEY_VALUE_SIGNATURE, key_info);
        let resolver = DefaultKeyResolver::new(KeyResolverConfig {
            lookup_certs: vec![certificate_der(include_str!(
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
    fn overlapping_trusted_and_lookup_certificate_preserves_trust() {
        // One physical certificate appearing in both pools is one candidate;
        // deduplication must retain the stronger trusted classification.
        let certificate = certificate_der(RSA_4096_CERTIFICATE);
        let resolver = DefaultKeyResolver::new(KeyResolverConfig {
            trusted_certs: vec![certificate.clone()],
            lookup_certs: vec![certificate],
            ..KeyResolverConfig::default()
        });
        let result = super::super::VerifyContext::new()
            .policy(verification_policy_with_trust(chain_policy_at(
                fixture_certificate_time(),
            )))
            .key_resolver(&resolver)
            .verify(&x509_signature_with_leaf_subject())
            .expect("trusted/lookup overlap must resolve as one trusted candidate");

        assert_eq!(result.status, super::super::DsigStatus::Valid);
    }

    #[test]
    fn distinct_x509_selector_matches_remain_ambiguous() {
        // Deduplication is identity-based, not selector-based: two distinct
        // certificates with the same subject remain separate candidates.
        let certificate = || {
            generated_certificate_params("ambiguous selector", false)
                .self_signed(
                    &rcgen::KeyPair::generate().expect("test key generation should succeed"),
                )
                .expect("test certificate should be self-signable")
                .der()
                .to_vec()
        };
        let xml = replace_unprefixed_key_info(
            X509_DIGEST_SIGNATURE,
            "<KeyInfo><X509Data><X509SubjectName>CN=ambiguous selector</X509SubjectName></X509Data></KeyInfo>",
        );
        let resolver = DefaultKeyResolver::new(KeyResolverConfig {
            lookup_certs: vec![certificate(), certificate()],
            ..KeyResolverConfig::default()
        });
        let error = super::super::VerifyContext::new()
            .key_resolver(&resolver)
            .verify(&xml)
            .expect_err("distinct selector matches must fail closed");

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
            lookup_certs: vec![certificate_der(include_str!(
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
    fn x509_digest_selector_uses_operation_provider() {
        // The SHA-512 selector is distinct from the SHA-256 reference digest,
        // so only provider-aware key selection can surface this rejection.
        let resolver = DefaultKeyResolver::new(KeyResolverConfig {
            lookup_certs: vec![certificate_der(RSA_4096_CERTIFICATE)],
            trusted_certs: vec![
                certificate_der(include_str!("../../tests/fixtures/keys/ca2cert.pem")),
                certificate_der(include_str!("../../tests/fixtures/keys/cacert.pem")),
            ],
            ..KeyResolverConfig::default()
        });
        let provider = RejectSecondSha512Provider {
            sha512_calls: AtomicUsize::new(0),
            verification_calls: AtomicUsize::new(0),
            reject_verification_call: None,
            rejected_verification_data: None,
        };
        let error = super::super::VerifyContext::new()
            .key_resolver(&resolver)
            .provider(&provider)
            .verify(X509_DIGEST_SIGNATURE)
            .expect_err("X509Digest selection must use the operation provider");

        assert!(
            matches!(
                error,
                DsigError::Provider(crate::provider::ProviderError::Unsupported {
                    operation: crate::provider::ProviderOperation::Digest,
                    algorithm: Some(ref uri),
                }) if uri == super::super::DigestAlgorithm::Sha512.uri()
            ),
            "unexpected error: {error:?}"
        );
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
                algorithm: SignatureAlgorithm::EcdsaSha256,
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
        let (modulus, exponent) = rsa_key_value_parts(&public_key);
        let key_info = format!(
            "<KeyInfo><KeyValue><RSAKeyValue><Modulus>{}</Modulus><Exponent>{}</Exponent></RSAKeyValue></KeyValue></KeyInfo>",
            modulus, exponent,
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
        // The secure policy rejects legacy RSA-SHA1 independently of whether
        // the capable key came from RSAKeyValue, DER, X.509, or KeyName.
        let resolver = DefaultKeyResolver::default();
        let error = super::super::VerifyContext::new()
            .key_resolver(&resolver)
            .verify(LEGACY_RSA_KEY_VALUE_SIGNATURE)
            .expect_err("context policy must override permissive resolver defaults");

        assert!(matches!(
            error,
            DsigError::Policy(crate::policy::PolicyViolation::Algorithm {
                operation: "verification",
                ..
            })
        ));
    }

    #[test]
    fn operation_policy_rejects_disabled_embedded_key_source() {
        // Resolver-owned key material cannot override the operation snapshot's
        // decision about which attacker-controlled KeyInfo forms are trusted.
        let key_info = KeyInfo {
            sources: vec![KeyInfoSource::KeyValue(KeyValueInfo::Rsa {
                modulus: vec![0x80; 256],
                exponent: vec![1, 0, 1],
            })],
        };
        let mut policy = crate::policy::VerificationPolicy::default();
        policy.key_sources.key_value = false;

        let error = match DefaultKeyResolver::default().resolve_with_policy(
            Some(&key_info),
            SignatureAlgorithm::RsaSha256,
            &policy,
        ) {
            Ok(_) => panic!("disabled KeyValue must fail before key construction"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            DsigError::Policy(crate::policy::PolicyViolation::KeyTrust {
                reason: "KeyValue key sources are disabled"
            })
        ));
    }

    #[test]
    fn operation_policy_bounds_ordered_key_info_candidates() {
        // The candidate ceiling belongs to the complete verification snapshot:
        // neither a first source nor fallback to a later source may bypass it.
        let mut config = KeyResolverConfig::default();
        config.named_keys.insert(
            "idp-signing".into(),
            VerificationKey {
                algorithm: SignatureAlgorithm::EcdsaSha256,
                public_key_bytes: public_key_der(SAML_PUBLIC_KEY),
                certificate_der: None,
                name: Some("idp-signing".into()),
            },
        );
        let resolver = DefaultKeyResolver::new(config);
        let key_info = KeyInfo {
            sources: vec![
                KeyInfoSource::KeyValue(KeyValueInfo::Ec {
                    curve_oid: "1.3.132.0.35".into(),
                    public_key: vec![4],
                }),
                KeyInfoSource::KeyName("idp-signing".into()),
            ],
        };

        for maximum in [0, 1] {
            let mut policy = crate::policy::VerificationPolicy::default();
            policy.resources.max_key_candidates = maximum;
            let error = match resolver.resolve_with_policy(
                Some(&key_info),
                SignatureAlgorithm::EcdsaSha256,
                &policy,
            ) {
                Ok(_) => panic!("candidate ceiling {maximum} must stop resolution"),
                Err(error) => error,
            };
            assert!(matches!(
                error,
                DsigError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::KEY_CANDIDATES,
                    maximum: observed,
                    actual,
                }) if observed == maximum && actual == maximum + 1
            ));
        }

        let mut policy = crate::policy::VerificationPolicy::default();
        policy.resources.max_key_candidates = 2;
        assert!(
            resolver
                .resolve_with_policy(Some(&key_info), SignatureAlgorithm::EcdsaSha256, &policy,)
                .expect("two allowed attempts must reach the named key")
                .is_some()
        );
    }

    #[test]
    fn operation_policy_bounds_configured_x509_selector_candidates() {
        // One X509Data selector can fan out across the resolver-owned store.
        // Every distinct certificate inspected is candidate work, rather than
        // the complete store counting as one KeyInfo source.
        let resolver = DefaultKeyResolver::new(KeyResolverConfig {
            lookup_certs: vec![
                certificate_der(include_str!("../../tests/fixtures/keys/ca2cert.pem")),
                certificate_der(RSA_4096_CERTIFICATE),
            ],
            ..KeyResolverConfig::default()
        });
        let mut policy = crate::policy::VerificationPolicy::default();
        policy.resources.max_key_candidates = 1;

        let error = super::super::VerifyContext::new()
            .policy(policy)
            .key_resolver(&resolver)
            .verify(&x509_signature_with_leaf_subject())
            .expect_err("the second configured certificate must exceed the candidate budget");

        assert!(matches!(
            error,
            DsigError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::KEY_CANDIDATES,
                maximum: 1,
                actual: 2,
            })
        ));
    }

    #[test]
    fn operation_policy_bounds_embedded_x509_certificate_candidates() {
        // Embedded X509Data is also composite key material. Its certificate
        // entries must not collapse into one candidate merely because they
        // share a single KeyInfo source node.
        let key_info = KeyInfo {
            sources: vec![KeyInfoSource::X509Data(X509DataInfo {
                certificates: vec![
                    certificate_der(RSA_4096_CERTIFICATE),
                    certificate_der(include_str!("../../tests/fixtures/keys/ca2cert.pem")),
                ],
                certificate_chain: vec![0],
                ..X509DataInfo::default()
            })],
        };
        let mut policy = crate::policy::VerificationPolicy::default();
        policy.resources.max_key_candidates = 1;

        let error = match DefaultKeyResolver::default().resolve_with_policy(
            Some(&key_info),
            SignatureAlgorithm::RsaSha256,
            &policy,
        ) {
            Ok(_) => panic!("the second embedded certificate must exceed the candidate budget"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            DsigError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::KEY_CANDIDATES,
                maximum: 1,
                actual: 2,
            })
        ));
    }

    #[test]
    fn policy_aware_resolver_rejects_resources_above_hard_ceiling() {
        // The resolver is a public policy enforcement boundary in its own
        // right; callers must not need VerifyContext to validate the snapshot.
        let mut policy = crate::policy::VerificationPolicy::default();
        policy.resources.max_key_candidates = usize::MAX;

        let error = match DefaultKeyResolver::default().resolve_with_policy(
            None,
            SignatureAlgorithm::RsaSha256,
            &policy,
        ) {
            Ok(_) => panic!("invalid resource policy must fail before key resolution"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            DsigError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::KEY_CANDIDATES,
                actual: usize::MAX,
                ..
            })
        ));
    }

    #[test]
    fn embedded_x509_digest_selection_uses_operation_provider() {
        // Embedded certificate selection happens while KeyInfo is parsed, so
        // that parser path must retain the verification operation's provider.
        let certificate = certificate_der(RSA_4096_CERTIFICATE);
        let digest =
            super::super::compute_digest(super::super::DigestAlgorithm::Sha512, &certificate);
        let xml = format!(
            "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><X509Data><X509Certificate>{}</X509Certificate><X509Digest xmlns=\"http://www.w3.org/2009/xmldsig11#\" Algorithm=\"{}\">{}</X509Digest></X509Data></KeyInfo>",
            STANDARD.encode(&certificate),
            super::super::DigestAlgorithm::Sha512.uri(),
            STANDARD.encode(digest),
        );
        let document = roxmltree::Document::parse(&xml).expect("generated KeyInfo must be XML");
        let provider = RejectSecondSha512Provider {
            sha512_calls: AtomicUsize::new(1),
            verification_calls: AtomicUsize::new(0),
            reject_verification_call: None,
            rejected_verification_data: None,
        };

        let error =
            super::super::parse::parse_key_info_with_provider(document.root_element(), &provider)
                .expect_err("embedded X509Digest selection must use the operation provider");

        assert!(
            matches!(
                error,
                ParseError::Provider(crate::provider::ProviderError::Unsupported {
                    operation: crate::provider::ProviderOperation::Digest,
                    algorithm: Some(ref uri),
                }) if uri == super::super::DigestAlgorithm::Sha512.uri()
            ),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn generic_key_resolution_keeps_legacy_capability_source_independent() {
        let certificate =
            include_bytes!("../../tests/fixtures/xmldsig/phaos-xmldsig-three/certs/rsa-cert.der")
                .to_vec();
        let (_, parsed_certificate) = X509Certificate::from_der(&certificate)
            .expect("the Phaos fixture is a DER certificate");
        let public_key = parsed_certificate.public_key().raw.to_vec();
        let rsa_public_key = rsa::RsaPublicKey::from_public_key_der(&public_key)
            .expect("the Phaos certificate contains an RSA public key");
        let certificate_metadata = parse_x509_certificate(&certificate)
            .expect("the Phaos fixture has supported X.509 metadata");
        let named_key = VerificationKey {
            algorithm: SignatureAlgorithm::RsaSha1,
            public_key_bytes: public_key.clone(),
            certificate_der: None,
            name: Some("legacy".into()),
        };
        let key_infos = [
            KeyInfo {
                sources: vec![KeyInfoSource::KeyName("legacy".into())],
            },
            KeyInfo {
                sources: vec![KeyInfoSource::DerEncodedKeyValue(public_key.clone())],
            },
            KeyInfo {
                sources: vec![KeyInfoSource::KeyValue(KeyValueInfo::Rsa {
                    modulus: rsa_public_key.n().to_be_bytes_trimmed_vartime().to_vec(),
                    exponent: rsa_public_key.e().to_be_bytes_trimmed_vartime().to_vec(),
                })],
            },
            KeyInfo {
                sources: vec![KeyInfoSource::X509Data(X509DataInfo {
                    certificates: vec![certificate],
                    parsed_certificates: vec![certificate_metadata],
                    certificate_chain: vec![0],
                    ..X509DataInfo::default()
                })],
            },
        ];
        let resolver = DefaultKeyResolver::new(KeyResolverConfig {
            named_keys: HashMap::from([("legacy".into(), named_key.clone())]),
            ..KeyResolverConfig::default()
        });
        let mut policy = crate::policy::VerificationPolicy::default();
        policy.key_trust.rsa_keys.minimum_modulus_bits = 1024;
        policy
            .key_trust
            .allowed_legacy_signature_algorithms
            .insert(SignatureAlgorithm::RsaSha1);

        for key_info in &key_infos {
            let key = resolver
                .resolve_with_policy(Some(key_info), SignatureAlgorithm::RsaSha1, &policy)
                .expect("the key source is valid")
                .expect("key resolution remains independent from operation policy");
            assert!(
                !key.verify(SignatureAlgorithm::RsaSha1, b"data", &[0; 128])
                    .expect("the legacy RSA key is structurally valid")
            );
        }
    }

    #[test]
    fn rsa_key_value_rejects_ecdsa_signature_method() {
        // Embedded RSA parameters must not be relabeled for an ECDSA SignatureMethod.
        let public_key = rsa::RsaPublicKey::from_public_key_pem(RSA_PUBLIC_KEY)
            .expect("fixture must contain an RSA public key");
        let (modulus, exponent) = rsa_key_value_parts(&public_key);
        let key_info = format!(
            "<ds:KeyInfo><ds:KeyValue><ds:RSAKeyValue><ds:Modulus>{}</ds:Modulus><ds:Exponent>{}</ds:Exponent></ds:RSAKeyValue></ds:KeyValue></ds:KeyInfo>",
            modulus, exponent,
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
        let (modulus, exponent) = rsa_key_value_parts(&public_key);
        let key_info = format!(
            r#"<KeyInfo xmlns:dsig11="http://www.w3.org/2009/xmldsig11#"><KeyValue><dsig11:ECKeyValue><dsig11:NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"/><dsig11:PublicKey>BJ/yaXNlq4FRObyJCBhb5jAz8GVzinK3bBGLjSDfjbJwNfydtgjnlS4EsDmxSRhWyJWq6GIqy5wvnaiARK04uB4=</dsig11:PublicKey></dsig11:ECKeyValue></KeyValue><KeyValue><RSAKeyValue><Modulus>{}</Modulus><Exponent>{}</Exponent></RSAKeyValue></KeyValue></KeyInfo>"#,
            modulus, exponent,
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
                algorithm: SignatureAlgorithm::EcdsaSha256,
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
                algorithm: SignatureAlgorithm::EcdsaSha256,
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
                algorithm: SignatureAlgorithm::EcdsaSha256,
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
                algorithm: SignatureAlgorithm::EcdsaSha256,
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
                algorithm: SignatureAlgorithm::EcdsaSha256,
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
                    algorithm: SignatureAlgorithm::EcdsaSha256,
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
    fn supported_ec_curve_does_not_fall_back_to_later_key_name() {
        // ECDSA-SHA256 accepts P-384, so this first source is a usable key and
        // must not be skipped merely because a later P-256 KeyName happens to
        // verify the signature. Verification fails against the selected key.
        let key_info = r#"<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:dsig11="http://www.w3.org/2009/xmldsig11#"><ds:KeyValue><dsig11:ECKeyValue><dsig11:NamedCurve URI="urn:oid:1.3.132.0.34"/><dsig11:PublicKey>BO/yd/OZzDfjX4qivDY/vsUIuh6KWAxoxW5P4ukvwd+T6pVljWsX2UBJNNy5MdhTwB8e2YwB8kUbJwdsAS/XGi/fz8unFrs+lVlAgIs6s/xBYFbfUoRiAacD2SpVDe6XBA==</dsig11:PublicKey></dsig11:ECKeyValue></ds:KeyValue><ds:KeyName>idp-signing</ds:KeyName></ds:KeyInfo>"#;
        let xml = replace_key_info(SIGNED_SAML, key_info);
        let mut config = KeyResolverConfig::default();
        config.named_keys.insert(
            "idp-signing".into(),
            VerificationKey {
                algorithm: SignatureAlgorithm::EcdsaSha256,
                public_key_bytes: public_key_der(SAML_PUBLIC_KEY),
                certificate_der: None,
                name: Some("idp-signing".into()),
            },
        );
        let resolver = DefaultKeyResolver::new(config);
        let error = super::super::VerifyContext::new()
            .key_resolver(&resolver)
            .verify(&xml)
            .expect_err("a usable first key source must not fall through after verification");

        assert!(matches!(
            error,
            DsigError::Crypto(super::super::SignatureVerificationError::InvalidSignatureFormat)
        ));
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
    fn lone_supported_ec_curve_reaches_signature_verification() {
        let key_info = r#"<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:dsig11="http://www.w3.org/2009/xmldsig11#"><ds:KeyValue><dsig11:ECKeyValue><dsig11:NamedCurve URI="urn:oid:1.3.132.0.34"/><dsig11:PublicKey>BO/yd/OZzDfjX4qivDY/vsUIuh6KWAxoxW5P4ukvwd+T6pVljWsX2UBJNNy5MdhTwB8e2YwB8kUbJwdsAS/XGi/fz8unFrs+lVlAgIs6s/xBYFbfUoRiAacD2SpVDe6XBA==</dsig11:PublicKey></dsig11:ECKeyValue></ds:KeyValue></ds:KeyInfo>"#;
        let xml = replace_key_info(SIGNED_SAML, key_info);
        let error = super::super::VerifyContext::new()
            .key_resolver(&DefaultKeyResolver::default())
            .verify(&xml)
            .expect_err("a supported EC curve must reach signature verification");

        assert!(matches!(
            error,
            DsigError::Crypto(super::super::SignatureVerificationError::InvalidSignatureFormat)
        ));
    }

    #[test]
    fn chain_verification_rejects_untrusted_embedded_certificate() {
        // Enabling chain policy must fail closed when no trust anchor is configured.
        let resolver = DefaultKeyResolver::new(KeyResolverConfig {
            ..KeyResolverConfig::default()
        });
        let error = super::super::VerifyContext::new()
            .policy(verification_policy_with_trust(chain_policy()))
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
                algorithm: SignatureAlgorithm::EcdsaSha256,
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
                algorithm: SignatureAlgorithm::EcdsaSha256,
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
